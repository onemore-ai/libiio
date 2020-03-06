/*
 * libiio - Library for interfacing industrial I/O (IIO) devices
 *
 * Copyright (C) 2014-2020 Analog Devices, Inc.
 * Author: Paul Cercueil <paul.cercueil@analog.com>
 *         Robin Getz <robin.getz@analog.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * Some of this is insipred from libavahi's example:
 * https://avahi.org/doxygen/html/client-browse-services_8c-example.html
 * which is also LGPL 2.1 or later.
 *
 * */

#include "iio-private.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include "debug.h"

/* in network.c */
int create_socket(const struct addrinfo *addrinfo, unsigned int timeout);
#define DEFAULT_TIMEOUT_MS 5000
#define IIOD_PORT 30431


struct avahi_discovery_data {
	AvahiSimplePoll *poll;
	AvahiAddress *address;
	char addr_str[AVAHI_ADDRESS_STR_MAX];
	char *hostname;
	uint16_t found, resolved;
	uint16_t port;
	struct avahi_discovery_data *next;
};

/*
 * Fundamentally, this builds up a linked list to manage
 * potential clients on the network
 */

static struct avahi_discovery_data * new_discovery_data(void)
{
	struct avahi_discovery_data *data;

	data = zalloc(sizeof(struct avahi_discovery_data));
	if (!data)
		return NULL;
	data->address = zalloc(sizeof(struct AvahiAddress));
	if (!data->address)
		return NULL;

	return data;
}

static void free_discovery_data(struct avahi_discovery_data *d)
{
	free(d->address);
	free(d);
}

static struct avahi_discovery_data * remove_node(struct avahi_discovery_data *ddata, int n)
{

	struct avahi_discovery_data *ndata, *ldata, *tdata;
	int i;

	if (n == 0) {
		tdata = ddata->next;
		free_discovery_data(ddata);
		ddata = tdata;
		return ddata;
	}

	for (i = 0, ndata = ddata; ndata->next != NULL; ndata = ndata->next) {
		if (i == n) {
			tdata = ndata->next;
			free_discovery_data(ndata);
			ldata->next = tdata;
			break;
		}
		ldata = ndata;
		i++;
	}

	return ddata;
}

static void free_all_discovery_data(struct avahi_discovery_data *d)
{
	while (d)
		d = remove_node(d, 0);
}

static struct avahi_discovery_data * remove_dup_discovery_data(struct avahi_discovery_data *ddata)
{
	struct avahi_discovery_data *ndata, *mdata;
	int i, j;

	if (!ddata)
		return NULL;

	if (!ddata->next)
		return ddata;

	for (i = 0, ndata = ddata; ndata->next != NULL; ndata = ndata->next) {
		for (j = i + 1, mdata = ndata->next; mdata->next != NULL; mdata = mdata->next) {
			if (!strcmp(mdata->hostname, ndata->hostname)){
				remove_node(ddata, j);
			}
			j++;
		}
		i++;
	}

	return ddata;
}

/*
 * libavahi calls backs for browswer and resolver
 * for more info, check out libavahi docs at:
 * https://avahi.org/doxygen/html/index.html
 */

static void __avahi_resolver_cb(AvahiServiceResolver *resolver,
		__notused AvahiIfIndex iface, __notused AvahiProtocol proto,
		AvahiResolverEvent event, const char *name,
		const char *type, const char *domain,
		const char *host_name, const AvahiAddress *address,
		uint16_t port, AvahiStringList *txt,
		__notused AvahiLookupResultFlags flags, void *d)
{
	struct avahi_discovery_data *ddata = (struct avahi_discovery_data *) d;

	ddata->resolved++;
	if (!resolver) {
		ERROR("Fatal Error in Avahi Resolver\n");
		return;
	}

	/* Find empty data to store things*/
	while (ddata->next) {
		ddata = ddata->next;
	}

	switch(event) {
	case AVAHI_RESOLVER_FAILURE:
		ERROR("Avahi Resolver: Failed resolve service '%s' "
				"of type '%s' in domain '%s': %s\n",
				name, type, domain,
				avahi_strerror(
					avahi_client_errno(
						avahi_service_resolver_get_client(
							resolver))));
		break;
	case AVAHI_RESOLVER_FOUND: {
		avahi_address_snprint(ddata->addr_str,
				sizeof(ddata->addr_str), address);
		memcpy(ddata->address, address, sizeof(*address));
		ddata->port = port;
		ddata->hostname = strdup(host_name);
		ddata->resolved = true;


		DEBUG("Avahi Resolver : service '%s' of type '%s' in domain '%s':\n",
				name, type, domain);
		DEBUG("\t\t%s:%u (%s)\n", host_name, port, ddata->addr_str);

		/* link a new placeholder to the list */
		ddata->next = new_discovery_data();

		/* duplicate poll info, since we don't know which might be discarded */
		if (ddata->next)
			ddata->next->poll = ddata->poll;

		break;
		}
	}
	avahi_service_resolver_free(resolver);
}

static void __avahi_browser_cb(AvahiServiceBrowser *browser,
		AvahiIfIndex iface, AvahiProtocol proto,
		AvahiBrowserEvent event, const char *name,
		const char *type, const char *domain,
		__notused AvahiLookupResultFlags flags, void *d)
{
	struct avahi_discovery_data *ddata = (struct avahi_discovery_data *) d;
	struct AvahiClient *client = avahi_service_browser_get_client(browser);
	int i;

	if (!browser) {
		ERROR("Fatal Error in Avahi Browser\n");
		return;
	}

	switch (event) {
	case AVAHI_BROWSER_REMOVE:
		DEBUG("Avahi Browser : REMOVE : "
				"service '%s' of type '%s' in domain '%s'\n",
				name, type, domain);
		break;
	case AVAHI_BROWSER_NEW:
		DEBUG("Avahi Browser : NEW: "
				"service '%s' of type '%s' in domain '%s'\n",
				name, type, domain);
		if(!avahi_service_resolver_new(client, iface,
				proto, name, type, domain,
				AVAHI_PROTO_UNSPEC, 0,
				__avahi_resolver_cb, d)) {
			ERROR("Failed to resolve service '%s\n", name);
		} else
			ddata->found++;
		break;
	case AVAHI_BROWSER_ALL_FOR_NOW:
		/* Wait for a max of 1 second */
		i = 0;
		DEBUG("Avahi Browser : ALL_FOR_NOW Browser : %d, Resolved : %d\n",
				ddata->found, ddata->resolved);
		while ((ddata->found != ddata->resolved)  && i <= 200) {
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 5e6;	/* 5ms in ns*/
			nanosleep(&ts, NULL);
			i++;
		}
		avahi_simple_poll_quit(ddata->poll);
		break;
	case AVAHI_BROWSER_FAILURE:
		DEBUG("Avahi Browser : FAILURE\n");
		avahi_simple_poll_quit(ddata->poll);
		break;
	case AVAHI_BROWSER_CACHE_EXHAUSTED:
		DEBUG("Avahi Browser : CACHE_EXHAUSTED\n");
		break;
	}
}

/*
 * This creates the linked lists, tests it (make sure a context is there)
 * and returns things. the returned structure must be freed with 
 * free_all_discovery_data();
 */

static struct avahi_discovery_data * dnssd_find_hosts(int *ret)
{
	struct avahi_discovery_data *ddata, *ndata;
	AvahiClient *client;
	AvahiServiceBrowser *browser;
	int i;

	ddata = new_discovery_data();

	if (!ddata) {
		*ret = -ENOMEM;
		return NULL;
	}

	ddata->poll = avahi_simple_poll_new();
	if (!ddata->poll) {
		*ret = -ENOMEM;
		return NULL;
	}

	client = avahi_client_new(avahi_simple_poll_get(ddata->poll),
			0, NULL, NULL, ret);
	if (!client) {
		ERROR("Unable to create Avahi DNS-SD client :%s\n",
				avahi_strerror(*ret));
		goto err_free_poll;
	}

	browser = avahi_service_browser_new(client,
			AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
			"_iio._tcp", NULL, 0, __avahi_browser_cb, ddata);
	if (!browser) {
		*ret = avahi_client_errno(client);
		ERROR("Unable to create Avahi DNS-SD browser: %s\n",
				avahi_strerror(*ret));
		goto err_free_client;
	}

	DEBUG("Trying to discover host\n");
	avahi_simple_poll_loop(ddata->poll);

	if (!ddata || strlen(ddata->addr_str) == 0)
		*ret = ENXIO;

	if (*ret == 0) {
		/* remove the ones in the list that you can't connect to */
		for (i = 0, ndata = ddata; ndata->next != NULL;
				ndata = ndata->next) {
			char port_str[6];
			struct addrinfo hints, *res, *rp;
			int fd;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			iio_snprintf(port_str, sizeof(port_str), "%hu",
					ndata->port);
			*ret = getaddrinfo(ndata->addr_str, port_str,
					&hints, &res);

			/* getaddrinfo() returns a list of address structures */
			if (*ret) {
				DEBUG("Unable to find host ('%s'): %s\n",
						ndata->hostname,
						gai_strerror(*ret));
				ddata = remove_node(ddata, i);
			} else {
				for (rp = res; rp != NULL; rp = rp->ai_next) {
					fd = create_socket(res,
							DEFAULT_TIMEOUT_MS);
					if (fd < 0) {
						DEBUG("Unable to create %s%s socket ('%s:%d' %s)\n",
								res->ai_family == AF_INET ? "ipv4" : "",
								res->ai_family == AF_INET6? "ipv6" : "",
								ndata->hostname, ndata->port, ndata->addr_str);
						ddata = remove_node(ddata, i);
					} else {
						close(fd);
						DEBUG("Something %s%s at '%s:%d' %s)\n",
								res->ai_family == AF_INET ? "ipv4" : "",
								res->ai_family == AF_INET6? "ipv6" : "",
								ndata->hostname, ndata->port, ndata->addr_str);
						i++;
					}
				}
			}
			freeaddrinfo(res);
		}
		ddata = remove_dup_discovery_data(ddata);
	}

	avahi_service_browser_free(browser);
err_free_client:
	avahi_client_free(client);
err_free_poll:
	avahi_simple_poll_free(ddata->poll);
	return ddata;
}

int discover_host(char *addr_str, size_t addr_len, uint16_t *port)
{
	struct avahi_discovery_data *ddata;
	int ret = 0;

	ddata = dnssd_find_hosts(&ret);

	if (ddata) {
		*port = ddata->port;
		strncpy(addr_str, ddata->addr_str, addr_len);
	}

	free_all_discovery_data(ddata);

	return ret; /* we want a negative error code */
}

struct iio_scan_backend_context {
	struct addrinfo *res;
};

static int dnssd_fill_context_info(struct iio_context_info *info,
		char *hostname, char *addr_str, int port)
{
	struct iio_context *ctx;
	char uri[HOST_NAME_MAX + 3];
	char description[255], *p;
	const char *hw_model, *serial;
	int i;

	ctx = network_create_context(addr_str);
	if (!ctx) {
		ERROR("No context at %s\n", addr_str);
		return -ENOMEM;
	}

	if (port == IIOD_PORT)
		sprintf(uri, "ip:%s", hostname);
	else
		sprintf(uri, "ip:%s:%d", hostname, port);

	hw_model = iio_context_get_attr_value(ctx, "hw_model");
	serial = iio_context_get_attr_value(ctx, "hw_serial");

	if (hw_model && serial) {
		sprintf(description, "%s (%s), serial=%s",
				addr_str, hw_model, serial);
	} else if (hw_model) {
		sprintf(description, "%s %s", addr_str, hw_model);
	} else if (serial) {
		sprintf(description, "%s %s", addr_str, serial);
	} else if (ctx->nb_devices == 0) {
		sprintf(description, "%s", ctx->description);
	} else {
		sprintf(description, "%s (", addr_str);
		p = description + strlen(description);
		for (i = 0; i < ctx->nb_devices - 1; i++) {
			sprintf(p, "%s,",  ctx->devices[i]->name);
			p += strlen(p);
		}
		p--;
		*p = ')';
	}

	iio_context_destroy(ctx);

	info->uri = iio_strdup(uri);
	if (!info->uri)
		return -ENOMEM;
	info->description = iio_strdup(description);
	if (!info->description)
		return -ENOMEM;

	return 0;
}

struct iio_scan_backend_context * dnssd_context_scan_init(void)
{
	struct iio_scan_backend_context *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		errno = ENOMEM;
		return NULL;
	}

	return ctx;
}

void dnssd_context_scan_free(struct iio_scan_backend_context *ctx)
{
	free(ctx);
}

int dnssd_context_scan(struct iio_scan_backend_context *ctx,
		struct iio_scan_result *scan_result)
{
	struct iio_context_info **info;
	struct avahi_discovery_data *ddata, *ndata;
	int ret = 0;

	ddata = dnssd_find_hosts(&ret);

	for (ndata = ddata; ndata->next != NULL; ndata = ndata->next) {
		info = iio_scan_result_add(scan_result, 1);
		if (!info)
			ret = -ENOMEM;
		else
			ret = dnssd_fill_context_info(*info,
					ndata->hostname, ndata->addr_str,
					ndata->port);

		if (ret < 0)
			goto cleanup_free_device_list;
	}

cleanup_free_device_list:
	free_all_discovery_data(ddata);

	return ret;
}
