/*
 * (C) 2006-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2011 by Vyatta Inc. <http://www.vyatta.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "conntrackd.h"
#include "sync.h"
#include "log.h"
#include "cache.h"
#include "external.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <stdlib.h>

static struct cache *external_fast;
static struct cache *external;
static struct cache *external_exp;

static struct alarm_block fast_alarm;
static struct alarm_block slow_alarm;

#define FAST_STEPS 3000
#define SLOW_STEPS 3000

static uint32_t fast_previous, slow_previous;

struct excache_notrack {
	void* owner;
	struct cache_object	*obj;
};

static void excache_notrack_add(struct cache_object *obj, void *data)
{
	struct excache_notrack *cn = data;
	cn->obj = obj;
	cn->owner = STATE_SYNC(channel)->current;
}

#include <stdio.h>
static int fast_iterate(void *data1, void *n)
{
	struct cache_object *obj = n;
	int id;

	if(time_cached() > obj->lastupdate + 180)
	{
		puts("Clearing fast connection\n");
		cache_del(external_fast, obj);
		cache_object_free(obj);
	}
	else if(time_cached() > obj->lifetime + 300)
	{
		puts("Elevating fast connection\n");
		cache_del(external_fast, obj);
		id = hashtable_hash(external->h, obj->ptr);
		cache_add(external, obj, id);
	}
	return 0;
}

static void do_gc_fast(struct alarm_block *a, void *data)
{
	uint32_t steps;
	
	steps = cache_iterate_limit(external_fast, NULL, fast_previous, FAST_STEPS, fast_iterate);
	if(steps != FAST_STEPS){
		fast_previous = 0;
	}
	add_alarm(&fast_alarm, 15, 0);
}

static void do_gc_slow(struct alarm_block *a, void *data)
{
	
	add_alarm(&slow_alarm, 30, 0);
}

static int external_cache_init(void)
{
	external = cache_create("external", CACHE_T_CT,
				STATE_SYNC(sync)->external_cache_flags,
				NULL, &cache_sync_external_ct_ops);
	if (external == NULL) {
		dlog(LOG_ERR, "can't allocate memory for the external cache");
		return -1;
	}
	
	external_fast = cache_create("external_fast", CACHE_T_CT,
				STATE_SYNC(sync)->external_cache_flags,
				NULL, &cache_sync_external_ct_ops);
	if (external == NULL) {
		dlog(LOG_ERR, "can't allocate memory for the external cache");
		return -1;
	}
	
	external_exp = cache_create("external", CACHE_T_EXP,
				STATE_SYNC(sync)->external_cache_flags,
				NULL, &cache_sync_external_exp_ops);
	if (external_exp == NULL) {
		dlog(LOG_ERR, "can't allocate memory for the external cache");
		return -1;
	}
	
	fast_previous = 0;
	slow_previous = 0;
	
	init_alarm(&fast_alarm, NULL, do_gc_fast);
	init_alarm(&slow_alarm, NULL, do_gc_slow);
	
	add_alarm(&fast_alarm, 15, 0);
	add_alarm(&slow_alarm, 30, 0);

	return 0;
}

static void external_cache_close(void)
{
	cache_destroy(external);
	cache_destroy(external_fast);
	cache_destroy(external_exp);
}

static void external_cache_ct_new(struct nf_conntrack *ct)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(external, ct, &id);
	if (obj == NULL) {
retry:
		obj = cache_find(external_fast, ct, &id);
		if (obj == NULL) {
retry2:
			obj = cache_object_new(external_fast, ct);
			if(obj == NULL){
				return;
			}
			if (cache_add(external, obj, id) == -1) {
				cache_object_free(obj);
				return;
			}
		} else {
			cache_del(external_fast, obj);
			cache_object_free(obj);
			goto retry2;
		}
	} else {
		cache_del(external, obj);
		cache_object_free(obj);
		goto retry;
	}
}

static void external_cache_ct_upd(struct nf_conntrack *ct)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(external, ct, &id);
	if (obj == NULL) {
		cache_update_force(external_fast, ct);
	}else{
		cache_update(external, obj, id, ct);
	}
}

static void external_cache_ct_del(struct nf_conntrack *ct)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(external, ct, &id);
	if (obj) {
		cache_del(external, obj);
		cache_object_free(obj);
		return;
	}	
	
	obj = cache_find(external_fast, ct, &id);
	if (obj) {
		cache_del(external, obj);
		cache_object_free(obj);
		return;
	}
}

static void external_cache_ct_dump(int fd, int type)
{
	cache_dump(external, fd, type);
	cache_dump(external_fast, fd, type);
}

static int external_cache_ct_commit(struct nfct_handle *h, int fd)
{
	return (cache_commit(external, h, fd) && cache_commit(external_fast, h, fd));
}

static void external_cache_ct_flush(void)
{
	cache_flush(external);
	cache_flush(external_fast);
}

static void external_cache_ct_stats(int fd)
{
	cache_stats(external, fd);
}

static void external_cache_ct_stats_ext(int fd)
{
	cache_stats_extended(external, fd);
}

static void external_cache_exp_new(struct nf_expect *exp)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(external_exp, exp, &id);
	if (obj == NULL) {
retry:
		obj = cache_object_new(external_exp, exp);
		if (obj == NULL)
			return;

		if (cache_add(external_exp, obj, id) == -1) {
			cache_object_free(obj);
			return;
		}
	} else {
		cache_del(external_exp, obj);
		cache_object_free(obj);
		goto retry;
	}
}

static void external_cache_exp_upd(struct nf_expect *exp)
{
	cache_update_force(external_exp, exp);
}

static void external_cache_exp_del(struct nf_expect *exp)
{
	struct cache_object *obj;
	int id;

	obj = cache_find(external_exp, exp, &id);
	if (obj) {
		cache_del(external_exp, obj);
		cache_object_free(obj);
	}
}

static void external_cache_exp_dump(int fd, int type)
{
	cache_dump(external_exp, fd, type);
}

static int external_cache_exp_commit(struct nfct_handle *h, int fd)
{
	return cache_commit(external_exp, h, fd);
}

static void external_cache_exp_flush(void)
{
	cache_flush(external_exp);
}

static void external_cache_exp_stats(int fd)
{
	cache_stats(external_exp, fd);
}

static void external_cache_exp_stats_ext(int fd)
{
	cache_stats_extended(external_exp, fd);
}

struct external_handler external_fastcache = {
	.init		= external_cache_init,
	.close		= external_cache_close,
	.ct = {
		.new		= external_cache_ct_new,
		.upd		= external_cache_ct_upd,
		.del		= external_cache_ct_del,
		.dump		= external_cache_ct_dump,
		.commit		= external_cache_ct_commit,
		.flush		= external_cache_ct_flush,
		.stats		= external_cache_ct_stats,
		.stats_ext	= external_cache_ct_stats_ext,
	},
	.exp = {
		.new		= external_cache_exp_new,
		.upd		= external_cache_exp_upd,
		.del		= external_cache_exp_del,
		.dump		= external_cache_exp_dump,
		.commit		= external_cache_exp_commit,
		.flush		= external_cache_exp_flush,
		.stats		= external_cache_exp_stats,
		.stats_ext	= external_cache_exp_stats_ext,
	},
};
