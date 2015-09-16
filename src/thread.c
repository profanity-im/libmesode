/* thread.c
** strophe XMPP client library -- thread abstraction
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Thread absraction.
 */

#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

#include "mesode.h"
#include "common.h"
#include "thread.h"

struct _mutex_t {
    const xmpp_ctx_t *ctx;
    pthread_mutex_t *mutex;
};

/* mutex functions */

mutex_t *mutex_create(const xmpp_ctx_t * ctx)
{
    mutex_t *mutex;

    mutex = xmpp_alloc(ctx, sizeof(mutex_t));
    if (mutex) {
	mutex->ctx = ctx;
	mutex->mutex = xmpp_alloc(ctx, sizeof(pthread_mutex_t));
	if (mutex->mutex)
	    if (pthread_mutex_init(mutex->mutex, NULL) != 0) {
		xmpp_free(ctx, mutex->mutex);
		mutex->mutex = NULL;
	    }
	if (!mutex->mutex) {
	    xmpp_free(ctx, mutex);
	    mutex = NULL;
	}
    }

    return mutex;
}

int mutex_destroy(mutex_t *mutex)
{
    int ret = 1;
    const xmpp_ctx_t *ctx;

    if (mutex->mutex)
	ret = pthread_mutex_destroy(mutex->mutex) == 0;
    ctx = mutex->ctx;
    xmpp_free(ctx, mutex);

    return ret;
}

int mutex_lock(mutex_t *mutex)
{
    int ret = pthread_mutex_lock(mutex->mutex) == 0;
    return ret;
}

int mutex_trylock(mutex_t *mutex)
{
    /* TODO */
    return 0;
}

int mutex_unlock(mutex_t *mutex)
{
    int ret = pthread_mutex_unlock(mutex->mutex) == 0;
    return ret;
}
