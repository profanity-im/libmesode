/* resolver.h
 * strophe XMPP client library -- DNS resolver
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  DNS resolver.
 */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>             /* res_query */
#include <string.h>             /* strncpy */

#include "ostypes.h"
#include "snprintf.h"
#include "resolver.h"

#define MESSAGE_HEADER_LEN 12
#define MESSAGE_RESPONSE 1
#define MESSAGE_T_SRV 33
#define MESSAGE_C_IN 1

struct message_header {
    uint16_t id;
    uint8_t octet2;
    uint8_t octet3;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* the same as ntohs(), but receives pointer to the value */
static uint16_t xmpp_ntohs_ptr(const void *ptr)
{
    const uint8_t *p = (const uint8_t *)ptr;

    return (uint16_t)((p[0] << 8U) + p[1]);
}

static uint8_t message_header_qr(const struct message_header *header)
{
    return (header->octet2 >> 7) & 1;
}

static uint8_t message_header_rcode(const struct message_header *header)
{
    return header->octet3 & 0x0f;
}

static unsigned message_name_get(const unsigned char *buf, size_t buf_len,
                                 unsigned buf_offset,
                                 char *name, size_t name_max)
{
    size_t name_len = 0;
    unsigned i = buf_offset;
    unsigned pointer;
    unsigned char label_len;

    while ((label_len = buf[i++]) != 0) {
        /* label */
        if ((label_len & 0xc0) == 0) {
            if (name != NULL) {
                if (name_len != 0)
                    name[name_len++] = '.';
                strncpy(&name[name_len], (char *)&buf[i], label_len);
            }
            i += label_len;
            name_len += label_len;

        /* pointer */
        } else if ((label_len & 0xc0) == 0xc0) {
            pointer = (label_len & 0x3f) << 8 | buf[i++];
            (void)message_name_get(buf, buf_len, pointer, &name[name_len],
                                   name_max - name_len);
            /* pointer is always the last */
            break;

        /* The 10 and 01 combinations are reserved for future use. */
        } else {
            return 0;
        }
    }
    if (label_len == 0 && name != NULL)
        name[name_len] = '\0';

    return i - buf_offset;
}

static unsigned message_name_len(const unsigned char *buf, size_t buf_len,
                                 unsigned buf_offset)
{
    return message_name_get(buf, buf_len, buf_offset, NULL, SIZE_MAX);
}

static void resolver_srv_list_sort(resolver_srv_rr_t **srv_rr_list)
{
    resolver_srv_rr_t * rr_head;
    resolver_srv_rr_t * rr_current;
    resolver_srv_rr_t * rr_next;
    resolver_srv_rr_t * rr_prev;
    int swap;

    rr_head = *srv_rr_list;

    if ((rr_head == NULL) || (rr_head->next == NULL)) {
        /* Empty or single record list */
        return;
    }

    do {
        rr_prev = NULL;
        rr_current = rr_head;
        rr_next = rr_head->next;
        swap = 0;
        while (rr_next != NULL) {
            /*
             * RFC2052: A client MUST attempt to contact the target host
             * with the lowest-numbered priority it can reach.
             * RFC2052: When selecting a target host among the
             * those that have the same priority, the chance of trying
             * this one first SHOULD be proportional to its weight.
             */
            if ((rr_current->priority > rr_next->priority) ||
                (rr_current->priority == rr_next->priority &&
                 rr_current->weight < rr_next->weight))
            {
                /* Swap node */
                swap = 1;
                if (rr_prev != NULL) {
                    rr_prev->next = rr_next;
                } else {
                    /* Swap head node */
                    rr_head = rr_next;
                }
                rr_current->next = rr_next->next;
                rr_next->next = rr_current;

                rr_prev = rr_next;
                rr_next = rr_current->next;
            } else {
                /* Next node */
                rr_prev = rr_current;
                rr_current = rr_next;
                rr_next = rr_next->next;
            }
        }
    } while (swap != 0);

    *srv_rr_list = rr_head;
}

int resolver_srv_lookup_buf(xmpp_ctx_t *ctx, const unsigned char *buf,
                            size_t len, resolver_srv_rr_t **srv_rr_list)
{
    unsigned i;
    unsigned j;
    unsigned name_len;
    unsigned rdlength;
    uint16_t type;
    uint16_t class;
    struct message_header header;
    resolver_srv_rr_t *rr;

    *srv_rr_list = NULL;

    if (len < MESSAGE_HEADER_LEN)
        return XMPP_DOMAIN_NOT_FOUND;

    header.id = xmpp_ntohs_ptr(&buf[0]);
    header.octet2 = buf[2];
    header.octet3 = buf[3];
    header.qdcount = xmpp_ntohs_ptr(&buf[4]);
    header.ancount = xmpp_ntohs_ptr(&buf[6]);
    header.nscount = xmpp_ntohs_ptr(&buf[8]);
    header.arcount = xmpp_ntohs_ptr(&buf[10]);
    if (message_header_qr(&header) != MESSAGE_RESPONSE ||
        message_header_rcode(&header) != 0)
    {
        return XMPP_DOMAIN_NOT_FOUND;
    }
    j = MESSAGE_HEADER_LEN;

    /* skip question section */
    for (i = 0; i < header.qdcount; ++i) {
        name_len = message_name_len(buf, len, j);
        if (name_len == 0) {
            /* error in name format */
            return XMPP_DOMAIN_NOT_FOUND;
        }
        j += name_len + 4;
    }

    for (i = 0; i < header.ancount; ++i) {
        name_len = message_name_len(buf, len, j);
        j += name_len;
        type = xmpp_ntohs_ptr(&buf[j]);
        class = xmpp_ntohs_ptr(&buf[j + 2]);
        rdlength = xmpp_ntohs_ptr(&buf[j + 8]);
        j += 10;
        if (type == MESSAGE_T_SRV && class == MESSAGE_C_IN) {
            rr = xmpp_alloc(ctx, sizeof(*rr));
            rr->next = *srv_rr_list;
            rr->priority = xmpp_ntohs_ptr(&buf[j]);
            rr->weight = xmpp_ntohs_ptr(&buf[j + 2]);
            rr->port = xmpp_ntohs_ptr(&buf[j + 4]);
            name_len = message_name_get(buf, len, j + 6, rr->target,
                                        sizeof(rr->target));
            if (name_len > 0)
                *srv_rr_list = rr;
            else
                xmpp_free(ctx, rr); /* skip broken record */
        }
        j += rdlength;
    }
    resolver_srv_list_sort(srv_rr_list);

    return *srv_rr_list != NULL ? XMPP_DOMAIN_FOUND : XMPP_DOMAIN_NOT_FOUND;
}

int resolver_srv_lookup(xmpp_ctx_t *ctx, const char *service, const char *proto,
                        const char *domain, resolver_srv_rr_t **srv_rr_list)
{
    char fulldomain[2048];
    unsigned char buf[65535];
    int len;
    int set = XMPP_DOMAIN_NOT_FOUND;

    xmpp_snprintf(fulldomain, sizeof(fulldomain),
                  "_%s._%s.%s", service, proto, domain);

    *srv_rr_list = NULL;

    len = res_query(fulldomain, MESSAGE_C_IN, MESSAGE_T_SRV, buf, sizeof(buf));

    if (len > 0)
        set = resolver_srv_lookup_buf(ctx, buf, (size_t)len, srv_rr_list);

    return set;
}

void resolver_srv_free(xmpp_ctx_t *ctx, resolver_srv_rr_t *srv_rr_list)
{
    resolver_srv_rr_t *rr;

    while (srv_rr_list != NULL) {
        rr = srv_rr_list->next;
        xmpp_free(ctx, srv_rr_list);
        srv_rr_list = rr;
    }
}

