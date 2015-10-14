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

#include "common.h"
#include "resolver.h"
#include "ostypes.h"

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

int resolver_srv_lookup_buf(const unsigned char *buf, size_t len,
                            char *target, size_t target_len,
                            unsigned short *port)
{
    int set = 0;
    unsigned i;
    unsigned j;
    unsigned name_len;
    unsigned rdlength;
    uint16_t type;
    uint16_t class;
    uint16_t priority;
    uint16_t priority_min;
    struct message_header header;

    if (len < MESSAGE_HEADER_LEN)
        return 0;

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
        return 0;
    }
    j = MESSAGE_HEADER_LEN;

    /* skip question section */
    for (i = 0; i < header.qdcount; ++i) {
        name_len = message_name_len(buf, len, j);
        if (name_len == 0) {
            /* error in name format */
            return 0;
        }
        j += name_len + 4;
    }

    /*
     * RFC2052: A client MUST attempt to contact the target host
     * with the lowest-numbered priority it can reach.
     */
    for (i = 0; i < header.ancount; ++i) {
        name_len = message_name_len(buf, len, j);
        j += name_len;
        type = xmpp_ntohs_ptr(&buf[j]);
        class = xmpp_ntohs_ptr(&buf[j + 2]);
        rdlength = xmpp_ntohs_ptr(&buf[j + 8]);
        j += 10;
        if (type == MESSAGE_T_SRV && class == MESSAGE_C_IN) {
            priority = xmpp_ntohs_ptr(&buf[j]);
            if (!set || priority < priority_min) {
                *port = xmpp_ntohs_ptr(&buf[j + 4]);
                name_len = message_name_get(buf, len, j + 6, target, target_len);
                set = name_len > 0 ? 1 : 0;
                priority_min = priority;
            }
        }
        j += rdlength;
    }

    return set;
}

int resolver_srv_lookup(const char *service, const char *proto,
                        const char *domain, char *target,
                        size_t target_len, unsigned short *port)
{
    char fulldomain[2048];
    unsigned char buf[65535];
    int len;
    int set = 0;

    xmpp_snprintf(fulldomain, sizeof(fulldomain),
                  "_%s._%s.%s", service, proto, domain);

    len = res_query(fulldomain, MESSAGE_C_IN, MESSAGE_T_SRV, buf, sizeof(buf));

    if (len > 0)
        set = resolver_srv_lookup_buf(buf, (size_t)len, target, target_len, port);

    return set;
}

/* FIXME: interface that returns array of results, maybe sorted by priority */
