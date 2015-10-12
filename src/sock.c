/* sock.c
** strophe XMPP client library -- socket abstraction implementation
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Socket abstraction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>

#include "sock.h"

int sock_error(void)
{
    return errno;
}

static int _in_progress(int error)
{
    return (errno == EINPROGRESS);
}

sock_t sock_connect(const char * const host, const unsigned int port)
{
    sock_t sock;
    char service[6];
    struct addrinfo *res, *ainfo, hints;
    int err;

    snprintf(service, 6, "%u", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(host, service, &hints, &res);
    if (err != 0)
        return -1;

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        sock = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
        if (sock < 0)
            continue;

        err = sock_set_nonblocking(sock);
        if (err == 0) {
            err = connect(sock, ainfo->ai_addr, ainfo->ai_addrlen);
            if (err == 0 || _in_progress(sock_error()))
                break;
        }

        close(sock);
    }
    freeaddrinfo(res);
    sock = ainfo == NULL ? -1 : sock;

    return sock;
}

int sock_close(const sock_t sock)
{
    return close(sock);
}

int sock_set_blocking(const sock_t sock)
{
    int rc;

    rc = fcntl(sock, F_GETFL, NULL);
    if (rc >= 0) {
        rc = fcntl(sock, F_SETFL, rc & (~O_NONBLOCK));
    }
    return rc;
}

int sock_set_nonblocking(const sock_t sock)
{
    int rc;

    rc = fcntl(sock, F_GETFL, NULL);
    if (rc >= 0) {
        rc = fcntl(sock, F_SETFL, rc | O_NONBLOCK);
    }
    return rc;
}

int sock_read(const sock_t sock, void * const buff, const size_t len)
{
    return recv(sock, buff, len, 0);
}

int sock_write(const sock_t sock, const void * const buff, const size_t len)
{
    return send(sock, buff, len, 0);
}

int sock_is_recoverable(const int error)
{
    return (error == EAGAIN || error == EINTR);
}

int sock_connect_error(const sock_t sock)
{
    struct sockaddr sa;
    socklen_t len;
    char temp;

    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_UNSPEC;
    len = sizeof(sa);

    /* we don't actually care about the peer name, we're just checking if
     * we're connected or not */
    if (getpeername(sock, &sa, &len) == 0)
    {
        return 0;
    }

    /* it's possible that the error wasn't ENOTCONN, so if it wasn't,
     * return that */
    if (sock_error() != ENOTCONN) return sock_error();

    /* load the correct error into errno through error slippage */
    recv(sock, &temp, 1, 0);

    return sock_error();
}

struct dnsquery_header
{
	unsigned short id;
	unsigned char qr;
	unsigned char opcode;
	unsigned char aa;
	unsigned char tc;
	unsigned char rd;
	unsigned char ra;
	unsigned char z;
	unsigned char rcode;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
};

struct dnsquery_question
{
	char qname[1024];
	unsigned short qtype;
	unsigned short qclass;
};

struct dnsquery_srvrdata
{
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	char target[1024];
};

struct dnsquery_resourcerecord
{
	char name[1024];
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short rdlength;
	struct dnsquery_srvrdata rdata;
};


void netbuf_add_32bitnum(unsigned char *buf, int buflen, int *offset, unsigned int num)
{
	unsigned char *start = buf + *offset;
	unsigned char *p = start;

	/* assuming big endian */
	*p++ = (num >> 24) & 0xff;
	*p++ = (num >> 16) & 0xff;
	*p++ = (num >> 8)  & 0xff;
	*p++ = (num)       & 0xff;

	*offset += 4;
}

void netbuf_get_32bitnum(unsigned char *buf, int buflen, int *offset, unsigned int *num)
{
	unsigned char *start = buf + *offset;
	unsigned char *p = start;
	*num = 0;

	/* assuming big endian */
	*num |= (*p++) << 24;
	*num |= (*p++) << 16;
	*num |= (*p++) << 8;
	*num |= (*p++);

	*offset += 4;
}

void netbuf_add_16bitnum(unsigned char *buf, int buflen, int *offset, unsigned short num)
{
	unsigned char *start = buf + *offset;
	unsigned char *p = start;

	/* assuming big endian */
	*p++ = (num >> 8) & 0xff;
	*p++ = (num)      & 0xff;

	*offset += 2;
}

void netbuf_get_16bitnum(unsigned char *buf, int buflen, int *offset, unsigned short *num)
{
	unsigned char *start = buf + *offset;
	unsigned char *p = start;
	*num = 0;

	/* assuming big endian */
	*num |= (*p++) << 8;
	*num |= (*p++);

	*offset += 2;
}

void netbuf_add_domain_name(unsigned char *buf, int buflen, int *offset,
			    char *name)
{
	unsigned char *start = buf + *offset;
	unsigned char *p = start;
	unsigned char *wordstart, *wordend;

	wordstart = (unsigned char *)name;

	while (*wordstart)
	{
		int len;
		wordend = wordstart;
		while (*wordend && *wordend != '.')
		{
			wordend++;
		}

		len = (int)(wordend - wordstart);

		if (len > 0x3F)
		{
			len = 0x3F;
		}

		*p++ = len;

		while (wordstart != wordend)
		{
			*p++ = *wordstart++;
		}

		if (*wordstart == '.')
		{
			wordstart++;
		}
	}

	*p++ = '\0';

	*offset += p - start;
}

int calc_domain_name_size(unsigned char *buf, int buflen, int offset)
{
	unsigned char *p = buf + offset;
	int len = 0;

	while (*p)
	{
		if ((*p & 0xC0) == 0xC0)
		{
			int newoffset = 0;
			newoffset |= (*p++ & 0x3F) << 8;
			newoffset |= *p;

			p = buf + newoffset;
		}
		else
		{
			if (len)
			{
				len += 1;
			}
			len += *p;
			p += *p + 1;
		}
	}

	return len;
}

int netbuf_get_domain_name(unsigned char *buf, int buflen, int *offset, char *namebuf, int namebuflen)
{
	unsigned char *start = buf + *offset;
	unsigned char *p, *p2;
	int *curroffset = offset;
	int len = 0;

	*namebuf = '\0';

	/* measure length */
	p = start;
	while (*p)
	{
		if ((*p & 0xC0) == 0xC0)
		{
			int newoffset = 0;
			newoffset |= (*p++ & 0x3F) << 8;
			newoffset |= *p++;

			p = buf + newoffset;
		}
		else
		{
			len += *p;
			p += *p + 1;
		}
	}

	if (namebuflen < len)
	{
		return len;
	}

	/* actually copy in name */
	p = start;
	p2 = (unsigned char *)namebuf;
	while (*p)
	{
		if ((*p & 0xC0) == 0xC0)
		{
			int newoffset = 0;
			newoffset |= (*p++ & 0x3F) << 8;
			newoffset |= *p++;

			if (curroffset)
			{
				*curroffset += (int)(p - start);
				curroffset = NULL;
			}

			p = buf + newoffset;
		}
		else
		{
			int i, partlen;

			if (*namebuf != '\0')
			{
				*p2++ = '.';
			}

			partlen = *p++;

			for (i=0; i < partlen; i++)
			{
                                *p2++ = *p++;
			}
		}
	}

	if (curroffset)
	{
		p++;
		*curroffset += (int)(p - start);
		curroffset = NULL;
	}

	*p2 = '\0';

	return 0;
}

void netbuf_add_dnsquery_header(unsigned char *buf, int buflen, int *offset, struct dnsquery_header *header)
{
	unsigned char *p;

	netbuf_add_16bitnum(buf, buflen, offset, header->id);

	p = buf + *offset;
	*p++ =    ((header->qr     & 0x01) << 7)
		| ((header->opcode & 0x0F) << 3)
		| ((header->aa     & 0x01) << 2)
		| ((header->tc     & 0x01) << 1)
		| ((header->rd     & 0x01));
	*p++ =    ((header->ra     & 0x01) << 7)
		| ((header->z      & 0x07) << 4)
		| ((header->rcode  & 0x0F));
	*offset += 2;

	netbuf_add_16bitnum(buf, buflen, offset, header->qdcount);
	netbuf_add_16bitnum(buf, buflen, offset, header->ancount);
	netbuf_add_16bitnum(buf, buflen, offset, header->nscount);
	netbuf_add_16bitnum(buf, buflen, offset, header->arcount);
}

void netbuf_get_dnsquery_header(unsigned char *buf, int buflen, int *offset, struct dnsquery_header *header)
{
	unsigned char *p;

	netbuf_get_16bitnum(buf, buflen, offset, &(header->id));

	p = buf + *offset;
	header->qr =     (*p >> 7) & 0x01;
	header->opcode = (*p >> 3) & 0x0F;
	header->aa =     (*p >> 2) & 0x01;
	header->tc =     (*p >> 1) & 0x01;
	header->rd =     (*p)      & 0x01;
	p++;
	header->ra =     (*p >> 7) & 0x01;
	header->z =      (*p >> 4) & 0x07;
	header->rcode =  (*p)      & 0x0F;
	p++;
	*offset += 2;

	netbuf_get_16bitnum(buf, buflen, offset, &(header->qdcount));
	netbuf_get_16bitnum(buf, buflen, offset, &(header->ancount));
	netbuf_get_16bitnum(buf, buflen, offset, &(header->nscount));
	netbuf_get_16bitnum(buf, buflen, offset, &(header->arcount));
}

void netbuf_add_dnsquery_question(unsigned char *buf, int buflen, int *offset, struct dnsquery_question *question)
{
	netbuf_add_domain_name(buf, buflen, offset, question->qname);
	netbuf_add_16bitnum(buf, buflen, offset, question->qtype);
	netbuf_add_16bitnum(buf, buflen, offset, question->qclass);
}

void netbuf_get_dnsquery_question(unsigned char *buf, int buflen, int *offset, struct dnsquery_question *question)
{
	netbuf_get_domain_name(buf, buflen, offset, question->qname, 1024);
	netbuf_get_16bitnum(buf, buflen, offset, &(question->qtype));
	netbuf_get_16bitnum(buf, buflen, offset, &(question->qclass));
}

void netbuf_get_dnsquery_srvrdata(unsigned char *buf, int buflen, int *offset, struct dnsquery_srvrdata *srvrdata)
{
	netbuf_get_16bitnum(buf, buflen, offset, &(srvrdata->priority));
	netbuf_get_16bitnum(buf, buflen, offset, &(srvrdata->weight));
	netbuf_get_16bitnum(buf, buflen, offset, &(srvrdata->port));
	netbuf_get_domain_name(buf, buflen, offset, srvrdata->target, 1024);
}

void netbuf_get_dnsquery_resourcerecord(unsigned char *buf, int buflen, int *offset, struct dnsquery_resourcerecord *rr)
{
	netbuf_get_domain_name(buf, buflen, offset, rr->name, 1024);
	netbuf_get_16bitnum(buf, buflen, offset, &(rr->type));
	netbuf_get_16bitnum(buf, buflen, offset, &(rr->_class));
	netbuf_get_32bitnum(buf, buflen, offset, &(rr->ttl));
	netbuf_get_16bitnum(buf, buflen, offset, &(rr->rdlength));
	if (rr->type == 33) /* SRV */
	{
		int newoffset = *offset;
		netbuf_get_dnsquery_srvrdata(buf, buflen, &newoffset, &(rr->rdata));
	}
	*offset += rr->rdlength;
}


int sock_srv_lookup(const char *service, const char *proto,
                    const char *domain, char *resulttarget,
                    int resulttargetlength, int *resultport)
{
    int set = 0;
    char fulldomain[2048];

    snprintf(fulldomain, sizeof(fulldomain),
             "_%s._%s.%s", service, proto, domain);

    if (!set) {
        unsigned char buf[65535];
	int len;

	if ((len = res_query(fulldomain, C_IN, T_SRV, buf, 65535)) > 0) {
	    int offset;
	    int i;
	    struct dnsquery_header header;
	    struct dnsquery_question question;
	    struct dnsquery_resourcerecord rr;

	    offset = 0;
	    netbuf_get_dnsquery_header(buf, 65536, &offset, &header);

	    for (i = 0; i < header.qdcount; i++) {
		netbuf_get_dnsquery_question(buf, 65536, &offset, &question);
	    }

	    for (i = 0; i < header.ancount; i++) {
		netbuf_get_dnsquery_resourcerecord(buf, 65536, &offset, &rr);

		if (rr.type == 33) {
		    struct dnsquery_srvrdata *srvrdata = &(rr.rdata);

		    snprintf(resulttarget, resulttargetlength, "%s",
			     srvrdata->target);
		    *resultport = srvrdata->port;
		    set = 1;
		}
	    }

	    for (i = 0; i < header.ancount; i++) {
		netbuf_get_dnsquery_resourcerecord(buf, 65536, &offset, &rr);
	    }
	}
    }

    return set;
}
