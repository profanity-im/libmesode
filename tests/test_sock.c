/* test_sock.c
** libstrophe XMPP client library -- test routines for the socket abstraction
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <stdio.h>
#include <string.h>

#include <sys/select.h>

#include "sock.h"

int wait_for_connect(sock_t sock)
{
    fd_set wfds, efds;
    int ret;

    FD_ZERO(&wfds); FD_SET(sock, &wfds);
    FD_ZERO(&efds); FD_SET(sock, &efds);

    ret = select(sock + 1, NULL, &wfds, &efds, NULL);
    if (ret <= 0) return -1;

    if (FD_ISSET(sock, &efds)) return 0;
    if (FD_ISSET(sock, &wfds)) return 1;

    return -1;
}

int main(int argc, char **argv)
{
    sock_t sock;
    int err;

    sock = sock_connect("www.google.com", 80);

    if (sock < 0) {
	return 1;
    }

    err = wait_for_connect(sock);
    if (err < 0) {
	sock_close(sock);
	return 1;
    }

    sock_close(sock);

    return 0;
}
