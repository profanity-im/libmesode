AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -g -Wall

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

SSL_CFLAGS = @openssl_CFLAGS@
SSL_LIBS = @openssl_LIBS@

MESODE_FLAGS = -I$(top_srcdir)
MESODE_LIBS = libmesode.la

## Main build targets
lib_LTLIBRARIES = libmesode.la

libmesode_la_CFLAGS = $(SSL_CFLAGS) $(MESODE_FLAGS) $(PARSER_CFLAGS)
libmesode_la_LDFLAGS = $(SSL_LIBS) $(PARSER_LIBS)
# Export only public API
libmesode_la_LDFLAGS += -export-symbols-regex '^xmpp_'
libmesode_la_SOURCES = src/auth.c src/conn.c src/ctx.c \
	src/event.c src/handler.c src/hash.c \
	src/jid.c src/md5.c src/sasl.c src/scram.c src/sha1.c \
	src/snprintf.c src/sock.c src/stanza.c src/thread.c \
	src/tls_openssl.c src/util.c src/rand.c \
	src/common.h src/hash.h src/md5.h src/ostypes.h src/parser.h \
	src/sasl.h src/scram.h src/sha1.h src/sock.h src/thread.h src/tls.h \
	src/util.h src/rand.h

libmesode_la_SOURCES += src/parser_expat.c

include_HEADERS = mesode.h

pkgconfig_DATA = libmesode.pc

EXTRA_DIST = docs

## Examples
noinst_PROGRAMS = examples/active examples/roster examples/basic examples/bot examples/component
examples_active_SOURCES = examples/active.c
examples_active_CFLAGS = $(MESODE_FLAGS)
examples_active_LDADD = $(MESODE_LIBS) 
examples_roster_SOURCES = examples/roster.c
examples_roster_CFLAGS = $(MESODE_FLAGS)
examples_roster_LDADD = $(MESODE_LIBS) 
examples_basic_SOURCES = examples/basic.c
examples_basic_CFLAGS = $(MESODE_FLAGS)
examples_basic_LDADD = $(MESODE_LIBS) 
examples_bot_SOURCES = examples/bot.c
examples_bot_CFLAGS = $(MESODE_FLAGS)
examples_bot_LDADD = $(MESODE_LIBS)
examples_component_SOURCES = examples/component.c
examples_component_CFLAGS = $(MESODE_FLAGS)
examples_component_LDADD = $(MESODE_LIBS)


## Tests
TESTS = tests/check_parser tests/test_rand tests/test_scram
check_PROGRAMS = tests/check_parser tests/test_rand tests/test_scram

tests_check_parser_SOURCES = tests/check_parser.c tests/test.h
tests_check_parser_CFLAGS = @check_CFLAGS@ $(PARSER_CFLAGS) $(MESODE_FLAGS) \
	-I$(top_srcdir)/src
tests_check_parser_LDADD = @check_LIBS@ $(MESODE_LIBS)
tests_check_parser_LDFLAGS = -static

tests_test_rand_SOURCES = tests/test_rand.c src/sha1.c
tests_test_rand_CFLAGS = $(MESODE_FLAGS) -I$(top_srcdir)/src

tests_test_scram_SOURCES = tests/test_scram.c src/sha1.c
tests_test_scram_CFLAGS = $(MESODE_FLAGS) -I$(top_srcdir)/src
