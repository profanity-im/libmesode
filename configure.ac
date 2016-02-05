AC_INIT([libmesode], [0.9.0], [boothj5web@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT([dlopen])

AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

AC_CANONICAL_HOST
AS_CASE([$host_os],
  [freebsd*],    [PLATFORM="bsd"],
  [openbsd*],    [PLATFORM="bsd"],
  [netbsd*],     [PLATFORM="bsd"],
  [*nto*|*qnx*], [PLATFORM="qnx"],
  [*solaris*],   [PLATFORM="solaris"],
                 [PLATFORM="nix"])

PKG_CHECK_MODULES([openssl], [openssl], [PC_REQUIRES="openssl ${PC_REQUIRES}"],
            [AC_CHECK_HEADER([openssl/ssl.h],
                             [
                              openssl_LIBS="-lssl -lcrypto"
                              PC_LIBS="${openssl_LIBS} ${PC_LIBS}"
                             ],
                             [AC_MSG_ERROR([openssl not found; openssl required])]
                            )])

PKG_CHECK_MODULES([check], [check >= 0.9.4], [], [AC_MSG_WARN([libcheck not found; unit tests will not be compilable])])

PKG_CHECK_MODULES([expat], [expat >= 2.0.0],
                  [PC_REQUIRES+=(expat)],
                  [AC_CHECK_HEADER([expat.h],
                                   [
                                    expat_LIBS="-lexpat"
                                    PC_LIBS+=($expat_LIBS)
                                   ],
                                   [AC_MSG_ERROR([expat not found; expat required.])]
                                  )
                  ])
with_parser=expat
PARSER_NAME=expat
PARSER_CFLAGS=$expat_CFLAGS
PARSER_LIBS=$expat_LIBS

AC_SEARCH_LIBS([socket], [socket])

DIST_LIBS=""
AS_CASE([$PLATFORM],
  [bsd],     [DIST_LIBS="${DIST_LIBS}"],
  [qnx],     [DIST_LIBS="-lsocket ${DIST_LIBS}"],
  [solaris], [DIST_LIBS="-lresolv -lsocket -lnsl ${DIST_LIBS}"],
             [DIST_LIBS="-lresolv ${DIST_LIBS}"])

LIBS_TMP="${LIBS}"
LIBS="${DIST_LIBS}"
AC_LINK_IFELSE([AC_LANG_SOURCE([
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/nameser.h>
    #include <resolv.h>
    #include <netdb.h>

    int main() {
        (void)res_query(NULL, 0, 0, NULL, 0);
        return 0;
    }
  ])],
  [],
  [AC_MSG_ERROR([res_query() not found with LIBS="${LIBS}"])])
LIBS="${LIBS_TMP}"
PC_LIBS="${DIST_LIBS} ${PC_LIBS}"

AC_CHECK_HEADERS([arpa/nameser_compat.h])


m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
        [AC_ARG_WITH([pkgconfigdir],
                [AS_HELP_STRING([--with-pkgconfigdir],
                        [install directory for libmesode.pc pkg-config file])],
                [],[with_pkgconfigdir='$(libdir)/pkgconfig'])
        AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

AC_SUBST([PC_REQUIRES], [${PC_REQUIRES}])
AC_SUBST([PC_CFLAGS], [${PC_CFLAGS}])
AC_SUBST([PC_LIBS], [${PC_LIBS}])

AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_SUBST(DIST_LIBS)
AC_CONFIG_FILES([Makefile libmesode.pc])
AC_OUTPUT
