AC_PREREQ([2.69])
AC_INIT([Krossock], [0.1.0], [bugs@kara-online.net], [krossock], [https://github.com/Kara1147/krossock])

m4_include([ax_valgrind_check.m4])

AC_ARG_ENABLE(debug,
  [AS_HELP_STRING([--enable-debug], [Enable debug messages (default is no)])],
  [enable_debug=$enableval],
  [enable_debug=no]
)

if test "x$enable_debug" = "xyes"; then
	AC_DEFINE([DEBUG], [], [enable debug messages])
	AC_MSG_NOTICE([debug messages will be enabled])
fi

#host switch
AC_CANONICAL_HOST

AS_CASE(["$host_os"],
  [*linux*], [
   # OS specific stuff here
    AC_CHECK_HEADERS([termios.h])
    AC_CHECK_HEADERS([unistd.h])
  ],
#  [*mingw*|*cygwin*], [ # not supporting win32 right now, sorry!
#   # OS specific stuff here
#    AC_DEFINE([WINVER], [_WIN32_WINNT_WIN10],
#      [Define windows version as WIN10])
#    AC_DEFINE([_WIN32_WINNT], [_WIN32_WINNT_WIN10],
#      [Define windows version as WIN10])
#  ],
  [AC_MSG_WARN([unsupported system: $host_os])]
)

#autoconf stuff
AM_INIT_AUTOMAKE([subdir-objects])
WARN_CFLAGS="-W -Wall -Wunused -Werror"
AC_SUBST(WARN_CFLAGS)
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AX_VALGRIND_DFLT([memcheck], [on])
AX_VALGRIND_CHECK

#program config
AC_PROG_CC
AC_C_RESTRICT
AC_PROG_RANLIB
AC_PROG_CXX
AM_PROG_AR

#headers
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([ctype.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([termios.h])
AC_CHECK_HEADERS([unistd.h])
#include <openssl/ssl.h>
AC_CHECK_HEADERS([openssl/ssl.h], [], [
  AC_MSG_ERROR([openssl/ssl.h required but not found.])
], [])
#include <openssl/err.h>
AC_CHECK_HEADERS([openssl/err.h], [], [
  AC_MSG_ERROR([openssl/err.h required but not found.])
], [])
#include <openssl/bio.h>
AC_CHECK_HEADERS([openssl/bio.h], [], [
  AC_MSG_ERROR([openssl/bio.h required but not found.])
], [])

#types
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

#functions
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtoul])

#makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  tests/Makefile
])
AC_OUTPUT
