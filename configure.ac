AC_PREREQ([2.69])
AC_INIT([Socket Helper Library w/ SSL], [0.1.0], [bugs@kara-online.net], [krossock], [])

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
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])

#program config
AC_PROG_CC
AC_C_RESTRICT
AC_PROG_RANLIB
AM_PROG_AR

#user and host info
# none

#headers
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

#functions
# none

WARN_CFLAGS="-W -Wall -Wunused -Werror"
AC_SUBST(WARN_CFLAGS)

#makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
