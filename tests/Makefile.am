@VALGRIND_CHECK_RULES@
TESTS = test1

check_PROGRAMS = $(top_builddir)/tests/test1
__top_builddir__tests_test1_SOURCES = test1.c
__top_builddir__tests_test1_CFLAGS = -I$(abs_top_srcdir)/src -ggdb
__top_builddir__tests_test1_LDFLAGS = -L$(abs_top_builddir)/bin
__top_builddir__tests_test1_LDADD = -lkrossock -lssl -lcrypto

# TODO: Make unit tests to make sure this thing is being built properly
