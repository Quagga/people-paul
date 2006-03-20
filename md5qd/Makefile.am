## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib @SNMP_INCLUDES@
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

sbin_PROGRAMS = md5qd

md5qd_SOURCES = md5qd.c
md5qd_LDADD = ../lib/libzebra.la -lipq @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = md5qd.conf.sample

EXTRA_DIST = README.md5qd.txt
