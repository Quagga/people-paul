INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

sbin_PROGRAMS = quagga
quagga_SOURCES = quagga.c

quagga_LDADD = ../lib/libzebra.la @LIBCAP@

EXTRA_DIST = mrlg.cgi rrcheck.pl rrlookup.pl zc.pl zebra.el
