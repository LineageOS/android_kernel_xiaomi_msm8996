AM_CFLAGS = -Wall \
            $(DIAG_CFLAGS)

if DEBUG
AM_CFLAGS += -g
else
AM_CFLAGS += -O2
endif

if USE_GLIB
AM_CFLAGS += -DUSE_GLIB $(GLIB_CFLAGS)
requiredlibs = $(GLIB_LIBS)
endif

AM_CFLAGS += -I $(top_srcdir)/../CORE/SERVICES/COMMON/

cld_fwlog_record_SOURCES = cld-fwlog-record.c

cnss_diag_SOURCES = cld-fwlog-netlink.c parser.c cld-diag-parser.c nan-parser.c
cnss_diag_LDADD = $(DIAG_LIBS)

cld_fwlog_parser_SOURCES = cld-fwlog-parser.c

bin_PROGRAMS = cld_fwlog_record
bin_PROGRAMS += cnss_diag
bin_PROGRAMS += cld_fwlog_parser
