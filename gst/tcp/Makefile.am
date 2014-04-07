plugin_LTLIBRARIES = libgsttcp.la

# variables used for enum/marshal generation
glib_enum_headers = gsttcp.h
glib_enum_define = GST_TCP
glib_gen_prefix = gst_tcp
glib_gen_basename = gsttcp

include $(top_srcdir)/common/gst-glib-gen.mak

built_sources = gsttcp-enumtypes.c gsttcp-marshal.c
built_headers = gsttcp-enumtypes.h gsttcp-marshal.h

BUILT_SOURCES = $(built_sources) $(built_headers)

if HAVE_WINSOCK2_H
multifd_sources =
multifd_headers =
else
multifd_sources = gstmultifdsink.c gsttcpserversink.c
multifd_headers = gstmultifdsink.h gsttcpserversink.h
endif

libgsttcp_la_SOURCES = \
	gsttcpplugin.c \
	gsttcp.c \
  $(multifd_sources)  \
	gsttcpclientsrc.c gsttcpclientsink.c \
  gsttcpserversrc.c

nodist_libgsttcp_la_SOURCES = \
	$(built_sources)

# remove ENABLE_NEW when dataprotocol is stable
libgsttcp_la_CFLAGS = $(GST_PLUGINS_BASE_CFLAGS) $(GST_BASE_CFLAGS) $(GST_CFLAGS)
libgsttcp_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgsttcp_la_LIBADD = $(GST_BASE_LIBS) $(GST_LIBS) $(WIN32_LIBS)
libgsttcp_la_LIBTOOLFLAGS = --tag=disable-static

noinst_HEADERS = \
  gsttcpplugin.h \
  gsttcp.h \
  $(multifd_headers)  \
  gsttcpclientsrc.h gsttcpclientsink.h \
  gsttcpserversrc.h

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = gsttcp-marshal.list

Android.mk: Makefile.am $(BUILT_SOURCES)
	androgenizer \
	-:PROJECT libgsttcp -:SHARED libgsttcp \
	 -:TAGS eng debug \
         -:REL_TOP $(top_srcdir) -:ABS_TOP $(abs_top_srcdir) \
	 -:SOURCES $(libgsttcp_la_SOURCES) \
	 	   $(nodist_libgsttcp_la_SOURCES) \
	 -:CFLAGS $(DEFS) $(DEFAULT_INCLUDES) $(libgsttcp_la_CFLAGS) \
	 -:LDFLAGS $(libgsttcp_la_LDFLAGS) \
	           $(libgsttcp_la_LIBADD) \
	           -ldl \
	 -:PASSTHROUGH LOCAL_ARM_MODE:=arm \
		       LOCAL_MODULE_PATH:='$$(TARGET_OUT)/lib/gstreamer-0.10' \
	> $@
