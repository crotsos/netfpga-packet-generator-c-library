bin_PROGRAMS = pkt_gen pkt_cap accurancy_capture accurancy_parse residual_delay

#AM_CPPFLAGS = -g -I$(top_srcdir)/include

pkt_gen_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
pkt_gen_CPPFLAGS = -g  -I$(top_srcdir)/include
pkt_gen_SOURCES = pkt_gen.c

pkt_cap_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
pkt_cap_CPPFLAGS = -g  -I$(top_srcdir)/include
pkt_cap_SOURCES = pkt_cap.c

accurancy_capture_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
accurancy_capture_CPPFLAGS = -g  -I$(top_srcdir)/include
accurancy_capture_SOURCES = accurancy_capture.c

accurancy_parse_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
accurancy_parse_CPPFLAGS = -g  -I$(top_srcdir)/include
accurancy_parse_SOURCES = accurancy_parse.c

residual_delay_LDADD = ../src/libnf_pktgten.la -lm -lpcap -lpthread
residual_delay_CPPFLAGS = -g  -I$(top_srcdir)/include
residual_delay_SOURCES = residual_delay.c