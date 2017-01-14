#CC=$(CXX)
#CXXFLAGS = $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --cflags) -pthread -Wall -g -O0 -fsanitize=address
#LDLIBS = -lasan $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --libs) -pthread

#SUFFIXES: .cc .hh .cpp
#.o.cc:
#	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o $@ $<

AM_CFLAGS = -Wall -g -O0 -fsanitize=address
#AM_CPPFLAGS = -pthread -Wall -g -O0 -fsanitize=address
#AM_CXXFLAGS = -std=c++14
#AM_LDFLAGS = -lasan -lnl -ldw -pthread

bin_PROGRAMS = drop_monitor kallsyms_dump libdwfl_test

drop_monitor_CXXFLAGS=$(libnl3_CFLAGS) $(libnl_genl3_CFLAGS) $(AM_CXXFLAGS) $(AM_CFLAGS)
drop_monitor_LDFLAGS = $(libnl3_LIBS) $(libnl_genl3_LIBS) -pthread
drop_monitor_SOURCES = drop_monitor.cc netlink_dropmon.cc kallsyms_lookup.cc dwarf_lookup.cc
kallsyms_lookup_LDFLAGS = -pthread
kallsyms_dump_SOURCES = kallsyms_lookup.cc kallsyms_dump.cc
libdwfl_test_SOURCES = libdwfl_test.cc dwarf_lookup.cc

#all:
#	echo $(LIBS)
#	echo $(libnl3_LIBS)
