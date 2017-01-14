#CC=$(CXX)
CXXFLAGS = $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --cflags) -pthread -Wall -g -O0 -fsanitize=address
LDLIBS = -lasan $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --libs) -pthread

bin_PROGRAMS = drop_monitor kallsyms_dump libdwfl_test

drop_monitor_SOURCES: drop_monitor.cc netlink_dropmon.cc kallsyms_lookup.cc dwarf_lookup.cc
kallsyms_dump_SOURCES: kallsyms_lookup.cc kallsyms_dump.cc
libdwfl_test_SOURCES: libdwfl_test.cc dwarf_lookup.cc
