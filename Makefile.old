CC=$(CXX)
CXXFLAGS = $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --cflags) -pthread -Wall -g -O0 -fsanitize=address
LDFLAGS = -lasan $(shell pkg-config libnl-3.0 libnl-genl-3.0 libdw --libs) -pthread

tools = drop_monitor kallsyms_dump libdwfl_test
all: $(tools)
clean:
	rm -f *.o $(tools)

dwarf_lookup.o: dwarf_lookup.cc
netlink_dropmon.o: netlink_dropmon.cc
kallsyms_dump.o: kallsyms_dump.cc
kallsyms_lookup.o: kallsyms_lookup.cc
drop_monitor.o: drop_monitor.cc

drop_monitor: drop_monitor.o netlink_dropmon.o kallsyms_lookup.o dwarf_lookup.o
kallsyms_dump: kallsyms_lookup.o kallsyms_dump.o

libdwfl_test.o: libdwfl_test.cc
libdwfl_test: LDFLAGS += $(shell pkg-config --libs libdw)
libdwfl_test: libdwfl_test.o dwarf_lookup.o
