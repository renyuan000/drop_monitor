AM_CFLAGS = -Wall -Werror # -fsanitize=address
bin_PROGRAMS = drop_monitor kallsyms_dump libdwfl_test

drop_monitor_CXXFLAGS=$(libnl3_CFLAGS) $(libnl_genl3_CFLAGS) $(AM_CXXFLAGS) $(AM_CFLAGS)
drop_monitor_LDFLAGS = $(libnl3_LIBS) $(libnl_genl3_LIBS) -pthread
drop_monitor_SOURCES = drop_monitor.cc netlink_dropmon.cc kallsyms_lookup.cc dwarf_lookup.cc
kallsyms_lookup_LDFLAGS = -pthread
kallsyms_dump_SOURCES = kallsyms_lookup.cc kallsyms_dump.cc
libdwfl_test_SOURCES = libdwfl_test.cc dwarf_lookup.cc
