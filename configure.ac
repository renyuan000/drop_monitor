#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(drop_monitor, 0.1, wr0112358@gmail.com)
AM_INIT_AUTOMAKE(drop_monitor, 0.1)

AC_CONFIG_SRCDIR([src/dwarf_lookup.cc])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lasan':
AC_CHECK_LIB([asan], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memchr memset strdup strerror strtoul])

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT(Makefile src/Makefile man/Makefile)
