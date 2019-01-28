dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.ac
dnl autotools build system for Lua
dnl ------------------------------------------------------------------------

AC_PREREQ(2.60)
AC_INIT([Lua],[5.3.1],[],[lua],[http://www.lua.org])
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_SRCDIR([src/lua.h])
AM_INIT_AUTOMAKE([1.11 foreign no-exeext no-installinfo])

# Tell autoconf to write a header, but note that nothing uses it
AC_CONFIG_HEADERS([autoconf.h])

AM_MAINTAINER_MODE

AC_USE_SYSTEM_EXTENSIONS
AC_LANG(C)
LT_INIT

AC_PROG_MAKE_SET
AC_HEADER_STDC

AC_SEARCH_LIBS([sqrt], [m])
# Add dynamic library library if needed
AC_SEARCH_LIBS([dlopen], [dl])

# Files to create
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])


AC_OUTPUT
