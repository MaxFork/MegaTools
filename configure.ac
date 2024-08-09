AC_PREREQ(2.60)
AC_INIT([megatools],[1.11.0-git],[megous@megous.com],[megatools])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([silent-rules foreign subdir-objects -Wno-portability])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

AC_PROG_CC
#AC_PROG_RANLIB
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_HEADER_STDC

AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL

# Define requirements

GLIB_VERSION="2.32.0"
LIBCURL_REQUIRES="libcurl"
OPENSSL_REQUIRES="openssl"

# check for glib/gio
PKG_CHECK_MODULES(GLIB, [gio-2.0 >= $GLIB_VERSION])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

# check openssl
PKG_CHECK_MODULES(OPENSSL, [$OPENSSL_REQUIRES])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# check libcurl
PKG_CHECK_MODULES(LIBCURL, [$LIBCURL_REQUIRES])
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(LIBCURL_LIBS)

# enable compatibility symlinks
AC_ARG_ENABLE([compat-symlinks], AC_HELP_STRING([--enable-compat-symlinks], [Install symlinks for compatibility with old megatools commands (megals, megacopy, megadl, ...).]))
AM_CONDITIONAL([INSTALL_COMPAT_SYMLINKS], [test "x$enable_compat_symlinks" = "xyes"])

# enable dev compiler warnings
AC_ARG_ENABLE([warnings], AC_HELP_STRING([--enable-warnings], [Build with compiler warnings enabled.]))
AS_IF([test "x$enable_warnings" = "xyes"], [
  CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-local-typedefs -Wno-sign-compare -Wno-pointer-sign -Wno-missing-field-initializers"

  AS_IF([$CC --version | head -n1 | grep '(GCC) 4\.8' &>/dev/null], [CFLAGS="$CFLAGS -Wno-unused-local-typedefs"])
], [
  CFLAGS="$CFLAGS -Wno-pointer-sign -Wno-unused-variable"
  enable_warnings=no
])

AC_CONFIG_FILES([
  Makefile
])

AC_OUTPUT

cat << EOF

Configured features:

  warnings: $enable_warnings

Run make now.

NOTE: On FreeBSD, you need to use GNU make (gmake)

EOF
