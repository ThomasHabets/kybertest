# -*- Autoconf -*-
AC_PREREQ([2.71])
AC_INIT([kybertest],[0.1.1],[thomas@habets.se])
AC_CONFIG_SRCDIR([src/encrypt.cc])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
AC_CONFIG_HEADERS([src/config.h])
AC_LANG(C++)

# Check for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

if test ! "x$PQLIBPATH" = "x"; then
   LDFLAGS="-Wl,-rpath,$PQLIBPATH -L$PQLIBPATH $LDFLAGS"
fi

# Check for libraries.
AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new])
AC_CHECK_LIB(
	[pqcrystals_fips202_ref],
	[pqcrystals_kyber_fips202_ref_shake256],,
	[AC_MSG_ERROR([Could not find library: pqcrystals_fips202_ref

You may need to run ./configure with PQLIBPATH=/usr/local/lib or something.
	])]
)

LIBS="-lpqcrystals_kyber1024_ref $LIBS"
AC_LINK_IFELSE(
[AC_LANG_SOURCE(
  extern "C" char pqcrystals_kyber1024_ref_keypair();
  extern "C" void randombytes(char*,int) {}
  int main (void) { return pqcrystals_kyber1024_ref_keypair (); return 0;}
)], , [AC_MSG_ERROR([Could not find library: pqcrystals_kyber1024_ref

Since pqcrystals_fips202_ref was found, this is odd. Is libpqcrystals_kyber1024_ref.so
not in the same place?
])]
)

AC_CHECK_FUNCS([getrandom])


# Check for header files.
AC_CHECK_HEADERS([\
sys/random.h \
])

MYSTD="c++17"
if test ! "x$STD" = "x"; then
   MYSTD="$STD"
fi
CXXFLAGS="$CXXFLAGS -std=$MYSTD -g -Wall -pedantic"

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Status
echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
