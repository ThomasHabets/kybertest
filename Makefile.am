AUTOMAKE_OPTIONS=foreign
DISTCLEANFILES=*~
AM_CPPFLAGS=-I$(builddir)

EXTRA_DIST=\
src/misc.h \
src/gcm.h \
src/kybtestlib.h

bin_PROGRAMS=\
kybertest_encrypt \
kybertest_decrypt \
kybertest_keygen

TESTS=\
gcm_test
check_PROGRAMS=$(TESTS)

gcm_test_SOURCES=\
src/main.cc \
src/gcm.cc \
src/gcm_test.cc \
src/kybtestlib.cc

kybertest_encrypt_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/version_original.cc \
src/version_fotransform.cc \
src/gcm.cc \
src/encrypt.cc

kybertest_decrypt_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/version_original.cc \
src/version_fotransform.cc \
src/gcm.cc \
src/decrypt.cc

kybertest_keygen_SOURCES=\
src/main.cc \
src/kybtestlib.cc \
src/version_original.cc \
src/version_fotransform.cc \
src/gcm.cc \
src/keygen.cc

