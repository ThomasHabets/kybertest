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
src/gcm.cc \
src/gcm_test.cc \
src/kybtestlib.cc

kybertest_encrypt_SOURCES=\
src/kybtestlib.cc \
src/gcm.cc \
src/encrypt.cc

kybertest_decrypt_SOURCES=\
src/kybtestlib.cc \
src/gcm.cc \
src/decrypt.cc

kybertest_keygen_SOURCES=\
src/kybtestlib.cc \
src/keygen.cc

