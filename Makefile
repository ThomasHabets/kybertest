.PHONY: .dummy

all: encrypt decrypt keygen

LIBS=\
-lpqcrystals_kyber768_ref \
-lpqcrystals_kyber1024_ref \
-lpqcrystals_fips202_ref \
-lpqcrystals_aes256ctr_ref \
-lpqcrystals_sha2_ref
LDFLAGS=\
-L$(HOME)/opt/kyber/lib \
-Wl,-rpath,$(HOME)/opt/kyber/lib \
$(LIBS)

encrypt: .dummy
	g++ encrypt.cc rand.cc $(LDFLAGS) -o encrypt
decrypt:.dummy
	g++ decrypt.cc rand.cc $(LDFLAGS) -o decrypt
keygen:.dummy
	g++ keygen.cc rand.cc $(LDFLAGS) -o keygen
