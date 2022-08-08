.PHONY: .dummy

all: encrypt decrypt keygen

LIBS=\
-lpqcrystals_kyber768_ref \
-lpqcrystals_kyber1024_ref \
-lpqcrystals_fips202_ref \
-lpqcrystals_aes256ctr_ref \
-lpqcrystals_sha2_ref

encrypt: .dummy
	g++ encrypt.cc rand.cc -Wl,-rpath,$(HOME)/opt/kyber -L$(HOME)/opt/kyber $(LIBS) -o encrypt
decrypt:.dummy
	g++ decrypt.cc rand.cc -Wl,-rpath,$(HOME)/opt/kyber -L$(HOME)/opt/kyber $(LIBS) -o decrypt
keygen:.dummy
	g++ keygen.cc rand.cc -Wl,-rpath,$(HOME)/opt/kyber -L$(HOME)/opt/kyber $(LIBS) -o keygen


