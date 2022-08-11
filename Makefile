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

CXXFLAGS=-Wall -pedantic -g

encrypt: .dummy
	g++ $(CXXFLAGS) encrypt.cc kybtestlib.cc $(LDFLAGS) -o encrypt
decrypt:.dummy
	g++ $(CXXFLAGS) decrypt.cc kybtestlib.cc $(LDFLAGS) -o decrypt
keygen:.dummy
	g++ $(CXXFLAGS) keygen.cc kybtestlib.cc $(LDFLAGS) -o keygen
