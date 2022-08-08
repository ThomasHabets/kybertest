#include<fstream>
#include<array>
#include"misc.h"

int main()
{
  std::array<uint8_t,CRYPTO_PUBLICKEYBYTES> pk;
  std::array<uint8_t,CRYPTO_SECRETKEYBYTES> sk;
  crypto_kem_keypair(pk.data(), sk.data());
  std::ofstream("key.pub") << std::string(pk.begin(), pk.end());
  std::ofstream("key.priv") << std::string(sk.begin(), sk.end());
}
