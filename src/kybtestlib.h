// -*- c++ -*-
#include "misc.h"

#include <sys/random.h>
#include <array>
#include <cinttypes>
#include <string>
#include <vector>

using pubkey_t = std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>;
using secret_key_t = std::array<uint8_t, CRYPTO_SECRETKEYBYTES>;
using encrypted_skey_t = std::array<uint8_t, CRYPTO_CIPHERTEXTBYTES>;
using plain_skey_t = std::array<uint8_t, CRYPTO_BYTES>;

class AutoCloser
{
public:
    AutoCloser(int& fd);
    ~AutoCloser();

private:
    int& fd_;
};

void do_mlockall(bool must);
void full_read(const int fd, void* buf, const size_t count);
void full_write(const int fd, const void* buf, const size_t count);
std::string encrypt_openssl(const std::string& data);
std::string decrypt_openssl(const std::string& data);
void run_openssl(const std::vector<std::string>& args,
                 const plain_skey_t& pass);
extern "C" void randombytes(uint8_t* out, size_t outlen);
