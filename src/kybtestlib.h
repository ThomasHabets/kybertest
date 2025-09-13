// -*- c++ -*-
#ifndef __INCLUDE_KYBTESTLIB_H__
#define __INCLUDE_KYBTESTLIB_H__

#include "misc.h"

#include <array>
#include <cinttypes>
#include <string>
#include <vector>

using sha256_output_t = std::array<unsigned char, 32>;
using pubkey_t = std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>;
using secret_key_t = std::array<uint8_t, CRYPTO_SECRETKEYBYTES>;
using encrypted_skey_t = std::array<uint8_t, CRYPTO_CIPHERTEXTBYTES>;
using plain_skey_t = std::array<uint8_t, CRYPTO_BYTES>;

namespace file_version_0 {
const std::string magic = "KYBTEST0";
const std::string magic_priv = "KYBSECe0";
const std::string magic_pub = "KYBPUB00";
const std::string magic_priv_unencrypted = "KYBPRIV0";
} // namespace file_version_0

namespace file_version_1_beta {
const std::string magic_priv = "KYbSECe1";
const std::string magic = "KYbTEST1";
constexpr int blocksize = 10000;
} // namespace file_version_1_beta

namespace file_version_1 {
const std::string magic_priv = "KYBSECe1";
const std::string magic = "KYBTEST1";
constexpr int blocksize = 10000;
} // namespace file_version_1

class AutoCloser
{
public:
    AutoCloser(int& fd);
    ~AutoCloser();

private:
    int& fd_;
};

sha256_output_t sha256(const uint8_t* data, size_t len);
sha256_output_t xgetpasskey(const std::string& prompt);
void do_mlockall(bool must);
void full_read(const int fd, void* buf, const size_t count);
void full_write(const int fd, const void* buf, const size_t count);
std::string encrypt_openssl(const std::string_view data);
std::string decrypt_openssl(const std::string_view data);
void run_openssl(const std::vector<std::string>& args,
                 const plain_skey_t& pass);
extern "C" void randombytes(uint8_t* out, size_t outlen);
secret_key_t read_priv_key(const std::string& fn);
#endif
