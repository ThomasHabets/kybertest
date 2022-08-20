// -*- c++ -*-
#include "kybtestlib.h"

#include <string_view>
#include <array>
#include <functional>
#include <optional>
#include <string>

namespace kybertest_gcm {
using iv_t = std::array<unsigned char, 32>;
using key_t = std::array<unsigned char, 32>;
using tag_t = std::array<unsigned char, 16>;
using v8 = std::vector<unsigned char>;

template <typename T>
T generate_data()
{
    T ret;
    randombytes(ret.data(), ret.size());
    return ret;
}

template <typename T>
std::string_view to_sv(const T& in)
{
    return std::string_view(reinterpret_cast<const char*>(in.data()),
                            in.size());
}

class IV
{
public:
    IV() : iv_(generate_data<iv_t>()) {}
    IV(const iv_t& iv) : iv_(iv) {}

    iv_t& get() { return iv_; }
    const iv_t& get() const { return iv_; }
    void mix(uint64_t counter);

private:
    iv_t iv_;
};

std::tuple<v8, tag_t>
encrypt(const std::string_view plaintext, const key_t& key, const iv_t& iv);
std::optional<v8> decrypt(const std::string_view ciphertext,
                          const key_t& key,
                          const iv_t& iv,
                          const tag_t& tag);

v8 encrypt_block(const key_t& key,
                 const std::string_view plain,
                 const uint64_t counter,
                 IV iv);
std::optional<v8> decrypt_block(const key_t& key,
                                const std::string_view data,
                                const uint64_t counter,
                                IV iv);

ssize_t encrypt_stream(
    const key_t& key,
    const size_t blocksize,
    const std::function<std::pair<std::string, ssize_t>(size_t)>& readcb,
    const std::function<ssize_t(std::string_view)>& writecb);
ssize_t decrypt_stream(
    const key_t& key,
    const size_t plainblocksize,
    const std::function<std::pair<std::string, ssize_t>(size_t)>& readcb,
    const std::function<ssize_t(std::string_view)>& writecb);
} // namespace kybertest_gcm
