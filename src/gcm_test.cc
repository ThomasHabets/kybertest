#include "gcm.h"

#include <iostream>
#include <stdexcept>

namespace kybertest_gcm {

void test_raw()
{
    const std::string plaintext =
        "hello world hello world hello world hello world hello world";
    const auto key = generate_data<key_t>();

    std::cout << "Plain: " << plaintext.size() << "\n";

    // Try one block.
    IV iv;
    auto [enc, tag] = encrypt(plaintext, key, iv.get());
    std::cout << "Encrypted (" << enc.size() << ")\n";

    auto dec = decrypt(to_sv(enc), key, iv.get(), tag).value();
    std::cout << "Output (" << dec.size() << "): " << to_sv(dec) << "\n";

    enc[3] = 0;
    if (decrypt(to_sv(enc), key, iv.get(), tag).has_value()) {
        throw std::runtime_error("bad input should fail()");
    }
}

void test_stream()
{
    const std::string plaintext =
        "hello world hello world hello world hello world hello world";
    key_t key;

    for (const auto block_size : { 1, 2, 1024 }) {

        // Stream encrypt.
        std::string encrypted;
        std::string_view plainstream = plaintext;
        const auto err = encrypt_stream(
            key,
            block_size,
            [&plainstream](size_t size) -> std::pair<std::string, ssize_t> {
                size = std::min(size, plainstream.size());
                auto ret =
                    std::string(std::string_view(plainstream.data(), size));
                plainstream = std::string_view(plainstream.data() + size,
                                               plainstream.size() - size);
                return std::make_pair(ret, (int)ret.size());
            },
            [&encrypted](std::string_view sv) -> ssize_t {
                encrypted += sv;
                return sv.size();
            });
        if (err < 0) {
            throw std::runtime_error("encrypt_stream()");
        }
        std::cerr << "Stream encrypted size: " << encrypted.size() << "\n";

        // Stream decrypt.
        {
            std::string decrypted;
            std::string_view cryptstream = encrypted;
            const auto err = decrypt_stream(
                key,
                block_size,
                [&cryptstream](size_t size) -> std::pair<std::string, ssize_t> {
                    size = std::min(size, cryptstream.size());
                    auto ret =
                        std::string(std::string_view(cryptstream.data(), size));
                    cryptstream = std::string_view(cryptstream.data() + size,
                                                   cryptstream.size() - size);
                    return std::make_pair(ret, (int)ret.size());
                },
                [&decrypted](std::string_view sv) -> ssize_t {
                    decrypted += sv;
                    return sv.size();
                });
            if (err < 0) {
                throw std::runtime_error("decrypt_stream()");
            }
            std::cerr << "Stream decrypted (" << decrypted.size()
                      << "): " << decrypted << "\n";
        }
    }
}
} // namespace kybertest_gcm

int mainwrap(int argc, char** argv)
{
    kybertest_gcm::test_raw();
    kybertest_gcm::test_stream();
    return 0;
}
