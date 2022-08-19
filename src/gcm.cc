#include "gcm.h"

#include "kybtestlib.h"
#include "misc.h"

#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <string_view>
#include <sys/random.h>
#include <array>
#include <cassert>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

namespace kybertest_gcm {

/*
 * Simple RAII wrapper for EVP_CIPHER_CTX.
 */
class CTX
{
public:
    CTX() : ctx_(EVP_CIPHER_CTX_new())
    {
        if (!ctx_) {
            throw std::runtime_error("EVP_CIPHER_CTX_new()");
        }
    }
    ~CTX() { EVP_CIPHER_CTX_free(ctx_); }

    // No move or copy.
    CTX(const CTX&) = delete;
    CTX(CTX&&) = delete;
    CTX& operator=(const CTX&) = delete;
    CTX& operator=(CTX&&) = delete;


    EVP_CIPHER_CTX* get() const { return ctx_; }

private:
    EVP_CIPHER_CTX* ctx_;
};

void IV::mix(uint64_t counter)
{
    constexpr int sha256_output = 32;
    static_assert(sizeof(iv_) == sha256_output);

    // Change the IV.
    for (int c = 0; counter; c++) {
        iv_[c] ^= counter & 0xff;
        counter >>= 8;
    }

    // Hash the IV to not create a bitwise difference in IV across blocks.
    std::array<unsigned char, 32> buf;
    pqcrystals_sha2_ref_sha256(buf.data(), iv_.data(), iv_.size());
    std::copy(buf.begin(), buf.end(), iv_.data());
}

/*
 * Mostly taken from
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption,
 * but with some bug fixes and improvements in readability.
 *
 * Return encrypted blob and tag.
 *
 * Throws for anything that "can't happen".
 */
std::tuple<v8, tag_t>
encrypt(const std::string_view plaintext, const key_t& key, const iv_t& iv)
{
    CTX ctx;

    /* Initialise the encryption operation. */
    if (1 !=
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        throw std::runtime_error(
            "EVP_EncryptInit_ex(initialize encryption operation)");
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(
                 ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl(set IV length)");
    }

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key.data(), iv.data())) {
        throw std::runtime_error("EVP_EncryptInit_ex(init key and IV)");
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required.
     */
    if (false) {
        const std::string_view aad;
        int len;
        if (1 != EVP_EncryptUpdate(
                     ctx.get(),
                     NULL,
                     &len,
                     reinterpret_cast<const unsigned char*>(aad.data()),
                     aad.size())) {
            throw std::runtime_error("EVP_EncryptUpdate(AAD)");
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary.
     */
    v8 ciphertext;
    {
        v8 buf(plaintext.size() * 2);
        int len = buf.size();

        if (1 != EVP_EncryptUpdate(
                     ctx.get(),
                     buf.data(),
                     &len,
                     reinterpret_cast<const unsigned char*>(plaintext.data()),
                     plaintext.size())) {
            throw std::runtime_error("EVP_EncryptUpdate()");
        }
        buf.resize(len);
        ciphertext = buf;
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode.
     */
    {
        v8 buf(plaintext.size());
        int len = buf.size();
        if (1 != EVP_EncryptFinal_ex(ctx.get(), buf.data(), &len)) {
            throw std::runtime_error("EVP_EncryptFinal_ex()");
        }
        buf.resize(len);
        ciphertext.insert(ciphertext.end(), buf.begin(), buf.end());
    }

    /* Get the tag */
    tag_t tag;
    if (1 != EVP_CIPHER_CTX_ctrl(
                 ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)");
    }

    return std::make_tuple(ciphertext, tag);
}

/*
 * Mostly taken from
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption,
 * but with some bug fixes and improvements in readability.
 *
 * Return plaintext.
 */
std::optional<v8> decrypt(const std::string_view ciphertext,
                          const key_t& key,
                          const iv_t& iv,
                          const tag_t& tag)
{
    CTX ctx;

    /* Initialise the decryption operation. */
    if (1 !=
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        throw std::runtime_error("EVP_DecryptInit_ex(EVP_aes_256_gcm())");
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (1 != EVP_CIPHER_CTX_ctrl(
                 ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN)");
    }

    /* Initialise key and IV */
    if (1 != EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key.data(), iv.data())) {
        throw std::runtime_error("EVP_DecryptInit_ex(init key and IV)");
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (false) {
        const std::string_view aad;
        int len;
        if (1 != EVP_DecryptUpdate(
                     ctx.get(),
                     NULL,
                     &len,
                     reinterpret_cast<const unsigned char*>(aad.data()),
                     aad.size())) {
            throw std::runtime_error("EVP_DecryptUpdate(AAD)");
        }
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    v8 plaintext;
    {
        v8 buf(ciphertext.size());
        int len = buf.size();

        if (1 != EVP_DecryptUpdate(
                     ctx.get(),
                     buf.data(),
                     &len,
                     reinterpret_cast<const unsigned char*>(ciphertext.data()),
                     ciphertext.size())) {
            throw std::runtime_error("EVP_DecryptUpdate()");
        }
        buf.resize(len);
        plaintext = buf;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (1 !=
        EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_TAG,
            tag.size(),
            const_cast<void*>(reinterpret_cast<const void*>(tag.data())))) {
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG)");
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    {
        v8 buf(ciphertext.size());
        int len = buf.size();
        if (1 != EVP_DecryptFinal_ex(ctx.get(), buf.data(), &len)) {
            return std::nullopt;
        }
        buf.resize(len);
        plaintext.insert(plaintext.end(), buf.begin(), buf.end());
    }

    return plaintext;
}

// Every block is an encrypted plaintext and the tag.
// IV stays the same, but counter increments.
v8 encrypt_block(const key_t& key,
                 const std::string_view plain,
                 const uint64_t counter,
                 IV iv)
{
    iv.mix(counter);
    const auto [enc, tag] = encrypt(plain, key, iv.get());
    v8 buf;
    buf.insert(buf.end(), enc.begin(), enc.end());
    buf.insert(buf.end(), tag.begin(), tag.end());
    return buf;
}

// Return plaintext.
//
// (lowel level functions can throw, though)
std::optional<v8> decrypt_block(const key_t& key,
                                const std::string_view data,
                                const uint64_t counter,
                                IV iv)
{
    iv.mix(counter);
    tag_t tag;

    if (data.size() < tag.size() + 1) {
        return std::nullopt;
    }

    // Extract ciphertext.
    const auto ct_size = data.size() - tag.size();
    const auto ciphertext = std::string_view(data.begin(), ct_size);

    // Extract tag.
    std::copy(&data[ct_size], &data[data.size()], tag.data());

    return decrypt(ciphertext, key, iv.get(), tag);
}

// Stream unbounded amount of data.
// Return <0 on error.
ssize_t encrypt_stream(
    const key_t& key,
    const size_t blocksize,
    const std::function<std::pair<std::string, ssize_t>(size_t)>& readcb,
    const std::function<ssize_t(std::string_view)>& writecb)
{
    IV iv;
    {
        const auto err = writecb(to_sv(iv.get()));
        if (err < 0) {
            return err;
        }
    }

    uint64_t counter = 0;
    for (;;) {
        auto [data, err] = readcb(blocksize);
        if (err <= 0) {
            return err;
        }
        assert(data.size() <= blocksize);

        const auto buf = encrypt_block(key, data, counter, iv);

        if (true) {
            // Confirm that encryption worked.
            const auto dec =
                decrypt_block(key, to_sv(buf), counter, iv).value();
            if (to_sv(dec) != to_sv(data)) {
                throw std::runtime_error("CAN'T HAPPEN: decrypt of freshly "
                                         "encrypted block mismatched");
            }
        }

        const auto werr = writecb(to_sv(buf));
        if (werr < 0) {
            return werr;
        }
        counter++;
    }
}

// Return -1 on failure.
ssize_t decrypt_stream(
    const key_t& key,
    const size_t plainblocksize,
    const std::function<std::pair<std::string, ssize_t>(size_t)>& readcb,
    const std::function<ssize_t(std::string_view)>& writecb)
{
    IV iv{ iv_t() };
    {
        auto [data, err] = readcb(iv.get().size());
        if (err <= 0) {
            return err;
        }
        if (data.size() != iv.get().size()) {
            throw std::runtime_error(
                "CAN'T HAPPEN: readcb() returned wrong number of bytes");
        }
        std::copy(data.begin(), data.end(), iv.get().data());
    }

    const auto blocksize = plainblocksize + tag_t().size();

    uint64_t counter = 0;
    for (;;) {
        auto [data, err] = readcb(blocksize);
        if (err <= 0) {
            return err;
        }
        assert(data.size() <= blocksize);
        assert(data.size() >= tag_t().size());

        auto dec = decrypt_block(key, data, counter, iv);
        if (!dec.has_value()) {
            return -1;
        }
        const auto werr = writecb(to_sv(dec.value()));
        if (werr < 0) {
            return werr;
        }
        counter++;
    }
}
} // namespace kybertest_gcm
