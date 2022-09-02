/**
 * Decrypt binary.
 *
 * Supports version 0 and 1beta, and will continue to support older
 * versions.
 */
#include "config.h"

#include "gcm.h"
#include "kybtestlib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <array>
#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>


namespace {

std::string read_rest(int fd, const std::string_view fn)
{
    std::string rest;
    for (;;) {
        std::array<char, 1024> buf;
        const auto rc = read(fd, buf.data(), buf.size());
        if (rc == -1) {
            throw std::system_error(errno,
                                    std::generic_category(),
                                    "read(" + std::string(fn) + ")");
        }
        if (rc == 0) {
            break;
        }
        rest += std::string(&buf[0], &buf[rc]);
    }
    return rest;
}

// takes std::string because we need to know it's nullterminated.
secret_key_t read_priv_key(const std::string& fn)
{
    int fd = open(fn.c_str(), O_RDONLY);
    if (-1 == fd) {
        throw std::system_error(
            errno, std::generic_category(), "open(" + fn + ")");
    }
    AutoCloser cfd(fd);

    std::vector<char> h(8);
    full_read(fd, h.data(), h.size());
    auto h2 = kybertest_gcm::to_sv(h);

    // Check for unencrypted key.
    if (h2 == file_version_0::magic_priv_unencrypted) {
        secret_key_t priv;
        full_read(fd, priv.data(), priv.size());
        return priv;
    }

    if (h2 == file_version_0::magic_priv) {
        const auto rest = read_rest(fd, fn);
        const auto data = decrypt_openssl(rest);
        secret_key_t priv;
        if (data.size() != priv.size()) {
            throw std::runtime_error("priv key has bad size");
        }
        std::copy(data.begin(), data.end(), priv.begin());
        return priv;
    }

    if (h2 == file_version_1_beta::magic_priv) {
        using namespace kybertest_gcm;
        iv_t iv;
        kybertest_gcm::key_t key = xgetpasskey("Private key password: ");
        full_read(fd, iv.data(), iv.size());
        const auto rest = read_rest(fd, fn);
        const auto sec = decrypt_block(key, rest, 0, iv).value();
        secret_key_t priv;
        if (sec.size() != priv.size()) {
            throw std::runtime_error("priv key has bad size");
        }
        std::copy(sec.begin(), sec.end(), priv.begin());
        return priv;
    }

    throw std::runtime_error("priv key has bad header " + std::string(h2));
}

std::pair<std::string, encrypted_skey_t> read_header(int fd)
{
    std::vector<char> h(8);
    full_read(fd, h.data(), h.size());

    encrypted_skey_t ct;
    full_read(fd, ct.data(), ct.size());
    return { std::string(h.begin(), h.end()), ct };
}

void usage(const char* av0, int err)
{
    auto o = (err == EXIT_SUCCESS) ? &std::cout : &std::cerr;
    *o << "Usage: " << av0 << " [ -hL ] -k <keyfile>\n"
       << "    -L     Continue even if mlockall() fails\n";
    exit(err);
}
} // namespace

int mainwrap(int argc, char** argv)
{
    std::string privfn;
    bool must_lock = true;
    {
        int opt;
        while ((opt = getopt(argc, argv, "hLk:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'k':
                privfn = optarg;
                break;
            case 'L':
                must_lock = false;
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }
    do_mlockall(must_lock);

    if (privfn.empty()) {
        std::cerr << "-k (recipient privkey) is mandatory\n";
        return EXIT_FAILURE;
    }

    if (optind != argc) {
        std::cerr << "Extra args on command line\n";
        return EXIT_FAILURE;
    }

    const auto sk = read_priv_key(privfn);
    if (sk.size() != CRYPTO_SECRETKEYBYTES) {
        std::cerr << "Priv file has wrong size. Want " << CRYPTO_SECRETKEYBYTES
                  << " got " << sk.size() << "\n";
        return EXIT_FAILURE;
    }

    const auto [head, ct] = read_header(STDIN_FILENO);

    plain_skey_t pt;
    if (crypto_kem_dec(pt.data(),
                       reinterpret_cast<const uint8_t*>(ct.data()),
                       reinterpret_cast<const uint8_t*>(sk.data()))) {
        std::cerr << "Failed decryption\n";
        return 1;
    }
    if (head == file_version_0::magic) {
        run_openssl({ "aes-256-cbc", "-d", "-pbkdf2" }, pt);
    } else if (head == file_version_1_beta::magic) {
        if (0 > kybertest_gcm::decrypt_stream(
                    pt,
                    file_version_1_beta::blocksize,
                    [](size_t size) -> auto{
                        std::vector<char> buf(size);
                        const auto rc =
                            read(STDIN_FILENO, buf.data(), buf.size());
                        if (rc >= 0) {
                            buf.resize(rc);
                        }
                        // TODO: with a better interface maybe we
                        // could avoid this copy.
                        return std::make_pair(
                            std::string(buf.begin(), buf.end()), rc);
                    },
                    [](std::string_view sv) -> auto{
                        full_write(STDOUT_FILENO, sv.data(), sv.size());
                        return sv.size();
                    })) {
            std::cerr << "Bulk decryption failed\n";
            return 1;
        }
    } else {
        std::cerr << "Bad header\n";
        return 1;
    }
    return 0;
}
