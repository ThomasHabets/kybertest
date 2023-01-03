/**
 * Encrypt binary.
 *
 * Supports the latest stable file format, and any beta.
 *
 * When the next version becomes stable, it will drop ability to
 * encrypt to previous version.
 *
 * encrypt to previous version, in order to keep the code simple and
 * secure.
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
#include <cerrno>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

using kybertest_gcm::to_sv;

namespace {
namespace file_version_0_encrypt {
void write_header(int fd, const encrypted_skey_t& key)
{
    using file_version_0::magic;
    full_write(fd, magic.data(), magic.size());
    full_write(fd, key.data(), key.size());
}
} // namespace file_version_0_encrypt

namespace file_version_1_encrypt {
void write_header(int fd, const encrypted_skey_t& key)
{
    using file_version_1_beta::magic;
    full_write(fd, magic.data(), magic.size());
    full_write(fd, key.data(), key.size());
}
} // namespace file_version_1_encrypt

// takes std::string because we need to know it's nullterminated.
pubkey_t read_pub_key(const std::string& fn)
{
    int fd = open(fn.c_str(), O_RDONLY);
    if (-1 == fd) {
        throw std::system_error(
            errno, std::generic_category(), "open(" + fn + ")");
    }
    AutoCloser cfd(fd);

    std::vector<char> h(8);
    full_read(fd, h.data(), h.size());
    if (to_sv(h) != file_version_0::magic_pub) {
        throw std::runtime_error("pubkey has bad header");
    }
    pubkey_t pub;
    full_read(fd, pub.data(), pub.size());
    return pub;
}

void usage(const char* av0, int err)
{
    auto o = (err == EXIT_SUCCESS) ? &std::cout : &std::cerr;
    // -F deliberately not documented.
    *o << "Usage: " << av0 << " [ -hL ] -r <recipient pubkey file>\n"
       << "    -L     Continue even if mlockall() fails\n";
    exit(err);
}
} // namespace

int mainwrap(int argc, char** argv)
{
    std::string pubfn;
    bool must_lock = true;
    int file_version = 1;
    {
        int opt;
        while ((opt = getopt(argc, argv, "F:hLr:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'r':
                pubfn = optarg;
                break;
            case 'L':
                must_lock = false;
                break;
            case 'F':
                file_version = atoi(optarg);
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }
    do_mlockall(must_lock);

    if (pubfn.empty()) {
        std::cerr << "-r (recipient pubkey) is mandatory\n";
        return EXIT_FAILURE;
    }

    if (optind != argc) {
        std::cerr << "Extra args on command line\n";
        return EXIT_FAILURE;
    }

    const auto pk = read_pub_key(pubfn);
    plain_skey_t pt;
    encrypted_skey_t ct;
    if (crypto_kem_enc(ct.data(),
                       (uint8_t*)pt.data(),
                       reinterpret_cast<const uint8_t*>(pk.data()))) {
        std::cerr << "Encryption of session key failed\n";
        return 1;
    }
    if (file_version == 0) {
        file_version_0_encrypt::write_header(STDOUT_FILENO, ct);
        run_openssl({ "aes-256-cbc", "-pbkdf2" }, pt);
    } else if (file_version == 1) {
        file_version_1_encrypt::write_header(STDOUT_FILENO, ct);
        if (0 > kybertest_gcm::encrypt_stream(
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
            std::cerr << "Bulk encryption failed\n";
            return 1;
        }
    }
    return 0;
}
