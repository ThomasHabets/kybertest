/**
 * Encrypt
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

namespace {
namespace file_version_0 {
void write_header(int fd, const encrypted_skey_t& key)
{
    const std::string head = "KYBTEST0";
    full_write(fd, head.data(), head.size());
    full_write(fd, key.data(), key.size());
}
} // namespace file_version_0

namespace file_version_1 {
void write_header(int fd, const encrypted_skey_t& key)
{
    const std::string head = "KYBTEST1";
    full_write(fd, head.data(), head.size());
    full_write(fd, key.data(), key.size());
}
} // namespace file_version_1

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
    if (std::string(h.begin(), h.end()) != "KYBPUB00") {
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

int mainwrap(int argc, char** argv)
{
    std::string pubfn;
    bool must_lock = true;
    int file_version = 0;
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
        file_version_0::write_header(STDOUT_FILENO, ct);
        run_openssl({ "aes-256-cbc", "-pbkdf2" }, pt);
    } else if (file_version == 1) {
        file_version_1::write_header(STDOUT_FILENO, ct);
        if (0 > kybertest_gcm::encrypt_stream(
                    pt,
                    ::file_version_1::blocksize,
                    [](size_t size) -> auto{
                        std::vector<char> buf(size);
                        const auto rc =
                            read(STDIN_FILENO, buf.data(), buf.size());
                        if (rc >= 0) {
                            buf.resize(rc);
                        }
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
} // namespace

int main(int argc, char** argv)
{
    try {
        return mainwrap(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        exit(EXIT_FAILURE);
    }
}
