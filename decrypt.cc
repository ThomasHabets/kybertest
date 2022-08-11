#include <unistd.h>
#include <array>
#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "kybtestlib.h"

namespace {

void full_read(const int fd, void* buf, const size_t count)
{
    auto p = reinterpret_cast<char*>(buf);
    ssize_t left = count;
    for (;;) {
        const auto rc = read(fd, p, left);
        if (rc == left) {
            return;
        }
        if (rc == -1) {
            throw std::system_error(errno, std::generic_category(), "read()");
        }
        if (rc == 0) {
            throw std::runtime_error("read() eof");
        }
        left -= rc;
        p += rc;
    }
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
    *o << "Usage: " << av0 << " [ -h ] -k <keyfile>\n";
    exit(err);
}

int mainwrap(int argc, char** argv)
{
    do_mlockall();
    std::string privfn;
    {
        int opt;
        while ((opt = getopt(argc, argv, "hk:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'k':
                privfn = optarg;
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }

    if (privfn.empty()) {
        std::cerr << "-k (recipient privkey) is mandatory\n";
        return EXIT_FAILURE;
    }

    const auto sk = read_file(privfn);
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
    run_openssl({ "aes-256-cbc", "-d", "-pbkdf2" }, pt);
    return 0;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        return mainwrap(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
