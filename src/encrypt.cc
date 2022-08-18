/**
 * Encrypt
 */
#include "config.h"
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
void write_header(int fd, const encrypted_skey_t& key)
{
    const std::string head = "KYBTEST0";
    full_write(fd, head.data(), head.size());
    full_write(fd, key.data(), key.size());
}

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
    *o << "Usage: " << av0 << " [ -h ] -r <recipient pubkey file>\n";
    exit(err);
}

int mainwrap(int argc, char** argv)
{
    do_mlockall();
    std::string pubfn;
    {
        int opt;
        while ((opt = getopt(argc, argv, "hr:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'r':
                pubfn = optarg;
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }

    if (pubfn.empty()) {
        std::cerr << "-r (recipient pubkey) is mandatory\n";
        return EXIT_FAILURE;
    }

    const auto pk = read_pub_key(pubfn);
    plain_skey_t pt;
    encrypted_skey_t ct;
    if (crypto_kem_enc(ct.data(),
                       (uint8_t*)pt.data(),
                       reinterpret_cast<const uint8_t*>(pk.data()))) {
        std::cerr << "Encryption of ression key failed\n";
        return 1;
    }
    write_header(STDOUT_FILENO, ct);
    run_openssl({ "aes-256-cbc", "-pbkdf2" }, pt);
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
