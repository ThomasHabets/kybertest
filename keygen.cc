#include "kybtestlib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <array>
#include <fstream>
#include <iostream>

namespace {

void usage(const char* av0, int err)
{
    auto o = (err == EXIT_SUCCESS) ? &std::cout : &std::cerr;
    *o << "Usage: " << av0 << " [ -hP ] -o <file output base. E.g. 'key'>\n"
       << "    -P     Store private key in plain text\n";
    exit(err);
}

void write_file(const std::string& fn, const std::string& content, int mode)
{
    int fd = open(fn.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
    if (-1 == fd) {
        throw std::system_error(
            errno, std::generic_category(), "open(" + fn + ")");
    }
    AutoCloser cfd(fd);

    full_write(fd, content.data(), content.size());
    if (-1 == close(fd)) {
        throw std::system_error(
            errno, std::generic_category(), "close(" + fn + ")");
    }
    fd = -1;
}

std::string make_header_pub() { return "KYBPUB00"; }

std::string make_header_priv() { return "KYBSECe0"; }

std::string make_header_priv_unencrypted() { return "KYBPRIV0"; }

int mainwrap(int argc, char** argv)
{
    do_mlockall();
    std::string outbase;
    bool encrypt = true;
    {
        int opt;
        while ((opt = getopt(argc, argv, "hPo:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'o':
                outbase = optarg;
                break;
            case 'P':
                encrypt = false;
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }

    if (outbase.empty()) {
        std::cerr << "-o (output file base) is mandatory\n";
        return EXIT_FAILURE;
    }

    pubkey_t pk;
    secret_key_t sk;
    if (crypto_kem_keypair(pk.data(), sk.data())) {
        std::cerr << "Key generation failed\n";
        return 1;
    }
    write_file(outbase + ".pub",
               make_header_pub() + std::string(pk.begin(), pk.end()),
               0644);
    std::string head = make_header_priv_unencrypted();
    std::string data = std::string(sk.begin(), sk.end());
    if (encrypt) {
        head = make_header_priv();
        data = encrypt_openssl(data);
    }
    write_file(outbase + ".priv", head + data, 0600);
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
