#include "config.h"
#include "gcm.h"
#include "kybtestlib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <array>
#include <fstream>
#include <iostream>

namespace {

void usage(const char* av0, int err)
{
    auto o = (err == EXIT_SUCCESS) ? &std::cout : &std::cerr;
    // -F deliberately not documented.
    *o << "Usage: " << av0 << " [ -hLP ] -o <file output base. E.g. 'key'>\n"
       << "    -L     Continue even if mlockall() fails\n"
       << "    -P     Store private key in plain text\n";
    exit(err);
}

// takes std::string because we need to know it's nullterminated.
void write_file(const std::string& fn, const std::string_view content, int mode)
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

namespace file_version_0_keygen {
std::string make_header_priv() { return file_version_0::magic_priv; }
} // namespace file_version_0_keygen

namespace file_version_1_keygen {
std::string make_header_priv() { return file_version_1_beta::magic_priv; }
} // namespace file_version_1_keygen

std::string make_header_pub() { return file_version_0::magic_pub; }
std::string make_header_priv_unencrypted()
{
    return file_version_0::magic_priv_unencrypted;
}

} // namespace

int mainwrap(int argc, char** argv)
{
    std::string outbase;
    bool encrypt = true;
    int file_version = 0;
    bool must_lock = true;
    {
        int opt;
        while ((opt = getopt(argc, argv, "F:hPo:")) != -1) {
            switch (opt) {
            case 'F':
                file_version = atoi(optarg);
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'L':
                must_lock = false;
                break;
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
    do_mlockall(must_lock);

    if (outbase.empty()) {
        std::cerr << "-o (output file base) is mandatory\n";
        return EXIT_FAILURE;
    }

    if (optind != argc) {
        std::cerr << "Extra args on command line\n";
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
    std::string data(sk.begin(), sk.end());
    if (encrypt) {
        if (file_version == 0) {
            head = file_version_0_keygen::make_header_priv();
            data = encrypt_openssl(data);
        } else if (file_version == 1) {
            using namespace kybertest_gcm;
            head = file_version_1_keygen::make_header_priv();
            const kybertest_gcm::key_t key =
                xgetpasskey("Private key password: ");
            const auto again = xgetpasskey("Again: ");
            if (to_sv(key) != to_sv(again)) {
                std::cerr << "Password mismatch.\n";
                return EXIT_FAILURE;
            }
            const IV iv;
            const auto enc = encrypt_block(key, data, 0, iv);
            data = std::string(to_sv(iv.get())) +
                   std::string(enc.begin(), enc.end());
        } else {
            std::cerr << "Unknown file version.\n";
            return EXIT_FAILURE;
        }
    }
    write_file(outbase + ".priv", head + data, 0600);
    return 0;
}
