/**
 * Decrypt binary.
 *
 * Supports version 0, 1beta, and 1, and will continue to support older
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
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>


namespace {

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
    std::string inputfile = "-";
    bool must_lock = true;
    {
        int opt;
        while ((opt = getopt(argc, argv, "f:hLk:")) != -1) {
            switch (opt) {
            case 'f':
                inputfile = optarg;
                break;
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

    if (inputfile != "-") {
        const int input_fd = open(inputfile.c_str(), O_RDONLY);
        if (input_fd < 0) {
            std::cerr << argv[0] << ": Failed to open "
                      << std::quoted(inputfile) << ": " << strerror(errno)
                      << " \n";
            exit(1);
        }
        if (dup2(input_fd, STDIN_FILENO) < 0) {
            std::cerr << argv[0] << ": Failed to open "
                      << std::quoted(inputfile) << ": " << strerror(errno)
                      << " \n";
        }
    }

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
    } else if (head == file_version_1_beta::magic ||
               head == file_version_1::magic) {
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
        std::cerr << argv[0] << ": Bad header\n";
        return 1;
    }
    return 0;
}
