#include "kybtestlib.h"

#include <unistd.h>
#include <array>
#include <fstream>
#include <iostream>

namespace {
void usage(const char* av0, int err)
{
    auto o = (err == EXIT_SUCCESS) ? &std::cout : &std::cerr;
    *o << "Usage: " << av0 << " [ -h ] -o <file output base. E.g. 'key'>\n";
    exit(err);
}

void write_file(const std::string& fn, const std::string& content)
{
    std::ofstream t(fn);
    t << content;
    if (!t.good()) {
        throw std::system_error(
            errno, std::generic_category(), "ofstream write");
    }
}

int mainwrap(int argc, char** argv)
{
    do_mlockall();
    std::string outbase;
    {
        int opt;
        while ((opt = getopt(argc, argv, "ho:")) != -1) {
            switch (opt) {
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'o':
                outbase = optarg;
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
    write_file(outbase + ".pub", std::string(pk.begin(), pk.end()));
    write_file(outbase + ".priv", std::string(sk.begin(), sk.end()));
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
