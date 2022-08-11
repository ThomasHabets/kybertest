#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "kybtestlib.h"

std::string read_file(const std::string& fn)
{
    std::ifstream t(fn);
    std::stringstream buf;
    buf << t.rdbuf();
    if (!t.good()) {
        throw std::system_error(
            errno, std::generic_category(), "ifstream read");
    }
    return buf.str();
}

void full_write(const int fd, const void* buf, const size_t count)
{
    auto p = reinterpret_cast<const char*>(buf);
    ssize_t left = count;
    for (;;) {
        const auto rc = write(fd, p, left);
        if (rc == left) {
            return;
        }
        if (rc == -1) {
            throw std::system_error(errno, std::generic_category(), "write()");
        }
        left -= rc;
        p += rc;
    }
}

std::string hex_encode(const plain_skey_t& in)
{
    std::ostringstream ss;
    for (auto& ch : in) {
        ss << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>(ch);
    }
    std::cerr << ss.str() << "\n";
    return ss.str();
}

void run_openssl(const std::vector<std::string>& args, const plain_skey_t& pass)
{
    int fds[2];
    if (pipe(fds)) {
        throw std::system_error(errno, std::generic_category(), "pipe()");
    }

    const auto pid = fork();
    if (pid == -1) {
        throw std::system_error(errno, std::generic_category(), "fork()");
    }

    if (!pid) {
        close(fds[1]);
        const auto kfd = "fd:" + std::to_string(fds[0]);
        std::vector<const char*> av;
        av.push_back("openssl");
        for (const auto& a : args) {
            av.push_back(a.c_str());
        }
        av.push_back("-pass");
        av.push_back(kfd.c_str());
        av.push_back(nullptr);
        execvp("openssl", const_cast<char* const*>(av.data()));
    }

    close(fds[0]);
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    const auto hexpass = hex_encode(pass);
    full_write(
        fds[1], reinterpret_cast<const void*>(hexpass.data()), hexpass.size());
    if (-1 == close(fds[1])) {
        throw std::system_error(
            errno, std::generic_category(), "close(openssl password fd)");
    }

    int st;
    if (-1 == waitpid(pid, &st, 0)) {
        throw std::system_error(
            errno, std::generic_category(), "waitpid(openssl)");
    }
    if (WEXITSTATUS(st)) {
        throw std::runtime_error("openssl returned error");
    }
}

extern "C" void randombytes(uint8_t* out, size_t outlen)
{
    auto p = out;
    ssize_t left = outlen;
    for (;;) {
        const auto rc = getrandom(p, left, GRND_RANDOM);
        if (rc == -1) {
            throw std::system_error(
                errno, std::generic_category(), "getrandom()");
        }
        if (left == rc) {
            return;
        }
        p += rc;
        left -= rc;
    }
}

void do_mlockall()
{
    if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
        throw std::system_error(errno, std::generic_category(), "mlockall()");
    }
}
