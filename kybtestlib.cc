#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <array>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "kybtestlib.h"

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
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
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
    return ss.str();
}

class Pipe
{
public:
    Pipe();
    ~Pipe();
    void close();
    void close_read();
    void close_write();
    int read_fd() { return read_fd_; }
    int write_fd() { return write_fd_; }

private:
    int read_fd_;
    int write_fd_;
};

Pipe::Pipe()
{
    int fds[2];
    if (pipe(fds)) {
        throw std::system_error(errno, std::generic_category(), "pipe()");
    }
    read_fd_ = fds[0];
    write_fd_ = fds[1];
}
void Pipe::close()
{
    close_read();
    close_write();
}
void Pipe::close_read()
{
    if (read_fd_ == -1) {
        return;
    }
    if (-1 == ::close(read_fd_)) {
        throw std::system_error(
            errno, std::generic_category(), "close(read pipe)");
    }
    read_fd_ = -1;
}
void Pipe::close_write()
{
    if (write_fd_ == -1) {
        return;
    }
    if (-1 == ::close(write_fd_)) {
        throw std::system_error(
            errno, std::generic_category(), "close(write pipe)");
    }
    write_fd_ = -1;
}
Pipe::~Pipe() { close(); }

class Subprocess
{
public:
    Subprocess(std::function<void()>);
    ~Subprocess();

    Pipe& stdin() { return stdin_; }
    Pipe& stdout() { return stdout_; }

private:
    Pipe stdin_;
    Pipe stdout_;
    std::function<void()> cb_;
    pid_t pid_;
};

Subprocess::Subprocess(std::function<void()> func) : cb_(func)
{
    pid_ = fork();
    if (pid_ == -1) {
        throw std::system_error(errno, std::generic_category(), "fork()");
    }
    if (pid_) {
        stdin_.close_read();
        stdout_.close_write();
        return;
    }
    if (-1 == dup2(stdin_.read_fd(), STDIN_FILENO)) {
        throw std::system_error(errno, std::generic_category(), "dup2(stdin)");
    }
    if (-1 == dup2(stdout_.write_fd(), STDOUT_FILENO)) {
        throw std::system_error(errno, std::generic_category(), "dup2(stdout)");
    }
    stdin_.close();
    stdout_.close();
    func();
    exit(EXIT_SUCCESS);
}

Subprocess::~Subprocess()
{
    int st;
    if (-1 == waitpid(pid_, &st, 0)) {
        std::cerr << "waitpid(): " << strerror(errno) << "\n";
    }
    if (WEXITSTATUS(st)) {
        std::cerr << "subprocess failed\n";
    }
}


// TODO: kill subprocess on failure.
std::string pipe_openssl(const std::vector<std::string>& args,
                         const std::string& data)
{
    Subprocess openssl([&args] {
        std::vector<const char*> av;
        av.push_back("openssl");
        for (const auto& a : args) {
            av.push_back(a.c_str());
        }
        av.push_back(nullptr);

        execvp("openssl", const_cast<char* const*>(av.data()));
        exit(EXIT_FAILURE);
    });

    Subprocess writer([&openssl, &data] {
        full_write(openssl.stdin().write_fd(), data.data(), data.size());
        exit(EXIT_SUCCESS);
    });
    openssl.stdin().close();

    std::string ret;
    for (;;) {
        std::array<char, 1024> buf;
        const auto rc =
            read(openssl.stdout().read_fd(), buf.data(), buf.size());
        if (rc == 0) {
            return ret;
        }
        if (rc == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            throw std::system_error(
                errno, std::generic_category(), "read(openssl)");
        }
        ret += std::string(&buf[0], &buf[rc]);
    }
}

std::string encrypt_openssl(const std::string& data)
{
    return pipe_openssl({ "aes-256-cbc", "-pbkdf2" }, data);
}

std::string decrypt_openssl(const std::string& data)
{
    return pipe_openssl({ "aes-256-cbc", "-pbkdf2", "-d" }, data);
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
        exit(EXIT_FAILURE);
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
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "read()");
        }
        if (rc == 0) {
            throw std::runtime_error("read() eof");
        }
        left -= rc;
        p += rc;
    }
}

AutoCloser::AutoCloser(int& fd) : fd_(fd) {}
AutoCloser::~AutoCloser()
{
    if (fd_ != -1) {
        close(fd_);
        fd_ = -1;
    }
}
