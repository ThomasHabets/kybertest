#include<unistd.h>
#include<fstream>
#include<iostream>
#include<array>
#include<sstream>
#include<cassert>
#include"misc.h"

std::string read_file(const std::string&fn)
{
  std::ifstream t(fn);
  std::stringstream buf;
  buf << t.rdbuf();
  return buf.str();
}

int main()
{
  std::cerr << "Decrypt\n";
  const auto sk = read_file("key.priv");
  assert(sk.size() == CRYPTO_SECRETKEYBYTES);

  std::array<uint8_t, CRYPTO_CIPHERTEXTBYTES> ct;
  if (ct.size() != read(STDIN_FILENO, ct.data(), ct.size())) {
    std::cerr << "Failed to read silly header\n";
    return 1;
  }

  std::array<uint8_t, CRYPTO_BYTES> pt;
  if (crypto_kem_dec(
			      pt.data(),
			      reinterpret_cast<const uint8_t*>(ct.data()),
			      reinterpret_cast<const uint8_t*>(sk.data()))) {
    std::cerr << "Failed decryption\n";
    return 1;
  }

  int fds[2];
  if (pipe(fds)) {
    perror("pipe()");
    return 1;
  }

  const auto pid = fork();
  if (pid == -1) {
    perror("fork()");
    return 1;
  }
  if (!pid) {
    close(fds[0]);
    close(STDOUT_FILENO);
    auto p = pt.data();
    auto len = pt.size();
    for (;;) {
      const auto rc = write(fds[1], p, len);
      if (rc == len) {
	exit(EXIT_SUCCESS);
      }
      if (rc == -1) {
	perror("write()");
	exit(EXIT_FAILURE);
      }
      len -= rc;
      p += rc;
    }
  }
  close(fds[1]);
  const auto keyfile = "/dev/fd/" + std::to_string(fds[0]);
  execlp("openssl", "aes-256-cbc", "-d", "-kfile", keyfile.c_str(), NULL);
}
