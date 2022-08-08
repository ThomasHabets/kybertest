#include <unistd.h>
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
  const auto pk = read_file("key.pub");
  assert(pk.size() == CRYPTO_PUBLICKEYBYTES);

  std::array<uint8_t, CRYPTO_BYTES> pt;
  std::array<uint8_t, CRYPTO_CIPHERTEXTBYTES> ct;
  if (crypto_kem_enc(
					    ct.data(),
					    (uint8_t*)pt.data(),
					    reinterpret_cast<const uint8_t*>(pk.data()))) {
    std::cerr << "Encryption failed\n";
    return 1;
  }
  if (ct.size() != write(STDOUT_FILENO, ct.data(), ct.size())) {
    std::cerr << "Write failed\n";
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
  execlp("openssl", "aes-256-cbc", "-kfile", keyfile.c_str(), NULL);
}
