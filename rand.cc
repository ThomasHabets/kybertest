#include<sys/random.h>
#include<cinttypes>

extern "C" void randombytes(uint8_t *out, size_t outlen)
{
  getrandom(out, outlen, 0);
}
