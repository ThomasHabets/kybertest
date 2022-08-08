

#define KYBER_K 4

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES         384
#define KYBER_POLYVECBYTES      (KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMB\
YTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)


// kem.h
#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if (KYBER_K == 3)
#define crypto_kem_keypair pqcrystals_kyber768_ref_keypair
#define crypto_kem_enc pqcrystals_kyber768_ref_enc
#define crypto_kem_dec pqcrystals_kyber768_ref_dec
#elif (KYBER_K == 4)
#define crypto_kem_keypair pqcrystals_kyber1024_ref_keypair
#define crypto_kem_enc pqcrystals_kyber1024_ref_enc
#define crypto_kem_dec pqcrystals_kyber1024_ref_dec
#endif

extern "C" {
  int pqcrystals_kyber1024_ref_keypair(uint8_t*pk,uint8_t*sk);
  int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *sk);
  int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
  int pqcrystals_kyber768_ref_keypair(uint8_t*pk,uint8_t*sk);
  int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *sk);
  int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
}
