#ifndef HQC_WRAPPERS_H
#define HQC_WRAPPERS_H

#include <stdlib.h>
#include <string.h>

#include <stdint.h>

/*
 * Public HQC KEM wrapper header (Swift bridging header imports this).
 * Self-contained on purpose — the Apple build only ships THIS header.
 *
 * IND-CCA2 KEM API (SECURITY_AUDIT §KM-1). The bare PKE wrappers
 * (hqc_keygen_wrap / hqc_encrypt_wrap / hqc_decrypt_wrap) are GONE; everything
 * goes through encapsulate/decapsulate → a 32-byte shared secret that callers
 * stretch with HKDF. Keep in sync with implement/lib/src/wrapper.h.
 */

/* HQC-256 sizes. */
#define CRYPTO_SECRETKEYBYTES  7333
#define CRYPTO_PUBLICKEYBYTES  7237
#define CRYPTO_BYTES           32     /* shared-secret length */
#define CRYPTO_CIPHERTEXTBYTES 14421  /* KEM ciphertext length */

#define SEED_BYTES       32                     ///< identity-seed size in bytes
#define PUBLIC_KEY_BYTES CRYPTO_PUBLICKEYBYTES  ///< public key size in bytes
#define SECRET_KEY_BYTES CRYPTO_SECRETKEYBYTES  ///< secret key size in bytes
#define SHARED_SECRET_BYTES CRYPTO_BYTES        ///< shared-secret size in bytes
#define CIPHERTEXT_BYTES CRYPTO_CIPHERTEXTBYTES ///< KEM ciphertext size in bytes

/*
 * Deterministic KEM keypair from a 32-byte identity seed. Writes pk/sk into
 * caller buffers. Returns 0 on success. The public key is byte-identical to the
 * pre-KEM build for the same seed (stable identity / safety numbers).
 */
int hqc_kem_keypair_wrap(const uint8_t seed[SEED_BYTES],
                         uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                         uint8_t sk[CRYPTO_SECRETKEYBYTES]);

/*
 * Encapsulate to `pk` with fresh OS entropy. Writes ct (CIPHERTEXT) + ss (32)
 * into caller buffers. Returns 0 on success.
 */
int hqc_kem_enc_wrap(uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     uint8_t ss[CRYPTO_BYTES],
                     const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

/*
 * Decapsulate `ct` with `sk`. Writes ss (32) into the caller buffer. Constant-
 * time with masked implicit rejection — a bad ciphertext yields a pseudo-random
 * ss, never an error signal (no decryption oracle). Returns 0.
 */
int hqc_kem_dec_wrap(uint8_t ss[CRYPTO_BYTES],
                     const uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#endif
