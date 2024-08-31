module ys3ds.mbedtls.psa.crypto_builtin_composites;

// didnt wanna auto convert so done by hand

import ys3ds.mbedtls.psa.crypto_driver_common;
import ys3ds.mbedtls.psa.crypto;
import ys3ds.mbedtls.cmac;
import ys3ds.mbedtls.cipher;

extern (C):

struct mbedtls_psa_hmac_operation_t
{
  psa_algorithm_t alg;
  psa_hash_operation_s hash_ctx;
  ubyte[PSA_HMAC_MAX_HASH_BLOCK_SIZE] opad;
}

struct mbedtls_psa_mac_operation_t
{
  psa_algorithm_t alg;

  union _Anonymous_0
  {
    uint dummy;
    // idk if these are meant to be here
    mbedtls_psa_hmac_operation_t hmac;
    mbedtls_cipher_context_t cmac;
  }

  _Anonymous_0 ctx;
}
