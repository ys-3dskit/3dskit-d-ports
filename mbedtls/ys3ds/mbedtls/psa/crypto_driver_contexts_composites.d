module ys3ds.mbedtls.psa.crypto_driver_contexts_composites;

// didnt wanna auto convert so done by hand

import ys3ds.mbedtls.psa.crypto_builtin_composites;
import ys3ds.mbedtls.psa.crypto_driver_common;

extern (C):

union psa_driver_mac_context_t
{
  uint dummy; // make sure this union is always non-empty
  mbedtls_psa_mac_operation_t mbedtls_ctx;
}
