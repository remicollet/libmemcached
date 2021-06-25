/*
    +--------------------------------------------------------------------+
    | libmemcached-awesome - C/C++ Client Library for memcached          |
    +--------------------------------------------------------------------+
    | Redistribution and use in source and binary forms, with or without |
    | modification, are permitted under the terms of the BSD license.    |
    | You should have received a copy of the license in a bundled file   |
    | named LICENSE; in case you did not receive a copy you can review   |
    | the terms online at: https://opensource.org/licenses/BSD-3-Clause  |
    +--------------------------------------------------------------------+
    | Copyright (c) 2006-2014 Brian Aker   https://datadifferential.com/ |
    | Copyright (c) 2020-2021 Michael Wallner        https://awesome.co/ |
    +--------------------------------------------------------------------+
*/

#include "libhashkit/common.h"

hashkit_string_st *hashkit_encrypt(hashkit_st *kit, const char *source,
                                   size_t source_length) {
  return aes_encrypt(kit->encryption_context, (const unsigned char *)source,
                     source_length);
}

hashkit_string_st *hashkit_decrypt(hashkit_st *kit, const char *source,
                                   size_t source_length) {
  return aes_decrypt(kit->decryption_context, (const unsigned char *)source,
                     source_length);
}

bool hashkit_initialize_encryption(hashkit_st *kit, const char *key,
                                   const size_t key_length) {
  kit->encryption_context = EVP_CIPHER_CTX_new();
  kit->decryption_context = EVP_CIPHER_CTX_new();
  if (kit->encryption_context == NULL || kit->decryption_context == NULL) {
    return false;
  }
  return kit->use_encryption =
             aes_initialize((const unsigned char *)key, key_length,
                            kit->encryption_context, kit->decryption_context);
}