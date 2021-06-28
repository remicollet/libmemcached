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

#include <cstring>

#define DIGEST_ROUNDS 5

#define AES_KEY_NBYTES 32
#define AES_IV_NBYTES 32

bool aes_initialize(const unsigned char *key, const size_t key_length,
                    EVP_CIPHER_CTX *encryption_context,
                    EVP_CIPHER_CTX *decryption_context) {
  unsigned char aes_key[AES_KEY_NBYTES];
  unsigned char aes_iv[AES_IV_NBYTES];
  if (aes_key == NULL || aes_iv == NULL) {
    return false;
  }

  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, key, key_length,
                         DIGEST_ROUNDS, aes_key, aes_iv);
  if (i != AES_KEY_NBYTES) {
    return false;
  }

  EVP_CIPHER_CTX_init(encryption_context);
  EVP_CIPHER_CTX_init(decryption_context);
  if (EVP_EncryptInit_ex(encryption_context, EVP_aes_256_cbc(), NULL, key,
                         aes_iv) != 1 ||
      EVP_DecryptInit_ex(decryption_context, EVP_aes_256_cbc(), NULL, key,
                         aes_iv) != 1) {
    return false;
  }
  return true;
}

hashkit_string_st *aes_encrypt(EVP_CIPHER_CTX *encryption_context,
                               const unsigned char *source,
                               size_t source_length) {
  int cipher_length =
      source_length + EVP_CIPHER_CTX_block_size(encryption_context);
  int final_length = 0;
  unsigned char *cipher_text = (unsigned char *)malloc(cipher_length);
  if (cipher_text == NULL) {
    return NULL;
  }
  if (EVP_EncryptInit_ex(encryption_context, NULL, NULL, NULL, NULL) != 1 ||
      EVP_EncryptUpdate(encryption_context, cipher_text, &cipher_length, source,
                        source_length) != 1 ||
      EVP_EncryptFinal_ex(encryption_context, cipher_text + cipher_length,
                          &final_length) != 1) {
    free(cipher_text);
    return NULL;
  }

  hashkit_string_st *destination =
      hashkit_string_create(cipher_length + final_length);
  if (destination == NULL) {
    return NULL;
  }
  char *dest = hashkit_string_c_str_mutable(destination);
  memcpy(dest, cipher_text, cipher_length + final_length);
  hashkit_string_set_length(destination, cipher_length + final_length);
  return destination;
}

hashkit_string_st *aes_decrypt(EVP_CIPHER_CTX *decryption_context,
                               const unsigned char *source,
                               size_t source_length) {
  int plain_text_length = source_length;
  int final_length = 0;
  unsigned char *plain_text = (unsigned char *)malloc(plain_text_length);
  if (plain_text == NULL) {
    return NULL;
  }
  if (EVP_DecryptInit_ex(decryption_context, NULL, NULL, NULL, NULL) != 1 ||
      EVP_DecryptUpdate(decryption_context, plain_text, &plain_text_length,
                        source, source_length) != 1 ||
      EVP_DecryptFinal_ex(decryption_context, plain_text + plain_text_length,
                          &final_length) != 1) {
    free(plain_text);
    return NULL;
  }

  hashkit_string_st *destination =
      hashkit_string_create(plain_text_length + final_length);
  if (destination == NULL) {
    return NULL;
  }
  char *dest = hashkit_string_c_str_mutable(destination);
  memcpy(dest, plain_text, plain_text_length + final_length);
  hashkit_string_set_length(destination, plain_text_length + final_length);
  return destination;
}

