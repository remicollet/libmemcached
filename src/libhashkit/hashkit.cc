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

#include <openssl/evp.h>

static inline void _hashkit_init(hashkit_st *self) {
  self->base_hash.function = hashkit_one_at_a_time;
  self->base_hash.context = NULL;

  self->distribution_hash.function = hashkit_one_at_a_time;
  self->distribution_hash.context = NULL;

  self->flags.is_base_same_distributed = true;
  self->use_encryption = false;
}

static inline hashkit_st *_hashkit_create(hashkit_st *self) {
  if (self) {
    self->options.is_allocated = false;
  } else {
    self = (hashkit_st *) calloc(1, sizeof(hashkit_st));
    if (self == NULL) {
      return NULL;
    }

    self->options.is_allocated = true;
  }

  return self;
}

hashkit_st *hashkit_create(hashkit_st *self) {
  self = _hashkit_create(self);
  if (self == NULL) {
    return NULL;
  }

  _hashkit_init(self);

  return self;
}

void hashkit_free(hashkit_st *self) {
  if (self and self->use_encryption) {
    EVP_CIPHER_CTX_free(self->encryption_context);
    EVP_CIPHER_CTX_free(self->decryption_context);
    self->use_encryption = false;
  }

  if (hashkit_is_allocated(self)) {
    free(self);
  }
}

hashkit_st *hashkit_clone(hashkit_st *destination, const hashkit_st *source) {
  if (source == NULL) {
    return hashkit_create(destination);
  }

  /* new_clone will be a pointer to destination */
  destination = _hashkit_create(destination);

  // Should only happen on allocation failure.
  if (destination == NULL) {
    return NULL;
  }

  destination->base_hash = source->base_hash;
  destination->distribution_hash = source->distribution_hash;
  destination->flags = source->flags;
  destination->use_encryption = source->use_encryption;
  if (destination->use_encryption) {
    destination->encryption_context = EVP_CIPHER_CTX_new();
    destination->decryption_context = EVP_CIPHER_CTX_new();
    if (destination->encryption_context == NULL ||
        destination->decryption_context == NULL)
      return NULL;
    EVP_CIPHER_CTX_copy(destination->encryption_context,
                        source->encryption_context);
    EVP_CIPHER_CTX_copy(destination->decryption_context,
                        source->decryption_context);
  }

  return destination;
}

bool hashkit_compare(const hashkit_st *first, const hashkit_st *second) {
  if (not first or not second)
    return false;

  if (first->base_hash.function == second->base_hash.function
      and first->base_hash.context == second->base_hash.context
      and first->distribution_hash.function == second->distribution_hash.function
      and first->distribution_hash.context == second->distribution_hash.context
      and first->flags.is_base_same_distributed == second->flags.is_base_same_distributed)
  {
    return true;
  }

  return false;
}
