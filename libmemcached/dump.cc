/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011 Data Differential, http://datadifferential.com/
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *      * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *  copyright notice, this list of conditions and the following disclaimer
 *  in the documentation and/or other materials provided with the
 *  distribution.
 *
 *      * The names of its contributors may not be used to endorse or
 *  promote products derived from this software without specific prior
 *  written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
  We use this to dump all keys.

  At this point we only support a callback method. This could be optimized by first
  calling items and finding active slabs. For the moment though we just loop through
  all slabs on servers and "grab" the keys.
*/

#include <libmemcached/common.h>

static memcached_return_t ascii_dump(memcached_st *ptr, memcached_dump_fn *callback, void *context, uint32_t number_of_callbacks)
{
  memcached_return_t rc= MEMCACHED_SUCCESS;

  for (uint32_t server_key= 0; server_key < memcached_server_count(ptr); server_key++)
  {
    memcached_server_write_instance_st instance;
    instance= memcached_server_instance_fetch(ptr, server_key);

    /* 256 I BELIEVE is the upper limit of slabs */
    for (uint32_t x= 0; x < 256; x++)
    {
      char buffer[MEMCACHED_DEFAULT_COMMAND_SIZE];
      int buffer_length= snprintf(buffer, sizeof(buffer), "%u", x);
      if (buffer_length >= MEMCACHED_DEFAULT_COMMAND_SIZE or buffer_length < 0)
      {
        return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, 
                                   memcached_literal_param("snprintf(MEMCACHED_DEFAULT_COMMAND_SIZE)"));
      }

      libmemcached_io_vector_st vector[]=
      {
        { memcached_literal_param("stats cachedump ") },
        { buffer, buffer_length },
        { memcached_literal_param(" 0 0\r\n") }
      };

      rc= memcached_vdo(instance, vector, 3, true);

      if (rc != MEMCACHED_SUCCESS)
      {
        goto error;
      }

      while (1)
      {
        uint32_t callback_counter;
        rc= memcached_response(instance, buffer, MEMCACHED_DEFAULT_COMMAND_SIZE, NULL);

        if (rc == MEMCACHED_ITEM)
        {
          char *string_ptr, *end_ptr;

          string_ptr= buffer;
          string_ptr+= 5; /* Move past ITEM */

          for (end_ptr= string_ptr; isgraph(*end_ptr); end_ptr++) {} ;

          char *key= string_ptr;
          key[(size_t)(end_ptr-string_ptr)]= 0;

          for (callback_counter= 0; callback_counter < number_of_callbacks; callback_counter++)
          {
            rc= (*callback[callback_counter])(ptr, key, (size_t)(end_ptr-string_ptr), context);
            if (rc != MEMCACHED_SUCCESS)
            {
              break;
            }
          }
        }
        else if (rc == MEMCACHED_END)
        {
          break;
        }
        else if (rc == MEMCACHED_SERVER_ERROR or rc == MEMCACHED_CLIENT_ERROR)
        {
          /* If we try to request stats cachedump for a slab class that is too big
           * the server will return an incorrect error message:
           * "MEMCACHED_SERVER_ERROR failed to allocate memory"
           * This isn't really a fatal error, so let's just skip it. I want to
           * fix the return value from the memcached server to a CLIENT_ERROR,
           * so let's add support for that as well right now.
         */
          rc= MEMCACHED_END;
          break;
        }
        else
        {
          goto error;
        }
      }
    }
  }

error:
  if (rc == MEMCACHED_END)
  {
    return MEMCACHED_SUCCESS;
  }
  else
  {
    return rc;
  }
}

memcached_return_t memcached_dump(memcached_st *ptr, memcached_dump_fn *callback, void *context, uint32_t number_of_callbacks)
{
  memcached_return_t rc;
  if (memcached_failed(rc= initialize_query(ptr, true)))
  {
    return rc;
  }

  /* 
    No support for Binary protocol yet
    @todo Fix this so that we just flush, switch to ascii, and then go back to binary.
  */
  if (ptr->flags.binary_protocol)
  {
    return MEMCACHED_FAILURE;
  }

  return ascii_dump(ptr, callback, context, number_of_callbacks);
}
