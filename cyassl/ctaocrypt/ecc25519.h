/* ecc25519.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_ECC25519

#ifndef CTAO_CRYPT_ECC25519_H
#define CTAO_CRYPT_ECC25519_H

#include <cyassl/ctaocrypt/ecc25519_fe.h>
#include <cyassl/ctaocrypt/types.h>
#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ctaocrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define ECC25519_KEYSIZE 32

/* ECC set type */
typedef struct {
    int size;       /* The size of the curve in octets */
    const char* name;     /* name of this curve */
} ecc25519_set_type;


/* ECC point */
typedef struct {
    byte point[ECC25519_KEYSIZE];
}ECPoint;

/* ECC Point Format */
enum {
    montgomery_x_le = 0x41, /* TODO value to be determined */
};

/* An ECC25519 Key */
typedef struct {
    int type;           /* Public or Private */
    int idx;            /* Index into the ecc_sets[] for the parameters of
                           this curve if -1, this key is using user supplied
                           curve in dp */
    const ecc25519_set_type* dp;   /* domain parameters, either points to
                                   curves (idx >= 0) or user supplied */
    byte      f;        /* format of key */
    ECPoint   p;        /* public key  */
    ECPoint   k;        /* private key */
} ecc25519_key;

CYASSL_API
int ecc25519_make_key(RNG* rng, int keysize, ecc25519_key* key);

CYASSL_API
int ecc25519_shared_secret(ecc25519_key* private_key, ecc25519_key* public_key,
        byte* out, word32* outlen);

CYASSL_API
int ecc25519_init(ecc25519_key* key);

CYASSL_API
void ecc25519_free(ecc25519_key* key);


/* raw key helpers */
CYASSL_API
int ecc25519_import_private_raw(const byte* priv, word32 privSz,
                              const byte* pub, word32 pubSz, ecc25519_key* key);
CYASSL_API
int ecc25519_export_private_raw(ecc25519_key* key, byte* out, word32* outLen);

CYASSL_API
int ecc25519_import_public(const byte* in, word32 inLen, ecc25519_key* key);

CYASSL_API
int ecc25519_export_public(ecc25519_key* key, byte* out, word32* outLen);


/* size helper */
CYASSL_API
int ecc25519_size(ecc25519_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ECC25519_H */
#endif /* HAVE_ECC25519 */

