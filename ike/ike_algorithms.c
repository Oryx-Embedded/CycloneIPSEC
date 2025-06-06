/**
 * @file ike_algorithms.c
 * @brief IKEv2 algorithm negotiation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneIPSEC Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ike/ike.h"
#include "ike/ike_algorithms.h"
#include "ah/ah_algorithms.h"
#include "esp/esp_algorithms.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief List of supported key exchange algorithms
 **/

static const uint16_t ikeSupportedKeAlgos[] =
{
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_CURVE25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_CURVE25519,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_CURVE448_SUPPORT == ENABLED)
   //Curve448 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_CURVE448,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_256_SUPPORT == ENABLED)
   //NIST P-256 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_ECP_256,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_384_SUPPORT == ENABLED)
   //NIST P-384 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_ECP_384,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_521_SUPPORT == ENABLED)
   //NIST P-521 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_ECP_521,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_224_SUPPORT == ENABLED)
   //NIST P-224 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_ECP_224,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_192_SUPPORT == ENABLED)
   //NIST P-192 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_ECP_192,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP256R1,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP384R1,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP512R1,
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_BRAINPOOLP224R1_SUPPORT == ENABLED)
   //brainpoolP224r1 elliptic curve
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP224R1,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 2048 && \
   IKE_MIN_DH_MODULUS_SIZE <= 2048)
   //Diffie-Hellman group 14
   IKE_TRANSFORM_ID_DH_GROUP_MODP_2048,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 3072 && \
   IKE_MIN_DH_MODULUS_SIZE <= 3072)
   //Diffie-Hellman group 15
   IKE_TRANSFORM_ID_DH_GROUP_MODP_3072,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 4096 && \
   IKE_MIN_DH_MODULUS_SIZE <= 4096)
   //Diffie-Hellman group 16
   IKE_TRANSFORM_ID_DH_GROUP_MODP_4096,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 6144 && \
   IKE_MIN_DH_MODULUS_SIZE <= 6144)
   //Diffie-Hellman group 17
   IKE_TRANSFORM_ID_DH_GROUP_MODP_6144,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 8192 && \
   IKE_MIN_DH_MODULUS_SIZE <= 8192)
   //Diffie-Hellman group 18
   IKE_TRANSFORM_ID_DH_GROUP_MODP_8192,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 1536 && \
   IKE_MIN_DH_MODULUS_SIZE <= 1536)
   //Diffie-Hellman group 5
   IKE_TRANSFORM_ID_DH_GROUP_MODP_1536,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 1024 && \
   IKE_MIN_DH_MODULUS_SIZE <= 1024)
   //Diffie-Hellman group 2
   IKE_TRANSFORM_ID_DH_GROUP_MODP_1024,
#endif
#if (IKE_DH_KE_SUPPORT == ENABLED && IKE_MAX_DH_MODULUS_SIZE >= 768 && \
   IKE_MIN_DH_MODULUS_SIZE <= 768)
   //Diffie-Hellman group 1
   IKE_TRANSFORM_ID_DH_GROUP_MODP_768,
#endif
};


/**
 * @brief List of supported encryption algorithms
 **/

static const IkeEncAlgo ikeSupportedEncAlgos[] =
{
#if (IKE_CHACHA20_POLY1305_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305, 0},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 32},
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 16},
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 24},
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 32},
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 16},
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 24},
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 32},
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 16},
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 24},
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 32},
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 16},
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 24},
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 32},
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 16},
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 24},
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 32},
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 16},
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 24},
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 32},
#endif
#if (IKE_3DES_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_3DES, 0},
#endif
#if (IKE_DES_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_DES, 0},
#endif
#if (IKE_IDEA_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_IDEA, 0},
#endif
};


/**
 * @brief List of supported integrity algorithms
 **/

static const uint16_t ikeSupportedAuthAlgos[] =
{
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128,
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192,
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256,
#endif
#if (IKE_CMAC_AUTH_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_AES_CMAC_96,
#endif
#if (IKE_XCBC_MAC_AUTH_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_AES_XCBC_96,
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96,
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_MD5_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96,
#endif
   0
};


/**
 * @brief List of supported pseudorandom functions
 **/

static const uint16_t ikeSupportedPrfAlgos[] =
{
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256,
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384,
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512,
#endif
#if (IKE_CMAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_AES128_CMAC,
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_AES128_XCBC,
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_TIGER_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_TIGER,
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_SHA1,
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_MD5_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_PRF_HMAC_MD5,
#endif
};


/**
 * @brief Select the relevant encryption algorithm
 * @param[in] sa Pointer to the IKE SA
 * @param[in] encAlgoId Encryption algorithm identifier
 * @param[in] encKeyLen Length of the encryption key, in bytes
 * @return Error code
 **/

error_t ikeSelectEncAlgo(IkeSaEntry *sa, uint16_t encAlgoId,
   size_t encKeyLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_IDEA_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //IDEA-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_IDEA)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = IDEA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->ivLen = IDEA_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_DES_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //DES-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_DES)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = DES_CIPHER_ALGO;
      sa->encKeyLen = 8;
      sa->ivLen = DES_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_3DES_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //3DES-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_3DES)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = DES3_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->ivLen = DES3_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //AES-CBC with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //AES-CBC with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //AES-CBC with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //AES-CTR with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //AES-CTR with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //AES-CTR with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_AES_128_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_AES_192_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_AES_256_SUPPORT == ENABLED && IKE_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_GCM;
      sa->cipherAlgo = AES_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CBC;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CTR;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->saltLen = 4;
      sa->ivLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 8;
   }
   else
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_CAMELLIA_128_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 16)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 16;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_CAMELLIA_192_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 24)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 24;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_CAMELLIA_256_SUPPORT == ENABLED && IKE_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 32)
   {
      sa->cipherMode = CIPHER_MODE_CCM;
      sa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 3;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305)
   {
      sa->cipherMode = CIPHER_MODE_CHACHA20_POLY1305;
      sa->cipherAlgo = NULL;
      sa->encKeyLen = 32;
      sa->authKeyLen = 0;
      sa->saltLen = 4;
      sa->ivLen = 8;
      sa->icvLen = 16;
   }
   else
#endif
   //Unknown encryption algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the relevant MAC algorithm
 * @param[in] sa Pointer to the IKE SA
 * @param[in] authAlgoId Authentication algorithm identifier
 * @return Error code
 **/

error_t ikeSelectAuthAlgo(IkeSaEntry *sa, uint16_t authAlgoId)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_CMAC_AUTH_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-CMAC-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_CMAC_96)
   {
      sa->authHashAlgo = NULL;
      sa->authCipherAlgo = AES_CIPHER_ALGO;
      sa->authKeyLen = 16;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_MD5_SUPPORT == ENABLED)
   //HMAC-MD5-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96)
   {
      sa->authHashAlgo = MD5_HASH_ALGO;
      sa->authCipherAlgo = NULL;
      sa->authKeyLen = MD5_DIGEST_SIZE;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96)
   {
      sa->authHashAlgo = SHA1_HASH_ALGO;
      sa->authCipherAlgo = NULL;
      sa->authKeyLen = SHA1_DIGEST_SIZE;
      sa->icvLen = 12;
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256-128 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128)
   {
      sa->authHashAlgo = SHA256_HASH_ALGO;
      sa->authCipherAlgo = NULL;
      sa->authKeyLen = SHA256_DIGEST_SIZE;
      sa->icvLen = 16;
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384-192 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192)
   {
      sa->authHashAlgo = SHA384_HASH_ALGO;
      sa->authCipherAlgo = NULL;
      sa->authKeyLen = SHA384_DIGEST_SIZE;
      sa->icvLen = 24;
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512-256 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256)
   {
      sa->authHashAlgo = SHA512_HASH_ALGO;
      sa->authCipherAlgo = NULL;
      sa->authKeyLen = SHA512_DIGEST_SIZE;
      sa->icvLen = 32;
   }
   else
#endif
#if (IKE_XCBC_MAC_AUTH_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-XCBC-MAC-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_XCBC_96)
   {
      sa->authHashAlgo = NULL;
      sa->authCipherAlgo = AES_CIPHER_ALGO;
      sa->authKeyLen = 16;
      sa->icvLen = 12;
   }
   else
#endif
   //Unknown authentication algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the relevant PRF algorithm
 * @param[in] sa Pointer to the IKE SA
 * @param[in] prfAlgoId PRF algorithm identifier
 * @return Error code
 **/

error_t ikeSelectPrfAlgo(IkeSaEntry *sa, uint16_t prfAlgoId)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_CMAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-CMAC PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC)
   {
      sa->prfHashAlgo = NULL;
      sa->prfCipherAlgo = AES_CIPHER_ALGO;
      sa->prfKeyLen = 16;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_MD5_SUPPORT == ENABLED)
   //HMAC-MD5 PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_MD5)
   {
      sa->prfHashAlgo = MD5_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = MD5_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1 PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA1)
   {
      sa->prfHashAlgo = SHA1_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = SHA1_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256 PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256)
   {
      sa->prfHashAlgo = SHA256_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = SHA256_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384 PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384)
   {
      sa->prfHashAlgo = SHA384_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = SHA384_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512 PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512)
   {
      sa->prfHashAlgo = SHA512_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = SHA512_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_TIGER_SUPPORT == ENABLED)
   //HMAC-Tiger PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_TIGER)
   {
      sa->prfHashAlgo = TIGER_HASH_ALGO;
      sa->prfCipherAlgo = NULL;
      sa->prfKeyLen = TIGER_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-XCBC-MAC PRF algorithm?
   if(prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC)
   {
      sa->prfHashAlgo = NULL;
      sa->prfCipherAlgo = AES_CIPHER_ALGO;
      sa->prfKeyLen = 16;
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported transforms to the proposal
 * @param[in] transformType Transform type
 * @param[in] transformId Transform identifier
 * @param[in] keyLen Key length attribute (for encryption algorithms with
 *   variable-length keys)
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddTransform(IkeTransformType transformType, uint16_t transformId,
   uint16_t keyLen, IkeProposal *proposal, uint8_t **lastSubstruc)
{
   size_t n;
   size_t length;
   uint8_t *p;
   IkeTransform *transform;
   IkeTransformAttr *attr;

   //Get the length of the Proposal substructure
   length = ntohs(proposal->proposalLength);
   //Point to the buffer where to format the Transform substructure
   p = (uint8_t *) proposal + length;

   //The Last Substruc field has a value of 2 if there are more Transform
   //substructures
   if(*lastSubstruc != NULL)
   {
      **lastSubstruc = IKE_LAST_SUBSTRUC_MORE_TRANSFORMS;
   }

   //Point to the Transform substructure
   transform = (IkeTransform *) p;

   //Format Transform substructure
   transform->lastSubstruc = IKE_LAST_SUBSTRUC_LAST;
   transform->reserved1 = 0;
   transform->transformType = transformType;
   transform->reserved2 = 0;
   transform->transformId = htons(transformId);

   //Length of the Transform substructure
   n = sizeof(IkeTransform);

   //Encryption algorithm with variable-length keys?
   if(transformType == IKE_TRANSFORM_TYPE_ENCR &&
      ikeIsVariableLengthKeyEncAlgo(transformId))
   {
      //The Key Length attribute is used by certain encryption transforms
      //with variable-length keys (refer to RFC 7296, section 3.3.2)
      attr = (IkeTransformAttr *) transform->transformAttr;

      //The Key Length attribute uses Type/value format
      attr->type = HTONS((uint16_t) IKE_ATTR_FORMAT_TV |
         (uint16_t) IKE_TRANSFORM_ATTR_TYPE_KEY_LEN);

      //The value of the attribute specifies the length of the key, in bits
      attr->length = htons(keyLen * 8);

      //Adjust the length of the Transform substructure
      n += sizeof(IkeTransformAttr);
   }

   //The Transform Length field indicates the length of the Transform
   //substructure including header and attributes
   transform->transformLength = htons(n);

   //Keep track of the Last Substruc field
   *lastSubstruc = &transform->lastSubstruc;

   //Increment the number of transforms
   proposal->numTransforms++;

   //Adjust the length of the Proposal substructure
   length += n;
   //Save the actual length of the Proposal substructure
   proposal->proposalLength = htons(length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Add the supported IKE transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddSupportedTransforms(IkeContext *context, IkeProposal *proposal,
   uint8_t **lastSubstruc)
{
   error_t error;

   //Add supported encryption transforms
   error = ikeAddSupportedEncTransforms(context, proposal, lastSubstruc);

   //Check status code
   if(!error)
   {
      //Add supported PRF transforms
      error = ikeAddSupportedPrfTransforms(context, proposal, lastSubstruc);
   }

   //Check status code
   if(!error)
   {
      //Add supported integrity transforms
      error = ikeAddSupportedAuthTransforms(context, proposal, lastSubstruc);
   }

   //Check status code
   if(!error)
   {
      //Add supported key exchange transforms
      error = ikeAddSupportedKeTransforms(context, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported key exchange transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddSupportedKeTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported key exchange transforms
   for(i = 0; i < arraysize(ikeSupportedKeAlgos) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_DH,
         ikeSupportedKeAlgos[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported encryption transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddSupportedEncTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported encryption transforms
   for(i = 0; i < arraysize(ikeSupportedEncAlgos) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_ENCR,
         ikeSupportedEncAlgos[i].id, ikeSupportedEncAlgos[i].keyLen,
         proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported integrity transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddSupportedAuthTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported integrity transforms
   for(i = 0; i < (arraysize(ikeSupportedAuthAlgos) - 1) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG,
         ikeSupportedAuthAlgos[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported PRF transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ikeAddSupportedPrfTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported PRF transforms
   for(i = 0; i < arraysize(ikeSupportedPrfAlgos) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_PRF,
         ikeSupportedPrfAlgos[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Get the number of transforms that match a given transform type
 * @param[in] transformType Transform type
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Number of transforms
 **/

uint_t ikeGetNumTransforms(IkeTransformType transformType,
   const IkeProposal *proposal, size_t proposalLen)
{
   uint_t i;
   size_t n;
   size_t length;
   uint_t numTransforms;
   const uint8_t *p;
   IkeTransform *transform;

   //Number of transforms
   numTransforms = 0;

   //Check the length of the Proposal substructure
   if(proposalLen >= sizeof(IkeProposal) &&
      proposalLen >= (sizeof(IkeProposal) + proposal->spiSize))
   {
      //Get the length of the Proposal substructure
      length = proposalLen - sizeof(IkeProposal) - proposal->spiSize;
      //Point to the first Transform substructure
      p = (uint8_t *) proposal + sizeof(IkeProposal) + proposal->spiSize;

      //Loop through the list of algorithms supported by the peer
      for(i = 0; i < proposal->numTransforms; i++)
      {
         //Malformed substructure?
         if(length < sizeof(IkeTransform))
            break;

         //Point to the Transform substructure
         transform = (IkeTransform *) p;

         //The Transform Length field indicates the length of the Transform
         //substructure including header and attributes
         n = ntohs(transform->transformLength);

         //Check the length of the transform
         if(n < sizeof(IkeTransform) || n > length)
            break;

         //Check transform type
         if(transform->transformType == transformType)
         {
            numTransforms++;
         }

         //The Last Substruc field has a value of 0 if this was the last
         //Transform Substructure
         if(transform->lastSubstruc == IKE_LAST_SUBSTRUC_LAST)
            break;

         //Jump to the next Transform substructure
         p += n;
         length -= n;
      }
   }

   //Return the number of transforms
   return numTransforms;
}


/**
 * @brief Transform negotiation
 * @param[in] transformType Transform type
 * @param[in] algoList List of algorithms
 * @param[in] algoListLen Number of items in the list
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected transform, if any
 **/

uint16_t ikeSelectTransform(IkeTransformType transformType,
   const uint16_t *algoList, uint_t algoListLen, const IkeProposal *proposal,
   size_t proposalLen)
{
   uint_t i;
   uint_t j;
   size_t n;
   size_t length;
   bool_t found;
   const uint8_t *p;
   uint16_t selectedAlgo;
   IkeTransform *transform;

   //Initialize flag
   found = FALSE;

   //Key exchange transform negotiation?
   if(transformType == IKE_TRANSFORM_TYPE_DH)
   {
      selectedAlgo = IKE_TRANSFORM_ID_DH_GROUP_NONE;
   }
   else
   {
      selectedAlgo = IKE_TRANSFORM_ID_INVALID;
   }

   //Check the length of the Proposal substructure
   if(proposalLen >= sizeof(IkeProposal) &&
      proposalLen >= (sizeof(IkeProposal) + proposal->spiSize))
   {
      //Loop through the list of algorithms supported by the entity
      for(i = 0; i < algoListLen && !found; i++)
      {
         //Get the length of the Proposal substructure
         length = proposalLen - sizeof(IkeProposal) - proposal->spiSize;
         //Point to the first Transform substructure
         p = (uint8_t *) proposal + sizeof(IkeProposal) + proposal->spiSize;

         //Loop through the list of algorithms supported by the peer
         for(j = 0; j < proposal->numTransforms && !found; j++)
         {
            //Malformed substructure?
            if(length < sizeof(IkeTransform))
               break;

            //Point to the Transform substructure
            transform = (IkeTransform *) p;

            //The Transform Length field indicates the length of the Transform
            //substructure including header and attributes
            n = ntohs(transform->transformLength);

            //Check the length of the transform
            if(n < sizeof(IkeTransform) || n > length)
               break;

            //Check transform type
            if(transform->transformType == transformType)
            {
               //Check transform identifier
               if(ntohs(transform->transformId) == algoList[i])
               {
                  selectedAlgo = algoList[i];
                  found = TRUE;
               }
            }

            //The Last Substruc field has a value of 0 if this was the last
            //Transform Substructure
            if(transform->lastSubstruc == IKE_LAST_SUBSTRUC_LAST)
               break;

            //Jump to the next Transform substructure
            p += n;
            length -= n;
         }
      }
   }

   //Return the chosen algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Key exchange transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected key exchange transform, if any
 **/

uint16_t ikeSelectKeTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the key exchange transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_DH, ikeSupportedKeAlgos,
      arraysize(ikeSupportedKeAlgos), proposal, proposalLen);
}


/**
 * @brief Encryption transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected encryption transform, if any
 **/

const IkeEncAlgo *ikeSelectEncTransform(IkeContext *context,
   const IkeProposal *proposal, size_t proposalLen)
{
   uint_t i;
   uint_t j;
   size_t n;
   size_t length;
   uint8_t *p;
   uint16_t transformId;
   const IkeEncAlgo *selectedAlgo;
   const IkeTransform *transform;
   const IkeTransformAttr *attr;

   //Chosen algorithm
   selectedAlgo = NULL;

   //Check the length of the Proposal substructure
   if(proposalLen >= sizeof(IkeProposal) &&
      proposalLen >= (sizeof(IkeProposal) + proposal->spiSize))
   {
      //Loop through the list of algorithms supported by the entity
      for(i = 0; i < arraysize(ikeSupportedEncAlgos) && selectedAlgo == NULL; i++)
      {
         //Get the length of the Proposal substructure
         length = proposalLen - sizeof(IkeProposal) - proposal->spiSize;
         //Point to the first Transform substructure
         p = (uint8_t *) proposal + sizeof(IkeProposal) + proposal->spiSize;

         //Loop through the list of algorithms supported by the peer
         for(j = 0; j < proposal->numTransforms && selectedAlgo == NULL; j++)
         {
            //Malformed substructure?
            if(length < sizeof(IkeTransform))
               break;

            //Point to the Transform substructure
            transform = (IkeTransform *) p;

            //The Transform Length field indicates the length of the Transform
            //substructure including header and attributes
            n = ntohs(transform->transformLength);

            //Check the length of the transform
            if(n < sizeof(IkeTransform) || n > length)
               break;

            //Check transform type
            if(transform->transformType == IKE_TRANSFORM_TYPE_ENCR)
            {
               //Convert the Transform ID field to host byte order
               transformId = ntohs(transform->transformId);

               //Variable-length key encryption algorithm?
               if(ikeIsVariableLengthKeyEncAlgo(transformId))
               {
                  //For algorithms that accept a variable-length key, a fixed
                  //key size must be specified as part of the cryptographic
                  //transform negotiated (refer to RFC 7296, section 2.13)
                  if(n == (sizeof(IkeTransform) + sizeof(IkeTransformAttr)))
                  {
                     //Point to the transform attribute
                     attr = (IkeTransformAttr *) transform->transformAttr;

                     //Check attribute format and type
                     if(ntohs(attr->type) == ((uint16_t) IKE_ATTR_FORMAT_TV |
                        (uint16_t) IKE_TRANSFORM_ATTR_TYPE_KEY_LEN))
                     {
                        //Check transform identifier and key length
                        if(transformId == ikeSupportedEncAlgos[i].id &&
                           ntohs(attr->length) == (ikeSupportedEncAlgos[i].keyLen * 8))
                        {
                           selectedAlgo = &ikeSupportedEncAlgos[i];
                        }
                     }
                  }
               }
               else
               {
                  //The Key Length attribute must not be used with transforms
                  //that use a fixed-length key (refer to RFC 7296, section 3.3.5)
                  if(n == sizeof(IkeTransform))
                  {
                     //Check transform identifier
                     if(transformId == ikeSupportedEncAlgos[i].id)
                     {
                        selectedAlgo = &ikeSupportedEncAlgos[i];
                     }
                  }
               }
            }

            //The Last Substruc field has a value of 0 if this was the last
            //Transform Substructure
            if(transform->lastSubstruc == IKE_LAST_SUBSTRUC_LAST)
               break;

            //Jump to the next Transform substructure
            p += n;
            length -= n;
         }
      }
   }

   //Return the chosen algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Integrity transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected integrity transform, if any
 **/

uint16_t ikeSelectAuthTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the integrity transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_INTEG, ikeSupportedAuthAlgos,
      arraysize(ikeSupportedAuthAlgos) - 1, proposal, proposalLen);
}


/**
 * @brief PRF transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected PRF transform, if any
 **/

uint16_t ikeSelectPrfTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the key exchange transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_PRF, ikeSupportedPrfAlgos,
      arraysize(ikeSupportedPrfAlgos), proposal, proposalLen);
}


/**
 * @brief Select a single proposal (IKE protocol)
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payload Pointer to the Security Association payload
 * @param[in] spiSize Expected SPI size, in bytes
 * @return Error code
 **/

error_t ikeSelectSaProposal(IkeSaEntry *sa, const IkeSaPayload *payload,
   size_t spiSize)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;
   const IkeEncAlgo *encAlgo;

   //Clear the set of parameters
   sa->dhGroupNum = IKE_TRANSFORM_ID_DH_GROUP_NONE;
   sa->prfAlgoId = IKE_TRANSFORM_ID_INVALID;
   sa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   sa->encKeyLen = 0;
   sa->authAlgoId = IKE_TRANSFORM_ID_INVALID;

   //Retrieve the length of the SA payload
   length = ntohs(payload->header.payloadLength);

   //Malformed payload?
   if(length < sizeof(IkeSaPayload))
      return ERROR_INVALID_MESSAGE;

   //Point to the first byte of the Proposals field
   p = payload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //Initialize status code
   error = ERROR_INVALID_PROPOSAL;

   //The Security Association payload contains one or more Proposal
   //substructures
   while(1)
   {
      //Malformed payload?
      if(length < sizeof(IkeProposal))
      {
         //Report an error
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Point to the Proposal substructure
      proposal = (IkeProposal *) p;

      //The Proposal Length field indicates the length of this proposal,
      //including all transforms and attributes that follow
      n = ntohs(proposal->proposalLength);

      //Check the length of the proposal
      if(n < sizeof(IkeProposal) || n > length)
      {
         //Report an error
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Check protocol identifier
      if(proposal->protocolId == IKE_PROTOCOL_ID_IKE &&
         proposal->spiSize == spiSize)
      {
         //Key exchange transform negotiation
         sa->dhGroupNum = ikeSelectKeTransform(sa->context, proposal, n);
         //PRF transform negotiation
         sa->prfAlgoId = ikeSelectPrfTransform(sa->context, proposal, n);
         //Encryption transform negotiation
         encAlgo = ikeSelectEncTransform(sa->context, proposal, n);

         //Valid encryption transform?
         if(encAlgo != NULL)
         {
            sa->encAlgoId = encAlgo->id;
            sa->encKeyLen = encAlgo->keyLen;
         }
         else
         {
            sa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
            sa->encKeyLen = 0;
         }

         //AEAD algorithm?
         if(ikeIsAeadEncAlgo(sa->encAlgoId))
         {
            //When an authenticated encryption algorithm is selected as the
            //encryption algorithm for any SA, an integrity algorithm must not
            //be selected for that SA (refer to RFC 5282, section 8)
            sa->authAlgoId = IKE_TRANSFORM_ID_AUTH_NONE;
         }
         else
         {
            //Integrity transform negotiation
            sa->authAlgoId = ikeSelectAuthTransform(sa->context, proposal, n);
         }

         //Valid proposal?
         if(sa->dhGroupNum != IKE_TRANSFORM_ID_DH_GROUP_NONE &&
            sa->prfAlgoId != IKE_TRANSFORM_ID_INVALID &&
            sa->encAlgoId != IKE_TRANSFORM_ID_INVALID &&
            sa->authAlgoId != IKE_TRANSFORM_ID_INVALID)
         {
            //Save the number of the proposal that was accepted
            sa->acceptedProposalNum = proposal->proposalNum;

            //A new initiator SPI is supplied in the SPI field of the SA
            //payload (refer to RFC 7296, section 1.3.2)
            if(spiSize != 0)
            {
               osMemcpy(sa->initiatorSpi, proposal->spi, IKE_SPI_SIZE);
            }

            //Successful negotiation
            error = NO_ERROR;
            break;
         }
      }

      //Jump to the next proposal
      p += n;
      length -= n;
   }

   //Return status code
   return error;
}


/**
 * @brief Select a single proposal (AH or ESP protocol)
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/


error_t ikeSelectChildSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload)
{
   error_t error;

#if (AH_SUPPORT == ENABLED)
   //AH protocol identifier?
   if(childSa->protocol == IPSEC_PROTOCOL_AH)
   {
      error = ahSelectSaProposal(childSa, payload);
   }
   else
#endif
#if (ESP_SUPPORT == ENABLED)
   //ESP protocol identifier?
   if(childSa->protocol == IPSEC_PROTOCOL_ESP)
   {
      error = espSelectSaProposal(childSa, payload);
   }
   else
#endif
   //Unknown protocol identifier?
   {
      error = ERROR_INVALID_PROTOCOL;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the selected proposal is acceptable (IKE protocol)
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ikeCheckSaProposal(IkeSaEntry *sa, const IkeSaPayload *payload)
{
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;
   const IkeEncAlgo *encAlgo;

   //Clear the set of parameters
   sa->prfAlgoId = IKE_TRANSFORM_ID_INVALID;
   sa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   sa->encKeyLen = 0;
   sa->authAlgoId = IKE_TRANSFORM_ID_INVALID;

   //Retrieve the length of the SA payload
   length = ntohs(payload->header.payloadLength);

   //Malformed payload?
   if(length < sizeof(IkeSaPayload))
      return ERROR_INVALID_MESSAGE;

   //Point to the first byte of the Proposals field
   p = payload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //Malformed payload?
   if(length < sizeof(IkeProposal))
      return ERROR_INVALID_MESSAGE;

   //Point to the Proposal substructure
   proposal = (IkeProposal *) p;

   //The Proposal Length field indicates the length of this proposal,
   //including all transforms and attributes that follow
   n = ntohs(proposal->proposalLength);

   //The responder must accept a single proposal (refer to RFC 7296,
   //section 2.7)
   if(n != length)
      return ERROR_INVALID_MESSAGE;

   //Check protocol identifier
   if(proposal->protocolId != IKE_PROTOCOL_ID_IKE)
      return ERROR_INVALID_MESSAGE;

   //Initial IKE SA negotiation?
   if(sa->state == IKE_SA_STATE_INIT_RESP)
   {
      //For an initial IKE SA negotiation, the SPI Size field must be zero
      if(proposal->spiSize != 0)
         return ERROR_INVALID_MESSAGE;
   }
   else
   {
      //During subsequent negotiations, it is equal to the size, in octets,
      //of the SPI of the corresponding protocol (8 for IKE)
      if(proposal->spiSize != IKE_SPI_SIZE)
         return ERROR_INVALID_MESSAGE;

      //A new responder SPI is supplied in the SPI field of the SA payload
      //(refer to RFC 7296, section 1.3.2)
      osMemcpy(sa->responderSpi, proposal->spi, IKE_SPI_SIZE);
   }

   //The accepted cryptographic suite must contain exactly one transform of
   //each type included in the proposal (refer to RFC 7296, section 2.7)
   if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_DH, proposal, n) != 1 ||
      ikeGetNumTransforms(IKE_TRANSFORM_TYPE_PRF, proposal, n) != 1 ||
      ikeGetNumTransforms(IKE_TRANSFORM_TYPE_ENCR, proposal, n) != 1)
   {
      return ERROR_INVALID_PROPOSAL;
   }

   //Make sure the selected Diffie-Hellman group is acceptable
   if(ikeSelectKeTransform(sa->context, proposal, n) != sa->dhGroupNum)
      return ERROR_INVALID_PROPOSAL;

   //Get the selected PRF transform
   sa->prfAlgoId = ikeSelectPrfTransform(sa->context, proposal, n);
   //Get the selected encryption transform
   encAlgo = ikeSelectEncTransform(sa->context, proposal, n);

   //Valid encryption transform?
   if(encAlgo != NULL)
   {
      sa->encAlgoId = encAlgo->id;
      sa->encKeyLen = encAlgo->keyLen;
   }

   //AEAD algorithm?
   if(ikeIsAeadEncAlgo(sa->encAlgoId))
   {
      //When an authenticated encryption algorithm is selected as the encryption
      //algorithm for any SA, an integrity algorithm must not be selected for
      //that SA (refer to RFC 5282, section 8)
      if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_INTEG, proposal, n) != 0)
         return ERROR_INVALID_PROPOSAL;

      //AEAD algorithms combine encryption and integrity into a single operation
      sa->authAlgoId = IKE_TRANSFORM_ID_AUTH_NONE;
   }
   else
   {
      //Exactly one integrity transform must be included in the proposal
      if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_INTEG, proposal, n) != 1)
         return ERROR_INVALID_PROPOSAL;

      //Get the selected integrity transform
      sa->authAlgoId = ikeSelectAuthTransform(sa->context, proposal, n);
   }

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   if(sa->dhGroupNum != IKE_TRANSFORM_ID_DH_GROUP_NONE &&
      sa->prfAlgoId != IKE_TRANSFORM_ID_INVALID &&
      sa->encAlgoId != IKE_TRANSFORM_ID_INVALID &&
      sa->authAlgoId != IKE_TRANSFORM_ID_INVALID)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_INVALID_PROPOSAL;
   }
}


/**
 * @brief Check whether the selected proposal is acceptable (AH or ESP protocol)
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ikeCheckChildSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload)
{
   error_t error;

#if (AH_SUPPORT == ENABLED)
   //AH protocol identifier?
   if(childSa->protocol == IPSEC_PROTOCOL_AH)
   {
      error = ahCheckSaProposal(childSa, payload);
   }
   else
#endif
#if (ESP_SUPPORT == ENABLED)
   //ESP protocol identifier?
   if(childSa->protocol == IPSEC_PROTOCOL_ESP)
   {
      error = espCheckSaProposal(childSa, payload);
   }
   else
#endif
   //Unknown protocol identifier?
   {
      error = ERROR_INVALID_PROTOCOL;
   }

   //Return status code
   return error;
}


/**
 * @brief Test if the transform ID identifies an AEAD encryption algorithm
 * @param[in] encAlgoId Encryption algorithm identifier
 * @return TRUE if AEAD encryption algorithm, else FALSE
 **/

bool_t ikeIsAeadEncAlgo(uint16_t encAlgoId)
{
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the transform ID identifies a variable-length key encryption algorithm
 * @param[in] encAlgoId Encryption algorithm identifier
 * @return TRUE if variable-length key encryption algorithm, else FALSE
 **/

bool_t ikeIsVariableLengthKeyEncAlgo(uint16_t encAlgoId)
{
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 ||
      encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the group number identifies a DH key exchange algorithm
 * @param[in] groupNum Group number
 * @return TRUE if DH key exchange algorithm, else FALSE
 **/

bool_t ikeIsDhKeyExchangeAlgo(uint16_t groupNum)
{
   //Diffie-Hellman key exchange?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_768 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_1024 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_1536 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_2048 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_3072 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_4096 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_6144 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_8192 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_1024_160 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_224 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_256)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the group number identifies an ECDH key exchange algorithm
 * @param[in] groupNum Group number
 * @return TRUE if ECDH key exchange algorithm, else FALSE
 **/

bool_t ikeIsEcdhKeyExchangeAlgo(uint16_t groupNum)
{
   //ECDH key exchange?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_192 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_224 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_256 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_384 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_521 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP224R1 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP256R1 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP384R1 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP512R1 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE25519 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE448)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the group number identifies an ML-KEM key exchange algorithm
 * @param[in] groupNum Group number
 * @return TRUE if ML-KEM key exchange algorithm, else FALSE
 **/

bool_t ikeIsMlkemKeyExchangeAlgo(uint16_t groupNum)
{
   //ML-KEM key exchange?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ML_KEM_512 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ML_KEM_768 ||
      groupNum == IKE_TRANSFORM_ID_DH_GROUP_ML_KEM_1024)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Get the elliptic curve that matches the specified group number
 * @param[in] groupNum Group number
 * @return Elliptic curve parameters
 **/

const EcCurve *ikeGetEcdhCurve(uint16_t groupNum)
{
   const EcCurve *curve;

#if (IKE_ECDH_KE_SUPPORT == ENABLED)
#if (IKE_ECP_192_SUPPORT == ENABLED)
   //NIST P-192 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_192)
   {
      curve = SECP192R1_CURVE;
   }
   else
#endif
#if (IKE_ECP_224_SUPPORT == ENABLED)
   //NIST P-224 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_224)
   {
      curve = SECP224R1_CURVE;
   }
   else
#endif
#if (IKE_ECP_256_SUPPORT == ENABLED)
   //NIST P-256 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_256)
   {
      curve = SECP256R1_CURVE;
   }
   else
#endif
#if (IKE_ECP_384_SUPPORT == ENABLED)
   //NIST P-384 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_384)
   {
      curve = SECP384R1_CURVE;
   }
   else
#endif
#if (IKE_ECP_521_SUPPORT == ENABLED)
   //NIST P-521 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_ECP_521)
   {
      curve = SECP521R1_CURVE;
   }
   else
#endif
#if (IKE_BRAINPOOLP224R1_SUPPORT == ENABLED)
   //brainpoolP224r1 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP224R1)
   {
      curve = BRAINPOOLP224R1_CURVE;
   }
   else
#endif
#if (IKE_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP256R1)
   {
      curve = BRAINPOOLP256R1_CURVE;
   }
   else
#endif
#if (IKE_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP384R1)
   {
      curve = BRAINPOOLP384R1_CURVE;
   }
   else
#endif
#if (IKE_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP512R1)
   {
      curve = BRAINPOOLP512R1_CURVE;
   }
   else
#endif
#if (IKE_CURVE25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE25519)
   {
      curve = X25519_CURVE;
   }
   else
#endif
#if (IKE_CURVE448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   if(groupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE448)
   {
      curve = X448_CURVE;
   }
   else
#endif
#endif
   //Unknown elliptic curve?
   {
      curve = NULL;
   }

   //Return the elliptic curve parameters, if any
   return curve;
}


/**
 * @brief Get the default Diffie-Hellman group number
 * @return Default Diffie-Hellman group number
 **/

uint16_t ikeSelectDefaultDhGroup(void)
{
   return ikeSupportedKeAlgos[0];
}


/**
 * @brief Check whether a given Diffie-Hellman group is supported
 * @param[in] groupNum Diffie-Hellman group number
 * @return TRUE is the Diffie-Hellman group is supported, else FALSE
 **/

bool_t ikeIsDhGroupSupported(uint16_t groupNum)
{
   uint_t i;
   bool_t acceptable;

   //Initialize flag
   acceptable = FALSE;

   //Loop through the list of Diffie-Hellman groups supported by the entity
   for(i = 0; i < arraysize(ikeSupportedKeAlgos); i++)
   {
      //Compare Diffie-Hellman groups
      if(ikeSupportedKeAlgos[i] == groupNum)
      {
         acceptable = TRUE;
         break;
      }
   }

   //Return TRUE is the Diffie-Hellman group is supported
   return acceptable;
}


/**
 * @brief Check whether a given signature hash algorithm is supported
 * @param[in] hashAlgoId Signature hash algorithm identifier
 * @return TRUE is the signature hash algorithm is supported, else FALSE
 **/

bool_t ikeIsHashAlgoSupported(uint16_t hashAlgoId)
{
   bool_t acceptable;

#if (IKE_SHA1_SUPPORT == ENABLED)
   //SHA-1 hash algorithm identifier?
   if(hashAlgoId == IKE_HASH_ALGO_SHA1)
   {
      acceptable = TRUE;
   }
   else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
   //SHA-256 hash algorithm identifier?
   if(hashAlgoId == IKE_HASH_ALGO_SHA256)
   {
      acceptable = TRUE;
   }
   else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
   //SHA-384 hash algorithm identifier?
   if(hashAlgoId == IKE_HASH_ALGO_SHA384)
   {
      acceptable = TRUE;
   }
   else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
   //SHA-512 hash algorithm identifier?
   if(hashAlgoId == IKE_HASH_ALGO_SHA512)
   {
      acceptable = TRUE;
   }
   else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED || IKE_ED448_SIGN_SUPPORT == ENABLED)
   //"Identity" hash algorithm identifier?
   if(hashAlgoId == IKE_HASH_ALGO_IDENTITY)
   {
      acceptable = TRUE;
   }
   else
#endif
   //Unknown hash algorithm identifier?
   {
      acceptable = FALSE;
   }

   //Return TRUE is the signature hash is supported
   return acceptable;
}

#endif
