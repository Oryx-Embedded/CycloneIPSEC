/**
 * @file esp_algorithms.c
 * @brief ESP algorithm negotiation
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
#define TRACE_LEVEL ESP_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_misc.h"
#include "esp/esp.h"
#include "esp/esp_algorithms.h"
#include "ike/ike_algorithms.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check IPsec library configuration
#if (ESP_SUPPORT == ENABLED)


/**
 * @brief List of supported encryption algorithms
 **/

static const IkeEncAlgo espSupportedEncAlgos[] =
{
#if (ESP_CHACHA20_POLY1305_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305, 0},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8, 32},
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 16},
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 24},
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16, 32},
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 16},
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 24},
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12, 32},
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 16},
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 24},
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CTR, 32},
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 16},
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 24},
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR, 32},
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 16},
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 24},
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_AES_CBC, 32},
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 16},
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 24},
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC, 32},
#endif
#if (ESP_3DES_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_3DES, 0},
#endif
#if (ESP_DES_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_DES, 0},
#endif
#if (ESP_IDEA_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   {IKE_TRANSFORM_ID_ENCR_IDEA, 0},
#endif
};


/**
 * @brief List of supported integrity algorithms
 **/

static const uint16_t espSupportedAuthAlgos[] =
{
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA256_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128,
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA384_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192,
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA512_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256,
#endif
#if (ESP_CMAC_SUPPORT == ENABLED && ESP_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_AES_CMAC_96,
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA1_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96,
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_MD5_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96,
#endif
   0
};


/**
 * @brief List of supported ESN transforms
 **/

static const uint16_t espSupportedEsnTranforms[] =
{
#if (ESP_ESN_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_ESN_YES,
#endif
   IKE_TRANSFORM_ID_ESN_NO
};


/**
 * @brief Select the relevant encryption algorithm
 * @param[in] childSa Pointer to the Child SA
 * @param[in] encAlgoId Encryption algorithm identifier
 * @param[in] encKeyLen Length of the encryption key, in bytes
 * @return Error code
 **/

error_t espSelectEncAlgo(IkeChildSaEntry *childSa, uint16_t encAlgoId,
   size_t encKeyLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (ESP_IDEA_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //IDEA-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_IDEA)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = IDEA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->ivLen = IDEA_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_DES_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //DES-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_DES)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = DES_CIPHER_ALGO;
      childSa->encKeyLen = 8;
      childSa->ivLen = DES_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_3DES_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //3DES-CBC encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_3DES)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = DES3_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->ivLen = DES3_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //AES-CBC with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //AES-CBC with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //AES-CBC with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CBC && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->ivLen = AES_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //AES-CTR with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //AES-CTR with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //AES-CTR with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CTR && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_8 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_12 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //AES-CCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_CCM_16 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_8_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_8 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_12_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_12 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_AES_128_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_AES_192_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_AES_256_SUPPORT == ENABLED && ESP_GCM_16_SUPPORT == ENABLED)
   //AES-GCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_AES_GCM_16 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_GCM;
      childSa->cipherAlgo = AES_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   //Camellia-CBC with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CBC;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->ivLen = CAMELLIA_BLOCK_SIZE;
   }
   else
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 128-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 192-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CTR_SUPPORT == ENABLED)
   //Camellia-CTR with 256-bit key encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CTR;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_8_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 8-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 8;
   }
   else
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_12_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 12-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_CAMELLIA_128_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 128-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 16)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 16;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_CAMELLIA_192_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 192-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 24)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 24;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_CAMELLIA_256_SUPPORT == ENABLED && ESP_CCM_16_SUPPORT == ENABLED)
   //Camellia-CCM with 256-bit key and 16-octet ICV encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16 && encKeyLen == 32)
   {
      childSa->cipherMode = CIPHER_MODE_CCM;
      childSa->cipherAlgo = CAMELLIA_CIPHER_ALGO;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 3;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 encryption algorithm?
   if(encAlgoId == IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305)
   {
      childSa->cipherMode = CIPHER_MODE_CHACHA20_POLY1305;
      childSa->cipherAlgo = NULL;
      childSa->encKeyLen = 32;
      childSa->authKeyLen = 0;
      childSa->saltLen = 4;
      childSa->ivLen = 8;
      childSa->icvLen = 16;
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
 * @param[in] childSa Pointer to the Child SA
 * @param[in] authAlgoId Authentication algorithm identifier
 * @return Error code
 **/

error_t espSelectAuthAlgo(IkeChildSaEntry *childSa, uint16_t authAlgoId)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (ESP_CMAC_SUPPORT == ENABLED && ESP_AES_128_SUPPORT == ENABLED)
   //AES-CMAC-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_CMAC_96)
   {
      childSa->authHashAlgo = NULL;
      childSa->authCipherAlgo = AES_CIPHER_ALGO;
      childSa->authKeyLen = 16;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_MD5_SUPPORT == ENABLED)
   //HMAC-MD5-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96)
   {
      childSa->authHashAlgo = MD5_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = MD5_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96)
   {
      childSa->authHashAlgo = SHA1_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA1_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256-128 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128)
   {
      childSa->authHashAlgo = SHA256_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA256_DIGEST_SIZE;
      childSa->icvLen = 16;
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384-192 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192)
   {
      childSa->authHashAlgo = SHA384_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA384_DIGEST_SIZE;
      childSa->icvLen = 24;
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512-256 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256)
   {
      childSa->authHashAlgo = SHA512_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA512_DIGEST_SIZE;
      childSa->icvLen = 32;
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
 * @brief Add the supported ESP transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t espAddSupportedTransforms(IkeContext *context, IkeProposal *proposal,
   uint8_t **lastSubstruc)
{
   error_t error;

   //Add supported encryption transforms
   error = espAddSupportedEncTransforms(context, proposal, lastSubstruc);

   //Check status code
   if(!error)
   {
      //Add supported integrity transforms
      error = espAddSupportedAuthTransforms(context, proposal, lastSubstruc);
   }

   //Check status code
   if(!error)
   {
      //An initiator who supports ESNs will usually include two ESN transforms,
      //with values "0" and "1", in its proposals (refer to RFC 7296,
      //section 3.3.2)
      error = espAddSupportedEsnTransforms(context, proposal, lastSubstruc);
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

error_t espAddSupportedEncTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported encryption transforms
   for(i = 0; i < arraysize(espSupportedEncAlgos) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_ENCR,
         espSupportedEncAlgos[i].id, espSupportedEncAlgos[i].keyLen,
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

error_t espAddSupportedAuthTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported integrity transforms
   for(i = 0; i < (arraysize(espSupportedAuthAlgos) - 1) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG,
         espSupportedAuthAlgos[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported ESN transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t espAddSupportedEsnTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported ESN transforms
   for(i = 0; i < arraysize(espSupportedEsnTranforms) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_ESN,
         espSupportedEsnTranforms[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Encryption transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected encryption transform, if any
 **/

const IkeEncAlgo *espSelectEncTransform(IkeContext *context,
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
      for(i = 0; i < arraysize(espSupportedEncAlgos) && selectedAlgo == NULL; i++)
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
                        if(transformId == espSupportedEncAlgos[i].id &&
                           ntohs(attr->length) == (espSupportedEncAlgos[i].keyLen * 8))
                        {
                           selectedAlgo = &espSupportedEncAlgos[i];
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
                     if(transformId == espSupportedEncAlgos[i].id)
                     {
                        selectedAlgo = &espSupportedEncAlgos[i];
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

uint16_t espSelectAuthTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the integrity transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_INTEG, espSupportedAuthAlgos,
      arraysize(espSupportedAuthAlgos) - 1, proposal, proposalLen);
}


/**
 * @brief ESN transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected ESN transform, if any
 **/

uint16_t espSelectEsnTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the ESN transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_ESN, espSupportedEsnTranforms,
      arraysize(espSupportedEsnTranforms), proposal, proposalLen);
}


/**
 * @brief Select a single proposal
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t espSelectSaProposal(IkeChildSaEntry *childSa, const IkeSaPayload *payload)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;
   const IkeEncAlgo *encAlgo;

   //Clear the set of parameters
   childSa->protocol = IPSEC_PROTOCOL_INVALID;
   childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->encKeyLen = 0;
   childSa->authAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->esn = IKE_TRANSFORM_ID_INVALID;

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
      if(proposal->protocolId == IKE_PROTOCOL_ID_ESP)
      {
         //Valid SPI value?
         if(proposal->spiSize == IPSEC_SPI_SIZE &&
            osMemcmp(proposal->spi, IPSEC_INVALID_SPI, IPSEC_SPI_SIZE) != 0)
         {
            //Encryption transform negotiation
            encAlgo = espSelectEncTransform(childSa->context, proposal, n);

            //Valid encryption transform?
            if(encAlgo != NULL)
            {
               childSa->encAlgoId = encAlgo->id;
               childSa->encKeyLen = encAlgo->keyLen;
            }
            else
            {
               childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
               childSa->encKeyLen = 0;
            }

            //AEAD algorithm?
            if(ikeIsAeadEncAlgo(childSa->encAlgoId))
            {
               //When an authenticated encryption algorithm is selected as the
               //encryption algorithm for any SA, an integrity algorithm must
               //not be selected for that SA (refer to RFC 5282, section 8)
               childSa->authAlgoId = IKE_TRANSFORM_ID_AUTH_NONE;
            }
            else
            {
               //Integrity transform negotiation
               childSa->authAlgoId = espSelectAuthTransform(childSa->context,
                  proposal, n);
            }

            //ESN transform negotiation
            childSa->esn = espSelectEsnTransform(childSa->context, proposal, n);

            //Valid proposal?
            if(childSa->encAlgoId != IKE_TRANSFORM_ID_INVALID &&
               childSa->authAlgoId != IKE_TRANSFORM_ID_INVALID &&
               childSa->esn != IKE_TRANSFORM_ID_INVALID)
            {
               //Select ESP security protocol
               childSa->protocol = IPSEC_PROTOCOL_ESP;
               //Save the number of the proposal that was accepted
               childSa->acceptedProposalNum = proposal->proposalNum;

               //The initiator SPI is supplied in the SPI field of the SA
               //payload
               osMemcpy(childSa->remoteSpi, proposal->spi, proposal->spiSize);

               //Successful negotiation
               error = NO_ERROR;
               break;
            }
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
 * @brief Check whether the selected proposal is acceptable
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t espCheckSaProposal(IkeChildSaEntry *childSa, const IkeSaPayload *payload)
{
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;
   const IkeEncAlgo *encAlgo;

   //Clear the set of parameters
   childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->encKeyLen = 0;
   childSa->authAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->esn = IKE_TRANSFORM_ID_INVALID;

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
   if(proposal->protocolId != IKE_PROTOCOL_ID_ESP)
      return ERROR_INVALID_MESSAGE;

   //During subsequent negotiations, the SPI Size field is equal to the size,
   //in octets, of the SPI of the corresponding protocol (4 for ESP and AH)
   if(proposal->spiSize != IPSEC_SPI_SIZE)
      return ERROR_INVALID_MESSAGE;

   //The SPI value of zero is reserved and must not be sent on the wire (refer
   //to RFC 4303, section 2.1)
   if(osMemcmp(proposal->spi, IPSEC_INVALID_SPI, IPSEC_SPI_SIZE) == 0)
      return ERROR_INVALID_MESSAGE;

   //The responder SPI is supplied in the SPI field of the SA payload
   osMemcpy(childSa->remoteSpi, proposal->spi, proposal->spiSize);

   //The accepted cryptographic suite must contain exactly one transform of
   //each type included in the proposal (refer to RFC 7296, section 2.7)
   if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_ENCR, proposal, n) != 1 ||
      ikeGetNumTransforms(IKE_TRANSFORM_TYPE_ESN, proposal, n) != 1)
   {
      return ERROR_INVALID_PROPOSAL;
   }

   //Get the selected encryption transform
   encAlgo = espSelectEncTransform(childSa->context, proposal, n);

   //Valid encryption transform?
   if(encAlgo != NULL)
   {
      childSa->encAlgoId = encAlgo->id;
      childSa->encKeyLen = encAlgo->keyLen;
   }

   //AEAD algorithm?
   if(ikeIsAeadEncAlgo(childSa->encAlgoId))
   {
      //When an authenticated encryption algorithm is selected as the encryption
      //algorithm for any SA, an integrity algorithm must not be selected for
      //that SA (refer to RFC 5282, section 8)
      if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_INTEG, proposal, n) != 0)
         return ERROR_INVALID_PROPOSAL;

      //AEAD algorithms combine encryption and integrity into a single operation
      childSa->authAlgoId = IKE_TRANSFORM_ID_AUTH_NONE;
   }
   else
   {
      //Exactly one integrity transform must be included in the proposal
      if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_INTEG, proposal, n) != 1)
         return ERROR_INVALID_PROPOSAL;

      //Get the selected integrity transform
      childSa->authAlgoId = espSelectAuthTransform(childSa->context, proposal,
         n);
   }

   //Get the selected ESN transform
   childSa->esn = espSelectEsnTransform(childSa->context, proposal, n);

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   if(childSa->encAlgoId != IKE_TRANSFORM_ID_INVALID &&
      childSa->authAlgoId != IKE_TRANSFORM_ID_INVALID &&
      childSa->esn != IKE_TRANSFORM_ID_INVALID)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_INVALID_PROPOSAL;
   }
}

#endif
