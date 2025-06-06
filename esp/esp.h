/**
 * @file esp.h
 * @brief ESP (IP Encapsulating Security Payload)
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

#ifndef _ESP_H
#define _ESP_H

//Dependencies
#include "ipsec/ipsec.h"

//ESP support
#ifndef ESP_SUPPORT
   #define ESP_SUPPORT ENABLED
#elif (ESP_SUPPORT != ENABLED && ESP_SUPPORT != DISABLED)
   #error ESP_SUPPORT parameter is not valid
#endif

//Extended Sequence Numbers support
#ifndef ESP_ESN_SUPPORT
   #define ESP_ESN_SUPPORT ENABLED
#elif (ESP_ESN_SUPPORT != ENABLED && ESP_ESN_SUPPORT != DISABLED)
   #error ESP_ESN_SUPPORT parameter is not valid
#endif

//CBC cipher mode support
#ifndef ESP_CBC_SUPPORT
   #define ESP_CBC_SUPPORT ENABLED
#elif (ESP_CBC_SUPPORT != ENABLED && ESP_CBC_SUPPORT != DISABLED)
   #error ESP_CBC_SUPPORT parameter is not valid
#endif

//CTR cipher mode support
#ifndef ESP_CTR_SUPPORT
   #define ESP_CTR_SUPPORT DISABLED
#elif (ESP_CTR_SUPPORT != ENABLED && ESP_CTR_SUPPORT != DISABLED)
   #error ESP_CTR_SUPPORT parameter is not valid
#endif

//CCM_8 AEAD support
#ifndef ESP_CCM_8_SUPPORT
   #define ESP_CCM_8_SUPPORT DISABLED
#elif (ESP_CCM_8_SUPPORT != ENABLED && ESP_CCM_8_SUPPORT != DISABLED)
   #error ESP_CCM_8_SUPPORT parameter is not valid
#endif

//CCM_12 AEAD support
#ifndef ESP_CCM_12_SUPPORT
   #define ESP_CCM_12_SUPPORT DISABLED
#elif (ESP_CCM_12_SUPPORT != ENABLED && ESP_CCM_12_SUPPORT != DISABLED)
   #error ESP_CCM_12_SUPPORT parameter is not valid
#endif

//CCM_16 AEAD support
#ifndef ESP_CCM_16_SUPPORT
   #define ESP_CCM_16_SUPPORT DISABLED
#elif (ESP_CCM_16_SUPPORT != ENABLED && ESP_CCM_16_SUPPORT != DISABLED)
   #error ESP_CCM_16_SUPPORT parameter is not valid
#endif

//GCM_8 AEAD support
#ifndef ESP_GCM_8_SUPPORT
   #define ESP_GCM_8_SUPPORT DISABLED
#elif (ESP_GCM_8_SUPPORT != ENABLED && ESP_GCM_8_SUPPORT != DISABLED)
   #error ESP_GCM_8_SUPPORT parameter is not valid
#endif

//GCM_12 AEAD support
#ifndef ESP_GCM_12_SUPPORT
   #define ESP_GCM_12_SUPPORT DISABLED
#elif (ESP_GCM_12_SUPPORT != ENABLED && ESP_GCM_12_SUPPORT != DISABLED)
   #error ESP_GCM_12_SUPPORT parameter is not valid
#endif

//GCM_16 AEAD support
#ifndef ESP_GCM_16_SUPPORT
   #define ESP_GCM_16_SUPPORT ENABLED
#elif (ESP_GCM_16_SUPPORT != ENABLED && ESP_GCM_16_SUPPORT != DISABLED)
   #error ESP_GCM_16_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 AEAD support
#ifndef ESP_CHACHA20_POLY1305_SUPPORT
   #define ESP_CHACHA20_POLY1305_SUPPORT ENABLED
#elif (ESP_CHACHA20_POLY1305_SUPPORT != ENABLED && ESP_CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error ESP_CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//CMAC integrity support
#ifndef ESP_CMAC_SUPPORT
   #define ESP_CMAC_SUPPORT DISABLED
#elif (ESP_CMAC_SUPPORT != ENABLED && ESP_CMAC_SUPPORT != DISABLED)
   #error ESP_CMAC_SUPPORT parameter is not valid
#endif

//HMAC integrity support
#ifndef ESP_HMAC_SUPPORT
   #define ESP_HMAC_SUPPORT ENABLED
#elif (ESP_HMAC_SUPPORT != ENABLED && ESP_HMAC_SUPPORT != DISABLED)
   #error ESP_HMAC_SUPPORT parameter is not valid
#endif

//KMAC128 integrity support (experimental)
#ifndef ESP_KMAC128_SUPPORT
   #define ESP_KMAC128_SUPPORT DISABLED
#elif (ESP_KMAC128_SUPPORT != ENABLED && ESP_KMAC128_SUPPORT != DISABLED)
   #error ESP_KMAC128_SUPPORT parameter is not valid
#endif

//KMAC256 integrity support (experimental)
#ifndef ESP_KMAC256_SUPPORT
   #define ESP_KMAC256_SUPPORT DISABLED
#elif (ESP_KMAC256_SUPPORT != ENABLED && ESP_KMAC256_SUPPORT != DISABLED)
   #error ESP_KMAC256_SUPPORT parameter is not valid
#endif

//IDEA cipher support (insecure)
#ifndef ESP_IDEA_SUPPORT
   #define ESP_IDEA_SUPPORT DISABLED
#elif (ESP_IDEA_SUPPORT != ENABLED && ESP_IDEA_SUPPORT != DISABLED)
   #error ESP_IDEA_SUPPORT parameter is not valid
#endif

//DES cipher support (insecure)
#ifndef ESP_DES_SUPPORT
   #define ESP_DES_SUPPORT DISABLED
#elif (ESP_DES_SUPPORT != ENABLED && ESP_DES_SUPPORT != DISABLED)
   #error ESP_DES_SUPPORT parameter is not valid
#endif

//Triple DES cipher support (weak)
#ifndef ESP_3DES_SUPPORT
   #define ESP_3DES_SUPPORT DISABLED
#elif (ESP_3DES_SUPPORT != ENABLED && ESP_3DES_SUPPORT != DISABLED)
   #error ESP_3DES_SUPPORT parameter is not valid
#endif

//AES 128-bit cipher support
#ifndef ESP_AES_128_SUPPORT
   #define ESP_AES_128_SUPPORT ENABLED
#elif (ESP_AES_128_SUPPORT != ENABLED && ESP_AES_128_SUPPORT != DISABLED)
   #error ESP_AES_128_SUPPORT parameter is not valid
#endif

//AES 192-bit cipher support
#ifndef ESP_AES_192_SUPPORT
   #define ESP_AES_192_SUPPORT ENABLED
#elif (ESP_AES_192_SUPPORT != ENABLED && ESP_AES_192_SUPPORT != DISABLED)
   #error ESP_AES_192_SUPPORT parameter is not valid
#endif

//AES 256-bit cipher support
#ifndef ESP_AES_256_SUPPORT
   #define ESP_AES_256_SUPPORT ENABLED
#elif (ESP_AES_256_SUPPORT != ENABLED && ESP_AES_256_SUPPORT != DISABLED)
   #error ESP_AES_256_SUPPORT parameter is not valid
#endif

//Camellia 128-bit cipher support
#ifndef ESP_CAMELLIA_128_SUPPORT
   #define ESP_CAMELLIA_128_SUPPORT DISABLED
#elif (ESP_CAMELLIA_128_SUPPORT != ENABLED && ESP_CAMELLIA_128_SUPPORT != DISABLED)
   #error ESP_CAMELLIA_128_SUPPORT parameter is not valid
#endif

//Camellia 192-bit cipher support
#ifndef ESP_CAMELLIA_192_SUPPORT
   #define ESP_CAMELLIA_192_SUPPORT DISABLED
#elif (ESP_CAMELLIA_192_SUPPORT != ENABLED && ESP_CAMELLIA_192_SUPPORT != DISABLED)
   #error ESP_CAMELLIA_192_SUPPORT parameter is not valid
#endif

//Camellia 256-bit cipher support
#ifndef ESP_CAMELLIA_256_SUPPORT
   #define ESP_CAMELLIA_256_SUPPORT DISABLED
#elif (ESP_CAMELLIA_256_SUPPORT != ENABLED && ESP_CAMELLIA_256_SUPPORT != DISABLED)
   #error ESP_CAMELLIA_256_SUPPORT parameter is not valid
#endif

//SM4 cipher support (experimental)
#ifndef ESP_SM4_SUPPORT
   #define ESP_SM4_SUPPORT DISABLED
#elif (ESP_SM4_SUPPORT != ENABLED && ESP_SM4_SUPPORT != DISABLED)
   #error ESP_SM4_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef ESP_MD5_SUPPORT
   #define ESP_MD5_SUPPORT DISABLED
#elif (ESP_MD5_SUPPORT != ENABLED && ESP_MD5_SUPPORT != DISABLED)
   #error ESP_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef ESP_SHA1_SUPPORT
   #define ESP_SHA1_SUPPORT ENABLED
#elif (ESP_SHA1_SUPPORT != ENABLED && ESP_SHA1_SUPPORT != DISABLED)
   #error ESP_SHA1_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef ESP_SHA256_SUPPORT
   #define ESP_SHA256_SUPPORT ENABLED
#elif (ESP_SHA256_SUPPORT != ENABLED && ESP_SHA256_SUPPORT != DISABLED)
   #error ESP_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef ESP_SHA384_SUPPORT
   #define ESP_SHA384_SUPPORT ENABLED
#elif (ESP_SHA384_SUPPORT != ENABLED && ESP_SHA384_SUPPORT != DISABLED)
   #error ESP_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef ESP_SHA512_SUPPORT
   #define ESP_SHA512_SUPPORT ENABLED
#elif (ESP_SHA512_SUPPORT != ENABLED && ESP_SHA512_SUPPORT != DISABLED)
   #error ESP_SHA512_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support (experimental)
#ifndef ESP_SHA3_256_SUPPORT
   #define ESP_SHA3_256_SUPPORT DISABLED
#elif (ESP_SHA3_256_SUPPORT != ENABLED && ESP_SHA3_256_SUPPORT != DISABLED)
   #error ESP_SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support (experimental)
#ifndef ESP_SHA3_384_SUPPORT
   #define ESP_SHA3_384_SUPPORT DISABLED
#elif (ESP_SHA3_384_SUPPORT != ENABLED && ESP_SHA3_384_SUPPORT != DISABLED)
   #error ESP_SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support (experimental)
#ifndef ESP_SHA3_512_SUPPORT
   #define ESP_SHA3_512_SUPPORT DISABLED
#elif (ESP_SHA3_512_SUPPORT != ENABLED && ESP_SHA3_512_SUPPORT != DISABLED)
   #error ESP_SHA3_512_SUPPORT parameter is not valid
#endif

//SM3 hash support (experimental)
#ifndef ESP_SM3_SUPPORT
   #define ESP_SM3_SUPPORT DISABLED
#elif (ESP_SM3_SUPPORT != ENABLED && ESP_SM3_SUPPORT != DISABLED)
   #error ESP_SM3_SUPPORT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef ESP_BUFFER_SIZE
   #define ESP_BUFFER_SIZE 2048
#elif (ESP_BUFFER_SIZE < 256)
   #error ESP_BUFFER_SIZE parameter is not valid
#endif

//Maximum digest size
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA512_SUPPORT == ENABLED)
   #define ESP_MAX_DIGEST_SIZE 64
#elif (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA384_SUPPORT == ENABLED)
   #define ESP_MAX_DIGEST_SIZE 48
#elif (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA256_SUPPORT == ENABLED)
   #define ESP_MAX_DIGEST_SIZE 32
#else
   #define ESP_MAX_DIGEST_SIZE 12
#endif

//Maximum size of the ICV field
#if (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA512_SUPPORT == ENABLED)
   #define ESP_MAX_ICV_SIZE 32
#elif (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA384_SUPPORT == ENABLED)
   #define ESP_MAX_ICV_SIZE 24
#elif (ESP_HMAC_SUPPORT == ENABLED && ESP_SHA256_SUPPORT == ENABLED)
   #define ESP_MAX_ICV_SIZE 16
#else
   #define ESP_MAX_ICV_SIZE 12
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief ESP header
 **/

typedef __packed_struct
{
   uint32_t spi;          //0-3
   uint32_t seqNum;       //4-7
   uint8_t payloadData[]; //8
} EspHeader;


/**
 * @brief ESP trailer
 **/

typedef __packed_struct
{
   uint8_t padLength;  //0
   uint8_t nextHeader; //1
   uint8_t icv[];      //2
} EspTrailer;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//ESP related functions
error_t ipv4ProcessEspHeader(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset,
   NetRxAncillary *ancillary);

void espDumpHeader(const EspHeader *espHeader);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
