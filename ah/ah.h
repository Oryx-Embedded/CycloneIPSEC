/**
 * @file ah.h
 * @brief AH (IP Authentication Header)
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

#ifndef _AH_H
#define _AH_H

//Dependencies
#include "ipsec/ipsec.h"

//AH support
#ifndef AH_SUPPORT
   #define AH_SUPPORT DISABLED
#elif (AH_SUPPORT != ENABLED && AH_SUPPORT != DISABLED)
   #error AH_SUPPORT parameter is not valid
#endif

//Extended Sequence Numbers support
#ifndef AH_ESN_SUPPORT
   #define AH_ESN_SUPPORT ENABLED
#elif (AH_ESN_SUPPORT != ENABLED && AH_ESN_SUPPORT != DISABLED)
   #error AH_ESN_SUPPORT parameter is not valid
#endif

//CMAC integrity support
#ifndef AH_CMAC_SUPPORT
   #define AH_CMAC_SUPPORT DISABLED
#elif (AH_CMAC_SUPPORT != ENABLED && AH_CMAC_SUPPORT != DISABLED)
   #error AH_CMAC_SUPPORT parameter is not valid
#endif

//HMAC integrity support
#ifndef AH_HMAC_SUPPORT
   #define AH_HMAC_SUPPORT ENABLED
#elif (AH_HMAC_SUPPORT != ENABLED && AH_HMAC_SUPPORT != DISABLED)
   #error AH_HMAC_SUPPORT parameter is not valid
#endif

//KMAC128 integrity support (experimental)
#ifndef AH_KMAC128_SUPPORT
   #define AH_KMAC128_SUPPORT DISABLED
#elif (AH_KMAC128_SUPPORT != ENABLED && AH_KMAC128_SUPPORT != DISABLED)
   #error AH_KMAC128_SUPPORT parameter is not valid
#endif

//KMAC256 integrity support (experimental)
#ifndef AH_KMAC256_SUPPORT
   #define AH_KMAC256_SUPPORT DISABLED
#elif (AH_KMAC256_SUPPORT != ENABLED && AH_KMAC256_SUPPORT != DISABLED)
   #error AH_KMAC256_SUPPORT parameter is not valid
#endif

//AES 128-bit cipher support
#ifndef AH_AES_128_SUPPORT
   #define AH_AES_128_SUPPORT DISABLED
#elif (AH_AES_128_SUPPORT != ENABLED && AH_AES_128_SUPPORT != DISABLED)
   #error AH_AES_128_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef AH_MD5_SUPPORT
   #define AH_MD5_SUPPORT DISABLED
#elif (AH_MD5_SUPPORT != ENABLED && AH_MD5_SUPPORT != DISABLED)
   #error AH_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef AH_SHA1_SUPPORT
   #define AH_SHA1_SUPPORT ENABLED
#elif (AH_SHA1_SUPPORT != ENABLED && AH_SHA1_SUPPORT != DISABLED)
   #error AH_SHA1_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef AH_SHA256_SUPPORT
   #define AH_SHA256_SUPPORT ENABLED
#elif (AH_SHA256_SUPPORT != ENABLED && AH_SHA256_SUPPORT != DISABLED)
   #error AH_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef AH_SHA384_SUPPORT
   #define AH_SHA384_SUPPORT ENABLED
#elif (AH_SHA384_SUPPORT != ENABLED && AH_SHA384_SUPPORT != DISABLED)
   #error AH_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef AH_SHA512_SUPPORT
   #define AH_SHA512_SUPPORT ENABLED
#elif (AH_SHA512_SUPPORT != ENABLED && AH_SHA512_SUPPORT != DISABLED)
   #error AH_SHA512_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support (experimental)
#ifndef AH_SHA3_256_SUPPORT
   #define AH_SHA3_256_SUPPORT DISABLED
#elif (AH_SHA3_256_SUPPORT != ENABLED && AH_SHA3_256_SUPPORT != DISABLED)
   #error AH_SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support (experimental)
#ifndef AH_SHA3_384_SUPPORT
   #define AH_SHA3_384_SUPPORT DISABLED
#elif (AH_SHA3_384_SUPPORT != ENABLED && AH_SHA3_384_SUPPORT != DISABLED)
   #error AH_SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support (experimental)
#ifndef AH_SHA3_512_SUPPORT
   #define AH_SHA3_512_SUPPORT DISABLED
#elif (AH_SHA3_512_SUPPORT != ENABLED && AH_SHA3_512_SUPPORT != DISABLED)
   #error AH_SHA3_512_SUPPORT parameter is not valid
#endif

//SM3 hash support (experimental)
#ifndef AH_SM3_SUPPORT
   #define AH_SM3_SUPPORT DISABLED
#elif (AH_SM3_SUPPORT != ENABLED && AH_SM3_SUPPORT != DISABLED)
   #error AH_SM3_SUPPORT parameter is not valid
#endif

//Maximum digest size
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA512_SUPPORT == ENABLED)
   #define AH_MAX_DIGEST_SIZE 64
#elif (AH_HMAC_SUPPORT == ENABLED && AH_SHA384_SUPPORT == ENABLED)
   #define AH_MAX_DIGEST_SIZE 48
#elif (AH_HMAC_SUPPORT == ENABLED && AH_SHA256_SUPPORT == ENABLED)
   #define AH_MAX_DIGEST_SIZE 32
#else
   #define AH_MAX_DIGEST_SIZE 12
#endif

//Maximum size of the ICV field
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA512_SUPPORT == ENABLED)
   #define AH_MAX_ICV_SIZE 32
#elif (AH_HMAC_SUPPORT == ENABLED && AH_SHA384_SUPPORT == ENABLED)
   #define AH_MAX_ICV_SIZE 24
#elif (AH_HMAC_SUPPORT == ENABLED && AH_SHA256_SUPPORT == ENABLED)
   #define AH_MAX_ICV_SIZE 16
#else
   #define AH_MAX_ICV_SIZE 12
#endif

//Maximum overhead caused by AH security protocol
#define AH_MAX_OVERHEAD (sizeof(AhHeader) + AH_MAX_ICV_SIZE)

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
 * @brief AH header
 **/

typedef __packed_struct
{
   uint8_t nextHeader;    //0
   uint8_t payloadLen;    //1
   uint16_t reserved;     //2-3
   uint32_t spi;          //4-7
   uint32_t seqNum;       //8-11
   uint8_t icv[];         //12
} AhHeader;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//AH related functions
error_t ipv4ProcessAhHeader(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset,
   NetRxAncillary *ancillary);

error_t ahGenerateIcv(IpsecSadEntry *sa, const Ipv4Header *ipv4Header,
   AhHeader *ahHeader, const NetBuffer *buffer, size_t offset);

error_t ahVerifyIcv(IpsecSadEntry *sa, const Ipv4Header *ipv4Header,
   const AhHeader *ahHeader, const NetBuffer *buffer, size_t offset);

void ahProcessMutableIpv4Options(Ipv4Header *header);

void ahDumpHeader(const AhHeader *ahHeader);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
