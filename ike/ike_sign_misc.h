/**
 * @file ike_sign_misc.h
 * @brief Helper functions for signature generation and verification
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

#ifndef _IKE_SIGN_MISC_H
#define _IKE_SIGN_MISC_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Signature format
 **/

typedef enum
{
   IKE_SIGN_FORMAT_RAW  = 1,
   IKE_SIGN_FORMAT_ASN1 = 2
} IkeSignFormat;


/**
 * @brief Signature algorithms
 **/

typedef enum
{
   IKE_SIGN_ALGO_NONE    = 0,
   IKE_SIGN_ALGO_RSA     = 1,
   IKE_SIGN_ALGO_RSA_PSS = 2,
   IKE_SIGN_ALGO_DSA     = 3,
   IKE_SIGN_ALGO_ECDSA   = 4,
   IKE_SIGN_ALGO_ED25519 = 5,
   IKE_SIGN_ALGO_ED448   = 6
} IkeSignAlgo;


//IKEv2 related functions
error_t ikeFormatDsaSignature(const DsaSignature *signature, uint8_t *data,
   size_t *length, IkeSignFormat format);

error_t ikeFormatEcdsaSignature(const EcdsaSignature *signature, uint8_t *data,
   size_t *length, IkeSignFormat format);

error_t ikeParseDsaSignature(const uint8_t *data, size_t length,
   DsaSignature *signature, IkeSignFormat format);

error_t ikeParseEcdsaSignature(const EcCurve *curve, const uint8_t *data,
   size_t length, EcdsaSignature *signature, IkeSignFormat format);

error_t ikeSelectSignAlgoId(IkeCertType certType, const HashAlgo *hashAlgo,
   X509SignAlgoId *signAlgoId);

error_t ikeSelectSignAlgo(const X509SignAlgoId *signAlgoId,
   IkeSignAlgo *signAlgo, const HashAlgo **hashAlgo);

const HashAlgo *ikeSelectSignHashAlgo(IkeSaEntry *sa,
   uint16_t preferredHashAlgoId);

error_t ikeGetSignedOctets(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t *macId, DataChunk *messageChunks, bool_t initiator);

error_t ikeDigestSignedOctets(IkeSaEntry *sa, const HashAlgo *hashAlgo,
   const uint8_t *id, size_t idLen, uint8_t *digest, bool_t initiator);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
