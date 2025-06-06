/**
 * @file ike_sign_generate.h
 * @brief RSA/DSA/ECDSA/EdDSA signature generation
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

#ifndef _IKE_SIGN_GENERATE_H
#define _IKE_SIGN_GENERATE_H

//Dependencies
#include "ike/ike.h"
#include "ike/ike_sign_misc.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related functions
error_t ikeGenerateSignature(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t *authMethod, uint8_t *signature, size_t *signatureLen);

error_t ikeGenerateDigitalSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, IkeAuthData *authData, size_t *authDataLen);

error_t ikeGenerateRsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, uint8_t *signature,
   size_t *signatureLen);

error_t ikeGenerateRsaPssSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, size_t saltLen, uint8_t *signature,
   size_t *signatureLen);

error_t ikeGenerateDsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, uint8_t *signature,
   size_t *signatureLen, IkeSignFormat format);

error_t ikeGenerateEcdsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const EcCurve *group, const HashAlgo *hashAlgo,
   uint8_t *signature, size_t *signatureLen, IkeSignFormat format);

error_t ikeGenerateEd25519Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, uint8_t *signature, size_t *signatureLen);

error_t ikeGenerateEd448Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, uint8_t *signature, size_t *signatureLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
