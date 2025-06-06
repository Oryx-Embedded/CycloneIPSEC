/**
 * @file ike_sign_verify.h
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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

#ifndef _IKE_SIGN_VERIFY_H
#define _IKE_SIGN_VERIFY_H

//Dependencies
#include "ike/ike.h"
#include "ike/ike_sign_misc.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related functions
error_t ikeVerifySignature(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t authMethod, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen);

error_t ikeVerifyDigitalSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const IkeAuthData *authData, size_t authDataLen);

error_t ikeVerifyRsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, const uint8_t *signature, size_t signatureLen);

error_t ikeVerifyRsaPssSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, size_t saltLen, const uint8_t *signature,
   size_t signatureLen);

error_t ikeVerifyDsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, const uint8_t *signature, size_t signatureLen,
   IkeSignFormat format);

error_t ikeVerifyEcdsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const EcCurve *group, const HashAlgo *hashAlgo, const uint8_t *signature,
   size_t signatureLen, IkeSignFormat format);

error_t ikeVerifyEd25519Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen);

error_t ikeVerifyEd448Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
