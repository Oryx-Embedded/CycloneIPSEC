/**
 * @file ike_certificate.h
 * @brief X.509 certificate handling
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

#ifndef _IKE_CERTIFICATE_H
#define _IKE_CERTIFICATE_H

//Dependencies
#include "ike/ike.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related functions
error_t ikeGetCertificateType(const X509CertInfo *certInfo,
   IkeCertType *certType);

error_t ikeGetCertSubjectDn(const char_t *cert, size_t certLen,
   uint8_t *subjectDn, size_t *subjectDnLen);

error_t ikeFormatCertAuthorities(const char_t *trustedCaList,
   size_t trustedCaListLen, uint8_t *certAuth, size_t *certAuthLen);

bool_t ikeIsDuplicateCa(const uint8_t *certAuth, size_t certAuthLen,
   const uint8_t *digest);

error_t ikeParseCertificateChain(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const uint8_t *message, size_t length);

error_t ikeValidateCertificate(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const X509CertInfo *certInfo, uint_t pathLen);

error_t ikeCheckKeyUsage(const X509CertInfo *certInfo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
