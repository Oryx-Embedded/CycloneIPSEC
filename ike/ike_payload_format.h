/**
 * @file ike_payload_format.h
 * @brief IKE payload formatting
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

#ifndef _IKE_PAYLOAD_FORMAT_H
#define _IKE_PAYLOAD_FORMAT_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
error_t ikeFormatSaPayload(IkeSaEntry *sa, const uint8_t *spi, uint8_t *p,
   size_t *written, uint8_t **nextPayload);

error_t ikeFormatSaProposal(IkeSaEntry *sa, const uint8_t *spi, uint8_t *p,
   size_t *written);

error_t ikeFormatChildSaPayload(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written, uint8_t **nextPayload);

error_t ikeFormatChildSaProposal(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written);

error_t ikeFormatKePayload(IkeKeContext *keContext, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatIdPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatCertPayloads(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatCertPayload(const char_t *certChain, size_t certChainLen,
   size_t *consumed, uint8_t *p, size_t *written, uint8_t **nextPayload);

error_t ikeFormatCertReqPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatAuthPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatNoncePayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *written, uint8_t **nextPayload);

error_t ikeFormatNotifyPayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   IkeNotifyMsgType notifyMsgType, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatNatDetectSrcIpNotificationData(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatNatDetectDestIpNotificationData(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatSignHashAlgosNotificationData(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatDeletePayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *written, uint8_t **nextPayload);

error_t ikeFormatTsiPayload(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written, uint8_t **nextPayload);

error_t ikeFormatTsrPayload(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written, uint8_t **nextPayload);

error_t ikeFormatTsEntry(const IkeTsEntry *tsEntry, uint8_t *p,
   size_t *written);

error_t ikeFormatConfigPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

error_t ikeFormatConfigAttr(IkeConfigAttrType type, const void *value,
   size_t length, uint8_t *p, size_t *written);

error_t ikeFormatEapPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
