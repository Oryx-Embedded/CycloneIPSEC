/**
 * @file ike_misc.h
 * @brief Helper functions for IKEv2
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

#ifndef _IKE_MISC_H
#define _IKE_MISC_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related constants
extern const uint8_t IKE_INVALID_SPI[8];

//IKEv2 related functions
error_t ikeRetransmitRequest(IkeSaEntry *sa);
error_t ikeRetransmitResponse(IkeSaEntry *sa);

IkeSaEntry *ikeCreateSaEntry(IkeContext *context);
IkeSaEntry *ikeFindSaEntry(IkeContext *context, const IkeHeader *ikeHeader);

IkeSaEntry *ikeFindHalfOpenSaEntry(IkeContext *context,
   const IkeHeader *ikeHeader, const IkeNoncePayload *noncePayload);

void ikeDeleteSaEntry(IkeSaEntry *sa);
void ikeDeleteDuplicateSaEntries(IkeSaEntry *sa);

IkeChildSaEntry *ikeCreateChildSaEntry(IkeContext *context);

IkeChildSaEntry *ikeFindChildSaEntry(IkeSaEntry *sa, uint8_t protocolId,
   const uint8_t *spi);

void ikeDeleteChildSaEntry(IkeChildSaEntry *childSa);

error_t ikeGenerateSaSpi(IkeSaEntry *sa, uint8_t *spi);
error_t ikeGenerateChildSaSpi(IkeChildSaEntry *childSa, uint8_t *spi);
error_t ikeGenerateNonce(IkeContext *context, uint8_t *nonce, size_t *length);

systime_t ikeRandomizeDelay(IkeContext *context, systime_t delay);

error_t ikeSelectTs(IkeChildSaEntry *childSa, const IkeTsPayload *tsiPayload,
   const IkeTsPayload *tsrPayload);

error_t ikeCheckTs(IkeChildSaEntry *childSa, const IkeTsPayload *tsiPayload,
   const IkeTsPayload *tsrPayload);

error_t ikeCheckNonceLength(IkeSaEntry *sa, size_t nonceLen);

error_t ikeCreateIpsecSaPair(IkeChildSaEntry *childSa);

bool_t ikeIsInitialContact(IkeSaEntry *sa);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
