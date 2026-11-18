/**
 * @file ike_payload_parse.h
 * @brief IKE payload parsing
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

#ifndef _IKE_PAYLOAD_PARSE_H
#define _IKE_PAYLOAD_PARSE_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief IKE message payloads
 **/

typedef struct
{
   const IkeSaPayload *sa;
   const IkeKePayload *ke;
   const IkeIdPayload *idi;
   const IkeIdPayload *idr;
   const IkeCertPayload *cert;
   const IkeCertReqPayload *certReq;
   const IkeAuthPayload *auth;
   const IkeNoncePayload *nonce;
   const IkeTsPayload *tsi;
   const IkeTsPayload *tsr;
   const IkeConfigPayload *config;
   const IkeEapPayload *eap;
   const IkeNotifyPayload *useTransportModeNotify;
   const IkeNotifyPayload *rekeySaNotify;
#if (IKE_COOKIE_SUPPORT == ENABLED)
   const IkeNotifyPayload *cookieNotify;
#endif
#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
   const IkeNotifyPayload *initialContactNotify;
#endif
#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   const IkeNotifyPayload *signHashAlgosNotify;
#endif
#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   const IkeNotifyPayload *natDetectSrcIpNotify;
   const IkeNotifyPayload *natDetectDestIpNotify;
#endif
   const IkeNotifyPayload *errorNotify;
} IkeMessagePayloads;


//IKE related functions
void ikeParseIkeMessagePayloads(const uint8_t *message, size_t length,
   IkeMessagePayloads *payloads);

error_t ikeParseSaPayload(const IkeSaPayload *saPayload);
error_t ikeParseProposal(const IkeProposal *proposal, size_t length);
error_t ikeParseTransform(const IkeTransform *transform, size_t length);

error_t ikeParseTransformAttr(const IkeTransformAttr *attr, size_t length,
   size_t *consumed);

error_t ikeParseKePayload(IkeKeContext *keContext,
   const IkeKePayload *kePayload);

error_t ikeParseIdPayload(IkeSaEntry *sa, const IkeIdPayload *idPayload);

error_t ikeParseCertReqPayload(IkeSaEntry *sa,
   const IkeCertReqPayload *certReqPayload);

error_t ikeParseAuthPayload(IkeSaEntry *sa, const IkeAuthPayload *authPayload,
   const IkeCertPayload *certPayload);

error_t ikeParseNoncePayload(const IkeNoncePayload *noncePayload,
   uint8_t *nonce, size_t *nonceLen);

error_t ikeParseInvalidKePayloadNotification(IkeKeContext *keContext,
   const IkeNotifyPayload *notifyPayload);

error_t ikeParseCookieNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload);

error_t ikeParseSignHashAlgosNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload);

error_t ikeParseNatDetectSrcIpNotification(IkeSaEntry *sa,
   const uint8_t *message, size_t length);

error_t ikeParseNatDetectDestIpNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload);

error_t ikeParseDeletePayload(IkeSaEntry *sa,
   const IkeDeletePayload *deletePayload, bool_t response);

error_t ikeParseTsPayload(const IkeTsPayload *tsPayload, uint_t index,
   IkeTsEntry *tsEntry);

error_t ikeParseTsEntry(const IkeTs *ts, size_t length, IkeTsEntry *tsEntry);

error_t ikeParseConfigPayload(IkeSaEntry *sa,
   const IkeConfigPayload *configPayload);

error_t ikeParseEapPayload(IkeSaEntry *sa, const IkeEapPayload *eapPayload);

const IkePayloadHeader *ikeGetPayload(const uint8_t *message, size_t length,
   uint8_t type, uint_t index);

const IkeNotifyPayload *ikeGetErrorNotifyPayload(const uint8_t *message,
   size_t length);

const IkeNotifyPayload *ikeGetStatusNotifyPayload(const uint8_t *message,
   size_t length, uint16_t type, uint_t index);

error_t ikeCheckCriticalPayloads(const uint8_t *message, size_t length,
   uint8_t *unsupportedCriticalPayload);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
