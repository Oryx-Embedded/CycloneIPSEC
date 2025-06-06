/**
 * @file ike_debug.h
 * @brief Data logging functions for debugging purpose (IKEv2)
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

#ifndef _IKE_DEBUG_H
#define _IKE_DEBUG_H

//Dependencies
#include "ike/ike.h"
#include "debug.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Parameter value/name binding
 **/

typedef struct
{
   uint_t value;
   const char_t *name;
} IkeParamName;


//IKEv2 related functions
#if (IKE_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   void ikeDumpMessage(const uint8_t *message, size_t length);
#else
   #define ikeDumpMessage(message, length)
#endif

void ikeDumpHeader(const IkeHeader *header);
void ikeDumpFlags(uint8_t flags);

void ikeDumpPayloads(const uint8_t *payloads, size_t length,
   uint8_t nextPayload);

void ikeDumpPayloadHeader(const IkePayloadHeader *header);

void ikeDumpSaPayload(const IkeSaPayload *payload, size_t length);

void ikeDumpKePayload(const IkeKePayload *payload, size_t length);
void ikeDumpProposal(const IkeProposal *proposal, size_t length);
void ikeDumpTransform(const IkeTransform *transform, size_t length);

error_t ikeDumpTransformAttr(const IkeTransformAttr *attr, size_t length,
   size_t *consumed);

void ikeDumpIdPayload(const IkeIdPayload *payload, size_t length);

void ikeDumpCertPayload(const IkeCertPayload *payload, size_t length);

void ikeDumpCertReqPayload(const IkeCertReqPayload *payload, size_t length);

void ikeDumpAuthPayload(const IkeAuthPayload *payload, size_t length);

void ikeDumpNoncePayload(const IkeNoncePayload *payload, size_t length);

void ikeDumpNotifyPayload(const IkeNotifyPayload *payload, size_t length);

void ikeDumpDeletePayload(const IkeDeletePayload *payload, size_t length);

void ikeDumpTsPayload(const IkeTsPayload *payload, size_t length);
void ikeDumpTs(const IkeTs *selector, size_t length);

void ikeDumpEncryptedPayload(const IkeEncryptedPayload *payload, size_t length);

void ikeDumpEncryptedFragPayload(const IkeEncryptedFragPayload *payload,
   size_t length);

const char_t *ikeGetParamName(uint_t value, const IkeParamName *paramList,
   size_t paramListLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
