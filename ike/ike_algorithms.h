/**
 * @file ike_algorithms.h
 * @brief IKEv2 algorithm negotiation
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

#ifndef _IKE_ALGORITHMS_H
#define _IKE_ALGORITHMS_H

//Dependencies
#include "ike/ike.h"

//Invalid transform identifier
#define IKE_TRANSFORM_ID_INVALID 0xFFFF

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Encryption algorithm
 **/

typedef struct
{
   uint16_t id;
   uint16_t keyLen;
} IkeEncAlgo;


//IKEv2 related functions
error_t ikeSelectEncAlgo(IkeSaEntry *sa, uint16_t encAlgoId,
   size_t encKeyLen);

error_t ikeSelectAuthAlgo(IkeSaEntry *sa, uint16_t authAlgoId);
error_t ikeSelectPrfAlgo(IkeSaEntry *sa, uint16_t prfAlgoId);

error_t ikeAddTransform(IkeTransformType transformType, uint16_t transformId,
   uint16_t keyLen, IkeProposal *proposal, uint8_t **lastSubstruc);

error_t ikeAddSupportedTransforms(IkeContext *context, IkeProposal *proposal,
   uint8_t **lastSubstruc);

error_t ikeAddSupportedKeTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc);

error_t ikeAddSupportedEncTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc);

error_t ikeAddSupportedAuthTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc);

error_t ikeAddSupportedPrfTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc);

uint_t ikeGetNumTransforms(IkeTransformType transformType,
   const IkeProposal *proposal, size_t proposalLen);

uint16_t ikeSelectTransform(IkeTransformType transformType,
   const uint16_t *algoList, uint_t algoListLen, const IkeProposal *proposal,
   size_t proposalLen);

uint16_t ikeSelectKeTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen);

const IkeEncAlgo *ikeSelectEncTransform(IkeContext *context,
   const IkeProposal *proposal, size_t proposalLen);

uint16_t ikeSelectAuthTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen);

uint16_t ikeSelectPrfTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen);

error_t ikeSelectSaProposal(IkeSaEntry *sa, const IkeSaPayload *payload,
   size_t spiSize);

error_t ikeSelectChildSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload);

error_t ikeCheckSaProposal(IkeSaEntry *sa, const IkeSaPayload *payload);

error_t ikeCheckChildSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload);

bool_t ikeIsAeadEncAlgo(uint16_t encAlgoId);
bool_t ikeIsVariableLengthKeyEncAlgo(uint16_t encAlgoId);

bool_t ikeIsDhKeyExchangeAlgo(uint16_t groupNum);
bool_t ikeIsEcdhKeyExchangeAlgo(uint16_t groupNum);
bool_t ikeIsMlkemKeyExchangeAlgo(uint16_t groupNum);

const EcCurve *ikeGetEcdhCurve(uint16_t groupNum);
uint16_t ikeSelectDefaultDhGroup(void);
bool_t ikeIsDhGroupSupported(uint16_t groupNum);
bool_t ikeIsHashAlgoSupported(uint16_t hashAlgoId);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
