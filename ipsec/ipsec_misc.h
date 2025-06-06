/**
 * @file ipsec_misc.h
 * @brief Helper routines for IPsec
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

#ifndef _IPSEC_MISC_H
#define _IPSEC_MISC_H

//Dependencies
#include "ipsec/ipsec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IPsec related constants
extern const uint8_t IPSEC_INVALID_SPI[4];

//IPsec related functions
IpsecSpdEntry *ipsecFindSpdEntry(IpsecContext *context,
   IpsecPolicyAction policyAction, const IpsecSelector *selector);

int_t ipsecAllocateSadEntry(IpsecContext *context);

IpsecSadEntry *ipsecFindInboundSadEntry(IpsecContext *context,
   IpsecProtocol protocol, uint32_t spi);

IpsecSadEntry *ipsecFindOutboundSadEntry(IpsecContext *context,
   const IpsecSelector *selector);

IpsecPadEntry *ipsecFindPadEntry(IpsecContext *context, uint8_t idType,
   const uint8_t *id, size_t idLen);

bool_t ipsecIsSubsetSelector(const IpsecSelector *selector1,
   const IpsecSelector *selector2);

bool_t ipsecIntersectSelectors(const IpsecSelector *selector1,
   const IpsecSelector *selector2, IpsecSelector *result);

error_t ipsecDeriveSelector(const IpsecSpdEntry *spdEntry,
   const IpsecPacketInfo *packet, IpsecSelector *selector);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
