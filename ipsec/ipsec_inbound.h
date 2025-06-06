/**
 * @file ipsec_inbound.h
 * @brief IPsec processing of inbound IP traffic
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

#ifndef _IPSEC_INBOUND_H
#define _IPSEC_INBOUND_H

//Dependencies
#include "ipsec/ipsec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IPsec related functions
error_t ipsecProcessInboundIpv4Packet(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset);

error_t ipsecGetInboundIpv4PacketSelector(const Ipv4Header *ipv4Header,
   uint8_t nextHeader, const NetBuffer *buffer, size_t offset,
   IpsecSelector *selector);

uint64_t ipsecGetSeqNum(IpsecSadEntry *sa, uint32_t seql);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
