/**
 * @file ipsec_outbound.h
 * @brief IPsec processing of outbound IP traffic
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

#ifndef _IPSEC_OUTBOUND_H
#define _IPSEC_OUTBOUND_H

//Dependencies
#include "ipsec/ipsec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IPsec related functions
error_t ipsecProcessOutboundIpv4Packet(NetInterface *interface,
   const Ipv4PseudoHeader *pseudoHeader, uint16_t fragId, NetBuffer *buffer,
   size_t offset, NetTxAncillary *ancillary);

error_t ipsecGetOutboundIpv4PacketSelector(const Ipv4PseudoHeader *pseudoHeader,
   const NetBuffer *buffer, size_t offset, IpsecSelector *selector);

error_t ipsecProtectIpv4Packet(IpsecContext *context, IpsecSadEntry *sa,
   NetInterface *interface, const Ipv4PseudoHeader *pseudoHeader,
   uint16_t fragId, NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t ipsecSendIpv4Packet(NetInterface *interface,
   const Ipv4PseudoHeader *pseudoHeader, uint16_t fragId, NetBuffer *buffer,
   size_t offset, NetTxAncillary *ancillary);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
