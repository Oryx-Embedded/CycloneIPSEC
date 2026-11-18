/**
 * @file ike_eap_debug.h
 * @brief Data logging functions for debugging purpose (EAP)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEAP Open.
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

#ifndef _IKE_EAP_DEBUG_H
#define _IKE_EAP_DEBUG_H

//Dependencies
#include "ike/ike_eap.h"
#include "ike/ike_eap_md5.h"
#include "ike/ike_eap_mschapv2.h"
#include "debug.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP related functions
#if (IKE_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   void ikeDumpEapPacket(const IkeEapPacket *packet, size_t length);
#else
   #define ikeDumpEapPacket(packet, length)
#endif

void ikeDumpEapHeader(const IkeEapPacket *header);

void ikeDumpEapRequest(const IkeEapRequest *request, size_t length);
void ikeDumpEapResponse(const IkeEapResponse *response, size_t length);

void ikeDumpEapIdentityRequest(const IkeEapRequest *request, size_t length);
void ikeDumpEapIdentityResponse(const IkeEapResponse *response, size_t length);

void ikeDumpEapNakResponse(const IkeEapResponse *response, size_t length);

void ikeDumpEapMd5Packet(const IkeEapMd5Packet *packet, size_t length);

void ikeDumpEapMschapv2Packet(const IkeEapMschapv2Packet *packet, size_t length);

void ikeDumpEapMschapv2Challenge(const IkeEapMschapv2Challenge *challenge,
   size_t length);

void ikeDumpEapMschapv2Response(const IkeEapMschapv2Response *response,
   size_t length);

void ikeDumpEapMschapv2SuccessRequest(const IkeEapMschapv2SuccessRequest *request,
   size_t length);

void ikeDumpEapMschapv2SuccessResponse(const IkeEapMschapv2SuccessResponse *response,
   size_t length);

void ikeDumpEapMschapv2FailureRequest(const IkeEapMschapv2FailureRequest *request,
   size_t length);

void ikeDumpEapMschapv2FailureResponse(const IkeEapMschapv2FailureResponse *response,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
