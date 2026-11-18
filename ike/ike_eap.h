/**
 * @file ike_eap.h
 * @brief EAP authentication
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

#ifndef _IKE_EAP_H
#define _IKE_EAP_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EAP codes
 **/

typedef enum
{
   IKE_EAP_CODE_REQUEST  = 1, ///<Request
   IKE_EAP_CODE_RESPONSE = 2, ///<Response
   IKE_EAP_CODE_SUCCESS  = 3, ///<Success
   IKE_EAP_CODE_FAILURE  = 4  ///<Failure
} IkeEapCode;


/**
 * @brief EAP method types
 **/

typedef enum
{
   IKE_EAP_METHOD_TYPE_NONE          = 0,  ///<None
   IKE_EAP_METHOD_TYPE_IDENTITY      = 1,  ///<Identity
   IKE_EAP_METHOD_TYPE_NOTIFICATION  = 2,  ///<Notification
   IKE_EAP_METHOD_TYPE_NAK           = 3,  ///<Legacy Nak
   IKE_EAP_METHOD_TYPE_MD5_CHALLENGE = 4,  ///<MD5-Challenge
   IKE_EAP_METHOD_TYPE_OTP           = 5,  ///<One-Time Password (OTP)
   IKE_EAP_METHOD_TYPE_GTC           = 6,  ///<Generic Token Card (GTC)
   IKE_EAP_METHOD_TYPE_TLS           = 13, ///<EAP-TLS
   IKE_EAP_METHOD_TYPE_TTLS          = 21, ///<EAP-TTLS
   IKE_EAP_METHOD_TYPE_PEAP          = 25, ///<PEAP
   IKE_EAP_METHOD_TYPE_MSCHAPV2      = 26, ///<MS-CHAP-V2
   IKE_EAP_METHOD_TYPE_EXPANDED_NAK  = 254 ///<Expanded NAK
} IkeEapMethodType;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief EAP packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t data[];     //4
} IkeEapPacket;


/**
 * @brief EAP request
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t data[];     //5
} IkeEapRequest;


/**
 * @brief EAP response
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t data[];     //5
} IkeEapResponse;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//EAP related functions
error_t ikeProcessEapPacket(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length);

error_t ikeProcessEapRequest(IkeSaEntry *sa, const IkeEapRequest *request,
   size_t length);

error_t ikeProcessEapIdentityRequest(IkeSaEntry *sa,
   const IkeEapRequest *request, size_t length);

error_t ikeProcessEapSuccess(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length);

error_t ikeProcessEapFailure(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length);

error_t ikeFormatEapPacket(IkeSaEntry *sa, uint8_t *p, size_t *written);

error_t ikeFormatEapIdentityResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatEapNakResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatEapNakResponse(IkeSaEntry *sa, uint8_t *p, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
