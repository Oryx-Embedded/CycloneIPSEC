/**
 * @file ike_eap_mschapv2.h
 * @brief EAP MS-CHAP-V2 authentication method
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

#ifndef _IKE_EAP_MSCHAPV2_H
#define _IKE_EAP_MSCHAPV2_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief MS-CHAP-V2 opcodes
 **/

typedef enum
{
   IKE_EAP_MSCHAPV2_CODE_INVALID    = 0,
   IKE_EAP_MSCHAPV2_CODE_CHALLENGE  = 1, ///<Challenge
   IKE_EAP_MSCHAPV2_CODE_RESPONSE   = 2, ///<Response
   IKE_EAP_MSCHAPV2_CODE_SUCCESS    = 3, ///<Success
   IKE_EAP_MSCHAPV2_CODE_FAILURE    = 4  ///<Failure
} IkeEapMschapv2Code;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief EAP MS-CHAP-V2 packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t opcode;     //5
} IkeEapMschapv2Packet;


/**
 * @brief EAP MS-CHAP-V2 Challenge packet
 **/

typedef __packed_struct
{
   uint8_t code;          //0
   uint8_t identifier;    //1
   uint16_t length;       //2-3
   uint8_t type;          //4
   uint8_t opcode;        //5
   uint8_t mschapv2Id;    //6
   uint16_t msLength;     //7-8
   uint8_t valueSize;     //9
   uint8_t challenge[16]; //10-25
   uint8_t name[];        //26
} IkeEapMschapv2Challenge;


/**
 * @brief EAP MS-CHAP-V2 Response packet
 **/

typedef __packed_struct
{
   uint8_t code;              //0
   uint8_t identifier;        //1
   uint16_t length;           //2-3
   uint8_t type;              //4
   uint8_t opcode;            //5
   uint8_t mschapv2Id;        //6
   uint16_t msLength;         //7-8
   uint8_t valueSize;         //9
   uint8_t peerChallenge[16]; //10-25
   uint8_t reserved[8];       //26-33
   uint8_t ntResponse[24];    //34-57
   uint8_t flags;             //58
   uint8_t name[];            //59
} IkeEapMschapv2Response;


/**
 * @brief EAP MS-CHAP-V2 Success Request packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
   uint8_t mschapv2Id;   //6
   uint16_t msLength;    //7-8
   uint8_t message[];    //9
} IkeEapMschapv2SuccessRequest;


/**
 * @brief EAP MS-CHAP-V2 Success Response packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
} IkeEapMschapv2SuccessResponse;


/**
 * @brief EAP MS-CHAP-V2 Failure Request packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
   uint8_t mschapv2Id;   //6
   uint16_t msLength;    //7-8
   uint8_t message[];    //9
} IkeEapMschapv2FailureRequest;


/**
 * @brief EAP MS-CHAP-V2 Failure Response packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
} IkeEapMschapv2FailureResponse;


/**
 * @brief EAP MS-CHAP-V2 Change-Password packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t opcode;     //5
   uint8_t mschapv2Id; //6
   uint16_t msLength;  //7-8
   uint8_t data[];     //9
} IkeEapMschapv2ChangePassword;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//EAP MS-CHAP-V2 related functions
error_t ikeProcessEapMschapv2Request(IkeSaEntry *sa,
   const IkeEapMschapv2Packet *request, size_t length);

error_t ikeProcessEapMschapv2Challenge(IkeSaEntry *sa,
   const IkeEapMschapv2Challenge *challenge, size_t length);

error_t ikeProcessEapMschapv2SuccessRequest(IkeSaEntry *sa,
   const IkeEapMschapv2SuccessRequest *request, size_t length);

error_t ikeProcessEapMschapv2FailureRequest(IkeSaEntry *sa,
   const IkeEapMschapv2FailureRequest *request, size_t length);

error_t ikeFormatEapMschapv2Response(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatEapMschapv2SuccessResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

error_t ikeFormatEapMschapv2FailureResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *written);

void ikeEapMschapv2GenerateNtResponse(const uint8_t *authChallenge,
   const uint8_t *peerChallenge, const char_t *username,
   const char_t *password, uint8_t *response);

void ikeEapMschapv2ChallengeHash(const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *challenge);

void ikeEapMschapv2NtPasswordHash(const char_t *password, uint8_t *passwordHash);

void ikeEapMschapv2HashNtPasswordHash(const uint8_t *passwordHash,
   uint8_t *passwordHashHash);

void ikeEapMschapv2ChallengeResponse(const uint8_t *challenge,
   const uint8_t *passwordHash, uint8_t *response);

void ikeEapMschapv2GenerateAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *authResponse);

bool_t ikeEapMschapv2CheckAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username,
   const uint8_t *receivedResponse);

void ikeEapMschapv2GenerateMasterSessionKey(const char_t *password,
   const uint8_t *ntResponse, uint8_t *masterSessionKey);

void ikeEapMschapv2GetMasterKey(const uint8_t *passwordHashHash,
   const uint8_t *ntResponse, uint8_t *masterKey);

void ikeEapMschapv2GetAsymmetricStartKey(const uint8_t *masterKey,
   uint8_t *sessionKey, size_t sessionKeyLen, bool_t isSend);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
