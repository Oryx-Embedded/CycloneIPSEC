/**
 * @file ike_eap_debug.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ike/ike.h"
#include "ike/ike_debug.h"
#include "ike/ike_eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (IKE_EAP_AUTH_SUPPORT == ENABLED && IKE_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)

//EAP codes
static const IkeParamName ikeEapCodeList[] =
{
   {IKE_EAP_CODE_REQUEST,  "Request"},
   {IKE_EAP_CODE_RESPONSE, "Response"},
   {IKE_EAP_CODE_SUCCESS,  "Success"},
   {IKE_EAP_CODE_FAILURE,  "Failure"}
};

//EAP method types
static const IkeParamName methodTypeList[] =
{
   {IKE_EAP_METHOD_TYPE_IDENTITY,      "Identity"},
   {IKE_EAP_METHOD_TYPE_NOTIFICATION,  "Notification"},
   {IKE_EAP_METHOD_TYPE_NAK,           "Nak"},
   {IKE_EAP_METHOD_TYPE_MD5_CHALLENGE, "MD5-Challenge"},
   {IKE_EAP_METHOD_TYPE_OTP,           "One-Time Password"},
   {IKE_EAP_METHOD_TYPE_GTC,           "Generic Token Card"},
   {IKE_EAP_METHOD_TYPE_TLS,           "EAP-TLS"},
   {IKE_EAP_METHOD_TYPE_TTLS,          "EAP-TTLS"},
   {IKE_EAP_METHOD_TYPE_PEAP,          "PEAP"},
   {IKE_EAP_METHOD_TYPE_MSCHAPV2,      "MS-CHAP-V2"},
   {IKE_EAP_METHOD_TYPE_EXPANDED_NAK,  "Expanded NAK"}
};

//MS-CHAP-V2 opcodes
static const IkeParamName mschapv2OpcodeList[] =
{
   {IKE_EAP_MSCHAPV2_CODE_CHALLENGE, "Challenge"},
   {IKE_EAP_MSCHAPV2_CODE_RESPONSE,  "Response"},
   {IKE_EAP_MSCHAPV2_CODE_SUCCESS,   "Success"},
   {IKE_EAP_MSCHAPV2_CODE_FAILURE,   "Failure"}
};


/**
 * @brief Dump EAP packet
 * @param[in] packet Pointer to the EAP packet
 * @param[in] length Length of the EAP packet, in bytes
 **/

void ikeDumpEapPacket(const IkeEapPacket *packet, size_t length)
{
   //Check the length of the EAP packet
   if(length < sizeof(IkeEapPacket))
      return;

   //Dump EAP header
   ikeDumpEapHeader(packet);

   //Check Code field
   if(packet->code == IKE_EAP_CODE_REQUEST)
   {
      //Dump EAP request
      ikeDumpEapRequest((IkeEapRequest *) packet, length);
   }
   else if(packet->code == IKE_EAP_CODE_RESPONSE)
   {
      //Dump EAP response
      ikeDumpEapResponse((IkeEapResponse *) packet, length);
   }
   else
   {
      //Unknown Code value
   }
}


/**
 * @brief Dump EAP header
 * @param[in] header Pointer to the EAP header
 **/

void ikeDumpEapHeader(const IkeEapPacket *header)
{
   const char_t *codeName;

   //Convert the Code field to string representation
   codeName = ikeGetParamName(header->code, ikeEapCodeList,
      arraysize(ikeEapCodeList));

   //Dump EAP header contents
   TRACE_DEBUG("      Code = %" PRIu8 " (%s)\r\n", header->code, codeName);
   TRACE_DEBUG("      Identifier = %" PRIu8 "\r\n", header->identifier);
   TRACE_DEBUG("      Length = %" PRIu16 "\r\n", ntohs(header->length));
}


/**
 * @brief Dump EAP request
 * @param[in] request Pointer to the EAP request
 * @param[in] length Length of the EAP request, in bytes
 **/

void ikeDumpEapRequest(const IkeEapRequest *request, size_t length)
{
   const char_t *methodTypeName;

   //Malformed EAP request?
   if(length < sizeof(IkeEapRequest))
      return;

   //Convert the Method Type field to string representation
   methodTypeName = ikeGetParamName(request->type, methodTypeList,
      arraysize(methodTypeList));

   //Dump Method Type field
   TRACE_DEBUG("      Method Type = %" PRIu8 " (%s)\r\n", request->type,
      methodTypeName);

   //Check Method Type value
   if(request->type == IKE_EAP_METHOD_TYPE_IDENTITY)
   {
      //Dump Identity request
      ikeDumpEapIdentityRequest(request, length);
   }
   else if(request->type == IKE_EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Dump EAP-MD5 request
      ikeDumpEapMd5Packet((IkeEapMd5Packet *) request, length);
   }
   else if(request->type == IKE_EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Dump EAP MS-CHAP-V2 request
      ikeDumpEapMschapv2Packet((IkeEapMschapv2Packet *) request, length);
   }
   else
   {
      //Unknown Method Type value
   }
}


/**
 * @brief Dump EAP response
 * @param[in] response Pointer to the EAP response
 * @param[in] length Length of the EAP request, in bytes
 **/

void ikeDumpEapResponse(const IkeEapResponse *response, size_t length)
{
   const char_t *methodTypeName;

   //Malformed EAP response?
   if(length < sizeof(IkeEapResponse))
      return;

   //Convert the Method Type field to string representation
   methodTypeName = ikeGetParamName(response->type, methodTypeList,
      arraysize(methodTypeList));

   //Dump Method Type field
   TRACE_DEBUG("      Method Type = %" PRIu8 " (%s)\r\n", response->type,
      methodTypeName);

   //Check Method Type value
   if(response->type == IKE_EAP_METHOD_TYPE_IDENTITY)
   {
      //Dump Identity response
      ikeDumpEapIdentityResponse(response, length);
   }
   else if(response->type == IKE_EAP_METHOD_TYPE_NAK)
   {
      //Dump Nak response
      ikeDumpEapNakResponse(response, length);
   }
   else if(response->type == IKE_EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Dump EAP-MD5 response
      ikeDumpEapMd5Packet((IkeEapMd5Packet *) response, length);
   }
   else if(response->type == IKE_EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Dump EAP MS-CHAP-V2 response
      ikeDumpEapMschapv2Packet((IkeEapMschapv2Packet *) response, length);
   }
   else
   {
      //Unknown EAP method
   }
}


/**
 * @brief Dump Identity request
 * @param[in] request Pointer to the Identity request
 * @param[in] length Length of the Identity request, in bytes
 **/

void ikeDumpEapIdentityRequest(const IkeEapRequest *request, size_t length)
{
   //Retrieve the length of the message
   length -= sizeof(IkeEapRequest);

   //Dump message
   TRACE_DEBUG("      Message (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", request->data, length);
}


/**
 * @brief Dump Identity response
 * @param[in] response Pointer to the Identity response
 * @param[in] length Length of the Identity response, in bytes
 **/

void ikeDumpEapIdentityResponse(const IkeEapResponse *response, size_t length)
{
   //Retrieve the length of the identity
   length -= sizeof(IkeEapResponse);

   //Dump identity
   TRACE_DEBUG("      Identity (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", response->data, length);
}


/**
 * @brief Dump Nak response
 * @param[in] response Pointer to the Nak response
 * @param[in] length Length of the Nak response, in bytes
 **/

void ikeDumpEapNakResponse(const IkeEapResponse *response, size_t length)
{
   size_t i;
   const char_t *name;

   //The response contains one or more authentication types desired by the peer
   length -= sizeof(IkeEapResponse);

   //Debug message
   TRACE_DEBUG("      Authentication Types (%" PRIuSIZE " bytes)\r\n", length);

   //Dump authentication types
   for(i = 0; i < length; i++)
   {
      //Convert the authentication type to string representation
      name = ikeGetParamName(response->data[i], methodTypeList,
         arraysize(methodTypeList));

      //Dump authentication type
      TRACE_DEBUG("        %" PRIu8 " (%s)\r\n", response->data[i], name);
   }
}


/**
 * @brief Dump EAP-MD5 packet
 * @param[in] packet Pointer to the EAP-MD5 packet
 * @param[in] length Length of the EAP-MD5 packet, in bytes
 **/

void ikeDumpEapMd5Packet(const IkeEapMd5Packet *packet, size_t length)
{
   //Malformed EAP-MD5 packet?
   if(length < sizeof(IkeEapMd5Packet))
      return;

   //Check the length of the challenge value
   if(length < (sizeof(IkeEapMd5Packet) + packet->valueSize))
      return;

   //Dump Value-Size field
   TRACE_DEBUG("      Value-Size = %" PRIu8 "\r\n", packet->valueSize);

   //Dump Value field
   TRACE_DEBUG("      Value (%" PRIu8 " bytes)\r\n", packet->valueSize);
   TRACE_DEBUG_ARRAY("        ", packet->value, packet->valueSize);
}


/**
 * @brief Dump EAP MS-CHAP-V2 packet
 * @param[in] request Pointer to the EAP MS-CHAP-V2 request
 * @param[in] length Length of the EAP MS-CHAP-V2 request, in bytes
 **/

void ikeDumpEapMschapv2Packet(const IkeEapMschapv2Packet *packet, size_t length)
{
   const char_t *opcodeName;

   //Malformed MS-CHAP-V2 packet?
   if(length < sizeof(IkeEapMschapv2Packet))
      return;

   //Convert the OpCode field to string representation
   opcodeName = ikeGetParamName(packet->opcode, mschapv2OpcodeList,
      arraysize(mschapv2OpcodeList));

   //Dump OpCode field
   TRACE_DEBUG("      OpCode = %" PRIu8 " (%s)\r\n", packet->opcode, opcodeName);

   //Check Code field
   if(packet->code == IKE_EAP_CODE_REQUEST)
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_CHALLENGE)
      {
         //Dump MS-CHAP-V2 Challenge packet
         ikeDumpEapMschapv2Challenge((IkeEapMschapv2Challenge *) packet,
            length);
      }
      else if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_SUCCESS)
      {
         //Dump MS-CHAP-V2 Success Request packet
         ikeDumpEapMschapv2SuccessRequest((IkeEapMschapv2SuccessRequest *) packet,
            length);
      }
      else if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_FAILURE)
      {
         //Dump MS-CHAP-V2 Failure Request packet
         ikeDumpEapMschapv2FailureRequest((IkeEapMschapv2FailureRequest *) packet,
            length);
      }
      else
      {
         //Unknown OpCode value
      }
   }
   else if(packet->code == IKE_EAP_CODE_RESPONSE)
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_RESPONSE)
      {
         //Dump MS-CHAP-V2 Response packet
         ikeDumpEapMschapv2Response((IkeEapMschapv2Response *) packet,
            length);
      }
      else if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_SUCCESS)
      {
         //Dump MS-CHAP-V2 Success Response packet
         ikeDumpEapMschapv2SuccessResponse((IkeEapMschapv2SuccessResponse *) packet,
            length);
      }
      else if(packet->opcode == IKE_EAP_MSCHAPV2_CODE_FAILURE)
      {
         //Dump MS-CHAP-V2 Failure Response packet
         ikeDumpEapMschapv2FailureResponse((IkeEapMschapv2FailureResponse *) packet,
            length);
      }
      else
      {
         //Unknown OpCode value
      }
   }
   else
   {
      //Unknown Code value
   }
}


/**
 * @brief Dump EAP MS-CHAP-V2 Challenge packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Challenge packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Challenge packet, in bytes
 **/

void ikeDumpEapMschapv2Challenge(const IkeEapMschapv2Challenge *challenge,
   size_t length)
{
   //Malformed MS-CHAP-V2 Challenge packet?
   if(length < sizeof(IkeEapMschapv2Challenge))
      return;

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("      MS-CHAPv2-ID = %" PRIu8 "\r\n", challenge->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("      MS-Length = %" PRIu8 "\r\n", ntohs(challenge->msLength));
   //Dump Value-Size field
   TRACE_DEBUG("      Value-Size = %" PRIu8 "\r\n", challenge->valueSize);

   //Dump Challenge field
   TRACE_DEBUG("      Challenge (%" PRIuSIZE " bytes)\r\n", 16);
   TRACE_DEBUG_ARRAY("        ", challenge->challenge, 16);

   //Retrieve the length of the name
   length -= sizeof(IkeEapMschapv2Challenge);

   //Dump Name field
   TRACE_DEBUG("      Name (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", challenge->name, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Response packet, in bytes
 **/

void ikeDumpEapMschapv2Response(const IkeEapMschapv2Response *response,
   size_t length)
{
   //Malformed MS-CHAP-V2 Response packet?
   if(length < sizeof(IkeEapMschapv2Response))
      return;

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("      MS-CHAPv2-ID = %" PRIu8 "\r\n", response->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("      MS-Length = %" PRIu8 "\r\n", ntohs(response->msLength));
   //Dump Value-Size field
   TRACE_DEBUG("      Value-Size = %" PRIu8 "\r\n", response->valueSize);

   //Dump Peer-Challenge field
   TRACE_DEBUG("      Peer-Challenge (%" PRIuSIZE " bytes)\r\n", 16);
   TRACE_DEBUG_ARRAY("        ", response->peerChallenge, 16);

   //Dump Reserved field
   TRACE_DEBUG("      Reserved (%" PRIuSIZE " bytes)\r\n", 8);
   TRACE_DEBUG_ARRAY("        ", response->reserved, 8);

   //Dump NT-Response field
   TRACE_DEBUG("      NT-Response (%" PRIuSIZE " bytes)\r\n", 24);
   TRACE_DEBUG_ARRAY("        ", response->ntResponse, 24);

   //Retrieve the length of the name
   length -= sizeof(IkeEapMschapv2Response);

   //Dump Name field
   TRACE_DEBUG("      Name (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", response->name, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Success Request packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Success Request packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Success Request packet, in bytes
 **/

void ikeDumpEapMschapv2SuccessRequest(const IkeEapMschapv2SuccessRequest *request,
   size_t length)
{
   //Malformed MS-CHAP-V2 Success Request packet?
   if(length < sizeof(IkeEapMschapv2SuccessRequest))
      return;

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("      MS-CHAPv2-ID = %" PRIu8 "\r\n", request->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("      MS-Length = %" PRIu8 "\r\n", ntohs(request->msLength));

   //Retrieve the length of the message
   length -= sizeof(IkeEapMschapv2SuccessRequest);

   //Dump Message field
   TRACE_DEBUG("      Message (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", request->message, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Success Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Success Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Success Response packet, in bytes
 **/

void ikeDumpEapMschapv2SuccessResponse(const IkeEapMschapv2SuccessResponse *response,
   size_t length)
{
}


/**
 * @brief Dump EAP MS-CHAP-V2 Failure Request packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Failure Request packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Failure Request packet, in bytes
 **/

void ikeDumpEapMschapv2FailureRequest(const IkeEapMschapv2FailureRequest *request,
   size_t length)
{
   //Malformed MS-CHAP-V2 Failure Request packet?
   if(length < sizeof(IkeEapMschapv2FailureRequest))
      return;

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("      MS-CHAPv2-ID = %" PRIu8 "\r\n", request->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("      MS-Length = %" PRIu8 "\r\n", ntohs(request->msLength));

   //Retrieve the length of the message
   length -= sizeof(IkeEapMschapv2FailureRequest);

   //Dump Message field
   TRACE_DEBUG("      Message (%" PRIuSIZE " bytes)\r\n", length);
   ikeDumpString("        ", request->message, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Failure Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Failure Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Failure Response packet, in bytes
 **/

void ikeDumpEapMschapv2FailureResponse(const IkeEapMschapv2FailureResponse *response,
   size_t length)
{
}

#endif
