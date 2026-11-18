/**
 * @file ike_eap.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ike/ike.h"
#include "ike/ike_eap.h"
#include "ike/ike_eap_md5.h"
#include "ike/ike_eap_mschapv2.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_EAP_AUTH_SUPPORT == ENABLED)


/**
 * @brief Process EAP packet
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP packet
 * @param[in] length Length of the EAP packet, in bytes
 * @return Error code
 **/

error_t ikeProcessEapPacket(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length)
{
   error_t error;

   //Malformed EAP packet?
   if(length < sizeof(IkeEapPacket))
      return ERROR_INVALID_LENGTH;

   //The Length field is two octets and indicates the length, in octets, of the
   //EAP packet including the Code, Identifier, Length, and Data fields
   if(ntohs(packet->length) < sizeof(IkeEapPacket))
      return ERROR_INVALID_LENGTH;

   //A message with the Length field set to a value larger than the number of
   //received octets must be silently discarded (refer to RFC 3748, section 4.0)
   if(ntohs(packet->length) > length)
      return ERROR_INVALID_LENGTH;

   //Octets outside the range of the Length field should be treated as data
   //link layer padding and must be ignored upon reception
   length = ntohs(packet->length);

   //Based on the Code field, the EAP layer demultiplexes incoming EAP packets
   //to the EAP peer and authenticator layers
   if(packet->code == IKE_EAP_CODE_REQUEST)
   {
      //Process EAP request
      error = ikeProcessEapRequest(sa, (IkeEapRequest *) packet, length);
   }
   else if(packet->code == IKE_EAP_CODE_SUCCESS)
   {
      //Process EAP success packet
      error = ikeProcessEapSuccess(sa, packet, length);
   }
   else if(packet->code == IKE_EAP_CODE_FAILURE)
   {
      //Process EAP failure packet
      error = ikeProcessEapFailure(sa, packet, length);
   }
   else
   {
      //Unknown EAP packet
      error = ERROR_UNKNOWN_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Process EAP request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP request
 * @param[in] length Length of the EAP request, in bytes
 * @return Error code
 **/

error_t ikeProcessEapRequest(IkeSaEntry *sa, const IkeEapRequest *request,
   size_t length)
{
   error_t error;

   //Malformed EAP request?
   if(length < sizeof(IkeEapRequest))
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   error = NO_ERROR;

   //Since in IKE, EAP runs over a reliable protocol, the Identifier serves no
   //function here. In a response message, this octet must be set to match the
   //identifier in the corresponding request (refer to RFC 7296, section 3.16)
   sa->eapRequestId = request->identifier;

   //Check method type
   if(request->type == IKE_EAP_METHOD_TYPE_IDENTITY)
   {
      //Process Identity request
      error = ikeProcessEapIdentityRequest(sa, request, length);
   }
#if (IKE_EAP_MD5_SUPPORT == ENABLED)
   else if(request->type == IKE_EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Process EAP-MD5 request
      error = ikeProcessEapMd5Request(sa, (IkeEapMd5Packet *) request, length);
   }
#endif
#if (IKE_EAP_MSCHAPV2_SUPPORT == ENABLED)
   else if(request->type == IKE_EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Process EAP MS-CHAP-V2 request
      error = ikeProcessEapMschapv2Request(sa, (IkeEapMschapv2Packet *) request,
         length);
   }
#endif
   else
   {
      //The method type is unacceptable
      sa->eapState = IKE_EAP_STATE_NAK;
   }

   //Return status code
   return error;
}


/**
 * @brief Process EAP Identity request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP Identity request
 * @param[in] length Length of the EAP Identity request, in bytes
 * @return Error code
 **/

error_t ikeProcessEapIdentityRequest(IkeSaEntry *sa,
   const IkeEapRequest *request, size_t length)
{
   //Check current state
   if(sa->eapState != IKE_EAP_STATE_INIT)
      return ERROR_WRONG_STATE;

   //Since IKE passes an indication of initiator identity in the first message
   //in the IKE_AUTH exchange, the responder should not send EAP Identity
   //requests. The initiator may, however, respond to such requests if it
   //receives them (refer to RFC 7296, section 3.16)
   sa->eapState = IKE_EAP_STATE_IDENTITY;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Process EAP success packet
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP success packet
 * @param[in] length Length of the EAP success packet, in bytes
 * @return Error code
 **/

error_t ikeProcessEapSuccess(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length)
{
   //Check current state
   if(sa->eapState != IKE_EAP_STATE_MD5_CHALLENGE &&
      sa->eapState != IKE_EAP_STATE_MSCHAPV2_SUCCESS)
   {
      return ERROR_WRONG_STATE;
   }

   //The Success packet is sent by the authenticator to the peer after
   //completion of an EAP authentication method to indicate that the peer has
   //authenticated successfully to the authenticator (refer to RFC 3748,
   //section 4.2)
   sa->eapState = IKE_EAP_STATE_SUCCESS;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Process EAP failure packet
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP failure packet
 * @param[in] length Length of the EAP failure packet, in bytes
 * @return Error code
 **/

error_t ikeProcessEapFailure(IkeSaEntry *sa, const IkeEapPacket *packet,
   size_t length)
{
   //The authenticator cannot authenticate the peer
   sa->eapState = IKE_EAP_STATE_FAILURE;

   //The responder may at any time terminate the IKE exchange by sending an EAP
   //payload containing the Failure message (refer to RFC 7296, section 2.16)
   return ERROR_AUTHENTICATION_FAILED;
}


/**
 * @brief Format EAP packet
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the EAP packet
 * @param[out] written Length of the resulting EAP packet
 * @return Error code
 **/

error_t ikeFormatEapPacket(IkeSaEntry *sa, uint8_t *p, size_t *written)
{
   error_t error;

   //Check current state
   if(sa->eapState == IKE_EAP_STATE_IDENTITY)
   {
      //Format Identity response
      error = ikeFormatEapIdentityResponse(sa, p, written);
   }
   else if(sa->eapState == IKE_EAP_STATE_NAK)
   {
      //Format Nak response
      error = ikeFormatEapNakResponse(sa, p, written);
   }
#if (IKE_EAP_MD5_SUPPORT == ENABLED)
   else if(sa->eapState == IKE_EAP_STATE_MD5_CHALLENGE)
   {
      //Format EAP-MD5 response
      error = ikeFormatEapMd5Response(sa, p, written);
   }
#endif
#if (IKE_EAP_MSCHAPV2_SUPPORT == ENABLED)
   else if(sa->eapState == IKE_EAP_STATE_MSCHAPV2_CHALLENGE)
   {
      //Format EAP MS-CHAP-V2 Response packet
      error = ikeFormatEapMschapv2Response(sa, p, written);
   }
   else if(sa->eapState == IKE_EAP_STATE_MSCHAPV2_SUCCESS)
   {
      //Format EAP MS-CHAP-V2 Success Response packet
      error = ikeFormatEapMschapv2SuccessResponse(sa, p, written);
   }
   else if(sa->eapState == IKE_EAP_STATE_MSCHAPV2_FAILURE)
   {
      //Format EAP MS-CHAP-V2 Failure Response packet
      error = ikeFormatEapMschapv2FailureResponse(sa, p, written);
   }
#endif
   else
   {
      //Report an error
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format EAP Identity response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the EAP Identity response
 * @param[out] written Length of the resulting EAP Identity response
 * @return Error code
 **/

error_t ikeFormatEapIdentityResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *written)
{
   size_t n;
   IkeContext *context;
   IkeEapResponse *response;

   //Point to the IKE context
   context = sa->context;

   //Point to the buffer where to format the EAP packet
   response = (IkeEapResponse *) p;

   //A response of type 1 (Identity) should be sent in response to a request
   //with a type of 1 (Identity)
   response->code = IKE_EAP_CODE_RESPONSE;
   response->identifier = sa->eapRequestId;
   response->type = IKE_EAP_METHOD_TYPE_IDENTITY;

   //Determine the length of the user name
   n = osStrlen(context->username);
   //Copy user name
   osMemcpy(response->data, context->username, n);

   //Total length of the EAP packet
   *written = sizeof(IkeEapResponse) + n;
   //Convert the length field to network byte order
   response->length = htons(*written);

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Format EAP Nak response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the EAP Nak response
 * @param[out] written Length of the resulting EAP Nak response
 * @return Error code
 **/

error_t ikeFormatEapNakResponse(IkeSaEntry *sa, uint8_t *p, size_t *written)
{
   size_t n;
   IkeEapResponse *response;

   //Point to the buffer where to format the EAP packet
   response = (IkeEapResponse *) p;

   //The legacy Nak Type is valid only in response messages. It is sent in
   //reply to a request where the desired authentication type is unacceptable
   //(refer to RFC 3748, section 5.3.1)
   response->code = IKE_EAP_CODE_RESPONSE;
   response->identifier = sa->eapRequestId;
   response->type = IKE_EAP_METHOD_TYPE_NAK;

   //The response contains one or more authentication types desired by the peer
   n = 0;

#if (IKE_EAP_MD5_SUPPORT == ENABLED)
   //MD5-Challenge authentication method
   response->data[n++] = IKE_EAP_METHOD_TYPE_MD5_CHALLENGE;
#endif

#if (IKE_EAP_MSCHAPV2_SUPPORT == ENABLED)
   //MS-CHAP-V2 authentication method
   response->data[n++] = IKE_EAP_METHOD_TYPE_MSCHAPV2;
#endif

   //Type zero is used to indicate that the sender has no viable alternatives,
   //and therefore the authenticator should not send another request after
   //receiving a Nak Response containing a zero value
   if(n == 0)
   {
      response->data[n++] = IKE_EAP_METHOD_TYPE_NONE;
   }

   //Total length of the EAP packet
   *written = sizeof(IkeEapResponse) + n;
   //Convert the length field to network byte order
   response->length = htons(*written);

   //Sucessful processing
   return NO_ERROR;
}

#endif
