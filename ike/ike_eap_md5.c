/**
 * @file ike_eap_md5.c
 * @brief EAP-MD5 authentication method
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
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_EAP_AUTH_SUPPORT == ENABLED && IKE_EAP_MD5_SUPPORT == ENABLED)


/**
 * @brief Process EAP-MD5 request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] packet Pointer to the EAP-MD5 request
 * @param[in] length Length of the EAP-MD5 request, in bytes
 * @return Error code
 **/

error_t ikeProcessEapMd5Request(IkeSaEntry *sa, const IkeEapMd5Packet *request,
   size_t length)
{
   IkeContext *context;
   Md5Context md5Context;

   //Point to the IKE context
   context = sa->context;

   //Check current state
   if(sa->eapState != IKE_EAP_STATE_INIT &&
      sa->eapState != IKE_EAP_STATE_IDENTITY)
   {
      return ERROR_WRONG_STATE;
   }

   //Malformed EAP-MD5 packet?
   if(length < sizeof(IkeEapMd5Packet))
      return ERROR_INVALID_LENGTH;

   //Check the length of the challenge value
   if(length < (sizeof(IkeEapMd5Packet) + request->valueSize))
      return ERROR_INVALID_LENGTH;

   //The MD5 challenge method is analogous to the PPP CHAP protocol (with MD5
   //as the specified algorithm)
   md5Init(&md5Context);
   md5Update(&md5Context, &request->identifier, sizeof(uint8_t));
   md5Update(&md5Context, context->password, osStrlen(context->password));
   md5Update(&md5Context, request->value, request->valueSize);
   md5Final(&md5Context, sa->digest);
   md5Deinit(&md5Context);

   //EAP-MD5 does not generate a master session key
   sa->mskLen = 0;

   //Send an EAP-MD5 response
   sa->eapState = IKE_EAP_STATE_MD5_CHALLENGE;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Format EAP-MD5 response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the EAP-MD5 packet
 * @param[out] written Length of the resulting EAP-MD5 packet
 * @return Error code
 **/

error_t ikeFormatEapMd5Response(IkeSaEntry *sa, uint8_t *p, size_t *written)
{
   IkeEapMd5Packet *response;

   //Point to the buffer where to format the EAP packet
   response = (IkeEapMd5Packet *) p;

   //Format EAP packet
   response->code = IKE_EAP_CODE_RESPONSE;
   response->identifier = sa->eapRequestId;
   response->type = IKE_EAP_METHOD_TYPE_MD5_CHALLENGE;
   response->valueSize = MD5_DIGEST_SIZE;

   //The length of the response value depends upon the hash algorithm used
   osMemcpy(response->value, sa->digest, MD5_DIGEST_SIZE);

   //Total length of the EAP packet
   *written = sizeof(IkeEapMd5Packet) + MD5_DIGEST_SIZE;
   //Convert the length field to network byte order
   response->length = htons(*written);

   //Sucessful processing
   return NO_ERROR;
}

#endif
