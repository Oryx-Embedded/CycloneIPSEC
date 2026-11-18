/**
 * @file ike_request_format.c
 * @brief IKE request formatting
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
#include "ike/ike_fsm.h"
#include "ike/ike_message_encrypt.h"
#include "ike/ike_request_format.h"
#include "ike/ike_payload_format.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Send IKE request message
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendRequest(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Debug message
   TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->requestLen);
   //Dump IKE message for debugging purpose
   ikeDumpMessage(sa->request + IKE_PREFIX_SIZE, sa->requestLen);

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //IKE packets must be sent from UDP port 500 or 4500
   if(sa->localNat || sa->remoteNat)
   {
      //The UDP payload of all packets containing IKE messages sent on port 4500
      //must begin with the prefix of four zeros (refer to RFC 7296, section 2)
      error = socketSendTo(context->altSocket, &sa->remoteIpAddr, IPSEC_NAT_PORT,
         sa->request, sa->requestLen + IKE_PREFIX_SIZE, NULL, 0);
   }
   else
#endif
   {
      //Send the IKE request on port 500
      error = socketSendTo(context->socket, &sa->remoteIpAddr, IKE_PORT,
         sa->request + IKE_PREFIX_SIZE, sa->requestLen, NULL, 0);
   }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //A peer should send a NAT-keepalive packet if no other packet to the peer
   //has been sent in M seconds (refer to RFC 3948, section 4)
   sa->natKeepAliveTimestamp = osGetSystemTime();
#endif

   //Return status code
   return error;
}


/**
 * @brief Send IKE_SA_INIT request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendIkeSaInitRequest(IkeSaEntry *sa)
{
   error_t error;

   //The Message ID is a 32-bit quantity, which is zero for the IKE_SA_INIT
   //messages (including retries of the message due to responses such as
   //COOKIE and INVALID_KE_PAYLOAD)
   sa->txMessageId = 0;

   //Four octets of zero are prepended to the IKE header
   STORE32BE(IKE_PREFIX_VALUE, sa->request);

   //Format IKE_SA_INIT request
   error = ikeFormatIkeSaInitRequest(sa, sa->request + IKE_PREFIX_SIZE,
      &sa->requestLen);

   //Check status code
   if(!error)
   {
      //Send IKE request
      ikeSendRequest(sa);

      //Wait for the IKE_SA_INIT response from the responder
      ikeChangeSaState(sa, IKE_SA_STATE_INIT_RESP);
   }

   //Return status code
   return error;
}


/**
 * @brief Send IKE_AUTH request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendIkeAuthRequest(IkeSaEntry *sa)
{
   error_t error;

   //The message ID is incremented for each subsequent exchange
   sa->txMessageId++;

   //Four octets of zero are prepended to the IKE header
   STORE32BE(IKE_PREFIX_VALUE, sa->request);

   //Format IKE_AUTH request
   error = ikeFormatIkeAuthRequest(sa, sa->request + IKE_PREFIX_SIZE,
      &sa->requestLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->request + IKE_PREFIX_SIZE,
         &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //Send IKE request
      ikeSendRequest(sa);

      //Wait for the IKE_AUTH response from the responder
      ikeChangeSaState(sa, IKE_SA_STATE_AUTH_RESP);
   }

   //Return status code
   return error;
}


/**
 * @brief Send CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendCreateChildSaRequest(IkeSaEntry *sa)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;

   //The message ID is incremented for each subsequent exchange
   sa->txMessageId++;

   //Four octets of zero are prepended to the IKE header
   STORE32BE(IKE_PREFIX_VALUE, sa->request);

   //Format CREATE_CHILD_SA request
   error = ikeFormatCreateChildSaRequest(sa, sa->request + IKE_PREFIX_SIZE,
      &sa->requestLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->request + IKE_PREFIX_SIZE,
         &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //Send IKE request
      ikeSendRequest(sa);

      //Wait for the CREATE_CHILD_SA response
      if(sa->state == IKE_SA_STATE_REKEY_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_RESP);
      }
      else if(sa->state == IKE_SA_STATE_CREATE_CHILD_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_CREATE_CHILD_RESP);
      }
      else if(sa->state == IKE_SA_STATE_REKEY_CHILD_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_CHILD_RESP);
      }
      else
      {
         //Just for sanity
      }
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send INFORMATIONAL request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendInfoRequest(IkeSaEntry *sa)
{
   error_t error;

   //The message ID is incremented for each subsequent exchange
   sa->txMessageId++;

   //Four octets of zero are prepended to the IKE header
   STORE32BE(IKE_PREFIX_VALUE, sa->request);

   //Format INFORMATIONAL request
   error = ikeFormatInfoRequest(sa, sa->request + IKE_PREFIX_SIZE,
      &sa->requestLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->request + IKE_PREFIX_SIZE,
         &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //Send IKE request
      ikeSendRequest(sa);

      //Wait for the INFORMATIONAL response
      if(sa->state == IKE_SA_STATE_DPD_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_DPD_RESP);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_DELETE_RESP);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_CHILD_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_DELETE_CHILD_RESP);
      }
      else if(sa->state == IKE_SA_STATE_AUTH_FAILURE_REQ)
      {
         ikeChangeSaState(sa, IKE_SA_STATE_AUTH_FAILURE_RESP);
      }
      else
      {
         //Just for sanity
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send NAT-keepalive packet
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendNatKeepalive(IkeSaEntry *sa)
{
#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //The sender must use a one octet long payload with the value 0xFF (refer to
   //RFC 3948, section 2.3)
   context->message[0] = IKE_NAT_KEEPALIVE_PACKET_VALUE;
   context->messageLen = IKE_NAT_KEEPALIVE_PACKET_SIZE;

   //Debug message
   TRACE_INFO("Sending NAT keepalive packet (%" PRIuSIZE " bytes)...\r\n",
      context->messageLen);

   //The sole purpose of sending NAT-keepalive packets is to keep NAT mappings
   //alive for the duration of a connection between the peers
   socketSendTo(context->altSocket, &sa->remoteIpAddr, IPSEC_NAT_PORT,
      context->message, context->messageLen, NULL, 0);

   //Save the time at which the NAT-keepalive packet was sent
   sa->natKeepAliveTimestamp = osGetSystemTime();

   //Successful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support NAT traversal (refer
   //to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format IKE_SA_INIT request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatIkeSaInitRequest(IkeSaEntry *sa, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *nextPayload;
   IkeHeader *ikeHeader;

   //Total length of the message
   *length = 0;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) p;

   //Format IKE header
   osMemcpy(ikeHeader->initiatorSpi, sa->initiatorSpi, IKE_SPI_SIZE);
   osMemset(ikeHeader->responderSpi, 0, IKE_SPI_SIZE);
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   ikeHeader->majorVersion = IKE_MAJOR_VERSION;
   ikeHeader->minorVersion = IKE_MINOR_VERSION;
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_IKE_SA_INIT;
   ikeHeader->flags = IKE_FLAGS_I;
   ikeHeader->messageId = HTONL(0);

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //If the IKE_SA_INIT response includes the COOKIE notification, the
   //initiator must then retry the IKE_SA_INIT request (refer to RFC 7296,
   //section 2.6)
   if(sa->cookieLen > 0)
   {
      //The initiator must include the COOKIE notification containing the
      //received data as the first payload, and all other payloads unchanged
      error = ikeFormatNotifyPayload(sa, NULL, IKE_NOTIFY_MSG_TYPE_COOKIE,
         p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //The SAi payload states the cryptographic algorithms the initiator supports
   //for the IKE SA (refer to RFC 7296, section 1.2)
   error = ikeFormatSaPayload(sa, NULL, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //The KEi payload sends the initiator's Diffie-Hellman value
   error = ikeFormatKePayload(&sa->keContext, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //The initiator sends its nonce in the Ni payload
   error = ikeFormatNoncePayload(sa, NULL, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //There MAY be multiple NAT_DETECTION_SOURCE_IP payloads in a message if the
   //sender does not know which of several network attachments will be used to
   //send the packet (refer to RFC 7296, section 2.23)
   error = ikeFormatNotifyPayload(sa, NULL,
      IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_SOURCE_IP, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //The NAT_DETECTION_DESTINATION_IP payloads can be used to detect if there is
   //NAT between the hosts
   error = ikeFormatNotifyPayload(sa, NULL,
      IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_DESTINATION_IP, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;
#endif

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   //The supported hash algorithms that can be used for the signature algorithms
   //are indicated with a Notify payload of type SIGNATURE_HASH_ALGORITHMS sent
   //inside the IKE_SA_INIT exchange (refer to RFC 7427, section 4)
   error = ikeFormatNotifyPayload(sa, NULL,
      IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;
#endif

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format IKE_AUTH request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatIkeAuthRequest(IkeSaEntry *sa, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *nextPayload;
   IkeHeader *ikeHeader;

   //Total length of the message
   *length = 0;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) p;

   //Format IKE header
   osMemcpy(ikeHeader->initiatorSpi, sa->initiatorSpi, IKE_SPI_SIZE);
   osMemcpy(ikeHeader->responderSpi, sa->responderSpi, IKE_SPI_SIZE);
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   ikeHeader->majorVersion = IKE_MAJOR_VERSION;
   ikeHeader->minorVersion = IKE_MINOR_VERSION;
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_IKE_AUTH;
   ikeHeader->flags = IKE_FLAGS_I;
   ikeHeader->messageId = htonl(sa->txMessageId);

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //Check EAP state
   if(sa->eapState == IKE_EAP_STATE_DISABLED ||
      sa->eapState == IKE_EAP_STATE_INIT)
   {
      //The initiator asserts its identity with the IDi payload (refer to
      //RFC 7296, section 1.2)
      error = ikeFormatIdPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //The initiator might send its certificate(s) in CERT payload(s)
      error = ikeFormatCertPayloads(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
      //The INITIAL_CONTACT notification asserts that this IKE SA is the only
      //IKE SA currently active between the authenticated identities
      if(ikeIsInitialContact(sa))
      {
         //It may be sent when an IKE SA is established after a crash, and the
         //recipient may use this information to delete any other IKE SAs it
         //has to the same authenticated identity without waiting for a timeout
         error = ikeFormatNotifyPayload(sa, NULL,
            IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Point to the next payload
         p += n;
         *length += n;
      }
#endif

      //The initiator might also send list of its trust anchors in CERTREQ
      //payload(s)
      error = ikeFormatCertReqPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //Check EAP state
   if(sa->eapState == IKE_EAP_STATE_DISABLED ||
      sa->eapState == IKE_EAP_STATE_SUCCESS)
   {
      //The initiator proves knowledge of the secret corresponding to IDi and
      //integrity protects the contents of the first message using the AUTH
      //payload
      error = ikeFormatAuthPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }
   else if(sa->eapState == IKE_EAP_STATE_INIT)
   {
      //An initiator indicates a desire to use EAP by leaving out the AUTH
      //payload from the first message in the IKE_AUTH exchange (refer to
      //RFC 7296, section 2.16)
   }
   else
   {
      //The Extensible Authentication Protocol payload allows IKE SAs to be
      //authenticated using the EAP protocol
      error = ikeFormatEapPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //Check EAP state
   if(sa->eapState == IKE_EAP_STATE_DISABLED ||
      sa->eapState == IKE_EAP_STATE_INIT)
   {

      //Child SAs can be created either by being piggybacked on the IKE_AUTH
      //exchange, or using a separate CREATE_CHILD_SA exchange
      if(sa->childSa1 != NULL)
      {
         //Piggyback setup of the Child SA
         error = ikeFormatChildSaCreateRequest(sa, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Total length of the message
         *length += n;
      }
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatCreateChildSaRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *nextPayload;
   IkeHeader *ikeHeader;

   //Total length of the message
   *length = 0;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) p;

   //Format IKE header
   osMemcpy(ikeHeader->initiatorSpi, sa->initiatorSpi, IKE_SPI_SIZE);
   osMemcpy(ikeHeader->responderSpi, sa->responderSpi, IKE_SPI_SIZE);
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   ikeHeader->majorVersion = IKE_MAJOR_VERSION;
   ikeHeader->minorVersion = IKE_MINOR_VERSION;
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_CREATE_CHILD_SA;
   ikeHeader->messageId = htonl(sa->txMessageId);

   //This I bit must be set in messages sent by the original initiator of the
   //IKE SA and must be cleared in messages sent by the original responder
   if(sa->originalInitiator)
   {
      ikeHeader->flags = IKE_FLAGS_I;
   }
   else
   {
      ikeHeader->flags = 0;
   }

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //The CREATE_CHILD_SA exchange is used to create new Child SAs and to rekey
   //both IKE SAs and Child SAs (refer to RFC 7296, section 1.3)
   if(sa->state == IKE_SA_STATE_REKEY_REQ)
   {
      //IKE SA rekeying
      error = ikeFormatIkeSaRekeyRequest(sa, p, &n, &nextPayload);
   }
   else if(sa->state == IKE_SA_STATE_CREATE_CHILD_REQ ||
      sa->state == IKE_SA_STATE_REKEY_CHILD_REQ)
   {
      //Child SA creation/rekeying
      error = ikeFormatChildSaCreateRequest(sa, p, &n, &nextPayload);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_STATE;
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;

      //The Length field indicates the total length of the IKE message in octets
      ikeHeader->length = htonl(*length);
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format INFORMATIONAL request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatInfoRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *nextPayload;
   IkeHeader *ikeHeader;

   //Total length of the message
   *length = 0;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) p;

   //Format IKE header
   osMemcpy(ikeHeader->initiatorSpi, sa->initiatorSpi, IKE_SPI_SIZE);
   osMemcpy(ikeHeader->responderSpi, sa->responderSpi, IKE_SPI_SIZE);
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   ikeHeader->majorVersion = IKE_MAJOR_VERSION;
   ikeHeader->minorVersion = IKE_MINOR_VERSION;
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_INFORMATIONAL;
   ikeHeader->messageId = htonl(sa->txMessageId);

   //This I bit must be set in messages sent by the original initiator of the
   //IKE SA and must be cleared in messages sent by the original responder
   if(sa->originalInitiator)
   {
      ikeHeader->flags = IKE_FLAGS_I;
   }
   else
   {
      ikeHeader->flags = 0;
   }

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_DPD_REQ)
   {
      //An INFORMATIONAL request with no payloads is commonly used as a check
      //for liveness (refer to RFC 7296, section 1)
   }
   else if(sa->state == IKE_SA_STATE_DELETE_REQ ||
      sa->state == IKE_SA_STATE_DELETE_CHILD_REQ)
   {
      //To delete an SA, an INFORMATIONAL exchange with one or more Delete
      //payloads is sent listing the SPIs (as they would be expected in the
      //headers of inbound packets) of the SAs to be deleted
      error = ikeFormatDeletePayload(sa, sa->childSa1, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Total length of the message
      *length += n;
   }
   else if(sa->state == IKE_SA_STATE_AUTH_FAILURE_REQ)
   {
      //All errors causing the authentication to fail for whatever reason
      //(invalid shared secret, invalid ID, untrusted certificate issuer,
      //revoked or expired certificate, etc.) should result in an
      //AUTHENTICATION_FAILED notification
      error = ikeFormatNotifyPayload(sa, NULL, IKE_NOTIFY_MSG_TYPE_AUTH_FAILED,
         p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Total length of the message
      *length += n;
   }
   else
   {
      //Just for sanity
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Child SA creation/rekeying request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payloads
 * @param[out] length Length of the resulting payloads, in bytes
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatChildSaCreateRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length, uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeChildSaEntry *childSa;

   //Point to the Child SA
   childSa = sa->childSa1;

   //Total length of the payloads
   *length = 0;

   //Child SA rekeying?
   if(sa->state == IKE_SA_STATE_REKEY_CHILD_REQ)
   {
      //The REKEY_SA notification must be included in a CREATE_CHILD_SA exchange if
      //the purpose of the exchange is to replace an existing ESP or AH SA (refer
      //to RFC 7296, section 1.3.3)
      error = ikeFormatNotifyPayload(sa, childSa,
         IKE_NOTIFY_MSG_TYPE_REKEY_SA, p, &n, nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //The USE_TRANSPORT_MODE notification may be included in a request message
   //that also includes an SA payload requesting a Child SA. It requests that
   //the Child SA use transport mode rather than tunnel mode for the SA created
   //(refer to RFC 7296, section 1.3.1)
   if(childSa->mode == IPSEC_MODE_TRANSPORT)
   {
      //Include a notification of type USE_TRANSPORT_MODE
      error = ikeFormatNotifyPayload(sa, childSa,
         IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE, p, &n, nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //The initiator sends SA offers in the SAi payload
   error = ikeFormatChildSaPayload(childSa, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //Child SA creation/rekeying?
   if(sa->state == IKE_SA_STATE_CREATE_CHILD_REQ ||
      sa->state == IKE_SA_STATE_REKEY_CHILD_REQ)
   {
      //The initiator sends a nonce in the Ni payload
      error = ikeFormatNoncePayload(sa, childSa, p, &n, nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      //Perfect forward secrecy?
      if(childSa->pfs)
      {
         //Optionally, the initiator sends a Diffie-Hellman value in the KEi
         //payload (refer to RFC 7296, section 1.3.1)
         error = ikeFormatKePayload(&childSa->keContext, p, &n, nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Point to the next payload
         p += n;
         *length += n;
      }
#endif
   }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //Child SA creation?
   if(sa->state == IKE_SA_STATE_INIT_RESP ||
      sa->state == IKE_SA_STATE_CREATE_CHILD_REQ)
   {
      //NAT detected?
      if(sa->localNat || sa->remoteNat)
      {
         //Check if the client is proposing transport mode
         if(childSa->mode == IPSEC_MODE_TRANSPORT)
         {
            //The TSi entries must have exactly one IP address, and that must
            //match the source address of the IKE SA (refer to RFC 7296,
            //section 2.23.1)
            childSa->selector.localIpAddr.start = childSa->packetInfo.localIpAddr;
            childSa->selector.localIpAddr.end = childSa->packetInfo.localIpAddr;

            //The TSr entries must have exactly one IP address, and that must
            //match the destination address of the IKE SA
            childSa->selector.remoteIpAddr.start = childSa->packetInfo.remoteIpAddr;
            childSa->selector.remoteIpAddr.end = childSa->packetInfo.remoteIpAddr;
         }
      }
   }
#endif

   //TSi specifies the source address of traffic forwarded from (or the
   //destination address of traffic forwarded to) the initiator of the
   //Child SA pair
   error = ikeFormatTsiPayload(childSa, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //TSr specifies the destination address of the traffic forwarded to (or
   //the source address of the traffic forwarded from) the responder of the
   //Child SA pair
   error = ikeFormatTsrPayload(childSa, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Total length of the payloads
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format IKE SA rekeying request
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payloads
 * @param[out] length Length of the resulting payloads, in bytes
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatIkeSaRekeyRequest(IkeSaEntry *sa, uint8_t *p, size_t *length,
   uint8_t **nextPayload)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   IkeSaEntry *newSa;

   //Point to the new IKE SA
   newSa = sa->newSa1;

   //Total length of the payloads
   *length = 0;

   //A new initiator SPI is supplied in the SPI field of the SA payload
   //(refer to 7296, section 1.3.2)
   error = ikeFormatSaPayload(newSa, newSa->initiatorSpi, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //The initiator sends its nonce in the Ni payload
   error = ikeFormatNoncePayload(newSa, NULL, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //The KEi payload sends the initiator's Diffie-Hellman value
   error = ikeFormatKePayload(&newSa->keContext, p, &n, nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Total length of the payloads
   *length += n;

   //Successful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
