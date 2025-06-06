/**
 * @file ike_message_format.c
 * @brief IKE message formatting
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

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ike/ike_fsm.h"
#include "ike/ike_algorithms.h"
#include "ike/ike_message_format.h"
#include "ike/ike_message_encrypt.h"
#include "ike/ike_payload_format.h"
#include "ike/ike_auth.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_dh_groups.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "ah/ah_algorithms.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Send IKE_SA_INIT request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendIkeSaInitRequest(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //The Message ID is a 32-bit quantity, which is zero for the IKE_SA_INIT
   //messages (including retries of the message due to responses such as
   //COOKIE and INVALID_KE_PAYLOAD)
   sa->txMessageId = 0;

   //Format IKE_SA_INIT request
   error = ikeFormatIkeSaInitRequest(sa, sa->request, &sa->requestLen);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->requestLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->request, sa->requestLen);

      //Send IKE request
      socketSendTo(context->socket, &sa->remoteIpAddr, sa->remotePort,
         sa->request, sa->requestLen, NULL, 0);

      //Wait for the IKE_SA_INIT response from the responder
      ikeChangeSaState(sa, IKE_SA_STATE_INIT_RESP);
   }

   //Return status code
   return error;
}


/**
 * @brief Send IKE_SA_INIT response
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendIkeSaInitResponse(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //Successful IKE SA creation?
   if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NONE)
   {
      //Save the first message (IKE_SA_INIT request), starting with the first
      //octet of the first SPI in the header and ending with the last octet of
      //the last payload
      osMemcpy(sa->request, context->message, sa->initiatorSaInitLen);
      sa->initiatorSaInit = sa->request;

      //Each endpoint chooses one of the two SPIs and must choose them so as to
      //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
      error = ikeGenerateSaSpi(sa, sa->responderSpi);

      //Check status code
      if(!error)
      {
         //Nonces used in IKEv2 must be randomly chosen and must be at least
         //128 bits in size (refer to RFC 7296, section 2.10)
         error = ikeGenerateNonce(context, sa->responderNonce,
            &sa->responderNonceLen);
      }

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = ikeGenerateDhKeyPair(sa);
      }

      //Check status code
      if(!error)
      {
         //Let g^ir be the Diffie-Hellman shared secret
         error = ikeComputeDhSharedSecret(sa);
      }

      //Check status code
      if(!error)
      {
         //At this point in the negotiation, each party can generate a quantity
         //called SKEYSEED, from which all keys are derived for that IKE SA
         //(refer to RFC 7296, section 1.2)
         error = ikeGenerateSaKeyMaterial(sa, NULL);
      }
   }
   else
   {
      //When the IKE_SA_INIT exchange does not result in the creation of an
      //IKE SA due to INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE, the
      //responder's SPI will be zero also in the response message (refer to
      //RFC 7296, section 2.6)
      osMemset(sa->responderSpi, 0, IKE_SPI_SIZE);
   }

   //Check status code
   if(!error)
   {
      //Format IKE_SA_INIT response
      error = ikeFormatIkeSaInitResponse(sa, sa->response, &sa->responseLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->responseLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->response, sa->responseLen);

      //An implementation must respond to the address and port from which the
      //request was received (refer to RFC 7296, section 2.11)
      socketSendTo(context->socket, &context->remoteIpAddr, context->remotePort,
         sa->response, sa->responseLen, NULL, 0);

      //In an IKE_SA_INIT exchange, any error notification causes the exchange
      //to fail (refer to RFC 7296, section 2.21.1)
      if(sa->notifyMsgType != IKE_NOTIFY_MSG_TYPE_NONE)
      {
         error = ERROR_UNEXPECTED_STATUS;
      }
   }

   //Check status code
   if(!error)
   {
      //Wait for the IKE_AUTH request from the initiator
      ikeChangeSaState(sa, IKE_SA_STATE_AUTH_REQ);
   }
   else
   {
      //The IKE_SA_INIT exchange has failed
      ikeDeleteSaEntry(sa);
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
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Save the second message (IKE_SA_INIT response), starting with the first
   //octet of the first SPI in the header and ending with the last octet of
   //the last payload
   osMemcpy(sa->response, context->message, sa->responderSaInitLen);
   sa->responderSaInit = sa->response;

   //Save the first message (IKE_SA_INIT request), starting with the first
   //octet of the first SPI in the header and ending with the last octet of
   //the last payload
   osMemcpy(context->message, sa->request, sa->initiatorSaInitLen);
   sa->initiatorSaInit = context->message;

   //Let g^ir be the Diffie-Hellman shared secret
   error = ikeComputeDhSharedSecret(sa);

   //Check status code
   if(!error)
   {
      //At this point in the negotiation, each party can generate a quantity
      //called SKEYSEED, from which all keys are derived for that IKE SA (refer
      //to RFC 7296, section 1.2)
      error = ikeGenerateSaKeyMaterial(sa, NULL);
   }

   //Check status code
   if(!error)
   {
      //Valid Child SA?
      if(sa->childSa != NULL)
      {
         //Generate a new SPI for the Child SA
         error = ikeGenerateChildSaSpi(sa->childSa, sa->childSa->localSpi);
      }
   }

   //Check status code
   if(!error)
   {
      //The message ID is incremented for each subsequent exchange
      sa->txMessageId++;

      //Format IKE_AUTH request
      error = ikeFormatIkeAuthRequest(sa, sa->request, &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->request, &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->requestLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->request, sa->requestLen);

      //Send IKE request
      socketSendTo(context->socket, &sa->remoteIpAddr, sa->remotePort,
         sa->request, sa->requestLen, NULL, 0);

      //Wait for the IKE_AUTH response from the responder
      ikeChangeSaState(sa, IKE_SA_STATE_AUTH_RESP);
   }

   //Return status code
   return error;
}


/**
 * @brief Send IKE_AUTH response
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendIkeAuthResponse(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;
   //Point to the Child SA
   childSa = sa->childSa;

   //Save the second message (IKE_SA_INIT response), starting with the first
   //octet of the first SPI in the header and ending with the last octet of
   //the last payload
   osMemcpy(context->message, sa->response, sa->responderSaInitLen);
   sa->responderSaInit = context->message;

   //Successful Child SA creation?
   if(childSa != NULL)
   {
      //For the first Child SA created, Ni and Nr are the nonces from the
      //IKE_SA_INIT exchange (refer to RFC 7296, section 2.17)
      osMemcpy(childSa->initiatorNonce, sa->initiatorNonce,
         sa->initiatorNonceLen);
      osMemcpy(childSa->responderNonce, sa->responderNonce,
         sa->responderNonceLen);

      //Save the length of Ni and Nr nonces
      childSa->initiatorNonceLen = sa->initiatorNonceLen;
      childSa->responderNonceLen = sa->responderNonceLen;

      //A single Child SA is created by the IKE_AUTH exchange. Keying
      //material for the Child SA must be taken from the expanded KEYMAT
      //(refer to RFC 7296, section 2.17)
      error = ikeGenerateChildSaKeyMaterial(childSa);
   }

   //Check status code
   if(!error)
   {
      //Format IKE_AUTH response
      error = ikeFormatIkeAuthResponse(sa, sa->response, &sa->responseLen);
   }

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->response, &sa->responseLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->responseLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->response, sa->responseLen);

      //An implementation must respond to the address and port from which the
      //request was received (refer to RFC 7296, section 2.11)
      socketSendTo(context->socket, &context->remoteIpAddr, context->remotePort,
         sa->response, sa->responseLen, NULL, 0);

      //If creating the Child SA during the IKE_AUTH exchange fails for some
      //reason, the IKE SA is still created as usual (refer to RFC 7296,
      //section 1.2)
      if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NONE ||
         sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN ||
         sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE ||
         sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED ||
         sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE ||
         sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED)
      {
         //The responder has sent the IKE_AUTH response
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);

         //Successful Child SA creation?
         if(childSa != NULL)
         {
            //Update the state of the Child SA
            ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_OPEN);

            //ESP and AH SAs exist in pairs (one in each direction), so two SAs
            //are created in a single Child SA negotiation for them
            ikeCreateIpsecSaPair(childSa);
         }

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
         //The INITIAL_CONTACT notification asserts that this IKE SA is the only
         //IKE SA currently active between the authenticated identities
         if(sa->initialContact)
         {
            //It may be sent when an IKE SA is established after a crash, and the
            //recipient may use this information to delete any other IKE SAs it
            //has to the same authenticated identity without waiting for a timeout
            ikeDeleteDuplicateSaEntries(sa);

            //Reset flag
            sa->initialContact = FALSE;
         }
#endif
      }
      else if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD)
      {
         //An unsupported critical payload was included in the IKE_AUTH request
      }
      else
      {
         //Only authentication failures (AUTHENTICATION_FAILED) and malformed
         //messages (INVALID_SYNTAX) lead to a deletion of the IKE SA without
         //requiring an explicit INFORMATIONAL exchange carrying a Delete
         //payload
         error = ERROR_AUTHENTICATION_FAILED;
      }
   }

   //Check status code
   if(error)
   {
      //The IKE_AUTH exchange has failed
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Send CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeSendCreateChildSaRequest(IkeSaEntry *sa, IkeChildSaEntry *childSa)
{
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
}


/**
 * @brief Send CREATE_CHILD_SA response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeSendCreateChildSaResponse(IkeSaEntry *sa, IkeChildSaEntry *childSa)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Format CREATE_CHILD_SA response
   error = ikeFormatCreateChildSaResponse(sa, childSa, sa->response,
      &sa->responseLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->response, &sa->responseLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->responseLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->response, sa->responseLen);

      //An implementation must respond to the address and port from which the
      //request was received (refer to RFC 7296, section 2.11)
      socketSendTo(context->socket, &context->remoteIpAddr, context->remotePort,
         sa->response, sa->responseLen, NULL, 0);
   }

   //Return status code
   return error;
}


/**
 * @brief Send INFORMATIONAL request
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendInfoRequest(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //The message ID is incremented for each subsequent exchange
   sa->txMessageId++;

   //Format INFORMATIONAL request
   error = ikeFormatInfoRequest(sa, sa->request, &sa->requestLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->request, &sa->requestLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->requestLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->request, sa->requestLen);

      //Send IKE request
      socketSendTo(context->socket, &sa->remoteIpAddr, sa->remotePort,
         sa->request, sa->requestLen, NULL, 0);

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
 * @brief Send INFORMATIONAL response
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeSendInfoResponse(IkeSaEntry *sa)
{
   error_t error;
   uint_t i;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Point to the IKE context
   context = sa->context;

   //Format INFORMATIONAL response
   error = ikeFormatInfoResponse(sa, sa->response, &sa->responseLen);

   //Check status code
   if(!error)
   {
      //All messages following the initial exchange are cryptographically
      //protected using the cryptographic algorithms and keys negotiated in
      //the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
      error = ikeEncryptMessage(sa, sa->response, &sa->responseLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", sa->responseLen);
      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->response, sa->responseLen);

      //An implementation must respond to the address and port from which the
      //request was received (refer to RFC 7296, section 2.11)
      socketSendTo(context->socket, &context->remoteIpAddr, context->remotePort,
         sa->response, sa->responseLen, NULL, 0);
   }

   //Check whether the IKE SA should be closed
   if(sa->deleteReceived)
   {
      //Delete the IKE SA
      ikeDeleteSaEntry(sa);
   }

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check whether the Child SA should be closed
      if(childSa->state != IKE_CHILD_SA_STATE_CLOSED &&
         childSa->deleteReceived)
      {
         //Delete the Child SA
         ikeDeleteChildSaEntry(childSa);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send INFORMATIONAL response (outside of an IKE SA)
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeSendErrorResponse(IkeContext *context, uint8_t *message,
   size_t length)
{
   error_t error;
   IkeHeader ikeHeader;

   //Check the length of the IKE message
   if(length >= sizeof(IkeHeader))
   {
      //Copy the IKE header
      osMemcpy(&ikeHeader, message, sizeof(IkeHeader));

      //Format INFORMATIONAL response
      error = ikeFormatErrorResponse(&ikeHeader, context->message,
         &context->messageLen);

      //Check status code
      if(!error)
      {
         //Debug message
         TRACE_INFO("Sending IKE message (%" PRIuSIZE " bytes)...\r\n", context->messageLen);
         //Dump IKE message for debugging purpose
         ikeDumpMessage(context->message, context->messageLen);

         //The message is always sent without cryptographic protection. The message
         //is a response message, and thus it is sent to the IP address and port
         //from whence it came (refer to RFC 7296, section 1.5)
         error = socketSendTo(context->socket, &context->remoteIpAddr,
            context->remotePort, context->message, context->messageLen, NULL, 0);
      }
   }
   else
   {
      //The length of the received IKE message is not valid
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
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

   //In the first message of an initial IKE exchange, the initiator will not
   //know the responder's SPI value and will therefore set that field to zero
   //(refer to RFC 7296, section 2.6)
   osMemset(sa->responderSpi, 0, IKE_SPI_SIZE);

   //Format IKE header
   osMemcpy(ikeHeader->initiatorSpi, sa->initiatorSpi, IKE_SPI_SIZE);
   osMemcpy(ikeHeader->responderSpi, sa->responderSpi, IKE_SPI_SIZE);
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   ikeHeader->majorVersion = IKE_MAJOR_VERSION;
   ikeHeader->minorVersion = IKE_MINOR_VERSION;
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_IKE_SA_INIT;
   ikeHeader->flags = IKE_FLAGS_I;
   ikeHeader->messageId = htonl(sa->txMessageId);

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
   error = ikeFormatKePayload(sa, p, &n, &nextPayload);
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

   //Save the length of the first message (IKE_SA_INIT request)
   sa->initiatorSaInitLen = *length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format IKE_SA_INIT response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatIkeSaInitResponse(IkeSaEntry *sa, uint8_t *p, size_t *length)
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
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_IKE_SA_INIT;
   ikeHeader->flags = IKE_FLAGS_R;
   ikeHeader->messageId = htonl(sa->rxMessageId);

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //Successful IKE SA creation?
   if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NONE)
   {
      //The responder chooses a cryptographic suite from the initiator's offered
      //choices and expresses that choice in the SAr payload
      error = ikeFormatSaPayload(sa, NULL, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //The responder completes the Diffie-Hellman exchange with the KEr payload
      error = ikeFormatKePayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //The responder sends its nonce in the Nr payload
      error = ikeFormatNoncePayload(sa, NULL, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //A CERTREQ payload can optionally be included
      error = ikeFormatCertReqPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
      //The hash algorithms that can be used for the signature algorithms
      //are indicated with a Notify payload of type SIGNATURE_HASH_ALGORITHMS
      //sent inside the IKE_SA_INIT exchange (refer to RFC 7427, section 4)
      error = ikeFormatNotifyPayload(sa, NULL,
         IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Total length of the message
      *length += n;
#endif
   }
   else
   {
      //In an IKE_SA_INIT exchange, any error notification causes the
      //exchange to fail. Note that some error notifications such as COOKIE,
      //INVALID_KE_PAYLOAD or INVALID_MAJOR_VERSION may lead to a subsequent
      //successful exchange (refer to RFC 7296, section 2.21.1)
      error = ikeFormatNotifyPayload(sa, NULL, sa->notifyMsgType, p, &n,
         &nextPayload);

      //Total length of the message
      *length += n;
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Save the length of the second message (IKE_SA_INIT response)
   sa->responderSaInitLen = *length;

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
   IkeChildSaEntry *childSa;
   IkeHeader *ikeHeader;
   IkeIdPayload *idPayload;

   //Point to the Child SA
   childSa = sa->childSa;

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

   //The initiator asserts its identity with the IDi payload (refer to RFC 7296,
   //section 1.2)
   error = ikeFormatIdPayload(sa, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the Identification payload
   idPayload = (IkeIdPayload *) p;

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
      error = ikeFormatNotifyPayload(sa, NULL, IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT,
         p, &n, &nextPayload);
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

   //The initiator proves knowledge of the secret corresponding to IDi and
   //integrity protects the contents of the first message using the AUTH payload
   error = ikeFormatAuthPayload(sa, idPayload, p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Point to the next payload
   p += n;
   *length += n;

   //Child SAs can be created either by being piggybacked on the IKE_AUTH
   //exchange, or using a separate CREATE_CHILD_SA exchange
   if(childSa != NULL)
   {
      //The USE_TRANSPORT_MODE notification may be included in a request
      //message that also includes an SA payload requesting a Child SA. It
      //requests that the Child SA use transport mode rather than tunnel
      //mode for the SA created (refer to RFC 7296, section 1.3.1)
      if(childSa->mode == IPSEC_MODE_TRANSPORT)
      {
         //Include a notification of type USE_TRANSPORT_MODE
         error = ikeFormatNotifyPayload(sa, childSa,
            IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Point to the next payload
         p += n;
         *length += n;
      }

      //The initiator begins negotiation of a Child SA using the SAi payload
      error = ikeFormatSaPayload(sa, childSa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //TSi specifies the source address of traffic forwarded from (or the
      //destination address of traffic forwarded to) the initiator of the
      //Child SA pair
      error = ikeFormatTsiPayload(childSa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //TSr specifies the destination address of the traffic forwarded to (or
      //the source address of the traffic forwarded from) the responder of the
      //Child SA pair
      error = ikeFormatTsrPayload(childSa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Total length of the message
      *length += n;
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format IKE_AUTH response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatIkeAuthResponse(IkeSaEntry *sa, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;
   uint8_t *nextPayload;
   IkeChildSaEntry *childSa;
   IkeHeader *ikeHeader;
   IkeIdPayload *idPayload;

   //Point to the Child SA
   childSa = sa->childSa;

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
   ikeHeader->flags = IKE_FLAGS_R;
   ikeHeader->messageId = htonl(sa->rxMessageId);

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //If creating the Child SA during the IKE_AUTH exchange fails for some
   //reason, the IKE SA is still created as usual (refer to RFC 7296,
   //section 1.2)
   if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NONE ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED)
   {
      //The responder asserts its identity with the IDr payload (refer to
      //RFC 7296, section 1.2)
      error = ikeFormatIdPayload(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the Identification payload
      idPayload = (IkeIdPayload *) p;

      //Point to the next payload
      p += n;
      *length += n;

      //The responder optionally sends one or more certificates
      error = ikeFormatCertPayloads(sa, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //The responder authenticates its identity and protects the integrity
      //of the second message with the AUTH payload
      error = ikeFormatAuthPayload(sa, idPayload, p, &n, &nextPayload);
      //Any error to report?
      if(error)
         return error;

      //Point to the next payload
      p += n;
      *length += n;

      //The responder completes negotiation of a Child SA with additional fields
      if(childSa != NULL)
      {
         //The initiator can request that the Child SA use transport mode rather
         //than tunnel mode for the SA created
         if(childSa->mode == IPSEC_MODE_TRANSPORT)
         {
            //If the request is accepted, the response must also include a
            //notification of type USE_TRANSPORT_MODE
            error = ikeFormatNotifyPayload(sa, childSa,
               IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE, p, &n, &nextPayload);
            //Any error to report?
            if(error)
               return error;

            //Point to the next payload
            p += n;
            *length += n;
         }

         //The responder chooses a cryptographic suite from the initiator's
         //offered choices and expresses that choice in the SAr payload
         error = ikeFormatSaPayload(sa, sa->childSa, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Point to the next payload
         p += n;
         *length += n;

         //TSi specifies the source address of traffic forwarded from (or the
         //destination address of traffic forwarded to) the initiator of the
         //Child SA pair
         error = ikeFormatTsiPayload(childSa, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Point to the next payload
         p += n;
         *length += n;

         //TSr specifies the destination address of the traffic forwarded to (or
         //the source address of the traffic forwarded from) the responder of the
         //Child SA pair
         error = ikeFormatTsrPayload(childSa, p, &n, &nextPayload);
         //Any error to report?
         if(error)
            return error;

         //Total length of the message
         *length += n;
      }
      else
      {
         //Check whether the Child SA creation has failed
         if(sa->notifyMsgType != IKE_NOTIFY_MSG_TYPE_NONE)
         {
            //Format Notify payload
            error = ikeFormatNotifyPayload(sa, NULL, sa->notifyMsgType, p, &n,
               &nextPayload);

            //Total length of the message
            *length += n;
         }
      }
   }
   else
   {
      //If the failure is related to creating the IKE SA (for example, an
      //AUTHENTICATION_FAILED Notify error message is returned), the IKE SA
      //is not created
      error = ikeFormatNotifyPayload(sa, NULL, sa->notifyMsgType, p, &n,
         &nextPayload);

      //Total length of the message
      *length += n;
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatCreateChildSaRequest(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *length)
{
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
}


/**
 * @brief Format CREATE_CHILD_SA response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatCreateChildSaResponse(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *length)
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
   ikeHeader->exchangeType = IKE_EXCHANGE_TYPE_CREATE_CHILD_SA;
   ikeHeader->messageId = htonl(sa->rxMessageId);

   //This I bit must be set in messages sent by the original initiator of the
   //IKE SA and must be cleared in messages sent by the original responder
   if(sa->originalInitiator)
   {
      ikeHeader->flags = IKE_FLAGS_R | IKE_FLAGS_I;
   }
   else
   {
      ikeHeader->flags = IKE_FLAGS_R;
   }

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //A minimal implementation may support the CREATE_CHILD_SA exchange only in
   //so far as to recognize requests and reject them with a Notify payload of
   //type NO_ADDITIONAL_SAS (refer to RFC 7296, section 4)
   error = ikeFormatNotifyPayload(sa, NULL, IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS,
      p, &n, &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
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
      error = ikeFormatDeletePayload(sa, sa->childSa, p, &n, &nextPayload);
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
 * @brief Format INFORMATIONAL response
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatInfoResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *length)
{
   uint_t i;
   size_t n;
   uint8_t *nextPayload;
   IkeContext *context;
   IkeChildSaEntry *childSa;
   IkeHeader *ikeHeader;
   IkeDeletePayload *deletePayload;

   //Point to the IKE context
   context = sa->context;

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
   ikeHeader->messageId = htonl(sa->rxMessageId);

   //This I bit must be set in messages sent by the original initiator of the
   //IKE SA and must be cleared in messages sent by the original responder
   if(sa->originalInitiator)
   {
      ikeHeader->flags = IKE_FLAGS_R | IKE_FLAGS_I;
   }
   else
   {
      ikeHeader->flags = IKE_FLAGS_R;
   }

   //Keep track of the Next Payload field
   nextPayload = &ikeHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //Point to the Delete payload header
   deletePayload = (IkeDeletePayload *) p;

   //Format Delete payload header
   deletePayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   deletePayload->header.critical = FALSE;
   deletePayload->header.reserved = 0;
   deletePayload->protocolId = IKE_PROTOCOL_ID_AH;
   deletePayload->spiSize = IPSEC_SPI_SIZE;
   deletePayload->numSpi = 0;

   //Length of the SPI list
   n = 0;

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check the state of the Child SA
      if(childSa->state != IKE_CHILD_SA_STATE_CLOSED &&
         childSa->protocol == IPSEC_PROTOCOL_AH &&
         childSa->deleteReceived)
      {
         //The SPI is the SPI the sending endpoint would expect in inbound ESP
         //or AH packets
         osMemcpy(deletePayload->spi + n, childSa->localSpi, IPSEC_SPI_SIZE);
         n += IPSEC_SPI_SIZE;

         //Increment the number of SPIs
         deletePayload->numSpi++;
      }
   }

   //Any SPI included in the Delete payload?
   if(n > 0)
   {
      //Calculate the length of the Delete payload
      n += sizeof(IkeDeletePayload);

      //Fix the Next Payload field of the previous payload
      *nextPayload = IKE_PAYLOAD_TYPE_D;

      //Fix the Payload Length field of the payload header
      deletePayload->header.payloadLength = htons(n);
      //Convert the number of SPIs to network byte order
      deletePayload->numSpi = htons(deletePayload->numSpi);

      //Keep track of the Next Payload field
      nextPayload = &deletePayload->header.nextPayload;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //Point to the Delete payload header
   deletePayload = (IkeDeletePayload *) p;

   //Format Delete payload header
   deletePayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   deletePayload->header.critical = FALSE;
   deletePayload->header.reserved = 0;
   deletePayload->protocolId = IKE_PROTOCOL_ID_ESP;
   deletePayload->spiSize = IPSEC_SPI_SIZE;
   deletePayload->numSpi = 0;

   //Length of the SPI list
   n = 0;

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check the state of the Child SA
      if(childSa->state != IKE_CHILD_SA_STATE_CLOSED &&
         childSa->protocol == IPSEC_PROTOCOL_ESP &&
         childSa->deleteReceived)
      {
         //The SPI is the SPI the sending endpoint would expect in inbound ESP
         //or AH packets
         osMemcpy(deletePayload->spi + n, childSa->localSpi, IPSEC_SPI_SIZE);
         n += IPSEC_SPI_SIZE;

         //Increment the number of SPIs
         deletePayload->numSpi++;
      }
   }

   //Any SPI included in the Delete payload?
   if(n > 0)
   {
      //Calculate the length of the Delete payload
      n += sizeof(IkeDeletePayload);

      //Fix the Next Payload field of the previous payload
      *nextPayload = IKE_PAYLOAD_TYPE_D;

      //Fix the Payload Length field of the payload header
      deletePayload->header.payloadLength = htons(n);
      //Convert the number of SPIs to network byte order
      deletePayload->numSpi = htons(deletePayload->numSpi);

      //Keep track of the Next Payload field
      nextPayload = &deletePayload->header.nextPayload;

      //Point to the next payload
      p += n;
      *length += n;
   }

   //The Length field indicates the total length of the IKE message in octets
   ikeHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format INFORMATIONAL response (outside of an IKE SA)
 * @param[in] requestHeader Pointer to the IKE header of the request
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t ikeFormatErrorResponse(IkeHeader *requestHeader, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;
   IkeNotifyMsgType notifyMsgType;
   uint8_t *nextPayload;
   IkeHeader *responseHeader;

   //Total length of the message
   *length = 0;

   //Each message begins with the IKE header
   responseHeader = (IkeHeader *) p;

   //The IKE SPIs are copied from the request
   osMemcpy(responseHeader->initiatorSpi, requestHeader->initiatorSpi,
      IKE_SPI_SIZE);
   osMemcpy(responseHeader->responderSpi, requestHeader->responderSpi,
      IKE_SPI_SIZE);

   //The Response flag is set to 1, and the version flags are set in the
   //normal fashion (refer to RFC 7296, section 1.5)
   responseHeader->nextPayload = IKE_PAYLOAD_TYPE_LAST;
   responseHeader->majorVersion = IKE_MAJOR_VERSION;
   responseHeader->minorVersion = IKE_MINOR_VERSION;
   responseHeader->exchangeType = IKE_EXCHANGE_TYPE_INFORMATIONAL;
   responseHeader->flags = IKE_FLAGS_R;
   responseHeader->messageId = requestHeader->messageId;

   //Keep track of the Next Payload field
   nextPayload = &responseHeader->nextPayload;

   //Point to the first IKE payload
   p += sizeof(IkeHeader);
   *length += sizeof(IkeHeader);

   //The message includes either an INVALID_IKE_SPI or an INVALID_MAJOR_VERSION
   //notification (with no notification data)
   if(requestHeader->majorVersion > IKE_MAJOR_VERSION)
   {
      notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_MAJOR_VERSION;
   }
   else
   {
      notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_IKE_SPI;
   }

   //Format Notify payload
   error = ikeFormatNotifyPayload(NULL, NULL, notifyMsgType, p, &n,
      &nextPayload);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //The Length field indicates the total length of the IKE message in octets
   responseHeader->length = htonl(*length);

   //Successful processing
   return NO_ERROR;
}

#endif
