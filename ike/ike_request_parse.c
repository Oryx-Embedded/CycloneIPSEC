/**
 * @file ike_request_parse.c
 * @brief IKE request parsing
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
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ike/ike_fsm.h"
#include "ike/ike_algorithms.h"
#include "ike/ike_request_parse.h"
#include "ike/ike_response_format.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_misc.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Parse incoming IKE_SA_INIT request
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseIkeSaInitRequest(IkeContext *context, const uint8_t *message,
   size_t length)
{
   error_t error;
   IkeSaEntry *sa;
   const IkeHeader *ikeHeader;
   IkeMessagePayloads payloads;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;

   //The initiator's SPI must not be zero (refer to RFC 7296, section 3.1)
   if(osMemcmp(ikeHeader->initiatorSpi, IKE_INVALID_SPI, IKE_SPI_SIZE) == 0)
      return ERROR_INVALID_MESSAGE;

   //The responder's SPI must be zero in the first message of an IKE initial
   //exchange (including repeats of that message including a cookie)
   if(osMemcmp(ikeHeader->responderSpi, IKE_INVALID_SPI, IKE_SPI_SIZE) != 0)
      return ERROR_INVALID_MESSAGE;

   //The Message ID is a 32-bit quantity, which is zero for the IKE_SA_INIT
   //messages (including retries of the message due to responses such as
   //COOKIE and INVALID_KE_PAYLOAD)
   if(ntohl(ikeHeader->messageId) != 0)
      return ERROR_INVALID_MESSAGE;

   //Parse IKE message payloads
   ikeParseIkeMessagePayloads(message, length, &payloads);

   //Mandatory payloads must be included in the received message
   if(payloads.sa == NULL || payloads.ke == NULL || payloads.nonce == NULL)
      return ERROR_INVALID_MESSAGE;

   //When a responder receives an IKE_SA_INIT request, it has to determine
   //whether the packet is a retransmission belonging to an existing half-open
   //IKE SA, or a new request, or it belongs to an existing IKE SA where the
   //IKE_AUTH request has been already received (refer to RFC 7296, section 2.1)
   sa = ikeFindHalfOpenSaEntry(context, ikeHeader, payloads.nonce);

   //Existing IKE SA found?
   if(sa != NULL)
   {
      //Half-open IKE SA?
      if(sa->state == IKE_SA_STATE_AUTH_REQ)
      {
         //If the packet is a retransmission belonging to an existing half-open
         //IKE SA The responder retransmits the same response
         return ikeRetransmitResponse(sa);
      }
      else
      {
         //If the packet belongs to an existing IKE SA where the IKE_AUTH
         //request has been already received, then the responder ignores it
         return ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //If the packet is a new request, the responder creates a new IKE SA and
   //sends a fresh response
   sa = ikeCreateSaEntry(context);
   //Failed to create IKE SA?
   if(sa == NULL)
      return ERROR_OUT_OF_RESOURCES;

   //Initialize IKE SA
   sa->remoteIpAddr = context->remoteIpAddr;

   //The original initiator always refers to the party who initiated the
   //exchange (refer to RFC 7296, section 2.2)
   sa->originalInitiator = FALSE;

   //The Message ID is zero for the IKE_SA_INIT messages
   sa->rxMessageId = 0;

   //Save initiator's IKE SPI
   osMemcpy(sa->initiatorSpi, ikeHeader->initiatorSpi, IKE_SPI_SIZE);

   //Start of exception handling block
   do
   {
      //Check whether the message contains an unsupported critical payload
      error = ikeCheckCriticalPayloads(message, length,
         &sa->unsupportedCriticalPayload);

      //Valid IKE message?
      if(error == NO_ERROR)
      {
         //The message is valid
      }
      else if(error == ERROR_UNSUPPORTED_OPTION)
      {
         //Reject the message and send an UNSUPPORTED_CRITICAL_PAYLOAD error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
         break;
      }
      else
      {
         //Reject the message and send an INVALID_SYNTAX error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Save initiator's nonce
      error = ikeParseNoncePayload(payloads.nonce, sa->initiatorNonce,
         &sa->initiatorNonceLen);

      //Malformed nonce?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

#if (IKE_COOKIE_SUPPORT == ENABLED)
      //Any registered callbacks?
      if(context->cookieVerifyCallback != NULL &&
         context->cookieGenerateCallback != NULL)
      {
         //COOKIE notification received?
         if(payloads.cookieNotify != NULL)
         {
            //Save the received cookie
            error = ikeParseCookieNotification(sa, payloads.cookieNotify);

            //Malformed notification?
            if(error)
            {
               sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
               break;
            }
         }
         else
         {
            //No cookie has been included in the IKE_SA_INIT message
            sa->cookieLen = 0;
         }

         //The cookie can be recomputed when the IKE_SA_INIT arrives the second
         //time and compared to the cookie in the received message
         error = context->cookieVerifyCallback(context,
            &context->remoteIpAddr, sa->initiatorSpi, sa->initiatorNonce,
            sa->initiatorNonceLen, sa->cookie, sa->cookieLen);

         //Check status code
         if(error == NO_ERROR)
         {
            //The received cookie is valid
         }
         else if(error == ERROR_WRONG_COOKIE)
         {
            //When one party receives an IKE_SA_INIT request containing a cookie
            //whose contents do not match the value expected, that party must
            //ignore the cookie and process the message as if no cookie had been
            //included (refer to RFC 7296, section 2.6)
            error = context->cookieGenerateCallback(context,
               &context->remoteIpAddr, sa->initiatorSpi, sa->initiatorNonce,
               sa->initiatorNonceLen, sa->cookie, &sa->cookieLen);

            //Check status code
            if(!error)
            {
               //Send a response containing a new cookie
               sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_COOKIE;
            }
            else
            {
               //Reject the request with a generic error notification
               sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            }

            //Send IKE_SA_INIT response message
            break;
         }
         else
         {
            //Reject the request with a generic error notification
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }
      }
#endif

      //Check the syntax of the SAi payload
      error = ikeParseSaPayload(payloads.sa);

      //Malformed SAi payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The responder must choose a single suite, which may be any subset of
      //the SA proposal (refer to RFC 7296, section 2.7)
      error = ikeSelectSaProposal(sa, payloads.sa, 0);

      //The responder must accept a single proposal or reject them all and
      //return an error. The error is given in a notification of type
      //NO_PROPOSAL_CHOSEN
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Nonces used in IKEv2 must be at least half the key size of the
      //negotiated pseudorandom function (refer to RFC 7296, section 2.10)
      error = ikeCheckNonceLength(sa, sa->initiatorNonceLen);

      //Unacceptable nonce length?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The Key Exchange payload is used to exchange Diffie-Hellman public
      //numbers as part of a Diffie-Hellman key exchange
      error = ikeParseKePayload(&sa->keContext, payloads.ke);

      //Check status code
      if(error == NO_ERROR)
      {
         //The Key Exchange payload is acceptable
      }
      else if(error == ERROR_INVALID_SYNTAX)
      {
         //The Key Exchange payload is malformed
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }
      else if(error == ERROR_INVALID_GROUP)
      {
         //If the initiator guesses wrong, the responder will respond with a
         //Notify payload of type INVALID_KE_PAYLOAD indicating the selected
         //group (refer to RFC 7296, section 1.2)
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD;
         sa->preferredGroupNum = sa->keContext.groupNum;
         break;
      }
      else
      {
         //Reject the request with a generic error notification
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //NAT_DETECTION_SOURCE_IP notification received?
      if(payloads.natDetectSrcIpNotify != NULL)
      {
         //There MAY be multiple NAT_DETECTION_SOURCE_IP payloads in a message
         //if the sender does not know which of several network attachments
         //will be used to send the packet (refer to RFC 7296, section 2.23)
         error = ikeParseNatDetectSrcIpNotification(sa, message, length);

         //Malformed notification?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }

      //NAT_DETECTION_DESTINATION_IP notification received?
      if(payloads.natDetectDestIpNotify != NULL)
      {
         //The NAT_DETECTION_DESTINATION_IP payloads can be used to detect if
         //there is NAT between the hosts
         error = ikeParseNatDetectDestIpNotification(sa,
            payloads.natDetectDestIpNotify);

         //Malformed notification?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }
#endif

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
      //SIGNATURE_HASH_ALGORITHMS notification received?
      if(payloads.signHashAlgosNotify != NULL)
      {
         //This notification indicates the list of hash functions supported by
         //the sending peer (refer to RFC 7427, section 4)
         error = ikeParseSignHashAlgosNotification(sa,
            payloads.signHashAlgosNotify);

         //Malformed notification?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }
      else
      {
         //The notification is not present in the IKE_SA_INIT message
         sa->signHashAlgos = 0;
      }
#endif

      //Save the first message (IKE_SA_INIT request), starting with the first
      //octet of the first SPI in the header and ending with the last octet of
      //the last payload
      osMemcpy(sa->request, message, length);
      sa->initiatorSaInit = sa->request;
      sa->initiatorSaInitLen = length;

      //End of exception handling block
   } while(0);

   //An IKE message flow always consists of a request followed by a response
   return ikeSendIkeSaInitResponse(sa);
}


/**
 * @brief Parse incoming IKE_AUTH request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseIkeAuthRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   IpsecPadEntry *padEntry;
   IkeMessagePayloads payloads;

   //Check the state of the IKE SA
   if(sa->state != IKE_SA_STATE_AUTH_REQ)
      return ERROR_UNEXPECTED_MESSAGE;

   //Start of exception handling block
   do
   {
      //Check whether the message contains an unsupported critical payload
      error = ikeCheckCriticalPayloads(message, length,
         &sa->unsupportedCriticalPayload);

      //Valid IKE message?
      if(error == NO_ERROR)
      {
         //The message is valid
      }
      else if(error == ERROR_UNSUPPORTED_OPTION)
      {
         //Reject the message and send an UNSUPPORTED_CRITICAL_PAYLOAD error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
         break;
      }
      else
      {
         //Reject the message and send an INVALID_SYNTAX error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //Mandatory payloads must be included in the received message
      if(payloads.idi == NULL || payloads.auth == NULL)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Parse Identification payload
      error = ikeParseIdPayload(sa, payloads.idi);
      //Malformed Identification payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Perform lookup in the PAD database based on the ID
      padEntry = ipsecFindPadEntry(sa->context->netContext->ipsecContext,
         sa->peerId.type, sa->peerId.data, sa->peerId.length);

      //All errors causing the authentication to fail for whatever reason
      //(invalid shared secret, invalid ID, untrusted certificate issuer,
      //revoked or expired certificate, etc.) should result in an
      //AUTHENTICATION_FAILED notification
      if(padEntry == NULL)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_AUTH_FAILED;
         break;
      }

#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Certificate-based authentication?
      if(padEntry->authMethod == IPSEC_AUTH_METHOD_CERT)
      {
         //Parse the certificate chain
         error = ikeParseCertificateChain(sa, padEntry, message, length);

         //Failed to validate certificate chain?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_AUTH_FAILED;
            break;
         }
      }
#endif

      //The peers are authenticated by having each sign (or MAC using a shared
      //secret as the key) a block of data (refer to RFC 7296, section 2.15)
      error = ikeParseAuthPayload(sa, payloads.auth, payloads.cert);

      //Authentication failure?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_AUTH_FAILED;
         break;
      }

      //The Certificate Request payload is optional
      if(payloads.certReq != NULL)
      {
         //The Certificate Request payload provides a means to request preferred
         //certificates via IKE (refer to RFC 7296, section 3.7)
         error = ikeParseCertReqPayload(sa, payloads.certReq);

         //Malformed Certificate Request payload?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }

      //Child SAs can be created either by being piggybacked on the IKE_AUTH
      //exchange, or using a separate CREATE_CHILD_SA exchange
      if(payloads.sa != NULL && payloads.tsi != NULL && payloads.tsr != NULL)
      {
         //Piggyback setup of the Child SA
         ikeProcessInitialChildSaCreateRequest(sa, &payloads);
      }

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
      //The INITIAL_CONTACT notification asserts that this IKE SA is the only
      //IKE SA currently active between the authenticated identities
      if(payloads.initialContactNotify)
      {
         //It may be sent when an IKE SA is established after a crash, and the
         //recipient may use this information to delete any other IKE SAs it
         //has to the same authenticated identity without waiting for a timeout
         sa->initialContact = TRUE;
      }
#endif

      //End of exception handling block
   } while(0);

   //An IKE message flow always consists of a request followed by a response
   return ikeSendIkeAuthResponse(sa);
}


/**
 * @brief Parse incoming CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseCreateChildSaRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   IkeMessagePayloads payloads;

   //The CREATE_CHILD_SA exchange may be initiated by either end of the IKE SA
   //after the initial exchanges are completed (refer to RFC 7296, section 1.3)
   if(sa->state < IKE_SA_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Start of exception handling block
   do
   {
      //Check whether the message contains an unsupported critical payload
      error = ikeCheckCriticalPayloads(message, length,
         &sa->unsupportedCriticalPayload);

      //Valid IKE message?
      if(error == NO_ERROR)
      {
         //The message is valid
      }
      else if(error == ERROR_UNSUPPORTED_OPTION)
      {
         //Reject the message and send an UNSUPPORTED_CRITICAL_PAYLOAD error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
         break;
      }
      else
      {
         //Reject the message and send an INVALID_SYNTAX error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //The CREATE_CHILD_SA exchange is used to create new Child SAs and to
      //rekey both IKE SAs and Child SAs (refer to RFC 7296, section 1.3)
      if(payloads.sa != NULL && payloads.nonce != NULL &&
         payloads.tsi != NULL && payloads.tsr != NULL &&
         payloads.rekeySaNotify == NULL)
      {
         //Child SA creation
         ikeProcessChildSaCreateRequest(sa, NULL, &payloads);
      }
      else if(payloads.sa != NULL && payloads.nonce != NULL &&
         payloads.tsi != NULL && payloads.tsr != NULL &&
         payloads.rekeySaNotify != NULL)
      {
         //Child SA rekeying
         ikeProcessChildSaRekeyRequest(sa, &payloads);
      }
      else if(payloads.sa != NULL && payloads.nonce != NULL &&
         payloads.ke != NULL && payloads.tsi == NULL &&
         payloads.tsr == NULL && payloads.rekeySaNotify == NULL)
      {
         //IKE SA rekeying
         ikeProcessIkeSaRekeyRequest(sa, &payloads);
      }
      else
      {
         //The received message does not include mandatory payloads
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //End of exception handling block
   } while(0);

   //An IKE message flow always consists of a request followed by a response
   return ikeSendCreateChildSaResponse(sa);
#else
   //The CREATE_CHILD_SA exchange may be initiated by either end of the IKE SA
   //after the initial exchanges are completed (refer to RFC 7296, section 1.3)
   if(sa->state < IKE_SA_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //A minimal implementation may support the CREATE_CHILD_SA exchange only in
   //so far as to recognize requests and reject them with a Notify payload of
   //type NO_ADDITIONAL_SAS (refer to RFC 7296, section 4)
   sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS;

   //An IKE message flow always consists of a request followed by a response
   return ikeSendCreateChildSaResponse(sa);
#endif
}


/**
 * @brief Parse incoming INFORMATIONAL request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseInfoRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint_t i;
   uint16_t notifyMsgType;
   IkeMessagePayloads payloads;
   const IkeDeletePayload *deletePayload;

   //INFORMATIONAL exchanges must only occur after the initial exchanges
   //and are cryptographically protected with the negotiated keys (refer to
   //RFC 7296, section 1.4)
   if(sa->state < IKE_SA_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Start of exception handling block
   do
   {
      //Check whether the message contains an unsupported critical payload
      error = ikeCheckCriticalPayloads(message, length,
         &sa->unsupportedCriticalPayload);

      //Valid IKE message?
      if(error == NO_ERROR)
      {
         //The message is valid
      }
      else if(error == ERROR_UNSUPPORTED_OPTION)
      {
         //Reject the message and send an UNSUPPORTED_CRITICAL_PAYLOAD error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD;
         break;
      }
      else
      {
         //Reject the message and send an INVALID_SYNTAX error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //Error notification received?
      if(payloads.errorNotify != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(payloads.errorNotify->notifyMsgType);

         //Check error type
         if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_AUTH_FAILED ||
            notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
         {
            //This error notification is considered fatal in both peers
            sa->deleteReceived = TRUE;
         }
         else
         {
            //Unrecognized error types in a request must be ignored (refer to
            //RFC 7296, section 3.10.1)
         }
      }

      //To delete an SA, an INFORMATIONAL exchange with one or more Delete
      //payloads is sent listing the SPIs of the SAs to be deleted (refer to
      //RFC 7296, section 1.4.1)
      for(i = 0; ; i++)
      {
         //Extract next Delete payload
         deletePayload = (IkeDeletePayload *) ikeGetPayload(message, length,
            IKE_PAYLOAD_TYPE_D, i);

         //Delete payload not found?
         if(deletePayload == NULL)
            break;

         //The Delete payload list the SPIs to be deleted
         error = ikeParseDeletePayload(sa, deletePayload, FALSE);

         //Malformed payload?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }

      //End of exception handling block
   } while(0);

   //An IKE message flow always consists of a request followed by a response
   return ikeSendInfoResponse(sa);
}


/**
 * @brief Process initial Child SA creation request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 **/

void ikeProcessInitialChildSaCreateRequest(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
   error_t error;
   IkeChildSaEntry *childSa;

   //Create a new Child SA
   childSa = ikeCreateChildSaEntry(sa->context);

   //Successful Child SA creation?
   if(childSa != NULL)
   {
      //Start of exception handling block
      do
      {
         //Initialize Child SA
         childSa->sa = sa;
         childSa->mode = IPSEC_MODE_TUNNEL;
         childSa->initiator = FALSE;

         //Generate a new SPI for the Child SA
         error = ikeGenerateChildSaSpi(childSa, childSa->localSpi);

         //Any error to report?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }

         //The USE_TRANSPORT_MODE notification may be included in a request
         //message that also includes an SA payload requesting a Child SA
         if(payloads->useTransportModeNotify != NULL)
         {
            //It requests that the Child SA use transport mode rather than
            //tunnel mode for the SA created
            childSa->mode = IPSEC_MODE_TRANSPORT;
         }

         //IKEv2 allows the responder to choose a subset of the traffic proposed
         //by the initiator (refer to RFC 7296, section 2.9)
         error = ikeSelectTs(childSa, payloads->tsi, payloads->tsr);

         //Check status code
         if(error)
         {
            //If no SPD entry was found, or (if found) the SPD entry does not
            //allow transport mode, undo the Traffic Selector substitutions.
            //Do SPD lookup again using the original traffic selectors, but
            //also searching for tunnel mode SPD entry (refer to RFC 7296,
            //section 2.23.1)
            if(childSa->mode == IPSEC_MODE_TRANSPORT)
            {
               //Fall back to tunnel mode
               childSa->mode = IPSEC_MODE_TUNNEL;

               //Perform SPD lookup again
               error = ikeSelectTs(childSa, payloads->tsi, payloads->tsr);
            }
         }

         //If the responder's policy does not allow it to accept any part of
         //the proposed Traffic Selectors, it responds with a TS_UNACCEPTABLE
         //Notify message
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE;
            break;
         }

         //Check the syntax of the SAi payload
         error = ikeParseSaPayload(payloads->sa);

         //Malformed SAi payload?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }

         //The responder must choose a single suite, which may be any subset
         //of the SA proposal (refer to RFC 7296, section 2.7)
         error = ikeSelectChildSaProposal(childSa, payloads->sa);

         //The responder must accept a single proposal or reject them all and
         //return an error. The error is given in a notification of type
         //NO_PROPOSAL_CHOSEN
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }

         //Attach the newly created Child SA to the IKE SA
         sa->childSa2 = childSa;

         //End of exception handling block
      } while(0);

      //Clean up any side effects if an error occurred
      if(error)
      {
         ikeDeleteChildSaEntry(childSa);
      }
   }
   else
   {
      //The NO_PROPOSAL_CHOSEN error notification can be used as a generic
      //error when a Child SA cannot be created for some reason(refer to
      //RFC 7296, section 3.10.1)
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
   }
}


/**
 * @brief Process Child SA creation request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] oldChildSa Pointer to the existing Child SA (for rekeying)
 * @param[in] payloads Pointer to the IKE message payloads
 **/

void ikeProcessChildSaCreateRequest(IkeSaEntry *sa, IkeChildSaEntry *oldChildSa,
   IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Point to the IKE context
   context = sa->context;

   //If a peer receives a request to create or rekey a Child SA when it is
   //currently rekeying the IKE SA, it should reply with TEMPORARY_FAILURE
   //(refer to RFC 7296, section 2.25.2)
   if(sa->state == IKE_SA_STATE_REKEY_RESP)
   {
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
      return;
   }

   //Create a new Child SA
   childSa = ikeCreateChildSaEntry(sa->context);

   //Failed to create Child SA?
   if(childSa == NULL)
   {
      //The NO_PROPOSAL_CHOSEN error notification can be used as a generic
      //error when a Child SA cannot be created for some reason(refer to
      //RFC 7296, section 3.10.1)
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
      return;
   }

   //Start of exception handling block
   do
   {
      //Initialize Child SA
      childSa->sa = sa;
      childSa->oldChildSa = oldChildSa;
      childSa->mode = IPSEC_MODE_TUNNEL;
      childSa->esn = FALSE;
      childSa->initiator = FALSE;

      //The KEi payload is optional
      if(payloads->ke != NULL)
      {
#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
         //The CREATE_CHILD_SA request may optionally contain a KE payload for
         //an additional Diffie-Hellman exchange to enable stronger guarantees
         //of forward secrecy for the Child SA (refer to RFC 7296, section 1.3)
         childSa->pfs = TRUE;
#else
         //Perfect forward secrecy is not supported
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;

         //Report an error
         error = ERROR_INVALID_PROPOSAL;
         break;
#endif
      }

      //Save initiator's nonce
      error = ikeParseNoncePayload(payloads->nonce, childSa->initiatorNonce,
         &childSa->initiatorNonceLen);

      //Malformed nonce?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Nonces used in IKEv2 must be at least half the key size of the
      //negotiated pseudorandom function (refer to RFC 7296, section 2.10)
      error = ikeCheckNonceLength(sa, childSa->initiatorNonceLen);

      //Unacceptable nonce length?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Generate a new SPI for the Child SA
      error = ikeGenerateChildSaSpi(childSa, childSa->localSpi);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Nonces used in IKEv2 must be randomly chosen and must be at least
      //128 bits in size (refer to RFC 7296, section 2.10)
      error = ikeGenerateNonce(context, childSa->responderNonce,
         &childSa->responderNonceLen);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //The USE_TRANSPORT_MODE notification may be included in a request
      //message that also includes an SA payload requesting a Child SA
      if(payloads->useTransportModeNotify != NULL)
      {
         //It requests that the Child SA use transport mode rather than
         //tunnel mode for the SA created
         childSa->mode = IPSEC_MODE_TRANSPORT;
      }

      //IKEv2 allows the responder to choose a subset of the traffic proposed
      //by the initiator (refer to RFC 7296, section 2.9)
      error = ikeSelectTs(childSa, payloads->tsi, payloads->tsr);

      //Check status code
      if(error)
      {
         //If no SPD entry was found, or (if found) the SPD entry does not allow
         //transport mode, undo the Traffic Selector substitutions. Do SPD
         //lookup again using the original traffic selectors, but also searching
         //for tunnel mode SPD entry (refer to RFC 7296, section 2.23.1)
         if(childSa->mode == IPSEC_MODE_TRANSPORT)
         {
            //Fall back to tunnel mode
            childSa->mode = IPSEC_MODE_TUNNEL;

            //Perform SPD lookup again
            error = ikeSelectTs(childSa, payloads->tsi, payloads->tsr);
         }
      }

      //If the responder's policy does not allow it to accept any part of
      //the proposed Traffic Selectors, it responds with a TS_UNACCEPTABLE
      //Notify message
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE;
         break;
      }

      //Check the syntax of the SAi payload
      error = ikeParseSaPayload(payloads->sa);

      //Malformed SAi payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The responder must choose a single suite, which may be any subset
      //of the SA proposal (refer to RFC 7296, section 2.7)
      error = ikeSelectChildSaProposal(childSa, payloads->sa);

      //The responder must accept a single proposal or reject them all and
      //return an error. The error is given in a notification of type
      //NO_PROPOSAL_CHOSEN
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      //Perfect forward secrecy?
      if(childSa->pfs)
      {
         //The Key Exchange payload is used to exchange Diffie-Hellman public
         //numbers as part of a Diffie-Hellman key exchange
         error = ikeParseKePayload(&childSa->keContext, payloads->ke);

         //Check status code
         if(error == NO_ERROR)
         {
            //The Key Exchange payload is acceptable
         }
         else if(error == ERROR_INVALID_SYNTAX)
         {
            //The Key Exchange payload is malformed
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
         else if(error == ERROR_INVALID_GROUP)
         {
            //If the responder selects a proposal using a different group, the
            //responder must reject the request and indicate its preferred group
            //in the INVALID_KE_PAYLOAD Notify payload (refer to RFC 7296,
            //section 1.3)
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD;
            sa->preferredGroupNum = childSa->keContext.groupNum;
            break;
         }
         else
         {
            //Reject the request with a generic error notification
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }

         //Generate an ephemeral key pair
         error = ikeGenerateKeyPair(&childSa->keContext, context->prngAlgo,
            context->prngContext);

         //Any error to report?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }

         //Let g^ir be the Diffie-Hellman shared secret
         error = ikeComputeSharedSecret(&childSa->keContext,
            childSa->sharedSecret, &childSa->sharedSecretLen);

         //Any error to report?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }
      }
#endif

      //Additional Child SAs can optionally be created in CREATE_CHILD_SA
      //exchanges. Keying material for Child SAs must be taken from the
      //expanded KEYMAT (refer to RFC 7296, section 2.17)
      error = ikeGenerateChildSaKeyMaterial(childSa);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Simultaneous Child SA rekeying may temporarily result in multiple
      //similar SAs between the same pairs of nodes
      if(oldChildSa != NULL && oldChildSa->state == IKE_CHILD_SA_STATE_REKEY)
      {
         //The peer will close the redundant SAs later based on the nonces
         //(refer to RFC 7296, section 2.25.1)
      }
      else
      {
         //The new Child SA has been successfully created
         ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_OPEN);

         //ESP and AH SAs exist in pairs (one in each direction), so two SAs
         //are created in a single Child SA negotiation for them
         ikeCreateIpsecSaPair(childSa);
      }

      //Attach the newly created Child SA to the IKE SA
      sa->childSa2 = childSa;

      //End of exception handling block
   } while(0);

   //Clean up any side effects if an error occurred
   if(error)
   {
      ikeDeleteChildSaEntry(childSa);
   }
#endif
}


/**
 * @brief Process Child SA rekeying request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 **/

void ikeProcessChildSaRekeyRequest(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   IkeChildSaEntry *oldChildSa;

   //The SPI is included only with INVALID_SELECTORS, REKEY_SA, and
   //CHILD_SA_NOT_FOUND notifications (refer to RFC 7296, section 3.10)
   if(payloads->rekeySaNotify->spiSize != IPSEC_SPI_SIZE)
   {
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
      return;
   }

   //The SA being rekeyed is identified by the SPI field in the Notify payload;
   //this is the SPI the exchange initiator would expect in inbound ESP or AH
   //packet (refer to RFC 7296, section 1.3.3)
   oldChildSa = ikeFindChildSaEntry(sa, payloads->rekeySaNotify->protocolId,
      payloads->rekeySaNotify->spi);

   //If a peer receives a request to rekey a Child SA that does not exist, it
   //should reply with CHILD_SA_NOT_FOUND (refer to RFC 7296, section 2.25.1)
   if(oldChildSa == NULL)
   {
      //Send a CHILD_SA_NOT_FOUND error notification
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_CHILD_SA_NOT_FOUND;
      sa->notifyProtocolId = payloads->rekeySaNotify->protocolId;

      //The SA that the initiator attempted to rekey is indicated by the SPI
      //field in the Notify payload, which is copied from the SPI field in the
      //REKEY_SA notification (refer to RFC 7296, section 2.25)
      osMemcpy(sa->notifySpi, payloads->rekeySaNotify->spi, IPSEC_SPI_SIZE);

      //We are done
      return;
   }

   //Exchange collision?
   if(oldChildSa->state == IKE_CHILD_SA_STATE_REKEY)
   {
      //If a peer receives a request to rekey a Child SA that it is currently
      //rekeying, it should reply as usual, and should prepare to close
      //redundant SAs later based on the nonces (refer to RFC 7296, section
      //2.25.1)
   }
   else if(oldChildSa->state == IKE_CHILD_SA_STATE_DELETE)
   {
      //If a peer receives a request to rekey a Child SA that it is currently
      //trying to close, it should reply with TEMPORARY_FAILURE (refer to
      //RFC 7296, section 2.25.1)
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
      return;
   }
   else
   {
      //No collision detected
   }

   //Create a new equivalent Child SA
   ikeProcessChildSaCreateRequest(sa, oldChildSa, payloads);
#endif
}


/**
 * @brief Process IKE SA rekeying request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 **/

void ikeProcessIkeSaRekeyRequest(IkeSaEntry *sa, IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   IkeSaEntry *newSa;

   //Point to the IKE context
   context = sa->context;

   //Exchange collision?
   if(sa->state == IKE_SA_STATE_REKEY_RESP)
   {
      //If a peer receives a request to rekey an IKE SA that it is currently
      //rekeying, it should reply as usual, and should prepare to close
      //redundant SAs and move inherited Child SAs later based on the nonces
      //(refer to RFC 7296, section 2.25.2)
   }
   else if(sa->state == IKE_SA_STATE_DELETE_RESP)
   {
      //If a peer receives a request to rekey an IKE SA that it is currently
      //trying to close, it should reply with TEMPORARY_FAILURE (refer to
      //RFC 7296, section 2.25.2)
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
      return;
   }
   else if(sa->state == IKE_SA_STATE_CREATE_CHILD_RESP ||
      sa->state == IKE_SA_STATE_REKEY_CHILD_RESP ||
      sa->state == IKE_SA_STATE_DELETE_CHILD_RESP)
   {
      //If a peer receives a request to rekey the IKE SA, and it is currently
      //creating, rekeying, or closing a Child SA of that IKE SA, it should
      //reply with TEMPORARY_FAILURE (refer to RFC 7296, section 2.25.1)
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
      return;
   }
   else
   {
      //No collision detected
   }

   //Create a new IKE SA
   newSa = ikeCreateSaEntry(context);

   //Failed to create IKE SA?
   if(newSa == NULL)
   {
      sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
      return;
   }

   //Start of exception handling block
   do
   {
      //Initialize IKE SA
      newSa->remoteIpAddr = sa->remoteIpAddr;
#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      newSa->localNat = sa->localNat;
      newSa->remoteNat = sa->remoteNat;
#endif

      //The initiator of the rekey exchange is the new "original initiator" of
      //the new IKE SA (refer to RFC 7296, section 1.3.2)
      newSa->originalInitiator = FALSE;

      //Save initiator's nonce
      error = ikeParseNoncePayload(payloads->nonce, newSa->initiatorNonce,
         &newSa->initiatorNonceLen);

      //Malformed nonce?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Check the syntax of the SAi payload
      error = ikeParseSaPayload(payloads->sa);

      //Malformed SAi payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The responder must choose a single suite, which may be any subset of
      //the SA proposal (refer to RFC 7296, section 2.7)
      error = ikeSelectSaProposal(newSa, payloads->sa, IKE_SPI_SIZE);

      //The responder must accept a single proposal or reject them all and
      //return an error. The error is given in a notification of type
      //NO_PROPOSAL_CHOSEN
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Nonces used in IKEv2 must be at least half the key size of the
      //negotiated pseudorandom function (refer to RFC 7296, section 2.10)
      error = ikeCheckNonceLength(newSa, newSa->initiatorNonceLen);

      //Unacceptable nonce length?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The Key Exchange payload is used to exchange Diffie-Hellman public
      //numbers as part of a Diffie-Hellman key exchange
      error = ikeParseKePayload(&newSa->keContext, payloads->ke);

      //Check status code
      if(error == NO_ERROR)
      {
         //The Key Exchange payload is acceptable
      }
      else if(error == ERROR_INVALID_SYNTAX)
      {
         //The Key Exchange payload is malformed
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }
      else if(error == ERROR_INVALID_GROUP)
      {
         //If the responder selects a proposal using a different group, the
         //responder must reject the request and indicate its preferred group
         //in the INVALID_KE_PAYLOAD Notify payload (refer to RFC 7296,
         //section 1.3)
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD;
         sa->preferredGroupNum = newSa->keContext.groupNum;
         break;
      }
      else
      {
         //Reject the request with a generic error notification
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Each endpoint chooses one of the two SPIs and must choose them so as to
      //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
      error = ikeGenerateSaSpi(newSa, newSa->responderSpi);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Nonces used in IKEv2 must be randomly chosen and must be at least 128
      //bits in size (refer to RFC 7296, section 2.10)
      error = ikeGenerateNonce(context, newSa->responderNonce,
         &newSa->responderNonceLen);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Generate an ephemeral key pair
      error = ikeGenerateKeyPair(&newSa->keContext, context->prngAlgo,
         context->prngContext);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //Let g^ir be the Diffie-Hellman shared secret
      error = ikeComputeSharedSecret(&newSa->keContext, newSa->sharedSecret,
         &newSa->sharedSecretLen);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //At this point in the negotiation, each party can generate a quantity
      //called SKEYSEED, from which all keys are derived for that IKE SA (refer
      //to RFC 7296, section 1.2)
      error = ikeGenerateSaKeyMaterial(newSa, sa);

      //Any error to report?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
         break;
      }

      //When both peers try to rekey the IKE SA at the same time, it is
      //important to ensure that the Child SAs are inherited by the correct
      //IKE SA (refer to RFC 7296, section 2.8.2)
      if(sa->state == IKE_SA_STATE_REKEY_RESP)
      {
         //The peer will move inherited Child SAs later based on the nonces
      }
      else
      {
         //The new IKE SA has been successfully created
         ikeChangeSaState(newSa, IKE_SA_STATE_OPEN);

         //The new IKE SA inherits all of the original IKE SA's Child SAs, and
         //is used for all control messages needed to maintain those Child SAs
         ikeInheritChildSas(newSa, sa);
      }

      //Attach the newly created IKE SA
      sa->newSa2 = newSa;

      //End of exception handling block
   } while(0);

   //Clean up any side effects if an error occurred
   if(error)
   {
      ikeDeleteSaEntry(newSa);
   }
#endif
}

#endif
