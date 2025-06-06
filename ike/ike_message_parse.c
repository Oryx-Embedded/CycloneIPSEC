/**
 * @file ike_message_parse.c
 * @brief IKE message parsing
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
#include "ike/ike_message_parse.h"
#include "ike/ike_message_decrypt.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_dh_groups.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "ah/ah_algorithms.h"
#include "esp/esp_algorithms.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Process incoming IKE message
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessMessage(IkeContext *context, uint8_t *message, size_t length)
{
   error_t error;
   IkeHeader *ikeHeader;

   //Malformed IKE message?
   if(length < sizeof(IkeHeader))
      return ERROR_INVALID_LENGTH;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;

   //Debug message
   TRACE_INFO("IKE message received (%" PRIuSIZE " bytes)...\r\n", length);
   //Dump IKE message for debugging purpose
   ikeDumpMessage(message, length);

   //Check the length of the IKE message
   if(length < ntohl(ikeHeader->length))
      return ERROR_INVALID_LENGTH;

   //The Length field indicates the total length of the IKE message in octets
   length = ntohl(ikeHeader->length);

   //The R bit indicates whether the message is a request or response
   if((ikeHeader->flags & IKE_FLAGS_R) == 0)
   {
      //Process incoming IKE request
      error = ikeProcessRequest(context, message, length);
   }
   else
   {
      //Process incoming IKE response
      error = ikeProcessResponse(context, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming IKE request
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessRequest(IkeContext *context, uint8_t *message, size_t length)
{
   error_t error;
   uint8_t exchangeType;
   IkeHeader *ikeHeader;
   IkeSaEntry *sa;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;
   //The Exchange Type field indicates the type of exchange being used
   exchangeType = ikeHeader->exchangeType;

   //Check the major version number
   if(ikeHeader->majorVersion <= IKE_MAJOR_VERSION)
   {
      //Initial exchange?
      if(exchangeType == IKE_EXCHANGE_TYPE_IKE_SA_INIT)
      {
         //Process IKE_SA_INIT request
         error = ikeProcessIkeSaInitRequest(context, message, length);
      }
      else
      {
         //Perform IKE SA lookup
         sa = ikeFindSaEntry(context, ikeHeader);

         //Check whether the receiving node has an active IKE SA
         if(sa != NULL)
         {
            //All messages following the initial exchange are cryptographically
            //protected using the cryptographic algorithms and keys negotiated
            //in the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
            error = ikeDecryptMessage(sa, message, &length);

            //Check status code
            if(!error)
            {
               //The responder must remember each response until it receives a
               //request whose sequence number is larger than or equal to the
               //sequence number in the response plus its window size
               if(ntohl(ikeHeader->messageId) < sa->rxMessageId &&
                  sa->rxMessageId != UINT32_MAX)
               {
                  //If the responder receives a retransmitted request for which
                  //it has already forgotten the response, it must ignore the
                  //request
               }
               else if(ntohl(ikeHeader->messageId) == sa->rxMessageId &&
                  sa->rxMessageId != UINT32_MAX)
               {
                  //The responder has received a retransmission of the request
                  error = ikeRetransmitResponse(sa);
               }
               else if(ntohl(ikeHeader->messageId) == (sa->rxMessageId + 1))
               {
                  //The counter increments as requests are received
                  sa->rxMessageId++;

                  //In the unlikely event that Message IDs grow too large to fit
                  //in 32 bits, the IKE SA must be closed or rekeyed (refer to
                  //RFC 7296, section 2.2)
                  if(sa->rxMessageId == UINT32_MAX)
                  {
                     //Delete the IKE SA
                     ikeDeleteSaEntry(sa);
                  }
                  else
                  {
                     //Forget the previous response
                     sa->responseLen = 0;
                     //Clear error notification
                     sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NONE;

                     //Check IKE exchange type
                     if(exchangeType == IKE_EXCHANGE_TYPE_IKE_AUTH)
                     {
                        //Process IKE_AUTH request
                        error = ikeProcessIkeAuthRequest(sa, message, length);
                     }
                     else if(exchangeType == IKE_EXCHANGE_TYPE_CREATE_CHILD_SA)
                     {
                        //Process CREATE_CHILD_SA request
                        error = ikeProcessCreateChildSaRequest(sa, message,
                           length);
                     }
                     else if(exchangeType == IKE_EXCHANGE_TYPE_INFORMATIONAL)
                     {
                        //Process INFORMATIONAL request
                        error = ikeProcessInfoRequest(sa, message, length);
                     }
                     else
                     {
                        //Unknown exchange type
                        error = ERROR_UNKNOWN_TYPE;
                     }

                     //Only authentication failures (AUTHENTICATION_FAILED) and
                     //malformed messages (INVALID_SYNTAX) lead to a deletion of
                     //the IKE SA without requiring an explicit INFORMATIONAL
                     //exchange carrying a Delete payload
                     if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_AUTH_FAILED ||
                        sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
                     {
                        //This error notification is considered fatal in both peers
                        ikeDeleteSaEntry(sa);
                     }
                  }
               }
               else
               {
                  //Discard the request since the message ID is outside the
                  //supported window
               }
            }
         }
         else
         {
            //If a node receives a message on UDP port 500 or 4500 outside the
            //context of an IKE SA known to it (and the message is not a request
            //to start an IKE SA), this may be the result of a recent crash of
            //the node. If the message is marked as a request, the node can audit
            //the suspicious event and may send a response
            error = ikeSendErrorResponse(context, message, length);
         }
      }
   }
   else
   {
      //If an IKE request packet arrives with a higher major version number
      //than the implementation supports, the node notifies the sender about
      //this situation (refer to RFC 7296, section 1.5)
      error = ikeSendErrorResponse(context, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming IKE response
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessResponse(IkeContext *context, uint8_t *message, size_t length)
{
   error_t error;
   uint8_t exchangeType;
   IkeHeader *ikeHeader;
   IkeSaEntry *sa;

   //Initialize status code
   error = NO_ERROR;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;
   //The Exchange Type field indicates the type of exchange being used
   exchangeType = ikeHeader->exchangeType;

   //Check the major version number
   if(ikeHeader->majorVersion <= IKE_MAJOR_VERSION)
   {
      //Perform IKE SA lookup
      sa = ikeFindSaEntry(context, ikeHeader);

      //Check whether the receiving node has an active IKE SA
      if(sa != NULL)
      {
         //Check the state of the IKE SA
         if(sa->state == IKE_SA_STATE_INIT_RESP ||
            sa->state == IKE_SA_STATE_AUTH_RESP ||
            sa->state == IKE_SA_STATE_DPD_RESP ||
            sa->state == IKE_SA_STATE_REKEY_RESP ||
            sa->state == IKE_SA_STATE_DELETE_RESP ||
            sa->state == IKE_SA_STATE_CREATE_CHILD_RESP ||
            sa->state == IKE_SA_STATE_REKEY_CHILD_RESP ||
            sa->state == IKE_SA_STATE_DELETE_CHILD_RESP ||
            sa->state == IKE_SA_STATE_AUTH_FAILURE_RESP)
         {
            //The Message ID field is used to match requests and responses
            if(ntohl(ikeHeader->messageId) == sa->txMessageId)
            {
               //All messages following the initial exchange are cryptographically
               //protected using the cryptographic algorithms and keys negotiated
               //in the IKE_SA_INIT exchange (refer to RFC 7296, section 1.2)
               if(exchangeType != IKE_EXCHANGE_TYPE_IKE_SA_INIT)
               {
                  //Decrypt IKE message
                  error = ikeDecryptMessage(sa, message, &length);
               }

               //Check status code
               if(!error)
               {
                  //Check IKE exchange type
                  if(exchangeType == IKE_EXCHANGE_TYPE_IKE_SA_INIT)
                  {
                     //Process IKE_SA_INIT response
                     error = ikeProcessIkeSaInitResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_IKE_AUTH)
                  {
                     //Process IKE_AUTH response
                     error = ikeProcessIkeAuthResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_CREATE_CHILD_SA)
                  {
                     //Process CREATE_CHILD_SA response
                     error = ikeProcessCreateChildSaResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_INFORMATIONAL)
                  {
                     //Process INFORMATIONAL response
                     error = ikeProcessInfoResponse(sa, message, length);
                  }
                  else
                  {
                     //Unknown exchange type
                     error = ERROR_UNKNOWN_TYPE;
                  }

                  //Only authentication failures (AUTHENTICATION_FAILED) and
                  //malformed messages (INVALID_SYNTAX) lead to a deletion of
                  //the IKE SA without requiring an explicit INFORMATIONAL
                  //exchange carrying a Delete payload
                  if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_AUTH_FAILED ||
                     sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
                  {
                     //This error notification is considered fatal in both peers
                     ikeDeleteSaEntry(sa);
                  }
               }
            }
            else
            {
               //Unexpected Message ID
               error = ERROR_WRONG_IDENTIFIER;
            }
         }
         else
         {
            //Unexpected response
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //If a node receives a message on UDP port 500 or 4500 outside the
         //context of an IKE SA known to it, this may be the result of a
         //recent crash of the node. If the message is marked as a response,
         //the node can audit the suspicious event but must not respond
         error = ERROR_INVALID_SPI;
      }
   }
   else
   {
      //If an endpoint receives a message with a higher major version number,
      //it must drop the message
      error = ERROR_INVALID_VERSION;
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming IKE_SA_INIT request
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessIkeSaInitRequest(IkeContext *context, const uint8_t *message,
   size_t length)
{
   error_t error;
   IkeSaEntry *sa;
   const IkeHeader *ikeHeader;
   const IkeSaPayload *saPayload;
   const IkeKePayload *kePayload;
   const IkeNoncePayload *noncePayload;
#if (IKE_COOKIE_SUPPORT == ENABLED || IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   const IkeNotifyPayload *notifyPayload;
#endif

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

   //The SAi payload states the cryptographic algorithms the initiator supports
   //for the IKE SA (refer to RFC 7296, section 1.2)
   saPayload = (IkeSaPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_SA, 0);

   //The KEi payload sends the initiator's Diffie-Hellman value
   kePayload = (IkeKePayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_KE, 0);

   //The initiator sends its nonce in the Ni payload
   noncePayload = (IkeNoncePayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_NONCE, 0);

   //Mandatory payloads must be included in the received message
   if(saPayload == NULL || kePayload == NULL || noncePayload == NULL)
      return ERROR_INVALID_MESSAGE;

   //When a responder receives an IKE_SA_INIT request, it has to determine
   //whether the packet is a retransmission belonging to an existing half-open
   //IKE SA, or a new request, or it belongs to an existing IKE SA where the
   //IKE_AUTH request has been already received (refer to RFC 7296, section 2.1)
   sa = ikeFindHalfOpenSaEntry(context, ikeHeader, noncePayload);

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
   sa->remotePort = IKE_PORT;

   //The original initiator always refers to the party who initiated the
   //exchange (refer to RFC 7296, section 2.2)
   sa->originalInitiator = FALSE;

   //The Message ID is zero for the IKE_SA_INIT messages
   sa->rxMessageId = 0;

   //Save initiator's IKE SPI
   osMemcpy(sa->initiatorSpi, ikeHeader->initiatorSpi, IKE_SPI_SIZE);

   //Save the length of the first message (IKE_SA_INIT request)
   sa->initiatorSaInitLen = length;

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
      error = ikeParseNoncePayload(noncePayload, sa->initiatorNonce,
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
         //Check whether the response includes a COOKIE notification
         notifyPayload = ikeGetStatusNotifyPayload(message, length,
            IKE_NOTIFY_MSG_TYPE_COOKIE);

         //COOKIE notification received?
         if(notifyPayload != NULL)
         {
            //Save the received cookie
            error = ikeParseCookieNotification(sa, notifyPayload);

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
               //Send an error response
               sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
            }

            //Send IKE_SA_INIT response message
            break;
         }
         else
         {
            //Send an error response
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
            break;
         }
      }
#endif

      //Check the syntax of the SAi payload
      error = ikeParseSaPayload(saPayload);

      //Malformed SAi payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //The responder must choose a single suite, which may be any subset of
      //the SA proposal (refer to RFC 7296, section 2.7)
      error = ikeSelectSaProposal(sa, saPayload, 0);

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
      error = ikeParseKePayload(sa, kePayload);

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
         //Reject the message with a Notify payload of type INVALID_KE_PAYLOAD
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD;
         break;
      }
      else
      {
         //Report an error
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
         break;
      }

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
      //Search the IKE_SA_INIT message for a Notify payload of type
      //SIGNATURE_HASH_ALGORITHMS
      notifyPayload = ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS);

      //SIGNATURE_HASH_ALGORITHMS notification received?
      if(notifyPayload != NULL)
      {
         //This notification indicates the list of hash functions supported by
         //the sending peer (refer to RFC 7427, section 4)
         error = ikeParseSignHashAlgosNotification(sa, notifyPayload);

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

      //End of exception handling block
   } while(0);

   //An IKE message flow always consists of a request followed by a response
   return ikeSendIkeSaInitResponse(sa);
}


/**
 * @brief Process incoming IKE_SA_INIT response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessIkeSaInitResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint16_t notifyMsgType;
   const IkeHeader *ikeHeader;
   const IkeSaPayload *saPayload;
   const IkeKePayload *kePayload;
   const IkeNoncePayload *noncePayload;
   const IkeCertReqPayload *certReqPayload;
   const IkeNotifyPayload *notifyPayload;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;

   //Check the state of the IKE SA
   if(sa->state != IKE_SA_STATE_INIT_RESP)
      return ERROR_UNEXPECTED_MESSAGE;

   //Save the length of the second message (IKE_SA_INIT response)
   sa->responderSaInitLen = length;

   //Start of exception handling block
   do
   {
      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Check whether the response includes a Notify payload indicating an error
      notifyPayload = ikeGetErrorNotifyPayload(message, length);

      //Error notification found?
      if(notifyPayload != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(notifyPayload->notifyMsgType);

         //Some error notifications such as INVALID_KE_PAYLOAD may lead to a
         //subsequent successful exchange
         if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
         {
            //If the initiator guesses wrong, the responder will respond with a
            //Notify payload of type INVALID_KE_PAYLOAD indicating the selected
            //group (refer to RFC 7296, section 1.2)
            error = ikeParseInvalidKeyPayloadNotification(sa, notifyPayload);
            //Malformed notification?
            if(error)
               break;

            //Reinitialize Diffie-Hellman context
            ikeFreeDhContext(sa);
            ikeInitDhContext(sa);

            //Generate a new ephemeral key pair
            error = ikeGenerateDhKeyPair(sa);
            //Any error to report?
            if(error)
               break;

            //The initiator must retry the IKE_SA_INIT with the corrected
            //Diffie-Hellman group (refer to RFC 7296, section 1.2)
            error = ERROR_RETRY;
            break;
         }
         else
         {
            //An implementation receiving an error type that it does not
            //recognize in a response must assume that the corresponding
            //request has failed entirely (refer to RFC 7296, section 3.10.1)
            error = ERROR_UNEXPECTED_STATUS;
            break;
         }
      }

      //Check whether the response includes a COOKIE notification
      notifyPayload = ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_COOKIE);

      //COOKIE notification received?
      if(notifyPayload != NULL)
      {
         //Save the received cookie
         error = ikeParseCookieNotification(sa, notifyPayload);
         //Malformed notification?
         if(error)
            break;

         //If the IKE_SA_INIT response includes the COOKIE notification, the
         //initiator must then retry the IKE_SA_INIT request
         error = ERROR_RETRY;
         break;
      }

      //The responder chooses a cryptographic suite from the initiator's offered
      //choices and expresses that choice in the SAr payload
      saPayload = (IkeSaPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_SA, 0);

      //The responder completes the Diffie-Hellman exchange with the KEr payload
      kePayload = (IkeKePayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_KE, 0);

      //The responder sends its nonce in the Nr payload
      noncePayload = (IkeNoncePayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_NONCE, 0);

      //A Certificate Request payload can optionally be included
      certReqPayload = (IkeCertReqPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_CERTREQ, 0);

      //Mandatory payloads must be included in the received message
      if(saPayload == NULL || kePayload == NULL || noncePayload == NULL)
      {
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //The responder's SPI must not be zero
      if(osMemcmp(ikeHeader->responderSpi, IKE_INVALID_SPI, IKE_SPI_SIZE) == 0)
      {
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Save responder's IKE SPI
      osMemcpy(sa->responderSpi, ikeHeader->responderSpi, IKE_SPI_SIZE);

      //Save responder's nonce
      error = ikeParseNoncePayload(noncePayload, sa->responderNonce,
         &sa->responderNonceLen);
      //Malformed nonce?
      if(error)
         break;

      //Check the syntax of the SAr payload
      error = ikeParseSaPayload(saPayload);
      //Malformed SAr payload?
      if(error)
         break;

      //The initiator of an exchange must check that the accepted offer is
      //consistent with one of its proposals, and if not must terminate the
      //exchange (refer to RFC 7296, section 3.3.6)
      error = ikeCheckSaProposal(sa, saPayload);
      //Invalid cryptographic suite?
      if(error)
         break;

      //Nonces used in IKEv2 must be at least half the key size of the
      //negotiated pseudorandom function (refer to RFC 7296, section 2.10)
      error = ikeCheckNonceLength(sa, sa->responderNonceLen);
      //Unacceptable nonce length?
      if(error)
         break;

      //The Key Exchange payload is used to exchange Diffie-Hellman public
      //numbers as part of a Diffie-Hellman key exchange
      error = ikeParseKePayload(sa, kePayload);
      //Any error to report?
      if(error)
         break;

      //The Certificate Request payload is optional
      if(certReqPayload != NULL)
      {
         //The Certificate Request payload provides a means to request preferred
         //certificates via IKE (refer to RFC 7296, section 3.7)
         error = ikeParseCertReqPayload(sa, certReqPayload);
         //Any error to report?
         if(error)
            break;
      }

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
      //Search the IKE_SA_INIT message for a Notify payload of type
      //SIGNATURE_HASH_ALGORITHMS
      notifyPayload = ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS);

      //SIGNATURE_HASH_ALGORITHMS notification received?
      if(notifyPayload != NULL)
      {
         //This notification indicates the list of hash functions supported by
         //the sending peer (refer to RFC 7427, section 4)
         error = ikeParseSignHashAlgosNotification(sa, notifyPayload);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //The notification is not present in the IKE_SA_INIT message
         sa->signHashAlgos = 0;
      }
#endif

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //The second pair of messages (IKE_AUTH) authenticate the previous
      //messages, exchange identities and certificates, and establish the
      //first Child SA
      error = ikeSendIkeAuthRequest(sa);
   }
   else if(error == ERROR_RETRY)
   {
      //The initiator must then retry the IKE_SA_INIT request
      error = ikeSendIkeSaInitRequest(sa);
   }
   else
   {
      //The IKE_SA_INIT response is not valid
   }

   //Check whether the IKE_SA_INIT exchange has failed
   if(error)
   {
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming IKE_AUTH request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessIkeAuthRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   IkeChildSaEntry *childSa;
   IpsecPadEntry *padEntry;
   const IkeIdPayload *idPayload;
   const IkeCertPayload *certPayload;
   const IkeCertReqPayload *certReqPayload;
   const IkeAuthPayload *authPayload;
   const IkeSaPayload *saPayload;
   const IkeTsPayload *tsiPayload;
   const IkeTsPayload *tsrPayload;

   //Initialize Child SA
   childSa = NULL;

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

      //The initiator asserts its identity with the IDi payload (refer to
      //RFC 7296, section 1.2)
      idPayload = (IkeIdPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_IDI, 0);

      //The Certificate payload provides a means to transport certificates or
      //other authentication-related information via IKE
      certPayload = (IkeCertPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_CERT, 0);

      //A Certificate Request payload can optionally be included
      certReqPayload = (IkeCertReqPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_CERTREQ, 0);

      //The initiator proves knowledge of the secret corresponding to IDi and
      //integrity protects the contents of the first message using the AUTH
      //payload
      authPayload = (IkeAuthPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_AUTH, 0);

      //Mandatory payloads must be included in the received message
      if(idPayload == NULL || authPayload == NULL)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Parse Identification payload
      error = ikeParseIdPayload(sa, idPayload);

      //Malformed Identification payload?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
         break;
      }

      //Perform lookup in the PAD database based on the ID
      padEntry = ipsecFindPadEntry(netContext.ipsecContext, sa->peerIdType,
         sa->peerId, sa->peerIdLen);

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
      //Check whether a Certificate payload is included
      if(certPayload != NULL)
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

      //The peers are authenticated by having each sign (or MAC using a padded
      //shared secret as the key, as described later in this section) a block
      //of data (refer to RFC 7296, section 2.15)
      error = ikeVerifyAuth(sa, padEntry, idPayload, certPayload, authPayload);

      //Authentication failure?
      if(error)
      {
         sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_AUTH_FAILED;
         break;
      }

      //The Certificate Request payload is optional
      if(certReqPayload != NULL)
      {
         //The Certificate Request payload provides a means to request preferred
         //certificates via IKE (refer to RFC 7296, section 3.7)
         error = ikeParseCertReqPayload(sa, certReqPayload);

         //Malformed Certificate Request payload?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }

      //The initiator begins negotiation of a Child SA using the SAi payload
      saPayload = (IkeSaPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_SA, 0);

      //TSi specifies the source address of traffic forwarded from (or the
      //destination address of traffic forwarded to) the initiator of the
      //Child SA pair
      tsiPayload = (IkeTsPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_TSI, 0);

      //TSr specifies the destination address of the traffic forwarded to (or
      //the source address of the traffic forwarded from) the responder of the
      //Child SA pair
      tsrPayload = (IkeTsPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_TSR, 0);

      //Child SAs can be created either by being piggybacked on the IKE_AUTH
      //exchange, or using a separate CREATE_CHILD_SA exchange
      if(saPayload != NULL && tsiPayload != NULL && tsrPayload != NULL)
      {
         //Create a new Child SA
         childSa = ikeCreateChildSaEntry(sa->context);

         //Failed to create Child SA?
         if(childSa == NULL)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
            break;
         }

         //Initialize Child SA
         childSa->sa = sa;
         childSa->mode = IPSEC_MODE_TUNNEL;
         childSa->initiator = FALSE;

         //Generate a new SPI for the Child SA
         error = ikeGenerateChildSaSpi(childSa, childSa->localSpi);

         //Any error to report?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE;
            break;
         }

         //IKEv2 allows the responder to choose a subset of the traffic proposed
         //by the initiator (refer to RFC 7296, section 2.9)
         error = ikeSelectTs(childSa, tsiPayload, tsrPayload);

         //If the responder's policy does not allow it to accept any part of
         //the proposed Traffic Selectors, it responds with a TS_UNACCEPTABLE
         //Notify message
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE;
            break;
         }

         //Check the syntax of the SAi payload
         error = ikeParseSaPayload(saPayload);

         //Malformed SAi payload?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }

         //The responder must choose a single suite, which may be any subset
         //of the SA proposal (refer to RFC 7296, section 2.7)
         error = ikeSelectChildSaProposal(childSa, saPayload);

         //The responder must accept a single proposal or reject them all and
         //return an error. The error is given in a notification of type
         //NO_PROPOSAL_CHOSEN
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN;
            break;
         }

         //The USE_TRANSPORT_MODE notification may be included in a request
         //message that also includes an SA payload requesting a Child SA
         if(ikeGetStatusNotifyPayload(message, length,
            IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE) != NULL)
         {
            //It requests that the Child SA use transport mode rather than
            //tunnel mode for the SA created
            childSa->mode = IPSEC_MODE_TRANSPORT;
         }

         //Attach the newly created Child SA to the IKE SA
         sa->childSa = childSa;
      }

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
      //The INITIAL_CONTACT notification asserts that this IKE SA is the only
      //IKE SA currently active between the authenticated identities
      if(ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT) != NULL)
      {
         //It may be sent when an IKE SA is established after a crash, and the
         //recipient may use this information to delete any other IKE SAs it
         //has to the same authenticated identity without waiting for a timeout
         sa->initialContact = TRUE;
      }
#endif

      //End of exception handling block
   } while(0);

   //Failed to create Child SA?
   if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE ||
      sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED)
   {
      //If creating the Child SA during the IKE_AUTH exchange fails for some
      //reason, the IKE SA is still created as usual (refer to RFC 7296,
      //section 1.2)
      if(childSa != NULL)
      {
         ikeDeleteChildSaEntry(childSa);
      }
   }

   //An IKE message flow always consists of a request followed by a response
   return ikeSendIkeAuthResponse(sa);
}


/**
 * @brief Process incoming IKE_AUTH response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessIkeAuthResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint16_t notifyMsgType;
   IkeChildSaEntry *childSa;
   IpsecPadEntry *padEntry;
   const IkeIdPayload *idPayload;
   const IkeCertPayload *certPayload;
   const IkeAuthPayload *authPayload;
   const IkeSaPayload *saPayload;
   const IkeNotifyPayload *notifyPayload;
   const IkeTsPayload *tsiPayload;
   const IkeTsPayload *tsrPayload;

   //Point to the Child SA
   childSa = sa->childSa;

   //Start of exception handling block
   do
   {
      //Check the state of the IKE SA
      if(sa->state != IKE_SA_STATE_AUTH_RESP)
      {
         error = ERROR_UNEXPECTED_MESSAGE;
         break;
      }

      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Check whether the response includes a Notify payload indicating an error
      notifyPayload = ikeGetErrorNotifyPayload(message, length);

      //Error notification found?
      if(notifyPayload != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(notifyPayload->notifyMsgType);

         //If creating the Child SA during the IKE_AUTH exchange fails for some
         //reason, the IKE SA is still created as usual (refer to RFC 7296,
         //section 1.2)
         if(notifyMsgType != IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED)
         {
            error = ERROR_UNEXPECTED_STATUS;
            break;
         }
      }

      //The responder asserts its identity with the IDr payload (refer to
      //RFC 7296, section 1.2)
      idPayload = (IkeIdPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_IDR, 0);

      //The Certificate payload provides a means to transport certificates or
      //other authentication-related information via IKE
      certPayload = (IkeCertPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_CERT, 0);

      //The responder authenticates its identity and protects the integrity
      //of the second message with the AUTH payload
      authPayload = (IkeAuthPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_AUTH, 0);

      //Mandatory payloads must be included in the received message
      if(idPayload == NULL || authPayload == NULL)
      {
         error = ERROR_AUTHENTICATION_FAILED;
         break;
      }

      //Parse Identification payload
      error = ikeParseIdPayload(sa, idPayload);
      //Malformed Identification payload?
      if(error)
      {
         error = ERROR_AUTHENTICATION_FAILED;
         break;
      }

      //Perform lookup in the PAD database based on the ID
      padEntry = ipsecFindPadEntry(netContext.ipsecContext, sa->peerIdType,
         sa->peerId, sa->peerIdLen);
      //Invalid ID?
      if(padEntry == NULL)
      {
         error = ERROR_AUTHENTICATION_FAILED;
         break;
      }

#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Check whether a Certificate payload is included
      if(certPayload != NULL)
      {
         //Parse the certificate chain
         error = ikeParseCertificateChain(sa, padEntry, message, length);
         //Failed to validate certificate chain?
         if(error)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }
#endif

      //The peers are authenticated by having each sign (or MAC using a padded
      //shared secret as the key, as described later in this section) a block
      //of data (refer to RFC 7296, section 2.15)
      error = ikeVerifyAuth(sa, padEntry, idPayload, certPayload, authPayload);
      //Authentication failure?
      if(error)
      {
         error = ERROR_AUTHENTICATION_FAILED;
         break;
      }

      //The responder completes negotiation of a Child SA with additional fields
      if(childSa != NULL)
      {
         //Successful Child SA creation?
         if(notifyPayload == NULL)
         {
            //The responder chooses a cryptographic suite from the initiator's
            //offered choices and expresses that choice in the SAr payload
            saPayload = (IkeSaPayload *) ikeGetPayload(message, length,
               IKE_PAYLOAD_TYPE_SA, 0);

            //TSi specifies the source address of traffic forwarded from (or
            //the destination address of traffic forwarded to) the initiator
            //of the Child SA pair
            tsiPayload = (IkeTsPayload *) ikeGetPayload(message, length,
               IKE_PAYLOAD_TYPE_TSI, 0);

            //TSr specifies the destination address of the traffic forwarded
            //to (or the source address of the traffic forwarded from) the
            //responder of the Child SA pair
            tsrPayload = (IkeTsPayload *) ikeGetPayload(message, length,
               IKE_PAYLOAD_TYPE_TSR, 0);

            //Mandatory payloads must be included in the received message
            if(saPayload == NULL || tsiPayload == NULL || tsrPayload == NULL)
            {
               error = ERROR_INVALID_MESSAGE;
               break;
            }

            //Check the syntax of the SAr payload
            error = ikeParseSaPayload(saPayload);
            //Malformed SAr payload?
            if(error)
               break;

            //The initiator of an exchange must check that the accepted offer
            //is consistent with one of its proposals, and if not must terminate
            //the exchange (refer to RFC 7296, section 3.3.6)
            error = ikeCheckChildSaProposal(childSa, saPayload);
            //Invalid cryptographic suite?
            if(error)
               break;

            //When the responder chooses a subset of the traffic proposed by
            //the initiator, it narrows the Traffic Selectors to some subset
            //of the initiator's proposal (refer to RFC 7296, section 2.9)
            error = ikeCheckTs(childSa, tsiPayload, tsrPayload);
            //Invalid traffic selector?
            if(error)
               break;

            //The initiator can request that the Child SA use transport mode rather
            //than tunnel mode for the SA created
            if(childSa->mode == IPSEC_MODE_TRANSPORT)
            {
               //If the request is accepted, the response must also include a
               //notification of type USE_TRANSPORT_MODE
               if(ikeGetStatusNotifyPayload(message, length,
                  IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE) == NULL)
               {
                  //Use tunnel mode
                  childSa->mode = IPSEC_MODE_TUNNEL;
               }
            }

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
            //Any error to report?
            if(error)
               break;
         }
         else
         {
            //The Child SA creation has failed
            ikeDeleteChildSaEntry(childSa);
            sa->childSa = NULL;
            childSa = NULL;

            //Request closure of the IKE SA
            sa->deleteRequest = TRUE;
         }
      }

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
      //The INITIAL_CONTACT notification asserts that this IKE SA is the only
      //IKE SA currently active between the authenticated identities
      if(ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT) != NULL)
      {
         //It may be sent when an IKE SA is established after a crash, and the
         //recipient may use this information to delete any other IKE SAs it
         //has to the same authenticated identity without waiting for a timeout
         ikeDeleteDuplicateSaEntries(sa);
      }
#endif

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //The initiator has received the IKE_AUTH response
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

      //Check whether reauthentication is on-going
      if(sa->oldSa != NULL)
      {
         //IKEv2 does not have any special support for reauthentication.
         //Reauthentication is done by creating a new IKE SA from scratch,
         //creating new Child SAs within the new IKE SA, and finally deleting
         //the old IKE SA
         ikeProcessSaDeleteEvent(sa->oldSa);

         //Detach the old IKE SA
         sa->oldSa = NULL;
      }
   }
   else if(error == ERROR_AUTHENTICATION_FAILED)
   {
      //All errors causing the authentication to fail for whatever reason
      //(invalid shared secret, invalid ID, untrusted certificate issuer,
      //revoked or expired certificate, etc.) should result in an
      //AUTHENTICATION_FAILED notification
      ikeChangeSaState(sa, IKE_SA_STATE_AUTH_FAILURE_REQ);

      //If the error occurs on the initiator, the notification may be returned
      //in a separate INFORMATIONAL exchange, usually with no other payloads.
      //This is an exception for the general rule of not starting new exchanges
      //based on errors in responses (refer to RFC 7296, section 2.21.2)
      ikeSendInfoRequest(sa);
   }
   else
   {
      //The IKE_AUTH exchange has failed
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming CREATE_CHILD_SA request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessCreateChildSaRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   //The CREATE_CHILD_SA exchange may be initiated by either end of the IKE SA
   //after the initial exchanges are completed (refer to RFC 7296, section 1.3)
   if(sa->state < IKE_SA_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //A minimal implementation may support the CREATE_CHILD_SA exchange only in
   //so far as to recognize requests and reject them with a Notify payload of
   //type NO_ADDITIONAL_SAS (refer to RFC 7296, section 4)
   sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS;

   //An IKE message flow always consists of a request followed by a response
   return ikeSendCreateChildSaResponse(sa, NULL);
}


/**
 * @brief Process incoming CREATE_CHILD_SA response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessCreateChildSaResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_UNEXPECTED_MESSAGE;
}


/**
 * @brief Process incoming INFORMATIONAL request
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessInfoRequest(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint_t i;
   uint16_t notifyMsgType;
   const IkeDeletePayload *deletePayload;
   const IkeNotifyPayload *notifyPayload;

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

      //Check whether the response includes a Notify payload indicating an error
      notifyPayload = ikeGetErrorNotifyPayload(message, length);

      //Error notification found?
      if(notifyPayload != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(notifyPayload->notifyMsgType);

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
 * @brief Process incoming INFORMATIONAL response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeProcessInfoResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint_t i;
   const IkeDeletePayload *deletePayload;
   const IkeNotifyPayload *notifyPayload;

   //Start of exception handling block
   do
   {
      //Check the state of the IKE SA
      if(sa->state != IKE_SA_STATE_DPD_RESP &&
         sa->state != IKE_SA_STATE_DELETE_RESP &&
         sa->state != IKE_SA_STATE_DELETE_CHILD_RESP &&
         sa->state != IKE_SA_STATE_AUTH_FAILURE_RESP)
      {
         error = ERROR_UNEXPECTED_MESSAGE;
         break;
      }

      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Check whether the response includes a Notify payload indicating an error
      notifyPayload = ikeGetErrorNotifyPayload(message, length);

      //Error notification found?
      if(notifyPayload != NULL)
      {
         //An implementation receiving an error type that it does not recognize
         //in a response must assume that the corresponding request has failed
         //entirely (refer to RFC 7296, section 3.10.1)
         error = ERROR_UNEXPECTED_STATUS;
         break;
      }

      //The response in the INFORMATIONAL exchange will contain Delete payloads
      //for the paired SAs going in the other direction
      for(i = 0; ; i++)
      {
         //Extract next Delete payload
         deletePayload = (IkeDeletePayload *) ikeGetPayload(message, length,
            IKE_PAYLOAD_TYPE_D, i);
         //Delete payload not found?
         if(deletePayload == NULL)
            break;

         //The Delete payload list the SPIs to be deleted
         error = ikeParseDeletePayload(sa, deletePayload, TRUE);
         //Malformed payload?
         if(error)
            break;
      }

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //Check the state of the IKE SA
      if(sa->state == IKE_SA_STATE_DPD_RESP)
      {
         //Receipt of a fresh cryptographically protected message on an IKE SA
         //ensures liveness of the IKE SA and all of its Child SAs
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_RESP ||
         sa->state == IKE_SA_STATE_AUTH_FAILURE_RESP)
      {
         //Deleting an IKE SA implicitly closes any remaining Child SAs
         //negotiated under it (refer to RFC 7296, section 1.4.1)
         ikeDeleteSaEntry(sa);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_CHILD_RESP)
      {
         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);
      }
      else
      {
         //Just for sanity
      }
   }
   else
   {
      //Delete the IKE SA
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}

#endif
