/**
 * @file ike_message_dispatch.c
 * @brief IKE message dispatching
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
#include "ike/ike_message_dispatch.h"
#include "ike/ike_message_decrypt.h"
#include "ike/ike_request_parse.h"
#include "ike/ike_response_format.h"
#include "ike/ike_response_parse.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Dispatch incoming IKE message
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeDispatchMessage(IkeContext *context, uint8_t *message, size_t length)
{
   error_t error;
   IkeHeader *ikeHeader;

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //Port 4500 is reserved for UDP-encapsulated ESP and IKE
   if(context->localPort == IPSEC_NAT_PORT)
   {
      //The receiver should ignore a received NAT-keepalive packet (refer to
      //RFC 3948, section 2.3)
      if(length == IKE_NAT_KEEPALIVE_PACKET_SIZE &&
         message[0] == IKE_NAT_KEEPALIVE_PACKET_VALUE)
      {
         return NO_ERROR;
      }

      //Malformed IKE message?
      if(length < IKE_PREFIX_SIZE)
         return ERROR_INVALID_LENGTH;

      //The UDP payload of all packets containing IKE messages sent on port 4500
      //must begin with the prefix of four zeros (refer to RFC 7296, section 2)
      if(LOAD32BE(message) != IKE_PREFIX_VALUE)
         return ERROR_INVALID_MESSAGE;

      //These four octets of zeros are not part of the IKE message and are not
      //included in any of the length fields or checksums defined by IKE
      message += IKE_PREFIX_SIZE;
      length -= IKE_PREFIX_SIZE;
   }
#endif

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
   if(ntohl(ikeHeader->length) < sizeof(IkeHeader) ||
      ntohl(ikeHeader->length) > length)
   {
      return ERROR_INVALID_LENGTH;
   }

   //The Length field indicates the total length of the IKE message in octets
   length = ntohl(ikeHeader->length);

   //The R bit indicates whether the message is a request or response
   if((ikeHeader->flags & IKE_FLAGS_R) == 0)
   {
      //Process IKE request
      error = ikeDispatchRequest(context, message, length);
   }
   else
   {
      //Process IKE response
      error = ikeDispatchResponse(context, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Dispatch incoming IKE request
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeDispatchRequest(IkeContext *context, uint8_t *message, size_t length)
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
         error = ikeParseIkeSaInitRequest(context, message, length);
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
                        error = ikeParseIkeAuthRequest(sa, message, length);
                     }
                     else if(exchangeType == IKE_EXCHANGE_TYPE_CREATE_CHILD_SA)
                     {
                        //Process CREATE_CHILD_SA request
                        error = ikeParseCreateChildSaRequest(sa, message,
                           length);
                     }
                     else if(exchangeType == IKE_EXCHANGE_TYPE_INFORMATIONAL)
                     {
                        //Process INFORMATIONAL request
                        error = ikeParseInfoRequest(sa, message, length);
                     }
                     else
                     {
                        //Unknown exchange type
                        error = ERROR_UNKNOWN_TYPE;
                     }

                     //Check the state of the IKE SA
                     if(sa->state != IKE_SA_STATE_CLOSED) 
                     {
                        //Only authentication failures (AUTHENTICATION_FAILED
                        //and EAP failure) and malformed messages (INVALID_SYNTAX)
                        //lead to a deletion of the IKE SA without requiring an
                        //explicit INFORMATIONAL exchange carrying a Delete payload
                        if(sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_AUTH_FAILED ||
                           sa->notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
                        {
                           //This error notification is considered fatal in both
                           //peers
                           ikeDeleteSaEntry(sa);
                        }
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
            //the node. If the message is marked as a request, the node can
            //audit the suspicious event and may send a response
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
 * @brief Dispatch incoming IKE response
 * @param[in] context Pointer to the IKE context
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeDispatchResponse(IkeContext *context, uint8_t *message, size_t length)
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
                     error = ikeParseIkeSaInitResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_IKE_AUTH)
                  {
                     //Process IKE_AUTH response
                     error = ikeParseIkeAuthResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_CREATE_CHILD_SA)
                  {
                     //Process CREATE_CHILD_SA response
                     error = ikeParseCreateChildSaResponse(sa, message, length);
                  }
                  else if(exchangeType == IKE_EXCHANGE_TYPE_INFORMATIONAL)
                  {
                     //Process INFORMATIONAL response
                     error = ikeParseInfoResponse(sa, message, length);
                  }
                  else
                  {
                     //Unknown exchange type
                     error = ERROR_UNKNOWN_TYPE;
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

#endif
