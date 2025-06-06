/**
 * @file ike_misc.c
 * @brief Helper functions for IKEv2
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
#include "ike/ike.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "ipsec/ipsec_misc.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)

//Invalid IKE SPI value
const uint8_t IKE_INVALID_SPI[8] = {0};


/**
 * @brief Retransmit IKE request message
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeRetransmitRequest(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Debug message
   TRACE_INFO("Retransmitting IKE request (%" PRIuSIZE " bytes)...\r\n",
      sa->requestLen);

   //Dump IKE message for debugging purpose
   ikeDumpMessage(sa->request, sa->requestLen);

   //A retransmission from the initiator must be bitwise identical to the
   //original request (refer to RFC 7296, section 2.1)
   error = socketSendTo(context->socket, &sa->remoteIpAddr, sa->remotePort,
      sa->request, sa->requestLen, NULL, 0);

   //Retransmission times must increase exponentially to avoid flooding the
   //network and making an existing congestion situation worse (refer to
   //RFC 7296, section 2.4)
   sa->timeout = MIN(sa->timeout * 2, IKE_MAX_TIMEOUT);

   //Save the time at which the message was sent
   sa->timestamp = osGetSystemTime();

   //Increment retransmission counter
   sa->retransmitCount++;

   //Return status code
   return error;
}


/**
 * @brief Retransmit IKE response message
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeRetransmitResponse(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //In order to allow saving memory, responders are allowed to forget the
   //response after a timeout of several minutes
   if(sa->responseLen > 0)
   {
      //Debug message
      TRACE_INFO("Retransmitting IKE response (%" PRIuSIZE " bytes)...\r\n",
         sa->responseLen);

      //Dump IKE message for debugging purpose
      ikeDumpMessage(sa->response, sa->responseLen);

      //Retransmit the response
      error = socketSendTo(context->socket, &context->remoteIpAddr,
         context->remotePort, sa->response, sa->responseLen, NULL, 0);
   }

   //Return status code
   return error;
}


/**
 * @brief Create a new IKE Security Association
 * @param[in] context Pointer to the IKE context
 * @return Pointer to the newly created IKE SA
 **/

IkeSaEntry *ikeCreateSaEntry(IkeContext *context)
{
   uint_t i;
   IkeSaEntry *sa;

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      sa = &context->sa[i];

      //Check whether the current IKE SA is free
      if(sa->state == IKE_SA_STATE_CLOSED)
      {
         //Clear IKE SA entry
         osMemset(sa, 0, sizeof(IkeSaEntry));

         //Attach IKE context
         sa->context = context;

         //Initialize IKE SA parameters
         sa->txMessageId = UINT32_MAX;
         sa->rxMessageId = UINT32_MAX;

         //Initialize Diffie-Hellman context
         ikeInitDhContext(sa);

         //Default state
         sa->state = IKE_SA_STATE_RESERVED;

         //Return a pointer to the newly created IKE SA
         return sa;
      }
   }

   //The IKE SA table runs out of space
   return NULL;
}


/**
 * @brief Find an IKE SA that matches an incoming IKE message
 * @param[in] context Pointer to the IKE context
 * @param[in] ikeHeader Pointer to the IKE header
 * @return Pointer to the matching IKE SA, if any
 **/

IkeSaEntry *ikeFindSaEntry(IkeContext *context, const IkeHeader *ikeHeader)
{
   uint_t i;
   const uint8_t *spi;
   IkeSaEntry *sa;

   //The I bit is used by the recipient to determine which eight octets of the
   //SPI were generated by the recipient (refer to RFC 7296, section 3.1)
   if((ikeHeader->flags & IKE_FLAGS_I) != 0)
   {
      spi = ikeHeader->responderSpi;
   }
   else
   {
      spi = ikeHeader->initiatorSpi;
   }

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      sa = &context->sa[i];

      //Check whether the current IKE SA is active
      if(sa->state != IKE_SA_STATE_CLOSED)
      {
         //Check whether the entity is the original initiator of the IKE SA
         if(sa->originalInitiator)
         {
            //Compare SPIs
            if(osMemcmp(sa->initiatorSpi, spi, IKE_SPI_SIZE) == 0)
            {
               //A matching IKE SA has been found
               return sa;
            }
         }
         else
         {
            //Compare SPIs
            if(osMemcmp(sa->responderSpi, spi, IKE_SPI_SIZE) == 0)
            {
               //A matching IKE SA has been found
               return sa;
            }
         }
      }
   }

   //The incoming IKE message does not match any IKE SA
   return NULL;
}


/**
 * @brief Find an half-open IKE SA that matches an incoming IKE_SA_INIT request
 * @param[in] context Pointer to the IKE context
 * @param[in] ikeHeader Pointer to the IKE header
 * @param[in] noncePayload Pointer to the Ni payload
 * @return Pointer to the matching IKE SA, if any
 **/

IkeSaEntry *ikeFindHalfOpenSaEntry(IkeContext *context,
   const IkeHeader *ikeHeader, const IkeNoncePayload *noncePayload)
{
   uint_t i;
   size_t n;
   IkeSaEntry *sa;

   //Retrieve the length of the Ni payload
   n = ntohs(noncePayload->header.payloadLength);

   //Check the length of the Ni payload
   if(n >= sizeof(IkeNoncePayload))
   {
      //Determine the length of the nonce
      n -= sizeof(IkeNoncePayload);

      //Loop through IKE SA entries
      for(i = 0; i < context->numSaEntries; i++)
      {
         //Point to the current IKE SA
         sa = &context->sa[i];

         //Check whether the current IKE SA is active
         if(sa->state != IKE_SA_STATE_CLOSED)
         {
            //Compare SPIs
            if(osMemcmp(sa->initiatorSpi, ikeHeader->initiatorSpi,
               IKE_SPI_SIZE) == 0)
            {
               //It is not sufficient to use the initiator's SPI to lookup the
               //IKE SA. Instead, a robust responder will do the IKE SA lookup
               //using the whole packet, its hash, or the Ni payload (refer to
               //RFC 7296, section 2.1)
               if(sa->initiatorNonceLen == n && osMemcmp(sa->initiatorNonce,
                  noncePayload->nonceData, n) == 0)
               {
                  //A matching IKE SA has been found
                  return sa;
               }
            }
         }
      }
   }

   //The incoming IKE_SA_INIT request does not match any half-open IKE SA
   return NULL;
}


/**
 * @brief Delete an IKE Security Association
 * @param[in] sa Pointer to the IKE SA
 **/

void ikeDeleteSaEntry(IkeSaEntry *sa)
{
   uint_t i;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Debug message
   TRACE_INFO("Deleting IKE SA...\r\n");

   //Point to the IKE context
   context = sa->context;

   //Achieving perfect forward secrecy requires that when a connection is
   //closed, each endpoint must forget not only the keys used by the
   //connection but also any information that could be used to recompute
   //those keys (refer to RFC 7296, section 2.12)
   ikeFreeDhContext(sa);

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check the state of the Child SA
      if(childSa->state != IKE_CHILD_SA_STATE_CLOSED)
      {
         //Deleting an IKE SA implicitly closes any remaining Child SAs
         //negotiated under it (refer to RFC 7296, section 1.4.1)
         if(childSa->sa == sa)
         {
            ikeDeleteChildSaEntry(childSa);
         }
      }
   }

   //Check whether reauthentication is on-going
   if(sa->oldSa != NULL && sa->oldSa->state != IKE_SA_STATE_CLOSED)
   {
      //Close the old IKE SA since reauthentication has failed
      sa->oldSa->deleteRequest = TRUE;
      //Notify the IKE context that the IKE SA should be closed
      osSetEvent(&context->event);
   }

   //Mark the IKE SA as closed
   sa->state = IKE_SA_STATE_CLOSED;
}


/**
 * @brief Delete an duplicate IKE Security Associations
 * @param[in] sa Pointer to the currently active IKE SA
 **/

void ikeDeleteDuplicateSaEntries(IkeSaEntry *sa)
{
   uint_t i;
   IkeContext *context;
   IkeSaEntry *entry;

   //Debug message
   TRACE_INFO("Deleting duplicate IKE SAs...\r\n");

   //Point to the IKE context
   context = sa->context;

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      entry = &context->sa[i];

      //Check the state of the IKE SA
      if(entry != sa && entry->state != IKE_SA_STATE_CLOSED)
      {
         //Different IKE SA with same authenticated identity?
         if(entry->peerIdType == sa->peerIdType &&
            entry->peerIdLen == sa->peerIdLen &&
            osMemcmp(entry->peerId, sa->peerId, sa->peerIdLen) == 0)
         {
            //The recipient of an INITIAL_CONTACT notification may use this
            //information to delete any other IKE SAs it has to the same
            //authenticated identity without waiting for a timeout (refer to
            //RFC 7296, section 2.4)
            ikeDeleteSaEntry(entry);
         }
      }
   }
}


/**
 * @brief Create a new Child Security Association
 * @param[in] context Pointer to the IKE context
 * @return Pointer to the newly created Child SA
 **/

IkeChildSaEntry *ikeCreateChildSaEntry(IkeContext *context)
{
   uint_t i;
   IkeChildSaEntry *childSa;

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check whether the current Child SA is free
      if(childSa->state == IKE_CHILD_SA_STATE_CLOSED)
      {
         //Clear Child SA entry
         osMemset(childSa, 0, sizeof(IkeChildSaEntry));

         //Attach IKE context
         childSa->context = context;

         //Allocate inbound SAD entry
         childSa->inboundSa = ipsecAllocateSadEntry(netContext.ipsecContext);

         //Failed to allocated SAD entry?
         if(childSa->inboundSa < 0)
         {
            //The SAD database runs out of space
            return NULL;
         }

         //Allocate outbound SAD entry
         childSa->outboundSa = ipsecAllocateSadEntry(netContext.ipsecContext);

         //Failed to allocated SAD entry?
         if(childSa->outboundSa < 0)
         {
            //Clean up side effects
            ipsecClearSadEntry(netContext.ipsecContext, childSa->inboundSa);
            //The SAD database runs out of space
            return NULL;
         }

         //Default state
         childSa->state = IKE_CHILD_SA_STATE_RESERVED;

         //Return a pointer to the newly created Child SA
         return childSa;
      }
   }

   //The Child SA table runs out of space
   return NULL;
}


/**
 * @brief Find an Child SA that matches the specified SPI
 * @param[in] sa Pointer to the IKE SA
 * @param[in] protocolId Protocol identifier (AH or ESP)
 * @param[in] spi Security parameter index
 * @return Pointer to the matching Child SA, if any
 **/

IkeChildSaEntry *ikeFindChildSaEntry(IkeSaEntry *sa, uint8_t protocolId,
   const uint8_t *spi)
{
   uint_t i;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Point to the IKE context
   context = sa->context;

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check the state of the Child SA
      if(childSa->state != IKE_CHILD_SA_STATE_CLOSED)
      {
         //Matching IKE SA and protocol identifier?
         if(childSa->sa == sa && childSa->protocol == protocolId)
         {
            //Compare SPIs
            if(osMemcmp(childSa->remoteSpi, spi, IPSEC_SPI_SIZE) == 0)
            {
               //A matching Child SA has been found
               return childSa;
            }
         }
      }
   }

   //The specified SPI does not match any Child SA
   return NULL;
}


/**
 * @brief Delete a Child Security Association
 * @param[in] childSa Pointer to the Child SA
 **/

void ikeDeleteChildSaEntry(IkeChildSaEntry *childSa)
{
   //Debug message
   TRACE_INFO("Deleting Child SA...\r\n");

   //Close inbound SAD entry
   if(childSa->inboundSa >= 0)
   {
      ipsecClearSadEntry(netContext.ipsecContext, childSa->inboundSa);
   }

   //Close outbound SAD entry
   if(childSa->outboundSa >= 0)
   {
      ipsecClearSadEntry(netContext.ipsecContext, childSa->outboundSa);
   }

   //Mark the Child SA as closed
   childSa->state = IKE_CHILD_SA_STATE_CLOSED;
}


/**
 * @brief Generate a new IKE SA SPI
 * @param[in] sa Pointer to the IKE SA
 * @param[out] spi Pointer to the buffer where to store the resulting SPI
 * @return Error code
 **/

error_t ikeGenerateSaSpi(IkeSaEntry *sa, uint8_t *spi)
{
   error_t error;
   uint_t i;
   IkeContext *context;
   IkeSaEntry *entry;

   //Debug message
   TRACE_INFO("Generating new IKE SA SPI (%u bytes)...\r\n", IKE_SPI_SIZE);

   //Point to the IKE context
   context = sa->context;

   //Each endpoint chooses one of the two SPIs and must choose them so as to
   //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
   do
   {
      //Generate an arbitrary 8-octet value
      error = context->prngAlgo->generate(context->prngContext, spi,
         IKE_SPI_SIZE);

      //Check status code
      if(!error)
      {
         //Non-zero SPI value?
         if(osMemcmp(spi, IKE_INVALID_SPI, IKE_SPI_SIZE) != 0)
         {
            //Loop through IKE SA entries
            for(i = 0; i < context->numSaEntries && !error; i++)
            {
               //Point to the current IKE SA
               entry = &context->sa[i];

               //Check the state of the IKE SA
               if(entry != sa && entry->state != IKE_SA_STATE_CLOSED)
               {
                  //Check whether the entity is the original initiator of the
                  //IKE SA
                  if(entry->originalInitiator)
                  {
                     //Test whether the SPI is a duplicate
                     if(osMemcmp(spi, entry->initiatorSpi, IKE_SPI_SIZE) == 0)
                     {
                        error = ERROR_INVALID_SPI;
                     }
                  }
                  else
                  {
                     //Test whether the SPI is a duplicate
                     if(osMemcmp(spi, entry->responderSpi, IKE_SPI_SIZE) == 0)
                     {
                        error = ERROR_INVALID_SPI;
                     }
                  }
               }
            }
         }
         else
         {
            //The SPI value must not be zero (refer to RFC 7296, section 3.1)
            error = ERROR_INVALID_SPI;
         }
      }

      //Repeat as necessary until a unique SPI is generated
   } while(error == ERROR_INVALID_SPI);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG_ARRAY("  ", spi, IKE_SPI_SIZE);
   }

   //Return status code
   return error;
}


/**
 * @brief Generate a new Child SA SPI
 * @param[in] childSa Pointer to the Child SA
 * @param[out] spi Pointer to the buffer where to store the resulting SPI
 * @return Error code
 **/

error_t ikeGenerateChildSaSpi(IkeChildSaEntry *childSa, uint8_t *spi)
{
   error_t error;
   uint_t i;
   IkeContext *context;
   IkeChildSaEntry *entry;

   //Debug message
   TRACE_INFO("Generating new Child SA SPI (%u bytes)...\r\n", IKE_SPI_SIZE);

   //Point to the IKE context
   context = childSa->context;

   //Generate a unique SPI value
   do
   {
      //Generate an arbitrary 4-octet value
      error = context->prngAlgo->generate(context->prngContext, spi,
         IPSEC_SPI_SIZE);

      //Check status code
      if(!error)
      {
         //Non-zero SPI value?
         if(osMemcmp(spi, IPSEC_INVALID_SPI, IPSEC_SPI_SIZE) != 0)
         {
            //Loop through Child SA entries
            for(i = 0; i < context->numChildSaEntries && !error; i++)
            {
               //Point to the current Child SA
               entry = &context->childSa[i];

               //Check the state of the Child SA
               if(entry != childSa && entry->state != IKE_CHILD_SA_STATE_CLOSED)
               {
                  //Test whether the SPI is a duplicate
                  if(osMemcmp(spi, entry->localSpi, IPSEC_SPI_SIZE) == 0)
                  {
                     error = ERROR_INVALID_SPI;
                  }
               }
            }
         }
         else
         {
            //The SPI value of zero is reserved and must not be sent on the
            //wire (refer to RFC 4302, section 2.4 and RFC 4303, section 2.1)
            error = ERROR_INVALID_SPI;
         }
      }

      //Repeat as necessary until a unique SPI is generated
   } while(error == ERROR_INVALID_SPI);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG_ARRAY("  ", spi, IPSEC_SPI_SIZE);
   }

   //Return status code
   return error;
}


/**
 * @brief Generate a new nonce
 * @param[in] context Pointer to the IKE context
 * @param[out] nonce Pointer to the buffer where to store the resulting nonce
 * @param[in] length Length of the nonce, in bytes
 * @return Error code
 **/

error_t ikeGenerateNonce(IkeContext *context, uint8_t *nonce, size_t *length)
{
   error_t error;

   //Debug message
   TRACE_INFO("Generating new nonce (%u bytes)...\r\n", IKE_DEFAULT_NONCE_SIZE);

   //Nonces used in IKEv2 must be randomly chosen and must be at least 128 bits
   //in size (refer to RFC 7296, section 2.10)
   error = context->prngAlgo->generate(context->prngContext, nonce,
      IKE_DEFAULT_NONCE_SIZE);

   //Check status code
   if(!error)
   {
      //Set the length of the nonce
      *length = IKE_DEFAULT_NONCE_SIZE;

      //Debug message
      TRACE_DEBUG_ARRAY("  ", nonce, IKE_DEFAULT_NONCE_SIZE);
   }

   //Return status code
   return error;
}


/**
 * @brief Apply random jitter to a time interval
 * @param[in] context Pointer to the IKE context
 * @param[out] delay Time interval to be randomized
 * @return Randomized time interval
 **/

systime_t ikeRandomizeDelay(IkeContext *context, systime_t delay)
{
   error_t error;
   systime_t delta;
   systime_t value;

   //Maximum jitter to be applied to the time interval
   delta = (delay * IKE_RANDOM_JITTER) / 100;

   //Sanity check
   if(delta > 0)
   {
      //Generate a random value
      error = context->prngAlgo->generate(context->prngContext,
         (uint8_t *) &value, sizeof(value));

      //Check status code
      if(!error)
      {
         //Apply random jitter to the time interval
         delay -= value % delta;
      }
   }

   //Return the randomized time interval
   return delay;
}


/**
 * @brief Traffic selector selection
 * @param[in] childSa Pointer to the Child SA
 * @param[in] tsiPayload Pointer to the TSi payload
 * @param[in] tsrPayload Pointer to the TSr payload
 * @return Error code
 **/

error_t ikeSelectTs(IkeChildSaEntry *childSa, const IkeTsPayload *tsiPayload,
   const IkeTsPayload *tsrPayload)
{
   error_t error;
   size_t n;
   IkeTsParams localTsParams;
   IkeTsParams remoteTsParams;
   IpsecSpdEntry *spdEntry;
   IpsecSelector selector;

   //Get the length of the TSi payload
   n = ntohs(tsiPayload->header.payloadLength);

   //Malformed TSi payload?
   if(n < sizeof(IkeTsPayload))
      return ERROR_INVALID_MESSAGE;

   //Check the number of traffic selectors
   if(tsiPayload->numTs < 1)
      return ERROR_INVALID_MESSAGE;

   //Parse the first Traffic Selector substructure of the TSi payload
   error = ikeParseTs(tsiPayload->trafficSelectors, n - sizeof(IkeTsPayload),
      &remoteTsParams);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the TSr payload
   n = ntohs(tsrPayload->header.payloadLength);

   //Malformed TSi payload?
   if(n < sizeof(IkeTsPayload))
      return ERROR_INVALID_MESSAGE;

   //Check the number of traffic selectors
   if(tsrPayload->numTs < 1)
      return ERROR_INVALID_MESSAGE;

   //Parse the first Traffic Selector substructure of the TSr payload
   error = ikeParseTs(tsrPayload->trafficSelectors, n - sizeof(IkeTsPayload),
      &localTsParams);
   //Any error to report?
   if(error)
      return error;

   //Make sure the IP Protocol ID fields are consistent
   if(localTsParams.ipProtocolId != remoteTsParams.ipProtocolId)
      return ERROR_INVALID_PROTOCOL;

   //Retrieve selector parameters
   selector.localIpAddr.start = localTsParams.startAddr;
   selector.localIpAddr.end = localTsParams.endAddr;
   selector.remoteIpAddr.start = remoteTsParams.startAddr;
   selector.remoteIpAddr.end = remoteTsParams.endAddr;
   selector.nextProtocol = localTsParams.ipProtocolId;
   selector.localPort.start = localTsParams.startPort;
   selector.localPort.end = localTsParams.endPort;
   selector.remotePort.start = remoteTsParams.startPort;
   selector.remotePort.end = remoteTsParams.endPort;

   //A responder uses the traffic selector proposals it receives via an SA
   //management protocol to select an appropriate entry in its SPD (refer to
   //RFC 4301, section 4.4.1)
   spdEntry = ipsecFindSpdEntry(netContext.ipsecContext,
      IPSEC_POLICY_ACTION_PROTECT, &selector);
   //No matching SPD entry?
   if(spdEntry == NULL)
      return ERROR_INVALID_SELECTOR;

   //IKEv2 allows the responder to choose a subset of the traffic proposed by
   //the initiator (refer to RFC 7296, section 2.9)
   if(!ipsecIntersectSelectors(&spdEntry->selector, &selector,
      &childSa->selector))
   {
      return ERROR_INVALID_SELECTOR;
   }

   //The SPD entry specifies the security protocol (AH or ESP) to employ
   childSa->protocol = spdEntry->protocol;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether the selected traffic selectors are acceptable
 * @param[in] childSa Pointer to the Child SA
 * @param[in] tsiPayload Pointer to the TSi payload
 * @param[in] tsrPayload Pointer to the TSr payload
 * @return Error code
 **/

error_t ikeCheckTs(IkeChildSaEntry *childSa, const IkeTsPayload *tsiPayload,
   const IkeTsPayload *tsrPayload)
{
   error_t error;
   size_t n;
   IpsecSelector selector;
   IkeTsParams localTsParams;
   IkeTsParams remoteTsParams;

   //Get the length of the TSi payload
   n = ntohs(tsiPayload->header.payloadLength);

   //Malformed TSi payload?
   if(n < sizeof(IkeTsPayload))
      return ERROR_INVALID_MESSAGE;

   //Check the number of traffic selectors
   if(tsiPayload->numTs < 1)
      return ERROR_INVALID_MESSAGE;

   //Parse the first Traffic Selector substructure of the TSi payload
   error = ikeParseTs(tsiPayload->trafficSelectors, n - sizeof(IkeTsPayload),
      &localTsParams);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the TSr payload
   n = ntohs(tsrPayload->header.payloadLength);

   //Malformed TSi payload?
   if(n < sizeof(IkeTsPayload))
      return ERROR_INVALID_MESSAGE;

   //Check the number of traffic selectors
   if(tsrPayload->numTs < 1)
      return ERROR_INVALID_MESSAGE;

   //Parse the first Traffic Selector substructure of the TSr payload
   error = ikeParseTs(tsrPayload->trafficSelectors, n - sizeof(IkeTsPayload),
      &remoteTsParams);
   //Any error to report?
   if(error)
      return error;

   //Make sure the IP Protocol ID fields are consistent
   if(localTsParams.ipProtocolId != remoteTsParams.ipProtocolId)
      return ERROR_INVALID_PROTOCOL;

   //Retrieve selector parameters
   selector.localIpAddr.start = localTsParams.startAddr;
   selector.localIpAddr.end = localTsParams.endAddr;
   selector.remoteIpAddr.start = remoteTsParams.startAddr;
   selector.remoteIpAddr.end = remoteTsParams.endAddr;
   selector.nextProtocol = localTsParams.ipProtocolId;
   selector.localPort.start = localTsParams.startPort;
   selector.localPort.end = localTsParams.endPort;
   selector.remotePort.start = remoteTsParams.startPort;
   selector.remotePort.end = remoteTsParams.endPort;

   //IKEv2 allows the responder to choose a subset of the traffic proposed by
   //the initiator (refer to RFC 7296, section 2.9)
   if(!ipsecIsSubsetSelector(&selector, &childSa->selector))
      return ERROR_INVALID_SELECTOR;

   //Save traffic selector
   childSa->selector = selector;

   //The selected traffic selectors are acceptable
   return NO_ERROR;
}


/**
 * @brief Check the length of the nonce
 * @param[in] sa Pointer to the IKE SA
 * @param[in] nonceLen Length of the nonce, in bytes
 * @return Error code
 **/

error_t ikeCheckNonceLength(IkeSaEntry *sa, size_t nonceLen)
{
   size_t prfKeyLen;

#if (IKE_CMAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-CMAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC)
   {
      prfKeyLen = 16;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_MD5_SUPPORT == ENABLED)
   //HMAC-MD5 PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_MD5)
   {
      prfKeyLen = MD5_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1 PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA1)
   {
      prfKeyLen = SHA1_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256 PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256)
   {
      prfKeyLen = SHA256_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384 PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384)
   {
      prfKeyLen = SHA384_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512 PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512)
   {
      prfKeyLen = SHA512_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED && IKE_TIGER_SUPPORT == ENABLED)
   //HMAC-Tiger PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_HMAC_TIGER)
   {
      prfKeyLen = TIGER_DIGEST_SIZE;
   }
   else
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED && IKE_AES_128_SUPPORT == ENABLED)
   //AES-XCBC-MAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC)
   {
      prfKeyLen = 16;
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      prfKeyLen = 0;
   }

   //Nonces used in IKEv2 must be at least half the key size of the negotiated
   //pseudorandom function (refer to RFC 7296, section 2.10)
   if(nonceLen >= (prfKeyLen / 2))
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_INVALID_LENGTH;
   }
}


/**
 * @brief Create AH or ESP SA pair
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeCreateIpsecSaPair(IkeChildSaEntry *childSa)
{
   error_t error;
   IpsecSadEntry sadEntry;

   //Debug message
   TRACE_INFO("Creating IPsec SA pair...\r\n");
   TRACE_INFO("  Outbound SPI = 0x%08" PRIX32 "\r\n", LOAD32BE(childSa->remoteSpi));
   TRACE_INFO("  Inbound SPI = 0x%08" PRIX32 "\r\n", LOAD32BE(childSa->localSpi));

   //Set SAD entry parameters (outbound traffic)
   osMemset(&sadEntry, 0, sizeof(IpsecSadEntry));
   sadEntry.direction = IPSEC_DIR_OUTBOUND;
   sadEntry.mode = childSa->mode;
   sadEntry.protocol = childSa->protocol;
   sadEntry.selector = childSa->selector;
   sadEntry.spi = LOAD32BE(childSa->remoteSpi);
   sadEntry.authCipherAlgo = childSa->authCipherAlgo;
   sadEntry.authHashAlgo = childSa->authHashAlgo;
   sadEntry.authKeyLen = childSa->authKeyLen;
   sadEntry.icvLen = childSa->icvLen;
   sadEntry.esn = (childSa->esn == IKE_TRANSFORM_ID_ESN_YES) ? TRUE : FALSE;
   sadEntry.seqNum = 0;
   sadEntry.antiReplayEnabled = TRUE;

   //Set integrity protection key
   if(childSa->initiator)
   {
      osMemcpy(sadEntry.authKey, childSa->skai, childSa->authKeyLen);
   }
   else
   {
      osMemcpy(sadEntry.authKey, childSa->skar, childSa->authKeyLen);
   }

#if (ESP_SUPPORT == ENABLED)
   //Set encryption parameters
   sadEntry.cipherMode = childSa->cipherMode;
   sadEntry.cipherAlgo = childSa->cipherAlgo;
   sadEntry.encKeyLen = childSa->encKeyLen;
   sadEntry.saltLen = childSa->saltLen;
   sadEntry.ivLen = childSa->ivLen;

   //Set encryption key
   if(childSa->initiator)
   {
      osMemcpy(sadEntry.encKey, childSa->skei, childSa->encKeyLen +
         childSa->saltLen);
   }
   else
   {
      osMemcpy(sadEntry.encKey, childSa->sker, childSa->encKeyLen +
         childSa->saltLen);
   }

   //Check encryption mode
   if(childSa->protocol == IPSEC_PROTOCOL_ESP &&
      childSa->cipherMode != CIPHER_MODE_CBC)
   {
      //Copy initialization vector
      osMemcpy(sadEntry.iv, childSa->iv, childSa->ivLen);
   }
#endif

   //Update SAD entry (outbound traffic)
   error = ipsecSetSadEntry(netContext.ipsecContext, childSa->outboundSa,
      &sadEntry);

   //Check status code
   if(!error)
   {
      //Set SAD entry parameters (inbound traffic)
      osMemset(&sadEntry, 0, sizeof(IpsecSadEntry));
      sadEntry.direction = IPSEC_DIR_INBOUND;
      sadEntry.mode = childSa->mode;
      sadEntry.protocol = childSa->protocol;
      sadEntry.selector = childSa->selector;
      sadEntry.spi = LOAD32BE(childSa->localSpi);
      sadEntry.authCipherAlgo = childSa->authCipherAlgo;
      sadEntry.authHashAlgo = childSa->authHashAlgo;
      sadEntry.authKeyLen = childSa->authKeyLen;
      sadEntry.icvLen = childSa->icvLen;
      sadEntry.esn = (childSa->esn == IKE_TRANSFORM_ID_ESN_YES) ? TRUE : FALSE;
      sadEntry.seqNum = 0;
      sadEntry.antiReplayEnabled = TRUE;

      //Set integrity protection key
      if(childSa->initiator)
      {
         osMemcpy(sadEntry.authKey, childSa->skar, childSa->authKeyLen);
      }
      else
      {
         osMemcpy(sadEntry.authKey, childSa->skai, childSa->authKeyLen);
      }

#if (ESP_SUPPORT == ENABLED)
      //Set encryption parameters
      sadEntry.cipherMode = childSa->cipherMode;
      sadEntry.cipherAlgo = childSa->cipherAlgo;
      sadEntry.encKeyLen = childSa->encKeyLen;
      sadEntry.saltLen = childSa->saltLen;
      sadEntry.ivLen = childSa->ivLen;

      //Set encryption key
      if(childSa->initiator)
      {
         osMemcpy(sadEntry.encKey, childSa->sker, childSa->encKeyLen +
            childSa->saltLen);
      }
      else
      {
         osMemcpy(sadEntry.encKey, childSa->skei, childSa->encKeyLen +
            childSa->saltLen);
      }
#endif

      //Update SAD entry (inbound traffic)
      error = ipsecSetSadEntry(netContext.ipsecContext, childSa->inboundSa,
         &sadEntry);
   }

   //Return status code
   return error;
}


/**
 * @brief Test if the IKE SA is the only currently active with a given peer
 * @param[in] sa Pointer to the IKE SA
 * @return TRUE if this IKE SA is the only IKE SA currently active between the
 *   authenticated identities, else FALSE
 **/

bool_t ikeIsInitialContact(IkeSaEntry *sa)
{
   uint_t i;
   IkeContext *context;
   IkeSaEntry *entry;

   //Point to the IKE context
   context = sa->context;

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      entry = &context->sa[i];

      //Check the state of the IKE SA
      if(entry != sa && entry->state != IKE_SA_STATE_CLOSED)
      {
         //Check whether another IKE SA exists between the authenticated
         //identities
         if(ipCompAddr(&entry->remoteIpAddr, &sa->remoteIpAddr))
         {
            return FALSE;
         }
      }
   }

   //This IKE SA is the only IKE SA currently active between the authenticated
   //identities
   return TRUE;
}

#endif
