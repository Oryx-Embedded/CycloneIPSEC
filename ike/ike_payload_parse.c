/**
 * @file ike_payload_parse.c
 * @brief IKE payload parsing
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
#include "ike/ike_algorithms.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_sign_misc.h"
#include "ike/ike_misc.h"
#include "ah/ah_algorithms.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Parse Security Association payload
 * @param[in] saPayload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ikeParseSaPayload(const IkeSaPayload *saPayload)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;

   //Retrieve the length of the Security Association payload
   length = ntohs(saPayload->header.payloadLength);

   //Malformed Security Association payload?
   if(length < sizeof(IkeSaPayload))
      return ERROR_INVALID_SYNTAX;

   //Point to the first byte of the Proposals field
   p = saPayload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //The SA payload must contain at least one Proposal substructure
   if(length == 0)
      return ERROR_INVALID_SYNTAX;

   //Loop through the Proposal substructures
   while(length > 0)
   {
      //Malformed payload?
      if(length < sizeof(IkeProposal))
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the Proposal substructure
      proposal = (IkeProposal *) p;

      //The Proposal Length field indicates the length of this proposal,
      //including all transforms and attributes that follow
      n = ntohs(proposal->proposalLength);

      //Check the length of the proposal
      if(n < sizeof(IkeProposal) || n > length)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Parse Proposal substructure
      error = ikeParseProposal(proposal, n);
      //Any error to report?
      if(error)
         break;

      //Jump to the next proposal
      p += n;
      length -= n;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse Proposal substructure
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] length Length of the Proposal substructure, in bytes
 * @return Error code
 **/

error_t ikeParseProposal(const IkeProposal *proposal, size_t length)
{
   error_t error;
   uint_t i;
   size_t n;
   const uint8_t *p;
   const IkeTransform *transform;

   //Check the length of the Proposal substructure
   if(length < sizeof(IkeProposal))
      return ERROR_INVALID_SYNTAX;

   //Malformed substructure?
   if(length < (sizeof(IkeProposal) + proposal->spiSize))
      return ERROR_INVALID_SYNTAX;

   //Get the length of the Proposal substructure
   length = length - sizeof(IkeProposal) - proposal->spiSize;
   //Point to the first Transform substructure
   p = (uint8_t *) proposal + sizeof(IkeProposal) + proposal->spiSize;

   //The Transforms field must contains at least one Transform substructure
   if(proposal->numTransforms == 0)
      return ERROR_INVALID_SYNTAX;

   //Loop through the Transform substructures
   for(i = 1; i <= proposal->numTransforms; i++)
   {
      //Malformed substructure?
      if(length < sizeof(IkeTransform))
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the Transform substructure
      transform = (IkeTransform *) p;

      //The Transform Length field indicates the length of the Transform
      //substructure including header and attributes
      n = ntohs(transform->transformLength);

      //Check the length of the transform
      if(n < sizeof(IkeTransform) || n > length)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Parse Transform substructure
      error = ikeParseTransform(transform, n);
      //Any error to report?
      if(error)
         break;

      //Jump to the next transform
      p += n;
      length -= n;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse Transform substructure
 * @param[in] transform Pointer to the Transform substructure
 * @param[in] length Length of the Transform substructure, in bytes
 * @return Error code
 **/

error_t ikeParseTransform(const IkeTransform *transform, size_t length)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const IkeTransformAttr *attr;

   //Check the length of the Transform substructure
   if(length < sizeof(IkeTransform))
      return ERROR_INVALID_SYNTAX;

   //Point to the first byte of the Transform Attributes field
   p = transform->transformAttr;
   //Get the length of the Transform Attributes field
   length -= sizeof(IkeTransform);

   //The Transform Attributes field is optional
   if(length > 0)
   {
      //The Transform Attributes field contains one or more attributes
      while(length > 0)
      {
         //Malformed attribute?
         if(length < sizeof(IkeTransformAttr))
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the transform attribute
         attr = (IkeTransformAttr *) p;

         //Parse transform attribute
         error = ikeParseTransformAttr(attr, length, &n);
         //Any error to report?
         if(error)
            break;

         //Jump to the next attribute
         p += n;
         length -= n;
      }
   }
   else
   {
      //The Transform Attributes field is not present
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse transform attribute
 * @param[in] attr Pointer to the transform attribute
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of characters that have been consumed
 * @return Error code
 **/

error_t ikeParseTransformAttr(const IkeTransformAttr *attr, size_t length,
   size_t *consumed)
{
   size_t n;

   //Malformed attribute?
   if(length < sizeof(IkeTransformAttr))
      return ERROR_INVALID_SYNTAX;

   //Check the format of the attribute
   if((ntohs(attr->type) & IKE_ATTR_FORMAT_TV) != 0)
   {
      //If the AF bit is set, then the attribute value has a fixed length
      n = 0;
   }
   else
   {
      //If the AF bit is not set, then this attribute has a variable length
      //defined by the Attribute Length field
      n = ntohs(attr->length);

      //Malformed attribute?
      if(length < (sizeof(IkeTransformAttr) + n))
         return ERROR_INVALID_SYNTAX;
   }

   //Total number of bytes that have been consumed
   *consumed = sizeof(IkeTransformAttr) + n;

   //Parsing was successful
   return NO_ERROR;
}


/**
 * @brief Parse Key Exchange payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] kePayload Pointer to the Key Exchange payload
 * @return Error code
 **/

error_t ikeParseKePayload(IkeSaEntry *sa, const IkeKePayload *kePayload)
{
   error_t error;
   size_t n;
   uint16_t dhGroupNum;

   //Retrieve the length of the Key Exchange payload
   n = ntohs(kePayload->header.payloadLength);

   //Malformed Key Exchange payload?
   if(n < sizeof(IkeKePayload))
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the key exchange data
   n -= sizeof(IkeKePayload);

   //The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
   //which the Key Exchange Data was computed
   dhGroupNum = ntohs(kePayload->dhGroupNum);

   //Make sure the Diffie-Hellman group is acceptable
   if(dhGroupNum != sa->dhGroupNum)
      return ERROR_INVALID_GROUP;

   //Parse peer's Diffie-Hellman public key
   error = ikeParseDhPublicKey(sa, kePayload->keyExchangeData, n);

   //Return status code
   return error;
}


/**
 * @brief Parse Identification payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] idPayload Pointer to the Identification payload
 * @return Error code
 **/

error_t ikeParseIdPayload(IkeSaEntry *sa, const IkeIdPayload *idPayload)
{
   size_t n;

   //Retrieve the length of the Identification payload
   n = ntohs(idPayload->header.payloadLength);

   //Malformed Identification payload?
   if(n < sizeof(IkeIdPayload))
      return ERROR_INVALID_MESSAGE;

   //Determine the length of the identification data
   n -= sizeof(IkeIdPayload);

   //Check the length of the identification data
   if(n == 0 || n > IKE_MAX_ID_LEN)
      return ERROR_INVALID_LENGTH;

   //Save identification data
   sa->peerIdType = (IkeIdType) idPayload->idType;
   osMemcpy(sa->peerId, idPayload->idData, n);
   sa->peerIdLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Certificate Request payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] certReqPayload Pointer to the Certificate Request payload
 * @return Error code
 **/

error_t ikeParseCertReqPayload(IkeSaEntry *sa,
   const IkeCertReqPayload *certReqPayload)
{
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   size_t n;

   //Retrieve the length of the Identification payload
   n = ntohs(certReqPayload->header.payloadLength);

   //Malformed Identification payload?
   if(n < sizeof(IkeCertReqPayload))
      return ERROR_INVALID_MESSAGE;

   //Determine the length of the Certification Authority field
   n -= sizeof(IkeCertReqPayload);

   //Check the length of the Certification Authority field
   if((n % IKE_SHA1_DIGEST_SIZE) != 0)
      return ERROR_INVALID_LENGTH;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Nonce payload
 * @param[in] noncePayload Pointer to the Nonce payload
 * @param[out] nonce Pointer to the buffer where to store the nonce
 * @param[out] nonceLen Length of the nonce, in bytes
 * @return Error code
 **/

error_t ikeParseNoncePayload(const IkeNoncePayload *noncePayload,
   uint8_t *nonce, size_t *nonceLen)
{
   size_t n;

   //Retrieve the length of the Nonce payload
   n = ntohs(noncePayload->header.payloadLength);

   //Malformed payload?
   if(n < sizeof(IkeNoncePayload))
      return ERROR_INVALID_MESSAGE;

   //Determine the length of the nonce
   n -= sizeof(IkeNoncePayload);

   //Nonces used in IKEv2 must be at least 128 bits in size (refer to
   //RFC 7296, section 2.10)
   if(n < IKE_MIN_NONCE_SIZE || n > IKE_MAX_NONCE_SIZE)
      return ERROR_INVALID_LENGTH;

   //Save the nonce
   osMemcpy(nonce, noncePayload->nonceData, n);
   *nonceLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse Delete payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] deletePayload Pointer to the Delete payload
 * @param[in] response TRUE if the received INFORMATIONAL message is a response
 * @return Error code
 **/

error_t ikeParseDeletePayload(IkeSaEntry *sa,
   const IkeDeletePayload *deletePayload, bool_t response)
{
   uint_t i;
   size_t n;
   const uint8_t *spi;
   IkeChildSaEntry *childSa;

   //Retrieve the length of the Delete payload
   n = ntohs(deletePayload->header.payloadLength);

   //Malformed payload?
   if(n < sizeof(IkeDeletePayload))
      return ERROR_INVALID_MESSAGE;

   //Determine the length of the list
   n -= sizeof(IkeDeletePayload);

   //Malformed SPI list?
   if(n != (deletePayload->spiSize * ntohs(deletePayload->numSpi)))
      return ERROR_INVALID_MESSAGE;

   //Check protocol identifier
   if(deletePayload->protocolId == IKE_PROTOCOL_ID_IKE)
   {
      //The SPI Size field must be zero for IKE
      if(deletePayload->spiSize != 0)
         return ERROR_INVALID_MESSAGE;

      //If a peer receives a request to close an IKE SA that it is currently
      //rekeying, it should reply as usual, and forget about its own rekeying
      //request (refer to RFC 7296, section 2.25.2)

      //If a peer receives a request to close an IKE SA that it is currently
      //trying to close, it should reply as usual, and forget about its own
      //close request
      if(!response)
         sa->deleteReceived = TRUE;
   }
   else if(deletePayload->protocolId == IKE_PROTOCOL_ID_AH ||
      deletePayload->protocolId == IKE_PROTOCOL_ID_ESP)
   {
      //The SPI Size field must be four for AH and ESP
      if(deletePayload->spiSize != 4)
         return ERROR_INVALID_MESSAGE;

      //The Delete payload list the SPIs to be deleted
      for(i = 0; i < ntohs(deletePayload->numSpi); i++)
      {
         //Point to the current SPI
         spi = deletePayload->spi + (i * deletePayload->spiSize);

         //Perform Child SA lookup
         childSa = ikeFindChildSaEntry(sa, deletePayload->protocolId, spi);

         //Child SA found?
         if(childSa != NULL)
         {
            //Check the state of the Child SA
            if(childSa->state == IKE_CHILD_SA_STATE_REKEY)
            {
               //If a peer receives a request to close a Child SA that it is currently
               //rekeying, it should reply as usual, with a Delete payload (refer to
               //RFC 7296, section 2.25.1)
               if(!response)
                  childSa->deleteReceived = TRUE;
            }
            else if(childSa->state == IKE_CHILD_SA_STATE_DELETE)
            {
               //If a peer receives a request to close a Child SA that it is currently
               //trying to close, it should reply without a Delete payload
               if(response)
                  ikeDeleteChildSaEntry(childSa);
            }
            else
            {
               //If a peer receives a request to delete a Child SA when it is currently
               //rekeying the IKE SA, it should reply as usual, with a Delete payload
               //(refer to RFC 7296, section 2.25.2)
               if(!response)
                  childSa->deleteReceived = TRUE;
            }
         }
         else
         {
            //If a peer receives a request to close a Child SA that does not exist,
            //it should reply without a Delete payload (refer to RFC 7296,
            //section 2.25.1)
         }
      }
   }
   else
   {
      //Unknown protocol identifier
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse INVALID_KE_PAYLOAD notification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] notifyPayload Pointer to the Notify payload
 * @return Error code
 **/

error_t ikeParseInvalidKeyPayloadNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload)
{
   size_t n;
   uint16_t dhGroupNum;
   const uint8_t *data;

   //Retrieve the length of the notification data
   n = ntohs(notifyPayload->header.payloadLength) - sizeof(IkeNotifyPayload) -
      notifyPayload->spiSize;

   //There are two octets of data associated with this notification
   if(n != sizeof(uint16_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the notification data
   data = notifyPayload->spi + notifyPayload->spiSize;

   //The Diffie-Hellman group number is encoded in big endian order (refer to
   //RFC 7296, section 1.3)
   dhGroupNum = LOAD16BE(data);

   //Ensure the specified group number is supported
   if(!ikeIsDhGroupSupported(dhGroupNum))
      return ERROR_INVALID_GROUP;

   //Save the corrected Diffie-Hellman group number
   sa->dhGroupNum = dhGroupNum;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse COOKIE notification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] notifyPayload Pointer to the Notify payload
 * @return Error code
 **/

error_t ikeParseCookieNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload)
{
   size_t n;
   const uint8_t *data;

   //Retrieve the length of the notification data
   n = ntohs(notifyPayload->header.payloadLength) - sizeof(IkeNotifyPayload) -
      notifyPayload->spiSize;

   //The data associated with this notification must be between 1 and 64
   //octets in length (refer to RFC 7296, section 2.6)
   if(n < IKE_MIN_COOKIE_SIZE || n > IKE_MAX_COOKIE_SIZE)
      return ERROR_INVALID_MESSAGE;

   //Point to the notification data
   data = notifyPayload->spi + notifyPayload->spiSize;

   //Save cookie
   osMemcpy(sa->cookie, data, n);
   sa->cookieLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SIGNATURE_HASH_ALGORITHMS notification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] notifyPayload Pointer to the Notify payload
 * @return Error code
 **/

error_t ikeParseSignHashAlgosNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload)
{
#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   size_t i;
   size_t n;
   uint16_t hashAlgoId;
   const uint8_t *data;

   //Retrieve the length of the notification data
   n = ntohs(notifyPayload->header.payloadLength) - sizeof(IkeNotifyPayload) -
      notifyPayload->spiSize;

   //Malformed notification?
   if((n % sizeof(uint16_t)) != 0)
      return ERROR_INVALID_MESSAGE;

   //Point to the notification data
   data = notifyPayload->spi + notifyPayload->spiSize;

   //Clear the list of hash algorithms supported by the peer
   sa->signHashAlgos = 0;

   //The Notification Data field contains the list of 16-bit hash algorithm
   //identifiers
   for(i = 0; i < n; i += sizeof(uint16_t))
   {
      //Get the current 16-bit hash algorithm identifier
      hashAlgoId = LOAD16BE(data + i);

      //Check whether the hash algorithm is supported
      if(ikeIsHashAlgoSupported(hashAlgoId))
      {
         sa->signHashAlgos |= (1U << hashAlgoId);
      }
   }

   //Successful processing
   return NO_ERROR;
#else
   //The SIGNATURE_HASH_ALGORITHMS notification is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse Traffic Selector substructure
 * @param[in] p Pointer to the input data to parse
 * @param[in] length Number of bytes available in the input data
 * @param[out] tsParams Traffic selector parameters
 * @return Error code
 **/

error_t ikeParseTs(const uint8_t *p, size_t length, IkeTsParams *tsParams)
{
   size_t n;
   const IkeTs *ts;

   //Malformed substructure?
   if(length < sizeof(IkeTs))
      return ERROR_INVALID_MESSAGE;

   //Point to the Traffic Selector substructure
   ts = (IkeTs *) p;

   //The Selector Length field indicates the length of the Traffic Selector
   //substructure including the header
   n = ntohs(ts->selectorLength);

   //Check the length of the selector
   if(n < sizeof(IkeTs) || n > length)
      return ERROR_INVALID_MESSAGE;

   //The IP protocol ID value specifies the IP protocol ID (such as UDP, TCP,
   //and ICMP). A value of zero means that the protocol ID is not relevant to
   //this Traffic Selector
   tsParams->ipProtocolId = ts->ipProtocolId;

   //The Start Port value specifies the smallest port number allowed by this
   //Traffic Selector
   tsParams->startPort = ntohs(ts->startPort);

   //The End Port value specifies the smallest port number allowed by this
   //Traffic Selector
   tsParams->endPort = ntohs(ts->endPort);

   //The length of the Starting Address and Ending Address fields depends on
   //the TS Type field
   n -= sizeof(IkeTs);

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV4_ADDR_RANGE)
   {
      //A range of IPv4 addresses is represented by two four-octet values
      if(n == (2 * sizeof(Ipv4Addr)))
      {
         //The Starting Address field specifies the smallest address included
         //in this Traffic Selector
         tsParams->startAddr.length = sizeof(Ipv4Addr);
         ipv4CopyAddr(&tsParams->startAddr.ipv4Addr, ts->startAddr);

         //The Ending Address field specifies the smallest address included in
         //this Traffic Selector
         tsParams->endAddr.length = sizeof(Ipv4Addr);
         ipv4CopyAddr(&tsParams->endAddr.ipv4Addr, ts->startAddr + sizeof(Ipv4Addr));
      }
      else
      {
         //Report an error
         return ERROR_INVALID_ADDRESS;
      }
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV6_ADDR_RANGE && n == (2 * sizeof(Ipv6Addr)))
   {
      //A range of IPv6 addresses is represented by two sixteen-octet values
      if(n == (2 * sizeof(Ipv6Addr)))
      {
         //The Starting Address field specifies the smallest address included
         //in this Traffic Selector
         tsParams->startAddr.length = sizeof(Ipv4Addr);
         ipv6CopyAddr(&tsParams->startAddr.ipv6Addr, ts->startAddr);

         //The Ending Address field specifies the smallest address included in
         //this Traffic Selector
         tsParams->endAddr.length = sizeof(Ipv4Addr);
         ipv6CopyAddr(&tsParams->endAddr.ipv6Addr, ts->startAddr + sizeof(Ipv6Addr));
      }
      else
      {
         //Report an error
         return ERROR_INVALID_ADDRESS;
      }
   }
   else
#endif
   //Unknown Traffic Selector type?
   {
      //Report an error
      return ERROR_INVALID_ADDRESS;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search an IKE message for a given payload type
 * @param[in] message Pointer to the IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @param[in] type Payload type
 * @param[in] index Payload occurrence index
 * @return If the specified payload type is found, a pointer to the payload
 *   header is returned. Otherwise NULL pointer is returned
 **/

const IkePayloadHeader *ikeGetPayload(const uint8_t *message, size_t length,
   uint8_t type, uint_t index)
{
   uint_t k;
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;

   //The Next Payload field indicates the type of payload that immediately
   //follows the header
   nextPayload = ikeHeader->nextPayload;

   //Initialize occurrence index
   k = 0;

   //Point to the IKE payloads
   p = message + sizeof(IkeHeader);
   //Get the length of the IKE payloads, in bytes
   length -= sizeof(IkeHeader);

   //Following the header are one or more IKE payloads each identified by
   //a Next Payload field in the preceding payload
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST &&
      length >= sizeof(IkePayloadHeader))
   {
      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) p;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
         return NULL;

      //Check IKE payload type
      if(nextPayload == type)
      {
         //Matching occurrence found?
         if(k++ == index)
         {
            return payload;
         }
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      p += n;
      length -= n;
   }

   //The specified payload type was not found
   return NULL;
}


/**
 * @brief Search an IKE message for an error Notify payload
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Pointer to the error Notify payload, if any
 **/

const IkeNotifyPayload *ikeGetErrorNotifyPayload(const uint8_t *message,
   size_t length)
{
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;
   const IkeNotifyPayload *notifyPayload;

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;

   //The Next Payload field indicates the type of payload that immediately
   //follows the header
   nextPayload = ikeHeader->nextPayload;

   //Point to the IKE payloads
   p = message + sizeof(IkeHeader);
   //Get the length of the IKE payloads, in bytes
   length -= sizeof(IkeHeader);

   //Following the header are one or more IKE payloads each identified by
   //a Next Payload field in the preceding payload
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST &&
      length >= sizeof(IkePayloadHeader))
   {
      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) p;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
         return NULL;

      //Notify payload?
      if(nextPayload == IKE_PAYLOAD_TYPE_N)
      {
         //Point to the Notify payload
         notifyPayload = (IkeNotifyPayload *) p;

         //Malformed Notify payload?
         if(n < sizeof(IkeNotifyPayload))
            return NULL;

         //Check the length of the SPI
         if(n < (sizeof(IkeNotifyPayload) + notifyPayload->spiSize))
            return NULL;

         //Types in the range 0-16383 are intended for reporting errors (refer
         //to RFC 7296, section 3.10.1)
         if(ntohs(notifyPayload->notifyMsgType) < 16384)
         {
            return notifyPayload;
         }
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      p += n;
      length -= n;
   }

   //The specified payload type was not found
   return NULL;
}


/**
 * @brief Search an IKE message for a given status Notify payload
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @param[in] type Notify message type
 * @return Pointer to the error Notify payload, if any
 **/

const IkeNotifyPayload *ikeGetStatusNotifyPayload(const uint8_t *message,
   size_t length, uint16_t type)
{
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;
   const IkeNotifyPayload *notifyPayload;

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;

   //The Next Payload field indicates the type of payload that immediately
   //follows the header
   nextPayload = ikeHeader->nextPayload;

   //Point to the IKE payloads
   p = message + sizeof(IkeHeader);
   //Get the length of the IKE payloads, in bytes
   length -= sizeof(IkeHeader);

   //Following the header are one or more IKE payloads each identified by
   //a Next Payload field in the preceding payload
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST &&
      length >= sizeof(IkePayloadHeader))
   {
      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) p;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
         return NULL;

      //Notify payload?
      if(nextPayload == IKE_PAYLOAD_TYPE_N)
      {
         //Point to the Notify payload
         notifyPayload = (IkeNotifyPayload *) p;

         //Malformed Notify payload?
         if(n < sizeof(IkeNotifyPayload))
            return NULL;

         //Check the length of the SPI
         if(n < (sizeof(IkeNotifyPayload) + notifyPayload->spiSize))
            return NULL;

         //Check the type of the notification message
         if(ntohs(notifyPayload->notifyMsgType) == type)
         {
            return notifyPayload;
         }
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      p += n;
      length -= n;
   }

   //The specified payload type was not found
   return NULL;
}


/**
 * @brief Check whether the message contains an unsupported critical payload
 * @param[in] message Pointer to the IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @param[out] unsupportedCriticalPayload Type of the unsupported critical
 *   payload, if any
 * @return Error code
 **/

error_t ikeCheckCriticalPayloads(const uint8_t *message, size_t length,
   uint8_t *unsupportedCriticalPayload)
{
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;

   //Check the length of the IKE message
   if(length < ntohl(ikeHeader->length))
      return ERROR_INVALID_MESSAGE;

   //The Next Payload field indicates the type of payload that immediately
   //follows the header
   nextPayload = ikeHeader->nextPayload;

   //Point to the IKE payloads
   p = message + sizeof(IkeHeader);
   //Get the length of the IKE payloads, in bytes
   length -= sizeof(IkeHeader);

   //Following the header are one or more IKE payloads each identified by
   //a Next Payload field in the preceding payload
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST)
   {
      //Malformed IKE message?
      if(length < sizeof(IkePayloadHeader))
         return ERROR_INVALID_MESSAGE;

      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) p;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
         return ERROR_INVALID_MESSAGE;

      //Check whether the critical flag is set
      if(payload->critical)
      {
         //Unrecognized payload type?
         if(nextPayload < IKE_PAYLOAD_TYPE_SA ||
            nextPayload > IKE_PAYLOAD_TYPE_EAP)
         {
            //Return the type of the unsupported critical payload
            if(unsupportedCriticalPayload != NULL)
            {
               *unsupportedCriticalPayload = nextPayload;
            }

            //The message must be rejected
            return ERROR_UNSUPPORTED_OPTION;
         }
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      p += n;
      length -= n;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
