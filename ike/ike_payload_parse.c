/**
 * @file ike_payload_parse.c
 * @brief IKE payload parsing
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
#include "ike/ike_algorithms.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_eap.h"
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
 * @brief Parse IKE message payloads
 * @param[in] message Pointer to the IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @param[out] payloads IKE message payloads
 **/

void ikeParseIkeMessagePayloads(const uint8_t *message, size_t length,
   IkeMessagePayloads *payloads)
{
   //The Security Association payload, denoted SA, is used to negotiate
   //attributes of a Security Association (refer to RFC 7296, section 3.3)
   payloads->sa = (IkeSaPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_SA, 0);

   //The Key Exchange payload, denoted KE, is used to exchange Diffie-Hellman
   //public numbers as part of a Diffie-Hellman key exchange (refer to RFC 7296,
   //section 3.4)
   payloads->ke = (IkeKePayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_KE, 0);

   //The Identification payloads, denoted IDi and IDr, allow peers to assert an
   //identity to one another (refer to RFC 7296, section 3.5)
   payloads->idi = (IkeIdPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_IDI, 0);

   payloads->idr = (IkeIdPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_IDR, 0);

   //The Certificate payload, denoted CERT, provides a means to transport
   //certificates or other authentication-related information via IKE (refer
   //to RFC 7296, section 3.6)
   payloads->cert = (IkeCertPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_CERT, 0);

   //The Certificate Request payload, denoted CERTREQ, provides a means to
   //request preferred certificates via IKE (refer to RFC 7296, section 3.7)
   payloads->certReq = (IkeCertReqPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_CERTREQ, 0);

   //The Authentication payload, denoted AUTH, contains data used for
   //authentication purposes (refer to RFC 7296, section 3.8)
   payloads->auth = (IkeAuthPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_AUTH, 0);

   //The Nonce payload, denoted as Ni and Nr, contains random data used to
   //guarantee liveness during an exchange and protect against replay attacks
   //(Refer to RFC 7296, section 3.9)
   payloads->nonce = (IkeNoncePayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_NONCE, 0);

   //The Traffic Selector payload, denoted TSi and TSr, allows peers to identify
   //packet flows for processing by IPsec security services (refer to RFC 7296,
   //section 3.13)
   payloads->tsi = (IkeTsPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_TSI, 0);

   payloads->tsr = (IkeTsPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_TSR, 0);

   //The Configuration payload, denoted CP, is used to exchange configuration
   //information between IKE peers (refer to RFC 7296, section 3.15)
   payloads->config = (IkeConfigPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_CP, 0);

   //The Extensible Authentication Protocol payload, denoted EAP, allows IKE SAs
   //to be authenticated using EAP protocol (refer to RFC 7296, section 3.16)
   payloads->eap = (IkeEapPayload *) ikeGetPayload(message, length,
      IKE_PAYLOAD_TYPE_EAP, 0);

   //The USE_TRANSPORT_MODE notification may be included in a request
   //message that also includes an SA payload requesting a Child SA
   payloads->useTransportModeNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE, 0);

   //The REKEY_SA notification is included in a CREATE_CHILD_SA exchange if the
   //purpose of the exchange is to replace an existing ESP or AH SA
   payloads->rekeySaNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_REKEY_SA, 0);

#if (IKE_COOKIE_SUPPORT == ENABLED)
   //Check whether the message includes a COOKIE notification
   payloads->cookieNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_COOKIE, 0);
#endif

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
   //The INITIAL_CONTACT notification asserts that this IKE SA is the only IKE
   //SA currently active between the authenticated identities
   payloads->initialContactNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT, 0);
#endif

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   //The supported hash algorithms that can be used for the signature algorithms
   //are indicated with a Notify payload of type SIGNATURE_HASH_ALGORITHMS sent
   //inside the IKE_SA_INIT exchange (refer to RFC 7427, section 4)
   payloads->signHashAlgosNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS, 0);
#endif

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //The NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP payloads can
   //be used to detect if there is NAT between the hosts, and which end is
   //behind the NAT (refer to RFC 7296, section 2.23)
   payloads->natDetectSrcIpNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_SOURCE_IP, 0);

   payloads->natDetectDestIpNotify = ikeGetStatusNotifyPayload(message, length,
      IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_DESTINATION_IP, 0);
#endif

   //Check whether the message includes an error notification
   payloads->errorNotify = ikeGetErrorNotifyPayload(message, length);
}


/**
 * @brief Parse Security Association payload
 * @param[in] saPayload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ikeParseSaPayload(const IkeSaPayload *saPayload)
{
   error_t error;
   uint_t i;
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
   for(i = 1; length > 0; i++)
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

      //The first proposal in an SA payload must be 1, and subsequent proposals
      //must be one more than the previous proposal (refer to RFC 7296,
      //section 3.3.1)
      if(proposal->proposalNum != i)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //The Last Substruc field has a value of 0 if this was the last Proposal
      //substructure, and a value of 2 if there are more Proposal substructures
      if(n == length)
      {
         //Last Proposal substructure?
         if(proposal->lastSubstruc != IKE_LAST_SUBSTRUC_LAST)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }
      }
      else
      {
         //More Proposal substructures?
         if(proposal->lastSubstruc != IKE_LAST_SUBSTRUC_MORE_PROPOSALS)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }
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

   //Initialize status code
   error = NO_ERROR;

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

      //The Last Substruc field has a value of 0 if this was the last Transform
      //substructure, and a value of 3 if there are more Transform substructures
      //(refer to RFC 7296, section 3.3.2)
      if(i == proposal->numTransforms)
      {
         //Last Transform substructure?
         if(transform->lastSubstruc != IKE_LAST_SUBSTRUC_LAST)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }
      }
      else
      {
         //More Transform substructures?
         if(transform->lastSubstruc != IKE_LAST_SUBSTRUC_MORE_TRANSFORMS)
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
            break;
         }
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

   //Check status code
   if(!error)
   {
      //The Proposal Length field must match the total length of the transforms
      if(length != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
      }
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
 * @param[in] keContext Pointer to the key exchange context
 * @param[in] kePayload Pointer to the Key Exchange payload
 * @return Error code
 **/

error_t ikeParseKePayload(IkeKeContext *keContext,
   const IkeKePayload *kePayload)
{
   error_t error;
   size_t n;
   uint16_t groupNum;

   //Retrieve the length of the Key Exchange payload
   n = ntohs(kePayload->header.payloadLength);

   //Malformed Key Exchange payload?
   if(n < sizeof(IkeKePayload))
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the key exchange data
   n -= sizeof(IkeKePayload);

   //The Key Exchange Method identifies the Diffie-Hellman group in which the
   //Key Exchange Data was computed
   groupNum = ntohs(kePayload->keyExchangeMethod);

   //Make sure the key exchange method is acceptable
   if(groupNum != keContext->groupNum)
      return ERROR_INVALID_GROUP;

   //Parse peer's Diffie-Hellman public key
   error = ikeParsePublicKey(keContext, kePayload->keyExchangeData, n);

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
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the identification data
   n -= sizeof(IkeIdPayload);

   //Check the length of the identification data
   if(n == 0 || n > IKE_MAX_ID_LEN)
      return ERROR_INVALID_LENGTH;

   //Save identification type
   sa->peerId.type = (IkeIdType) idPayload->idType;

   //Save reserved field
   osMemcpy(sa->peerId.reserved, idPayload->reserved, 3);

   //Save identification data
   osMemcpy(sa->peerId.data, idPayload->idData, n);
   sa->peerId.length = n;

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

   //Malformed Certificate Request payload?
   if(n < sizeof(IkeCertReqPayload))
      return ERROR_INVALID_SYNTAX;

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
 * @brief Parse Authentication payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] authPayload Pointer to the Authentication payload
 * @param[in] certPayload Pointer to the first Certificate payload
 * @return Error code
 **/

error_t ikeParseAuthPayload(IkeSaEntry *sa, const IkeAuthPayload *authPayload,
   const IkeCertPayload *certPayload)
{
   size_t n;
   size_t authDataLen;
   size_t certDataLen;
   const uint8_t *certData;

   //Retrieve the length of the Authentication payload
   n = ntohs(authPayload->header.payloadLength);

   //Malformed Authentication payload?
   if(n < sizeof(IkeAuthPayload))
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the Authentication Data field
   authDataLen = n - sizeof(IkeAuthPayload);

   //Certificate authentication?
   if(authPayload->authMethod == IKE_AUTH_METHOD_RSA ||
      authPayload->authMethod == IKE_AUTH_METHOD_DSS ||
      authPayload->authMethod == IKE_AUTH_METHOD_ECDSA_P256_SHA256 ||
      authPayload->authMethod == IKE_AUTH_METHOD_ECDSA_P384_SHA384 ||
      authPayload->authMethod == IKE_AUTH_METHOD_ECDSA_P521_SHA512 ||
      authPayload->authMethod == IKE_AUTH_METHOD_DIGITAL_SIGN)
   {
      //The first CERT payload holds the public key used to validate the
      //sender's AUTH payload (refer to RFC 7296, section 3.6)
      if(certPayload == NULL)
         return ERROR_AUTHENTICATION_FAILED;

      //Retrieve the length of the Certificate payload
      n = ntohs(certPayload->header.payloadLength);

      //Malformed Certificate payload?
      if(n < sizeof(IkeCertPayload))
         return ERROR_INVALID_SYNTAX;

      //Point to the Certificate Data field
      certData = certPayload->certData;
      //Determine the length of the Certificate Data field
      certDataLen = n - sizeof(IkeCertPayload);
   }
   else
   {
      //The CERT payload is not used to validate the AUTH payload
      certData = NULL;
      certDataLen = 0;
   }

   //Verify the AUTH value
   return ikeVerifyAuth(sa, authPayload->authMethod, authPayload->authData,
      authDataLen, certData, certDataLen);
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
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the nonce
   n -= sizeof(IkeNoncePayload);

   //Nonces used in IKEv2 must be at least 128 bits in size (refer to RFC 7296,
   //section 2.10)
   if(n < IKE_MIN_NONCE_SIZE || n > IKE_MAX_NONCE_SIZE)
      return ERROR_INVALID_LENGTH;

   //Save the nonce
   osMemcpy(nonce, noncePayload->nonceData, n);
   *nonceLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse INVALID_KE_PAYLOAD notification
 * @param[in] keContext Pointer to the key exchange context
 * @param[in] notifyPayload Pointer to the Notify payload
 * @return Error code
 **/

error_t ikeParseInvalidKePayloadNotification(IkeKeContext *keContext,
   const IkeNotifyPayload *notifyPayload)
{
   size_t n;
   uint16_t groupNum;
   const uint8_t *data;

   //Retrieve the length of the notification data
   n = ntohs(notifyPayload->header.payloadLength) - sizeof(IkeNotifyPayload) -
      notifyPayload->spiSize;

   //There are two octets of data associated with this notification
   if(n != sizeof(uint16_t))
      return ERROR_INVALID_SYNTAX;

   //Point to the notification data
   data = notifyPayload->spi + notifyPayload->spiSize;

   //The Diffie-Hellman group number is encoded in big endian order (refer to
   //RFC 7296, section 1.3)
   groupNum = LOAD16BE(data);

   //Ensure the specified key exchange method is supported
   if(!ikeIsGroupSupported(groupNum))
      return ERROR_INVALID_GROUP;

   //Save the corrected group number
   keContext->groupNum = groupNum;

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
      return ERROR_INVALID_SYNTAX;

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
      return ERROR_INVALID_SYNTAX;

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
 * @brief Parse NAT_DETECTION_SOURCE_IP notification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseNatDetectSrcIpNotification(IkeSaEntry *sa,
   const uint8_t *message, size_t length)
{
#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   uint_t i;
   size_t n;
   bool_t match;
   const uint8_t *data;
   IkeContext *context;
   const IkeNotifyPayload *notifyPayload;
   Sha1Context sha1Context;
   uint8_t temp[SHA1_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize variable
   match = FALSE;

   //There MAY be multiple NAT_DETECTION_SOURCE_IP payloads in a message if the
   //sender does not know which of several network attachments will be used to
   //send the packet (refer to RFC 7296, section 2.23)
   for(i = 0; ; i++)
   {
      //Point to the NAT_DETECTION_SOURCE_IP notification
      notifyPayload = ikeGetStatusNotifyPayload(message, length,
         IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_SOURCE_IP, i);

      //NAT_DETECTION_SOURCE_IP notification not found?
      if(notifyPayload == NULL)
         break;

      //Retrieve the length of the notification data
      n = ntohs(notifyPayload->header.payloadLength) -
         sizeof(IkeNotifyPayload) - notifyPayload->spiSize;

      //Malformed notification?
      if(n != SHA1_DIGEST_SIZE)
         return ERROR_INVALID_SYNTAX;

      //The data associated with the NAT_DETECTION_SOURCE_IP notification is a
      //SHA-1 digest of the SPIs (in the order they appear in the header), IP
      //address, and port from which this packet was sent
      data = notifyPayload->spi + notifyPayload->spiSize;

      //Retrieve the length of the source IP address
      n = context->remoteIpAddr.length;
      //Convert the source port number to network byte order
      STORE16BE(context->remotePort, temp);

      //Compute the SHA-1 hash of the SPIs, source IP address, and port
      sha1Init(&sha1Context);
      sha1Update(&sha1Context, sa->initiatorSpi, IKE_SPI_SIZE);
      sha1Update(&sha1Context, sa->responderSpi, IKE_SPI_SIZE);
      sha1Update(&sha1Context, context->remoteIpAddr.addr, n);
      sha1Update(&sha1Context, temp, sizeof(uint16_t));
      sha1Final(&sha1Context, temp);

      //Compares the supplied value to the calculated SHA-1 hash
      if(osMemcmp(data, temp, SHA1_DIGEST_SIZE) == 0)
      {
         match = TRUE;
      }
   }

   //If none of the NAT_DETECTION_SOURCE_IP payload(s) received matches the
   //expected value of the source IP and port found from the IP header of the
   //packet containing the payload, it means that the system sending those
   //payloads is behind a NAT
   if(!match)
   {
      //A NAT has been detected in front of the remote security endpoint
      sa->remoteNat = TRUE;
   }

   //The IKE_SA_INIT message contains a NAT_DETECTION_SOURCE_IP notification
   sa->natDetectSrcIpReceived = TRUE;

   //Sucessful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support NAT traversal (refer
   //to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse NAT_DETECTION_DESTINATION_IP notification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] notifyPayload Pointer to the Notify payload
 * @return Error code
 **/

error_t ikeParseNatDetectDestIpNotification(IkeSaEntry *sa,
   const IkeNotifyPayload *notifyPayload)
{
#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   size_t n;
   const uint8_t *data;
   IkeContext *context;
   Sha1Context sha1Context;
   uint8_t temp[SHA1_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Retrieve the length of the notification data
   n = ntohs(notifyPayload->header.payloadLength) - sizeof(IkeNotifyPayload) -
      notifyPayload->spiSize;

   //Malformed notification?
   if(n != SHA1_DIGEST_SIZE)
      return ERROR_INVALID_SYNTAX;

   //The data associated with the NAT_DETECTION_DESTINATION_IP notification is
   //a SHA-1 digest of the SPIs (in the order they appear in the header), IP
   //address, and port to which this packet was sent
   data = notifyPayload->spi + notifyPayload->spiSize;

   //Retrieve the length of the recipient IP address
   n = context->localIpAddr.length;
   //Convert the recipient port number to network byte order
   STORE16BE(context->localPort, temp);

   //Compute the SHA-1 hash of the SPIs, recipient IP address, and port
   sha1Init(&sha1Context);
   sha1Update(&sha1Context, sa->initiatorSpi, IKE_SPI_SIZE);
   sha1Update(&sha1Context, sa->responderSpi, IKE_SPI_SIZE);
   sha1Update(&sha1Context, context->localIpAddr.addr, n);
   sha1Update(&sha1Context, temp, sizeof(uint16_t));
   sha1Final(&sha1Context, temp);

   //In the case of a mismatching NAT_DETECTION_DESTINATION_IP hash, it means
   //that the system receiving the NAT_DETECTION_DESTINATION_IP payload is
   //behind a NAT
   if(osMemcmp(data, temp, SHA1_DIGEST_SIZE) != 0)
   {
      //A NAT has been detected in front of the local security endpoint
      sa->localNat = TRUE;

      //The system should start sending keepalive packets (refer to RFC 7296,
      //section 2.23)
      sa->natKeepAliveTimestamp = osGetSystemTime();
   }

   //The IKE_SA_INIT message contains a NAT_DETECTION_DESTINATION_IP notification
   sa->natDetectDestIpReceived = TRUE;

   //Sucessful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support NAT traversal (refer
   //to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
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
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the list
   n -= sizeof(IkeDeletePayload);

   //Malformed SPI list?
   if(n != (deletePayload->spiSize * ntohs(deletePayload->numSpi)))
      return ERROR_INVALID_SYNTAX;

   //Check protocol identifier
   if(deletePayload->protocolId == IKE_PROTOCOL_ID_IKE)
   {
      //The SPI Size field must be zero for IKE
      if(deletePayload->spiSize != 0)
         return ERROR_INVALID_SYNTAX;

      //If a peer receives a request to close an IKE SA that it is currently
      //rekeying, it should reply as usual, and forget about its own rekeying
      //request (refer to RFC 7296, section 2.25.2)

      //If a peer receives a request to close an IKE SA that it is currently
      //trying to close, it should reply as usual, and forget about its own
      //close request
      if(!response)
      {
         sa->deleteReceived = TRUE;
      }
   }
   else if(deletePayload->protocolId == IKE_PROTOCOL_ID_AH ||
      deletePayload->protocolId == IKE_PROTOCOL_ID_ESP)
   {
      //The SPI Size field must be four for AH and ESP
      if(deletePayload->spiSize != IPSEC_SPI_SIZE)
         return ERROR_INVALID_SYNTAX;

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
               //If a peer receives a request to close a Child SA that it is
               //currently rekeying, it should reply as usual, with a Delete
               //payload (refer to RFC 7296, section 2.25.1)
               if(!response)
               {
                  childSa->deleteReceived = TRUE;
               }
            }
            else if(childSa->state == IKE_CHILD_SA_STATE_DELETE)
            {
               //If a peer receives a request to close a Child SA that it is
               //currently trying to close, it should reply without a Delete
               //payload
               if(response)
               {
                  ikeDeleteChildSaEntry(childSa);
               }
            }
            else
            {
               //If a peer receives a request to delete a Child SA when it is
               //currently rekeying the IKE SA, it should reply as usual, with
               //a Delete payload (refer to RFC 7296, section 2.25.2)
               if(!response)
               {
                  childSa->deleteReceived = TRUE;
               }
            }
         }
         else
         {
            //If a peer receives a request to close a Child SA that does not
            //exist, it should reply without a Delete payload (refer to
            //RFC 7296, section 2.25.1)
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
 * @brief Parse Traffic Selector payload
 * @param[in] tsPayload Pointer to the Traffic Selector payload
 * @param[in] index Index of the Traffic Selector substructure to parse
 * @param[out] tsEntry Traffic selector entry
 * @return Error code
 **/

error_t ikeParseTsPayload(const IkeTsPayload *tsPayload, uint_t index,
   IkeTsEntry *tsEntry)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeTs *ts;

   //Get the length of the TS payload
   length = ntohs(tsPayload->header.payloadLength);

   //Malformed TS payload?
   if(length < sizeof(IkeTsPayload))
      return ERROR_INVALID_SYNTAX;

   //The Traffic Selectors field must contains at least one Traffic Selector
   //substructure (refer to RFC 7296, section 3.13)
   if(tsPayload->numTs == 0)
      return ERROR_INVALID_SYNTAX;

   //Invalid index?
   if(index >= tsPayload->numTs)
      return ERROR_NOT_FOUND;

   //Point to the first byte of the Traffic Selectors field
   p = tsPayload->trafficSelectors;
   //Determine the length of the Traffic Selectors field
   length -= sizeof(IkeTsPayload);

   //Loop through the Traffic Selector substructures
   for(i = 0; i <= index; i++)
   {
      //Malformed substructure?
      if(length < sizeof(IkeTs))
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Point to the Traffic Selector substructure
      ts = (IkeTs *) p;

      //The Selector Length field indicates the length of the Traffic Selector
      //substructure including the header (refer to RFC 7296, section 3.13.1)
      n = ntohs(ts->selectorLength);

      //Check the length of the selector
      if(n < sizeof(IkeTs) || n > length)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Parse Traffic Selector substructure
      error = ikeParseTsEntry(ts, n, tsEntry);
      //Any error to report?
      if(error)
         break;

      //Jump to the next substructure
      p += n;
      length -= n;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse Traffic Selector substructure
 * @param[in] ts Pointer to the Traffic Selector substructure
 * @param[in] length Length of the Traffic Selector substructure, in bytes
 * @param[out] tsEntry Traffic selector entry
 * @return Error code
 **/

error_t ikeParseTsEntry(const IkeTs *ts, size_t length, IkeTsEntry *tsEntry)
{
   error_t error;
   size_t n;

   //Malformed substructure?
   if(length < sizeof(IkeTs))
      return ERROR_INVALID_SYNTAX;

   //Initialize status code
   error = NO_ERROR;

   //The IP protocol ID value specifies the IP protocol ID (such as UDP, TCP,
   //and ICMP). A value of zero means that the protocol ID is not relevant to
   //this Traffic Selector
   tsEntry->ipProtocolId = ts->ipProtocolId;

   //The Start Port value specifies the smallest port number allowed by this
   //Traffic Selector
   tsEntry->startPort = ntohs(ts->startPort);

   //The End Port value specifies the smallest port number allowed by this
   //Traffic Selector
   tsEntry->endPort = ntohs(ts->endPort);

   //The length of the Starting Address and Ending Address fields depends on
   //the TS Type field
   length -= sizeof(IkeTs);

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV4_ADDR_RANGE)
   {
      //A range of IPv4 addresses is represented by two four-octet values
      n = sizeof(Ipv4Addr);

      //Valid length?
      if(length == (2 * n))
      {
         //The Starting Address field specifies the smallest address included
         //in this Traffic Selector
         tsEntry->startAddr.length = n;
         ipv4CopyAddr(&tsEntry->startAddr.ipv4Addr, ts->startAddr);

         //The Ending Address field specifies the smallest address included in
         //this Traffic Selector
         tsEntry->endAddr.length = n;
         ipv4CopyAddr(&tsEntry->endAddr.ipv4Addr, ts->startAddr + n);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_ADDRESS;
      }
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV6_ADDR_RANGE)
   {
      //A range of IPv6 addresses is represented by two sixteen-octet values
      n = sizeof(Ipv6Addr);

      //Valid length?
      if(length == (2 * n))
      {
         //The Starting Address field specifies the smallest address included
         //in this Traffic Selector
         tsEntry->startAddr.length = n;
         ipv6CopyAddr(&tsEntry->startAddr.ipv6Addr, ts->startAddr);

         //The Ending Address field specifies the smallest address included in
         //this Traffic Selector
         tsEntry->endAddr.length = n;
         ipv6CopyAddr(&tsEntry->endAddr.ipv6Addr, ts->startAddr + n);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_ADDRESS;
      }
   }
   else
#endif
   //Unknown Traffic Selector type?
   {
      //Report an error
      error = ERROR_INVALID_ADDRESS;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse Configuration payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] configPayload Pointer to the Configuration payload
 * @return Error code
 **/

error_t ikeParseConfigPayload(IkeSaEntry *sa,
   const IkeConfigPayload *configPayload)
{
   //Minimal implementations are not required to support requesting temporary
   //IP addresses (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
}


/**
 * @brief Parse EAP payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] eapPayload Pointer to the EAP payload
 * @return Error code
 **/

error_t ikeParseEapPayload(IkeSaEntry *sa, const IkeEapPayload *eapPayload)
{
#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Retrieve the length of the EAP payload
   n = ntohs(eapPayload->header.payloadLength);

   //Malformed payload?
   if(n < sizeof(IkeEapPayload))
      return ERROR_INVALID_SYNTAX;

   //Determine the length of the EAP message
   n -= sizeof(IkeEapPayload);

   //Increment the number of EAP request received
   sa->eapRequestCount++;

   //Process EAP message
   error = ikeProcessEapPacket(sa, (IkeEapPacket *) eapPayload->eapMessage, n);

   //Check status code
   if(!error)
   {
      //The initiator of an IKE SA using EAP needs to be capable of extending
      //the initial protocol exchange to at least ten IKE_AUTH exchanges
      if(sa->eapState != IKE_EAP_STATE_SUCCESS &&
         sa->eapRequestCount >= IKE_MAX_EAP_EXCHANGES)
      {
         error = ERROR_AUTHENTICATION_FAILED;
      }
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support EAP-based
   //authentication (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
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
   uint_t i;
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;

   //Check the length of the IKE message
   if(length >= sizeof(IkeHeader))
   {
      //Point to the IKE header
      ikeHeader = (IkeHeader *) message;

      //The Next Payload field indicates the type of payload that immediately
      //follows the header
      nextPayload = ikeHeader->nextPayload;

      //Initialize occurrence index
      i = 0;

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

         //The Payload Length field indicates the length in octets of the
         //current payload, including the generic payload header
         n = ntohs(payload->payloadLength);

         //Check the length of the IKE payload
         if(n < sizeof(IkePayloadHeader) || n > length)
            return NULL;

         //Check IKE payload type
         if(nextPayload == type)
         {
            //Matching occurrence found?
            if(i++ == index)
            {
               return payload;
            }
         }

         //The Next Payload field indicates the payload type of the next
         //payload in the message
         nextPayload = payload->nextPayload;

         //Jump to the next IKE payload
         p += n;
         length -= n;
      }
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

   //Check the length of the IKE message
   if(length >= sizeof(IkeHeader))
   {
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

         //The Payload Length field indicates the length in octets of the
         //current payload, including the generic payload header
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

            //Types in the range 0-16383 are intended for reporting errors
            //(refer to RFC 7296, section 3.10.1)
            if(ntohs(notifyPayload->notifyMsgType) < 16384)
            {
               return notifyPayload;
            }
         }

         //The Next Payload field indicates the payload type of the next
         //payload in the message
         nextPayload = payload->nextPayload;

         //Jump to the next IKE payload
         p += n;
         length -= n;
      }
   }

   //The specified payload type was not found
   return NULL;
}


/**
 * @brief Search an IKE message for a given status Notify payload
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @param[in] type Notify message type
 * @param[in] index Notification occurrence index
 * @return Pointer to the error Notify payload, if any
 **/

const IkeNotifyPayload *ikeGetStatusNotifyPayload(const uint8_t *message,
   size_t length, uint16_t type, uint_t index)
{
   uint_t i;
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;
   const IkeNotifyPayload *notifyPayload;

   //Check the length of the IKE message
   if(length >= sizeof(IkeHeader))
   {
      //Point to the IKE header
      ikeHeader = (IkeHeader *) message;

      //The Next Payload field indicates the type of payload that immediately
      //follows the header
      nextPayload = ikeHeader->nextPayload;

      //Initialize occurrence index
      i = 0;

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

         //The Payload Length field indicates the length in octets of the
         //current payload, including the generic payload header
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
               //Matching occurrence found?
               if(i++ == index)
               {
                  return notifyPayload;
               }
            }
         }

         //The Next Payload field indicates the payload type of the next
         //payload in the message
         nextPayload = payload->nextPayload;

         //Jump to the next IKE payload
         p += n;
         length -= n;
      }
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
   error_t error;
   size_t n;
   uint8_t nextPayload;
   const uint8_t *p;
   const IkeHeader *ikeHeader;
   const IkePayloadHeader *payload;

   //Malformed IKE message?
   if(length < sizeof(IkeHeader))
      return ERROR_INVALID_SYNTAX;

   //Initialize status code
   error = NO_ERROR;

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
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST)
   {
      //Malformed IKE message?
      if(length < sizeof(IkePayloadHeader))
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) p;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
         break;
      }

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
            error = ERROR_UNSUPPORTED_OPTION;
            break;
         }
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      p += n;
      length -= n;
   }

   //Check status code
   if(!error)
   {
      //The last payload of the chain must end exactly at the end of the IKE
      //message
      if(length != 0)
      {
         //Report an error
         error = ERROR_INVALID_SYNTAX;
      }
   }

   //Return status code
   return error;
}

#endif
