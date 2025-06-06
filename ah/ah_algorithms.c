/**
 * @file ah_algorithms.c
 * @brief AH algorithm negotiation
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
#define TRACE_LEVEL AH_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_misc.h"
#include "ah/ah.h"
#include "ah/ah_algorithms.h"
#include "ike/ike_algorithms.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check IPsec library configuration
#if (AH_SUPPORT == ENABLED)


/**
 * @brief List of supported integrity algorithms
 **/

static const uint16_t ahSupportedAuthAlgos[] =
{
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA256_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128,
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA384_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192,
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA512_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256,
#endif
#if (AH_CMAC_SUPPORT == ENABLED && AH_AES_128_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_AES_CMAC_96,
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA1_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96,
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_MD5_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96,
#endif
};


/**
 * @brief List of supported ESN transforms
 **/

static const uint16_t ahSupportedEsnTranforms[] =
{
#if (AH_ESN_SUPPORT == ENABLED)
   IKE_TRANSFORM_ID_ESN_YES,
#endif
   IKE_TRANSFORM_ID_ESN_NO
};


/**
 * @brief Select the relevant MAC algorithm
 * @param[in] childSa Pointer to the Child SA
 * @param[in] authAlgoId Authentication algorithm identifier
 * @return Error code
 **/

error_t ahSelectAuthAlgo(IkeChildSaEntry *childSa, uint16_t authAlgoId)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (AH_CMAC_SUPPORT == ENABLED && AH_AES_128_SUPPORT == ENABLED)
   //AES-CMAC-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_CMAC_96)
   {
      childSa->authHashAlgo = NULL;
      childSa->authCipherAlgo = AES_CIPHER_ALGO;
      childSa->authKeyLen = 16;
      childSa->icvLen = 12;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_MD5_SUPPORT == ENABLED)
   //HMAC-MD5-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96)
   {
      childSa->authHashAlgo = MD5_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = MD5_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96)
   {
      childSa->authHashAlgo = SHA1_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA1_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256-128 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128)
   {
      childSa->authHashAlgo = SHA256_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA256_DIGEST_SIZE;
      childSa->icvLen = 16;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384-192 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192)
   {
      childSa->authHashAlgo = SHA384_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA384_DIGEST_SIZE;
      childSa->icvLen = 24;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512-256 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256)
   {
      childSa->authHashAlgo = SHA512_HASH_ALGO;
      childSa->authCipherAlgo = NULL;
      childSa->authKeyLen = SHA512_DIGEST_SIZE;
      childSa->icvLen = 32;
   }
   else
#endif
   //Unknown authentication algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported AH transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedTransforms(IkeContext *context, IkeProposal *proposal,
   uint8_t **lastSubstruc)
{
   error_t error;

   //Add supported integrity transforms
   error = ahAddSupportedAuthTransforms(context, proposal, lastSubstruc);

   //Check status code
   if(!error)
   {
      //An initiator who supports ESNs will usually include two ESN transforms,
      //with values "0" and "1", in its proposals (refer to RFC 7296,
      //section 3.3.2)
      error = ahAddSupportedEsnTransforms(context, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported integrity transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedAuthTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported integrity transforms
   for(i = 0; i < arraysize(ahSupportedAuthAlgos) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG,
         ahSupportedAuthAlgos[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported ESN transforms to the proposal
 * @param[in] context Pointer to the IKE context
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedEsnTransforms(IkeContext *context,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;
   uint_t i;

   //Initialize status code
   error = NO_ERROR;

   //Loop through the list of supported ESN transforms
   for(i = 0; i < arraysize(ahSupportedEsnTranforms) && !error; i++)
   {
      //Add a new transform to the proposal
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_ESN,
         ahSupportedEsnTranforms[i], 0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Integrity transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected integrity transform, if any
 **/

uint16_t ahSelectAuthTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the integrity transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_INTEG, ahSupportedAuthAlgos,
      arraysize(ahSupportedAuthAlgos), proposal, proposalLen);
}


/**
 * @brief ESN transform negotiation
 * @param[in] context Pointer to the IKE context
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected ESN transform, if any
 **/

uint16_t ahSelectEsnTransform(IkeContext *context, const IkeProposal *proposal,
   size_t proposalLen)
{
   //Select the ESN transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_ESN, ahSupportedEsnTranforms,
      arraysize(ahSupportedEsnTranforms), proposal, proposalLen);
}


/**
 * @brief Select a single proposal
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ahSelectSaProposal(IkeChildSaEntry *childSa, const IkeSaPayload *payload)
{
   error_t error;
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;

   //Clear the set of parameters
   childSa->protocol = IPSEC_PROTOCOL_INVALID;
   childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->encKeyLen = 0;
   childSa->authAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->esn = IKE_TRANSFORM_ID_INVALID;

   //Retrieve the length of the SA payload
   length = ntohs(payload->header.payloadLength);

   //Malformed payload?
   if(length < sizeof(IkeSaPayload))
      return ERROR_INVALID_MESSAGE;

   //Point to the first byte of the Proposals field
   p = payload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //Initialize status code
   error = ERROR_INVALID_PROPOSAL;

   //The Security Association payload contains one or more Proposal
   //substructures
   while(1)
   {
      //Malformed payload?
      if(length < sizeof(IkeProposal))
      {
         //Report an error
         error = ERROR_INVALID_MESSAGE;
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
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Check protocol identifier
      if(proposal->protocolId == IKE_PROTOCOL_ID_AH)
      {
         //Valid SPI value?
         if(proposal->spiSize == IPSEC_SPI_SIZE &&
            osMemcmp(proposal->spi, IPSEC_INVALID_SPI, IPSEC_SPI_SIZE) != 0)
         {
            //Integrity transform negotiation
            childSa->authAlgoId = ahSelectAuthTransform(childSa->context,
               proposal, n);

            //ESN transform negotiation
            childSa->esn = ahSelectEsnTransform(childSa->context, proposal, n);

            //Valid proposal?
            if(childSa->authAlgoId != IKE_TRANSFORM_ID_INVALID &&
               childSa->esn != IKE_TRANSFORM_ID_INVALID)
            {
               //Select AH security protocol
               childSa->protocol = IPSEC_PROTOCOL_AH;
               //Save the number of the proposal that was accepted
               childSa->acceptedProposalNum = proposal->proposalNum;

               //The initiator SPI is supplied in the SPI field of the SA
               //payload
               osMemcpy(childSa->remoteSpi, proposal->spi, proposal->spiSize);

               //Successful negotiation
               error = NO_ERROR;
               break;
            }
         }
      }

      //Jump to the next proposal
      p += n;
      length -= n;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the selected proposal is acceptable
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ahCheckSaProposal(IkeChildSaEntry *childSa, const IkeSaPayload *payload)
{
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;

   //Clear the set of parameters
   childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->encKeyLen = 0;
   childSa->authAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->esn = IKE_TRANSFORM_ID_INVALID;

   //Retrieve the length of the SA payload
   length = ntohs(payload->header.payloadLength);

   //Malformed payload?
   if(length < sizeof(IkeSaPayload))
      return ERROR_INVALID_MESSAGE;

   //Point to the first byte of the Proposals field
   p = payload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //Malformed payload?
   if(length < sizeof(IkeProposal))
      return ERROR_INVALID_MESSAGE;

   //Point to the Proposal substructure
   proposal = (IkeProposal *) p;

   //The Proposal Length field indicates the length of this proposal,
   //including all transforms and attributes that follow
   n = ntohs(proposal->proposalLength);

   //The responder must accept a single proposal (refer to RFC 7296,
   //section 2.7)
   if(n != length)
      return ERROR_INVALID_MESSAGE;

   //Check protocol identifier
   if(proposal->protocolId != IKE_PROTOCOL_ID_AH)
      return ERROR_INVALID_MESSAGE;

   //During subsequent negotiations, the SPI Size field is equal to the size,
   //in octets, of the SPI of the corresponding protocol (4 for ESP and AH)
   if(proposal->spiSize != IPSEC_SPI_SIZE)
      return ERROR_INVALID_MESSAGE;

   //The SPI value of zero is reserved and must not be sent on the wire (refer
   //to RFC 4302, section 2.4)
   if(osMemcmp(proposal->spi, IPSEC_INVALID_SPI, IPSEC_SPI_SIZE) == 0)
      return ERROR_INVALID_MESSAGE;

   //The responder SPI is supplied in the SPI field of the SA payload
   osMemcpy(childSa->remoteSpi, proposal->spi, proposal->spiSize);

   //The accepted cryptographic suite must contain exactly one transform of
   //each type included in the proposal (refer to RFC 7296, section 2.7)
   if(ikeGetNumTransforms(IKE_TRANSFORM_TYPE_INTEG, proposal, n) != 1 ||
      ikeGetNumTransforms(IKE_TRANSFORM_TYPE_ESN, proposal, n) != 1)
   {
      return ERROR_INVALID_PROPOSAL;
   }

   //Get the selected integrity transform
   childSa->authAlgoId = ahSelectAuthTransform(childSa->context, proposal, n);
   //Get the selected ESN transform
   childSa->esn = ahSelectEsnTransform(childSa->context, proposal, n);

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   if(childSa->authAlgoId != IKE_TRANSFORM_ID_INVALID &&
      childSa->esn != IKE_TRANSFORM_ID_INVALID)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_INVALID_PROPOSAL;
   }
}

#endif
