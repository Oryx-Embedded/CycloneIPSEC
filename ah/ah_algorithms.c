/**
 * @file ah_algorithms.c
 * @brief AH algorithm negotiation
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
      childSa->authMacAlgo = MAC_ALGO_CMAC;
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
      childSa->authMacAlgo = MAC_ALGO_HMAC;
      childSa->authHashAlgo = MD5_HASH_ALGO;
      childSa->authKeyLen = MD5_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA1_SUPPORT == ENABLED)
   //HMAC-SHA1-96 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96)
   {
      childSa->authMacAlgo = MAC_ALGO_HMAC;
      childSa->authHashAlgo = SHA1_HASH_ALGO;
      childSa->authKeyLen = SHA1_DIGEST_SIZE;
      childSa->icvLen = 12;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA256_SUPPORT == ENABLED)
   //HMAC-SHA256-128 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128)
   {
      childSa->authMacAlgo = MAC_ALGO_HMAC;
      childSa->authHashAlgo = SHA256_HASH_ALGO;
      childSa->authKeyLen = SHA256_DIGEST_SIZE;
      childSa->icvLen = 16;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA384_SUPPORT == ENABLED)
   //HMAC-SHA384-192 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192)
   {
      childSa->authMacAlgo = MAC_ALGO_HMAC;
      childSa->authHashAlgo = SHA384_HASH_ALGO;
      childSa->authKeyLen = SHA384_DIGEST_SIZE;
      childSa->icvLen = 24;
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED && AH_SHA512_SUPPORT == ENABLED)
   //HMAC-SHA512-256 authentication algorithm?
   if(authAlgoId == IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256)
   {
      childSa->authMacAlgo = MAC_ALGO_HMAC;
      childSa->authHashAlgo = SHA512_HASH_ALGO;
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
 * @param[in] childSa Pointer to the Child SA
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedTransforms(IkeChildSaEntry *childSa,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;

   //Add supported integrity transforms
   error = ahAddSupportedAuthTransforms(childSa, proposal, lastSubstruc);

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Although AH does not directly include a Diffie-Hellman exchange, a
      //Diffie-Hellman group may be negotiated for the Child SA. This allows
      //the peers to employ Diffie-Hellman in the CREATE_CHILD_SA exchange,
      //providing perfect forward secrecy for the generated Child SA keys
      //(refer to RFC 7296, section 3.3.2)
      if(childSa->pfs)
      {
         //Add supported key exchange transforms
         error = ikeAddSupportedKeTransforms(childSa->context, proposal,
            lastSubstruc);
      }
   }
#endif

   //Check status code
   if(!error)
   {
      //An initiator who supports ESNs will usually include two ESN transforms,
      //with values "0" and "1", in its proposals (refer to RFC 7296,
      //section 3.3.2)
      error = ahAddSupportedSnTransforms(childSa, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Add the supported integrity transforms to the proposal
 * @param[in] childSa Pointer to the Child SA
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedAuthTransforms(IkeChildSaEntry *childSa,
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
 * @brief Add the supported SN transforms to the proposal
 * @param[in] childSa Pointer to the Child SA
 * @param[in,out] proposal Pointer to the Proposal substructure
 * @param[in,out] lastSubstruc Pointer to the Last Substruc field
 * @return Error code
 **/

error_t ahAddSupportedSnTransforms(IkeChildSaEntry *childSa,
   IkeProposal *proposal, uint8_t **lastSubstruc)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (AH_ESN_SUPPORT == ENABLED)
   //Check whether extended sequence numbers are preferred
   if(childSa->esn)
   {
      //Transform ID 1 defines sequence numbers as monotonically increasing
      //64-bit counters. The low-order 32 bits are transmitted in the Sequence
      //Number field of AH packets (refer to RFC 9827, section 3)
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_SN, IKE_TRANSFORM_ID_SN_64BIT,
         0, proposal, lastSubstruc);
   }
#endif

   //Check status code
   if(!error)
   {
      //Transform ID 0 defines sequence numbers as monotonically increasing
      //32-bit counters that are transmitted in the Sequence Number field of
      //AH packets
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_SN, IKE_TRANSFORM_ID_SN_32BIT,
         0, proposal, lastSubstruc);
   }

   //Return status code
   return error;
}


/**
 * @brief Integrity transform negotiation
 * @param[in] childSa Pointer to the Child SA
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected integrity transform, if any
 **/

uint16_t ahSelectAuthTransform(IkeChildSaEntry *childSa,
   const IkeProposal *proposal, size_t proposalLen)
{
   //Select the integrity transform to use
   return ikeSelectTransform(IKE_TRANSFORM_TYPE_INTEG, ahSupportedAuthAlgos,
      arraysize(ahSupportedAuthAlgos), proposal, proposalLen);
}


/**
 * @brief SN transform negotiation
 * @param[in] childSa Pointer to the Child SA
 * @param[in] proposal Pointer to the Proposal substructure
 * @param[in] proposalLen Length of the Proposal substructure, in bytes
 * @return Selected SN transform, if any
 **/

uint16_t ahSelectSnTransform(IkeChildSaEntry *childSa,
   const IkeProposal *proposal, size_t proposalLen)
{
   uint16_t transformId;

   //Chosen SN transform
   transformId = IKE_TRANSFORM_ID_INVALID;

#if (AH_ESN_SUPPORT == ENABLED)
   //Check whether extended sequence numbers are preferred
   if(childSa->esn)
   {
      //Transform ID 1 defines sequence numbers as monotonically increasing
      //64-bit counters. The low-order 32 bits are transmitted in the Sequence
      //Number field of ESP packets (refer to RFC 9827, section 3)
      if(ikeFindTranform(IKE_TRANSFORM_TYPE_SN, IKE_TRANSFORM_ID_SN_64BIT, 0,
         proposal, proposalLen))
      {
         transformId = IKE_TRANSFORM_ID_SN_64BIT;
      }
   }
#endif

   //Invalid SN transform?
   if(transformId == IKE_TRANSFORM_ID_INVALID)
   {
      //Transform ID 0 defines sequence numbers as monotonically increasing
      //32-bit counters that are transmitted in the Sequence Number field of
      //ESP packets
      if(ikeFindTranform(IKE_TRANSFORM_TYPE_SN, IKE_TRANSFORM_ID_SN_32BIT, 0,
         proposal, proposalLen))
      {
         transformId = IKE_TRANSFORM_ID_SN_32BIT;
      }
   }

   //Return the chosen SN transform, if any
   return transformId;
}


/**
 * @brief Select a single proposal
 * @param[in] childSa Pointer to the Child SA
 * @param[in] payload Pointer to the Security Association payload
 * @return Error code
 **/

error_t ahSelectSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload)
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
   childSa->snId = IKE_TRANSFORM_ID_INVALID;
#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
   childSa->keContext.groupNum = IKE_TRANSFORM_ID_KE_NONE;
#endif

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
            //Initialize status code
            error = NO_ERROR;

            //Integrity transform negotiation
            childSa->authAlgoId = ahSelectAuthTransform(childSa, proposal, n);
            //SN transform negotiation
            childSa->snId = ahSelectSnTransform(childSa, proposal, n);

            //Unacceptable proposal?
            if(childSa->authAlgoId == IKE_TRANSFORM_ID_INVALID ||
               childSa->snId == IKE_TRANSFORM_ID_INVALID)
            {
               error = ERROR_INVALID_PROPOSAL;
            }

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
            //Although AH does not directly include a Diffie-Hellman exchange,
            //a Diffie-Hellman group may be negotiated for the Child SA. This
            //allows the peers to employ Diffie-Hellman in the CREATE_CHILD_SA
            //exchange, providing perfect forward secrecy for the generated
            //Child SA keys (refer to RFC 7296, section 3.3.2)
            if(childSa->pfs)
            {
               //Key exchange transform negotiation
               childSa->keContext.groupNum = ikeSelectKeTransform(
                  childSa->context, proposal, n);

               //Unacceptable proposal?
               if(childSa->keContext.groupNum == IKE_TRANSFORM_ID_KE_NONE)
               {
                  error = ERROR_INVALID_PROPOSAL;
               }
            }
#endif
            //Valid proposal?
            if(!error)
            {
               //Select AH security protocol
               childSa->protocol = IPSEC_PROTOCOL_AH;
               //Save the number of the proposal that was accepted
               childSa->acceptedProposalNum = proposal->proposalNum;

               //The initiator SPI is supplied in the SPI field of the SA
               //payload
               osMemcpy(childSa->remoteSpi, proposal->spi, proposal->spiSize);

               //Successful negotiation
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

error_t ahCheckSaProposal(IkeChildSaEntry *childSa,
   const IkeSaPayload *payload)
{
   size_t n;
   size_t length;
   const uint8_t *p;
   const IkeProposal *proposal;

   //Clear the set of parameters
   childSa->encAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->encKeyLen = 0;
   childSa->authAlgoId = IKE_TRANSFORM_ID_INVALID;
   childSa->snId = IKE_TRANSFORM_ID_INVALID;

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
      ikeGetNumTransforms(IKE_TRANSFORM_TYPE_SN, proposal, n) != 1)
   {
      return ERROR_INVALID_PROPOSAL;
   }

   //Get the selected integrity transform
   childSa->authAlgoId = ahSelectAuthTransform(childSa, proposal, n);
   //Get the selected SN transform
   childSa->snId = ahSelectSnTransform(childSa, proposal, n);

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   if(childSa->authAlgoId != IKE_TRANSFORM_ID_INVALID &&
      childSa->snId != IKE_TRANSFORM_ID_INVALID)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_INVALID_PROPOSAL;
   }
}

#endif
