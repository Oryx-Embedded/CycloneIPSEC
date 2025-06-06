/**
 * @file ike_payload_format.c
 * @brief IKE payload formatting
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
#include "ike/ike_payload_format.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ah/ah_algorithms.h"
#include "esp/esp_algorithms.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Format Security Association payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatSaPayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *written, uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeSaPayload *saPayload;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_SA;

   //Point to the Security Association payload header
   saPayload = (IkeSaPayload *) p;

   //Format Security Association payload header
   saPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   saPayload->header.critical = FALSE;
   saPayload->header.reserved = 0;

   //Length of the payload header
   *written = sizeof(IkeSaPayload);

   //Point to the Proposals field
   p = saPayload->proposals;

   //Valid Child SA?
   if(childSa != NULL)
   {
      //Format Proposal substructure (AH or ESP protocol)
      error = ikeFormatChildSaProposal(childSa, childSa->protocol,
         childSa->localSpi, p, &n);
   }
   else
   {
      //Format Proposal substructure (IKE protocol)
      if(sa->state == IKE_SA_STATE_REKEY_REQ && sa->newSa != NULL)
      {
         error = ikeFormatSaProposal(sa, sa->newSa->initiatorSpi, p, &n);
      }
      else if(sa->state == IKE_SA_STATE_OPEN && sa->newSa != NULL)
      {
         error = ikeFormatSaProposal(sa, sa->newSa->responderSpi, p, &n);
      }
      else
      {
         error = ikeFormatSaProposal(sa, NULL, p, &n);
      }
   }

   //Any error to report?
   if(error)
      return error;

   //Total length of the payload
   *written += n;

   //Fix the Payload Length field of the payload header
   saPayload->header.payloadLength = htons(*written);

   //Keep track of the Next Payload field
   *nextPayload = &saPayload->header.nextPayload;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Proposal substructure (IKE protocol)
 * @param[in] sa Pointer to the IKE SA
 * @param[in] spi Security parameter index (optional parameter)
 * @param[out] p Buffer where to format the Proposal substructure
 * @param[out] written Length of the resulting Proposal substructure
 * @return Error code
 **/

error_t ikeFormatSaProposal(IkeSaEntry *sa, const uint8_t *spi, uint8_t *p,
   size_t *written)
{
   error_t error;
   size_t n;
   uint8_t *lastSubstruc;
   IkeContext *context;
   IkeProposal *proposal;

   //Point to the IKE context
   context = sa->context;

   //Point to the Proposal substructure
   proposal = (IkeProposal *) p;

   //Format Proposal substructure
   proposal->lastSubstruc = IKE_LAST_SUBSTRUC_LAST;
   proposal->reserved = 0;
   proposal->proposalLength = 0;
   proposal->protocolId = IKE_PROTOCOL_ID_IKE;
   proposal->spiSize = (spi != NULL) ? IKE_SPI_SIZE : 0;
   proposal->numTransforms = 0;

   //Length of the Proposal substructure
   n = sizeof(IkeProposal);

   //When the SPI Size field is zero, the SPI field is not present
   if(spi != NULL)
   {
      //Copy the sending entity's SPI
      osMemcpy(proposal->spi, spi, IKE_SPI_SIZE);
      //Adjust the length of the Proposal substructure
      n += IKE_SPI_SIZE;
   }

   //The Proposal Length field indicates the length of the proposal, including
   //all transforms and attributes that follow
   proposal->proposalLength = htons(n);

   //The Last Substruc field has a value of 0 if this was the last Transform
   //Substructure, and a value of 3 if there are more Transform Substructures
   lastSubstruc = NULL;

   //Check whether the entity is the original initiator of the IKE SA
   if(sa->originalInitiator)
   {
      //When a proposal is made, the first proposal in an SA payload must be 1,
      //and subsequent proposals must be one more than the previous proposal
      //(refer to RFC 7296, section 3.3.1)
      proposal->proposalNum = 1;

      //IKE generally has four transforms: a Diffie-Hellman group, an
      //integrity check algorithm, a PRF algorithm, and an encryption
      //algorithm
      error = ikeAddSupportedTransforms(context, proposal, &lastSubstruc);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //When a proposal is accepted, the proposal number in the SA payload must
      //match the number on the proposal sent that was accepted (refer to
      //RFC 7296, section 3.3.1)
      proposal->proposalNum = sa->acceptedProposalNum;

      //The accepted cryptographic suite must contain exactly one encryption
      //transform
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_ENCR, sa->encAlgoId,
         sa->encKeyLen, proposal, &lastSubstruc);
      //Any error to report?
      if(error)
         return error;

      //The accepted cryptographic suite must contain exactly one PRF
      //transform
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_PRF, sa->prfAlgoId, 0,
         proposal, &lastSubstruc);
      //Any error to report?
      if(error)
         return error;

      //AEAD encryption algorithm?
      if(ikeIsAeadEncAlgo(sa->encAlgoId))
      {
         //If all of the encryption algorithms in any proposal are
         //authenticated encryption algorithms, then the proposal must not
         //propose any integrity transforms (refer to RFC 5282, section 8)
         error = NO_ERROR;
      }
      else
      {
         //The accepted cryptographic suite must contain exactly one
         //integrity transform
         error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG, sa->authAlgoId, 0,
            proposal, &lastSubstruc);
      }

      //Any error to report?
      if(error)
         return error;

      //The accepted cryptographic suite must contain exactly one key
      //exchange transform
      error = ikeAddTransform(IKE_TRANSFORM_TYPE_DH, sa->dhGroupNum, 0,
         proposal, &lastSubstruc);
      //Any error to report?
      if(error)
         return error;
   }

   //Total length of the Proposal substructure
   *written = ntohs(proposal->proposalLength);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Proposal substructure (AH or ESP protocol)
 * @param[in] childSa Pointer to the Child SA
 * @param[in] protocolId Protocol identifier (AH or ESP)
 * @param[in] spi Security parameter index
 * @param[out] p Buffer where to format the Proposal substructure
 * @param[out] written Length of the resulting Proposal substructure
 * @return Error code
 **/

error_t ikeFormatChildSaProposal(IkeChildSaEntry *childSa,
   IpsecProtocol protocolId, const uint8_t *spi, uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;
   uint8_t *lastSubstruc;
   IkeContext *context;
   IkeProposal *proposal;

   //Point to the IKE context
   context = childSa->context;

   //Point to the Proposal substructure
   proposal = (IkeProposal *) p;

   //Format Proposal substructure
   proposal->lastSubstruc = IKE_LAST_SUBSTRUC_LAST;
   proposal->reserved = 0;
   proposal->proposalLength = 0;
   proposal->protocolId = protocolId;
   proposal->spiSize = IPSEC_SPI_SIZE;
   proposal->numTransforms = 0;

   //Length of the Proposal substructure
   n = sizeof(IkeProposal);

   //Copy the sending entity's SPI
   osMemcpy(proposal->spi, spi, IPSEC_SPI_SIZE);
   //Adjust the length of the Proposal substructure
   n += IPSEC_SPI_SIZE;

   //The Proposal Length field indicates the length of the proposal, including
   //all transforms and attributes that follow
   proposal->proposalLength = htons(n);

   //The Last Substruc field has a value of 0 if this was the last Transform
   //Substructure, and a value of 3 if there are more Transform Substructures
   lastSubstruc = NULL;

   //Check whether the entity is the initiator of the CREATE_CHILD_SA
   //exchange
   if(childSa->initiator)
   {
      //When a proposal is made, the first proposal in an SA payload must be 1,
      //and subsequent proposals must be one more than the previous proposal
      //(refer to RFC 7296, section 3.3.1)
      proposal->proposalNum = 1;

#if (AH_SUPPORT == ENABLED)
      //AH protocol identifier?
      if(protocolId == IPSEC_PROTOCOL_AH)
      {
         //AH generally has two transforms: ESN and an integrity check
         //algorithm
         error = ahAddSupportedTransforms(context, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (ESP_SUPPORT == ENABLED)
      //ESP protocol identifier?
      if(protocolId == IPSEC_PROTOCOL_ESP)
      {
         //ESP generally has three transforms: ESN, an encryption algorithm
         //and an integrity check algorithm
         error = espAddSupportedTransforms(context, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
      //Unknown protocol identifier?
      {
         //Report an error
         return ERROR_FAILURE;
      }
   }
   else
   {
      //When a proposal is accepted, the proposal number in the SA payload must
      //match the number on the proposal sent that was accepted (refer to
      //RFC 7296, section 3.3.1)
      proposal->proposalNum = childSa->acceptedProposalNum;

#if (AH_SUPPORT == ENABLED)
      //AH protocol identifier?
      if(protocolId == IPSEC_PROTOCOL_AH)
      {
         //The accepted proposal contains a single integrity transform
         error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG,
            childSa->authAlgoId, 0, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;

         //The accepted proposal contains a single ESN transform
         error = ikeAddTransform(IKE_TRANSFORM_TYPE_ESN, childSa->esn,
            0, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
#if (ESP_SUPPORT == ENABLED)
      //ESP protocol identifier?
      if(protocolId == IPSEC_PROTOCOL_ESP)
      {
         //The accepted proposal contains a single encryption transform
         error = ikeAddTransform(IKE_TRANSFORM_TYPE_ENCR, childSa->encAlgoId,
            childSa->encKeyLen, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;

         //AEAD encryption algorithm?
         if(ikeIsAeadEncAlgo(childSa->encAlgoId))
         {
            //If all of the encryption algorithms in any proposal are
            //authenticated encryption algorithms, then the proposal must not
            //propose any integrity transforms (refer to RFC 5282, section 8)
            error = NO_ERROR;
         }
         else
         {
            //The accepted proposal contains a single integrity transform
            error = ikeAddTransform(IKE_TRANSFORM_TYPE_INTEG,
               childSa->authAlgoId, 0, proposal, &lastSubstruc);
         }

         //Any error to report?
         if(error)
            return error;

         //The accepted proposal contains a single ESN transform
         error = ikeAddTransform(IKE_TRANSFORM_TYPE_ESN, childSa->esn,
            0, proposal, &lastSubstruc);
         //Any error to report?
         if(error)
            return error;
      }
      else
#endif
      //Unknown protocol identifier?
      {
         //Report an error
         return ERROR_FAILURE;
      }
   }

   //Total length of the Proposal substructure
   *written = ntohs(proposal->proposalLength);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Key Exchange payload
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatKePayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeKePayload *kePayload;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_KE;

   //Point to the Key Exchange payload header
   kePayload = (IkeKePayload *) p;

   //Format Key Exchange payload header
   kePayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   kePayload->header.critical = FALSE;
   kePayload->header.reserved = 0;

   //The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
   //which the Key Exchange Data was computed
   kePayload->dhGroupNum = htons(sa->dhGroupNum);

   //For forward compatibility, all fields marked RESERVED must be set to
   //zero (refer to RFC 7296, section 2.5)
   kePayload->reserved = 0;

   //A Key Exchange payload is constructed by copying one's Diffie-Hellman
   //public value into the Key Exchange Data portion of the payload
   error = ikeFormatDhPublicKey(sa, kePayload->keyExchangeData, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of payload
   *written = sizeof(IkeKePayload) + n;
   //Fix the Payload Length field of the payload header
   kePayload->header.payloadLength = htons(*written);

   //Keep track of the Next Payload field
   *nextPayload = &kePayload->header.nextPayload;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Identification payload
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatIdPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload)
{
   error_t error;
   IkeContext *context;
   IkeIdPayload *idPayload;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //Fix the Next Payload field of the previous payload
   if(sa->originalInitiator)
   {
      **nextPayload = IKE_PAYLOAD_TYPE_IDI;
   }
   else
   {
      **nextPayload = IKE_PAYLOAD_TYPE_IDR;
   }

   //Point to the Identification payload header
   idPayload = (IkeIdPayload *) p;

   //Format Identification payload header
   idPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   idPayload->header.critical = FALSE;
   idPayload->header.reserved = 0;

   //For forward compatibility, all fields marked RESERVED must be set to
   //zero (refer to RFC 7296, section 2.5)
   osMemset(idPayload->reserved, 0, 3);

   //Length of the payload header
   *written = sizeof(IkeIdPayload);

   //Check the type of identification being used
   if(context->idType != IKE_ID_TYPE_INVALID)
   {
      //Set ID type
      idPayload->idType = context->idType;

      //Copy identification data
      osMemcpy(idPayload->idData, context->id, context->idLen);
      //Total length of the payload
      *written += context->idLen;
   }
   else
   {
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Check whether an end-entity's certificate exists
      if(context->certChain != NULL && context->certChainLen > 0)
      {
         size_t n;

         //Set ID type
         idPayload->idType = IKE_ID_TYPE_DER_ASN1_DN;

         //Extract the subject's distinguished name from the certificate
         error = ikeGetCertSubjectDn(context->certChain, context->certChainLen,
            idPayload->idData, &n);

         //Check status code
         if(!error)
         {
            //Total length of the payload
            *written += n;
         }
      }
      else
#endif
      {
         //Report an error
         error = ERROR_INVALID_TYPE;
      }
   }

   //Check status code
   if(!error)
   {
      //Fix the Payload Length field of the payload header
      idPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &idPayload->header.nextPayload;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Certificate payloads
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payloads
 * @param[out] written Length of the resulting payloads
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatCertPayloads(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload)
{
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   error_t error;
   size_t m;
   size_t n;
   size_t certChainLen;
   const char_t *certChain;
   IkeContext *context;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //Total length of the Certificate payloads
   *written = 0;

   //Check whether an end-entity's certificate exists
   if(context->certChain != NULL && context->certChainLen > 0)
   {
      //Point to the certificate chain
      certChain = context->certChain;
      //Get the total length, in bytes, of the certificate chain
      certChainLen = context->certChainLen;

      //If multiple certificates are sent, the first certificate must contain
      //the public key associated with the private key used to sign the AUTH
      //payload (refer to RFC 7296, section 3.6)
      error = ikeFormatCertPayload(certChain, certChainLen, &m, p, &n,
         nextPayload);

      //Check status code
      if(!error)
      {
         //Point to the next payload
         p += n;
         *written += n;

         //Move to the next certificate of the chain
         certChain += m;
         certChainLen -= m;

         //If a chain of certificates needs to be sent, multiple Certificate
         //payloads are used
         while(certChainLen > 0 && !error)
         {
            //Format Certificate payload
            error = ikeFormatCertPayload(certChain, certChainLen, &m, p, &n,
               nextPayload);

            //Check status code
            if(!error)
            {
               //Point to the next payload
               p += n;
               *written += n;

               //Move to the next certificate of the chain
               certChain += m;
               certChainLen -= m;
            }
         }

         //The end of the certificate chain has been reached
         error = NO_ERROR;
      }
   }

   //Return status code
   return error;
#else
   //Certificate authentication is not supported
   *written = 0;
   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Format Certificate payload
 * @param[in] certChain Pointer to the certificate chain (PEM format)
 * @param[in] certChainLen Length of the certificate chain, in bytes
 * @param[out] consumed Total number of characters that have been consumed
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatCertPayload(const char_t *certChain, size_t certChainLen,
   size_t *consumed, uint8_t *p, size_t *written, uint8_t **nextPayload)
{
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   IkeCertPayload *certPayload;

   //Point to the Certificate payload header
   certPayload = (IkeCertPayload *) p;

   //The Certificate Data field Extract the DER-encoded certificate
   error = pemImportCertificate(certChain, certChainLen, certPayload->certData,
      &n, consumed);

   //Check status code
   if(!error)
   {
      //Fix the Next Payload field of the previous payload
      **nextPayload = IKE_PAYLOAD_TYPE_CERT;

      //Format Certificate payload header
      certPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
      certPayload->header.critical = FALSE;
      certPayload->header.reserved = 0;
      certPayload->certEncoding = IKE_CERT_ENCODING_X509_CERT_SIGN;

      //Total length of the payload
      *written = sizeof(IkeCertPayload) + n;
      //Fix the Payload Length field of the payload header
      certPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &certPayload->header.nextPayload;
   }
   else
   {
      //End of file detected
      *written = 0;
   }

   //Return status code
   return error;
#else
   //Certificate authentication is not supported
   *written = 0;
   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Format Certificate Request payload
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatCertReqPayload(IkeSaEntry *sa, uint8_t *p, size_t *written,
   uint8_t **nextPayload)
{
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   size_t n;
   IpsecPadEntry *entry;
   IpsecContext *ipsecContext;
   IkeCertReqPayload *certReqPayload;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IPsec context
   ipsecContext = netContext.ipsecContext;
   //Any error to report?
   if(ipsecContext == NULL)
      return ERROR_FAILURE;

   //Point to the Certificate Request payload header
   certReqPayload = (IkeCertReqPayload *) p;

   //Length of the Certification Authority field
   n = 0;

   //Loop through PAD entries
   for(i = 0; i < ipsecContext->numPadEntries && !error; i++)
   {
      //Point to the current PAD entry
      entry = &ipsecContext->pad[i];

      //Valid authentication method?
      if(entry->authMethod == IPSEC_AUTH_METHOD_IKEV2)
      {
         //Valid trusted CA list?
         if(entry->trustedCaList != NULL && entry->trustedCaListLen > 0)
         {
            //The Certification Authority value is a concatenated list of
            //SHA-1 hashes of the public keys of trusted Certification
            //Authorities (CAs)
            error = ikeFormatCertAuthorities(entry->trustedCaList,
               entry->trustedCaListLen, certReqPayload->certAuthority, &n);
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Check the length of the Certification Authority field
      if(n > 0)
      {
         //Fix the Next Payload field of the previous payload
         **nextPayload = IKE_PAYLOAD_TYPE_CERTREQ;

         //Format Certificate payload header
         certReqPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
         certReqPayload->header.critical = FALSE;
         certReqPayload->header.reserved = 0;
         certReqPayload->certEncoding = IKE_CERT_ENCODING_X509_CERT_SIGN;

         //Total length of the payload
         *written = sizeof(IkeCertReqPayload) + n;
         //Fix the Payload Length field of the payload header
         certReqPayload->header.payloadLength = htons(*written);

         //Keep track of the Next Payload field
         *nextPayload = &certReqPayload->header.nextPayload;
      }
      else
      {
         //The Certification Authority field is empty
         *written = 0;
      }
   }

   //Return status code
   return error;
#else
   //Certificate authentication is not supported
   *written = 0;
   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Format Authentication payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] idPayload Pointer to the Identification payload
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatAuthPayload(IkeSaEntry *sa, const IkeIdPayload *idPayload,
   uint8_t *p, size_t *written, uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeAuthPayload *authPayload;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_AUTH;

   //Point to the Authentication payload header
   authPayload = (IkeAuthPayload *) p;

   //Format Authentication payload header
   authPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   authPayload->header.critical = FALSE;
   authPayload->header.reserved = 0;

   //For forward compatibility, all fields marked RESERVED must be set to
   //zero (refer to RFC 7296, section 2.5)
   osMemset(authPayload->reserved, 0, 3);

   //Generate AUTH value
   error = ikeGenerateAuth(sa, idPayload, &authPayload->authMethod,
      authPayload->authData, &n);

   //Check status code
   if(!error)
   {
      //Total length of the payload
      *written = sizeof(IkeAuthPayload) + n;
      //Fix the Payload Length field of the payload header
      authPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &authPayload->header.nextPayload;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Nonce payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatNoncePayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *written, uint8_t **nextPayload)
{
   IkeNoncePayload *noncePayload;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_NONCE;

   //Point to the Nonce payload header
   noncePayload = (IkeNoncePayload *) p;

   //Format Nonce payload header
   noncePayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   noncePayload->header.critical = FALSE;
   noncePayload->header.reserved = 0;

   //Length of the payload header
   *written = sizeof(IkeNoncePayload);

   //Valid Child SA?
   if(childSa != NULL)
   {
      //Check whether the entity is the initiator of the CREATE_CHILD_SA
      //exchange
      if(childSa->initiator)
      {
         //Copy the initiator's nonce
         osMemcpy(noncePayload->nonceData, childSa->initiatorNonce,
            childSa->initiatorNonceLen);

         //The size of the Nonce Data must be between 16 and 256 octets
         *written += childSa->initiatorNonceLen;
      }
      else
      {
         //Copy the responder's nonce
         osMemcpy(noncePayload->nonceData, childSa->responderNonce,
            childSa->responderNonceLen);

         //The size of the Nonce Data must be between 16 and 256 octets
         *written += childSa->responderNonceLen;
      }
   }
   else
   {
      //Check whether the entity is the original initiator of the IKE SA
      if(sa->originalInitiator)
      {
         //Copy the initiator's nonce
         osMemcpy(noncePayload->nonceData, sa->initiatorNonce,
            sa->initiatorNonceLen);

         //The size of the Nonce Data must be between 16 and 256 octets
         *written += sa->initiatorNonceLen;
      }
      else
      {
         //Copy the responder's nonce
         osMemcpy(noncePayload->nonceData, sa->responderNonce,
            sa->responderNonceLen);

         //The size of the Nonce Data must be between 16 and 256 octets
         *written += sa->responderNonceLen;
      }
   }

   //Fix the Payload Length field of the payload header
   noncePayload->header.payloadLength = htons(*written);

   //Keep track of the Next Payload field
   *nextPayload = &noncePayload->header.nextPayload;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Notify payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[in] notifyMsgType Type of notification
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatNotifyPayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   IkeNotifyMsgType notifyMsgType, uint8_t *p, size_t *written,
   uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeNotifyPayload *notifyPayload;

   //Initialize status code
   error = NO_ERROR;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_N;

   //Point to the Notify payload header
   notifyPayload = (IkeNotifyPayload *) p;

   //Format Notify payload header
   notifyPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   notifyPayload->header.critical = FALSE;
   notifyPayload->header.reserved = 0;

   //If the SPI field is empty, the Protocol ID field must be sent as zero and
   //must be ignored on receipt (refer to RFC 7296, section 3.10)
   notifyPayload->protocolId = 0;
   notifyPayload->spiSize = 0;

   //The Notify Message Type field specifies the type of notification message
   notifyPayload->notifyMsgType = htons(notifyMsgType);

   //Length of the payload header
   *written = sizeof(IkeNotifyPayload);

   //The notification may include additional data
   if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD)
   {
      //In that Notify payload, the Notification Data contains the one-octet
      //payload type (refer to RFC 7296, section 2.5)
      notifyPayload->spi[0] = sa->unsupportedCriticalPayload;

      //Total length of the payload
      *written += sizeof(uint8_t);
   }
   else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
   {
      //The responder indicate its preferred Diffie-Hellman group in the
      //INVALID_KE_PAYLOAD Notify payload
      STORE16BE(sa->dhGroupNum, notifyPayload->spi);

      //Total length of the payload
      *written += sizeof(uint16_t);
   }
   else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_CHILD_SA_NOT_FOUND)
   {
      //The Protocol ID field must contain either 2 to indicate AH or 3 to
      //indicate ESP
      notifyPayload->protocolId = sa->notifyProtocolId;

      //The SPI Size field specifies the length in octets of the SPI as
      //defined by the IPsec protocol ID
      notifyPayload->spiSize = IPSEC_SPI_SIZE;

      //The SPI is included only with INVALID_SELECTORS, REKEY_SA, and
      //CHILD_SA_NOT_FOUND notifications (refer to RFC 7296, section 3.10)
      osMemcpy(notifyPayload->spi, sa->notifySpi, IPSEC_SPI_SIZE);

      //Total length of the payload
      *written += notifyPayload->spiSize;
   }
   else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_COOKIE)
   {
      //The data associated with this notification must be between 1 and 64
      //octets in length (refer to RFC 7296, section 2.6)
      osMemcpy(notifyPayload->spi, sa->cookie, sa->cookieLen);

      //Adjust the length of the Notify payload
      *written += sa->cookieLen;
   }
   else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_REKEY_SA)
   {
      //The Protocol ID field must contain either 2 to indicate AH or 3 to
      //indicate ESP
      notifyPayload->protocolId = childSa->protocol;

      //The SPI Size field specifies the length in octets of the SPI as
      //defined by the IPsec protocol ID
      notifyPayload->spiSize = IPSEC_SPI_SIZE;

      //The SA being rekeyed is identified by the SPI field in the Notify
      //payload; this is the SPI the exchange initiator would expect in
      //inbound ESP or AH packets.  There is no data associated with this
      //Notify message type (refer to RFC 7296, section 1.3.3)
      osMemcpy(notifyPayload->spi, childSa->oldChildSa->localSpi,
         IPSEC_SPI_SIZE);

      //Total length of the payload
      *written += notifyPayload->spiSize;
   }
   else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS)
   {
      //The Notification Data field contains the list of 16-bit hash algorithm
      //identifiers (refer to RFC 7427, section 4)
      error = ikeFormatSignHashAlgosNotificationData(sa, notifyPayload->spi,
         &n);

      //Check status code
      if(!error)
      {
         //Total length of the payload
         *written += n;
      }
   }
   else
   {
      //Just for sanity
   }

   //Check status code
   if(!error)
   {
      //Fix the Payload Length field of the payload header
      notifyPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &notifyPayload->header.nextPayload;
   }

   //Return status code
   return error;
}


/**
 * @brief Format SIGNATURE_HASH_ALGORITHMS notification data
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the notification data
 * @param[out] written Length of the notification data, in bytes
 * @return Error code
 **/

error_t ikeFormatSignHashAlgosNotificationData(IkeSaEntry *sa, uint8_t *p,
   size_t *written)
{
   //The Notification Data field contains the list of 16-bit hash algorithm
   //identifiers
   *written = 0;

#if (IKE_SHA1_SUPPORT == ENABLED)
   //SHA-1 hash algorithm is supported
   STORE16BE(IKE_HASH_ALGO_SHA1, p);

   //Adjust the length of the notification data
   p += sizeof(uint16_t);
   *written += sizeof(uint16_t);
#endif

#if (IKE_SHA256_SUPPORT == ENABLED)
   //SHA-256 hash algorithm is supported
   STORE16BE(IKE_HASH_ALGO_SHA256, p);

   //Adjust the length of the notification data
   p += sizeof(uint16_t);
   *written += sizeof(uint16_t);
#endif

#if (IKE_SHA384_SUPPORT == ENABLED)
   //SHA-384 hash algorithm is supported
   STORE16BE(IKE_HASH_ALGO_SHA384, p);

   //Adjust the length of the notification data
   p += sizeof(uint16_t);
   *written += sizeof(uint16_t);
#endif

#if (IKE_SHA512_SUPPORT == ENABLED)
   //SHA-512 hash algorithm is supported
   STORE16BE(IKE_HASH_ALGO_SHA512, p);

   //Adjust the length of the notification data
   p += sizeof(uint16_t);
   *written += sizeof(uint16_t);
#endif

#if (IKE_ED25519_SIGN_SUPPORT == ENABLED || IKE_ED448_SIGN_SUPPORT == ENABLED)
   //Inserting "Identity" hash identifier indicates that the receiver supports
   //at least one signature algorithm that accepts messages of arbitrary size
   //such as Ed25519 and Ed448 (refer to RFC 8420, section 2)
   STORE16BE(IKE_HASH_ALGO_IDENTITY, p);

   //Adjust the length of the notification data
   p += sizeof(uint16_t);
   *written += sizeof(uint16_t);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Delete payload
 * @param[in] sa Pointer to the IKE SA
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatDeletePayload(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *written, uint8_t **nextPayload)
{
   IkeDeletePayload *deletePayload;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_D;

   //Point to the Delete payload header
   deletePayload = (IkeDeletePayload *) p;

   //Format Delete payload header
   deletePayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   deletePayload->header.critical = FALSE;
   deletePayload->header.reserved = 0;

   //Length of the payload header
   *written = sizeof(IkeDeletePayload);

   //Valid Child SA?
   if(childSa != NULL)
   {
      deletePayload->protocolId = childSa->protocol;
      deletePayload->spiSize = IPSEC_SPI_SIZE;
      deletePayload->numSpi = HTONS(1);

      //Deletion of a Child SA, such as ESP or AH, will contain the IPsec
      //protocol ID of that protocol (2 for AH, 3 for ESP), and the SPI is the
      //SPI the sending endpoint would expect in inbound ESP or AH packets
      osMemcpy(deletePayload->spi, childSa->localSpi, IPSEC_SPI_SIZE);

      //Total length of the payload
      *written += IPSEC_SPI_SIZE;
   }
   else
   {
      //Deletion of the IKE SA is indicated by a protocol ID of 1 (IKE) but
      //no SPIs
      deletePayload->protocolId = IKE_PROTOCOL_ID_IKE;
      deletePayload->spiSize = 0;
      deletePayload->numSpi = HTONS(0);
   }

   //Fix the Payload Length field of the payload header
   deletePayload->header.payloadLength = htons(*written);

   //Keep track of the Next Payload field
   *nextPayload = &deletePayload->header.nextPayload;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format Traffic Selector payload (initiator)
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatTsiPayload(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written, uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeTsParams tsParams;
   IkeTsPayload *tsPayload;
   IpsecSelector *selector;

   //Get selector parameters
   selector = &childSa->selector;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_TSI;

   //Point to the Traffic Selector payload header
   tsPayload = (IkeTsPayload *) p;

   //Format Traffic Selector payload header
   tsPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   tsPayload->header.critical = FALSE;
   tsPayload->header.reserved = 0;

   //Set the number of Traffic Selectors being provided
   tsPayload->numTs = 1;
   //The reserved field must be sent as zero
   osMemset(tsPayload->reserved, 0, 3);

   //Length of the payload header
   *written = sizeof(IkeTsPayload);

   //Point to the Traffic Selectors field
   p = tsPayload->trafficSelectors;

   //TSi specifies the source address of traffic forwarded from (or the
   //destination address of traffic forwarded to) the initiator of the
   //Child SA pair (refer to RFC 7296, section 2.9)
   if(childSa->initiator)
   {
      tsParams.startAddr = selector->localIpAddr.start;
      tsParams.endAddr = selector->localIpAddr.end;
      tsParams.ipProtocolId = selector->nextProtocol;
      tsParams.startPort = selector->localPort.start;
      tsParams.endPort = selector->localPort.end;
   }
   else
   {
      tsParams.startAddr = selector->remoteIpAddr.start;
      tsParams.endAddr = selector->remoteIpAddr.end;
      tsParams.ipProtocolId = selector->nextProtocol;
      tsParams.startPort = selector->remotePort.start;
      tsParams.endPort = selector->remotePort.end;
   }

   //Format Traffic Selector substructure
   error = ikeFormatTs(&tsParams, p, &n);

   //Check status code
   if(!error)
   {
      //Total length of the payload
      *written += n;

      //Fix the Payload Length field of the payload header
      tsPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &tsPayload->header.nextPayload;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Traffic Selector payload (responder)
 * @param[in] childSa Pointer to the Child SA
 * @param[out] p Buffer where to format the payload
 * @param[out] written Length of the resulting payload
 * @param[in,out] nextPayload Pointer to the Next Payload field
 * @return Error code
 **/

error_t ikeFormatTsrPayload(IkeChildSaEntry *childSa, uint8_t *p,
   size_t *written, uint8_t **nextPayload)
{
   error_t error;
   size_t n;
   IkeTsParams tsParams;
   IkeTsPayload *tsPayload;
   IpsecSelector *selector;

   //Get selector parameters
   selector = &childSa->selector;

   //Fix the Next Payload field of the previous payload
   **nextPayload = IKE_PAYLOAD_TYPE_TSR;

   //Point to the Traffic Selector payload header
   tsPayload = (IkeTsPayload *) p;

   //Format Traffic Selector payload header
   tsPayload->header.nextPayload = IKE_PAYLOAD_TYPE_LAST;
   tsPayload->header.critical = FALSE;
   tsPayload->header.reserved = 0;

   //Set the number of Traffic Selectors being provided
   tsPayload->numTs = 1;
   //The reserved field must be sent as zero
   osMemset(tsPayload->reserved, 0, 3);

   //Length of the payload header
   *written = sizeof(IkeTsPayload);

   //Point to the Traffic Selectors field
   p = tsPayload->trafficSelectors;

   //TSr specifies the source address of traffic forwarded from (or the
   //destination address of traffic forwarded to) the responder of the
   //Child SA pair (refer to RFC 7296, section 2.9)
   if(childSa->initiator)
   {
      tsParams.startAddr = selector->remoteIpAddr.start;
      tsParams.endAddr = selector->remoteIpAddr.end;
      tsParams.ipProtocolId = selector->nextProtocol;
      tsParams.startPort = selector->remotePort.start;
      tsParams.endPort = selector->remotePort.end;
   }
   else
   {
      tsParams.startAddr = selector->localIpAddr.start;
      tsParams.endAddr = selector->localIpAddr.end;
      tsParams.ipProtocolId = selector->nextProtocol;
      tsParams.startPort = selector->localPort.start;
      tsParams.endPort = selector->localPort.end;
   }

   //Format Traffic Selector substructure
   error = ikeFormatTs(&tsParams, p, &n);

   //Check status code
   if(!error)
   {
      //Total length of the payload
      *written += n;

      //Fix the Payload Length field of the payload header
      tsPayload->header.payloadLength = htons(*written);

      //Keep track of the Next Payload field
      *nextPayload = &tsPayload->header.nextPayload;
   }

   //Return status code
   return error;
}


/**
 * @brief Format Traffic Selector substructure
 * @param[in] tsParams Traffic selector parameters
 * @param[out] p Buffer where to format the Traffic Selector substructure
 * @param[out] written Length of the resulting Traffic Selector substructure
 * @return Error code
 **/

error_t ikeFormatTs(const IkeTsParams *tsParams, uint8_t *p, size_t *written)
{
   error_t error;
   IkeTs *ts;

   //Initialize status code
   error = NO_ERROR;

   //Point to the Traffic Selector substructure
   ts = (IkeTs *) p;

   //Format Traffic Selector substructure
   ts->ipProtocolId = tsParams->ipProtocolId;
   ts->startPort = htons(tsParams->startPort);
   ts->endPort = htons(tsParams->endPort);

   //Length of the substructure
   *written = sizeof(IkeTs);

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(tsParams->startAddr.length == sizeof(Ipv4Addr) &&
      tsParams->endAddr.length == sizeof(Ipv4Addr))
   {
      //Specify the type of Traffic Selector
      ts->tsType = IKE_TS_TYPE_IPV4_ADDR_RANGE;

      //A range of IPv4 addresses is represented by two four-octet values
      ipv4CopyAddr(ts->startAddr, &tsParams->startAddr.ipv4Addr);
      ipv4CopyAddr(ts->startAddr + sizeof(Ipv4Addr), &tsParams->endAddr.ipv4Addr);

      //The length of the selector depends on the TS Type field
      *written += 2 * sizeof(Ipv4Addr);
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(tsParams->startAddr.length == sizeof(Ipv6Addr) &&
      tsParams->endAddr.length == sizeof(Ipv6Addr))
   {
      //Specify the type of Traffic Selector
      ts->tsType = IKE_TS_TYPE_IPV6_ADDR_RANGE;

      //A range of IPv6 addresses is represented by two sixteen-octet values
      ipv6CopyAddr(ts->startAddr, &tsParams->startAddr.ipv6Addr);
      ipv6CopyAddr(ts->startAddr + sizeof(Ipv6Addr), &tsParams->endAddr.ipv6Addr);

      //The length of the selector depends on the TS Type field
      *written += 2 * sizeof(Ipv6Addr);
   }
   else
#endif
   //Unknown Traffic Selector type?
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Check status code
   if(!error)
   {
      //The Selector Length field specifies the length of this Traffic Selector
      //substructure including the header
      ts->selectorLength = htons(*written);
   }

   //Return status code
   return error;
}

#endif
