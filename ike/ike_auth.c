/**
 * @file ike_auth.c
 * @brief Authentication of the IKE SA
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
#include "ike/ike_request_format.h"
#include "ike/ike_response_format.h"
#include "ike/ike_auth.h"
#include "ike/ike_sign_generate.h"
#include "ike/ike_sign_verify.h"
#include "ike/ike_key_material.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "kdf/ike_kdf.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Generate signature or MAC
 * @param[in] sa Pointer to the IKE SA
 * @param[out] authMethod Authentication method
 * @param[out] authData Pointer to the authentication data
 * @param[out] authDataLen Length of the authentication data
 * @return Error code
 **/

error_t ikeGenerateAuth(IkeSaEntry *sa, uint8_t *authMethod, uint8_t *authData,
   size_t *authDataLen)
{
   error_t error;
   size_t n;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Check whether the entity is the original initiator of the IKE SA
   if(sa->originalInitiator)
   {
      //Format the first message (IKE_SA_INIT request)
      error = ikeFormatIkeSaInitRequest(sa, context->message, &n);

      //Check status code
      if(!error)
      {
         //The octets to be signed start with the first octet of the first SPI
         //in the header of the IKE_SA_INIT request and end with the last octet
         //of the last payload (refer to RFC 7296, section 2.15)
         sa->initiatorSaInit = context->message;
         sa->initiatorSaInitLen = n;
      }
   }
   else
   {
      //Format the second message (IKE_SA_INIT response)
      error = ikeFormatIkeSaInitResponse(sa, context->message, &n);

      //Check status code
      if(!error)
      {
         //The octets to be signed start with the first octet of the first SPI
         //in the header of the IKE_SA_INIT response and end with the last octet
         //of the last payload (refer to RFC 7296, section 2.15)
         sa->responderSaInit = context->message;
         sa->responderSaInitLen = n;
      }
   }

   //Check status code
   if(!error)
   {
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Certificate authentication?
      if(context->authMethod == IPSEC_AUTH_METHOD_CERT)
      {
         //Compute the signature using the entity's private key
         error = ikeGenerateSignature(sa, authMethod, authData, authDataLen);
      }
      else
#endif
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
      //Pre-shared key authentication?
      if(context->authMethod == IPSEC_AUTH_METHOD_PSK)
      {
         //Set authentication method
         *authMethod = IKE_AUTH_METHOD_SHARED_KEY;

         //Compute the MAC authentication code using the shared key
         error = ikeComputeMacAuth(sa, context->psk, context->pskLen,
            &context->id, authData, sa->originalInitiator);

         //Check status code
         if(!error)
         {
            //Length of the resulting MAC authentication code
            *authDataLen = sa->prfKeyLen;
         }
      }
      else
#endif
#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
      //EAP-based authentication?
      if(context->authMethod == IPSEC_AUTH_METHOD_EAP)
      {
         size_t sharedKeyLen;
         const uint8_t *sharedKey;

         //Set authentication method
         *authMethod = IKE_AUTH_METHOD_SHARED_KEY;

         //Key-generating EAP method?
         if(sa->mskLen > 0)
         {
            //If the EAP method is key-generating, substitute master session key
            //for the shared secret in the computation (refer to RFC 7296,
            //section 2.15)
            sharedKey = sa->msk;
            sharedKeyLen = sa->mskLen;
         }
         else
         {
            //For non-key-generating methods, the initiator computes its AUTH
            //payload with SK_pi, whereas the responder computes its AUTH
            //payload with SK_pr
            sharedKey = sa->originalInitiator ? sa->skpi : sa->skpr;
            sharedKeyLen = sa->prfKeyLen;
         }

         //Compute the MAC authentication code using the shared key
         error = ikeComputeMacAuth(sa, sharedKey, sharedKeyLen, &context->id,
            authData, sa->originalInitiator);

         //Check status code
         if(!error)
         {
            //Length of the resulting MAC authentication code
            *authDataLen = sa->prfKeyLen;
         }
      }
      else
#endif
      //Invalid authentication method?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Verify signature or MAC
 * @param[in] sa Pointer to the IKE SA
 * @param[in] authMethod Authentication method
 * @param[in] authData Pointer to the authentication data
 * @param[in] authDataLen Length of the authentication data
 * @param[in] certData Pointer to the peer's certificate
 * @param[in] certDataLen Length of the peer's certificate
 * @return Error code
 **/

error_t ikeVerifyAuth(IkeSaEntry *sa, uint8_t authMethod,
   const uint8_t *authData, size_t authDataLen, const uint8_t *certData,
   size_t certDataLen)
{
   error_t error;
   IkeContext *context;
   IpsecPadEntry *padEntry;

   //Initialize status code
   error = ERROR_AUTHENTICATION_FAILED;

   //Point to the IKE context
   context = sa->context;

#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
   //EAP-based authentication?
   if(context->authMethod == IPSEC_AUTH_METHOD_EAP &&
      sa->eapState == IKE_EAP_STATE_SUCCESS)
   {
      //Check authentication method
      if(authMethod == IKE_AUTH_METHOD_SHARED_KEY)
      {
         size_t sharedKeyLen;
         const uint8_t *sharedKey;
         uint8_t mac[IKE_MAX_DIGEST_SIZE];

         //Check the length of the MAC authentication code
         if(authDataLen == sa->prfKeyLen)
         {
            //Key-generating EAP method?
            if(sa->mskLen > 0)
            {
               //If the EAP method is key-generating, substitute master session
               //key for the shared secret in the computation (refer to
               //RFC 7296, section 2.15)
               sharedKey = sa->msk;
               sharedKeyLen = sa->mskLen;
            }
            else
            {
               //For non-key-generating methods, the initiator computes its AUTH
               //payload with SK_pi, whereas the responder computes its AUTH
               //payload with SK_pr. The peer's AUTH payload is verified, hence
               //the keys are swapped
               sharedKey = sa->originalInitiator ? sa->skpr : sa->skpi;
               sharedKeyLen = sa->prfKeyLen;
            }

            //Compute the MAC authentication code using the shared key
            error = ikeComputeMacAuth(sa, sharedKey, sharedKeyLen, &sa->peerId,
               mac, !sa->originalInitiator);

            //Check status code
            if(!error)
            {
               //Check the MAC authentication code against the calculated value
               if(cryptoCompMem(authData, mac, sa->prfKeyLen) != 0)
               {
                  error = ERROR_AUTHENTICATION_FAILED;
               }
            }
         }
      }
   }
   else
#endif
   {
      //Perform lookup in the PAD database based on the ID
      padEntry = ipsecFindPadEntry(context->netContext->ipsecContext,
         sa->peerId.type, sa->peerId.data, sa->peerId.length);

      //Matching PAD entry found?
      if(padEntry != NULL)
      {
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
         //Certificate authentication?
         if(padEntry->authMethod == IPSEC_AUTH_METHOD_CERT)
         {
            //Check authentication method
            if(authMethod == IKE_AUTH_METHOD_RSA ||
               authMethod == IKE_AUTH_METHOD_DSS ||
               authMethod == IKE_AUTH_METHOD_ECDSA_P256_SHA256 ||
               authMethod == IKE_AUTH_METHOD_ECDSA_P384_SHA384 ||
               authMethod == IKE_AUTH_METHOD_ECDSA_P521_SHA512 ||
               authMethod == IKE_AUTH_METHOD_DIGITAL_SIGN)
            {
               X509CertInfo *certInfo;

               //Allocate a memory buffer to store X.509 certificate info
               certInfo = ikeAllocMem(sizeof(X509CertInfo));

               //Successful memory allocation?
               if(certInfo != NULL)
               {
                  //Parse the DER-encoded X.509 certificate
                  error = x509ParseCertificate(certData, certDataLen, certInfo);

                  //Check status code
                  if(!error)
                  {
                     //Check whether the signature is correct
                     error = ikeVerifySignature(sa, authMethod,
                        &certInfo->tbsCert.subjectPublicKeyInfo, authData,
                        authDataLen);
                  }

                  //Free previously allocated memory
                  ikeFreeMem(certInfo);
               }
               else
               {
                  //Failed to allocate memory
                  error = ERROR_OUT_OF_MEMORY;
               }
            }
         }
         else
#endif
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
         //Pre-shared key authentication?
         if(padEntry->authMethod == IPSEC_AUTH_METHOD_PSK)
         {
            //Check authentication method
            if(authMethod == IKE_AUTH_METHOD_SHARED_KEY)
            {
               uint8_t mac[IKE_MAX_DIGEST_SIZE];

               //Check the length of the MAC authentication code
               if(authDataLen == sa->prfKeyLen)
               {
                  //Compute the MAC authentication code using the shared key
                  error = ikeComputeMacAuth(sa, padEntry->authData.psk,
                     padEntry->authData.pskLen, &sa->peerId, mac,
                     !sa->originalInitiator);

                  //Check status code
                  if(!error)
                  {
                     //Check the MAC authentication code against the calculated
                     //value
                     if(cryptoCompMem(authData, mac, sa->prfKeyLen) != 0)
                     {
                        error = ERROR_AUTHENTICATION_FAILED;
                     }
                  }
               }
            }
         }
         else
#endif
         //Invalid authentication method?
         {
            //Just for sanity
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Compute MAC authentication data
 * @param[in] sa Pointer to the IKE SA
 * @param[in] key Pre-shared key
 * @param[in] keyLen Length of the pre-shared key
 * @param[in] id Identification data
 * @param[out] mac MAC authentication data
 * @param[in] initiator Specifies whether the operation is performed at
 *   initiator or responder side
 * @return Error code
 **/

error_t ikeComputeMacAuth(IkeSaEntry *sa, const uint8_t *key, size_t keyLen,
   const IkeId *id, uint8_t *mac, bool_t initiator)
{
#if (IKE_PSK_AUTH_SUPPORT == ENABLED || IKE_EAP_AUTH_SUPPORT == ENABLED)
   error_t error;
   uint8_t macId[IKE_MAX_DIGEST_SIZE];
   uint8_t macKey[IKE_MAX_DIGEST_SIZE];
   DataFrag dataFrags[3];

   //Derive the shared secret from the password
   error = ikePrf(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo, key,
      keyLen, "Key Pad for IKEv2", 17, macKey);

   //Check status code
   if(!error)
   {
      //Let ID' = IDType | RESERVED | InitIDData
      dataFrags[0].buffer = &id->type;
      dataFrags[0].length = sizeof(id->type);
      dataFrags[1].buffer = id->reserved;
      dataFrags[1].length = sizeof(id->reserved);
      dataFrags[2].buffer = id->data;
      dataFrags[2].length = id->length;

      //Check whether the calculation is performed at initiator side
      if(initiator)
      {
         //Compute prf(SK_pi, IDi')
         error = ikePrfEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
            sa->skpi, sa->prfKeyLen, dataFrags, arraysize(dataFrags), macId);

         //Check status code
         if(!error)
         {
            //The initiator signs the first message (IKE_SA_INIT request),
            //starting with the first octet of the first SPI in the header and
            //ending with the last octet of the last payload. Appended to this
            //(for purposes of computing the signature) are the responder's
            //nonce Nr, and the value prf(SK_pi, IDi')
            dataFrags[0].buffer = sa->initiatorSaInit;
            dataFrags[0].length = sa->initiatorSaInitLen;
            dataFrags[1].buffer = sa->responderNonce;
            dataFrags[1].length = sa->responderNonceLen;
            dataFrags[2].buffer = macId;
            dataFrags[2].length = sa->prfKeyLen;

            //Compute the AUTH value
            error = ikePrfEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
               macKey, sa->prfKeyLen, dataFrags, arraysize(dataFrags), mac);
         }
      }
      else
      {
         //Compute prf(SK_pr, IDr')
         error = ikePrfEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
            sa->skpr, sa->prfKeyLen, dataFrags, arraysize(dataFrags), macId);

         //Check status code
         if(!error)
         {
            //For the responder, the octets to be signed start with the first
            //octet of the first SPI in the header of the second message
            //(IKE_SA_INIT response) and end with the last octet of the last
            //payload in the second message. Appended to this (for purposes of
            //computing the signature) are the initiator's nonce Ni, and the
            //value prf(SK_pr, IDr')
            dataFrags[0].buffer = sa->responderSaInit;
            dataFrags[0].length = sa->responderSaInitLen;
            dataFrags[1].buffer = sa->initiatorNonce;
            dataFrags[1].length = sa->initiatorNonceLen;
            dataFrags[2].buffer = macId;
            dataFrags[2].length = sa->prfKeyLen;

            //Compute the AUTH value
            error = ikePrfEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
               macKey, sa->prfKeyLen, dataFrags, arraysize(dataFrags), mac);
         }
      }
   }

   //Erase working state
   cryptoZeroizeMem(macKey, sizeof(macKey));

   //Return status code
   return error;
#else
   //Pre-shared key authentication is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
