/**
 * @file ike_auth.c
 * @brief Authentication of the IKE SA
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
#include "ike/ike_auth.h"
#include "ike/ike_sign_generate.h"
#include "ike/ike_sign_verify.h"
#include "ike/ike_key_material.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Generate signature or MAC
 * @param[in] sa Pointer to the IKE SA
 * @param[in] idPayload Pointer to the Identification payload
 * @param[out] authMethod Authentication method
 * @param[out] authData Pointer to the authentication data
 * @param[out] authDataLen Length of the authentication data
 * @return Error code
 **/

error_t ikeGenerateAuth(IkeSaEntry *sa, const IkeIdPayload *idPayload,
   uint8_t *authMethod, uint8_t *authData, size_t *authDataLen)
{
   error_t error;
   size_t idLen;
   const uint8_t *id;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Retrieve the length of the Identification payload
   idLen = ntohs(idPayload->header.payloadLength);

   //Check the length of the payload
   if(idLen >= sizeof(IkePayloadHeader))
   {
      //Point to the RestOfInitIDPayload field
      id = (uint8_t *) idPayload + sizeof(IkePayloadHeader);
      idLen -= sizeof(IkePayloadHeader);

#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Certificate authentication?
      if(context->certChain != NULL && context->certChainLen > 0)
      {
         //Compute the signature using the entity's private key
         error = ikeGenerateSignature(sa, id, idLen, authMethod, authData,
            authDataLen);
      }
      else
#endif
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
      //Pre-shared key authentication?
      if(context->pskLen > 0)
      {
         //Set authentication method
         *authMethod = IKE_AUTH_METHOD_SHARED_KEY;

         //Compute the MAC authentication code using the shared key
         error = ikeComputeMacAuth(sa, context->psk, context->pskLen, id,
            idLen, authData, sa->originalInitiator);

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
   else
   {
      //Malformed payload
      error = ERROR_INVALID_MESSAGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Verify signature or MAC
 * @param[in] sa Pointer to the IKE SA
 * @param[in] padEntry Pointer to the PAD entry
 * @param[in] idPayload Pointer to the Identification payload
 * @param[in] certPayload Pointer to the Certificate payload
 * @param[out] authPayload Pointer to the Authentication payload
 * @return Error code
 **/

error_t ikeVerifyAuth(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const IkeIdPayload *idPayload, const IkeCertPayload *certPayload,
   const IkeAuthPayload *authPayload)
{
   error_t error;
   uint8_t authMethod;
   size_t idLen;
   size_t authDataLen;
   const uint8_t *id;
   const uint8_t *authData;

   //Retrieve the length of the Identification payload
   idLen = ntohs(idPayload->header.payloadLength);
   //Retrieve the length of the Authentication payload
   authDataLen = ntohs(authPayload->header.payloadLength);

   //Check the length of the payloads
   if(idLen >= sizeof(IkePayloadHeader) &&
      authDataLen >= sizeof(IkeAuthPayload))
   {
      //Point to the RestOfInitIDPayload field
      id = (uint8_t *) idPayload + sizeof(IkePayloadHeader);
      idLen -= sizeof(IkePayloadHeader);

      //Point to the Authentication Data field
      authData = authPayload->authData;
      authDataLen -= sizeof(IkeAuthPayload);

      //Retrieve the authentication method used
      authMethod = authPayload->authMethod;

#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Certificate authentication?
      if(authMethod == IKE_AUTH_METHOD_RSA ||
         authMethod == IKE_AUTH_METHOD_DSS ||
         authMethod == IKE_AUTH_METHOD_ECDSA_P256_SHA256 ||
         authMethod == IKE_AUTH_METHOD_ECDSA_P384_SHA384 ||
         authMethod == IKE_AUTH_METHOD_ECDSA_P521_SHA512 ||
         authMethod == IKE_AUTH_METHOD_DIGITAL_SIGN)
      {
         size_t certDataLen;
         X509CertInfo *certInfo;

         //The first CERT payload holds the public key used to validate the
         //sender's AUTH payload (refer to RFC7296, section 3.6)
         if(certPayload != NULL)
         {
            //Retrieve the length of the CERT payload
            certDataLen = ntohs(certPayload->header.payloadLength);

            //Check the length of the payload
            if(certDataLen >= sizeof(IkeCertPayload))
            {
               //Determine the length of the Certificate Data field
               certDataLen -= sizeof(IkeCertPayload);

               //Allocate a memory buffer to store X.509 certificate info
               certInfo = ikeAllocMem(sizeof(X509CertInfo));

               //Successful memory allocation?
               if(certInfo != NULL)
               {
                  //Parse the DER-encoded X.509 certificate
                  error = x509ParseCertificate(certPayload->certData,
                     certDataLen, certInfo);

                  //Check status code
                  if(!error)
                  {
                     //Display ASN.1 structure
                     error = asn1DumpObject(certPayload->certData,
                        certDataLen, 0);
                  }

                  //Check status code
                  if(!error)
                  {
                     //Check whether the signature is correct
                     error = ikeVerifySignature(sa, id, idLen, authMethod,
                        &certInfo->tbsCert.subjectPublicKeyInfo, authData,
                        authDataLen);
                  }
               }
               else
               {
                  //Failed to allocate memory
                  error = ERROR_OUT_OF_MEMORY;
               }
            }
            else
            {
               //Malformed payload
               error = ERROR_INVALID_MESSAGE;
            }
         }
         else
         {
            //The AUTH payload is not present
            error = ERROR_INVALID_MESSAGE;
         }
      }
      else
#endif
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
      //Pre-shared key authentication?
      if(authMethod == IKE_AUTH_METHOD_SHARED_KEY)
      {
         uint8_t mac[IKE_MAX_DIGEST_SIZE];

         //The CERT payload must not be included
         if(certPayload == NULL)
         {
            //Check the length of the MAC authentication code
            if(authDataLen == sa->prfKeyLen)
            {
               //Compute the MAC authentication code using the shared key
               error = ikeComputeMacAuth(sa, padEntry->psk, padEntry->pskLen, id,
                  idLen, mac, !sa->originalInitiator);

               //Check status code
               if(!error)
               {
                  //Check the MAC authentication code against the calculated value
                  if(osMemcmp(mac, authData, authDataLen) != 0)
                  {
                     error = ERROR_AUTHENTICATION_FAILED;
                  }
               }
            }
            else
            {
               //The length of the MAC authentication code is not valid
               error = ERROR_AUTHENTICATION_FAILED;
            }
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_MESSAGE;
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
   else
   {
      //Malformed payload
      error = ERROR_INVALID_MESSAGE;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute MAC authentication data
 * @param[in] sa Pointer to the IKE SA
 * @param[in] key Pre-shared key
 * @param[in] keyLen Length of the pre-shared key
 * @param[in] id MAC authentication data
 * @param[in] idLen MAC authentication data
 * @param[out] mac MAC authentication data
 * @param[in] initiator Specifies whether the computation is performed at
 *   initiator or responder side
 * @return Error code
 **/

error_t ikeComputeMacAuth(IkeSaEntry *sa, const uint8_t *key, size_t keyLen,
   const uint8_t *id, size_t idLen, uint8_t *mac, bool_t initiator)
{
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
   error_t error;
   uint8_t macId[IKE_MAX_DIGEST_SIZE];
   uint8_t macKey[IKE_MAX_DIGEST_SIZE];

   //Derive the shared secret from the password
   error = ikeComputePrf(sa, key, keyLen, "Key Pad for IKEv2", 17, macKey);

   //Check whether the calculation is performed at initiator side
   if(initiator)
   {
      //Check status code
      if(!error)
      {
         //Compute prf(SK_pi, IDi')
         error = ikeComputePrf(sa, sa->skpi, sa->prfKeyLen, id, idLen, macId);
      }

      //Check status code
      if(!error)
      {
         //Initialize PRF calculation
         error = ikeInitPrf(sa, macKey, sa->prfKeyLen);
      }

      //Check status code
      if(!error)
      {
         //The initiator signs the first message (IKE_SA_INIT request), starting
         //with the first octet of the first SPI in the header and ending with
         //the last octet of the last payload
         ikeUpdatePrf(sa, sa->initiatorSaInit, sa->initiatorSaInitLen);

         //Appended to this (for purposes of computing the signature) are the
         //responder's nonce Nr, and the value prf(SK_pi, IDi')
         ikeUpdatePrf(sa, sa->responderNonce, sa->responderNonceLen);
         ikeUpdatePrf(sa, macId, sa->prfKeyLen);

         //Finalize PRF calculation
         error = ikeFinalizePrf(sa, mac);
      }
   }
   else
   {
      //Check status code
      if(!error)
      {
         //Compute prf(SK_pr, IDr')
         error = ikeComputePrf(sa, sa->skpr, sa->prfKeyLen, id, idLen, macId);
      }

      //Check status code
      if(!error)
      {
         //Initialize PRF calculation
         error = ikeInitPrf(sa, macKey, sa->prfKeyLen);
      }

      //Check status code
      if(!error)
      {
         //For the responder, the octets to be signed start with the first octet
         //of the first SPI in the header of the second message (IKE_SA_INIT
         //response) and end with the last octet of the last payload in the
         //second message
         ikeUpdatePrf(sa, sa->responderSaInit, sa->responderSaInitLen);

         //Appended to this (for purposes of computing the signature) are the
         //initiator's nonce Ni, and the value prf(SK_pr, IDr')
         ikeUpdatePrf(sa, sa->initiatorNonce, sa->initiatorNonceLen);
         ikeUpdatePrf(sa, macId, sa->prfKeyLen);

         //Finalize PRF calculation
         error = ikeFinalizePrf(sa, mac);
      }
   }

   //Return status code
   return error;
#else
   //Pre-shared key authentication is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
