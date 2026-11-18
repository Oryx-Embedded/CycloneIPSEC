/**
 * @file ike_key_material.c
 * @brief Key material generation
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
#include "ike/ike_key_material.h"
#include "ike/ike_algorithms.h"
#include "ah/ah_algorithms.h"
#include "esp/esp_algorithms.h"
#include "kdf/ike_kdf.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Generate keying material for the IKE SA
 * @param[in] sa Pointer to the IKE SA
 * @param[in] oldSa Pointer to the old IKE SA
 * @return Error code
 **/

error_t ikeGenerateSaKeyMaterial(IkeSaEntry *sa, IkeSaEntry *oldSa)
{
   error_t error;
   size_t keyMaterialLen;
   IkeContext *context;
   uint8_t skeyseed[IKE_MAX_DIGEST_SIZE];
   DataFrag dataFrags[4];

   //Initialize variable
   keyMaterialLen = 0;

   //Point to the IKE context
   context = sa->context;

   //Select the relevant PRF algorithm
   error = ikeSelectPrfAlgo(sa, sa->prfAlgoId);

   //Check status code
   if(!error)
   {
      //Select the relevant encryption algorithm
      error = ikeSelectEncAlgo(sa, sa->encAlgoId, sa->encKeyLen);
   }

   //Check status code
   if(!error)
   {
      //AEAD encryption algorithm?
      if(ikeIsAeadEncAlgo(sa->encAlgoId))
      {
         //When an authenticated encryption algorithm is selected as the
         //encryption algorithm for any IKE SA, an integrity algorithm must not
         //be selected for that SA (refer to RFC 5282, section 8)
         sa->authMacAlgo = MAC_ALGO_NONE;
         sa->authHashAlgo = NULL;
         sa->authCipherAlgo = NULL;
      }
      else
      {
         //Select the relevant MAC algorithm
         error = ikeSelectAuthAlgo(sa, sa->authAlgoId);
      }
   }

   //Check status code
   if(!error)
   {
      //Length of necessary keying material
      keyMaterialLen = 2 * sa->authKeyLen + 2 * (sa->encKeyLen + sa->saltLen) +
         3 * sa->prfKeyLen;

      //Make sure that the buffer is large enough
      if(keyMaterialLen > IKE_MAX_SA_KEY_MAT_LEN)
      {
         error = ERROR_FAILURE;
      }
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("Generating IKE SA keying material...\r\n");
      TRACE_DEBUG("  Nonce (initiator):\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->initiatorNonce, sa->initiatorNonceLen);
      TRACE_DEBUG("  Nonce (responder):\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->responderNonce, sa->responderNonceLen);
      TRACE_DEBUG("  Shared secret:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->sharedSecret, sa->sharedSecretLen);

      //IKE SA rekeying?
      if(oldSa != NULL)
      {
         //Debug message
         TRACE_DEBUG("  SK_d (old):\r\n");
         TRACE_DEBUG_ARRAY("    ", oldSa->skd, oldSa->prfKeyLen);

         //Concatenate g^ir (new), Ni and Nr
         dataFrags[0].buffer = sa->sharedSecret;
         dataFrags[0].length = sa->sharedSecretLen;
         dataFrags[1].buffer = sa->initiatorNonce;
         dataFrags[1].length = sa->initiatorNonceLen;
         dataFrags[2].buffer = sa->responderNonce;
         dataFrags[2].length = sa->responderNonceLen;

         //Calculate SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
         error = ikePrfEx(oldSa->prfMacAlgo, oldSa->prfHashAlgo,
            oldSa->prfCipherAlgo, oldSa->skd, oldSa->prfKeyLen, dataFrags, 3,
            skeyseed);
      }
      else
      {
         size_t bufferLen;
         uint8_t buffer[2 * IKE_MAX_NONCE_SIZE];

         //For historical backward-compatibility reasons, there are two PRFs
         //that are treated specially in this calculation
         if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC ||
            sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC)
         {
            //If the negotiated PRF is AES-XCBC-PRF-128 or AES-CMAC-PRF-128,
            //only the first 64 bits of Ni and the first 64 bits of Nr are used
            //in calculating SKEYSEED (refer to RFC 7296, section 2.14)
            osMemcpy(buffer, sa->initiatorNonce, 8);
            bufferLen = 8;
            osMemcpy(buffer + bufferLen, sa->responderNonce, 8);
            bufferLen += 8;
         }
         else
         {
            //Concatenate Ni and Nr
            osMemcpy(buffer, sa->initiatorNonce, sa->initiatorNonceLen);
            bufferLen = sa->initiatorNonceLen;
            osMemcpy(buffer + bufferLen, sa->responderNonce, sa->responderNonceLen);
            bufferLen += sa->responderNonceLen;
         }

         //Each party generates a quantity called SKEYSEED = prf(Ni | Nr, g^ir)
         error = ikePrf(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
            buffer, bufferLen, sa->sharedSecret, sa->sharedSecretLen, skeyseed);
      }

      //Any shared secret derived from key establishment must be destroyed
      //immediately after its use (refer to RFC 9206, section 10)
      cryptoZeroizeMem(sa->sharedSecret, IKE_MAX_SHARED_SECRET_LEN);
      sa->sharedSecretLen = 0;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  SKEYSEED:\r\n");
      TRACE_DEBUG_ARRAY("    ", skeyseed, sa->prfKeyLen);

      //Concatenate Ni, Nr, SPIi and SPIr
      dataFrags[0].buffer = sa->initiatorNonce;
      dataFrags[0].length = sa->initiatorNonceLen;
      dataFrags[1].buffer = sa->responderNonce;
      dataFrags[1].length = sa->responderNonceLen;
      dataFrags[2].buffer = sa->initiatorSpi;
      dataFrags[2].length = IKE_SPI_SIZE;
      dataFrags[3].buffer = sa->responderSpi;
      dataFrags[3].length = IKE_SPI_SIZE;

      //SKEYSEED is used to calculate seven other secrets (refer to RFC 7296,
      //section 2.14)
      error = ikePrfPlusEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
         skeyseed, sa->prfKeyLen, dataFrags, 4, sa->keyMaterial,
         keyMaterialLen);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  Keying material:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->keyMaterial, keyMaterialLen);

      //SK_d is used for deriving new keys for the Child SAs established with
      //this IKE SA
      sa->skd = sa->keyMaterial;

      //SK_ai and SK_ar used as a key to the integrity protection algorithm
      //for authenticating the component messages of subsequent exchanges
      sa->skai = sa->skd + sa->prfKeyLen;
      sa->skar = sa->skai + sa->authKeyLen;

      //SK_ei and SK_er are used for encrypting and decrypting all subsequent
      //exchanges
      sa->skei = sa->skar + sa->authKeyLen;
      sa->sker = sa->skei + sa->encKeyLen + sa->saltLen;

      //SK_pi and SK_pr are used when generating an AUTH payload
      sa->skpi = sa->sker + sa->encKeyLen + sa->saltLen;
      sa->skpr = sa->skpi + sa->prfKeyLen;

      //Debug message
      TRACE_DEBUG("  SK_d:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skd, sa->prfKeyLen);
      TRACE_DEBUG("  SK_ai:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skai, sa->authKeyLen);
      TRACE_DEBUG("  SK_ar:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skar, sa->authKeyLen);
      TRACE_DEBUG("  SK_ei:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skei, sa->encKeyLen + sa->saltLen);
      TRACE_DEBUG("  SK_er:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->sker, sa->encKeyLen + sa->saltLen);
      TRACE_DEBUG("  SK_pi:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skpi, sa->prfKeyLen);
      TRACE_DEBUG("  SK_pr:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skpr, sa->prfKeyLen);

      //Check encryption mode
      if(sa->cipherMode != CIPHER_MODE_CBC)
      {
         //The IV must be chosen by the encryptor in a manner that ensures that
         //the same IV value is used only once for a given key (refer to
         //RFC 5282, section 3.1)
         error = context->prngAlgo->generate(context->prngContext, sa->iv, 8);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  IV:\r\n");
            TRACE_DEBUG_ARRAY("    ", sa->iv, 8);
         }
      }
   }

   //Erase working state
   cryptoZeroizeMem(skeyseed, sizeof(skeyseed));

   //Return status code
   return error;
}


/**
 * @brief Generate keying material for the Child SA
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeGenerateChildSaKeyMaterial(IkeChildSaEntry *childSa)
{
   error_t error;
   uint_t n;
   size_t keyMaterialLen;
   IkeSaEntry *sa;
   DataFrag dataFrags[3];

   //Initialize variable
   keyMaterialLen = 0;

   //Point to the IKE SA
   sa = childSa->sa;

#if (AH_SUPPORT == ENABLED)
   //AH protocol?
   if(childSa->protocol == IPSEC_PROTOCOL_AH)
   {
      //AH does not provide confidentiality (encryption) service
      childSa->cipherAlgo = NULL;
      childSa->cipherMode = CIPHER_MODE_NULL;
      childSa->encKeyLen = 0;
      childSa->saltLen = 0;
      childSa->ivLen = 0;

      //Select the relevant MAC algorithm
      error = ahSelectAuthAlgo(childSa, childSa->authAlgoId);
   }
   else
#endif
#if (ESP_SUPPORT == ENABLED)
   //ESP protocol?
   if(childSa->protocol == IPSEC_PROTOCOL_ESP)
   {
      //Select the relevant encryption algorithm
      error = espSelectEncAlgo(childSa, childSa->encAlgoId, childSa->encKeyLen);

      //Check status code
      if(!error)
      {
         //AEAD encryption algorithm?
         if(ikeIsAeadEncAlgo(childSa->encAlgoId))
         {
            //When an authenticated encryption algorithm is selected as the
            //encryption algorithm for any IKE SA, an integrity algorithm must
            //not be selected for that SA (refer to RFC 5282, section 8)
            childSa->authMacAlgo = MAC_ALGO_NONE;
            childSa->authHashAlgo = NULL;
            childSa->authCipherAlgo = NULL;
         }
         else
         {
            //Select the relevant MAC algorithm
            error = espSelectAuthAlgo(childSa, childSa->authAlgoId);
         }
      }
   }
   else
#endif
   //Invalid IPsec protocol?
   {
      //Report an error
      error = ERROR_INVALID_PROTOCOL;
   }

   //Check status code
   if(!error)
   {
      //Length of necessary keying material
      keyMaterialLen = 2 * childSa->authKeyLen + 2 * (childSa->encKeyLen +
         childSa->saltLen);

      //Make sure that the buffer is large enough
      if(keyMaterialLen > IKE_MAX_CHILD_SA_KEY_MAT_LEN)
      {
         error = ERROR_FAILURE;
      }
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("Generating Child SA keying material...\r\n");
      TRACE_DEBUG("  SK_d:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->skd, sa->prfKeyLen);
      TRACE_DEBUG("  Nonce (initiator):\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->initiatorNonce, childSa->initiatorNonceLen);
      TRACE_DEBUG("  Nonce (responder):\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->responderNonce, childSa->responderNonceLen);

      //Concatenate g^ir (new), Ni and Nr
      n = 0;

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      //Perfect forward secrecy?
      if(childSa->pfs)
      {
         //g^ir (new) is the shared secret from the ephemeral Diffie-Hellman
         //exchange of this CREATE_CHILD_SA exchange
         dataFrags[n].buffer = childSa->sharedSecret;
         dataFrags[n++].length = childSa->sharedSecretLen;
      }
#endif

      //Ni and Nr are the nonces from the IKE_SA_INIT exchange if this request
      //is the first Child SA created or the fresh Ni and Nr from the
      //CREATE_CHILD_SA exchange if this is a subsequent creation (refer to
      //RFC 7296, section 2.17)
      dataFrags[n].buffer = childSa->initiatorNonce;
      dataFrags[n++].length = childSa->initiatorNonceLen;
      dataFrags[n].buffer = childSa->responderNonce;
      dataFrags[n++].length = childSa->responderNonceLen;

      //Calculate KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)
      error = ikePrfPlusEx(sa->prfMacAlgo, sa->prfHashAlgo, sa->prfCipherAlgo,
         sa->skd, sa->prfKeyLen, dataFrags, n, childSa->keyMaterial,
         keyMaterialLen);

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      //Any shared secret derived from key establishment must be destroyed
      //immediately after its use (refer to RFC 9206, section 10)
      cryptoZeroizeMem(childSa->sharedSecret, IKE_MAX_SHARED_SECRET_LEN);
      childSa->sharedSecretLen = 0;
#endif
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("  Keying material:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->keyMaterial, keyMaterialLen);

      //All keys for SAs carrying data from the initiator to the responder are
      //taken before SAs going from the responder to the initiator. the
      //encryption key must be taken from the first bits and the integrity key
      //must be taken from the remaining bits (refer to RFC 7296, section 2.17)
      childSa->skei = childSa->keyMaterial;
      childSa->skai = childSa->skei + childSa->encKeyLen + childSa->saltLen;
      childSa->sker = childSa->skai + childSa->authKeyLen;
      childSa->skar = childSa->sker + childSa->encKeyLen + childSa->saltLen;

      //Debug message
      TRACE_DEBUG("  SK_ei:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->skei, childSa->encKeyLen + childSa->saltLen);
      TRACE_DEBUG("  SK_ai:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->skai, childSa->authKeyLen);
      TRACE_DEBUG("  SK_er:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->sker, childSa->encKeyLen + childSa->saltLen);
      TRACE_DEBUG("  SK_ar:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->skar, childSa->authKeyLen);

#if (ESP_SUPPORT == ENABLED)
      //Check ESP encryption mode
      if(childSa->protocol == IPSEC_PROTOCOL_ESP &&
         childSa->cipherMode != CIPHER_MODE_CBC)
      {
         IkeContext *context;

         //Point to the IKE context
         context = childSa->context;

         //The IV must be chosen by the encryptor in a manner that ensures that
         //the same IV value is used only once for a given key
         error = context->prngAlgo->generate(context->prngContext,
            childSa->iv, 8);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("  IV:\r\n");
            TRACE_DEBUG_ARRAY("    ", childSa->iv, 8);
         }
      }
#endif
   }

   //Return status code
   return error;
}

#endif
