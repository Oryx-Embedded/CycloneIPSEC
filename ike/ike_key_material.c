/**
 * @file ike_key_material.c
 * @brief Key material generation
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
#include "ike/ike_key_material.h"
#include "ike/ike_algorithms.h"
#include "ah/ah_algorithms.h"
#include "esp/esp_algorithms.h"
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
   size_t bufferLen;
   size_t keyMaterialLen;
   IkeContext *context;
   uint8_t skeyseed[IKE_MAX_DIGEST_SIZE];
   uint8_t buffer[2 * IKE_MAX_NONCE_SIZE + 2 * IKE_SPI_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Select the relevant PRF algorithm
   error = ikeSelectPrfAlgo(sa, sa->prfAlgoId);
   //Any error to report?
   if(error)
      return error;

   //Select the relevant encryption algorithm
   error = ikeSelectEncAlgo(sa, sa->encAlgoId, sa->encKeyLen);
   //Any error to report?
   if(error)
      return error;

   //AEAD encryption algorithm?
   if(ikeIsAeadEncAlgo(sa->encAlgoId))
   {
      //When an authenticated encryption algorithm is selected as the encryption
      //algorithm for any IKE SA, an integrity algorithm must not be selected
      //for that SA (refer to RFC 5282, section 8)
      sa->authHashAlgo = NULL;
      sa->authCipherAlgo = NULL;
   }
   else
   {
      //Select the relevant MAC algorithm
      error = ikeSelectAuthAlgo(sa, sa->authAlgoId);
      //Any error to report?
      if(error)
         return error;
   }

   //Length of necessary keying material
   keyMaterialLen = 2 * sa->authKeyLen + 2 * (sa->encKeyLen + sa->saltLen) +
      3 * sa->prfKeyLen;

   //Make sure that the buffer is large enough
   if(keyMaterialLen > IKE_MAX_SA_KEY_MAT_LEN)
      return ERROR_FAILURE;

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

      //Concatenate Ni and Nr
      osMemcpy(buffer, sa->initiatorNonce, sa->initiatorNonceLen);
      bufferLen = sa->initiatorNonceLen;
      osMemcpy(buffer + bufferLen, sa->responderNonce, sa->responderNonceLen);
      bufferLen += sa->responderNonceLen;

      //SKEYSEED for the new IKE SA is computed using SK_d from the existing
      //IKE SA (refer to RFC 7296, section 2.18)
      error = ikeInitPrf(oldSa, oldSa->skd, oldSa->prfKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Calculate SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
      ikeUpdatePrf(oldSa, sa->sharedSecret, sa->sharedSecretLen);
      ikeUpdatePrf(oldSa, buffer, bufferLen);

      //Finalize PRF calculation
      error = ikeFinalizePrf(oldSa, skeyseed);
      //Any error to report?
      if(error)
         return error;
   }
   else
   {
      //For historical backward-compatibility reasons, there are two PRFs that
      //are treated specially in this calculation
      if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC ||
         sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC)
      {
         //If the negotiated PRF is AES-XCBC-PRF-128 or AES-CMAC-PRF-128, only
         //the first 64 bits of Ni and the first 64 bits of Nr are used in
         //calculating SKEYSEED (refer to RFC 7296, section 2.14)
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
      error = ikeComputePrf(sa, buffer, bufferLen, sa->sharedSecret,
         sa->sharedSecretLen, skeyseed);
      //Any error to report?
      if(error)
         return error;
   }

   //Debug message
   TRACE_DEBUG("  SKEYSEED:\r\n");
   TRACE_DEBUG_ARRAY("    ", skeyseed, sa->prfKeyLen);

   //Concatenate Ni, Nr, SPIi and SPIr
   osMemcpy(buffer, sa->initiatorNonce, sa->initiatorNonceLen);
   bufferLen = sa->initiatorNonceLen;
   osMemcpy(buffer + bufferLen, sa->responderNonce, sa->responderNonceLen);
   bufferLen += sa->responderNonceLen;
   osMemcpy(buffer + bufferLen, sa->initiatorSpi, IKE_SPI_SIZE);
   bufferLen += IKE_SPI_SIZE;
   osMemcpy(buffer + bufferLen, sa->responderSpi, IKE_SPI_SIZE);
   bufferLen += IKE_SPI_SIZE;

   //SKEYSEED is used to calculate seven other secrets (refer to RFC 7296,
   //section 2.14)
   error = ikeComputePrfPlus(sa, skeyseed, sa->prfKeyLen, buffer, bufferLen,
      sa->keyMaterial, keyMaterialLen);
   //Any error to report?
   if(error)
      return error;

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
      //the same IV value is used only once for a given key (refer to RFC 5282,
      //section 3.1)
      error = context->prngAlgo->generate(context->prngContext, sa->iv, 8);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("  IV:\r\n");
      TRACE_DEBUG_ARRAY("    ", sa->iv, 8);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generate keying material for the Child SA
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeGenerateChildSaKeyMaterial(IkeChildSaEntry *childSa)
{
   error_t error;
   size_t bufferLen;
   size_t keyMaterialLen;
   uint8_t buffer[2 * IKE_MAX_NONCE_SIZE];
   IkeSaEntry *sa;

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
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (ESP_SUPPORT == ENABLED)
   //ESP protocol?
   if(childSa->protocol == IPSEC_PROTOCOL_ESP)
   {
      //Select the relevant encryption algorithm
      error = espSelectEncAlgo(childSa, childSa->encAlgoId, childSa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //AEAD encryption algorithm?
      if(ikeIsAeadEncAlgo(childSa->encAlgoId))
      {
         //When an authenticated encryption algorithm is selected as the
         //encryption algorithm for any IKE SA, an integrity algorithm must
         //not be selected for that SA (refer to RFC 5282, section 8)
         childSa->authHashAlgo = NULL;
         childSa->authCipherAlgo = NULL;
      }
      else
      {
         //Select the relevant MAC algorithm
         error = espSelectAuthAlgo(childSa, childSa->authAlgoId);
         //Any error to report?
         if(error)
            return error;
      }
   }
   else
#endif
   //Invalid IPsec protocol?
   {
      //Report an error
      return ERROR_INVALID_PROTOCOL;
   }

   //Length of necessary keying material
   keyMaterialLen = 2 * childSa->authKeyLen + 2 * (childSa->encKeyLen +
      childSa->saltLen);

   //Make sure that the buffer is large enough
   if(keyMaterialLen > IKE_MAX_CHILD_SA_KEY_MAT_LEN)
      return ERROR_FAILURE;

   //Debug message
   TRACE_DEBUG("Generating Child SA keying material...\r\n");
   TRACE_DEBUG("  SK_d:\r\n");
   TRACE_DEBUG_ARRAY("    ", sa->skd, sa->prfKeyLen);
   TRACE_DEBUG("  Nonce (initiator):\r\n");
   TRACE_DEBUG_ARRAY("    ", childSa->initiatorNonce, childSa->initiatorNonceLen);
   TRACE_DEBUG("  Nonce (responder):\r\n");
   TRACE_DEBUG_ARRAY("    ", childSa->responderNonce, childSa->responderNonceLen);

   //Ni and Nr are the nonces from the IKE_SA_INIT exchange if this request is
   //the first Child SA created or the fresh Ni and Nr from the CREATE_CHILD_SA
   //exchange if this is a subsequent creation (refer to RFC 7296, section 2.17)
   osMemcpy(buffer, childSa->initiatorNonce, childSa->initiatorNonceLen);
   bufferLen = childSa->initiatorNonceLen;
   osMemcpy(buffer + bufferLen, childSa->responderNonce, childSa->responderNonceLen);
   bufferLen += childSa->responderNonceLen;

   //Calculate KEYMAT = prf+(SK_d, Ni | Nr)
   error = ikeComputePrfPlus(childSa->sa, sa->skd, sa->prfKeyLen, buffer,
      bufferLen, childSa->keyMaterial, keyMaterialLen);
   //Any error to report?
   if(error)
      return error;

   //Debug message
   TRACE_DEBUG("  Keying material:\r\n");
   TRACE_DEBUG_ARRAY("    ", childSa->keyMaterial, keyMaterialLen);

   //All keys for SAs carrying data from the initiator to the responder are
   //taken before SAs going from the responder to the initiator. the encryption
   //key must be taken from the first bits and the integrity key must be taken
   //from the remaining bits (refer to RFC 7296, section 2.17)
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
      error = context->prngAlgo->generate(context->prngContext, childSa->iv, 8);
      //Any error to report?
      if(error)
         return error;

      //Debug message
      TRACE_DEBUG("  IV:\r\n");
      TRACE_DEBUG_ARRAY("    ", childSa->iv, 8);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Pseudorandom function (prf function)
 * @param[in] sa Pointer to the IKE SA
 * @param[in] k Pointer to the key
 * @param[in] kLen Length of the key, in bytes
 * @param[in] s Pointer to the data
 * @param[in] sLen Length of the data, in bytes
 * @param[in] output Pseudorandom output
 * @return Error code
 **/

error_t ikeComputePrf(IkeSaEntry *sa, const uint8_t *k, size_t kLen,
   const void *s, size_t sLen, uint8_t *output)
{
   error_t error;

   //Initialize PRF calculation
   error = ikeInitPrf(sa, k, kLen);

   //Check status code
   if(!error)
   {
      //Update PRF calculation
      ikeUpdatePrf(sa, s, sLen);

      //Finalize PRF calculation
      error = ikeFinalizePrf(sa, output);
   }

   //Return status code
   return error;
}


/**
 * @brief Function that outputs a pseudorandom stream (prf+ function)
 * @param[in] sa Pointer to the IKE SA
 * @param[in] k Pointer to the key
 * @param[in] kLen Length of the key, in bytes
 * @param[in] s Pointer to the data
 * @param[in] sLen Length of the data, in bytes
 * @param[out] output Pseudorandom output stream
 * @param[in] outputLen Desired length of the pseudorandom output stream
 * @return Error code
 **/

error_t ikeComputePrfPlus(IkeSaEntry *sa, const uint8_t *k, size_t kLen,
   const uint8_t *s, size_t sLen, uint8_t *output, size_t outputLen)
{
   error_t error;
   uint8_t c;

   //Initialize status code
   error = NO_ERROR;

   {
      size_t n;
      uint8_t t[IKE_MAX_DIGEST_SIZE];

      //Keying material will always be derived as the output of the negotiated
      //PRF algorithm.  Since the amount of keying material needed may be
      //greater than the size of the output of the PRF, the PRF is used
      //iteratively (refer to RFC 7296, section 2.13)
      for(c = 1; outputLen > 0; c++)
      {
         //Initialize PRF calculation
         error = ikeInitPrf(sa, k, kLen);
         //Any error to report?
         if(error)
            break;

         //Digest T(n-1)
         if(c > 1)
         {
            ikeUpdatePrf(sa, t, sa->prfKeyLen);
         }

         //Compute T(n) = prf(K, T(n-1) | S | c)
         ikeUpdatePrf(sa, s, sLen);
         ikeUpdatePrf(sa, &c, sizeof(uint8_t));

         //Finalize PRF calculation
         error = ikeFinalizePrf(sa, t);
         //Any error to report?
         if(error)
            break;

         //Calculate the number of bytes to copy
         n = MIN(outputLen, sa->prfKeyLen);
         //Copy the output of the PRF
         osMemcpy(output, t, n);

         //This process is repeated until enough key material is available
         output += n;
         outputLen -= n;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize PRF calculation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] vk Pointer to the variable-length key
 * @param[in] vkLen Length of the key, in bytes
 * @return Error code
 **/

error_t ikeInitPrf(IkeSaEntry *sa, const uint8_t *vk, size_t vkLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_CMAC_PRF_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC &&
      sa->prfCipherAlgo != NULL)
   {
      CmacContext *cmacContext;
      uint8_t k[16];

      //Point to the CMAC context
      cmacContext = &sa->context->cmacContext;

      //Derive the 128-bit key K from the variable-length key VK
      if(vkLen == 16)
      {
         //If the key VK is exactly 128 bits, then we use it as-is
         osMemcpy(k, vk, vkLen);
      }
      else
      {
         //If the key VK is longer or shorter than 128 bits, then we derive the
         //key K by applying the AES-CMAC algorithm using the 128-bit all-zero
         //string as the key and VK as the input message (refer to RFC 4615,
         //section 3)
         osMemset(k, 0, 16);

         //Initialize CMAC calculation
         error = cmacInit(cmacContext, sa->prfCipherAlgo, k, 16);

         //Check status code
         if(!error)
         {
            //Compute K = AES-CMAC(0^128, VK, VKlen)
            cmacUpdate(cmacContext, vk, vkLen);

            //Derive the 128-bit key K
            error = cmacFinal(cmacContext, k, 16);
         }
      }

      //Check status code
      if(!error)
      {
         //We apply the AES-CMAC algorithm using K as the key
         error = cmacInit(cmacContext, sa->prfCipherAlgo, k, 16);
      }
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(sa->prfHashAlgo != NULL)
   {
      //Initialize HMAC calculation
      error = hmacInit(&sa->context->hmacContext, sa->prfHashAlgo, vk, vkLen);
   }
   else
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC &&
      sa->prfCipherAlgo != NULL)
   {
      XcbcMacContext *xcbcMacContext;
      uint8_t k[16];

      //Point to the XCBC-MAC context
      xcbcMacContext = &sa->context->xcbcMacContext;

      //Derive the 128-bit key K from the variable-length key VK
      if(vkLen == 16)
      {
         //If the key is exactly 128 bits long, use it as-is
         osMemcpy(k, vk, vkLen);
      }
      else if(vkLen < 16)
      {
         //If the key has fewer than 128 bits, lengthen it to exactly 128 bits
         //by padding it on the right with zero bits
         osMemcpy(k, vk, vkLen);
         osMemset(k + vkLen, 0, 16 - vkLen);
      }
      else
      {
         //If the key is 129 bits or longer, shorten it to exactly 128 bits
         //by performing the steps in AES-XCBC-PRF-128 (refer to RFC 4434,
         //section 2)
         osMemset(k, 0, 16);

         //The key is 128 zero bits
         error = xcbcMacInit(xcbcMacContext, sa->prfCipherAlgo, k, 16);

         //Check status code
         if(!error)
         {
            //The message is the too-long current key
            xcbcMacUpdate(xcbcMacContext, vk, vkLen);

            //Derive the 128-bit key K
            error = xcbcMacFinal(xcbcMacContext, k, 16);
         }
      }

      //Check status code
      if(!error)
      {
         //We apply the XCBC-MAC algorithm using K as the key
         error = xcbcMacInit(xcbcMacContext, sa->prfCipherAlgo, k, 16);
      }
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Update PRF calculation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] s Pointer to the data
 * @param[in] sLen Length of the data, in bytes
 **/

void ikeUpdatePrf(IkeSaEntry *sa, const uint8_t *s, size_t sLen)
{
#if (IKE_CMAC_PRF_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC &&
      sa->prfCipherAlgo != NULL)
   {
      //Update CMAC calculation
      cmacUpdate(&sa->context->cmacContext, s, sLen);
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(sa->prfHashAlgo != NULL)
   {
      //Update HMAC calculation
      hmacUpdate(&sa->context->hmacContext, s, sLen);
   }
   else
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC &&
      sa->prfCipherAlgo != NULL)
   {
      //Update XCBC-MAC calculation
      xcbcMacUpdate(&sa->context->xcbcMacContext, s, sLen);
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Just for sanity
   }
}


/**
 * @brief Finalize PRF calculation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] output Pseudorandom output
 * @return Error code
 **/

error_t ikeFinalizePrf(IkeSaEntry *sa, uint8_t *output)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_CMAC_PRF_SUPPORT == ENABLED)
   //CMAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_CMAC &&
      sa->prfCipherAlgo != NULL)
   {
      //Finalize CMAC calculation
      error = cmacFinal(&sa->context->cmacContext, output, sa->prfKeyLen);
   }
   else
#endif
#if (IKE_HMAC_PRF_SUPPORT == ENABLED)
   //HMAC PRF algorithm?
   if(sa->prfHashAlgo != NULL)
   {
      //Finalize HMAC calculation
      hmacFinal(&sa->context->hmacContext, output);
   }
   else
#endif
#if (IKE_XCBC_MAC_PRF_SUPPORT == ENABLED)
   //XCBC-MAC PRF algorithm?
   if(sa->prfAlgoId == IKE_TRANSFORM_ID_PRF_AES128_XCBC &&
      sa->prfCipherAlgo != NULL)
   {
      //Finalize XCBC-MAC calculation
      error = xcbcMacFinal(&sa->context->xcbcMacContext, output, sa->prfKeyLen);
   }
   else
#endif
   //Unknown PRF algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}

#endif
