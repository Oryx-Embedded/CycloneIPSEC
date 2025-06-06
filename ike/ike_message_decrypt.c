/**
 * @file ike_message_decrypt.c
 * @brief IKE message decryption
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
#include "ike/ike_message_decrypt.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_debug.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Decrypt an incoming IKE message
 * @param[in] sa Pointer to the IKE SA
 * @param[in,out] message IKE message to be decrypted
 * @param[in,out] messageLen Actual length of the IKE message
 * @return Error code
 **/

error_t ikeDecryptMessage(IkeSaEntry *sa, uint8_t *message, size_t *messageLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *iv;
   uint8_t *data;
   uint8_t *icv;
   IkeHeader *ikeHeader;
   IkeEncryptedPayload *encryptedPayload;
   const uint8_t *encKey;
   const CipherAlgo *cipherAlgo;

   //Malformed IKE message?
   if(*messageLen < sizeof(IkeHeader))
      return ERROR_INVALID_MESSAGE;

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;
   //Retrieve the length of the IKE message
   n = ntohl(ikeHeader->length);

   //Malformed IKE message?
   if(n < sizeof(IkeHeader) || n > *messageLen)
      return ERROR_INVALID_MESSAGE;

   //Cipher algorithm used to decrypt the packet
   cipherAlgo = sa->cipherAlgo;

   //The encryption key is obtained from the SK_ei or SK_er key, whichever
   //is appropriate
   if(sa->originalInitiator)
   {
      encKey = sa->sker;
   }
   else
   {
      encKey = sa->skei;
   }

   //The Encrypted payload is often the only payload in the message
   encryptedPayload = (IkeEncryptedPayload *) ikeGetPayload(message, n,
      IKE_PAYLOAD_TYPE_SK, 0);
   //Encrypted payload not found?
   if(encryptedPayload == NULL)
      return ERROR_INVALID_MESSAGE;

   //The Payload Length field of the Encrypted payload header includes the
   //lengths of the header, initialization vector (IV), encrypted IKE payloads,
   //Padding, Pad Length, and Integrity Checksum Value (ICV)
   length = ntohs(encryptedPayload->header.payloadLength);

   //The Encrypted payload, if present in a message, must be the last payload
   //in the message (refer to RFC 7296, section 3.14)
   if(((uint8_t *) encryptedPayload + length) != (message + n))
      return ERROR_INVALID_MESSAGE;

   //Check the length of the Encrypted payload
   if(length < (sizeof(IkeEncryptedPayload) + sa->ivLen + sa->icvLen + 1))
      return ERROR_INVALID_MESSAGE;

   //Determine the length of the ciphertext
   length -= sizeof(IkeEncryptedPayload) + sa->ivLen + sa->icvLen;

   //Point to the initialization vector (IV)
   iv = encryptedPayload->iv;
   //Point to the ciphertext
   data = iv + sa->ivLen;
   //Point to the Integrity Checksum Value (ICV)
   icv = data + length;

#if (IKE_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      //The length of the ciphertext must be a multiple of the block size
      if((length % cipherAlgo->blockSize) != 0)
         return ERROR_INVALID_MESSAGE;

      //Verify checksum value
      error = ikeVerifyChecksum(sa, message, n - sa->icvLen, icv);
      //Any error to report?
      if(error)
         return error;

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CBC decryption
      error = cbcDecrypt(cipherAlgo, &sa->cipherContext, iv, data, data,
         length);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (IKE_CTR_SUPPORT == ENABLED)
   //CTR cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CTR)
   {
      uint8_t counter[16];

      //The counter block is 128 bits, including a 4-octet nonce, 8-octet IV,
      //and 4-octet block counter, in that order (refer to RFC 5930, section 2)
      osMemcpy(counter, encKey + sa->encKeyLen, 4);
      osMemcpy(counter + 4, iv, 8);

      //The block counter begins with the value of one and increments by one
      //to generate the next portion of the key stream
      STORE32BE(1, counter + 12);

      //Verify checksum value
      error = ikeVerifyChecksum(sa, message, n - sa->icvLen, icv);
      //Any error to report?
      if(error)
         return error;

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CTR decryption
      error = ctrDecrypt(cipherAlgo, &sa->cipherContext,
         cipherAlgo->blockSize * 8, counter, data, data, length);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (IKE_CCM_8_SUPPORT == ENABLED || IKE_CCM_12_SUPPORT == ENABLED || \
   IKE_CCM_16_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_CCM)
   {
      size_t aadLen;
      uint8_t *aad;
      uint8_t nonce[11];

      //Construct the nonce by concatenating the salt with the IV, in that
      //order (refer to RFC 5282, section 4)
      osMemcpy(nonce, encKey + sa->encKeyLen, 3);
      osMemcpy(nonce + 3, iv, 8);

      //The associated data must consist of the partial contents of the IKEv2
      //message, starting from the first octet of the fixed IKE header through
      //the last octet of the Encrypted payload header (refer to RFC 5282,
      //section 5.1)
      aad = message;
      aadLen = encryptedPayload->iv - message;

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Authenticated decryption using CCM
      error = ccmDecrypt(sa->cipherAlgo, &sa->cipherContext, nonce, 11, aad,
         aadLen, data, data, length, icv, sa->icvLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (IKE_GCM_8_SUPPORT == ENABLED || IKE_GCM_12_SUPPORT == ENABLED || \
   IKE_GCM_16_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_GCM)
   {
      size_t aadLen;
      uint8_t *aad;
      uint8_t nonce[12];
      GcmContext gcmContext;

      //Construct the nonce by concatenating the salt with the IV, in that
      //order (refer to RFC 5282, section 4)
      osMemcpy(nonce, encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, iv, 8);

      //The associated data must consist of the partial contents of the IKEv2
      //message, starting from the first octet of the fixed IKE header through
      //the last octet of the Encrypted payload header (refer to RFC 5282,
      //section 5.1)
      aad = message;
      aadLen = encryptedPayload->iv - message;

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Initialize GCM context
      error = gcmInit(&gcmContext, sa->cipherAlgo, &sa->cipherContext);
      //Any error to report?
      if(error)
         return error;

      //Authenticated decryption using GCM
      error = gcmDecrypt(&gcmContext, nonce, 12, aad, aadLen, data, data,
         length, icv, sa->icvLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (IKE_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      size_t aadLen;
      uint8_t *aad;
      uint8_t nonce[12];

      //The 96-bit nonce is formed from a concatenation of the 32-bit salt and
      //the 64-bit IV (refer to RFC 7634, section 2)
      osMemcpy(nonce, encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, iv, 8);

      //The associated data must consist of the partial contents of the IKEv2
      //message, starting from the first octet of the fixed IKE header through
      //the last octet of the Encrypted payload header (refer to RFC 5282,
      //section 5.1)
      aad = message;
      aadLen = encryptedPayload->iv - message;

      //Authenticated decryption using ChaCha20Poly1305
      error = chacha20Poly1305Decrypt(encKey, sa->encKeyLen, nonce, 12, aad,
         aadLen, data, data, length, icv, sa->icvLen);
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      return ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //The Pad Length field is the length of the Padding field
   n = data[length - 1];

   //Malformed padding?
   if((n + 1) > length)
      return ERROR_DECRYPTION_FAILED;

   //Strip padding bytes from the message
   length -= n + 1;

   //Total length of the resulting IKE message
   *messageLen = sizeof(IkeHeader) + length;

   //Fix the Next Payload and Length fields of the IKE header
   ikeHeader->nextPayload = encryptedPayload->header.nextPayload;
   ikeHeader->length = htonl(*messageLen);

   //Strip the Encrypted payload header from the message
   osMemmove(message + sizeof(IkeHeader), data, length);

   //Debug message
   TRACE_DEBUG("Decrypted IKE message (%" PRIuSIZE " bytes):\r\n", *messageLen);
   //Dump IKE message for debugging purpose
   ikeDumpMessage(message, *messageLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Verify ICV checksum
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the message
 * @param[in] length Length of the message, in bytes
 * @param[in] icv Integrity Checksum Value (ICV)
 * @return Error code
 **/

error_t ikeVerifyChecksum(IkeSaEntry *sa, const uint8_t *message,
   size_t length, const uint8_t *icv)
{
   size_t i;
   uint8_t mask;
   error_t error;
   const uint8_t *authKey;
   uint8_t checksum[IKE_MAX_DIGEST_SIZE];

   //The integrity protection key key is obtained from the SK_ai or SK_ar
   //key, whichever is appropriate
   if(sa->originalInitiator)
   {
      authKey = sa->skar;
   }
   else
   {
      authKey = sa->skai;
   }

#if (IKE_CMAC_AUTH_SUPPORT == ENABLED)
   //CMAC integrity algorithm?
   if(sa->authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_CMAC_96 &&
      sa->authCipherAlgo != NULL)
   {
      CmacContext *cmacContext;

      //Point to the CMAC context
      cmacContext = &sa->context->cmacContext;

      //Initialize CMAC calculation
      error = cmacInit(cmacContext, sa->authCipherAlgo, authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The checksum must be computed over the encrypted message. Its length
         //is determined by the integrity algorithm negotiated
         cmacUpdate(cmacContext, message, length);
         cmacFinal(cmacContext, checksum, sa->icvLen);
      }
   }
   else
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED)
   //HMAC integrity algorithm?
   if(sa->authHashAlgo != NULL)
   {
      HmacContext *hmacContext;

      //Point to the HMAC context
      hmacContext = &sa->context->hmacContext;

      //Initialize HMAC calculation
      error = hmacInit(hmacContext, sa->authHashAlgo, authKey, sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The checksum must be computed over the encrypted message. Its length
         //is determined by the integrity algorithm negotiated
         hmacUpdate(hmacContext, message, length);
         hmacFinal(hmacContext, checksum);
      }
   }
   else
#endif
#if (IKE_XCBC_MAC_AUTH_SUPPORT == ENABLED)
   //XCBC-MAC integrity algorithm?
   if(sa->authAlgoId == IKE_TRANSFORM_ID_AUTH_AES_XCBC_96 &&
      sa->authCipherAlgo != NULL)
   {
      XcbcMacContext *xcbcMacContext;

      //Point to the XCBC-MAC context
      xcbcMacContext = &sa->context->xcbcMacContext;

      //Initialize XCBC-MAC calculation
      error = xcbcMacInit(xcbcMacContext, sa->authCipherAlgo, authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The checksum must be computed over the encrypted message. Its length
         //is determined by the integrity algorithm negotiated
         xcbcMacUpdate(xcbcMacContext, message, length);
         xcbcMacFinal(xcbcMacContext, checksum, sa->icvLen);
      }
   }
   else
#endif
   //Unknown integrity algorithm?
   {
      //Report an error
      error = ERROR_DECRYPTION_FAILED;
   }

   //Check status code
   if(!error)
   {
      //The calculated checksum is bitwise compared to the received ICV
      for(mask = 0, i = 0; i < sa->icvLen; i++)
      {
         mask |= checksum[i] ^ icv[i];
      }

      //The message is authenticated if and only if the checksums match
      error = (mask == 0) ? NO_ERROR : ERROR_DECRYPTION_FAILED;
   }

   //Return status code
   return error;
}

#endif
