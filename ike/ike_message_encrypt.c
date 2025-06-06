/**
 * @file ike_message_encrypt.c
 * @brief IKE message encryption
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
#include "ike/ike_message_encrypt.h"
#include "ike/ike_debug.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Encrypt an outgoing IKE message
 * @param[in] sa Pointer to the IKE SA
 * @param[in,out] message IKE message to be encrypted
 * @param[in,out] messageLen Actual length of the IKE message
 * @return Error code
 **/

error_t ikeEncryptMessage(IkeSaEntry *sa, uint8_t *message, size_t *messageLen)
{
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   uint8_t *data;
   uint8_t *icv;
   IkeContext *context;
   IkeHeader *ikeHeader;
   IkeEncryptedPayload *encryptedPayload;
   const uint8_t *encKey;
   const CipherAlgo *cipherAlgo;

   //Malformed IKE message?
   if(*messageLen < sizeof(IkeHeader))
      return ERROR_INVALID_MESSAGE;

   //Debug message
   TRACE_DEBUG("IKE message to be encrypted (%" PRIuSIZE " bytes):\r\n", *messageLen);
   //Dump IKE message for debugging purpose
   ikeDumpMessage(message, *messageLen);

   //Point to the IKE header
   ikeHeader = (IkeHeader *) message;

   //Point to the IKE payloads
   p = message + sizeof(IkeHeader);
   //Get the length of the IKE payloads, in bytes
   length = *messageLen - sizeof(IkeHeader);

   //Point to the IKE context
   context = sa->context;
   //Cipher algorithm used to encrypt the packet
   cipherAlgo = sa->cipherAlgo;

   //The encryption key is obtained from the SK_ei or SK_er key, whichever
   //is appropriate
   if(sa->originalInitiator)
   {
      encKey = sa->skei;
   }
   else
   {
      encKey = sa->sker;
   }

   //Make room for the Encrypted payload header and initialization vector
   osMemmove(p + sizeof(IkeEncryptedPayload) + sa->ivLen, p, length);

   //Point to the Encrypted payload header
   encryptedPayload = (IkeEncryptedPayload *) p;
   //Point to the plaintext
   data = encryptedPayload->iv + sa->ivLen;
   //Append Padding and Pad Length fields
   length = ikePadPayload(sa, data, length);
   //Point to the Integrity Checksum Value (ICV)
   icv = data + length;

   //The Payload Length field of the Encrypted payload header includes the
   //lengths of the header, initialization vector (IV), encrypted IKE
   //payloads, Padding, Pad Length, and Integrity Checksum Value (ICV)
   n = sizeof(IkeEncryptedPayload) + sa->ivLen + length + sa->icvLen;

   //Format Encrypted payload header
   encryptedPayload->header.nextPayload = ikeHeader->nextPayload;
   encryptedPayload->header.critical = FALSE;
   encryptedPayload->header.reserved = 0;
   encryptedPayload->header.payloadLength = htons(n);

   //Consider the length of the IKE header
   n += sizeof(IkeHeader);

   //Fix the Next Payload and Length fields of the IKE header
   ikeHeader->nextPayload = IKE_PAYLOAD_TYPE_SK;
   ikeHeader->length = htonl(n);

#if (IKE_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      uint8_t iv[MAX_CIPHER_BLOCK_SIZE];

      //Senders must select a new unpredictable IV for every message (refer
      //to RFC 7296, section 3.14)
      error = context->prngAlgo->generate(context->prngContext, iv, sa->ivLen);
      //Any error to report?
      if(error)
         return error;

      //For CBC mode ciphers, the length of the initialization vector (IV) is
      //equal to the block length of the underlying encryption algorithm
      osMemcpy(encryptedPayload->iv, iv, sa->ivLen);

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CBC encryption
      error = cbcEncrypt(cipherAlgo, &sa->cipherContext, iv, data, data,
         length);
      //Any error to report?
      if(error)
         return error;

      //The checksum must be computed over the encrypted message. Its length
      //is determined by the integrity algorithm negotiated
      error = ikeComputeChecksum(sa, message, n - sa->icvLen, icv);
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

      //The IV must be chosen by the encryptor in a manner that ensures that
      //the same IV value is used only once for a given key (refer to RFC 3686,
      //section 3.1)
      ikeGenerateIv(sa->iv);

      //The IV field must be 8 octets when the AES-CTR algorithm is used for
      //IKEv2 encryption
      osMemcpy(encryptedPayload->iv, sa->iv, 8);

      //The counter block is 128 bits, including a 4-octet nonce, 8-octet IV,
      //and 4-octet block counter, in that order (refer to RFC 5930, section 2)
      osMemcpy(counter, encKey + sa->encKeyLen, 4);
      osMemcpy(counter + 4, sa->iv, 8);

      //The block counter begins with the value of one and increments by one
      //to generate the next portion of the key stream
      STORE32BE(1, counter + 12);

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CTR encryption
      error = ctrEncrypt(cipherAlgo, &sa->cipherContext,
         cipherAlgo->blockSize * 8, counter, data, data, length);
      //Any error to report?
      if(error)
         return error;

      //The checksum must be computed over the encrypted message. Its length
      //is determined by the integrity algorithm negotiated
      error = ikeComputeChecksum(sa, message, n - sa->icvLen, icv);
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

      //The IV must be chosen by the encryptor in a manner that ensures that
      //the same IV value is used only once for a given key (refer to RFC 5282,
      //section 3.1)
      ikeGenerateIv(sa->iv);

      //The Initialization Vector (IV) must be eight octets
      osMemcpy(encryptedPayload->iv, sa->iv, 8);

      //Construct the nonce by concatenating the salt with the IV, in that
      //order (refer to RFC 5282, section 4)
      osMemcpy(nonce, encKey + sa->encKeyLen, 3);
      osMemcpy(nonce + 3, sa->iv, 8);

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

      //Authenticated encryption using CCM
      error = ccmEncrypt(sa->cipherAlgo, &sa->cipherContext, nonce, 11, aad,
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

      //The IV must be chosen by the encryptor in a manner that ensures that
      //the same IV value is used only once for a given key (refer to RFC 5282,
      //section 3.1)
      ikeGenerateIv(sa->iv);

      //The Initialization Vector (IV) must be eight octets
      osMemcpy(encryptedPayload->iv, sa->iv, 8);

      //Construct the nonce by concatenating the salt with the IV, in that
      //order (refer to RFC 5282, section 4)
      osMemcpy(nonce, encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, sa->iv, 8);

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

      //Authenticated encryption using GCM
      error = gcmEncrypt(&gcmContext, nonce, 12, aad, aadLen, data, data,
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

      //The IV must be unique for each invocation for a particular security
      //association (SA) but does not need to be unpredictable (refer to
      //RFC 7634, section 2)
      ikeGenerateIv(sa->iv);

      //The IV is 64 bits, and is included explicitly in the Encrypted payload
      osMemcpy(encryptedPayload->iv, sa->iv, 8);

      //The 96-bit nonce is formed from a concatenation of the 32-bit salt and
      //the 64-bit IV (refer to RFC 7634, section 2)
      osMemcpy(nonce, encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, sa->iv, 8);

      //The associated data must consist of the partial contents of the IKEv2
      //message, starting from the first octet of the fixed IKE header through
      //the last octet of the Encrypted payload header (refer to RFC 5282,
      //section 5.1)
      aad = message;
      aadLen = encryptedPayload->iv - message;

      //Authenticated encryption using ChaCha20Poly1305
      error = chacha20Poly1305Encrypt(encKey, sa->encKeyLen, nonce, 12, aad,
         aadLen, data, data, length, icv, sa->icvLen);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      return ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Total length of the resulting IKE message
   *messageLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute ICV checksum
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the message
 * @param[in] length Length of the message, in bytes
 * @param[out] icv Integrity Checksum Value (ICV)
 * @return Error code
 **/

error_t ikeComputeChecksum(IkeSaEntry *sa, const uint8_t *message,
   size_t length, uint8_t *icv)
{
   error_t error;
   const uint8_t *authKey;

   //The integrity protection key key is obtained from the SK_ai or SK_ar
   //key, whichever is appropriate
   if(sa->originalInitiator)
   {
      authKey = sa->skai;
   }
   else
   {
      authKey = sa->skar;
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
         cmacFinal(cmacContext, icv, sa->icvLen);
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
         hmacFinal(hmacContext, NULL);

         //Copy the resulting checksum value
         osMemcpy(icv, hmacContext->digest, sa->icvLen);
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
         xcbcMacFinal(xcbcMacContext, icv, sa->icvLen);
      }
   }
   else
#endif
   //Unknown integrity algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Append Padding and Pad Length fields
 * @param[in] sa Pointer to the IKE SA
 * @param[in] data Pointer to the payload
 * @param[in] length Length of the payload, in bytes
 * @return Length of the resulting padded payload
 **/

size_t ikePadPayload(IkeSaEntry *sa, uint8_t *data, size_t length)
{
#if (IKE_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      size_t i;
      size_t n;

      //The sender should set the Pad Length to the minimum value that makes
      //the combination of the payloads, the Padding, and the Pad Length a
      //multiple of the block size (refer to RFC 7296, section 3.14)
      n = (length + 1) % sa->cipherAlgo->blockSize;

      //Check whether any padding is required
      if(n != 0)
      {
         //Calculate the length of the Padding field
         n = sa->cipherAlgo->blockSize - n;

         //Padding may contain any value chosen by the sender
         for(i = 1; i <= n; i++)
         {
            data[length++] = (uint8_t) i;
         }
      }

      //The Pad Length field is the length of the Padding field
      data[length++] = (uint8_t) n;
   }
   else
#endif
   //AEAD cipher mode?
   {
      //There are no alignment requirements on the length of the Padding
      //field (refer to RFC 5282, section 3)
      data[length++] = 0;
   }

   //Return the length of the resulting padded payload
   return length;
}


/**
 * @brief IV generation
 * @param[in,out] iv Pointer to the 8-octet initialization vector
 **/

void ikeGenerateIv(uint8_t *iv)
{
   uint16_t temp;

   //The encryptor may generate the IV in any manner that ensures uniqueness.
   //Common approaches to IV generation include incrementing a counter for each
   //packet and linear feedback shift registers (refer to RFC 5282, section 3.1)
   temp = iv[7] + 1;
   iv[7] = temp & 0xFF;
   temp = (temp >> 8) + iv[6];
   iv[6] = temp & 0xFF;
   temp = (temp >> 8) + iv[5];
   iv[5] = temp & 0xFF;
   temp = (temp >> 8) + iv[4];
   iv[4] = temp & 0xFF;
   temp = (temp >> 8) + iv[3];
   iv[3] = temp & 0xFF;
   temp = (temp >> 8) + iv[2];
   iv[2] = temp & 0xFF;
   temp = (temp >> 8) + iv[1];
   iv[1] = temp & 0xFF;
   temp = (temp >> 8) + iv[0];
   iv[0] = temp & 0xFF;
}

#endif
