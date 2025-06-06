/**
 * @file esp_packet_encrypt.c
 * @brief ESP packet encryption
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
#define TRACE_LEVEL ESP_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "esp/esp.h"
#include "esp/esp_packet_encrypt.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check IPsec library configuration
#if (ESP_SUPPORT == ENABLED)


/**
 * @brief Encrypt an outgoing ESP packet
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the SAD entry
 * @param[in] espHeader Pointer to the ESP header
 * @param[in,out] payload Payload data to be encrypted
 * @param[in,out] payloadLen Actual length of the payload data
 * @param[in] nextHeader Value of the next header field
 * @return Error code
 **/

error_t espEncryptPacket(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, uint8_t *payload, size_t *payloadLen,
   uint8_t nextHeader)
{
   error_t error;
   size_t length;
   uint8_t *data;
   uint8_t *icv;
   const CipherAlgo *cipherAlgo;

   //Get the length of the payload data, in bytes
   length = *payloadLen;

   //Point to the plaintext
   data = payload + sa->ivLen;

   //The transmitted ESP trailer consists of the Padding, Pad Length, and
   //Next Header fields (refer to RFC 4303, section 2)
   length = espAddTrailer(sa, data, length, nextHeader);

   //Point to the Integrity Checksum Value (ICV)
   icv = payload + sa->ivLen + length;

   //The SAD entry specifies the algorithms and keys to be employed for
   //encryption (refer to RFC 4303, section 3.4.2)
   cipherAlgo = sa->cipherAlgo;

#if (ESP_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      uint8_t iv[MAX_CIPHER_BLOCK_SIZE];

      //The IV must be chosen at random, and must be unpredictable
      error = context->prngAlgo->generate(context->prngContext, iv, sa->ivLen);
      //Any error to report?
      if(error)
         return error;

      //The IV field must be the same size as the block size of the cipher
      //algorithm being used
      osMemcpy(payload, iv, sa->ivLen);

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, sa->encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CBC encryption
      error = cbcEncrypt(cipherAlgo, &sa->cipherContext, iv, data, data,
         length);
      //Any error to report?
      if(error)
         return error;

      //The ICV is a variable-length field computed over the ESP header,
      //Payload, and ESP trailer fields (refer to RFC 4303, section 2.8)
      error = espComputeChecksum(context, sa, espHeader, payload,
         sa->ivLen + length, icv);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (ESP_CTR_SUPPORT == ENABLED)
   //CTR cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CTR)
   {
      uint8_t counter[16];

      //The IV must be chosen by the encryptor in a manner that ensures that
      //the same IV value is used only once for a given key (refer to RFC 3686,
      //section 3.1)
      espGenerateIv(sa->iv);

      //The IV field must be 8 octets when the AES-CTR algorithm is used for
      //IKEv2 encryption
      osMemcpy(payload, sa->iv, 8);

      //The counter block is 128 bits, including a 4-octet nonce, 8-octet IV,
      //and 4-octet block counter, in that order (refer to RFC 3686, section 4)
      osMemcpy(counter, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(counter + 4, sa->iv, 8);

      //The block counter begins with the value of one and increments by one
      //to generate the next portion of the key stream
      STORE32BE(1, counter + 12);

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, sa->encKey, sa->encKeyLen);
      //Any error to report?
      if(error)
         return error;

      //Perform CTR encryption
      error = ctrEncrypt(cipherAlgo, &sa->cipherContext,
         cipherAlgo->blockSize * 8, counter, data, data, length);
      //Any error to report?
      if(error)
         return error;

      //The ICV is a variable-length field computed over the ESP header,
      //Payload, and ESP trailer fields (refer to RFC 4303, section 2.8)
      error = espComputeChecksum(context, sa, espHeader, payload,
         sa->ivLen + length, icv);
      //Any error to report?
      if(error)
         return error;
   }
   else
#endif
#if (ESP_CCM_8_SUPPORT == ENABLED || ESP_CCM_12_SUPPORT == ENABLED || \
   ESP_CCM_16_SUPPORT == ENABLED)
   //CCM AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_CCM)
   {
      size_t aadLen;
      uint8_t aad[12];
      uint8_t nonce[11];

      //The IV must be chosen by the encryptor in a manner that ensures that
      //the same IV value is used only once for a given key (refer to RFC 4309,
      //section 3.1)
      espGenerateIv(sa->iv);

      //The Initialization Vector (IV) must be eight octets
      osMemcpy(payload, sa->iv, 8);

      //The components of the nonce are the salt with the IV (refer to RFC 4309,
      //section 4)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 3);
      osMemcpy(nonce + 3, sa->iv, 8);

      //Two formats of the AAD are defined (refer to RFC 4309, section 5)
      if(sa->esn)
      {
         //AAD Format with 64-bit sequence number
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(sa->seqNum, aad + 4);
         aadLen = 12;
      }
      else
      {
         //AAD Format with 32-bit sequence number
         osMemcpy(aad, espHeader, 8);
         aadLen = 8;
      }

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, sa->encKey, sa->encKeyLen);
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
#if (ESP_GCM_8_SUPPORT == ENABLED || ESP_GCM_12_SUPPORT == ENABLED || \
   ESP_GCM_16_SUPPORT == ENABLED)
   //GCM AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_GCM)
   {
      size_t aadLen;
      uint8_t aad[12];
      uint8_t nonce[12];
      GcmContext gcmContext;

      //For a given key, the IV must not repeat. The encrypter can use any IV
      //generation method that meets the uniqueness requirement, without
      //coordinating with the decrypter (refer to RFC 4106, section 3.1)
      espGenerateIv(sa->iv);

      //The Initialization Vector (IV) must be eight octets
      osMemcpy(payload, sa->iv, 8);

      //The components of the nonce are the salt with the IV (refer to RFC 4106,
      //section 4)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, sa->iv, 8);

      //Two formats of the AAD are defined (refer to RFC 4106, section 5)
      if(sa->esn)
      {
         //AAD Format with 64-bit sequence number
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(sa->seqNum, aad + 4);
         aadLen = 12;
      }
      else
      {
         //AAD Format with 32-bit sequence number
         osMemcpy(aad, espHeader, 8);
         aadLen = 8;
      }

      //Initialize cipher context
      error = cipherAlgo->init(&sa->cipherContext, sa->encKey, sa->encKeyLen);
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
#if (ESP_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //ChaCha20Poly1305 AEAD cipher?
   if(sa->cipherMode == CIPHER_MODE_CHACHA20_POLY1305)
   {
      size_t aadLen;
      uint8_t aad[12];
      uint8_t nonce[12];

      //The IV must be unique for each invocation for a particular security
      //association (SA) but does not need to be unpredictable (refer to
      //RFC 7634, section 2)
      espGenerateIv(sa->iv);

      //The IV is 64 bits, and is included explicitly in the Encrypted payload
      osMemcpy(payload, sa->iv, 8);

      //The 96-bit nonce is formed from a concatenation of the 32-bit salt and
      //the 64-bit IV (refer to RFC 7634, section 2)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, sa->iv, 8);

      //Extended sequence numbers?
      if(sa->esn)
      {
         //For SAs with ESN, the AAD is 12 octets: a 4-octet SPI followed by an
         //8-octet sequence number as a 64-bit integer in big-endian byte order
         //(refer to RFC 7634, section 2.1)
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(sa->seqNum, aad + 4);
         aadLen = 12;
      }
      else
      {
         //For SAs with 32-bit sequence numbers, the AAD is 8 octets: a 4-octet
         //SPI followed by a 4-octet sequence number ordered exactly as it is in
         //the packet
         osMemcpy(aad, espHeader, 8);
         aadLen = 8;
      }

      //Authenticated encryption using ChaCha20Poly1305
      error = chacha20Poly1305Encrypt(sa->encKey, sa->encKeyLen, nonce, 12,
         aad, aadLen, data, data, length, icv, sa->icvLen);
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

   //Total length of the encrypted packet
   *payloadLen = sa->ivLen + length + sa->icvLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compute ICV checksum
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the SAD entry
 * @param[in] espHeader Pointer to the ESP header
 * @param[in] payload Pointer to the payload data
 * @param[in] length Length of the packet, in bytes
 * @param[out] icv Integrity Checksum Value (ICV)
 * @return Error code
 **/

error_t espComputeChecksum(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, const uint8_t *payload, size_t length,
   uint8_t *icv)
{
   error_t error;

#if (ESP_CMAC_SUPPORT == ENABLED)
   //CMAC integrity algorithm?
   if(sa->authCipherAlgo != NULL)
   {
      CmacContext *cmacContext;

      //Point to the CMAC context
      cmacContext = &context->cmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation
      error = cmacInit(cmacContext, sa->authCipherAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The checksum must be computed over the encrypted message. Its length
         //is determined by the integrity algorithm negotiated
         cmacUpdate(cmacContext, espHeader, sizeof(EspHeader));
         cmacUpdate(cmacContext, payload, length);

         //Extended sequence number?
         if(sa->esn)
         {
            //The high-order 32 bits are maintained as part of the sequence
            //number counter by both transmitter and receiver and are included
            //in the computation of the ICV (refer to RFC 4303, section 2.2.1)
            uint32_t h = htonl(sa->seqNum >> 32);
            cmacUpdate(cmacContext, (uint8_t *) &h, 4);
         }

         //Finalize CMAC computation
         cmacFinal(cmacContext, icv, sa->icvLen);
      }
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED)
   //HMAC integrity algorithm?
   if(sa->authHashAlgo != NULL)
   {
      HmacContext *hmacContext;

      //Point to the HMAC context
      hmacContext = &context->hmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation
      error = hmacInit(hmacContext, sa->authHashAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The checksum must be computed over the encrypted message. Its length
         //is determined by the integrity algorithm negotiated
         hmacUpdate(hmacContext, espHeader, sizeof(EspHeader));
         hmacUpdate(hmacContext, payload, length);

         //Extended sequence number?
         if(sa->esn)
         {
            //The high-order 32 bits are maintained as part of the sequence
            //number counter by both transmitter and receiver and are included
            //in the computation of the ICV (refer to RFC 4303, section 2.2.1)
            uint32_t h = htonl(sa->seqNum >> 32);
            hmacUpdate(hmacContext, (uint8_t *) &h, 4);
         }

         //Finalize HMAC computation
         hmacFinal(hmacContext, NULL);

         //Copy the resulting checksum value
         osMemcpy(icv, hmacContext->digest, sa->icvLen);
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
 * @brief Compute the number of padding bytes
 * @param[in] sa Pointer to the SAD entry
 * @param[in] length Length of the payload data, in bytes
 * @return Number of padding bytes
 **/

size_t espComputePadLength(IpsecSadEntry *sa, size_t length)
{
   size_t n;

#if (ESP_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      //For the purpose of ensuring that data to be encrypted are a multiple
      //of the algorithm's block size, the padding computation applies to the
      //Payload Data exclusive of any IV, but including the ESP trailer fields
      //(refer to RFC 4303, section 2.4)
      n = (length + sizeof(EspTrailer)) % sa->cipherAlgo->blockSize;

      //Check whether any padding is required
      if(n != 0)
      {
         //Calculate the length of the Padding field
         n = sa->cipherAlgo->blockSize - n;
      }
   }
   else
#endif
   //AEAD cipher mode?
   {
      //Implementations that do not seek to hide the length of the plaintext
      //should use the minimum amount of padding required, which will be less
      //than four octets (refer to RFC 4106, section 3.2)
      n = (length + sizeof(EspTrailer)) % 4;

      //Check whether any padding is required
      if(n != 0)
      {
         //Calculate the length of the Padding field
         n = 4 - n;
      }
   }

   //Return the number of padding bytes
   return n;
}


/**
 * @brief Append ESP trailer
 * @param[in] sa Pointer to the SAD entry
 * @param[in] data Pointer to the payload data
 * @param[in] length Length of the payload data, in bytes
 * @param[in] nextHeader Value of the next header field
 * @return Length of the resulting payload data
 **/

size_t espAddTrailer(IpsecSadEntry *sa, uint8_t *data, size_t length,
   uint8_t nextHeader)
{
   size_t i;
   size_t n;
   EspTrailer *espTrailer;

   //The sender may add 0 to 255 bytes of padding
   n = espComputePadLength(sa, length);

   //Padding bytes make up a monotonically increasing sequence
   for(i = 1; i <= n; i++)
   {
      data[length++] = (uint8_t) i;
   }

   //Point to the ESP trailer
   espTrailer = (EspTrailer *) (data + length);

   //The Pad Length field indicates the number of pad bytes immediately
   //preceding it in the Padding field (refer to RFC 4303, section 2.5)
   espTrailer->padLength = n;

   //The Next Header field identifies the type of data contained in the
   //payload data (refer to RFC 4303, section 2.6)
   espTrailer->nextHeader = nextHeader;

   //Return the length of the resulting payload data
   return length + sizeof(EspTrailer);
}


/**
 * @brief IV generation
 * @param[in,out] iv Pointer to the 8-octet initialization vector
 **/

void espGenerateIv(uint8_t *iv)
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
