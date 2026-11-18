/**
 * @file esp_packet_decrypt.c
 * @brief ESP packet decryption
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
#define TRACE_LEVEL ESP_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_inbound.h"
#include "esp/esp.h"
#include "esp/esp_packet_decrypt.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "aead/aead_algorithms.h"
#include "debug.h"

//Check IPsec library configuration
#if (ESP_SUPPORT == ENABLED)


/**
 * @brief Decrypt an incoming ESP packet
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the SAD entry
 * @param[in] espHeader Pointer to the ESP header
 * @param[in,out] payload Payload data to be decrypted
 * @param[in,out] payloadLen Actual length of the payload data
 * @param[out] nextHeader Value of the next header field
 * @return Error code
 **/

error_t espDecryptPacket(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, uint8_t *payload, size_t *payloadLen,
   uint8_t *nextHeader)
{
   error_t error;
   uint8_t *data;
   uint8_t *icv;
   size_t length;
   size_t padLen;
   const CipherAlgo *cipherAlgo;
   uint8_t iv[MAX_CIPHER_BLOCK_SIZE];

   //Check the length of the payload data
   if(*payloadLen < (sa->ivLen + sizeof(EspTrailer) + sa->icvLen))
      return ERROR_INVALID_PACKET;

   //Determine the length of the ciphertext
   length = *payloadLen - sa->ivLen - sa->icvLen;

   //If the algorithm used to encrypt the payload requires an Initialization
   //Vector (IV), then this data is carried explicitly in the payload field
   osMemcpy(iv, payload, sa->ivLen);

   //Point to the ciphertext
   data = payload + sa->ivLen;
   //Point to the Integrity Checksum Value (ICV)
   icv = data + length;

   //The SAD entry specifies the algorithms and keys to be employed for
   //decryption (refer to RFC 4303, section 3.4.2)
   cipherAlgo = sa->cipherAlgo;

   //Initialize status code
   error = NO_ERROR;

#if (ESP_NULL_SUPPORT == ENABLED)
   //Integrity-only ESP?
   if(sa->cipherMode == CIPHER_MODE_NULL)
   {
      //No confidentiality is offered by using the NULL encryption algorithm
      error = espVerifyChecksum(context, sa, espHeader, context->buffer, length,
         icv);
   }
   else
#endif
#if (ESP_CBC_SUPPORT == ENABLED)
   //CBC cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CBC)
   {
      //Check the length of the ciphertext
      if((length % cipherAlgo->blockSize) == 0)
      {
         //If a separate integrity algorithm is employed, then the receiver
         //proceeds to integrity verification (refer to RFC 4303, section 3.4.3)
         error = espVerifyChecksum(context, sa, espHeader, context->buffer,
            sa->ivLen + length, icv);

         //Check status code
         if(!error)
         {
            //Initialize cipher context
            error = cipherAlgo->init(&sa->cipherContext, sa->encKey,
               sa->encKeyLen);

            //Check status code
            if(!error)
            {
               //Perform CBC decryption
               error = cbcDecrypt(cipherAlgo, &sa->cipherContext, iv, data,
                  payload, length);

               //Erase cipher context
               cipherAlgo->deinit(&sa->cipherContext);
            }
         }
      }
      else
      {
         //The length of the ciphertext must be a multiple of the block size
         error = ERROR_INVALID_PACKET;
      }
   }
   else
#endif
#if (ESP_CTR_SUPPORT == ENABLED)
   //CTR cipher mode?
   if(sa->cipherMode == CIPHER_MODE_CTR)
   {
      uint8_t counter[16];

      //The counter block is 128 bits, including a 4-octet nonce, 8-octet IV,
      //and 4-octet block counter, in that order (refer to RFC 3686, section 4)
      osMemcpy(counter, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(counter + 4, iv, 8);

      //The block counter begins with the value of one and increments by one to
      //generate the next portion of the key stream
      STORE32BE(1, counter + 12);

      //If a separate integrity algorithm is employed, then the receiver
      //proceeds to integrity verification (refer to RFC 4303, section 3.4.3)
      error = espVerifyChecksum(context, sa, espHeader, context->buffer,
         sa->ivLen + length, icv);

      //Check status code
      if(!error)
      {
         //Initialize cipher context
         error = cipherAlgo->init(&sa->cipherContext, sa->encKey,
            sa->encKeyLen);

         //Check status code
         if(!error)
         {
            //Perform CTR decryption
            error = ctrDecrypt(cipherAlgo, &sa->cipherContext,
               cipherAlgo->blockSize * 8, counter, data, payload, length);

            //Erase cipher context
            cipherAlgo->deinit(&sa->cipherContext);
         }
      }
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

      //The components of the nonce are the salt with the IV (refer to RFC 4309,
      //section 4)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 3);
      osMemcpy(nonce + 3, iv, 8);

      //Two formats of the AAD are defined (refer to RFC 4309, section 5)
      if(sa->esn)
      {
         //Reconstruct the 64-bit sequence number
         uint64_t seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

         //AAD Format with 64-bit sequence number
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(seq, aad + 4);
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

      //Check status code
      if(!error)
      {
         //Authenticated decryption using CCM
         error = ccmDecrypt(sa->cipherAlgo, &sa->cipherContext, nonce, 11,
            aad, aadLen, data, payload, length, icv, sa->icvLen);

         //Erase cipher context
         cipherAlgo->deinit(&sa->cipherContext);
      }
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

      //The components of the nonce are the salt with the IV (refer to RFC 4106,
      //section 4)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, iv, 8);

      //Two formats of the AAD are defined (refer to RFC 4106, section 5)
      if(sa->esn)
      {
         //Reconstruct the 64-bit sequence number
         uint64_t seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

         //AAD Format with 64-bit sequence number
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(seq, aad + 4);
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

      //Check status code
      if(!error)
      {
         //Initialize GCM context
         error = gcmInit(&gcmContext, sa->cipherAlgo, &sa->cipherContext);

         //Check status code
         if(!error)
         {
            //Authenticated decryption using GCM
            error = gcmDecrypt(&gcmContext, nonce, 12, aad, aadLen, data,
               payload, length, icv, sa->icvLen);

            //Erase GCM context
            gcmDeinit(&gcmContext);
         }

         //Erase cipher context
         cipherAlgo->deinit(&sa->cipherContext);
      }
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

      //The 96-bit nonce is formed from a concatenation of the 32-bit salt and
      //the 64-bit IV (refer to RFC 7634, section 2)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, iv, 8);

      //Extended sequence numbers?
      if(sa->esn)
      {
         //Reconstruct the 64-bit sequence number
         uint64_t seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

         //For SAs with ESN, the AAD is 12 octets: a 4-octet SPI followed by an
         //8-octet sequence number as a 64-bit integer in big-endian byte order
         //(refer to RFC 7634, section 2.1)
         osMemcpy(aad, (uint8_t *) &espHeader->spi, 4);
         STORE64BE(seq, aad + 4);
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

      //Authenticated decryption using ChaCha20Poly1305
      error = chacha20Poly1305Decrypt(sa->encKey, sa->encKeyLen, nonce, 12,
         aad, aadLen, data, payload, length, icv, sa->icvLen);
   }
   else
#endif
#if (ESP_NULL_SUPPORT == ENABLED && ESP_GMAC_SUPPORT == ENABLED)
   //GMAC authentication algorithm?
   if(sa->cipherMode == CIPHER_MODE_GMAC)
   {
      uint8_t temp[16];
      uint8_t nonce[12];
      GmacContext gmacContext;

      //The components of the nonce are the salt with the IV (refer to RFC 4543,
      //section 3.2)
      osMemcpy(nonce, sa->encKey + sa->encKeyLen, 4);
      osMemcpy(nonce + 4, iv, 8);

      //Initialize GMAC context
      error = gmacInit(&gmacContext, sa->cipherAlgo, sa->encKey, sa->encKeyLen);

      //Check status code
      if(!error)
      {
         //The nonce is passed to the AES-GMAC authentication algorithm
         error = gmacReset(&gmacContext, nonce, 12);

         //Check status code
         if(!error)
         {
            //Two formats of the AAD are defined (refer to RFC 4543,
            //section 3.3)
            if(sa->esn)
            {
               //Reconstruct the 64-bit sequence number
               uint64_t seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

               //Convert the 64-bit sequence number to network byte order
               STORE64BE(seq, temp);

               //The AAD consists of the SPI, 64-bit sequence number, and ESP
               //payload
               gmacUpdate(&gmacContext, (uint8_t *) &espHeader->spi, 4);
               gmacUpdate(&gmacContext, temp, 8);
               gmacUpdate(&gmacContext, iv, 8);
               gmacUpdate(&gmacContext, data, length);
            }
            else
            {
               //The AAD consists of the SPI, 32-bit sequence number, and ESP
               //payload
               gmacUpdate(&gmacContext, espHeader, sizeof(EspHeader));
               gmacUpdate(&gmacContext, iv, 8);
               gmacUpdate(&gmacContext, data, length);
            }

            //Finalize GMAC computation
            error = gmacFinal(&gmacContext, temp, sa->icvLen);
         }

         //Erase GMAC context
         gmacDeinit(&gmacContext);
      }

      //Check status code
      if(!error)
      {
         //If the computed and received ICVs match, then the datagram is valid,
         //and it is accepted (refer to RFC 4303, section 3.4.4.1)
         if(cryptoCompMem(temp, icv, sa->icvLen) != 0)
         {
            error = ERROR_DECRYPTION_FAILED;
         }
      }

      //Check status code
      if(!error)
      {
         //Copy payload data
         osMemcpy(payload, data, length);
      }
   }
   else
#endif
   //Invalid cipher mode?
   {
      //The specified cipher mode is not supported
      error = ERROR_UNSUPPORTED_CIPHER_MODE;
   }

   //Check status code
   if(!error)
   {
      //Parse ESP trailer
      error = espParseTrailer(payload, length, &padLen, nextHeader);
   }

   //Check status code
   if(!error)
   {
      //Remove the padding and the ESP trailer prior to passing the decrypted
      //data to the next layer
      *payloadLen = length - padLen - sizeof(EspTrailer);
   }

   //Return status code
   return error;
}


/**
 * @brief Verify ICV checksum
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the SAD entry
 * @param[in] espHeader Pointer to the ESP header
 * @param[in] payload Pointer to the payload data
 * @param[in] length Length of the payload data, in bytes
 * @param[in] icv Integrity Checksum Value (ICV)
 * @return Error code
 **/

error_t espVerifyChecksum(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, const uint8_t *payload, size_t length,
   const uint8_t *icv)
{
   error_t error;
   uint8_t checksum[ESP_MAX_DIGEST_SIZE];

#if (ESP_CMAC_SUPPORT == ENABLED)
   //CMAC integrity algorithm?
   if(sa->authMacAlgo == MAC_ALGO_CMAC)
   {
      CmacContext *cmacContext;

      //Point to the CMAC context
      cmacContext = &context->macContext.cmacContext;

      //The SAD entry specifies the algorithms and keys to be employed for
      //decryption and ICV computation (refer to RFC 4303, section 3.4.2)
      error = cmacInit(cmacContext, sa->authCipherAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The receiver computes the ICV over the ESP packet minus the ICV,
         //using the specified integrity algorithm
         cmacUpdate(cmacContext, espHeader, sizeof(EspHeader));
         cmacUpdate(cmacContext, payload, length);

         //Extended sequence numbers?
         if(sa->esn)
         {
            //Determine the higher-order bits of the sequence number
            uint32_t seqh = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum)) >> 32;

            //Convert the 32-bit value to network byte order
            seqh = htonl(seqh);

            //The high-order 32 bits are maintained as part of the sequence
            //number counter by both transmitter and receiver and are included
            //in the computation of the ICV (refer to RFC 4303, section 2.2.1)
            cmacUpdate(cmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize CMAC computation
         error = cmacFinal(cmacContext, checksum, sa->icvLen);

         //Erase CMAC context
         cmacDeinit(cmacContext);
      }
   }
   else
#endif
#if (ESP_HMAC_SUPPORT == ENABLED)
   //HMAC integrity algorithm?
   if(sa->authMacAlgo == MAC_ALGO_HMAC)
   {
      HmacContext *hmacContext;

      //Point to the HMAC context
      hmacContext = &context->macContext.hmacContext;

      //The SAD entry specifies the algorithms and keys to be employed for
      //decryption and ICV computation (refer to RFC 4303, section 3.4.2)
      error = hmacInit(hmacContext, sa->authHashAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //The receiver computes the ICV over the ESP packet minus the ICV,
         //using the specified integrity algorithm
         hmacUpdate(hmacContext, espHeader, sizeof(EspHeader));
         hmacUpdate(hmacContext, payload, length);

         //Extended sequence numbers?
         if(sa->esn)
         {
            //Determine the higher-order bits of the sequence number
            uint32_t seqh = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum)) >> 32;

            //Convert the 32-bit value to network byte order
            seqh = htonl(seqh);

            //The high-order 32 bits are maintained as part of the sequence
            //number counter by both transmitter and receiver and are included
            //in the computation of the ICV (refer to RFC 4303, section 2.2.1)
            hmacUpdate(hmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize HMAC computation
         hmacFinal(hmacContext, checksum);

         //Erase HMAC context
         hmacDeinit(hmacContext);
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
      //If the computed and received ICVs match, then the datagram is valid, and
      //it is accepted (refer to RFC 4303, section 3.4.4.1)
      if(cryptoCompMem(checksum, icv, sa->icvLen) != 0)
      {
         error = ERROR_DECRYPTION_FAILED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse ESP trailer
 * @param[in] data Pointer to the decrypted payload data
 * @param[in] length Length of the decrypted payload data, in bytes
 * @param[out] padLen Length of the padding, in bytes
 * @param[out] nextHeader Value of the next header field
 * @return Error code
 **/

error_t espParseTrailer(const uint8_t *data, size_t length, size_t *padLen,
   uint8_t *nextHeader)
{
   size_t i;
   const EspTrailer *espTrailer;

   //Malformed ESP trailer?
   if(length < sizeof(EspTrailer))
      return ERROR_DECRYPTION_FAILED;

   //Point to the ESP trailer
   length -= sizeof(EspTrailer);
   espTrailer = (const EspTrailer *) (data + length);

   //The Pad Length field is the length of the Padding field
   if(espTrailer->padLength > length)
      return ERROR_DECRYPTION_FAILED;

   //The receiver should inspect the Padding field (refer to RFC 4303,
   //section 2.4)
   for(i = 0; i < espTrailer->padLength; i++)
   {
      //Padding bytes make up a monotonically increasing sequence
      if(data[length - espTrailer->padLength + i] != (i + 1))
         return ERROR_DECRYPTION_FAILED;
   }

   //Return the length of the padding
   *padLen = espTrailer->padLength;

   //The Next Header field identifies the type of data contained in the
   //payload data (refer to RFC 4303, section 2.6)
   *nextHeader = espTrailer->nextHeader;

   //Successful processing
   return NO_ERROR;
}

#endif
