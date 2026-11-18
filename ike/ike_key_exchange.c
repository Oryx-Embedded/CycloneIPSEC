/**
 * @file ike_key_exchange.c
 * @brief Diffie-Hellman key exchange
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
#include "ike/ike_key_exchange.h"
#include "ike/ike_algorithms.h"
#include "ike/ike_dh_groups.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Initialize key exchange context
 * @param[in] keContext Pointer to the key exchange context
 **/

void ikeInitKeContext(IkeKeContext *keContext)
{
#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Initialize Diffie-Hellman context
   dhInit(&keContext->dhContext);
#endif

#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //Initialize ECDH context
   ecdhInit(&keContext->ecdhContext);
#endif
}


/**
 * @brief Release key exchange context
 * @param[in] keContext Pointer to the key exchange context
 **/

void ikeFreeKeContext(IkeKeContext *keContext)
{
#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Release Diffie-Hellman context
   dhFree(&keContext->dhContext);
#endif

#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //Release ECDH context
   ecdhFree(&keContext->ecdhContext);
#endif
}


/**
 * @brief Key pair generation
 * @param[in] keContext Pointer to the key exchange context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t ikeGenerateKeyPair(IkeKeContext *keContext, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   error_t error;

   //Debug message
   TRACE_INFO("Generating Diffie-Hellman key pair...\r\n");

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(keContext->groupNum))
   {
      //Load Diffie-Hellman parameters
      error = ikeLoadDhParams(&keContext->dhContext.params, keContext->groupNum);

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = dhGenerateKeyPair(&keContext->dhContext, prngAlgo,
            prngContext);
      }
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(keContext->groupNum))
   {
      const EcCurve *curve;

      //Get the elliptic curve that matches the specified group number
      curve = ikeGetEcdhCurve(keContext->groupNum);

      //Valid elliptic curve?
      if(curve != NULL)
      {
         //Save elliptic curve parameters
         error = ecdhSetCurve(&keContext->ecdhContext, curve);

         //Check status code
         if(!error)
         {
            //Generate an ephemeral key pair
            error = ecdhGenerateKeyPair(&keContext->ecdhContext, prngAlgo,
               prngContext);
         }
      }
      else
      {
         //Report an error
         error = ERROR_UNSUPPORTED_TYPE;
      }
   }
   else
#endif
   //Unknown key exchange algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Compute shared secret
 * @param[in] keContext Pointer to the key exchange context
 * @param[out] output Buffer where to store the shared secret
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

error_t ikeComputeSharedSecret(IkeKeContext *keContext, uint8_t *output,
   size_t *outputLen)
{
   error_t error;

   //Debug message
   TRACE_INFO("Computing shared secret...\r\n");

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(keContext->groupNum))
   {
      //Let g^ir be the shared secret from the ephemeral Diffie-Hellman
      //exchange
      error = dhComputeSharedSecret(&keContext->dhContext, output,
         IKE_MAX_SHARED_SECRET_LEN, outputLen);

      //The ephemeral private key must be destroyed as soon as possible (refer
      //to RFC 9206, section 10)
      dhErasePrivateKey(&keContext->dhContext);
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(keContext->groupNum))
   {
      //The Diffie-Hellman shared secret value consists of the x value of the
      //Diffie-Hellman common value (refer to RFC 5903, section 7)
      error = ecdhComputeSharedSecret(&keContext->ecdhContext, output,
         IKE_MAX_SHARED_SECRET_LEN, outputLen);

      //The ephemeral private key must be destroyed as soon as possible (refer
      //to RFC 9206, section 10)
      ecdhErasePrivateKey(&keContext->ecdhContext);
   }
   else
#endif
   //Unknown key exchange algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Format public key
 * @param[in] keContext Pointer to the key exchange context
 * @param[out] p Buffer where to format the public key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeFormatPublicKey(IkeKeContext *keContext, uint8_t *p,
   size_t *written)
{
   error_t error;

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(keContext->groupNum))
   {
      //The length of the Diffie-Hellman public value for MODP groups must be
      //equal to the length of the prime modulus over which the exponentiation
      //was performed, prepending zero bits to the value if necessary (refer
      //to RFC 7296, section 3.4)
      error = dhExportPublicKey(&keContext->dhContext, p, written,
         MPI_FORMAT_BIG_ENDIAN);
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(keContext->groupNum))
   {
      //The Diffie-Hellman public value is obtained by concatenating the x and
      //y values (refer to RFC 5903, section 7)
      error = ecdhExportPublicKey(&keContext->ecdhContext, p, written,
         EC_PUBLIC_KEY_FORMAT_RAW);
   }
   else
#endif
   //Unknown key exchange algorithm?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse peer's public key
 * @param[in] keContext Pointer to the key exchange context
 * @param[out] p Pointer the public key
 * @param[out] length Length of the public key, in bytes
 * @return Error code
 **/

error_t ikeParsePublicKey(IkeKeContext *keContext, const uint8_t *p,
   size_t length)
{
   error_t error;

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(keContext->groupNum))
   {
      const IkeDhGroup *dhGroup;

      //Get the Diffie-Hellman group that matches the specified group number
      dhGroup = ikeGetDhGroup(keContext->groupNum);

      //Valid Diffie-Hellman group?
      if(dhGroup != NULL)
      {
         //The length of the Diffie-Hellman public value for MODP groups must
         //be equal to the length of the prime modulus over which the
         //exponentiation was performed, prepending zero bits to the value if
         //necessary (refer to RFC 7296, section 3.4)
         if(length == dhGroup->pLen)
         {
            //Load Diffie-Hellman parameters
            error = ikeLoadDhParams(&keContext->dhContext.params, keContext->groupNum);

            //Check status code
            if(!error)
            {
               //Load peer's Diffie-Hellman public value
               error = dhImportPeerPublicKey(&keContext->dhContext, p, length,
                  MPI_FORMAT_BIG_ENDIAN);
            }
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_SYNTAX;
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_GROUP;
      }
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(keContext->groupNum))
   {
      const EcCurve *curve;

      //Get the elliptic curve that matches the specified group number
      curve = ikeGetEcdhCurve(keContext->groupNum);

      //Valid elliptic curve?
      if(curve != NULL)
      {
         //Save elliptic curve parameters
         error = ecdhSetCurve(&keContext->ecdhContext, curve);

         //Check status code
         if(!error)
         {
            //In an ECP key exchange, the Diffie-Hellman public value passed in
            //a KE payload consists of two components, x and y, corresponding
            //to the coordinates of an elliptic curve point
            error = ecdhImportPeerPublicKey(&keContext->ecdhContext, p, length,
               EC_PUBLIC_KEY_FORMAT_RAW);
         }
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_GROUP;
      }
   }
   else
#endif
   //Unknown key exchange algorithm?
   {
      //Report an error
      error = ERROR_INVALID_GROUP;
   }

   //Return status code
   return error;
}

#endif
