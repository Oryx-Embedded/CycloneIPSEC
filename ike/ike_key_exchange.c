/**
 * @file ike_key_exchange.c
 * @brief Diffie-Hellman key exchange
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
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
 * @brief Initialize Diffie-Hellman context
 * @param[in] sa Pointer to the IKE SA
 **/

void ikeInitDhContext(IkeSaEntry *sa)
{
#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Initialize Diffie-Hellman context
   dhInit(&sa->dhContext);
#endif

#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //Initialize ECDH context
   ecdhInit(&sa->ecdhContext);
#endif
}


/**
 * @brief Release Diffie-Hellman context
 * @param[in] sa Pointer to the IKE SA
 **/

void ikeFreeDhContext(IkeSaEntry *sa)
{
#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Release Diffie-Hellman context
   dhFree(&sa->dhContext);
#endif

#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //Release ECDH context
   ecdhFree(&sa->ecdhContext);
#endif
}


/**
 * @brief Diffie-Hellman key pair generation
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeGenerateDhKeyPair(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Debug message
   TRACE_INFO("Generating Diffie-Hellman key pair...\r\n");

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(sa->dhGroupNum))
   {
      //Load Diffie-Hellman parameters
      error = ikeLoadDhParams(&sa->dhContext.params, sa->dhGroupNum);

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = dhGenerateKeyPair(&sa->dhContext, context->prngAlgo,
            context->prngContext);
      }
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(sa->dhGroupNum))
   {
      //Load EC parameters
      error = ikeLoadEcdhParams(&sa->ecdhContext.params, sa->dhGroupNum);

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = ecdhGenerateKeyPair(&sa->ecdhContext, context->prngAlgo,
            context->prngContext);
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
 * @brief Compute Diffie-Hellman shared secret
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeComputeDhSharedSecret(IkeSaEntry *sa)
{
   error_t error;

   //Debug message
   TRACE_INFO("Computing Diffie-Hellman shared secret...\r\n");

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(sa->dhGroupNum))
   {
      //Let g^ir be the shared secret from the ephemeral Diffie-Hellman
      //exchange
      error = dhComputeSharedSecret(&sa->dhContext, sa->sharedSecret,
         IKE_MAX_SHARED_SECRET_LEN, &sa->sharedSecretLen);
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(sa->dhGroupNum))
   {
      //The Diffie-Hellman shared secret value consists of the x value of the
      //Diffie-Hellman common value (refer to RFC 5903, section 7)
      error = ecdhComputeSharedSecret(&sa->ecdhContext, sa->sharedSecret,
         IKE_MAX_SHARED_SECRET_LEN, &sa->sharedSecretLen);
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
 * @brief Format Diffie-Hellman public key
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Buffer where to format the Diffie-Hellman public key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeFormatDhPublicKey(IkeSaEntry *sa, uint8_t *p, size_t *written)
{
   error_t error;

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(sa->dhGroupNum))
   {
      const IkeDhGroup *dhGroup;

      //Get the Diffie-Hellman group that matches the specified group number
      dhGroup = ikeGetDhGroup(sa->dhGroupNum);

      //Valid Diffie-Hellman group?
      if(dhGroup != NULL)
      {
         //A Key Exchange payload is constructed by copying one's Diffie-Hellman
         //public value into the Key Exchange Data portion of the payload
         error = mpiExport(&sa->dhContext.ya, p, dhGroup->pLen,
            MPI_FORMAT_BIG_ENDIAN);
      }
      else
      {
         //Report an error
         error = ERROR_UNSUPPORTED_TYPE;
      }

      //Check status code
      if(!error)
      {
         //The length of the Diffie-Hellman public value for MODP groups must
         //be equal to the length of the prime modulus over which the
         //exponentiation was performed, prepending zero bits to the value if
         //necessary (refer to RFC 7296, section 3.4)
         *written = dhGroup->pLen;
      }
   }
   else
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   //ECDH key exchange algorithm?
   if(ikeIsEcdhKeyExchangeAlgo(sa->dhGroupNum))
   {
      const EcCurveInfo *curveInfo;

      //Get the elliptic curve that matches the specified group number
      curveInfo = ikeGetEcdhCurveInfo(sa->dhGroupNum);

      //Valid elliptic curve?
      if(curveInfo != NULL)
      {
         //Montgomery or Weierstrass curve?
         if(sa->dhGroupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE25519 ||
            sa->dhGroupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE448)
         {
            //Format public key
            error = mpiExport(&sa->ecdhContext.qa.q.x, p, curveInfo->pLen,
               MPI_FORMAT_LITTLE_ENDIAN);

            //Check status code
            if(!error)
            {
               //The Key Exchange Data consists of 32 or 56 octets (refer to
               //RFC 8031, section 3.1)
               *written = curveInfo->pLen;
            }
         }
         else
         {
            //In an ECP key exchange, the Diffie-Hellman public value passed in
            //a KE payload consists of two components, x and y, corresponding to
            //the coordinates of an elliptic curve point
            error = mpiExport(&sa->ecdhContext.qa.q.x, p, curveInfo->pLen,
               MPI_FORMAT_BIG_ENDIAN);

            //Check status code
            if(!error)
            {
               //The Diffie-Hellman public value is obtained by concatenating
               //the x and y values (refer to RFC 5903, section 7)
               error = mpiExport(&sa->ecdhContext.qa.q.y, p + curveInfo->pLen,
                  curveInfo->pLen, MPI_FORMAT_BIG_ENDIAN);
            }

            //Check status code
            if(!error)
            {
               //Each component has a fixed bit length
               *written = 2 * curveInfo->pLen;
            }
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
 * @brief Parse peer's Diffie-Hellman public key
 * @param[in] sa Pointer to the IKE SA
 * @param[out] p Pointer the Diffie-Hellman public key
 * @param[out] length Length of the Diffie-Hellman public key, in bytes
 * @return Error code
 **/

error_t ikeParseDhPublicKey(IkeSaEntry *sa, const uint8_t *p, size_t length)
{
   error_t error;

#if (IKE_DH_KE_SUPPORT == ENABLED)
   //Diffie-Hellman key exchange algorithm?
   if(ikeIsDhKeyExchangeAlgo(sa->dhGroupNum))
   {
      const IkeDhGroup *dhGroup;

      //Get the Diffie-Hellman group that matches the specified group number
      dhGroup = ikeGetDhGroup(sa->dhGroupNum);

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
            error = ikeLoadDhParams(&sa->dhContext.params, sa->dhGroupNum);

            //Check status code
            if(!error)
            {
               //Load peer's Diffie-Hellman public value
               error = mpiImport(&sa->dhContext.yb, p, length,
                  MPI_FORMAT_BIG_ENDIAN);
            }

            //Check status code
            if(!error)
            {
               //Ensure the public key is acceptable
               error = dhCheckPublicKey(&sa->dhContext.params,
                  &sa->dhContext.yb);
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
   if(ikeIsEcdhKeyExchangeAlgo(sa->dhGroupNum))
   {
      const EcCurveInfo *curveInfo;

      //Get the elliptic curve that matches the specified group number
      curveInfo = ikeGetEcdhCurveInfo(sa->dhGroupNum);

      //Valid elliptic curve?
      if(curveInfo != NULL)
      {
         //Montgomery or Weierstrass curve?
         if(sa->dhGroupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE25519 ||
            sa->dhGroupNum == IKE_TRANSFORM_ID_DH_GROUP_CURVE448)
         {
            //The Key Exchange Data consists of 32 or 56 octets (refer to
            //RFC 8031, section 3.1)
            if(length == curveInfo->pLen)
            {
               //Load public key
               error = mpiImport(&sa->ecdhContext.qb.q.x, p, curveInfo->pLen,
                  MPI_FORMAT_LITTLE_ENDIAN);
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_SYNTAX;
            }
         }
         else
         {
            //In an ECP key exchange, the Diffie-Hellman public value passed in
            //a KE payload consists of two components, x and y, corresponding to
            //the coordinates of an elliptic curve point
            if(length == (2 * curveInfo->pLen))
            {
               //Load EC parameters
               error = ikeLoadEcdhParams(&sa->ecdhContext.params,
                  sa->dhGroupNum);

               //Check status code
               if(!error)
               {
                  //Load x value
                  error = mpiImport(&sa->ecdhContext.qb.q.x, p, curveInfo->pLen,
                     MPI_FORMAT_BIG_ENDIAN);
               }

               //Check status code
               if(!error)
               {
                  //Load y value
                  error = mpiImport(&sa->ecdhContext.qb.q.y, p + curveInfo->pLen,
                     curveInfo->pLen, MPI_FORMAT_BIG_ENDIAN);
               }

               //Check status code
               if(!error)
               {
                  //Ensure the public key is acceptable
                  error = ecdhCheckPublicKey(&sa->ecdhContext.params,
                     &sa->ecdhContext.qb.q);
               }
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_SYNTAX;
            }
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
