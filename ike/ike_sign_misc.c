/**
 * @file ike_sign_misc.c
 * @brief Helper functions for signature generation and verification
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
#include "ike/ike_algorithms.h"
#include "ike/ike_sign_misc.h"
#include "ike/ike_key_material.h"
#include "encoding/oid.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED && IKE_CERT_AUTH_SUPPORT == ENABLED)


/**
 * @brief DSA signature formatting
 * @param[in] signature (R, S) integer pair
 * @param[out] data Pointer to the buffer where to store the encoded signature
 * @param[out] length Length of the encoded signature, in bytes
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeFormatDsaSignature(const DsaSignature *signature, uint8_t *data,
   size_t *length, IkeSignFormat format)
{
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Check signature format
   if(format == IKE_SIGN_FORMAT_RAW)
   {
      //Encode integer R
      error = mpiExport(&signature->r, data, IKE_SHA1_DIGEST_SIZE,
         MPI_FORMAT_BIG_ENDIAN);

      //Check status code
      if(!error)
      {
         //Encode integer S
         error = mpiExport(&signature->s, data + IKE_SHA1_DIGEST_SIZE,
            IKE_SHA1_DIGEST_SIZE, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Return the length of the signature
         *length = 2 * IKE_SHA1_DIGEST_SIZE;
      }
   }
   else if(format == IKE_SIGN_FORMAT_ASN1)
   {
      //Encode the DSA signature using ASN.1
      error = dsaExportSignature(signature, data, length);
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature formatting
 * @param[in] signature (R, S) integer pair
 * @param[out] data Pointer to the buffer where to store the encoded signature
 * @param[out] length Length of the encoded signature, in bytes
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeFormatEcdsaSignature(const EcdsaSignature *signature, uint8_t *data,
   size_t *length, IkeSignFormat format)
{
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Check signature format
   if(format == IKE_SIGN_FORMAT_RAW)
   {
      //The signature payload shall contain an encoding of the computed
      //signature consisting of the concatenation of a pair of integers R
      //and S (refer to RFC 4754, section 7)
      error = ecdsaExportSignature(signature, data, length,
         ECDSA_SIGNATURE_FORMAT_RAW);
   }
   else if(format == IKE_SIGN_FORMAT_ASN1)
   {
      //Encode the ECDSA signature using ASN.1
      error = ecdsaExportSignature(signature, data, length,
         ECDSA_SIGNATURE_FORMAT_ASN1);
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature parsing
 * @param[in] data Pointer to the encoded signature
 * @param[in] length Length of the encoded signature, in bytes
 * @param[out] signature (R, S) integer pair
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeParseDsaSignature(const uint8_t *data, size_t length,
   DsaSignature *signature, IkeSignFormat format)
{
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Check signature format
   if(format == IKE_SIGN_FORMAT_RAW)
   {
      //DSS is only defined with SHA-1
      if(length == (2 * IKE_SHA1_DIGEST_SIZE))
      {
         //Import integer R
         error = mpiImport(&signature->r, data, IKE_SHA1_DIGEST_SIZE,
            MPI_FORMAT_BIG_ENDIAN);

         //Check status code
         if(!error)
         {
            //Import integer S
            error = mpiImport(&signature->s, data + IKE_SHA1_DIGEST_SIZE,
               IKE_SHA1_DIGEST_SIZE, MPI_FORMAT_BIG_ENDIAN);
         }
      }
      else
      {
         //The length of the signature is not acceptable
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else if(format == IKE_SIGN_FORMAT_ASN1)
   {
      //Read the ASN.1 encoded signature
      error = dsaImportSignature(signature, data, length);
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature parsing
 * @param[in] curve Elliptic curve parameters
 * @param[in] data Pointer to the encoded signature
 * @param[in] length Length of the encoded signature, in bytes
 * @param[out] signature (R, S) integer pair
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeParseEcdsaSignature(const EcCurve *curve, const uint8_t *data,
   size_t length, EcdsaSignature *signature, IkeSignFormat format)
{
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Check signature format
   if(format == IKE_SIGN_FORMAT_RAW)
   {
      //The signature payload shall contain an encoding of the computed
      //signature consisting of the concatenation of a pair of integers
      //R and S (refer to RFC 4754, section 7)
      error = ecdsaImportSignature(signature, curve, data, length,
         ECDSA_SIGNATURE_FORMAT_RAW);
   }
   else if(format == IKE_SIGN_FORMAT_ASN1)
   {
      //Read the ASN.1 encoded signature
      error = ecdsaImportSignature(signature, curve, data, length,
         ECDSA_SIGNATURE_FORMAT_ASN1);
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Select the algorithm identifier that matches the specified
 *   certificate type and hash algorithms
 * @param[in] certType Certificate type
 * @param[in] hashAlgo Hash algorithm
 * @param[out] signAlgoId Signature algorithm identifier
 * @return Error code
 **/

error_t ikeSelectSignAlgoId(IkeCertType certType, const HashAlgo *hashAlgo,
   X509SignAlgoId *signAlgoId)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (IKE_RSA_SIGN_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(certType == IKE_CERT_TYPE_RSA)
   {
#if (IKE_SHA1_SUPPORT == ENABLED)
      //SHA-1 hash algorithm?
      if(hashAlgo == SHA1_HASH_ALGO)
      {
         //RSA with SHA-1 signature algorithm
         signAlgoId->oid.value = SHA1_WITH_RSA_ENCRYPTION_OID;
         signAlgoId->oid.length = sizeof(SHA1_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm?
      if(hashAlgo == SHA256_HASH_ALGO)
      {
         //RSA with SHA-256 signature algorithm
         signAlgoId->oid.value = SHA256_WITH_RSA_ENCRYPTION_OID;
         signAlgoId->oid.length = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm?
      if(hashAlgo == SHA384_HASH_ALGO)
      {
         //RSA with SHA-384 signature algorithm
         signAlgoId->oid.value = SHA384_WITH_RSA_ENCRYPTION_OID;
         signAlgoId->oid.length = sizeof(SHA384_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm?
      if(hashAlgo == SHA512_HASH_ALGO)
      {
         //RSA with SHA-512 signature algorithm
         signAlgoId->oid.value = SHA512_WITH_RSA_ENCRYPTION_OID;
         signAlgoId->oid.length = sizeof(SHA512_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
      //Invalid hash algorithm?
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm?
   if(certType == IKE_CERT_TYPE_RSA_PSS)
   {
      //Valid hash algorithm?
      if(hashAlgo != NULL)
      {
         //Set the OID of the signature algorithm
         signAlgoId->oid.value = RSASSA_PSS_OID;
         signAlgoId->oid.length = sizeof(RSASSA_PSS_OID);

         //Set the OID of the hash algorithm
         signAlgoId->rsaPssParams.hashAlgo.value = hashAlgo->oid;
         signAlgoId->rsaPssParams.hashAlgo.length = hashAlgo->oidSize;

         //Set RSASSA-PSS parameters
         signAlgoId->rsaPssParams.maskGenAlgo.value = MGF1_OID;
         signAlgoId->rsaPssParams.maskGenAlgo.length = sizeof(MGF1_OID);
         signAlgoId->rsaPssParams.maskGenHashAlgo.value = hashAlgo->oid;
         signAlgoId->rsaPssParams.maskGenHashAlgo.length = hashAlgo->oidSize;
         signAlgoId->rsaPssParams.saltLen = hashAlgo->digestSize;
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   //DSA signature algorithm?
   if(certType == IKE_CERT_TYPE_DSA)
   {
#if (IKE_SHA1_SUPPORT == ENABLED)
      //SHA-1 hash algorithm?
      if(hashAlgo == SHA1_HASH_ALGO)
      {
         //DSA with SHA-1 signature algorithm
         signAlgoId->oid.value = DSA_WITH_SHA1_OID;
         signAlgoId->oid.length = sizeof(DSA_WITH_SHA1_OID);
      }
      else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm?
      if(hashAlgo == SHA256_HASH_ALGO)
      {
         //DSA with SHA-256 signature algorithm
         signAlgoId->oid.value = DSA_WITH_SHA256_OID;
         signAlgoId->oid.length = sizeof(DSA_WITH_SHA256_OID);
      }
      else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm?
      if(hashAlgo == SHA384_HASH_ALGO)
      {
         //DSA with SHA-384 signature algorithm
         signAlgoId->oid.value = DSA_WITH_SHA384_OID;
         signAlgoId->oid.length = sizeof(DSA_WITH_SHA384_OID);
      }
      else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm?
      if(hashAlgo == SHA512_HASH_ALGO)
      {
         //DSA with SHA-512 signature algorithm
         signAlgoId->oid.value = DSA_WITH_SHA512_OID;
         signAlgoId->oid.length = sizeof(DSA_WITH_SHA512_OID);
      }
      else
#endif
      //Invalid hash algorithm?
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   if(certType == IKE_CERT_TYPE_ECDSA_P256 ||
      certType == IKE_CERT_TYPE_ECDSA_P384 ||
      certType == IKE_CERT_TYPE_ECDSA_P521 ||
      certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP256R1 ||
      certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP384R1 ||
      certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP512R1)
   {
#if (IKE_SHA1_SUPPORT == ENABLED)
      //SHA-1 hash algorithm?
      if(hashAlgo == SHA1_HASH_ALGO)
      {
         //ECDSA with SHA-1 signature algorithm
         signAlgoId->oid.value = ECDSA_WITH_SHA1_OID;
         signAlgoId->oid.length = sizeof(ECDSA_WITH_SHA1_OID);
      }
      else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm?
      if(hashAlgo == SHA256_HASH_ALGO)
      {
         //ECDSA with SHA-256 signature algorithm
         signAlgoId->oid.value = ECDSA_WITH_SHA256_OID;
         signAlgoId->oid.length = sizeof(ECDSA_WITH_SHA256_OID);
      }
      else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm?
      if(hashAlgo == SHA384_HASH_ALGO)
      {
         //ECDSA with SHA-384 signature algorithm
         signAlgoId->oid.value = ECDSA_WITH_SHA384_OID;
         signAlgoId->oid.length = sizeof(ECDSA_WITH_SHA384_OID);
      }
      else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm?
      if(hashAlgo == SHA512_HASH_ALGO)
      {
         //ECDSA with SHA-512 signature algorithm
         signAlgoId->oid.value = ECDSA_WITH_SHA512_OID;
         signAlgoId->oid.length = sizeof(ECDSA_WITH_SHA512_OID);
      }
      else
#endif
      //Invalid hash algorithm?
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(certType == IKE_CERT_TYPE_ED25519)
   {
      //Set the OID of the signature algorithm
      signAlgoId->oid.value = ED25519_OID;
      signAlgoId->oid.length = sizeof(ED25519_OID);
   }
   else
#endif
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(certType == IKE_CERT_TYPE_ED448)
   {
      //Set the OID of the signature algorithm
      signAlgoId->oid.value = ED448_OID;
      signAlgoId->oid.length = sizeof(ED448_OID);
   }
   else
#endif
   //Invalid signature algorithm?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the signature and hash algorithms that match the specified
 *   identifier
 * @param[in] signAlgoId Signature algorithm identifier
 * @param[out] signAlgo Signature algorithm
 * @param[out] hashAlgo Hash algorithm
 * @return Error code
 **/

error_t ikeSelectSignAlgo(const X509SignAlgoId *signAlgoId,
   IkeSignAlgo *signAlgo, const HashAlgo **hashAlgo)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Initialize status code
   error = NO_ERROR;

   //Point to the object identifier
   oid = signAlgoId->oid.value;
   oidLen = signAlgoId->oid.length;

#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 signature algorithm?
   if(OID_COMP(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_RSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 signature algorithm?
   if(OID_COMP(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_RSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //RSA with SHA-384 signature algorithm?
   if(OID_COMP(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_RSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 signature algorithm?
   if(OID_COMP(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_RSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm
   if(OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Get the OID of the hash algorithm
      oid = signAlgoId->rsaPssParams.hashAlgo.value;
      oidLen = signAlgoId->rsaPssParams.hashAlgo.length;

#if (IKE_SHA1_SUPPORT == ENABLED)
      //SHA-1 hash algorithm identifier?
      if(OID_COMP(oid, oidLen, SHA1_OID) == 0)
      {
         //RSA-PSS with SHA-1 signature algorithm
         *signAlgo = IKE_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA1_HASH_ALGO;
      }
      else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm identifier?
      if(OID_COMP(oid, oidLen, SHA256_OID) == 0)
      {
         //RSA-PSS with SHA-256 signature algorithm
         *signAlgo = IKE_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA256_HASH_ALGO;
      }
      else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm identifier?
      if(OID_COMP(oid, oidLen, SHA384_OID) == 0)
      {
         //RSA-PSS with SHA-384 signature algorithm
         *signAlgo = IKE_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA384_HASH_ALGO;
      }
      else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm identifier?
      if(OID_COMP(oid, oidLen, SHA512_OID) == 0)
      {
         //RSA-PSS with SHA-512 signature algorithm
         *signAlgo = IKE_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA512_HASH_ALGO;
      }
      else
#endif
      //Unknown hash algorithm identifier?
      {
         //The specified signature algorithm is not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //DSA with SHA-1 signature algorithm?
   if(OID_COMP(oid, oidLen, DSA_WITH_SHA1_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_DSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //DSA with SHA-256 signature algorithm?
   if(OID_COMP(oid, oidLen, DSA_WITH_SHA256_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_DSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //DSA with SHA-384 signature algorithm?
   if(OID_COMP(oid, oidLen, DSA_WITH_SHA384_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_DSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //DSA with SHA-512 signature algorithm?
   if(OID_COMP(oid, oidLen, DSA_WITH_SHA512_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_DSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //ECDSA with SHA-1 signature algorithm?
   if(OID_COMP(oid, oidLen, ECDSA_WITH_SHA1_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_SHA256_SUPPORT == ENABLED)
   //ECDSA with SHA-256 signature algorithm?
   if(OID_COMP(oid, oidLen, ECDSA_WITH_SHA256_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_SHA384_SUPPORT == ENABLED)
   //ECDSA with SHA-384 signature algorithm?
   if(OID_COMP(oid, oidLen, ECDSA_WITH_SHA384_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_SHA512_SUPPORT == ENABLED)
   //ECDSA with SHA-512 signature algorithm?
   if(OID_COMP(oid, oidLen, ECDSA_WITH_SHA512_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(OID_COMP(oid, oidLen, ED25519_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ED25519;
      *hashAlgo = NULL;
   }
   else
#endif
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(OID_COMP(oid, oidLen, ED448_OID) == 0)
   {
      *signAlgo = IKE_SIGN_ALGO_ED448;
      *hashAlgo = NULL;
   }
   else
#endif
   //Unknown signature algorithm?
   {
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select the hash algorithm to be used for signing
 * @param[in] sa Pointer to the IKE SA
 * @param[in] preferredHashAlgoId Preferred hash algorithm (provided as a hint)
 * @return Signature hash algorithm
 **/

const HashAlgo *ikeSelectSignHashAlgo(IkeSaEntry *sa,
   uint16_t preferredHashAlgoId)
{
#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   uint16_t n;
   uint16_t hashAlgoId;
   const HashAlgo *hashAlgo;

   //Clear hash algorithm identifier
   hashAlgoId = 0;

   //If the preferred hash algorithm is not supported by the peer, then select
   //a stronger hash algorithm
   for(n = preferredHashAlgoId; n <= IKE_HASH_ALGO_SHA512; n++)
   {
      //Check whether the current hash algorithm is supported by the peer
      if((sa->signHashAlgos & (1U << n)) != 0)
      {
         hashAlgoId = n;
         break;
      }
   }

   //If no stronger hash algorithm is not supported by the peer, then select
   //a weaker hash algorithm
   if(hashAlgoId == 0)
   {
      //Loop through the list of signature hash algorithms
      for(n = preferredHashAlgoId; n >= IKE_HASH_ALGO_SHA1; n--)
      {
         //Check whether the current hash algorithm is supported by the peer
         if((sa->signHashAlgos & (1U << n)) != 0)
         {
            hashAlgoId = n;
            break;
         }
      }
   }

#if (IKE_SHA1_SUPPORT == ENABLED)
   //SHA-1 hash algorithm?
   if(hashAlgoId == IKE_HASH_ALGO_SHA1)
   {
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (IKE_SHA256_SUPPORT == ENABLED)
   //SHA-256 hash algorithm?
   if(hashAlgoId == IKE_HASH_ALGO_SHA256)
   {
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (IKE_SHA384_SUPPORT == ENABLED)
   //SHA-384 hash algorithm?
   if(hashAlgoId == IKE_HASH_ALGO_SHA384)
   {
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (IKE_SHA512_SUPPORT == ENABLED)
   //SHA-512 hash algorithm?
   if(hashAlgoId == IKE_HASH_ALGO_SHA512)
   {
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown hash algorithm?
   {
      hashAlgo = NULL;
   }

   //Return the hash algorithm to be used for signing
   return hashAlgo;
#else
   //The digital signature method is not supported
   return NULL;
#endif
}


/**
 * @brief Retrieve the octets to be signed using EdDSA
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id MAC authentication data
 * @param[in] idLen MAC authentication data
 * @param[out] macId Temporary buffer needed to calculate MACedID
 * @param[out] messageChunks Array of data chunks representing the message
 *   to be signed
 * @param[in] initiator Specifies whether the digest is performed at initiator
 *   or responder side
 * @return Error code
 **/

error_t ikeGetSignedOctets(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t *macId, DataChunk *messageChunks, bool_t initiator)
{
   error_t error;

   //Check whether the calculation is performed at initiator side
   if(initiator)
   {
      //Compute prf(SK_pi, IDi')
      error = ikeComputePrf(sa, sa->skpi, sa->prfKeyLen, id, idLen,
         macId);

      //Check status code
      if(!error)
      {
         //The initiator signs the first message (IKE_SA_INIT request),
         //starting with the first octet of the first SPI in the header
         //and ending with the last octet of the last payload
         messageChunks[0].buffer = sa->initiatorSaInit;
         messageChunks[0].length = sa->initiatorSaInitLen;

         //Appended to this (for purposes of computing the signature)
         //are the responder's nonce Nr, and the value prf(SK_pi, IDi')
         messageChunks[1].buffer = sa->responderNonce;
         messageChunks[1].length = sa->responderNonceLen;
         messageChunks[2].buffer = macId;
         messageChunks[2].length = sa->prfKeyLen;
      }
   }
   else
   {
      //Compute prf(SK_pr, IDr')
      error = ikeComputePrf(sa, sa->skpr, sa->prfKeyLen, id, idLen, macId);

      //Check status code
      if(!error)
      {
         //For the responder, the octets to be signed start with the
         //first octet of the first SPI in the header of the second
         //message (IKE_SA_INIT response) and end with the last octet
         //of the last payload in the second message
         messageChunks[0].buffer = sa->responderSaInit;
         messageChunks[0].length = sa->responderSaInitLen;

         //Appended to this (for purposes of computing the signature)
         //are the initiator's nonce Ni, and the value prf(SK_pr, IDr')
         messageChunks[1].buffer = sa->initiatorNonce;
         messageChunks[1].length = sa->initiatorNonceLen;
         messageChunks[2].buffer = macId;
         messageChunks[2].length = sa->prfKeyLen;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Digest signed octets
 * @param[in] sa Pointer to the IKE SA
 * @param[in] hashAlgo Underlying hash function
 * @param[in] id MAC authentication data
 * @param[in] idLen MAC authentication data
 * @param[out] digest Calculated digest
 * @param[in] initiator Specifies whether the digest is performed at initiator
 *   or responder side
 * @return Error code
 **/

error_t ikeDigestSignedOctets(IkeSaEntry *sa, const HashAlgo *hashAlgo,
   const uint8_t *id, size_t idLen, uint8_t *digest, bool_t initiator)
{
   error_t error;
   HashContext hashContext;
   uint8_t macId[IKE_MAX_DIGEST_SIZE];

   //Check whether the calculation is performed at initiator side
   if(initiator)
   {
      //Compute prf(SK_pi, IDi')
      error = ikeComputePrf(sa, sa->skpi, sa->prfKeyLen, id, idLen, macId);

      //Check status code
      if(!error)
      {
         //The initiator signs the first message (IKE_SA_INIT request), starting
         //with the first octet of the first SPI in the header and ending with
         //the last octet of the last payload
         hashAlgo->init(&hashContext);
         hashAlgo->update(&hashContext, sa->initiatorSaInit, sa->initiatorSaInitLen);

         //Appended to this (for purposes of computing the signature) are the
         //responder's nonce Nr, and the value prf(SK_pi, IDi')
         hashAlgo->update(&hashContext, sa->responderNonce, sa->responderNonceLen);
         hashAlgo->update(&hashContext, macId, sa->prfKeyLen);
         hashAlgo->final(&hashContext, digest);
      }
   }
   else
   {
      //Compute prf(SK_pr, IDr')
      error = ikeComputePrf(sa, sa->skpr, sa->prfKeyLen, id, idLen, macId);

      //Check status code
      if(!error)
      {
         //For the responder, the octets to be signed start with the first octet
         //of the first SPI in the header of the second message (IKE_SA_INIT
         //response) and end with the last octet of the last payload in the
         //second message
         hashAlgo->init(&hashContext);
         hashAlgo->update(&hashContext, sa->responderSaInit, sa->responderSaInitLen);

         //Appended to this (for purposes of computing the signature) are the
         //initiator's nonce Ni, and the value prf(SK_pr, IDr')
         hashAlgo->update(&hashContext, sa->initiatorNonce, sa->initiatorNonceLen);
         hashAlgo->update(&hashContext, macId, sa->prfKeyLen);
         hashAlgo->final(&hashContext, digest);
      }
   }

   //Return status code
   return error;
}

#endif
