/**
 * @file ike_sign_verify.c
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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
#include "ike/ike_sign_verify.h"
#include "encoding/oid.h"
#include "pkix/x509_key_parse.h"
#include "pkix/x509_sign_parse.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED && IKE_CERT_AUTH_SUPPORT == ENABLED)


/**
 * @brief Signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] authMethod Authentication method
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @return Error code
 **/

error_t ikeVerifySignature(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t authMethod, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen)
{
   error_t error;

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   //Digital signature method?
   if(authMethod == IKE_AUTH_METHOD_DIGITAL_SIGN)
   {
      //The new digital signature method is flexible enough to include all
      //current signature methods (RSA, RSA-PSS, DSA, ECDSA and EdDSA) and add
      //new methods in the future
      error = ikeVerifyDigitalSignature(sa, id, idLen, publicKeyInfo,
         (const IkeAuthData *) signature, signatureLen);
   }
   else
#endif
#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //RSA signature method?
   if(authMethod == IKE_AUTH_METHOD_RSA)
   {
      //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = ikeVerifyRsaSignature(sa, id, idLen, publicKeyInfo,
         SHA1_HASH_ALGO, signature, signatureLen);
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //DSA signature method?
   if(authMethod == IKE_AUTH_METHOD_DSS)
   {
      //Verify DSA signature
      error = ikeVerifyDsaSignature(sa, id, idLen, publicKeyInfo,
         SHA1_HASH_ALGO, signature, signatureLen, IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_256_SUPPORT == ENABLED && \
   IKE_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 signature method?
   if(authMethod == IKE_AUTH_METHOD_ECDSA_P256_SHA256)
   {
      //Verify ECDSA signature
      error = ikeVerifyEcdsaSignature(sa, id, idLen, publicKeyInfo,
         SECP256R1_CURVE, SHA256_HASH_ALGO, signature, signatureLen,
         IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_384_SUPPORT == ENABLED && \
   IKE_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 signature method?
   if(authMethod == IKE_AUTH_METHOD_ECDSA_P384_SHA384)
   {
      //Verify ECDSA signature
      error = ikeVerifyEcdsaSignature(sa, id, idLen, publicKeyInfo,
         SECP384R1_CURVE, SHA384_HASH_ALGO, signature, signatureLen,
         IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_521_SUPPORT == ENABLED && \
   IKE_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 signature method?
   if(authMethod == IKE_AUTH_METHOD_ECDSA_P521_SHA512)
   {
      //Verify ECDSA signature
      error = ikeVerifyEcdsaSignature(sa, id, idLen, publicKeyInfo,
         SECP521R1_CURVE, SHA512_HASH_ALGO, signature, signatureLen,
         IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
   //Invalid signature method?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Digital signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] authData Pointer to the authentication data
 * @param[in] authDataLen Length of the authentication data, in bytes
 * @return Error code
 **/

error_t ikeVerifyDigitalSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const IkeAuthData *authData, size_t authDataLen)
{
   error_t error;
   size_t n;
   size_t signatureLen;
   const uint8_t *signature;
   const HashAlgo *hashAlgo;
   IkeSignAlgo signAlgo;
   X509SignAlgoId signAlgoId;

   //Check the length of the authentication data
   if(authDataLen >= sizeof(IkeAuthData))
   {
      //The signature value is prefixed with an ASN.1 object indicating the
      //algorithm used to generate the signature (refer to RFC 7427, section 3)
      if(authDataLen >= (sizeof(IkeAuthData) + authData->algoIdLen))
      {
         //Parse ASN.1 object
         error = x509ParseSignatureAlgo(authData->algoId, authData->algoIdLen,
            &n, &signAlgoId);

         //Check status code
         if(!error)
         {
            //Select the signature and hash algorithms that match the specified
            //identifier
            error = ikeSelectSignAlgo(&signAlgoId, &signAlgo, &hashAlgo);
         }

         //Check status code
         if(!error)
         {
            //There is no padding between the ASN.1 object and the signature value
            signature = authData->algoId + authData->algoIdLen;

            //Determine the length of the signature, in bytes
            signatureLen = authDataLen - sizeof(IkeAuthData) -
               authData->algoIdLen;

#if (IKE_RSA_SIGN_SUPPORT == ENABLED)
            //RSA signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_RSA)
            {
               //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
               error = ikeVerifyRsaSignature(sa, id, idLen, publicKeyInfo,
                  hashAlgo, signature, signatureLen);
            }
            else
#endif
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
            //RSA-PSS signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_RSA_PSS)
            {
               //Verify RSA signature (RSASSA-PSS signature scheme)
               error = ikeVerifyRsaPssSignature(sa, id, idLen, publicKeyInfo,
                  hashAlgo, signAlgoId.rsaPssParams.saltLen, signature,
                  signatureLen);
            }
            else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_DSA)
            {
               //Verify DSA signature
               error = ikeVerifyDsaSignature(sa, id, idLen, publicKeyInfo,
                  hashAlgo, signature, signatureLen, IKE_SIGN_FORMAT_ASN1);
            }
            else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_ECDSA)
            {
               //Verify ECDSA signature
               error = ikeVerifyEcdsaSignature(sa, id, idLen, publicKeyInfo,
                  NULL, hashAlgo, signature, signatureLen, IKE_SIGN_FORMAT_ASN1);
            }
            else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
            //Ed25519 signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_ED25519)
            {
               //Verify Ed25519 signature (PureEdDSA mode)
               error = ikeVerifyEd25519Signature(sa, id, idLen, publicKeyInfo,
                  signature, signatureLen);
            }
            else
#endif
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
            //Ed448 signature algorithm?
            if(signAlgo == IKE_SIGN_ALGO_ED448)
            {
               //Verify Ed448 signature (PureEdDSA mode)
               error = ikeVerifyEd448Signature(sa, id, idLen, publicKeyInfo,
                  signature, signatureLen);
            }
            else
#endif
            //Invalid signature algorithm?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
         }
      }
      else
      {
         //Malformed ASN.1 object
         error = ERROR_INVALID_MESSAGE;
      }
   }
   else
   {
      //Malformed authentication data
      error = ERROR_INVALID_MESSAGE;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] hashAlgo Hash algorithm
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @return Error code
 **/

error_t ikeVerifyRsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, const uint8_t *signature, size_t signatureLen)
{
#if (IKE_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey rsaPublicKey;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Check public key identifier
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      RSA_ENCRYPTION_OID) == 0)
   {
      //Initialize RSA public key
      rsaInitPublicKey(&rsaPublicKey);

      //Digest signed octets
      error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
         !sa->originalInitiator);

      //Check status code
      if(!error)
      {
         //Import RSA public key
         error = x509ImportRsaPublicKey(&rsaPublicKey, publicKeyInfo);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the modulus, in bits
         k = mpiGetBitLength(&rsaPublicKey.n);

         //Applications should also enforce minimum and maximum key sizes
         if(k < IKE_MIN_RSA_MODULUS_SIZE || k > IKE_MAX_RSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = rsassaPkcs1v15Verify(&rsaPublicKey, hashAlgo, digest,
            signature, signatureLen);
      }

      //Free previously allocated memory
      rsaFreePublicKey(&rsaPublicKey);
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] hashAlgo Hash algorithm
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @return Error code
 **/

error_t ikeVerifyRsaPssSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, size_t saltLen, const uint8_t *signature,
   size_t signatureLen)
{
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   size_t oidLen;
   const uint8_t *oid;
   RsaPublicKey rsaPublicKey;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Retrieve public key identifier
   oid = publicKeyInfo->oid.value;
   oidLen = publicKeyInfo->oid.length;

   //Check public key identifier
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0 ||
      OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Initialize RSA public key
      rsaInitPublicKey(&rsaPublicKey);

      //Digest signed octets
      error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
         !sa->originalInitiator);

      //Check status code
      if(!error)
      {
         //Import RSA public key
         error = x509ImportRsaPublicKey(&rsaPublicKey, publicKeyInfo);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the modulus, in bits
         k = mpiGetBitLength(&rsaPublicKey.n);

         //Applications should also enforce minimum and maximum key sizes
         if(k < IKE_MIN_RSA_MODULUS_SIZE || k > IKE_MAX_RSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
         error = rsassaPssVerify(&rsaPublicKey, hashAlgo, saltLen, digest,
            signature, signatureLen);
      }

      //Free previously allocated memory
      rsaFreePublicKey(&rsaPublicKey);
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] hashAlgo Hash algorithm
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeVerifyDsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const HashAlgo *hashAlgo, const uint8_t *signature, size_t signatureLen,
   IkeSignFormat format)
{
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   DsaPublicKey dsaPublicKey;
   DsaSignature dsaSignature;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Check public key identifier
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      DSA_OID) == 0)
   {
      //Initialize DSA public key
      dsaInitPublicKey(&dsaPublicKey);
      //Initialize DSA signature
      dsaInitSignature(&dsaSignature);

      //Digest signed octets
      error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
         !sa->originalInitiator);

      //Check status code
      if(!error)
      {
         //Import DSA public key
         error = x509ImportDsaPublicKey(&dsaPublicKey, publicKeyInfo);
      }

      //Check status code
      if(!error)
      {
         //Get the length of the modulus, in bits
         k = mpiGetBitLength(&dsaPublicKey.params.p);

         //Applications should also enforce minimum and maximum key sizes
         if(k < IKE_MIN_DSA_MODULUS_SIZE || k > IKE_MAX_DSA_MODULUS_SIZE)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
         }
      }

      //Check status code
      if(!error)
      {
         //Decode (R, S) integer pair
         error = ikeParseDsaSignature(signature, signatureLen, &dsaSignature,
            format);
      }

      //Check status code
      if(!error)
      {
         //Verify DSA signature
         error = dsaVerifySignature(&dsaPublicKey, digest, hashAlgo->digestSize,
            &dsaSignature);
      }

      //Free previously allocated memory
      dsaFreePublicKey(&dsaPublicKey);
      dsaFreeSignature(&dsaSignature);
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] group Elliptic curve group
 * @param[in] hashAlgo Hash algorithm
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeVerifyEcdsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const EcCurve *group, const HashAlgo *hashAlgo, const uint8_t *signature,
   size_t signatureLen, IkeSignFormat format)
{
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   const EcCurve *curve;
   EcPublicKey ecPublicKey;
   EcdsaSignature ecdsaSignature;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Check public key identifier
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      EC_PUBLIC_KEY_OID) == 0)
   {
      //Retrieve EC domain parameters
      curve = ecGetCurve(publicKeyInfo->ecParams.namedCurve.value,
         publicKeyInfo->ecParams.namedCurve.length);

      //Make sure the specified elliptic curve is acceptable
      if(curve != NULL && (curve == group || group == NULL))
      {
         //Initialize DSA public key
         ecInitPublicKey(&ecPublicKey);
         //Initialize DSA signature
         ecdsaInitSignature(&ecdsaSignature);

         //Digest signed octets
         error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
            !sa->originalInitiator);

         //Check status code
         if(!error)
         {
            //Import EC public key
            error = x509ImportEcPublicKey(&ecPublicKey, publicKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Decode (R, S) integer pair
            error = ikeParseEcdsaSignature(curve, signature, signatureLen,
               &ecdsaSignature, format);
         }

         //Check status code
         if(!error)
         {
            //Verify ECDSA signature
            error = ecdsaVerifySignature(&ecPublicKey, digest,
               hashAlgo->digestSize, &ecdsaSignature);
         }

         //Free previously allocated memory
         ecFreePublicKey(&ecPublicKey);
         ecdsaFreeSignature(&ecdsaSignature);
      }
      else
      {
         //Unknown elliptic curve identifier
         return ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @return Error code
 **/

error_t ikeVerifyEd25519Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen)
{
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   DataChunk messageChunks[3];
   uint8_t macId[IKE_MAX_DIGEST_SIZE];

   //Check public key identifier
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      ED25519_OID) == 0)
   {
      //Valid Ed25519 public key?
      if(publicKeyInfo->ecPublicKey.q.value != NULL &&
         publicKeyInfo->ecPublicKey.q.length == ED25519_PUBLIC_KEY_LEN)
      {
         //The Ed25519 signature shall consist of 32 octets
         if(signatureLen == ED25519_SIGNATURE_LEN)
         {
            //Data to be signed is run through the EdDSA algorithm without
            //pre-hashing
            error = ikeGetSignedOctets(sa, id, idLen, macId, messageChunks,
               !sa->originalInitiator);

            //Check status code
            if(!error)
            {
               //Verify Ed25519 signature (PureEdDSA mode)
               error = ed25519VerifySignatureEx(publicKeyInfo->ecPublicKey.q.value,
                  messageChunks, arraysize(messageChunks), NULL, 0, 0, signature);
            }
         }
         else
         {
            //The length of the signature is not valid
            error = ERROR_INVALID_SIGNATURE;
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] publicKeyInfo Pointer to the subject's public key
 * @param[in] signature Signature to be verified
 * @param[in] signatureLen Length of the signature, in bytes
 * @return Error code
 **/

error_t ikeVerifyEd448Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const uint8_t *signature, size_t signatureLen)
{
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   DataChunk messageChunks[3];
   uint8_t macId[IKE_MAX_DIGEST_SIZE];

   //Check public key identifier
   if(OID_COMP(publicKeyInfo->oid.value, publicKeyInfo->oid.length,
      ED448_OID) == 0)
   {
      //Valid Ed448 public key?
      if(publicKeyInfo->ecPublicKey.q.value != NULL &&
         publicKeyInfo->ecPublicKey.q.length == ED448_PUBLIC_KEY_LEN)
      {
         //The Ed448 signature shall consist of 57 octets
         if(signatureLen == ED448_SIGNATURE_LEN)
         {
            //Data to be signed is run through the EdDSA algorithm without
            //pre-hashing
            error = ikeGetSignedOctets(sa, id, idLen, macId, messageChunks,
               !sa->originalInitiator);

            //Check status code
            if(!error)
            {
               //Verify Ed448 signature (PureEdDSA mode)
               error = ed448VerifySignatureEx(publicKeyInfo->ecPublicKey.q.value,
                  messageChunks, arraysize(messageChunks), NULL, 0, 0, signature);
            }
         }
         else
         {
            //The length of the signature is not valid
            error = ERROR_INVALID_SIGNATURE;
         }
      }
      else
      {
         //The public key is not valid
         error = ERROR_INVALID_KEY;
      }
   }
   else
   {
      //Invalid public key identifier
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
