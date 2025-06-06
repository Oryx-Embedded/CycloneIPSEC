/**
 * @file ike_sign_generate.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation
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
#include "ike/ike_sign_generate.h"
#include "pkix/pem_key_import.h"
#include "pkix/x509_sign_format.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED && IKE_CERT_AUTH_SUPPORT == ENABLED)


/**
 * @brief Signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[out] authMethod Authentication method
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateSignature(IkeSaEntry *sa, const uint8_t *id, size_t idLen,
   uint8_t *authMethod, uint8_t *signature, size_t *signatureLen)
{
   error_t error;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   //Digital signature method?
   if(sa->signHashAlgos != 0)
   {
      //The peer is only allowed to use the "Digital Signature" authentication
      //method if the Notify payload of type SIGNATURE_HASH_ALGORITHMS has been
      //sent and received by each peer (refer to RFC 7427, section 3)
      *authMethod = IKE_AUTH_METHOD_DIGITAL_SIGN;

      //The new digital signature method is flexible enough to include all
      //current signature methods (RSA, RSA-PSS, DSA, ECDSA and EdDSA) and add
      //new methods in the future
      error = ikeGenerateDigitalSignature(sa, id, idLen,
         (IkeAuthData *) signature, signatureLen);
   }
   else
#endif
#if (IKE_RSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //RSA signature algorithm?
   if(context->certType == IKE_CERT_TYPE_RSA)
   {
      //Set authentication method
      *authMethod = IKE_AUTH_METHOD_RSA;

      //Generate an RSA signature using the entity's private key
      error = ikeGenerateRsaSignature(sa, id, idLen, SHA1_HASH_ALGO, signature,
         signatureLen);
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED && IKE_SHA1_SUPPORT == ENABLED)
   //DSA signature method?
   if(context->certType == IKE_CERT_TYPE_DSA)
   {
      //Set authentication method
      *authMethod = IKE_AUTH_METHOD_DSS;

      //Generate an DSA signature using the entity's private key
      error = ikeGenerateDsaSignature(sa, id, idLen, SHA1_HASH_ALGO, signature,
         signatureLen, IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_256_SUPPORT == ENABLED && \
   IKE_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 signature method?
   if(context->certType == IKE_CERT_TYPE_ECDSA_P256)
   {
      //Set authentication method
      *authMethod = IKE_AUTH_METHOD_ECDSA_P256_SHA256;

      //Generate an ECDSA signature using the entity's private key
      error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP256R1_CURVE,
         SHA256_HASH_ALGO, signature, signatureLen, IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_384_SUPPORT == ENABLED && \
   IKE_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 signature method?
   if(context->certType == IKE_CERT_TYPE_ECDSA_P384)
   {
      //Set authentication method
      *authMethod = IKE_AUTH_METHOD_ECDSA_P384_SHA384;

      //Generate an ECDSA signature using the entity's private key
      error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP384R1_CURVE,
         SHA384_HASH_ALGO, signature, signatureLen, IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_521_SUPPORT == ENABLED && \
   IKE_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 signature method?
   if(context->certType == IKE_CERT_TYPE_ECDSA_P521)
   {
      //Set authentication method
      *authMethod = IKE_AUTH_METHOD_ECDSA_P521_SHA512;

      //Generate an ECDSA signature using the entity's private key
      error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP521R1_CURVE,
         SHA512_HASH_ALGO, signature, signatureLen, IKE_SIGN_FORMAT_RAW);
   }
   else
#endif
   //Invalid signature method?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Digital signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[out] authData Output stream where to write the authentication data
 * @param[out] authDataLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateDigitalSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, IkeAuthData *authData, size_t *authDataLen)
{
   error_t error;
   size_t n;
   uint8_t *signature;
   const HashAlgo *hashAlgo;
   IkeContext *context;
   X509SignAlgoId signAlgoId;

   //Point to the IKE context
   context = sa->context;

   //When calculating the digital signature, a peer must pick one algorithm
   //sent by the other peer (refer to RFC 7427, section 4)
   if(context->certType == IKE_CERT_TYPE_RSA ||
      context->certType == IKE_CERT_TYPE_RSA_PSS ||
      context->certType == IKE_CERT_TYPE_DSA ||
      context->certType == IKE_CERT_TYPE_ECDSA_P256 ||
      context->certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP256R1)
   {
      //The preferred signature hash algorithm is SHA-256
      hashAlgo = ikeSelectSignHashAlgo(sa, IKE_HASH_ALGO_SHA256);
   }
   else if(context->certType == IKE_CERT_TYPE_ECDSA_P384 ||
      context->certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP384R1)
   {
      //The preferred signature hash algorithm is SHA-384
      hashAlgo = ikeSelectSignHashAlgo(sa, IKE_HASH_ALGO_SHA384);
   }
   else if(context->certType == IKE_CERT_TYPE_ECDSA_P521 ||
      context->certType == IKE_CERT_TYPE_ECDSA_BRAINPOOLP512R1)
   {
      //The preferred signature hash algorithm is SHA-512
      hashAlgo = ikeSelectSignHashAlgo(sa, IKE_HASH_ALGO_SHA512);
   }
   else
   {
      hashAlgo = NULL;
   }

   //Select the algorithm identifier that matches the specified certificate
   //type and hash algorithms
   error = ikeSelectSignAlgoId(context->certType, hashAlgo, &signAlgoId);

   //Check status code
   if(!error)
   {
      //The signature value is prefixed with an ASN.1 object indicating the
      //algorithm used to generate the signature (refer to RFC 7427, section 3)
      error = x509FormatSignatureAlgo(&signAlgoId, authData->algoId, &n);
   }

   //Check status code
   if(!error)
   {
      //Set the length of the ASN.1 object
      authData->algoIdLen = (uint8_t) n;

      //There is no padding between the ASN.1 object and the signature value
      signature = authData->algoId + authData->algoIdLen;

#if (IKE_RSA_SIGN_SUPPORT == ENABLED)
      //RSA signature algorithm?
      if(context->certType == IKE_CERT_TYPE_RSA)
      {
         //Generate an RSA signature using the entity's private key
         error = ikeGenerateRsaSignature(sa, id, idLen, hashAlgo, signature,
            &n);
      }
      else
#endif
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
      //RSA-PSS signature algorithm?
      if(context->certType == IKE_CERT_TYPE_RSA_PSS)
      {
         //Generate an RSA-PSS signature using the entity's private key
         error = ikeGenerateRsaPssSignature(sa, id, idLen, hashAlgo,
            signAlgoId.rsaPssParams.saltLen, signature, &n);
      }
      else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature method?
      if(context->certType == IKE_CERT_TYPE_DSA)
      {
         //Generate an DSA signature using the entity's private key
         error = ikeGenerateDsaSignature(sa, id, idLen, hashAlgo, signature,
            &n, IKE_SIGN_FORMAT_ASN1);
      }
      else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_256_SUPPORT == ENABLED)
      //ECDSA with NIST P-256 signature method?
      if(context->certType == IKE_CERT_TYPE_ECDSA_P256)
      {
         //Generate an ECDSA signature using the entity's private key
         error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP256R1_CURVE,
            hashAlgo, signature, &n, IKE_SIGN_FORMAT_ASN1);
      }
      else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_384_SUPPORT == ENABLED)
      //ECDSA with NIST P-384 signature method?
      if(context->certType == IKE_CERT_TYPE_ECDSA_P384)
      {
         //Generate an ECDSA signature using the entity's private key
         error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP384R1_CURVE,
            hashAlgo, signature, &n, IKE_SIGN_FORMAT_ASN1);
      }
      else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED && IKE_ECP_521_SUPPORT == ENABLED)
      //ECDSA with NIST P-521 signature method?
      if(context->certType == IKE_CERT_TYPE_ECDSA_P521)
      {
         //Generate an ECDSA signature using the entity's private key
         error = ikeGenerateEcdsaSignature(sa, id, idLen, SECP521R1_CURVE,
            hashAlgo, signature, &n, IKE_SIGN_FORMAT_ASN1);
      }
      else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
      //Ed25519 signature method?
      if(context->certType == IKE_CERT_TYPE_ED25519)
      {
         //Generate an Ed25519 signature using the entity's private key
         error = ikeGenerateEd25519Signature(sa, id, idLen, signature, &n);
      }
      else
#endif
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
      //Ed448 signature method?
      if(context->certType == IKE_CERT_TYPE_ED448)
      {
         //Generate an Ed448 signature using the entity's private key
         error = ikeGenerateEd448Signature(sa, id, idLen, signature, &n);
      }
      else
#endif
      //Invalid signature method?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Check status code
   if(!error)
   {
      //Total length of the authentication data
      *authDataLen = sizeof(IkeAuthData) + authData->algoIdLen + n;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] hashAlgo Hash algorithm
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateRsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, uint8_t *signature,
   size_t *signatureLen)
{
#if (IKE_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   RsaPrivateKey rsaPrivateKey;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize RSA private key
   rsaInitPrivateKey(&rsaPrivateKey);

   //Digest signed octets
   error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import RSA private key
      error = pemImportRsaPrivateKey(&rsaPrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = rsassaPkcs1v15Sign(&rsaPrivateKey, hashAlgo, digest, signature,
         signatureLen);
   }

   //Free previously allocated memory
   rsaFreePrivateKey(&rsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] hashAlgo Hash algorithm
 * @param[in] saltLen Length of the salt, in bytes
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateRsaPssSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, size_t saltLen, uint8_t *signature,
   size_t *signatureLen)
{
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   RsaPrivateKey rsaPrivateKey;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize RSA private key
   rsaInitPrivateKey(&rsaPrivateKey);

   //Digest signed octets
   error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import RSA private key
      error = pemImportRsaPrivateKey(&rsaPrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //Generate RSA signature (RSASSA-PSS signature scheme)
      error = rsassaPssSign(context->prngAlgo, context->prngContext,
         &rsaPrivateKey, hashAlgo, saltLen, digest, signature, signatureLen);
   }

   //Free previously allocated memory
   rsaFreePrivateKey(&rsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] hashAlgo Hash algorithm
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeGenerateDsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const HashAlgo *hashAlgo, uint8_t *signature,
   size_t *signatureLen, IkeSignFormat format)
{
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   DsaPrivateKey dsaPrivateKey;
   DsaSignature dsaSignature;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize DSA private key
   dsaInitPrivateKey(&dsaPrivateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Digest signed octets
   error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import DSA private key
      error = pemImportDsaPrivateKey(&dsaPrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(context->prngAlgo, context->prngContext,
         &dsaPrivateKey, digest, hashAlgo->digestSize, &dsaSignature);
   }

   //Check status code
   if(!error)
   {
      //Encode (R, S) integer pair
      error = ikeFormatDsaSignature(&dsaSignature, signature, signatureLen,
         format);
   }

   //Free previously allocated memory
   dsaFreePrivateKey(&dsaPrivateKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[in] group Elliptic curve group
 * @param[in] hashAlgo Hash algorithm
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @param[in] format Signature format (raw or ASN.1)
 * @return Error code
 **/

error_t ikeGenerateEcdsaSignature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, const EcCurve *group, const HashAlgo *hashAlgo,
   uint8_t *signature, size_t *signatureLen, IkeSignFormat format)
{
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   IkeContext *context;
   EcPrivateKey ecPrivateKey;
   EcdsaSignature ecdsaSignature;
   uint8_t digest[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize EC private key
   ecInitPrivateKey(&ecPrivateKey);
   //Initialize ECDSA signature
   ecdsaInitSignature(&ecdsaSignature);

   //Digest signed octets
   error = ikeDigestSignedOctets(sa, hashAlgo, id, idLen, digest,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import EC private key
      error = pemImportEcPrivateKey(&ecPrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //Generate ECDSA signature
      error = ecdsaGenerateSignature(context->prngAlgo, context->prngContext,
         &ecPrivateKey, digest, hashAlgo->digestSize, &ecdsaSignature);
   }

   //Check status code
   if(!error)
   {
      //Encode (R, S) integer pair
      error = ikeFormatEcdsaSignature(&ecdsaSignature, signature, signatureLen,
         format);
   }

   //Free previously allocated memory
   ecFreePrivateKey(&ecPrivateKey);
   ecdsaFreeSignature(&ecdsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateEd25519Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, uint8_t *signature, size_t *signatureLen)
{
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;
   IkeContext *context;
   EddsaPrivateKey ed25519PrivateKey;
   DataChunk messageChunks[3];
   uint8_t macId[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize Ed25519 private key
   eddsaInitPrivateKey(&ed25519PrivateKey);

   //Data to be signed is run through the EdDSA algorithm without pre-hashing
   error = ikeGetSignedOctets(sa, id, idLen, macId, messageChunks,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import Ed25519 private key
      error = pemImportEddsaPrivateKey(&ed25519PrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //The public key is optional
      q = (ed25519PrivateKey.q.curve != NULL) ? ed25519PrivateKey.q.q : NULL;

      //Generate Ed25519 signature
      error = ed25519GenerateSignatureEx(ed25519PrivateKey.d, q,
         messageChunks, arraysize(messageChunks), NULL, 0, 0, signature);
   }

   //Check status code
   if(!error)
   {
      //The Ed25519 signature consists of 32 octets
      *signatureLen = ED25519_SIGNATURE_LEN;
   }

   //Free previously allocated memory
   eddsaFreePrivateKey(&ed25519PrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation
 * @param[in] sa Pointer to the IKE SA
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @param[out] signature Output stream where to write the signature
 * @param[out] signatureLen Total number of bytes that have been written
 * @return Error code
 **/

error_t ikeGenerateEd448Signature(IkeSaEntry *sa, const uint8_t *id,
   size_t idLen, uint8_t *signature, size_t *signatureLen)
{
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *q;
   IkeContext *context;
   EddsaPrivateKey ed448PrivateKey;
   DataChunk messageChunks[3];
   uint8_t macId[IKE_MAX_DIGEST_SIZE];

   //Point to the IKE context
   context = sa->context;

   //Initialize Ed448 private key
   eddsaInitPrivateKey(&ed448PrivateKey);

   //Data to be signed is run through the EdDSA algorithm without pre-hashing
   error = ikeGetSignedOctets(sa, id, idLen, macId, messageChunks,
      sa->originalInitiator);

   //Check status code
   if(!error)
   {
      //Import Ed448 private key
      error = pemImportEddsaPrivateKey(&ed448PrivateKey, context->privateKey,
         context->privateKeyLen, context->password);
   }

   //Check status code
   if(!error)
   {
      //The public key is optional
      q = (ed448PrivateKey.q.curve != NULL) ? ed448PrivateKey.q.q : NULL;

      //Generate Ed448 signature
      error = ed448GenerateSignatureEx(ed448PrivateKey.d, q, messageChunks,
         arraysize(messageChunks), NULL, 0, 0, signature);
   }

   //Check status code
   if(!error)
   {
      //The Ed448 signature consists of 32 octets
      *signatureLen = ED448_SIGNATURE_LEN;
   }

   //Free previously allocated memory
   eddsaFreePrivateKey(&ed448PrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
