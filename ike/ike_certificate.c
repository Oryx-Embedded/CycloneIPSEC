/**
 * @file ike_certificate.c
 * @brief X.509 certificate handling
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
#include "ike/ike_certificate.h"
#include "ike/ike_payload_parse.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_validate.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED && IKE_CERT_AUTH_SUPPORT == ENABLED)


/**
 * @brief Retrieve the certificate type
 * @param[in] certInfo X.509 certificate
 * @param[out] certType Certificate type
 * @return Error code
 **/

error_t ikeGetCertificateType(const X509CertInfo *certInfo,
   IkeCertType *certType)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Initialize status code
   error = NO_ERROR;

   //Point to the public key identifier
   oid = certInfo->tbsCert.subjectPublicKeyInfo.oid.value;
   oidLen = certInfo->tbsCert.subjectPublicKeyInfo.oid.length;

#if (IKE_RSA_SIGN_SUPPORT == ENABLED || IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA public key?
   if(OID_COMP(oid, oidLen, RSA_ENCRYPTION_OID) == 0)
   {
      //Save certificate type
      *certType = IKE_CERT_TYPE_RSA;
   }
   else
#endif
#if (IKE_RSA_PSS_SIGN_SUPPORT == ENABLED)
   //RSA-PSS public key?
   if(OID_COMP(oid, oidLen, RSASSA_PSS_OID) == 0)
   {
      //Save certificate type
      *certType = IKE_CERT_TYPE_RSA_PSS;
   }
   else
#endif
#if (IKE_DSA_SIGN_SUPPORT == ENABLED)
   //DSA public key?
   if(OID_COMP(oid, oidLen, DSA_OID) == 0)
   {
      //Save certificate type
      *certType = IKE_CERT_TYPE_DSA;
   }
   else
#endif
#if (IKE_ECDSA_SIGN_SUPPORT == ENABLED)
   //EC public key?
   if(OID_COMP(oid, oidLen, EC_PUBLIC_KEY_OID) == 0)
   {
      const X509SubjectPublicKeyInfo *subjectPublicKeyInfo;

      //Point to the subject's public key information
      subjectPublicKeyInfo = &certInfo->tbsCert.subjectPublicKeyInfo;

      //The namedCurve field identifies a particular set of elliptic curve
      //domain parameters
      oid = subjectPublicKeyInfo->ecParams.namedCurve.value;
      oidLen = subjectPublicKeyInfo->ecParams.namedCurve.length;

#if (IKE_ECP_256_SUPPORT == ENABLED)
      //NIST P-256 elliptic curve?
      if(OID_COMP(oid, oidLen, SECP256R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_P256;
      }
      else
#endif
#if (IKE_ECP_384_SUPPORT == ENABLED)
      //NIST P-384 elliptic curve?
      if(OID_COMP(oid, oidLen, SECP384R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_P384;
      }
      else
#endif
#if (IKE_ECP_521_SUPPORT == ENABLED)
      //NIST P-521 elliptic curve?
      if(OID_COMP(oid, oidLen, SECP521R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_P521;
      }
      else
#endif
#if (IKE_BRAINPOOLP256R1_SUPPORT == ENABLED)
      //brainpoolP256r1 elliptic curve?
      if(OID_COMP(oid, oidLen, BRAINPOOLP256R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_BRAINPOOLP256R1;
      }
      else
#endif
#if (IKE_BRAINPOOLP384R1_SUPPORT == ENABLED)
      //brainpoolP384r1 elliptic curve?
      if(OID_COMP(oid, oidLen, BRAINPOOLP384R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_BRAINPOOLP384R1;
      }
      else
#endif
#if (IKE_BRAINPOOLP512R1_SUPPORT == ENABLED)
      //brainpoolP512r1 elliptic curve?
      if(OID_COMP(oid, oidLen, BRAINPOOLP512R1_OID) == 0)
      {
         *certType = IKE_CERT_TYPE_ECDSA_BRAINPOOLP512R1;
      }
      else
#endif
      //Unknown elliptic curve?
      {
         error = ERROR_BAD_CERTIFICATE;
      }
   }
   else
#endif
#if (IKE_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 public key?
   if(OID_COMP(oid, oidLen, ED25519_OID) == 0)
   {
      //Save certificate type
      *certType = IKE_CERT_TYPE_ED25519;
   }
   else
#endif
#if (IKE_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 public key?
   if(OID_COMP(oid, oidLen, ED448_OID) == 0)
   {
      //Save certificate type
      *certType = IKE_CERT_TYPE_ED448;
   }
   else
#endif
   //Invalid public key?
   {
      //The certificate does not contain any valid public key
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Extract subject's DN from certificate
 * @param[in] cert Certificate (PEM format)
 * @param[in] certLen Length of the certificate
 * @param[out] subjectDn Buffer where to copy the X.500 distinguished name
 * @param[out] subjectDnLen Length of the X.500 distinguished name
 * @return Error code
 **/

error_t ikeGetCertSubjectDn(const char_t *cert, size_t certLen,
   uint8_t *subjectDn, size_t *subjectDnLen)
{
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertInfo *certInfo;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(cert, certLen, NULL, &derCertLen, NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = ikeAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(cert, certLen, derCert, &derCertLen,
            NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = ikeAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Copy the X.500 distinguished name
                  osMemcpy(subjectDn, certInfo->tbsCert.subject.raw.value,
                     certInfo->tbsCert.subject.raw.length);

                  //Total length of the payload
                  *subjectDnLen = certInfo->tbsCert.subject.raw.length;
               }

               //Release previously allocated memory
               ikeFreeMem(certInfo);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }

            //Release previously allocated memory
            ikeFreeMem(derCert);
         }
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format list of acceptable certification authorities
 * @param[in] trustedCaList List of trusted CA (PEM format)
 * @param[in] trustedCaListLen Total length of the list
 * @param[out] certAuth List of SHA-1 hashes of the public keys of trusted CAs
 * @param[in,out] certAuthLen Actual length of the list, in bytes
 * @return Error code
 **/

error_t ikeFormatCertAuthorities(const char_t *trustedCaList,
   size_t trustedCaListLen, uint8_t *certAuth, size_t *certAuthLen)
{
#if (SHA1_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t derCertLen;
   uint8_t *derCert;
   X509CertInfo *certInfo;

   //Initialize status code
   error = NO_ERROR;

   //Allocate a memory buffer to store X.509 certificate info
   certInfo = ikeAllocMem(sizeof(X509CertInfo));

   //Successful memory allocation?
   if(certInfo != NULL)
   {
      //Loop through the list of trusted CA certificates
      while(trustedCaListLen > 0 && !error)
      {
         //The first pass calculates the length of the DER-encoded certificate
         error = pemImportCertificate(trustedCaList, trustedCaListLen, NULL,
            &derCertLen, &n);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to hold the DER-encoded certificate
            derCert = ikeAllocMem(derCertLen);

            //Successful memory allocation?
            if(derCert != NULL)
            {
               //The second pass decodes the PEM certificate
               error = pemImportCertificate(trustedCaList, trustedCaListLen,
                  derCert, &derCertLen, NULL);

               //Check status code
               if(!error)
               {
                  //Parse X.509 certificate
                  error = x509ParseCertificate(derCert, derCertLen, certInfo);
               }

               //Valid CA certificate?
               if(!error)
               {
                  //The Certification Authority value is a concatenated list of
                  //SHA-1 hashes of the public keys of trusted Certification
                  //Authorities (CAs). Each is encoded as the SHA-1 hash of the
                  //SubjectPublicKeyInfo element
                  error = sha1Compute(certInfo->tbsCert.subjectPublicKeyInfo.raw.value,
                     certInfo->tbsCert.subjectPublicKeyInfo.raw.length,
                     certAuth + *certAuthLen);

                  //Check status code
                  if(!error)
                  {
                     //Ensure the SHA-1 digest value is not a duplicate
                     if(!ikeIsDuplicateCa(certAuth, *certAuthLen,
                        certAuth + *certAuthLen))
                     {
                        //The 20-octet hashes are concatenated and included with no
                        //other formatting
                        *certAuthLen += IKE_SHA1_DIGEST_SIZE;
                     }
                  }
               }
               else
               {
                  //Discard current CA certificate
                  error = NO_ERROR;
               }

               //Free previously allocated memory
               ikeFreeMem(derCert);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }

            //Point to the next CA of the list
            trustedCaList += n;
            trustedCaListLen -= n;
         }
         else
         {
            //End of file detected
            trustedCaListLen = 0;
            error = NO_ERROR;
         }
      }

      //Free previously allocated memory
      ikeFreeMem(certInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //SHA-1 is not supported
   return NO_ERROR;
#endif
}


/**
 * @brief Test whether the provided SHA-1 digest value is a duplicate
 * @param[in] certAuth List of SHA-1 hashes of the public keys of trusted CAs
 * @param[in] certAuthLen Length of the list, in bytes
 * @param[in] digest SHA-1 digest to be checked for duplicate value
 * @return TRUE if the SHA-1 digest value is a duplicate, else FALSE
 **/

bool_t ikeIsDuplicateCa(const uint8_t *certAuth, size_t certAuthLen,
   const uint8_t *digest)
{
   size_t i;
   bool_t flag;

   //Initialize flag
   flag = FALSE;

   //The Certification Authority value is a concatenated list of SHA-1 hashes
   //of the public keys of trusted Certification Authorities (CAs)
   for(i = 0; i < certAuthLen; i += IKE_SHA1_DIGEST_SIZE)
   {
      //Compare SHA-1 digest values
      if(osMemcmp(certAuth + i, digest, IKE_SHA1_DIGEST_SIZE) == 0)
      {
         //The SHA-1 hash is a duplicate
         flag = TRUE;
      }
   }

   //Return TRUE if the SHA-1 hash value is a duplicate
   return flag;
}


/**
 * @brief Parse certificate chain
 * @param[in] sa Pointer to the IKE SA
 * @param[in] padEntry Pointer to the PAD entry
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseCertificateChain(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const uint8_t *message, size_t length)
{
   error_t error;
   error_t certValidResult;
   uint_t i;
   size_t n;
   X509CertInfo *certInfo;
   X509CertInfo *issuerCertInfo;
   IkeCertPayload *certPayload;

   //Initialize X.509 certificates
   certInfo = NULL;
   issuerCertInfo = NULL;

   //Start of exception handling block
   do
   {
      //Allocate a memory buffer to store X.509 certificate info
      certInfo = ikeAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Allocate a memory buffer to store the parent certificate
      issuerCertInfo = ikeAllocMem(sizeof(X509CertInfo));
      //Failed to allocate memory?
      if(issuerCertInfo == NULL)
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //The first CERT payload holds the public key used to validate the
      //sender's AUTH payload (refer to RFC7296, section 3.6)
      certPayload = (IkeCertPayload *) ikeGetPayload(message, length,
         IKE_PAYLOAD_TYPE_CERT, 0);
      //CERT payload no found?
      if(certPayload == NULL)
      {
         //Report an error
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Retrieve the length of the CERT payload
      n = ntohs(certPayload->header.payloadLength);

      //Malformed Certificate payload?
      if(n < sizeof(IkeCertPayload))
      {
         //Report an error
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Determine the length of the Certificate Data field
      n -= sizeof(IkeCertPayload);

      //Display ASN.1 structure
      error = asn1DumpObject(certPayload->certData, n, 0);
      //Any error to report?
      if(error)
         break;

      //Parse end-entity certificate
      error = x509ParseCertificate(certPayload->certData, n, certInfo);
      //Failed to parse the X.509 certificate?
      if(error)
      {
         //Report an error
         error = ERROR_BAD_CERTIFICATE;
         break;
      }

      //Check certificate key usage
      error = ikeCheckKeyUsage(certInfo);
      //Any error to report?
      if(error)
         break;

      //Check if the end-entity certificate can be matched with a trusted CA
      certValidResult = ikeValidateCertificate(sa, padEntry, certInfo, 0);

      //Check validation result
      if(certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
      {
         //The certificate is not valid
         error = certValidResult;
         break;
      }

      //PKIX path validation
      for(i = 0; length > 0; i++)
      {
         //If a chain of certificates needs to be sent, multiple CERT payloads
         //are used (refer to RFC 7296, section 3.6)
         certPayload = (IkeCertPayload *) ikeGetPayload(message, length,
            IKE_PAYLOAD_TYPE_CERT, i + 1);
         //End of certificate chain?
         if(certPayload == NULL)
         {
            //We are done
            error = NO_ERROR;
            break;
         }

         //Retrieve the length of the CERT payload
         n = ntohs(certPayload->header.payloadLength);

         //Malformed Certificate payload?
         if(n < sizeof(IkeCertPayload))
         {
            //Report an error
            error = ERROR_INVALID_MESSAGE;
            break;
         }

         //Determine the length of the Certificate Data field
         n -= sizeof(IkeCertPayload);

         //Display ASN.1 structure
         error = asn1DumpObject(certPayload->certData, n, 0);
         //Any error to report?
         if(error)
            break;

         //Parse intermediate certificate
         error = x509ParseCertificate(certPayload->certData, n, issuerCertInfo);
         //Failed to parse the X.509 certificate?
         if(error)
         {
            //Report an error
            error = ERROR_BAD_CERTIFICATE;
            break;
         }

         //Certificate chain validation in progress?
         if(certValidResult == ERROR_UNKNOWN_CA)
         {
            //Validate current certificate
            error = x509ValidateCertificate(certInfo, issuerCertInfo, i);
            //Certificate validation failed?
            if(error)
               break;

            //Check the version of the certificate
            if(issuerCertInfo->tbsCert.version < X509_VERSION_3)
            {
               //Conforming implementations may choose to reject all version 1
               //and version 2 intermediate certificates (refer to RFC 5280,
               //section 6.1.4)
               error = ERROR_BAD_CERTIFICATE;
               break;
            }

            //Check if the intermediate certificate can be matched with a
            //trusted CA
            certValidResult = ikeValidateCertificate(sa, padEntry,
               issuerCertInfo, i);

            //Check validation result
            if(certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
            {
               //The certificate is not valid
               error = certValidResult;
               break;
            }
         }

         //Keep track of the issuer certificate
         *certInfo = *issuerCertInfo;
      }

      //Certificate chain validation failed?
      if(error == NO_ERROR && certValidResult != NO_ERROR)
      {
         //A valid certificate chain or partial chain was received, but the
         //certificate was not accepted because the CA certificate could not
         //be matched with a known, trusted CA
         error = ERROR_UNKNOWN_CA;
      }

      //End of exception handling block
   } while(0);

   //Free previously allocated memory
   ikeFreeMem(certInfo);
   ikeFreeMem(issuerCertInfo);

   //Return status code
   return error;
}


/**
 * @brief Verify certificate against root CAs
 * @param[in] sa Pointer to the IKE SA
 * @param[in] padEntry Pointer to the PAD entry
 * @param[in] certInfo X.509 certificate to be verified
 * @param[in] pathLen Certificate path length
 * @return Error code
 **/

error_t ikeValidateCertificate(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const X509CertInfo *certInfo, uint_t pathLen)
{
   error_t error;
   size_t pemCertLen;
   const char_t *trustedCaList;
   size_t trustedCaListLen;
   uint8_t *derCert;
   size_t derCertLen;
   IkeContext *context;
   X509CertInfo *caCertInfo;

   //Initialize status code
   error = ERROR_UNKNOWN_CA;

   //Point to the IKE context
   context = sa->context;

   //Any registered callback?
   if(context->certVerifyCallback != NULL)
   {
      //Invoke user callback function
      error = context->certVerifyCallback(sa, certInfo, pathLen);
   }

   //Check status code
   if(error == NO_ERROR)
   {
      //The certificate is valid
   }
   else if(error == ERROR_UNKNOWN_CA)
   {
      //Check whether the certificate should be checked against root CAs
      if(padEntry->trustedCaListLen > 0)
      {
         //Point to the first trusted CA certificate
         trustedCaList = padEntry->trustedCaList;
         //Get the total length, in bytes, of the trusted CA list
         trustedCaListLen = padEntry->trustedCaListLen;

         //Allocate a memory buffer to store X.509 certificate info
         caCertInfo = ikeAllocMem(sizeof(X509CertInfo));

         //Successful memory allocation?
         if(caCertInfo != NULL)
         {
            //Loop through the list of trusted CA certificates
            while(trustedCaListLen > 0 && error == ERROR_UNKNOWN_CA)
            {
               //The first pass calculates the length of the DER-encoded
               //certificate
               error = pemImportCertificate(trustedCaList, trustedCaListLen,
                  NULL, &derCertLen, &pemCertLen);

               //Check status code
               if(!error)
               {
                  //Allocate a memory buffer to hold the DER-encoded certificate
                  derCert = ikeAllocMem(derCertLen);

                  //Successful memory allocation?
                  if(derCert != NULL)
                  {
                     //The second pass decodes the PEM certificate
                     error = pemImportCertificate(trustedCaList,
                        trustedCaListLen, derCert, &derCertLen, NULL);

                     //Check status code
                     if(!error)
                     {
                        //Parse X.509 certificate
                        error = x509ParseCertificate(derCert, derCertLen,
                           caCertInfo);
                     }

                     //Check status code
                     if(!error)
                     {
                        //Validate the certificate with the current CA
                        error = x509ValidateCertificate(certInfo, caCertInfo,
                           pathLen);
                     }

                     //Check status code
                     if(!error)
                     {
                        //The certificate is issued by a trusted CA
                        error = NO_ERROR;
                     }
                     else
                     {
                        //The certificate cannot be matched with the current CA
                        error = ERROR_UNKNOWN_CA;
                     }

                     //Free previously allocated memory
                     ikeFreeMem(derCert);
                  }
                  else
                  {
                     //Failed to allocate memory
                     error = ERROR_OUT_OF_MEMORY;
                  }

                  //Advance read pointer
                  trustedCaList += pemCertLen;
                  trustedCaListLen -= pemCertLen;
               }
               else
               {
                  //No more CA certificates in the list
                  trustedCaListLen = 0;
                  error = ERROR_UNKNOWN_CA;
               }
            }

            //Free previously allocated memory
            ikeFreeMem(caCertInfo);
         }
         else
         {
            //Failed to allocate memory
            error = ERROR_OUT_OF_MEMORY;
         }
      }
      else
      {
         //Do not check the certificate against root CAs
         error = NO_ERROR;
      }
   }
   else if(error == ERROR_BAD_CERTIFICATE ||
      error == ERROR_UNSUPPORTED_CERTIFICATE ||
      error == ERROR_UNKNOWN_CERTIFICATE ||
      error == ERROR_CERTIFICATE_REVOKED ||
      error == ERROR_CERTIFICATE_EXPIRED ||
      error == ERROR_HANDSHAKE_FAILED)
   {
      //The certificate is not valid
   }
   else
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check certificate key usage
 * @param[in] certInfo Pointer to the X.509 certificate
 * @return Error code
 **/

error_t ikeCheckKeyUsage(const X509CertInfo *certInfo)
{
   error_t error;
   const X509KeyUsage *keyUsage;
   const X509ExtendedKeyUsage *extKeyUsage;

   //Initialize status code
   error = NO_ERROR;

   //Point to the KeyUsage extension
   keyUsage = &certInfo->tbsCert.extensions.keyUsage;

   //Check if the KeyUsage extension is present
   if(keyUsage->bitmap != 0)
   {
      //If KeyUsage is present and does not mention digitalSignature or
      //nonRepudiation, then reject the certificate (refer to RFC4945,
      //section 5.1.3.2)
      if((keyUsage->bitmap & X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0 &&
         (keyUsage->bitmap & X509_KEY_USAGE_NON_REPUDIATION) == 0)
      {
         error = ERROR_BAD_CERTIFICATE;
      }
   }

   //Point to the ExtendedKeyUsage extension
   extKeyUsage = &certInfo->tbsCert.extensions.extKeyUsage;

   //Check if the ExtendedKeyUsage extension is present
   if(extKeyUsage->bitmap != 0)
   {
      //If ExtendedKeyUsage is present and contains either id-kp-ipsecIKE or
      //anyExtendedKeyUsage, continue. Otherwise, reject certificate (refer
      //to RFC 4945, section 5.1.3.12)
      if((extKeyUsage->bitmap & X509_EXT_KEY_USAGE_IPSEC_IKE) == 0)
      {
         error = ERROR_BAD_CERTIFICATE;
      }
   }

   //Return status code
   return error;
}

#endif
