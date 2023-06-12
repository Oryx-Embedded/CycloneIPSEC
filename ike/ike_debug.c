/**
 * @file ike_debug.c
 * @brief Data logging functions for debugging purpose (IKEv2)
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
#include "ike/ike_debug.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED && IKE_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)

//Exchange types
static const IkeParamName ikeExchangeTypeList[] =
{
   {IKE_EXCHANGE_TYPE_IKE_SA_INIT,        "IKE_SA_INIT"},
   {IKE_EXCHANGE_TYPE_IKE_AUTH,           "IKE_AUTH"},
   {IKE_EXCHANGE_TYPE_CREATE_CHILD_SA,    "CREATE_CHILD_SA"},
   {IKE_EXCHANGE_TYPE_INFORMATIONAL,      "INFORMATIONAL"},
   {IKE_EXCHANGE_TYPE_IKE_SESSION_RESUME, "IKE_SESSION_RESUME"},
   {IKE_EXCHANGE_TYPE_IKE_INTERMEDIATE,   "IKE_INTERMEDIATE"}
};

//Payload types
static const IkeParamName ikePayloadList[] =
{
   {IKE_PAYLOAD_TYPE_LAST,    "No Next Payload"},
   {IKE_PAYLOAD_TYPE_SA,      "Security Association"},
   {IKE_PAYLOAD_TYPE_KE,      "Key Exchange"},
   {IKE_PAYLOAD_TYPE_IDI,     "Identification - Initiator"},
   {IKE_PAYLOAD_TYPE_IDR,     "Identification - Responder"},
   {IKE_PAYLOAD_TYPE_CERT,    "Certificate"},
   {IKE_PAYLOAD_TYPE_CERTREQ, "Certificate Request"},
   {IKE_PAYLOAD_TYPE_AUTH,    "Authentication"},
   {IKE_PAYLOAD_TYPE_NONCE,   "Nonce"},
   {IKE_PAYLOAD_TYPE_N,       "Notify"},
   {IKE_PAYLOAD_TYPE_D,       "Delete"},
   {IKE_PAYLOAD_TYPE_V,       "Vendor ID"},
   {IKE_PAYLOAD_TYPE_TSI,     "Traffic Selector - Initiator"},
   {IKE_PAYLOAD_TYPE_TSR,     "Traffic Selector - Responder"},
   {IKE_PAYLOAD_TYPE_SK,      "Encrypted and Authenticated"},
   {IKE_PAYLOAD_TYPE_CP,      "Configuration"},
   {IKE_PAYLOAD_TYPE_EAP,     "Extensible Authentication"},
   {IKE_PAYLOAD_TYPE_GSPM,    "Generic Secure Password Method"},
   {IKE_PAYLOAD_TYPE_SKF,     "Encrypted and Authenticated Fragment"},
   {IKE_PAYLOAD_TYPE_PS,      "Puzzle Solution"}
};

//Last Substruc values
static const IkeParamName ikeLastSubstrucList[] =
{
   {IKE_LAST_SUBSTRUC_LAST,            "Last"},
   {IKE_LAST_SUBSTRUC_MORE_PROPOSALS,  "More Proposals"},
   {IKE_LAST_SUBSTRUC_MORE_TRANSFORMS, "More Transforms"}
};

//Protocol IDs
static const IkeParamName ikeProtocolIdList[] =
{
   {IKE_PROTOCOL_ID_IKE, "IKE"},
   {IKE_PROTOCOL_ID_AH,  "AH"},
   {IKE_PROTOCOL_ID_ESP, "ESP"}
};

//Transform types
static const IkeParamName ikeTransformTypeList[] =
{
   {IKE_TRANSFORM_TYPE_ENCR,  "Encryption Algorithm"},
   {IKE_TRANSFORM_TYPE_PRF,   "Pseudorandom Function"},
   {IKE_TRANSFORM_TYPE_INTEG, "Integrity Algorithm"},
   {IKE_TRANSFORM_TYPE_DH,    "Diffie-Hellman Group"},
   {IKE_TRANSFORM_TYPE_ESN,   "Extended Sequence Numbers"}
};

//Encryption algorithms
static const IkeParamName ikeEncrAlgoList[] =
{
   {IKE_TRANSFORM_ID_ENCR_DES_IV64,                 "ENCR_DES_IV64"},
   {IKE_TRANSFORM_ID_ENCR_DES,                      "ENCR_DES"},
   {IKE_TRANSFORM_ID_ENCR_3DES,                     "ENCR_3DES"},
   {IKE_TRANSFORM_ID_ENCR_RC5,                      "ENCR_RC5"},
   {IKE_TRANSFORM_ID_ENCR_IDEA,                     "ENCR_IDEA"},
   {IKE_TRANSFORM_ID_ENCR_CAST,                     "ENCR_CAST"},
   {IKE_TRANSFORM_ID_ENCR_BLOWFISH,                 "ENCR_BLOWFISH"},
   {IKE_TRANSFORM_ID_ENCR_3IDEA,                    "ENCR_3IDEA"},
   {IKE_TRANSFORM_ID_ENCR_DES_IV32,                 "ENCR_DES_IV32"},
   {IKE_TRANSFORM_ID_ENCR_NULL,                     "ENCR_NULL"},
   {IKE_TRANSFORM_ID_ENCR_AES_CBC,                  "ENCR_AES_CBC"},
   {IKE_TRANSFORM_ID_ENCR_AES_CTR,                  "ENCR_AES_CTR"},
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8,                "ENCR_AES_CCM_8"},
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_12,               "ENCR_AES_CCM_12"},
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_16,               "ENCR_AES_CCM_16"},
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_8,                "ENCR_AES_GCM_8"},
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_12,               "ENCR_AES_GCM_12"},
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16,               "ENCR_AES_GCM_16"},
   {IKE_TRANSFORM_ID_ENCR_NULL_AUTH_AES_GMAC,       "ENCR_NULL_AUTH_AES_GMAC"},
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC,             "ENCR_CAMELLIA_CBC"},
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR,             "ENCR_CAMELLIA_CTR"},
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8,           "ENCR_CAMELLIA_CCM_8"},
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12,          "ENCR_CAMELLIA_CCM_12"},
   {IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16,          "ENCR_CAMELLIA_CCM_16"},
   {IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305,        "ENCR_CHACHA20_POLY1305"},
   {IKE_TRANSFORM_ID_ENCR_AES_CCM_8_IIV,            "ENCR_AES_CCM_8_IIV"},
   {IKE_TRANSFORM_ID_ENCR_AES_GCM_16_IIV,           "ENCR_AES_GCM_16_IIV"},
   {IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305_IIV,    "ENCR_CHACHA20_POLY1305_IIV"},
   {IKE_TRANSFORM_ID_ENCR_KUZNYECHIK_MGM_KTREE,     "ENCR_KUZNYECHIK_MGM_KTREE"},
   {IKE_TRANSFORM_ID_ENCR_MAGMA_MGM_KTREE,          "ENCR_MAGMA_MGM_KTREE"},
   {IKE_TRANSFORM_ID_ENCR_KUZNYECHIK_MGM_MAC_KTREE, "ENCR_KUZNYECHIK_MGM_MAC_KTREE"},
   {IKE_TRANSFORM_ID_ENCR_MAGMA_MGM_MAC_KTREE,      "ENCR_MAGMA_MGM_MAC_KTREE"}
};

//Pseudorandom functions
static const IkeParamName ikePrfAlgoList[] =
{
   {IKE_TRANSFORM_ID_PRF_HMAC_MD5,      "PRF_HMAC_MD5"},
   {IKE_TRANSFORM_ID_PRF_HMAC_SHA1,     "PRF_HMAC_SHA1"},
   {IKE_TRANSFORM_ID_PRF_HMAC_TIGER,    "PRF_HMAC_TIGER"},
   {IKE_TRANSFORM_ID_PRF_AES128_XCBC,   "PRF_AES128_XCBC"},
   {IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256, "PRF_HMAC_SHA2_256"},
   {IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384, "PRF_HMAC_SHA2_384"},
   {IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512, "PRF_HMAC_SHA2_512"},
   {IKE_TRANSFORM_ID_PRF_AES128_CMAC,   "PRF_AES128_CMAC"}
};

//Integrity algorithms
static const IkeParamName ikeAuthAlgoList[] =
{
   {IKE_TRANSFORM_ID_AUTH_NONE,              "AUTH_NONE"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96,       "AUTH_HMAC_MD5_96"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96,      "AUTH_HMAC_SHA1_96"},
   {IKE_TRANSFORM_ID_AUTH_DES_MAC,           "AUTH_DES_MAC"},
   {IKE_TRANSFORM_ID_AUTH_KPDK_MD5,          "AUTH_KPDK_MD5"},
   {IKE_TRANSFORM_ID_AUTH_AES_XCBC_96,       "AUTH_AES_XCBC_96"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_MD5_128,      "AUTH_HMAC_MD5_128"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_160,     "AUTH_HMAC_SHA1_160"},
   {IKE_TRANSFORM_ID_AUTH_AES_CMAC_96,       "AUTH_AES_CMAC_96"},
   {IKE_TRANSFORM_ID_AUTH_AES_128_GMAC,      "AUTH_AES_128_GMAC"},
   {IKE_TRANSFORM_ID_AUTH_AES_192_GMAC,      "AUTH_AES_192_GMAC"},
   {IKE_TRANSFORM_ID_AUTH_AES_256_GMAC,      "AUTH_AES_256_GMAC"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128, "AUTH_HMAC_SHA2_256_128"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192, "AUTH_HMAC_SHA2_384_192"},
   {IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256, "AUTH_HMAC_SHA2_512_256"}
};

//Diffie-Hellman groups
static const IkeParamName ikeDhGroupList[] =
{
   {IKE_TRANSFORM_ID_DH_GROUP_NONE,            "None"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_768,        "768-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_1024,       "1024-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_1536,       "1536-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_2048,       "2048-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_3072,       "3072-bit MODP group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_4096,       "4096-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_6144,       "6144-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_8192,       "8192-bit MODP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_ECP_256,         "256-bit random ECP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_ECP_384,         "384-bit random ECP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_ECP_521,         "521-bit random ECP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_1024_160,   "1024-bit MODP Group with 160-bit Prime Order Subgroup"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_224,   "2048-bit MODP Group with 224-bit Prime Order Subgroup"},
   {IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_256,   "2048-bit MODP Group with 256-bit Prime Order Subgroup"},
   {IKE_TRANSFORM_ID_DH_GROUP_ECP_192,         "192-bit Random ECP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_ECP_224,         "224-bit Random ECP Group"},
   {IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP224R1, "brainpoolP224r1"},
   {IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP256R1, "brainpoolP256r1"},
   {IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP384R1, "brainpoolP384r1"},
   {IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP512R1, "brainpoolP512r1"},
   {IKE_TRANSFORM_ID_DH_GROUP_CURVE25519,      "Curve25519"},
   {IKE_TRANSFORM_ID_DH_GROUP_CURVE448,        "Curve448"}
};

//Extended sequence numbers
static const IkeParamName ikeEsnList[] =
{
   {IKE_TRANSFORM_ID_ESN_NO,  "No ESNs"},
   {IKE_TRANSFORM_ID_ESN_YES, "ESNs"}
};

//Transform attribute formats
static const IkeParamName ikeAttrFormatList[] =
{
   {IKE_ATTR_FORMAT_TLV, "TLV"},
   {IKE_ATTR_FORMAT_TV,  "TV"}
};

//Transform attribute types
static const IkeParamName ikeAttrTypeList[] =
{
   {IKE_TRANSFORM_ATTR_TYPE_KEY_LEN, "Key Length"},
};

//ID types
static const IkeParamName ikeIdTypeList[] =
{
   {IKE_ID_TYPE_IPV4_ADDR,   "ID_IPV4_ADDR"},
   {IKE_ID_TYPE_FQDN,        "ID_FQDN"},
   {IKE_ID_TYPE_RFC822_ADDR, "ID_RFC822_ADDR"},
   {IKE_ID_TYPE_IPV6_ADDR,   "ID_IPV6_ADDR"},
   {IKE_ID_TYPE_DER_ASN1_DN, "ID_DER_ASN1_DN"},
   {IKE_ID_TYPE_DER_ASN1_GN, "ID_DER_ASN1_GN"},
   {IKE_ID_TYPE_KEY_ID,      "ID_KEY_ID"},
   {IKE_ID_TYPE_FC_NAME,     "ID_FC_NAME"},
   {IKE_ID_TYPE_NULL,        "ID_NULL"}
};

//Certificate encoding
static const IkeParamName ikeCertEncodingList[] =
{
   {IKE_CERT_ENCODING_PKCS7_X509_CERT,      "PKCS #7 wrapped X.509 certificate"},
   {IKE_CERT_ENCODING_PGP_CERT,             "PGP certificate"},
   {IKE_CERT_ENCODING_DNS_SIGNED_KEY,       "DNS signed key"},
   {IKE_CERT_ENCODING_X509_CERT_SIGN,       "X.509 certificate - signature"},
   {IKE_CERT_ENCODING_KERBEROS_TOKEN,       "Kerberos token"},
   {IKE_CERT_ENCODING_CRL,                  "Certificate revocation list"},
   {IKE_CERT_ENCODING_ARL,                  "Authority revocation list"},
   {IKE_CERT_ENCODING_SPKI_CERT,            "SPKI certificate"},
   {IKE_CERT_ENCODING_X509_CERT_ATTR,       "X.509 certificate - attribute"},
   {IKE_CERT_ENCODING_RAW_RSA_KEY,          "Raw RSA key"},
   {IKE_CERT_ENCODING_HASH_URL_X509_CERT,   "Hash and URL of X.509 certificate"},
   {IKE_CERT_ENCODING_HASH_URL_X509_BUNDLE, "Hash and URL of X.509 bundle"},
   {IKE_CERT_ENCODING_OCSP_CONTENT,         "OCSP Content"},
   {IKE_CERT_ENCODING_RAW_PUBLIC_KEY,       "Raw Public Key"}
};

//Authentication methods
static const IkeParamName ikeAuthMethodList[] =
{
   {IKE_AUTH_METHOD_RSA,               "RSA Digital Signature"},
   {IKE_AUTH_METHOD_SHARED_KEY,        "Shared Key Message Integrity Code"},
   {IKE_AUTH_METHOD_DSS,               "DSS Digital Signature"},
   {IKE_AUTH_METHOD_ECDSA_P256_SHA256, "ECDSA with SHA-256 on the P-256 curve"},
   {IKE_AUTH_METHOD_ECDSA_P384_SHA384, "ECDSA with SHA-384 on the P-384 curve"},
   {IKE_AUTH_METHOD_ECDSA_P521_SHA512, "ECDSA with SHA-512 on the P-521 curve"},
   {IKE_AUTH_METHOD_GSPAM,             "Generic Secure Password Authentication Method"},
   {IKE_AUTH_METHOD_NULL,              "NULL Authentication"},
   {IKE_AUTH_METHOD_DIGITAL_SIGN,      "Digital Signature"},
};

//Notify message types
static const IkeParamName ikeNotifyMsgTypeList[] =
{
   {IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD,        "UNSUPPORTED_CRITICAL_PAYLOAD"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_IKE_SPI,                     "INVALID_IKE_SPI"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_MAJOR_VERSION,               "INVALID_MAJOR_VERSION"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX,                      "INVALID_SYNTAX"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_MESSAGE_ID,                  "INVALID_MESSAGE_ID"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_SPI,                         "INVALID_SPI"},
   {IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN,                  "NO_PROPOSAL_CHOSEN"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD,                  "INVALID_KE_PAYLOAD"},
   {IKE_NOTIFY_MSG_TYPE_AUTHENTICATION_FAILED,               "AUTHENTICATION_FAILED"},
   {IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED,                "SINGLE_PAIR_REQUIRED"},
   {IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS,                   "NO_ADDITIONAL_SAS"},
   {IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE,            "INTERNAL_ADDRESS_FAILURE"},
   {IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED,                  "FAILED_CP_REQUIRED"},
   {IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE,                     "TS_UNACCEPTABLE"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_SELECTORS,                   "INVALID_SELECTORS"},
   {IKE_NOTIFY_MSG_TYPE_UNACCEPTABLE_ADDRESSES,              "UNACCEPTABLE_ADDRESSES"},
   {IKE_NOTIFY_MSG_TYPE_UNEXPECTED_NAT_DETECTED,             "UNEXPECTED_NAT_DETECTED"},
   {IKE_NOTIFY_MSG_TYPE_USE_ASSIGNED_HOA,                    "USE_ASSIGNED_HOA"},
   {IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE,                   "TEMPORARY_FAILURE"},
   {IKE_NOTIFY_MSG_TYPE_CHILD_SA_NOT_FOUND,                  "CHILD_SA_NOT_FOUND"},
   {IKE_NOTIFY_MSG_TYPE_INVALID_GROUP_ID,                    "INVALID_GROUP_ID"},
   {IKE_NOTIFY_MSG_TYPE_AUTHORIZATION_FAILED,                "AUTHORIZATION_FAILED"},
   {IKE_NOTIFY_MSG_TYPE_STATE_NOT_FOUND,                     "STATE_NOT_FOUND"},
   {IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT,                     "INITIAL_CONTACT"},
   {IKE_NOTIFY_MSG_TYPE_SET_WINDOW_SIZE,                     "SET_WINDOW_SIZE"},
   {IKE_NOTIFY_MSG_TYPE_ADDITIONAL_TS_POSSIBLE,              "ADDITIONAL_TS_POSSIBLE"},
   {IKE_NOTIFY_MSG_TYPE_IPCOMP_SUPPORTED,                    "IPCOMP_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_SOURCE_IP,             "NAT_DETECTION_SOURCE_IP"},
   {IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_DESTINATION_IP,        "NAT_DETECTION_DESTINATION_IP"},
   {IKE_NOTIFY_MSG_TYPE_COOKIE,                              "COOKIE"},
   {IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE,                  "USE_TRANSPORT_MODE"},
   {IKE_NOTIFY_MSG_TYPE_HTTP_CERT_LOOKUP_SUPPORTED,          "HTTP_CERT_LOOKUP_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_REKEY_SA,                            "REKEY_SA"},
   {IKE_NOTIFY_MSG_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED,       "ESP_TFC_PADDING_NOT_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_NON_FIRST_FRAGMENTS_ALSO,            "NON_FIRST_FRAGMENTS_ALSO"},
   {IKE_NOTIFY_MSG_TYPE_MOBIKE_SUPPORTED,                    "MOBIKE_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_ADDITIONAL_IP4_ADDRESS,              "ADDITIONAL_IP4_ADDRESS"},
   {IKE_NOTIFY_MSG_TYPE_ADDITIONAL_IP6_ADDRESS,              "ADDITIONAL_IP6_ADDRESS"},
   {IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_ADDRESSES,             "NO_ADDITIONAL_ADDRESSES"},
   {IKE_NOTIFY_MSG_TYPE_UPDATE_SA_ADDRESSES,                 "UPDATE_SA_ADDRESSES"},
   {IKE_NOTIFY_MSG_TYPE_COOKIE2,                             "COOKIE2"},
   {IKE_NOTIFY_MSG_TYPE_NO_NATS_ALLOWED,                     "NO_NATS_ALLOWED"},
   {IKE_NOTIFY_MSG_TYPE_AUTH_LIFETIME,                       "AUTH_LIFETIME"},
   {IKE_NOTIFY_MSG_TYPE_MULTIPLE_AUTH_SUPPORTED,             "MULTIPLE_AUTH_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_ANOTHER_AUTH_FOLLOWS,                "ANOTHER_AUTH_FOLLOWS"},
   {IKE_NOTIFY_MSG_TYPE_REDIRECT_SUPPORTED,                  "REDIRECT_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_REDIRECT,                            "REDIRECT"},
   {IKE_NOTIFY_MSG_TYPE_REDIRECTED_FROM,                     "REDIRECTED_FROM"},
   {IKE_NOTIFY_MSG_TYPE_TICKET_LT_OPAQUE,                    "TICKET_LT_OPAQUE"},
   {IKE_NOTIFY_MSG_TYPE_TICKET_REQUEST,                      "TICKET_REQUEST"},
   {IKE_NOTIFY_MSG_TYPE_TICKET_ACK,                          "TICKET_ACK"},
   {IKE_NOTIFY_MSG_TYPE_TICKET_NACK,                         "TICKET_NACK"},
   {IKE_NOTIFY_MSG_TYPE_TICKET_OPAQUE,                       "TICKET_OPAQUE"},
   {IKE_NOTIFY_MSG_TYPE_LINK_ID,                             "LINK_ID"},
   {IKE_NOTIFY_MSG_TYPE_USE_WESP_MODE,                       "USE_WESP_MODE"},
   {IKE_NOTIFY_MSG_TYPE_ROHC_SUPPORTED,                      "ROHC_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_EAP_ONLY_AUTHENTICATION,             "EAP_ONLY_AUTHENTICATION"},
   {IKE_NOTIFY_MSG_TYPE_CHILDLESS_IKEV2_SUPPORTED,           "CHILDLESS_IKEV2_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_QUICK_CRASH_DETECTION,               "QUICK_CRASH_DETECTION"},
   {IKE_NOTIFY_MSG_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED,     "IKEV2_MESSAGE_ID_SYNC_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED, "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_IKEV2_MESSAGE_ID_SYNC,               "IKEV2_MESSAGE_ID_SYNC"},
   {IKE_NOTIFY_MSG_TYPE_IPSEC_REPLAY_COUNTER_SYNC,           "IPSEC_REPLAY_COUNTER_SYNC"},
   {IKE_NOTIFY_MSG_TYPE_SECURE_PASSWORD_METHODS,             "SECURE_PASSWORD_METHODS"},
   {IKE_NOTIFY_MSG_TYPE_PSK_PERSIST,                         "PSK_PERSIST"},
   {IKE_NOTIFY_MSG_TYPE_PSK_CONFIRM,                         "PSK_CONFIRM"},
   {IKE_NOTIFY_MSG_TYPE_ERX_SUPPORTED,                       "ERX_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_IFOM_CAPABILITY,                     "IFOM_CAPABILITY"},
   {IKE_NOTIFY_MSG_TYPE_SENDER_REQUEST_ID,                   "SENDER_REQUEST_ID"},
   {IKE_NOTIFY_MSG_TYPE_IKEV2_FRAGMENTATION_SUPPORTED,       "IKEV2_FRAGMENTATION_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS,           "SIGNATURE_HASH_ALGORITHMS"},
   {IKE_NOTIFY_MSG_TYPE_CLONE_IKE_SA_SUPPORTED,              "CLONE_IKE_SA_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_CLONE_IKE_SA,                        "CLONE_IKE_SA"},
   {IKE_NOTIFY_MSG_TYPE_PUZZLE,                              "PUZZLE"},
   {IKE_NOTIFY_MSG_TYPE_USE_PPK,                             "USE_PPK"},
   {IKE_NOTIFY_MSG_TYPE_PPK_IDENTITY,                        "PPK_IDENTITY"},
   {IKE_NOTIFY_MSG_TYPE_NO_PPK_AUTH,                         "NO_PPK_AUTH"},
   {IKE_NOTIFY_MSG_TYPE_INTERMEDIATE_EXCHANGE_SUPPORTED,     "INTERMEDIATE_EXCHANGE_SUPPORTED"},
   {IKE_NOTIFY_MSG_TYPE_IP4_ALLOWED,                         "IP4_ALLOWED"},
   {IKE_NOTIFY_MSG_TYPE_IP6_ALLOWED,                         "IP6_ALLOWED"},
   {IKE_NOTIFY_MSG_TYPE_ADDITIONAL_KEY_EXCHANGE,             "ADDITIONAL_KEY_EXCHANGE"},
   {IKE_NOTIFY_MSG_TYPE_USE_AGGFRAG,                         "USE_AGGFRAG"},
};

//Traffic selector types
static const IkeParamName ikeTsTypeList[] =
{
   {IKE_TS_TYPE_IPV4_ADDR_RANGE, "TS_IPV4_ADDR_RANGE"},
   {IKE_TS_TYPE_IPV6_ADDR_RANGE, "TS_IPV6_ADDR_RANGE"}
};

//IP protocol IDs
static const IkeParamName ikeIpProtocolIdList[] =
{
   {IKE_IP_PROTOCOL_ID_ICMP,   "ICMP"},
   {IKE_IP_PROTOCOL_ID_TCP,    "TCP"},
   {IKE_IP_PROTOCOL_ID_UDP,    "UDP"},
   {IKE_IP_PROTOCOL_ID_ICMPV6, "ICMPv6"},
};


/**
 * @brief Dump IKE message
 * @param[in] message Pointer to the IKE message to dump
 * @param[in] length Length of the IKE message, in bytes
 **/

void ikeDumpMessage(const uint8_t *message, size_t length)
{
   const IkeHeader *header;

   //Check the length of the IKE message
   if(length < sizeof(IkeHeader))
      return;

   //Each message begins with the IKE header
   header = (IkeHeader *) message;

   //Dump IKE header
   ikeDumpHeader(header);

   //Determine the length of the IKE payloads
   length -= sizeof(IkeHeader);

   //The Next Payload field indicates the type of payload that immediately
   //follows the header
   ikeDumpPayloads(message + sizeof(IkeHeader), length, header->nextPayload);
}


/**
 * @brief Dump IKE header
 * @param[in] header Pointer to the IKE header to dump
 **/

void ikeDumpHeader(const IkeHeader *header)
{
   const char_t *nextPayloadName;
   const char_t *exchangeTypeName;

   //Convert the Next Payload field to string representation
   nextPayloadName = ikeGetParamName(header->nextPayload,
      ikePayloadList, arraysize(ikePayloadList));

   //Convert the Exchange Type field to string representation
   exchangeTypeName = ikeGetParamName(header->exchangeType,
      ikeExchangeTypeList, arraysize(ikeExchangeTypeList));

   //Dump IKE header
   TRACE_DEBUG_ARRAY("  Initiator SPI = ", header->initiatorSpi, IKE_SPI_SIZE);
   TRACE_DEBUG_ARRAY("  Responder SPI = ", header->responderSpi, IKE_SPI_SIZE);
   TRACE_DEBUG("  Next Payload = %" PRIu8 " (%s)\r\n", header->nextPayload, nextPayloadName);
   TRACE_DEBUG("  Major Version = %" PRIu8 "\r\n", header->majorVersion);
   TRACE_DEBUG("  Minor Version = %" PRIu8 "\r\n", header->minorVersion);
   TRACE_DEBUG("  Exchange Type = %" PRIu8 " (%s)\r\n", header->exchangeType, exchangeTypeName);
   ikeDumpFlags(header->flags);
   TRACE_DEBUG("  Message ID = %" PRIu32 "\r\n", ntohl(header->messageId));
   TRACE_DEBUG("  Length = %" PRIu32 "\r\n", ntohl(header->length));
}


/**
 * @brief Dump flags
 * @param[in] flags specific options that are set for the IKE message
 **/

void ikeDumpFlags(uint8_t flags)
{
   uint8_t r;
   uint8_t v;
   uint8_t i;

   //The R bit indicates that this message is a response to a message containing
   //the same Message ID
   r = (flags & IKE_FLAGS_R) ? 1 : 0;

   //The V bit indicates that the transmitter is capable of speaking a higher
   //major version number of the protocol than the one indicated in the major
   //version number field
   v = (flags & IKE_FLAGS_V) ? 1 : 0;

   //The I bit must be set in messages sent by the original initiator of the
   //IKE SA and must be cleared in messages sent by the original responder
   i = (flags & IKE_FLAGS_I) ? 1 : 0;

   //Check whether any flag is set
   if(r != 0 || v != 0 || i != 0)
   {
      //Dump the value of the Flags field
      TRACE_DEBUG("  Flags = 0x%02" PRIX8 " (", flags);

      //Dump flags
      while(1)
      {
         if(r != 0)
         {
            TRACE_DEBUG("Response");
            r = FALSE;
         }
         else if(v != 0)
         {
            TRACE_DEBUG("Version");
            v = FALSE;
         }
         else if(i != 0)
         {
            TRACE_DEBUG("Initiator");
            i = FALSE;
         }
         else
         {
         }

         if(r != 0 || v != 0 || i != 0)
         {
            TRACE_DEBUG(", ");
         }
         else
         {
            TRACE_DEBUG(")\r\n");
            break;
         }
      }
   }
   else
   {
      //Dump the value of the Flags field
      TRACE_DEBUG("  Flags = 0x%02" PRIX8 "\r\n", flags);
   }
}


/**
 * @brief Dump IKE payloads
 * @param[in] payloads Pointer to the IKE payloads to dump
 * @param[in] length Length of the IKE payloads, in bytes
 * @param[in] nextPayload Next payload type
 **/

void ikeDumpPayloads(const uint8_t *payloads, size_t length,
   uint8_t nextPayload)
{
   size_t n;
   const char_t *payloadName;
   const IkePayloadHeader *payload;

   //Following the header are one or more IKE payloads each identified by
   //a Next Payload field in the preceding payload
   while(nextPayload != IKE_PAYLOAD_TYPE_LAST &&
      length >= sizeof(IkePayloadHeader))
   {
      //Retrieve the name of the current IKE payload
      payloadName = ikeGetParamName(nextPayload, ikePayloadList,
         arraysize(ikePayloadList));

      //Each IKE payload begins with a generic payload header
      payload = (IkePayloadHeader *) payloads;

      //The Payload Length field indicates the length in octets of the current
      //payload, including the generic payload header
      n = ntohs(payload->payloadLength);

      //Display the name of the current IKE payload
      TRACE_DEBUG("  %s Payload (%" PRIuSIZE " bytes)\r\n", payloadName, n);

      //Check the length of the IKE payload
      if(n < sizeof(IkePayloadHeader) || n > length)
         break;

      //Dump generic payload header
      ikeDumpPayloadHeader(payload);

      //Check IKE payload type
      if(nextPayload == IKE_PAYLOAD_TYPE_SA)
      {
         //Dump Security Association payload
         ikeDumpSaPayload((IkeSaPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_KE)
      {
         //Dump Key Exchange payload
         ikeDumpKePayload((IkeKePayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_IDI ||
         nextPayload == IKE_PAYLOAD_TYPE_IDR)
      {
         //Dump Identification payload
         ikeDumpIdPayload((IkeIdPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_CERT)
      {
         //Dump Certificate
         ikeDumpCertPayload((IkeCertPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_CERTREQ)
      {
         //Dump Certificate Request
         ikeDumpCertReqPayload((IkeCertReqPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_AUTH)
      {
         //Dump Authentication payload
         ikeDumpAuthPayload((IkeAuthPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_NONCE)
      {
         //Dump Nonce payload
         ikeDumpNoncePayload((IkeNoncePayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_N)
      {
         //Dump Notify payload
         ikeDumpNotifyPayload((IkeNotifyPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_D)
      {
         //Dump Delete payload
         ikeDumpDeletePayload((IkeDeletePayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_TSI ||
         nextPayload == IKE_PAYLOAD_TYPE_TSR)
      {
         //Dump Traffic Selector payload
         ikeDumpTsPayload((IkeTsPayload *) payload, n);
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_SK)
      {
         //Dump Encrypted payload
         ikeDumpEncryptedPayload((IkeEncryptedPayload *) payload, n);

         //The Encrypted payload, if present in a message, must be the last
         //payload in the message (refer to RFC 7296, section 3.14)
         break;
      }
      else if(nextPayload == IKE_PAYLOAD_TYPE_SKF)
      {
         //Dump Encrypted Fragment payload
         ikeDumpEncryptedFragPayload((IkeEncryptedFragPayload *) payload, n);

         //As is the case for the Encrypted payload, the Encrypted Fragment
         //payload, if present in a message, MUST be the last payload in the
         //message (refer to RFC 7383, section 2.5)
         break;
      }
      else
      {
         //Unknown IKE payload type
      }

      //The Next Payload field indicates the payload type of the next payload
      //in the message
      nextPayload = payload->nextPayload;

      //Jump to the next IKE payload
      payloads += n;
      length -= n;
   }
}


/**
 * @brief Dump generic payload header
 * @param[in] header Pointer to the generic payload header to dump
 **/

void ikeDumpPayloadHeader(const IkePayloadHeader *header)
{
   const char_t *nextPayloadName;

   //Convert the Next Payload field to string representation
   nextPayloadName = ikeGetParamName(header->nextPayload,
      ikePayloadList, arraysize(ikePayloadList));

   //Dump generic payload header
   TRACE_DEBUG("    Next Payload = %" PRIu8 " (%s)\r\n", header->nextPayload, nextPayloadName);
   TRACE_DEBUG("    Critical = %" PRIu8 "\r\n", header->critical);
   TRACE_DEBUG("    Payload Length = %" PRIu16 "\r\n", ntohs(header->payloadLength));
}


/**
 * @brief Dump Security Association payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpSaPayload(const IkeSaPayload *payload, size_t length)
{
   size_t n;
   const uint8_t *p;
   const IkeProposal *proposal;

   //Check the length of the payload
   if(length < sizeof(IkeSaPayload))
      return;

   //Point to the first byte of the Proposals field
   p = payload->proposals;
   //Determine the length of the Proposals field
   length -= sizeof(IkeSaPayload);

   //The Security Association payload contains one or more Proposal
   //substructures
   while(length >= sizeof(IkeProposal))
   {
      //Point to the Proposal substructure
      proposal = (IkeProposal *) p;

      //The Proposal Length field indicates the length of this proposal,
      //including all transforms and attributes that follow
      n = ntohs(proposal->proposalLength);

      //Debug message
      TRACE_DEBUG("    Proposal (%" PRIuSIZE " bytes)\r\n", n);

      //Check the length of the proposal
      if(n < sizeof(IkeProposal) || n > length)
         break;

      //Dump Proposal substructure
      ikeDumpProposal(proposal, n);

      //Jump to the next proposal
      p += n;
      length -= n;
   }
}


/**
 * @brief Dump Proposal substructure
 * @param[in] proposal Pointer to the Proposal substructure to dump
 * @param[in] length Length of the proposal, in bytes
 **/

void ikeDumpProposal(const IkeProposal *proposal, size_t length)
{
   uint_t i;
   size_t n;
   const uint8_t *p;
   const char_t *lastSubstrucName;
   const char_t *protocolIdName;
   const IkeTransform *transform;

   //Check the length of the Proposal substructure
   if(length < sizeof(IkeProposal))
      return;

   //The Last Substruc field specifies whether or not this is the last
   //Proposal Substructure in the SA
   lastSubstrucName = ikeGetParamName(proposal->lastSubstruc,
      ikeLastSubstrucList, arraysize(ikeLastSubstrucList));

   //The Protocol ID specifies the IPsec protocol identifier for the
   //current negotiation
   protocolIdName = ikeGetParamName(proposal->protocolId,
      ikeProtocolIdList, arraysize(ikeProtocolIdList));

   //Dump Proposal substructure
   TRACE_DEBUG("      Last Substruc = %" PRIu8 " (%s)\r\n",
      proposal->lastSubstruc, lastSubstrucName);

   TRACE_DEBUG("      Proposal Length = %" PRIu16 "\r\n",
      ntohs(proposal->proposalLength));

   TRACE_DEBUG("      Proposal Num = %" PRIu8 "\r\n", proposal->proposalNum);

   TRACE_DEBUG("      Protocol ID = %" PRIu8 " (%s)\r\n",
      proposal->protocolId, protocolIdName);

   TRACE_DEBUG("      SPI Size = %" PRIu8 "\r\n", proposal->spiSize);
   TRACE_DEBUG("      Num Transforms = %" PRIu8 "\r\n", proposal->numTransforms);

   //Malformed substructure?
   if(length < (sizeof(IkeProposal) + proposal->spiSize))
      return;

   //Dump SPI
   TRACE_DEBUG("      SPI (%" PRIu8 " bytes)\r\n", proposal->spiSize);
   TRACE_DEBUG_ARRAY("        ", proposal->spi, proposal->spiSize);

   //Point to the first byte of the Transforms field
   p = (uint8_t *) proposal + sizeof(IkeProposal) + proposal->spiSize;
   //Determine the length of the Transforms field
   length -= sizeof(IkeProposal) + proposal->spiSize;

   //The Transforms field contains one or more Transform substructures
   for(i = 1; i <= proposal->numTransforms; i++)
   {
      //Malformed substructure?
      if(length < sizeof(IkeTransform))
         break;

      //Point to the Transform substructure
      transform = (IkeTransform *) p;

      //The Transform Length field indicates the length of the Transform
      //substructure including header and attributes
      n = ntohs(transform->transformLength);

      //Debug message
      TRACE_DEBUG("      Transform %u (%" PRIuSIZE " bytes)\r\n", i, n);

      //Check the length of the transform
      if(n < sizeof(IkeTransform) || n > length)
         break;

      //Dump Transform substructure
      ikeDumpTransform(transform, n);

      //Jump to the next transform
      p += n;
      length -= n;
   }
}


/**
 * @brief Dump Transform substructure
 * @param[in] transform Pointer to the Transform substructure to dump
 * @param[in] length Length of the transform, in bytes
 **/

void ikeDumpTransform(const IkeTransform *transform, size_t length)
{
   error_t error;
   uint_t i;
   size_t n;
   uint16_t transformId;
   const uint8_t *p;
   const char_t *lastSubstrucName;
   const char_t *transformName;
   const char_t *algoName;
   const IkeTransformAttr *attr;

   //Check the length of the Transform substructure
   if(length < sizeof(IkeTransform))
      return;

   //The Last Substruc field specifies whether or not this is the last
   //Proposal Substructure in the SA
   lastSubstrucName = ikeGetParamName(transform->lastSubstruc,
      ikeLastSubstrucList, arraysize(ikeLastSubstrucList));

   //Retrieve the type of transform being specified in this transform
   transformName = ikeGetParamName(transform->transformType,
      ikeTransformTypeList, arraysize(ikeTransformTypeList));

   //Dump Transform substructure
   TRACE_DEBUG("        Last Substruc = %" PRIu8 " (%s)\r\n",
      transform->lastSubstruc, lastSubstrucName);

   TRACE_DEBUG("        Transform Length = %" PRIu16 "\r\n",
      ntohs(transform->transformLength));

   TRACE_DEBUG("        Transform Type = %" PRIu8 " (%s)\r\n",
      transform->transformType, transformName);

   //Convert the Transform ID field to host byte order
   transformId = ntohs(transform->transformId);

   //Check transform type
   if(transform->transformType == IKE_TRANSFORM_TYPE_ENCR)
   {
      //Transform type 1 (encryption algorithm)
      algoName = ikeGetParamName(transformId, ikeEncrAlgoList,
         arraysize(ikeEncrAlgoList));
   }
   else if(transform->transformType == IKE_TRANSFORM_TYPE_PRF)
   {
      //Transform type 2 (pseudorandom functions)
      algoName = ikeGetParamName(transformId, ikePrfAlgoList,
         arraysize(ikePrfAlgoList));
   }
   else if(transform->transformType == IKE_TRANSFORM_TYPE_INTEG)
   {
      //Transform type 3 (integrity algorithm)
      algoName = ikeGetParamName(transformId, ikeAuthAlgoList,
         arraysize(ikeAuthAlgoList));
   }
   else if(transform->transformType == IKE_TRANSFORM_TYPE_DH)
   {
      //Transform type 4 (Diffie-Hellman group)
      algoName = ikeGetParamName(transformId, ikeDhGroupList,
         arraysize(ikeDhGroupList));
   }
   else if(transform->transformType == IKE_TRANSFORM_TYPE_ESN)
   {
      //Transform type 5 (extended sequence numbers)
      algoName = ikeGetParamName(transformId, ikeEsnList,
         arraysize(ikeEsnList));
   }
   else
   {
      //Unknown transform
      algoName = "Unknown";
   }

   //Dump Transform ID field
   TRACE_DEBUG("        Transform ID = %" PRIu16 " (%s)\r\n",
      transformId, algoName);

   //Point to the first byte of the Transform Attributes field
   p = transform->transformAttr;
   //Get the length of the Transform Attributes field
   length -= sizeof(IkeTransform);

   //The Transform Attributes field contains one or more attributes
   for(i = 1; ; i++)
   {
      //Malformed attribute?
      if(length < sizeof(IkeTransformAttr))
         break;

      //Point to the Transform attribute
      attr = (IkeTransformAttr *) p;

      //Debug message
      TRACE_DEBUG("        Transform Attribute %u\r\n", i);

      //Dump transform attribute
      error = ikeDumpTransformAttr(attr, length, &n);
      //Any error to report?
      if(error)
         break;

      //Jump to the next attribute
      p += n;
      length -= n;
   }
}


/**
 * @brief Dump transform attribute
 * @param[in] attr Pointer to the transform attribute to dump
 * @param[in] length Number of bytes available in the input stream
 * @param[out] consumed Total number of characters that have been consumed
 * @return Error code
 **/

error_t ikeDumpTransformAttr(const IkeTransformAttr *attr, size_t length,
   size_t *consumed)
{
   size_t n;
   uint16_t attrFormat;
   uint16_t attrType;
   const char_t *attrFormatName;
   const char_t *attrTypeName;

   //Malformed attribute?
   if(length < sizeof(IkeTransformAttr))
      return ERROR_INVALID_SYNTAX;

   //Retrieve the format of the attribute
   attrFormat = (ntohs(attr->type) & 0x8000) >> 15;
   //Retrieve the type of the attribute
   attrType = ntohs(attr->type) & 0x7FFF;

   //The AF field indicates whether the data attribute follows the TLV
   //format or a shortened TV format
   attrFormatName = ikeGetParamName(ntohs(attr->type) & 0x8000,
      ikeAttrFormatList, arraysize(ikeAttrFormatList));

   //The Attribute Type field is a unique identifier for each type of
   //attribute
   attrTypeName = ikeGetParamName(attrType, ikeAttrTypeList,
      arraysize(ikeAttrTypeList));

   //Dump Transform Attribute
   TRACE_DEBUG("          Attribute Format = %" PRIu16 " (%s)\r\n",
      attrFormat, attrFormatName);

   TRACE_DEBUG("          Attribute Type = %" PRIu16 " (%s)\r\n",
      attrType, attrTypeName);

   //Check the format of the attribute
   if((ntohs(attr->type) & IKE_ATTR_FORMAT_TV) != 0)
   {
      //If the AF bit is set, then the attribute value has a fixed length
      n = 0;

      //Dump attribute value
      TRACE_DEBUG("          Attribute Value = %" PRIu16 "\r\n",
         ntohs(attr->length));
   }
   else
   {
      //If the AF bit is not set, then this attribute has a variable length
      //defined by the Attribute Length field
      n = ntohs(attr->length);

      //Dump attribute length
      TRACE_DEBUG("          Attribute Length = %" PRIu16 "\r\n", n);

      //Malformed attribute?
      if(length < (sizeof(IkeTransformAttr) + n))
         return ERROR_INVALID_SYNTAX;

      //Dump attribute value
      TRACE_DEBUG("          Attribute Value (%" PRIuSIZE " bytes)\r\n", n);
      TRACE_DEBUG_ARRAY("            ", attr->value, n);
   }

   //Total number of bytes that have been consumed
   *consumed = sizeof(IkeTransformAttr) + n;

   //Parsing was successful
   return NO_ERROR;
}


/**
 * @brief Dump Key Exchange payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpKePayload(const IkeKePayload *payload, size_t length)
{
   size_t n;
   uint16_t groupNum;
   const char_t *groupName;

   //Check the length of the payload
   if(length < sizeof(IkeKePayload))
      return;

   //Determine the length of the Key Exchange Data field
   n = length - sizeof(IkeKePayload);

   //The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
   //which the Key Exchange Data was computed
   groupNum = ntohs(payload->dhGroupNum);

   //Convert the Diffie-Hellman Group Num field to string representation
   groupName = ikeGetParamName(groupNum, ikeDhGroupList,
      arraysize(ikeDhGroupList));

   //Dump Diffie-Hellman Group Num field
   TRACE_DEBUG("    Diffie-Hellman Group Num = 0x%" PRIX16 " (%s)\r\n",
      groupNum, groupName);

   //Dump Key Exchange Data field
   TRACE_DEBUG("    Key Exchange Data (%" PRIuSIZE " bytes)\r\n", n);
   TRACE_DEBUG_ARRAY("      ", payload->keyExchangeData, n);
}


/**
 * @brief Dump Identification payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpIdPayload(const IkeIdPayload *payload, size_t length)
{
   const char_t *idTypeName;

   //Check the length of the payload
   if(length < sizeof(IkeIdPayload))
      return;

   //The ID Type field specifies the type of Identification being used
   idTypeName = ikeGetParamName(payload->idType, ikeIdTypeList,
      arraysize(ikeIdTypeList));

   //Dump ID Type field
   TRACE_DEBUG("    ID Type = %" PRIu8 " (%s)\r\n", payload->idType,
      idTypeName);

   //The Identification Data field has a variable length
   length -= sizeof(IkeIdPayload);

   //Dump Identification Data field
   TRACE_DEBUG("    Identification Data (%" PRIuSIZE " bytes)\r\n", length);

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address?
   if(payload->idType == IKE_ID_TYPE_IPV4_ADDR && length == sizeof(Ipv4Addr))
   {
      Ipv4Addr ipv4Addr;

      //Copy IPv4 address
      ipv4CopyAddr(&ipv4Addr, payload->idData);
      //Dump IPv4 address
      TRACE_DEBUG("      %s\r\n", ipv4AddrToString(ipv4Addr, NULL));
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv4 address?
   if(payload->idType == IKE_ID_TYPE_IPV6_ADDR && length == sizeof(Ipv6Addr))
   {
      Ipv6Addr ipv6Addr;

      //Copy IPv6 address
      ipv6CopyAddr(&ipv6Addr, payload->idData);
      //Dump IPv6 address
      TRACE_DEBUG("      %s\r\n", ipv6AddrToString(&ipv6Addr, NULL));
   }
   else
#endif
   {
      //Dump Identification Data field
      TRACE_DEBUG_ARRAY("      ", payload->idData, length);
   }
}


/**
 * @brief Dump Certificate payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpCertPayload(const IkeCertPayload *payload, size_t length)
{
   const char_t *certEncodingName;

   //Check the length of the payload
   if(length < sizeof(IkeCertPayload))
      return;

   //The Certificate Encoding field indicates the type of certificate or
   //certificate-related information contained in the Certificate Data field
   certEncodingName = ikeGetParamName(payload->certEncoding,
      ikeCertEncodingList, arraysize(ikeCertEncodingList));

   //Dump Certificate Encoding field
   TRACE_DEBUG("    Certificate Encoding = %" PRIu8 " (%s)\r\n",
      payload->certEncoding, certEncodingName);

   //The Certificate Data field has a variable length
   length -= sizeof(IkeCertPayload);

   //Dump Certificate Data field
   TRACE_DEBUG("    Certificate Data (%" PRIuSIZE " bytes)\r\n", length);
   TRACE_DEBUG_ARRAY("      ", payload->certData, length);
}


/**
 * @brief Dump Certificate Request payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpCertReqPayload(const IkeCertReqPayload *payload, size_t length)
{
   const char_t *certEncodingName;

   //Check the length of the payload
   if(length < sizeof(IkeCertReqPayload))
      return;

   //The Certificate Encoding field contains an encoding of the type or
   //format of certificate requested
   certEncodingName = ikeGetParamName(payload->certEncoding,
      ikeCertEncodingList, arraysize(ikeCertEncodingList));

   //Dump Certificate Encoding field
   TRACE_DEBUG("    Certificate Encoding = %" PRIu8 " (%s)\r\n",
      payload->certEncoding, certEncodingName);

   //The Certification Authority field has a variable length
   length -= sizeof(IkeCertReqPayload);

   //Dump Certification Authority field
   TRACE_DEBUG("    Certification Authority (%" PRIuSIZE " bytes)\r\n", length);
   TRACE_DEBUG_ARRAY("      ", payload->certAuthority, length);
}


/**
 * @brief Dump Authentication payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpAuthPayload(const IkeAuthPayload *payload, size_t length)
{
   size_t n;
   const char_t *authMethodName;

   //Check the length of the payload
   if(length < sizeof(IkeAuthPayload))
      return;

   //The Auth Method field specifies the method of authentication used
   authMethodName = ikeGetParamName(payload->authMethod, ikeAuthMethodList,
      arraysize(ikeAuthMethodList));

   //Dump Auth Method field
   TRACE_DEBUG("    Auth Method = %" PRIu8 " (%s)\r\n",
      payload->authMethod, authMethodName);

   //The Authentication Data field has a variable length
   n = length - sizeof(IkeAuthPayload);

   //Dump Authentication Data field
   TRACE_DEBUG("    Auth Data (%" PRIuSIZE " bytes)\r\n", n);
   TRACE_DEBUG_ARRAY("      ", payload->authData, n);
}


/**
 * @brief Dump Nonce payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpNoncePayload(const IkeNoncePayload *payload, size_t length)
{
   size_t n;

   //Check the length of the payload
   if(length < sizeof(IkeNoncePayload))
      return;

   //The size of the Nonce Data must be between 16 and 256 octets, inclusive
   n = length - sizeof(IkeNoncePayload);

   //Dump Nonce Data field
   TRACE_DEBUG("    Nonce (%" PRIuSIZE " bytes)\r\n", n);
   TRACE_DEBUG_ARRAY("      ", payload->nonceData, n);
}


/**
 * @brief Dump Notify payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpNotifyPayload(const IkeNotifyPayload *payload, size_t length)
{
   size_t n;
   const uint8_t *p;
   const char_t *protocolIdName;
   const char_t *notifyMsgName;

   //Check the length of the payload
   if(length < sizeof(IkeNotifyPayload))
      return;

   //Check the length of the SPI
   if(length < (sizeof(IkeNotifyPayload) + payload->spiSize))
      return;

   //Convert the Protocol ID to string representation
   protocolIdName = ikeGetParamName(payload->protocolId,
      ikeProtocolIdList, arraysize(ikeProtocolIdList));

   //Convert the Notify Message Type to string representation
   notifyMsgName = ikeGetParamName(ntohs(payload->notifyMsgType),
      ikeNotifyMsgTypeList, arraysize(ikeNotifyMsgTypeList));

   //Dump Notify payload
   TRACE_DEBUG("    Protocol ID = %" PRIu8 " (%s)\r\n",
      payload->protocolId, protocolIdName);

   TRACE_DEBUG("    SPI Size = %" PRIu8 "\r\n", payload->spiSize);

   TRACE_DEBUG("    Notify Message Type = %" PRIu16 " (%s)\r\n",
      ntohs(payload->notifyMsgType), notifyMsgName);

   //Dump SPI field
   TRACE_DEBUG("    SPI (%" PRIu8 " bytes)\r\n", payload->spiSize);

   if(payload->spiSize > 0)
   {
      TRACE_DEBUG_ARRAY("      ", payload->spi, payload->spiSize);
   }

   //The Notification Data field has a variable length
   p = payload->spi + payload->spiSize;
   n = length - sizeof(IkeNotifyPayload) - payload->spiSize;

   //Dump Notification Data field
   TRACE_DEBUG("    Notification Data (%" PRIuSIZE " bytes)\r\n", n);

   if(n > 0)
   {
      TRACE_DEBUG_ARRAY("      ", p, n);
   }
}


/**
 * @brief Dump Delete payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpDeletePayload(const IkeDeletePayload *payload, size_t length)
{
   size_t n;
   const char_t *protocolIdName;

   //Check the length of the payload
   if(length < sizeof(IkeDeletePayload))
      return;

   //Convert the Protocol ID to string representation
   protocolIdName = ikeGetParamName(payload->protocolId,
      ikeProtocolIdList, arraysize(ikeProtocolIdList));

   //Dump Delete payload
   TRACE_DEBUG("    Protocol ID = %" PRIu8 " (%s)\r\n",
      payload->protocolId, protocolIdName);

   TRACE_DEBUG("    SPI Size = %" PRIu8 "\r\n", payload->spiSize);

   TRACE_DEBUG("    Number Of SPIs = %" PRIu16 "\r\n", ntohs(payload->numSpi));

   //The SPIs field has a variable length
   n = length - sizeof(IkeDeletePayload);

   //Dump SPIs field
   TRACE_DEBUG("    SPIs (%" PRIuSIZE " bytes)\r\n", n);

   //The SPI size must be zero for IKE (SPI is in message header) or four
   //for AH and ESP
   if(n > 0)
   {
      TRACE_DEBUG_ARRAY("      ", payload->spi, n);
   }
}


/**
 * @brief Dump Traffic Selector payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpTsPayload(const IkeTsPayload *payload, size_t length)
{
   uint_t i;
   size_t n;
   const uint8_t *p;
   const IkeTs *ts;

   //Check the length of the payload
   if(length < sizeof(IkeTsPayload))
      return;

   //Dump Number of TSs field
   TRACE_DEBUG("    Number of TSs = %" PRIu8 "\r\n", payload->numTs);

   //Point to the first byte of the Traffic Selectors field
   p = (uint8_t *) payload + sizeof(IkeProposal);
   //Determine the length of the Traffic Selectors field
   length -= sizeof(IkeTsPayload);

   //The Traffic Selectors field contains one or more Traffic Selector
   //substructures
   for(i = 1; i <= payload->numTs; i++)
   {
      //Malformed substructure?
      if(length < sizeof(IkeTs))
         break;

      //Point to the Traffic Selector substructure
      ts = (IkeTs *) p;

      //The Selector Length field indicates the length of the Traffic Selector
      //substructure including the header
      n = ntohs(ts->selectorLength);

      //Debug message
      TRACE_DEBUG("    Traffic Selector (%" PRIuSIZE " bytes)\r\n", n);

      //Check the length of the selector
      if(n < sizeof(IkeTs) || n > length)
         break;

      //Dump Traffic Selector substructure
      ikeDumpTs(ts, n);

      //Jump to the next selector
      p += n;
      length -= n;
   }
}


/**
 * @brief Dump Traffic Selector substructure
 * @param[in] ts Pointer to the Traffic Selector substructure to dump
 * @param[in] length Length of the selector, in bytes
 **/

void ikeDumpTs(const IkeTs *ts, size_t length)
{
   size_t n;
   const char_t *tsTypeName;
   const char_t *ipProtocolIdName;

   //Check the length of the Traffic Selector substructure
   if(length < sizeof(IkeTs))
      return;

   //Convert the TS Type to string representation
   tsTypeName = ikeGetParamName(ts->tsType, ikeTsTypeList,
      arraysize(ikeTsTypeList));

   //Convert the IP Protocol ID to string representation
   ipProtocolIdName = ikeGetParamName(ts->ipProtocolId, ikeIpProtocolIdList,
      arraysize(ikeIpProtocolIdList));

   //Dump Traffic Selector substructure
   TRACE_DEBUG("      TS Type = %" PRIu8 " (%s)\r\n", ts->tsType,
      tsTypeName);

   TRACE_DEBUG("      IP Protocol ID = %" PRIu8 " (%s)\r\n",
      ts->ipProtocolId, ipProtocolIdName);

   TRACE_DEBUG("      Selector Length = %" PRIu16 "\r\n",
      ntohs(ts->selectorLength));

   TRACE_DEBUG("      Start Port = %" PRIu16 "\r\n", ntohs(ts->startPort));
   TRACE_DEBUG("      End Port = %" PRIu16 "\r\n", ntohs(ts->endPort));

   //The length of the Starting Address and Ending Address fields are
   //determined by the Traffic Selector type
   n = length - sizeof(IkeTs);

#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV4_ADDR_RANGE &&
      n == (2 * sizeof(Ipv4Addr)))
   {
      Ipv4Addr ipv4StartAddr;
      Ipv4Addr ipv4EndAddr;

      //Copy IPv4 addresses
      ipv4CopyAddr(&ipv4StartAddr, ts->startAddr);
      ipv4CopyAddr(&ipv4EndAddr, ts->startAddr + sizeof(Ipv4Addr));

      //Dump IPv4 address range
      TRACE_DEBUG("      Starting Address = %s\r\n",
         ipv4AddrToString(ipv4StartAddr, NULL));

      TRACE_DEBUG("      Ending Address = %s\r\n",
         ipv4AddrToString(ipv4EndAddr, NULL));
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(ts->tsType == IKE_TS_TYPE_IPV6_ADDR_RANGE &&
      length == (2 * sizeof(Ipv6Addr)))
   {
      Ipv6Addr ipv6StartAddr;
      Ipv6Addr ipv6EndAddr;

      //Copy IPv6 addresses
      ipv6CopyAddr(&ipv6StartAddr, ts->startAddr);
      ipv6CopyAddr(&ipv6EndAddr, ts->startAddr + sizeof(Ipv6Addr));

      //Dump IPv6 address range
      TRACE_DEBUG("      Starting Address = %s\r\n",
         ipv6AddrToString(&ipv6StartAddr, NULL));

      TRACE_DEBUG("      Ending Address = %s\r\n",
         ipv6AddrToString(&ipv6EndAddr, NULL));
   }
   else
#endif
   {
      //Just for sanity
   }
}


/**
 * @brief Dump Encrypted payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpEncryptedPayload(const IkeEncryptedPayload *payload, size_t length)
{
   size_t n;

   //Check the length of the payload
   if(length < sizeof(IkeEncryptedPayload))
      return;

   //The Payload Length field indicates the length of the encrypted data
   n = length - sizeof(IkeEncryptedPayload);

   //Dump encrypted data
   TRACE_DEBUG("    Encrypted Data (%" PRIuSIZE " bytes)\r\n", n);
   TRACE_DEBUG_ARRAY("      ", payload->iv, n);

}


/**
 * @brief Dump Encrypted Fragment payload
 * @param[in] payload Pointer to the payload to dump
 * @param[in] length Length of the payload, in bytes
 **/

void ikeDumpEncryptedFragPayload(const IkeEncryptedFragPayload *payload,
   size_t length)
{
   size_t n;

   //Check the length of the payload
   if(length < sizeof(IkeEncryptedFragPayload))
      return;

   //The Payload Length field indicates the length of the encrypted data
   n = length - sizeof(IkeEncryptedFragPayload);

   //The Fragment Number field specifies the current Fragment message number
   TRACE_DEBUG("      Fragment Number = %" PRIu16 "\r\n",
      ntohs(payload->fragNum));

   //The Total Fragments field specifies the number of Fragment messages into
   //which the original message was divided
   TRACE_DEBUG("      Total Fragments = %" PRIu16 "\r\n",
      ntohs(payload->totalFrags));

   //Dump encrypted data
   TRACE_DEBUG("    Encrypted Data (%" PRIuSIZE " bytes)\r\n", n);
   TRACE_DEBUG_ARRAY("      ", payload->iv, n);
}


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *ikeGetParamName(uint_t value, const IkeParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
         return paramList[i].name;
   }

   //Unknown value
   return defaultName;
}

#endif
