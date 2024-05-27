/**
 * @file ike.h
 * @brief IKEv2 (Internet Key Exchange Protocol)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.2
 **/

#ifndef _IKE_H
#define _IKE_H

//Dependencies
#include "ipsec/ipsec.h"
#include "cipher/cipher_algorithms.h"
#include "pkc/key_exch_algorithms.h"
#include "pkix/x509_common.h"

//IKEv2 support
#ifndef IKE_SUPPORT
   #define IKE_SUPPORT ENABLED
#elif (IKE_SUPPORT != ENABLED && IKE_SUPPORT != DISABLED)
   #error IKE_SUPPORT parameter is not valid
#endif

//Stack size required to run the IKE service
#ifndef IKE_STACK_SIZE
   #define IKE_STACK_SIZE 650
#elif (IKE_STACK_SIZE < 1)
   #error IKE_STACK_SIZE parameter is not valid
#endif

//Priority at which the IKE service should run
#ifndef IKE_PRIORITY
   #define IKE_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//IKE tick interval
#ifndef IKE_TICK_INTERVAL
   #define IKE_TICK_INTERVAL 500
#elif (IKE_TICK_INTERVAL < 100)
   #error IKE_TICK_INTERVAL parameter is not valid
#endif

//Default lifetime for IKE SAs
#ifndef IKE_DEFAULT_SA_LIFETIME
   #define IKE_DEFAULT_SA_LIFETIME 14400000
#elif (IKE_DEFAULT_SA_LIFETIME < 1000)
   #error IKE_DEFAULT_SA_LIFETIME parameter is not valid
#endif

//Default lifetime for Child SAs
#ifndef IKE_DEFAULT_CHILD_SA_LIFETIME
   #define IKE_DEFAULT_CHILD_SA_LIFETIME 3600000
#elif (IKE_DEFAULT_CHILD_SA_LIFETIME < 1000)
   #error IKE_DEFAULT_CHILD_SA_LIFETIME parameter is not valid
#endif

//Certificate authentication
#ifndef IKE_CERT_AUTH_SUPPORT
   #define IKE_CERT_AUTH_SUPPORT ENABLED
#elif (IKE_CERT_AUTH_SUPPORT != ENABLED && IKE_CERT_AUTH_SUPPORT != DISABLED)
   #error IKE_CERT_AUTH_SUPPORT parameter is not valid
#endif

//Pre-shared key authentication
#ifndef IKE_PSK_AUTH_SUPPORT
   #define IKE_PSK_AUTH_SUPPORT ENABLED
#elif (IKE_PSK_AUTH_SUPPORT != ENABLED && IKE_PSK_AUTH_SUPPORT != DISABLED)
   #error IKE_PSK_AUTH_SUPPORT parameter is not valid
#endif

//Cookie support
#ifndef IKE_COOKIE_SUPPORT
   #define IKE_COOKIE_SUPPORT DISABLED
#elif (IKE_COOKIE_SUPPORT != ENABLED && IKE_COOKIE_SUPPORT != DISABLED)
   #error IKE_COOKIE_SUPPORT parameter is not valid
#endif

//INITIAL_CONTACT notification support
#ifndef IKE_INITIAL_CONTACT_SUPPORT
   #define IKE_INITIAL_CONTACT_SUPPORT ENABLED
#elif (IKE_INITIAL_CONTACT_SUPPORT != ENABLED && IKE_INITIAL_CONTACT_SUPPORT != DISABLED)
   #error IKE_INITIAL_CONTACT_SUPPORT parameter is not valid
#endif

//SIGNATURE_HASH_ALGORITHMS notification support
#ifndef IKE_SIGN_HASH_ALGOS_SUPPORT
   #define IKE_SIGN_HASH_ALGOS_SUPPORT ENABLED
#elif (IKE_SIGN_HASH_ALGOS_SUPPORT != ENABLED && IKE_SIGN_HASH_ALGOS_SUPPORT != DISABLED)
   #error IKE_SIGN_HASH_ALGOS_SUPPORT parameter is not valid
#endif

//CREATE_CHILD_SA support
#ifndef IKE_CREATE_CHILD_SA_SUPPORT
   #define IKE_CREATE_CHILD_SA_SUPPORT ENABLED
#elif (IKE_CREATE_CHILD_SA_SUPPORT != ENABLED && IKE_CREATE_CHILD_SA_SUPPORT != DISABLED)
   #error IKE_CREATE_CHILD_SA_SUPPORT parameter is not valid
#endif

//Dead peer detection support
#ifndef IKE_DPD_SUPPORT
   #define IKE_DPD_SUPPORT ENABLED
#elif (IKE_DPD_SUPPORT != ENABLED && IKE_DPD_SUPPORT != DISABLED)
   #error IKE_DPD_SUPPORT parameter is not valid
#endif

//Maximum number of retransmissions of IKE requests
#ifndef IKE_MAX_RETRIES
   #define IKE_MAX_RETRIES 5
#elif (IKE_MAX_RETRIES < 1)
   #error IKE_MAX_RETRIES parameter is not valid
#endif

//Initial retransmission timeout
#ifndef IKE_INIT_TIMEOUT
   #define IKE_INIT_TIMEOUT 3000
#elif (IKE_INIT_TIMEOUT < 1000)
   #error IKE_INIT_TIMEOUT parameter is not valid
#endif

//Maximum retransmission timeout
#ifndef IKE_MAX_TIMEOUT
   #define IKE_MAX_TIMEOUT 60000
#elif (IKE_MAX_TIMEOUT < 1000)
   #error IKE_MAX_TIMEOUT parameter is not valid
#endif

//Timeout for half-open IKE SAs
#ifndef IKE_HALF_OPEN_TIMEOUT
   #define IKE_HALF_OPEN_TIMEOUT 30000
#elif (IKE_HALF_OPEN_TIMEOUT < 1000)
   #error IKE_HALF_OPEN_TIMEOUT parameter is not valid
#endif

//Maximum jitter in percent applied randomly to calculated timeouts
#ifndef IKE_RANDOM_JITTER
   #define IKE_RANDOM_JITTER 10
#elif (IKE_RANDOM_JITTER < 0 || IKE_RANDOM_JITTER > 100)
   #error IKE_RANDOM_JITTER parameter is not valid
#endif

//Maximum size of IKE messages
#ifndef IKE_MAX_MSG_SIZE
   #define IKE_MAX_MSG_SIZE 1452
#elif (IKE_MAX_MSG_SIZE < 1280)
   #error IKE_MAX_MSG_SIZE parameter is not valid
#endif

//Minimum size for cookies
#ifndef IKE_MIN_COOKIE_SIZE
   #define IKE_MIN_COOKIE_SIZE 1
#elif (IKE_MIN_COOKIE_SIZE < 1)
   #error IKE_MIN_COOKIE_SIZE parameter is not valid
#endif

//Maximum size for cookies
#ifndef IKE_MAX_COOKIE_SIZE
   #define IKE_MAX_COOKIE_SIZE 64
#elif (IKE_MAX_COOKIE_SIZE < 64)
   #error IKE_MAX_COOKIE_SIZE parameter is not valid
#endif

//Minimum size for nonce
#ifndef IKE_MIN_NONCE_SIZE
   #define IKE_MIN_NONCE_SIZE 16
#elif (IKE_MIN_NONCE_SIZE < 16 || IKE_MIN_NONCE_SIZE > 256)
   #error IKE_MIN_NONCE_SIZE parameter is not valid
#endif

//Default size for nonce
#ifndef IKE_DEFAULT_NONCE_SIZE
   #define IKE_DEFAULT_NONCE_SIZE 32
#elif (IKE_DEFAULT_NONCE_SIZE < 16 || IKE_DEFAULT_NONCE_SIZE > 256)
   #error IKE_DEFAULT_NONCE_SIZE parameter is not valid
#endif

//Maximum size for nonce
#ifndef IKE_MAX_NONCE_SIZE
   #define IKE_MAX_NONCE_SIZE 64
#elif (IKE_MAX_NONCE_SIZE < 16 || IKE_MAX_NONCE_SIZE > 256)
   #error IKE_MAX_NONCE_SIZE parameter is not valid
#endif

//Maximum length of ID
#ifndef IKE_MAX_ID_LEN
   #define IKE_MAX_ID_LEN 64
#elif (IKE_MAX_ID_LEN < 0)
   #error IKE_MAX_ID_LEN is not valid
#endif

//Maximum length of pre-shared keys
#ifndef IKE_MAX_PSK_LEN
   #define IKE_MAX_PSK_LEN 64
#elif (IKE_MAX_PSK_LEN < 0)
   #error IKE_MAX_PSK_LEN is not valid
#endif

//Maximum length of password
#ifndef IKE_MAX_PASSWORD_LEN
   #define IKE_MAX_PASSWORD_LEN 32
#elif (IKE_MAX_PASSWORD_LEN < 0)
   #error IKE_MAX_PASSWORD_LEN parameter is not valid
#endif

//CBC cipher mode support
#ifndef IKE_CBC_SUPPORT
   #define IKE_CBC_SUPPORT ENABLED
#elif (IKE_CBC_SUPPORT != ENABLED && IKE_CBC_SUPPORT != DISABLED)
   #error IKE_CBC_SUPPORT parameter is not valid
#endif

//CTR cipher mode support
#ifndef IKE_CTR_SUPPORT
   #define IKE_CTR_SUPPORT DISABLED
#elif (IKE_CTR_SUPPORT != ENABLED && IKE_CTR_SUPPORT != DISABLED)
   #error IKE_CTR_SUPPORT parameter is not valid
#endif

//CCM_8 AEAD support
#ifndef IKE_CCM_8_SUPPORT
   #define IKE_CCM_8_SUPPORT DISABLED
#elif (IKE_CCM_8_SUPPORT != ENABLED && IKE_CCM_8_SUPPORT != DISABLED)
   #error IKE_CCM_8_SUPPORT parameter is not valid
#endif

//CCM_12 AEAD support
#ifndef IKE_CCM_12_SUPPORT
   #define IKE_CCM_12_SUPPORT DISABLED
#elif (IKE_CCM_12_SUPPORT != ENABLED && IKE_CCM_12_SUPPORT != DISABLED)
   #error IKE_CCM_12_SUPPORT parameter is not valid
#endif

//CCM_16 AEAD support
#ifndef IKE_CCM_16_SUPPORT
   #define IKE_CCM_16_SUPPORT DISABLED
#elif (IKE_CCM_16_SUPPORT != ENABLED && IKE_CCM_16_SUPPORT != DISABLED)
   #error IKE_CCM_16_SUPPORT parameter is not valid
#endif

//GCM_8 AEAD support
#ifndef IKE_GCM_8_SUPPORT
   #define IKE_GCM_8_SUPPORT DISABLED
#elif (IKE_GCM_8_SUPPORT != ENABLED && IKE_GCM_8_SUPPORT != DISABLED)
   #error IKE_GCM_8_SUPPORT parameter is not valid
#endif

//GCM_12 AEAD support
#ifndef IKE_GCM_12_SUPPORT
   #define IKE_GCM_12_SUPPORT DISABLED
#elif (IKE_GCM_12_SUPPORT != ENABLED && IKE_GCM_12_SUPPORT != DISABLED)
   #error IKE_GCM_12_SUPPORT parameter is not valid
#endif

//GCM_16 AEAD support
#ifndef IKE_GCM_16_SUPPORT
   #define IKE_GCM_16_SUPPORT ENABLED
#elif (IKE_GCM_16_SUPPORT != ENABLED && IKE_GCM_16_SUPPORT != DISABLED)
   #error IKE_GCM_16_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 AEAD support
#ifndef IKE_CHACHA20_POLY1305_SUPPORT
   #define IKE_CHACHA20_POLY1305_SUPPORT ENABLED
#elif (IKE_CHACHA20_POLY1305_SUPPORT != ENABLED && IKE_CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error IKE_CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//CMAC integrity support
#ifndef IKE_CMAC_AUTH_SUPPORT
   #define IKE_CMAC_AUTH_SUPPORT DISABLED
#elif (IKE_CMAC_AUTH_SUPPORT != ENABLED && IKE_CMAC_AUTH_SUPPORT != DISABLED)
   #error IKE_CMAC_AUTH_SUPPORT parameter is not valid
#endif

//HMAC integrity support
#ifndef IKE_HMAC_AUTH_SUPPORT
   #define IKE_HMAC_AUTH_SUPPORT ENABLED
#elif (IKE_HMAC_AUTH_SUPPORT != ENABLED && IKE_HMAC_AUTH_SUPPORT != DISABLED)
   #error IKE_HMAC_AUTH_SUPPORT parameter is not valid
#endif

//XCBC-MAC integrity support
#ifndef IKE_XCBC_MAC_AUTH_SUPPORT
   #define IKE_XCBC_MAC_AUTH_SUPPORT DISABLED
#elif (IKE_XCBC_MAC_AUTH_SUPPORT != ENABLED && IKE_XCBC_MAC_AUTH_SUPPORT != DISABLED)
   #error IKE_XCBC_MAC_AUTH_SUPPORT parameter is not valid
#endif

//CMAC PRF support
#ifndef IKE_CMAC_PRF_SUPPORT
   #define IKE_CMAC_PRF_SUPPORT DISABLED
#elif (IKE_CMAC_PRF_SUPPORT != ENABLED && IKE_CMAC_PRF_SUPPORT != DISABLED)
   #error IKE_CMAC_PRF_SUPPORT parameter is not valid
#endif

//HMAC PRF support
#ifndef IKE_HMAC_PRF_SUPPORT
   #define IKE_HMAC_PRF_SUPPORT ENABLED
#elif (IKE_HMAC_PRF_SUPPORT != ENABLED && IKE_HMAC_PRF_SUPPORT != DISABLED)
   #error IKE_HMAC_PRF_SUPPORT parameter is not valid
#endif

//XCBC-MAC PRF support
#ifndef IKE_XCBC_MAC_PRF_SUPPORT
   #define IKE_XCBC_MAC_PRF_SUPPORT DISABLED
#elif (IKE_XCBC_MAC_PRF_SUPPORT != ENABLED && IKE_XCBC_MAC_PRF_SUPPORT != DISABLED)
   #error IKE_XCBC_MAC_PRF_SUPPORT parameter is not valid
#endif

//IDEA cipher support (insecure)
#ifndef IKE_IDEA_SUPPORT
   #define IKE_IDEA_SUPPORT DISABLED
#elif (IKE_IDEA_SUPPORT != ENABLED && IKE_IDEA_SUPPORT != DISABLED)
   #error IKE_IDEA_SUPPORT parameter is not valid
#endif

//DES cipher support (insecure)
#ifndef IKE_DES_SUPPORT
   #define IKE_DES_SUPPORT DISABLED
#elif (IKE_DES_SUPPORT != ENABLED && IKE_DES_SUPPORT != DISABLED)
   #error IKE_DES_SUPPORT parameter is not valid
#endif

//Triple DES cipher support (weak)
#ifndef IKE_3DES_SUPPORT
   #define IKE_3DES_SUPPORT DISABLED
#elif (IKE_3DES_SUPPORT != ENABLED && IKE_3DES_SUPPORT != DISABLED)
   #error IKE_3DES_SUPPORT parameter is not valid
#endif

//AES 128-bit cipher support
#ifndef IKE_AES_128_SUPPORT
   #define IKE_AES_128_SUPPORT ENABLED
#elif (IKE_AES_128_SUPPORT != ENABLED && IKE_AES_128_SUPPORT != DISABLED)
   #error IKE_AES_128_SUPPORT parameter is not valid
#endif

//AES 192-bit cipher support
#ifndef IKE_AES_192_SUPPORT
   #define IKE_AES_192_SUPPORT ENABLED
#elif (IKE_AES_192_SUPPORT != ENABLED && IKE_AES_192_SUPPORT != DISABLED)
   #error IKE_AES_192_SUPPORT parameter is not valid
#endif

//AES 256-bit cipher support
#ifndef IKE_AES_256_SUPPORT
   #define IKE_AES_256_SUPPORT ENABLED
#elif (IKE_AES_256_SUPPORT != ENABLED && IKE_AES_256_SUPPORT != DISABLED)
   #error IKE_AES_256_SUPPORT parameter is not valid
#endif

//Camellia 128-bit cipher support
#ifndef IKE_CAMELLIA_128_SUPPORT
   #define IKE_CAMELLIA_128_SUPPORT DISABLED
#elif (IKE_CAMELLIA_128_SUPPORT != ENABLED && IKE_CAMELLIA_128_SUPPORT != DISABLED)
   #error IKE_CAMELLIA_128_SUPPORT parameter is not valid
#endif

//Camellia 192-bit cipher support
#ifndef IKE_CAMELLIA_192_SUPPORT
   #define IKE_CAMELLIA_192_SUPPORT DISABLED
#elif (IKE_CAMELLIA_192_SUPPORT != ENABLED && IKE_CAMELLIA_192_SUPPORT != DISABLED)
   #error IKE_CAMELLIA_192_SUPPORT parameter is not valid
#endif

//Camellia 256-bit cipher support
#ifndef IKE_CAMELLIA_256_SUPPORT
   #define IKE_CAMELLIA_256_SUPPORT DISABLED
#elif (IKE_CAMELLIA_256_SUPPORT != ENABLED && IKE_CAMELLIA_256_SUPPORT != DISABLED)
   #error IKE_CAMELLIA_256_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef IKE_MD5_SUPPORT
   #define IKE_MD5_SUPPORT DISABLED
#elif (IKE_MD5_SUPPORT != ENABLED && IKE_MD5_SUPPORT != DISABLED)
   #error IKE_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef IKE_SHA1_SUPPORT
   #define IKE_SHA1_SUPPORT ENABLED
#elif (IKE_SHA1_SUPPORT != ENABLED && IKE_SHA1_SUPPORT != DISABLED)
   #error IKE_SHA1_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef IKE_SHA256_SUPPORT
   #define IKE_SHA256_SUPPORT ENABLED
#elif (IKE_SHA256_SUPPORT != ENABLED && IKE_SHA256_SUPPORT != DISABLED)
   #error IKE_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef IKE_SHA384_SUPPORT
   #define IKE_SHA384_SUPPORT ENABLED
#elif (IKE_SHA384_SUPPORT != ENABLED && IKE_SHA384_SUPPORT != DISABLED)
   #error IKE_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef IKE_SHA512_SUPPORT
   #define IKE_SHA512_SUPPORT ENABLED
#elif (IKE_SHA512_SUPPORT != ENABLED && IKE_SHA512_SUPPORT != DISABLED)
   #error IKE_SHA512_SUPPORT parameter is not valid
#endif

//Tiger hash support
#ifndef IKE_TIGER_SUPPORT
   #define IKE_TIGER_SUPPORT DISABLED
#elif (IKE_TIGER_SUPPORT != ENABLED && IKE_TIGER_SUPPORT != DISABLED)
   #error IKE_TIGER_SUPPORT parameter is not valid
#endif

//Diffie-Hellman key exchange support
#ifndef IKE_DH_KE_SUPPORT
   #define IKE_DH_KE_SUPPORT ENABLED
#elif (IKE_DH_KE_SUPPORT != ENABLED && IKE_DH_KE_SUPPORT != DISABLED)
   #error IKE_DH_KE_SUPPORT parameter is not valid
#endif

//ECDH key exchange support
#ifndef IKE_ECDH_KE_SUPPORT
   #define IKE_ECDH_KE_SUPPORT ENABLED
#elif (IKE_ECDH_KE_SUPPORT != ENABLED && IKE_ECDH_KE_SUPPORT != DISABLED)
   #error IKE_ECDH_KE_SUPPORT parameter is not valid
#endif

//RSA signature support
#ifndef IKE_RSA_SIGN_SUPPORT
   #define IKE_RSA_SIGN_SUPPORT ENABLED
#elif (IKE_RSA_SIGN_SUPPORT != ENABLED && IKE_RSA_SIGN_SUPPORT != DISABLED)
   #error IKE_RSA_SIGN_SUPPORT parameter is not valid
#endif

//RSA-PSS signature support
#ifndef IKE_RSA_PSS_SIGN_SUPPORT
   #define IKE_RSA_PSS_SIGN_SUPPORT DISABLED
#elif (IKE_RSA_PSS_SIGN_SUPPORT != ENABLED && IKE_RSA_PSS_SIGN_SUPPORT != DISABLED)
   #error IKE_RSA_PSS_SIGN_SUPPORT parameter is not valid
#endif

//DSA signature support
#ifndef IKE_DSA_SIGN_SUPPORT
   #define IKE_DSA_SIGN_SUPPORT DISABLED
#elif (IKE_DSA_SIGN_SUPPORT != ENABLED && IKE_DSA_SIGN_SUPPORT != DISABLED)
   #error IKE_DSA_SIGN_SUPPORT parameter is not valid
#endif

//ECDSA signature support
#ifndef IKE_ECDSA_SIGN_SUPPORT
   #define IKE_ECDSA_SIGN_SUPPORT ENABLED
#elif (IKE_ECDSA_SIGN_SUPPORT != ENABLED && IKE_ECDSA_SIGN_SUPPORT != DISABLED)
   #error IKE_ECDSA_SIGN_SUPPORT parameter is not valid
#endif

//Ed25519 signature support
#ifndef IKE_ED25519_SIGN_SUPPORT
   #define IKE_ED25519_SIGN_SUPPORT ENABLED
#elif (IKE_ED25519_SIGN_SUPPORT != ENABLED && IKE_ED25519_SIGN_SUPPORT != DISABLED)
   #error IKE_ED25519_SIGN_SUPPORT parameter is not valid
#endif

//Ed448 signature support
#ifndef IKE_ED448_SIGN_SUPPORT
   #define IKE_ED448_SIGN_SUPPORT DISABLED
#elif (IKE_ED448_SIGN_SUPPORT != ENABLED && IKE_ED448_SIGN_SUPPORT != DISABLED)
   #error IKE_ED448_SIGN_SUPPORT parameter is not valid
#endif

//NIST P-192 elliptic curve support (weak)
#ifndef IKE_ECP_192_SUPPORT
   #define IKE_ECP_192_SUPPORT DISABLED
#elif (IKE_ECP_192_SUPPORT != ENABLED && IKE_ECP_192_SUPPORT != DISABLED)
   #error IKE_ECP_192_SUPPORT parameter is not valid
#endif

//NIST P-224 elliptic curve support
#ifndef IKE_ECP_224_SUPPORT
   #define IKE_ECP_224_SUPPORT DISABLED
#elif (IKE_ECP_224_SUPPORT != ENABLED && IKE_ECP_224_SUPPORT != DISABLED)
   #error IKE_ECP_224_SUPPORT parameter is not valid
#endif

//NIST P-256 elliptic curve support
#ifndef IKE_ECP_256_SUPPORT
   #define IKE_ECP_256_SUPPORT ENABLED
#elif (IKE_ECP_256_SUPPORT != ENABLED && IKE_ECP_256_SUPPORT != DISABLED)
   #error IKE_ECP_256_SUPPORT parameter is not valid
#endif

//NIST P-384 elliptic curve support
#ifndef IKE_ECP_384_SUPPORT
   #define IKE_ECP_384_SUPPORT ENABLED
#elif (IKE_ECP_384_SUPPORT != ENABLED && IKE_ECP_384_SUPPORT != DISABLED)
   #error IKE_ECP_384_SUPPORT parameter is not valid
#endif

//NIST P-521 elliptic curve support
#ifndef IKE_ECP_521_SUPPORT
   #define IKE_ECP_521_SUPPORT DISABLED
#elif (IKE_ECP_521_SUPPORT != ENABLED && IKE_ECP_521_SUPPORT != DISABLED)
   #error IKE_ECP_521_SUPPORT parameter is not valid
#endif

//brainpoolP224r1 elliptic curve support
#ifndef IKE_BRAINPOOLP224R1_SUPPORT
   #define IKE_BRAINPOOLP224R1_SUPPORT DISABLED
#elif (IKE_BRAINPOOLP224R1_SUPPORT != ENABLED && IKE_BRAINPOOLP224R1_SUPPORT != DISABLED)
   #error IKE_BRAINPOOLP224R1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef IKE_BRAINPOOLP256R1_SUPPORT
   #define IKE_BRAINPOOLP256R1_SUPPORT DISABLED
#elif (IKE_BRAINPOOLP256R1_SUPPORT != ENABLED && IKE_BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error IKE_BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef IKE_BRAINPOOLP384R1_SUPPORT
   #define IKE_BRAINPOOLP384R1_SUPPORT DISABLED
#elif (IKE_BRAINPOOLP384R1_SUPPORT != ENABLED && IKE_BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error IKE_BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef IKE_BRAINPOOLP512R1_SUPPORT
   #define IKE_BRAINPOOLP512R1_SUPPORT DISABLED
#elif (IKE_BRAINPOOLP512R1_SUPPORT != ENABLED && IKE_BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error IKE_BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//Curve25519 elliptic curve support
#ifndef IKE_CURVE25519_SUPPORT
   #define IKE_CURVE25519_SUPPORT ENABLED
#elif (IKE_CURVE25519_SUPPORT != ENABLED && IKE_CURVE25519_SUPPORT != DISABLED)
   #error IKE_CURVE25519_SUPPORT parameter is not valid
#endif

//Curve448 elliptic curve support
#ifndef IKE_CURVE448_SUPPORT
   #define IKE_CURVE448_SUPPORT DISABLED
#elif (IKE_CURVE448_SUPPORT != ENABLED && IKE_CURVE448_SUPPORT != DISABLED)
   #error IKE_CURVE448_SUPPORT parameter is not valid
#endif

//Minimum acceptable size for Diffie-Hellman prime modulus
#ifndef IKE_MIN_DH_MODULUS_SIZE
   #define IKE_MIN_DH_MODULUS_SIZE 1024
#elif (IKE_MIN_DH_MODULUS_SIZE < 768)
   #error IKE_MIN_DH_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for Diffie-Hellman prime modulus
#ifndef IKE_MAX_DH_MODULUS_SIZE
   #define IKE_MAX_DH_MODULUS_SIZE 2048
#elif (IKE_MAX_DH_MODULUS_SIZE < IKE_PREFERRED_DH_MODULUS_SIZE)
   #error IKE_MAX_DH_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef IKE_MIN_RSA_MODULUS_SIZE
   #define IKE_MIN_RSA_MODULUS_SIZE 1024
#elif (IKE_MIN_RSA_MODULUS_SIZE < 512)
   #error IKE_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef IKE_MAX_RSA_MODULUS_SIZE
   #define IKE_MAX_RSA_MODULUS_SIZE 4096
#elif (IKE_MAX_RSA_MODULUS_SIZE < IKE_MIN_RSA_MODULUS_SIZE)
   #error IKE_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef IKE_MIN_DSA_MODULUS_SIZE
   #define IKE_MIN_DSA_MODULUS_SIZE 1024
#elif (IKE_MIN_DSA_MODULUS_SIZE < 512)
   #error IKE_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef IKE_MAX_DSA_MODULUS_SIZE
   #define IKE_MAX_DSA_MODULUS_SIZE 4096
#elif (IKE_MAX_DSA_MODULUS_SIZE < IKE_MIN_DSA_MODULUS_SIZE)
   #error IKE_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum length of IKE SA key material
#ifndef IKE_MAX_SA_KEY_MAT_LEN
   #define IKE_MAX_SA_KEY_MAT_LEN 392
#elif (IKE_MAX_SA_KEY_MAT_LEN < 1)
   #error IKE_MAX_SA_KEY_MAT_LEN parameter is not valid
#endif

//Maximum length of Child SA key material
#ifndef IKE_MAX_CHILD_SA_KEY_MAT_LEN
   #define IKE_MAX_CHILD_SA_KEY_MAT_LEN 200
#elif (IKE_MAX_CHILD_SA_KEY_MAT_LEN < 1)
   #error IKE_MAX_CHILD_SA_KEY_MAT_LEN parameter is not valid
#endif

//Allocate memory block
#ifndef ikeAllocMem
   #define ikeAllocMem(size) osAllocMem(size)
#endif

//Deallocate memory block
#ifndef ikeFreeMem
   #define ikeFreeMem(p) osFreeMem(p)
#endif

//Maximum shared secret length (Diffie-Hellman key exchange)
#if (IKE_DH_KE_SUPPORT == ENABLED)
   #define IKE_MAX_DH_SHARED_SECRET_LEN ((IKE_MAX_DH_MODULUS_SIZE + 7) / 8)
#else
   #define IKE_MAX_DH_SHARED_SECRET_LEN 0
#endif

//Maximum shared secret length (ECDH key exchange)
#if (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_521_SUPPORT == ENABLED)
   #define IKE_MAX_ECDH_SHARED_SECRET_LEN 66
#elif (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_CURVE448_SUPPORT == ENABLED)
   #define IKE_MAX_ECDH_SHARED_SECRET_LEN 56
#elif (IKE_ECDH_KE_SUPPORT == ENABLED && IKE_ECP_384_SUPPORT == ENABLED)
   #define IKE_MAX_ECDH_SHARED_SECRET_LEN 48
#else
   #define IKE_MAX_ECDH_SHARED_SECRET_LEN 32
#endif

//Maximum shared secret length
#if (IKE_MAX_DH_SHARED_SECRET_LEN >= IKE_MAX_ECDH_SHARED_SECRET_LEN)
   #define IKE_MAX_SHARED_SECRET_LEN IKE_MAX_DH_SHARED_SECRET_LEN
#else
   #define IKE_MAX_SHARED_SECRET_LEN IKE_MAX_ECDH_SHARED_SECRET_LEN
#endif

//Major version of the IKE protocol
#define IKE_MAJOR_VERSION 2
//Minor version of the IKE protocol
#define IKE_MINOR_VERSION 0

//UDP port number used by IKE
#define IKE_PORT 500
//UDP port number used by UDP-encapsulated IKE
#define IKE_ALT_PORT 4500

//Size of IKE SPI
#define IKE_SPI_SIZE 8
//Size of SHA-1 digest
#define IKE_SHA1_DIGEST_SIZE 20

//Forward declaration of IkeContext structure
struct _IkeContext;
#define IkeContext struct _IkeContext

//Forward declaration of IkeSaEntry structure
struct _IkeSaEntry;
#define IkeSaEntry struct _IkeSaEntry

//Forward declaration of IkeChildSaEntry structure
struct _IkeChildSaEntry;
#define IkeChildSaEntry struct _IkeChildSaEntry

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Exchange types
 **/

typedef enum
{
   IKE_EXCHANGE_TYPE_IKE_SA_INIT        = 34, ///<IKE_SA_INIT
   IKE_EXCHANGE_TYPE_IKE_AUTH           = 35, ///<IKE_AUTH
   IKE_EXCHANGE_TYPE_CREATE_CHILD_SA    = 36, ///<CREATE_CHILD_SA
   IKE_EXCHANGE_TYPE_INFORMATIONAL      = 37, ///<INFORMATIONAL
   IKE_EXCHANGE_TYPE_IKE_SESSION_RESUME = 38, ///<IKE_SESSION_RESUME
   IKE_EXCHANGE_TYPE_IKE_INTERMEDIATE   = 43  ///<IKE_INTERMEDIATE
} IkeExchangeType;


/**
 * @brief Flags
 **/

typedef enum
{
   IKE_FLAGS_R = 0x20, ///<Response flag
   IKE_FLAGS_V = 0x10, ///<Version flag
   IKE_FLAGS_I = 0x08  ///<Initiator flag
} IkeFlags;


/**
 * @brief Payload types
 **/

typedef enum
{
   IKE_PAYLOAD_TYPE_LAST    = 0,  ///<No Next Payload
   IKE_PAYLOAD_TYPE_SA      = 33, ///<Security Association
   IKE_PAYLOAD_TYPE_KE      = 34, ///<Key Exchange
   IKE_PAYLOAD_TYPE_IDI     = 35, ///<Identification - Initiator
   IKE_PAYLOAD_TYPE_IDR     = 36, ///<Identification - Responder
   IKE_PAYLOAD_TYPE_CERT    = 37, ///<Certificate
   IKE_PAYLOAD_TYPE_CERTREQ = 38, ///<Certificate Request
   IKE_PAYLOAD_TYPE_AUTH    = 39, ///<Authentication
   IKE_PAYLOAD_TYPE_NONCE   = 40, ///<Nonce
   IKE_PAYLOAD_TYPE_N       = 41, ///<Notify
   IKE_PAYLOAD_TYPE_D       = 42, ///<Delete
   IKE_PAYLOAD_TYPE_V       = 43, ///<Vendor ID
   IKE_PAYLOAD_TYPE_TSI     = 44, ///<Traffic Selector - Initiator
   IKE_PAYLOAD_TYPE_TSR     = 45, ///<Traffic Selector - Responder
   IKE_PAYLOAD_TYPE_SK      = 46, ///<Encrypted and Authenticated
   IKE_PAYLOAD_TYPE_CP      = 47, ///<Configuration
   IKE_PAYLOAD_TYPE_EAP     = 48, ///<Extensible Authentication
   IKE_PAYLOAD_TYPE_GSPM    = 49, ///<Generic Secure Password Method
   IKE_PAYLOAD_TYPE_SKF     = 53, ///<Encrypted and Authenticated Fragment
   IKE_PAYLOAD_TYPE_PS      = 54  ///<Puzzle Solution
} IkePayloadType;


/**
 * @brief Last Substruc values
 **/

typedef enum
{
   IKE_LAST_SUBSTRUC_LAST            = 0, ///<Last proposal/transform substructure
   IKE_LAST_SUBSTRUC_MORE_PROPOSALS  = 2, ///<More proposal substructures
   IKE_LAST_SUBSTRUC_MORE_TRANSFORMS = 3  ///<More transform substructures
} IkeLastSubstruc;


/**
 * @brief Protocol IDs
 **/

typedef enum
{
   IKE_PROTOCOL_ID_IKE = 1, ///<IKE protocol
   IKE_PROTOCOL_ID_AH  = 2, ///<AH protocol
   IKE_PROTOCOL_ID_ESP = 3  ///<ESP protocol
} IkeProtocolId;


/**
 * @brief Transform types
 **/

typedef enum
{
   IKE_TRANSFORM_TYPE_ENCR  = 1, ///<Encryption Algorithm
   IKE_TRANSFORM_TYPE_PRF   = 2, ///<Pseudorandom Function
   IKE_TRANSFORM_TYPE_INTEG = 3, ///<Integrity Algorithm
   IKE_TRANSFORM_TYPE_DH    = 4, ///<Diffie-Hellman Group
   IKE_TRANSFORM_TYPE_ESN   = 5  ///<Extended Sequence Numbers
} IkeTransformType;


/**
 * @brief Transform IDs (Encryption Algorithm)
 **/

typedef enum
{
   IKE_TRANSFORM_ID_ENCR_RESERVED                 = 0,
   IKE_TRANSFORM_ID_ENCR_DES_IV64                 = 1,
   IKE_TRANSFORM_ID_ENCR_DES                      = 2,
   IKE_TRANSFORM_ID_ENCR_3DES                     = 3,
   IKE_TRANSFORM_ID_ENCR_RC5                      = 4,
   IKE_TRANSFORM_ID_ENCR_IDEA                     = 5,
   IKE_TRANSFORM_ID_ENCR_CAST                     = 6,
   IKE_TRANSFORM_ID_ENCR_BLOWFISH                 = 7,
   IKE_TRANSFORM_ID_ENCR_3IDEA                    = 8,
   IKE_TRANSFORM_ID_ENCR_DES_IV32                 = 9,
   IKE_TRANSFORM_ID_ENCR_NULL                     = 11,
   IKE_TRANSFORM_ID_ENCR_AES_CBC                  = 12,
   IKE_TRANSFORM_ID_ENCR_AES_CTR                  = 13,
   IKE_TRANSFORM_ID_ENCR_AES_CCM_8                = 14,
   IKE_TRANSFORM_ID_ENCR_AES_CCM_12               = 15,
   IKE_TRANSFORM_ID_ENCR_AES_CCM_16               = 16,
   IKE_TRANSFORM_ID_ENCR_AES_GCM_8                = 18,
   IKE_TRANSFORM_ID_ENCR_AES_GCM_12               = 19,
   IKE_TRANSFORM_ID_ENCR_AES_GCM_16               = 20,
   IKE_TRANSFORM_ID_ENCR_NULL_AUTH_AES_GMAC       = 21,
   IKE_TRANSFORM_ID_ENCR_CAMELLIA_CBC             = 23,
   IKE_TRANSFORM_ID_ENCR_CAMELLIA_CTR             = 24,
   IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_8           = 25,
   IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_12          = 26,
   IKE_TRANSFORM_ID_ENCR_CAMELLIA_CCM_16          = 27,
   IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305        = 28,
   IKE_TRANSFORM_ID_ENCR_AES_CCM_8_IIV            = 29,
   IKE_TRANSFORM_ID_ENCR_AES_GCM_16_IIV           = 30,
   IKE_TRANSFORM_ID_ENCR_CHACHA20_POLY1305_IIV    = 31,
   IKE_TRANSFORM_ID_ENCR_KUZNYECHIK_MGM_KTREE     = 32,
   IKE_TRANSFORM_ID_ENCR_MAGMA_MGM_KTREE          = 33,
   IKE_TRANSFORM_ID_ENCR_KUZNYECHIK_MGM_MAC_KTREE = 34,
   IKE_TRANSFORM_ID_ENCR_MAGMA_MGM_MAC_KTREE      = 35
} IkeTransformIdEncr;


/**
 * @brief Transform IDs (Pseudorandom Function)
 **/

typedef enum
{
   IKE_TRANSFORM_ID_PRF_RESERVED          = 0,
   IKE_TRANSFORM_ID_PRF_HMAC_MD5          = 1,
   IKE_TRANSFORM_ID_PRF_HMAC_SHA1         = 2,
   IKE_TRANSFORM_ID_PRF_HMAC_TIGER        = 3,
   IKE_TRANSFORM_ID_PRF_AES128_XCBC       = 4,
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256     = 5,
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384     = 6,
   IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512     = 7,
   IKE_TRANSFORM_ID_PRF_AES128_CMAC       = 8,
   IKE_TRANSFORM_ID_PRF_HMAC_STREEBOG_512 = 9
} IkeTransformIdPrf;


/**
 * @brief Transform IDs (Integrity Algorithm)
 **/

typedef enum
{
   IKE_TRANSFORM_ID_AUTH_NONE              = 0,
   IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96       = 1,
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96      = 2,
   IKE_TRANSFORM_ID_AUTH_DES_MAC           = 3,
   IKE_TRANSFORM_ID_AUTH_KPDK_MD5          = 4,
   IKE_TRANSFORM_ID_AUTH_AES_XCBC_96       = 5,
   IKE_TRANSFORM_ID_AUTH_HMAC_MD5_128      = 6,
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_160     = 7,
   IKE_TRANSFORM_ID_AUTH_AES_CMAC_96       = 8,
   IKE_TRANSFORM_ID_AUTH_AES_128_GMAC      = 9,
   IKE_TRANSFORM_ID_AUTH_AES_192_GMAC      = 10,
   IKE_TRANSFORM_ID_AUTH_AES_256_GMAC      = 11,
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128 = 12,
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192 = 13,
   IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256 = 14
} IkeTransformIdAuth;


/**
 * @brief Transform IDs (Diffie-Hellman Group)
 **/

typedef enum
{
   IKE_TRANSFORM_ID_DH_GROUP_NONE              = 0,  ///<None
   IKE_TRANSFORM_ID_DH_GROUP_MODP_768          = 1,  ///<768-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_1024         = 2,  ///<1024-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_1536         = 5,  ///<1536-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_2048         = 14, ///<2048-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_3072         = 15, ///<3072-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_4096         = 16, ///<4096-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_6144         = 17, ///<6144-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_8192         = 18, ///<8192-bit MODP Group
   IKE_TRANSFORM_ID_DH_GROUP_ECP_256           = 19, ///<256-bit Random ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_ECP_384           = 20, ///<384-bit Random ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_ECP_521           = 21, ///<521-bit Random ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_MODP_1024_160     = 22, ///<1024-bit MODP Group with 160-bit Prime Order Subgroup
   IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_224     = 23, ///<2048-bit MODP Group with 224-bit Prime Order Subgroup
   IKE_TRANSFORM_ID_DH_GROUP_MODP_2048_256     = 24, ///<2048-bit MODP Group with 256-bit Prime Order Subgroup
   IKE_TRANSFORM_ID_DH_GROUP_ECP_192           = 25, ///<192-bit Random ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_ECP_224           = 26, ///<224-bit Random ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP224R1   = 27, ///<224-bit Brainpool ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP256R1   = 28, ///<256-bit Brainpool ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP384R1   = 29, ///<384-bit Brainpool ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_BRAINPOOLP512R1   = 30, ///<512-bit Brainpool ECP Group
   IKE_TRANSFORM_ID_DH_GROUP_CURVE25519        = 31, ///<Curve25519
   IKE_TRANSFORM_ID_DH_GROUP_CURVE448          = 32, ///<Curve448
   IKE_TRANSFORM_ID_DH_GROUP_GOST3410_2012_256 = 32, ///<GOST3410_2012_256
   IKE_TRANSFORM_ID_DH_GROUP_GOST3410_2012_512 = 32  ///<GOST3410_2012_512
} IkeTransformIdDhGroup;


/**
 * @brief Transform IDs (Extended Sequence Numbers)
 **/

typedef enum
{
   IKE_TRANSFORM_ID_ESN_NO      = 0, ///<No Extended Sequence Numbers
   IKE_TRANSFORM_ID_ESN_YES     = 1  ///<Extended Sequence Numbers
} IkeTransformIdEsn;


/**
 * @brief Transform attribute format
 **/

typedef enum
{
   IKE_ATTR_FORMAT_TLV = 0x0000, ///<Type/Length/Value format
   IKE_ATTR_FORMAT_TV  = 0x8000  ///<shortened Type/Value format
} IkeTransformAttrFormat;


/**
 * @brief Transform attribute types
 **/

typedef enum
{
   IKE_TRANSFORM_ATTR_TYPE_KEY_LEN = 14 ///<Key Length (in bits)
} IkeTransformAttrType;


/**
 * @brief ID types
 **/

typedef enum
{
   IKE_ID_TYPE_INVALID     = 0,
   IKE_ID_TYPE_IPV4_ADDR   = 1,
   IKE_ID_TYPE_FQDN        = 2,
   IKE_ID_TYPE_RFC822_ADDR = 3,
   IKE_ID_TYPE_IPV6_ADDR   = 5,
   IKE_ID_TYPE_DER_ASN1_DN = 9,
   IKE_ID_TYPE_DER_ASN1_GN = 10,
   IKE_ID_TYPE_KEY_ID      = 11,
   IKE_ID_TYPE_FC_NAME     = 12,
   IKE_ID_TYPE_NULL        = 13
} IkeIdType;


/**
 * @brief Certificate encodings
 **/

typedef enum
{
   IKE_CERT_ENCODING_PKCS7_X509_CERT      = 1,  ///<PKCS #7 wrapped X.509 certificate
   IKE_CERT_ENCODING_PGP_CERT             = 2,  ///<PGP certificate
   IKE_CERT_ENCODING_DNS_SIGNED_KEY       = 3,  ///<DNS signed key
   IKE_CERT_ENCODING_X509_CERT_SIGN       = 4,  ///<X.509 certificate - signature
   IKE_CERT_ENCODING_KERBEROS_TOKEN       = 6,  ///<Kerberos token
   IKE_CERT_ENCODING_CRL                  = 7,  ///<Certificate revocation list
   IKE_CERT_ENCODING_ARL                  = 8,  ///<Authority revocation list
   IKE_CERT_ENCODING_SPKI_CERT            = 9,  ///<SPKI certificate
   IKE_CERT_ENCODING_X509_CERT_ATTR       = 10, ///<X.509 certificate - attribute
   IKE_CERT_ENCODING_RAW_RSA_KEY          = 11, ///<Raw RSA key (deprecated)
   IKE_CERT_ENCODING_HASH_URL_X509_CERT   = 12, ///<Hash and URL of X.509 certificate
   IKE_CERT_ENCODING_HASH_URL_X509_BUNDLE = 13, ///<Hash and URL of X.509 bundle
   IKE_CERT_ENCODING_OCSP_CONTENT         = 14, ///<OCSP Content
   IKE_CERT_ENCODING_RAW_PUBLIC_KEY       = 15  ///<Raw Public Key
} IkeCertEncoding;


/**
 * @brief Authentication methods
 **/

typedef enum
{
   IKE_AUTH_METHOD_RSA               = 1,  ///<RSA Digital Signature
   IKE_AUTH_METHOD_SHARED_KEY        = 2,  ///<Shared Key Message Integrity Code
   IKE_AUTH_METHOD_DSS               = 3,  ///<DSS Digital Signature
   IKE_AUTH_METHOD_ECDSA_P256_SHA256 = 9,  ///<ECDSA with SHA-256 on the P-256 curve
   IKE_AUTH_METHOD_ECDSA_P384_SHA384 = 10, ///<ECDSA with SHA-384 on the P-384 curve
   IKE_AUTH_METHOD_ECDSA_P521_SHA512 = 11, ///<ECDSA with SHA-512 on the P-521 curve
   IKE_AUTH_METHOD_GSPAM             = 12, ///<Generic Secure Password Authentication Method
   IKE_AUTH_METHOD_NULL              = 13, ///<NULL Authentication
   IKE_AUTH_METHOD_DIGITAL_SIGN      = 14  ///<Digital Signature
} IkeAuthMethod;


/**
 * @brief Notify message types
 **/

typedef enum
{
   IKE_NOTIFY_MSG_TYPE_NONE                                = 0,
   IKE_NOTIFY_MSG_TYPE_UNSUPPORTED_CRITICAL_PAYLOAD        = 1,     //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_IKE_SPI                     = 4,     //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_MAJOR_VERSION               = 5,     //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX                      = 7,     //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_MESSAGE_ID                  = 9,     //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_SPI                         = 11,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN                  = 14,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD                  = 17,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_AUTH_FAILED                         = 24,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED                = 34,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS                   = 35,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE            = 36,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED                  = 37,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE                     = 38,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_SELECTORS                   = 39,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_UNACCEPTABLE_ADDRESSES              = 40,    //RFC 4555
   IKE_NOTIFY_MSG_TYPE_UNEXPECTED_NAT_DETECTED             = 41,    //RFC 4555
   IKE_NOTIFY_MSG_TYPE_USE_ASSIGNED_HOA                    = 42,    //RFC 5026
   IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE                   = 43,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_CHILD_SA_NOT_FOUND                  = 44,    //RFC 7296
   IKE_NOTIFY_MSG_TYPE_INVALID_GROUP_ID                    = 45,    //Draft
   IKE_NOTIFY_MSG_TYPE_AUTHORIZATION_FAILED                = 46,    //Draft
   IKE_NOTIFY_MSG_TYPE_STATE_NOT_FOUND                     = 47,    //Draft
   IKE_NOTIFY_MSG_TYPE_INITIAL_CONTACT                     = 16384, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_SET_WINDOW_SIZE                     = 16385, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_ADDITIONAL_TS_POSSIBLE              = 16386, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_IPCOMP_SUPPORTED                    = 16387, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_SOURCE_IP             = 16388, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_NAT_DETECTION_DESTINATION_IP        = 16389, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_COOKIE                              = 16390, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_USE_TRANSPORT_MODE                  = 16391, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_HTTP_CERT_LOOKUP_SUPPORTED          = 16392, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_REKEY_SA                            = 16393, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED       = 16394, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_NON_FIRST_FRAGMENTS_ALSO            = 16395, //RFC 7296
   IKE_NOTIFY_MSG_TYPE_MOBIKE_SUPPORTED                    = 16396, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_ADDITIONAL_IP4_ADDRESS              = 16397, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_ADDITIONAL_IP6_ADDRESS              = 16398, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_ADDRESSES             = 16399, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_UPDATE_SA_ADDRESSES                 = 16400, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_COOKIE2                             = 16401, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_NO_NATS_ALLOWED                     = 16402, //RFC 4555
   IKE_NOTIFY_MSG_TYPE_AUTH_LIFETIME                       = 16403, //RFC 4478
   IKE_NOTIFY_MSG_TYPE_MULTIPLE_AUTH_SUPPORTED             = 16404, //RFC 4739
   IKE_NOTIFY_MSG_TYPE_ANOTHER_AUTH_FOLLOWS                = 16405, //RFC 4739
   IKE_NOTIFY_MSG_TYPE_REDIRECT_SUPPORTED                  = 16406, //RFC 5685
   IKE_NOTIFY_MSG_TYPE_REDIRECT                            = 16407, //RFC 5685
   IKE_NOTIFY_MSG_TYPE_REDIRECTED_FROM                     = 16408, //RFC 5685
   IKE_NOTIFY_MSG_TYPE_TICKET_LT_OPAQUE                    = 16409, //RFC 5723
   IKE_NOTIFY_MSG_TYPE_TICKET_REQUEST                      = 16410, //RFC 5723
   IKE_NOTIFY_MSG_TYPE_TICKET_ACK                          = 16411, //RFC 5723
   IKE_NOTIFY_MSG_TYPE_TICKET_NACK                         = 16412, //RFC 5723
   IKE_NOTIFY_MSG_TYPE_TICKET_OPAQUE                       = 16413, //RFC 5723
   IKE_NOTIFY_MSG_TYPE_LINK_ID                             = 16414, //RFC 5739
   IKE_NOTIFY_MSG_TYPE_USE_WESP_MODE                       = 16415, //RFC 5840
   IKE_NOTIFY_MSG_TYPE_ROHC_SUPPORTED                      = 16416, //RFC 5857
   IKE_NOTIFY_MSG_TYPE_EAP_ONLY_AUTHENTICATION             = 16417, //RFC 5998
   IKE_NOTIFY_MSG_TYPE_CHILDLESS_IKEV2_SUPPORTED           = 16418, //RFC 6023
   IKE_NOTIFY_MSG_TYPE_QUICK_CRASH_DETECTION               = 16419, //RFC 6290
   IKE_NOTIFY_MSG_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED     = 16420, //RFC 6311
   IKE_NOTIFY_MSG_TYPE_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421, //RFC 6311
   IKE_NOTIFY_MSG_TYPE_IKEV2_MESSAGE_ID_SYNC               = 16422, //RFC 6311
   IKE_NOTIFY_MSG_TYPE_IPSEC_REPLAY_COUNTER_SYNC           = 16423, //RFC 6311
   IKE_NOTIFY_MSG_TYPE_SECURE_PASSWORD_METHODS             = 16424, //RFC 6467
   IKE_NOTIFY_MSG_TYPE_PSK_PERSIST                         = 16425, //RFC 6631
   IKE_NOTIFY_MSG_TYPE_PSK_CONFIRM                         = 16426, //RFC 6631
   IKE_NOTIFY_MSG_TYPE_ERX_SUPPORTED                       = 16427, //RFC 6867
   IKE_NOTIFY_MSG_TYPE_IFOM_CAPABILITY                     = 16428, //Draft
   IKE_NOTIFY_MSG_TYPE_SENDER_REQUEST_ID                   = 16429, //Draft
   IKE_NOTIFY_MSG_TYPE_IKEV2_FRAGMENTATION_SUPPORTED       = 16430, //RFC 7383
   IKE_NOTIFY_MSG_TYPE_SIGNATURE_HASH_ALGORITHMS           = 16431, //RFC 7427
   IKE_NOTIFY_MSG_TYPE_CLONE_IKE_SA_SUPPORTED              = 16432, //RFC 7791
   IKE_NOTIFY_MSG_TYPE_CLONE_IKE_SA                        = 16433, //RFC 7791
   IKE_NOTIFY_MSG_TYPE_PUZZLE                              = 16434, //RFC 8019
   IKE_NOTIFY_MSG_TYPE_USE_PPK                             = 16435, //RFC 8784
   IKE_NOTIFY_MSG_TYPE_PPK_IDENTITY                        = 16436, //RFC 8784
   IKE_NOTIFY_MSG_TYPE_NO_PPK_AUTH                         = 16437, //RFC 8784
   IKE_NOTIFY_MSG_TYPE_INTERMEDIATE_EXCHANGE_SUPPORTED     = 16438, //RFC 9242
   IKE_NOTIFY_MSG_TYPE_IP4_ALLOWED                         = 16439, //RFC 8983
   IKE_NOTIFY_MSG_TYPE_IP6_ALLOWED                         = 16440, //RFC 8983
   IKE_NOTIFY_MSG_TYPE_ADDITIONAL_KEY_EXCHANGE             = 16441, //Draft
   IKE_NOTIFY_MSG_TYPE_USE_AGGFRAG                         = 16442, //Draft
   IKE_NOTIFY_MSG_TYPE_R_U_THERE                           = 36136, //RFC 3706
   IKE_NOTIFY_MSG_TYPE_R_U_THERE_ACK                       = 36137  //RFC 3706
} IkeNotifyMsgType;


/**
 * @brief Traffic selector types
 **/

typedef enum
{
   IKE_TS_TYPE_IPV4_ADDR_RANGE = 7,
   IKE_TS_TYPE_IPV6_ADDR_RANGE = 8
} IkeTsType;


/**
 * @brief IP protocol IDs
 **/

typedef enum
{
   IKE_IP_PROTOCOL_ID_ICMP   = 1,
   IKE_IP_PROTOCOL_ID_TCP    = 6,
   IKE_IP_PROTOCOL_ID_UDP    = 17,
   IKE_IP_PROTOCOL_ID_ICMPV6 = 58,
} IkeIpProtocolId;


/**
 * @brief Configuration types
 **/

typedef enum
{
   IKE_CONFIG_TYPE_REQUEST = 1,
   IKE_CONFIG_TYPE_REPLY   = 2,
   IKE_CONFIG_TYPE_SET     = 3,
   IKE_CONFIG_TYPE_ACK     = 4
} IkeConfigType;


/**
 * @brief Configuration attribute types
 **/

typedef enum
{
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_ADDRESS = 1,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_NETMASK = 2,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_DNS     = 3,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_NBNS    = 4,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_DHCP    = 6,
   IKE_CONFIG_ATTR_TYPE_APPLICATION_VERSION  = 7,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_ADDRESS = 8,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_DNS     = 10,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_DHCP    = 12,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP4_SUBNET  = 13,
   IKE_CONFIG_ATTR_TYPE_SUPPORTED_ATTRIBUTES = 14,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_SUBNET  = 15,
   IKE_CONFIG_ATTR_TYPE_MIP6_HOME_PREFIX     = 16,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_LINK    = 17,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_IP6_PREFIX  = 18,
   IKE_CONFIG_ATTR_TYPE_P_CSCF_IP4_ADDRESS   = 20,
   IKE_CONFIG_ATTR_TYPE_P_CSCF_IP6_ADDRESS   = 21,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_DNS_DOMAIN  = 25,
   IKE_CONFIG_ATTR_TYPE_INTERNAL_DNSSEC_TA   = 26
} IkeAttrType;


/**
 * @brief IKE Security Association state
 **/

typedef enum
{
   IKE_SA_STATE_CLOSED            = 0,
   IKE_SA_STATE_RESERVED          = 1,
   IKE_SA_STATE_INIT_REQ          = 2,
   IKE_SA_STATE_INIT_RESP         = 3,
   IKE_SA_STATE_AUTH_REQ          = 4,
   IKE_SA_STATE_AUTH_RESP         = 5,
   IKE_SA_STATE_OPEN              = 6,
   IKE_SA_STATE_DPD_REQ           = 7,
   IKE_SA_STATE_DPD_RESP          = 8,
   IKE_SA_STATE_REKEY_REQ         = 9,
   IKE_SA_STATE_REKEY_RESP        = 10,
   IKE_SA_STATE_DELETE_REQ        = 11,
   IKE_SA_STATE_DELETE_RESP       = 12,
   IKE_SA_STATE_CREATE_CHILD_REQ  = 13,
   IKE_SA_STATE_CREATE_CHILD_RESP = 14,
   IKE_SA_STATE_REKEY_CHILD_REQ   = 15,
   IKE_SA_STATE_REKEY_CHILD_RESP  = 16,
   IKE_SA_STATE_DELETE_CHILD_REQ  = 17,
   IKE_SA_STATE_DELETE_CHILD_RESP = 18,
   IKE_SA_STATE_AUTH_FAILURE_REQ  = 19,
   IKE_SA_STATE_AUTH_FAILURE_RESP = 20
} IkeSaState;


/**
 * @brief Child Security Association state
 **/

typedef enum
{
   IKE_CHILD_SA_STATE_CLOSED   = 0,
   IKE_CHILD_SA_STATE_RESERVED = 1,
   IKE_CHILD_SA_STATE_INIT     = 2,
   IKE_CHILD_SA_STATE_OPEN     = 3,
   IKE_CHILD_SA_STATE_REKEY    = 4,
   IKE_CHILD_SA_STATE_DELETE   = 5
} IkeChildSaState;


/**
 * @brief Hash algorithms
 **/

typedef enum
{
   IKE_HASH_ALGO_SHA1     = 1,
   IKE_HASH_ALGO_SHA256   = 2,
   IKE_HASH_ALGO_SHA384   = 3,
   IKE_HASH_ALGO_SHA512   = 4,
   IKE_HASH_ALGO_IDENTITY = 5
} IkeHashAlgo;


/**
 * @brief Certificate types
 **/

typedef enum
{
   IKE_CERT_TYPE_INVALID               = 0,
   IKE_CERT_TYPE_RSA                   = 1,
   IKE_CERT_TYPE_RSA_PSS               = 2,
   IKE_CERT_TYPE_DSA                   = 3,
   IKE_CERT_TYPE_ECDSA_P256            = 4,
   IKE_CERT_TYPE_ECDSA_P384            = 5,
   IKE_CERT_TYPE_ECDSA_P521            = 6,
   IKE_CERT_TYPE_ECDSA_BRAINPOOLP256R1 = 7,
   IKE_CERT_TYPE_ECDSA_BRAINPOOLP384R1 = 8,
   IKE_CERT_TYPE_ECDSA_BRAINPOOLP512R1 = 9,
   IKE_CERT_TYPE_ED25519               = 10,
   IKE_CERT_TYPE_ED448                 = 11
} IkeCertType;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief IKE header
 **/

typedef __packed_struct
{
   uint8_t initiatorSpi[IKE_SPI_SIZE]; //0-7
   uint8_t responderSpi[IKE_SPI_SIZE]; //8-15
   uint8_t nextPayload;                //16
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t majorVersion : 4;           //17
   uint8_t minorVersion : 4;
#else
   uint8_t minorVersion : 4;           //17
   uint8_t majorVersion : 4;
#endif
   uint8_t exchangeType;               //18
   uint8_t flags;                      //19
   uint32_t messageId;                 //20-23
   uint32_t length;                    //24-27
} IkeHeader;


/**
 * @brief Generic payload header
 **/

typedef __packed_struct
{
   uint8_t nextPayload;    //0
#if defined(_CPU_BIG_ENDIAN) && !defined(__ICCRX__)
   uint8_t critical : 1;   //1
   uint8_t reserved : 7;
#else
   uint8_t reserved : 7;   //1
   uint8_t critical : 1;
#endif
   uint16_t payloadLength; //2-3
} IkePayloadHeader;


/**
 * @brief Security Association payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t proposals[];     //4
} IkeSaPayload;


/**
 * @brief Proposal substructure
 **/

typedef __packed_struct
{
   uint8_t lastSubstruc;    //0
   uint8_t reserved;        //1
   uint16_t proposalLength; //2-3
   uint8_t proposalNum;     //4
   uint8_t protocolId;      //5
   uint8_t spiSize;         //6
   uint8_t numTransforms;   //7
   uint8_t spi[];           //8
} IkeProposal;


/**
 * @brief Transform substructure
 **/

typedef __packed_struct
{
   uint8_t lastSubstruc;     //0
   uint8_t reserved1;        //1
   uint16_t transformLength; //2-3
   uint8_t transformType;    //4
   uint8_t reserved2;        //5
   uint16_t transformId;     //6-7
   uint8_t transformAttr[];  //8
} IkeTransform;


/**
 * @brief Transform attribute
 **/

typedef __packed_struct
{
   uint16_t type;   //0-1
   uint16_t length; //2-3
   uint8_t value[]; //4
} IkeTransformAttr;


/**
 * @brief Key Exchange payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header;   //0-3
   uint16_t dhGroupNum;       //4-5
   uint16_t reserved;         //6-7
   uint8_t keyExchangeData[]; //8
} IkeKePayload;


/**
 * @brief Identification payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t idType;          //4
   uint8_t reserved[3];     //5-7
   uint8_t idData[];        //8
} IkeIdPayload;


/**
 * @brief Certificate payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t certEncoding;    //4
   uint8_t certData[];      //5
} IkeCertPayload;


/**
 * @brief Certificate Request payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t certEncoding;    //4
   uint8_t certAuthority[]; //5
} IkeCertReqPayload;


/**
 * @brief Authentication payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t authMethod;      //4
   uint8_t reserved[3];     //4-7
   uint8_t authData[];      //8
} IkeAuthPayload;


/**
 * @brief Authentication data for digital signatures
 **/

typedef __packed_struct
{
   uint8_t algoIdLen; //0
   uint8_t algoId[];  //1
} IkeAuthData;


/**
 * @brief Nonce payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t nonceData[];     //4
} IkeNoncePayload;


/**
 * @brief Notify payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t protocolId;      //4
   uint8_t spiSize;         //5
   uint16_t notifyMsgType;  //6-7
   uint8_t spi[];           //8
} IkeNotifyPayload;


/**
 * @brief Delete payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t protocolId;      //4
   uint8_t spiSize;         //5
   uint16_t numSpi;         //6-7
   uint8_t spi[];           //8
} IkeDeletePayload;


/**
 * @brief Vendor ID payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t vid[];           //4
} IkeVendorIdPayload;


/**
 * @brief Traffic Selector payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header;    //0-3
   uint8_t numTs;              //4
   uint8_t reserved[3];        //5-7
   uint8_t trafficSelectors[]; //8
} IkeTsPayload;


/**
 * @brief Traffic selector
 **/

typedef __packed_struct
{
   uint8_t tsType;          //0
   uint8_t ipProtocolId;    //1
   uint16_t selectorLength; //2-3
   uint16_t startPort;      //4-5
   uint16_t endPort;        //6-7
   uint8_t startAddr[];     //8
} IkeTs;


/**
 * @brief Encrypted payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t iv[];            //4
} IkeEncryptedPayload;


/**
 * @brief Configuration payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header;    //0-3
   uint8_t configType;         //4
   uint8_t reserved[3];        //5-7
   uint8_t configAttributes[]; //8
} IkeConfigPayload;


/**
 * @brief Configuration attribute
 **/

typedef __packed_struct
{
   uint16_t type;   //0-1
   uint16_t length; //2-3
   uint8_t value[]; //4
} IkeConfigAttr;


/**
 * @brief EAP payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint8_t eapMessage[];    //4
} IkeEapPayload;


/**
 * @brief EAP message
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t data[];     //5
} IkeEapMessage;


/**
 * @brief Encrypted Fragment payload
 **/

typedef __packed_struct
{
   IkePayloadHeader header; //0-3
   uint16_t fragNum;        //4-5
   uint16_t totalFrags;     //6-7
   uint8_t iv[];            //8
} IkeEncryptedFragPayload;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief Certificate verification callback function
 **/

typedef error_t (*IkeCertVerifyCallback)(IkeSaEntry *sa,
   const X509CertInfo *certInfo, uint_t pathLen);


/**
 * @brief Cookie generation callback function
 **/

typedef error_t (*IkeCookieGenerateCallback)(IkeContext *context,
   const IpAddr *ipAddr, const uint8_t *spi, const uint8_t *nonce,
   size_t nonceLen, uint8_t *cookie, size_t *cookieLen);


/**
 * @brief Cookie verification callback function
 **/

typedef error_t (*IkeCookieVerifyCallback)(IkeContext *context,
   const IpAddr *ipAddr, const uint8_t *spi, const uint8_t *nonce,
   size_t nonceLen, const uint8_t *cookie, size_t cookieLen);


/**
 * @brief Traffic selector parameters
 **/

typedef struct
{
   IpAddr startAddr;
   IpAddr endAddr;
   uint8_t ipProtocolId;
   uint16_t startPort;
   uint16_t endPort;
} IkeTsParams;


/**
 * @brief IKE Security Association entry
 **/

struct _IkeSaEntry
{
   IkeSaState state;                    ///<IKE SA state
   IkeContext *context;                 ///<IKE context
   IkeSaEntry *oldSa;                   ///<Old IKE SA
   IkeSaEntry *newSa;                   ///<New IKE SA
   IkeChildSaEntry *childSa;            ///<Child SA
   IpAddr remoteIpAddr;                 ///<IP address of the peer
   uint16_t remotePort;
   bool_t originalInitiator;            ///<Original initiator of the IKE SA
   systime_t lifetimeStart;
   systime_t lifetime;                  ///<Lifetime of the IKE SA
   systime_t reauthPeriod;              ///<Reauthentication period
#if (IKE_DPD_SUPPORT == ENABLED)
   systime_t dpdStart;
   systime_t dpdPeriod;                 ///<Dead peer detection period
#endif
   systime_t timestamp;
   systime_t timeout;
   uint_t retransmitCount;
   uint32_t txMessageId;
   uint32_t rxMessageId;
   uint8_t cookie[IKE_MAX_COOKIE_SIZE]; ///<Cookie
   size_t cookieLen;                    ///<Length of the cookie, in bytes
   uint8_t initiatorSpi[IKE_SPI_SIZE];  ///<Initiator SPI
   uint8_t responderSpi[IKE_SPI_SIZE];  ///<Responder SPI

   uint8_t initiatorNonce[IKE_MAX_NONCE_SIZE];
   size_t initiatorNonceLen;
   uint8_t responderNonce[IKE_MAX_NONCE_SIZE];
   size_t responderNonceLen;

   IkeIdType peerIdType;                ///<Peer ID type
   uint8_t peerId[IKE_MAX_ID_LEN];      ///<Peer ID
   size_t peerIdLen;                    ///<Length of the peer ID, in bytes

   IkeNotifyMsgType notifyMsgType;
   uint8_t unsupportedCriticalPayload;
   uint8_t notifyProtocolId;
   uint8_t notifySpi[4];

   uint16_t encAlgoId;                  ///<Encryption algorithm
   uint16_t prfAlgoId;                  ///<Pseudorandom function
   uint16_t authAlgoId;                 ///<Integrity algorithm
   uint16_t dhGroupNum;                 ///<Diffie-Hellman group number

   uint8_t sharedSecret[IKE_MAX_SHARED_SECRET_LEN]; ///<Shared secret
   size_t sharedSecretLen;              ///<Length of the shared secret, in bytes
   uint8_t keyMaterial[IKE_MAX_SA_KEY_MAT_LEN]; ///<Keying material
   const uint8_t *skd;                  ///<Key used for deriving new keys for Child SAs
   const uint8_t *skai;                 ///<Integrity protection key (initiator)
   const uint8_t *skar;                 ///<Integrity protection key (responder)
   const uint8_t *skei;                 ///<Encryption key (initiator)
   const uint8_t *sker;                 ///<Encryption key (responder)
   const uint8_t *skpi;                 ///<Key used for generating AUTH payload (initiator)
   const uint8_t *skpr;                 ///<Key used for generating AUTH payload (responder)

   CipherMode cipherMode;               ///<Cipher mode of operation
   const CipherAlgo *cipherAlgo;        ///<Cipher algorithm
   CipherContext cipherContext;         ///<Cipher context
   const HashAlgo *authHashAlgo;        ///<Hash algorithm for HMAC-based integrity calculations
   const CipherAlgo *authCipherAlgo;    ///<Cipher algorithm for CMAC-based integrity calculations
   const HashAlgo *prfHashAlgo;         ///<Hash algorithm for HMAC-based PRF calculations
   const CipherAlgo *prfCipherAlgo;     ///<Cipher algorithm for CMAC-based PRF calculations
   size_t encKeyLen;                    ///<Size of the encryption key, in bytes
   size_t authKeyLen;                   ///<Size of the integrity protection key, in bytes
   size_t prfKeyLen;                    ///<Preferred size of the PRF key, in bytes
   size_t saltLen;                      ///<Length of the salt, in bytes
   size_t ivLen;                        ///<Length of the initialization vector, in bytes
   size_t icvLen;                       ///<Length of the ICV tag, in bytes
   uint8_t iv[8];                       ///<Initialization vector

#if (IKE_DH_KE_SUPPORT == ENABLED)
   DhContext dhContext;                 ///<Diffie-Hellman context
#endif
#if (IKE_ECDH_KE_SUPPORT == ENABLED)
   EcdhContext ecdhContext;             ///<ECDH context
#endif

   uint8_t *initiatorSaInit;            ///<Pointer to the IKE_SA_INIT request
   size_t initiatorSaInitLen;           ///<Length of the IKE_SA_INIT request, in bytes
   uint8_t *responderSaInit;            ///<Pointer to the IKE_SA_INIT response
   size_t responderSaInitLen;           ///<Length of the IKE_SA_INIT response, in bytes

   uint8_t request[IKE_MAX_MSG_SIZE];   ///<Request message
   size_t requestLen;                   ///<Length of the request message, in bytes
   uint8_t response[IKE_MAX_MSG_SIZE];  ///<Response message
   size_t responseLen;                  ///<Length of the response message, in bytes

   bool_t rekeyRequest;                 ///<IKE SA rekey request
   bool_t reauthRequest;                ///<IKE SA reauthentication request
   bool_t reauthPending;                ///<Reauthentication process is on-going
   bool_t deleteRequest;                ///<IKE SA delete request
   bool_t deleteReceived;
   bool_t nonAdditionalSas;             ///<NO_ADDITIONAL_SAS notification received
#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
   bool_t initialContact;               ///<INITIAL_CONTACT notification received
#endif
#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
   uint32_t signHashAlgos;              ///<List of hash algorithms supported by the peer
#endif
};


/**
 * @brief Child Security Association entry
 **/

struct _IkeChildSaEntry
{
   IkeChildSaState state;              ///<Child SA state
   IkeContext *context;                ///<IKE context
   IkeSaEntry *sa;                     ///<IKE SA entry
   IkeChildSaEntry *oldChildSa;        ///<Old Child SA
   IpAddr remoteIpAddr;                ///<IP address of the peer
   IpsecMode mode;                     ///<IPsec mode (tunnel or transport)
   IpsecProtocol protocol;             ///<Security protocol (AH or ESP)
   bool_t initiator;                   ///<Initiator of the CREATE_CHILD_SA exchange
   systime_t lifetimeStart;
   uint8_t initiatorNonce[IKE_MAX_NONCE_SIZE]; ///<Initiator nonce
   size_t initiatorNonceLen;           ///<Length of the initiator nonce
   uint8_t responderNonce[IKE_MAX_NONCE_SIZE]; ///<Responder nonce
   size_t responderNonceLen;           ///<Length of the responder nonce
   uint8_t localSpi[4];
   uint8_t remoteSpi[4];
   uint16_t encAlgoId;                 ///<Encryption algorithm
   uint16_t authAlgoId;                ///<Integrity algorithm
   uint16_t esn;                       ///<Extended sequence numbers

   uint8_t keyMaterial[IKE_MAX_CHILD_SA_KEY_MAT_LEN]; ///<Keying material
   const uint8_t *skai;                ///<Integrity protection key (initiator)
   const uint8_t *skar;                ///<Integrity protection key (responder)
   const uint8_t *skei;                ///<Encryption key (initiator)
   const uint8_t *sker;                ///<Encryption key (responder)

   CipherMode cipherMode;              ///<Cipher mode of operation
   const CipherAlgo *cipherAlgo;       ///<Cipher algorithm
   const HashAlgo *authHashAlgo;       ///<Hash algorithm for HMAC-based integrity calculations
   const CipherAlgo *authCipherAlgo;   ///<Cipher algorithm for CMAC-based integrity calculations
   size_t encKeyLen;                   ///<Length of the encryption key, in bytes
   size_t authKeyLen;                  ///<Length of the integrity protection key, in bytes
   size_t saltLen;                     ///<Length of the salt, in bytes
   size_t ivLen;                       ///<Length of the initialization vector, in bytes
   size_t icvLen;                      ///<Length of the ICV tag, in bytes
   uint8_t iv[8];                      ///<Initialization vector

   IpsecPacketInfo packetInfo;
   IpsecSelector selector;

   bool_t rekeyRequest;                ///<Child SA rekey request
   bool_t deleteRequest;               ///<Child SA delete request
   bool_t deleteReceived;

   int_t inboundSa;                    ///<Inbound SAD entry
   int_t outboundSa;                   ///<Outbound SAD entry
};


/**
 * @brief IKE settings
 **/

typedef struct
{
   OsTaskParameters task;                            ///<Task parameters
   NetInterface *interface;                          ///<Underlying network interface
   const PrngAlgo *prngAlgo;                         ///<Pseudo-random number generator to be used
   void *prngContext;                                ///<Pseudo-random number generator context
   IkeSaEntry *saEntries;                            ///<IKE SA entries
   uint_t numSaEntries;                              ///<Number of IKE SA entries
   IkeChildSaEntry *childSaEntries;                  ///<Child SA entries
   uint_t numChildSaEntries;                         ///<Number of Child SA entries
   systime_t saLifetime;                             ///<Lifetime of IKE SAs
   systime_t childSaLifetime;                        ///<Lifetime of Child SAs
   systime_t reauthPeriod;                           ///<Reauthentication period
#if (IKE_DPD_SUPPORT == ENABLED)
   systime_t dpdPeriod;                              ///<Dead peer detection period
#endif
#if (IKE_COOKIE_SUPPORT == ENABLED)
   IkeCookieGenerateCallback cookieGenerateCallback; ///<Cookie generation callback function
   IkeCookieVerifyCallback cookieVerifyCallback;     ///<Cookie verification callback function
#endif
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   IkeCertVerifyCallback certVerifyCallback;         ///<Certificate verification callback function
#endif
} IkeSettings;


/**
 * @brief IKE context
 **/

struct _IkeContext
{
   bool_t running;                        ///<Operational state of IKEv2
   bool_t stop;                           ///<Stop request
   OsEvent event;                         ///<Event object used to poll the sockets
   OsTaskParameters taskParams;           ///<Task parameters
   OsTaskId taskId;                       ///<Task identifier
   NetInterface *interface;               ///<Underlying network interface
   const PrngAlgo *prngAlgo;              ///<Pseudo-random number generator to be used
   void *prngContext;                     ///<Pseudo-random number generator context
   systime_t saLifetime;                  ///<Lifetime of IKE SAs
   systime_t childSaLifetime;             ///<Lifetime of Child SAs
   systime_t reauthPeriod;                ///<Reauthentication period
#if (IKE_DPD_SUPPORT == ENABLED)
   systime_t dpdPeriod;                   ///<Dead peer detection period
#endif
   uint16_t preferredDhGroupNum;          ///<Preferred Diffie-Hellman group number
   IkeIdType idType;                      ///<ID type
   uint8_t id[IKE_MAX_ID_LEN];            ///<ID
   size_t idLen;                          ///<Length of the ID, in bytes
   uint8_t psk[IKE_MAX_PSK_LEN];          ///<Pre-shared key
   size_t pskLen;                         ///<Length of the pre-shared key, in bytes
   IkeCertType certType;                  ///<Certificate type
   const char_t *certChain;               ///<Entity's certificate chain (PEM format)
   size_t certChainLen;                   ///<Length of the certificate chain
   const char_t *privateKey;              ///<Entity's private key (PEM format)
   size_t privateKeyLen;                  ///<Length of the private key
   char_t password[IKE_MAX_PASSWORD_LEN]; ///<Password used to decrypt the private key

   Socket *socket;                        ///<Underlying UDP socket
   IpAddr localIpAddr;                    ///<Destination IP address of the received IKE message
   IpAddr remoteIpAddr;                   ///<Source IP address of the received IKE message
   uint16_t remotePort;                   ///<Source port of the received IKE message
   IkeSaEntry *sa;                        ///<IKE SA entries
   uint_t numSaEntries;                   ///<Number of IKE SA entries
   IkeChildSaEntry *childSa;              ///<Child SA entries
   uint_t numChildSaEntries;              ///<Number of Child SA entries
   uint8_t message[IKE_MAX_MSG_SIZE];     ///<Incoming IKE message
   size_t messageLen;                     ///<Length of the incoming IKE message, in bytes

#if (IKE_CMAC_AUTH_SUPPORT == ENABLED || IKE_CMAC_PRF_SUPPORT == ENABLED)
   CmacContext cmacContext;               ///<CMAC context
#endif
#if (IKE_HMAC_AUTH_SUPPORT == ENABLED || IKE_HMAC_PRF_SUPPORT == ENABLED)
   HmacContext hmacContext;               ///<HMAC context
#endif
#if (IKE_XCBC_MAC_AUTH_SUPPORT == ENABLED || IKE_XCBC_MAC_PRF_SUPPORT == ENABLED)
   XcbcMacContext xcbcMacContext;         ///<XCBC-MAC context
#endif

#if (IKE_COOKIE_SUPPORT == ENABLED)
   IkeCookieGenerateCallback cookieGenerateCallback; ///<Cookie generation callback function
   IkeCookieVerifyCallback cookieVerifyCallback;     ///<Cookie verification callback function
#endif
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   IkeCertVerifyCallback certVerifyCallback;         ///<Certificate verification callback function
#endif
};


//IKEv2 related functions
void ikeGetDefaultSettings(IkeSettings *settings);

error_t ikeInit(IkeContext *context, const IkeSettings *settings);
error_t ikeStart(IkeContext *context);
error_t ikeStop(IkeContext *context);

error_t ikeSetPreferredDhGroup(IkeContext *context, uint16_t dhGroupNum);

error_t ikeSetId(IkeContext *context, IkeIdType idType, const void *id,
   size_t idLen);

error_t ikeSetPsk(IkeContext *context, const uint8_t *psk, size_t pskLen);

error_t ikeSetCertificate(IkeContext *context, const char_t *certChain,
   size_t certChainLen, const char_t *privateKey, size_t privateKeyLen,
   const char_t *password);

error_t ikeCreateSa(IkeContext *context, const IpsecPacketInfo *packet);
error_t ikeRekeySa(IkeSaEntry *sa);
error_t ikeDeleteSa(IkeSaEntry *sa);

error_t ikeCreateChildSa(IkeContext *context, const IpsecPacketInfo *packet);
error_t ikeRekeyChildSa(IkeChildSaEntry *childSa);
error_t ikeDeleteChildSa(IkeChildSaEntry *childSa);

void ikeTask(IkeContext *context);

void ikeDeinit(IkeContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
