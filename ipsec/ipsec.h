/**
 * @file ipsec.h
 * @brief IPsec (IP security)
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

#ifndef _IPSEC_H
#define _IPSEC_H

//Forward declaration of IpsecSadEntry structure
struct _IpsecSadEntry;
#define IpsecSadEntry struct _IpsecSadEntry

//Dependencies
#include "ipsec_config.h"
#include "core/net.h"
#include "core/udp.h"
#include "core/tcp.h"
#include "ipv4/icmp.h"
#include "core/crypto.h"
#include "ah/ah.h"
#include "esp/esp.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "hash/hash_algorithms.h"
#include "mac/mac_algorithms.h"


/*
 * CycloneIPSEC Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneIPSEC Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneIPSEC Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneIPSEC Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneIPSEC Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_IPSEC_VERSION_STRING "2.5.2"
//Major version
#define CYCLONE_IPSEC_MAJOR_VERSION 2
//Minor version
#define CYCLONE_IPSEC_MINOR_VERSION 5
//Revision number
#define CYCLONE_IPSEC_REV_NUMBER 2

//IPsec support
#ifndef IPSEC_SUPPORT
   #define IPSEC_SUPPORT ENABLED
#elif (IPSEC_SUPPORT != ENABLED && IPSEC_SUPPORT != DISABLED)
   #error IPSEC_SUPPORT parameter is not valid
#endif

//Anti-replay mechanism
#ifndef IPSEC_ANTI_REPLAY_SUPPORT
   #define IPSEC_ANTI_REPLAY_SUPPORT ENABLED
#elif (IPSEC_ANTI_REPLAY_SUPPORT != ENABLED && IPSEC_ANTI_REPLAY_SUPPORT != DISABLED)
   #error IPSEC_ANTI_REPLAY_SUPPORT parameter is not valid
#endif

//Size of the sliding window for replay protection
#ifndef IPSEC_ANTI_REPLAY_WINDOW_SIZE
   #define IPSEC_ANTI_REPLAY_WINDOW_SIZE 64
#elif (IPSEC_ANTI_REPLAY_WINDOW_SIZE < 1)
   #error IPSEC_ANTI_REPLAY_WINDOW_SIZE parameter is not valid
#endif

//Maximum length of ID
#ifndef IPSEC_MAX_ID_LEN
   #define IPSEC_MAX_ID_LEN 64
#elif (IPSEC_MAX_ID_LEN < 0)
   #error IPSEC_MAX_ID_LEN is not valid
#endif

//Maximum length of pre-shared keys
#ifndef IPSEC_MAX_PSK_LEN
   #define IPSEC_MAX_PSK_LEN 64
#elif (IPSEC_MAX_PSK_LEN < 0)
   #error IPSEC_MAX_PSK_LEN is not valid
#endif

//Maximum length of encryption keys
#ifndef IPSEC_MAX_ENC_KEY_LEN
   #define IPSEC_MAX_ENC_KEY_LEN 36
#elif (IPSEC_MAX_ENC_KEY_LEN < 1)
   #error IPSEC_MAX_ENC_KEY_LEN parameter is not valid
#endif

//Maximum length of integrity protection keys
#ifndef IPSEC_MAX_AUTH_KEY_LEN
   #define IPSEC_MAX_AUTH_KEY_LEN 64
#elif (IPSEC_MAX_AUTH_KEY_LEN < 1)
   #error IPSEC_MAX_AUTH_KEY_LEN parameter is not valid
#endif

//Size of SPI for AH and ESP protocols
#define IPSEC_SPI_SIZE 4

//ANY protocol selector
#define IPSEC_PROTOCOL_ANY 0

//ANY port selector
#define IPSEC_PORT_START_ANY 0
#define IPSEC_PORT_END_ANY   65535

//OPAQUE port selector
#define IPSEC_PORT_START_OPAQUE 65535
#define IPSEC_PORT_END_OPAQUE   0

//ICMP port selector
#define IPSEC_ICMP_PORT(type, code) (((type) * 256) + (code))

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Direction
 **/

typedef enum
{
   IPSEC_DIR_INVALID  = 0,
   IPSEC_DIR_INBOUND  = 1,
   IPSEC_DIR_OUTBOUND = 2
} IpsecDirection;


/**
 * @brief Authentication methods
 **/

typedef enum
{
   IPSEC_AUTH_METHOD_INVALID = 0,
   IPSEC_AUTH_METHOD_IKEV1   = 1,
   IPSEC_AUTH_METHOD_IKEV2   = 2,
   IPSEC_AUTH_METHOD_KINK    = 3
} IpsecAuthMethod;


/**
 * @brief Security protocols
 **/

typedef enum
{
   IPSEC_PROTOCOL_INVALID = 0,
   IPSEC_PROTOCOL_AH      = 2,
   IPSEC_PROTOCOL_ESP     = 3
} IpsecProtocol;


/**
 * @brief IPsec protocol modes
 **/

typedef enum
{
   IPSEC_MODE_INVALID   = 0,
   IPSEC_MODE_TUNNEL    = 1,
   IPSEC_MODE_TRANSPORT = 2
} IpsecMode;


/**
 * @brief ID types
 **/

typedef enum
{
   IPSEC_ID_TYPE_IPV4_ADDR   = 1, ///<IPv4 address
   IPSEC_ID_TYPE_FQDN        = 2, ///<Fully-qualified domain name
   IPSEC_ID_TYPE_RFC822_ADDR = 3, ///<RFC 822 email address
   IPSEC_ID_TYPE_IPV6_ADDR   = 5, ///<IPv6 address
   IPSEC_ID_TYPE_DN          = 9, ///<X.500 distinguished name
   IPSEC_ID_TYPE_KEY_ID      = 11 ///<Key ID
} IpsecIdType;


/**
 * @brief Policy action
 **/

typedef enum
{
   IPSEC_POLICY_ACTION_INVALID = 0,
   IPSEC_POLICY_ACTION_DISCARD = 1,
   IPSEC_POLICY_ACTION_BYPASS  = 2,
   IPSEC_POLICY_ACTION_PROTECT = 3
} IpsecPolicyAction;


/**
 * @brief PFP flags
 **/

typedef enum
{
   IPSEC_PFP_FLAG_LOCAL_ADDR    = 0x01,
   IPSEC_PFP_FLAG_REMOTE_ADDR   = 0x02,
   IPSEC_PFP_FLAG_NEXT_PROTOCOL = 0x04,
   IPSEC_PFP_FLAG_LOCAL_PORT    = 0x08,
   IPSEC_PFP_FLAG_REMOTE_PORT   = 0x10
} IpsecPfpFlags;


/**
 * @brief DF flag policy
 **/

typedef enum
{
   IPSEC_DF_POLICY_CLEAR = 0,
   IPSEC_DF_POLICY_SET   = 1,
   IPSEC_DF_POLICY_COPY  = 2
} IpsecDfPolicy;


/**
 * @brief IPsec SAD entry state
 **/

typedef enum
{
   IPSEC_SA_STATE_CLOSED   = 0,
   IPSEC_SA_STATE_RESERVED = 1,
   IPSEC_SA_STATE_OPEN     = 2
} IpsecSaState;


/**
 * @brief IP address range
 **/

typedef struct
{
   IpAddr start;
   IpAddr end;
} IpsecAddrRange;


/**
 * @brief Port range
 **/

typedef struct
{
   uint16_t start;
   uint16_t end;
} IpsecPortRange;


/**
 * @brief IPsec selector
 **/

typedef struct
{
   IpsecAddrRange localIpAddr;  ///<Local IP address range
   IpsecAddrRange remoteIpAddr; ///<Remote IP address range
   uint8_t nextProtocol;        ///<Next layer protocol
   IpsecPortRange localPort;    ///<Local port range
   IpsecPortRange remotePort;   ///<Remote port range
} IpsecSelector;


/**
 * @brief IP packet information
 **/

typedef struct
{
   IpAddr localIpAddr;   ///<Local IP address
   IpAddr remoteIpAddr;  ///<Remote IP address
   uint8_t nextProtocol; ///<Next layer protocol
   uint16_t localPort;   ///<Local port
   uint16_t remotePort;  ///<Remote port
} IpsecPacketInfo;


/**
 * @brief IPsec ID
 **/

typedef union
{
   char_t fqdn[IPSEC_MAX_ID_LEN + 1];  ///<Fully-qualified domain name
   char_t email[IPSEC_MAX_ID_LEN + 1]; ///<RFC 822 email address
   uint8_t dn[IPSEC_MAX_ID_LEN];       ///<X.500 Distinguished Name
   uint8_t keyId[IPSEC_MAX_ID_LEN];    ///<Key ID
   IpsecAddrRange ipAddr;              ///<IPv4 or IPv6 address range
} IpsecId;


/**
 * @brief Security Policy Database (SPD) entry
 **/

typedef struct
{
   IpsecPolicyAction policyAction; ///<Processing choice (DISCARD, BYPASS or PROTECT)
   uint_t pfpFlags;                ///<PFP flags
   IpsecSelector selector;         ///<Traffic selector
   IpsecMode mode;                 ///<IPsec mode (tunnel or transport)
   IpsecProtocol protocol;         ///<Security protocol (AH or ESP)
   bool_t esn;                     ///<Extended sequence numbers
   IpAddr localTunnelAddr;         ///<Local tunnel IP address
   IpAddr remoteTunnelAddr;        ///<Remote tunnel IP address
} IpsecSpdEntry;


/**
 * @brief Security Association Database (SAD) entry
 **/

struct _IpsecSadEntry
{
   IpsecSaState state;                      ///<SAD entry state
   IpsecDirection direction;                ///<Direction
   IpsecMode mode;                          ///<IPsec mode (tunnel or transport)
   IpsecProtocol protocol;                  ///<Security protocol (AH or ESP)
   IpsecSelector selector;                  ///<Traffic selector
   IpsecDfPolicy dfPolicy;                  ///<DF flag policy
   uint32_t spi;                            ///<Security parameter index
#if (ESP_SUPPORT == ENABLED)
   CipherMode cipherMode;                   ///<Cipher mode of operation
   const CipherAlgo *cipherAlgo;            ///<Cipher algorithm
   CipherContext cipherContext;             ///<Cipher context
   uint8_t encKey[IPSEC_MAX_ENC_KEY_LEN];   ///<Encryption key
   size_t encKeyLen;                        ///<Length of the encryption key, in bytes
   size_t saltLen;                          ///<Length of the salt, in bytes
   uint8_t iv[16];                          ///<Initialization vector
   size_t ivLen;                            ///<Length of the initialization vector, in bytes
#endif
   const HashAlgo *authHashAlgo;            ///<Hash algorithm for HMAC-based integrity calculations
   const CipherAlgo *authCipherAlgo;        ///<Cipher algorithm for CMAC-based integrity calculations
   uint8_t authKey[IPSEC_MAX_AUTH_KEY_LEN]; ///<Integrity protection key
   size_t authKeyLen;                       ///<Length of the integrity protection key, in bytes
   size_t icvLen;                           ///<Length of the ICV tag, in bytes
   bool_t esn;                              ///<Extended sequence numbers
   uint64_t seqNum;                         ///<Sequence number counter
   systime_t lifetimeStart;                 ///<Timestamp
#if (IPSEC_ANTI_REPLAY_SUPPORT == ENABLED)
   bool_t antiReplayEnabled;                ///<Anti-replay mechanism enabled
   uint32_t antiReplayWindow[(IPSEC_ANTI_REPLAY_WINDOW_SIZE + 31) / 32]; ///<Anti-replay window
#endif
   IpAddr tunnelDestIpAddr;                 ///<Tunnel header IP destination address
};


/**
 * @brief Peer Authorization Database (PAD) entry
 **/

typedef struct
{
   IpsecAuthMethod authMethod;     ///<Authentication method (IKEv1, IKEv2, KINK)
   IpsecIdType idType;             ///<ID type
   IpsecId id;                     ///<ID
   size_t idLen;                   ///<Length of the ID, in bytes
   uint8_t psk[IPSEC_MAX_PSK_LEN]; ///<Pre-shared key
   size_t pskLen;                  ///<Length of the pre-shared key, in bytes
   const char_t *trustedCaList;    ///Trusted CA list (PEM format)
   size_t trustedCaListLen;        ///<Total length of the trusted CA list
} IpsecPadEntry;


/**
 * @brief IPsec settings
 **/

typedef struct
{
   const PrngAlgo *prngAlgo;  ///<Pseudo-random number generator to be used
   void *prngContext;         ///<Pseudo-random number generator context
   IpsecSpdEntry *spdEntries; ///<Security Policy Database (SPD)
   uint_t numSpdEntries;      ///<Number of entries in the SPD database
   IpsecSadEntry *sadEntries; ///<Security Association Database (SAD)
   uint_t numSadEntries;      ///<Number of entries in the SAD database
   IpsecPadEntry *padEntries; ///<Peer Authorization Database (PAD)
   uint_t numPadEntries;      ///<Number of entries in the PAD database
} IpsecSettings;


/**
 * @brief IPsec context
 **/

typedef struct
{
   const PrngAlgo *prngAlgo;        ///<Pseudo-random number generator to be used
   void *prngContext;               ///<Pseudo-random number generator context
   IpsecSpdEntry *spd;              ///<Security Policy Database (SPD)
   uint_t numSpdEntries;            ///<Number of entries in the SPD database
   IpsecSadEntry *sad;              ///<Security Association Database (SAD)
   uint_t numSadEntries;            ///<Number of entries in the SAD database
   IpsecPadEntry *pad;              ///<Peer Authorization Database (PAD)
   uint_t numPadEntries;            ///<Number of entries in the PAD database
#if (AH_CMAC_SUPPORT == ENABLED || ESP_CMAC_SUPPORT == ENABLED)
   CmacContext cmacContext;         ///<CMAC context
#endif
#if (AH_HMAC_SUPPORT == ENABLED || ESP_HMAC_SUPPORT == ENABLED)
   HmacContext hmacContext;         ///<HMAC context
#endif
#if (ESP_SUPPORT == ENABLED)
   uint8_t buffer[ESP_BUFFER_SIZE]; ///<Memory buffer for input/output operations
#endif
} IpsecContext;


//IPsec related functions
void ipsecGetDefaultSettings(IpsecSettings *settings);

error_t ipsecInit(IpsecContext *context, const IpsecSettings *settings);

error_t ipsecSetSpdEntry(IpsecContext *context, uint_t index,
   IpsecSpdEntry *params);

error_t ipsecClearSpdEntry(IpsecContext *context, uint_t index);

error_t ipsecSetSadEntry(IpsecContext *context, uint_t index,
   IpsecSadEntry *params);

error_t ipsecClearSadEntry(IpsecContext *context, uint_t index);

error_t ipsecSetPadEntry(IpsecContext *context, uint_t index,
   IpsecPadEntry *params);

error_t ipsecClearPadEntry(IpsecContext *context, uint_t index);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
