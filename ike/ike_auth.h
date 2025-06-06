/**
 * @file ike_auth.h
 * @brief Authentication of the IKE SA
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

#ifndef _IKE_AUTH_H
#define _IKE_AUTH_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related functions
error_t ikeGenerateAuth(IkeSaEntry *sa, const IkeIdPayload *idPayload,
   uint8_t *authMethod, uint8_t *authData, size_t *authDataLen);

error_t ikeVerifyAuth(IkeSaEntry *sa, IpsecPadEntry *padEntry,
   const IkeIdPayload *idPayload, const IkeCertPayload *certPayload,
   const IkeAuthPayload *authPayload);

error_t ikeComputeMacAuth(IkeSaEntry *sa, const uint8_t *key, size_t keyLen,
   const uint8_t *id, size_t idLen, uint8_t *mac, bool_t initiator);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
