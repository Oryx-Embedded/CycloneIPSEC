/**
 * @file ike_message_encrypt.h
 * @brief IKE message encryption
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

#ifndef _IKE_MESSAGE_ENCRYPT_H
#define _IKE_MESSAGE_ENCRYPT_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
error_t ikeEncryptMessage(IkeSaEntry *sa, uint8_t *message, size_t *messageLen);

error_t ikeComputeChecksum(IkeSaEntry *sa, const uint8_t *message,
   size_t length, uint8_t *icv);

size_t ikePadPayload(IkeSaEntry *sa, uint8_t *data, size_t length);

void ikeGenerateIv(uint8_t *iv);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
