/**
 * @file ike_key_exchange.h
 * @brief Diffie-Hellman key exchange
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

#ifndef _IKE_KEY_EXCHANGE_H
#define _IKE_KEY_EXCHANGE_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
void ikeInitDhContext(IkeSaEntry *sa);
void ikeFreeDhContext(IkeSaEntry *sa);

error_t ikeGenerateDhKeyPair(IkeSaEntry *sa);
error_t ikeComputeDhSharedSecret(IkeSaEntry *sa);
error_t ikeFormatDhPublicKey(IkeSaEntry *sa, uint8_t *p, size_t *written);
error_t ikeParseDhPublicKey(IkeSaEntry *sa, const uint8_t *p, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
