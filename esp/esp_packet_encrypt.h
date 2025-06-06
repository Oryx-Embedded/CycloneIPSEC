/**
 * @file esp_packet_encrypt.h
 * @brief ESP packet encryption
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

#ifndef _ESP_PACKET_ENCRYPT_H
#define _ESP_PACKET_ENCRYPT_H

//Dependencies
#include "ipsec/ipsec.h"
#include "esp/esp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ESP related functions
error_t espEncryptPacket(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, uint8_t *payload, size_t *payloadLen,
   uint8_t nextHeader);

error_t espComputeChecksum(IpsecContext *context, IpsecSadEntry *sa,
   const EspHeader *espHeader, const uint8_t *payload, size_t length,
   uint8_t *icv);

size_t espComputePadLength(IpsecSadEntry *sa, size_t length);

size_t espAddTrailer(IpsecSadEntry *sa, uint8_t *data, size_t length,
   uint8_t nextHeader);

void espGenerateIv(uint8_t *iv);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
