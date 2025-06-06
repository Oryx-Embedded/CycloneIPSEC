/**
 * @file ike_key_material.h
 * @brief Key material generation
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

#ifndef _IKE_KEY_MATERIAL_H
#define _IKE_KEY_MATERIAL_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
error_t ikeGenerateSaKeyMaterial(IkeSaEntry *sa, IkeSaEntry *oldSa);
error_t ikeGenerateChildSaKeyMaterial(IkeChildSaEntry *childSa);

error_t ikeComputePrf(IkeSaEntry *sa, const uint8_t *k, size_t kLen,
   const void *s, size_t sLen, uint8_t *output);

error_t ikeComputePrfPlus(IkeSaEntry *sa, const uint8_t *k, size_t kLen,
   const uint8_t *s, size_t sLen, uint8_t *output, size_t outputLen);

error_t ikeInitPrf(IkeSaEntry *sa, const uint8_t *vk, size_t vkLen);
void ikeUpdatePrf(IkeSaEntry *sa, const uint8_t *s, size_t sLen);
error_t ikeFinalizePrf(IkeSaEntry *sa, uint8_t *output);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
