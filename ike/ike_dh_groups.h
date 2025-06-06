/**
 * @file ike_dh_groups.h
 * @brief Diffie-Hellman groups
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

#ifndef _IKE_DH_GROUPS_H
#define _IKE_DH_GROUPS_H

//Dependencies
#include "ike/ike.h"
#include "pkc/dh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Diffie-Hellman group
 **/

typedef struct
{
   const char_t *name;                           ///<Group name
   const uint8_t p[IKE_MAX_DH_MODULUS_SIZE / 8]; ///<Prime modulus
   size_t pLen;                                  ///<Length of the prime modulus, in bytes
   uint8_t g;                                    ///<Generator
} IkeDhGroup;


//Diffie-Hellman groups
extern const IkeDhGroup ikeDhGroup1;
extern const IkeDhGroup ikeDhGroup5;
extern const IkeDhGroup ikeDhGroup14;
extern const IkeDhGroup ikeDhGroup15;
extern const IkeDhGroup ikeDhGroup16;
extern const IkeDhGroup ikeDhGroup17;
extern const IkeDhGroup ikeDhGroup18;

//Diffie-Hellman group related functions
const IkeDhGroup *ikeGetDhGroup(uint16_t groupNum);
error_t ikeLoadDhParams(DhParameters *params, uint16_t groupNum);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
