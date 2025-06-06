/**
 * @file ike_message_format.h
 * @brief IKE message formatting
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

#ifndef _IKE_MESSAGE_FORMAT_H
#define _IKE_MESSAGE_FORMAT_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
error_t ikeSendIkeSaInitRequest(IkeSaEntry *sa);
error_t ikeSendIkeSaInitResponse(IkeSaEntry *sa);
error_t ikeSendIkeAuthRequest(IkeSaEntry *sa);
error_t ikeSendIkeAuthResponse(IkeSaEntry *sa);
error_t ikeSendCreateChildSaRequest(IkeSaEntry *sa, IkeChildSaEntry *childSa);
error_t ikeSendCreateChildSaResponse(IkeSaEntry *sa, IkeChildSaEntry *childSa);
error_t ikeSendInfoRequest(IkeSaEntry *sa);
error_t ikeSendInfoResponse(IkeSaEntry *sa);

error_t ikeSendErrorResponse(IkeContext *context, uint8_t *message,
   size_t length);

error_t ikeFormatIkeSaInitRequest(IkeSaEntry *sa, uint8_t *p, size_t *length);
error_t ikeFormatIkeSaInitResponse(IkeSaEntry *sa, uint8_t *p, size_t *length);
error_t ikeFormatIkeAuthRequest(IkeSaEntry *sa, uint8_t *p, size_t *length);
error_t ikeFormatIkeAuthResponse(IkeSaEntry *sa, uint8_t *p, size_t *length);

error_t ikeFormatCreateChildSaRequest(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *length);

error_t ikeFormatCreateChildSaResponse(IkeSaEntry *sa, IkeChildSaEntry *childSa,
   uint8_t *p, size_t *length);

error_t ikeFormatInfoRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length);

error_t ikeFormatInfoResponse(IkeSaEntry *sa, uint8_t *p,
   size_t *length);

error_t ikeFormatErrorResponse(IkeHeader *requestHeader, uint8_t *p,
   size_t *length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
