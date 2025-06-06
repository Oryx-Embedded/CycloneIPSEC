/**
 * @file ike_fsm.h
 * @brief IKEv2 finite state machine
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

#ifndef _IKE_FSM_H
#define _IKE_FSM_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKEv2 related functions
void ikeChangeSaState(IkeSaEntry *sa, IkeSaState newState);
void ikeChangeChildSaState(IkeChildSaEntry *childSa, IkeChildSaState newState);

void ikeProcessEvents(IkeContext *context);
error_t ikeProcessSaEvents(IkeSaEntry *sa);
error_t ikeProcessChildSaEvents(IkeChildSaEntry *childSa);

error_t ikeProcessSaInitEvent(IkeSaEntry *sa);
error_t ikeProcessSaDpdEvent(IkeSaEntry *sa);
error_t ikeProcessSaRekeyEvent(IkeSaEntry *sa);
error_t ikeProcessSaReauthEvent(IkeSaEntry *sa);
error_t ikeProcessSaDeleteEvent(IkeSaEntry *sa);

error_t ikeProcessChildSaInitEvent(IkeChildSaEntry *childSa);
error_t ikeProcessChildSaRekeyEvent(IkeChildSaEntry *childSa);
error_t ikeProcessChildSaDeleteEvent(IkeChildSaEntry *childSa);

error_t ikeRetransmitRequest(IkeSaEntry *sa);
error_t ikeRetransmitResponse(IkeSaEntry *sa);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
