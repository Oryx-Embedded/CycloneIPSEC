/**
 * @file ipsec.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL IPSEC_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_misc.h"
#include "debug.h"

//Check IPsec library configuration
#if (IPSEC_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains IPsec settings
 **/

void ipsecGetDefaultSettings(IpsecSettings *settings)
{
   //Pseudo-random number generator
   settings->prngAlgo = NULL;
   settings->prngContext = NULL;

   //Security Policy Database (SPD)
   settings->spdEntries = NULL;
   settings->numSpdEntries = 0;

   //Security Association Database (SAD)
   settings->sadEntries = NULL;
   settings->numSadEntries = 0;

   //Peer Authorization Database (PAD)
   settings->padEntries = NULL;
   settings->numPadEntries = 0;
}


/**
 * @brief IPsec service initialization
 * @param[in] context Pointer to the IPsec context
 * @param[in] settings IPsec specific settings
 * @return Error code
 **/

error_t ipsecInit(IpsecContext *context, const IpsecSettings *settings)
{
   //Debug message
   TRACE_INFO("Initializing IPsec...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

#if (ESP_SUPPORT == ENABLED && ESP_CBC_SUPPORT == ENABLED)
   if(settings->prngAlgo == NULL || settings->prngContext == NULL)
      return ERROR_INVALID_PARAMETER;
#endif

   if(settings->spdEntries == NULL || settings->numSpdEntries == 0)
      return ERROR_INVALID_PARAMETER;

   if(settings->sadEntries == NULL || settings->numSadEntries == 0)
      return ERROR_INVALID_PARAMETER;

   if(settings->padEntries == NULL || settings->numPadEntries == 0)
      return ERROR_INVALID_PARAMETER;

   //Clear the IPsec context
   osMemset(context, 0, sizeof(IpsecContext));

   //Pseudo-random number generator
   context->prngAlgo = settings->prngAlgo;
   context->prngContext = settings->prngContext;

   //Security Policy Database (SPD)
   context->spd = settings->spdEntries;
   context->numSpdEntries = settings->numSpdEntries;

   //Security Association Database (SAD)
   context->sad = settings->sadEntries;
   context->numSadEntries = settings->numSadEntries;

   //Peer Authorization Database (PAD)
   context->pad = settings->padEntries;
   context->numPadEntries = settings->numPadEntries;

   //Attach IPsec context
   netContext.ipsecContext = context;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Set entry at specified index in SPD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @param[in] params Pointer to the structure describing the SPD entry
 * @return Error code
 **/

error_t ipsecSetSpdEntry(IpsecContext *context, uint_t index,
   IpsecSpdEntry *params)
{
   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of SPD entries that can be loaded
   if(index >= context->numSpdEntries)
      return ERROR_INVALID_PARAMETER;

   //Update SPD entry
   osMemcpy(&context->spd[index], params, sizeof(IpsecSpdEntry));

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Clear entry at specified index in SPD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @return Error code
 **/

error_t ipsecClearSpdEntry(IpsecContext *context, uint_t index)
{
   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of SPD entries
   if(index >= context->numSpdEntries)
      return ERROR_INVALID_PARAMETER;

   //Clear SPD entry
   osMemset(&context->spd[index], 0, sizeof(IpsecSpdEntry));

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Set entry at specified index in SAD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @param[in] params Pointer to the structure describing the SAD entry
 * @return Error code
 **/

error_t ipsecSetSadEntry(IpsecContext *context, uint_t index,
   IpsecSadEntry *params)
{
   IpsecSadEntry *entry;

   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of SAD entries that can be loaded
   if(index >= context->numSadEntries)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the integrity protection key
   if(params->authKeyLen > IPSEC_MAX_AUTH_KEY_LEN)
      return ERROR_INVALID_KEY_LENGTH;

#if (ESP_SUPPORT == ENABLED)
   //Check the length of the encryption key
   if((params->encKeyLen + params->saltLen) > IPSEC_MAX_ENC_KEY_LEN)
      return ERROR_INVALID_KEY_LENGTH;
#endif

   //Point to the SAD entry
   entry = &context->sad[index];

   //Update SAD entry
   entry->direction = params->direction;
   entry->mode = params->mode;
   entry->protocol = params->protocol;
   entry->selector = params->selector;
   entry->spi = params->spi;
   entry->authCipherAlgo = params->authCipherAlgo;
   entry->authHashAlgo = params->authHashAlgo;
   entry->authKeyLen = params->authKeyLen;
   entry->icvLen = params->icvLen;
   entry->esn = params->esn;
   entry->seqNum = params->seqNum;
   entry->antiReplayEnabled = params->antiReplayEnabled;

   //Set integrity protection key
   osMemcpy(entry->authKey, params->authKey, params->authKeyLen);

#if (ESP_SUPPORT == ENABLED)
   //Set encryption parameters
   entry->cipherMode = params->cipherMode;
   entry->cipherAlgo = params->cipherAlgo;
   entry->encKeyLen = params->encKeyLen;
   entry->saltLen = params->saltLen;
   entry->ivLen = params->ivLen;

   //Set encryption key
   osMemcpy(entry->encKey, params->encKey, params->encKeyLen +
      params->saltLen);

   //Check encryption mode
   if(params->protocol == IPSEC_PROTOCOL_ESP &&
      params->cipherMode != CIPHER_MODE_CBC)
   {
      //Copy initialization vector
      osMemcpy(entry->iv, params->iv, params->ivLen);
   }
#endif

   //ESP and AH SA use secret keys that should be used only for a limited
   //amount of time
   entry->lifetimeStart = osGetSystemTime();

   //Update the state of the SAD entry
   entry->state = IPSEC_SA_STATE_OPEN;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Clear entry at specified index in SAD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @return Error code
 **/

error_t ipsecClearSadEntry(IpsecContext *context, uint_t index)
{
   IpsecSadEntry *entry;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of SAD entries
   if(index >= context->numSadEntries)
      return ERROR_INVALID_PARAMETER;

   //Point to the SAD entry
   entry = &context->sad[index];

   //Clear SAD entry
   entry->direction = IPSEC_DIR_INVALID;
   entry->mode = IPSEC_MODE_INVALID;
   entry->protocol = IPSEC_PROTOCOL_INVALID;
   entry->spi = 0;
   entry->authCipherAlgo = NULL;
   entry->authHashAlgo = NULL;
   entry->authKeyLen = 0;
   entry->icvLen = 0;
   entry->esn = 0;
   entry->seqNum = 0;
   entry->antiReplayEnabled = FALSE;

   //Clear selector
   osMemset(&entry->selector, 0, sizeof(IpsecSelector));
   //Clear integrity protection key
   osMemset(entry->authKey, 0, IPSEC_MAX_AUTH_KEY_LEN);

#if (ESP_SUPPORT == ENABLED)
   //Clear encryption parameters
   entry->cipherMode = CIPHER_MODE_NULL;
   entry->cipherAlgo = NULL;
   entry->encKeyLen = 0;
   entry->saltLen = 0;
   entry->ivLen = 0;

   //Clear encryption key
   osMemset(entry->encKey, 0, IPSEC_MAX_ENC_KEY_LEN);
#endif

   //Mark the entry as closed
   entry->state = IPSEC_SA_STATE_CLOSED;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Set entry at specified index in PAD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @param[in] params Pointer to the structure describing the PAD entry
 * @return Error code
 **/

error_t ipsecSetPadEntry(IpsecContext *context, uint_t index,
   IpsecPadEntry *params)
{
   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of PAD entries that can be loaded
   if(index >= context->numPadEntries)
      return ERROR_INVALID_PARAMETER;

   //Update PAD entry
   osMemcpy(&context->pad[index], params, sizeof(IpsecPadEntry));

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Clear entry at specified index in PAD database
 * @param[in] context Pointer to the IPsec context
 * @param[in] index Zero-based index identifying a given entry
 * @return Error code
 **/

error_t ipsecClearPadEntry(IpsecContext *context, uint_t index)
{
   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of PAD entries
   if(index >= context->numPadEntries)
      return ERROR_INVALID_PARAMETER;

   //Clear PAD entry
   osMemset(&context->pad[index], 0, sizeof(IpsecPadEntry));

   //Sucessful processing
   return NO_ERROR;
}

#endif
