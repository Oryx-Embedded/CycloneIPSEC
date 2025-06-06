/**
 * @file ike_fsm.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ike/ike_fsm.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_message_format.h"
#include "ike/ike_misc.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Update IKE SA state
 * @param[in] sa Pointer to the IKE SA
 * @param[in] newState New IKE SA state to switch to
 **/

void ikeChangeSaState(IkeSaEntry *sa, IkeSaState newState)
{
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Successful IKE SA creation?
   if(sa->state < IKE_SA_STATE_OPEN &&
      newState == IKE_SA_STATE_OPEN)
   {
      //IKE SA uses secret keys that should be used only for a limited amount
      //of time (refer to RFC 7296, section 2.8)
      sa->lifetimeStart = osGetSystemTime();

      //If the two ends have the same lifetime policies, it is possible that
      //both will initiate a rekeying at the same time. To reduce the
      //probability of this happening, the timing of rekeying requests should
      //be jittered (refer to RFC 7296, section 2.8.1)
      sa->lifetime = ikeRandomizeDelay(context, context->saLifetime);

      //Reauthentication period
      sa->reauthPeriod = ikeRandomizeDelay(context, context->reauthPeriod);
   }

#if (IKE_DPD_SUPPORT == ENABLED)
   //The dead peer detection mechanism is used to perform a liveness check
   if((sa->state < IKE_SA_STATE_OPEN || sa->state == IKE_SA_STATE_DPD_RESP) &&
      newState == IKE_SA_STATE_OPEN)
   {
      //Get current time
      sa->dpdStart = osGetSystemTime();
      //Set dead peer detection period
      sa->dpdPeriod = ikeRandomizeDelay(context, context->dpdPeriod);
   }
#endif

   //Set time stamp
   sa->timestamp = osGetSystemTime();
   //Set initial retransmission timeout
   sa->timeout = IKE_INIT_TIMEOUT;
   //Reset retransmission counter
   sa->retransmitCount = 0;

   //Switch to the new state
   sa->state = newState;
}


/**
 * @brief Update Child SA state
 * @param[in] childSa Pointer to the Child SA
 * @param[in] newState New Child SA state to switch to
 **/

void ikeChangeChildSaState(IkeChildSaEntry *childSa, IkeChildSaState newState)
{
   //Successful Child SA creation?
   if(childSa->state < IKE_CHILD_SA_STATE_OPEN &&
      newState == IKE_CHILD_SA_STATE_OPEN)
   {
      //ESP and AH SA use secret keys that should be used only for a limited
      //amount of time
      childSa->lifetimeStart = osGetSystemTime();
   }

   //Switch to the new state
   childSa->state = newState;
}


/**
 * @brief IKE event processing
 * @param[in] context Pointer to the IKE context
 **/

void ikeProcessEvents(IkeContext *context)
{
   error_t error;
   uint_t i;
   systime_t time;
   IkeSaEntry *sa;
   IkeChildSaEntry *childSa;

   //Get current time
   time = osGetSystemTime();

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      sa = &context->sa[i];

      //Check the state of the IKE SA
      if(sa->state == IKE_SA_STATE_INIT_REQ)
      {
         //Communication using IKE always begins with IKE_SA_INIT and IKE_AUTH
         //exchanges. These initial exchanges normally consist of four messages
         error = ikeProcessSaInitEvent(sa);

         //Check status code code
         if(error)
         {
            //Delete the IKE SA
            ikeDeleteSaEntry(sa);
         }
      }
      else if(sa->state == IKE_SA_STATE_AUTH_REQ)
      {
         //Delete half-open IKE SAs after timeout
         if(timeCompare(time, sa->timestamp + IKE_HALF_OPEN_TIMEOUT) >= 0)
         {
            //Debug message
            TRACE_INFO("Deleting half-open IKE SA...\r\n");
            //Delete the IKE SA
            ikeDeleteSaEntry(sa);
         }
      }
      else if(sa->state == IKE_SA_STATE_OPEN)
      {
         //Process IKE SA events
         ikeProcessSaEvents(sa);
      }
      else if(sa->state == IKE_SA_STATE_INIT_RESP ||
         sa->state == IKE_SA_STATE_AUTH_RESP ||
         sa->state == IKE_SA_STATE_DPD_RESP ||
         sa->state == IKE_SA_STATE_REKEY_RESP ||
         sa->state == IKE_SA_STATE_DELETE_RESP ||
         sa->state == IKE_SA_STATE_CREATE_CHILD_RESP ||
         sa->state == IKE_SA_STATE_REKEY_CHILD_RESP ||
         sa->state == IKE_SA_STATE_DELETE_CHILD_RESP ||
         sa->state == IKE_SA_STATE_AUTH_FAILURE_RESP)
      {
         //Check current time
         if(timeCompare(time, sa->timestamp + sa->timeout) >= 0)
         {
            //The initiator must retransmit the request until it either receives
            //a corresponding response or deems the IKE SA to have failed (refer
            //to RFC 7296, section 2.1)
            if(sa->retransmitCount < IKE_MAX_RETRIES)
            {
               //A retransmission from the initiator must be bitwise identical
               //to the original request
               ikeRetransmitRequest(sa);
            }
            else
            {
               //The initiator discards all state associated with the IKE SA
               //and any Child SAs that were negotiated using that IKE SA
               ikeDeleteSaEntry(sa);
            }
         }
      }
      else
      {
         //Just for sanity
      }
   }

   //Loop through Child SA entries
   for(i = 0; i < context->numChildSaEntries; i++)
   {
      //Point to the current Child SA
      childSa = &context->childSa[i];

      //Check the Child SA should be created
      if(childSa->state == IKE_CHILD_SA_STATE_INIT &&
         childSa->sa == NULL)
      {
         ikeProcessChildSaInitEvent(childSa);
      }
   }
}


/**
 * @brief IKE SA event processing
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaEvents(IkeSaEntry *sa)
{
   error_t error;
   uint_t i;
   systime_t time;
   IkeContext *context;
   IkeChildSaEntry *childSa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //Get current time
   time = osGetSystemTime();

#if (IKE_DPD_SUPPORT == ENABLED)
   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_OPEN)
   {
      //Check whether the dead peer detection mechanism is enabled
      if(sa->dpdPeriod != 0)
      {
         //Check whether the DPD period has expired
         if(timeCompare(time, sa->dpdStart + sa->dpdPeriod) >= 0)
         {
            //If no cryptographically protected messages have been received on
            //an IKE SA or any of its Child SAs recently, the system needs to
            //perform a liveness check in order to prevent sending messages to
            //a dead peer liveness of the other endpoint to avoid black holes
            error = ikeProcessSaDpdEvent(sa);
         }
      }
   }
#endif

   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_OPEN && !error)
   {
      //Check whether reauthentication is enabled
      if(sa->reauthPeriod != 0)
      {
         //Reauthentication has to be initiated by the same party as the
         //original IKE SA. IKEv2 does not currently allow the responder to
         //request reauthentication (refer to RFC 7296, section 2.8.3)
         if(sa->originalInitiator)
         {
            //Check whether the reauthentication period has expired
            if(timeCompare(time, sa->lifetimeStart + sa->reauthPeriod) >= 0)
            {
               //IKEv2 does not have any special support for reauthentication.
               //Reauthentication is done by creating a new IKE SA from scratch,
               //creating new Child SAs within the new IKE SA, and finally
               //deleting the old IKE SA
               sa->reauthRequest = TRUE;
            }

            //Check whether reauthentication should be initiated
            if(sa->reauthRequest && !sa->reauthPending)
            {
               //Initiate reauthentication
               error = ikeProcessSaReauthEvent(sa);
            }
         }
      }
   }

   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_OPEN && !error)
   {
      //Check whether the IKE SA should be closed
      if(sa->deleteRequest)
      {
         //Close the specified IKE SA
         error = ikeProcessSaDeleteEvent(sa);
      }
   }

   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_OPEN && !error)
   {
      //Loop through Child SA entries
      for(i = 0; i < context->numChildSaEntries && !error; i++)
      {
         //Point to the current Child SA
         childSa = &context->childSa[i];

         //Valid Child SA?
         if(childSa->state != IKE_CHILD_SA_STATE_CLOSED &&
            childSa->sa == sa)
         {
            //Process Child SA events
            error = ikeProcessChildSaEvents(childSa);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Child SA event processing
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeProcessChildSaEvents(IkeChildSaEntry *childSa)
{
   error_t error;
   IkeSaEntry *sa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE SA
   sa = childSa->sa;


   //Check the state of the IKE SA
   if(sa->state == IKE_SA_STATE_OPEN && !error)
   {
      //Check whether the Child SA should be closed
      if(childSa->deleteRequest)
      {
         //Close the specified Child SA
         error = ikeProcessChildSaDeleteEvent(childSa);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Handle IKE SA creation event
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaInitEvent(IkeSaEntry *sa)
{
   error_t error;
   bool_t valid;
   IkeContext *context;

   //Point to the IKE context
   context = sa->context;

   //Initialize flag
   valid = FALSE;

   //Valid entity's ID
   if(context->idType != IKE_ID_TYPE_INVALID)
   {
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
      //Pre-shared key authentication?
      if(context->pskLen > 0)
      {
         valid = TRUE;
      }
#endif
   }
   else
   {
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //Certificate authentication?
      if(context->certChain != NULL && context->certChainLen > 0)
      {
         valid = TRUE;
      }
#endif
   }

   //Valid credentials?
   if(valid)
   {
      //Each endpoint chooses one of the two SPIs and must choose them so as to
      //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
      error = ikeGenerateSaSpi(sa, sa->initiatorSpi);

      //Check status code
      if(!error)
      {
         //Nonces used in IKEv2 must be randomly chosen and must be at least
         //128 bits in size (refer to RFC 7296, section 2.10)
         error = ikeGenerateNonce(context, sa->initiatorNonce,
            &sa->initiatorNonceLen);
      }

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = ikeGenerateDhKeyPair(sa);
      }

      //Check status code
      if(!error)
      {
         //The first exchange of an IKE session, IKE_SA_INIT, negotiates security
         //parameters for the IKE SA, sends nonces, and sends Diffie-Hellman values
         error = ikeSendIkeSaInitRequest(sa);
      }
   }
   else
   {
      //No valid credentials provided
      error = ERROR_NOT_CONFIGURED;
   }

   //Return status code
   return error;
}


/**
 * @brief Handle IKE SA dead peer detection event
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaDpdEvent(IkeSaEntry *sa)
{
   //If no cryptographically protected messages have been received on an
   //IKE SA or any of its Child SAs recently, the system needs to perform
   //a liveness check in order to prevent sending messages to a dead peer
   //(refer to RFC 7296, section 2.4)
   ikeChangeSaState(sa, IKE_SA_STATE_DPD_REQ);

   //An INFORMATIONAL request with no payloads is commonly used as a check
   //for liveness (refer to RFC 7296, section 1)
   return ikeSendInfoRequest(sa);
}


/**
 * @brief Handle IKE SA rekeying event
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaRekeyEvent(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;
   IkeSaEntry *newSa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;

   //Create a new IKE SA
   newSa = ikeCreateSaEntry(context);

   //Successful IKE SA creation?
   if(newSa != NULL)
   {
      //Initialize IKE SA
      newSa->remoteIpAddr = sa->remoteIpAddr;
      newSa->remotePort = sa->remotePort;

      //The initiator of the rekey exchange is the new "original initiator"
      //of the new IKE SA (refer to RFC 7296, section 1.3.2)
      newSa->originalInitiator = TRUE;

      //Select the preferred Diffie-Hellman group number
      newSa->dhGroupNum = context->preferredDhGroupNum;

      //Each endpoint chooses one of the two SPIs and must choose them so as to
      //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
      error = ikeGenerateSaSpi(newSa, newSa->initiatorSpi);

      //Check status code
      if(!error)
      {
         //Nonces used in IKEv2 must be randomly chosen and must be at least
         //128 bits in size (refer to RFC 7296, section 2.10)
         error = ikeGenerateNonce(context, newSa->initiatorNonce,
            &newSa->initiatorNonceLen);
      }

      //Check status code
      if(!error)
      {
         //Generate an ephemeral key pair
         error = ikeGenerateDhKeyPair(newSa);
      }

      //Check status code
      if(!error)
      {
         //Acknowledge request
         sa->rekeyRequest = FALSE;

         //Attach the newly created IKE SA
         sa->newSa = newSa;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_REQ);

         //To rekey an IKE SA, establish a new equivalent IKE SA with the peer to
         //whom the old IKE SA is shared using a CREATE_CHILD_SA within the existing
         //IKE SA (refer to RFC 7296, section 2.8)
         ikeSendCreateChildSaRequest(sa, sa->childSa);
      }
   }
   else
   {
      //Failed to create IKE SA
   }

   //Return status code
   return error;
}


/**
 * @brief Handle IKE SA reauthentication event
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaReauthEvent(IkeSaEntry *sa)
{
   error_t error;
   IkeContext *context;
   IkeSaEntry *newSa;
   IkeChildSaEntry *childSa;
   IkeChildSaEntry *newChildSa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = sa->context;
   //Point to the Child SA
   childSa = sa->childSa;

   //Sanity check
   if(childSa != NULL)
   {
      //Acknowledge request
      sa->reauthPending = TRUE;

      //Create a new IKE SA
      newSa = ikeCreateSaEntry(context);

      //Successful IKE SA creation?
      if(newSa != NULL)
      {
         //Create a new Child SA
         newChildSa = ikeCreateChildSaEntry(context);

         //Successful IKE SA creation?
         if(newChildSa != NULL)
         {
            //Initialize IKE SA
            newSa->remoteIpAddr = sa->remoteIpAddr;
            newSa->remotePort = sa->remotePort;
            newSa->remoteIpAddr = sa->remoteIpAddr;
            newSa->remotePort = sa->remotePort;
            newSa->childSa = newChildSa;

            //The initiator of the rekey exchange is the new "original initiator"
            //of the new IKE SA (refer to RFC 7296, section 1.3.2)
            newSa->originalInitiator = TRUE;

            //Select the preferred Diffie-Hellman group number
            newSa->dhGroupNum = context->preferredDhGroupNum;

            //Initialize Child SA
            newChildSa->sa = newSa;
            newChildSa->mode = childSa->mode;
            newChildSa->protocol = childSa->protocol;
            newChildSa->initiator = TRUE;
            newChildSa->selector = childSa->selector;

            //Each endpoint chooses one of the two SPIs and must choose them so as to
            //be unique identifiers of an IKE SA (refer to RFC 7296, section 2.6)
            error = ikeGenerateSaSpi(newSa, newSa->initiatorSpi);

            //Check status code
            if(!error)
            {
               //Nonces used in IKEv2 must be randomly chosen and must be at least
               //128 bits in size (refer to RFC 7296, section 2.10)
               error = ikeGenerateNonce(context, newSa->initiatorNonce,
                  &newSa->initiatorNonceLen);
            }

            //Check status code
            if(!error)
            {
               //Generate an ephemeral key pair
               error = ikeGenerateDhKeyPair(newSa);
            }

            //Check status code
            if(!error)
            {
               //The first exchange of an IKE session, IKE_SA_INIT, negotiates security
               //parameters for the IKE SA, sends nonces, and sends Diffie-Hellman values
               error = ikeSendIkeSaInitRequest(newSa);
            }

            //Check status code
            if(!error)
            {
               //Attach the old IKE SA
               newSa->oldSa = sa;
            }
            else
            {
               //Failed to initiate reauthentication
               ikeDeleteSaEntry(newSa);
            }
         }
         else
         {
            //Failed to create Child SA
            ikeDeleteSaEntry(newSa);
            //Report en error
            error = ERROR_OUT_OF_RESOURCES;
         }
      }
      else
      {
         //Failed to create IKE SA
         error = ERROR_OUT_OF_RESOURCES;
      }

      //Failed to initiate reauthentication?
      if(error)
      {
         //Close the old IKE SA
         sa->deleteRequest = TRUE;
         //Notify the IKE context that the IKE SA should be closed
         osSetEvent(&context->event);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Handle IKE SA deletion event
 * @param[in] sa Pointer to the IKE SA
 * @return Error code
 **/

error_t ikeProcessSaDeleteEvent(IkeSaEntry *sa)
{
   //Acknowledge request
   sa->deleteRequest = FALSE;
   sa->childSa = NULL;

   //Update the state of the IKE SA
   ikeChangeSaState(sa, IKE_SA_STATE_DELETE_REQ);

   //To delete an SA, an INFORMATIONAL exchange with one or more Delete payloads
   //is sent listing the SPIs of the SAs to be deleted
   return ikeSendInfoRequest(sa);
}


/**
 * @brief Handle Child SA creation event
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeProcessChildSaInitEvent(IkeChildSaEntry *childSa)
{
   error_t error;
   IkeContext *context;
   IkeSaEntry *sa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = childSa->context;

   {
      //Create a new IKE SA
      sa = ikeCreateSaEntry(context);

      //Successful IKE SA creation?
      if(sa != NULL)
      {
         //Initialize IKE SA
         sa->remoteIpAddr = childSa->remoteIpAddr;
         sa->remotePort = IKE_PORT;
         sa->childSa = childSa;

         //The original initiator always refers to the party who initiated the
         //exchange (refer to RFC 7296, section 2.2)
         sa->originalInitiator = TRUE;

         //Select the preferred Diffie-Hellman group number
         sa->dhGroupNum = context->preferredDhGroupNum;

         //Attach the newly created IKE SA to the Child SA
         childSa->sa = sa;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_INIT_REQ);
         //Notify the IKE context that the IKE SA should be created
         osSetEvent(&context->event);
      }
      else
      {
         //Failed to create IKE SA
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Handle Child SA rekeying event
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeProcessChildSaRekeyEvent(IkeChildSaEntry *childSa)
{
   error_t error;
   IkeSaEntry *sa;
   IkeContext *context;
   IkeChildSaEntry *newChildSa;

   //Initialize status code
   error = NO_ERROR;

   //Point to the IKE context
   context = childSa->context;
   //Point to the IKE SA
   sa = childSa->sa;

   //Create a new Child SA
   newChildSa = ikeCreateChildSaEntry(context);

   //Successful Child SA creation?
   if(newChildSa != NULL)
   {
      //Initialize Child SA
      newChildSa->sa = sa;
      newChildSa->oldChildSa = childSa;
      newChildSa->protocol = childSa->protocol;
      newChildSa->mode = childSa->mode;
      newChildSa->initiator = TRUE;
      newChildSa->selector = childSa->selector;

      //Generate a new SPI for the Child SA
      error = ikeGenerateChildSaSpi(newChildSa, newChildSa->localSpi);

      //Check status code
      if(!error)
      {
         //Nonces used in IKEv2 must be randomly chosen and must be at least
         //128 bits in size (refer to RFC 7296, section 2.10)
         error = ikeGenerateNonce(context, newChildSa->initiatorNonce,
            &newChildSa->initiatorNonceLen);
      }

      //Check status code
      if(!error)
      {
         //Acknowledge request
         childSa->rekeyRequest = FALSE;

         //Attach the newly created Child SA to the IKE SA
         sa->childSa = newChildSa;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_CHILD_REQ);
         //Update the state of the Child SA
         ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_REKEY);

         //To rekey a Child SA within an existing IKE SA, create a new
         //equivalent SA, and when the new one is established, delete the
         //old one
         error = ikeSendCreateChildSaRequest(sa, newChildSa);
      }
   }
   else
   {
      //Failed to create Child SA
   }

   //Return status code
   return error;
}


/**
 * @brief Handle Child SA deletion event
 * @param[in] childSa Pointer to the Child SA
 * @return Error code
 **/

error_t ikeProcessChildSaDeleteEvent(IkeChildSaEntry *childSa)
{
   IkeSaEntry *sa;

   //Point to the IKE SA
   sa = childSa->sa;

   //Acknowledge request
   childSa->deleteRequest = FALSE;

   //Attach the Child SA to the IKE SA
   sa->childSa = childSa;

   //Update the state of the IKE SA
   ikeChangeSaState(sa, IKE_SA_STATE_DELETE_CHILD_REQ);
   //Update the state of the Child SA
   ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_DELETE);

   //To delete an SA, an INFORMATIONAL exchange with one or more Delete payloads
   //is sent listing the SPIs of the SAs to be deleted
   return ikeSendInfoRequest(sa);
}

#endif
