/**
 * @file ike.c
 * @brief IKEv2 (Internet Key Exchange Protocol)
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
#include "ike/ike_algorithms.h"
#include "ike/ike_certificate.h"
#include "ike/ike_message_parse.h"
#include "ike/ike_misc.h"
#include "ike/ike_debug.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains IKE settings
 **/

void ikeGetDefaultSettings(IkeSettings *settings)
{
   //Default task parameters
   settings->task = OS_TASK_DEFAULT_PARAMS;
   settings->task.stackSize = IKE_STACK_SIZE;
   settings->task.priority = IKE_PRIORITY;

   //Underlying network interface
   settings->interface = NULL;

   //Pseudo-random number generator
   settings->prngAlgo = NULL;
   settings->prngContext = NULL;

   //IKE SA entries
   settings->saEntries = NULL;
   settings->numSaEntries = 0;

   //Child SA entries
   settings->childSaEntries = NULL;
   settings->numChildSaEntries = 0;

   //Lifetime of IKE SAs
   settings->saLifetime = IKE_DEFAULT_SA_LIFETIME;
   //Lifetime of Child SAs
   settings->childSaLifetime = IKE_DEFAULT_CHILD_SA_LIFETIME;
   //Reauthentication period
   settings->reauthPeriod = 0;

#if (IKE_DPD_SUPPORT == ENABLED)
   //Dead peer detection period
   settings->dpdPeriod = 0;
#endif
#if (IKE_COOKIE_SUPPORT == ENABLED)
   //Cookie generation callback function
   settings->cookieGenerateCallback = NULL;
   //Cookie verification callback function
   settings->cookieVerifyCallback = NULL;
#endif
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   //Certificate verification callback function
   settings->certVerifyCallback = NULL;
#endif
}


/**
 * @brief IKE service initialization
 * @param[in] context Pointer to the IKE context
 * @param[in] settings IKE specific settings
 * @return Error code
 **/

error_t ikeInit(IkeContext *context, const IkeSettings *settings)
{
   error_t error;

   //Debug message
   TRACE_INFO("Initializing IKE...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   if(settings->prngAlgo == NULL || settings->prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   if(settings->saEntries == NULL || settings->numSaEntries == 0)
      return ERROR_INVALID_PARAMETER;

   if(settings->childSaEntries == NULL || settings->numChildSaEntries == 0)
      return ERROR_INVALID_PARAMETER;

   //Clear the IKE context
   osMemset(context, 0, sizeof(IkeContext));

   //Initialize task parameters
   context->taskParams = settings->task;
   context->taskId = OS_INVALID_TASK_ID;

   //Underlying network interface
   context->interface = settings->interface;

   //Pseudo-random number generator
   context->prngAlgo = settings->prngAlgo;
   context->prngContext = settings->prngContext;

   //IKE SA entries
   context->sa = settings->saEntries;
   context->numSaEntries = settings->numSaEntries;

   //Child SA entries
   context->childSa = settings->childSaEntries;
   context->numChildSaEntries = settings->numChildSaEntries;

   //Lifetime of IKE SAs
   context->saLifetime = settings->saLifetime;
   //Lifetime of Child SAs
   context->childSaLifetime = settings->childSaLifetime;
   //Reauthentication period
   context->reauthPeriod = settings->reauthPeriod;

#if (IKE_DPD_SUPPORT == ENABLED)
   //Dead peer detection period
   context->dpdPeriod = settings->dpdPeriod;
#endif
#if (IKE_COOKIE_SUPPORT == ENABLED)
   //Cookie generation callback function
   context->cookieGenerateCallback = settings->cookieGenerateCallback;
   //Cookie verification callback function
   context->cookieVerifyCallback = settings->cookieVerifyCallback;
#endif
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   //Certificate verification callback function
   context->certVerifyCallback = settings->certVerifyCallback;
#endif

   //Save the preferred Diffie-Hellman group number
   context->preferredDhGroupNum = ikeSelectDefaultDhGroup();

   //Attach IKE context
   netContext.ikeContext = context;

   //Initialize status code
   error = NO_ERROR;

   //Create an event object to poll the state of the UDP socket
   if(!osCreateEvent(&context->event))
   {
      //Failed to create event
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(error)
   {
      //Clean up side effects
      ikeDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Start IKE service
 * @param[in] context Pointer to the IKE context
 * @return Error code
 **/

error_t ikeStart(IkeContext *context)
{
   error_t error;

   //Make sure the IKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting IKE...\r\n");

   //Make sure the IKE service is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Start of exception handling block
   do
   {
      //Open a UDP socket
      context->socket = socketOpen(SOCKET_TYPE_DGRAM, SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->socket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket,
         context->interface);
      //Unable to bind the socket to the desired interface?
      if(error)
         break;

      //IKE normally listens and sends on UDP port 500 (refer to RFC 7296,
      //section 2);
      error = socketBind(context->socket, &IP_ADDR_ANY, IKE_PORT);
      //Unable to bind the socket to the desired port?
      if(error)
         break;

      //Start the IKE service
      context->stop = FALSE;
      context->running = TRUE;

      //Create a task
      context->taskId = osCreateTask("IKE", (OsTaskCode) ikeTask, context,
         &context->taskParams);

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Stop IKE service
 * @param[in] context Pointer to the IKE context
 * @return Error code
 **/

error_t ikeStop(IkeContext *context)
{
   //Make sure the IKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping IKE...\r\n");

   //Check whether the IKE service is running
   if(context->running)
   {
#if (NET_RTOS_SUPPORT == ENABLED)
      //Stop the IKE service
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }
#endif

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the preferred Diffie-Hellman group
 * @param[in] context Pointer to the IKE context
 * @param[in] dhGroupNum Preferred Diffie-Hellman group number
 * @return Error code
 **/

error_t ikeSetPreferredDhGroup(IkeContext *context, uint16_t dhGroupNum)
{
   //Make sure the IKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the specified group number is supported
   if(!ikeIsDhGroupSupported(dhGroupNum))
      return ERROR_INVALID_GROUP;

   //Save the preferred Diffie-Hellman group number
   context->preferredDhGroupNum = dhGroupNum;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set entity's ID
 * @param[in] context Pointer to the IKE context
 * @param[in] idType ID type
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @return Error code
 **/

error_t ikeSetId(IkeContext *context, IkeIdType idType, const void *id,
   size_t idLen)
{
   //Check parameters
   if(context == NULL || id == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the identification data
   if(idLen > IKE_MAX_ID_LEN)
      return ERROR_INVALID_LENGTH;

   //Save identification data
   context->idType = idType;
   osMemcpy(context->id, id, idLen);
   context->idLen = idLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set entity's pre-shared key
 * @param[in] context Pointer to the IKE context
 * @param[in] psk Pointer to the pre-shared key
 * @param[in] pskLen Length of the pre-shared key, in bytes
 * @return Error code
 **/

error_t ikeSetPsk(IkeContext *context, const uint8_t *psk, size_t pskLen)
{
#if (IKE_PSK_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || psk == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the pre-shared key
   if(pskLen > IKE_MAX_PSK_LEN)
      return ERROR_INVALID_LENGTH;

   //Save pre-shared key
   osMemcpy(context->psk, psk, pskLen);
   context->pskLen = pskLen;

   //Successful processing
   return NO_ERROR;
#else
   //Pre-shared key authentication is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Load entity's certificate
 * @param[in] context Pointer to the IKE context
 * @param[in] certChain Certificate chain (PEM format). This parameter is
 *   taken as reference
 * @param[in] certChainLen Length of the certificate chain
 * @param[in] privateKey Private key (PEM format). This parameter is taken
 *   as reference
 * @param[in] privateKeyLen Length of the private key
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t ikeSetCertificate(IkeContext *context, const char_t *certChain,
   size_t certChainLen, const char_t *privateKey, size_t privateKeyLen,
   const char_t *password)
{
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   IkeCertType certType;
   X509CertInfo *certInfo;

   //Check parameters
   if(context == NULL || certChain == NULL || certChainLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The private key is optional
   if(privateKey == NULL && privateKeyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //The password if required only for encrypted private keys
   if(password != NULL && osStrlen(password) > IKE_MAX_PASSWORD_LEN)
      return ERROR_INVALID_PASSWORD;

   //The first pass calculates the length of the DER-encoded certificate
   error = pemImportCertificate(certChain, certChainLen, NULL, &derCertLen,
      NULL);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = ikeAllocMem(derCertLen);

      //Successful memory allocation?
      if(derCert != NULL)
      {
         //The second pass decodes the PEM certificate
         error = pemImportCertificate(certChain, certChainLen, derCert,
            &derCertLen, NULL);

         //Check status code
         if(!error)
         {
            //Allocate a memory buffer to store X.509 certificate info
            certInfo = ikeAllocMem(sizeof(X509CertInfo));

            //Successful memory allocation?
            if(certInfo != NULL)
            {
               X509Options options;

               //Additional certificate parsing options
               options = X509_DEFAULT_OPTIONS;
               options.ignoreUnknownExtensions = TRUE;

               //Parse X.509 certificate
               error = x509ParseCertificateEx(derCert, derCertLen, certInfo,
                  &options);

               //Check status code
               if(!error)
               {
                  //Retrieve certificate type
                  error = ikeGetCertificateType(certInfo, &certType);
               }

               //Release previously allocated memory
               ikeFreeMem(certInfo);
            }
            else
            {
               //Failed to allocate memory
               error = ERROR_OUT_OF_MEMORY;
            }
         }

         //Release previously allocated memory
         ikeFreeMem(derCert);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Check status code
   if(!error)
   {
      //Save the certificate chain and the corresponding private key
      context->certType = certType;
      context->certChain = certChain;
      context->certChainLen = certChainLen;
      context->privateKey = privateKey;
      context->privateKeyLen = privateKeyLen;

      //The password if required only for encrypted private keys
      if(password != NULL)
      {
         osStrcpy(context->password, password);
      }
      else
      {
         osStrcpy(context->password, "");
      }
   }

   //Return status code
   return error;
#else
   //Certificate authentication is not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Delete an IKE SA
 * @param[in] sa Pointer to the IKE SA to delete
 * @return Error code
 **/

error_t ikeDeleteSa(IkeSaEntry *sa)
{
   IkeContext *context;

   //Make sure the IKE SA is valid
   if(sa == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Deleting IKE SA...\r\n");

   //Check the state of the IKE SA
   if(sa->state != IKE_SA_STATE_CLOSED)
   {
      //Point to the IKE context
      context = sa->context;

      //Request closure of the IKE SA
      sa->deleteRequest = TRUE;
      //Notify the IKE context that the IKE SA should be closed
      osSetEvent(&context->event);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Create a new Child SA
 * @param[in] context Pointer to the IKE context
 * @param[in] packet Triggering packet
 * @return Error code
 **/

error_t ikeCreateChildSa(IkeContext *context, const IpsecPacketInfo *packet)
{
   error_t error;
   IpAddr remoteIpAddr;
   IkeChildSaEntry *childSa;
   IpsecContext *ipsecContext;
   IpsecSpdEntry *spdEntry;
   IpsecSelector selector;

   //Check parameters
   if(context == NULL || packet == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Creating Child SA...\r\n");

   //Point to the IPsec context
   ipsecContext = netContext.ipsecContext;

   //The selectors are used to define the granularity of the SAs that are
   //created in response to the triggering packet
   selector.localIpAddr.start = packet->localIpAddr;
   selector.localIpAddr.end = packet->localIpAddr;
   selector.remoteIpAddr.start = packet->remoteIpAddr;
   selector.remoteIpAddr.end = packet->remoteIpAddr;
   selector.nextProtocol = packet->nextProtocol;
   selector.localPort.start = packet->localPort;
   selector.localPort.end = packet->localPort;

   //Set selector for the remote port
   if(packet->nextProtocol == IPV4_PROTOCOL_ICMP)
   {
      selector.remotePort.start = IPSEC_PORT_START_OPAQUE;
      selector.remotePort.end = IPSEC_PORT_END_OPAQUE;
   }
   else
   {
      selector.remotePort.start = packet->remotePort;
      selector.remotePort.end = packet->remotePort;
   }

   //Search the SPD for a matching entry
   spdEntry = ipsecFindSpdEntry(ipsecContext, IPSEC_POLICY_ACTION_PROTECT,
      &selector);

   //Every SPD should have a nominal, final entry that matches anything that is
   //otherwise unmatched, and discards it (refer to RFC 4301, section 4.4.1)
   if(spdEntry == NULL)
      return ERROR_NOT_FOUND;

   //End-to-end security?
   if(spdEntry->mode == IPSEC_MODE_TRANSPORT)
   {
      remoteIpAddr = packet->remoteIpAddr;
   }
   else
   {
      remoteIpAddr = spdEntry->remoteTunnelAddr;
   }

   //For each selector in an SPD entry, the entry specifies how to derive the
   //corresponding values for a new SAD entry from those in the SPD and the
   //packet (refer to RFC 4301, section 4.4.1)
   error = ipsecDeriveSelector(spdEntry, packet, &selector);
   //Any error to report?
   if(error)
      return error;

   //Create a new Child SA
   childSa = ikeCreateChildSaEntry(context);
   //Failed to create Child SA?
   if(childSa == NULL)
      return ERROR_OUT_OF_RESOURCES;

   //Initialize Child SA
   childSa->remoteIpAddr = remoteIpAddr;
   childSa->mode = spdEntry->mode;
   childSa->protocol = spdEntry->protocol;
   childSa->initiator = TRUE;
   childSa->packetInfo = *packet;
   childSa->selector = selector;

   //Initialize outbound SAD entry
   ipsecContext->sad[childSa->outboundSa].direction = IPSEC_DIR_OUTBOUND;
   ipsecContext->sad[childSa->outboundSa].selector = selector;

   //Request the creation of the Child SA
   ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_INIT);
   //Notify the IKE context that the Child SA should be created
   osSetEvent(&context->event);

   //Successful processing
   return NO_ERROR;
}




/**
 * @brief Delete a Child SA
 * @param[in] childSa Pointer to the Child SA to delete
 * @return Error code
 **/

error_t ikeDeleteChildSa(IkeChildSaEntry *childSa)
{
   IkeContext *context;

   //Make sure the Child SA is valid
   if(childSa == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Deleting Child SA...\r\n");

   //Check the state of the Child SA
   if(childSa->state != IKE_CHILD_SA_STATE_CLOSED)
   {
      //Point to the IKE context
      context = childSa->context;

      //Request closure of the Child SA
      childSa->deleteRequest = TRUE;
      //Notify the IKE context that the Child SA should be closed
      osSetEvent(&context->event);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief IKE task
 * @param[in] context Pointer to the IKE context
 **/

void ikeTask(IkeContext *context)
{
   error_t error;
   SocketEventDesc eventDesc;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Main loop
   while(1)
   {
#endif
      //Specify the events the application is interested in
      eventDesc.socket = context->socket;
      eventDesc.eventMask = SOCKET_EVENT_RX_READY;
      eventDesc.eventFlags = 0;

      //Wait for an event
      socketPoll(&eventDesc, 1, &context->event, IKE_TICK_INTERVAL);

      //Stop request?
      if(context->stop)
      {
         //Stop SNMP agent operation
         context->running = FALSE;
         //Task epilogue
         osExitTask();
         //Kill ourselves
         osDeleteTask(OS_SELF_TASK_ID);
      }

      //Any datagram received?
      if(eventDesc.eventFlags != 0)
      {
         //An implementation must accept incoming requests even if the source
         //port is not 500 or 4500 (refer to RFC 7296, section 2.11)
         error = socketReceiveEx(context->socket, &context->remoteIpAddr,
            &context->remotePort, &context->localIpAddr, context->message,
            IKE_MAX_MSG_SIZE, &context->messageLen, 0);

         //Check status code
         if(!error)
         {
            //Process the received IKE message
            ikeProcessMessage(context, context->message, context->messageLen);
         }
      }

      //Handle IKE events
      ikeProcessEvents(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release IKE context
 * @param[in] context Pointer to the IKE context
 **/

void ikeDeinit(IkeContext *context)
{
   //Make sure the IKE context is valid
   if(context != NULL)
   {
      //Detach IKE context
      netContext.ikeContext = NULL;

      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear IKE context
      osMemset(context, 0, sizeof(IkeContext));
   }
}

#endif
