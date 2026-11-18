/**
 * @file ike.c
 * @brief IKEv2 (Internet Key Exchange Protocol)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL IKE_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ike/ike_fsm.h"
#include "ike/ike_algorithms.h"
#include "ike/ike_certificate.h"
#include "ike/ike_message_dispatch.h"
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

   //TCP/IP stack context
   settings->netContext = NULL;
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

#if (IKE_REAUTH_SUPPORT == ENABLED)
   //Reauthentication period
   settings->reauthPeriod = 0;
#endif

#if (IKE_DPD_SUPPORT == ENABLED)
   //Dead peer detection period
   settings->dpdPeriod = 0;
#endif

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //NAT keepalive interval 
   settings->natKeepaliveInterval = IKE_DEFAULT_NAT_KEEPALIVE_INTERVAL;
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

   //Attach TCP/IP stack context
   if(settings->netContext != NULL)
   {
      context->netContext = settings->netContext;
   }
   else if(settings->interface != NULL)
   {
      context->netContext = settings->interface->netContext;
   }
   else
   {
      context->netContext = netGetDefaultContext();
   }

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

#if (IKE_REAUTH_SUPPORT == ENABLED)
   //Reauthentication period
   context->reauthPeriod = settings->reauthPeriod;
#endif

#if (IKE_DPD_SUPPORT == ENABLED)
   //Dead peer detection period
   context->dpdPeriod = settings->dpdPeriod;
#endif

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
   //NAT keepalive interval 
   context->natKeepaliveInterval = settings->natKeepaliveInterval;
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

   //Save the preferred key exchange method
   context->preferredGroupNum = ikeSelectDefaultGroup();

   //Get exclusive access
   netLock(context->netContext);
   //Attach IKE context
   context->netContext->ikeContext = context;
   //Release exclusive access
   netUnlock(context->netContext);

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
      context->socket = socketOpenEx(context->netContext, SOCKET_TYPE_DGRAM,
         SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->socket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket, context->interface);
      //Unable to bind the socket to the desired interface?
      if(error)
         break;

      //IKE normally listens and sends on UDP port 500 (refer to RFC 7296,
      //section 2);
      error = socketBind(context->socket, &IP_ADDR_ANY, IKE_PORT);
      //Unable to bind the socket to the desired port?
      if(error)
         break;

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //Open an alternate UDP socket
      context->altSocket = socketOpenEx(context->netContext, SOCKET_TYPE_DGRAM,
         SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->altSocket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->altSocket, context->interface);
      //Unable to bind the socket to the desired interface?
      if(error)
         break;

      //Port 4500 is reserved for UDP-encapsulated ESP and IKE (refer to
      //RFC 7296, section 2.23);
      error = socketBind(context->altSocket, &IP_ADDR_ANY, IPSEC_NAT_PORT);
      //Unable to bind the socket to the desired port?
      if(error)
         break;
#endif

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

      //Close UDP socket
      if(context->socket != NULL)
      {
         socketClose(context->socket);
         context->socket = NULL;
      }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //Close alternate UDP socket
      if(context->altSocket != NULL)
      {
         socketClose(context->altSocket);
         context->altSocket = NULL;
      }
#endif
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
      if(context->socket != NULL)
      {
         socketClose(context->socket);
         context->socket = NULL;
      }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //Close alternate UDP socket
      if(context->altSocket != NULL)
      {
         socketClose(context->altSocket);
         context->altSocket = NULL;
      }
#endif
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the preferred key exchange method
 * @param[in] context Pointer to the IKE context
 * @param[in] groupNum Preferred group number
 * @return Error code
 **/

error_t ikeSetPreferredGroup(IkeContext *context, uint16_t groupNum)
{
   //Make sure the IKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the specified key exchange method is supported
   if(!ikeIsGroupSupported(groupNum))
      return ERROR_INVALID_GROUP;

   //Save the preferred key exchange method
   context->preferredGroupNum = groupNum;

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
   error_t error;

   //Check parameters
   if(context == NULL || idType == IKE_ID_TYPE_INVALID)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the identification data
   if(idLen > IKE_MAX_ID_LEN)
      return ERROR_INVALID_LENGTH;

   //Initialize status code
   error = NO_ERROR;

   //Clear identification data
   osMemset(&context->id, 0, sizeof(IkeId));

   //Valid identification data?
   if(id != NULL && idLen > 0)
   {
      //Save identification type
      context->id.type = idType;

      //Save identification data
      osMemcpy(context->id.data, id, idLen);
      context->id.length = idLen;
   }
   else
   {
#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
      //X.500 distinguished name?
      if(idType == IKE_ID_TYPE_DER_ASN1_DN)
      {
         size_t n;

         //The first pass calculates the length of the subject's DN
         error = ikeGetCertSubjectDn(context->certChain, context->certChainLen,
            NULL, &n);

         //Check status code
         if(!error)
         {
            //Check the length of the subject's DN
            if(n <= IKE_MAX_ID_LEN)
            {
               //The second pass extracts the subject's DN from the certificate
               error = ikeGetCertSubjectDn(context->certChain,
                  context->certChainLen, context->id.data, &n);
            }
            else
            {
               //Report an error
               error = ERROR_BUFFER_OVERFLOW;
            }
         }

         //Check status code
         if(!error)
         {
            //Save identification type
            context->id.type = idType;
            //Save the length of the identification data
            context->id.length = n;
         }
      }
      else
#endif
      {
         //Report an error
         error = ERROR_INVALID_PARAMETER;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Set authentication method
 * @param[in] context Pointer to the IKE context
 * @param[in] authMethod Authentication method (certificate, PSK or EAP)
 * @return Error code
 **/

error_t ikeSetAuthMethod(IkeContext *context, IpsecAuthMethod authMethod)
{
   //Make sure the IKE context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save authentication method
   context->authMethod = authMethod;

   //Successful processing
   return NO_ERROR;
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

      //Erase the existing password, if any
      cryptoZeroizeMem(context->privateKeyPassword, IKE_MAX_PASSWORD_LEN);

      //The password if required only for encrypted private keys
      if(password != NULL)
      {
         osStrcpy(context->privateKeyPassword, password);
      }
      else
      {
         osStrcpy(context->privateKeyPassword, "");
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
 * @brief Set user name
 * @param[in] context Pointer to the IKE context
 * @param[in] username NULL-terminated string containing the user name
 * @return Error code
 **/

error_t ikeSetUsername(IkeContext *context, const char_t *username)
{
#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || username == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the user name is acceptable
   if(osStrlen(username) > IKE_MAX_USERNAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Save user name
   osStrcpy(context->username, username);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set password
 * @param[in] context Pointer to the IKE context
 * @param[in] password NULL-terminated string containing the password
 * @return Error code
 **/

error_t ikeSetPassword(IkeContext *context, const char_t *password)
{
#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || password == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the password is acceptable
   if(osStrlen(password) > IKE_MAX_PASSWORD_LEN)
      return ERROR_INVALID_LENGTH;

   //Erase the existing password, if any
   cryptoZeroizeMem(context->password, IKE_MAX_PASSWORD_LEN);
   //Save the new password
   osStrcpy(context->password, password);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Request the specified configuration attribute from the server
 * @param[in] context Pointer to the IKE context
 * @param[in] type Configuration attribute type
 * @param[in] enable Specifies whether the specified configuration attribute
 *   is requested
 * @return Error code
 **/

error_t ikeRequestConfigAttribute(IkeContext *context, IkeConfigAttrType type,
   bool_t enable)
{
   //Minimal implementations are not required to support the ability to request
   //a temporary IP address on the remote end of a tunnel (refer to RFC 7296,
   //section 4)
   return ERROR_NOT_IMPLEMENTED;
}


/**
 * @brief Create a new IKE SA
 * @param[in] context Pointer to the IKE context
 * @param[in] remoteIpAddr IP address of the peer
 * @return Error code
 **/

error_t ikeCreateSa(IkeContext *context, const IpAddr *remoteIpAddr)
{
   uint_t i;
   IkeSaEntry *sa;

   //Check parameters
   if(context == NULL || remoteIpAddr == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Creating IKE SA...\r\n");

   //Loop through IKE SA entries
   for(i = 0; i < context->numSaEntries; i++)
   {
      //Point to the current IKE SA
      sa = &context->sa[i];

      //Check whether the current IKE SA matches the peer's IP address
      if(sa->state != IKE_SA_STATE_CLOSED &&
         ipCompAddr(&sa->remoteIpAddr, remoteIpAddr))
      {
         break;
      }
   }

   //A new IKE SA should only be created if there is no existing entry
   if(i >= context->numSaEntries)
   {
      //Create a new IKE SA
      sa = ikeCreateSaEntry(context);
      //Failed to create IKE SA?
      if(sa == NULL)
         return ERROR_OUT_OF_RESOURCES;

      //Initialize IKE SA
      sa->remoteIpAddr = *remoteIpAddr;

      //The original initiator always refers to the party who initiated the
      //exchange (refer to RFC 7296, section 2.2)
      sa->originalInitiator = TRUE;

      //Select the preferred key exchange method
      sa->keContext.groupNum = context->preferredGroupNum;

      //Request the creation of the IKE SA
      ikeChangeSaState(sa, IKE_SA_STATE_INIT_REQ);
      //Notify the IKE context that the IKE SA should be created
      osSetEvent(&context->event);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Rekey an IKE SA
 * @param[in] sa Pointer to the IKE SA to rekey
 * @return Error code
 **/

error_t ikeRekeySa(IkeSaEntry *sa)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   IkeContext *context;

   //Make sure the IKE SA is valid
   if(sa == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Rekeying IKE SA...\r\n");

   //Check the state of the IKE SA
   if(sa->state != IKE_SA_STATE_CLOSED)
   {
      //Point to the IKE context
      context = sa->context;

      //Request rekeying of the IKE SA
      sa->rekeyRequest = TRUE;
      //Notify the IKE context that the IKE SA should be rekeyed
      osSetEvent(&context->event);
   }

   //Successful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
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
   ipsecContext = context->netContext->ipsecContext;
   //Sanity check
   if(ipsecContext == NULL)
      return ERROR_FAILURE;

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
      &selector, TRUE);

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
   childSa->esn = spdEntry->esn;
#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
   childSa->pfs = spdEntry->pfs;
#endif
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
 * @brief Rekey a Child SA
 * @param[in] childSa Pointer to the Child SA to rekey
 * @return Error code
 **/

error_t ikeRekeyChildSa(IkeChildSaEntry *childSa)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   IkeContext *context;

   //Make sure the Child SA is valid
   if(childSa == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Rekeying Child SA...\r\n");

   //Check the state of the Child SA
   if(childSa->state != IKE_CHILD_SA_STATE_CLOSED)
   {
      //Point to the IKE context
      context = childSa->context;

      //Request rekeying of the Child SA
      childSa->rekeyRequest = TRUE;
      //Notify the IKE context that the Child SA should be rekeyed
      osSetEvent(&context->event);
   }

   //Successful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
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
   uint_t n;
   Socket *socket;
   SocketMsg msg;
   SocketEventDesc eventDesc[2];

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Main loop
   while(1)
   {
#endif
      //Number of entries in the descriptor set
      n = 0;

      //IKE normally listens on UDP port 500
      eventDesc[n].socket = context->socket;
      eventDesc[n].eventMask = SOCKET_EVENT_RX_READY;
      eventDesc[n++].eventFlags = 0;

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //IKE messages may also be received on UDP port 4500 with a slightly
      //different format (refer to RFC 7296, section 2)
      eventDesc[n].socket = context->altSocket;
      eventDesc[n].eventMask = SOCKET_EVENT_RX_READY;
      eventDesc[n++].eventFlags = 0;
#endif

      //Wait for an event
      socketPoll(eventDesc, n, &context->event, IKE_TICK_INTERVAL);

      //Stop request?
      if(context->stop)
      {
         //Stop IKE service
         context->running = FALSE;
         //Task epilogue
         osExitTask();
         //Kill ourselves
         osDeleteTask(OS_SELF_TASK_ID);
      }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //IKE runs over UDP ports 500 and 4500
      if(n > 0 && eventDesc[0].eventFlags != 0)
      {
         socket = context->socket;
      }
      else if(n > 1 && eventDesc[1].eventFlags != 0)
      {
         socket = context->altSocket;
      }
      else
      {
         socket = NULL;
      }
#else
      //IKE runs over UDP port 500
      if(n > 0 && eventDesc[0].eventFlags != 0)
      {
         socket = context->socket;
      }
      else
      {
         socket = NULL;
      }
#endif

      //Any datagram received?
      if(socket != NULL)
      {
         //Point to the receive buffer
         msg = SOCKET_DEFAULT_MSG;
         msg.data = context->message;
         msg.size = IKE_MAX_MSG_SIZE;

         //Receive incoming datagram
         error = socketReceiveMsg(socket, &msg, 0);

         //Check status code
         if(!error)
         {
            //Retrieve the length of the datagram
            context->messageLen = msg.length;

            //An implementation must accept incoming requests even if the source
            //port is not 500 or 4500 (refer to RFC 7296, section 2.11)
            context->localInterface = msg.interface;
            context->localIpAddr = msg.destIpAddr;
            context->localPort = msg.destPort;
            context->remoteIpAddr = msg.srcIpAddr;
            context->remotePort = msg.srcPort;

            //Process the received IKE message
            ikeDispatchMessage(context, context->message, context->messageLen);
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
   NetContext *netContext;

   //Make sure the IKE context is valid
   if(context != NULL)
   {
      //Point to the TCP/IP stack context
      netContext = context->netContext;

      //Get exclusive access
      netLock(netContext);
      //Detach the IKE context
      netContext->ikeContext = NULL;
      //Release exclusive access
      netUnlock(netContext);

      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear IKE context
      cryptoZeroizeMem(context, sizeof(IkeContext));
   }
}

#endif
