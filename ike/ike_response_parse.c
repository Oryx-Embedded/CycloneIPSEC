/**
 * @file ike_response_parse.c
 * @brief IKE response parsing
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
#include "ike/ike_request_format.h"
#include "ike/ike_response_parse.h"
#include "ike/ike_payload_parse.h"
#include "ike/ike_auth.h"
#include "ike/ike_certificate.h"
#include "ike/ike_key_exchange.h"
#include "ike/ike_key_material.h"
#include "ike/ike_misc.h"
#include "debug.h"

//Check IKEv2 library configuration
#if (IKE_SUPPORT == ENABLED)


/**
 * @brief Parse incoming IKE_SA_INIT response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseIkeSaInitResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint16_t notifyMsgType;
   const IkeHeader *ikeHeader;
   IkeMessagePayloads payloads;

   //Each message begins with the IKE header
   ikeHeader = (IkeHeader *) message;

   //Check the state of the IKE SA
   if(sa->state != IKE_SA_STATE_INIT_RESP)
      return ERROR_UNEXPECTED_MESSAGE;

   //Start of exception handling block
   do
   {
      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //Error notification received?
      if(payloads.errorNotify != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(payloads.errorNotify->notifyMsgType);

         //Some error notifications such as INVALID_KE_PAYLOAD may lead to a
         //subsequent successful exchange
         if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
         {
            IkeContext *context;

            //Point to the IKE context
            context = sa->context;

            //If the initiator guesses wrong, the responder will respond with a
            //Notify payload of type INVALID_KE_PAYLOAD indicating the selected
            //group (refer to RFC 7296, section 1.2)
            error = ikeParseInvalidKePayloadNotification(&sa->keContext,
               payloads.errorNotify);
            //Malformed notification?
            if(error)
               break;

            //Reinitialize Diffie-Hellman context
            ikeFreeKeContext(&sa->keContext);
            ikeInitKeContext(&sa->keContext);

            //Generate a new ephemeral key pair
            error = ikeGenerateKeyPair(&sa->keContext, context->prngAlgo,
               context->prngContext);
            //Any error to report?
            if(error)
               break;

            //The initiator must retry the IKE_SA_INIT with the corrected
            //Diffie-Hellman group (refer to RFC 7296, section 1.2)
            error = ERROR_RETRY;
            break;
         }
         else
         {
            //An implementation receiving an error type that it does not
            //recognize in a response must assume that the corresponding
            //request has failed entirely (refer to RFC 7296, section 3.10.1)
            error = ERROR_UNEXPECTED_STATUS;
            break;
         }
      }

      //COOKIE notification received?
      if(payloads.cookieNotify != NULL)
      {
         //Save the received cookie
         error = ikeParseCookieNotification(sa, payloads.cookieNotify);
         //Malformed notification?
         if(error)
            break;

         //If the IKE_SA_INIT response includes the COOKIE notification, the
         //initiator must then retry the IKE_SA_INIT request
         error = ERROR_RETRY;
         break;
      }

      //Mandatory payloads must be included in the received message
      if(payloads.sa == NULL || payloads.ke == NULL || payloads.nonce == NULL)
      {
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //The responder's SPI must not be zero
      if(osMemcmp(ikeHeader->responderSpi, IKE_INVALID_SPI, IKE_SPI_SIZE) == 0)
      {
         error = ERROR_INVALID_MESSAGE;
         break;
      }

      //Save responder's IKE SPI
      osMemcpy(sa->responderSpi, ikeHeader->responderSpi, IKE_SPI_SIZE);

      //Save responder's nonce
      error = ikeParseNoncePayload(payloads.nonce, sa->responderNonce,
         &sa->responderNonceLen);
      //Malformed nonce?
      if(error)
         break;

      //Check the syntax of the SAr payload
      error = ikeParseSaPayload(payloads.sa);
      //Malformed SAr payload?
      if(error)
         break;

      //The initiator of an exchange must check that the accepted offer is
      //consistent with one of its proposals, and if not must terminate the
      //exchange (refer to RFC 7296, section 3.3.6)
      error = ikeCheckSaProposal(sa, payloads.sa);
      //Invalid cryptographic suite?
      if(error)
         break;

      //Nonces used in IKEv2 must be at least half the key size of the
      //negotiated pseudorandom function (refer to RFC 7296, section 2.10)
      error = ikeCheckNonceLength(sa, sa->responderNonceLen);
      //Unacceptable nonce length?
      if(error)
         break;

      //The Key Exchange payload is used to exchange Diffie-Hellman public
      //numbers as part of a Diffie-Hellman key exchange
      error = ikeParseKePayload(&sa->keContext, payloads.ke);
      //Any error to report?
      if(error)
         break;

      //The Certificate Request payload is optional
      if(payloads.certReq != NULL)
      {
         //The Certificate Request payload provides a means to request preferred
         //certificates via IKE (refer to RFC 7296, section 3.7)
         error = ikeParseCertReqPayload(sa, payloads.certReq);
         //Any error to report?
         if(error)
            break;
      }

#if (IKE_NAT_TRAVERSAL_SUPPORT == ENABLED)
      //NAT_DETECTION_SOURCE_IP notification received?
      if(payloads.natDetectSrcIpNotify != NULL)
      {
         //There MAY be multiple NAT_DETECTION_SOURCE_IP payloads in a message
         //if the sender does not know which of several network attachments
         //will be used to send the packet (refer to RFC 7296, section 2.23)
         error = ikeParseNatDetectSrcIpNotification(sa, message, length);

         //Malformed notification?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }

      //NAT_DETECTION_DESTINATION_IP notification received?
      if(payloads.natDetectDestIpNotify != NULL)
      {
         //The NAT_DETECTION_DESTINATION_IP payloads can be used to detect if
         //there is NAT between the hosts
         error = ikeParseNatDetectDestIpNotification(sa,
            payloads.natDetectDestIpNotify);

         //Malformed notification?
         if(error)
         {
            sa->notifyMsgType = IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX;
            break;
         }
      }
#endif

#if (IKE_SIGN_HASH_ALGOS_SUPPORT == ENABLED)
      //SIGNATURE_HASH_ALGORITHMS notification received?
      if(payloads.signHashAlgosNotify != NULL)
      {
         //This notification indicates the list of hash functions supported by
         //the sending peer (refer to RFC 7427, section 4)
         error = ikeParseSignHashAlgosNotification(sa,
            payloads.signHashAlgosNotify);
         //Any error to report?
         if(error)
            break;
      }
      else
      {
         //The notification is not present in the IKE_SA_INIT message
         sa->signHashAlgos = 0;
      }
#endif

      //Let g^ir be the Diffie-Hellman shared secret
      error = ikeComputeSharedSecret(&sa->keContext, sa->sharedSecret,
         &sa->sharedSecretLen);
      //Any error to report?
      if(error)
         break;

      //At this point in the negotiation, each party can generate a quantity
      //called SKEYSEED, from which all keys are derived for that IKE SA (refer
      //to RFC 7296, section 1.2)
      error = ikeGenerateSaKeyMaterial(sa, NULL);
      //Any error to report?
      if(error)
         break;

      //Save the second message (IKE_SA_INIT response), starting with the first
      //octet of the first SPI in the header and ending with the last octet of
      //the last payload
      osMemcpy(sa->response, message, length);
      sa->responderSaInit = sa->response;
      sa->responderSaInitLen = length;

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //The second pair of messages (IKE_AUTH) authenticate the previous
      //messages, exchange identities and certificates, and establish the
      //first Child SA
      error = ikeSendIkeAuthRequest(sa);
   }
   else if(error == ERROR_RETRY)
   {
      //The initiator must then retry the IKE_SA_INIT request
      error = ikeSendIkeSaInitRequest(sa);
   }
   else
   {
      //The IKE_SA_INIT response is not valid
   }

   //Check whether the IKE_SA_INIT exchange has failed
   if(error)
   {
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse incoming IKE_AUTH response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseIkeAuthResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint16_t notifyMsgType;
   IkeEapState eapState;
   IkeMessagePayloads payloads;
   IpsecPadEntry *padEntry;

   //Start of exception handling block
   do
   {
      //Check the state of the IKE SA
      if(sa->state != IKE_SA_STATE_AUTH_RESP)
      {
         error = ERROR_UNEXPECTED_MESSAGE;
         break;
      }

      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //Error notification received?
      if(payloads.errorNotify != NULL)
      {
         //Types in the range 0-16383 are intended for reporting errors
         notifyMsgType = ntohs(payloads.errorNotify->notifyMsgType);

         //If creating the Child SA during the IKE_AUTH exchange fails for some
         //reason, the IKE SA is still created as usual (refer to RFC 7296,
         //section 1.2)
         if(notifyMsgType != IKE_NOTIFY_MSG_TYPE_NO_PROPOSAL_CHOSEN &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_TS_UNACCEPTABLE &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_SINGLE_PAIR_REQUIRED &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_INTERNAL_ADDRESS_FAILURE &&
            notifyMsgType != IKE_NOTIFY_MSG_TYPE_FAILED_CP_REQUIRED)
         {
            error = ERROR_UNEXPECTED_STATUS;
            break;
         }
      }

      //Get current EAP state
      eapState = sa->eapState;

      //Check EAP state
      if(eapState == IKE_EAP_STATE_DISABLED ||
         eapState == IKE_EAP_STATE_INIT)
      {
         //IDr and AUTH payloads must be included in the received message
         if(payloads.idr == NULL || payloads.auth == NULL)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }
      else if(eapState == IKE_EAP_STATE_SUCCESS)
      {
         //The EAP AUTH payloads must be included in the two messages following
         //the one containing the EAP Success message (refer to RFC 7296,
         //section 2.16)
         if(payloads.auth == NULL)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }
      else
      {
         //The EAP payload must be included in the received message
         if(payloads.eap == NULL)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }

      //Check EAP state
      if(eapState == IKE_EAP_STATE_DISABLED ||
         eapState == IKE_EAP_STATE_INIT)
      {
         //Parse Identification payload
         error = ikeParseIdPayload(sa, payloads.idr);
         //Malformed Identification payload?
         if(error)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }

         //Perform lookup in the PAD database based on the ID
         padEntry = ipsecFindPadEntry(sa->context->netContext->ipsecContext,
            sa->peerId.type, sa->peerId.data, sa->peerId.length);
         //Invalid ID?
         if(padEntry == NULL)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }

#if (IKE_CERT_AUTH_SUPPORT == ENABLED)
         //Certificate-based authentication?
         if(padEntry->authMethod == IPSEC_AUTH_METHOD_CERT)
         {
            //Parse the certificate chain
            error = ikeParseCertificateChain(sa, padEntry, message, length);
            //Failed to validate certificate chain?
            if(error)
            {
               error = ERROR_AUTHENTICATION_FAILED;
               break;
            }
         }
#endif

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
         //The INITIAL_CONTACT notification, if sent, must be in the first
         //IKE_AUTH response, not as a separate exchange afterwards; receiving
         //parties may ignore it in other messages (refer to RFC 7296,
         //section 2.4)
         if(payloads.initialContactNotify)
         {
            //The INITIAL_CONTACT notification asserts that this IKE SA is the
            //only IKE SA currently active between the authenticated identities
            sa->initialContact = TRUE;
         }
#endif
      }

      //Check EAP state
      if(eapState == IKE_EAP_STATE_DISABLED ||
         eapState == IKE_EAP_STATE_INIT ||
         eapState == IKE_EAP_STATE_SUCCESS)
      {
         //The peers are authenticated by having each sign (or MAC using a
         //shared secret as the key) a block of data (refer to RFC 7296,
         //section 2.15)
         error = ikeParseAuthPayload(sa, payloads.auth, payloads.cert);
         //Authentication failure?
         if(error)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }

      //Check EAP state
      if(eapState == IKE_EAP_STATE_DISABLED ||
         eapState == IKE_EAP_STATE_SUCCESS)
      {
         //Child SAs can be created either by being piggybacked on the IKE_AUTH
         //exchange, or using a separate CREATE_CHILD_SA exchange
         if(sa->childSa1 != NULL)
         {
            //The responder completes negotiation of a Child SA with additional
            //fields
            error = ikeProcessInitialChildSaCreateResponse(sa, &payloads);
            //Any error to report?
            if(error)
               break;
         }

      }
      else
      {
         //The Extensible Authentication Protocol payload allows IKE SAs to be
         //authenticated using the EAP protocol
         error = ikeParseEapPayload(sa, payloads.eap);
         //Authentication failure?
         if(error)
         {
            error = ERROR_AUTHENTICATION_FAILED;
            break;
         }
      }

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //Check EAP state
      if(eapState == IKE_EAP_STATE_DISABLED ||
         eapState == IKE_EAP_STATE_SUCCESS)
      {
         //Release Diffie-Hellman context
         ikeFreeKeContext(&sa->keContext);
         ikeInitKeContext(&sa->keContext);

#if (IKE_EAP_AUTH_SUPPORT == ENABLED)
         //Erase master session key
         cryptoZeroizeMem(sa->msk, sizeof(sa->msk));
         sa->mskLen = 0;
#endif
         //If authentication has succeeded in the IKE_AUTH exchange, the IKE SA
         //is established (refer to RFC 7296, section 2.21.2)
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);

         //Successful Child SA creation?
         if(sa->childSa1 != NULL)
         {
            //Update the state of the Child SA
            ikeChangeChildSaState(sa->childSa1, IKE_CHILD_SA_STATE_OPEN);

            //ESP and AH SAs exist in pairs (one in each direction), so two SAs
            //are created in a single Child SA negotiation for them
            ikeCreateIpsecSaPair(sa->childSa1);
         }

#if (IKE_INITIAL_CONTACT_SUPPORT == ENABLED)
         //The INITIAL_CONTACT notification asserts that this IKE SA is the only
         //IKE SA currently active between the authenticated identities
         if(sa->initialContact)
         {
            //Delete duplicate IKE SAs
            ikeDeleteDuplicateSaEntries(sa);
         }
#endif

#if (IKE_REAUTH_SUPPORT == ENABLED)
         //Check whether reauthentication is on-going
         if(sa->oldSa != NULL && sa->oldSa->state != IKE_SA_STATE_CLOSED)
         {
            //IKEv2 does not have any special support for reauthentication.
            //Reauthentication is done by creating a new IKE SA from scratch,
            //creating new Child SAs within the new IKE SA, and finally deleting
            //the old IKE SA
            ikeProcessSaDeleteEvent(sa->oldSa);

            //Detach the old IKE SA
            sa->oldSa = NULL;
         }
#endif
      }
      else
      {
         //EAP authentication is on-going
         ikeChangeSaState(sa, IKE_SA_STATE_AUTH_REQ);

         //Send the next IKE_AUTH message
         ikeSendIkeAuthRequest(sa);
      }
   }
   else if(error == ERROR_AUTHENTICATION_FAILED)
   {
      //EAP failure?
      if(sa->eapState == IKE_EAP_STATE_FAILURE)
      {
         //If the exchange is terminated with EAP Failure, an
         //AUTHENTICATION_FAILED notification is not sent (refer to RFC 7296,
         //section 2.21)
         ikeDeleteSaEntry(sa);
      }
      else
      {
         //All errors causing the authentication to fail for whatever reason
         //(invalid shared secret, invalid ID, untrusted certificate issuer,
         //revoked or expired certificate, etc.) should result in an
         //AUTHENTICATION_FAILED notification
         ikeChangeSaState(sa, IKE_SA_STATE_AUTH_FAILURE_REQ);

         //If the error occurs on the initiator, the notification may be
         //returned in a separate INFORMATIONAL exchange, usually with no other
         //payloads. This is an exception for the general rule of not starting
         //new exchanges based on errors in responses (refer to RFC 7296,
         //section 2.21.2)
         ikeSendInfoRequest(sa);
      }
   }
   else
   {
      //The IKE_AUTH exchange has failed
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse incoming CREATE_CHILD_SA response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseCreateChildSaResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   IkeMessagePayloads payloads;

   //Payloads sent in IKE response messages must not have the critical flag
   //set (refer to RFC 7296, section 2.5)
   error = ikeCheckCriticalPayloads(message, length, NULL);

   //Check status code
   if(!error)
   {
      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //The CREATE_CHILD_SA exchange is used to create new Child SAs and to
      //rekey both IKE SAs and Child SAs (refer to RFC 7296, section 1.3)
      if(sa->state == IKE_SA_STATE_REKEY_RESP)
      {
         //IKE SA rekeying
         error = ikeProcessIkeSaRekeyResponse(sa, &payloads);
      }
      else if(sa->state == IKE_SA_STATE_CREATE_CHILD_RESP)
      {
         //Child SA creation
         error = ikeProcessChildSaCreateResponse(sa, &payloads);
      }
      else if(sa->state == IKE_SA_STATE_REKEY_CHILD_RESP)
      {
         //Child SA rekeying
         error = ikeProcessChildSaRekeyResponse(sa, &payloads);
      }
      else
      {
         //Unexpected message received
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }

   //Check status code
   if(error)
   {
      //IKE SA rekeying?
      if(sa->state == IKE_SA_STATE_REKEY_RESP)
      {
         //Delete the new IKE SA
         ikeDeleteSaEntry(sa->newSa1);
      }

      //Delete the IKE SA
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse incoming INFORMATIONAL response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] message Pointer to the received IKE message
 * @param[in] length Length of the IKE message, in bytes
 * @return Error code
 **/

error_t ikeParseInfoResponse(IkeSaEntry *sa, const uint8_t *message,
   size_t length)
{
   error_t error;
   uint_t i;
   IkeMessagePayloads payloads;
   const IkeDeletePayload *deletePayload;

   //Start of exception handling block
   do
   {
      //Check the state of the IKE SA
      if(sa->state != IKE_SA_STATE_DPD_RESP &&
         sa->state != IKE_SA_STATE_DELETE_RESP &&
         sa->state != IKE_SA_STATE_DELETE_CHILD_RESP &&
         sa->state != IKE_SA_STATE_AUTH_FAILURE_RESP)
      {
         error = ERROR_UNEXPECTED_MESSAGE;
         break;
      }

      //Payloads sent in IKE response messages must not have the critical flag
      //set (refer to RFC 7296, section 2.5)
      error = ikeCheckCriticalPayloads(message, length, NULL);
      //Any error to report?
      if(error)
         break;

      //Parse IKE message payloads
      ikeParseIkeMessagePayloads(message, length, &payloads);

      //Error notification received?
      if(payloads.errorNotify != NULL)
      {
         //An implementation receiving an error type that it does not recognize
         //in a response must assume that the corresponding request has failed
         //entirely (refer to RFC 7296, section 3.10.1)
         error = ERROR_UNEXPECTED_STATUS;
         break;
      }

      //The response in the INFORMATIONAL exchange will contain Delete payloads
      //for the paired SAs going in the other direction
      for(i = 0; ; i++)
      {
         //Extract next Delete payload
         deletePayload = (IkeDeletePayload *) ikeGetPayload(message, length,
            IKE_PAYLOAD_TYPE_D, i);
         //Delete payload not found?
         if(deletePayload == NULL)
            break;

         //The Delete payload list the SPIs to be deleted
         error = ikeParseDeletePayload(sa, deletePayload, TRUE);
         //Malformed payload?
         if(error)
            break;
      }

      //End of exception handling block
   } while(0);

   //Check status code
   if(error == NO_ERROR)
   {
      //Check the state of the IKE SA
      if(sa->state == IKE_SA_STATE_DPD_RESP)
      {
         //Receipt of a fresh cryptographically protected message on an IKE SA
         //ensures liveness of the IKE SA and all of its Child SAs
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_RESP ||
         sa->state == IKE_SA_STATE_AUTH_FAILURE_RESP)
      {
         //Deleting an IKE SA implicitly closes any remaining Child SAs
         //negotiated under it (refer to RFC 7296, section 1.4.1)
         ikeDeleteSaEntry(sa);
      }
      else if(sa->state == IKE_SA_STATE_DELETE_CHILD_RESP)
      {
         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);
         sa->childSa1 = NULL;
      }
      else
      {
         //Just for sanity
      }
   }
   else
   {
      //Delete the IKE SA
      ikeDeleteSaEntry(sa);
   }

   //Return status code
   return error;
}


/**
 * @brief Process initial Child SA creation response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 * @return Error code
 **/

error_t ikeProcessInitialChildSaCreateResponse(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
   error_t error;
   IkeChildSaEntry *childSa;

   //Point to the Child SA
   childSa = sa->childSa1;

   //Error notification received?
   if(payloads->errorNotify != NULL)
   {
      //Delete the Child SA
      ikeDeleteChildSaEntry(sa->childSa1);
      sa->childSa1 = NULL;

#if (IKE_CREATE_CHILD_SA_SUPPORT == DISABLED)
      //Request closure of the IKE SA
      sa->deleteRequest = TRUE;
#endif

      //If creating the Child SA during the IKE_AUTH exchange fails for some
      //reason, the IKE SA is still created as usual (refer to RFC 7296,
      //section 1.2)
      return NO_ERROR;
   }

   //Mandatory payloads must be included in the received message
   if(payloads->sa == NULL || payloads->tsi == NULL ||
      payloads->tsr == NULL)
   {
      return ERROR_INVALID_MESSAGE;
   }

   //Check the syntax of the SAr payload
   error = ikeParseSaPayload(payloads->sa);
   //Malformed SAr payload?
   if(error)
      return error;

   //The initiator of an exchange must check that the accepted offer
   //is consistent with one of its proposals, and if not must terminate
   //the exchange (refer to RFC 7296, section 3.3.6)
   error = ikeCheckChildSaProposal(childSa, payloads->sa);
   //Invalid cryptographic suite?
   if(error)
      return error;

   //The initiator can request that the Child SA use transport mode
   //rather than tunnel mode for the SA created
   if(childSa->mode == IPSEC_MODE_TRANSPORT)
   {
      //If the request is accepted, the response must also include a
      //notification of type USE_TRANSPORT_MODE
      if(payloads->useTransportModeNotify == NULL)
      {
         //Use tunnel mode
         childSa->mode = IPSEC_MODE_TUNNEL;
      }
   }

   //When the responder chooses a subset of the traffic proposed by
   //the initiator, it narrows the Traffic Selectors to some subset
   //of the initiator's proposal (refer to RFC 7296, section 2.9)
   error = ikeCheckTs(childSa, payloads->tsi, payloads->tsr, FALSE);
   //Invalid traffic selector?
   if(error)
      return error;

   //For the first Child SA created, Ni and Nr are the nonces from the
   //IKE_SA_INIT exchange (refer to RFC 7296, section 2.17)
   osMemcpy(childSa->initiatorNonce, sa->initiatorNonce,
      sa->initiatorNonceLen);

   osMemcpy(childSa->responderNonce, sa->responderNonce,
      sa->responderNonceLen);

   //Save the length of Ni and Nr nonces
   childSa->initiatorNonceLen = sa->initiatorNonceLen;
   childSa->responderNonceLen = sa->responderNonceLen;

   //A single Child SA is created by the IKE_AUTH exchange. Keying
   //material for the Child SA must be taken from the expanded KEYMAT
   //(refer to RFC 7296, section 2.17)
   return ikeGenerateChildSaKeyMaterial(childSa);
}


/**
 * @brief Process Child SA creation response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 * @return Error code
 **/

error_t ikeProcessChildSaCreateResponse(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   uint16_t notifyMsgType;
   IkeChildSaEntry *childSa;

   //Point to the Child SA
   childSa = sa->childSa1;

   //Error notification received?
   if(payloads->errorNotify != NULL)
   {
      //Types in the range 0-16383 are intended for reporting errors
      notifyMsgType = ntohs(payloads->errorNotify->notifyMsgType);

      //Check the type of the notification message
      if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
      {
         //The INVALID_SYNTAX error notification is considered fatal in both
         //peers, meaning that the IKE SA is deleted without needing an explicit
         //Delete payload (refer to RFC 7296, section 2.21.3)
         return ERROR_INVALID_SYNTAX;
      }
#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
      {
         IkeContext *context;

         //Point to the IKE context
         context = sa->context;

         //If the responder indicates its preferred Diffie-Hellman group in the
         //INVALID_KE_PAYLOAD Notify payload (refer to RFC 7296, section 1.3)
         error = ikeParseInvalidKePayloadNotification(&childSa->keContext,
            payloads->errorNotify);
         //Malformed notification?
         if(error)
            return error;

         //Reinitialize Diffie-Hellman context
         ikeFreeKeContext(&childSa->keContext);
         ikeInitKeContext(&childSa->keContext);

         //Generate a new ephemeral key pair
         error = ikeGenerateKeyPair(&childSa->keContext, context->prngAlgo,
            context->prngContext);
         //Any error to report?
         if(error)
            return error;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_CREATE_CHILD_REQ);

         //The initiator retries the exchange with a Diffie-Hellman proposal and
         //KEi in the group that the responder gave in the INVALID_KE_PAYLOAD
         //Notify payload
         return ikeSendCreateChildSaRequest(sa);
      }
#endif
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS)
      {
         //The responder sends a NO_ADDITIONAL_SAS notification to indicate
         //that a CREATE_CHILD_SA request is unacceptable because the responder
         //is unwilling to accept any more Child SAs on this IKE SA (refer to
         //RFC 7296, section 1.3)
         sa->noAdditionalSas = TRUE;

         //Delete the Child SA
         ikeDeleteChildSaEntry(childSa);
         sa->childSa1 = NULL;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);

         //A failed attempt to create a Child SA should not tear down the IKE
         //SA. There is no reason to lose the work done to set up the IKE SA
         //(refer to RFC 7296, section 1.3.1)
         return NO_ERROR;
      }
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE)
      {
         //When a peer receives a TEMPORARY_FAILURE notification, it must not
         //immediately retry the operation; it must wait so that the sender may
         //complete whatever operation caused the temporary condition (refer to
         //RFC 7296, section 2.25)
         return NO_ERROR;
      }
      else
      {
         //An implementation receiving an error type that it does not recognize
         //in a response must assume that the corresponding request has failed
         //entirely (refer to RFC 7296, section 3.10.1)
         ikeDeleteChildSaEntry(childSa);
         sa->childSa1 = NULL;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_OPEN);

         //A failed attempt to create a Child SA should not tear down the IKE
         //SA. There is no reason to lose the work done to set up the IKE SA
         //(refer to RFC 7296, section 1.3.1)
         return NO_ERROR;
      }
   }

   //Mandatory payloads must be included in the received message
   if(payloads->sa == NULL || payloads->nonce == NULL ||
      payloads->tsi == NULL || payloads->tsr == NULL)
   {
      return ERROR_INVALID_MESSAGE;
   }

   //Save responder's nonce
   error = ikeParseNoncePayload(payloads->nonce, childSa->responderNonce,
      &childSa->responderNonceLen);
   //Malformed nonce?
   if(error)
      return error;

   //Check the syntax of the SAr payload
   error = ikeParseSaPayload(payloads->sa);
   //Malformed SAr payload?
   if(error)
      return error;

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   error = ikeCheckChildSaProposal(childSa, payloads->sa);
   //Invalid cryptographic suite?
   if(error)
      return error;

   //The initiator can request that the Child SA use transport mode rather than
   //tunnel mode for the SA created
   if(childSa->mode == IPSEC_MODE_TRANSPORT)
   {
      //If the request is accepted, the response must also include a
      //notification of type USE_TRANSPORT_MODE
      if(payloads->useTransportModeNotify == NULL)
      {
         //Use tunnel mode
         childSa->mode = IPSEC_MODE_TUNNEL;
      }
   }

   //When the responder chooses a subset of the traffic proposed by the
   //initiator, it narrows the Traffic Selectors to some subset of the
   //initiator's proposal (refer to RFC 7296, section 2.9)
   error = ikeCheckTs(childSa, payloads->tsi, payloads->tsr, FALSE);
   //Invalid traffic selector?
   if(error)
      return error;

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
   //Perfect forward secrecy?
   if(childSa->pfs)
   {
      //The responder replies with a Diffie-Hellman value in the KEr payload if
      //KEi was included in the request and the selected cryptographic suite
      //includes that group (refer to RFC 7296, section 1.3.1)
      error = ikeParseKePayload(&childSa->keContext, payloads->ke);
      //Any error to report?
      if(error)
         return error;

      //Let g^ir be the Diffie-Hellman shared secret
      error = ikeComputeSharedSecret(&childSa->keContext, childSa->sharedSecret,
            &childSa->sharedSecretLen);
      //Any error to report?
      if(error)
         return error;

      //Release Diffie-Hellman context
      ikeFreeKeContext(&childSa->keContext);
      ikeInitKeContext(&childSa->keContext);
   }
#endif

   //Keying material for Child SAs must be taken from the expanded KEYMAT (refer
   //to RFC 7296, section 2.17)
   error = ikeGenerateChildSaKeyMaterial(childSa);
   //Any error to report?
   if(error)
      return error;

   //The new Child SA has been successfully created
   ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_OPEN);

   //ESP and AH SAs exist in pairs (one in each direction), so two SAs are
   //created in a single Child SA negotiation for them
   ikeCreateIpsecSaPair(childSa);

   //Update the state of the IKE SA
   ikeChangeSaState(sa, IKE_SA_STATE_OPEN);
   sa->childSa1 = NULL;

   //Successful processing
   return NO_ERROR;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Process Child SA rekeying response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 * @return Error code
 **/

error_t ikeProcessChildSaRekeyResponse(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   uint16_t notifyMsgType;
   IkeChildSaEntry *childSa;
   IkeChildSaEntry *oldChildSa;

   //Point to the Child SA
   childSa = sa->childSa1;
   //Point to the old Child SA
   oldChildSa = childSa->oldChildSa;

   //Error notification received?
   if(payloads->errorNotify != NULL)
   {
      //Types in the range 0-16383 are intended for reporting errors
      notifyMsgType = ntohs(payloads->errorNotify->notifyMsgType);

      //Check the type of the notification message
      if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
      {
         //The INVALID_SYNTAX error notification is considered fatal in both
         //peers, meaning that the IKE SA is deleted without needing an explicit
         //Delete payload (refer to RFC 7296, section 2.21.3)
         return ERROR_INVALID_SYNTAX;
      }
#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
      {
         IkeContext *context;

         //Point to the IKE context
         context = sa->context;

         //If the responder indicates its preferred Diffie-Hellman group in the
         //INVALID_KE_PAYLOAD Notify payload (refer to RFC 7296, section 1.3)
         error = ikeParseInvalidKePayloadNotification(&childSa->keContext,
            payloads->errorNotify);
         //Malformed notification?
         if(error)
            return error;

         //Reinitialize Diffie-Hellman context
         ikeFreeKeContext(&childSa->keContext);
         ikeInitKeContext(&childSa->keContext);

         //Generate a new ephemeral key pair
         error = ikeGenerateKeyPair(&childSa->keContext, context->prngAlgo,
            context->prngContext);
         //Any error to report?
         if(error)
            return error;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_CHILD_REQ);

         //The initiator retries the exchange with a Diffie-Hellman proposal and
         //KEi in the group that the responder gave in the INVALID_KE_PAYLOAD
         //Notify payload
         return ikeSendCreateChildSaRequest(sa);
      }
#endif
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS)
      {
         //The responder sends a NO_ADDITIONAL_SAS notification to indicate
         //that a CREATE_CHILD_SA request is unacceptable because the responder
         //is unwilling to accept any more Child SAs on this IKE SA (refer to
         //RFC 7296, section 1.3)
         ikeDeleteChildSaEntry(childSa);
         sa->childSa1 = NULL;

         //Close the IKE SA
         return ikeProcessSaDeleteEvent(sa);
      }
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE)
      {
         //When a peer receives a TEMPORARY_FAILURE notification, it must not
         //immediately retry the operation; it must wait so that the sender may
         //complete whatever operation caused the temporary condition (refer to
         //RFC 7296, section 2.25)
         return NO_ERROR;
      }
      else
      {
         //An implementation receiving an error type that it does not recognize
         //in a response must assume that the corresponding request has failed
         //entirely (refer to RFC 7296, section 3.10.1)
         ikeDeleteChildSaEntry(childSa);
         sa->childSa1 = NULL;

         //Close the old Child SA
         return ikeProcessChildSaDeleteEvent(oldChildSa);
      }
   }

   //Mandatory payloads must be included in the received message
   if(payloads->sa == NULL || payloads->nonce == NULL ||
      payloads->tsi == NULL || payloads->tsr == NULL)
   {
      return ERROR_INVALID_MESSAGE;
   }

   //Save responder's nonce
   error = ikeParseNoncePayload(payloads->nonce, childSa->responderNonce,
      &childSa->responderNonceLen);
   //Malformed nonce?
   if(error)
      return error;

   //Check the syntax of the SAr payload
   error = ikeParseSaPayload(payloads->sa);
   //Malformed SAr payload?
   if(error)
      return error;

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   error = ikeCheckChildSaProposal(childSa, payloads->sa);
   //Invalid cryptographic suite?
   if(error)
      return error;

   //The initiator can request that the Child SA use transport mode rather than
   //tunnel mode for the SA created
   if(childSa->mode == IPSEC_MODE_TRANSPORT)
   {
      //If the request is accepted, the response must also include a
      //notification of type USE_TRANSPORT_MODE
      if(payloads->useTransportModeNotify == NULL)
      {
         //Use tunnel mode
         childSa->mode = IPSEC_MODE_TUNNEL;
      }
   }

   //The responder must not narrow down the Traffic Selectors narrower than the
   //scope currently in use (refer to RFC 7296, section 2.9.2)
   error = ikeCheckTs(childSa, payloads->tsi, payloads->tsr, TRUE);
   //Invalid traffic selector?
   if(error)
      return error;

#if (IKE_CHILD_SA_PFS_SUPPORT == ENABLED)
   //Perfect forward secrecy?
   if(childSa->pfs)
   {
      //The responder replies with a Diffie-Hellman value in the KEr payload if
      //KEi was included in the request and the selected cryptographic suite
      //includes that group (refer to RFC 7296, section 1.3.1)
      error = ikeParseKePayload(&childSa->keContext, payloads->ke);
      //Any error to report?
      if(error)
         return error;

      //Let g^ir be the Diffie-Hellman shared secret
      error = ikeComputeSharedSecret(&childSa->keContext, childSa->sharedSecret,
            &childSa->sharedSecretLen);
      //Any error to report?
      if(error)
         return error;

      //Release Diffie-Hellman context
      ikeFreeKeContext(&childSa->keContext);
      ikeInitKeContext(&childSa->keContext);
   }
#endif

   //Keying material for Child SAs must be taken from the expanded KEYMAT (refer
   //to RFC 7296, section 2.17)
   error = ikeGenerateChildSaKeyMaterial(childSa);
   //Any error to report?
   if(error)
      return error;

   //Simultaneous rekeying?
   if(sa->childSa2 != NULL)
   {
      //Simultaneous Child SA rekeying may temporarily result in multiple
      //similar SAs between the same pairs of nodes (refer to RFC 7296,
      //section 2.8.1)
      if(ikeCompareChildSaNonces(sa->childSa2, childSa) > 0)
      {
         //Update the state of the surviving new Child SA
         ikeChangeChildSaState(sa->childSa2, IKE_CHILD_SA_STATE_OPEN);

         //ESP and AH SAs always exist in pairs, with one SA in each direction
         ikeCreateIpsecSaPair(sa->childSa2);

         //Detach the newly created Child SA
         sa->childSa2 = NULL;

         //The SA created with the lowest of the four nonces used in the two
         //exchanges should be closed by the endpoint that created it
         error = ikeProcessChildSaDeleteEvent(childSa);
      }
      else
      {
         //The SA created with the lowest of the four nonces used in the two
         //exchanges should be closed by the endpoint that created it
         ikeChangeChildSaState(sa->childSa2, IKE_CHILD_SA_STATE_OPEN);

         //Detach the newly created Child SA
         sa->childSa2 = NULL;

         //Update the state of the surviving new Child SA
         ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_OPEN);

         //ESP and AH SAs always exist in pairs, with one SA in each direction
         ikeCreateIpsecSaPair(childSa);

         //The node that initiated the surviving rekeyed SA should delete the
         //replaced SA after the new one is established
         error = ikeProcessChildSaDeleteEvent(oldChildSa);
      }
   }
   else
   {
      //The new Child SA has been successfully created
      ikeChangeChildSaState(childSa, IKE_CHILD_SA_STATE_OPEN);

      //ESP and AH SAs always exist in pairs, with one SA in each direction
      ikeCreateIpsecSaPair(childSa);

      //To rekey a Child SA within an existing IKE SA, create a new, equivalent
      //SA, and when the new one is established, delete the old one (refer to
      //RFC 7296, section 2.8)
      error = ikeProcessChildSaDeleteEvent(oldChildSa);
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Process IKE SA rekeying response
 * @param[in] sa Pointer to the IKE SA
 * @param[in] payloads Pointer to the IKE message payloads
 * @return Error code
 **/

error_t ikeProcessIkeSaRekeyResponse(IkeSaEntry *sa,
   IkeMessagePayloads *payloads)
{
#if (IKE_CREATE_CHILD_SA_SUPPORT == ENABLED)
   error_t error;
   uint16_t notifyMsgType;
   IkeSaEntry *newSa;

   //Point to the new IKE SA
   newSa = sa->newSa1;

   //Error notification received?
   if(payloads->errorNotify != NULL)
   {
      //Types in the range 0-16383 are intended for reporting errors
      notifyMsgType = ntohs(payloads->errorNotify->notifyMsgType);

      //Check the type of the notification message
      if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_SYNTAX)
      {
         //The INVALID_SYNTAX error notification is considered fatal in both
         //peers, meaning that the IKE SA is deleted without needing an explicit
         //Delete payload (refer to RFC 7296, section 2.21.3)
         return ERROR_INVALID_SYNTAX;
      }
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_INVALID_KE_PAYLOAD)
      {
         IkeContext *context;

         //Point to the IKE context
         context = sa->context;

         //If the initiator guesses wrong, the responder will respond with a
         //Notify payload of type INVALID_KE_PAYLOAD indicating the selected
         //group (refer to RFC 7296, section 1.2)
         error = ikeParseInvalidKePayloadNotification(&newSa->keContext,
            payloads->errorNotify);
         //Malformed notification?
         if(error)
            return error;

         //Reinitialize Diffie-Hellman context
         ikeFreeKeContext(&newSa->keContext);
         ikeInitKeContext(&newSa->keContext);

         //Generate a new ephemeral key pair
         error = ikeGenerateKeyPair(&newSa->keContext, context->prngAlgo,
            context->prngContext);
         //Any error to report?
         if(error)
            return error;

         //Update the state of the IKE SA
         ikeChangeSaState(sa, IKE_SA_STATE_REKEY_REQ);

         //The initiator must retry the CREATE_CHILD_SA with the corrected
         //Diffie-Hellman group
         return ikeSendCreateChildSaRequest(sa);
      }
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_NO_ADDITIONAL_SAS)
      {
         //If the responder rejects the CREATE_CHILD_SA request with a
         //NO_ADDITIONAL_SAS notification, the implementation must be capable
         //of instead deleting the old SA and creating a new one (refer to
         //RFC 7296, section 4)
         ikeDeleteSaEntry(newSa);
         sa->newSa1 = NULL;

         //Close the IKE SA
         return ikeProcessSaDeleteEvent(sa);
      }
      else if(notifyMsgType == IKE_NOTIFY_MSG_TYPE_TEMPORARY_FAILURE)
      {
         //When a peer receives a TEMPORARY_FAILURE notification, it must not
         //immediately retry the operation; it must wait so that the sender may
         //complete whatever operation caused the temporary condition (refer to
         //RFC 7296, section 2.25)
         return NO_ERROR;
      }
      else
      {
         //An implementation receiving an error type that it does not recognize
         //in a response must assume that the corresponding request has failed
         //entirely (refer to RFC 7296, section 3.10.1)
         ikeDeleteSaEntry(newSa);
         sa->newSa1 = NULL;

         //Close the IKE SA
         return ikeProcessSaDeleteEvent(sa);
      }
   }

   //Mandatory payloads must be included in the received message
   if(payloads->sa == NULL || payloads->nonce == NULL || payloads->ke == NULL)
      return ERROR_INVALID_MESSAGE;

   //Save responder's nonce
   error = ikeParseNoncePayload(payloads->nonce, newSa->responderNonce,
      &newSa->responderNonceLen);
   //Malformed nonce?
   if(error)
      return error;

   //Check the syntax of the SAr payload
   error = ikeParseSaPayload(payloads->sa);
   //Malformed SAr payload?
   if(error)
      return error;

   //The initiator of an exchange must check that the accepted offer is
   //consistent with one of its proposals, and if not must terminate the
   //exchange (refer to RFC 7296, section 3.3.6)
   error = ikeCheckSaProposal(newSa, payloads->sa);
   //Invalid cryptographic suite?
   if(error)
      return error;

   //Nonces used in IKEv2 must be at least half the key size of the negotiated
   //pseudorandom function (refer to RFC 7296, section 2.10)
   error = ikeCheckNonceLength(newSa, newSa->responderNonceLen);
   //Unacceptable nonce length?
   if(error)
      return error;

   //The Key Exchange payload is used to exchange Diffie-Hellman public numbers
   //as part of a Diffie-Hellman key exchange
   error = ikeParseKePayload(&newSa->keContext, payloads->ke);
   //Any error to report?
   if(error)
      return error;

   //Let g^ir be the Diffie-Hellman shared secret
   error = ikeComputeSharedSecret(&newSa->keContext, newSa->sharedSecret,
         &newSa->sharedSecretLen);
   //Any error to report?
   if(error)
      return error;

   //Release Diffie-Hellman context
   ikeFreeKeContext(&newSa->keContext);
   ikeInitKeContext(&newSa->keContext);

   //At this point in the negotiation, each party can generate a quantity
   //called SKEYSEED, from which all keys are derived for that IKE SA (refer
   //to RFC 7296, section 1.2)
   error = ikeGenerateSaKeyMaterial(newSa, sa);
   //Any error to report?
   if(error)
      return error;

   //Simultaneous rekeying?
   if(sa->newSa2 != NULL)
   {
      //When both peers try to rekey the IKE SA at the same time, it is
      //important to ensure that the Child SAs are inherited by the correct
      //IKE SA (refer to RFC 7296, section 2.8.2)
      if(ikeCompareSaNonces(sa->newSa2, newSa) > 0)
      {
         //Update the state of the surviving new IKE SA
         ikeChangeSaState(sa->newSa2, IKE_SA_STATE_OPEN);

         //The surviving new IKE SA must inherit all the Child SAs
         ikeInheritChildSas(sa->newSa2, sa);

         //Detach the newly created IKE SA
         sa->newSa2 = NULL;

         //The new IKE SA containing the lowest nonce should be deleted by the
         //node that created it
         error = ikeProcessSaDeleteEvent(newSa);
      }
      else
      {
         //The new IKE SA containing the lowest nonce should be deleted by the
         //node that created it
         ikeChangeSaState(sa->newSa2, IKE_SA_STATE_OPEN);

         //Detach the newly created IKE SA
         sa->newSa2 = NULL;

         //Update the state of the surviving new IKE SA
         ikeChangeSaState(newSa, IKE_SA_STATE_OPEN);

         //The surviving new IKE SA must inherit all the Child SAs
         ikeInheritChildSas(newSa, sa);

         //The node that initiated the surviving rekeyed SA should delete the
         //replaced SA after the new one is established
         error = ikeProcessSaDeleteEvent(sa);
      }
   }
   else
   {
      //The new IKE SA has been successfully created
      ikeChangeSaState(newSa, IKE_SA_STATE_OPEN);

      //The new IKE SA inherits all of the original IKE SA's Child SAs, and is
      //used for all control messages needed to maintain those Child SAs
      ikeInheritChildSas(newSa, sa);

      //After the new equivalent IKE SA is created, the initiator deletes the
      //old IKE SA, and the Delete payload to delete itself must be the last
      //request sent over the old IKE SA (refer to RFC 7296, section 2.8)
      error = ikeProcessSaDeleteEvent(sa);
   }

   //Return status code
   return error;
#else
   //Minimal implementations are not required to support the CREATE_CHILD_SA
   //exchange (refer to RFC 7296, section 4)
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
