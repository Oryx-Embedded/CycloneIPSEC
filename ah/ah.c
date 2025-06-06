/**
 * @file ah.c
 * @brief AH (IP Authentication Header)
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
#define TRACE_LEVEL AH_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_inbound.h"
#include "ipsec/ipsec_anti_replay.h"
#include "ipsec/ipsec_misc.h"
#include "ah/ah.h"
#include "core/tcp_fsm.h"
#include "core/raw_socket.h"
#include "ipv4/icmp.h"
#include "debug.h"

//Check IPsec library configuration
#if (AH_SUPPORT == ENABLED)


/**
 * @brief Process AH protected packet
 * @param[in] interface Underlying network interface
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] buffer Multi-part buffer containing the AH protected packet
 * @param[in] offset Offset to the first byte of the AH header
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t ipv4ProcessAhHeader(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset,
   NetRxAncillary *ancillary)
{
   error_t error;
   size_t n;
   size_t length;
   uint64_t seq;
   IpsecSadEntry *sa;
   AhHeader *ahHeader;
   IpsecSelector selector;
   IpPseudoHeader pseudoHeader;

   //Retrieve the length of the payload
   length = netBufferGetLength(buffer) - offset;

   //Malformed packet?
   if(length < sizeof(AhHeader))
      return ERROR_INVALID_HEADER;

   //Point to the AH header
   ahHeader = netBufferAt(buffer, offset, 0);
   //Sanity check
   if(ahHeader == NULL)
      return ERROR_FAILURE;

   //If a packet offered to AH for processing appears to be an IP fragment,
   //the receiver must discard the packet (refer to RFC 4302, section 3.4.1)
   if((ntohs(ipv4Header->fragmentOffset) & IPV4_OFFSET_MASK) != 0 ||
      (ntohs(ipv4Header->fragmentOffset) & IPV4_FLAG_MF) != 0)
   {
      return ERROR_INVALID_HEADER;
   }

   //Upon receipt of a packet containing an IP Authentication Header, the
   //receiver determines the appropriate (unidirectional) SA via lookup in
   //the SAD (refer to RFC 4302, section 3.4.2)
   sa = ipsecFindInboundSadEntry(netContext.ipsecContext, IPSEC_PROTOCOL_AH,
      ntohl(ahHeader->spi));

   //If no valid Security Association exists for this packet the receiver
   //must discard the packet. This is an auditable event
   if(sa == NULL)
   {
      //Debug message
      TRACE_WARNING("AH: No matching SA found!\r\n");
      //Report an error
      return ERROR_POLICY_FAILURE;
   }

   //The Payload Length field specifies the length of AH header in 32-bit
   //words (4-byte units), minus 2
   n = (ahHeader->payloadLen + 2) * sizeof(uint32_t);

   //Check the length of the AH header
   if(n > length || n != (sizeof(AhHeader) + sa->icvLen))
      return ERROR_INVALID_HEADER;

   //Debug message
   TRACE_INFO("Parsing AH header...\r\n");
   //Dump AH header contents for debugging purpose
   ahDumpHeader(ahHeader);

   //Because only the low-order 32 bits are transmitted with the packet, the
   //receiver must deduce and track the sequence number subspace into which
   //each packet falls
   seq = ipsecGetSeqNum(sa, ntohl(ahHeader->seqNum));

   //For each received packet, the receiver must verify that the packet
   //contains a Sequence Number that does not duplicate the Sequence Number of
   //any other packets received during the life of this SA. This should be the
   //first AH check applied to a packet after it has been matched to an SA, to
   //speed rejection of duplicate packets (refer to RFC 4302, section 3.4.3)
   error = ipsecCheckReplayWindow(sa, seq);

   //Duplicate packets are rejected
   if(error)
   {
      //Debug message
      TRACE_WARNING("AH: Invalid sequence number!\r\n");
      //Report an error
      return ERROR_WRONG_SEQUENCE_NUMBER;
   }

   //If the received packet falls within the window and is not a duplicate, or
   //if the packet is to the right of the window, then the receiver proceeds to
   //ICV verification
   error = ahVerifyIcv(sa, ipv4Header, ahHeader, buffer,
      offset + sizeof(AhHeader) + sa->icvLen);

   //If the ICV validation fails, the receiver must discard the received IP
   //datagram as invalid. This is is an auditable event (refer to RFC 4302,
   //section 3.4.3)
   if(error)
   {
      //Debug message
      TRACE_WARNING("AH: ICV validation failed!\r\n");
      //Report an error
      return ERROR_AUTHENTICATION_FAILED;
   }

   //The receive window is updated only if the ICV verification succeeds
   ipsecUpdateReplayWindow(sa, seq);

   //Point to the payload
   offset += n;
   length -= n;

   //Match the packet against the inbound selectors identified by the SAD entry
   //to verify that the received packet is appropriate for the SA via which it
   //was received (refer to RFC 4301, section 5.2)
   error = ipsecGetInboundIpv4PacketSelector(ipv4Header, ahHeader->nextHeader,
      buffer, offset, &selector);
   //Any error to report?
   if(error)
      return error;

   //If an IPsec system receives an inbound packet on an SA and the packet's
   //header fields are not consistent with the selectors for the SA, it must
   //discard the packet. This is an auditable event
   if(!ipsecIsSubsetSelector(&selector, &sa->selector))
      return ERROR_POLICY_FAILURE;

   //Form the IPv4 pseudo header
   pseudoHeader.length = sizeof(Ipv4PseudoHeader);
   pseudoHeader.ipv4Data.srcAddr = ipv4Header->srcAddr;
   pseudoHeader.ipv4Data.destAddr = ipv4Header->destAddr;
   pseudoHeader.ipv4Data.reserved = 0;
   pseudoHeader.ipv4Data.protocol = ahHeader->nextHeader;
   pseudoHeader.ipv4Data.length = htons(length);

   //If the computed and received ICVs match, then the datagram is valid, and
   //it is accepted (refer to RFC 4302, section 3.4.4)
   switch(ahHeader->nextHeader)
   {
   //ICMP protocol?
   case IPV4_PROTOCOL_ICMP:
      //Process incoming ICMP message
      icmpProcessMessage(interface, &pseudoHeader.ipv4Data, buffer, offset);

#if (RAW_SOCKET_SUPPORT == ENABLED)
      //Allow raw sockets to process ICMP messages
      rawSocketProcessIpPacket(interface, &pseudoHeader, buffer, offset,
         ancillary);
#endif

      //Continue processing
      break;

#if (IGMP_HOST_SUPPORT == ENABLED || IGMP_ROUTER_SUPPORT == ENABLED || \
   IGMP_SNOOPING_SUPPORT == ENABLED)
   //IGMP protocol?
   case IPV4_PROTOCOL_IGMP:
      //Process incoming IGMP message
      igmpProcessMessage(interface, &pseudoHeader.ipv4Data, buffer, offset,
         ancillary);

#if (RAW_SOCKET_SUPPORT == ENABLED)
      //Allow raw sockets to process IGMP messages
      rawSocketProcessIpPacket(interface, &pseudoHeader, buffer, offset,
         ancillary);
#endif

      //Continue processing
      break;
#endif

#if (TCP_SUPPORT == ENABLED)
   //TCP protocol?
   case IPV4_PROTOCOL_TCP:
      //Process incoming TCP segment
      tcpProcessSegment(interface, &pseudoHeader, buffer, offset, ancillary);
      //Continue processing
      break;
#endif

#if (UDP_SUPPORT == ENABLED)
   //UDP protocol?
   case IPV4_PROTOCOL_UDP:
      //Process incoming UDP datagram
      error = udpProcessDatagram(interface, &pseudoHeader, buffer, offset,
         ancillary);
      //Continue processing
      break;
#endif

   //Unknown protocol?
   default:
#if (RAW_SOCKET_SUPPORT == ENABLED)
      //Allow raw sockets to process IPv4 packets
      error = rawSocketProcessIpPacket(interface, &pseudoHeader, buffer, offset,
         ancillary);
#else
      //Report an error
      error = ERROR_PROTOCOL_UNREACHABLE;
#endif
      //Continue processing
      break;
   }

   //Return status code
   return error;
}


/**
 * @brief ICV generation
 * @param[in] sa Pointer to the SA
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in,out] ahHeader Pointer to the AH header
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @return Error code
 **/

error_t ahGenerateIcv(IpsecSadEntry *sa, const Ipv4Header *ipv4Header,
   AhHeader *ahHeader, const NetBuffer *buffer, size_t offset)
{
   error_t error;
   uint_t i;
   size_t n;
   uint8_t *p;
   IpsecContext *context;

   //Point to the IPsec context
   context = netContext.ipsecContext;
   //Invalid IPsec context?
   if(context == NULL)
      return ERROR_FAILURE;

#if (AH_CMAC_SUPPORT == ENABLED)
   //CMAC integrity algorithm?
   if(sa->authCipherAlgo != NULL)
   {
      CmacContext *cmacContext;

      //Point to the CMAC context
      cmacContext = &context->cmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation
      error = cmacInit(cmacContext, sa->authCipherAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //Compute CMAC over the IP or extension header fields before the AH
         //header that are either immutable in transit or that are predictable
         //in value upon arrival at the endpoint for the AH SA
         cmacUpdate(cmacContext, ipv4Header, sizeof(Ipv4Header));

         //Compute CMAC over the Next Header, Payload Length, Reserved, SPI,
         //Sequence Number (low-order 32 bits) fields, and the ICV (which is
         //set to zero for this computation)
         cmacUpdate(cmacContext, ahHeader, sizeof(AhHeader) + sa->icvLen);

         //Everything after AH is assumed to be immutable in transit
         for(i = 0; i < buffer->chunkCount; i++)
         {
            //Is there any data to process from the current chunk?
            if(offset < buffer->chunk[i].length)
            {
               //Point to the first byte to be processed
               p = (uint8_t *) buffer->chunk[i].address + offset;
               //Compute the number of bytes to process at a time
               n = buffer->chunk[i].length - offset;

               //Update CMAC calculation
               cmacUpdate(cmacContext, p, n);

               //Process the next block from the start
               offset = 0;
            }
            else
            {
               //Skip the current chunk
               offset -= buffer->chunk[i].length;
            }
         }

         //Extended sequence numbers?
         if(sa->esn)
         {
            //If the ESN option is elected for an SA, then the high-order 32
            //bits of the ESN must be included in the ICV computation
            uint32_t seqh = htonl(sa->seqNum >> 32);

            //For purposes of ICV computation, these bits are appended
            //(implicitly) immediately after the end of the payload
            cmacUpdate(cmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize CMAC calculation
         cmacFinal(cmacContext, ahHeader->icv, sa->icvLen);
      }
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED)
   //HMAC integrity algorithm?
   if(sa->authHashAlgo != NULL)
   {
      HmacContext *hmacContext;

      //Point to the HMAC context
      hmacContext = &context->hmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation
      error = hmacInit(hmacContext, sa->authHashAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //Compute HMAC over the IP or extension header fields before the AH
         //header that are either immutable in transit or that are predictable
         //in value upon arrival at the endpoint for the AH SA
         hmacUpdate(hmacContext, ipv4Header, sizeof(Ipv4Header));

         //Compute HMAC over the Next Header, Payload Length, Reserved, SPI,
         //Sequence Number (low-order 32 bits) fields, and the ICV (which is
         //set to zero for this computation)
         hmacUpdate(hmacContext, ahHeader, sizeof(AhHeader) + sa->icvLen);

         //Everything after AH is assumed to be immutable in transit
         for(i = 0; i < buffer->chunkCount; i++)
         {
            //Is there any data to process from the current chunk?
            if(offset < buffer->chunk[i].length)
            {
               //Point to the first byte to be processed
               p = (uint8_t *) buffer->chunk[i].address + offset;
               //Compute the number of bytes to process at a time
               n = buffer->chunk[i].length - offset;

               //Update HMAC calculation
               hmacUpdate(hmacContext, p, n);

               //Process the next block from the start
               offset = 0;
            }
            else
            {
               //Skip the current chunk
               offset -= buffer->chunk[i].length;
            }
         }

         //Extended sequence numbers?
         if(sa->esn)
         {
            //If the ESN option is elected for an SA, then the high-order 32
            //bits of the ESN must be included in the ICV computation
            uint32_t seqh = htonl(sa->seqNum >> 32);

            //For purposes of ICV computation, these bits are appended
            //(implicitly) immediately after the end of the payload
            hmacUpdate(hmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize HMAC calculation
         hmacFinal(hmacContext, NULL);
         //The output of the HMAC can be truncated
         osMemcpy(ahHeader->icv, hmacContext->digest, sa->icvLen);
      }
   }
   else
#endif
   //Unknown integrity algorithm?
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief ICV verification
 * @param[in] sa Pointer to the SA
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] ahHeader Pointer to the AH header
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @return Error code
 **/

error_t ahVerifyIcv(IpsecSadEntry *sa, const Ipv4Header *ipv4Header,
   const AhHeader *ahHeader, const NetBuffer *buffer, size_t offset)
{
   error_t error;
   uint8_t mask;
   uint_t i;
   size_t n;
   uint8_t *p;
   IpsecContext *context;
   Ipv4Header *ipv4Header2;
   AhHeader *ahHeader2;
   uint8_t temp[IPV4_MAX_HEADER_LENGTH];
   uint8_t checksum[AH_MAX_DIGEST_SIZE];

   //Point to the IPsec context
   context = netContext.ipsecContext;
   //Invalid IPsec context?
   if(context == NULL)
      return ERROR_FAILURE;

   //Calculate the length of the IPv4 header
   n = ipv4Header->headerLength * 4;
   //Copy the IPv4 header
   osMemcpy(temp, ipv4Header, n);
   //Point to the IPv4 header
   ipv4Header2 = (Ipv4Header *) temp;

   //If a field may be modified during transit, the value of the field is set
   //to zero for purposes of the ICV computation
   ipv4Header2->typeOfService = 0;
   ipv4Header2->fragmentOffset = 0;
   ipv4Header2->timeToLive = 0;
   ipv4Header2->headerChecksum = 0;

   //Mutable options are zeroed before performing the ICV calculation
   ahProcessMutableIpv4Options(ipv4Header2);

#if (AH_CMAC_SUPPORT == ENABLED)
   //CMAC integrity algorithm?
   if(sa->authCipherAlgo != NULL)
   {
      CmacContext *cmacContext;

      //Point to the CMAC context
      cmacContext = &context->cmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation,
      //and indicates the key required to validate the ICV
      error = cmacInit(cmacContext, sa->authCipherAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //Compute CMAC over the IP or extension header fields before the AH
         //header that are either immutable in transit or that are predictable
         //in value upon arrival at the endpoint for the AH SA
         cmacUpdate(cmacContext, temp, n);

         //The Payload Length field specifies the length of AH header in 32-bit
         //words (4-byte units), minus 2
         n = (ahHeader->payloadLen + 2) * sizeof(uint32_t);

         //Copy the AH header
         osMemcpy(temp, ahHeader, n);
         //Point to the AH header
         ahHeader2 = (AhHeader *) temp;

         //The Integrity Check Value field is also set to zero in preparation
         //for this computation (refer to RFC 4302, section 3.3.3.1)
         osMemset(ahHeader2->icv, 0, sa->icvLen);

         //Compute CMAC over the Next Header, Payload Length, Reserved, SPI,
         //Sequence Number (low-order 32 bits) fields, and the ICV (which is
         //set to zero for this computation)
         cmacUpdate(cmacContext, temp, n);

         //Everything after AH is assumed to be immutable in transit
         for(i = 0; i < buffer->chunkCount; i++)
         {
            //Is there any data to process from the current chunk?
            if(offset < buffer->chunk[i].length)
            {
               //Point to the first byte to be processed
               p = (uint8_t *) buffer->chunk[i].address + offset;
               //Compute the number of bytes to process at a time
               n = buffer->chunk[i].length - offset;

               //Update CMAC calculation
               cmacUpdate(cmacContext, p, n);

               //Process the next block from the start
               offset = 0;
            }
            else
            {
               //Skip the current chunk
               offset -= buffer->chunk[i].length;
            }
         }

         //Extended sequence numbers?
         if(sa->esn)
         {
            //If the ESN option is elected for an SA, then the high-order 32
            //bits of the ESN must be included in the ICV computation
            uint32_t seqh = ipsecGetSeqNum(sa, ntohl(ahHeader->seqNum)) >> 32;

            //Convert the 32-bit value to network byte order
            seqh = htonl(seqh);

            //For purposes of ICV computation, these bits are appended
            //(implicitly) immediately after the end of the payload
            cmacUpdate(cmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize CMAC computation
         cmacFinal(cmacContext, checksum, sa->icvLen);
      }
   }
   else
#endif
#if (AH_HMAC_SUPPORT == ENABLED)
   //HMAC integrity algorithm?
   if(sa->authHashAlgo != NULL)
   {
      HmacContext *hmacContext;

      //Point to the HMAC context
      hmacContext = &context->hmacContext;

      //The SAD entry specifies the algorithm employed for ICV computation,
      //and indicates the key required to validate the ICV
      error = hmacInit(hmacContext, sa->authHashAlgo, sa->authKey,
         sa->authKeyLen);

      //Check status code
      if(!error)
      {
         //Compute HMAC over the IP or extension header fields before the AH
         //header that are either immutable in transit or that are predictable
         //in value upon arrival at the endpoint for the AH SA
         hmacUpdate(hmacContext, temp, n);

         //The Payload Length field specifies the length of AH header in 32-bit
         //words (4-byte units), minus 2
         n = (ahHeader->payloadLen + 2) * 4;

         //Copy the AH header
         osMemcpy(temp, ahHeader, n);
         //Point to the AH header
         ahHeader2 = (AhHeader *) temp;

         //The Integrity Check Value field is also set to zero in preparation
         //for this computation (refer to RFC 4302, section 3.3.3.1)
         osMemset(ahHeader2->icv, 0, sa->icvLen);

         //Compute HMAC over the Next Header, Payload Length, Reserved, SPI,
         //Sequence Number (low-order 32 bits) fields, and the ICV (which is
         //set to zero for this computation)
         hmacUpdate(hmacContext, temp, n);

         //Everything after AH is assumed to be immutable in transit
         for(i = 0; i < buffer->chunkCount; i++)
         {
            //Is there any data to process from the current chunk?
            if(offset < buffer->chunk[i].length)
            {
               //Point to the first byte to be processed
               p = (uint8_t *) buffer->chunk[i].address + offset;
               //Compute the number of bytes to process at a time
               n = buffer->chunk[i].length - offset;

               //Update HMAC calculation
               hmacUpdate(hmacContext, p, n);

               //Process the next block from the start
               offset = 0;
            }
            else
            {
               //Skip the current chunk
               offset -= buffer->chunk[i].length;
            }
         }

         //Extended sequence numbers?
         if(sa->esn)
         {
            //If the ESN option is elected for an SA, then the high-order 32
            //bits of the ESN must be included in the ICV computation
            uint32_t seqh = ipsecGetSeqNum(sa, ntohl(ahHeader->seqNum)) >> 32;

            //Convert the 32-bit value to network byte order
            seqh = htonl(seqh);

            //For purposes of ICV computation, these bits are appended
            //(implicitly) immediately after the end of the payload
            hmacUpdate(hmacContext, (uint8_t *) &seqh, 4);
         }

         //Finalize HMAC computation
         hmacFinal(hmacContext, checksum);
      }
   }
   else
#endif
   //Unknown integrity algorithm?
   {
      //Report an error
      error = ERROR_INVALID_MAC;
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG_ARRAY("Calculated ICV = ", checksum, sa->icvLen);

      //The calculated checksum is bitwise compared to the received ICV
      for(mask = 0, i = 0; i < sa->icvLen; i++)
      {
         mask |= checksum[i] ^ ahHeader->icv[i];
      }

      //If the ICV validation fails, the receiver must discard the received IP
      //datagram as invalid. This is is an auditable event (refer to RFC 4302,
      //section 3.4.3)
      error = (mask == 0) ? NO_ERROR : ERROR_INVALID_MAC;
   }

   //Return status code
   return error;
}


/**
 * @brief Zeroize mutable IPv4 options
 * @param[in] header Pointer to the IPv4 header
 **/

void ahProcessMutableIpv4Options(Ipv4Header *header)
{
   size_t i;
   size_t n;
   size_t length;
   Ipv4Option *option;

   //Compute the length of the options field
   length = (header->headerLength * 4) - sizeof(TcpHeader);

   //Point to the very first option
   i = 0;

   //Loop through the list of options
   while(i < length)
   {
      //Point to the current option
      option = (Ipv4Option *) (header->options + i);

      //Check option type
      if(option->type == IPV4_OPTION_EEOL)
      {
         //This option code indicates the end of the option list
         break;
      }
      else if(option->type == IPV4_OPTION_NOP)
      {
         //This option consists of a single octet
         i++;
      }
      else
      {
         //Malformed option?
         if((i + 1) >= length)
            break;

         //The option code is followed by a one-byte length field
         n = option->length;

         //Check the length of the option
         if(n < sizeof(Ipv4Option) || (i + n) > length)
            break;

         //Mutable option?
         if(option->type != IPV4_OPTION_SEC &&
            option->type != IPV4_OPTION_ESEC &&
            option->type != IPV4_OPTION_CIPSO &&
            option->type != IPV4_OPTION_RTRALT &&
            option->type != IPV4_OPTION_SDB)
         {
            //The entire option is zeroed before performing the ICV calculation
            osMemset(option, 0, n);
         }

         //Jump to the next option
         i += n;
      }
   }
}


/**
 * @brief Dump AH header for debugging purpose
 * @param[in] ahHeader Pointer to the AH header
 **/

void ahDumpHeader(const AhHeader *ahHeader)
{
   size_t n;

   //The Payload Length field specifies the length of AH header in 32-bit
   //words (4-byte units), minus 2
   n = (ahHeader->payloadLen + 2) * sizeof(uint32_t);

   //Check the length of the AH header
   if(n >= sizeof(AhHeader))
   {
      //Retrieve the length of the ICV tag
      n -= sizeof(AhHeader);

      //Dump AH header contents
      TRACE_DEBUG("  Next Header = %" PRIu8 "\r\n", ahHeader->nextHeader);
      TRACE_DEBUG("  Payload Length = %" PRIu8 "\r\n", ahHeader->payloadLen);
      TRACE_DEBUG("  SPI = 0x%08" PRIX32 "\r\n", ntohl(ahHeader->spi));
      TRACE_DEBUG("  Sequence Number = 0x%08" PRIX32 "\r\n", ntohl(ahHeader->seqNum));
      TRACE_DEBUG_ARRAY("  ICV = ", ahHeader->icv, n);
   }
}

#endif
