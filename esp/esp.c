/**
 * @file esp.c
 * @brief ESP (IP Encapsulating Security Payload)
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
#define TRACE_LEVEL ESP_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_inbound.h"
#include "ipsec/ipsec_anti_replay.h"
#include "ipsec/ipsec_misc.h"
#include "esp/esp.h"
#include "esp/esp_packet_decrypt.h"
#include "core/tcp_fsm.h"
#include "core/raw_socket.h"
#include "ipv4/icmp.h"
#include "debug.h"

//Check IPsec library configuration
#if (ESP_SUPPORT == ENABLED)


/**
 * @brief Process ESP protected packet
 * @param[in] interface Underlying network interface
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] buffer Multi-part buffer containing the ESP protected packet
 * @param[in] offset Offset to the first byte of the ESP header
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t ipv4ProcessEspHeader(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset,
   NetRxAncillary *ancillary)
{
   error_t error;
   size_t length;
   uint64_t seq;
   uint8_t nextHeader;
   size_t offset2;
   NetBuffer *buffer2;
   IpsecContext *context;
   IpsecSadEntry *sa;
   EspHeader *espHeader;
   IpsecSelector selector;
   IpPseudoHeader pseudoHeader;

   //Point to the IPsec context
   context = netContext.ipsecContext;
   //Sanity check
   if(context == NULL)
      return ERROR_FAILURE;

   //Retrieve the length of the payload
   length = netBufferGetLength(buffer) - offset;

   //Malformed packet?
   if(length < sizeof(EspHeader))
      return ERROR_INVALID_HEADER;

   //Point to the ESP header
   espHeader = netBufferAt(buffer, offset, 0);
   //Sanity check
   if(espHeader == NULL)
      return ERROR_FAILURE;

   //Debug message
   TRACE_INFO("Parsing ESP header...\r\n");
   //Dump AH header contents for debugging purpose
   espDumpHeader(espHeader);

   //Upon receipt of a packet containing an ESP Header, the receiver determines
   //the appropriate (unidirectional) SA via lookup in the SAD (refer to
   //RFC 4303, section 3.4.2)
   sa = ipsecFindInboundSadEntry(context, IPSEC_PROTOCOL_ESP,
      ntohl(espHeader->spi));

   //If no valid Security Association exists for this packet the receiver
   //must discard the packet. This is an auditable event
   if(sa == NULL)
   {
      //Debug message
      TRACE_WARNING("ESP: No matching SA found!\r\n");
      //Report an error
      return ERROR_POLICY_FAILURE;
   }

   //Check IPsec mode
   if(sa->mode == IPSEC_MODE_TRANSPORT)
   {
      //Transport mode ESP is applied only to whole IP datagrams (not to IP
      //fragments)
      if((ntohs(ipv4Header->fragmentOffset) & IPV4_OFFSET_MASK) != 0 ||
         (ntohs(ipv4Header->fragmentOffset) & IPV4_FLAG_MF) != 0)
      {
         return ERROR_INVALID_HEADER;
      }
   }
   else
   {
      //In tunnel mode, ESP is applied to an IP packet, which may be a fragment
      //of an IP datagram
   }

   //Because only the low-order 32 bits are transmitted with the packet, the
   //receiver must deduce and track the sequence number subspace into which
   //each packet falls
   seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

   //For each received packet, the receiver must verify that the packet
   //contains a Sequence Number that does not duplicate the Sequence Number of
   //any other packets received during the life of this SA. This should be the
   //first ESP check applied to a packet after it has been matched to an SA, to
   //speed rejection of duplicate packets (refer to RFC 4303, section 3.4.3)
   error = ipsecCheckReplayWindow(sa, seq);

   //Duplicate packets are rejected
   if(error)
   {
      //Debug message
      TRACE_WARNING("ESP: Invalid sequence number!\r\n");
      //Report an error
      return ERROR_WRONG_SEQUENCE_NUMBER;
   }

   //Point to the payload data
   offset += sizeof(EspHeader);
   length -= sizeof(EspHeader);

   //Check the length of the payload data
   if(length > ESP_BUFFER_SIZE)
      return ERROR_INVALID_LENGTH;

   //Copy the payload data to be decrypted
   netBufferRead(context->buffer, buffer, offset, length);

   //if a separate integrity algorithm is employed, then the receiver proceeds
   //to integrity verification, then decryption. If a combined mode algorithm
   //is employed, the integrity check is performed along with decryption
   error = espDecryptPacket(context, sa, espHeader, context->buffer, &length,
      &nextHeader);

   //If the integrity check fails, the receiver must discard the received IP
   //datagram as invalid. This is an auditable event
   if(error)
   {
      //Debug message
      TRACE_WARNING("ESP: ICV validation failed!\r\n");
      //Report an error
      return ERROR_AUTHENTICATION_FAILED;
   }

   //The receive window is updated only if the ICV verification succeeds
   ipsecUpdateReplayWindow(sa, seq);

   //Allocate a buffer to hold the decrypted payload
   buffer2 = ipAllocBuffer(length, &offset2);
   //Failed to allocate memory?
   if(buffer2 == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the resulting data
   netBufferWrite(buffer2, offset2, context->buffer, length);

   //Retrieve packet's selector
   error = ipsecGetInboundIpv4PacketSelector(ipv4Header, nextHeader, buffer2,
      offset2, &selector);

   //Check status code
   if(!error)
   {
      //Match the packet against the inbound selectors identified by the SAD
      //entry to verify that the received packet is appropriate for the SA via
      //which it was received (refer to RFC 4301, section 5.2)
      if(ipsecIsSubsetSelector(&selector, &sa->selector))
      {
         //Form the IPv4 pseudo header
         pseudoHeader.length = sizeof(Ipv4PseudoHeader);
         pseudoHeader.ipv4Data.srcAddr = ipv4Header->srcAddr;
         pseudoHeader.ipv4Data.destAddr = ipv4Header->destAddr;
         pseudoHeader.ipv4Data.reserved = 0;
         pseudoHeader.ipv4Data.protocol = nextHeader;
         pseudoHeader.ipv4Data.length = htons(length);

         //If the computed and received ICVs match, then the datagram is valid,
         //and it is accepted (refer to RFC 4303, section 3.4.4.1)
         switch(nextHeader)
         {
         //ICMP protocol?
         case IPV4_PROTOCOL_ICMP:
            //Process incoming ICMP message
            icmpProcessMessage(interface, &pseudoHeader.ipv4Data, buffer2,
               offset2);

#if (RAW_SOCKET_SUPPORT == ENABLED)
            //Allow raw sockets to process ICMP messages
            rawSocketProcessIpPacket(interface, &pseudoHeader, buffer2,
               offset2, ancillary);
#endif
            //Continue processing
            break;

#if (IGMP_HOST_SUPPORT == ENABLED || IGMP_ROUTER_SUPPORT == ENABLED || \
   IGMP_SNOOPING_SUPPORT == ENABLED)
         //IGMP protocol?
         case IPV4_PROTOCOL_IGMP:
            //Process incoming IGMP message
            igmpProcessMessage(interface, &pseudoHeader.ipv4Data, buffer2,
               offset2, ancillary);

#if (RAW_SOCKET_SUPPORT == ENABLED)
            //Allow raw sockets to process IGMP messages
            rawSocketProcessIpPacket(interface, &pseudoHeader, buffer2,
               offset2, ancillary);
#endif
            //Continue processing
            break;
#endif

#if (TCP_SUPPORT == ENABLED)
         //TCP protocol?
         case IPV4_PROTOCOL_TCP:
            //Process incoming TCP segment
            tcpProcessSegment(interface, &pseudoHeader, buffer2, offset2,
               ancillary);
            //Continue processing
            break;
#endif

#if (UDP_SUPPORT == ENABLED)
         //UDP protocol?
         case IPV4_PROTOCOL_UDP:
            //Process incoming UDP datagram
            error = udpProcessDatagram(interface, &pseudoHeader, buffer2, offset2,
               ancillary);
            //Continue processing
            break;
#endif

         //Unknown protocol?
         default:
#if (RAW_SOCKET_SUPPORT == ENABLED)
            //Allow raw sockets to process IPv4 packets
            error = rawSocketProcessIpPacket(interface, &pseudoHeader, buffer2,
               offset2, ancillary);
#else
            //Report an error
            error = ERROR_PROTOCOL_UNREACHABLE;
#endif
            //Continue processing
            break;
         }
      }
      else
      {
         //If an IPsec system receives an inbound packet on an SA and the
         //packet's header fields are not consistent with the selectors for
         //the SA, it must discard the packet. This is an auditable event
         error = ERROR_POLICY_FAILURE;
      }
   }

   //Free previously allocated memory
   netBufferFree(buffer2);

   //Return status code
   return error;
}


/**
 * @brief Dump ESP header for debugging purpose
 * @param[in] espHeader Pointer to the ESP header
 **/

void espDumpHeader(const EspHeader *espHeader)
{
   //Dump ESP header contents
   TRACE_DEBUG("  SPI = 0x%08" PRIX32 "\r\n", ntohl(espHeader->spi));
   TRACE_DEBUG("  Sequence Number = 0x%08" PRIX32 "\r\n", ntohl(espHeader->seqNum));
}

#endif
