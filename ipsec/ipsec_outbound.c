/**
 * @file ipsec_outbound.c
 * @brief IPsec processing of outbound IP traffic
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_outbound.h"
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ah/ah.h"
#include "esp/esp_packet_encrypt.h"
#include "debug.h"

//Check IPsec library configuration
#if (IPSEC_SUPPORT == ENABLED)


/**
 * @brief Outbound IPv4 traffic processing
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] fragId Fragment identification field
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t ipsecProcessOutboundIpv4Packet(NetInterface *interface,
   const Ipv4PseudoHeader *pseudoHeader, uint16_t fragId, NetBuffer *buffer,
   size_t offset, NetTxAncillary *ancillary)
{
   error_t error;
   size_t length;
   const uint8_t *data;
   IpsecContext *context;
   IpsecSadEntry *sadEntry;
   IpsecSpdEntry *spdEntry;
   IpsecSelector selector;

   //Point to the IPsec context
   context = netContext.ipsecContext;

   //The packet fields are chosen as the selector
   selector.localIpAddr.start.length = sizeof(Ipv4Addr);
   selector.localIpAddr.start.ipv4Addr = pseudoHeader->srcAddr;
   selector.localIpAddr.end.length = sizeof(Ipv4Addr);
   selector.localIpAddr.end.ipv4Addr = pseudoHeader->srcAddr;
   selector.remoteIpAddr.start.length = sizeof(Ipv4Addr);
   selector.remoteIpAddr.start.ipv4Addr = pseudoHeader->destAddr;
   selector.remoteIpAddr.end.length = sizeof(Ipv4Addr);
   selector.remoteIpAddr.end.ipv4Addr = pseudoHeader->destAddr;
   selector.nextProtocol = pseudoHeader->protocol;

   //Retrieve the length of the data
   length = netBufferGetLength(buffer) - offset;
   //Point to the data
   data = netBufferAt(buffer, offset);

   //Sanity check
   if(data != NULL)
   {
      //Several additional selectors depend on the Next Layer Protocol value
      //(refer to RFC 4301, section 4.4.1.1)
      if(pseudoHeader->protocol == IPV4_PROTOCOL_UDP &&
         length >= sizeof(UdpHeader))
      {
         //Point to the UDP header
         UdpHeader *udpHeader = (UdpHeader *) data;

         //If the Next Layer Protocol value is UDP, then there are selectors
         //for local and remote ports
         selector.localPort.start = ntohs(udpHeader->srcPort);
         selector.localPort.end = ntohs(udpHeader->srcPort);
         selector.remotePort.start = ntohs(udpHeader->destPort);
         selector.remotePort.end = ntohs(udpHeader->destPort);
      }
      else if(pseudoHeader->protocol == IPV4_PROTOCOL_TCP &&
         length >= sizeof(TcpHeader))
      {
         //Point to the TCP header
         TcpHeader *tcpHeader = (TcpHeader *) data;

         //If the Next Layer Protocol value is TCP, then there are selectors
         //for local and remote ports
         selector.localPort.start = ntohs(tcpHeader->srcPort);
         selector.localPort.end = ntohs(tcpHeader->srcPort);
         selector.remotePort.start = ntohs(tcpHeader->destPort);
         selector.remotePort.end = ntohs(tcpHeader->destPort);
      }
      else if(pseudoHeader->protocol == IPV4_PROTOCOL_ICMP &&
         length >= sizeof(IcmpHeader))
      {
         //Point to the ICMP header
         IcmpHeader *icmpHeader = (IcmpHeader *) data;

         //If the Next Layer Protocol value is ICMP, then there is a 16-bit
         //selector for the ICMP message type and code
         selector.localPort.start = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
         selector.localPort.end = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
         selector.remotePort.start = IPSEC_PORT_START_OPAQUE;
         selector.remotePort.end = IPSEC_PORT_END_OPAQUE;
      }
      else
      {
         //The local and remote port selectors may be labeled as OPAQUE to
         //accommodate situations where these fields are inaccessible
         selector.localPort.start = IPSEC_PORT_START_OPAQUE;
         selector.localPort.end = IPSEC_PORT_END_OPAQUE;
         selector.remotePort.start = IPSEC_PORT_START_OPAQUE;
         selector.remotePort.end = IPSEC_PORT_END_OPAQUE;
      }

      //Match the packet header against the cache
      sadEntry = ipsecFindOutboundSadEntry(context, &selector);
   }
   else
   {
      //Malformed IPv4 packet
      sadEntry = NULL;
   }

   //If there is a match, then process the packet as specified by the matching
   //cache entry
   if(sadEntry != NULL)
   {
      //Check the state of the SAD entry
      if(sadEntry->state == IPSEC_SA_STATE_OPEN)
      {
#if (AH_SUPPORT == ENABLED)
         //AH protocol?
         if(sadEntry->protocol == IPSEC_PROTOCOL_AH)
         {
            AhHeader *ahHeader;
            Ipv4Header ipv4Header;
            Ipv4PseudoHeader pseudoHeader2;

            //Sanity check
            if(offset < (sizeof(AhHeader) + sadEntry->icvLen))
               return ERROR_FAILURE;

            //Make room for the AH header
            offset -= sizeof(AhHeader) + sadEntry->icvLen;
            length += sizeof(AhHeader) + sadEntry->icvLen;

            //The AH header is inserted after the IP header and before a next
            //layer protocol
            ahHeader = netBufferAt(buffer, offset);

            //The sender increments the sequence number counter for this SA and
            //inserts the low-order 32 bits of the value into the Sequence
            //Number field (refer to RFC 4302, section 3.3.2)
            sadEntry->seqNum++;

            //Format AH header
            ahHeader->nextHeader = pseudoHeader->protocol;
            ahHeader->payloadLen = (sizeof(AhHeader) + sadEntry->icvLen) / 4 - 2;
            ahHeader->reserved = 0;
            ahHeader->spi = htonl(sadEntry->spi);
            ahHeader->seqNum = htonl(sadEntry->seqNum);

            //The Integrity Check Value field is also set to zero in preparation
            //for this computation (refer to RFC 4302, section 3.3.3.1)
            osMemset(ahHeader->icv, 0, sadEntry->icvLen);

            //Format outer IPv4 header
            osMemset(&ipv4Header, 0, sizeof(Ipv4Header));
            ipv4Header.version = IPV4_VERSION;
            ipv4Header.headerLength = 5;
            ipv4Header.typeOfService = 0;
            ipv4Header.totalLength = htons(length + sizeof(Ipv4Header));
            ipv4Header.identification = htons(fragId);
            ipv4Header.fragmentOffset = 0;
            ipv4Header.timeToLive = 0;
            ipv4Header.protocol = IPV4_PROTOCOL_AH;
            ipv4Header.headerChecksum = 0;
            ipv4Header.srcAddr = pseudoHeader->srcAddr;
            ipv4Header.destAddr = pseudoHeader->destAddr;

            //Compute ICV value
            error = ahGenerateIcv(sadEntry, &ipv4Header, ahHeader, buffer,
               offset + sizeof(AhHeader) + sadEntry->icvLen);
            //Any error to report?
            if(error)
               return error;

            //Fix the Next Layer Protocol value
            pseudoHeader2 = *pseudoHeader;
            pseudoHeader2.protocol = IPV4_PROTOCOL_AH;

            //Debug message
            TRACE_INFO("AH Header:\r\n");
            ahDumpHeader(ahHeader);

            //Send AH packet
            error = ipsecSendIpv4Packet(interface, &pseudoHeader2, fragId,
               buffer, offset, ancillary);
         }
         else
#endif
#if (ESP_SUPPORT == ENABLED)
         //ESP protocol?
         if(sadEntry->protocol == IPSEC_PROTOCOL_ESP)
         {
            size_t offset2;
            NetBuffer *buffer2;
            Ipv4PseudoHeader pseudoHeader2;
            EspHeader *espHeader;

            //Sanity check
            if((length + sizeof(EspHeader)) > ESP_BUFFER_SIZE)
               return ERROR_FAILURE;

            //The ESP header is inserted after the IP header and before the
            //next layer protocol header (transport mode) or before an
            //encapsulated IP header (tunnel mode)
            espHeader = (EspHeader *) context->buffer;

            //The sender increments the sequence number counter for this SA and
            //inserts the low-order 32 bits of the value into the Sequence
            //Number field (refer to RFC 4303, section 3.3.3)
            sadEntry->seqNum++;

            //Format ESP header
            espHeader->spi = htonl(sadEntry->spi);
            espHeader->seqNum = htonl(sadEntry->seqNum);

            //Debug message
            TRACE_INFO("ESP Header:\r\n");
            espDumpHeader(espHeader);

            //Copy the payload data to be encrypted
            netBufferRead(espHeader->payloadData + sadEntry->ivLen, buffer,
               offset, length);

            //The encryption algorithm employed to protect the ESP packet is
            //specified by the SA via which the packet is transmitted
            error = espEncryptPacket(context, sadEntry, espHeader,
               espHeader->payloadData, &length, pseudoHeader->protocol);
            //Any error to report?
            if(error)
               return error;

            //Calculate the length of the resulting ESP packet
            length += sizeof(EspHeader);

            //Allocate a buffer to hold the ESP packet
            buffer2 = ipAllocBuffer(length, &offset2);
            //Failed to allocate memory?
            if(buffer2 == NULL)
               return ERROR_OUT_OF_MEMORY;

            //Copy the resulting ESP packet
            netBufferWrite(buffer2, offset2, context->buffer, length);

            //The outer IPv4 protocol header that immediately precedes the ESP
            //header shall contain the value 50 in its Protocol field (refer to
            //RFC 4303, section 2)
            pseudoHeader2 = *pseudoHeader;
            pseudoHeader2.protocol = IPV4_PROTOCOL_ESP;

            //Send ESP packet
            error = ipsecSendIpv4Packet(interface, &pseudoHeader2, fragId,
               buffer2, offset2, ancillary);

            //Free previously allocated memory
            netBufferFree(buffer2);
         }
         else
#endif
         //Invalid IPsec protocol?
         {
            //Report an error
            error = ERROR_INVALID_PROTOCOL;
         }
      }
      else
      {
         //The establishment of the SA pair is in progress
         error = ERROR_IN_PROGRESS;
      }
   }
   else
   {
      //If no match is found in the cache, search the SPD
      spdEntry = ipsecFindSpdEntry(context, IPSEC_POLICY_ACTION_INVALID,
         &selector);

      //Any SPD entry found?
      if(spdEntry != NULL)
      {
         //Check applicable SPD policies
         if(spdEntry->policyAction == IPSEC_POLICY_ACTION_PROTECT)
         {
            IpsecPacketInfo packetInfo;

            //If the SPD entry calls for PROTECT, the key management mechanism
            //is invoked to create the SA
            packetInfo.localIpAddr.length = sizeof(Ipv4Addr);
            packetInfo.localIpAddr.ipv4Addr = pseudoHeader->srcAddr;
            packetInfo.remoteIpAddr.length = sizeof(Ipv4Addr);
            packetInfo.remoteIpAddr.ipv4Addr = pseudoHeader->destAddr;
            packetInfo.nextProtocol = pseudoHeader->protocol;
            packetInfo.localPort = selector.localPort.start;
            packetInfo.remotePort = selector.remotePort.start;

            //Create a new SA
            ikeCreateChildSa(netContext.ikeContext, &packetInfo);

            //There is no requirement that an implementation buffer the packet
            //if there is a cache miss (refer to RFC 4301, section 5.2)
            error = ERROR_IN_PROGRESS;
         }
         else if(spdEntry->policyAction == IPSEC_POLICY_ACTION_BYPASS)
         {
            //If the SPD entry calls for BYPASS, then the packet is not
            //protected
            error = ipsecSendIpv4Packet(interface, pseudoHeader, fragId,
               buffer, offset, ancillary);
         }
         else
         {
            //If the SPD entry calls for DISCARD, then drop the packet
            error = ERROR_POLICY_FAILURE;
         }
      }
      else
      {
         //If there is no match, discard the traffic
         error = ERROR_POLICY_FAILURE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send an IPv4 packet
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] fragId Fragment identification field
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t ipsecSendIpv4Packet(NetInterface *interface,
   const Ipv4PseudoHeader *pseudoHeader, uint16_t fragId, NetBuffer *buffer,
   size_t offset, NetTxAncillary *ancillary)
{
   error_t error;
   size_t length;

   //Retrieve the length of payload
   length = netBufferGetLength(buffer) - offset;

   //Check the length of the payload
   if((length + sizeof(Ipv4Header)) <= interface->ipv4Context.linkMtu)
   {
      //If the payload length is smaller than the network interface MTU
      //then no fragmentation is needed
      error = ipv4SendPacket(interface, pseudoHeader, fragId, 0, buffer,
         offset, ancillary);
   }
   else
   {
#if (IPV4_FRAG_SUPPORT == ENABLED)
      //If the payload length exceeds the network interface MTU then the
      //device must fragment the data
      error = ipv4FragmentDatagram(interface, pseudoHeader, fragId, buffer,
         offset, ancillary);
#else
      //Fragmentation is not supported
      error = ERROR_MESSAGE_TOO_LONG;
#endif
   }

   //Return status code
   return error;
}

#endif
