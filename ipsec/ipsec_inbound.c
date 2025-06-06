/**
 * @file ipsec_inbound.c
 * @brief IPsec processing of inbound IP traffic
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

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_inbound.h"
#include "ipsec/ipsec_misc.h"
#include "debug.h"

//Check IPsec library configuration
#if (IPSEC_SUPPORT == ENABLED)


/**
 * @brief Inbound IPv4 traffic processing
 * @param[in] interface Underlying network interface
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] buffer Multi-part buffer containing the IP payload
 * @param[in] offset Offset from the beginning of the buffer
 * @return Error code
 **/

error_t ipsecProcessInboundIpv4Packet(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset)
{
   error_t error;
   IpsecSpdEntry *spdEntry;
   IpsecSelector selector;

   //The packet is examined and demuxed into one of two categories (refer to
   //RFC 7296, section 5.2)
   if(ipv4Header->protocol == IPV4_PROTOCOL_AH ||
      ipv4Header->protocol == IPV4_PROTOCOL_ESP)
   {
      //If the packet appears to be IPsec protected and it is addressed to
      //this device, then parse the AH or the ESP header
      error = NO_ERROR;
   }
   else
   {
      //If the packet is not addressed to the device or is addressed to this
      //device and is not AH or ESP, look up the packet header in the SPD-I
      //cache (refer to RFC 4301, section 5.2)
      error = ipsecGetInboundIpv4PacketSelector(ipv4Header,
         ipv4Header->protocol, buffer, offset, &selector);

      //Check status code
      if(!error)
      {
         //Search the SPD for a matching entry
         spdEntry = ipsecFindSpdEntry(netContext.ipsecContext,
            IPSEC_POLICY_ACTION_INVALID, &selector);

         //Any SPD entry found?
         if(spdEntry != NULL)
         {
            //Check applicable SPD policies
            if(spdEntry->policyAction == IPSEC_POLICY_ACTION_BYPASS)
            {
               //The packet allowed to bypass IPsec protection
               error = NO_ERROR;
            }
            else
            {
               //Discard the packet
               error = ERROR_POLICY_FAILURE;
            }
         }
         else
         {
            //If there is no match, discard the traffic
            error = ERROR_POLICY_FAILURE;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Extract packet's selector from inbound IPv4 packet
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] nextHeader Value of the next header field
 * @param[in] buffer Multi-part buffer containing the IP payload
 * @param[in] offset Offset from the beginning of the buffer
 * @param[out] selector Pointer to the IPsec selector
 * @return Error code
 **/

error_t ipsecGetInboundIpv4PacketSelector(const Ipv4Header *ipv4Header,
   uint8_t nextHeader, const NetBuffer *buffer, size_t offset,
   IpsecSelector *selector)
{
   error_t error;
   size_t length;
   const uint8_t *data;

   //Initialize status code
   error = NO_ERROR;

   //Local IP address range
   selector->localIpAddr.start.length = sizeof(Ipv4Addr);
   selector->localIpAddr.start.ipv4Addr = ipv4Header->destAddr;
   selector->localIpAddr.end.length = sizeof(Ipv4Addr);
   selector->localIpAddr.end.ipv4Addr = ipv4Header->destAddr;

   //Remote IP address range
   selector->remoteIpAddr.start.length = sizeof(Ipv4Addr);
   selector->remoteIpAddr.start.ipv4Addr = ipv4Header->srcAddr;
   selector->remoteIpAddr.end.length = sizeof(Ipv4Addr);
   selector->remoteIpAddr.end.ipv4Addr = ipv4Header->srcAddr;

   //Next Layer Protocol value
   selector->nextProtocol = nextHeader;

   //Retrieve the length of the data
   length = netBufferGetLength(buffer) - offset;
   //Point to the data
   data = netBufferAt(buffer, offset, 0);

   //Sanity check
   if(data != NULL)
   {
      //Several additional selectors depend on the Next Layer Protocol value
      //(refer to RFC 4301, section 4.4.1.1)
      if(nextHeader == IPV4_PROTOCOL_UDP && length >= sizeof(UdpHeader))
      {
         //Point to the UDP header
         UdpHeader *udpHeader = (UdpHeader *) data;

         //If the Next Layer Protocol value is UDP, then there are selectors
         //for local and remote ports
         selector->localPort.start = ntohs(udpHeader->destPort);
         selector->localPort.end = ntohs(udpHeader->destPort);
         selector->remotePort.start = ntohs(udpHeader->srcPort);
         selector->remotePort.end = ntohs(udpHeader->srcPort);
      }
      else if(nextHeader == IPV4_PROTOCOL_TCP && length >= sizeof(TcpHeader))
      {
         //Point to the TCP header
         TcpHeader *tcpHeader = (TcpHeader *) data;

         //If the Next Layer Protocol value is TCP, then there are selectors
         //for local and remote ports
         selector->localPort.start = ntohs(tcpHeader->destPort);
         selector->localPort.end = ntohs(tcpHeader->destPort);
         selector->remotePort.start = ntohs(tcpHeader->srcPort);
         selector->remotePort.end = ntohs(tcpHeader->srcPort);
      }
      else if(nextHeader == IPV4_PROTOCOL_ICMP && length >= sizeof(IcmpHeader))
      {
         //Point to the ICMP header
         IcmpHeader *icmpHeader = (IcmpHeader *) data;

         //If the Next Layer Protocol value is ICMP, then there is a 16-bit
         //selector for the ICMP message type and code
         selector->localPort.start = IPSEC_PORT_START_OPAQUE;
         selector->localPort.end = IPSEC_PORT_END_OPAQUE;
         selector->remotePort.start = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
         selector->remotePort.end = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
      }
      else
      {
         //The local and remote port selectors may be labeled as OPAQUE to
         //accommodate situations where these fields are inaccessible
         selector->localPort.start = IPSEC_PORT_START_OPAQUE;
         selector->localPort.end = IPSEC_PORT_END_OPAQUE;
         selector->remotePort.start = IPSEC_PORT_START_OPAQUE;
         selector->remotePort.end = IPSEC_PORT_END_OPAQUE;
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_HEADER;
   }

   //Return status code
   return error;
}


/**
 * @brief Determine the higher-order bits of the sequence number
 * @param[in] sa Pointer to the security association
 * @param[in] seql Lower 32 bits of the sequence number extracted from the
 *   received packet
 * @return 64-bit sequence number
 **/

uint64_t ipsecGetSeqNum(IpsecSadEntry *sa, uint32_t seql)
{
   uint32_t bl;
   uint32_t tl;
   uint32_t th;
   uint32_t seqh;

   //Extended sequence numbers?
   if(sa->esn)
   {
      //The upper bound of window represents the highest sequence number
      //authenticated so far
      tl = sa->seqNum & 0xFFFFFFFF;
      th = (sa->seqNum >> 32) & 0xFFFFFFFF;

      //Lower bound of window
      bl = tl - IPSEC_ANTI_REPLAY_WINDOW_SIZE + 1;

      //When performing the anti-replay check, or when determining which
      //high-order bits to use to authenticate an incoming packet, there are
      //two cases
      if(tl >= (IPSEC_ANTI_REPLAY_WINDOW_SIZE - 1))
      {
         //In this case, the window is within one sequence number subspace
         if(seql >= bl)
         {
            seqh = th;
         }
         else
         {
            seqh = th + 1;
         }
      }
      else
      {
         //In this case, the window spans two sequence number subspaces
         if(seql >= bl)
         {
            seqh = th - 1;
         }
         else
         {
            seqh = th;
         }
      }
   }
   else
   {
      //The sequence number is a 32-bit field
      seqh = 0;
   }

   //Reconstruct the 64-bit sequence number
   return ((uint64_t) seqh << 32) | seql;
}

#endif
