/**
 * @file ipsec_outbound.c
 * @brief IPsec processing of outbound IP traffic
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

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_outbound.h"
#include "ipsec/ipsec_misc.h"
#include "ike/ike.h"
#include "ah/ah.h"
#include "esp/esp.h"
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
   IpsecContext *context;
   IpsecSadEntry *sadEntry;
   IpsecSpdEntry *spdEntry;
   IpsecSelector selector;

   //Point to the IPsec context
   context = interface->netContext->ipsecContext;

   //Extract packet's selector from the packet headers
   error = ipsecGetOutboundIpv4PacketSelector(pseudoHeader, buffer, offset,
      &selector);

   //Check status code
   if(!error)
   {
      //Search the SPD for a matching entry
      spdEntry = ipsecFindSpdEntry(context, IPSEC_POLICY_ACTION_INVALID,
         &selector, TRUE);

      //Any SPD entry found?
      if(spdEntry != NULL)
      {
         //Check applicable SPD policies
         if(spdEntry->policyAction == IPSEC_POLICY_ACTION_PROTECT)
         {
            //If the SPD entry calls for PROTECT, then search the SAD for an
            //existing security association
            sadEntry = ipsecFindOutboundSadEntry(context, &selector);

            //Any SAD entry found?
            if(sadEntry != NULL)
            {
               //Protect the outbound packet using AH or ESP
               error = ipsecProtectOutboundIpv4Packet(context, sadEntry,
                  interface, pseudoHeader, fragId, buffer, offset, ancillary);
            }
            else
            {
               //Broadcast or multicast packet?
               if(ipv4IsBroadcastAddr(interface, pseudoHeader->destAddr) ||
                  ipv4IsMulticastAddr(pseudoHeader->destAddr))
               {
                  //Standard IKEv2 cannot negotiate SAs for multicast traffic
                  error = ERROR_POLICY_FAILURE;
               }
               else
               {
                  IpsecPacketInfo packetInfo;

                  //The key management mechanism is invoked to create the SA
                  packetInfo.localIpAddr.length = sizeof(Ipv4Addr);
                  packetInfo.localIpAddr.ipv4Addr = pseudoHeader->srcAddr;
                  packetInfo.remoteIpAddr.length = sizeof(Ipv4Addr);
                  packetInfo.remoteIpAddr.ipv4Addr = pseudoHeader->destAddr;
                  packetInfo.nextProtocol = pseudoHeader->protocol;
                  packetInfo.localPort = selector.localPort.start;
                  packetInfo.remotePort = selector.remotePort.start;

                  //Create a new SA using IKEv2
                  ikeCreateChildSa(interface->netContext->ikeContext, &packetInfo);

                  //There is no requirement that an implementation buffer the
                  //packet if there is a cache miss (refer to RFC 4301,
                  //section 5.2)
                  error = ERROR_IN_PROGRESS;
               }
            }
         }
         else if(spdEntry->policyAction == IPSEC_POLICY_ACTION_BYPASS)
         {
            //If the SPD entry calls for BYPASS, then the packet is not protected
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
 * @brief Extract packet's selector from outbound IPv4 packet
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] buffer Multi-part buffer containing the IP payload
 * @param[in] offset Offset from the beginning of the buffer
 * @param[out] selector Pointer to the IPsec selector
 * @return Error code
 **/

error_t ipsecGetOutboundIpv4PacketSelector(const Ipv4PseudoHeader *pseudoHeader,
   const NetBuffer *buffer, size_t offset, IpsecSelector *selector)
{
   error_t error;
   size_t length;
   const uint8_t *data;

   //Initialize status code
   error = NO_ERROR;

   //Local IP address range
   selector->localIpAddr.start.length = sizeof(Ipv4Addr);
   selector->localIpAddr.start.ipv4Addr = pseudoHeader->srcAddr;
   selector->localIpAddr.end.length = sizeof(Ipv4Addr);
   selector->localIpAddr.end.ipv4Addr = pseudoHeader->srcAddr;

   //Remote IP address range
   selector->remoteIpAddr.start.length = sizeof(Ipv4Addr);
   selector->remoteIpAddr.start.ipv4Addr = pseudoHeader->destAddr;
   selector->remoteIpAddr.end.length = sizeof(Ipv4Addr);
   selector->remoteIpAddr.end.ipv4Addr = pseudoHeader->destAddr;

   //Next Layer Protocol value
   selector->nextProtocol = pseudoHeader->protocol;

   //Retrieve the length of the data
   length = netBufferGetLength(buffer) - offset;
   //Point to the data
   data = netBufferAt(buffer, offset, 0);

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
         selector->localPort.start = ntohs(udpHeader->srcPort);
         selector->localPort.end = ntohs(udpHeader->srcPort);
         selector->remotePort.start = ntohs(udpHeader->destPort);
         selector->remotePort.end = ntohs(udpHeader->destPort);
      }
      else if(pseudoHeader->protocol == IPV4_PROTOCOL_TCP &&
         length >= sizeof(TcpHeader))
      {
         //Point to the TCP header
         TcpHeader *tcpHeader = (TcpHeader *) data;

         //If the Next Layer Protocol value is TCP, then there are selectors
         //for local and remote ports
         selector->localPort.start = ntohs(tcpHeader->srcPort);
         selector->localPort.end = ntohs(tcpHeader->srcPort);
         selector->remotePort.start = ntohs(tcpHeader->destPort);
         selector->remotePort.end = ntohs(tcpHeader->destPort);
      }
      else if(pseudoHeader->protocol == IPV4_PROTOCOL_ICMP &&
         length >= sizeof(IcmpHeader))
      {
         //Point to the ICMP header
         IcmpHeader *icmpHeader = (IcmpHeader *) data;

         //If the Next Layer Protocol value is ICMP, then there is a 16-bit
         //selector for the ICMP message type and code
         selector->localPort.start = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
         selector->localPort.end = IPSEC_ICMP_PORT(icmpHeader->type, icmpHeader->code);
         selector->remotePort.start = IPSEC_PORT_START_OPAQUE;
         selector->remotePort.end = IPSEC_PORT_END_OPAQUE;
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
 * @brief Protect an outbound IPv4 packet using AH or ESP
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the security association
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] fragId Fragment identification field
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t ipsecProtectOutboundIpv4Packet(IpsecContext *context, IpsecSadEntry *sa,
   NetInterface *interface, const Ipv4PseudoHeader *pseudoHeader,
   uint16_t fragId, NetBuffer *buffer, size_t offset,
   NetTxAncillary *ancillary)
{
   error_t error;

   //Check the state of the SAD entry
   if(sa->state == IPSEC_SA_STATE_OPEN)
   {
#if (AH_SUPPORT == ENABLED)
      //AH protocol?
      if(sa->protocol == IPSEC_PROTOCOL_AH)
      {
         //Protect the IPv4 packet using AH
         error = ahProtectOutboundIpv4Packet(context, sa, interface,
            pseudoHeader, fragId, buffer, offset, ancillary);
      }
      else
#endif
#if (ESP_SUPPORT == ENABLED)
      //ESP protocol?
      if(sa->protocol == IPSEC_PROTOCOL_ESP)
      {
         //Protect the IPv4 packet using ESP
         error = espProtectOutboundIpv4Packet(context, sa, interface,
            pseudoHeader, fragId, buffer, offset, ancillary);
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
      //An IP datagram can be marked "don't fragment". Any IP datagram so
      //marked is not to be fragmented under any circumstances (refer to
      //RFC791, section 2.3)
      if(!ancillary->dontFrag)
      {
         //If the payload length exceeds the network interface MTU then the
         //device must fragment the data
         error = ipv4FragmentDatagram(interface, pseudoHeader, fragId, buffer,
            offset, ancillary);
      }
      else
#endif
      {
         //If IP datagram cannot be delivered to its destination without
         //fragmenting it, it is to be discarded instead
         error = ERROR_MESSAGE_TOO_LONG;
      }
   }

   //Return status code
   return error;
}

#endif
