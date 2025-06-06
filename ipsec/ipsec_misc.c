/**
 * @file ipsec_misc.c
 * @brief Helper routines for IPsec
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
#include "ipsec/ipsec_misc.h"
#include "debug.h"

//Check IPsec library configuration
#if (IPSEC_SUPPORT == ENABLED)

//Invalid SPI value
const uint8_t IPSEC_INVALID_SPI[4] = {0};


/**
 * @brief Search the SPD database for a matching entry
 * @param[in] context Pointer to the IPsec context
 * @param[in] policyAction Policy action
 * @param[in] selector Pointer to the IPsec selector
 * @return Pointer to the matching SPD entry, if any
 **/

IpsecSpdEntry *ipsecFindSpdEntry(IpsecContext *context,
   IpsecPolicyAction policyAction, const IpsecSelector *selector)
{
   uint_t i;
   IpsecSelector temp;
   IpsecSpdEntry *entry;

   //Valid parameters?
   if(context != NULL && selector != NULL)
   {
      //Loop through SPD entries
      for(i = 0; i < context->numSpdEntries; i++)
      {
         //Point to the current SPD entry
         entry = &context->spd[i];

         //Valid entry?
         if(entry->policyAction != IPSEC_POLICY_ACTION_INVALID)
         {
            //Matching policy action
            if(policyAction == IPSEC_POLICY_ACTION_INVALID ||
               entry->policyAction == policyAction)
            {
               //Check if there is a non-null intersection between the values of
               //the selectors
               if(ipsecIntersectSelectors(&entry->selector, selector, &temp))
               {
                  return entry;
               }
            }
         }
      }
   }

   //No matching entry in the SPD database
   return NULL;
}


/**
 * @brief Allocate a new entry in the SAD database
 * @param[in] context Pointer to the IPsec context
 * @return Index of the newly allocated entry
 **/

int_t ipsecAllocateSadEntry(IpsecContext *context)
{
   uint_t i;
   IpsecSadEntry *sa;

   //Valid parameters?
   if(context != NULL)
   {
      //Loop through SAD entries
      for(i = 0; i < context->numSadEntries; i++)
      {
         //Point to the current SAD entry
         sa = &context->sad[i];

         //Check whether the current entry is available for use
         if(sa->state == IPSEC_SA_STATE_CLOSED)
         {
            //Default state
            sa->state = IPSEC_SA_STATE_RESERVED;
            //Return the index of the newly allocated entry
            return i;
         }
      }
   }

   //Failed to allocate a new entry in the SAD database
   return -1;
}


/**
 * @brief Search the SAD database for a matching inbound entry
 * @param[in] context Pointer to the IPsec context
 * @param[in] protocol Security protocol (AH or ESP)
 * @param[in] spi Security parameter index
 * @return Pointer to the matching SAD entry, if any
 **/

IpsecSadEntry *ipsecFindInboundSadEntry(IpsecContext *context,
   IpsecProtocol protocol, uint32_t spi)
{
   uint_t i;
   IpsecSadEntry *sa;

   //Valid IPsec context?
   if(context != NULL)
   {
      //Loop through SAD entries
      for(i = 0; i < context->numSadEntries; i++)
      {
         //Point to the current SAD entry
         sa = &context->sad[i];

         //Inbound entry?
         if(sa->state == IPSEC_SA_STATE_OPEN &&
            sa->direction == IPSEC_DIR_INBOUND)
         {
            //Matching protocol and SPI?
            if(sa->protocol == protocol && sa->spi == spi)
            {
               return sa;
            }
         }
      }
   }

   //No matching entry in the SAD database
   return NULL;
}


/**
 * @brief Search the SAD database for a matching outbound entry
 * @param[in] context Pointer to the IPsec context
 * @param[in] selector Pointer to the IPsec selector
 * @return Pointer to the SAD entry, if any
 **/

IpsecSadEntry *ipsecFindOutboundSadEntry(IpsecContext *context,
   const IpsecSelector *selector)
{
   uint_t i;
   systime_t time;
   IpsecSadEntry *sa;
   IpsecSadEntry *bestSa;

   //Initialize pointer
   bestSa = NULL;

   //Get current time
   time = osGetSystemTime();

   //Valid parameters?
   if(context != NULL && selector != NULL)
   {
      //Loop through SAD entries
      for(i = 0; i < context->numSadEntries; i++)
      {
         //Point to the current SAD entry
         sa = &context->sad[i];

         //Outbound entry?
         if(sa->state != IPSEC_SA_STATE_CLOSED &&
            sa->direction == IPSEC_DIR_OUTBOUND)
         {
            //Matching traffic selector?
            if(ipsecIsSubsetSelector(selector, &sa->selector))
            {
               if(bestSa == NULL)
               {
                  bestSa = sa;
               }
               else if(sa->state == IPSEC_SA_STATE_OPEN &&
                  bestSa->state == IPSEC_SA_STATE_RESERVED)
               {
                  bestSa = sa;
               }
               else if(sa->state == IPSEC_SA_STATE_RESERVED &&
                  bestSa->state == IPSEC_SA_STATE_OPEN)
               {
               }
               else if((time - sa->lifetimeStart) < (time - bestSa->lifetimeStart))
               {
                  bestSa = sa;
               }
               else
               {
               }
            }
         }
      }
   }

   //Return a pointer to the SAD entry
   return bestSa;
}


/**
 * @brief Find PAD entry that matches the specified identification data
 * @param[in] context Pointer to the IPsec context
 * @param[in] idType ID type
 * @param[in] id Pointer to the identification data
 * @param[in] idLen Length of the identification data, in bytes
 * @return Pointer to the matching PAD entry, if any
 **/

IpsecPadEntry *ipsecFindPadEntry(IpsecContext *context, uint8_t idType,
   const uint8_t *id, size_t idLen)
{
   uint_t i;
   IpsecPadEntry *entry;

   //Valid parameters
   if(context != NULL && id != NULL)
   {
      //Loop through PAD entries
      for(i = 0; i < context->numPadEntries; i++)
      {
         //Point to the current PAD entry
         entry = &context->pad[i];

         //Valid authentication method and ID type?
         if(entry->authMethod == IPSEC_AUTH_METHOD_IKEV2 &&
            entry->idType == idType)
         {
            //Fully-qualified domain name?
            if(idType == IPSEC_ID_TYPE_FQDN)
            {
               //Compare DNS names
               if(idLen == entry->idLen &&
                  osMemcmp(id, entry->id.fqdn, idLen) == 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
            //RFC 822 email address?
            else if(idType == IPSEC_ID_TYPE_RFC822_ADDR)
            {
               //Compare email addresses
               if(idLen == entry->idLen &&
                  osMemcmp(id, entry->id.email, idLen) == 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
            //X.500 Distinguished Name?
            else if(idType == IPSEC_ID_TYPE_DN)
            {
               //Compare DNs
               if(idLen == entry->idLen &&
                  osMemcmp(id, entry->id.dn, idLen) == 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
            //Key ID?
            else if(idType == IPSEC_ID_TYPE_KEY_ID)
            {
               //Compare key IDs
               if(idLen == entry->idLen &&
                  osMemcmp(id, entry->id.keyId, idLen) == 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
#if (IPV4_SUPPORT == ENABLED)
            //IPv4 address?
            else if(idType == IPSEC_ID_TYPE_IPV4_ADDR)
            {
               //For IPv4 addresses, the same address range syntax used for SPD
               //entries must be supported. This allows specification of an
               //individual address, an address prefix, or an arbitrary address
               //range (refer to RFC 4301, section 4.4.3.1)
               if(idLen == sizeof(Ipv4Addr) &&
                  osMemcmp(id, &entry->id.ipAddr.start.ipv4Addr, 4) >= 0 &&
                  osMemcmp(id, &entry->id.ipAddr.end.ipv4Addr, 4) <= 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
#endif
#if (IPV6_SUPPORT == ENABLED)
            //IPv6 address?
            else if(idType == IPSEC_ID_TYPE_IPV6_ADDR)
            {
               //For IPv6 addresses, the same address range syntax used for SPD
               //entries must be supported. This allows specification of an
               //individual address, an address prefix, or an arbitrary address
               //range (refer to RFC 4301, section 4.4.3.1)
               if(idLen == sizeof(Ipv6Addr) &&
                  osMemcmp(id, &entry->id.ipAddr.start.ipv6Addr, 16) >= 0 &&
                  osMemcmp(id, &entry->id.ipAddr.end.ipv6Addr, 16) <= 0)
               {
                  //A matching PAD entry has been found
                  return entry;
               }
            }
#endif
            //Unknown ID type?
            else
            {
               //Just for sanity
            }
         }
      }
   }

   //The specified identification data does not match any PAD entry
   return NULL;
}


/**
 * @brief Test if a selector is a subset of another selector
 * @param[in] selector1 Pointer to the first IPsec selector
 * @param[in] selector2 Pointer to the second IPsec selector
 * @return TRUE is the first selector is a subset of the second selector,
 *   else FALSE
 **/

bool_t ipsecIsSubsetSelector(const IpsecSelector *selector1,
   const IpsecSelector *selector2)
{
#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(selector1->localIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector1->localIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector1->remoteIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector1->remoteIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector2->localIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector2->localIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector2->remoteIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector2->remoteIpAddr.end.length == sizeof(Ipv4Addr))
   {
      //Check whether the first selector is valid
      if(ntohl(selector1->localIpAddr.start.ipv4Addr) >
         ntohl(selector1->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->remoteIpAddr.start.ipv4Addr) >
         ntohl(selector1->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      //Check whether the second selector is valid
      if(ntohl(selector2->localIpAddr.start.ipv4Addr) >
         ntohl(selector2->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector2->remoteIpAddr.start.ipv4Addr) >
         ntohl(selector2->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      //Compare local IP address ranges
      if(ntohl(selector1->localIpAddr.start.ipv4Addr) <
         ntohl(selector2->localIpAddr.start.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->localIpAddr.end.ipv4Addr) >
         ntohl(selector2->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      //Compare remote IP address ranges
      if(ntohl(selector1->remoteIpAddr.start.ipv4Addr) <
         ntohl(selector2->remoteIpAddr.start.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->remoteIpAddr.end.ipv4Addr) >
         ntohl(selector2->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(selector1->localIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector1->localIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector1->remoteIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector1->remoteIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector2->localIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector2->localIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector2->remoteIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector2->remoteIpAddr.end.length == sizeof(Ipv6Addr))
   {
      return FALSE;
   }
   else
#endif
   //Unknown Traffic Selector type?
   {
      return FALSE;
   }

   //Check Next Layer Protocol value
   if(selector2->nextProtocol == IPSEC_PROTOCOL_ANY)
   {
      //ANY is a wildcard that matches any value protocol value
   }
   else
   {
      //Compare Next Layer Protocol value
      if(selector1->nextProtocol != selector2->nextProtocol)
      {
         return FALSE;
      }
   }

   //Check local port ranges
   if(selector1->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->localPort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->localPort.end == IPSEC_PORT_END_OPAQUE)
   {
      //OPAQUE indicates that the corresponding selector field is not
      //available for examination
   }
   else if(selector1->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->localPort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->localPort.start == IPSEC_PORT_START_ANY &&
      selector2->localPort.end == IPSEC_PORT_END_ANY)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
   }
   else
   {
      //Check whether the selectors are valid
      if(selector1->localPort.start > selector1->localPort.end ||
         selector2->localPort.start > selector2->localPort.end)
      {
         return FALSE;
      }

      //Compare local port ranges
      if(selector1->localPort.start < selector2->localPort.start ||
         selector1->localPort.end > selector2->localPort.end)
      {
         return FALSE;
      }
   }

   //Check remote port ranges
   if(selector1->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->remotePort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->remotePort.end == IPSEC_PORT_END_OPAQUE)
   {
      //OPAQUE indicates that the corresponding selector field is not
      //available for examination
   }
   else if(selector1->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->remotePort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->remotePort.start == IPSEC_PORT_START_ANY &&
      selector2->remotePort.end == IPSEC_PORT_END_ANY)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
   }
   else
   {
      //Check whether the selectors are valid
      if(selector1->remotePort.start > selector1->remotePort.end ||
         selector2->remotePort.start > selector2->remotePort.end)
      {
         return FALSE;
      }

      //Compare remote port ranges
      if(selector1->remotePort.start < selector2->remotePort.start ||
         selector1->remotePort.end > selector2->remotePort.end)
      {
         return FALSE;
      }
   }

   //The first selector is a subset of the second selector
   return TRUE;
}


/**
 * @brief Calculate the intersection of two selectors
 * @param[in] selector1 Pointer to the first IPsec selector
 * @param[in] selector2 Pointer to the second IPsec selector
 * @param[out] result Resulting IPsec selector
 * @return TRUE if there is a non-null intersection, else FALSE
 **/

bool_t ipsecIntersectSelectors(const IpsecSelector *selector1,
   const IpsecSelector *selector2, IpsecSelector *result)
{
#if (IPV4_SUPPORT == ENABLED)
   //IPv4 address range?
   if(selector1->localIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector1->localIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector1->remoteIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector1->remoteIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector2->localIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector2->localIpAddr.end.length == sizeof(Ipv4Addr) &&
      selector2->remoteIpAddr.start.length == sizeof(Ipv4Addr) &&
      selector2->remoteIpAddr.end.length == sizeof(Ipv4Addr))
   {
      //Check whether the first selector is valid
      if(ntohl(selector1->localIpAddr.start.ipv4Addr) >
         ntohl(selector1->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->remoteIpAddr.start.ipv4Addr) >
         ntohl(selector1->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      //Check whether the second selector is valid
      if(ntohl(selector2->localIpAddr.start.ipv4Addr) >
         ntohl(selector2->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector2->remoteIpAddr.start.ipv4Addr) >
         ntohl(selector2->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      //Check local IP address ranges
      if(ntohl(selector1->localIpAddr.start.ipv4Addr) >
         ntohl(selector2->localIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->localIpAddr.end.ipv4Addr) <
         ntohl(selector2->localIpAddr.start.ipv4Addr))
      {
         return FALSE;
      }

      //Calculate the intersection of the local IP address ranges
      result->localIpAddr.start.length = sizeof(Ipv4Addr);

      result->localIpAddr.start.ipv4Addr = htonl(MAX(
         ntohl(selector1->localIpAddr.start.ipv4Addr),
         ntohl(selector2->localIpAddr.start.ipv4Addr)));

      result->localIpAddr.end.length = sizeof(Ipv4Addr);

      result->localIpAddr.end.ipv4Addr = htonl(MIN(
         ntohl(selector1->localIpAddr.end.ipv4Addr),
         ntohl(selector2->localIpAddr.end.ipv4Addr)));

      //Check remote IP address ranges
      if(ntohl(selector1->remoteIpAddr.start.ipv4Addr) >
         ntohl(selector2->remoteIpAddr.end.ipv4Addr))
      {
         return FALSE;
      }

      if(ntohl(selector1->remoteIpAddr.end.ipv4Addr) <
         ntohl(selector2->remoteIpAddr.start.ipv4Addr))
      {
         return FALSE;
      }

      //Calculate the intersection of the remote IP address ranges
      result->remoteIpAddr.start.length = sizeof(Ipv4Addr);

      result->remoteIpAddr.start.ipv4Addr = htonl(MAX(
         ntohl(selector1->remoteIpAddr.start.ipv4Addr),
         ntohl(selector2->remoteIpAddr.start.ipv4Addr)));

      result->remoteIpAddr.end.length = sizeof(Ipv4Addr);

      result->remoteIpAddr.end.ipv4Addr = htonl(MIN(
         ntohl(selector1->remoteIpAddr.end.ipv4Addr),
         ntohl(selector2->remoteIpAddr.end.ipv4Addr)));
   }
   else
#endif
#if (IPV6_SUPPORT == ENABLED)
   //IPv6 address range?
   if(selector1->localIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector1->localIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector1->remoteIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector1->remoteIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector2->localIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector2->localIpAddr.end.length == sizeof(Ipv6Addr) &&
      selector2->remoteIpAddr.start.length == sizeof(Ipv6Addr) &&
      selector2->remoteIpAddr.end.length == sizeof(Ipv6Addr))
   {
      return FALSE;
   }
   else
#endif
   //Unknown Traffic Selector type?
   {
      return FALSE;
   }

   //Check Next Layer Protocol values
   if(selector1->nextProtocol == IPSEC_PROTOCOL_ANY)
   {
      //ANY is a wildcard that matches any value protocol value
      result->nextProtocol = selector2->nextProtocol;
   }
   else if(selector2->nextProtocol == IPSEC_PROTOCOL_ANY)
   {
      //ANY is a wildcard that matches any value protocol value
      result->nextProtocol = selector1->nextProtocol;
   }
   else if(selector1->nextProtocol == selector2->nextProtocol)
   {
      result->nextProtocol = selector1->nextProtocol;
   }
   else
   {
      return FALSE;
   }

   //Check local port ranges
   if(selector1->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->localPort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->localPort.end == IPSEC_PORT_END_OPAQUE)
   {
      //OPAQUE indicates that the corresponding selector field is not
      //available for examination
      result->localPort.start = IPSEC_PORT_START_OPAQUE;
      result->localPort.end = IPSEC_PORT_END_OPAQUE;
   }
   else if(selector1->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->localPort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->localPort.start == IPSEC_PORT_START_ANY &&
      selector2->localPort.end == IPSEC_PORT_END_ANY)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
      result->localPort.start = IPSEC_PORT_START_OPAQUE;
      result->localPort.end = IPSEC_PORT_END_OPAQUE;
   }
   else if(selector1->localPort.start == IPSEC_PORT_START_ANY &&
      selector1->localPort.end == IPSEC_PORT_END_ANY &&
      selector2->localPort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->localPort.end == IPSEC_PORT_END_OPAQUE)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
      result->localPort.start = IPSEC_PORT_START_OPAQUE;
      result->localPort.end = IPSEC_PORT_END_OPAQUE;
   }
   else
   {
      //Check whether the selectors are valid
      if(selector1->localPort.start > selector1->localPort.end ||
         selector2->localPort.start > selector2->localPort.end)
      {
         return FALSE;
      }

      //Check local port ranges
      if(selector1->localPort.start > selector2->localPort.end ||
         selector1->localPort.end < selector2->localPort.start)
      {
         return FALSE;
      }

      //Calculate the intersection of the local port ranges
      result->localPort.start = MAX(selector1->localPort.start,
         selector2->localPort.start);

      result->localPort.end = MIN(selector1->localPort.end,
         selector2->localPort.end);
   }

   //Check remote port ranges
   if(selector1->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->remotePort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->remotePort.end == IPSEC_PORT_END_OPAQUE)
   {
      //OPAQUE indicates that the corresponding selector field is not
      //available for examination
      result->remotePort.start = IPSEC_PORT_START_OPAQUE;
      result->remotePort.end = IPSEC_PORT_END_OPAQUE;
   }
   else if(selector1->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector1->remotePort.end == IPSEC_PORT_END_OPAQUE &&
      selector2->remotePort.start == IPSEC_PORT_START_ANY &&
      selector2->remotePort.end == IPSEC_PORT_END_ANY)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
      result->remotePort.start = IPSEC_PORT_START_OPAQUE;
      result->remotePort.end = IPSEC_PORT_END_OPAQUE;
   }
   else if(selector1->remotePort.start == IPSEC_PORT_START_ANY &&
      selector1->remotePort.end == IPSEC_PORT_END_ANY &&
      selector2->remotePort.start == IPSEC_PORT_START_OPAQUE &&
      selector2->remotePort.end == IPSEC_PORT_END_OPAQUE)
   {
      //The ANY value encompasses the OPAQUE value (refer to RFC 4301,
      //section 4.4.1)
      result->remotePort.start = IPSEC_PORT_START_OPAQUE;
      result->remotePort.end = IPSEC_PORT_END_OPAQUE;
   }
   else
   {
      //Check whether the selectors are valid
      if(selector1->remotePort.start > selector1->remotePort.end ||
         selector2->remotePort.start > selector2->remotePort.end)
      {
         return FALSE;
      }

      //Check remote port ranges
      if(selector1->remotePort.start > selector2->remotePort.end ||
         selector1->remotePort.end < selector2->remotePort.start)
      {
         return FALSE;
      }

      //Calculate the intersection of the remote port ranges
      result->remotePort.start = MAX(selector1->remotePort.start,
         selector2->remotePort.start);

      result->remotePort.end = MIN(selector1->remotePort.end,
         selector2->remotePort.end);
   }

   //Return TRUE if there is a non-null intersection
   return TRUE;
}


/**
 * @brief Derive SAD selector from SPD entry and triggering packet
 * @param[in] spdEntry Pointer to the SPD entry
 * @param[in] packet Triggering packet
 * @param[out] selector SAD selector
 * @return Error code
 **/

error_t ipsecDeriveSelector(const IpsecSpdEntry *spdEntry,
   const IpsecPacketInfo *packet, IpsecSelector *selector)
{
   //Select local IP address range
   if((spdEntry->pfpFlags & IPSEC_PFP_FLAG_LOCAL_ADDR) != 0)
   {
      selector->localIpAddr.start = packet->localIpAddr;
      selector->localIpAddr.end = packet->localIpAddr;
   }
   else
   {
      selector->localIpAddr.start = spdEntry->selector.localIpAddr.start;
      selector->localIpAddr.end = spdEntry->selector.localIpAddr.end;
   }

   //Select remote IP address range
   if((spdEntry->pfpFlags & IPSEC_PFP_FLAG_REMOTE_ADDR) != 0)
   {
      selector->remoteIpAddr.start = packet->remoteIpAddr;
      selector->remoteIpAddr.end = packet->remoteIpAddr;
   }
   else
   {
      selector->remoteIpAddr.start = spdEntry->selector.remoteIpAddr.start;
      selector->remoteIpAddr.end = spdEntry->selector.remoteIpAddr.end;
   }

   //Select Next Layer Protocol value
   if((spdEntry->pfpFlags & IPSEC_PFP_FLAG_NEXT_PROTOCOL) != 0)
   {
      selector->nextProtocol = packet->nextProtocol;
   }
   else
   {
      selector->nextProtocol = spdEntry->selector.nextProtocol;
   }

   //Select local port range
   if((spdEntry->pfpFlags & IPSEC_PFP_FLAG_LOCAL_PORT) != 0)
   {
      selector->localPort.start = packet->localPort;
      selector->localPort.end = packet->localPort;
   }
   else
   {
      selector->localPort.start = spdEntry->selector.localPort.start;
      selector->localPort.end = spdEntry->selector.localPort.end;
   }

   //Select remote port range
   if((spdEntry->pfpFlags & IPSEC_PFP_FLAG_REMOTE_PORT) != 0)
   {
      selector->remotePort.start = packet->remotePort;
      selector->remotePort.end = packet->remotePort;
   }
   else
   {
      selector->remotePort.start = spdEntry->selector.remotePort.start;
      selector->remotePort.end = spdEntry->selector.remotePort.end;
   }

   //Successful processing
   return NO_ERROR;
}

#endif
