/**
 * @file ipsec_anti_replay.c
 * @brief Anti-replay mechanism
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
#include "ipsec/ipsec_anti_replay.h"

//Check IPsec library configuration
#if (IPSEC_SUPPORT == ENABLED)


/**
 * @brief Initialize sliding window
 * @param[in] sa Pointer to the security association
 **/

void ipsecInitReplayWindow(IpsecSadEntry *sa)
{
#if (IPSEC_ANTI_REPLAY_SUPPORT == ENABLED)
   uint_t i;

   //Clear the bitmap window
   for(i = 0; i < (IPSEC_ANTI_REPLAY_WINDOW_SIZE + 31) / 32; i++)
   {
      sa->antiReplayWindow[i] = 0;
   }
#endif
}


/**
 * @brief Perform replay detection
 * @param[in] sa Pointer to the security association
 * @param[in] seqNum Sequence number of the received packet
 * @return Error code
 **/

error_t ipsecCheckReplayWindow(const IpsecSadEntry *sa, uint64_t seqNum)
{
   error_t error;

#if (IPSEC_ANTI_REPLAY_SUPPORT == ENABLED)
   //All AH implementations must support the anti-replay service, though its
   //use may be enabled or disabled by the receiver on a per-SA basis (refer
   //to RFC 4302, section 3.4.3)
   if(sa->antiReplayEnabled)
   {
      uint_t j;
      uint_t k;
      uint64_t n;
      uint64_t right;

      //The right edge of the window represents the highest validated sequence
      //number value received on this SA
      right = sa->seqNum;

      //Check sequence number
      if(seqNum == 0)
      {
         //the first packet sent using a given SA will contain a sequence
         //number of 1
         error = ERROR_INVALID_SEQUENCE_NUMBER;
      }
      else if(seqNum <= right)
      {
         //Calculate the position relative to the right edge of the window
         n = right - seqNum;

         //Check whether the sequence number falls within the window
         if(n < IPSEC_ANTI_REPLAY_WINDOW_SIZE)
         {
            //Records falling within the window are checked against a list of
            //received packets within the window
            j = (uint_t) (n / 32);
            k = (uint_t) (n % 32);

            //Duplicate record are rejected through the use of a sliding
            //receive window
            if(sa->antiReplayWindow[j] & (1U << k))
            {
               //The received record is a duplicate
               error = ERROR_INVALID_SEQUENCE_NUMBER;
            }
            else
            {
               //If the received record falls within the window and is new,
               //then the receiver proceeds to ICV verification
               error = NO_ERROR;
            }

         }
         else
         {
            //Records that contain sequence numbers lower than the left edge
            //of the window are rejected
            error = ERROR_INVALID_SEQUENCE_NUMBER;
         }
      }
      else
      {
         //If the packet is to the right of the window, then the receiver
         //proceeds to ICV verification
         error = NO_ERROR;
      }
   }
   else
#endif
   {
      //If the receiver does not enable anti-replay for an SA, no inbound
      //checks are performed on the sequence number
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Update sliding window
 * @param[in] sa Pointer to the security association
 * @param[in] seqNum Sequence number of the received packet
 **/

void ipsecUpdateReplayWindow(IpsecSadEntry *sa, uint64_t seqNum)
{
   uint64_t n;
   uint64_t right;

   //The right edge of the window represents the highest validated sequence
   //number value received on this SA
   right = sa->seqNum;

   //Check sequence number
   if(seqNum <= right)
   {
#if (IPSEC_ANTI_REPLAY_SUPPORT == ENABLED)
      uint_t j;
      uint_t k;

      //Calculate the position relative to the right edge of the window
      n = right - seqNum;

      //Check whether the sequence number falls within the window
      if(n < IPSEC_ANTI_REPLAY_WINDOW_SIZE)
      {
         j = (uint_t) (n / 32);
         k = (uint_t) (n % 32);

         //Set the corresponding bit in the bitmap window
         sa->antiReplayWindow[j] |= 1U << k;
      }
#endif
   }
   else
   {
#if (IPSEC_ANTI_REPLAY_SUPPORT == ENABLED)
      uint_t i;
      uint_t j;
      uint_t k;

      //Calculate the position relative to the right edge of the window
      n = seqNum - right;

      //Check resulting value
      if(n < IPSEC_ANTI_REPLAY_WINDOW_SIZE)
      {
         j = (uint_t) (n / 32);
         k = (uint_t) (n % 32);

         //First, shift words
         if(j > 0)
         {
            //Shift the most significant words of the window
            for(i = (IPSEC_ANTI_REPLAY_WINDOW_SIZE - 1) / 32; i >= j; i--)
            {
               sa->antiReplayWindow[i] = sa->antiReplayWindow[i - j];
            }

            //Fill the least significant words with zeroes
            for(i = 0; i < j; i++)
            {
               sa->antiReplayWindow[i] = 0;
            }
         }

         //Then shift bits
         if(k > 0)
         {
            //Shift the most significant words of the window
            for(i = (IPSEC_ANTI_REPLAY_WINDOW_SIZE - 1) / 32; i >= 1; i--)
            {
               sa->antiReplayWindow[i] = (sa->antiReplayWindow[i] << k) |
                  (sa->antiReplayWindow[i - 1] >> (32 - k));
            }

            //Shift the least significant word
            sa->antiReplayWindow[0] <<= k;
         }
      }
      else
      {
         //Clear the bitmap window
         for(i = 0; i < (IPSEC_ANTI_REPLAY_WINDOW_SIZE + 31) / 32; i++)
         {
            sa->antiReplayWindow[i] = 0;
         }
      }

      //Set the corresponding bit in the bitmap window
      sa->antiReplayWindow[0] |= 1;
#endif

      //Save the highest sequence number value received on this session
      sa->seqNum = seqNum;
   }
}

#endif
