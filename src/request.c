/*
**  igmpproxy - IGMP proxy based multicast router 
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of igmpproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/
/**
*   request.c 
*
*   Functions for recieveing and processing IGMP requests.
*
*/

#include "igmpproxy.h"
#include "time.h"

// Prototypes...
void doLastMemberDetection(uint32_t group, in_addr_t vifAddr);
void sendGroupSpecificMemberQuery(void *argument);  
    
typedef struct {
    uint32_t      group;
    uint32_t      vifAddr;
    short       started;
} GroupVifDesc;


/**
*   Handles incoming membership reports, and
*   appends them to the routing table.
*/
void acceptGroupReport(uint32_t src, uint32_t group, uint8_t type) {
    struct IfDesc  *sourceVif;

    // Sanitycheck the group adress...
    if(!IN_MULTICAST( ntohl(group) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group.",
            inetFmt(group, s1));
        return;
    }

    // Find the interface on which the report was recieved.
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
            inetFmt(src,s1));
        return;
    }

    if(sourceVif->InAdr.s_addr == src) {
        my_log(LOG_NOTICE, 0, "The IGMP message was from myself. Ignoring.");
        return;
    }

    // We have a IF so check that it's an downstream IF.
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {

        my_log(LOG_DEBUG, 0, "Should insert group %s (from: %s) to route table. Vif Ix : %d",
            inetFmt(group,s1), inetFmt(src,s2), sourceVif->index);

        // TODO add multicast subscriber to route registry
        // TODO insert source vif (IF not already added)

        // The membership report was OK... Insert it into the route table..
        insertRoute(group, sourceVif->index, src);


    } else {
        // Log the state of the interface the report was recieved on.
        my_log(LOG_INFO, 0, "Mebership report was recieved on %s. Ignoring.",
            sourceVif->state==IF_STATE_UPSTREAM?"the upstream interface":"a disabled interface");
    }

}

/**
*   Recieves and handles a group leave message.
*/
void acceptLeaveMessage(uint32_t src, uint32_t group) {
    struct IfDesc   *sourceVif;
    
    my_log(LOG_NOTICE, 0,
	    "Got leave message, from: %s group: %s",
	    inetFmt(src, s1), inetFmt(group, s2));

    // Sanitycheck the group adress...
    if(!IN_MULTICAST( ntohl(group) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group.",
            inetFmt(group, s1));
        return;
    }

    // Find the interface on which the report was recieved.
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
            inetFmt(src,s1));
        return;
    }

    // We have a IF so check that it's an downstream IF.
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {
        leaveRoute(group, sourceVif->index, src);

        // TODO shall we do the last member detection also in quickleave/cleanleave mode??
        doLastMemberDetection(group, sourceVif->InAdr.s_addr);
    } else {
        // just ignore the leave request...
        my_log(LOG_DEBUG, 0, "Interface for %s is not downstream. Ignoring leave request.", inetFmt(src, s1));
    }
}

/**
*   Sends a group specific member report query until the 
*   group times out...
*/
void doLastMemberDetection(uint32_t group, in_addr_t vifAddr) {
    // TODO is this freed anywhere? Maybe include it in RouteTable entry
    GroupVifDesc   *gvDesc;
    gvDesc = (GroupVifDesc*) malloc(sizeof(GroupVifDesc));
    gvDesc->group = group;
    gvDesc->vifAddr = vifAddr;
    gvDesc->started = 0;

    // Tell the route table that we are checking for remaining members...
    my_log(LOG_WARNING, 0, "Start last member detection for group %s.",
        inetFmt(group, s1));
    setRouteLastMemberMode(group);
    sendGroupSpecificMemberQuery(gvDesc);
}

/**
*   Sends a group specific member report query until the 
*   group times out...
*/
void sendGroupSpecificMemberQuery(void *argument) {
    struct  Config  *conf = getCommonConfig();

    // Cast argument to correct type...
    GroupVifDesc   *gvDesc = (GroupVifDesc*) argument;

    if(gvDesc->started) {
        // If aging returns false, we don't do any further action...
        if(!lastMemberGroupAge(gvDesc->group)) {
            return;
        }
    } else {
        gvDesc->started = 1;
    }

    // Send a group specific membership query...
    sendIgmp(gvDesc->vifAddr, gvDesc->group, 
             IGMP_MEMBERSHIP_QUERY,
             conf->lastMemberQueryInterval * IGMP_TIMER_SCALE, 
             gvDesc->group, 0);

    my_log(LOG_INFO, 0, "Sent membership query from %s to %s. Delay: %d",
        inetFmt(gvDesc->vifAddr,s1), inetFmt(gvDesc->group,s2),
        conf->lastMemberQueryInterval);

    // Set timeout for next round...
    timer_setTimer(conf->lastMemberQueryInterval, sendGroupSpecificMemberQuery, gvDesc);

}


/**
*   Sends a general membership query on downstream VIFs
*/
void sendGeneralMembershipQuery() {
    struct  Config  *conf = getCommonConfig();
    struct  IfDesc  *Dp;
    int             Ix;

    my_log(LOG_INFO, 0, "\n\n");
    my_log(LOG_INFO, 0, "-- Trigger general membership query --");

    // Loop through all downstream vifs...
    for ( Ix = 0; (Dp = getIfByIx(Ix)); Ix++ ) {
        if ( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) ) {
            if(Dp->state == IF_STATE_DOWNSTREAM) {
                // Send the membership query...
                sendIgmp(Dp->InAdr.s_addr, allhosts_group, 
                         IGMP_MEMBERSHIP_QUERY,
                         conf->queryResponseInterval * IGMP_TIMER_SCALE, 0, 0);
                
                my_log(LOG_DEBUG, 0,
			"Sent membership query from %s to %s. Delay: %d",
			inetFmt(Dp->InAdr.s_addr,s1),
			inetFmt(allhosts_group,s2),
			conf->queryResponseInterval);
            }
        }
    }

	// Install timer for aging active routes.
    timer_setTimer(conf->queryResponseInterval, ageActiveRoutes, NULL);

    // Install timer for next general query...
    if(conf->startupQueryCount>0) {
        // Use quick timer...
        timer_setTimer(conf->startupQueryInterval, sendGeneralMembershipQuery, NULL);
        // Decrease startup counter...
        conf->startupQueryCount--;
    } 
    else {
        // Use slow timer...
        timer_setTimer(conf->queryInterval, sendGeneralMembershipQuery, NULL);
    }


}
 
