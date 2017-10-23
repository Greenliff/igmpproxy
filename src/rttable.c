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
*   rttable.c 
*
*   Updates the routingtable according to 
*     recieved request.
*/

#include "igmpproxy.h"
    
/**
*   Routing table structure definition. Double linked list...
*/
struct RouteTable {
    struct RouteTable   *nextroute;     // Pointer to the next group in line.
    struct RouteTable   *prevroute;     // Pointer to the previous group in line.
    uint32_t              group;          // The group to route
    uint32_t              originAddr;     // The origin address (only set on activated routes)
    uint32_t              vifBits;        // Bits representing receiving VIFs.

    // Keeps the upstream membership state...
    short               upstrState;     // Upstream membership state.

    // These parameters contain aging details (for non quickleave mode).
    uint32_t              ageVifBits;     // Bits representing aging VIFs.
    int                 ageValue;       // Down counter for death.
    int                 ageActivity;    // Records any activity that notes there are still listeners.

    // Subscribers (for cleanleave/quickleave mode)
    struct GroupSubscriber  *subscribers;
};

/**
*   Subscribers for a multicast group. Double linked list...
*/
struct GroupSubscriber {
    struct GroupSubscriber   *nextsubscriber;
    struct GroupSubscriber   *prevsubscriber;
    uint32_t                 subscriberAddr;     // The IP of subscriber
    int                      vifIndex;
    int                      ageValue;       // Down counter for death (i.e. subscribers which forgot to leave on power loss, ...)
};
                 


// Keeper for the routing table...
static struct RouteTable   *routing_table;

// Prototypes
void logRouteTable(char *header);
int  internAgeRoute(struct RouteTable*  croute);
int internUpdateKernelRoute(struct RouteTable *route, int activate);
int removeRoute(struct RouteTable*  croute);

// Socket for sending join or leave requests.
int mcGroupSock = 0;


/**
*   Function for retrieving the Multicast Group socket.
*/
int getMcGroupSock() {
    if( ! mcGroupSock ) {
        mcGroupSock = openUdpSocket( INADDR_ANY, 0 );;
    }
    return mcGroupSock;
}
 
/**
*   Initializes the routing table.
*/
void initRouteTable() {
    unsigned Ix;
    struct IfDesc *Dp;

    // Clear routing table...
    routing_table = NULL;

    // Join the all routers group on downstream vifs...
    for ( Ix = 0; (Dp = getIfByIx(Ix)); Ix++ ) {
        // If this is a downstream vif, we should join the All routers group...
        if( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) && Dp->state == IF_STATE_DOWNSTREAM) {
            my_log(LOG_DEBUG, 0, "Joining all-routers group %s on vif %s",
                         inetFmt(allrouters_group,s1),inetFmt(Dp->InAdr.s_addr,s2));
            
            //k_join(allrouters_group, Dp->InAdr.s_addr);
            joinMcGroup( getMcGroupSock(), Dp, allrouters_group );
        }
    }
}

/**
*   Internal function to send join or leave requests for
*   a specified route upstream...
*/
void sendJoinLeaveUpstream(struct RouteTable* route, int join) {
    struct IfDesc*      upstrIf;
    
    // Get the upstream VIF...
    upstrIf = getIfByIx( upStreamVif );
    if(upstrIf == NULL) {
        my_log(LOG_ERR, 0 ,"FATAL: Unable to get Upstream IF.");
    }

    // Send join or leave request...
    if(join) {

        // Only join a group if there are listeners downstream...
        if(route->vifBits > 0) {
            my_log(LOG_DEBUG, 0, "Joining group %s upstream on IF address %s",
                         inetFmt(route->group, s1), 
                         inetFmt(upstrIf->InAdr.s_addr, s2));

            //k_join(route->group, upstrIf->InAdr.s_addr);
            joinMcGroup( getMcGroupSock(), upstrIf, route->group );

            route->upstrState = ROUTESTATE_JOINED;
        } else {
            my_log(LOG_DEBUG, 0, "No downstream listeners for group %s. No join sent.",
                inetFmt(route->group, s1));
        }

    } else {
        // Only leave if group is not left already...
        if(route->upstrState != ROUTESTATE_NOTJOINED) {
            my_log(LOG_DEBUG, 0, "Leaving group %s upstream on IF address %s",
                         inetFmt(route->group, s1), 
                         inetFmt(upstrIf->InAdr.s_addr, s2));
            
            //k_leave(route->group, upstrIf->InAdr.s_addr);
            leaveMcGroup( getMcGroupSock(), upstrIf, route->group );

            route->upstrState = ROUTESTATE_NOTJOINED;
        }
    }
}

/**
*   Clear all routes from routing table, and alerts Leaves upstream.
*/
void clearAllRoutes() {
    struct RouteTable   *croute, *remainroute;

    // Loop through all routes...
    for(croute = routing_table; croute; croute = remainroute) {

        remainroute = croute->nextroute;

        // Log the cleanup in debugmode...
        my_log(LOG_DEBUG, 0, "Removing route entry for %s",
                     inetFmt(croute->group, s1));

        // Uninstall current route
        if(!internUpdateKernelRoute(croute, 0)) {
            my_log(LOG_WARNING, 0, "The removal from Kernel failed.");
        }

        // Send Leave message upstream.
        sendJoinLeaveUpstream(croute, 0);

        // Clear memory, and set pointer to next route...
        free(croute);
    }
    routing_table = NULL;

    // Send a notice that the routing table is empty...
    my_log(LOG_NOTICE, 0, "All routes removed. Routing table is empty.");
}
                 
/**
*   Private access function to find a route from a given 
*   Route Descriptor.
*/
struct RouteTable *findRoute(uint32_t group) {
    struct RouteTable*  croute;

    for(croute = routing_table; croute; croute = croute->nextroute) {
        if(croute->group == group) {
            return croute;
        }
    }

    return NULL;
}

struct RouteTable* createRoute(uint32_t group) {
    struct Config *conf = getCommonConfig();
    struct RouteTable* newroute;

    // Create and initialize the new route table entry..
    newroute = (struct RouteTable*)malloc(sizeof(struct RouteTable));
    // Insert the route desc and clear all pointers...
    newroute->group      = group;
    newroute->originAddr = 0;
    newroute->nextroute  = NULL;
    newroute->prevroute  = NULL;

    // The group is not joined initially.
    newroute->upstrState = ROUTESTATE_NOTJOINED;

    // The route is not active yet, so the age is unimportant.
    newroute->ageValue    = conf->robustnessValue;
    newroute->ageActivity = 0;

    // Set the listener flag...
    BIT_ZERO(newroute->ageVifBits);     // Initially we assume no listeners.
    BIT_ZERO(newroute->vifBits);    // Initially no listeners...

    // Start with empty subscriber list
    newroute->subscribers  = NULL;

    return newroute;
}

/**
*   Adds a route to the routing table
*/
void addRoute(struct RouteTable* newroute) {

    struct RouteTable* croute;

    // Check if there is a table already....
    if(routing_table == NULL) {
        my_log(LOG_DEBUG, 0, "No routes in table. Insert at beginning.");

        // No location set, so insert in on the table top.
        newroute->nextroute = NULL;
        newroute->prevroute = NULL;
        routing_table = newroute;
        return;
    }

    // Check if the route could be inserted at the beginning...
    if(routing_table->group > newroute->group) {
        my_log(LOG_DEBUG, 0, "Inserting at beginning, before route %s",inetFmt(routing_table->group,s1));

        // Insert at beginning...
        newroute->nextroute = routing_table;
        newroute->prevroute = NULL;
        routing_table = newroute;

        // If the route has a next node, the previous pointer must be updated.
        if(newroute->nextroute != NULL) {
            newroute->nextroute->prevroute = newroute;
        }
        return;
    }


    // Find the location which is closest to the route.
    for( croute = routing_table; croute->nextroute != NULL; croute = croute->nextroute ) {
        // Find insert position.
        if(croute->nextroute->group > newroute->group) {
            break;
        }
    }

    my_log(LOG_DEBUG, 0, "Inserting after route %s",inetFmt(croute->group,s1));

    // Insert after current...
    newroute->nextroute = croute->nextroute;
    newroute->prevroute = croute;
    if(croute->nextroute != NULL) {
        croute->nextroute->prevroute = newroute;
    }
    croute->nextroute = newroute;
}

struct GroupSubscriber* createSubscriber(int ifx, uint32_t src) {
    struct Config *conf = getCommonConfig();
    struct GroupSubscriber* newsubscriber;

    // Create and initialize the new route table entry..
    newsubscriber = (struct GroupSubscriber*)malloc(sizeof(struct GroupSubscriber));
    newsubscriber->nextsubscriber  = NULL;
    newsubscriber->prevsubscriber  = NULL;
    newsubscriber->subscriberAddr = src;
    newsubscriber->vifIndex = ifx;
    newsubscriber->ageValue = conf->robustnessValue;

    return newsubscriber;
}

/**
*   Remove a subscriber from a route.
*/
int removeSubscriber(struct RouteTable* route, int ifx, uint32_t src) {
    struct GroupSubscriber* csubscriber;

    if(route->subscribers == NULL) {
        return 0;
    }

    if(route->subscribers->vifIndex == ifx && route->subscribers->subscriberAddr == src) {
        // subscriber is found at head of list
        csubscriber = route->subscribers;
        route->subscribers = route->subscribers->nextsubscriber;
        if (route->subscribers != NULL) {
            route->subscribers->prevsubscriber= NULL;
        }
        free(csubscriber);
        return 1;
    }

    for( csubscriber = route->subscribers; csubscriber != NULL; csubscriber = csubscriber->nextsubscriber ) {
        if(csubscriber->vifIndex == ifx && csubscriber->subscriberAddr == src) {
            // subscriber is found
            break;
        }
        if(csubscriber->vifIndex > ifx || csubscriber->subscriberAddr > src) {
            // subscriber not found
            return 0;
        }
    }
    if (csubscriber == NULL) {
        return 0;
    }

    csubscriber->prevsubscriber->nextsubscriber = csubscriber->nextsubscriber;
    if (csubscriber->nextsubscriber != NULL) {
        csubscriber->nextsubscriber->prevsubscriber = csubscriber->prevsubscriber;
    }
    free(csubscriber);
    return 1;
}


/**
*   Adds a subscriber to a route.
*/
void addSubscriber(struct RouteTable* route, int ifx, uint32_t src) {
    struct GroupSubscriber* newsubscriber;
    struct GroupSubscriber* csubscriber;
    struct Config *conf = getCommonConfig();

    // Check if there are any subscribers already....
    if(route->subscribers == NULL) {
        my_log(LOG_WARNING, 0, "No subscribers in route. Insert at beginning.");

        route->subscribers = createSubscriber(ifx, src);
        return;
    }

    // Check if the route could be inserted at the beginning...
    if(route->subscribers->vifIndex > ifx || route->subscribers->subscriberAddr > src) {
        my_log(LOG_WARNING, 0, "Inserting at beginning, before subscriber %s",inetFmt(route->subscribers->subscriberAddr,s1));

        // Insert at beginning...
        newsubscriber = createSubscriber(ifx, src);
        newsubscriber->nextsubscriber = route->subscribers;
        newsubscriber->prevsubscriber = NULL;
        route->subscribers = newsubscriber;

        // If the subscriber has a next node, its previous pointer must be updated.
        if(newsubscriber->nextsubscriber != NULL) {
            newsubscriber->nextsubscriber->prevsubscriber = newsubscriber;
        }
        return;
    }


    // Find insertion point or existing subscription
    for( csubscriber = route->subscribers; csubscriber->nextsubscriber != NULL; csubscriber = csubscriber->nextsubscriber ) {
        if(csubscriber->nextsubscriber->vifIndex > ifx || csubscriber->nextsubscriber->subscriberAddr > src) {
            break;
        }
    }

    if(csubscriber->vifIndex == ifx && csubscriber->subscriberAddr == src) {
        // subscriber is already registered, just return
        csubscriber->ageValue = conf->robustnessValue;
        my_log(LOG_WARNING, 0, "Subscriber %s already registered, skipping.", inetFmt(csubscriber->subscriberAddr,s1));
        return;
    }
    my_log(LOG_WARNING, 0, "Inserting after subscriber %s",inetFmt(csubscriber->subscriberAddr,s1));

    // Insert after current...
    newsubscriber = createSubscriber(ifx, src);
    newsubscriber->nextsubscriber = csubscriber->nextsubscriber;
    newsubscriber->prevsubscriber = csubscriber;
    if(csubscriber->nextsubscriber != NULL) {
        csubscriber->nextsubscriber->prevsubscriber = newsubscriber;
    }
    csubscriber->nextsubscriber = newsubscriber;
}

/**
 * Ages all subscribers of a route.
 */
void ageSubscribersForRoute(struct RouteTable * route) {
    struct GroupSubscriber * csubscriber;
    struct GroupSubscriber * nextsubscriber;

    csubscriber = route->subscribers;

    while (csubscriber != NULL) {
        nextsubscriber = csubscriber->nextsubscriber;
        csubscriber->ageValue--;
        my_log(LOG_WARNING, 0, "Aged subscriber %s in group %s: age %d",
                inetFmt(csubscriber->subscriberAddr, s1), inetFmt(route->group, s2), csubscriber->ageValue);
        if (csubscriber->ageValue == 0) {
            removeSubscriber(route, csubscriber->vifIndex, csubscriber->subscriberAddr);
        }
        csubscriber = nextsubscriber;
    }
}


/**
*   Adds a specified route to the routingtable.
*   If the route already exists, the existing route is updated...
*/
int insertRoute(uint32_t group, int ifx, uint32_t src) {
    
    struct Config *conf = getCommonConfig();
    struct RouteTable* croute;

    // Sanity check the group address...
    if( ! IN_MULTICAST( ntohl(group) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group. Table insert failed.",
            inetFmt(group, s1));
        return 0;
    }

    // Santiy check the VIF index...
    //if(ifx < 0 || ifx >= MAX_MC_VIFS) {
    if(ifx >= MAX_MC_VIFS) {
        my_log(LOG_WARNING, 0, "The VIF Ix %d is out of range (0-%d). Table insert failed.",ifx,MAX_MC_VIFS);
        return 0;
    }

    // Try to find an existing route for this group...
    croute = findRoute(group);
    if(croute==NULL) {
        struct RouteTable*  newroute;

        my_log(LOG_DEBUG, 0, "No existing route for %s. Create new.",
                inetFmt(group, s1));

        // Add the route to the routing table
        newroute = createRoute(group);
        addRoute(newroute);

        // Set the new route as the current...
        croute = newroute;

        if (src > 0) {
            my_log(LOG_INFO, 0, "Added route, group %s on VIF #%d",
                    inetFmt(croute->group, s1),ifx);
        } else {
            my_log(LOG_INFO, 0, "Added route, group %s no subscriber yet",
                    inetFmt(croute->group, s1));
        }
    }

    if(ifx >= 0) {
        // Register the VIF activity for the aging routine
        BIT_SET(croute->ageVifBits, ifx);
        if (!BIT_TST(croute->vifBits, ifx)) {
            BIT_SET(croute->vifBits, ifx);
            
            // If the route is active, it must be reloaded into the Kernel..
            if(croute->originAddr != 0) {
                if(!internUpdateKernelRoute(croute, 1)) {
                    my_log(LOG_WARNING, 0, "The insertion into Kernel failed.");
                    return 0;
                }
            }
        }

        my_log(LOG_INFO, 0, "Updated route, group %s subscriber %s (on VIF #%d)",
                inetFmt(croute->group, s1),inetFmt(src, s2),ifx);
        addSubscriber(croute, ifx, src);

        // Log the cleanup in debugmode...
        my_log(LOG_INFO, 0, "Updated route entry for %s on VIF #%d",
               inetFmt(croute->group, s1), ifx);

        // Return to JOINED state, if in CHECK_LAST_MEMBER state
        if(croute->upstrState == ROUTESTATE_CHECK_LAST_MEMBER) {
            croute->upstrState = ROUTESTATE_JOINED;
            croute->ageValue = conf->robustnessValue;
        }
        // Send join message upstream, if the route has no joined flag...
        if(croute->upstrState != ROUTESTATE_JOINED) {
            // Send Join request upstream
            sendJoinLeaveUpstream(croute, 1);
        }
    }

    logRouteTable("Insert/Refresh Route");

    return 1;
}


/**
*   Removes a specific subscriber from the route.
*   If no subscribers remain the route may be removed
*/
void leaveRoute(uint32_t group, int ifx, uint32_t src) {

    struct RouteTable* croute;
    croute = findRoute(group);
    if(croute == NULL){
        my_log(LOG_WARNING, 0, "Cant leave route: Route not found.");
        return;
    }
    if (!removeSubscriber(croute, ifx, src)) {
        my_log(LOG_WARNING, 0, "Cant leave route: Subscriber not found.");
    }

    if(croute->subscribers == NULL) {
        // TODO no subscribers left -> remove route in quickleave mode
        my_log(LOG_WARNING, 0, "No subscribers left, route can be removed.");
        struct Config *conf = getCommonConfig();
        if (conf->fastUpstreamLeave) {
            removeRoute(croute);
        }
    }
}


/**
*   Activates a passive group. If the group is already
*   activated, it's reinstalled in the kernel. If
*   the route is activated, no originAddr is needed.
*/
int activateRoute(uint32_t group, uint32_t originAddr) {
    struct RouteTable*  croute;
    int result = 0;

    // Find the requested route.
    croute = findRoute(group);
    if(croute == NULL) {
        my_log(LOG_DEBUG, 0,
		"No table entry for %s [From: %s]. Inserting route.",
		inetFmt(group, s1),inetFmt(originAddr, s2));

        // Insert route, but no interfaces have yet requested it downstream.
        insertRoute(group, -1, 0);

        // Retrieve the route from table...
        croute = findRoute(group);
    }

    if(croute != NULL) {
        // If the origin address is set, update the route data.
        if(originAddr > 0) {
            if(croute->originAddr > 0 && croute->originAddr!=originAddr) {
                my_log(LOG_WARNING, 0, "The origin for route %s changed from %s to %s",
                    inetFmt(croute->group, s1),
                    inetFmt(croute->originAddr, s2),
                    inetFmt(originAddr, s3));
            }
            croute->originAddr = originAddr;
        }

        // Only update kernel table if there are listeners !
        if(croute->vifBits > 0) {
            result = internUpdateKernelRoute(croute, 1);
        }
    } else {
        my_log(LOG_WARNING, 0,
        "WARN: activateRoute for group %s, route was NOT created!",
        inetFmt(group, s1));
    }

    logRouteTable("Activate Route");

    return result;
}


/**
*   This function loops through all routes, and updates the age 
*   of any active routes.
*/
void ageActiveRoutes() {
    struct RouteTable   *croute, *nroute;
    
    my_log(LOG_DEBUG, 0, "Aging routes in table.");

    // Scan all routes...
    for( croute = routing_table; croute != NULL; croute = nroute ) {
        
        // Keep the next route (since current route may be removed)...
        nroute = croute->nextroute;

        // Run the aging round algorithm.
        if(croute->upstrState != ROUTESTATE_CHECK_LAST_MEMBER) {
            // Only age routes if Last member probe is not active...
            internAgeRoute(croute);
        }
    }
    logRouteTable("Age active routes");
}

/**
*   Should be called when a leave message is recieved, to
*   mark a route for the last member probe state.
*/
void setRouteLastMemberMode(uint32_t group) {
    struct Config       *conf = getCommonConfig();
    struct RouteTable   *croute;

    croute = findRoute(group);
    if(croute!=NULL) {
        // Check for fast leave mode...
        // TODO disabled old fastleave
        //    client interface should "quickleave" (i.e. remove route to vif)
        //    upstream interface should quickleave when no client interfaces left
        //if(croute->upstrState == ROUTESTATE_JOINED && conf->fastUpstreamLeave) {
        //    my_log(LOG_DEBUG, 0, "quickleave option enabled, leaving now.");
        //
        //    // Send a leave message right away..
        //    sendJoinLeaveUpstream(croute, 0);
        //}
        // Set the routingstate to Last member check...
        croute->upstrState = ROUTESTATE_CHECK_LAST_MEMBER;
        // Set the count value for expiring... (-1 since first aging)
        croute->ageValue = conf->lastMemberQueryCount;
    }
}


/**
*   Ages groups in the last member check state. If the
*   route is not found, or not in this state, 0 is returned.
*/
int lastMemberGroupAge(uint32_t group) {
    struct RouteTable   *croute;

    croute = findRoute(group);
    if(croute!=NULL) {
        if(croute->upstrState == ROUTESTATE_CHECK_LAST_MEMBER) {
            return !internAgeRoute(croute);
        } else {
            return 0;
        }
    }
    return 0;
}

/**
*   Remove a specified route. Returns 1 on success,
*   and 0 if route was not found.
*/
int removeRoute(struct RouteTable*  croute) {
    struct Config       *conf = getCommonConfig();
    int result = 1;
    
    // If croute is null, no routes was found.
    if(croute==NULL) {
        return 0;
    }

    // Log the cleanup in debugmode...
    my_log(LOG_DEBUG, 0, "Removed route entry for %s from table.",
                 inetFmt(croute->group, s1));

    //BIT_ZERO(croute->vifBits);

    // Uninstall current route from kernel
    if(!internUpdateKernelRoute(croute, 0)) {
        my_log(LOG_WARNING, 0, "The removal from Kernel failed.");
        result = 0;
    }

    // Send Leave request upstream if group is joined
    // TODO  do we need to keep the check for fastUpstreamLeave? (any harm sending LEAVE twice?)
    //if(croute->upstrState == ROUTESTATE_JOINED ||
    //   (croute->upstrState == ROUTESTATE_CHECK_LAST_MEMBER && !conf->fastUpstreamLeave))
    if(croute->upstrState == ROUTESTATE_JOINED || croute->upstrState == ROUTESTATE_CHECK_LAST_MEMBER)
    {
        sendJoinLeaveUpstream(croute, 0);
    }

    // Update pointers...
    if(croute->prevroute == NULL) {
        // Topmost node...
        if(croute->nextroute != NULL) {
            croute->nextroute->prevroute = NULL;
        }
        routing_table = croute->nextroute;

    } else {
        croute->prevroute->nextroute = croute->nextroute;
        if(croute->nextroute != NULL) {
            croute->nextroute->prevroute = croute->prevroute;
        }
    }
    // Free the memory, and set the route to NULL...
    free(croute);
    croute = NULL;

    logRouteTable("Remove route");

    return result;
}


/**
*   Ages a specific route
*/
int internAgeRoute(struct RouteTable*  croute) {
    struct Config *conf = getCommonConfig();
    int result = 0;

    // Drop age by 1.
    croute->ageValue--;
    ageSubscribersForRoute(croute);

    // Check if there has been any activity...
    if( croute->ageVifBits > 0 && croute->ageActivity == 0 ) {
        // There was some activity, check if all registered vifs responded.
        if(croute->vifBits == croute->ageVifBits) {
            // Everything is in perfect order, so we just reset the route age.
            croute->ageValue = conf->robustnessValue;
            //croute->ageActivity = 0;
        } else {
            // One or more VIF has not gotten any response.
            croute->ageActivity++;

            // Update the actual bits for the route...
            croute->vifBits = croute->ageVifBits;
        }
    } 
    // Check if there have been activity in aging process...
    else if( croute->ageActivity > 0 ) {

        // If the bits are different in this round, we must
        if(croute->vifBits != croute->ageVifBits) {
            // Or the bits together to insure we don't lose any listeners.
            croute->vifBits |= croute->ageVifBits;

            // Register changes in this round as well..
            croute->ageActivity++;
        }
    }

    // If the aging counter has reached zero, its time for updating...
    if(croute->ageValue == 0) {
        // Check for activity in the aging process,
        if(croute->ageActivity>0) {
            
            my_log(LOG_DEBUG, 0, "Updating route after aging : %s",
                         inetFmt(croute->group,s1));
            
            // Just update the routing settings in kernel...
            internUpdateKernelRoute(croute, 1);
    
            // ...reset the route age and start over.
            croute->ageValue = conf->robustnessValue;
            croute->ageActivity = 0;
        } else {

            my_log(LOG_DEBUG, 0, "Removing group %s. Died of old age.",
                         inetFmt(croute->group,s1));

            // No activity was registered within the timelimit, so remove the route.
            removeRoute(croute);
        }
        // Tell that the route was updated...
        result = 1;
    }

    // The aging vif bits must be reset for each round...
    BIT_ZERO(croute->ageVifBits);

    return result;
}

/**
*   Updates the Kernel routing table. If activate is 1, the route
*   is (re-)activated. If activate is false, the route is removed.
*/
int internUpdateKernelRoute(struct RouteTable *route, int activate) {
    struct   MRouteDesc     mrDesc;
    struct   IfDesc         *Dp;
    unsigned                Ix;
    
    if(route->originAddr>0 && route->vifBits!=0) {

        // Build route descriptor from table entry...
        // Set the source address and group address...
        mrDesc.McAdr.s_addr     = route->group;
        mrDesc.OriginAdr.s_addr = route->originAddr;
    
        // clear output interfaces 
        memset( mrDesc.TtlVc, 0, sizeof( mrDesc.TtlVc ) );
    
        my_log(LOG_DEBUG, 0, "Vif bits : 0x%08x", route->vifBits);

        // Set the TTL's for the route descriptor...
        for ( Ix = 0; (Dp = getIfByIx(Ix)); Ix++ ) {
            if(Dp->state == IF_STATE_UPSTREAM) {
                mrDesc.InVif = Dp->index;
            }
            else if(BIT_TST(route->vifBits, Dp->index)) {
                my_log(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", Dp->index, Dp->threshold);
                mrDesc.TtlVc[ Dp->index ] = Dp->threshold;
            }
        }
    
        // Do the actual Kernel route update...
        if(activate) {
            // Add route in kernel...
            addMRoute( &mrDesc );
    
        } else {
            // Delete the route from Kernel...
            delMRoute( &mrDesc );
        }

    } else {
        my_log(LOG_NOTICE, 0, "Route is not active. No kernel updates done.");
    }

    return 1;
}

/**
*   Debug function that writes the routing table entries
*   to the log.
*/
void logRouteTable(char *header) {
        struct RouteTable*      croute = routing_table;
        struct GroupSubscriber* csubscriber;
        unsigned                rcount = 0;
    
        my_log(LOG_DEBUG, 0, "");
        my_log(LOG_INFO, 0, "Current routing table (%s):", header);
        my_log(LOG_DEBUG, 0, "-----------------------------------------------------");
        if(croute==NULL) {
            my_log(LOG_DEBUG, 0, "No routes in table...");
        } else {
            do {
                /*
                my_log(LOG_DEBUG, 0, "#%d: Src: %s, Dst: %s, Age:%d, St: %s, Prev: 0x%08x, T: 0x%08x, Next: 0x%08x",
                    rcount, inetFmt(croute->originAddr, s1), inetFmt(croute->group, s2),
                    croute->ageValue,(croute->originAddr>0?"A":"I"),
                    croute->prevroute, croute, croute->nextroute);
                */
                my_log(LOG_DEBUG, 0, "#%d: Src: %s, Dst: %s, Age:%d, St: %s, OutVifs: 0x%08x",
                    rcount, inetFmt(croute->originAddr, s1), inetFmt(croute->group, s2),
                    croute->ageValue,(croute->originAddr>0?"A":"I"),
                    croute->vifBits);
                  
                my_log(LOG_INFO, 0, "   Group: %s",
                        inetFmt(croute->group, s1));

                for (csubscriber = croute->subscribers; csubscriber != NULL; csubscriber = csubscriber->nextsubscriber) {
                    my_log(LOG_INFO, 0, "       Subscriber: %s, Vif: %d",
                            inetFmt(csubscriber->subscriberAddr, s2),
                            csubscriber->vifIndex);
                }

                croute = croute->nextroute; 
        
                rcount++;
            } while ( croute != NULL );
        }
    
        my_log(LOG_DEBUG, 0, "-----------------------------------------------------");
}
