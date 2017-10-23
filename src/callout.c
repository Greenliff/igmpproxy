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


#include "igmpproxy.h"

/* the code below implements a callout queue */
static int id = 0;
static struct timeOutQueue  *queue = 0; /* pointer to the beginning of timeout queue */

struct timeOutQueue {
    struct timeOutQueue    *next;   // Next event in queue
    int                     id;  
    timer_f                 func;   // function to call
    void                    *data;  // Data for function
    struct timeval			time;   // Point in time for the event
};

// Method for dumping the Queue to the log.
static void debugQueue(void);

/**
*   Initializes the callout queue
*/
void callout_init() {
    queue = NULL;
}

/**
*   Clears all scheduled timeouts...
*/
void free_all_callouts() {
    struct timeOutQueue *p;

    while (queue) {
        p = queue;
        queue = queue->next;
        free(p);
    }
}


/**
 * elapsed_time seconds have passed; perform all the events that should
 * happen.
 */
void age_callout_queue() {
    struct timeval  curtime;
    struct timeOutQueue *timer;

    gettimeofday(&curtime, NULL);
    while (queue != NULL && timercmp(&curtime, &queue->time, >)) {
    	timer = queue;
        queue = queue->next;

        my_log(LOG_DEBUG, 0, "About to call timeout %d", timer->id);
        if (timer->func)
        	timer->func(timer->data);
        free(timer);
    }
}

/**
 *  Inserts a timer in queue.
 *  @param delay - Number of seconds the timeout should happen in.
 *  @param action - The function to call on timeout.
 *  @param data - Pointer to the function data to supply...
 */
int timer_setTimer(int delay, timer_f action, void *data) {
    struct     timeOutQueue  *ptr, *node, *prev;

    /* create a node */ 
    node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue));
    if (node == 0) {
        my_log(LOG_WARNING, 0, "Malloc Failed in timer_settimer\n");
        return -1;
    }
    node->func = action; 
    node->data = data;
    node->next = NULL;
    node->id   = ++id;
    gettimeofday(&node->time, NULL);
    node->time.tv_sec += delay;

    prev = ptr = queue;

    /* insert node in the queue */

    /* if the queue is empty, insert the node and return */
    if (!queue) {
        queue = node;
        return node->id;
    }
    /* search for the right place */
    while (ptr) {
        if (timercmp(&node->time, &ptr->time, <)) {
            // We found the insertion place
            break;
        }
        if (node->data == ptr->data && node->func == ptr->func) {
        	// function is already scheduled, lets not do it again (we only care if data == NULL;-)
            my_log(LOG_WARNING, 0, "Function already scheduled, skipped\n");
        	free(node);
        	return ptr->id;
        }
        prev = ptr;
        ptr = ptr->next;
    }
    node->next = ptr;
    if (ptr == queue) {
    	// insert at head
        queue = node;
    }
    else {
    	// insert in the middle (i.e. there is a previous element)
        prev->next = node;
    }

    return node->id;
}


/**
 * debugging utility
 */
static void debugQueue() {
    struct timeOutQueue  *ptr;

    for (ptr = queue; ptr; ptr = ptr->next) {
            my_log(LOG_DEBUG, 0, "(Id:%d, Time:%d) ", ptr->id, ptr->time);
    }
}
