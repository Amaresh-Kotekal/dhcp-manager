/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef DHCP_LEASE_MONITOR_THRD_H
#define DHCP_LEASE_MONITOR_THRD_H

#include <stdbool.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include "dhcpv6_interface.h"
#include "dhcpv4_interface.h"

#define DHCP_MANAGER_ADDR              "tcp://127.0.0.1:50324"

#define LEASE_MONITOR_BIND_MAX_RETRIES          40
#define LEASE_MONITOR_BIND_RETRY_DELAY_USEC    500000

typedef enum {
    DHCP_VERSION_4,
    DHCP_VERSION_6,
} DHCP_SOURCE;

typedef struct {
    char ifname[BUFLEN_32];
    DHCP_SOURCE version;
    union {
        DHCPv4_PLUGIN_MSG dhcpv4;
        DHCPv6_PLUGIN_MSG dhcpv6;
    } data;
} PLUGIN_MSG;

/**
 * @brief Starts the DHCP Lease Monitor service.
 *
 * This function initializes and starts the DHCP Lease Monitor,
 * which listens for DHCP lease events and processes lease updates.
 *
 * @return 0 on successful start, -1 otherwise.
 */
int  DhcpMgr_LeaseMonitor_Start();

#endif
