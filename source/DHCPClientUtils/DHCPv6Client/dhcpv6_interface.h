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
#ifndef DHCPV6_INTERFACE_H
#define DHCPV6_INTERFACE_H

#include <sys/types.h>

#include "dhcp_client_common_utils.h"
#include "util.h"


#define AFTR_NAME_LENGTH                 256

typedef struct _DHCPv6_PLUGIN_MSG
{
    bool isExpired;        /** Is the lease time expired ? */
    char ifname[BUFLEN_32];    /** Dhcp interface name */

    //address details
    struct {
        bool     assigned;     /**< Have we been assigned an address ? */
        char     address[BUFLEN_48];      /**< New IPv6 address */
        uint32_t IA_ID;
        uint32_t PreferedLifeTime;
        uint32_t ValidLifeTime;
        uint32_t T1;
        uint32_t T2;
    }ia_na;

    //IAPD details
    struct {
        bool     assigned;     /**< Have we been assigned an prefix ? */
        char     Prefix[BUFLEN_48];   /**< New site prefix, if prefixAssigned==TRUE */
        uint32_t PrefixLength;
        uint32_t IA_ID;
        uint32_t PreferedLifeTime;
        uint32_t ValidLifeTime;
        uint32_t T1;
        uint32_t T2;
    }ia_pd;

    //DNS details
    struct {
        bool assigned;
        char nameserver[BUFLEN_128];  /**< New nameserver,   */
        char nameserver1[BUFLEN_128];  /**< New nameserver,   */
    } dns;

    //MAPT
    struct {
        bool Assigned;     /**< Have we been assigned mapt config ? */
        unsigned char  Container[BUFLEN_256]; /* MAP-T option 95 in hex format*/
    }mapt;
 
    //MAPE
    struct {
        bool Assigned;     /**< Have we been assigned mape config ? */
        unsigned char  Container[BUFLEN_256]; /* MAP-E option 94 in hex format*/
    }mape;

    //Vendor Specific Options
    struct {
        bool Assigned;  /**< Have we received vendor-specific options? */
        char Data[BUFLEN_256]; /* Buffer to store vendor-specific options */
        uint32_t Length; /* Length of vendor-specific options */
    }vendor;

    char domainName[BUFLEN_64];  /**< New domain Name,   */
    char ntpserver[BUFLEN_128];  /**< New ntp server(s), dhcp server may provide this */
    char aftr[AFTR_NAME_LENGTH]; /**< dhcp server may provide this */
    uint32_t ipv6_TimeOffset; /**< New time offset (seconds, stored as 32-bit bit pattern of signed value) */
    struct _DHCPv6_PLUGIN_MSG  *next;  /** link to the next lease */
}DHCPv6_PLUGIN_MSG;

/**
 * @brief Interface API for starting the DHCPv6 client.
 *
 * This function creates the configuration file using the provided request and send option lists,
 * starts the DHCPv6 client, and collects the process ID (PID).
 *
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return The process ID (PID) of the started DHCPv6 client.
 */
pid_t start_dhcpv6_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list);

/**
 * @brief Interface API for triggering a renew from the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to trigger a renew.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv6_renew(pid_t processID);

/**
 * @brief Interface API for triggering a release from the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to trigger a release and terminate.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv6_release(pid_t processID);

/**
 * @brief Interface API for stopping the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to stop the client.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
int stop_dhcpv6_client(pid_t processID);

#endif // DHCPV6_INTERFACE_H
