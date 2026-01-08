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

#ifndef _DHCPMGR_RBUS_H_
#define _DHCPMGR_RBUS_H_
#include <rbus/rbus.h>
#include "cosa_apis.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv6_apis.h"
#include "ipc_msg.h"

/* DHCPv4 rbus entries */
#define DHCP_MGR_DHCPv4_IFACE "Device.DHCPv4.Client.{i}."
#define DHCP_MGR_DHCPv4_TABLE "Device.DHCPv4.Client"
#define DHCP_MGR_DHCPv4_STATUS "Device.DHCPv4.Client.{i}.Events"
#define DHCPv4_EVENT_FORMAT "Device.DHCPv4.Client.%d.Events"


/*DHCPv6 rbus entries */
#define DHCP_MGR_DHCPv6_IFACE "Device.DHCPv6.Client.{i}."
#define DHCP_MGR_DHCPv6_TABLE "Device.DHCPv6.Client"
#define DHCP_MGR_DHCPv6_STATUS "Device.DHCPv6.Client.{i}.Events"
#define DHCPv6_EVENT_FORMAT "Device.DHCPv6.Client.%d.Events"

/**
 * @brief Initializes the DHCP Manager by opening an rbus handle and registering rbus DML, DML tables, and rbus events.
 *
 * This function is responsible for setting up the necessary rbus components for the DHCP Manager to operate.
 * It opens an rbus handle and registers the required rbus DML, DML tables, and rbus events.
 *
 * @return ANSC_STATUS
 * @retval ANSC_STATUS_SUCCESS if the initialization is successful.
 * @retval ANSC_STATUS_FAILURE if the initialization fails.
 */
ANSC_STATUS DhcpMgr_Rbus_Init();

/**
 * @brief Publishes DHCPv4 rbus events.
 *
 * This function publishes DHCPv4 rbus events based on the specified message type.
 * The rbus event will include the tags "IfName" and "MsgType". For the `DHCP_LEASE_UPDATE` message type,
 * it additionally sends "LeaseInfo".
 *
 * @param pDhcpc Pointer to the DHCP client structure.
 * @param msgType The type of DHCP message to be published. The possible values are:
 * - DHCP_CLIENT_STARTED: Indicates the DHCP client has started.
 * - DHCP_CLIENT_STOPPED: Indicates the DHCP client has stopped.
 * - DHCP_CLIENT_FAILED: Indicates the DHCP client has failed.
 * - DHCP_LEASE_UPDATE: Indicates a new lease or a change in the lease value.
 * - DHCP_LEASE_DEL: Indicates the lease has expired or been released.
 * - DHCP_LEASE_RENEW: Indicates the lease has been renewed.
 *
 * @return int
 * @retval 0 if the event is published successfully.
 * @retval -1 if there is an error in publishing the event.
 */
int DhcpMgr_PublishDhcpV4Event(PCOSA_DML_DHCPC_FULL pDhcpc, DHCP_MESSAGE_TYPE msgType);

/**
 * @brief Publishes DHCPv6 rbus events.
 *
 * This function publishes DHCPv6 rbus events based on the specified message type.
 * The rbus event will include the tags "IfName" and "MsgType". For the `DHCP_LEASE_UPDATE` message type,
 * it additionally sends "LeaseInfo".
 *
 * @param pDhcpv6c Pointer to the DHCPv6 client structure.
 * @param msgType The type of DHCP message to be published. The possible values are:
 * - DHCP_CLIENT_STARTED: Indicates the DHCP client has started.
 * - DHCP_CLIENT_STOPPED: Indicates the DHCP client has stopped.
 * - DHCP_CLIENT_FAILED: Indicates the DHCP client has failed.
 * - DHCP_LEASE_UPDATE: Indicates a new lease or a change in the lease value.
 * - DHCP_LEASE_DEL: Indicates the lease has expired or been released.
 * - DHCP_LEASE_RENEW: Indicates the lease has been renewed.
 *
 * @return int
 * @retval 0 if the event is published successfully.
 * @retval -1 if there is an error in publishing the event.
 */
int DhcpMgr_PublishDhcpV6Event(PCOSA_DML_DHCPCV6_FULL pDhcpv6c, DHCP_MESSAGE_TYPE msgType);

/*
 *@brief rbus get data handler.
 * This function is called when other components request data for the registered rbus data elements.
 * It handles the get data actions for the specified rbus properties.
 * @param handle The rbus handle.
 * @param rbusProperty The rbus property for which data is requested.
 * @param pRbusGetHandlerOptions Options for the get handler.
 * @return rbusError_t
 * @retval RBUS_ERROR_SUCCESS if the data is retrieved successfully.
 * @retval RBUS_ERROR_FAILURE if there is an error retrieving the data.
*/
rbusError_t getDataHandler(rbusHandle_t rbusHandle, rbusProperty_t rbusProperty,rbusGetHandlerOptions_t *pRbusGetHandlerOptions);
#endif// _DHCPMGR_RBUS_H_

