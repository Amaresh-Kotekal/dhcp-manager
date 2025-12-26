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

#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "secure_wrapper.h"
#include "ansc_platform.h"
#include "util.h"
#include "cosa_dhcpv4_apis.h"
#include "dhcpv4_interface.h"
#include "dhcpv6_interface.h"
#include "dhcpmgr_controller.h"
#include "dhcp_lease_monitor_thrd.h"
#include "cosa_apis_util.h"

static int ipcListenFd = 0;

static ANSC_STATUS DhcpMgr_LeaseMonitor_Init();
static void* DhcpMgr_LeaseMonitor_Thrd(void *arg);

static ANSC_STATUS DhcpMgr_LeaseMonitor_Init()
{
    if ((ipcListenFd = nn_socket(AF_SP, NN_PULL)) < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to create IPC socket\n", __FUNCTION__, __LINE__);
        return ANSC_STATUS_FAILURE;
    }
    if ((nn_bind(ipcListenFd, DHCP_MANAGER_ADDR)) < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to bind IPC socket\n", __FUNCTION__, __LINE__);
        nn_close(ipcListenFd);
        return ANSC_STATUS_FAILURE;
    }
    DHCPMGR_LOG_INFO("[%s-%d] IPC Socket initialized and bound successfully\n", __FUNCTION__, __LINE__);
    return ANSC_STATUS_SUCCESS;
}

int DhcpMgr_LeaseMonitor_Start()
{
    pthread_t ipcThreadId;
    int retStatus = -1;
    int ret = -1;

    if(DhcpMgr_LeaseMonitor_Init() != ANSC_STATUS_SUCCESS)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to initialise IPC messaging\n", __FUNCTION__, __LINE__);
        return -1;
    }

    ret = pthread_create(&ipcThreadId, NULL, &DhcpMgr_LeaseMonitor_Thrd, NULL);
    if (0 != ret)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to start IPC Thread Error:%d\n", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] IPC Thread Started Successfully\n", __FUNCTION__, __LINE__);
        retStatus = 0;

    }
    return retStatus;
}

static void* DhcpMgr_LeaseMonitor_Thrd(void *arg)
{
    (void)arg;  // Mark argument as intentionally unused
    pthread_detach(pthread_self());

    BOOL bRunning = TRUE;

    int bytes = 0;
    int msg_size = sizeof(PLUGIN_MSG);
    PLUGIN_MSG plugin_msg;
    memset(&plugin_msg, 0, sizeof(PLUGIN_MSG));

    DHCPMGR_LOG_INFO("[%s-%d] DHCP Lease Monitor Thread Started\n", __FUNCTION__, __LINE__);

    while (bRunning)
    {
        bytes = nn_recv(ipcListenFd, (PLUGIN_MSG *)&plugin_msg, msg_size, 0);
        if (bytes == msg_size)
        {
            DHCPMGR_LOG_INFO("[%s-%d] Received message of size %d\n", __FUNCTION__, __LINE__, plugin_msg.version);
           //DHCPMGR_LOG_INFO("[%s-%d] Received valid message of size %d\n", __FUNCTION__, __LINE__, bytes);
            switch (plugin_msg.version)
            {
                case DHCP_VERSION_4:
                {
                    DHCPv4_PLUGIN_MSG *newLease = (DHCPv4_PLUGIN_MSG *) malloc(sizeof(DHCPv4_PLUGIN_MSG));
                    memcpy(newLease,&plugin_msg.data.dhcpv4, sizeof(DHCPv4_PLUGIN_MSG));
                    newLease->next = NULL;
                    DHCPMGR_LOG_INFO("[%s-%d] Processing DHCPv4 lease for interface: %s\n",__FUNCTION__, __LINE__, plugin_msg.ifname);
                    DHCPMgr_AddDhcpv4Lease(plugin_msg.ifname, newLease);

                    // Send the lease to the Controller via message queue
                    char mq_name[MAX_STR_LEN];
                    snprintf(mq_name, sizeof(mq_name), "mq_if_%s", plugin_msg.ifname);
                    DHCPMGR_LOG_INFO("[%s-%d] Attempting to open message queue %s\n", __FUNCTION__, __LINE__, mq_name);
                    // Open the message queue
                    mqd_t mq_desc = mq_open(mq_name, O_WRONLY | O_NONBLOCK);
                    if (mq_desc == (mqd_t)-1) {
                        DHCPMGR_LOG_ERROR("[%s-%d] Failed to open message queue %s\n", __FUNCTION__, __LINE__, mq_name);
                    } else {
                        interface_info_t info;
                        memset(&info, 0, sizeof(interface_info_t));
                        strncpy(info.if_name, plugin_msg.ifname, MAX_STR_LEN - 1);
                        strncpy(info.mq_name, mq_name, MAX_STR_LEN - 1);
                        info.thread_running = TRUE;
                        info.mq_desc = mq_desc;
                        info.msg.dhcpType = DML_DHCPV4;
                        strcpy(info.msg.ParamName, "ProcessLease");

                        
                        if (mq_send(info.mq_desc,(char*) &info, sizeof(info), 0) == -1) {
                            DHCPMGR_LOG_ERROR("[%s-%d] Failed to send message to queue %s\n", __FUNCTION__, __LINE__, mq_name);
                        } else {
                            DHCPMGR_LOG_INFO("[%s-%d] Successfully sent DHCPv4 lease to controller queue %s\n", __FUNCTION__, __LINE__, mq_name);
                        }
                        mq_close(mq_desc);
                    }
                    
                    break;
                }
                case DHCP_VERSION_6:
                {
                    DHCPv6_PLUGIN_MSG *newLeasev6 = (DHCPv6_PLUGIN_MSG *) malloc(sizeof(DHCPv6_PLUGIN_MSG));
                    memcpy(newLeasev6,&plugin_msg.data.dhcpv6, sizeof(DHCPv6_PLUGIN_MSG));
                    newLeasev6->next = NULL;
                    DHCPMGR_LOG_INFO("[%s-%d] Processing DHCPv6  lease for interface: %s\n",__FUNCTION__, __LINE__, plugin_msg.ifname);
                    DHCPMgr_AddDhcpv6Lease(plugin_msg.ifname, newLeasev6);

                    // Send the lease to the Controller via message queue
                    char mq_name[MAX_STR_LEN];
                    snprintf(mq_name, sizeof(mq_name), "/mq_if_%s", plugin_msg.ifname);  
                    DHCPMGR_LOG_INFO("[%s-%d] Attempting to open message queue %s\n", __FUNCTION__, __LINE__, mq_name);
                    // Open the message queue
                    mqd_t mq_desc = mq_open(mq_name, O_WRONLY | O_NONBLOCK);
                    if (mq_desc == (mqd_t)-1) {
                        DHCPMGR_LOG_ERROR("[%s-%d] Failed to open message queue %s\n", __FUNCTION__, __LINE__, mq_name);
                    } else {
                        interface_info_t info;
                        memset(&info, 0, sizeof(interface_info_t));
                        strncpy(info.if_name, plugin_msg.ifname, MAX_STR_LEN - 1);
                        strncpy(info.mq_name, mq_name, MAX_STR_LEN - 1);
                        info.thread_running = TRUE;
                        info.mq_desc = mq_desc;
                        info.msg.dhcpType = DML_DHCPV6;
                        strcpy(info.msg.ParamName, "ProcessLease");
                        if (mq_send(info.mq_desc,(char*) &info, sizeof(info), 0) == -1) {
                            DHCPMGR_LOG_ERROR("[%s-%d] Failed to send message to queue %s\n", __FUNCTION__, __LINE__, mq_name);
                        } else {
                            DHCPMGR_LOG_INFO("[%s-%d] Successfully sent DHCPv6 lease to controller queue %s\n", __FUNCTION__, __LINE__, mq_name);
                        }
                        mq_close(mq_desc);
                    }
                    break;
                }
                default:
                    DHCPMGR_LOG_ERROR("[%s-%d] Invalid Message version sent to DhcpManager\n", __FUNCTION__, __LINE__);
                    break;
            }
            memset(&plugin_msg, 0, sizeof(PLUGIN_MSG));
        }
        else if (bytes < 0)
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Failed to receive message from IPC\n", __FUNCTION__, __LINE__);
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] message size unexpected\n", __FUNCTION__, __LINE__);
        }
    }
    nn_shutdown(ipcListenFd, 0);
    nn_close(ipcListenFd);
    DHCPMGR_LOG_INFO("[%s-%d] DHCP Lease Monitor Thread Exiting\n", __FUNCTION__, __LINE__);
    pthread_exit(NULL);
}
