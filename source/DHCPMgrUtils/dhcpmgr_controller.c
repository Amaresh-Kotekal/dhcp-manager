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

/* ---- Include Files ---------------------------------------- */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "util.h"
#include "ansc_platform.h"
#include "cosa_apis.h"
#include "cosa_dml_api_common.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv4_dml.h"
#include "dhcpv4_interface.h"
#include "cosa_dhcpv6_dml.h"
#include "cosa_dhcpv6_apis.h"
#include "cosa_dhcpv6_internal.h"
#include "dhcpv6_interface.h"
#include "dhcpmgr_controller.h"
#include "dhcp_lease_monitor_thrd.h"
#include "dhcpmgr_rbus_apis.h"
#include "dhcp_client_common_utils.h"
#include "cosa_apis.h"
#include "dhcpmgr_recovery_handler.h"
#include "dhcpmgr_custom_options.h"


/* ---- Global Constants -------------------------- */

static void* DhcpMgr_MainController( void *arg );

/**
 * @brief Starts the main controller thread.
 *
 * This function initializes and starts the main controller thread for the DHCP Manager.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int DhcpMgr_StartMainController()
{
    pthread_t threadId;
    int ret = -1;

    ret = pthread_create( &threadId, NULL, &DhcpMgr_MainController, NULL );

    if( 0 != ret )
    {
        DHCPMGR_LOG_ERROR("%s %d - Failed to start Main Controller Thread Error:%d\n", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d - Main Controller Thread Started Successfully\n", __FUNCTION__, __LINE__);
        ret = 0;
    }

    return ret;
}

/**
 * @brief Builds the DHCPv4 option lists.
 *
 * This function constructs the `req_opt_list` and `send_opt_list` from the DML entries.
 *
 * @param[in] hInsContext A handle to the DHCP client context.
 * @param[out] req_opt_list A pointer to the list of requested DHCP options.
 * @param[out] send_opt_list A pointer to the list of DHCP options to be sent.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
static int DhcpMgr_build_dhcpv4_opt_list (PCOSA_CONTEXT_DHCPC_LINK_OBJECT hInsContext, dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    PCOSA_DML_DHCPC_REQ_OPT         pDhcpReqOpt   = NULL;
    PCOSA_DML_DHCP_OPT              pDhcpSentOpt  = NULL;
    ULONG                           noOfReqOpt    = 0;
    ULONG                           noOfSentOpt   = 0;
    PCOSA_DML_DHCPC_FULL pDhcpc                   = (PCOSA_DML_DHCPC_FULL)hInsContext->hContext;

    DHCPMGR_LOG_INFO("%s %d: Entered \n",__FUNCTION__, __LINE__);
    noOfReqOpt = CosaDmlDhcpcGetNumberOfReqOption(hInsContext, pDhcpc->Cfg.InstanceNumber);

    for (ULONG reqIdx = 0; reqIdx < noOfReqOpt; reqIdx++)
    {
        pDhcpReqOpt = CosaDmlDhcpcGetReqOption_Entry(hInsContext, reqIdx);
        if (!pDhcpReqOpt)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpReqOpt is NULL",__FUNCTION__);
        }
        else if (pDhcpReqOpt->bEnabled)
        {
            add_dhcp_opt_to_list(req_opt_list, (int)pDhcpReqOpt->Tag, NULL);
        }
    }
    noOfSentOpt = CosaDmlDhcpcGetNumberOfSentOption(hInsContext, pDhcpc->Cfg.InstanceNumber);

    for (ULONG sentIdx = 0; sentIdx < noOfSentOpt; sentIdx++)
    {
        pDhcpSentOpt = CosaDmlDhcpcGetSentOption_Entry(hInsContext, sentIdx);

        if (!pDhcpSentOpt)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpSentOpt is NULL",__FUNCTION__);
        }
        else if (pDhcpSentOpt->bEnabled)
        {
            if(pDhcpSentOpt->Tag == DHCPV4_OPT_60 && strlen((char *)pDhcpSentOpt->Value) <= 0)
            {
                DHCPMGR_LOG_INFO("%s %d: DHCPv4 option 60 (Vendor Class Identifier) entry found without value. \n", __FUNCTION__, __LINE__);
                char optionValue[BUFLEN_256] = {0};
                int ret = Get_DhcpV4_CustomOption60(pDhcpc->Cfg.Interface, optionValue, sizeof(optionValue));
                if (ret == 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: Adding DHCPv4 option 60 (Vendor Class Identifier) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                    add_dhcp_opt_to_list(send_opt_list, (int)pDhcpSentOpt->Tag, optionValue);
                }
            }
            else if(pDhcpSentOpt->Tag == DHCPV4_OPT_61 && strlen((char *)pDhcpSentOpt->Value) <= 0)
            {
                DHCPMGR_LOG_INFO("%s %d: DHCPv4 option 61 (Client Identifier) entry found without value. \n", __FUNCTION__, __LINE__);
                char optionValue[BUFLEN_256] = {0};
                int ret = Get_DhcpV4_CustomOption61(pDhcpc->Cfg.Interface, optionValue, sizeof(optionValue));
                if (ret == 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: Adding DHCPv4 option 61 (Client Identifier) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                    add_dhcp_opt_to_list(send_opt_list, (int)pDhcpSentOpt->Tag, optionValue);
                }
            }
            else if(pDhcpSentOpt->Tag == DHCPV4_OPT_43 && strlen((char *)pDhcpSentOpt->Value) <= 0)
            {
                DHCPMGR_LOG_INFO("%s %d: DHCPv4 option 43 (Vendor-Specific Information) entry found without value. \n", __FUNCTION__, __LINE__);
                char optionValue[BUFLEN_512] = {0};
                int ret = Get_DhcpV4_CustomOption43(pDhcpc->Cfg.Interface, optionValue, sizeof(optionValue));
                if (ret == 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: Adding DHCPv4 option 43 (Vendor-Specific Information) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                    add_dhcp_opt_to_list(send_opt_list, (int)pDhcpSentOpt->Tag, optionValue);
                }
            }
            else
            {
                add_dhcp_opt_to_list(send_opt_list, (int)pDhcpSentOpt->Tag, (char *)pDhcpSentOpt->Value);
            }
        }
    }

    return 0;
}

/**
 * @brief Builds the DHCPv6 option lists.
 *
 * This function constructs the `req_opt_list` and `send_opt_list` from the DML entries.
 *
 * @param[in] hInsContext A handle to the DHCPv6 client context.
 * @param[out] req_opt_list A pointer to the list of requested DHCP options.
 * @param[out] send_opt_list A pointer to the list of DHCP options to be sent.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
static int DhcpMgr_build_dhcpv6_opt_list (PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT hInsContext, dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    PCOSA_DML_DHCPCV6_SENT          pSentOption  = NULL;
    ULONG                           noOfSentOpt   = 0;
    PSINGLE_LINK_ENTRY                pSListEntry   = NULL;
    ULONG                             instanceNum   = 0;
    PCOSA_DML_DHCPCV6_FULL pDhcp6c                   = (PCOSA_DML_DHCPCV6_FULL)hInsContext->hContext;

    DHCPMGR_LOG_INFO("%s %d: Entered \n",__FUNCTION__, __LINE__);
    //Build T1 T2 buffer
    char t1T2Buffer[BUFLEN_128] = {0};
    if (pDhcp6c->Cfg.SuggestedT1 != -1 || pDhcp6c->Cfg.SuggestedT2 != -1)
    {
        char t1Buffer[16] = {0};
        char t2Buffer[16] = {0};

        if (pDhcp6c->Cfg.SuggestedT1 != -1) {
            snprintf(t1Buffer, sizeof(t1Buffer), "t1 %ld", pDhcp6c->Cfg.SuggestedT1);
        }

        if (pDhcp6c->Cfg.SuggestedT2 != -1) {
            snprintf(t2Buffer, sizeof(t2Buffer), "t2 %ld", pDhcp6c->Cfg.SuggestedT2);
        }

        snprintf(t1T2Buffer, sizeof(t1T2Buffer), "{\n\t%s\n\t%s\n\t}", t1Buffer, t2Buffer);
        DHCPMGR_LOG_INFO("%s %d: T1 and T2 values found : %s\n", __FUNCTION__, __LINE__, t1T2Buffer);
    }

    if(pDhcp6c->Cfg.RequestAddresses == TRUE)
    {
        //Identity Association for Non-temporary Addresses.  OPTION_IA_NA(3) 
        DHCPMGR_LOG_INFO("%s %d: Adding DHCPv6 option - Number: %d, Value: %s\n", __FUNCTION__, __LINE__, DHCPV6_OPT_3, t1T2Buffer);
        add_dhcp_opt_to_list(send_opt_list, DHCPV6_OPT_3, t1T2Buffer);
    }

    if(pDhcp6c->Cfg.RequestPrefixes == TRUE)
    {
        DHCPMGR_LOG_INFO("%s %d: Adding DHCPv6 option - Number: %d, Value: %s\n", __FUNCTION__, __LINE__, DHCPV6_OPT_25, t1T2Buffer);
        // Identity Association (IA) for Prefix Delegation option OPTION_IA_PD(25) 
        add_dhcp_opt_to_list(send_opt_list, DHCPV6_OPT_25, t1T2Buffer);
    }

    if(pDhcp6c->Cfg.RapidCommit == TRUE)
    {
        add_dhcp_opt_to_list(send_opt_list, DHCPV6_OPT_14, NULL);
    }

    noOfSentOpt = CosaDmlDhcpv6cGetNumberOfSentOption(NULL, pDhcp6c->Cfg.InstanceNumber);
    for (ULONG sentOptIdx = 0; sentOptIdx < noOfSentOpt; sentOptIdx++)
    {
        pSListEntry = (PSINGLE_LINK_ENTRY)SentOption1_GetEntry(hInsContext, sentOptIdx, &instanceNum);
        if (pSListEntry)
        {
            PCOSA_CONTEXT_LINK_OBJECT pCxtLink            = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
            pSentOption         = (PCOSA_DML_DHCPCV6_SENT)pCxtLink->hContext;
            if (pSentOption->bEnabled)
            {
                if(pSentOption->Tag == DHCPV6_OPT_15 && strlen((char *)pSentOption->Value) <= 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: DHCPv6 option 15 (User Class Option) entry found without value. \n", __FUNCTION__, __LINE__);
                    char optionValue[BUFLEN_256] = {0};
                    int ret = Get_DhcpV6_CustomOption15(pDhcp6c->Cfg.Interface, optionValue, sizeof(optionValue));
                    if (ret == 0)
                    {
                        DHCPMGR_LOG_INFO("%s %d: Adding DHCPv6 option 15 (User Class Option) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                        add_dhcp_opt_to_list(send_opt_list, (int)pSentOption->Tag, optionValue);
                    }
                }
                else if(pSentOption->Tag == DHCPV6_OPT_16 && strlen((char *)pSentOption->Value) <= 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: DHCPv6 option 16 (Vendor Class Option) entry found without value. \n", __FUNCTION__, __LINE__);
                    char optionValue[BUFLEN_256] = {0};
                    int ret = Get_DhcpV6_CustomOption16(pDhcp6c->Cfg.Interface, optionValue, sizeof(optionValue));
                    if (ret == 0)
                    {
                        DHCPMGR_LOG_INFO("%s %d: Adding DHCPv6 option 16 (Vendor Class Option) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                        add_dhcp_opt_to_list(send_opt_list, (int)pSentOption->Tag, optionValue);
                    }
                }
                else if(pSentOption->Tag == DHCPV6_OPT_17 && strlen((char *)pSentOption->Value) <= 0)
                {
                    DHCPMGR_LOG_INFO("%s %d: DHCPv6 option 17 (Vendor-Specific Information) entry found without value. \n", __FUNCTION__, __LINE__);
                    char optionValue[BUFLEN_256] = {0};
                    int ret = Get_DhcpV6_CustomOption17(pDhcp6c->Cfg.Interface, optionValue, sizeof(optionValue));
                    if (ret == 0)
                    {
                        DHCPMGR_LOG_INFO("%s %d: Adding DHCPv6 option 17 (Vendor-Specific Information) custom value: %s \n", __FUNCTION__, __LINE__, optionValue);
                        add_dhcp_opt_to_list(send_opt_list, (int)pSentOption->Tag, optionValue);
                    }
                }
                else
                {
                    add_dhcp_opt_to_list(send_opt_list, (INT)pSentOption->Tag, (CHAR *)pSentOption->Value);
                }
            }
        }
    }

    char *reqOptions = strdup((CHAR *)pDhcp6c->Cfg.RequestedOptions);
    char *token = NULL;
    token = strtok(reqOptions, " , ");
    while (token != NULL)
    {
        int opt = atoi(token);
        if(opt == 95)
        {
            /* Check for MAPT RFC */
            char MaptEnable[BUFLEN_16] = {0};
            syscfg_get(NULL, "MAPT_Enable", MaptEnable, sizeof(MaptEnable));
            if(strcmp(MaptEnable, "true") == 0)
            {
                DHCPMGR_LOG_INFO("%s %d: MAPT RFC enabled and  DHCPv6 MAPT option is requested - (Number: %d, RFC Value: %s)\n", __FUNCTION__, __LINE__, opt, MaptEnable);
            }
            else
            {
                DHCPMGR_LOG_WARNING("%s %d: MAPT RFC Disabled and  DHCPv6 MAPT option is requested. Skipping MAPT option - (Number: %d, Value: %s)\n", __FUNCTION__, __LINE__, opt, MaptEnable);
                token = strtok(NULL, " , ");
                continue;
            }
        }
        
        DHCPMGR_LOG_INFO("Adding Request option : %d\n", opt);
        add_dhcp_opt_to_list(req_opt_list, opt, NULL);
        token = strtok(NULL, " , ");
    }
    if(reqOptions)
        free(reqOptions);

    return 0;
}

/**
 * @brief Checks the status of a network interface.
 *
 * This function verifies that the length of the interface name is greater than 0
 * and checks if the specified network interface is up and running.
 *
 * @param ifName The name of the network interface to check.
 * @return true if the interface name length is greater than 0 and the interface is up and running, false otherwise.
 */
static bool DhcpMgr_checkInterfaceStatus(const char * ifName)
{
    if(ifName == NULL || (strlen(ifName) <=0))
    {
        DHCPMGR_LOG_ERROR("%s : DHCP interface name is Empty",__FUNCTION__);
        return FALSE;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        perror("socket");
        return FALSE;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) 
    {
        perror("ioctl");
        close(sockfd);
        return FALSE;
    }

    close(sockfd);

    if ((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING)) 
    {
        DHCPMGR_LOG_INFO("Interface %s is up and running.\n", ifName);
    } 
    else 
    {
        DHCPMGR_LOG_ERROR("Interface %s is down or not running.\n", ifName);
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Checks for the presence of a link-local address and its DAD status on a network interface.
 *
 * This function checks if the specified network interface has a link-local address (LLA) by
 * executing the command `ip address show dev %s tentative`. It also verifies the link-local
 * Duplicate Address Detection (DAD) status. If no LLA is found, it restarts the IPv6 stack
 * on the interface.
 *
 * @param interfaceName The name of the network interface to check.
 * @return true if the link-local address is found and DAD status is verified, false otherwise.
 */
static bool DhcpMgr_checkLinkLocalAddress(const char * interfaceName)
{ 
    // check if interface is ipv6 ready with a link-local address
    unsigned int waitTime = INTF_V6LL_TIMEOUT_IN_MSEC;
    char cmd[BUFLEN_128] = {0};
    snprintf(cmd, sizeof(cmd), "ip address show dev %s tentative", interfaceName);
    while (waitTime > 0)
    {
        FILE *fp_dad   = NULL;
        char buffer[BUFLEN_256] = {0};

        fp_dad = popen(cmd, "r");
        if(fp_dad != NULL)
        {
            if ((fgets(buffer, BUFLEN_256, fp_dad) == NULL) || (strlen(buffer) == 0))
            {
                pclose(fp_dad);
                break;
            }
            DHCPMGR_LOG_WARNING("%s %d: interface still tentative: %s\n", __FUNCTION__, __LINE__, buffer);
            pclose(fp_dad);
        }
        usleep(INTF_V6LL_INTERVAL_IN_MSEC * USECS_IN_MSEC);
        waitTime -= INTF_V6LL_INTERVAL_IN_MSEC;
    }

    if (waitTime <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: interface %s doesnt have link local address\n", __FUNCTION__, __LINE__, interfaceName);
        /* No link-local address. Restart IPv6 stack and retry. Rare edge case. */
        DHCPMGR_LOG_INFO("%s %d force toggle initiated\n", __FUNCTION__, __LINE__);
        if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", interfaceName, "1") != 0)
        {
            DHCPMGR_LOG_WARNING("%s-%d : Failure writing to /proc file\n", __FUNCTION__, __LINE__);
        }

        if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", interfaceName, "0") != 0)
        {
            DHCPMGR_LOG_WARNING("%s-%d : Failure writing to /proc file\n", __FUNCTION__, __LINE__);
        }
        return FALSE;
    }

    return TRUE;
}

static void* DhcpMgr_MainController( void *args )
{
    (void) args;
    //detach thread from caller stack
    pthread_detach(pthread_self());

    DHCPMGR_LOG_INFO("%s %d DhcpMgr_MainController started \n", __FUNCTION__, __LINE__);
    BOOL bRunning = TRUE;
    struct timeval tv;
    int n = 0;
    const char *filename = "/tmp/dhcpmanager_restarted";
    int retStatus = 0;

    if(access(filename, F_OK) != -1)
    {
        retStatus = DhcpMgr_Dhcp_Recovery_Start();
        if(retStatus != 0)
        {
            DHCPMGR_LOG_ERROR("%s %d - Failed to start dhcp recovery thread\n", __FUNCTION__, __LINE__);
        }
        else
        {
            DHCPMGR_LOG_INFO("%s %d - Dhcp crash recovery thread started successfully\n", __FUNCTION__, __LINE__);
            if (remove(filename) != 0)
            {
                DHCPMGR_LOG_ERROR("%s %d Error deleting %s file\n", __FUNCTION__, __LINE__, filename);
            }
        }
    }

    retStatus = DhcpMgr_LeaseMonitor_Start();
    if(retStatus < 0)
    {
        DHCPMGR_LOG_INFO("%s %d - Lease Monitor Thread failed to start!\n", __FUNCTION__, __LINE__ );
    }

    while (bRunning)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        //TODO : add a Signaling mechanism instead of sleep.
        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        //DHCPv4 client entries
        //TODO : implement a internal DHCP structures and APIs, replace COSA APIs
        PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
        PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
        PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
        ULONG ulIndex;
        ULONG instanceNum;
        ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);

        for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
        {
            pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL,ulIndex,&instanceNum);
            if ( pSListEntry )
            {
                pDhcpCxtLink          = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
                pDhcpc            = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
            }

            if (!pDhcpc)
            {
                DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
                continue;
            }
            
            pthread_mutex_lock(&pDhcpc->mutex); //MUTEX lock
            if(pDhcpc->Cfg.bEnabled == TRUE )
            {
                if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Disabled)
                {
                    ////DHCP client Enabled, start the client if not started.
                    DHCPMGR_LOG_INFO("%s %d: Starting dhcpv4 client on %s\n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
                    if(DhcpMgr_checkInterfaceStatus(pDhcpc->Cfg.Interface)== FALSE)
                    {
                        pDhcpc->Cfg.bEnabled = FALSE;
                        DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_CLIENT_FAILED);
                    }
                    else
                    {
                        dhcp_opt_list *req_opt_list = NULL;
                        dhcp_opt_list *send_opt_list = NULL;
                        DhcpMgr_build_dhcpv4_opt_list (pDhcpCxtLink, &req_opt_list, &send_opt_list);

                        pDhcpc->Info.ClientProcessId  = start_dhcpv4_client(pDhcpc->Cfg.Interface, req_opt_list, send_opt_list);

                        //Free optios list
                        if(req_opt_list)
                            free_opt_list_data (req_opt_list);
                        if(send_opt_list)
                            free_opt_list_data (send_opt_list);

                        if(pDhcpc->Info.ClientProcessId > 0 ) 
                        {
                            pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                            DHCPMGR_LOG_INFO("%s %d: dhcpv4 client for %s started PID : %d \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                            DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_CLIENT_STARTED);
                        }
                        else
                        {
                            DHCPMGR_LOG_INFO("%s %d: dhcpv4 client for %s failed to start \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
                            DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_CLIENT_FAILED);
                        }
                    }
                } 
                else if (pDhcpc->Cfg.Renew == TRUE)
                {
                    DHCPMGR_LOG_INFO("%s %d: Triggering renew for  dhcpv4 client : %s PID : %d\n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                    send_dhcpv4_renew(pDhcpc->Info.ClientProcessId);
                    pDhcpc->Cfg.Renew = FALSE;
                }
                else if (pDhcpc->Cfg.Restart == TRUE)
                {
                    //Only stoping the client here, restart will be done in the next iteration
                    DHCPMGR_LOG_INFO("%s %d: Restarting dhcpv4 client : %s PID : %d\n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                    send_dhcpv4_release(pDhcpc->Info.ClientProcessId);
                    pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                    pDhcpc->Cfg.Restart = FALSE;
                    DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_LEASE_DEL);
                }
                
                //Process new lease
                DhcpMgr_ProcessV4Lease(pDhcpc);
            }
            else
            {
                //DHCP client disabled, stop the client if it is running.
                if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
                {
                    DHCPMGR_LOG_INFO("%s %d: Stopping the dhcpv4 client : %s PID : %d \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                    //Always send release and stop the client
                    send_dhcpv4_release(pDhcpc->Info.ClientProcessId); 
                    pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                    pDhcpc->Cfg.Renew = FALSE;
                    DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_LEASE_DEL); //Send lease expired event
                    DhcpMgr_clearDHCPv4Lease(pDhcpc);
                    remove_dhcp_lease_file(pDhcpc->Cfg.InstanceNumber,DHCP_v4);
                    DhcpMgr_PublishDhcpV4Event(pDhcpc, DHCP_CLIENT_STOPPED);
                }
            }

            pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX unlock

        }


        /********************************************* DHCPv6 Handling ********************************************* */
       		//DHCPv6 client entries
        //TODO : implement a internal DHCP structures and APIs, replace COSA APIs
        PCOSA_DML_DHCPCV6_FULL            pDhcp6c        = NULL;
        PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcp6cxtLink  = NULL;
        pSListEntry   = NULL;
        ulIndex = 0;
        instanceNum =0;
        clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);

        for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
        {
            pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL,ulIndex,&instanceNum);
            if ( pSListEntry )
            {
                pDhcp6cxtLink          = ACCESS_COSA_CONTEXT_DHCPCV6_LINK_OBJECT(pSListEntry);
                pDhcp6c            = (PCOSA_DML_DHCPC_FULL)pDhcp6cxtLink->hContext;
            }

            if (!pDhcp6c)
            {
                DHCPMGR_LOG_ERROR("%s : pDhcp6c is NULL\n",__FUNCTION__);
                continue;
            }
            
            pthread_mutex_lock(&pDhcp6c->mutex); //MUTEX lock
            if(pDhcp6c->Cfg.bEnabled == TRUE )
            {
                if(pDhcp6c->Info.Status == COSA_DML_DHCP_STATUS_Disabled)
                {
                    ////DHCP client Enabled, start the client if not started.
                    DHCPMGR_LOG_INFO("%s %d: Starting dhcpv6 client on %s\n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
                    if(DhcpMgr_checkInterfaceStatus(pDhcp6c->Cfg.Interface)== FALSE)
                    {
                        pDhcp6c->Cfg.bEnabled = FALSE;
                        DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_CLIENT_FAILED);
                    }
                    else if(DhcpMgr_checkLinkLocalAddress(pDhcp6c->Cfg.Interface)== FALSE)
                    {
                        //Link local failed. Retry
                    }
                    else
                    {
                        dhcp_opt_list *req_opt_list = NULL;
                        dhcp_opt_list *send_opt_list = NULL;
                        DhcpMgr_build_dhcpv6_opt_list (pDhcp6cxtLink, &req_opt_list, &send_opt_list);

                        pDhcp6c->Info.ClientProcessId  = start_dhcpv6_client(pDhcp6c->Cfg.Interface, req_opt_list, send_opt_list);

                        //Free optios list
                        if(req_opt_list)
                            free_opt_list_data (req_opt_list);
                        if(send_opt_list)
                            free_opt_list_data (send_opt_list);

                        if(pDhcp6c->Info.ClientProcessId > 0 ) 
                        {
                            pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                            DHCPMGR_LOG_INFO("%s %d: dhcpv6 client for %s started PID : %d \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface, pDhcp6c->Info.ClientProcessId);
                            DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_CLIENT_STARTED);
                        }
                        else
                        {
                            DHCPMGR_LOG_INFO("%s %d: dhcpv6 client for %s failed to start \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
                            DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_CLIENT_FAILED);
                        }
                    }

                } 
                else if (pDhcp6c->Cfg.Renew == TRUE)
                {
                    DHCPMGR_LOG_INFO("%s %d: Triggering renew for  dhcpv6 client : %s PID : %d\n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface, pDhcp6c->Info.ClientProcessId);
                    send_dhcpv6_renew(pDhcp6c->Info.ClientProcessId);
                    pDhcp6c->Cfg.Renew = FALSE;
                }
                else if( pDhcp6c->Cfg.Restart == TRUE)
                {
                    //Only stoping the client here, restart will be done in the next iteration
                    DHCPMGR_LOG_INFO("%s %d: Restarting dhcpv6 client : %s PID : %d\n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface, pDhcp6c->Info.ClientProcessId);
                    send_dhcpv6_release(pDhcp6c->Info.ClientProcessId);
                    pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                    pDhcp6c->Cfg.Restart = FALSE;
                    DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_LEASE_DEL);
                    DhcpMgr_clearDHCPv6Lease(pDhcp6c);
                }

                //Process new lease
                DhcpMgr_ProcessV6Lease(pDhcp6c);
            }
            else
            {
                //DHCP client disabled, stop the client if it is running.
                if(pDhcp6c->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
                {
                    DHCPMGR_LOG_INFO("%s %d: Stopping the dhcpv6 client : %s PID : %d \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface, pDhcp6c->Info.ClientProcessId);
                    //Always send release and stop the client. 
                    send_dhcpv6_release(pDhcp6c->Info.ClientProcessId);
                    pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                    pDhcp6c->Cfg.Renew = FALSE;
                    DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_LEASE_DEL); //Send lease expired event
                    DhcpMgr_clearDHCPv6Lease(pDhcp6c);
                    remove_dhcp_lease_file(pDhcp6c->Cfg.InstanceNumber,DHCP_v6);
                    DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_CLIENT_STOPPED);
                }
            }

            pthread_mutex_unlock(&pDhcp6c->mutex); //MUTEX unlock

        }
    }
    return NULL;

}

/**
 * @brief Adds a new DHCPv4 lease.
 *
 * This function locates the DHCPv4 client interface using the provided interface name (`ifName`) and updates the `pDhcpc->NewLeases` linked list with the new lease information.
 *  If the operation fails, it frees the memory allocated for the new lease.
 *
 * @param[in] ifName The name of the interface.
 * @param[in] newLease A pointer to the new DHCPv4 lease information.
 */
void DHCPMgr_AddDhcpv4Lease(char * ifName, DHCPv4_PLUGIN_MSG *newLease)
{
    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG ulIndex;
    ULONG instanceNum;
    BOOL interfaceFound                           = FALSE;
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
    //iterate all entries and find the ineterface with the ifname
    for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
    {
        pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL,ulIndex,&instanceNum);
        if ( pSListEntry )
        {
            pDhcpCxtLink          = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pDhcpc            = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
        }

        if (!pDhcpc)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
            continue;
        }

        pthread_mutex_lock(&pDhcpc->mutex); //MUTEX lock

        // Verify if the DHCP clients are running. There may be multiple DHCP client interfaces with the same name that are not active.
        if(strcmp(ifName, pDhcpc->Cfg.Interface) == 0 && pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
        {
            DHCPv4_PLUGIN_MSG *temp = pDhcpc->NewLeases;
            //Find the tail of the list
            if (temp == NULL) 
            {
                // If the list is empty, add the new lease as the first element
                pDhcpc->NewLeases = newLease;
            } else 
            {
                while (temp->next != NULL) 
                {
                    temp = temp->next;
                }
                // Add the new lease details to the tail of the list
                temp->next = newLease;
            }

            //Just the add the new lease details in the list. the controlled thread will hanlde it. 
            newLease->next = NULL;
            interfaceFound = TRUE;
            DHCPMGR_LOG_INFO("%s %d: New dhcpv4 lease msg added for %s \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
            pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX release before break
            break;
        }

        pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX unlock

    }

    if( interfaceFound == FALSE)
    {
        //if we are here, we didn't find the correct interface the received lease. free the memory
        free(newLease);
        DHCPMGR_LOG_ERROR("%s %d: dhcpv4 lease msg not added for ineterface %s. DHCP client may not be running. \n", __FUNCTION__, __LINE__, ifName);
    }

    return;
}

/**
 * @brief Adds a new DHCPv6 lease.
 *
 * This function locates the DHCPv6 client interface using the provided interface name (`ifName`) and updates the `pDhcp6c->NewLeases` linked list with the new lease information.
 *  If the operation fails, it frees the memory allocated for the new lease.
 *
 * @param[in] ifName The name of the interface.
 * @param[in] newLease A pointer to the new DHCPv6 lease information.
 */
void DHCPMgr_AddDhcpv6Lease(char * ifName, DHCPv6_PLUGIN_MSG *newLease)
{
    PCOSA_DML_DHCPCV6_FULL            pDhcp6c        = NULL;
    PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcp6cxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG ulIndex;
    ULONG instanceNum;
    BOOL interfaceFound                           = FALSE;
    ULONG clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);
    //iterate all entries and find the ineterface with the ifname
    for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
    {
        pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL,ulIndex,&instanceNum);
        if ( pSListEntry )
        {
            pDhcp6cxtLink          = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pDhcp6c            = (PCOSA_DML_DHCPCV6_FULL)pDhcp6cxtLink->hContext;
        }

        if (!pDhcp6c)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcp6c is NULL\n",__FUNCTION__);
            continue;
        }

        pthread_mutex_lock(&pDhcp6c->mutex); //MUTEX lock

        // Verify if the DHCP clients are running. There may be multiple DHCP client interfaces with the same name that are not active.
        if(strcmp(ifName, pDhcp6c->Cfg.Interface) == 0 && pDhcp6c->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
        {
            DHCPv6_PLUGIN_MSG *temp = pDhcp6c->NewLeases;
            //Find the tail of the list
            if (temp == NULL) 
            {
                // If the list is empty, add the new lease as the first element
                pDhcp6c->NewLeases = newLease;
            } else 
            {
                while (temp->next != NULL) 
                {
                    temp = temp->next;
                }
                // Add the new lease details to the tail of the list
                temp->next = newLease;
            }

            //Just the add the new lease details in the list. the controlled thread will hanlde it. 
            newLease->next = NULL;
            interfaceFound = TRUE;
            DHCPMGR_LOG_INFO("%s %d: New DHCPv6 lease msg added for %s \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
            pthread_mutex_unlock(&pDhcp6c->mutex); //MUTEX release before break
            break;
        }

        pthread_mutex_unlock(&pDhcp6c->mutex); //MUTEX unlock
    }

    if( interfaceFound == FALSE)
    {
        //if we are here, we didn't find the correct interface the received lease. free the memory
        free(newLease);
        DHCPMGR_LOG_ERROR("%s %d: dhcpv6 lease msg not added for ineterface %s. DHCP client may not be running. \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
    }

    return;
}

/**
 * @brief Updates the status of the DHCP client interface to 'stopped' based on the given process ID.
 *
 * This function iterates through the DHCPv4 and DHCPv6 client lists to find the interface
 * associated with the specified process ID (`pid`). Once found, it updates the status of
 * that interface to 'stopped'.
 *
 * This function is called from a SIGCHLD handler, so it is designed to be simple and quick.
 *
 * @param pid The process ID of the DHCP client to be marked as stopped.
 */
void processKilled(pid_t pid)
{
    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG ulIndex;
    ULONG instanceNum;
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
    //iterate all entries and find the ineterface with the ifname
    for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
    {
        pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL,ulIndex,&instanceNum);
        if ( pSListEntry )
        {
            pDhcpCxtLink          = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pDhcpc            = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
        }

        if (!pDhcpc)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
            continue;
        }

        //No mutex lock, since this funtions is called from teh sigchild handler. Keep this function simple and quick
        if(pDhcpc->Info.ClientProcessId == pid)
        {
            DHCPMGR_LOG_INFO("%s %d: DHCpv4 client for %s pid %d is terminated.\n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pid);
            if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
            {
                pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
            }
            return;
        }
    }

    //DHCPv6 client entries
    PCOSA_DML_DHCPCV6_FULL            pDhcp6c        = NULL;
    PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcp6cxtLink  = NULL;
    pSListEntry   = NULL;
    ulIndex = 0;
    instanceNum =0;
    clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);

    for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
    {
        pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL,ulIndex,&instanceNum);
        if ( pSListEntry )
        {
            pDhcp6cxtLink          = ACCESS_COSA_CONTEXT_DHCPCV6_LINK_OBJECT(pSListEntry);
            pDhcp6c            = (PCOSA_DML_DHCPCV6_FULL)pDhcp6cxtLink->hContext;
        }

        if (!pDhcp6c)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcp6c is NULL\n",__FUNCTION__);
            continue;
        }

        //No mutex lock, since this funtions is called from teh sigchild handler. Keep this function simple and quick
        if(pDhcp6c->Info.ClientProcessId == pid)
        {
            DHCPMGR_LOG_INFO("%s %d: DHCpv6 client for %s pid %d is terminated.\n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface, pid);
            if(pDhcp6c->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
            {
                pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
            }
            return;
        }

    }
    return;
}
