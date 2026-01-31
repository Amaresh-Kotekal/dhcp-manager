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

#include <stdio.h>
#include <stdlib.h>
#include "dhcpmgr_rbus_apis.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv6_apis.h"

#include "util.h"
#include "dhcpv4_interface.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv4_dml.h"
#include "dhcpv6_interface.h"
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
#include "dhcpmgr_map_apis.h"
#endif

#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
#define  MAC_ADDR_SIZE 18
static rbusHandle_t rbusHandle;
char *componentName = "DHCPMANAGER";

rbusError_t DhcpMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish);


/***********************************************************************

  Data Elements declaration:

 ***********************************************************************/
rbusDataElement_t DhcpMgrRbusDataElements[] = {
    {DHCP_MGR_DHCPv4_IFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {DHCP_MGR_DHCPv4_STATUS,  RBUS_ELEMENT_TYPE_PROPERTY, {getDataHandler, NULL, NULL, NULL, DhcpMgr_Rbus_SubscribeHandler, NULL}},
    {DHCP_MGR_DHCPv6_IFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {DHCP_MGR_DHCPv6_STATUS,  RBUS_ELEMENT_TYPE_PROPERTY, {NULL, NULL, NULL, NULL, DhcpMgr_Rbus_SubscribeHandler, NULL}},
};


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
ANSC_STATUS DhcpMgr_Rbus_Init()
{
    DHCPMGR_LOG_INFO("%s %d: rbus init called\n",__FUNCTION__, __LINE__);
    int rc = ANSC_STATUS_FAILURE;
    rc = rbus_open(&rbusHandle, componentName);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        DHCPMGR_LOG_ERROR("DhcpManager_Rbus_Init rbus initialization failed\n");
        return rc;
    }

    
    // Register data elements
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(DhcpMgrRbusDataElements), DhcpMgrRbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        DHCPMGR_LOG_WARNING("rbus register data elements failed\n");
        rbus_close(rbusHandle);
        return rc;
    }

    char AliasName[64] = {0};
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);

    for (ULONG i = 0; i < clientCount; i++)
    {
        rc = rbusTable_registerRow(rbusHandle, DHCP_MGR_DHCPv4_TABLE, (i+1), NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            DHCPMGR_LOG_ERROR("%s %d - Iterface(%lu) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv4_TABLE, rc);
            return rc;
        }
        else
        {
            DHCPMGR_LOG_INFO("%s %d - Iterface(%lu) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv4_TABLE, AliasName);
        }

        memset(AliasName,0,64);
    }

    //Register DHCPv6 table
    clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);
    for (ULONG i = 0; i < clientCount; i++)
    {
        rc = rbusTable_registerRow(rbusHandle, DHCP_MGR_DHCPv6_TABLE, (i+1), NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            DHCPMGR_LOG_ERROR("%s %d - Iterface(%lu) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv6_TABLE, rc);
            return rc;
        }
        else
        {
            DHCPMGR_LOG_INFO("%s %d - Iterface(%lu) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv6_TABLE, AliasName);
        }

        memset(AliasName,0,64);
    }
     

    return ANSC_STATUS_SUCCESS;
}

/**
 * @brief Rbus subscribe handler.
 *
 * This function is called when other components subscribe to the events registered with this callback.
 * It handles the subscription actions for the specified rbus events.
 *
 * @param handle The rbus handle.
 * @param action The subscription action to be performed.
 * @param eventName The name of the event being subscribed to.
 * @param filter The filter applied to the event.
 * @param interval The interval for event notifications.
 * @param autoPublish A flag indicating whether the event should be auto-published.
 *
 * @return rbusError_t
 * @retval RBUS_ERROR_SUCCESS if the subscription is handled successfully.
 * @retval RBUS_ERROR_BUS_ERROR if there is an error handling the subscription.
 */

rbusError_t DhcpMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
    (void)handle;
    (void)filter;
    (void)(interval);
    (void)(autoPublish);

    char *subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribed" : "unsubscribed";
    DHCPMGR_LOG_INFO("%s %d - Event %s has been  %s \n", __FUNCTION__, __LINE__,eventName, subscribe_action );

    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief Copies DHCPv4_PLUGIN_MSG to DHCP_MGR_IPV4_MSG struct for the rbus event publish.
 *
 * This function copies the contents of a DHCPv4_PLUGIN_MSG structure to a DHCP_MGR_IPV4_MSG structure.
 * It is used for preparing the data to be published as an rbus event.
 *
 * @param src Pointer to the source DHCPv4_PLUGIN_MSG structure.
 * @param dest Pointer to the destination DHCP_MGR_IPV4_MSG structure.
 */
static void DhcpMgr_createLeaseInfoMsg(DHCPv4_PLUGIN_MSG *src, DHCP_MGR_IPV4_MSG *dest) 
{
    strncpy(dest->ifname, src->ifname, sizeof(dest->ifname) - 1);
    strncpy(dest->address, src->address, sizeof(dest->address) - 1);
    strncpy(dest->netmask, src->netmask, sizeof(dest->netmask) - 1);
    strncpy(dest->gateway, src->gateway, sizeof(dest->gateway) - 1);
    strncpy(dest->dnsServer, src->dnsServer, sizeof(dest->dnsServer) - 1);
    strncpy(dest->dnsServer1, src->dnsServer1, sizeof(dest->dnsServer1) - 1);
    strncpy(dest->timeZone, src->timeZone, sizeof(dest->timeZone) - 1);
    strncpy(dest->cOption122, src->mtaOption.option_122, sizeof(dest->cOption122) - 1);
    strncpy(dest->cOption67, src->mtaOption.cOption67, sizeof(dest->cOption67) - 1);
    strncpy(dest->cTftpServer, src->cTftpServer, sizeof(dest->cTftpServer) - 1);
    strncpy(dest->cHostName, src->cHostName, sizeof(dest->cHostName) - 1);
    strncpy(dest->cDomainName, src->cDomainName, sizeof(dest->cDomainName) - 1);
    dest->mtuSize = src->mtuSize;
    dest->timeOffset = src->timeOffset;
    dest->isTimeOffsetAssigned = src->isTimeOffsetAssigned;
    dest->upstreamCurrRate = src->upstreamCurrRate;
    dest->downstreamCurrRate = src->downstreamCurrRate;
}

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
/**
 * @brief Updates the MapInfo field of a DHCPv6 client structure from the mapt field of a DHCP_MGR_IPV6_MSG.
 *
 * @param pDhcpv6c Pointer to the DHCPv6 client structure to update.
 * @param src Pointer to the DHCP_MGR_IPV6_MSG structure containing the mapt data.
 */
static void DhcpMgr_UpdateDhcpv6MapInfo(PCOSA_DML_DHCPCV6_FULL pDhcpv6c, DHCP_MGR_IPV6_MSG *src)
{
    DHCPMGR_LOG_INFO("%s: Entry\n", __FUNCTION__);

    if (!pDhcpv6c || !src)
        return;

    PDML_DHCPCV6_MAP_INFO mapInfo = &pDhcpv6c->Info.MapInfo;
    ipc_mapt_data_t *mapt = &src->mapt;

    mapInfo->MaptAssigned = src->maptAssigned ? TRUE : FALSE;
    mapInfo->IsFMR = mapt->isFMR ? TRUE : FALSE;
    mapInfo->MapEALen = mapt->eaLen;
    mapInfo->MapPSIDOffset = mapt->psidOffset;
    mapInfo->MapPSIDLen = mapt->psidLen;
    mapInfo->MapPSIDValue = mapt->psid;
    mapInfo->MapRatio = mapt->ratio;

    snprintf((char*)mapInfo->MapBRPrefix, sizeof(mapInfo->MapBRPrefix), "%s", mapt->brIPv6Prefix);
    snprintf((char*)mapInfo->MapRuleIPv4Prefix, sizeof(mapInfo->MapRuleIPv4Prefix), "%s", mapt->ruleIPv4Prefix);
    snprintf((char*)mapInfo->MapRuleIPv6Prefix, sizeof(mapInfo->MapRuleIPv6Prefix), "%s", mapt->ruleIPv6Prefix);
    
}
#endif // FEATURE_MAPT || FEATURE_SUPPORT_MAPT_NAT46

/**
 * @brief Copies DHCPv6_PLUGIN_MSG to DHCP_MGR_IPV6_MSG struct for the rbus event publish.
 *
 * This function copies the contents of a DHCPv6_PLUGIN_MSG structure to a DHCP_MGR_IPV6_MSG structure.
 * It is used for preparing the data to be published as an rbus event.
 *
 * @param src Pointer to the source DHCPv6_PLUGIN_MSG structure.
 * @param dest Pointer to the destination DHCP_MGR_IPV6_MSG structure.
 */
static void DhcpMgr_createDhcpv6LeaseInfoMsg(DHCPv6_PLUGIN_MSG *src, DHCP_MGR_IPV6_MSG *dest)
{
    strncpy(dest->ifname, src->ifname, sizeof(dest->ifname) - 1);
    strncpy(dest->address, src->ia_na.address, sizeof(dest->address) - 1);
    strncpy(dest->nameserver, src->dns.nameserver, sizeof(dest->nameserver) - 1);
    strncpy(dest->nameserver1, src->dns.nameserver1, sizeof(dest->nameserver1) - 1);
    strncpy(dest->domainName, src->domainName, sizeof(dest->domainName) - 1);
    snprintf(dest->sitePrefix, sizeof(dest->sitePrefix), "%s/%d", src->ia_pd.Prefix, src->ia_pd.PrefixLength);

    dest->prefixPltime = src->ia_pd.PreferedLifeTime;
    dest->prefixVltime = src->ia_pd.ValidLifeTime;

    dest->addrAssigned = src->ia_na.assigned;
    dest->prefixAssigned = src->ia_pd.assigned;
    dest->domainNameAssigned = (strlen(src->domainName) > 0);

    if(src->ipv6_TimeOffset)
    {
        dest->ipv6_TimeOffset = src->ipv6_TimeOffset;
    }
    else
    {
        dest->ipv6_TimeOffset = 0; // Default value if not assigned
    }
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    if(src->mapt.Assigned == TRUE)
    {
        unsigned char  maptContainer[BUFLEN_256]; /* MAP-T option 95 in hex format*/
        memset(maptContainer, 0, sizeof(maptContainer));
        memcpy(maptContainer, src->mapt.Container, sizeof(src->mapt.Container));
        DhcpMgr_MaptParseOpt95Response(dest->sitePrefix, maptContainer, &dest->mapt);
        dest->maptAssigned = TRUE;
    }
#endif // FEATURE_MAPT || FEATURE_SUPPORT_MAPT_NAT46
}

rbusError_t getDataHandler(rbusHandle_t rbusHandle, rbusProperty_t rbusProperty,rbusGetHandlerOptions_t *pRbusGetHandlerOptions)
{
    (void)rbusHandle;
    (void)pRbusGetHandlerOptions;
    (void)rbusProperty;
    return RBUS_ERROR_SUCCESS;
}
#if 0
rbusError_t getDataHandler(rbusHandle_t rbusHandle,rbusProperty_t rbusProperty,rbusGetHandlerOptions_t *pRbusGetHandlerOptions)
{
    (void)rbusHandle;
    (void)pRbusGetHandlerOptions;

    char const *pName = rbusProperty_GetName(rbusProperty);
    int iDmIndex = -1;
    if (0 != strncmp(pName, DHCP_MGR_DHCPv4_TABLE, strlen(DHCP_MGR_DHCPv4_TABLE)))
    {
        DHCPMGR_LOG_ERROR("%s %d - Unsupported property name %s\n", __FUNCTION__, __LINE__, pName);
        return RBUS_ERROR_SUCCESS;
    }
    sscanf(pName, DHCPv4_EVENT_FORMAT, &iDmIndex);
    DHCPMGR_LOG_INFO("%s %d - Getting data for property %s with index %d\n", __FUNCTION__, __LINE__, pName, iDmIndex);

    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    unsigned long ulInstanceNum;

    int iIndex = iDmIndex - 1;
    pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL, iIndex, &ulInstanceNum);
    if (pSListEntry)
    {
        pDhcpCxtLink = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
        pDhcpc       = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
    }
    if (NULL == pDhcpc)
    {
        DHCPMGR_LOG_ERROR("%s %d - Failed to get DHCPv4 client context for index %d\n", __FUNCTION__, __LINE__, iIndex);
        return RBUS_ERROR_SUCCESS;
    }
    if (ulInstanceNum != (unsigned long) iDmIndex)
    {
        DHCPMGR_LOG_ERROR("%s %d - Instance number mismatch: expected %d, got %lu\n", __FUNCTION__, __LINE__, iDmIndex, ulInstanceNum);
        return RBUS_ERROR_SUCCESS;
    }
    if ('\0' == pDhcpc->Cfg.Interface[0] || 0 == strlen(pDhcpc->Cfg.Interface))
    {
        DHCPMGR_LOG_ERROR("%s %d - Interface name is NULL for index %d\n", __FUNCTION__, __LINE__, iIndex);
        return RBUS_ERROR_SUCCESS;
    }
    DHCPMGR_LOG_INFO("%s %d Ifname: %s, index: %d, InstanceNumber: %lu\n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, iIndex, ulInstanceNum);

    // Create rbus object with IfName, MsgType, and LeaseInfo
    rbusObject_t rdata;
    rbusValue_t ifNameVal, typeVal, leaseInfoVal;

    rbusObject_Init(&rdata, NULL);

    // Set Interface Name
    rbusValue_Init(&ifNameVal);
    rbusValue_SetString(ifNameVal, (char*)pDhcpc->Cfg.Interface);
    rbusObject_SetValue(rdata, "IfName", ifNameVal);

    // Set Message Type (using DHCP_LEASE_UPDATE as default for get handler)
    rbusValue_Init(&typeVal);
    rbusValue_SetUInt32(typeVal, DHCP_LEASE_UPDATE);
    rbusObject_SetValue(rdata, "MsgType", typeVal);

    // Set Lease Info
    if (pDhcpc->currentLease)
    {
        DHCP_MGR_IPV4_MSG leaseInfo;
        memset(&leaseInfo, 0, sizeof(leaseInfo));
        DhcpMgr_createLeaseInfoMsg(pDhcpc->currentLease, &leaseInfo);
        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, &leaseInfo, sizeof(leaseInfo));
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
        rbusValue_Release(leaseInfoVal);
    }

    // Set the object as the property value
    rbusValue_t rbusValue;
    rbusValue_Init(&rbusValue);
    rbusValue_SetObject(rbusValue, rdata);
    rbusProperty_SetValue(rbusProperty, rbusValue);

    // Cleanup
    rbusValue_Release(rbusValue);
    rbusValue_Release(ifNameVal);
    rbusValue_Release(typeVal);
    rbusObject_Release(rdata);
    DHCPMGR_LOG_INFO("%s %d - Exiting getDataHandler for property %s\n", __FUNCTION__, __LINE__, pName);

    return RBUS_ERROR_SUCCESS;
}
#endif
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
int DhcpMgr_PublishDhcpV4Event(PCOSA_DML_DHCPC_FULL pDhcpc, DHCP_MESSAGE_TYPE msgType)
{
    if(pDhcpc == NULL)
    {
        DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
        return -1;
    }

    int rc = -1;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t ifNameVal , typeVal, leaseInfoVal;

    DHCPMGR_LOG_INFO("%s %d - Publishing DHCPv4 Event for Interface %s with MsgType %d\n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, msgType);
    /*Set Interface Name */
    rbusObject_Init(&rdata, NULL);
    rbusValue_Init(&ifNameVal);
    rbusValue_SetString(ifNameVal, (char*)pDhcpc->Cfg.Interface);
    rbusObject_SetValue(rdata, "IfName", ifNameVal);

    /*Set Msg type Name */
    rbusValue_Init(&typeVal);
    rbusValue_SetUInt32(typeVal, msgType);
    rbusObject_SetValue(rdata, "MsgType", typeVal);

    /*Set the lease deatails */
    if(msgType == DHCP_LEASE_UPDATE)
    { 
        DHCP_MGR_IPV4_MSG leaseInfo;
        memset(&leaseInfo, 0, sizeof(leaseInfo));
        DhcpMgr_createLeaseInfoMsg(pDhcpc->currentLease,&leaseInfo);
        DHCPMGR_LOG_INFO("%s %d - Mta Option 122: %s\n", __FUNCTION__, __LINE__, pDhcpc->currentLease->mtaOption.option_122);
        DHCPMGR_LOG_INFO("%s %d - Mta Option 67: %s\n", __FUNCTION__, __LINE__, pDhcpc->currentLease->mtaOption.cOption67);
        DHCPMGR_LOG_INFO("%s %d - cTftpServer: %s\n", __FUNCTION__, __LINE__, pDhcpc->currentLease->cTftpServer);
        DHCPMGR_LOG_INFO("%s %d - HostName: %s\n", __FUNCTION__, __LINE__, pDhcpc->currentLease->cHostName);
        DHCPMGR_LOG_INFO("%s %d - DomainName: %s\n", __FUNCTION__, __LINE__, pDhcpc->currentLease->cDomainName);
        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, &leaseInfo, sizeof(leaseInfo));
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
    }

    

    int index = pDhcpc->Cfg.InstanceNumber;
    char eventStr[64] = {0};
    snprintf(eventStr,sizeof(eventStr), DHCPv4_EVENT_FORMAT, index);


    event.name = eventStr;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rbusError_t rt = rbusEvent_Publish(rbusHandle, &event); 
    
    if( rt != RBUS_ERROR_SUCCESS && rt != RBUS_ERROR_NOSUBSCRIBERS)
    {
        DHCPMGR_LOG_WARNING("%s %d - Event %s Publish Failed \n", __FUNCTION__, __LINE__,eventStr );
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d - Event %s Published \n", __FUNCTION__, __LINE__,eventStr );
        rc = 0;
    }


    rbusValue_Release(ifNameVal);
    rbusValue_Release(typeVal);
    rbusObject_Release(rdata);

    return rc;

}


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
int DhcpMgr_PublishDhcpV6Event(PCOSA_DML_DHCPCV6_FULL pDhcpv6c, DHCP_MESSAGE_TYPE msgType)
{
    if(pDhcpv6c == NULL)
    {
        DHCPMGR_LOG_ERROR("%s : pDhcpv6c is NULL\n",__FUNCTION__);
        return -1;
    }

    int rc = -1;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t ifNameVal , typeVal, leaseInfoVal;

    /*Set Interface Name */
    rbusObject_Init(&rdata, NULL);
    rbusValue_Init(&ifNameVal);
    rbusValue_SetString(ifNameVal, (char*)pDhcpv6c->Cfg.Interface);
    rbusObject_SetValue(rdata, "IfName", ifNameVal);

    /*Set Msg type Name */
    rbusValue_Init(&typeVal);
    rbusValue_SetUInt32(typeVal, msgType);
    rbusObject_SetValue(rdata, "MsgType", typeVal);

    /*Set the lease details */
    if(msgType == DHCP_LEASE_UPDATE)
    { 
        DHCP_MGR_IPV6_MSG leaseInfo;
        memset(&leaseInfo, 0, sizeof(leaseInfo));
        DhcpMgr_createDhcpv6LeaseInfoMsg(pDhcpv6c->currentLease,&leaseInfo);
        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, &leaseInfo, sizeof(leaseInfo));
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
        //Update MAPT dml values 
        if(leaseInfo.maptAssigned)
        {
            DhcpMgr_UpdateDhcpv6MapInfo(pDhcpv6c, &leaseInfo);
        }
#endif // FEATURE_MAPT || FEATURE_SUPPORT_MAPT_NAT46
    }

    int index = pDhcpv6c->Cfg.InstanceNumber;
    char eventStr[64] = {0};
    snprintf(eventStr,sizeof(eventStr), DHCPv6_EVENT_FORMAT, index);

    event.name = eventStr;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rbusError_t rt = rbusEvent_Publish(rbusHandle, &event); 
    
    if( rt != RBUS_ERROR_SUCCESS && rt != RBUS_ERROR_NOSUBSCRIBERS)
    {
        DHCPMGR_LOG_WARNING("%s %d - Event %s Publish Failed \n", __FUNCTION__, __LINE__,eventStr );
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d - Event %s Published \n", __FUNCTION__, __LINE__,eventStr );
        rc = 0;
    }

    rbusValue_Release(ifNameVal);
    rbusValue_Release(typeVal);
    rbusObject_Release(rdata);

    return rc;
}
