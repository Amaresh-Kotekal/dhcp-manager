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
#include <ctype.h>
#include "dhcpmgr_rbus_apis.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv6_apis.h"

#include "util.h"
#include "dhcpv4_interface.h"
#include <telemetry_busmessage_sender.h>
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv4_dml.h"
#include "dhcpv6_interface.h"
#include "cosa_dhcpv6_internal.h"
#include "cosa_dhcpv6_dml.h"
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46) || defined(FEATURE_MAPE)
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
    {DHCP_MGR_DHCPv6_STATUS,  RBUS_ELEMENT_TYPE_PROPERTY, {getDataHandler, NULL, NULL, NULL, DhcpMgr_Rbus_SubscribeHandler, NULL}},
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
     *autoPublish = false;

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
    ipc_map_data_t *mapt = &src->map;

    mapInfo->MaptAssigned = src->maptAssigned ? TRUE : FALSE;
    mapInfo->IsFMR = mapt->isFMR ? TRUE : FALSE;
    mapInfo->MapEALen = mapt->eaLen;
    mapInfo->MapPSIDOffset = mapt->psidOffset;
    mapInfo->MapPSIDLen = mapt->psidLen;
    mapInfo->MapPSIDValue = mapt->psid;
    mapInfo->MapRatio = mapt->ratio;

    snprintf((char*)mapInfo->MapBRPrefix, sizeof(mapInfo->MapBRPrefix), "%s", mapt->brIPv6Prefix);
    snprintf((char*)mapInfo->MapRuleIPv4Prefix, sizeof(mapInfo->MapRuleIPv4Prefix), "%s/%u",
                mapt->ruleIPv4Prefix, mapt->v4Len);
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
    strncpy(dest->aftr, src->aftr, sizeof(dest->aftr) - 1);
    dest->aftr[sizeof(dest->aftr) - 1] = '\0';

    dest->prefixPltime = src->ia_pd.PreferedLifeTime;
    dest->prefixVltime = src->ia_pd.ValidLifeTime;

    dest->addrAssigned = src->ia_na.assigned;
    dest->prefixAssigned = src->ia_pd.assigned;
    dest->domainNameAssigned = (strlen(src->domainName) > 0);

    // Default to UNKNOWN
    dest->map.mapType = MAP_TYPE_UNKNOWN;
    dest->maptAssigned = FALSE;
    dest->mapeAssigned = FALSE;

    if(src->ipv6_TimeOffset)
    {
        dest->ipv6_TimeOffset = src->ipv6_TimeOffset;
    }
    else
    {
        dest->ipv6_TimeOffset = 0; // Default value if not assigned
    }
    if(src->mapt.Assigned == TRUE)
    {
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
        unsigned char  maptContainer[BUFLEN_256] = {0}; /* MAP-T option 95 in hex format*/
        memset(maptContainer, 0, sizeof(maptContainer));
        memcpy(maptContainer, src->mapt.Container, sizeof(src->mapt.Container));
        if (DhcpMgr_MapParseOptResponse(dest->sitePrefix, maptContainer, &dest->map) == ANSC_STATUS_SUCCESS)
        {
            dest->maptAssigned = TRUE;
            dest->map.mapType = MAP_TYPE_MAPT;
            t2_event_d("DHCPMGR_INFO_MAPTConfigured", 1);
        } else {
            DHCPMGR_LOG_ERROR("%s: MAP-T option95 parsing failed. Set maptAssigned to FALSE.\n", __FUNCTION__);
            dest->maptAssigned = FALSE;
            t2_event_d("DHCPMGR_ERROR_MAPTParseFail", 1);
        }
#endif // FEATURE_MAPT || FEATURE_SUPPORT_MAPT_NAT46
    }
    else if (src->mape.Assigned == TRUE)
    {
#ifdef FEATURE_MAPE
        unsigned char  mapeContainer[BUFLEN_256]; /* MAP-E option 94 in hex format*/
        memset(mapeContainer, 0, sizeof(mapeContainer));
        memcpy(mapeContainer, src->mape.Container, sizeof(src->mape.Container));
        if (DhcpMgr_MapParseOptResponse(dest->sitePrefix, mapeContainer, &dest->map) == ANSC_STATUS_SUCCESS)
        {
            dest->mapeAssigned = TRUE;
            dest->map.mapType = MAP_TYPE_MAPE;
            t2_event_d("DHCPMGR_INFO_MAPEConfigured", 1);
        } else {
            DHCPMGR_LOG_ERROR("%s: MAP-E option94 parsing failed. Set mapeAssigned to FALSE.\n", __FUNCTION__);
            dest->mapeAssigned = FALSE;
            t2_event_d("DHCPMGR_ERROR_MAPEParseFail", 1);
        } 
#endif
    }
}


/* Convert "ab:cd:ef" to bytes. Returns the byte count, or -1 if s is not colon-separated hex or does not fit. */
static int DhcpMgr_HexColonToBytes(const char *pString, unsigned char *pOut, size_t outSize)
{
    size_t iSize = 0;

    while (*pString != '\0')
    {
        if (iSize >= outSize || !isxdigit((unsigned char)pString[0]) || !isxdigit((unsigned char)pString[1]))
        {
            return -1;
        }
        char cHex[3] = { pString[0], pString[1], '\0' };
        pOut[iSize++] = (unsigned char)strtoul(cHex, NULL, 16);
        pString += 2;
        if (*pString == ':')
        {
            pString++;
        }
        else if (*pString != '\0')
        {
            return -1;
        }
    }
    return (int)iSize;
}

/* For FQDN, the rest is length-prefixed labels ending in a zero byte:
 * 00 | 12 "dpe1-grp2-pub-mtnk" | 04 "rpub" | 03 "net" | 06 "rogers" | 03 "com" | 00
 * ^type   ^ each label = 1 length byte + that many characters         ^ end
 * Decode length-prefixed DNS labels into a dotted name without the trailing dot. Returns 0 on success. */
static int DhcpMgr_DecodeDnsName(const unsigned char *pBuf, size_t iLen, char *pOut, size_t outSize)
{
    size_t iPos = 0, iWritten = 0;

    while (iPos < iLen && pBuf[iPos] != 0)
    {
        size_t iLabelLen = pBuf[iPos++];
        //iLabelLen > 63: a DNS label may be at most 63 bytes.
        if (iLabelLen > 63 || iPos + iLabelLen > iLen || iWritten + iLabelLen + 2 > outSize)
        {
            pOut[0] = '\0';
            return -1;
        }
        if (iWritten > 0)
        {
            pOut[iWritten++] = '.';
        }
        memcpy(&pOut[iWritten], &pBuf[iPos], iLabelLen);
        iWritten += iLabelLen;
        iPos += iLabelLen;
    }
    pOut[iWritten] = '\0';
    return (iWritten > 0) ? 0 : -1;
}

/* Write the first address of a list of 16-byte IPv6 addresses as text. */
static void DhcpMgr_FirstIpv6ToText(const unsigned char *pBuf, size_t iLen, char *pOut, size_t outSize)
{
    if (iLen >= 16 && NULL == inet_ntop(AF_INET6, pBuf, pOut, outSize))
    {
        pOut[0] = '\0';
    }
}

/* 4,Sub-option 2171 (server reply): nested 2-byte code, 2-byte length
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   nested-code (1,2,3,6)       |        nested-len             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  nested value ...                                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * |NestedCode	Meaning	                            Length	   Value in the capture (Example)
 * |1	        Primary DHCPv6 server selector ID	4	       ff ff ff ff (binary)
 * |2	        Secondary server selector ID        4	       ff ff ff ff (binary)
 * |3	        Provisioning server	                41	       1 type byte, then the address (see below)
 * |6	        Kerberos realm	                    9	       label-encoded BASIC.1.
 *
 * Nested 3 value: the first byte is the type: 0x00 FQDN, 0x01 IPv4, 0x02 IPv6.
 * Only the FQDN type was seen in the capture. The IPv4 and IPv6 types come from the voice HAL header comment.
 */

/* Option 17 sub-option 2171 holds nested 2-byte code/length TLVs; nested 3 is the provisioning server (type byte 0=FQDN, 1=IPv4, 2=IPv6). */
static void DhcpMgr_ParseProvServer(const unsigned char *pBuf, size_t iLen, char *pOut, size_t outSize)
{
    size_t iPos = 0;

    while (iPos + 4 <= iLen)
    {
        unsigned int uiCode = ((unsigned int)pBuf[iPos] << 8) | pBuf[iPos + 1];
        size_t iSubLen = ((size_t)pBuf[iPos + 2] << 8) | pBuf[iPos + 3];
        iPos += 4;
        if (iPos + iSubLen > iLen)
        {
            return;
        }
        /* Only process nested code 3 (Provisioning server) */
        if (uiCode == 3 && iSubLen > 1)
        {
            const unsigned char *pVal = &pBuf[iPos + 1];
            switch (pBuf[iPos])
            {
                case 0: // FQDN
                    DhcpMgr_DecodeDnsName(pVal, iSubLen - 1, pOut, outSize);
                    break;
                case 1: // IPv4
                    if (iSubLen == 5 && NULL == inet_ntop(AF_INET, pVal, pOut, outSize)) pOut[0] = '\0';
                    break;
                case 2: // IPv6
                    if (iSubLen == 17 && NULL == inet_ntop(AF_INET6, pVal, pOut, outSize)) pOut[0] = '\0';
                    break;
                default:
                    break;
            }
            return;
        }
        iPos += iSubLen;
    }
}


 /**
 * https://www.rfc-editor.org/info/rfc8415/ section 21.17
 * 1, Option 17 (Vendor-specific Information)
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|       option-code = 17        |          option-len           |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                       enterprise-number                       |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|                 sub-options (repeated, see 2)                 |
 *.                                                               .
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * |Field	          Size	    Type	    Value in the capture
 * |option-code	      2 bytes	unsigned	0x0011 (17)
 * |option-len	      2 bytes	unsigned	SOLICIT 0x00E5 (229), REPLY 0x00C1 (193). It counts everything after this field, including the 4-byte enterprise number.
 * |enterprise-number  4 bytes	unsigned	0x0000118B (4491, CableLabs)
 * |sub-options	      variable	TLV list	see below
 *
 * 2, Each sub-option (2-byte code, 2-byte length)
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        sub-option-code        |        sub-option-len         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   value (sub-option-len bytes)                |
 * .                                                               .
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * sub-option-len counts the value only, not the 4-byte header.
 *
 * Sent by the MTA (SOLICIT)
 * |Code	 Name	                   Length	  Type	                Example|
 * |1	     Option request	            12	      list of 2-byte codes	0020 0021 0022 0025 0026 087B|
 * |2	     Device type	            4	      ASCII	                EDVA|
 * |4	     Serial number	            variable  ASCII	                3363043022102272|
 * |5/6/7	 Hardware/software/         variable  ASCII	                2.2, Prod_23.2_231009, S1TC-3.63.20.104
 * |         boot ROM version
 * |8	     OUI	                    6	      ASCII hex text        48bdce|
 * |9/10	 Model / vendor	            variable  ASCII	                CGM4331COM, Technicolor|
 * |35	     PacketCable capabilities 	73	      TLV block (see 3)
 * |36	     MTA MAC	                6	      binary	            48:bd:ce:5f:48:01|
 * |2172	 Correlation ID	            4	      binary	            58 c0 06 33|
 *
 * Returned by the server (REPLY)
 * |Code	Name	                        Length	        Type
 * |32	    TFTP server addresses	        16 per address	IPv6 addresses, back to back
 * |33	    Config file name	            67	            ASCII
 * |34	    Syslog servers	                16 per address	IPv6 addresses, back to back
 * |2171	CableLabs client configuration	74	            nested sub-elements (see 4)
 *
 * 3,Sub-option 35 body (capabilities): 1-byte type, 1-byte length
 *
 *  0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     type      |    length     |    value ...  |  type | len | ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * For example 01 01 02 means PacketCable version 2, and 0B 0B 06 09 0E ... is the supported-codecs list.
 * Here the type and length are one byte each, unlike the outer sub-options.
 *
 *
 * 5, Option 39 (Client FQDN, RFC 4704)
 * | 0                   1                   2                   3
 * |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       option-code = 39        |          option-len           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | flags (MBZ|N|O|S) | domain name (length-prefixed labels) ...   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * The flags byte is 0x01 in your capture (S bit set). The client sends it with an empty name.
 * The server REPLY returned a 45-byte option: the flags byte plus EMTA48bdce5f4801.gpon-emta6.net.rogers.com. in label form.
 *
 * 6, How DHCP Manager receives it
 * Dibbler hands the plugin the sub-options as text, one code=value per sub-option, with the value as colon-separated hex bytes
 * vendor=4491 33=64:38:2d:... 32=20:01:04:e8:... 34=20:01:... 37=...
 * The first byte pair of each value is the first byte after the 2-byte length field.
 * The parser we have added here reads that text, converts it to bytes, and then applies the layouts above.
 */



 /**
 * @brief Extract the voice data from the server option 17 string and option 39 string of a lease.
 *
 * Option 17 is "vendor=4491 32=aa:bb:.. 33=.. 34=.. 2171=.."; option 39 is flags byte plus DNS labels.
 *
 * @param src  Source DHCPv6 lease.
 * @param dest Destination voice message.
 * @return true if at least one voice value was found.
 */
static bool DhcpMgr_createVoiceInfoMsg(const DHCPv6_PLUGIN_MSG *pSrcData, DHCP_MGR_VOICE_V6_MSG *pDestData)
{
    memset(pDestData, 0, sizeof(*pDestData));

    char cVendorData[sizeof(pSrcData->vendor.Data)];
    snprintf(cVendorData, sizeof(cVendorData), "%s", pSrcData->vendor.Data);

    char *saveptr = NULL;
    for (char *pToken = strtok_r(cVendorData, " ", &saveptr); pToken != NULL; pToken = strtok_r(NULL, " ", &saveptr))
    {
        char *pValue = strchr(pToken, '=');
        if (pValue == NULL)
        {
            continue;
        }
        *pValue++ = '\0';

        int iCode = atoi(pToken);
        if (iCode != 32 && iCode != 33 && iCode != 34 && iCode != 2171)
        {
            continue;
        }

        unsigned char cBuf[BUFLEN_512];
        int iLen = DhcpMgr_HexColonToBytes(pValue, cBuf, sizeof(cBuf));
        if (iLen <= 0)
        {
            DHCPMGR_LOG_ERROR("%s: Invalid option 17 sub-option %d data\n", __FUNCTION__, iCode);
            continue;
        }

        switch (iCode)
        {
            case 32:
                DhcpMgr_FirstIpv6ToText(cBuf, (size_t)iLen, pDestData->cTftpServer, sizeof(pDestData->cTftpServer));
                break;
            case 33:
            {
                size_t n = ((size_t)iLen < sizeof(pDestData->cTftpFileName) - 1) ? (size_t)iLen : sizeof(pDestData->cTftpFileName) - 1;
                memcpy(pDestData->cTftpFileName, cBuf, n);
                pDestData->cTftpFileName[n] = '\0';
                break;
            }
            case 34:
                DhcpMgr_FirstIpv6ToText(cBuf, (size_t)iLen, pDestData->cSyslogServer, sizeof(pDestData->cSyslogServer));
                break;
            case 2171:
                DhcpMgr_ParseProvServer(cBuf, (size_t)iLen, pDestData->cProvServer, sizeof(pDestData->cProvServer));
                break;
            default:
                break;
        }
    }

    if (pSrcData->cFqdn[0] != '\0')
    {
        unsigned char cBuf[BUFLEN_256];
        int iLen = DhcpMgr_HexColonToBytes(pSrcData->cFqdn, cBuf, sizeof(cBuf));
        if (iLen > 1)
        {
            DhcpMgr_DecodeDnsName(&cBuf[1], (size_t)iLen - 1, pDestData->cClientFqdn, sizeof(pDestData->cClientFqdn));
        }
        else if (iLen < 0)
        {
            /* Not hex, so already text */
            snprintf(pDestData->cClientFqdn, sizeof(pDestData->cClientFqdn), "%s", pSrcData->cFqdn);
        }
    }

    bool bFound = (pDestData->cTftpServer[0] || pDestData->cTftpFileName[0] || pDestData->cSyslogServer[0] || pDestData->cProvServer[0] || pDestData->cClientFqdn[0]);
    if (bFound)
    {
        DHCPMGR_LOG_INFO("%s: Voice info - TFTP server: %s, file: %s, syslog: %s, provisioning server: %s, client FQDN: %s\n", __FUNCTION__,
            pDestData->cTftpServer, pDestData->cTftpFileName, pDestData->cSyslogServer, pDestData->cProvServer, pDestData->cClientFqdn);
    }
    return bFound;
}

/* Attach the voice data to the event object when the lease has any. */
static void DhcpMgr_SetVoiceInfo(rbusObject_t rdata, const DHCPv6_PLUGIN_MSG *pLease)
{
    DHCP_MGR_VOICE_V6_MSG sVoiceInfo;
    if (FALSE == DhcpMgr_createVoiceInfoMsg(pLease, &sVoiceInfo))
    {
        return;
    }

    rbusValue_t voiceInfoVal;
    rbusValue_Init(&voiceInfoVal);
    rbusValue_SetBytes(voiceInfoVal, (const uint8_t *)&sVoiceInfo, sizeof(sVoiceInfo));
    rbusObject_SetValue(rdata, "VoiceInfo", voiceInfoVal);
    rbusValue_Release(voiceInfoVal);
}

static void DhcpMgr_SetLeaseDataOnProperty(rbusProperty_t rbusProperty, const char *ifName,
                                            DHCP_MESSAGE_TYPE msgType,
                                            const void *leaseData, size_t leaseDataSize)
{
    rbusObject_t rdata;
    rbusValue_t ifNameVal, typeVal, leaseInfoVal;

    rbusObject_Init(&rdata, NULL);

    rbusValue_Init(&ifNameVal);
    rbusValue_SetString(ifNameVal, ifName);
    rbusObject_SetValue(rdata, "IfName", ifNameVal);
    rbusValue_Release(ifNameVal);

    rbusValue_Init(&typeVal);
    rbusValue_SetUInt32(typeVal, msgType);
    rbusObject_SetValue(rdata, "MsgType", typeVal);
    rbusValue_Release(typeVal);

    if (leaseData != NULL)
    {
        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, (const uint8_t*)leaseData, leaseDataSize);
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
        rbusValue_Release(leaseInfoVal);
    }

    rbusProperty_SetObject(rbusProperty, rdata);
    rbusObject_Release(rdata);
}

rbusError_t getDataHandler(rbusHandle_t rbusHandle, rbusProperty_t rbusProperty, rbusGetHandlerOptions_t *pRbusGetHandlerOptions)
{
    (void)rbusHandle;
    (void)pRbusGetHandlerOptions;

    char const *pName = rbusProperty_GetName(rbusProperty);
    int iDmIndex = -1;
    DHCP_MESSAGE_TYPE msgType;

    if (pName && 0 == strncmp(pName, DHCP_MGR_DHCPv4_TABLE, strlen(DHCP_MGR_DHCPv4_TABLE)))
    {
        if (sscanf(pName, DHCPv4_EVENT_FORMAT, &iDmIndex) != 1 || iDmIndex < 1)
        {
            DHCPMGR_LOG_ERROR("%s %d - Invalid DHCPv4 property name %s\n", __FUNCTION__, __LINE__, pName);
            return RBUS_ERROR_SUCCESS;
        }

        PCOSA_DML_DHCPC_FULL pDhcpc = NULL;
        PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink = NULL;
        PSINGLE_LINK_ENTRY pSListEntry = NULL;
        unsigned long ulInstanceNum = 0;

        pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL, (ULONG)(iDmIndex - 1), &ulInstanceNum);
        if (pSListEntry)
        {
            pDhcpCxtLink = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pDhcpc = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
        }

        if (!pDhcpc || !pDhcpc->currentLease)
        {
            DHCPMGR_LOG_INFO("%s %d - DHCPv4 client context or lease not available for %s\n", __FUNCTION__, __LINE__, pName);
            return RBUS_ERROR_SUCCESS;
        }

        msgType = pDhcpc->currentLease->isExpired ? DHCP_LEASE_DEL : DHCP_LEASE_UPDATE;
        DHCPMGR_LOG_INFO("%s %d - Getting DHCPv4 data for %s, MsgType=%d\n", __FUNCTION__, __LINE__, pName, msgType);

        if (msgType == DHCP_LEASE_UPDATE)
        {
            DHCP_MGR_IPV4_MSG leaseInfo;
            memset(&leaseInfo, 0, sizeof(leaseInfo));
            DhcpMgr_createLeaseInfoMsg(pDhcpc->currentLease, &leaseInfo);
            DhcpMgr_SetLeaseDataOnProperty(rbusProperty, pDhcpc->Cfg.Interface, msgType, &leaseInfo, sizeof(leaseInfo));
        }
        else
        {
            DhcpMgr_SetLeaseDataOnProperty(rbusProperty, pDhcpc->Cfg.Interface, msgType, NULL, 0);
        }
    }
    else if (pName && 0 == strncmp(pName, DHCP_MGR_DHCPv6_TABLE, strlen(DHCP_MGR_DHCPv6_TABLE)))
    {
        if (sscanf(pName, DHCPv6_EVENT_FORMAT, &iDmIndex) != 1 || iDmIndex < 1)
        {
            DHCPMGR_LOG_ERROR("%s %d - Invalid DHCPv6 property name %s\n", __FUNCTION__, __LINE__, pName);
            return RBUS_ERROR_SUCCESS;
        }

        PCOSA_DML_DHCPCV6_FULL pDhcpv6c = NULL;
        PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcpv6CxtLink = NULL;
        PSINGLE_LINK_ENTRY pSListEntry = NULL;
        unsigned long ulInstanceNum = 0;

        pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL, (ULONG)(iDmIndex - 1), &ulInstanceNum);
        if (pSListEntry)
        {
            pDhcpv6CxtLink = ACCESS_COSA_CONTEXT_DHCPCV6_LINK_OBJECT(pSListEntry);
            pDhcpv6c = (PCOSA_DML_DHCPCV6_FULL)pDhcpv6CxtLink->hContext;
        }

        if (!pDhcpv6c || !pDhcpv6c->currentLease)
        {
            DHCPMGR_LOG_INFO("%s %d - DHCPv6 client context or lease not available for %s\n", __FUNCTION__, __LINE__, pName);
            return RBUS_ERROR_SUCCESS;
        }

        msgType = pDhcpv6c->currentLease->isExpired ? DHCP_LEASE_DEL : DHCP_LEASE_UPDATE;
        DHCPMGR_LOG_INFO("%s %d - Getting DHCPv6 data for %s, MsgType=%d\n", __FUNCTION__, __LINE__, pName, msgType);

        if (msgType == DHCP_LEASE_UPDATE)
        {
            DHCP_MGR_IPV6_MSG leaseInfo;
            memset(&leaseInfo, 0, sizeof(leaseInfo));
            DhcpMgr_createDhcpv6LeaseInfoMsg(pDhcpv6c->currentLease, &leaseInfo);
            DhcpMgr_SetLeaseDataOnProperty(rbusProperty, pDhcpv6c->Cfg.Interface, msgType, &leaseInfo, sizeof(leaseInfo));
            rbusValue_t propValue = rbusProperty_GetValue(rbusProperty);
            if (propValue != NULL && rbusValue_GetType(propValue) == RBUS_OBJECT)
            {
                DhcpMgr_SetVoiceInfo(rbusValue_GetObject(propValue), pDhcpv6c->currentLease);
            }
        }
        else
        {
            DhcpMgr_SetLeaseDataOnProperty(rbusProperty, pDhcpv6c->Cfg.Interface, msgType, NULL, 0);
        }
    }
    else
    {
        DHCPMGR_LOG_ERROR("%s %d - Unsupported property name %s\n", __FUNCTION__, __LINE__, pName ? pName : "NULL");
    }

    return RBUS_ERROR_SUCCESS;
}

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

    /*Set the lease details */
    if(msgType == DHCP_LEASE_UPDATE || msgType == DHCP_LEASE_RENEW)
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
        rbusValue_Release(leaseInfoVal);
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
    if(msgType == DHCP_LEASE_UPDATE || msgType == DHCP_LEASE_RENEW)
    {
        DHCP_MGR_IPV6_MSG leaseInfo;
        memset(&leaseInfo, 0, sizeof(leaseInfo));
        DhcpMgr_createDhcpv6LeaseInfoMsg(pDhcpv6c->currentLease,&leaseInfo);
        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, &leaseInfo, sizeof(leaseInfo));
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
        rbusValue_Release(leaseInfoVal);
        DhcpMgr_SetVoiceInfo(rdata, pDhcpv6c->currentLease);
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
        //Update MAPT dml values 
        if(leaseInfo.maptAssigned)
        {
            DhcpMgr_UpdateDhcpv6MapInfo(pDhcpv6c, &leaseInfo);
        }
        else if(pDhcpv6c->Info.MapInfo.MaptAssigned) // previously assigned MAPT in DML but not in the new lease, clear the MAPT info in DML
        {
            //Clear MAPT related info in DML if MAPT is not assigned in the lease
            DHCPMGR_LOG_INFO("%s: Clearing MAPT info in DML as MAPT is not assigned in the lease\n", __FUNCTION__);
            memset(&pDhcpv6c->Info.MapInfo, 0, sizeof(DML_DHCPCV6_MAP_INFO));
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
