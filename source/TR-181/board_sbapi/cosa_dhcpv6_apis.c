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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**************************************************************************

    module: cosa_dhcpv6_apis.c

        For COSA Data Model Library Development.

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.
        03/15/2011    Added for backend Dhcp4 clients.
        04/08/2011    Added Dhcp4 clients Sent Options and Req Options.


**************************************************************************/
#include "cosa_apis.h"
#include "cosa_dhcpv6_apis.h"
#include "cosa_dhcpv6_internal.h"
#include "plugin_main_apis.h"
#include "autoconf.h"
#include "secure_wrapper.h"
#include "safec_lib_common.h"
#include "cosa_common_util.h"
#include <ccsp_psm_helper.h>
#include <sys/stat.h>
#include "sysevent/sysevent.h"
#include "cosa_apis_util.h"
#include "util.h"
#include "ifl.h"
//#include <libnet.h>

#define DHCPV6_BINARY   "dibbler-client"
extern void* g_pDslhDmlAgent;
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern int executeCmd(char *cmd);
ULONG          g_Dhcp6ClientNum = 0;

#define BUFF_LEN_8      8
#define BUFF_LEN_16    16
#define BUFF_LEN_32    32
#define BUFF_LEN_64    64
#define BUFF_LEN_128  128
#define BUFF_LEN_256  256

#define GUEST_INTERFACE_NAME "brlan1"
char GUEST_PREVIOUS_IP[128]     = {0};
char GUEST_PREVIOUS_PREFIX[128] = {0};
int  brlan1_prefix_changed      = 0;

#define IP6_ADDR_ADD(ipaddr,iface)   {\
   if ((strlen(ipaddr) > 0) && (strlen(iface) > 0))\
   {\
       v_secure_system("ip -6 addr add %s/64 dev %s valid_lft forever preferred_lft forever",ipaddr,iface);\
   }\
}\

#define IP6_ADDR_DEL(ipaddr,iface)   {\
   if ((strlen(ipaddr) > 0) && (strlen(iface) > 0))\
   {\
       v_secure_system("ip -6 addr del %s/64 dev %s",ipaddr,iface);\
   }\
}\

extern int executeCmd(char *cmd);
extern int CheckAndGetDevicePropertiesEntry( char *pOutput, int size, char *sDevicePropContent );
ANSC_STATUS syscfg_set_bool(const char* name, int value);
ANSC_STATUS syscfg_set_string(const char* name, const char* value);

#include "ipc_msg.h"
#if defined SUCCESS
#undef SUCCESS
#endif
#define SYSEVENT_FIELD_IPV6_DNS_SERVER    "wan6_ns"

#if defined(_HUB4_PRODUCT_REQ_) || defined(FEATURE_RDKB_WAN_MANAGER)
#define SYSEVENT_FIELD_IPV6_PREFIXVLTIME  "ipv6_prefix_vldtime"
#define SYSEVENT_FIELD_IPV6_PREFIXPLTIME  "ipv6_prefix_prdtime"
#define SYSEVENT_FIELD_IPV6_ULA_ADDRESS   "ula_address"
#endif

#if defined(RDKB_EXTENDER_ENABLED) || defined(WAN_FAILOVER_SUPPORTED)
typedef enum deviceMode
{
    DEVICE_MODE_ROUTER,
    DEVICE_MODE_EXTENDER
}deviceMode;
#endif

#if defined (INTEL_PUMA7)
//Intel Proposed RDKB Generic Bug Fix from XB6 SDK
#define NO_OF_RETRY 90  /*No of times the file will poll for TLV config file*/
#endif

#if defined _COSA_SIM_

COSA_DML_DHCPCV6_FULL  g_dhcpv6_client[] =
    {
        {
            {
                1,
                "Client1",
                1,
                5,
                "Layer3Interface1",
                "RequestedOption1,RequestedOption2",
                TRUE,
                TRUE,
                TRUE,
                TRUE,
                FALSE
            },
            {
                COSA_DML_DHCP_STATUS_Enabled,
                "SupportedOptions1,SupportedOptions2",
                "duid1,duid2"
            }
        }
    };


COSA_DML_DHCPCV6_SENT    g_dhcpv6_client_sent[] =
    {
        {
            1,
            "SentOption1",
            TRUE,
            11,
            "Value1"
        },
        {
            2,
            "SentOption2",
            TRUE,
            12,
            "Value2"
        }
    };

COSA_DML_DHCPCV6_SVR g_dhcpv6_client_server[] =
    {
        {
            "2002::1",
            "Interface1",
            "2002:02:03",
        },
        {
            "2002::2",
            "Interface2",
            "2002:02:04",
        }
    };

COSA_DML_DHCPCV6_RECV g_dhcpv6_client_recv[] =
    {
        {
            23,
            "Server1",
            "Value1"
        },
        {
            24,
            "Server2",
            "Value2"
        }
    };

BOOL  g_dhcpv6_server = TRUE;

COSA_DML_DHCPSV6_POOL_FULL  g_dhcpv6_server_pool[]=
{
    {
        {
            1,
            "Pool1",
            3,
            "Layer3Interface",
            "vendorid",                       /*VendorClassID*/
            "usrerid",
            "2002:3:4",
            "ffff:ffff:ffff:0",
            "IANAManualPrefixes",  /*IANAManualPrefixes*/
            "IAPDManualPrefixes",  /*IAPDManualPrefixes*/
            1999,
            "duid1",                        /*DUID*/
            TRUE,
            TRUE,                           /*DUIDExclude*/
            TRUE,
            TRUE,                           /*UserClassIDExclude*/
            TRUE,
            TRUE,  /*IANA enable*/
            TRUE
        },
        {
            COSA_DML_DHCP_STATUS_Enabled,
            "IANAPrefixes",  /*IANAPrefixes*/
            "IAPDPrefixes"   /*IAPDPrefixes*/
        }
    }
};

COSA_DML_DHCPSV6_CLIENT g_dhcpv6_server_client[] =
{
    "client1",
    "2002::01",
    TRUE
};

COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS g_dhcpv6_server_client_ipv6address[] =
{
   {
        "2002::01",
        "1000",
        "1200"
    }
};

COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX g_dhcpv6_server_client_ipv6prefix[] =
{
    {
        "2002::03",
        "1100",
        "1300"
    }
};

COSA_DML_DHCPSV6_CLIENT_OPTION g_dhcpv6_server_client_option[] =
{

    {
        23,
        "Value1"
    }
};

COSA_DML_DHCPSV6_POOL_OPTION g_dhcpv6_server_pool_option[] =
{
    {
        1,
        "Option1",
        10023,
        "PassthroughClient",
        "Value1",
        TRUE
    }
};

ANSC_STATUS
CosaDmlDhcpv6Init
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the number of DHCP clients in the system.
 */
ULONG
CosaDmlDhcpv6cGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    )
{
    PCOSA_DATAMODEL_DHCPV6          pDhcpv6           = (PCOSA_DATAMODEL_DHCPV6)g_pCosaBEManager->hDhcpv6;

    return 1;
}

/*
    Description:
        The API retrieves the complete info of the DHCP clients designated by index. The usual process is the caller gets the total number of entries, then iterate through those by calling this API.
    Arguments:
        ulIndex        Indicates the index number of the entry.
        pEntry        To receive the complete info of the entry.
*/
ANSC_STATUS
CosaDmlDhcpv6cGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPCV6_FULL      pEntry
    )
{

   if ( ulIndex >= sizeof(g_dhcpv6_client)/sizeof(COSA_DML_DHCPCV6_FULL) )
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory(pEntry, &g_dhcpv6_client[ulIndex], sizeof(COSA_DML_DHCPCV6_FULL));

        return ANSC_STATUS_SUCCESS;
    }

ANSC_STATUS
CosaDmlDhcpv6cSetValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    errno_t                         rc              = -1;

    if ( ulIndex >= sizeof(g_dhcpv6_client)/sizeof(COSA_DML_DHCPCV6_FULL) )
        return ANSC_STATUS_SUCCESS;

    g_dhcpv6_client[ulIndex].Cfg.InstanceNumber  = ulInstanceNumber;
    rc = STRCPY_S_NOCLOBBER(g_dhcpv6_client[ulIndex].Cfg.Alias, sizeof(g_dhcpv6_client[ulIndex].Cfg.Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API adds DHCP client.
    Arguments:
        pEntry        Caller fills in pEntry->Cfg, except Alias field. Upon return, callee fills pEntry->Cfg.Alias field and as many as possible fields in pEntry->Info.
*/
ANSC_STATUS
CosaDmlDhcpv6cAddEntry
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_FULL        pEntry
    )
{
    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API removes the designated DHCP client entry.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
CosaDmlDhcpv6cDelEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
            return ANSC_STATUS_SUCCESS;
}

/*
Description:
    The API re-configures the designated DHCP client entry.
Arguments:
    pAlias        The entry is identified through Alias.
    pEntry        The new configuration is passed through this argument, even Alias field can be changed.
*/
ANSC_STATUS
CosaDmlDhcpv6cSetCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_CFG       pCfg
    )
{
    ULONG                           index  = 0;

    for( index = 0 ; index < sizeof (g_dhcpv6_client)/sizeof(COSA_DML_DHCPCV6_FULL); index++)
    {
        if ( pCfg->InstanceNumber == g_dhcpv6_client[index].Cfg.InstanceNumber )
        {
            AnscCopyMemory(&g_dhcpv6_client[index].Cfg, pCfg, sizeof(COSA_DML_DHCPCV6_CFG));
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cGetCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_CFG       pCfg
    )
{
    ULONG                           index  = 0;

    for( index = 0 ; index < sizeof (g_dhcpv6_client)/sizeof(COSA_DML_DHCPCV6_FULL); index++)
    {
        if ( pCfg->InstanceNumber == g_dhcpv6_client[index].Cfg.InstanceNumber )
        {
            AnscCopyMemory(pCfg,  &g_dhcpv6_client[index].Cfg, sizeof(COSA_DML_DHCPCV6_CFG));
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}


/* this memory need to be freed by caller */
ANSC_STATUS
CosaDmlDhcpv6cGetServerCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SVR      *ppCfg,
        PULONG                      pSize
    )
{
    *ppCfg = (PCOSA_DML_DHCPCV6_SVR)AnscAllocateMemory( sizeof(g_dhcpv6_client_server ) );
    AnscCopyMemory( *ppCfg, &g_dhcpv6_client_server[0], sizeof(g_dhcpv6_client_server) );
    *pSize = sizeof(g_dhcpv6_client_server) / sizeof(COSA_DML_DHCPCV6_SVR);

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API initiates a DHCP client renewal.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
CosaDmlDhcpv6cRenew
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    DHCPMGR_LOG_INFO(" CosaDmlDhcpv6cRenew -- ulInstanceNumber:%d.\n", ulInstanceNumber);

    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Client Send/Req Option
 *
 *  The options are managed on top of a DHCP client,
 *  which is identified through pClientAlias
 */
ULONG
CosaDmlDhcpv6cGetNumberOfSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    )
{
    return sizeof(g_dhcpv6_client_sent)/sizeof(COSA_DML_DHCPCV6_SENT);
}

ANSC_STATUS
CosaDmlDhcpv6cGetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    PCOSA_DML_DHCPCV6_SENT          pDhcpSendOption      = pEntry;

    if ( ulIndex+1 > sizeof(g_dhcpv6_client_sent)/sizeof(COSA_DML_DHCPCV6_SENT) )
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory( pEntry, &g_dhcpv6_client_sent[ulIndex], sizeof(COSA_DML_DHCPCV6_SENT));

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
CosaDmlDhcpv6cGetSentOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    ULONG                           index  = 0;

    for( index=0;  index<sizeof(g_dhcpv6_client_sent)/sizeof(COSA_DML_DHCPCV6_SENT); index++)
    {
        if ( pEntry->InstanceNumber == g_dhcpv6_client_sent[index].InstanceNumber )
        {
            AnscCopyMemory( pEntry, &g_dhcpv6_client_sent[index], sizeof(COSA_DML_DHCPCV6_SENT));
             return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
CosaDmlDhcpv6cSetSentOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    errno_t                         rc              = -1;
    if ( ulIndex+1 > sizeof(g_dhcpv6_client_sent)/sizeof(COSA_DML_DHCPCV6_SENT) )
        return ANSC_STATUS_SUCCESS;

    g_dhcpv6_client_sent[ulIndex].InstanceNumber  = ulInstanceNumber;

    rc = STRCPY_S_NOCLOBBER(g_dhcpv6_client_sent[ulIndex].Alias, sizeof(g_dhcpv6_client_sent[ulIndex].Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cAddSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cDelSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cSetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    ULONG                           index  = 0;

    for( index=0;  index<sizeof(g_dhcpv6_client_sent)/sizeof(COSA_DML_DHCPCV6_SENT); index++)
    {
        if ( pEntry->InstanceNumber == g_dhcpv6_client_sent[index].InstanceNumber )
        {
            AnscCopyMemory( &g_dhcpv6_client_sent[index], pEntry, sizeof(COSA_DML_DHCPCV6_SENT));
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* This is to get all
 */
ANSC_STATUS
CosaDmlDhcpv6cGetReceivedOptionCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_RECV     *ppEntry,
        PULONG                      pSize
    )
{
    *ppEntry = (PCOSA_DML_DHCPCV6_RECV)AnscAllocateMemory( sizeof(g_dhcpv6_client_recv) );
    AnscCopyMemory( *ppEntry, &g_dhcpv6_client_recv[0], sizeof(g_dhcpv6_client_recv) );
    *pSize = sizeof(g_dhcpv6_client_recv) / sizeof(COSA_DML_DHCPCV6_RECV);

    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Server
 */
ANSC_STATUS
CosaDmlDhcpv6sEnable
    (
        ANSC_HANDLE                 hContext,
        BOOL                        bEnable
    )
{
    g_dhcpv6_server = bEnable;

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the current state of DHCP server: Enabled or Disabled.
*/
BOOLEAN
CosaDmlDhcpv6sGetState
    (
        ANSC_HANDLE                 hContext
    )
{
    return g_dhcpv6_server;
}

/*
 *  DHCP Server Pool
 */
ULONG
CosaDmlDhcpv6sGetNumberOfPools
    (
        ANSC_HANDLE                 hContext
    )
{
    return sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL);
}

ANSC_STATUS
CosaDmlDhcpv6sGetPool
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPSV6_POOL_FULL pEntry
    )
{
    if ( ulIndex+1 > sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL) )
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory(pEntry, &g_dhcpv6_server_pool[ulIndex], sizeof(COSA_DML_DHCPSV6_POOL_FULL));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sSetPoolValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    errno_t                         rc              = -1;
    if ( ulIndex+1 > sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL) )
        return ANSC_STATUS_FAILURE;

    g_dhcpv6_server_pool[ulIndex].Cfg.InstanceNumber  = ulInstanceNumber;
    rc = STRCPY_S_NOCLOBBER(g_dhcpv6_server_pool[ulIndex].Cfg.Alias, sizeof(g_dhcpv6_server_pool[ulIndex].Cfg.Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sAddPool
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_FULL   pEntry
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sDelPool
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sSetPoolCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_CFG  pCfg
    )
{
    ULONG                          index = 0;

    for(index = 0; index <sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL); index++)
    {
        if ( pCfg->InstanceNumber == g_dhcpv6_server_pool[index].Cfg.InstanceNumber )
        {
            AnscCopyMemory( &g_dhcpv6_server_pool[index].Cfg, pCfg, sizeof(COSA_DML_DHCPSV6_POOL_FULL) );
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetPoolCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_CFG    pCfg
    )
{
    ULONG                          index = 0;

    for(index = 0; index <sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL); index++)
    {
        if ( pCfg->InstanceNumber == g_dhcpv6_server_pool[index].Cfg.InstanceNumber )
        {
            AnscCopyMemory( pCfg, &g_dhcpv6_server_pool[index].Cfg, sizeof(COSA_DML_DHCPSV6_POOL_FULL) );
            return ANSC_STATUS_FAILURE;
        }
    }

    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
CosaDmlDhcpv6sGetPoolInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_INFO pInfo
    )
{
    ULONG                          index = 0;

    for(index = 0; index <sizeof(g_dhcpv6_server_pool)/sizeof(COSA_DML_DHCPSV6_POOL_FULL); index++)
    {
        if ( ulInstanceNumber == g_dhcpv6_server_pool[index].Cfg.InstanceNumber )
        {
            AnscCopyMemory( pInfo, &g_dhcpv6_server_pool[index].Info, sizeof(COSA_DML_DHCPSV6_POOL_INFO) );
            return ANSC_STATUS_FAILURE;
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
CosaDmlDhcpv6sPing
    (
        PCOSA_DML_DHCPSV6_CLIENT    pDhcpsClient
    )
{
    return ANSC_STATUS_SUCCESS;
}


/*
 *   This is for
 *     Pool.{i}.Client.{i}.
 *
 */
ANSC_STATUS
CosaDmlDhcpv6sGetClient
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_CLIENT   *ppEntry,
        PULONG                      pSize
    )
{
    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT)AnscAllocateMemory( sizeof(g_dhcpv6_server_client) );
    AnscCopyMemory( *ppEntry, &g_dhcpv6_server_client[0], sizeof(g_dhcpv6_server_client) );
    *pSize = sizeof(g_dhcpv6_server_client) / sizeof(COSA_DML_DHCPSV6_CLIENT);

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Address.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Address
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS   *ppEntry,
        PULONG                      pSize
    )
{
    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)AnscAllocateMemory( sizeof(g_dhcpv6_server_client_ipv6address) );
    AnscCopyMemory( *ppEntry, &g_dhcpv6_server_client_ipv6address[0], sizeof(g_dhcpv6_server_client_ipv6address) );
    *pSize = sizeof(g_dhcpv6_server_client_ipv6address) / sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS);

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Prefix.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Prefix
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX   *ppEntry,
        PULONG                      pSize
    )
{
    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)AnscAllocateMemory( sizeof(g_dhcpv6_server_client_ipv6prefix) );
    AnscCopyMemory( *ppEntry, &g_dhcpv6_server_client_ipv6prefix[0], sizeof(g_dhcpv6_server_client_ipv6prefix) );
    *pSize = sizeof(g_dhcpv6_server_client_ipv6prefix) / sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX);

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Option.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Option
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_OPTION   *ppEntry,
        PULONG                      pSize
    )
{
    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_OPTION)AnscAllocateMemory( sizeof(g_dhcpv6_server_client_option) );
    AnscCopyMemory( *ppEntry, &g_dhcpv6_server_client_option[0], sizeof(g_dhcpv6_server_client_option) );
    *pSize = sizeof(g_dhcpv6_server_client_option) / sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION);

    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Server Pool Option
 *
 *  The options are managed on top of a DHCP server pool,
 *  which is identified through pPoolAlias
 */
ULONG
CosaDmlDhcpv6sGetNumberOfOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber
    )
{
    return sizeof(g_dhcpv6_server_pool_option) / sizeof(COSA_DML_DHCPSV6_POOL_OPTION);
}

ANSC_STATUS
CosaDmlDhcpv6sGetOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    if ( ulIndex+1 > sizeof(g_dhcpv6_server_pool_option)/sizeof(COSA_DML_DHCPSV6_POOL_OPTION) )
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory(pEntry, &g_dhcpv6_server_pool_option[ulIndex], sizeof(COSA_DML_DHCPSV6_POOL_OPTION));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    ULONG                           index = 0;

    for(index = 0; index < sizeof(g_dhcpv6_server_pool_option[index])/sizeof(COSA_DML_DHCPSV6_POOL_OPTION); index++)
    {
        if ( pEntry->InstanceNumber == g_dhcpv6_server_pool_option[index].InstanceNumber )
        {
            AnscCopyMemory(pEntry, &g_dhcpv6_server_pool_option[index], sizeof(COSA_DML_DHCPSV6_POOL_OPTION));
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
CosaDmlDhcpv6sSetOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    errno_t                         rc              = -1;
    if ( ulIndex+1 > sizeof(g_dhcpv6_server_pool_option)/sizeof(COSA_DML_DHCPSV6_POOL_OPTION) )
        return ANSC_STATUS_FAILURE;

    g_dhcpv6_server_pool_option[ulIndex].InstanceNumber  = ulInstanceNumber;

    rc = STRCPY_S_NOCLOBBER(g_dhcpv6_server_pool_option[ulIndex].Alias, sizeof(g_dhcpv6_server_pool_option[ulIndex].Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sAddOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    return ANSC_STATUS_SUCCESS;

}

ANSC_STATUS
CosaDmlDhcpv6sDelOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    return ANSC_STATUS_SUCCESS;

}

ANSC_STATUS
CosaDmlDhcpv6sSetOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    ULONG                          index = 0;

    for(index = 0; index <sizeof(g_dhcpv6_server_pool_option)/sizeof(COSA_DML_DHCPSV6_POOL_OPTION); index++)
    {
        if ( pEntry->InstanceNumber == g_dhcpv6_server_pool_option[index].InstanceNumber )
        {
            AnscCopyMemory( &g_dhcpv6_server_pool_option[index], pEntry, sizeof(COSA_DML_DHCPSV6_POOL_OPTION) );
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

void
CosaDmlDhcpv6Remove(ANSC_HANDLE hContext)
{
    return;
}

BOOL tagPermitted(int tag)
{
    return TRUE;
}

#elif (defined _COSA_INTEL_USG_ARM_) || (defined _COSA_BCM_MIPS_)

#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <utapi.h>
#include <utapi_util.h>
#include <utctx/utctx_api.h>
#include "syscfg/syscfg.h"
#include "cosa_drg_common.h"
#include "cosa_common_util.h"

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && defined(_COSA_BCM_MIPS_)
#include <netinet/in.h>
#endif

#define SYSCFG_FORMAT_DHCP6C "tr_dhcpv6c"
#define CLIENT_DUID_FILE "/var/lib/dibbler/client-duid"
#define SERVER_DUID_FILE "/var/lib/dibbler/server-duid"

//for test
#define CLIENT_BIN     "dibbler-client"
#define SERVER_BIN     "dibbler-server"
//#define SERVER_BIN     "/usr/local/sbin//dibbler-server"

/* Server global variable  Begin*/

#if defined (MULTILAN_FEATURE)
#define IPV6_PREF_MAXLEN               128
#define DHCPV6S_POOL_NUM               64  /* this pool means interface. We just supported such number interfaces. Each interface can include many pools*/
#else
#define DHCPV6S_POOL_NUM               1
#endif
#define DHCPV6S_POOL_OPTION_NUM        16 /* each interface supports this number options */
#if defined (MULTILAN_FEATURE)
#define CMD_BUFF_SIZE                  256
#endif
#define DHCPV6S_NAME                   "dhcpv6s"

#if defined (INTEL_PUMA7)
#define NO_OF_RETRY 90
#if defined(MULTILAN_FEATURE)
#define IPV6_PREF_MAXLEN 128
#endif
#endif

#if defined(RA_MONITOR_SUPPORT) || defined(DHCPV6_SERVER_SUPPORT)
static struct {
    pthread_t          dbgthrdc;
    pthread_t          dbgthrds;
    pthread_t          dbgthrd_rtadv;
}g_be_ctx;
#endif

#ifdef RA_MONITOR_SUPPORT
typedef struct
{
    char managedFlag;
    char otherFlag;
    char ra_Ifname[64];
} desiredRtAdvInfo;
static desiredRtAdvInfo *rtAdvInfo;

#define IPv6_RT_MON_NOTIFY_CMD "kill -10 `pidof ipv6rtmon`"
#endif // RA_MONITOR_SUPPORT

#ifdef DHCPV6_SERVER_SUPPORT
extern void * dhcpv6s_dbg_thrd(void * in);
#endif

#ifdef RA_MONITOR_SUPPORT
static void * rtadv_dbg_thread(void * in);
#endif // RA_MONITOR_SUPPORT

extern COSARepopulateTableProc            g_COSARepopulateTable;

#define UTOPIA_SIMULATOR                0

enum {
    DHCPV6_SERVER_TYPE_STATEFUL  =1,
    DHCPV6_SERVER_TYPE_STATELESS
};

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && defined(_COSA_BCM_MIPS_)
#define MAX_LAN_IF_NUM              3

/*erouter topology mode*/
enum tp_mod {
    TPMOD_UNKNOWN,
    FAVOR_DEPTH,
    FAVOR_WIDTH,
};

typedef struct pd_pool {
    char start[INET6_ADDRSTRLEN];
    char end[INET6_ADDRSTRLEN];
    int  prefix_length;
    int  pd_length;
} pd_pool_t;

typedef struct ia_info {
    union {
        char v6addr[INET6_ADDRSTRLEN];
        char v6pref[INET6_ADDRSTRLEN];
    } value;

    char t1[32], t2[32], iaid[32], pretm[32], vldtm[32];
    int len;
} ia_pd_t;

typedef struct ipv6_prefix {
    char value[INET6_ADDRSTRLEN];
    int  len;
} ipv6_prefix_t;

#endif

ULONG                               uDhcpv6ServerPoolNum                                  = 0;
COSA_DML_DHCPSV6_POOL_FULL          sDhcpv6ServerPool[DHCPV6S_POOL_NUM]                   = {};
ULONG                               uDhcpv6ServerPoolOptionNum[DHCPV6S_POOL_NUM]          = {0};
COSA_DML_DHCPSV6_POOL_OPTION        sDhcpv6ServerPoolOption[DHCPV6S_POOL_NUM][DHCPV6S_POOL_OPTION_NUM] = {};

#if defined(MULTILAN_FEATURE)
static char v6addr_prev[IPV6_PREF_MAXLEN] = {0};
#endif

BOOL  g_dhcpv6_server      = TRUE;
ULONG g_dhcpv6_server_type = DHCPV6_SERVER_TYPE_STATELESS;

BOOL g_lan_ready = FALSE;
BOOL g_dhcpv6_server_prefix_ready = FALSE;
ULONG g_dhcpv6s_refresh_count = 0;

#if defined (_HUB4_PRODUCT_REQ_)
    #define DHCPV6S_SERVER_PID_FILE   "/etc/dibbler/server.pid"
#else
    #define DHCPV6S_SERVER_PID_FILE   "/tmp/dibbler/server.pid"
#endif

#define DHCPVS_DEBUG_PRINT \
DHCPMGR_LOG_INFO("%s %d", __FUNCTION__, __LINE__);

#define SETS_INTO_UTOPIA( uniqueName, table1Name, table1Index, table2Name, table2Index, parameter, value ) \
{ \
    char Namespace[128]; \
    snprintf(Namespace, sizeof(Namespace), "%s%s%lu%s%lu", uniqueName, table1Name, (ULONG)table1Index, table2Name, (ULONG)table2Index ); \
    Utopia_RawSet(&utctx, Namespace, parameter, (char *) value); \
} \

#define SETI_INTO_UTOPIA( uniqueName, table1Name, table1Index, table2Name, table2Index, parameter, value ) \
{ \
    char Namespace[128]; \
    char Value[12]; \
    snprintf(Namespace, sizeof(Namespace), "%s%s%lu%s%lu", uniqueName, table1Name, (ULONG)table1Index, table2Name, (ULONG)table2Index ); \
    snprintf(Value, sizeof(Value), "%lu", (ULONG) value ); \
    Utopia_RawSet(&utctx, Namespace, parameter, Value); \
} \

#define UNSET_INTO_UTOPIA( uniqueName, table1Name, table1Index, table2Name, table2Index, parameter ) \
{ \
    char Namespace[128]; \
    snprintf(Namespace, sizeof(Namespace), "%s%s%lu%s%lu", uniqueName, table1Name, (ULONG)table1Index, table2Name, (ULONG)table2Index ); \
    syscfg_unset(Namespace, parameter); \
} \

#define GETS_FROM_UTOPIA( uniqueName, table1Name, table1Index, table2Name, table2Index, parameter, out ) \
{ \
    char Namespace[128]; \
    snprintf(Namespace, sizeof(Namespace), "%s%s%lu%s%lu", uniqueName, table1Name, (ULONG)table1Index, table2Name, (ULONG)table2Index ); \
    Utopia_RawGet(&utctx, Namespace, parameter, (char *) out, sizeof(out)); \
} \

#define GETI_FROM_UTOPIA( uniqueName, table1Name, table1Index, table2Name, table2Index, parameter, out ) \
{ \
    char Namespace[128]; \
    char Value[12] = {0}; \
    snprintf(Namespace, sizeof(Namespace), "%s%s%lu%s%lu", uniqueName, table1Name, (ULONG)table1Index, table2Name, (ULONG)table2Index ); \
    Utopia_RawGet(&utctx, Namespace, parameter, Value, sizeof(Value)); \
    if (strcmp(Value, "4294967295") == 0) out = -1; \
    else if (Value[0]) out = atoi(Value); \
} \

/* set a ulong type value into utopia */
void setpool_into_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index, PCOSA_DML_DHCPSV6_POOL_FULL pEntry )
{
    UtopiaContext utctx = {0};

    if (!Utopia_Init(&utctx))
        return;

    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "instancenumber", pEntry->Cfg.InstanceNumber)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "alias", pEntry->Cfg.Alias)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Order", pEntry->Cfg.Order)
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAInterface", pEntry->Cfg.Interface)
#else
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Interface", pEntry->Cfg.Interface)
#endif
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassID", pEntry->Cfg.VendorClassID)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassID", pEntry->Cfg.UserClassID)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddress", pEntry->Cfg.SourceAddress)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressMask", pEntry->Cfg.SourceAddressMask)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAManualPrefixes", pEntry->Cfg.IANAManualPrefixes)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDManualPrefixes", pEntry->Cfg.IAPDManualPrefixes)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeBegin", pEntry->Cfg.PrefixRangeBegin)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeEnd", pEntry->Cfg.PrefixRangeEnd)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "LeaseTime", pEntry->Cfg.LeaseTime)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDAddLength", pEntry->Cfg.IAPDAddLength)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUID", pEntry->Cfg.DUID)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDEnable", pEntry->Cfg.IAPDEnable)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressExclude", pEntry->Cfg.SourceAddressExclude)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAEnable", pEntry->Cfg.IANAEnable)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassIDExclude", pEntry->Cfg.UserClassIDExclude)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassIDExclude", pEntry->Cfg.VendorClassIDExclude)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUIDExclude", pEntry->Cfg.DUIDExclude)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "bEnabled", pEntry->Cfg.bEnabled)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Status", pEntry->Info.Status)
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAInterfacePrefixes", pEntry->Info.IANAPrefixes)
#else
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAPrefixes", pEntry->Info.IANAPrefixes)
#endif
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDPrefixes", pEntry->Info.IAPDPrefixes)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "RapidEnable", pEntry->Cfg.RapidEnable)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UnicastEnable", pEntry->Cfg.UnicastEnable)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "EUI64Enable", pEntry->Cfg.EUI64Enable)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAAmount", pEntry->Cfg.IANAAmount)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "StartAddress", pEntry->Cfg.StartAddress)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServersEnabled", pEntry->Cfg.X_RDKCENTRAL_COM_DNSServersEnabled)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServers", pEntry->Cfg.X_RDKCENTRAL_COM_DNSServers)

    Utopia_Free(&utctx,1);

    return;
}

void unsetpool_from_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index )
{
    UtopiaContext utctx = {0};

    if (!Utopia_Init(&utctx))
        return;

    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "instancenumber" )
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "alias")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Order")
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAInterface")
#else
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Interface")
#endif
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassID")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassID")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddress")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressMask")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAManualPrefixes")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDManualPrefixes")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeBegin")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeEnd")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "LeaseTime")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDAddLength")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUID")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDEnable")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressExclude")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAEnable")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassIDExclude")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassIDExclude")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUIDExclude")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "bEnabled")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Status")
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAInterfacePrefixes")
#else
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAPrefixes")
#endif
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDPrefixes")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "RapidEnable")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UnicastEnable")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "EUI64Enable")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAAmount")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "StartAddress")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServersEnabled")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServers")

    Utopia_Free(&utctx,1);

    return;
}

void getpool_from_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index, PCOSA_DML_DHCPSV6_POOL_FULL pEntry )
{
    UtopiaContext utctx = {0};
 #if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && defined(_BCI_FEATURE_REQ)
    char *INVALID_IANAInterfacePrefixes = "Device.IP.Interface.4.IPv6Prefix.1.";
    char *FIXED_IANAInterfacePrefixes   = "Device.IP.Interface.1.IPv6Prefix.1.";
#endif

    if (!Utopia_Init(&utctx))
        return;

    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "instancenumber", pEntry->Cfg.InstanceNumber)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "alias", pEntry->Cfg.Alias)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Order", pEntry->Cfg.Order)
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAInterface", pEntry->Cfg.Interface)
#else
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Interface", pEntry->Cfg.Interface)
#endif
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassID", pEntry->Cfg.VendorClassID)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassID", pEntry->Cfg.UserClassID)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddress", pEntry->Cfg.SourceAddress)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressMask", pEntry->Cfg.SourceAddressMask)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAManualPrefixes", pEntry->Cfg.IANAManualPrefixes)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDManualPrefixes", pEntry->Cfg.IAPDManualPrefixes)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeBegin", pEntry->Cfg.PrefixRangeBegin)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "PrefixRangeEnd", pEntry->Cfg.PrefixRangeEnd)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "LeaseTime", pEntry->Cfg.LeaseTime)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDAddLength", pEntry->Cfg.IAPDAddLength)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUID", pEntry->Cfg.DUID)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDEnable", pEntry->Cfg.IAPDEnable)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "SourceAddressExclude", pEntry->Cfg.SourceAddressExclude)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAEnable", pEntry->Cfg.IANAEnable)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UserClassIDExclude", pEntry->Cfg.UserClassIDExclude)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "VendorClassIDExclude", pEntry->Cfg.VendorClassIDExclude)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "DUIDExclude", pEntry->Cfg.DUIDExclude)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "bEnabled", pEntry->Cfg.bEnabled)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "Status", pEntry->Info.Status)
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAInterfacePrefixes", pEntry->Info.IANAPrefixes)
 #if defined(_BCI_FEATURE_REQ)
    DHCPMGR_LOG_INFO("%s table1Name: %s, table1Index: %lu, get IANAInterfacePrefixes: %s\n",
                  __func__, table1Name, table1Index, pEntry->Info.IANAPrefixes);

    if ( _ansc_strcmp((const char*)table1Name, "pool") == 0 && table1Index == 0 &&
        _ansc_strcmp((const char*)pEntry->Info.IANAPrefixes, INVALID_IANAInterfacePrefixes) == 0)
      {
       DHCPMGR_LOG_INFO("%s Fix invalid IANAInterfacePrefixes by setting it to new default: %s\n", __func__, FIXED_IANAInterfacePrefixes);
       SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAInterfacePrefixes", FIXED_IANAInterfacePrefixes)
       GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAInterfacePrefixes", pEntry->Info.IANAPrefixes)
       DHCPMGR_LOG_INFO("%s Try again to get IANAInterfacePrefixes: %s\n", __func__, pEntry->Info.IANAPrefixes);
      }
 #endif
#else
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAPrefixes", pEntry->Info.IANAPrefixes)
#endif
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IAPDPrefixes", pEntry->Info.IAPDPrefixes)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "RapidEnable", pEntry->Cfg.RapidEnable)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "UnicastEnable", pEntry->Cfg.UnicastEnable)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "EUI64Enable", pEntry->Cfg.EUI64Enable)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "IANAAmount", pEntry->Cfg.IANAAmount)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "StartAddress", pEntry->Cfg.StartAddress)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServersEnabled", pEntry->Cfg.X_RDKCENTRAL_COM_DNSServersEnabled)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, "", 0, "X_RDKCENTRAL_COM_DNSServers", pEntry->Cfg.X_RDKCENTRAL_COM_DNSServers)
    char l_cSecWebUI_Enabled[8] = {0};
    syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));
    if ( '\0' == pEntry->Cfg.X_RDKCENTRAL_COM_DNSServers[ 0 ] )
    {
        if (!strncmp(l_cSecWebUI_Enabled, "true", 4)){
            pEntry->Cfg.X_RDKCENTRAL_COM_DNSServersEnabled = 1;
        }
        else {
            pEntry->Cfg.X_RDKCENTRAL_COM_DNSServersEnabled = 0;
        }
    }


    Utopia_Free(&utctx,0);

    return;
}


void setpooloption_into_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index, PUCHAR table2Name, ULONG table2Index, PCOSA_DML_DHCPSV6_POOL_OPTION pEntry )
{
    UtopiaContext utctx = {0};

    if (!Utopia_Init(&utctx))
        return;

    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "InstanceNumber", pEntry->InstanceNumber)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "alias", pEntry->Alias)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Tag", pEntry->Tag)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "PassthroughClient", pEntry->PassthroughClient)
    SETS_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Value", pEntry->Value)
    SETI_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "bEnabled", pEntry->bEnabled)

    Utopia_Free(&utctx,1);

    return;
}

void unsetpooloption_from_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index, PUCHAR table2Name, ULONG table2Index )
{
    UtopiaContext utctx = {0};

    if (!Utopia_Init(&utctx))
        return;

    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "InstanceNumber" )
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "alias")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Tag")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "PassthroughClient")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Value")
    UNSET_INTO_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "bEnabled")

    Utopia_Free(&utctx,1);

    return;
}

void getpooloption_from_utopia( PUCHAR uniqueName, PUCHAR table1Name, ULONG table1Index, PUCHAR table2Name, ULONG table2Index, PCOSA_DML_DHCPSV6_POOL_OPTION pEntry )

{
    UtopiaContext utctx = {0};

    if (!Utopia_Init(&utctx))
        return;

    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "InstanceNumber", pEntry->InstanceNumber)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "alias", pEntry->Alias)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Tag", pEntry->Tag)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "PassthroughClient", pEntry->PassthroughClient)
    GETS_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "Value", pEntry->Value)
    GETI_FROM_UTOPIA(uniqueName, table1Name, table1Index, table2Name, table2Index, "bEnabled", pEntry->bEnabled)

    Utopia_Free(&utctx,0);

    return;
}

/* Server global variable  End*/

static int _dibbler_client_operation(char * arg);

static COSA_DML_DHCPCV6_FULL  g_dhcpv6_client = {.Cfg.bEnabled = 0};

#ifdef DHCPV6_SERVER_SUPPORT
extern int _dibbler_server_operation(char * arg);
extern void _cosa_dhcpsv6_refresh_config();
extern int CosaDmlDHCPv6sTriggerRestart(BOOL OnlyTrigger);
//extern int CosaDmlDhcpv6sRestartOnLanStarted(void * arg);
#endif

#define DHCPS6V_SERVER_RESTART_FIFO "/tmp/ccsp-dhcpv6-server-restart-fifo.txt"

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(_CBR_PRODUCT_REQ_) && ! defined(_BCI_FEATURE_REQ)

#else
ANSC_STATUS
CosaDmlDhcpv6SMsgHandler
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char ret[16] = {0};

    /*We may restart by DM manager when pam crashed. We need to get current two status values */
    ifl_get_event("lan-status", ret, sizeof(ret));
    if ( !strncmp(ret, "started", strlen("started") ) ) {
        DHCPVS_DEBUG_PRINT
        g_lan_ready = TRUE;
    }

    ifl_get_event("ipv6_prefix", ret, sizeof(ret));
    if (strlen(ret) > 3) {
        DHCPVS_DEBUG_PRINT
        g_dhcpv6_server_prefix_ready = TRUE;
    }

    /*we start a thread to hear dhcpv6 server messages */
    if ( !mkfifo(DHCPS6V_SERVER_RESTART_FIFO, 0666) || errno == EEXIST )
    {
	#ifdef DHCPV6_SERVER_SUPPORT
        if (pthread_create(&g_be_ctx.dbgthrds, NULL, dhcpv6s_dbg_thrd, NULL)  || pthread_detach(g_be_ctx.dbgthrds))
            DHCPMGR_LOG_WARNING("%s error in creating dhcpv6s_dbg_thrd\n", __FUNCTION__);
        #endif
    }

#ifdef RA_MONITOR_SUPPORT
    FILE *fp     = NULL;
    /* Start RA listening utility(ipv6rtmon) */
    fp = popen("/usr/bin/ipv6rtmon &", "r");
    if(!fp)
    {
        DHCPMGR_LOG_WARNING("[%s-%d]Failed to satrt ipv6rtmon.\n", __FUNCTION__, __LINE__)
    }
    else
    {
        pclose(fp);
    }

    /* Spawning thread for assessing Router Advertisement message from FIFO file written by ipv6rtmon daemon */
    if ( !mkfifo(RA_COMMON_FIFO, 0666) || errno == EEXIST )
    {
        if (pthread_create(&g_be_ctx.dbgthrd_rtadv, NULL, rtadv_dbg_thread, NULL)  || pthread_detach(g_be_ctx.dbgthrd_rtadv))
            DHCPMGR_LOG_WARNING("%s error in creating rtadv_dbg_thread\n", __FUNCTION__);
    }
#endif // RA_MONITOR_SUPPORT

    return 0;
}

int CosaDmlDhcpv6sRestartOnLanStarted(void * arg)
{
    UNREFERENCED_PARAMETER(arg);
    DHCPMGR_LOG_WARNING("%s -- lan status is started. \n", __FUNCTION__);
    g_lan_ready = TRUE;

#if defined(_CBR_PRODUCT_REQ_)
    // TCCBR-3353: dibbler-server is failing because brlan's IP address is "tentative".
    // Add a delay so the IP address has time to become "prefered".
    sleep(2);
#endif

#ifdef RDKB_EXTENDER_ENABLED
    {
        char buf[8] ={0};
        int deviceMode = 0;

        memset(buf,0,sizeof(buf));
        if (0 == syscfg_get(NULL, "Device_Mode", buf, sizeof(buf)))
        {
            deviceMode = atoi(buf);
        }

        DHCPMGR_LOG_WARNING("%s -- %d Device Mode %d \n", __FUNCTION__, __LINE__,deviceMode);
        //dont start dibbler server in extender mode.
        if (deviceMode == DEVICE_MODE_EXTENDER)
        {
            return 0;
        }
    }
#endif

#if defined(_HUB4_PRODUCT_REQ_)
    g_dhcpv6_server_prefix_ready = TRUE; // To start dibbler server while lan-statues value is 'started'
    /* we have to start the dibbler client on Box bootup even without wan-connection
     * This needs to call dibbler-stop action, before dibbler-start */
#ifdef DHCPV6_SERVER_SUPPORT
    CosaDmlDHCPv6sTriggerRestart(FALSE);
    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

#else

#ifdef DHCPV6_SERVER_SUPPORT
    DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(TRUE)...\n", __FUNCTION__, __LINE__);
    CosaDmlDHCPv6sTriggerRestart(TRUE);
    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "1", 0);
#endif

#endif
    //the thread will start dibbler if need

    return 0;
}

#endif

ANSC_STATUS
CosaDmlDhcpv6Init
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext
    )
{
    UNREFERENCED_PARAMETER(hDml);
    UNREFERENCED_PARAMETER(phContext);
    UtopiaContext utctx = {0};
    ULONG         Index = 0;
    ULONG         Index2 = 0;
    //DSLHDMAGNT_CALLBACK *  pEntry = NULL;
    char         value[32] = {0};
    BOOLEAN		 bIsChangesHappened = FALSE;
    errno_t     rc = -1;

    /* Server Part Beginning */

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
#ifdef _HUB4_PRODUCT_REQ_
    /* Dibbler-init is called to set the pre-configuration for dibbler */
    DHCPMGR_LOG_INFO("%s dibbler-init.sh Called \n", __func__);
    v_secure_system("/lib/rdk/dibbler-init.sh");
#endif
    GETI_FROM_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "serverenable", g_dhcpv6_server)

    /*We need enable dhcpv6 for 1.5.1 and above by default*/
    Utopia_RawGet(&utctx,NULL, "router_enabledhcpv6_DoOnce",value,sizeof(value));
    if ( !g_dhcpv6_server && value[0]!= '1' )
    {
        g_dhcpv6_server = 1;
        SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "serverenable", g_dhcpv6_server)
    }

    if ( value[0] != '1' )
    {
        Utopia_RawSet(&utctx,NULL,"router_enabledhcpv6_DoOnce","1");
    }

    GETI_FROM_UTOPIA(DHCPV6S_NAME,    "", 0, "", 0, "servertype",   g_dhcpv6_server_type)
    GETI_FROM_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "poolnumber", uDhcpv6ServerPoolNum)

    if (uDhcpv6ServerPoolNum > DHCPV6S_POOL_NUM) {
        uDhcpv6ServerPoolNum = DHCPV6S_POOL_NUM;
		bIsChangesHappened = TRUE;
    }

#ifndef _HUB4_PRODUCT_REQ_
    /*This logic code is used to change default behavior to stateful dhcpv6 server */
    Utopia_RawGet(&utctx,NULL, "router_statefuldhcpv6_DoOnce",value,sizeof(value));
    if ( value[0]!= '1'  && g_dhcpv6_server_type == 2 )
    {
        g_dhcpv6_server_type = 1;
        Utopia_RawSet(&utctx,NULL,"router_other_flag","1");
        Utopia_RawSet(&utctx,NULL,"router_managed_flag","1");
        SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "servertype", g_dhcpv6_server_type)

        commonSyseventSet("zebra-restart", "");
    }
#endif

    if ( value[0]!= '1' )
    {
        Utopia_RawSet(&utctx,NULL,"router_statefuldhcpv6_DoOnce","1");
    }

    Utopia_Free(&utctx,1);

        /*  Set server pool when changed case */
        if( TRUE == bIsChangesHappened )
        {
                if (!Utopia_Init(&utctx))
                       return ANSC_STATUS_FAILURE;
        SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "poolnumber", uDhcpv6ServerPoolNum)
                Utopia_Free(&utctx,1);
        }

    /*  Out-of-bounds read
    ** Maximum size of Dhcp Server Pool and DHCP Server Pool Option Number
    ** is defined as DHCPV6S_POOL_NUM. Limiting max number w.r.t global variables defined.
    */
    for ( Index = 0; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++ )
    {
        getpool_from_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index, &sDhcpv6ServerPool[Index]);

        if (!Utopia_Init(&utctx))
            return ANSC_STATUS_FAILURE;
        GETI_FROM_UTOPIA(DHCPV6S_NAME,  "pool", Index, "", 0, "optionnumber", uDhcpv6ServerPoolOptionNum[Index])
        Utopia_Free(&utctx,0);

        for( Index2 = 0; (Index2 < uDhcpv6ServerPoolOptionNum[Index]) && (Index2 < DHCPV6S_POOL_OPTION_NUM); Index2++ )
        {
            getpooloption_from_utopia((PUCHAR)DHCPV6S_NAME,(PUCHAR)"pool",Index,(PUCHAR)"option",Index2,&sDhcpv6ServerPoolOption[Index][Index2]);
        }
    }

    if ( uDhcpv6ServerPoolNum == 0 )
    {
        uDhcpv6ServerPoolNum = 1;

        AnscZeroMemory( &sDhcpv6ServerPool[0], sizeof(sDhcpv6ServerPool[0]));
        sDhcpv6ServerPool[0].Cfg.InstanceNumber = 1;
        rc = sprintf_s((char*)sDhcpv6ServerPool[0].Cfg.Alias, sizeof(sDhcpv6ServerPool[0].Cfg.Alias), "Pool%d", 1);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        sDhcpv6ServerPool[0].Cfg.bEnabled = TRUE; //By default it's TRUE because we will use stateless DHCPv6 server at lease.
        sDhcpv6ServerPool[0].Cfg.Order = 1;
        sDhcpv6ServerPool[0].Info.Status  = COSA_DML_DHCP_STATUS_Disabled;
        sDhcpv6ServerPool[0].Cfg.IANAEnable = FALSE;
        sDhcpv6ServerPool[0].Cfg.IAPDEnable = FALSE;
        sDhcpv6ServerPool[0].Cfg.IAPDAddLength = 64; // actually, this is subnet mask
        sDhcpv6ServerPool[0].Cfg.SourceAddressExclude = FALSE;
        sDhcpv6ServerPool[0].Cfg.DUIDExclude = FALSE;
        sDhcpv6ServerPool[0].Cfg.VendorClassIDExclude = FALSE;
        sDhcpv6ServerPool[0].Cfg.UserClassIDExclude= FALSE;
        sDhcpv6ServerPool[0].Cfg.X_RDKCENTRAL_COM_DNSServersEnabled = FALSE;

        if (!Utopia_Init(&utctx))
            return ANSC_STATUS_FAILURE;
        SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "poolnumber", uDhcpv6ServerPoolNum)
        Utopia_Free(&utctx,1);

        setpool_into_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", 0, &sDhcpv6ServerPool[0]);
    }

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "serverenable", g_dhcpv6_server)
    Utopia_Free(&utctx,1);

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(_CBR_PRODUCT_REQ_) && ! defined(_BCI_FEATURE_REQ)

#else

    /*register callback function to handle message from wan dchcp6 client */
    /* CosaDmlDhcpv6SMsgHandler will be directly called from CosaDhcpv6Initialize
    pEntry = (PDSLHDMAGNT_CALLBACK)AnscAllocateMemory(sizeof(*pEntry));
    pEntry->func = CosaDmlDhcpv6SMsgHandler;
    g_RegisterCallBackAfterInitDml(g_pDslhDmlAgent, pEntry);
   */
    /*register callback function to restart dibbler-server at right time*/
    DHCPMGR_LOG_WARNING("%s -- %d register lan-status to event dispatcher \n", __FUNCTION__, __LINE__);
    EvtDispterRgstCallbackForEvent("lan-status", CosaDmlDhcpv6sRestartOnLanStarted, NULL);
#endif

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the number of DHCP clients in the system.
 */
ULONG
CosaDmlDhcpv6cGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
#ifdef DHCPV6C_PSM_ENABLE
    int retPsmGet        = CCSP_SUCCESS;
    char param_name[512] = {0};
    char* param_value    = NULL;
    if(g_Dhcp6ClientNum > 0)
    return g_Dhcp6ClientNum;

    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, PSM_DHCPMANAGER_DHCPV6C_CLIENTCOUNT, NULL, &param_value);
    if (retPsmGet != CCSP_SUCCESS) {
        DHCPMGR_LOG_ERROR("%s Error %d writing %s %s\n", __FUNCTION__, retPsmGet, param_name, param_value);
        return 0;
    }
    else
    {
        g_Dhcp6ClientNum = atoi(param_value);
        return g_Dhcp6ClientNum;
    }
#else
    return 1;
#endif
}

/*
    Description:
        The API retrieves the complete info of the DHCP clients designated by index. The usual process is the caller gets the total number of entries, then iterate through those by calling this API.
    Arguments:
        ulIndex        Indicates the index number of the entry.
        pEntry        To receive the complete info of the entry.
*/
static int _get_client_duid(UCHAR * out, int len)
{
    char buf[256] = {0};
    FILE * fp = fopen(CLIENT_DUID_FILE, "r+");
    int  i = 0;
    int  j = 0;

    if(fp)
    {
        fgets(buf, sizeof(buf), fp);

        if(buf[0])
        {
            while(j<len && buf[i])
            {
                if (buf[i] != ':')
                    out[j++] = buf[i];

                i++;
            }
        }
        fclose(fp);
    }

    return 0;
}


ANSC_STATUS
CosaDmlDhcpv6cGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPCV6_FULL      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
#ifdef DHCPV6C_PSM_ENABLE
    char param_name[256]  = {0};
    char param_value[256] = {0};
    int retPsmGet = CCSP_SUCCESS;
    //char DhcpStateSys[64] = {0};
    /* Cfg Memebers */
    pEntry->Cfg.InstanceNumber = ulIndex;

    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_CLIENTALIAS, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
         STRCPY_S_NOCLOBBER((CHAR *)pEntry->Cfg.Alias, sizeof(pEntry->Cfg.Alias), param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_REQADDR, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strcmp("TRUE",param_value) == 0)
        {
            pEntry->Cfg.RequestAddresses = TRUE;
        }
        else
        {
            pEntry->Cfg.RequestAddresses = FALSE;
        }
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_REQPREFIX, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strcmp("TRUE",param_value) == 0)
        {
            pEntry->Cfg.RequestPrefixes = TRUE;
        }
        else
        {
            pEntry->Cfg.RequestPrefixes = FALSE;
        }
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_RAPIDCOMMIT, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        if (strcmp("TRUE",param_value) == 0)
        {
            pEntry->Cfg.RapidCommit = TRUE;
        }
        else
        {
            pEntry->Cfg.RapidCommit = FALSE;
        }
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_T1, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        pEntry->Cfg.SuggestedT1 = atoi(param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_T2, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        pEntry->Cfg.SuggestedT2 = atoi(param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_REQUESTEDOPTIONS, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        STRCPY_S_NOCLOBBER((CHAR *)pEntry->Cfg.RequestedOptions, sizeof(pEntry->Cfg.RequestedOptions), param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_SUPPORTEDOPTIONS, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        STRCPY_S_NOCLOBBER((CHAR *)pEntry->Info.SupportedOptions, sizeof(pEntry->Info.SupportedOptions), param_value);
    }
#else
    UtopiaContext utctx = {0};
    char buf[256] = {0};
    char out[256] = {0};
    errno_t rc = -1;
    
    if (ulIndex)
        return ANSC_STATUS_FAILURE;

    pEntry->Cfg.InstanceNumber = 1;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    pEntry->Cfg.SuggestedT1 = pEntry->Cfg.SuggestedT2 = 0;

    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_t1");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    sscanf(out, "%lu", &pEntry->Cfg.SuggestedT1);

    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_t2");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    sscanf(out, "%lu", &pEntry->Cfg.SuggestedT2);

    /*pEntry->Cfg.Interface stores interface name, dml will calculate the full path name*/
    rc = strcpy_s((char*)pEntry->Cfg.Interface, sizeof(pEntry->Cfg.Interface), COSA_DML_DHCPV6_CLIENT_IFNAME);
    ERR_CHK(rc);

    rc = sprintf_s((char*)pEntry->Cfg.Alias, sizeof(pEntry->Cfg.Alias), "cpe-%s", pEntry->Cfg.Interface);
    ERR_CHK(rc);
    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_requested_options");
    ERR_CHK(rc);
    memset(pEntry->Cfg.RequestedOptions, 0, sizeof(pEntry->Cfg.RequestedOptions));
    Utopia_RawGet(&utctx,NULL,buf,(char*)pEntry->Cfg.RequestedOptions,sizeof(pEntry->Cfg.RequestedOptions));

    /*rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_enabled");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    pEntry->Cfg.bEnabled = (out[0] == '1') ? TRUE:FALSE;*/

    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_iana_enabled");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    pEntry->Cfg.RequestAddresses = (out[0] == '1') ? TRUE:FALSE;

    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_iapd_enabled");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    pEntry->Cfg.RequestPrefixes = (out[0] == '1') ? TRUE:FALSE;

    rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_rapidcommit_enabled");
    ERR_CHK(rc);
    memset(out, 0, sizeof(out));
    Utopia_RawGet(&utctx,NULL,buf,out,sizeof(out));
    pEntry->Cfg.RapidCommit = (out[0] == '1') ? TRUE:FALSE;

    Utopia_Free(&utctx,0);
#endif

    if (pEntry->Cfg.bEnabled)
    {
       pEntry->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
    }
    else
    {
        pEntry->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
    }

    /*TODO: supported options*/

    _get_client_duid(pEntry->Info.DUID, sizeof(pEntry->Info.DUID));

    AnscCopyMemory(&g_dhcpv6_client, pEntry, sizeof(g_dhcpv6_client));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cSetValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    UtopiaContext utctx = {0};
    errno_t rc = -1;

    if (ulIndex)
        return ANSC_STATUS_FAILURE;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;



    rc = strcpy_s((char*)g_dhcpv6_client.Cfg.Alias, sizeof(g_dhcpv6_client.Cfg.Alias), pAlias);
    ERR_CHK(rc);
    Utopia_RawSet(&utctx,NULL,SYSCFG_FORMAT_DHCP6C"_alias",pAlias);

    Utopia_Free(&utctx,1);

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API adds DHCP client.
    Arguments:
        pEntry        Caller fills in pEntry->Cfg, except Alias field. Upon return, callee fills pEntry->Cfg.Alias field and as many as possible fields in pEntry->Info.
*/
ANSC_STATUS
CosaDmlDhcpv6cAddEntry
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_FULL        pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(pEntry);
    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API removes the designated DHCP client entry.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
CosaDmlDhcpv6cDelEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    return ANSC_STATUS_SUCCESS;
}

void _get_shell_output(FILE *fp, char * buf, int len);
int _get_shell_output2(FILE *fp, char * dststr);

static int _dibbler_client_operation(char * arg)
{
#if defined(INTEL_PUMA7)
    FILE *fp = NULL;
    char out[256] = {0};
    int watchdog = NO_OF_RETRY;
#endif

    if (!strncmp(arg, "stop", 4))
    {
        DHCPMGR_LOG_INFO("%s stop\n", __func__);
        /*TCXB6 is also calling service_dhcpv6_client.sh but the actuall script is installed from meta-rdk-oem layer as the intel specific code
                   had to be removed */
#if defined (FEATURE_RDKB_DHCP_MANAGER) || defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX)
        commonSyseventSet("dhcpv6_client-stop", "");
#endif

#if defined (_COSA_BCM_ARM_) && !defined (FEATURE_RDKB_DHCP_MANAGER)
        v_secure_system("killall " CLIENT_BIN);
        sleep(2);
        v_secure_system("killall -9 " CLIENT_BIN);
#endif
    }
    else if (!strncmp(arg, "start", 5))
    {
        DHCPMGR_LOG_INFO("%s start\n", __func__);

#if defined(INTEL_PUMA7)
        //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
        /* Waiting for the TLV file to be parsed correctly so that the right erouter mode can be used in the code below.
        For ANYWAN please extend the below code to support the case of TLV config file not being there. */
      do{
         fp = v_secure_popen("r", "sysevent get TLV202-status");
         _get_shell_output(fp, out, sizeof(out));
         fprintf( stderr, "\n%s:%s(): Waiting for CcspGwProvApp to parse TLV config file", __FILE__);
         sleep(1);//sleep(1) is to avoid lots of trace msgs when there is latency
         watchdog--;
        }while((!strstr(out,"success")) && (watchdog != 0));

        if(watchdog == 0)
        {
            //When 60s have passed and the file is still not configured by CcspGwprov module
            DHCPMGR_LOG_INFO("\n%s()%s(): TLV data has not been initialized by CcspGwProvApp.Continuing with the previous configuration",__FILE__);
        }
#endif
        /*This is for ArrisXB6 */
        /*TCXB6 is also calling service_dhcpv6_client.sh but the actuall script is installed from meta-rdk-oem layer as the intel specific code
         had to be removed */
#if defined (FEATURE_RDKB_DHCP_MANAGER) || defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX)
        commonSyseventSet("dhcpv6_client-start", "");
#endif

#if defined (_COSA_BCM_ARM_) && !defined (FEATURE_RDKB_DHCP_MANAGER)
        //Dibbler-init is called to set the pre-configuration for dibbler
        DHCPMGR_LOG_INFO("%s dibbler-init.sh Called \n", __func__);
        v_secure_system("/lib/rdk/dibbler-init.sh");
        //Start Dibber client for tchxb6
        DHCPMGR_LOG_INFO("%s Dibbler Client Started \n", __func__);
        v_secure_system("/usr/sbin/dibbler-client start");
#endif
    }
    else if (!strncmp(arg, "restart", 7))
    {
        _dibbler_client_operation("stop");
        _dibbler_client_operation("start");
    }

    return 0;
}

#ifdef DHCPV6C_COMS

/*
Description:
    The API re-configures the designated DHCP client entry.
Arguments:
    pAlias        The entry is identified through Alias.
    pEntry        The new configuration is passed through this argument, even Alias field can be changed.
*/
ANSC_STATUS
CosaDmlDhcpv6cSetCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_CFG       pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    char buf[256] = {0};
    char out[256] = {0};
    int  need_to_restart_service = 0;
    errno_t rc = -1;

    if (pCfg->InstanceNumber != 1)
        return ANSC_STATUS_FAILURE;

    /*handle syscfg*/
    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;


    if (strcmp((char*)pCfg->Alias, (char*)g_dhcpv6_client.Cfg.Alias) != 0)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_alias");
        ERR_CHK(rc);
        Utopia_RawSet(&utctx,NULL,buf,(char*)pCfg->Alias);
    }

    if (pCfg->SuggestedT1 != g_dhcpv6_client.Cfg.SuggestedT1)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_t1");
        ERR_CHK(rc);
        rc = sprintf_s(out, sizeof(out), "%lu", pCfg->SuggestedT1);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        Utopia_RawSet(&utctx,NULL,buf,out);
        need_to_restart_service = 1;
    }

    if (pCfg->SuggestedT2 != g_dhcpv6_client.Cfg.SuggestedT2)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_t2");
        ERR_CHK(rc);
        rc = sprintf_s(out, sizeof(out), "%lu", pCfg->SuggestedT2);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        Utopia_RawSet(&utctx,NULL,buf,out);
        need_to_restart_service = 1;
    }

    if (strcmp((char*)pCfg->RequestedOptions, (char*)g_dhcpv6_client.Cfg.RequestedOptions) != 0)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_requested_options");
        ERR_CHK(rc);
        Utopia_RawSet(&utctx,NULL,buf,(char*)pCfg->RequestedOptions);
        need_to_restart_service = 1;
    }

    if (pCfg->bEnabled != g_dhcpv6_client.Cfg.bEnabled)
    {
        /*rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_enabled");
        ERR_CHK(rc);
        out[0] = pCfg->bEnabled ? '1':'0';
        out[1] = 0;
        Utopia_RawSet(&utctx,NULL,buf,out);*/
        need_to_restart_service = 1;
    }

    if (pCfg->RequestAddresses != g_dhcpv6_client.Cfg.RequestAddresses)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_iana_enabled");
        ERR_CHK(rc);
        out[0] = pCfg->RequestAddresses ? '1':'0';
        out[1] = 0;
        Utopia_RawSet(&utctx,NULL,buf,out);
        need_to_restart_service = 1;
    }

    if (pCfg->RequestPrefixes != g_dhcpv6_client.Cfg.RequestPrefixes)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_iapd_enabled");
        ERR_CHK(rc);
        out[0] = pCfg->RequestPrefixes ? '1':'0';
        out[1] = 0;
        Utopia_RawSet(&utctx,NULL,buf,out);
        need_to_restart_service = 1;
    }

    if (pCfg->RapidCommit != g_dhcpv6_client.Cfg.RapidCommit)
    {
        rc = strcpy_s(buf, sizeof(buf), SYSCFG_FORMAT_DHCP6C"_rapidcommit_enabled");
        ERR_CHK(rc);
        out[0] = pCfg->RapidCommit ? '1':'0';
        out[1] = 0;
        Utopia_RawSet(&utctx,NULL,buf,out);
        need_to_restart_service = 1;
    }

    Utopia_Free(&utctx,1);

    AnscCopyMemory(&g_dhcpv6_client.Cfg, pCfg, sizeof(COSA_DML_DHCPCV6_CFG));

    return ANSC_STATUS_SUCCESS;
}

#endif

ANSC_STATUS
CosaDmlDhcpv6cGetCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPCV6_CFG       pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    /*for rollback*/
    if (pCfg->InstanceNumber != 1)
        return ANSC_STATUS_FAILURE;

    AnscCopyMemory(pCfg,  &g_dhcpv6_client.Cfg, sizeof(COSA_DML_DHCPCV6_CFG));

    return ANSC_STATUS_SUCCESS;
}


#define CLIENT_SERVER_INFO_FILE "/tmp/.dibbler-info/client_server"
/*this file's format:
 line 1: addr server_ipv6_addr
 line 2: duid server_duid*/
/* this memory need to be freed by caller */
ANSC_STATUS
CosaDmlDhcpv6cGetServerCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SVR      *ppCfg,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    FILE * fp = fopen(CLIENT_SERVER_INFO_FILE, "r+");

    *pSize = 0;
    if (fp)
    {
        char buf[1024];
        char val[1024];
        int  entry_count = 0;
        errno_t rc = -1;

        /*we only support one entry of ServerCfg*/
        *ppCfg = (PCOSA_DML_DHCPCV6_SVR)AnscAllocateMemory( sizeof(COSA_DML_DHCPCV6_SVR) );

        /*InformationRefreshTime not supported*/
        rc = strcpy_s((char*)(*ppCfg)->InformationRefreshTime, sizeof((*ppCfg)->InformationRefreshTime), "0001-01-01T00:00:00Z");
        ERR_CHK(rc);

        while(fgets(buf, sizeof(buf), fp))
        {
            if (sscanf(buf, "addr %s", val) == 1)
            {
                rc = strncpy_s((char*)(*ppCfg)->SourceAddress, sizeof((*ppCfg)->SourceAddress), val, sizeof((*ppCfg)->SourceAddress) - 1);
                ERR_CHK(rc);
                entry_count |= 1;
            }
            else if (sscanf(buf, "duid %s", val) == 1)
            {
                unsigned int i = 0, j = 0;
                /*the file stores duid in this format 00:01:..., we need to transfer it to continuous hex*/

                for (i=0; i<strlen(val) && j < sizeof((*ppCfg)->DUID)-1; i++)
                {
                    if (val[i] != ':')
                        ((*ppCfg)->DUID)[j++] = val[i];
                }

                entry_count |= 2;
            }

            /*only we have both addr and  duid we think we have a whole server-info*/
            if (entry_count == 3)
                *pSize = 1;

        }
        fclose(fp);
    }

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API initiates a DHCP client renewal.
    Arguments:
        pAlias        The entry is identified through Alias.
*/
ANSC_STATUS
CosaDmlDhcpv6cRenew
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulInstanceNumber);
    _dibbler_client_operation("restart");
    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Client Send/Req Option
 *
 *  The options are managed on top of a DHCP client,
 *  which is identified through pClientAlias
 */
#define SYSCFG_DHCP6C_SENT_OPTION_FORMAT "tr_dhcp6c_sent_option_%lu"
static int g_sent_option_num;
static COSA_DML_DHCPCV6_SENT * g_sent_options;
int g_recv_option_num   = 0;

COSA_DML_DHCPCV6_RECV * g_recv_options = NULL;

ULONG
CosaDmlDhcpv6cGetNumberOfSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
#ifndef DHCPV6C_PSM_ENABLE 
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UtopiaContext utctx = {0};
    char out[256];

    if (!Utopia_Init(&utctx))
        return 0;

    out[0] = 0;
    Utopia_RawGet(&utctx,NULL,"tr_dhcp6c_sent_option_num",out,sizeof(out));

    Utopia_Free(&utctx, 0);

    g_sent_option_num = atoi(out);

    if (g_sent_option_num)
        g_sent_options = (COSA_DML_DHCPCV6_SENT *)AnscAllocateMemory(sizeof(COSA_DML_DHCPCV6_SENT)* g_sent_option_num);

    return g_sent_option_num;

#else /* DHCPV6C_PSM_ENABLE */
    int retPsmGet = CCSP_SUCCESS;
    char param_name[256]  = {0};
    char param_value[256] = {0};

    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_SENDOPTIONCOUNT, (INT)ulClientInstanceNumber);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS) {
       return atoi(param_value);
    }
    else
      return 0;
#endif /* DHCPV6C_PSM_ENABLE */
}

#define CLIENT_SENT_OPTIONS_FILE "/tmp/.dibbler-info/client_sent_options"
/*this function will generate sent_option info file to dibbler-client,
 the format of CLIENT_SENT_OPTIONS_FILE:
    option-type:option-len:option-data*/
static int _write_dibbler_sent_option_file(void)
{
    FILE * fp = fopen(CLIENT_SENT_OPTIONS_FILE, "w+");
    int  i = 0;

    if (fp)
    {
        for (i=0; i<g_sent_option_num; i++)
        {
            if (g_sent_options[i].bEnabled)
                fprintf(fp, "%lu:%zu:%s\n",
                        g_sent_options[i].Tag,
                        strlen((const char*)g_sent_options[i].Value)/2,
                        g_sent_options[i].Value);
        }

        fclose(fp);
    }

    return 0;
}

ANSC_STATUS
CosaDmlDhcpv6cGetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
#ifndef DHCPV6C_PSM_ENABLE
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    UtopiaContext utctx = {0};
    char out[256];
    char namespace[256];
    errno_t rc = -1;

    if ( (int)ulIndex > g_sent_option_num - 1  || !g_sent_options)
        return ANSC_STATUS_FAILURE;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    /*note in syscfg, sent_options start from 1*/
    rc = sprintf_s(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, ulIndex+1);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    out[0] = 0;
    Utopia_RawGet(&utctx, namespace, "inst_num" ,out,sizeof(out));
    sscanf(out, "%lu", &pEntry->InstanceNumber);

    Utopia_RawGet(&utctx, namespace, "alias" ,(char*)pEntry->Alias, sizeof(pEntry->Alias));

    out[0] = 0;
    Utopia_RawGet(&utctx, namespace, "enabled" ,out,sizeof(out));
    pEntry->bEnabled = (out[0] == '1') ? TRUE:FALSE;

    out[0] = 0;
    Utopia_RawGet(&utctx, namespace, "tag" ,out,sizeof(out));
    sscanf(out, "%lu", &pEntry->Tag);

    Utopia_RawGet(&utctx, namespace, "value" ,(char*)pEntry->Value, sizeof(pEntry->Value));

    Utopia_Free(&utctx, 0);

    AnscCopyMemory( &g_sent_options[ulIndex], pEntry, sizeof(COSA_DML_DHCPCV6_SENT));

    /*we only wirte to file when obtaining the last entry*/
    if ((int)ulIndex == g_sent_option_num-1)
        _write_dibbler_sent_option_file();

#else /* DHCPV6C_PSM_ENABLE */
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256] = {0};
    char param_name[256]= {0};
    pEntry->InstanceNumber = ulIndex;
    pEntry->bEnabled = TRUE;

    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_SENDOPTIONALIAS, (INT)ulClientInstanceNumber, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        STRCPY_S_NOCLOBBER((CHAR *)pEntry->Alias, sizeof(pEntry->Alias), param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_SENDOPTIONTAG, (INT)ulClientInstanceNumber, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
       pEntry->Tag = atoi(param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DHCPMANAGER_DHCPV6C_SENDOPTIONVALUE, (INT)ulClientInstanceNumber, (INT)ulIndex);
    retPsmGet = PsmReadParameter(param_name, param_value, sizeof(param_value));
    if (retPsmGet == CCSP_SUCCESS)
    {
        STRCPY_S_NOCLOBBER((CHAR *)pEntry->Value, sizeof(pEntry->Value), param_value);
    }
#endif /* DHCPV6C_PSM_ENABLE */

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cGetSentOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    int                           index  = 0;

    for( index=0;  index<g_sent_option_num; index++)
    {
        if ( pEntry->InstanceNumber == g_sent_options[index].InstanceNumber )
        {
            AnscCopyMemory( pEntry, &g_sent_options[index], sizeof(COSA_DML_DHCPCV6_SENT));
             return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
CosaDmlDhcpv6cSetSentOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    char out[16];
    char namespace[256];
    errno_t rc = -1;

    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;

    if ( (int)ulIndex+1 > g_sent_option_num )
        return ANSC_STATUS_SUCCESS;

    g_sent_options[ulIndex].InstanceNumber  = ulInstanceNumber;

    rc = STRCPY_S_NOCLOBBER((char*)g_sent_options[ulIndex].Alias, sizeof(g_sent_options[ulIndex].Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    rc = sprintf_s(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, ulIndex+1);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    snprintf(out, sizeof(out), "%lu", ulInstanceNumber);
    Utopia_RawSet(&utctx, namespace, "inst_num", out);

    Utopia_RawSet(&utctx, namespace, "alias" ,pAlias);

    Utopia_Free(&utctx, 1);

    return ANSC_STATUS_SUCCESS;
}

static int _syscfg_add_sent_option(PCOSA_DML_DHCPCV6_SENT      pEntry, int index)
{
    UtopiaContext utctx = {0};
    char out[16];
    char namespace[256];
    errno_t rc = -1;

    if (!pEntry)
        return -1;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    rc = sprintf_s(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, (ULONG)index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    snprintf(out, sizeof(out), "%lu", pEntry->InstanceNumber);
    Utopia_RawSet(&utctx, namespace, "inst_num", out );

    Utopia_RawSet(&utctx, namespace, "alias" ,(char*)pEntry->Alias);

    rc = strcpy_s(out, sizeof(out), ((pEntry->bEnabled) ? "1" : "0"));
    ERR_CHK(rc);
    Utopia_RawSet(&utctx, namespace, "enabled" ,out);

    snprintf(out, sizeof(out), "%lu", pEntry->Tag);
    Utopia_RawSet(&utctx, namespace, "tag" , out);

    Utopia_RawSet(&utctx, namespace, "value" ,(char*)pEntry->Value);

    Utopia_Free(&utctx, 1);

    return 0;
}

ANSC_STATUS
CosaDmlDhcpv6cAddSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    char out[16];
    struct _COSA_DML_DHCPCV6_SENT *realloc_tmp;

    /*we only have one client*/
    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;

    realloc_tmp = realloc(g_sent_options, (++g_sent_option_num)* sizeof(COSA_DML_DHCPCV6_SENT));
    if (!realloc_tmp)
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        g_sent_options = realloc_tmp;
    }

    _syscfg_add_sent_option(pEntry, g_sent_option_num);

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    snprintf(out, sizeof(out), "%d", g_sent_option_num);
    Utopia_RawSet(&utctx, NULL, "tr_dhcp6c_sent_option_num" ,out);
    Utopia_Free(&utctx, 1);

    g_sent_options[g_sent_option_num-1] = *pEntry;

    /*if the added entry is disabled, don't update dibbler-info file*/
    if (pEntry->bEnabled)
    {
        _write_dibbler_sent_option_file();
        _dibbler_client_operation("restart");
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cDelSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    char out[16];
    char namespace[256];
    int  i = 0;
    int  j = 0;
    int  saved_enable = 0;
    errno_t rc = -1;

    /*we only have one client*/
    if (ulClientInstanceNumber != g_dhcpv6_client.Cfg.InstanceNumber)
        return ANSC_STATUS_FAILURE;


    for (i=0; i<g_sent_option_num; i++)
    {
        if (g_sent_options[i].InstanceNumber == ulInstanceNumber)
            break;
    }

    if (i == g_sent_option_num)
        return ANSC_STATUS_CANT_FIND;

    saved_enable = g_sent_options[i].bEnabled;

    for (j=i; j<g_sent_option_num-1; j++)
    {
        g_sent_options[j] = g_sent_options[j+1];

        /*move syscfg ahead to fill in the deleted one*/
        _syscfg_add_sent_option(g_sent_options+j+1, j+1);
    }

    g_sent_option_num--;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    /*syscfg unset the last one, since we move the syscfg table ahead*/
    rc = sprintf_s(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, (ULONG)(g_sent_option_num+1));
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    syscfg_unset(namespace, "inst_num");
    syscfg_unset(namespace, "alias");
    syscfg_unset(namespace, "enabled");
    syscfg_unset(namespace, "tag");
    syscfg_unset(namespace, "value");

    snprintf(out, sizeof(out), "%d", g_sent_option_num);
    Utopia_RawSet(&utctx, NULL, "tr_dhcp6c_sent_option_num" ,out);

    Utopia_Free(&utctx, 1);

    /*only take effect when the deleted entry was enabled*/
    if (saved_enable)
    {
        _write_dibbler_sent_option_file();
        _dibbler_client_operation("restart");
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6cSetSentOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_SENT      pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    ULONG                           index  = 0;
    UtopiaContext                   utctx = {0};
    char                            out[16];
    char                            namespace[256];
    int                             need_restart_service = 0;
    PCOSA_DML_DHCPCV6_SENT          p_old_entry = NULL;
    errno_t                         rc = -1;

    for( index=0;  (int)index<g_sent_option_num; index++)
    {
        if ( pEntry->InstanceNumber == g_sent_options[index].InstanceNumber )
        {
            p_old_entry = &g_sent_options[index];

            if (!Utopia_Init(&utctx))
                return ANSC_STATUS_FAILURE;

            /*handle syscfg*/
            rc = sprintf_s(namespace, sizeof(namespace), SYSCFG_DHCP6C_SENT_OPTION_FORMAT, index+1);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            if (strcmp((char*)pEntry->Alias, (char*)p_old_entry->Alias) != 0)
                Utopia_RawSet(&utctx, namespace, "alias" ,(char*)pEntry->Alias);

            if (pEntry->bEnabled != p_old_entry->bEnabled)
            {
                rc = strcpy_s(out, sizeof(out), ((pEntry->bEnabled) ? "1" : "0"));
                ERR_CHK(rc);
                Utopia_RawSet(&utctx, namespace, "enabled" ,out);

                need_restart_service = 1;
            }


            if (pEntry->Tag != p_old_entry->Tag)
            {
                snprintf(out, sizeof(out), "%lu", pEntry->Tag);
                Utopia_RawSet(&utctx, namespace, "tag" , out);

                need_restart_service = 1;
            }

            if (strcmp((char*)pEntry->Value, (char*)p_old_entry->Value) != 0)
            {
                Utopia_RawSet(&utctx, namespace, "value" ,(char*)pEntry->Value);

                need_restart_service = 1;
            }

            Utopia_Free(&utctx, 1);

            AnscCopyMemory( &g_sent_options[index], pEntry, sizeof(COSA_DML_DHCPCV6_SENT));

            if (need_restart_service)
            {
                _write_dibbler_sent_option_file();
                _dibbler_client_operation("restart");
            }

            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* This is to get all
 */
#define CLIENT_RCVED_OPTIONS_FILE "/tmp/.dibbler-info/client_received_options"
/*this file has the following format:
 ......
 line n : opt-len opt-type opt-data(HexBinary)
 ......
*/
ANSC_STATUS
CosaDmlDhcpv6cGetReceivedOptionCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulClientInstanceNumber,
        PCOSA_DML_DHCPCV6_RECV     *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulClientInstanceNumber);
    FILE *                          fp = fopen(CLIENT_RCVED_OPTIONS_FILE, "r+");
    SLIST_HEADER                    option_list;
    COSA_DML_DHCPCV6_RECV *         p_rcv = NULL;
    char                            buf[1024];
    PSINGLE_LINK_ENTRY              pSLinkEntry       = NULL;
    ULONG                           ulIndex = 0;

    AnscSListInitializeHeader( &option_list );

    if (fp)
    {
        while (fgets(buf, sizeof(buf), fp))
        {
            int  opt_len = 0;
            char * p = NULL;

            p_rcv = (COSA_DML_DHCPCV6_RECV * )AnscAllocateMemory(sizeof(*p_rcv));
            if (!p_rcv)
                break;

            if (sscanf(buf, "%d %lu", &opt_len, &p_rcv->Tag) != 2)
            {
                AnscFreeMemory(p_rcv); /* free unused resource*/
                p_rcv = NULL;
                continue;
            }

            /*don't trust opt_len record in file, calculate by self*/
            if ((p = strrchr(buf, ' ')))
            {
                p++;
                if ((unsigned int)opt_len*2 < (strlen(buf)- (p-buf)))
                    opt_len = (strlen(buf)- (p-buf))/2;
            }
            else
            {
                AnscFreeMemory(p_rcv); /* free unused resource*/
                p_rcv = NULL;
                continue;
            }

            if ((unsigned int)opt_len*2 >= sizeof(p_rcv->Value))
            {
                AnscFreeMemory(p_rcv); /* free unused resource*/
                p_rcv = NULL;
                continue;
            }

            /*finally we are safe, copy string into Value*/
            if (sscanf(buf, "%*d %*d %s", p_rcv->Value) != 1)
            {
                AnscFreeMemory(p_rcv); /* free unused resource*/
                p_rcv = NULL;
                continue;
            }
            /*we only support one server, hardcode it*/
            safe_strcpy((char*)p_rcv->Server, "Device.DHCPv6.Client.1.Server.1", sizeof(p_rcv->Server));
            AnscSListPushEntryAtBack(&option_list, &p_rcv->Link);

        }
        fclose(fp);
    }

    if (!AnscSListGetFirstEntry(&option_list))
    {
        *pSize = 0;
        return ANSC_STATUS_SUCCESS;
    }

    *ppEntry = (PCOSA_DML_DHCPCV6_RECV)AnscAllocateMemory( AnscSListQueryDepth(&option_list) *sizeof(COSA_DML_DHCPCV6_RECV) );

    pSLinkEntry = AnscSListGetFirstEntry(&option_list);

    for ( ulIndex = 0; ulIndex < option_list.Depth; ulIndex++ )
    {
        p_rcv = ACCESS_DHCPV6_RECV_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        /* CID 75064 fix */
        AnscCopyMemory( *ppEntry + ulIndex, p_rcv, (sizeof(*p_rcv)-1) );
        AnscFreeMemory(p_rcv);
    }

    *pSize = AnscSListQueryDepth(&option_list);

    /* we need keep this for reference in server*/
    if ( g_recv_options )
        AnscFreeMemory(g_recv_options);

    g_recv_option_num = *pSize;
    g_recv_options = (COSA_DML_DHCPCV6_RECV *)AnscAllocateMemory( sizeof(COSA_DML_DHCPCV6_RECV) * g_recv_option_num );
    AnscCopyMemory(g_recv_options, *ppEntry, sizeof(COSA_DML_DHCPCV6_RECV) * g_recv_option_num);

    return ANSC_STATUS_SUCCESS;
}

int remove_single_quote (char *buf)
{
  int i = 0;
  int j = 0;

  while (buf[i] != '\0' && i < 255) {
    if (buf[i] != '\'') {
      buf[j++] = buf[i];
    }
    i++;
  }
  buf[j] = '\0';
  return 0;
}

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && defined(_COSA_BCM_MIPS_)
// adding new logics to handle pd-class
static int get_ipv6_tpmode (int *tpmod)
{
  char buf[16] = { 0 };
  char fixed_buf[16] = { 0 };
  int  mode;
  int i = 0;
  int j = 0;

  // sysevent_get(si6->sefd, si6->setok, "erouter_topology-mode", buf, sizeof(buf));
  commonSyseventGet(COSA_DML_DHCPV6C_PREF_IAID_SYSEVENT_NAME, buf, sizeof(buf));
  while (buf[i] != '\0') {
    if (buf[i] != '\'') {
        fixed_buf[j++] = buf[i];
      }
      i++;
  }

  mode = atoi(fixed_buf);

  switch(mode) {
  case 1:
    *tpmod = FAVOR_DEPTH;
    break;
  case 2:
    *tpmod = FAVOR_WIDTH;
    break;
  default:
    DHCPMGR_LOG_INFO("%s: unknown erouter topology mode, buf: %s\n", __FUNCTION__, buf);
    *tpmod = TPMOD_UNKNOWN;
    break;
  }

  return 0;
}

static int get_iapd_info(ia_pd_t *iapd)
{
    char evt_val[256] = {0};
    char *st = NULL;
    errno_t rc = -1;
    if(iapd == NULL)
      return -1;

    commonSyseventGet(COSA_DML_DHCPV6C_PREF_T1_SYSEVENT_NAME, evt_val, sizeof(evt_val));
    if(evt_val[0]!='\0')
    {
      if(!strcmp(evt_val,"'\\0'"))
      {
        rc = STRCPY_S_NOCLOBBER(iapd->t1, sizeof(iapd->t1), "0");
        ERR_CHK(rc);
      }
      else
      {
        rc = STRCPY_S_NOCLOBBER(iapd->t1, sizeof(iapd->t1), strtok_r (evt_val,"'", &st));
        ERR_CHK(rc);
      }
    }
    DHCPMGR_LOG_INFO("[%s] iapd->t1: %s\n", __FUNCTION__, iapd->t1);

    commonSyseventGet(COSA_DML_DHCPV6C_PREF_T2_SYSEVENT_NAME, evt_val, sizeof(evt_val));
    st = NULL;
    if(evt_val[0]!='\0')
    {
      if(!strcmp(evt_val,"'\\0'"))
      {
        rc = STRCPY_S_NOCLOBBER(iapd->t2, sizeof(iapd->t2), "0");
        ERR_CHK(rc);
      }
      else
      {
        rc = STRCPY_S_NOCLOBBER(iapd->t2, sizeof(iapd->t2), strtok_r (evt_val,"'", &st));
        ERR_CHK(rc);
      }
    }
    DHCPMGR_LOG_INFO("[%s] iapd->t2: %s\n", __FUNCTION__, iapd->t2);

    commonSyseventGet(COSA_DML_DHCPV6C_PREF_PRETM_SYSEVENT_NAME, evt_val, sizeof(evt_val));
    st = NULL;
    if(evt_val[0]!='\0')
    {
      if(!strcmp(evt_val,"'\\0'"))
      {
        rc = STRCPY_S_NOCLOBBER(iapd->pretm, sizeof(iapd->pretm), "0");
        ERR_CHK(rc);
      }
      else
      {
        rc = STRCPY_S_NOCLOBBER(iapd->pretm, sizeof(iapd->pretm), strtok_r (evt_val,"'", &st));
        ERR_CHK(rc);
      }
    }
    DHCPMGR_LOG_INFO("[%s] iapd->pretm: %s\n", __FUNCTION__, iapd->pretm);

    st = NULL;
    if(evt_val[0]!='\0')
    {
      if(!strcmp(evt_val,"'\\0'"))
      {
        rc = STRCPY_S_NOCLOBBER(iapd->vldtm, sizeof(iapd->vldtm), "0");
        ERR_CHK(rc);
      }
      else
      {
        rc = STRCPY_S_NOCLOBBER(iapd->vldtm, sizeof(iapd->vldtm), strtok_r (evt_val,"'", &st));
        ERR_CHK(rc);
      }
    }
    DHCPMGR_LOG_INFO("[%s] iapd->vldtm: %s\n", __FUNCTION__, iapd->vldtm);

    return 0;
}

#endif

ANSC_STATUS
CosaDmlDhcpv6sEnable
    (
        ANSC_HANDLE                 hContext,
        BOOL                        bEnable
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};

    if (g_dhcpv6_server == bEnable) {
        DHCPMGR_LOG_INFO("-- %d server is :%d. bEnable:%d", __LINE__, g_dhcpv6_server, bEnable);
        return ANSC_STATUS_SUCCESS;
    }

    g_dhcpv6_server = bEnable;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "serverenable", g_dhcpv6_server)
    Utopia_Free(&utctx,1);

    #if defined(_BCI_FEATURE_REQ)
    commonSyseventSet("zebra-restart", "");
    #endif

    if ( bEnable )
    {
       #if defined(_BCI_FEATURE_REQ)
       DHCPMGR_LOG_INFO("Enable DHCPv6. Starting Dibbler-Server and Zebra Process\n");
       #endif
 
        #ifdef DHCPV6_SERVER_SUPPORT
        /* We need enable server */
        DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
        CosaDmlDHCPv6sTriggerRestart(FALSE);
	//sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
        #endif
    }
    else if ( !bEnable  )
    {
       #if defined(_BCI_FEATURE_REQ)
       DHCPMGR_LOG_INFO("Disable DHCPv6. Stopping Dibbler-Server and Zebra Process\n ");
       #endif
      /* we need disable server. */

       #if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(DHCPV6_PREFIX_FIX)
        commonSyseventSet("dhcpv6_server-stop", "");
       #else

       #ifdef DHCPV6_SERVER_SUPPORT
        _dibbler_server_operation("stop");
	//sysevent_set(sysevent_fd_server, sysevent_token_server, "dibbler_server_operation", "stop", 0);
       #endif

       #endif
    }

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the current state of DHCP server: Enabled or Disabled.
*/
BOOLEAN
CosaDmlDhcpv6sGetState
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    /*
    char cmd[256] = {0};
    char out[256] = {0};
    sprintf(cmd, "busybox ps |grep %s|grep -v grep", SERVER_BIN);
    _get_shell_output(cmd, out, sizeof(out));
    if (strstr(out, SERVER_BIN))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }*/

    return g_dhcpv6_server;
}

/*
    Description:
        The API retrieves the current type of DHCP server: STATELESS or STATEFUL.
*/
ANSC_STATUS
CosaDmlDhcpv6sSetType
    (
        ANSC_HANDLE                 hContext,
        ULONG                        type
    )
{
    UNREFERENCED_PARAMETER(hContext);
    BOOL                            bApply = FALSE;
    UtopiaContext utctx = {0};

    if ( type != g_dhcpv6_server_type )
        bApply = TRUE;

    g_dhcpv6_server_type = type;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;

    SETI_INTO_UTOPIA(DHCPV6S_NAME,  "", 0, "", 0, "servertype", g_dhcpv6_server_type)

    Utopia_Free(&utctx,1);

    /* Stateful address is not effecting for clients whenever pool range is changed.
     * Added gw_lan_refresh to effect the stateful address to the clients according
     * to the configured poll range.
     */
    v_secure_system("gw_lan_refresh");

    if ( g_dhcpv6_server && bApply )
    {
       
#ifdef DHCPV6_SERVER_SUPPORT
        /* We need enable server */
        DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
	CosaDmlDHCPv6sTriggerRestart(FALSE);
	//sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

#ifdef _HUB4_PRODUCT_REQ_
        commonSyseventSet("zebra-restart", "");
#endif
    }

    return ANSC_STATUS_SUCCESS;
}

/*
    Description:
        The API retrieves the current state of DHCP server: Enabled or Disabled.
*/
ULONG
CosaDmlDhcpv6sGetType
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    return g_dhcpv6_server_type;
}

/*
 *  DHCP Server Pool
 */
ULONG
CosaDmlDhcpv6sGetNumberOfPools
    (
        ANSC_HANDLE                 hContext
    )
{
    UNREFERENCED_PARAMETER(hContext);
    return uDhcpv6ServerPoolNum;
}

ANSC_STATUS
CosaDmlDhcpv6sGetPool
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPSV6_POOL_FULL pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    if ( ulIndex+1 > uDhcpv6ServerPoolNum )
        return ANSC_STATUS_FAILURE;

    /* CID 72229 fix */
    AnscCopyMemory(pEntry, &sDhcpv6ServerPool[ulIndex], sizeof(sDhcpv6ServerPool[ulIndex]));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sSetPoolValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    errno_t                         rc              = -1;

    if ( ulIndex+1 > uDhcpv6ServerPoolNum )
        return ANSC_STATUS_FAILURE;

    sDhcpv6ServerPool[ulIndex].Cfg.InstanceNumber  = ulInstanceNumber;

    rc = STRCPY_S_NOCLOBBER((char*)sDhcpv6ServerPool[ulIndex].Cfg.Alias, sizeof(sDhcpv6ServerPool[ulIndex].Cfg.Alias), pAlias);
    if ( rc != EOK )
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    SETI_INTO_UTOPIA(DHCPV6S_NAME, "pool", ulIndex, "", 0, "instancenumber", ulInstanceNumber)
    SETS_INTO_UTOPIA(DHCPV6S_NAME, "pool", ulIndex, "", 0, "alias", pAlias)
    Utopia_Free(&utctx,1);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sAddPool
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_FULL   pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx = {0};
    ULONG         Index = 0;
#if defined (MULTILAN_FEATURE)
    CHAR         param_val[CMD_BUFF_SIZE] = {0};
#endif

    if ( uDhcpv6ServerPoolNum >= DHCPV6S_POOL_NUM )
        return ANSC_STATUS_NOT_SUPPORTED;

    Index = uDhcpv6ServerPoolNum;
#if defined (MULTILAN_FEATURE)
    if(!commonSyseventGet(COSA_DML_DHCPV6C_PREF_PRETM_SYSEVENT_NAME, param_val, sizeof(param_val)))
    {
        if(param_val[0] != '\0')
            pEntry->Cfg.LeaseTime = atoi(param_val);
    }

    if(pEntry->Cfg.Interface[0] != '\0')
    {
        snprintf((char*)pEntry->Info.IANAPrefixes, sizeof(pEntry->Info.IANAPrefixes), "%s%s", pEntry->Cfg.Interface, "IPv6Prefix.1.");
    }
#endif
    sDhcpv6ServerPool[Index] = *pEntry;
    sDhcpv6ServerPool[Index].Info.Status = COSA_DML_DHCP_STATUS_Enabled; /* We set this to be enabled all time */

    /* Add this entry into utopia */
    setpool_into_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index, &sDhcpv6ServerPool[Index]);

    /* do this lastly */
    uDhcpv6ServerPoolNum++;

    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    SETI_INTO_UTOPIA(DHCPV6S_NAME, "", 0, "", 0, "poolnumber", uDhcpv6ServerPoolNum)
    Utopia_Free(&utctx,1);

#ifdef DHCPV6_SERVER_SUPPORT
    DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
    CosaDmlDHCPv6sTriggerRestart(FALSE);
    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sDelPool
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx  = {0};
    ULONG         Index  = 0;

    /* Out-of-bounds read
    ** Global array defined is of size DHCPV6S_POOL_NUM
    ** Hence limiting upper boundary of index to avoid out of boud access.
    */
    for( Index = 0; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++)
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulInstanceNumber )
            break;
    }
#if defined (MULTILAN_FEATURE)
    ULONG         Index2 = 0;
    for ( Index2 = Index+1; (Index2 < uDhcpv6ServerPoolNum) && (Index2 < DHCPV6S_POOL_NUM); Index2++ )
    {
        setpool_into_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index2-1, &sDhcpv6ServerPool[Index2]);
        sDhcpv6ServerPool[Index2-1] =  sDhcpv6ServerPool[Index2];
    }
#else
#if 0
    for ( Index2 = Index+1; (Index2 < uDhcpv6ServerPoolNum) && (Index2 < DHCPV6S_POOL_NUM); Index2++ )
    {
        setpool_into_utopia(DHCPV6S_NAME, "pool", Index2-1, &sDhcpv6ServerPool[Index2]);
        sDhcpv6ServerPool[Index2-1] =  sDhcpv6ServerPool[Index2];
    }
#endif
#endif

    /* unset last one in utopia , limiting upper bounday*/
    if (uDhcpv6ServerPoolNum == 0)
    {
        Index = DHCPV6S_POOL_NUM - 1;
    }
    else
    {
        Index =((uDhcpv6ServerPoolNum < DHCPV6S_POOL_NUM)? (uDhcpv6ServerPoolNum - 1):(DHCPV6S_POOL_NUM-1));
    }

    unsetpool_from_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index );
    AnscZeroMemory(&sDhcpv6ServerPool[Index], sizeof(sDhcpv6ServerPool[Index]));

    /* do this lastly */
    /* limiting lower boundary of the DHCP Server Pool Num to avoid -ve values*/
    /* Unsigned compared against 0*/
    uDhcpv6ServerPoolNum = (0 == (uDhcpv6ServerPoolNum)? 0 : (uDhcpv6ServerPoolNum-1) );


    if (!Utopia_Init(&utctx))
        return ANSC_STATUS_FAILURE;
    SETI_INTO_UTOPIA(DHCPV6S_NAME, "", 0, "", 0, "poolnumber", uDhcpv6ServerPoolNum)
    Utopia_Free(&utctx,1);

#ifdef DHCPV6_SERVER_SUPPORT
    DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
    CosaDmlDHCPv6sTriggerRestart(FALSE);
    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

    return ANSC_STATUS_SUCCESS;

}

static int
_get_iapd_prefix_pathname(char ** pp_pathname, int * p_len)
{
    char * p_ipif_path = NULL;
    int i = 0;
    int num = 0;
    char name[64] = {0};
    char path[256] = {0};
    char param_val[64] = {0};
    ULONG inst2 = 0;
    ULONG val_len = 0;
    errno_t rc = -1;

    if (!p_len || !pp_pathname)
        return -1;

    *p_len = 1; /* use after null check*/

    p_ipif_path = (char*)CosaUtilGetFullPathNameByKeyword
        (
            (PUCHAR)"Device.IP.Interface.",
            (PUCHAR)"Name",
            (PUCHAR)COSA_DML_DHCPV6_CLIENT_IFNAME
            );

    if (!p_ipif_path)
        return -2;

    rc = sprintf_s(name, sizeof(name), "%sIPv6PrefixNumberOfEntries", p_ipif_path);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }

    num = g_GetParamValueUlong(g_pDslhDmlAgent, name);

    for (i=0; i<num; i++)
    {
        rc = sprintf_s(name, sizeof(name), "%sIPv6Prefix.", p_ipif_path);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        inst2 = g_GetInstanceNumberByIndex(g_pDslhDmlAgent, name, i);

        if ( inst2 )
        {
            rc = sprintf_s(name,  sizeof(name), "%sIPv6Prefix.%lu.Origin", p_ipif_path, inst2);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            val_len = sizeof(param_val);
            if ( ( 0 == g_GetParamValueString(g_pDslhDmlAgent, name, param_val, &val_len)) &&
                 (strcmp(param_val, "PrefixDelegation") == 0))
            {
                snprintf(path, sizeof(path)-1, "%sIPv6Prefix.%lu.", p_ipif_path, inst2);
                *p_len += strlen(path)+1;

                if (!*pp_pathname)
                    *pp_pathname = calloc(1, *p_len);
                else
                    *pp_pathname = realloc(*pp_pathname, *p_len);

                if (!*pp_pathname)
                {
                    AnscFreeMemory(p_ipif_path); /* free unused resource before return*/
                    return -3;
                }

                rc = sprintf_s(*pp_pathname+strlen(*pp_pathname), *p_len - strlen(*pp_pathname), "%s,",path);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }

                break;
            }
        }
    }

    AnscFreeMemory(p_ipif_path);

    return 0;
}

int
CosaDmlDhcpv6sGetIAPDPrefixes
    (
        PCOSA_DML_DHCPSV6_POOL_CFG  pCfg,
        char*                       pValue,
        ULONG*                      pSize
    )
{
    int size = 0;
    char * p1 = NULL;
    int need_append_comma = 0;
    char * p_pathname = NULL;
    int pathname_len = 0;
    int ret = 0;
    errno_t rc = -1;

    size = strlen((const char*)pCfg->IAPDManualPrefixes);

    p1 = (char*)pCfg->IAPDManualPrefixes;
    if ( strlen(p1) && (p1[strlen(p1)-1] != ',') )
    {
        need_append_comma = 1;
        size++;
    }

    _get_iapd_prefix_pathname(&p_pathname, &pathname_len);
    size += pathname_len;

    if ((unsigned int)size > *pSize)
    {
        *pSize = size+1;
        ret = 1;
    }
    else
    {
        /*pValue is big enough*/
        rc = STRCPY_S_NOCLOBBER(pValue, *pSize, (const char*)pCfg->IAPDManualPrefixes);
        ERR_CHK(rc);

        if (need_append_comma)
        {
            rc = sprintf_s(pValue+strlen(pValue), *pSize - strlen(pValue), ",");
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
        }

        if (p_pathname)
        {
            rc = sprintf_s(pValue+strlen(pValue), *pSize - strlen(pValue), "%s", p_pathname);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
        }

        ret = 0;
    }

    if (p_pathname)
        free(p_pathname);

    return ret;
}
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
/*this function gets IAPD prefixes from sysevent, the value is PD prefix range*/
int
CosaDmlDhcpv6sGetIAPDPrefixes2
    (
        PCOSA_DML_DHCPSV6_POOL_CFG  pCfg,
        char*                       pValue,
        ULONG*                      pSize
    )
{
    ULONG size = 0;
    int ret = 0;
    char pd_pool[128] = {0};
    char start[64], end[64], pd_len[4];
    UNREFERENCED_PARAMETER(pCfg);
    errno_t rc = -1;

    commonSyseventGet("ipv6_subprefix-start", start, sizeof(start));
    commonSyseventGet("ipv6_subprefix-end", end, sizeof(end));
    commonSyseventGet("ipv6_pd-length", pd_len, sizeof(pd_len));

    if(start[0] != '\0' && end[0] != '\0' && pd_len[0] != '\0'){
        rc = sprintf_s(pd_pool, sizeof(pd_pool), "%s-%s/%s", start, end, pd_len);
        if(rc < EOK) ERR_CHK(rc);
    }

    size = strlen(pd_pool);

    if (size > *pSize)
    {
        *pSize = size+1;
        ret = 1;
    }
    else
    {
        /*pValue is big enough*/
        rc = STRCPY_S_NOCLOBBER(pValue, *pSize, pd_pool);
        ERR_CHK(rc);

        ret = 0;
    }

    return ret;
}
#endif
ANSC_STATUS
CosaDmlDhcpv6sSetPoolCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_CFG  pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index = 0;
    BOOLEAN                         bNeedZebraRestart = FALSE;

    /* Out-of-bounds write
    ** Maximum size of Dhcp Server Pool is DHCPV6S_POOL_NUM.
    */
    for( Index = 0; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++)
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == pCfg->InstanceNumber)
            break;
    }

    if(Index < DHCPV6S_POOL_NUM)
    {
                // Zebra restart based on below criteria
                if( ( pCfg->X_RDKCENTRAL_COM_DNSServersEnabled != sDhcpv6ServerPool[Index].Cfg.X_RDKCENTRAL_COM_DNSServersEnabled ) || \
                         ( ( '\0' != pCfg->X_RDKCENTRAL_COM_DNSServers[ 0 ] ) && \
                            ( 0 != strcmp( (const char*)pCfg->X_RDKCENTRAL_COM_DNSServers, (const char*)sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg.X_RDKCENTRAL_COM_DNSServers ) )
                         )
                  )
                {
                    bNeedZebraRestart = TRUE;
                }
//#ifdef _HUB4_PRODUCT_REQ_
        /* Stateful address is not effecting for clients whenever pool range is changed.
         * Added gw_lan_refresh to effect the stateful address to the clients according
         * to the configured poll range.
         */
        if ( ( 0 != strcmp( (const char*)pCfg->PrefixRangeBegin, (const char*)sDhcpv6ServerPool[Index].Cfg.PrefixRangeBegin ) ) || \
             ( 0 != strcmp( (const char*)pCfg->PrefixRangeEnd, (const char*)sDhcpv6ServerPool[Index].Cfg.PrefixRangeEnd ) ) )
        {
            v_secure_system("gw_lan_refresh");
        }
//#endif

        sDhcpv6ServerPool[Index].Cfg = *pCfg;
    }
    else
    {
                // Zebra restart based on below criteria
                if( ( pCfg->X_RDKCENTRAL_COM_DNSServersEnabled != sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg.X_RDKCENTRAL_COM_DNSServersEnabled ) || \
                  ( ( '\0' != pCfg->X_RDKCENTRAL_COM_DNSServers[ 0 ] ) && \
                    ( 0 != strcmp( (const char*)pCfg->X_RDKCENTRAL_COM_DNSServers, (const char*)sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg.X_RDKCENTRAL_COM_DNSServers ) )
                  )
                  )
                {
                  bNeedZebraRestart = TRUE;
                }
//#ifdef _HUB4_PRODUCT_REQ_
        /* Stateful address is not effecting for clients whenever pool range is changed.
         * Added gw_lan_refresh to effect the stateful address to the clients according
         * to the configured poll range.
         */
        if ( ( 0 != strcmp((const char*)pCfg->PrefixRangeBegin, (const char*)sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg.PrefixRangeBegin)) ||
             ( 0 != strcmp((const char*)pCfg->PrefixRangeEnd, (const char*)sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg.PrefixRangeEnd ) ) )
        {
            v_secure_system("gw_lan_refresh");
        }
//#endif

        sDhcpv6ServerPool[DHCPV6S_POOL_NUM -1].Cfg = *pCfg;
        Index = DHCPV6S_POOL_NUM - 1;
    }
#if defined (MULTILAN_FEATURE)
    if(pCfg->Interface[0] != '\0')
    {
        snprintf((char*)sDhcpv6ServerPool[Index].Info.IANAPrefixes, sizeof(sDhcpv6ServerPool[Index].Info.IANAPrefixes), "%s%s", pCfg->Interface, "IPv6Prefix.1.");
    }
#endif

    /* We do this synchronization here*/
    if ( ( _ansc_strlen((const char*)sDhcpv6ServerPool[Index].Cfg.IANAManualPrefixes) > 0 ) &&
         !_ansc_strstr((const char*)sDhcpv6ServerPool[Index].Info.IANAPrefixes, (const char*)sDhcpv6ServerPool[Index].Cfg.IANAManualPrefixes) ){
        _ansc_strcat((char*)sDhcpv6ServerPool[Index].Info.IANAPrefixes, "," );
        _ansc_strcat((char*)sDhcpv6ServerPool[Index].Info.IANAPrefixes, (const char*)sDhcpv6ServerPool[Index].Cfg.IANAManualPrefixes );
    }

    setpool_into_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index, &sDhcpv6ServerPool[Index]);

#ifdef DHCPV6_SERVER_SUPPORT
    DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
    CosaDmlDHCPv6sTriggerRestart(FALSE);
    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

        // Check whether static DNS got enabled or not. If enabled then we need to restart the zebra process
        if( bNeedZebraRestart )
        {
        DHCPMGR_LOG_WARNING("%s Restarting Zebra Process\n", __FUNCTION__);
        v_secure_system("killall zebra && sysevent set zebra-restart");
        }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetPoolCfg
    (
        ANSC_HANDLE                 hContext,
        PCOSA_DML_DHCPSV6_POOL_CFG    pCfg
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index = 0;

    /*  out of bound read
    ** Index must be less than the max array size
    */
    for( Index = 0; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++)
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == pCfg->InstanceNumber)
            break;
    }

    if(Index < DHCPV6S_POOL_NUM)
    {
        *pCfg = sDhcpv6ServerPool[Index].Cfg;
    }
    else
    {
        *pCfg = sDhcpv6ServerPool[DHCPV6S_POOL_NUM-1].Cfg;
    }
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetPoolInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_INFO pInfo
    )
{
    UNREFERENCED_PARAMETER(hContext);
    FILE *fp = NULL;
    char out[256] = {0};

    ULONG                           Index = 0;

    /* Out-of-bounds read
    ** Global array defined is of size DHCPV6S_POOL_NUM
    ** Hence limiting upper boundary of index to avoid out of boud access.
    */
    for( Index = 0; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++)
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulInstanceNumber )
            break;
    }

    if (Index >= DHCPV6S_POOL_NUM)
    {
        return ANSC_STATUS_FAILURE;
    }

    fp = v_secure_popen("r","busybox ps |grep %s|grep -v grep", SERVER_BIN);
    _get_shell_output(fp, out, sizeof(out));
    if ( (strstr(out, SERVER_BIN)) && sDhcpv6ServerPool[Index].Cfg.bEnabled )
    {
        sDhcpv6ServerPool[0].Info.Status  = COSA_DML_DHCP_STATUS_Enabled;
    }
    else
    {
        sDhcpv6ServerPool[0].Info.Status  = COSA_DML_DHCP_STATUS_Disabled;
    }

    *pInfo = sDhcpv6ServerPool[Index].Info;

    return ANSC_STATUS_SUCCESS;
}


#define DHCPS6V_CLIENT_FILE "/var/lib/dibbler/server-client.txt"
ULONG   g_dhcps6v_client_num  = 0;
PCOSA_DML_DHCPSV6_CLIENT        g_dhcps6v_client        = NULL;
PCOSA_DML_DHCPSV6_CLIENTCONTENT g_dhcps6v_clientcontent = NULL;

/*
file: /var/lib/dibbler/server-client.txt

ClientNum:1
DUID:00:01:00:01:c7:92:bf:d0:00:25:2e:7d:05:b5
Unicast:fe80::225:2eff:fe7d:5b4
Addr:fc00:1::2:fdd1:a9ab:bbc7
Timestamp:1318388831
Prefered:3600
Valid:7200
Addr:fc00:1::2:8fd8:da4f:a598
Timestamp:1318388831
Prefered:3600
Prefered:7200
option:1:00010001C793092300252E7D05B4
option:3:00000001FFFFFFFFFFFFFFFF00050018FC000002000000000003968D133EC4A800000E1000001C20
option:3:00000002FFFFFFFFFFFFFFFF00050018FC000002000000000003678E7E6D42CF00000E1000001C20
option:3:00000003FFFFFFFFFFFFFFFF00050018FC000002000000000003B19B73D106E500000E1000001C20
option:6:0017
option:2:000100011654D9A4000C299B4E7A
option:8:0000

*/
void _cosa_dhcpsv6_get_client()
{
    ULONG i = 0;
    FILE * fp = fopen(DHCPS6V_CLIENT_FILE, "r");
    CHAR  oneLine[256] = {0};
    PCHAR pTmp1 = NULL;
    PCHAR pTmp2 = NULL;
    PCHAR pTmp3 = NULL;
    ULONG  Index = 0xFFFFFFFF;
    time_t t1    = 0;
    struct tm t2 = {0};
    CHAR  buf[128] = {0};
    ULONG  timeStamp = 0;
    errno_t rc = -1;
    PCOSA_DML_DHCPSV6_CLIENT_OPTION          pOption1 = NULL;
    PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS     pIPv6Address1 = NULL;
    PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX      pIPv6Prefix1  = NULL;

    /* When read error, we keep current configuration */
    if ( fp == NULL )
        return;

    /* First free all */
    if ( g_dhcps6v_client )
    {
        for(i=0; i<g_dhcps6v_client_num; i++)
        {
            if ( g_dhcps6v_clientcontent[i].pIPv6Address )
                AnscFreeMemory(g_dhcps6v_clientcontent[i].pIPv6Address);

            if ( g_dhcps6v_clientcontent[i].pIPv6Prefix )
                AnscFreeMemory(g_dhcps6v_clientcontent[i].pIPv6Prefix);

            if ( g_dhcps6v_clientcontent[i].pOption )
                AnscFreeMemory(g_dhcps6v_clientcontent[i].pOption);
        }

        AnscFreeMemory( g_dhcps6v_client );
        AnscFreeMemory( g_dhcps6v_clientcontent );

        g_dhcps6v_client = NULL;
        g_dhcps6v_clientcontent = NULL;

        g_dhcps6v_client_num = 0;
    }

    /* Get all from file again */
    while ( fgets(oneLine, sizeof(oneLine), fp ) != NULL )
    {
        pTmp1 = &oneLine[0];
        pTmp2 = pTmp1;
        while( (*pTmp2 != ':') && ( *pTmp2 != 0) ) pTmp2++;

        if ( *pTmp2 == 0 )
        {
            continue;
        }

        *pTmp2 = 0;
        pTmp2++;

        pTmp3 = pTmp2;

        while( (*pTmp2 != 10) && (*pTmp2 != 13) && ( *pTmp2 != 0) ) pTmp2++;

        if ( *pTmp2 != 0)
        {
            *pTmp2 = 0;
            pTmp2++;
        }

        if ( (ULONG)pTmp2 <= (ULONG)pTmp3 )
        {
            /* Case: XXX:      */
            continue;
        }

        /*
                    pTmp1  name
                    pTmp3: value
                */

        if ( _ansc_strcmp(pTmp1, "ClientNum") == 0 )
        {
            // this case must be first one
            g_dhcps6v_client_num = atoi(pTmp3);

            if ( g_dhcps6v_client_num )
            {
                g_dhcps6v_client = (PCOSA_DML_DHCPSV6_CLIENT)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENT)*g_dhcps6v_client_num);
                 if ( !g_dhcps6v_client )
                {
                    g_dhcps6v_client_num = 0;
                    goto EXIT;
                }

                for ( i=0; i < g_dhcps6v_client_num; i++ )
                {
                    rc = sprintf_s(g_dhcps6v_client[i].Alias, sizeof(g_dhcps6v_client[i].Alias), "Client%lu",i+1);
                    if(rc < EOK)
                    {
                        ERR_CHK(rc);
                    }
                }

                g_dhcps6v_clientcontent = (PCOSA_DML_DHCPSV6_CLIENTCONTENT)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENTCONTENT)*g_dhcps6v_client_num);

                if ( !g_dhcps6v_clientcontent )
                {
                    AnscFreeMemory(g_dhcps6v_client);
                    g_dhcps6v_client = NULL;

                    g_dhcps6v_client_num = 0;
                    goto EXIT;
                }

                Index = 0xFFFFFFFF;
            }
            else
            {
                goto EXIT;
            }

        }else if ( _ansc_strcmp(pTmp1, "DUID") == 0 )
        {
            if ( Index == 0xFFFFFFFF )
            {
                Index = 0;
            }
            else
            {
                Index++;
            }
            /* DUID will be in dump files */

        }else if ( _ansc_strcmp(pTmp1, "option") == 0 )
        {
              //  pTmp1  name //option
              //  pTmp3: value //1:00010001C793092300252E7D05B4
            pTmp1 = pTmp3;
            while((*pTmp1 != ':') && (*pTmp1 != 0)) pTmp1++;

            if ( *pTmp1 == 0 )
                continue;

            *pTmp1 = 0;

            // commenting out for warning "value computed is not used [-Werror=unused-value]".
            //*pTmp1++;

            // pTmp3 is 1
            // pTmp1 is 00010001C793092300252E7D05B4

            // allocate new one array
            if(g_dhcps6v_clientcontent != NULL)
            {
                g_dhcps6v_clientcontent[Index].NumberofOption++;
                if ( g_dhcps6v_clientcontent[Index].NumberofOption == 1 )
                {
                    g_dhcps6v_clientcontent[Index].pOption = (PCOSA_DML_DHCPSV6_CLIENT_OPTION)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION));
                }
                else
                {
                    pOption1 = (PCOSA_DML_DHCPSV6_CLIENT_OPTION)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION)*g_dhcps6v_clientcontent[Index].NumberofOption );
                    if ( !pOption1 )
                        continue;


                    AnscCopyMemory(pOption1, g_dhcps6v_clientcontent[Index].pOption, sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION)*(g_dhcps6v_clientcontent[Index].NumberofOption-1) );
                    AnscFreeMemory(g_dhcps6v_clientcontent[Index].pOption);
                    g_dhcps6v_clientcontent[Index].pOption = pOption1;
                    pOption1 = NULL;
                }

                if (  g_dhcps6v_clientcontent[Index].pOption == NULL )
                {
                    g_dhcps6v_clientcontent[Index].NumberofOption = 0;
                    continue;
                }

                g_dhcps6v_clientcontent[Index].pOption[g_dhcps6v_clientcontent[Index].NumberofOption-1].Tag = _ansc_atoi(pTmp3);

                rc = STRCPY_S_NOCLOBBER( (char*)g_dhcps6v_clientcontent[Index].pOption[g_dhcps6v_clientcontent[Index].NumberofOption-1].Value, sizeof(g_dhcps6v_clientcontent[Index].pOption[g_dhcps6v_clientcontent[Index].NumberofOption-1].Value), pTmp1);
                ERR_CHK(rc);
            }
        }else if ( _ansc_strcmp(pTmp1, "Unicast") == 0 )
        {
          /* Explicit null dereferenced*/
          if (g_dhcps6v_client) {
            rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_client[Index].SourceAddress, sizeof(g_dhcps6v_client[Index].SourceAddress), pTmp3);
            ERR_CHK(rc);
          }
        }else if ( _ansc_strcmp(pTmp1, "Addr") == 0 )
        {
            if(g_dhcps6v_clientcontent != NULL)
            {
                g_dhcps6v_clientcontent[Index].NumberofIPv6Address++;
                if ( g_dhcps6v_clientcontent[Index].NumberofIPv6Address == 1 )
                {
                    g_dhcps6v_clientcontent[Index].pIPv6Address = (PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS));
                }
                else
                {
                    pIPv6Address1 = (PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)*g_dhcps6v_clientcontent[Index].NumberofIPv6Address );
                    if ( !pIPv6Address1 )
                        continue;

                    AnscCopyMemory(pIPv6Address1, g_dhcps6v_clientcontent[Index].pIPv6Address, sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)*(g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1) );
                    AnscFreeMemory(g_dhcps6v_clientcontent[Index].pIPv6Address);
                    g_dhcps6v_clientcontent[Index].pIPv6Address = pIPv6Address1;
                    pIPv6Address1 = NULL;
                }

                if ( g_dhcps6v_clientcontent[Index].pIPv6Address == NULL )
                {
                    g_dhcps6v_clientcontent[Index].NumberofIPv6Address = 0;
                    continue;
                }


                rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].IPAddress, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].IPAddress), pTmp3);
                ERR_CHK(rc);
            }
        }else if ( _ansc_strcmp(pTmp1, "Timestamp") == 0 )
        {
            timeStamp = atoi(pTmp3);
        }else if ( _ansc_strcmp(pTmp1, "Prefered") == 0 )
        {
            /* Explicit null dereferenced*/
            if ( g_dhcps6v_clientcontent && g_dhcps6v_clientcontent[Index].NumberofIPv6Address )
            {
                t1 = timeStamp;
                t1 += atoi(pTmp3);

                if ((unsigned int)t1 == 0xffffffff)
                {
                    rc = strcpy_s(buf, sizeof(buf), "9999-12-31T23:59:59Z");
                    ERR_CHK(rc);
                }
                else
                {
                    localtime_r(&t1, &t2);
                    snprintf(buf, sizeof(buf), "%d-%d-%dT%02d:%02d:%02dZ%c",
                         1900+t2.tm_year, t2.tm_mon+1, t2.tm_mday,
                         t2.tm_hour, t2.tm_min, t2.tm_sec, '\0');
                }


                rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].PreferredLifetime, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].PreferredLifetime), buf);
                ERR_CHK(rc);
            }
        }else if ( _ansc_strcmp(pTmp1, "Valid") == 0 )
        {
            if(g_dhcps6v_clientcontent != NULL)
            {
                if ( g_dhcps6v_clientcontent[Index].NumberofIPv6Address )
                {
                    t1 = timeStamp;
                    t1 += atoi(pTmp3);

                    if ((unsigned int)t1 == 0xffffffff)
                    {
                        rc = strcpy_s(buf, sizeof(buf), "9999-12-31T23:59:59Z");
                        ERR_CHK(rc);
                    }
                    else
                    {
                        localtime_r(&t1, &t2);
                        snprintf(buf, sizeof(buf), "%d-%d-%dT%02d:%02d:%02dZ%c",
                            1900+t2.tm_year, t2.tm_mon+1, t2.tm_mday,
                            t2.tm_hour, t2.tm_min, t2.tm_sec, '\0');
                    }


                    rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].ValidLifetime, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Address[g_dhcps6v_clientcontent[Index].NumberofIPv6Address-1].ValidLifetime), buf);
                    ERR_CHK(rc);
                }
            }
        }else if ( _ansc_strcmp(pTmp1, "pdPrefix") == 0 )
        {
            if(g_dhcps6v_clientcontent != NULL)
            {
                g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix++;
                if ( g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix == 1 )
                {
                    g_dhcps6v_clientcontent[Index].pIPv6Prefix = (PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)AnscAllocateMemory(sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX));
                }
                else
                {
                    pIPv6Prefix1 = (PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)*g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix );
                    if ( !pIPv6Prefix1 )
                        continue;

                    AnscCopyMemory(pIPv6Prefix1, g_dhcps6v_clientcontent[Index].pIPv6Prefix, sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)*(g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1) );
                    AnscFreeMemory(g_dhcps6v_clientcontent[Index].pIPv6Prefix);
                    g_dhcps6v_clientcontent[Index].pIPv6Prefix= pIPv6Prefix1;
                    pIPv6Prefix1 = NULL;
                }

                if ( g_dhcps6v_clientcontent[Index].pIPv6Prefix== NULL )
                {
                    g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix= 0;
                    continue;
                }

                rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].Prefix, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].Prefix), pTmp3);
                ERR_CHK(rc);
            }

        }else if ( _ansc_strcmp(pTmp1, "pdTimestamp") == 0 )
        {
            timeStamp = atoi(pTmp3);
        }else if ( _ansc_strcmp(pTmp1, "pdPrefered") == 0 )
        {
            if(g_dhcps6v_clientcontent != NULL)
            {
                if ( g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix )
                {
                    t1 = timeStamp;
                    t1 += atoi(pTmp3);

                    if ((unsigned int)t1 == 0xffffffff)
                    {
                        rc = strcpy_s(buf, sizeof(buf), "9999-12-31T23:59:59Z");
                        ERR_CHK(rc);
                    }
                    else
                    {
                        localtime_r(&t1, &t2);
                        snprintf(buf, sizeof(buf), "%d-%d-%dT%02d:%02d:%02dZ%c",
                            1900+t2.tm_year, t2.tm_mon+1, t2.tm_mday,
                            t2.tm_hour, t2.tm_min, t2.tm_sec, '\0');
                    }

                    rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].PreferredLifetime, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].PreferredLifetime), buf);
                    ERR_CHK(rc);
                }
            }
        }else if ( _ansc_strcmp(pTmp1, "pdValid") == 0 )
        {
            if(g_dhcps6v_clientcontent != NULL)
            {
                if ( g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix )
                {
                    t1 = timeStamp;
                    t1 += atoi(pTmp3);

                    if ((unsigned int)t1 == 0xffffffff)
                    {
                        rc = strcpy_s(buf, sizeof(buf), "9999-12-31T23:59:59Z");
                        ERR_CHK(rc);
                    }
                    else
                    {
                        localtime_r(&t1, &t2);
                        snprintf(buf, sizeof(buf), "%d-%d-%dT%02d:%02d:%02dZ%c",
                            1900+t2.tm_year, t2.tm_mon+1, t2.tm_mday,
                            t2.tm_hour, t2.tm_min, t2.tm_sec, '\0');
                    }

                    rc = STRCPY_S_NOCLOBBER((char*)g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].ValidLifetime, sizeof(g_dhcps6v_clientcontent[Index].pIPv6Prefix[g_dhcps6v_clientcontent[Index].NumberofIPv6Prefix-1].ValidLifetime), buf);
                    ERR_CHK(rc);
                }
            }
        }else
        {
            continue;
        }

        AnscZeroMemory( oneLine, sizeof(oneLine) );
    }

EXIT:

    fclose(fp);

    return;
}


ANSC_STATUS
CosaDmlDhcpv6sPing( PCOSA_DML_DHCPSV6_CLIENT        pDhcpsClient )
{
    FILE *fp = NULL;
    ULONG     i        = 0;

    for( i =0; i<g_dhcps6v_client_num; i++ )
    {
        if ( _ansc_strcmp((const char*)g_dhcps6v_client[i].SourceAddress, (const char*)pDhcpsClient->SourceAddress) == 0 )
        {
            break;
        }
    }

    if ( i >= g_dhcps6v_client_num )
    {
        return ANSC_STATUS_FAILURE;
    }

    if ( !g_dhcps6v_clientcontent[i].NumberofIPv6Address )
    {
        return ANSC_STATUS_FAILURE;
    }

    if ( g_dhcps6v_clientcontent[i].pIPv6Address == NULL )
    {
        return ANSC_STATUS_FAILURE;
    }

    /*ping -w 2 -c 1 fe80::225:2eff:fe7d:5b5 */
    fp = v_secure_popen("r",  "ping6 -w 2 -c 1 %s", g_dhcps6v_clientcontent[i].pIPv6Address[i].IPAddress );
    if (_get_shell_output2(fp, "0 packets received"))
    {
        /*1 packets transmitted, 0 packets received, 100% packet loss*/
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        /*1 packets transmitted, 1 packets received, 0% packet loss*/
        return ANSC_STATUS_SUCCESS;
    }
}

/*
  *   This is for
        Pool.{i}.Client.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetClient
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_CLIENT   *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulPoolInstanceNumber);
    /* We don't support this table currently */
    _cosa_dhcpsv6_get_client();

    *pSize = g_dhcps6v_client_num;

    if (!*pSize)
        return ANSC_STATUS_FAILURE;

    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT) * *pSize);
    if ( *ppEntry == NULL )
    {
        *pSize = 0;
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyMemory( *ppEntry, g_dhcps6v_client,  sizeof(COSA_DML_DHCPSV6_CLIENT)*(*pSize) );

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Address.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Address
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS   *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulPoolInstanceNumber);
    *pSize = g_dhcps6v_clientcontent[ulClientIndex].NumberofIPv6Address ;

    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS) * (*pSize) );

    if ( *ppEntry == NULL )
    {
        *pSize = 0;
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyMemory( *ppEntry, g_dhcps6v_clientcontent[ulClientIndex].pIPv6Address, sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6ADDRESS) * (*pSize) );

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Prefix.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Prefix
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX   *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulPoolInstanceNumber);
    *pSize = g_dhcps6v_clientcontent[ulClientIndex].NumberofIPv6Prefix;

    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_IPV6PREFIX)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX) * (*pSize) );

    if ( *ppEntry == NULL )
    {
        *pSize = 0;
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyMemory( *ppEntry, g_dhcps6v_clientcontent[ulClientIndex].pIPv6Prefix, sizeof(COSA_DML_DHCPSV6_CLIENT_IPV6PREFIX) * (*pSize) );

    return ANSC_STATUS_SUCCESS;
}

/*
  *   This is for
        Pool.{i}.Client.{i}.IPv6Option.{i}.
  *
  */
ANSC_STATUS
CosaDmlDhcpv6sGetIPv6Option
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulClientIndex,
        PCOSA_DML_DHCPSV6_CLIENT_OPTION   *ppEntry,
        PULONG                      pSize
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UNREFERENCED_PARAMETER(ulPoolInstanceNumber);
    *pSize = g_dhcps6v_clientcontent[ulClientIndex].NumberofOption;

    *ppEntry = (PCOSA_DML_DHCPSV6_CLIENT_OPTION)AnscAllocateMemory( sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION) * (*pSize) );

    if ( *ppEntry == NULL )
    {
        *pSize = 0;
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyMemory( *ppEntry, g_dhcps6v_clientcontent[ulClientIndex].pOption, sizeof(COSA_DML_DHCPSV6_CLIENT_OPTION) * (*pSize) );

    return ANSC_STATUS_SUCCESS;
}

/*
 *  DHCP Server Pool Option
 *
 *  The options are managed on top of a DHCP server pool,
 *  which is identified through pPoolAlias
 */
ULONG
CosaDmlDhcpv6sGetNumberOfOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index  =  0;
    /* boundary check for upper limit*/
    for( Index = 0 ; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM) ; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
            break;
    }

    /* boundary check for upper limit
    ** In case index exceeds the upper limit, return last value.
    */
    if(Index < DHCPV6S_POOL_NUM)
    {
        return uDhcpv6ServerPoolOptionNum[Index];
    }
    else
    {
        return uDhcpv6ServerPoolOptionNum[DHCPV6S_POOL_NUM - 1];
    }
}

ANSC_STATUS
CosaDmlDhcpv6sGetStartAddress
    (
        ANSC_HANDLE                 hContext,
        char*                       addr,
        int                         len
    )
{
    UNREFERENCED_PARAMETER(hContext);
    char globalAddress[64] = {0};
    commonSyseventGet(COSA_DML_DHCPV6C_PREF_SYSEVENT_NAME, globalAddress, sizeof(globalAddress));

    strncpy(addr, globalAddress, (unsigned int)len>strlen(globalAddress)?strlen(globalAddress):(unsigned int)len);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulIndex,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index  =  0;

    /* out of bound read
    ** Index must be less than the max array size
    */
    for( Index = 0 ; (Index < uDhcpv6ServerPoolNum) && (Index < DHCPV6S_POOL_NUM); Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
            break;
    }

    if(Index < DHCPV6S_POOL_NUM)
    {
        *pEntry = sDhcpv6ServerPoolOption[Index][ulIndex];
    }
    else
    {
        *pEntry = sDhcpv6ServerPoolOption[DHCPV6S_POOL_NUM - 1][ulIndex];
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sGetOptionbyInsNum
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index   =  0;
    ULONG                           Index2  =  0;

    for( Index = 0 ; Index < uDhcpv6ServerPoolNum; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
        {
            for( Index2 = 0; Index2 < uDhcpv6ServerPoolOptionNum[Index]; Index2++ )
            {
                if ( sDhcpv6ServerPoolOption[Index][Index2].InstanceNumber == pEntry->InstanceNumber )
                {
                    *pEntry = sDhcpv6ServerPoolOption[Index][Index2];
                    return ANSC_STATUS_SUCCESS;
                }
            }
        }
    }

    return ANSC_STATUS_FAILURE;
}


ANSC_STATUS
CosaDmlDhcpv6sSetOptionValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx             = {0};
    ULONG                           Index   =  0;
    errno_t                         rc      = -1;

    for( Index = 0 ; Index < uDhcpv6ServerPoolNum; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
        {
            sDhcpv6ServerPoolOption[Index][ulIndex].InstanceNumber = ulInstanceNumber;

            rc = STRCPY_S_NOCLOBBER((char*)sDhcpv6ServerPoolOption[Index][ulIndex].Alias, sizeof(sDhcpv6ServerPoolOption[Index][ulIndex].Alias), pAlias);
            ERR_CHK(rc);

            if (!Utopia_Init(&utctx))
                return ANSC_STATUS_FAILURE;
            SETI_INTO_UTOPIA(DHCPV6S_NAME, "pool", Index, "option", ulIndex, "InstanceNumber", ulInstanceNumber)
            SETS_INTO_UTOPIA(DHCPV6S_NAME, "pool", Index, "option", ulIndex, "alias", pAlias)
            Utopia_Free(&utctx,1);

            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS
CosaDmlDhcpv6sAddOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx             = {0};
    ULONG                           Index   =  0;
    ULONG                           Index2  =  0;

    for( Index = 0 ; Index < uDhcpv6ServerPoolNum; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
        {

            if ( uDhcpv6ServerPoolOptionNum[Index] >= DHCPV6S_POOL_OPTION_NUM )
                return ANSC_STATUS_NOT_SUPPORTED;

            Index2 = uDhcpv6ServerPoolOptionNum[Index];
            uDhcpv6ServerPoolOptionNum[Index]++;
            if (!Utopia_Init(&utctx))
                return ANSC_STATUS_FAILURE;
            SETI_INTO_UTOPIA(DHCPV6S_NAME, "pool", Index, "", 0, "optionnumber", uDhcpv6ServerPoolOptionNum[Index])
            Utopia_Free(&utctx,1);

            sDhcpv6ServerPoolOption[Index][Index2] = *pEntry;
            setpooloption_into_utopia((PUCHAR)DHCPV6S_NAME,(PUCHAR)"pool",Index,(PUCHAR)"option",Index2,&sDhcpv6ServerPoolOption[Index][Index2]);

#ifdef DHCPV6_SERVER_SUPPORT
            DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
	    CosaDmlDHCPv6sTriggerRestart(FALSE);
	    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif
            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;

}

ANSC_STATUS
CosaDmlDhcpv6sDelOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        ULONG                       ulInstanceNumber
    )
{
    UNREFERENCED_PARAMETER(hContext);
    UtopiaContext utctx             = {0};
    ULONG                           Index   =  0;
    ULONG                           Index2  =  0;

    for( Index = 0 ; Index < uDhcpv6ServerPoolNum; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
        {
            for ( Index2 = 0; Index2 < uDhcpv6ServerPoolOptionNum[Index]; Index2++ )
            {
                if ( sDhcpv6ServerPoolOption[Index][Index2].InstanceNumber == ulInstanceNumber )
                {
                    break;
                }
            }
#ifndef MULTILAN_FEATURE
            unsetpooloption_from_utopia((PUCHAR)DHCPV6S_NAME,(PUCHAR)"pool",Index,(PUCHAR)"option",Index2);
#endif
            for( Index2++; Index2  < uDhcpv6ServerPoolOptionNum[Index]; Index2++ )
            {
#if defined (MULTILAN_FEATURE)
                setpooloption_into_utopia((PUCHAR)DHCPV6S_NAME,(PUCHAR)"pool",Index,(PUCHAR)"option",Index2-1,&sDhcpv6ServerPoolOption[Index][Index2]);
#endif
                sDhcpv6ServerPoolOption[Index][Index2-1] =  sDhcpv6ServerPoolOption[Index][Index2];
            }
#if defined (MULTILAN_FEATURE)
            unsetpooloption_from_utopia((PUCHAR)DHCPV6S_NAME,(PUCHAR)"pool",Index,(PUCHAR)"option",Index2-1);
#endif
            uDhcpv6ServerPoolOptionNum[Index]--;
            if (!Utopia_Init(&utctx))
                return ANSC_STATUS_FAILURE;
            SETI_INTO_UTOPIA(DHCPV6S_NAME, "pool", Index, "", 0, "optionnumber", uDhcpv6ServerPoolOptionNum[Index])
            Utopia_Free(&utctx,1);

#ifdef DHCPV6_SERVER_SUPPORT
            DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
	    CosaDmlDHCPv6sTriggerRestart(FALSE);
            //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

            return ANSC_STATUS_SUCCESS;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDhcpv6sSetOption
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPoolInstanceNumber,
        PCOSA_DML_DHCPSV6_POOL_OPTION  pEntry
    )
{
    UNREFERENCED_PARAMETER(hContext);
    ULONG                           Index   =  0;
    ULONG                           Index2  =  0;

    for( Index = 0 ; Index < uDhcpv6ServerPoolNum; Index++ )
    {
        if ( sDhcpv6ServerPool[Index].Cfg.InstanceNumber == ulPoolInstanceNumber )
        {
            for ( Index2 = 0; Index2 < uDhcpv6ServerPoolOptionNum[Index]; Index2++ )
            {
                if ( sDhcpv6ServerPoolOption[Index][Index2].InstanceNumber == pEntry->InstanceNumber )
                {
                    if ( pEntry->Tag == 23 &&
                        ( _ansc_strcmp((const char*)sDhcpv6ServerPoolOption[Index][Index2].PassthroughClient, (const char*)pEntry->PassthroughClient ) ||
                        ( _ansc_strcmp((const char*)sDhcpv6ServerPoolOption[Index][Index2].Value, (const char*)pEntry->Value) &&
                                  !_ansc_strlen((const char*)pEntry->PassthroughClient) ) ) )
                    {
                        commonSyseventSet("zebra-restart", "");
                    }

                    sDhcpv6ServerPoolOption[Index][Index2] = *pEntry;

                    setpooloption_into_utopia((PUCHAR)DHCPV6S_NAME, (PUCHAR)"pool", Index, (PUCHAR)"option", Index2, &sDhcpv6ServerPoolOption[Index][Index2]);

#ifdef DHCPV6_SERVER_SUPPORT
                    DHCPMGR_LOG_DEBUG("%s,%d: Calling CosaDmlDHCPv6sTriggerRestart(FALSE)...\n", __FUNCTION__, __LINE__);
		    CosaDmlDHCPv6sTriggerRestart(FALSE);
                    //sysevent_set(sysevent_fd_server, sysevent_token_server, "dhcpv6s_trigger_restart", "0", 0);
#endif

                    return ANSC_STATUS_SUCCESS;
                }
            }
        }
    }

    return ANSC_STATUS_FAILURE;
}

void
CosaDmlDhcpv6Remove(ANSC_HANDLE hContext)
{
    UNREFERENCED_PARAMETER(hContext);
    /*remove backend memory*/
    if (g_sent_options)
        AnscFreeMemory(g_sent_options);

    /* empty global variable */
    AnscZeroMemory(&uDhcpv6ServerPoolOptionNum, sizeof(uDhcpv6ServerPoolOptionNum));
    AnscZeroMemory(&sDhcpv6ServerPool, sizeof(sDhcpv6ServerPool));
    AnscZeroMemory(&sDhcpv6ServerPoolOption, sizeof(sDhcpv6ServerPoolOption));
    uDhcpv6ServerPoolNum = 0;

    return;
}

#ifdef RA_MONITOR_SUPPORT
static void *
rtadv_dbg_thread(void * in)
{
    UNREFERENCED_PARAMETER(in);
    int fd = 0;
    char msg[64] = {0};
    char *buf = NULL;
    fd_set rfds;
    int clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);
    rtAdvInfo = (desiredRtAdvInfo*) AnscAllocateMemory(sizeof(desiredRtAdvInfo) * clientCount);
    char temp[5] = {0};
    dhcp_params dhcpParams = {0};
    char managedFlag;
    char otherFlag;
    char ra_Ifname[64] = {0};
    /* Message format written to the FIFO by ipv6rtmon daemon would be either one of the below :
             "ra-flags 0 0"
             "ra-flags 0 1"
             "ra-flags 1 0"
       Possible values for managedFlag and otherFlag set by the daemon will ONLY be 0 or 1 and no other positive values.
    */
    const size_t ra_flags_len = 32; /* size of ra_flags message including terminating character */
    int i = 0;
    while (i < clientCount)
        rtAdvInfo[i++].managedFlag = '-';

    fd = open(RA_COMMON_FIFO, O_RDWR);
    if (fd < 0)
    {
        DHCPMGR_LOG_ERROR("%s : Open failed for fifo file %s due to error %s.\n", __FUNCTION__, RA_COMMON_FIFO, strerror(errno));
        goto EXIT;
    }
    v_secure_system(IPv6_RT_MON_NOTIFY_CMD); /* SIGUSR1 for ipv6rtmon daemon upon creation of FIFO file from the thread. */
    DHCPMGR_LOG_INFO("%s : Inside %s %d\n", __FUNCTION__, __FUNCTION__, fd);

    while (1)
    {
        int retCode = 0;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        retCode = select(fd+1, &rfds, NULL, NULL, NULL);

        if (retCode < 0) {

            if (errno == EINTR)
                continue;

            DHCPMGR_LOG_ERROR("%s -- select() returns error %s.\n", __FUNCTION__, strerror(errno));
            goto EXIT;
        }
        else if (retCode == 0)
            continue;

        if (FD_ISSET(fd, &rfds))
        {
            size_t ofst = 0;
            memset(msg, 0, sizeof(msg));
            while (ofst < ra_flags_len) {
                ssize_t ret = read(fd, &msg[ofst], ra_flags_len - ofst);
                if (ret < 0) {
                    DHCPMGR_LOG_ERROR("%s : read() returned error %s after already reading %zu. Ignoring the message...\n", __FUNCTION__, strerror(errno), ret);
                    continue;
                }
                ofst += ret;
            }
        }
        else
            continue;
        if ((!strncmp(msg, "ra-flags", strlen("ra-flags"))) > 0) /*Ensure that message has "ra-flags" as the first substring. */
        {
            DHCPMGR_LOG_INFO("%s: get message %s\n", __func__, msg);
            int needEnable = 0;
            buf = msg + strlen("ra-flags");
            while (isblank(*buf))
                buf++;

            memset(temp, 0, sizeof(temp));
            if ((syscfg_get(NULL, "tr_dhcpv6c_enabled", temp, sizeof(temp)) == 0) && (!strcmp(temp, "1")))
                needEnable = 1;

            if (sscanf(buf, "%c %c %s", &managedFlag, &otherFlag, ra_Ifname)) { /* Possible managedFlag and otherFlag values will be either 0 or 1 only. */
             int index = 0;
             while(index < clientCount)
             {
                 if(strcmp(rtAdvInfo[index].ra_Ifname,ra_Ifname) == 0)
                     break;
                 else
                     index ++;
              }
               /* continue if interface is not found*/
              if(index == clientCount)
                  continue;
                  /*continue if manage is 0 and other is 0 */
              if(managedFlag == '0' && otherFlag == '0')
              {
                   syscfg_set_u_commit(NULL, "dibbler_requestAddress", 0 );
                   syscfg_set_u_commit(NULL, "dibbler_requestPrefix", 0 );
                   continue;
              }
                /* continue if the previous manage flag is same as current */
              if (managedFlag == rtAdvInfo[index].managedFlag)
                   continue;
              rtAdvInfo[index].managedFlag = managedFlag;
              rtAdvInfo[index].otherFlag = otherFlag;
#if 0          /* Will revisit when we support sysevents based restart of dibbler*/
               if (needDibblerRestart) {
                   prev_Mflag_val[index] = '-';
                   needDibblerRestart = FALSE;
               }
#endif
              dhcpParams.ifname = rtAdvInfo[index].ra_Ifname;

              //stop_dhcpv6_client(&dhcpParams);
              if(rtAdvInfo[index].managedFlag == '1')
              {
                  syscfg_set_u_commit(NULL, "dibbler_requestAddress", 1 );
                  syscfg_set_u_commit(NULL, "dibbler_requestPrefix", 1 );
               }
               else if(rtAdvInfo[index].otherFlag == '1')
               {
                   syscfg_set_u_commit(NULL, "dibbler_requestAddress", 0 );
                   syscfg_set_u_commit(NULL, "dibbler_requestPrefix", 1 );
               }
               sleep(0.4);
               ULONG instanceNum;
               PCOSA_DML_DHCPCV6_FULL pDhcpcv6        = NULL;
               PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcpv6CxtLink  = NULL;
               PSINGLE_LINK_ENTRY  pSListEntry   = NULL;
               pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL,index,&instanceNum);
               if (pSListEntry)
               {
                   pDhcpv6CxtLink      = ACCESS_COSA_CONTEXT_DHCPCV6_LINK_OBJECT(pSListEntry);
                   pDhcpcv6            = (PCOSA_DML_DHCPCV6_FULL)pDhcpv6CxtLink->hContext;
               }

               if(rtAdvInfo[index].managedFlag == '1')
               {
                   pDhcpcv6->Cfg.RequestAddresses = TRUE;
               }

               if((rtAdvInfo[index].managedFlag == '1') || (rtAdvInfo[index].otherFlag == '1'))
               {
                   pDhcpcv6->Cfg.RequestPrefixes = TRUE;
               }

               if( ((rtAdvInfo[index].managedFlag == '1') || (rtAdvInfo[index].otherFlag == '1')) && (needEnable == 1) )
               {
                   syscfg_set_commit(NULL, "NeedDibblerRestart", "false");
                   _prepare_client_conf(&pDhcpcv6->Cfg);
                   int count = 0;
                   PCOSA_DML_DHCPCV6_SENT pSentOption = NULL;
                   dhcp_opt_list* send_opt_list = NULL;
                   dhcp_opt_list* req_opt_list = NULL;
                   PCOSA_CONTEXT_LINK_OBJECT       pCxtLink      = NULL;
                   count = CosaDmlDhcpv6cGetNumberOfSentOption(NULL, instanceNum);
                   for ( int ulIndex2 = 0; ulIndex2 < count; ulIndex2++ )
                   {
                       pSListEntry = (PSINGLE_LINK_ENTRY)SentOption1_GetEntry(pDhcpv6CxtLink, ulIndex2, &instanceNum);
                       if (pSListEntry)
                       {
                           pCxtLink           = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
                           pSentOption         = (PCOSA_DML_DHCPCV6_SENT)pCxtLink->hContext;
                           if (pSentOption->bEnabled)
                           {
                               add_dhcpv4_opt_to_list(&send_opt_list, (int)pSentOption->Tag, (CHAR *)pSentOption->Value);
                           }
                       }
                   }
                   char *tmpstr = NULL;
                   tmpstr = strdup((CHAR *)pDhcpcv6->Cfg.RequestedOptions);
                   char* token = strtok(tmpstr, " , ");
                   while (token != NULL)
                   {
                       DHCPMGR_LOG_ERROR("token : %d\n", atoi(token));
                       add_dhcpv4_opt_to_list(&req_opt_list, atoi(token), "");
                       token = strtok(NULL, " , ");
                   }
                   dhcpParams.ifType = WAN_LOCAL_IFACE;
                   //start_dhcpv6_client(&dhcpParams);
                   free_opt_list_data (req_opt_list);
                   free_opt_list_data (send_opt_list);
               }
            }
        }
    }
EXIT:
    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}
#endif // RA_MONITOR_SUPPORT

#endif