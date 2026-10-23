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

#include <mqueue.h>
#include <pthread.h>

#define LM_GEN_STR_SIZE    64
#define LM_MAX_IP_AMOUNT 24
#define LM_MAX_COMMENT_SIZE 64
#define MAX_STR_SIZE 256
#define MAX_STR_LEN 64
#define MAX_INTERFACES 10
#define MQ_NAME_LEN 64
#define MQ_MAX_MESSAGES 20
#define MQ_MSG_SIZE 1024

#ifdef FEATURE_RDKB_WAN_MANAGER
extern ANSC_HANDLE bus_handle;
#define ETHERNET_INTERFACE_OBJECT "Device.Ethernet.Interface"
#define ETH_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.ethagent"
#define ETH_DBUS_PATH "/com/cisco/spvtg/ccsp/ethagent"
#endif

#define PARTNERS_INFO_FILE              "/nvram/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE             "/opt/secure/bootstrap.json"
/*
enum LM_ADDR_SOURCE{
        LM_ADDRESS_SOURCE_STATIC =0,
        LM_ADDRESS_SOURCE_DHCP,
        LM_ADDRESS_SOURCE_RESERVED,
        LM_ADDRESS_SOURCE_NONE
};

enum LM_MEDIA_TYPE{
        LM_MEDIA_TYPE_UNKNOWN=0,
        LM_MEDIA_TYPE_ETHERNET,
        LM_MEDIA_TYPE_WIFI,
        LM_MEDIA_TYPE_MOCA
};

typedef struct{
        unsigned char   addr[16];
    int active;
    int LeaseTime;
        enum LM_ADDR_SOURCE     addrSource;
    unsigned int priFlg;
}LM_ip_addr_t;

typedef struct{
        unsigned char   phyAddr[6];
        unsigned char   online;
        unsigned char   ipv4AddrAmount;
        unsigned char   ipv6AddrAmount;
//      LM_ip_addr_t    priAddr;
        enum LM_MEDIA_TYPE mediaType;
        char    hostName[LM_GEN_STR_SIZE];
        char    l1IfName[LM_GEN_STR_SIZE];
        char    l3IfName[LM_GEN_STR_SIZE];
    char    AssociatedDevice[LM_GEN_STR_SIZE];//Only works if this is a wifi host. 
    time_t  activityChangeTime;
        LM_ip_addr_t    ipv4AddrList[LM_MAX_IP_AMOUNT];
        LM_ip_addr_t    ipv6AddrList[LM_MAX_IP_AMOUNT];
    unsigned char   comments[LM_MAX_COMMENT_SIZE];
    int             RSSI;
}LM_host_t, *LM_host_ptr_t;


typedef struct{
    int result;
    union{
        LM_host_t host;
        int online_num;
    }data;
}LM_cmd_common_result_t;
*/

ULONG
CosaGetParamValueUlong
    (
        char*                       pParamName
    );

ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    );


PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword);

ANSC_STATUS is_usg_in_bridge_mode(BOOL *pBridgeMode);

ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    );


ANSC_STATUS UpdateJsonParam
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue,
                char*                   pSource,
                char*                   pCurrentTime
    );

int writeToJson(char *data, char *file);
ANSC_STATUS UpdateJsonParamLegacy
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue
    );

PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    );




//static int openCommonSyseventConnection();
int commonSyseventSet(char* key, char* value);
int commonSyseventGet(char* key, char* value, int valLen);
int commonSyseventClose();
void _get_shell_output(FILE *fp, char *buf, int len);
int _get_shell_output2(FILE *fp, char * dststr);
char *safe_strcpy (char *dst, char *src, size_t dst_size);

int GetInstanceNumberByIndex(char* pObjName,unsigned int* Inscont,unsigned int** InsArray);

ANSC_STATUS fillCurrentPartnerId
        (
                char*                       pValue,
        PULONG                      pulSize
    );


int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    );

int g_GetParamValueString(ANSC_HANDLE g_pDslhDmlAgent, char* prefixFullName, char* prefixValue,PULONG uSize);

//int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost);

INT PsmWriteParameter( char *pParamName, char *pParamVal );

INT PsmReadParameter( char *pParamName, char *pReturnVal, int returnValLength );

typedef struct {
    char if_name[MAX_STR_LEN];
    char mq_name[MAX_STR_LEN];
    BOOL thread_running;
    pthread_mutex_t q_mutex; // Mutex for Queue operations
} interface_info_t;

typedef struct {
    char if_name[MAX_STR_LEN];
    char ParamName[MAX_STR_LEN];
    union {
        BOOL bValue;
        int iValue;
        ULONG uValue;
        char strValue[MAX_STR_LEN];
    } value;
    enum {
        DML_SET_MSG_TYPE_BOOL,
        DML_SET_MSG_TYPE_INT,
        DML_SET_MSG_TYPE_ULONG,
        DML_SET_MSG_TYPE_STRING
    } valueType;
    enum {
        DML_DHCPV4 = 1,
        DML_DHCPV6
    } dhcpType;
} dhcp_info_t;

typedef struct {
    interface_info_t if_info;
    dhcp_info_t msg_info; // DHCP message info  
} mq_send_msg_t;



/* Message queue operations */
/* Create/open a POSIX message queue with the given name. */
int create_message_queue(const char *mq_name, mqd_t *mq_desc);
/* Close an opened message queue descriptor. */
int delete_message_queue(mqd_t mq_desc);
/* Remove (unlink) the named message queue from the system. */
int unlink_message_queue(const char *mq_name);
/* Find an existing interface entry or create a new one in the global registry. */
int find_or_create_interface(char *info_name, interface_info_t *info_out);
/* Create and start the per-interface controller thread. */
int create_interface_thread(char *info_name);
/* Update copyable fields of an interface entry in the global registry. */
int update_interface_info(const char *alias_name, interface_info_t *info);
/* Mark the per-interface controller thread as stopped in the global registry. */
int mark_thread_stopped(const char *alias_name);

/* Lock the canonical per-interface queue mutex.
 * If the mutex is already locked, this call will wait until it can acquire it.
 * Returns 0 on success, -1 on error.
 */
int DhcpMgr_LockInterfaceQueueMutexByName(const char *if_name);

/* Unlock the canonical per-interface queue mutex.
 * Returns 0 on success, -1 on error.
 */
int DhcpMgr_UnlockInterfaceQueueMutexByName(const char *if_name);

void* DhcpMgr_MainController( void *args );

/* Helper: open MQ, ensure controller thread, and send the provided info */
int DhcpMgr_OpenQueueEnsureThread(dhcp_info_t info);

/**********************DHCPManager Queue requirements END ***************************/

/**********************DHCP Enable Sysevent Helpers ***************************/

/**
 * @brief Set the sysevent value for DHCPCV4_ENABLE_ / DHCPCV6_ENABLE_ keys.
 *
 * Formats the value as "<ifname> 1" when enabled or "<ifname> 0" when disabled
 * and sets it via commonSyseventSet.
 *
 * @param sysevent_key  The sysevent key (e.g. "DHCPCV4_ENABLE_1").
 * @param ifname        Interface name (e.g. "erouter0"). Must not be NULL or empty.
 * @param enabled       TRUE for enabled, FALSE for disabled.
 * @return 0 on success, -1 on error.
 */
int Dhcp_set_Sysevent_InterfaceEnable(const char *sysevent_key, const char *ifname, BOOL enabled);

/**
 * @brief Get and parse the sysevent value for DHCPCV4_ENABLE_ / DHCPCV6_ENABLE_ keys.
 *
 * Reads the sysevent via commonSyseventGet and parses format "<ifname> 1" or "<ifname> 0".
 *
 * @param sysevent_key  The sysevent key (e.g. "DHCPCV4_ENABLE_1").
 * @param ifname        Output buffer for the extracted interface name.
 * @param ifnameLen     Size of ifname buffer.
 * @param enabled       Output: TRUE if status is 1, FALSE if 0.
 * @return 0 on success, -1 on error (sysevent not set, invalid format, or NULL inputs).
 */
int Dhcp_get_Sysevent_InterfaceEnable(const char *sysevent_key, char *ifname, size_t ifnameLen, BOOL *enabled);