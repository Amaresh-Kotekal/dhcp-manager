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

#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <syscfg/syscfg.h>
#include <errno.h>
#include "sysevent/sysevent.h"
#include "utapi/utapi.h"
#include "utapi/utapi_util.h"
#include "ansc_platform.h"
#include "cosa_apis.h"
#include "cosa_apis_util.h"
#include "plugin_main.h"
#include "plugin_main_apis.h"
#include "secure_wrapper.h"
#include "safec_lib_common.h"
#include "cJSON.h"
#include "ifl.h"
#include <sys/ioctl.h>
#include "util.h"

#ifdef DHCPV6C_PSM_ENABLE
#include "ccsp_psm_helper.h"
#endif //DHCPV6C_PSM_ENABLE

#define BOOTSTRAP_INFO_FILE_BACKUP  "/nvram/bootstrap.json"
#define CLEAR_TRACK_FILE            "/nvram/ClearUnencryptedData_flags"
#define NVRAM_BOOTSTRAP_CLEARED     (1 << 0)

#define UNUSED(x) (void)(x)
#define PARTNER_ID_LEN 64
typedef int (*CALLBACK_FUNC_NAME)(void *);
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];


/*****************DHCPMgr queue requirements ********************************/

static interface_info_t interfaces[MAX_INTERFACES];
static int interface_count = 0;
static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Open existing or create new message queue */
int create_message_queue(const char *alias_name, char mq_name_out[], mqd_t *mq_desc) {
    struct mq_attr attr;
    
    /* Create queue name: /mq_if_<alias_name> */
    snprintf(mq_name_out, MQ_NAME_LEN, "/mq_if_%s", alias_name);
    DHCPMGR_LOG_INFO("%s %d Creating/opening message queue with name: %s\n", __FUNCTION__, __LINE__, mq_name_out);
    
    /* Try to open existing queue first */
    mq_name_out[MQ_NAME_LEN - 1] = '\0';

    /* Log the name we're passing to mq_open for diagnostics */
//    DHCPMGR_LOG_INFO("%s %d Attempting mq_open for name: %s\n", __FUNCTION__, __LINE__, mq_name_out);

    *mq_desc = mq_open(mq_name_out, O_RDWR | O_NONBLOCK);
    
    if (*mq_desc != (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s %d Message queue %s already exists, opened successfully\n", __FUNCTION__, __LINE__, mq_name_out);
        return 0;
    }
    
    /* Queue doesn't exist, create it */
    DHCPMGR_LOG_INFO("%s %d Creating new message queue %s\n", __FUNCTION__, __LINE__, mq_name_out);
    
    /* Set queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = MQ_MAX_MESSAGES;
    attr.mq_msgsize = sizeof(interface_info_t);
    attr.mq_curmsgs = 0;

//    DHCPMGR_LOG_INFO("%s %d Creating mq with attrs: maxmsg=%ld msgsize=%ld\n", __FUNCTION__, __LINE__, (long)attr.mq_maxmsg, (long)attr.mq_msgsize);
    *mq_desc = mq_open(mq_name_out, O_CREAT | O_RDWR | O_NONBLOCK, 0644, &attr);
    
    if (*mq_desc == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s %d mq_open failed", __FUNCTION__, __LINE__);
        return -1;
    }
    
    DHCPMGR_LOG_INFO("%s %d Message queue %s created successfully", __FUNCTION__, __LINE__, mq_name_out);
    return 0;
}


/* Delete (close) a message queue */
int delete_message_queue(mqd_t mq_desc) {
    if (mq_close(mq_desc) == -1) {
        DHCPMGR_LOG_ERROR("%s %d mq_close failed", __FUNCTION__, __LINE__);
        return -1;
    }
    
    DHCPMGR_LOG_INFO("%s %d Message queue closed successfully", __FUNCTION__, __LINE__  );
    return 0;
}

/* Unlink a message queue */
int unlink_message_queue(const char *mq_name) {
    if (mq_unlink(mq_name) == -1) {
        DHCPMGR_LOG_ERROR("%s %d mq_unlink failed", __FUNCTION__, __LINE__);
        return -1;
    }
    
    DHCPMGR_LOG_INFO("%s %d Message queue %s unlinked successfully", __FUNCTION__, __LINE__, mq_name);
    return 0;
}


/* Mark thread as stopped in the global array */
int mark_thread_stopped(const char *alias_name) {
    DHCPMGR_LOG_INFO("%s %d: Marking thread for %s as stopped\n", __FUNCTION__, __LINE__, alias_name);
    pthread_mutex_lock(&global_mutex);
    
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interfaces[i].if_name, alias_name) == 0) {
            interfaces[i].thread_running = false;
            pthread_mutex_unlock(&global_mutex);
            DHCPMGR_LOG_INFO("%s %d: Marked thread for %s as stopped\n", __FUNCTION__, __LINE__, alias_name);
            return 0;
        }
    }
    DHCPMGR_LOG_INFO("%s %d: Thread for %s not found\n", __FUNCTION__, __LINE__, alias_name);
    pthread_mutex_unlock(&global_mutex);
    return -1;
}

int find_or_create_interface(interface_info_t *info_in, interface_info_t *info_out) {
    DHCPMGR_LOG_INFO("%s %d: Finding or creating interface entry for %s\n", __FUNCTION__, __LINE__, info_in->if_name);
    pthread_mutex_lock(&global_mutex);
    
    /* Check if interface already exists */
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interfaces[i].if_name, info_in->if_name) == 0) {
            pthread_mutex_unlock(&global_mutex);
            DHCPMGR_LOG_INFO("%s %d: Found existing interface entry for %s\n", __FUNCTION__, __LINE__, info_in->if_name);
            memcpy(info_out, &interfaces[i], sizeof(interface_info_t));
            return 0;
        }
    }
    
    DHCPMGR_LOG_INFO("%s %d: Interface entry for %s not found, creating new entry\n", __FUNCTION__, __LINE__, info_in->if_name);
    /* Create new interface entry */
    if (interface_count >= MAX_INTERFACES) {
        DHCPMGR_LOG_ERROR("%s %d Maximum number of interfaces reached\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&global_mutex);
        return -1;
    }
    
    interface_info_t *new_info = &interfaces[interface_count];
    strncpy(new_info->if_name, info_in->if_name, MAX_STR_LEN - 1);
    new_info->if_name[MAX_STR_LEN - 1] = '\0';
    strncpy(new_info->mq_name, info_in->mq_name, MAX_STR_LEN - 1);
    new_info->mq_name[MAX_STR_LEN - 1] = '\0';
    new_info->thread_running = false;
    pthread_mutex_init(&new_info->q_mutex, NULL);
    
    interface_count++;
    
    pthread_mutex_unlock(&global_mutex);
    memcpy(info_out, new_info, sizeof(interface_info_t));
    return 0;
}

/* Create a thread for the interface */
int create_interface_thread(char *info_ifName) {
    DHCPMGR_LOG_INFO("%s %d: Creating thread for interface %s\n", __FUNCTION__, __LINE__, info_ifName);
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, DhcpMgr_MainController, info_ifName) != 0) {
        DHCPMGR_LOG_ERROR("%s %d pthread_create failed for interface %s\n", __FUNCTION__, __LINE__, info_ifName);
        return -1;
    }
    
    pthread_detach(thread_id);
    DHCPMGR_LOG_INFO("%s %d Thread created for interface %s\n", __FUNCTION__, __LINE__, info_ifName);
    return 0;
}

/* Update interface info in the global array */
int update_interface_info(const char *alias_name, interface_info_t *info) {
//    DHCPMGR_LOG_INFO("%s %d: Updating interface info for %s\n", __FUNCTION__, __LINE__, alias_name);
    pthread_mutex_lock(&global_mutex);
    
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interfaces[i].if_name, alias_name) == 0) {
            memcpy(&interfaces[i], info, sizeof(interface_info_t));
            pthread_mutex_unlock(&global_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&global_mutex);
    return -1;
}

/* Common helper: send a control message to the per-interface controller queue
   and ensure its controller thread exists. Returns 0 on success, -1 on error. */
int DhcpMgr_OpenQueueEnsureThread(interface_info_t *info)
{
    if (!info)
    {
        DHCPMGR_LOG_ERROR("%s %d Invalid info argument\n", __FUNCTION__, __LINE__);
        return -1;
    }
    if (info->if_name[0] == '\0')
    {
        DHCPMGR_LOG_ERROR("%s %d Missing interface name in info\n", __FUNCTION__, __LINE__);
        return -1;
    }

    memset(info->mq_name, 0, sizeof(info->mq_name));
    snprintf(info->mq_name, sizeof(info->mq_name), "/mq_if_%s", info->if_name);
    DHCPMGR_LOG_INFO("%s %d Attempting to open message queue %s\n", __FUNCTION__, __LINE__, info->mq_name);

    mqd_t mq_desc = mq_open(info->mq_name, O_WRONLY | O_NONBLOCK);
    if (mq_desc == (mqd_t)-1)
    {
        DHCPMGR_LOG_ERROR("%s %d Failed to open message queue %s\n", __FUNCTION__, __LINE__, info->mq_name);
        // Try to create the queue if it doesn't exist
        char created_name[MQ_NAME_LEN] = {0};
        mqd_t created_desc = (mqd_t)-1;
        if (create_message_queue(info->if_name, created_name, &created_desc) == 0)
        {
            // Use the newly created descriptor for sending
            strncpy(info->mq_name, created_name, sizeof(info->mq_name) - 1);
            mq_desc = created_desc;
            DHCPMGR_LOG_INFO("%s %d Created message queue successfully\n", __FUNCTION__, __LINE__);
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s %d Unable to create message queue %s\n", __FUNCTION__, __LINE__, info->mq_name);
            return -1;
        }
    }

 //   info->thread_running = TRUE;

    interface_info_t tmp_info;
    memset(&tmp_info, 0, sizeof(tmp_info));
    if (find_or_create_interface(info, &tmp_info) == 0)
    {
        DHCPMGR_LOG_INFO("%s %d Thread running %d\n", __FUNCTION__, __LINE__, tmp_info.thread_running);
        if (!tmp_info.thread_running)
        {
            if (create_interface_thread(info->mq_name) == 0)
            {
                DHCPMGR_LOG_INFO("%s %d Controller thread started for %s\n", __FUNCTION__, __LINE__, info->if_name);
                tmp_info.thread_running = TRUE;
                update_interface_info(info->if_name, &tmp_info);   //TODO need to check why its required
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s %d Failed to create controller thread for %s\n", __FUNCTION__, __LINE__, info->if_name);
                mq_close(mq_desc);
                return -1;
            }
        }
        else
        {
            DHCPMGR_LOG_INFO("%s %d Thread already running for %s\n", __FUNCTION__, __LINE__, info->if_name);
        }
    }
    pthread_mutex_lock(&tmp_info.q_mutex); // Lock the mutex before sending message
    /* Send the filled info to the controller queue */
    if (mq_send(mq_desc, (char*)info, sizeof(*info), 0) == -1)
    {
        DHCPMGR_LOG_ERROR("%s %d Failed to send message to queue %s\n", __FUNCTION__, __LINE__, info->mq_name);
        mq_close(mq_desc);
        pthread_mutex_unlock(&tmp_info.q_mutex);
        return -1;
    }
    DHCPMGR_LOG_INFO("%s %d Successfully sent message to controller queue %s\n", __FUNCTION__, __LINE__, info->mq_name);
    mq_close(mq_desc);
    pthread_mutex_unlock(&tmp_info.q_mutex);
    return 0;
}

/********************DHCPMgr queue requirements End ***************************/

#ifdef FEATURE_RDKB_WAN_MANAGER
static ANSC_STATUS RdkBus_GetParamValues( char *pComponent, char *pBus, char *pParamName, char *pReturnVal )
{
    parameterValStruct_t   **retVal;
    char                   *ParamName[1];
    int                    ret               = 0,
                           nval;

    //Assign address for get parameter name
    ParamName[0] = pParamName;

    ret = CcspBaseIf_getParameterValues(
                                    bus_handle,
                                    pComponent,
                                    pBus,
                                    ParamName,
                                    1,
                                    &nval,
                                    &retVal);

    //Copy the value
    if( CCSP_SUCCESS == ret )
    {
        if( NULL != retVal[0]->parameterValue )
        {
            memcpy( pReturnVal, retVal[0]->parameterValue, strlen( retVal[0]->parameterValue ) + 1 );
        }

        if( retVal )
        {
            free_parameterValStruct_t (bus_handle, nval, retVal);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if( retVal )
    {
       free_parameterValStruct_t (bus_handle, nval, retVal);
    }

    return ANSC_STATUS_FAILURE;
}
#endif

static int Get_comp_namespace(char* compName,char* dbusPath,char *obj_name){


        if(!obj_name || AnscSizeOfString(obj_name) == 0) return -1;

        char                        dst_pathname_cr[256] = {0};
        componentStruct_t **        ppComponents = NULL;
        errno_t                     safec_rc = -1;
        int                         size = 0;
        int                         ret = -1;

        safec_rc = sprintf_s(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
        if(safec_rc < EOK)
        {
                ERR_CHK(safec_rc);
        }

        ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle, dst_pathname_cr, obj_name, g_Subsystem, &ppComponents, &size);

        if ( ret == CCSP_SUCCESS && size == 1)
        {
                strncpy(compName, ppComponents[0]->componentName, MAX_STR_SIZE);
                strncpy(dbusPath, ppComponents[0]->dbusPath, MAX_STR_SIZE);
                free_componentStruct_t(bus_handle, size, ppComponents);
                return 1;
        }
        free_componentStruct_t(bus_handle, size, ppComponents);

        return 0;

}

static int Get_comp_paramvalue(char* compName,char* dbusPath,char *param_name,char *param_value){


        if(!param_name || AnscSizeOfString(param_name) == 0) return -1;
        char*                       getList[1] = {0};
        int                         val_size=0;
        int                         ret = -1;
        parameterValStruct_t **parameterval = NULL;

        getList[0]=param_name;
        ret = CcspBaseIf_getParameterValues(bus_handle,compName,dbusPath,getList,1, &val_size, &parameterval);



        if(ret == CCSP_SUCCESS){
                strncpy(param_value, parameterval[0]->parameterValue, MAX_STR_SIZE);
                free_parameterValStruct_t (bus_handle, val_size, parameterval);
                return 1;
        }

        free_parameterValStruct_t (bus_handle, val_size, parameterval);
        return 0;
}

ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */


    return g_GetInstanceNumberByIndex(g_pDslhDmlAgent, pObjName, ulIndex);
}

int GetInstanceNumberByIndex(char* pObjName,unsigned int* Inscont,unsigned int** InsArray){
    int ret = -1;
    char comp_name[MAX_STR_SIZE];
    char dbus_path[MAX_STR_SIZE];


    ret = Get_comp_namespace(comp_name,dbus_path,pObjName);

    if(ret){
        if(CcspBaseIf_GetNextLevelInstances(bus_handle,comp_name,dbus_path,pObjName,Inscont,InsArray) == CCSP_SUCCESS){
           return 0;
        }
    }

    return 1;

}

int g_GetParamValueString(ANSC_HANDLE g_pDslhDmlAgent, char* prefixFullName, char* prefixValue,PULONG uSize){

        UNUSED(g_pDslhDmlAgent);
        return CosaGetParamValueString(prefixFullName, prefixValue, &uSize);
}

int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    )
{
    char        acTmpReturnValue[256] = {0};
    int         ret = -1;
    char        comp_name[MAX_STR_SIZE];
    char        dbus_path[MAX_STR_SIZE];

#ifdef FEATURE_RDKB_WAN_MANAGER
    if (strstr(pParamName, ETHERNET_INTERFACE_OBJECT))
    {
        if (ANSC_STATUS_FAILURE == RdkBus_GetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, pParamName, acTmpReturnValue))
        {
            DHCPMGR_LOG_ERROR("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__);
            return -1;
        }
        strncpy(pBuffer, acTmpReturnValue, strlen(acTmpReturnValue));
        *pulSize = strlen(acTmpReturnValue) + 1;
        return 0;
    }
#endif
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */



    ret = Get_comp_namespace(comp_name,dbus_path,pParamName);

    if(ret){

        ret=Get_comp_paramvalue(comp_name,dbus_path,pParamName,acTmpReturnValue);
        if(ret){

                strncpy(pBuffer, acTmpReturnValue, strlen(acTmpReturnValue));
                *pulSize = strlen(acTmpReturnValue) + 1;
                return 0;
        }

    }

        return 1;
}


PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword
    )
{

    unsigned int                    ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           ulEntryNameLen;
    CHAR                            ucEntryParamName[256]       = {0};
    CHAR                            ucEntryNameValue[256]       = {0};
    CHAR                            ucTmp[128]                  = {0};
    CHAR                            ucTmp2[128]                 = {0};
    CHAR                            ucEntryFullPath[256]        = {0};
    PUCHAR                          pMatchedLowerLayer          = NULL;
    unsigned int*                   ulEntryInstanceNum          = NULL;
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;
    PCHAR                           pString                     = NULL;
    PCHAR                           pString2                    = NULL;
    errno_t                         rc                          = -1;

    if ( !pTableName || AnscSizeOfString((const char*)pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString((const char*)pKeyword) == 0   ||
         !pParameterName   || AnscSizeOfString((const char*)pParameterName) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate((char*)pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
         /* Array compared against 0*/
            /* Get the string XXXNumberOfEntries */
            pString2 = &pTableStringToken->Name[0];
            pString  = pString2;
            for (i = 0;pTableStringToken->Name[i]; i++)
            {
                if ( pTableStringToken->Name[i] == '.' )
                {
                    pString2 = pString;
                    pString  = &pTableStringToken->Name[i+1];
                }
            }

            pString--;
            pString[0] = '\0';
            //rc = sprintf_s(ucTmp2, sizeof(ucTmp2), "%sNumberOfEntries", pString2);
            rc = sprintf_s(ucTmp2, sizeof(ucTmp2), "%s.", pString2);
            if(rc < EOK)
            {
              ERR_CHK(rc);
              continue;
            }
            pString[0] = '.';

            /* Enumerate the entry in this table */
            if ( TRUE )
            {
                pString2--;
                pString2[0]='\0';
                rc = sprintf_s(ucTmp, sizeof(ucTmp), "%s.%s", pTableStringToken->Name, ucTmp2);
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  continue;
                }

                pString2[0]='.';

                GetInstanceNumberByIndex (ucTmp,&ulNumOfEntries,&ulEntryInstanceNum);

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {

                    if ( ulEntryInstanceNum[i] )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath), "%s%d.", pTableStringToken->Name, ulEntryInstanceNum[i]);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }


                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath, pParameterName);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }


                        ulEntryNameLen = sizeof(ucEntryNameValue);
                        memset(ucEntryNameValue,0,sizeof(ucEntryNameValue));

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, (char*)pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);
                            break;
                        }

                    }
                }
            }

            if ( pMatchedLowerLayer )
            {
                break;
            }

        AnscFreeMemory(pTableStringToken);

        if ( ulEntryInstanceNum ){
             AnscFreeMemory(ulEntryInstanceNum);
        }
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }


    return pMatchedLowerLayer;
}

ANSC_STATUS is_usg_in_bridge_mode(BOOL *pBridgeMode)
{
    char retVal[128] = {'\0'};
    ULONG retLen;
        retLen = sizeof( retVal );
    if (pBridgeMode == NULL)
        return ANSC_STATUS_FAILURE;

    if (0 == CosaGetParamValueString(
                "Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode",
                retVal,
                &retLen)){
        if (strcmp(retVal, "router") == 0)
            *pBridgeMode = FALSE;
        else
            *pBridgeMode = TRUE;
        return ANSC_STATUS_SUCCESS;
    }else
        return ANSC_STATUS_FAILURE;

}


ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}


PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContextEntry->InstanceNumber == InstanceNumber )
            {
                return pCosaContextEntry;
            }
        }
    }

    return NULL;
}


int commonSyseventFd = -1;
token_t commonSyseventToken;

static int openCommonSyseventConnection() {
    if (commonSyseventFd == -1) {
        //commonSyseventFd = s_sysevent_connect(&commonSyseventToken);
        if (IFL_SUCCESS != ifl_init_ctx("cosa_apis_util", IFL_CTX_STATIC))
        {
            DHCPMGR_LOG_ERROR("Failed to init ifl ctx for cosa_apis_util");
        }
        else
        {
            commonSyseventFd = 0;
        }
    }
    return 0;
}

int commonSyseventSet(char* key, char* value){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    //return sysevent_set(commonSyseventFd, commonSyseventToken, key, value, 0);
    return ifl_set_event(key, value);
}

int commonSyseventGet(char* key, char* value, int valLen){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    //return sysevent_get(commonSyseventFd, commonSyseventToken, key, value, valLen);
    return ifl_get_event(key, value, valLen);
}

int commonSyseventClose() {
    int retval;

    if(commonSyseventFd == -1) {
        return 0;
    }

    //retval = sysevent_close(commonSyseventFd, commonSyseventToken);
    retval = ifl_deinit_ctx("cosa_apis_util");
    commonSyseventFd = -1;
    return retval;
}

void _get_shell_output(FILE *fp, char *buf, int len)
{
    char * p;

    if (fp)
    {
        if(fgets (buf, len-1, fp) != NULL)
        {
            buf[len-1] = '\0';
            if ((p = strchr(buf, '\n'))) {
                *p = '\0';
            }
        }
    v_secure_pclose(fp);
    }
}

int _get_shell_output2(FILE *fp, char * dststr)
{
    char   buf[256];
//    char * p;
    int   bFound = 0;

    if (fp)
    {
        while( fgets(buf, sizeof(buf), fp) )
        {
            if (strstr(buf, dststr))
            {
                bFound = 1;;
                break;
            }
        }

        v_secure_pclose(fp);
    }

    return bFound;
}


char *safe_strcpy (char *dst, char *src, size_t dst_size)
{
    size_t len;

    if (dst_size == 0)
        return dst;

    len = strlen (src);

    if (len >= dst_size)
    {
        dst[dst_size - 1] = 0;
        return memcpy (dst, src, dst_size - 1);
    }

    return memcpy (dst, src, len + 1);
}

ANSC_STATUS fillCurrentPartnerId
        (
                char*                       pValue,
        PULONG                      pulSize
    )
{
        char buf[PARTNER_ID_LEN];
        memset(buf, 0, sizeof(buf));
    if(ANSC_STATUS_SUCCESS == syscfg_get( NULL, "PartnerID", buf, sizeof(buf)))
    {
         strncpy(pValue ,buf,strlen(buf));
         *pulSize = AnscSizeOfString(pValue);
         return ANSC_STATUS_SUCCESS;
    }
        else
                return ANSC_STATUS_FAILURE;

}


int writeToJson(char *data, char *file)
{
    if (file == NULL || data == NULL)
    {
        DHCPMGR_LOG_WARNING("%s : %d Invalid input parameter", __FUNCTION__,__LINE__);
        return -1;
    }
    FILE *fp;
    fp = fopen(file, "w");
    if (fp == NULL )
    {
        DHCPMGR_LOG_WARNING("%s : %d Failed to open file %s\n", __FUNCTION__,__LINE__,file);
        return -1;
    }

    fwrite(data, strlen(data), 1, fp);
    fclose(fp);
    return 0;
}


ANSC_STATUS UpdateJsonParamLegacy
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue
    )
{
        cJSON *partnerObj = NULL;
        cJSON *json = NULL;
        FILE *fileRead = NULL;
        char * cJsonOut = NULL;
        char* data = NULL;
         int len ;
         int configUpdateStatus = -1;
         fileRead = fopen( PARTNERS_INFO_FILE, "r" );
         if( fileRead == NULL )
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ );
                 return ANSC_STATUS_FAILURE;
         }

         fseek( fileRead, 0, SEEK_END );
         len = ftell( fileRead );
         /* Argument cannot be negative*/
         if(len < 0) {
               DHCPMGR_LOG_WARNING("%s-%d : Error in file handle\n" , __FUNCTION__, __LINE__ );
               fclose( fileRead );
               return ANSC_STATUS_FAILURE;
         }
         fseek( fileRead, 0, SEEK_SET );
         data = ( char* )malloc( sizeof(char) * (len + 1) );
         if (data != NULL)
         {
                memset( data, 0, ( sizeof(char) * (len + 1) ));
                int chk_ret = fread( data, 1, len, fileRead );
                if(chk_ret <=0){
                 DHCPMGR_LOG_WARNING("%s-%d : Failed to read the data from file \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 free(data);
                 return ANSC_STATUS_FAILURE;
                }
         }
         else
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 return ANSC_STATUS_FAILURE;
         }

         fclose( fileRead );
         /* String not null terminated*/
         data[len]='\0';
         if ( data == NULL )
         {
                DHCPMGR_LOG_WARNING("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__);
                return ANSC_STATUS_FAILURE;
         }
         else if ( strlen(data) != 0)
         {
                 json = cJSON_Parse( data );
                 if( !json )
                 {
                         DHCPMGR_LOG_WARNING(  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__);
                         free(data);
                         return ANSC_STATUS_FAILURE;
                 }
                 else
                 {
                         partnerObj = cJSON_GetObjectItem( json, PartnerId );
                         if ( NULL != partnerObj)
                         {
                                 if (NULL != cJSON_GetObjectItem( partnerObj, pKey) )
                                 {
                                         cJSON_ReplaceItemInObject(partnerObj, pKey, cJSON_CreateString(pValue));
                                         cJsonOut = cJSON_Print(json);
                                         DHCPMGR_LOG_WARNING( "Updated json content is %s\n", cJsonOut);
                                         configUpdateStatus = writeToJson(cJsonOut, PARTNERS_INFO_FILE);
                                         free(cJsonOut);
                                         if ( !configUpdateStatus)
                                         {
                                                 DHCPMGR_LOG_WARNING( "Updated Value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s - Value:%s\n",pKey,pValue);
                                         }
                                         else
                                        {
                                                 DHCPMGR_LOG_WARNING( "Failed to update value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s\n",pKey);
                                                 cJSON_Delete(json);
                                                 return ANSC_STATUS_FAILURE;
                                        }
                                 }
                                else
                                {
                                        DHCPMGR_LOG_WARNING("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ );
                                        cJSON_Delete(json);
                                        return ANSC_STATUS_FAILURE;
                                }

                         }
                         else
                         {
                                DHCPMGR_LOG_WARNING("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ );
                                cJSON_Delete(json);
                                return ANSC_STATUS_FAILURE;
                         }
                        cJSON_Delete(json);
                 }
          }
          else
          {
                DHCPMGR_LOG_WARNING("PARTNERS_INFO_FILE %s is empty\n", PARTNERS_INFO_FILE);
                /* Resource leak*/
                if (data)
                   free(data);
                return ANSC_STATUS_FAILURE;
          }
         return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS UpdateJsonParam
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue,
                char*                   pSource,
                char*                   pCurrentTime
    )
{
        cJSON *partnerObj = NULL;
        cJSON *json = NULL;
        FILE *fileRead = NULL;
        char * cJsonOut = NULL;
        char* data = NULL;
         int len ;
         int configUpdateStatus = -1;
         fileRead = fopen( BOOTSTRAP_INFO_FILE, "r" );
         if( fileRead == NULL )
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ );
                 return ANSC_STATUS_FAILURE;
         }

         fseek( fileRead, 0, SEEK_END );
         len = ftell( fileRead );
         /* Argument cannot be negative*/
         if (len < 0) {
             DHCPMGR_LOG_WARNING("%s-%d : Error in File handle\n" , __FUNCTION__, __LINE__ );
             fclose( fileRead );
             return ANSC_STATUS_FAILURE;
         }
         fseek( fileRead, 0, SEEK_SET );
         data = ( char* )malloc( sizeof(char) * (len + 1) );
         if (data != NULL)
         {
                memset( data, 0, ( sizeof(char) * (len + 1) ));
                int chk_ret = fread( data, 1, len, fileRead );
                if(chk_ret <= 0){
                 DHCPMGR_LOG_WARNING("%s-%d : Failed to read the data from file \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 free(data);
                 return ANSC_STATUS_FAILURE;
                }
         }
         else
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 return ANSC_STATUS_FAILURE;
         }

         fclose( fileRead );
         /* String not null terminated*/
         data[len] = '\0';
         if ( data == NULL )
         {
                DHCPMGR_LOG_WARNING("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__);
                return ANSC_STATUS_FAILURE;
         }
         else if ( strlen(data) != 0)
         {
                 json = cJSON_Parse( data );
                 if( !json )
                 {
                         DHCPMGR_LOG_WARNING(  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__);
                         free(data);
                         return ANSC_STATUS_FAILURE;
                 }
                 else
                 {
                         partnerObj = cJSON_GetObjectItem( json, PartnerId );
                         if ( NULL != partnerObj)
                         {
                                 cJSON *paramObj = cJSON_GetObjectItem( partnerObj, pKey);
                                 if (NULL != paramObj )
                                 {
                                         cJSON_ReplaceItemInObject(paramObj, "ActiveValue", cJSON_CreateString(pValue));
                                         cJSON_ReplaceItemInObject(paramObj, "UpdateTime", cJSON_CreateString(pCurrentTime));
                                         cJSON_ReplaceItemInObject(paramObj, "UpdateSource", cJSON_CreateString(pSource));

                                         cJsonOut = cJSON_Print(json);
                                         DHCPMGR_LOG_WARNING( "Updated json content is %s\n", cJsonOut);
                                         configUpdateStatus = writeToJson(cJsonOut, BOOTSTRAP_INFO_FILE);
                                         unsigned int flags = 0;
                                         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
                                         if (fp)
                                         {
                                             fscanf(fp, "%u", &flags);
                                             fclose(fp);
                                         }
                                         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
                                         {
                                             DHCPMGR_LOG_WARNING("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
                                             writeToJson(cJsonOut, BOOTSTRAP_INFO_FILE_BACKUP);
                                         }
                                         free(cJsonOut);
                                         if ( !configUpdateStatus)
                                         {
                                                 DHCPMGR_LOG_WARNING( "Bootstrap config update: %s, %s, %s, %s \n", pKey, pValue, PartnerId, pSource);
                                         }
                                         else
                                        {
                                                 DHCPMGR_LOG_WARNING( "Failed to update value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s\n",pKey);
                                                 cJSON_Delete(json);
                                                 return ANSC_STATUS_FAILURE;
                                        }
                                 }
                                else
                                {
                                        DHCPMGR_LOG_WARNING("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ );
                                        cJSON_Delete(json);
                                        return ANSC_STATUS_FAILURE;
                                }

                         }
                         else
                         {
                                DHCPMGR_LOG_WARNING("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ );
                                cJSON_Delete(json);
                                return ANSC_STATUS_FAILURE;
                         }
                        cJSON_Delete(json);
                 }
          }
          else
          {
                DHCPMGR_LOG_WARNING("BOOTSTRAP_INFO_FILE %s is empty\n", BOOTSTRAP_INFO_FILE);
                free(data);
                return ANSC_STATUS_FAILURE;
          }

         //Also update in the legacy file /nvram/partners_defaults.json for firmware roll over purposes.
         UpdateJsonParamLegacy(pKey, PartnerId, pValue);

         return ANSC_STATUS_SUCCESS;
}

/*
int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost){


        if(!mac || AnscSizeOfString((const char*)mac) == 0) return -1;
        ULONG                       NumberofEntries = 0;
        char                        ucEntryFullPath[MAX_STR_SIZE]={0};
        char                        ucEntryParamName[MAX_STR_SIZE]={0};
        char                        lm_param_name[MAX_STR_SIZE]={0};
        char                        ucEntryNameValue[MAX_STR_SIZE]={0};
        ULONG                       i;
        ULONG                       ulEntryInstanceNum;
        ULONG                       ulEntryNameLen;
        errno_t                     rc= -1;




        memset(lm_param_name,0,MAX_STR_SIZE);
        strncpy(lm_param_name,"Device.Hosts.HostNumberOfEntries", MAX_STR_SIZE);

        NumberofEntries = CosaGetParamValueUlong(lm_param_name);

        memset(lm_param_name,0,MAX_STR_SIZE);
        strncpy(lm_param_name,"Device.Hosts.Host.", MAX_STR_SIZE);

        for ( i = 0 ; i < NumberofEntries; i++ )
        {
                ulEntryInstanceNum = CosaGetInstanceNumberByIndex(lm_param_name, i);

                if ( ulEntryInstanceNum )
                {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath), "%s%lu.", lm_param_name, ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }

                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath, "PhysAddress");
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }

                        ulEntryNameLen = sizeof(ucEntryNameValue);
                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, (char*)mac) == 0))
                        {
                                memset(ucEntryParamName,0,sizeof(ucEntryParamName));

                                rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath,"Layer1Interface");
                                if(rc < EOK)
                                {
                                  ERR_CHK(rc);
                                  continue;
                                }
                                ulEntryNameLen = sizeof(ucEntryNameValue);
                                if(0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)){

                                        strncpy(pHost->data.host.l1IfName, ucEntryNameValue, sizeof(pHost->data.host.l1IfName));
                                        pHost->result=0;
                                }else{
                                        DHCPMGR_LOG_ERROR("%s failed to get ucEntryParamName = %s\n",__FUNCTION__,ucEntryParamName);
                               }

                            break;
                            return 0;
                        }
                    }
                }

       return -1;
}
*/

#ifdef DHCPV6C_PSM_ENABLE
INT PsmWriteParameter( char *pParamName, char *pParamVal )
{
    INT     retPsmSet  = CCSP_SUCCESS;

    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        DHCPMGR_LOG_ERROR("%s Invalid Input Parameters\n", __FUNCTION__);
        return CCSP_FAILURE;
    }

    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, pParamName, ccsp_string, pParamVal);
    if (retPsmSet != CCSP_SUCCESS)
    {
        DHCPMGR_LOG_INFO("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, pParamName, pParamVal);
    }

    return retPsmSet;
}

INT PsmReadParameter( char *pParamName, char *pReturnVal, int returnValLength )
{
    INT     retPsmGet     = CCSP_SUCCESS;
    CHAR   *param_value   = NULL;

    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        DHCPMGR_LOG_ERROR("%s Invalid Input Parameters\n", __FUNCTION__);
        return CCSP_FAILURE;
    }

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, pParamName, NULL, &param_value);
    if (retPsmGet != CCSP_SUCCESS) {
        DHCPMGR_LOG_ERROR("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, pParamName);
    }
    else {
        snprintf(pReturnVal, returnValLength, "%s", param_value);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    }

    return retPsmGet;
}
#endif //DHCPV6C_PSM_ENABLE
