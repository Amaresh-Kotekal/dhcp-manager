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

/*********************************************************************************

    description:

        This is the template file of ssp_main.c for XxxxSsp.
        Please replace "XXXX" with your own ssp name with the same up/lower cases.

  ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/


#ifdef __GNUC__
#ifndef _BUILD_ANDROID
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#include "stdlib.h"
#include "ccsp_dm_api.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"
#include "syscfg/syscfg.h"
#include "cap.h"
#include "safec_lib_common.h"
#include "ifl.h"

#ifdef DHCPV4_SERVER_SUPPORT
#include "service_dhcp_server.h"
#include "dhcpv4_server_interface.h"
#endif

#include "util.h"

#include "dhcpmgr_controller.h"
#include "dhcpmgr_rbus_apis.h"
#include <telemetry_busmessage_sender.h>

#ifdef DHCPV6_SERVER_SUPPORT
extern void dhcpv6_server_init();
#endif

extern void remove_file(char *);

static cap_user appcaps;

int GetLogInfo(ANSC_HANDLE bus_handle, char *Subsytem, char *pParameterName);
extern char*                                pComponentName;
char                                        g_Subsystem[32]         = {0};
extern ANSC_HANDLE bus_handle;

int  cmd_dispatch(int  command)
{
  
  errno_t rc = -1;
    switch ( command )
    {
        case    'e' :

            DHCPMGR_LOG_INFO("Connect to bus daemon...\n");

            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                   rc = sprintf_s(CName, sizeof(CName), "%s%s", g_Subsystem, CCSP_COMPONENT_ID_DHCPMGR);
                  if (rc < EOK)
                  {
                  ERR_CHK(rc);
                  return -1;
                  }
                  
                }
                else
                {
                    rc = sprintf_s(CName, sizeof(CName), "%s", CCSP_COMPONENT_ID_DHCPMGR);
                   if (rc < EOK)
                  {
                  ERR_CHK(rc);
                  return -1;
                  }
                }

                ssp_Mbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        CCSP_COMPONENT_PATH_DHCPMGR
                    );
            }

            ssp_create();
            ssp_engage();

            break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':
                
                ssp_cancel();

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, 2 );

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
            DHCPMGR_LOG_WARNING("%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

static void daemonize(void) {
        switch (fork()) {
        case 0:
             break;
        case -1:
              // Error
                DHCPMGR_LOG_INFO("error d(a)emonizing (fork)! %d - %s\n", errno, strerror(errno));
                exit(0);
                break;
        default:
                _exit(0);
        }

        /*creates a session and sets the process group ID */
        if (setsid() < 0) {
                DHCPMGR_LOG_INFO("error d(a)emonizing (setsid)! %d - %s\n", errno, strerror(errno));
                exit(0);
        }

#ifndef  _DEBUG
        int fd;

        /*Duplicate an Null File Descriptor to Standard Input file descriptor */
        fd = open("/dev/null", O_RDONLY);
        if (fd != 0) {
                dup2(fd, 0);
                close(fd);
        }

        /*Duplicate an Null File Descriptor to Standard Output file descriptor */
        fd = open("/dev/null", O_WRONLY);
        if (fd != 1) {
                dup2(fd, 1);
                close(fd);
        }

        /*Duplicate an Null File Descriptor to Standard Error file descriptor */
        fd = open("/dev/null", O_WRONLY);
        if (fd != 2) {
                dup2(fd, 2);
                close(fd);
        }
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
        signal(SIGINT, sig_handler); /* reset it to this function */
        DHCPMGR_LOG_INFO("SIGINT received!\n");
        exit(0);
    }
    else if ( sig == SIGUSR1 ) {
        signal(SIGUSR1, sig_handler); /* reset it to this function */
        DHCPMGR_LOG_INFO("SIGUSR1 received!\n");
    }
    else if ( sig == SIGUSR2 ) {
        DHCPMGR_LOG_INFO("SIGUSR2 received!\n");
    }
    else if ( sig == SIGCHLD ) {
        signal(SIGCHLD, sig_handler); /* reset it to this function */
        DHCPMGR_LOG_INFO("SIGCHLD received!\n");
    }
    else if ( sig == SIGPIPE ) {
        signal(SIGPIPE, sig_handler); /* reset it to this function */
        DHCPMGR_LOG_INFO("SIGPIPE received!\n");
    }
    else if ( sig == SIGALRM ) 
    {

        signal(SIGALRM, sig_handler); /* reset it to this function */
        DHCPMGR_LOG_INFO("SIGALRM received!\n");
    }
    else {
        /* get stack trace first */
        _print_stack_backtrace();
        DHCPMGR_LOG_INFO("Signal %d received, exiting!\n", sig);
        exit(0);
    }

}


#ifndef INCLUDE_BREAKPAD
static int is_core_dump_opened(void)
{
    FILE *fp;
    char path[256];
    char line[1024];
    char *start, *tok, *sp;
#define TITLE   "Max core file size"

    snprintf(path, sizeof(path), "/proc/%d/limits", getpid());
    if ((fp = fopen(path, "rb")) == NULL)
        return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if ((start = strstr(line, TITLE)) == NULL)
            continue;

        start += strlen(TITLE);
        if ((tok = strtok_r(start, " \t\r\n", &sp)) == NULL)
            break;

        fclose(fp);
        return (tok[0] == '0' && tok[1] == '\0') ? 0 : 1;
    }

    fclose(fp);
    return 0;
}
#endif

int main(int argc, char* argv[])
{
    BOOL                            bRunAsDaemon       = TRUE;
    int                             cmdChar            = 0;
    int                             idx = 0;
    FILE *fd = NULL;
    char pid_buf[12]={0};
    appcaps.caps = NULL;
    appcaps.user_name = NULL;
    extern ANSC_HANDLE bus_handle;
    char *subSys            = NULL;  
    DmErr_t    err;
    errno_t        rc = -1;
    int ind = -1;

    DHCPMGR_LOG_INFO("\nWithin the main function\n");

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif

    if (access("/tmp/dhcpmgr_initialized", F_OK) == 0)
    {
        DHCPMGR_LOG_INFO("/tmp/dhcpmgr_initialized already exists, removing it");
        remove("/tmp/dhcpmgr_initialized");
    }

    for (idx = 1; idx < argc; idx++)
    {
         rc = strcmp_s("-subsys",strlen("-subsys"),argv[idx],&ind);
         ERR_CHK(rc);
         if((!ind) && (rc == EOK))
        {
           if ((idx+1) < argc)
           {
              rc = strcpy_s(g_Subsystem,sizeof(g_Subsystem), argv[idx+1]);
              if(rc != EOK)
             {
               ERR_CHK(rc);
               return ANSC_STATUS_FAILURE;
             }
           }
           else
           {
               DHCPMGR_LOG_ERROR("parameter after -subsys is missing");
           }
             
        }
        else
        {
           rc = strcmp_s("-c", strlen("-c"),argv[idx],&ind );
           ERR_CHK(rc);
           if((!ind) && (rc == EOK))
          {
            bRunAsDaemon = FALSE;
          }
       }
    }

    pComponentName          = CCSP_COMPONENT_NAME_DHCPMGR;

    if ( bRunAsDaemon ) 
        daemonize();

DHCPMGR_LOG_INFO("\nAfter daemonize before signal\n");
        /*This is used for DHCPMgr kill recovery */
        fd = fopen("/var/tmp/CcspDHCPMgr.pid", "w+");
        if ( !fd )
        {
            CcspTraceWarning(("Create /var/tmp/CcspDHCPMgr.pid error. \n"));
        }
        else
        {
            rc = sprintf_s(pid_buf, sizeof(pid_buf),"%d", getpid());
            if(rc < EOK)
            {
            ERR_CHK(rc);
            CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
            fclose(fd);
            exit(1);
            }
            fputs(pid_buf, fd);
            fclose(fd);
        }
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
    signal(SIGUSR1, sig_handler);    
#else
    if (is_core_dump_opened())
    {
        signal(SIGUSR1, sig_handler);
        DHCPMGR_LOG_WARNING("Core dump is opened, do not catch signal\n");
    }
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGALRM, sig_handler);
#endif

    DHCPMGR_LOG_INFO("DHCPMgr InterfaceLayer initialization started\n");
    // inti dhcpmgr interfacelayer
    if (ifl_init("DHCP-Mgr") == IFL_SUCCESS)
    {
        if (IFL_SUCCESS != ifl_init_ctx("DHCP-Mgr-main", IFL_CTX_STATIC))
        {
            DHCPMGR_LOG_ERROR("Failed to init ifl ctx for DHCP-Mgr-main\n");
        }
        DHCPMGR_LOG_INFO("DHCPMgr InterfaceLayer initialized.\n");
    }
    else
    {
        DHCPMGR_LOG_ERROR("Error in initialising DHCPMgr InterfaceLayer\n");
    }

    DHCPMGR_LOG_INFO("\nbefore cmd_dispatch command\n");

    cmd_dispatch('e');

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif
DHCPMGR_LOG_WARNING("\nBefore Cdm_Init\n");

    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
DHCPMGR_LOG_WARNING("\nAfter Cdm_Init\n");

    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
        exit(1);
    }

#ifdef DHCPV4_SERVER_SUPPORT
    //Init dhcpv4 server
    DHCPMGR_LOG_INFO("dhcp_server_init (dhcpv4 server) Started\n");
    dhcp_server_init();
    DHCPMGR_LOG_INFO("dhcp_server_init (dhcpv4 server) Ended\n");
#endif

#ifdef DHCPV6_SERVER_SUPPORT
    //Init dhcpv6 server
    DHCPMGR_LOG_INFO("dhcp_server_init (dhcpv6 server) Started\n");
    dhcpv6_server_init();
    DHCPMGR_LOG_INFO("dhcp_server_init (dhcpv6 server) Ended\n");
#endif
 
#ifdef DHCPV4_SERVER_SUPPORT
    //Init dhcp server services
    DHCPMGR_LOG_INFO("init_dhcp_server_service Started\n");
    init_dhcp_server_service();
    DHCPMGR_LOG_INFO("init_dhcp_server_service Ended\n");
#endif

    DHCPMGR_LOG_INFO("t2_init Init \n");
    t2_init("dhcp-manager");

    DHCPMGR_LOG_INFO("DhcpMgr_Rbus_Init Init \n");
    DhcpMgr_Rbus_Init();

    DHCPMGR_LOG_INFO("DhcpMgr_StartMainController Init \n");
    if (DhcpMgr_StartMainController() != 0)
    {
        DHCPMGR_LOG_ERROR("DhcpMgr_StartMainController failed - Lease Monitor could not start. "
                          "Exiting so systemd can restart the process.\n");
        t2_event_d("DHCPMGR_ERROR_LeaseMonitorFatalExit", 1);
        exit(1);
    }
    DHCPMGR_LOG_INFO("DhcpMgr_StartMainController Init Complete\n");

    system("touch /tmp/dhcpmgr_initialized");

    ifl_deinit_ctx("DHCP-Mgr-main");

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            cmd_dispatch(cmdChar);
        }
    }

        err = Cdm_Term();
        if (err != CCSP_SUCCESS)
        {
        fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
        exit(1);
        }
DHCPMGR_LOG_INFO("\n Before ssp_cancel() \n");
        ssp_cancel();
        //exit_rbus_service();
#if defined(_CBR_PRODUCT_REQ_) && !defined(_CBR2_PRODUCT_REQ_)
	serv_ipv6_term();
#endif
DHCPMGR_LOG_INFO("\nExiting the main function\n");
    return 0;
}
