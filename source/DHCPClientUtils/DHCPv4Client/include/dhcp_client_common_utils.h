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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DHCPV_CLIENT_UTILS_H
#define DHCPV_CLIENT_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include "syscfg/syscfg.h"
#include <sys/stat.h>
//#include "platform_hal.h"
#include "rdk_debug.h"

typedef  unsigned long              ULONG;

#ifndef TRUE
#define TRUE     1
#endif

#ifndef FALSE
#define FALSE    0
#endif

#ifndef ENABLE
#define ENABLE   1
#endif

#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif

#define TRUE_STR               "true"
//#define TRUE                   1
//#define FALSE                  0
#define SUCCESS                0
#define FAILURE                1
#define BUFLEN_4               4           //!< buffer length 4
#define BUFLEN_8               8           //!< buffer length 8
#define BUFLEN_16              16          //!< buffer length 16
#define BUFLEN_18              18          //!< buffer length 18
#define BUFLEN_24              24          //!< buffer length 24
#define BUFLEN_32              32          //!< buffer length 32
#define BUFLEN_40              40          //!< buffer length 40
#define BUFLEN_48              48          //!< buffer length 48
#define BUFLEN_64              64          //!< buffer length 64
#define BUFLEN_80              80          //!< buffer length 80
#define BUFLEN_128             128         //!< buffer length 128
#define BUFLEN_256             256         //!< buffer length 256
#define BUFLEN_264             264         //!< buffer length 264
#define BUFLEN_512             512         //!< buffer length 512
#define BUFLEN_1024            1024        //!< buffer length 1024
#define CONSOLE_LOG_FILE       "/rdklogs/logs/DHCPMGRLog.txt.0"

#define COLLECT_WAIT_INTERVAL_MS          4
#define USECS_IN_MSEC                     1000
#define MSECS_IN_SEC                      1000
#define RETURN_PID_TIMEOUT_IN_MSEC        (5 * MSECS_IN_SEC)    // 5 sec
#define RETURN_PID_INTERVAL_IN_MSEC       (0.5 * MSECS_IN_SEC)  // 0.5 sec - half a second
#define INTF_V6LL_TIMEOUT_IN_MSEC        (5 * MSECS_IN_SEC)    // 5 sec
#define INTF_V6LL_INTERVAL_IN_MSEC       (0.5 * MSECS_IN_SEC)  // 0.5 sec - half a second


//DHCPv6 Options
#define DHCPV6_OPT_82  82  // OPTION_SOL_MAX_RT: Solicite Maximum Retry Time
#define DHCPV6_OPT_23  23  // OPTION_SOL_MAX_RT: Solicite Maximum Retry Time
#define DHCPV6_OPT_95  95  // OPTION_SOL_MAX_RT: Solicite Maximum Retry Time
#define DHCPV6_OPT_24  24  // OPTION_DOMAIN_LIST
#define DHCPV6_OPT_83  83  // OPTION_INF_MAX_RT
#define DHCPV6_OPT_17  17  // OPTION_VENDOR_OPTS
#define DHCPV6_OPT_31  31  // OPTION_SNTP_SERVERS
#define DHCPV6_OPT_14  14   //Rapid Commit Option
#define DHCPV6_OPT_15  15  // User Class Option
#define DHCPV6_OPT_16  16  // Vendor Class Option
#define DHCPV6_OPT_20  20  // Reconfigure Accept Option
#define DHCPV6_OPT_3    3  // Identity Association for Non-temporary Addresses Option
#define DHCPV6_OPT_5    5  // IA Address Option
#define DHCPV6_OPT_22  22  // OPTION_SIP_SERVER_A
#define DHCPV6_OPT_25  25  // Identity Association for Prefix Delegation Option
#define DHCPV6_OPT_64  64  // OPTION_AFTR_NAME

//DHCPv4 Options
#define DHCPV4_OPT_2   2   // Time Offset
#define DHCPV4_OPT_4   4   // Time Server
#define DHCPV4_OPT_7   7   // Log Server
#define DHCPV4_OPT_42  42  // NTP Server Addresses
#define DHCPV4_OPT_43  43  // Vendor Specific Information
#define DHCPV4_OPT_54  54  // DHCP Server Identifier
#define DHCPV4_OPT_58  58  // DHCP Renewal (T1) Time
#define DHCPV4_OPT_59  59  // DHCP Rebinding (T2) Time
#define DHCPV4_OPT_60  60  // Class Identifier
#define DHCPV4_OPT_61  61  // Client Identifier
#define DHCPV4_OPT_99  99  // TFTP Server IP Address
#define DHCPV4_OPT_100 100 // IEEE 1003.1 TZ String
#define DHCPV4_OPT_122 122 // CableLabs Client Configuration
#define DHCPV4_OPT_123 123 // Time zone offset
#define DHCPV4_OPT_125 125 // Vendor-Identifying Vendor-Specific Information
#define DHCPV4_OPT_242 242 // Private Use
#define DHCPV4_OPT_243 243 // Private Use
#define DHCPV4_OPT_END 255 // DHCP Option End - used to check if option is valid
#define DHCPV4_OPT_120 120 //DHCP Req option for sipsrv
#define DHCPV4_OPT_121 121 //DHCP Req option for classless static routes

//DHCPv6 Options



/*#define DBG_PRINT(fmt ...)     {\
    FILE     *fp        = NULL;\
    fp = fopen ( CONSOLE_LOG_FILE, "a+");\
    if (fp)\
    {\
        fprintf(fp,fmt);\
        fclose(fp);\
    }\
}\*/


#define DBG_PRINT(fmt, arg...) \
          RDK_LOG(RDK_LOG_INFO, "LOG.RDK.DHCPMGR", fmt, ##arg);

#define UNUSED_VARIABLE(x) (void)(x)


typedef enum {
    WAN_LOCAL_IFACE = 1,
    WAN_REMOTE_IFACE,
} IfaceType;

typedef struct dhcp_opt {
    char * ifname;      // VLAN interface name
    char * baseIface;   // Base interface name
    IfaceType ifType;
    bool is_release_required;
} dhcp_params;

/* DHCP options linked list */
typedef struct dhcp_option_list {
    int dhcp_opt;
    char *dhcp_opt_val;
    struct dhcp_option_list *next;
} dhcp_opt_list;

pid_t start_exe(char * exe, char * args);
pid_t start_exe2(char * exe, char * args);
pid_t get_process_pid (char * name, char * args, bool waitForProcEntry);
int collect_waiting_process(int pid, int timeout);
void free_opt_list_data (dhcp_opt_list * opt_list);
int signal_process (pid_t pid, int signal);
int add_dhcp_opt_to_list (dhcp_opt_list ** opt_list, int opt, char * opt_val);
void create_dir_path(const char *dirpath);

void processKilled(pid_t pid);

#endif //DHCPV_CLIENT_UTILS_H
