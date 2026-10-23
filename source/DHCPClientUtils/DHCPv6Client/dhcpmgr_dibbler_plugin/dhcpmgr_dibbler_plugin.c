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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include "util.h"
#include "dhcp_lease_monitor_thrd.h"

#define MAX_SEND_THRESHOLD                   5

#define DHCPv6_INTERFACE_NAME                "IFACE"
#define DHCPv6_IANA_ADDRESS                  "ADDR1"
#define DHCPv6_IANA_IAID                     "ADDR1IAID"
#define DHCPv6_IANA_PREF_LIFETIME            "ADDR1PREF"
#define DHCPv6_IANA_VALID_LIFETIME           "ADDR1VALID"
#define DHCPv6_IANA_T1                       "ADDR1T1"
#define DHCPv6_IANA_T2                       "ADDR1T2"
#define DHCPv6_IAPD_PREFIX                   "PREFIX1"
#define DHCPv6_IAPD_PREFIXLEN                "PREFIX1LEN"
#define DHCPv6_IAPD_IAID                     "PREFIX1IAID"
#define DHCPv6_IAPD_PREF_LIFETIME            "PREFIX1PREF"
#define DHCPv6_IAPD_VALID_LIFETIME           "PREFIX1VALID"
#define DHCPv6_IAPD_T1                       "PREFIX1T1"
#define DHCPv6_IAPD_T2                       "PREFIX1T2"
#define DHCPv6_VENDOR_SPEC                   "SRV_OPTION17"
#define DHCPv6_OPTION_DNS                    "SRV_OPTION23"
#define DHCPv6_OPTION_DOMAIN                 "SRV_OPTION24"
#define DHCPv6_OPTION_NTP                    "SRV_OPTION31"
#define DHCPv6_OPTION_DSLITE                 "SRV_OPTION64"
#define DHCPv6_OPTION_MAPT                   "SRV_OPTION95"
#define DHCPv6_OPTION_MAPE                   "SRV_OPTION94"

/* Plugin is a standalone binary without rdklogger init, use direct file logging */
#define PLUGIN_DBG_PRINT(level, fmt, ...)     do {\
    int _fd = open("/rdklogs/logs/DHCPMGRLog.txt.0", O_WRONLY | O_CREAT | O_APPEND, 0640);\
    FILE *fp = (_fd >= 0) ? fdopen(_fd, "a") : NULL;\
    if (_fd >= 0 && fp == NULL) close(_fd);\
    if (fp)\
    {\
        struct timeval tv;\
        struct tm tm_info;\
        gettimeofday(&tv, NULL);\
        localtime_r(&tv.tv_sec, &tm_info);\
        fprintf(fp, "%02d%02d%02d-%02d:%02d:%02d.%06ld [mod=DHCPMGR, lvl=%s] " fmt,\
                tm_info.tm_year % 100, tm_info.tm_mon + 1, tm_info.tm_mday,\
                tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, (long)tv.tv_usec,\
                level, ##__VA_ARGS__);\
        fclose(fp);\
    }\
} while(0)

#undef DHCPMGR_LOG_INFO
#undef DHCPMGR_LOG_ERROR
#undef DHCPMGR_LOG_WARNING
#define DHCPMGR_LOG_INFO(fmt, ...)     PLUGIN_DBG_PRINT("INFO", fmt, ##__VA_ARGS__)
#define DHCPMGR_LOG_ERROR(fmt, ...)    PLUGIN_DBG_PRINT("ERROR", fmt, ##__VA_ARGS__)
#define DHCPMGR_LOG_WARNING(fmt, ...)  PLUGIN_DBG_PRINT("WARN", fmt, ##__VA_ARGS__)

static void trim(char *in)
{
    if (NULL == in)
    {
        return;
    }

    char *start = in;
    while (isspace((unsigned char)*start))
    {
        start++;
    }

    if (*start == '\0')
    {
        *in = '\0';
        return;
    }

    char *end = start + strlen(start) - 1;

    while (end >= start && isspace((unsigned char)*end))
    {
        *end = '\0';
        end--;
    }

    if (start != in)
    {
        size_t len = strlen(start) + 1;
        memmove(in, start, len);
    }
}

static int get_and_fill_env_data_dhcp6(DHCPv6_PLUGIN_MSG *dhcpv6_data, char *input_option)
{
    char *env;

    if (dhcpv6_data == NULL || input_option == NULL)
    {
        DHCPMGR_LOG_INFO("[%s-%d] Invalid argument", __FUNCTION__, __LINE__);
        return -1;
    }

    /** Interface name */
    if ((env = getenv(DHCPv6_INTERFACE_NAME)) != NULL)
    {
        snprintf(dhcpv6_data->ifname, sizeof(dhcpv6_data->ifname), "%s", env);
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Interface name is missing\n", __FUNCTION__, __LINE__);
    }

    /** DHCP Lease state */
    if (strcmp(input_option, "add") == 0 || strcmp(input_option, "update") == 0)
    {
        dhcpv6_data->isExpired = false;
    }
    else if (strcmp(input_option, "del") == 0 || strcmp(input_option, "delete") == 0 ||  strcmp(input_option, "expire") == 0)
    {
        dhcpv6_data->isExpired = true;
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Unknown DHCPv6 state: %s\n", __FUNCTION__, __LINE__, input_option);
    }
    
    /** IA_NA (Non-temporary address) */
    if ((env = getenv(DHCPv6_IANA_ADDRESS)) != NULL)
    {
        snprintf(dhcpv6_data->ia_na.address, sizeof(dhcpv6_data->ia_na.address), "%s", env);
        dhcpv6_data->ia_na.assigned = true;
    }

    if ((env = getenv(DHCPv6_IANA_IAID)) != NULL)
    {
        dhcpv6_data->ia_na.IA_ID = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IANA_PREF_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_na.PreferedLifeTime = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IANA_VALID_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_na.ValidLifeTime = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IANA_T1)) != NULL)
    {
        dhcpv6_data->ia_na.T1 = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IANA_T2)) != NULL)
    {
        dhcpv6_data->ia_na.T2 = (uint32_t) strtol(env, NULL, 10);
    }

    /** IA_PD (Prefix delegation) */
    if ((env = getenv(DHCPv6_IAPD_PREFIX)) != NULL)
    {
        snprintf(dhcpv6_data->ia_pd.Prefix, sizeof(dhcpv6_data->ia_pd.Prefix), "%s", env);
        dhcpv6_data->ia_pd.assigned = true;
    }

    if ((env = getenv(DHCPv6_IAPD_PREFIXLEN)) != NULL)
    {
        dhcpv6_data->ia_pd.PrefixLength = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IAPD_IAID)) != NULL)
    {
        dhcpv6_data->ia_pd.IA_ID = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IAPD_PREF_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_pd.PreferedLifeTime = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IAPD_VALID_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_pd.ValidLifeTime = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IAPD_T1)) != NULL)
    {
        dhcpv6_data->ia_pd.T1 = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IAPD_T2)) != NULL)
    {
        dhcpv6_data->ia_pd.T2 = (uint32_t) strtol(env, NULL, 10);
    }

    /** DNS servers */
    if ((env = getenv(DHCPv6_OPTION_DNS)) != NULL)
    {
        char dns[256];
        char *tok = NULL, *saveptr = NULL;
        snprintf(dns, sizeof(dns), "%s", env);

        tok = strtok_r(dns, " ", &saveptr);
        if (tok)
        {
            snprintf(dhcpv6_data->dns.nameserver, sizeof(dhcpv6_data->dns.nameserver), "%s", tok);
        }

        tok = strtok_r(NULL, " ", &saveptr);
        if (tok)
        {
            snprintf(dhcpv6_data->dns.nameserver1, sizeof(dhcpv6_data->dns.nameserver1), "%s", tok);
        }
        dhcpv6_data->dns.assigned = true;
    }

    /** Domain Name */
    if ((env = getenv(DHCPv6_OPTION_DOMAIN)) != NULL)
    {
        snprintf(dhcpv6_data->domainName, sizeof(dhcpv6_data->domainName), "%s", env);
    }

    /** NTP Server */
    if ((env = getenv(DHCPv6_OPTION_NTP)) != NULL)
    {
        snprintf(dhcpv6_data->ntpserver, sizeof(dhcpv6_data->ntpserver), "%s", env);
    }

    /** AFTR (Access Gateway for DS-Lite) */
    if ((env = getenv(DHCPv6_OPTION_DSLITE)) != NULL)
    {
        strncpy(dhcpv6_data->aftr, env, sizeof(dhcpv6_data->aftr) - 1);
        dhcpv6_data->aftr[sizeof(dhcpv6_data->aftr) - 1] = '\0';
        trim(dhcpv6_data->aftr);
        DHCPMGR_LOG_INFO("[%s-%d] AFTR FQDN is %s\n", __FUNCTION__, __LINE__, dhcpv6_data->aftr);
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] AFTR FQDN is missing\n", __FUNCTION__, __LINE__);
    }

    /** MAP-T Configuration */
    if ((env = getenv(DHCPv6_OPTION_MAPT)) != NULL)
    {
        snprintf((char *) dhcpv6_data->mapt.Container, sizeof(dhcpv6_data->mapt.Container), "%s", env);
        dhcpv6_data->mapt.Assigned = true;
    }

    /** MAP-E Configuration */
    if ((env = getenv(DHCPv6_OPTION_MAPE)) != NULL)
    {
        snprintf((char *) dhcpv6_data->mape.Container, sizeof(dhcpv6_data->mape.Container), "%s", env);
        DHCPMGR_LOG_INFO("[%s-%d] MAP-E configuration is updated\n", __FUNCTION__, __LINE__);
        dhcpv6_data->mape.Assigned = true;
    }

    /** Vendor Specific Information */
    if ((env = getenv(DHCPv6_VENDOR_SPEC)) != NULL)
    {
        dhcpv6_data->vendor.Assigned = true;
        dhcpv6_data->vendor.Length = strlen(env);
        snprintf(dhcpv6_data->vendor.Data, sizeof(dhcpv6_data->vendor.Data), "%s", env);
    }

    return 0;
}

static  int send_dhcp6_data_to_leaseMonitor (DHCPv6_PLUGIN_MSG *dhcpv6_data)
{
    if ( NULL == dhcpv6_data)
    {
        DHCPMGR_LOG_INFO ("[%s-%d] Invalid argument\n", __FUNCTION__, __LINE__);
        return -1;
    }

    /**
     * Send data to dhcpmanager.
     */
    PLUGIN_MSG msg;
    memset(&msg, 0, sizeof(PLUGIN_MSG));

    strcpy(msg.ifname, dhcpv6_data->ifname);
    msg.version = DHCP_VERSION_6;
    memcpy(&msg.data.dhcpv6, dhcpv6_data, sizeof(DHCPv6_PLUGIN_MSG));

    int sock   = -1;
    int conn   = -1;
    int bytes  = -1;
    int sz_msg = sizeof(PLUGIN_MSG);

    sock = nn_socket(AF_SP, NN_PUSH);
    if (sock < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to create the socket , error = [%d][%s]\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -1;
    }

    DHCPMGR_LOG_INFO("[%s-%d] Created socket endpoint \n", __FUNCTION__, __LINE__);

    conn = nn_connect(sock, DHCP_MANAGER_ADDR);
    if (conn < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to connect to the dhcpmanager [%s], error= [%d][%s] \n", __FUNCTION__, __LINE__, DHCP_MANAGER_ADDR,errno, strerror(errno));
        nn_close(sock);
        return -1;
    }

    DHCPMGR_LOG_INFO("[%s-%d] Connected to server socket [%s] \n", __FUNCTION__, __LINE__, DHCP_MANAGER_ADDR);

    for (int i = 0; i < MAX_SEND_THRESHOLD; i++)
    {
        bytes = nn_send(sock, (char *) &msg, sz_msg, NN_DONTWAIT);
        if (bytes < 0)
        {
            sleep(1);
            DHCPMGR_LOG_WARNING("[%s-%d] Sending to dhcpmanager (attempt %d/%d) error=[%d][%s], retrying...\n", __FUNCTION__, __LINE__, i+1, MAX_SEND_THRESHOLD, errno, strerror(errno));
        }
        else
            break;
    }

    if (bytes > 0)
        DHCPMGR_LOG_INFO("[%s-%d] Successfully sent %d bytes to dhcpmanager \n", __FUNCTION__, __LINE__, bytes);
    else
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to send data after %d attempts \n", __FUNCTION__, __LINE__, MAX_SEND_THRESHOLD);
    nn_close(sock);
    return (bytes > 0) ? 0 : -1;
}

static int handle_dibbler_event(char *input_option)
{
    if (input_option == NULL)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Invalid argument error!!! \n", __FUNCTION__, __LINE__);
        return -1;
    }

    DHCPMGR_LOG_INFO("[%s][%d] Received [%s] event from Dibbler \n", __FUNCTION__, __LINE__, input_option);

    int ret = 0;
    DHCPv6_PLUGIN_MSG data;
    memset(&data, 0, sizeof(data));

    ret = get_and_fill_env_data_dhcp6(&data, input_option);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to get DHCPv6 data from environment \n", __FUNCTION__, __LINE__);
        return -1;
    }

    /* Print received DHCPv6 data */
    DHCPMGR_LOG_INFO("[%s][%d] ===============DHCPv6 Configuration Received==============================\n", __FUNCTION__, __LINE__);
    DHCPMGR_LOG_INFO("[%s][%d] Interface       = %s \n", __FUNCTION__, __LINE__, data.ifname);
    DHCPMGR_LOG_INFO("[%s][%d] Event           = %s \n", __FUNCTION__, __LINE__, input_option);
    DHCPMGR_LOG_INFO("[%s][%d] isExpired       = %d \n", __FUNCTION__, __LINE__, data.isExpired);
    if (data.ia_na.assigned)
    {
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA Address   = %s \n", __FUNCTION__, __LINE__, data.ia_na.address);
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA IAID      = %u \n", __FUNCTION__, __LINE__, data.ia_na.IA_ID);
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA PrefLife  = %u \n", __FUNCTION__, __LINE__, data.ia_na.PreferedLifeTime);
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA ValidLife = %u \n", __FUNCTION__, __LINE__, data.ia_na.ValidLifeTime);
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA T1        = %u \n", __FUNCTION__, __LINE__, data.ia_na.T1);
        DHCPMGR_LOG_INFO("[%s][%d] IA_NA T2        = %u \n", __FUNCTION__, __LINE__, data.ia_na.T2);
    }
    if (data.ia_pd.assigned)
    {
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD Prefix    = %s \n", __FUNCTION__, __LINE__, data.ia_pd.Prefix);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD PrefixLen = %u \n", __FUNCTION__, __LINE__, data.ia_pd.PrefixLength);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD IAID      = %u \n", __FUNCTION__, __LINE__, data.ia_pd.IA_ID);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD PrefLife  = %u \n", __FUNCTION__, __LINE__, data.ia_pd.PreferedLifeTime);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD ValidLife = %u \n", __FUNCTION__, __LINE__, data.ia_pd.ValidLifeTime);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD T1        = %u \n", __FUNCTION__, __LINE__, data.ia_pd.T1);
        DHCPMGR_LOG_INFO("[%s][%d] IA_PD T2        = %u \n", __FUNCTION__, __LINE__, data.ia_pd.T2);
    }
    if (data.dns.assigned)
    {
        DHCPMGR_LOG_INFO("[%s][%d] DNS Server1     = %s \n", __FUNCTION__, __LINE__, data.dns.nameserver);
        DHCPMGR_LOG_INFO("[%s][%d] DNS Server2     = %s \n", __FUNCTION__, __LINE__, data.dns.nameserver1);
    }
    DHCPMGR_LOG_INFO("[%s][%d] ==========================================================================\n", __FUNCTION__, __LINE__);

    /*
     * Filter out transient ADD/UPDATE events where the IA_PD prefix has zero lifetimes.
     * When dibbler receives a REPLY that replaces a prefix (e.g., old prefix 300 with
     * new prefix 400), the old prefix 300 is included with ValidLifeTime=0 and
     * PreferedLifeTime=0. Dibbler fires a separate ADD for this expired prefix before
     * firing the DEL. Forwarding this zero-lifetime ADD to DHCP Manager would overwrite
     * the active prefix and cause a spurious LEASE_DEL when the subsequent DEL arrives.
     */
    if (data.isExpired == false && data.ia_pd.assigned == true &&
        data.ia_pd.PreferedLifeTime == 0 && data.ia_pd.ValidLifeTime == 0)
    {
        DHCPMGR_LOG_WARNING("[%s][%d] Dropping ADD/UPDATE for prefix with zero lifetimes "  
                            "(transient expired prefix from dibbler)\n",  
                            __FUNCTION__, __LINE__);
        return 0;
    }

    // Send DHCPv6 data to lease monitor
    ret = send_dhcp6_data_to_leaseMonitor(&data);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to send DHCPv6 data to leaseMonitor \n", __FUNCTION__, __LINE__);
        return -1;
    }

    return ret;
}

int main(int argc, char *argv[])
{
    if (argc < 2 || !argv || !argv[1] || strlen(argv[1]) == 0)
    {
        DHCPMGR_LOG_ERROR ("%s:%d Invalid arguments\n", __FUNCTION__,__LINE__);
        return -1;
    }

    DHCPMGR_LOG_INFO("Dibbler Plugin: Received event %s\n", argv[1]);
    if (!strcmp(argv[1], "add") || !strcmp(argv[1], "del") || !strcmp(argv[1], "update") || !strcmp(argv[1], "delete") || !strcmp(argv[1], "expire"))
    {
        if (handle_dibbler_event(argv[1]) != 0)
        {
            DHCPMGR_LOG_INFO ("%s:%d handle_event failed for %s\n",__FUNCTION__,__LINE__,argv[1]);
        }
    }

    return 0;
}
