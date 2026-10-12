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

#include "dhcpv6_interface.h"
#include <stdio.h>
#include <time.h>
#include <telemetry_busmessage_sender.h>

#define DIBBLER_CLIENT                    "dibbler-client"
#define DIBBLER_CLIENT_PATH               "/usr/sbin/"DIBBLER_CLIENT
#define DIBBLER_CLIENT_RUN_CMD            "start"
#define DIBBLER_CLIENT_CMD                DIBBLER_CLIENT" "DIBBLER_CLIENT_RUN_CMD
#define DIBBLER_DFT_PATH                  "/etc/dibbler/"
#define DIBBLER_CLIENT_CONFIG_FILE        "client.conf"
#define DIBBLER_TMP_CONFIG_FILE           "/tmp/dibbler/client-tmp.conf"
#define DIBBLER_TEMPLATE_CONFIG_FILE      "/tmp/dibbler/client-template.conf"
#define DIBBLER_CLIENT_PIDFILE            "/tmp/dibbler/client.pid"
#define DIBBLER_DEFAULT_CONFIG_FILE       "/tmp/dibbler/client.conf"
#define DIBBLER_CLIENT_TERMINATE_TIMEOUT  (10 * MSECS_IN_SEC)
#define DIBBLER_PLUGIN_EXE                "/usr/bin/dhcpmgr_dibbler_plugin"
#define DIBBLER_LOG_CONFIG                "log-level 7\nlog-mode full\n"
#define DIBBLER_DUID_LL_CONFIG            "duid-type duid-ll\n"  
#define DIBBLER_CLIENT_TERMINATE_INTERVAL (MSECS_IN_SEC / 2)
#define DIBBLER_TMP_DIR_PATH              "/var/lib/dibbler"
#define DIBBLER_RADVD_FILE                "/etc/dibbler/radvd.conf"
#define DIBBLER_RADVD_FILE_OLD            "/etc/dibbler/radvd.conf.old"

/* Verify the PID still belongs to dibbler-client before sending another signal. */
static bool is_dibbler_running(pid_t pid)
{
    char path[BUFLEN_64];
    char name[sizeof(DIBBLER_CLIENT) + 1] = {0};
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);

    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        return false;
    }

    bool running = fgets(name, sizeof(name), fp) != NULL;
    fclose(fp);
    name[strcspn(name, "\n")] = '\0';
    return running && strcmp(name, DIBBLER_CLIENT) == 0;
}

/* Poll /proc because the SIGCHLD handler may reap the process before waitpid. */
static bool wait_for_dibbler_exit(pid_t pid, unsigned int timeout)
{
    while (is_dibbler_running(pid))
    {
        if (timeout == 0)
        {
            return false;
        }
        unsigned int wait_time = timeout > DIBBLER_CLIENT_TERMINATE_INTERVAL ? DIBBLER_CLIENT_TERMINATE_INTERVAL : timeout;
        usleep(wait_time * USECS_IN_MSEC);
        timeout -= wait_time;
    }
    return true;
}

static int copy_file (char * src, char * dst)
{
    if ((src == NULL) || (dst == NULL))
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    FILE * fin = NULL;
    FILE * fout = NULL;

    fout = fopen(dst, "wb");
    if (fout == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, dst);
        return FAILURE;
    }
    
    fin = fopen(src, "r");

    if (fin == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, src);
        fclose (fout);
        return FAILURE;
    }

    ssize_t nread;
    size_t len = 0;
    char *line = NULL;

    while ((nread = getline(&line, &len, fin)) != -1) 
    {
        fwrite(line, nread, 1, fout);
    }

    if (line)
    {
        free(line);
    }
    fclose(fin);
    fclose(fout);

    DHCPMGR_LOG_INFO("%s %d: successfully copied content from %s to %s\n", __FUNCTION__, __LINE__, src, dst);
    return SUCCESS;

}

/**
 * @brief Adds all request option list configurations to the DHCP configuration file.
 *
 * This function iterates through the request option list and writes the configurations
 * to the specified DHCP configuration file.
 *
 * @param fout Pointer to the DHCP configuration file.
 * @param send_opt_list Pointer to the list of DHCP request options to be sent.
 * @return int
 * @retval 0 if the options are added successfully.
 * @retval -1 if there is an error in adding the options.
 */
static int dibbler_get_req_options(FILE * fout,  dhcp_opt_list * req_opt_list)
{
    if(fout == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if(req_opt_list == NULL)
    {
        DHCPMGR_LOG_WARNING("%s %d: req_opt_list empty.\n", __FUNCTION__, __LINE__);
        return 0;
    }

    char args [BUFLEN_512] = {0};
    // request option
    dhcp_opt_list * opt_list = req_opt_list;
    while (opt_list)
    {
        memset (&args, 0, sizeof(args));
        switch (opt_list->dhcp_opt)
        {
            case DHCPV6_OPT_5:
            case DHCPV6_OPT_3:
                snprintf(args, sizeof(args), "\n\tia %s \n", (opt_list->dhcp_opt_val == NULL) ? "" : opt_list->dhcp_opt_val);
                fputs(args, fout);
                break;

            case DHCPV6_OPT_23:
                snprintf(args, sizeof(args), "\n\t%s \n", "option dns-server");
                fputs(args, fout);
                break;

            case DHCPV6_OPT_25:
                snprintf(args, sizeof(args), "\n\tpd %s \n", (opt_list->dhcp_opt_val == NULL) ? "" : opt_list->dhcp_opt_val);
                fputs(args, fout);
                break;

            case DHCPV6_OPT_24:
                snprintf(args, sizeof(args), "\n\t%s \n", "option domain");
                fputs(args, fout);
                break;

            case DHCPV6_OPT_95:
                snprintf(args, sizeof(args), "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                fputs(args, fout);
                break;

            case DHCPV6_OPT_94:
                snprintf(args, sizeof(args), "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                fputs(args, fout);
                break;

            case DHCPV6_OPT_64:
                fputs("\n\toption aftr\n", fout);
                break;

            default:
                snprintf(args, sizeof(args), "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                fputs(args, fout);
                break;
        }
        opt_list = opt_list->next;
    }

    return 0;

}

/**
 * @brief Adds all send option list configurations to the DHCP configuration file.
 *
 * This function iterates through the send option list and writes the configurations
 * to the specified DHCP configuration file.
 *
 * @param fout Pointer to the DHCP configuration file.
 * @param send_opt_list Pointer to the list of DHCP options to be sent.
 * @return int
 * @retval 0 if the options are added successfully.
 * @retval -1 if there is an error in adding the options.
 */
static int dibbler_get_send_options(FILE * fout,  dhcp_opt_list * send_opt_list)
{
    if(fout == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if(send_opt_list == NULL)
    {
        DHCPMGR_LOG_WARNING("%s %d: send_opt_list empty.\n", __FUNCTION__, __LINE__);
        return 0;
    }

    char args [BUFLEN_512] = {0};
    //send option list
    dhcp_opt_list * opt_list = send_opt_list;
    while (opt_list)
    {
        memset (&args, 0, sizeof(args));
        switch (opt_list->dhcp_opt)
        {
            case DHCPV6_OPT_5:
            case DHCPV6_OPT_3:
                snprintf(args, sizeof(args), "\n\tia %s \n", (opt_list->dhcp_opt_val == NULL) ? "" : opt_list->dhcp_opt_val);
                fputs(args, fout);
                break;
        
            case DHCPV6_OPT_25:
                snprintf(args, sizeof(args), "\n\tpd %s \n", (opt_list->dhcp_opt_val == NULL) ? "" : opt_list->dhcp_opt_val);
                fputs(args, fout);
                break;
                  
            case DHCPV6_OPT_14:
                fputs("\n\t rapid-commit yes\n", fout);
                break;

            case DHCPV6_OPT_20:
                // Do nothing, will be checked later.
                break;
        
            default:
                if (opt_list->dhcp_opt_val != NULL) /* Generic Dibbler option format */
                {
                    snprintf(args, sizeof(args), "\n\toption 00%d hex 0x%s\n", opt_list->dhcp_opt, opt_list->dhcp_opt_val);
                    fputs(args, fout);
                }
                break;
        }

        opt_list = opt_list->next;
    }

    return 0;

}

/**
 * @brief Checks if the DHCPv6 option 20 (Reconfigure Accept) is present in the send option list.
 *
 * This function iterates through the send option list and returns true if the DHCPv6 option 20
 * (Reconfigure Accept) is found, otherwise it returns false.
 *
 * @param send_opt_list Pointer to the list of DHCP options to be sent.
 * @return int
 * @retval 1 if DHCPv6 option 20 is found.
 * @retval 0 if DHCPv6 option 20 is not found.
 */
static int dibbler_get_reconfigureAccept(dhcp_opt_list * send_opt_list)
{
    dhcp_opt_list * opt_list = send_opt_list;
    while (opt_list)
    {
        if (opt_list->dhcp_opt == DHCPV6_OPT_20)
        {
            return 1;
        }
        opt_list = opt_list->next;
    }

    return 0;
}

/**
 * @brief Creates the Dibbler client configuration file.
 *
 * This function generates the Dibbler client configuration file in the specified config_path
 * using the provided interface name, request option list, and send option list.
 *
 * @param[in] config_path The path where the configuration file will be created. Example : /etc/dibbler/vdsl0
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return 0 on success, -1 on failure.
 */
static int dibbler_client_config_generator(char *config_path, char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list)
{
     //Create /etc/dibbler/radvd.conf file if doesn't exist. Dibbler client requires this file.
     FILE *radvdFile;
     radvdFile = fopen(DIBBLER_RADVD_FILE_OLD, "a");
     if(radvdFile != NULL)
     {
         fclose(radvdFile);
     }
 
     radvdFile = fopen(DIBBLER_RADVD_FILE, "a");
     if(radvdFile != NULL)
     {
         fclose(radvdFile);
     }
 
     /************ DIBBLER CLIENT CONF FILE GENERATION *************/
     
    FILE * fout;
    fout = fopen(DIBBLER_TMP_CONFIG_FILE, "w+");

    if (fout == NULL)
    {
        DBG_PRINT("%s %d: unable to open tmp file: %s\n", __FUNCTION__, __LINE__, DIBBLER_TMP_CONFIG_FILE);
        return FAILURE;
    }

    char buff[BUFLEN_128];
    // write common config
    snprintf(buff, sizeof(buff), "script \"%s\"\n", DIBBLER_PLUGIN_EXE);
    fputs(buff, fout);
    fputs(DIBBLER_LOG_CONFIG, fout);
    fputs(DIBBLER_DUID_LL_CONFIG, fout);

    // interface specific config start
    snprintf(buff, sizeof(buff), "iface %s {\n", interfaceName);
    fputs(buff, fout);

    if ((dibbler_get_req_options(fout, req_opt_list)) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv6 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DHCPMGR_LOG_INFO("%s %d: Constructing SEND option args to dibbler.\n", __FUNCTION__, __LINE__);
    if ((dibbler_get_send_options(fout, send_opt_list) != SUCCESS))
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv6 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    // interface specific config end
    fputs("\n}", fout);
    
    // write common config
    fputs("\nskip-confirm\n", fout);
    fputs("downlink-prefix-ifaces \"brlan0\"\n", fout);

    if(dibbler_get_reconfigureAccept(send_opt_list))
    {
        snprintf (buff, sizeof(buff), "\n%s\n", "reconfigure-accept 1");
        fputs(buff, fout);
    }
    fclose(fout);

    // copy the file to new location
    char file_path[BUFLEN_128];
    int ret = snprintf(file_path, sizeof(file_path), "%s/%s", config_path, DIBBLER_CLIENT_CONFIG_FILE);
    if (ret <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to contruct filepath\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (copy_file (DIBBLER_TMP_CONFIG_FILE, file_path) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to copy %s to %s due to %s\n", __FUNCTION__, __LINE__, DIBBLER_TEMPLATE_CONFIG_FILE, file_path, strerror(errno));
        return FAILURE;
    }
    
    // dibber-client uses default config to generate DUID, so linking default file to tmp file

    if (access(DIBBLER_DEFAULT_CONFIG_FILE, F_OK) == 0) {
        DHCPMGR_LOG_WARNING("%s %d: link already exists, continuing\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    } 
    else 
    {
        // Creating the link only if it doesn't already exist
        if (link(DIBBLER_TMP_CONFIG_FILE, DIBBLER_DEFAULT_CONFIG_FILE) == 0) {
            DHCPMGR_LOG_INFO("%s %d: link created successfully\n", __FUNCTION__, __LINE__);
            return SUCCESS;
        } else {
            DHCPMGR_LOG_ERROR("%s %d: unable to create link: %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return FAILURE;
        }
    }

    return SUCCESS;

}

/**
 * @brief Interface API for starting the DHCPv6 client.
 *
 * This function creates the configuration file using the provided request and send option lists,
 * starts the DHCPv6 client, and collects the process ID (PID).
 *
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return The process ID (PID) of the started DHCPv6 client.
 */
pid_t start_dhcpv6_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list) 
{
    DHCPMGR_LOG_INFO("%s %d start_dhcpv6_client dibbler API called \n", __FUNCTION__, __LINE__);
    pid_t dibbler_pid = 0;
    if ((interfaceName == NULL))
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //Check if default dibbler tmp path available or not. If not then create it
    create_dir_path(DIBBLER_TMP_DIR_PATH);

    dibbler_pid = get_process_pid(DIBBLER_CLIENT, interfaceName, false);
    if (dibbler_pid > 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: another instance of %s running on %s \n", __FUNCTION__, __LINE__, DIBBLER_CLIENT, interfaceName);
        return dibbler_pid;
    }

    //create a directry for dibbler client to run. 
    char config_path[BUFLEN_256] = {0};
    snprintf(config_path, sizeof(config_path), "%s%s", DIBBLER_DFT_PATH, interfaceName);
    if (mkdir(config_path, 0644) == 0)
    {
        DHCPMGR_LOG_INFO ("%s %d: created directory %s\n", __FUNCTION__, __LINE__, config_path);
    }
    else
    {
        DHCPMGR_LOG_INFO ("%s %d: Directory already exists / not created  %s\n", __FUNCTION__, __LINE__, config_path);
    }
    
    if (dibbler_client_config_generator(config_path,interfaceName, req_opt_list, send_opt_list) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to create dibbler conf.\n", __FUNCTION__, __LINE__);
        return FAILURE;

    }

    DHCPMGR_LOG_INFO("%s %d: Starting dibbler with config %s\n", __FUNCTION__, __LINE__, config_path);

    char cmd_args[BUFLEN_256] = {0};
    snprintf(cmd_args, sizeof(cmd_args), "%s -w %s", DIBBLER_CLIENT_RUN_CMD, config_path);

    pid_t ret = start_exe2(DIBBLER_CLIENT_PATH, cmd_args);
    if (ret <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to start dibbler-client %d.\n", __FUNCTION__, __LINE__, ret);
        t2_event_d("DHCPMGR_ERROR_Dhcpv6ClientStartFail", 1);
        return FAILURE;
    }

    //dibbler-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(ret, DIBBLER_CLIENT_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DHCPMGR_LOG_WARNING("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }
    struct timespec ts = {3, 0};
    nanosleep(&ts, NULL);
    DHCPMGR_LOG_INFO("%s %d: Started dibbler-client. returning pid..\n", __FUNCTION__, __LINE__);
    return get_process_pid (DIBBLER_CLIENT, cmd_args, true);

}

/**
 * @brief Interface API for triggering a renew from the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to trigger a renew.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv6_renew(pid_t processID) {
    DHCPMGR_LOG_INFO("%s %d  send_dhcpv6_renew\n", __FUNCTION__, __LINE__);
    DHCPMGR_LOG_INFO("sending SIGUSR2 to dhcp6c, this will let the dhcp6c to send renew packet out \n");
    signal_process(processID, SIGUSR2);
    return 0;
}

/**
 * @brief Interface API for triggering a release from the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to trigger a release and terminate.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv6_release(pid_t processID) {
    DHCPMGR_LOG_INFO("%s %d  send_dhcpv6_release\n", __FUNCTION__, __LINE__);
    // send unicast DHCPv6 RELEASE
    int fd = 0;
    //TODO : copiedfrom legacy implementation, change it to user def signal
    fd = creat("/tmp/dhcpv6_release",S_IRUSR | S_IWUSR | S_IRGRP);
    if(fd != -1)
    {
        close(fd);
    }
    DHCPMGR_LOG_INFO("%s %d Calling stop after sending release. \n", __FUNCTION__, __LINE__);
    stop_dhcpv6_client(processID);
    return 0;
}

/**
 * @brief Interface API for stopping the DHCPv6 client.
 *
 * This function sends the respective signal to the DHCPv6 client application to stop the client.
 *
 * @param[in] processID The process ID (PID) of the DHCPv6 client.
 * @return 0 on success, -1 on failure.
 */
 int stop_dhcpv6_client(pid_t processID) 
 {
    DHCPMGR_LOG_INFO("%s %d dibbler-client api called \n", __FUNCTION__, __LINE__);

    if (processID <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to get pid of dibbler\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (signal_process(processID, SIGTERM) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
         return FAILURE;
    }
    if (wait_for_dibbler_exit(processID, DIBBLER_CLIENT_TERMINATE_TIMEOUT))
    {
        return SUCCESS;
    }

    DHCPMGR_LOG_WARNING("%s %d: dibbler-client still running. Sending SIGKILL to pid %d\n", __FUNCTION__, __LINE__, processID);
    if (signal_process(processID, SIGKILL) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to send SIGKILL to pid %d\n", __FUNCTION__, __LINE__, processID);
        return FAILURE;
    }
    if (!wait_for_dibbler_exit(processID, MSECS_IN_SEC))
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to kill dibbler-client pid %d\n", __FUNCTION__, __LINE__, processID);
        return FAILURE;
    }
    return SUCCESS;
}