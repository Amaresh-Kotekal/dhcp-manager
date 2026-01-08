
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

#include "dhcpmgr_custom_options.h"
#include "util.h"
#include "ifl.h"
#include "ipc_msg.h"

static int DhcpMgr_Option17Set_Common(const char *ifName, const char *OptionValue,uint32_t *ipv6_TimeOffset);
#ifdef EROUTER_DHCP_OPTION_MTA
static int set_mta_config(const char *OptionValue, char *version);
#endif

// Weak function implementations
__attribute__((weak)) int Get_DhcpV4_CustomOption60(const char *ifName, char *OptionValue,size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption60 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV4_CustomOption61(const char *ifName, char *OptionValue, size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption61 \n", __FUNCTION__, __LINE__);
    return -1;
}
#ifdef EROUTER_DHCP_OPTION_MTA
__attribute__((weak)) int Get_DhcpV4_CustomOption_mta(char *OptionValue, size_t OptionValueSize) 
{
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption_mta \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Set_DhcpV4_CustomOption_mta(const char *OptionValue,char *version) 
{
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Set_DhcpV4_CustomOption_mta \n", __FUNCTION__, __LINE__);
    return set_mta_config(OptionValue, version);
}
#endif
__attribute__((weak)) int Get_DhcpV6_CustomOption15(const char *ifName, char *OptionValue,size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption15 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV6_CustomOption16(const char *ifName, char *OptionValue, size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption16 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV6_CustomOption17(const char *ifName, char *OptionValue, size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption17 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Set_DhcpV6_CustomOption17(const char *ifName, const char *OptionValue, uint32_t *ipv6_TimeOffset) 
{
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Set_DhcpV6_CustomOption17 \n", __FUNCTION__, __LINE__);
    return DhcpMgr_Option17Set_Common(ifName, OptionValue, ipv6_TimeOffset);
}

__attribute__((weak)) int Get_DhcpV4_CustomOption43(const char *ifName, char *OptionValue, size_t OptionValueSize) 
{
    (void)ifName;
    (void)OptionValue;
    (void)OptionValueSize;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption43 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Set_DhcpV4_CustomOption43(const char *ifName, const char *OptionValue)
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Set_DhcpV4_CustomOption43 \n", __FUNCTION__, __LINE__);
    return -1;
}

/* The following functions are implemented based on the reference from the dibbler notify script file */
/**
 * @brief Parses the DHCP option 17 suboption based on the provided DHCP option value and IP mode.
 *
 * @param dhcp_option_val A pointer to a string containing the DHCP option value to be parsed.
 * @param ip_mode A pointer to a string specifying the IP mode (e.g., IPv4 or IPv6).
 * 
 * @return A pointer to a dynamically allocated string containing the parsed suboption value.
 *         The caller is responsible for freeing the allocated memory.
 */
static char* parse_dhcp_17_suboption(const char *dhcp_option_val, const char *ip_mode) 
{
    if (dhcp_option_val == NULL || ip_mode == NULL) 
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid arguments..\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    char *option_format = NULL;
    char *dhcp_option_copy = strdup(dhcp_option_val);
    if (dhcp_option_copy == NULL) 
    {
        DHCPMGR_LOG_ERROR("%s %d: Memory allocation failed..\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    // Remove colons from the input string
    for (char *p = dhcp_option_copy; *p; ++p) 
    {
        if (*p == ':') 
        {
            *p = ' ';
        }
    }

    int val = 2;
    int len = (strcmp(ip_mode, "v4") == 0) ? 2 : 4;

    char *remaining = dhcp_option_copy;
    while (*remaining != '\0') 
    {
        char suboption[16] = {0};
        strncpy(suboption, remaining, len);
        remaining += len;

        char suboption_length_str[16] = {0};
        strncpy(suboption_length_str, remaining, len);
        remaining += len;

        int suboption_length = (int)strtol(suboption_length_str, NULL, 16);
        int length = suboption_length * val;

        char suboption_value[256] = {0};
        strncpy(suboption_value, remaining, length);
        remaining += length;

        char *new_format = NULL;
        if(option_format== NULL)
        {
            size_t new_format_len = strlen(suboption) + strlen(suboption_value) + 2; // '=' and '\0'
            new_format = malloc(new_format_len);
            if (new_format != NULL) 
            {
                snprintf(new_format, new_format_len, "%s=%s", suboption, suboption_value);
            }
        } 
        else 
        {
            size_t new_format_len = strlen(option_format) + strlen(suboption) + strlen(suboption_value) + 3; // ' ', '=' and '\0'
            new_format = malloc(new_format_len);
            if (new_format != NULL) 
            {
                snprintf(new_format, new_format_len, "%s %s=%s", option_format, suboption, suboption_value);
            }
            free(option_format);
        }

        if (new_format == NULL) 
        {
            DHCPMGR_LOG_ERROR("%s %d: Memory allocation failed..\n", __FUNCTION__, __LINE__);
            free(dhcp_option_copy);
            return NULL;
        }

        option_format = new_format;
    }

    free(dhcp_option_copy);
    return option_format;
}

/**
 * @brief Processes and sets DHCP Option 17 suboptions for a given interface.
 *
 * This function parses the provided OptionValue string, extracts suboptions, 
 * and sets corresponding system events based on the suboption type and value.
 *
 * @param[in] ifName The name of the network interface. Must not be NULL.
 * @param[in] OptionValue The DHCP Option 17 value string. Must not be NULL.
 *
 * @return 0 on success, -1 on failure (e.g., invalid arguments or memory allocation failure).
 *
 * @details
 * - The function expects the OptionValue string to contain suboptions in the format 
 *   "suboption=value", separated by spaces.
 * - Supported suboptions include:
 *   - "vendor": Sets the "ipv6-vendor-id" system event.
 *   - "38": Sets the "ipv6-timeoffset" system event.
 *   - "39": Sets the "wan6_ippref" and optionally "MTA_IP_PREF" system events.
 *   - "2": Sets the "ipv6-device-type" system event.
 *   - "3": Sets the "ipv6-embd-comp-in-device" system event.
 *   - "2170" and "2171": Parses nested suboptions and sets primary/secondary 
 *     address system events for IPv4 or IPv6.
 * - If any MTA-related DHCP options are received, the "dhcp_mta_option" system 
 *   event is set to "received".
 * - Memory allocated for tokenization is freed before returning.
 *
 */
//TODO: This function directly sets generic system events. If multiple WAN leases share this information, it may cause conflicts. These system events should be configured specifically for the active interface only.
static int DhcpMgr_Option17Set_Common(const char *ifName, const char *OptionValue,uint32_t *ipv6_TimeOffset)
{
    if (ifName == NULL || OptionValue == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    char *token, *suboption, *suboption_data;
    char *srv_option17 = strdup(OptionValue); // Duplicate OptionValue to tokenize
    int mta_dhcp_option_received = 0;

    if (srv_option17 == NULL) {
        DHCPMGR_LOG_ERROR("%s %d: Memory allocation failed..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    char *saveptr_option17 = NULL;
    token = strtok_r(srv_option17, " ", &saveptr_option17);
    while (token != NULL) 
    {
        char *saveptr_opt17_subOption = NULL;
        suboption = strtok_r(token, "=", &saveptr_opt17_subOption);
        suboption_data = strtok_r(NULL, "=", &saveptr_opt17_subOption);

        if (suboption && suboption_data) 
        {
            if (strcmp(suboption, "vendor") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption vendor-id is %s in option %s\n", suboption_data, OptionValue);
                ifl_set_event("ipv6-vendor-id", suboption_data);
            } else if (strcmp(suboption, "38") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption TimeOffset is %s in option %s\n", suboption_data, OptionValue);
                *ipv6_TimeOffset = atoi(suboption_data);
                DHCPMGR_LOG_INFO("ipv6_TimeOffset value is %u\n", *ipv6_TimeOffset);
                //ifl_set_event("ipv6-timeoffset", suboption_data);
                // Additional processing for TimeOffset can be added here
            } else if (strcmp(suboption, "39") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption IP Mode Preference is %s in option %s\n", suboption_data, OptionValue);
                ifl_set_event("wan6_ippref", suboption_data);
                char mta_ip_pref[64] = {0};
                ifl_get_event("MTA_IP_PREF", mta_ip_pref, sizeof(mta_ip_pref));
                if (strlen(mta_ip_pref) == 0) 
                {
                    DHCPMGR_LOG_INFO("Setting MTA_IP_PREF value to %s\n", suboption_data);
                    ifl_set_event("MTA_IP_PREF", suboption_data);
                    mta_dhcp_option_received = 1;
                } else 
                {
                    DHCPMGR_LOG_INFO("Mta_Ip_Pref value is already set to %s\n", mta_ip_pref);
                }
            } else if (strcmp(suboption, "2") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption Device Type is %s in option %s\n", suboption_data, OptionValue);
                ifl_set_event("ipv6-device-type", suboption_data);
            } else if (strcmp(suboption, "3") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption List of Embedded Components in eDOCSIS Device is %s in option %s\n", suboption_data, OptionValue);
                ifl_set_event("ipv6-embd-comp-in-device", suboption_data);
            } else if (strcmp(suboption, "2170") == 0 || strcmp(suboption, "2171") == 0) 
            {
                char *parsed_value = parse_dhcp_17_suboption(suboption_data, "v6"); //parsed_value should be freed
                if (parsed_value) 
                {
                    char *saveptr_mta_subOption = NULL;
                    char *val_token = strtok_r(parsed_value, " ", &saveptr_mta_subOption);
                    while (val_token != NULL) 
                    {
                        char *saveptr_mta_data = NULL;
                        char *subopt = strtok_r(val_token, "=", &saveptr_mta_data);
                        char *subopt_data = strtok_r(NULL, "=", &saveptr_mta_data);
                        if (subopt && subopt_data) {
                            if (strcmp(subopt, "0001") == 0) 
                            {
                                char primary_address[64] = {0};
                                ifl_get_event((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_PrimaryAddress" : "MTA_DHCPv6_PrimaryAddress", primary_address, sizeof(primary_address));
                                
                                if (strlen(primary_address) == 0) 
                                {
                                    DHCPMGR_LOG_INFO("Setting PrimaryAddress value as %s\n", subopt_data);
                                    ifl_set_event((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_PrimaryAddress" : "MTA_DHCPv6_PrimaryAddress", subopt_data);
                                    mta_dhcp_option_received = 1;
                                }
                            } else if (strcmp(subopt, "0002") == 0) 
                            {
                                char secondary_address[64] = {0};
                                ifl_get_event((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_SecondaryAddress" : "MTA_DHCPv6_SecondaryAddress", secondary_address, sizeof(secondary_address));
                                
                                if (strlen(secondary_address) == 0) 
                                {
                                    DHCPMGR_LOG_INFO("Setting SecondaryAddress value as %s\n", subopt_data);
                                    ifl_set_event((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_SecondaryAddress" : "MTA_DHCPv6_SecondaryAddress", subopt_data);
                                    mta_dhcp_option_received = 1;
                                }
                            }
                        }
                        val_token = strtok_r(NULL, " ", &saveptr_mta_subOption);
                    }
                    free(parsed_value);
                }
            }
        }
        token = strtok_r(NULL, " ", &saveptr_option17);
    }

    if (mta_dhcp_option_received) 
    {
        DHCPMGR_LOG_INFO("Setting dhcp_mta_option event as received\n");
        ifl_set_event("dhcp_mta_option", "received");
    }

    free(srv_option17);
    return 0;
}

#ifdef EROUTER_DHCP_OPTION_MTA

static void parse_nested_option(const char *nested_val, char *primary, char *secondary)
{
    if (!nested_val) return;

    char subop[3] = {0};
    char len_str[3] = {0};
    char value[256] = {0};
    int len = 0;

    while (strlen(nested_val) >= 4) {
        memcpy(subop, nested_val, 2);
        nested_val += 2;

        memcpy(len_str, nested_val, 2);
        nested_val += 2;

        len = strtol(len_str, NULL, 16);
        int hex_len = len * 2;
        if ((int)strlen(nested_val) < hex_len) break;

        memset(value, 0, sizeof(value));
        memcpy(value, nested_val, hex_len);
        nested_val += hex_len;

        if (atoi(subop) == 1 && primary) {
            strcpy(primary, value);
        } else if (atoi(subop) == 2 && secondary) {
            strcpy(secondary, value);
        }
    }
}

static int set_mta_config(const char *OptionValue, char *version)
{
    bool mta_param_rx = false;

    if(OptionValue == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    if (strcmp(version, "v4") == 0)
    {
        char *opt122 = strdup(OptionValue);
        if (opt122 == NULL)
        {
            return -1;
        }

        char subop[16] = {0};
        int len = 0;
        char buff[128] = {0};

        while (strlen(opt122))
        {
            // Get sub-option
            memset(subop, 0, sizeof(subop));
            memcpy(subop, opt122, 2);
            opt122 += 2;

            // Get length of suboption value
            memset(buff, 0, sizeof(buff));
            memcpy(buff, opt122, 2);
            opt122 += 2;

            len = atoi(buff);

            // Get value of the suboption
            memset(buff, 0, sizeof(buff));
            memcpy(buff, opt122, len * 2);
            opt122 += len * 2;

            if (atoi(subop) == 1)
            {
                ifl_set_event("MTA_DHCPv4_PrimaryAddress", buff);
                mta_param_rx = true;
            }
            else if (atoi(subop) == 2)
            {
                ifl_set_event("MTA_DHCPv4_SecondaryAddress", buff);
                mta_param_rx = true;
            }
        }   
    }
    else if (strcmp(version, "v6") == 0) 
    {
        const char *opt125 = OptionValue;
        char subop[3] = {0}, len_str[3] = {0}, value[512] = {0};
        int len = 0;

        while (strlen(opt125) >= 4) {
            memcpy(subop, opt125, 2); opt125 += 2;
            memcpy(len_str, opt125, 2); opt125 += 2;

            len = strtol(len_str, NULL, 16);
            int hex_len = len * 2;
            if ((int)strlen(opt125) < hex_len) break;

            memset(value, 0, sizeof(value));
            memcpy(value, opt125, hex_len); opt125 += hex_len;

            if (strcasecmp(subop, "7C") == 0) {
                ifl_set_event("MTA_IP_PREF", value);
                mta_param_rx = true;
            } else if (strcasecmp(subop, "7B") == 0) {
                char primary[256] = {0}, secondary[256] = {0};
                parse_nested_option(value, primary, secondary);

                if (strlen(primary) > 0) {
                    ifl_set_event("MTA_DHCPv6_PrimaryAddress", primary);
                    mta_param_rx = true;
                }
                if (strlen(secondary) > 0) {
                    ifl_set_event("MTA_DHCPv6_SecondaryAddress", secondary);
                    mta_param_rx = true;
                }
            }
        }
    }

    if (mta_param_rx) {
        ifl_set_event("dhcp_mta_option", "received");
    }
    return 0;
}
#endif
