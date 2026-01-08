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

#ifndef DHCP_CUSTOM_OPTIONS_H
#define DHCP_CUSTOM_OPTIONS_H
#include <stdlib.h>
#include <stdint.h>
/**
 * @brief Creates a custom DHCPv4 Option 43 (Vendor Specific Information) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV4_CustomOption43(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Sets the custom DHCPv4 Option 43 (Vendor Specific Information) value.
 *
 * @param[in] ifName The name of the network interface.
 * @param[in] OptionValue The buffer with option data.
 * @return int 0 on success, non-zero on failure.
 */
int Set_DhcpV4_CustomOption43(const char *ifName, const char *OptionValue);

/**
 * @brief Creates a custom DHCPv4 Option 60 (Vendor Class Identifier) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV4_CustomOption60(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Creates a custom DHCPv4 Option 61 (Client Identifier) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV4_CustomOption61(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Creates a custom DHCPv6 Option 15 (User Class Option) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV6_CustomOption15(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Creates a custom DHCPv6 Option 16 (Vendor Class Option) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV6_CustomOption16(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Creates a custom DHCPv6 Option 17 (Vendor Specific Information Option) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @param[in] OptionValueSize The size of the buffer.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV6_CustomOption17(const char *ifName, char *OptionValue, size_t OptionValueSize);

/**
 * @brief Sets the custom DHCPv6 Option 17 (Vendor Specific Information Option) value.
 *
 * @param[in] ifName The name of the network interface.
 * @param[in] OptionValue The buffer with  option data.
 * @return int 0 on success, non-zero on failure.
 */
int Set_DhcpV6_CustomOption17(const char *ifName, const char *OptionValue, uint32_t *ipv6_TimeOffset);

#ifdef EROUTER_DHCP_OPTION_MTA
/**
 * @brief Retrieves a custom DHCPv4 option for the specified network interface.
 *
 * This function provides a weak implementation for retrieving a custom DHCPv4 option
 * for the given network interface. It logs the operation and returns a failure code.
 *
 * @param OptionValue The buffer to store the retrieved option value.
 * @param OptionValueSize The size of the buffer.
 * 
 * @return Returns an integer indicating the success or failure of the operation.
 *         Typically, 0 indicates success, while a non-zero value indicates an error.
 */
int Get_DhcpV4_CustomOption_mta(char *OptionValue, size_t OptionValueSize);

/**
 * @brief Sets a custom DHCPv4 option for the specified network interface.
 *
 * This function configures a custom DHCPv4 option for the given network interface
 * by applying the provided option value.
 *
 * @param ifName The name of the network interface to configure.
 * @param OptionValue The value of the custom DHCPv4 option to set.qx2
 * 
 * @return Returns an integer indicating the success or failure of the operation.
 *         Typically, 0 indicates success, while a non-zero value indicates an error.
 */
int Set_DhcpV4_CustomOption_mta(const char *OptionValue,char *version);
#endif
#endif // DHCP_CUSTOM_OPTIONS_H
