#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
#
# This script cleans up stale "Value" PSM records associated with
# dhcpv6 SentOption entries that carry Tag 25 (IA_PD / prefix option).
# These Value records are no longer consumed by DHCP Manager and are
# removed here so they do not get recreated from bbhm_def_cfg xml during
# the next PSM commit.
#
# It is invoked as a pre-check (ExecStartPre) from the DHCP Manager
# systemd service, before CcspDHCPMgr starts up.

if [ -e /etc/log_timestamp.sh ]
then
    . /etc/log_timestamp.sh
else
    echo_t()
    {
	    echo "$(date +"%y%m%d-%T.%6N") $1"
    }
fi

LOG_FILE=/rdklogs/logs/Consolelog.txt.0
STALE_TAG=25

echo_t "[DHCP Manager PSM Cleanup] Running the script to clean up stale SentOption Value records for Tag ${STALE_TAG}" >> $LOG_FILE

clientcnt=$(psmcli getinstcnt dmsb.dhcpmanager.dhcpv6.Client.)
if ! echo "$clientcnt" | grep -qE "^[0-9]+$"; then
    echo_t "[DHCP Manager PSM Cleanup] Invalid dhcpv6 client count: '$clientcnt'" >> $LOG_FILE
    exit 1
fi

echo_t "[DHCP Manager PSM Cleanup] Number of dhcpv6 client instances is ${clientcnt}" >> $LOG_FILE

i=1
while [ "$i" -le "$clientcnt" ]
do
    sentoption_base="dmsb.dhcpmanager.dhcpv6.Client.${i}.SentOption."
    optcnt=$(psmcli getinstcnt ${sentoption_base})

    if ! echo "$optcnt" | grep -qE "^[0-9]+$"; then
        echo_t "[DHCP Manager PSM Cleanup] Invalid SentOption count for client ${i}: '$optcnt'" >> $LOG_FILE
        i=$((i + 1))
        continue
    fi

    echo_t "[DHCP Manager PSM Cleanup] Number of SentOption instances for Client.${i} is ${optcnt}" >> $LOG_FILE

    j=1
    while [ "$j" -le "$optcnt" ]
    do
        tag_obj_path="dmsb.dhcpmanager.dhcpv6.Client.${i}.SentOption.${j}.Tag"
        value_obj_path="dmsb.dhcpmanager.dhcpv6.Client.${i}.SentOption.${j}.Value"

        tag=$(psmcli get ${tag_obj_path} 2> /dev/null)

        if [ "$tag" = "$STALE_TAG" ]; then
            value=$(psmcli get ${value_obj_path} 2> /dev/null)
            if [ -n "$value" ]; then
                echo_t "[DHCP Manager PSM Cleanup] Found stale record \"${value_obj_path}\" with value \"${value}\" for Tag ${STALE_TAG}, deleting it" >> $LOG_FILE
                psmcli del ${value_obj_path} > /dev/null 2>&1
                echo_t "[DHCP Manager PSM Cleanup] PSM record \"${value_obj_path}\" deleted" >> $LOG_FILE
            else
                echo_t "[DHCP Manager PSM Cleanup] PSM record \"${value_obj_path}\" already absent for Tag ${STALE_TAG}" >> $LOG_FILE
            fi
        fi
        j=$((j + 1))
    done
    i=$((i + 1))
done
echo_t "[DHCP Manager PSM Cleanup] End Of the Script" >> $LOG_FILE
