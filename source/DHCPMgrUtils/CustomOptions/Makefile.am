##########################################################################
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
##########################################################################

AM_CFLAGS = -fno-exceptions -Wall -Wextra

AM_LDFLAGS =  -lz -lpthread -lccsp_common $(DBUS_LIBS)

ACLOCAL_AMFLAGS = -I m4

# Define the library name
lib_LTLIBRARIES = libcustomoptions.la

# Source files for the library
libcustomoptions_la_SOURCES = dhcpmgr_custom_options.c

if DHCP_VOICE_OPTIONS_SUPPORT
libcustomoptions_la_SOURCES += dhcpmgr_voice_custom_options.c
endif
# Include directories
libcustomoptions_la_CPPFLAGS = -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
              -I$(top_srcdir)/source/DHCPMgrInterface/include


