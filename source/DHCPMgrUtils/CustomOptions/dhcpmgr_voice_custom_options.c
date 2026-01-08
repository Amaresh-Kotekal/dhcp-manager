/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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
#include "ccsp_trace.h"
#include "util.h"
#include "dhcpmgr_custom_options.h"
#include "ccsp/autoconf.h"
#include "ccsp/platform_hal.h"
#include "voice_dhcp_hal.h"
#include "syscfg/syscfg.h"

typedef struct
{
    //char cDeviceType[32]; For Technicolor value is EDVA
    char cSerialNumber[64];
    char cHardwareVersion[64];
    char cSoftwareVersion[64];
    char cBootLoaderVersion[64];
    char cOUID[64];
    char cModelNumber[64];
    char cVendorName[64];
    char cMtaMacAddress[64];
    //char cCorrelationId[32]; For Technicolor value is 36392396
}dhcpOption43RawData_t;

/*
 * @brief Read the EMTA MAC address from the factory NVRAM file.
 *
 * This helper function scans the file "/tmp/factory_nvram.data" for a line
 * beginning with the literal prefix "EMTA " and, if found, copies the
 * remainder of that line (after the prefix and with the trailing newline
 * removed) into the caller-supplied buffer as a null-terminated string.
 *
 * The MAC address format is whatever textual representation is stored in
 * the file (for example, a hex string with or without separators); the
 * string is copied verbatim without validation or normalization.
 *
 * @param[in,out] pMacAddress
 *      Pointer to a character buffer that receives the MAC address string.
 *      The pointer must be non-NULL and reference a buffer of at least
 *      32 bytes in size to ensure sufficient space for the MAC address
 * @param[in] iMacBufSize
 *      Size of the pMacAddress buffer.
 *
 * @note
 *      This function does not return a status; on failure to open or parse
 *      the file, it logs an error via CcspTraceError and leaves the contents
 *      of pMacAddress unchanged or partially unchanged.
 */
static void readMacAddress (char * pMacAddress, int iMacBufSize)
{
    if (pMacAddress == NULL || iMacBufSize <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return;
    }

	FILE *pFILE = fopen("/tmp/factory_nvram.data", "r");
	if (pFILE != NULL)
	{
		char cLine[128] = {0};
		while (fgets(cLine, sizeof(cLine), pFILE) != NULL)
		{
			if (strncmp(cLine, "EMTA ",5) == 0)
			{
				char *pMac = cLine + 5;
				pMac[strcspn(pMac, "\n")] = 0; // Remove newline character
				snprintf(pMacAddress, iMacBufSize, "%s", pMac);
				break;
			}
		}
		fclose(pFILE);
	}
    else
    {
        CcspTraceError(("%s: Failed to open /tmp/factory_nvram.data\n", __FUNCTION__));
    }
}
/*
 * @brief Prepare the DHCP Option 43 value in hex-binary format.
 *
 * This function gathers various device information using platform HAL APIs
 * and constructs the DHCP Option 43 value in hex-binary format according
 * to the vendor-specific requirements.
 *
 * @param[out] pOptionValue
 *      Pointer to a buffer that receives the hex-binary encoded option data.
 * @param[in] iOptionValueSize
 *      Size of the pOptionValue buffer.
 *
 * @return
 *      Returns 0 on success, -1 on failure.
*/
static int prepareDhcpOption43(char *pOptionValue, size_t iOptionValueSize)
{
    srand((unsigned int)time(NULL));
    if (pOptionValue == NULL || iOptionValueSize == 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    dhcpOption43RawData_t sDhcpOption43RawData = {0};

    snprintf (sDhcpOption43RawData.cVendorName, sizeof(sDhcpOption43RawData.cVendorName), CONFIG_VENDOR_NAME);
    snprintf (sDhcpOption43RawData.cOUID, sizeof(sDhcpOption43RawData.cOUID), CONFIG_VENDOR_ID);
    if (RETURN_OK != platform_hal_GetModelName(sDhcpOption43RawData.cModelNumber))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetModelName failed..\n", __FUNCTION__, __LINE__);
    if (RETURN_OK != platform_hal_GetSerialNumber(sDhcpOption43RawData.cSerialNumber))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetSerialNumber failed..\n", __FUNCTION__, __LINE__);
    if (RETURN_OK != platform_hal_GetHardwareVersion(sDhcpOption43RawData.cHardwareVersion))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetHardwareVersion failed..\n", __FUNCTION__, __LINE__);
    if (RETURN_OK != platform_hal_GetFirmwareName(sDhcpOption43RawData.cSoftwareVersion, sizeof(sDhcpOption43RawData.cSoftwareVersion)))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetFirmwareName failed..\n", __FUNCTION__, __LINE__);
    if (RETURN_OK != platform_hal_GetBootloaderVersion(sDhcpOption43RawData.cBootLoaderVersion, sizeof(sDhcpOption43RawData.cBootLoaderVersion)))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetBootloaderVersion failed..\n", __FUNCTION__, __LINE__);
#if 0 //It is stubbed in platform_hal_oem.c
    if (RETURN_OK != platform_hal_GetMtaMacAddress(sDhcpOption43RawData.cMtaMacAddress))
        DHCPMGR_LOG_ERROR("%s %d: platform_hal_GetMtaMacAddress failed..\n", __FUNCTION__, __LINE__);
#else
    readMacAddress(sDhcpOption43RawData.cMtaMacAddress, sizeof(sDhcpOption43RawData.cMtaMacAddress));
#endif
    DHCPMGR_LOG_INFO("%s %d: Preparing DHCP Option 43, Values are\n", __FUNCTION__, __LINE__);
    DHCPMGR_LOG_INFO("VendorName=%s\n", sDhcpOption43RawData.cVendorName);
    DHCPMGR_LOG_INFO("OUID=%s\n", sDhcpOption43RawData.cOUID);
    DHCPMGR_LOG_INFO("ModelNumber=%s\n", sDhcpOption43RawData.cModelNumber);
    DHCPMGR_LOG_INFO("SerialNumber=%s\n", sDhcpOption43RawData.cSerialNumber);
    DHCPMGR_LOG_INFO("HardwareVersion=%s\n", sDhcpOption43RawData.cHardwareVersion);
    DHCPMGR_LOG_INFO("SoftwareVersion=%s\n", sDhcpOption43RawData.cSoftwareVersion);
    DHCPMGR_LOG_INFO("BootLoaderVersion=%s\n", sDhcpOption43RawData.cBootLoaderVersion);
    DHCPMGR_LOG_INFO("MtaMacAddress=%s\n", sDhcpOption43RawData.cMtaMacAddress);

    unsigned char cHexBuf[256] = {0};
    int iIndex = 0;

    //Type 02: Vendor Name
    cHexBuf[iIndex++] = 0x02; //Suboption Type
    cHexBuf[iIndex++] = 0x04; //Length
    cHexBuf[iIndex++] = 0x45; //'E'
    cHexBuf[iIndex++] = 0x44; //'D'
    cHexBuf[iIndex++] = 0x56; //'V'
    cHexBuf[iIndex++] = 0x41; //'A'

    DHCPMGR_LOG_INFO("%s %d: EVDA Identifier:%02x %02x %02x %02x\n", __FUNCTION__, __LINE__,
        cHexBuf[iIndex-4], cHexBuf[iIndex-3], cHexBuf[iIndex-2], cHexBuf[iIndex-1]);

    //Type 04: Serial Number
    int iSerialNumLen = (int)strlen(sDhcpOption43RawData.cSerialNumber);
    cHexBuf[iIndex++] = 0x04; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iSerialNumLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cSerialNumber, iSerialNumLen);
    iIndex += iSerialNumLen;

    //Type 05: Hardware Version
    int iHardwareVerLen = (int)strlen(sDhcpOption43RawData.cHardwareVersion);
    cHexBuf[iIndex++] = 0x05; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iHardwareVerLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cHardwareVersion, iHardwareVerLen);
    iIndex += iHardwareVerLen;

    //Type 06: Software Version
    int iSoftwareVerLen = (int)strlen(sDhcpOption43RawData.cSoftwareVersion);
    cHexBuf[iIndex++] = 0x06; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iSoftwareVerLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cSoftwareVersion, iSoftwareVerLen);
    iIndex += iSoftwareVerLen;

    //Type 07: Bootloader Version
    int iBootloaderVerLen = (int)strlen(sDhcpOption43RawData.cBootLoaderVersion);
    cHexBuf[iIndex++] = 0x07; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iBootloaderVerLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cBootLoaderVersion, iBootloaderVerLen);
    iIndex += iBootloaderVerLen;

    //Type 08: OUID
    int iOUIDLen = 3; // As per dhcp option 60 type 08 OUI length is 3 bytes
    cHexBuf[iIndex++] = 0x08; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iOUIDLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cOUID, iOUIDLen);
    iIndex += iOUIDLen;

    //Type 09: Model Number
    int iModelNumLen = (int)strlen(sDhcpOption43RawData.cModelNumber);
    cHexBuf[iIndex++] = 0x09; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iModelNumLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cModelNumber, iModelNumLen);
    iIndex += iModelNumLen;

    //Type 0A: Vendor Name
    int iVendorNameLen = (int)strlen(sDhcpOption43RawData.cVendorName);
    cHexBuf[iIndex++] = 0x0A; //Suboption Type
    cHexBuf[iIndex++] = (unsigned char)iVendorNameLen; //Length
    memcpy(&cHexBuf[iIndex], sDhcpOption43RawData.cVendorName, iVendorNameLen);
    iIndex += iVendorNameLen;

    //Type 1F: MTA MAC Address
    cHexBuf[iIndex++] = 0x1F; //Suboption Type
    cHexBuf[iIndex++] = 0x06; //As per dhcp option 60 type 1F MAC address length is 6 bytes
    unsigned char cMtaMacAddress[6] = {0};
    if (sscanf(sDhcpOption43RawData.cMtaMacAddress, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        &cMtaMacAddress[0], &cMtaMacAddress[1], &cMtaMacAddress[2],
        &cMtaMacAddress[3], &cMtaMacAddress[4], &cMtaMacAddress[5]) == 6)
    {
        memcpy(&cHexBuf[iIndex], cMtaMacAddress, 6);
        iIndex += 6;
    }
    else
    {
        if (sscanf(sDhcpOption43RawData.cMtaMacAddress, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
            &cMtaMacAddress[0], &cMtaMacAddress[1], &cMtaMacAddress[2],
            &cMtaMacAddress[3], &cMtaMacAddress[4], &cMtaMacAddress[5]) == 6)
        {
            memcpy(&cHexBuf[iIndex], cMtaMacAddress, 6);
            iIndex += 6;
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s %d: Invalid MTA MAC Address format..\n", __FUNCTION__, __LINE__);
        }
    }

    //Type 20: Correlation ID - Random 4 bytes
    // Generate random correlation ID
    uint32_t ui32CorrelationId = ((uint32_t)rand() << 16) | ((uint32_t)rand() & 0xFFFF);

    cHexBuf[iIndex++] = 0x20; //Suboption Type
    cHexBuf[iIndex++] = 0x04; //Length
    cHexBuf[iIndex++] = (unsigned char)((ui32CorrelationId >> 24) & 0xFF);
    cHexBuf[iIndex++] = (unsigned char)((ui32CorrelationId >> 16) & 0xFF);
    cHexBuf[iIndex++] = (unsigned char)((ui32CorrelationId >> 8) & 0xFF);
    cHexBuf[iIndex++] = (unsigned char)(ui32CorrelationId & 0xFF);

    DHCPMGR_LOG_INFO("%s %d: Correlation ID:%08x\n", __FUNCTION__, __LINE__, ui32CorrelationId);

    int iWritten = 0;
    for (int iVar = 0; iVar < iIndex; iVar++)
    {
        int iRet = snprintf(pOptionValue + iWritten, iOptionValueSize - iWritten, "%02x", cHexBuf[iVar]);
        if (iRet < 0 || (size_t)iRet >= iOptionValueSize - iWritten)
        {
            DHCPMGR_LOG_ERROR("%s %d: snprintf failed or buffer too small..\n", __FUNCTION__, __LINE__);
            return -1;
        }
        iWritten += iRet;
    }
    return 0;
}
/*
 * @brief Prepare the DHCP Option 60 value in hex-binary format.
 *
 * This function gathers voice packet capabilities using voice HAL APIs
 * and constructs the DHCP Option 60 value in hex-binary format according
 * to the vendor-specific requirements.
 *
 * @param[out] pOptionValue
 *      Pointer to a buffer that receives the hex-binary encoded option data.
 * @param[in] iOptionValueSize
 *      Size of the pOptionValue buffer.
 *
 * @return
 *      Returns 0 on success, -1 on failure.
*/
static int prepareDhcpOption60(char *pOptionValue, size_t iOptionValueSize)
{
    if (pOptionValue == NULL || iOptionValueSize == 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    VoicePktcCapabilitiesType sVoicePktcCapabilities = {0};
    DHCPMGR_LOG_INFO("%s %d: Preparing DHCP Option 60 for Voice Interface,Sizeof(VoicePktcCapabilitiesType) = %zu\n", __FUNCTION__, __LINE__, sizeof(VoicePktcCapabilitiesType));
    uint8_t ui8Ret = voice_hal_get_pktc_capabilities(&sVoicePktcCapabilities);
    if (1 != ui8Ret)
    {
        DHCPMGR_LOG_ERROR("%s %d: voice_hal_get_pktc_capabilities failed..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    DHCPMGR_LOG_INFO("%s %d: Original: voice_hal_get_pktc_capabilities Values are\n", __FUNCTION__, __LINE__);
    DHCPMGR_LOG_INFO("pktcblVersion=%d\n", sVoicePktcCapabilities.pktcblVersion);
    DHCPMGR_LOG_INFO("numEndpoints=%d\n", sVoicePktcCapabilities.numEndpoints);
    DHCPMGR_LOG_INFO("tgtSupport=%d\n", sVoicePktcCapabilities.tgtSupport);
    DHCPMGR_LOG_INFO("httpDownload=%d\n", sVoicePktcCapabilities.httpDownload);
    DHCPMGR_LOG_INFO("nvramInfoStorage=%d\n", sVoicePktcCapabilities.nvramInfoStorage);
    DHCPMGR_LOG_INFO("supportedCodecs=%02x %02x %02x\n",
        sVoicePktcCapabilities.supportedCodecs[0], sVoicePktcCapabilities.supportedCodecs[1],
        sVoicePktcCapabilities.supportedCodecs[2]);
    DHCPMGR_LOG_INFO("silenceSuppression=%d\n", sVoicePktcCapabilities.silenceSuppression);
    DHCPMGR_LOG_INFO("echoCancellation=%d\n", sVoicePktcCapabilities.echoCancellation);
    DHCPMGR_LOG_INFO("ugsAd=%d\n", sVoicePktcCapabilities.ugsAd);
    DHCPMGR_LOG_INFO("ifIndexStart=%d\n", sVoicePktcCapabilities.ifIndexStart);
    DHCPMGR_LOG_INFO("supportedProvFlow=%d\n", sVoicePktcCapabilities.supportedProvFlow);
    DHCPMGR_LOG_INFO("t38Version=%d\n", sVoicePktcCapabilities.t38Version);
    DHCPMGR_LOG_INFO("t38ErrorCorrection=%d\n", sVoicePktcCapabilities.t38ErrorCorrection);
    DHCPMGR_LOG_INFO("rfc2833=%d\n", sVoicePktcCapabilities.rfc2833);
    DHCPMGR_LOG_INFO("voiceMetrics=%d\n", sVoicePktcCapabilities.voiceMetrics);
    DHCPMGR_LOG_INFO("supportedMibs=%02x %02x %02x\n",
        sVoicePktcCapabilities.supportedMibs[0], sVoicePktcCapabilities.supportedMibs[1],
        sVoicePktcCapabilities.supportedMibs[2]);
    DHCPMGR_LOG_INFO("multiGrants=%d\n", sVoicePktcCapabilities.multiGrants);
    DHCPMGR_LOG_INFO("v_152=%d\n", sVoicePktcCapabilities.v_152);
    DHCPMGR_LOG_INFO("certBootstrapping=%d\n", sVoicePktcCapabilities.certBootstrapping);
    DHCPMGR_LOG_INFO("ipAddrProvCap=%d\n", sVoicePktcCapabilities.ipAddrProvCap);

    unsigned char cHexBuf[256] = {0};
    int iIndex = 0;

    /* Vendor prefix (Technicolor/Comcast specific) */
    cHexBuf[iIndex++] = 0x05;
    cHexBuf[iIndex++] = 0x49;

    /* Suboption 1: pktcblVersion */
    cHexBuf[iIndex++] = 0x01;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.pktcblVersion);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.pktcblVersion;

    /* Suboption 2: numEndpoints */
    cHexBuf[iIndex++] = 0x02;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.numEndpoints);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.numEndpoints;

    /* Suboption 3: tgtSupport */
    cHexBuf[iIndex++] = 0x03;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.tgtSupport);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.tgtSupport;

    /* Suboption 4: httpDownload */
    cHexBuf[iIndex++] = 0x04;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.httpDownload);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.httpDownload;

    /* Suboption 9: nvramInfoStorage */
    cHexBuf[iIndex++] = 0x09;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.nvramInfoStorage);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.nvramInfoStorage;

    /* Suboption 11: supportedCodecs, commented until we get the update from broadcom  */
    #if 0
    cHexBuf[iIndex++] = 0x0b;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.supportedCodecs);
    memcpy(&cHexBuf[iIndex], sVoicePktcCapabilities.supportedCodecs, sizeof(sVoicePktcCapabilities.supportedCodecs));
    iIndex += sizeof(sVoicePktcCapabilities.supportedCodecs);
    #else
    /* Subopt 11: supportedCodecs, As now hardcoded until we get the update from broadcom */
    cHexBuf[iIndex++] = 0x0b;
    cHexBuf[iIndex++] = 0x0b;  // Length = 11 bytes
    cHexBuf[iIndex++] = sVoicePktcCapabilities.supportedCodecs[0];
    cHexBuf[iIndex++] = sVoicePktcCapabilities.supportedCodecs[1];
    cHexBuf[iIndex++] = sVoicePktcCapabilities.supportedCodecs[2];
    //Rest of the value is   1 01 01 09 04 00 01 01
    cHexBuf[iIndex++] = 0x01;
    cHexBuf[iIndex++] = 0x01;
    cHexBuf[iIndex++] = 0x01;
    cHexBuf[iIndex++] = 0x09;
    cHexBuf[iIndex++] = 0x04;
    cHexBuf[iIndex++] = 0x00;
    cHexBuf[iIndex++] = 0x01;
    cHexBuf[iIndex++] = 0x01;
    #endif

    /* Suboption 12: silenceSuppression */
    cHexBuf[iIndex++] = 0x0C;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.silenceSuppression);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.silenceSuppression;

    /* Suboption 13: echoCancellation */
    cHexBuf[iIndex++] = 0x0D;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.echoCancellation);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.echoCancellation;

    /* Suboption 15: ugsAd */
    cHexBuf[iIndex++] = 0x0F;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.ugsAd);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.ugsAd;

    /* Suboption 16: ifIndexStart */
    cHexBuf[iIndex++] = 0x10;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.ifIndexStart);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.ifIndexStart;

    /* Suboption 18: supportedProvFlow */
    cHexBuf[iIndex++] = 0x12;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.supportedProvFlow);
    cHexBuf[iIndex++] = (sVoicePktcCapabilities.supportedProvFlow >> 8) & 0xFF;
    cHexBuf[iIndex++] = sVoicePktcCapabilities.supportedProvFlow & 0xFF;

    /* Suboption 19: t38Version */
    cHexBuf[iIndex++] = 0x13;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.t38Version);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.t38Version;

    /* Suboption 20: t38ErrorCorrection */
    cHexBuf[iIndex++] = 0x14;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.t38ErrorCorrection);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.t38ErrorCorrection;

    /* Suboption 21: rfc2833 */
    cHexBuf[iIndex++] = 0x15;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.rfc2833);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.rfc2833;

    /* Suboption 22: voiceMetrics */
    cHexBuf[iIndex++] = 0x16;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.voiceMetrics);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.voiceMetrics;

    /* Suboption 23: supportedMibs */
    cHexBuf[iIndex++] = 0x17;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.supportedMibs);
    memcpy(&cHexBuf[iIndex], sVoicePktcCapabilities.supportedMibs, sizeof(sVoicePktcCapabilities.supportedMibs));
    iIndex += sizeof(sVoicePktcCapabilities.supportedMibs);

    /* Suboption 24: multiGrants */
    cHexBuf[iIndex++] = 0x18;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.multiGrants);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.multiGrants;

    /* Suboption 25: v_152 */
    cHexBuf[iIndex++] = 0x19;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.v_152);;
    cHexBuf[iIndex++] = sVoicePktcCapabilities.v_152;

    /* Suboption 26: certBootstrapping */
    cHexBuf[iIndex++] = 0x1A;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.certBootstrapping);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.certBootstrapping;

    /* Suboption 38: ipAddrProvCap */
    cHexBuf[iIndex++] = 0x26;
    cHexBuf[iIndex++] = sizeof(sVoicePktcCapabilities.ipAddrProvCap);
    cHexBuf[iIndex++] = sVoicePktcCapabilities.ipAddrProvCap;

    int iWritten = snprintf(pOptionValue, iOptionValueSize, "pktc2.0:");
    if (iWritten < 0 || (size_t)iWritten >= iOptionValueSize)
    {
        DHCPMGR_LOG_ERROR("%s %d: snprintf failed or buffer too small..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    for (int iInd = 0; iInd < iIndex; iInd++)
    {
        int iRet = snprintf(pOptionValue + iWritten, iOptionValueSize - iWritten, "%02X", cHexBuf[iInd]);
        if (iRet < 0 || (size_t)iRet >= (iOptionValueSize - iWritten))
        {
            DHCPMGR_LOG_ERROR("%s %d: snprintf failed or buffer too small..\n", __FUNCTION__, __LINE__);
            return -1;
        }
        iWritten += iRet;
    }
    DHCPMGR_LOG_INFO("%s %d: Prepared DHCP Option 60 Value: %s\n", __FUNCTION__, __LINE__, pOptionValue);
    return 0;
}

/*
 *@brief Get the voice support interface name from syscfg.
 * This function retrieves the interface name used for voice support
 * from the syscfg configuration. It caches the value for subsequent calls.
 * @param[out] pIfname
 *      Pointer to a buffer that receives the interface name.
 * @param[in] iIfLen
 *      Size of the pIfname buffer.
*/
static void getVoiceIfname(char *pIfname, int iIfLen)
{
    if (pIfname == NULL || iIfLen == 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return;
    }
    static char cIfname[32] = {0};
    if (cIfname[0] != '\0')
    {
        snprintf(pIfname, iIfLen, "%s", cIfname);
        return;
    }
    syscfg_get(NULL, "VoiceSupport_IfaceName", cIfname, sizeof(cIfname));
    if (cIfname[0] == '\0')
    {
        snprintf(cIfname, sizeof(cIfname), "mta0");
        DHCPMGR_LOG_INFO("%s %d: VoiceSupport_IfaceName not set in syscfg, using default %s..\n", __FUNCTION__, __LINE__, cIfname);
    }
    snprintf(pIfname, iIfLen, "%s", cIfname);
}
/*
 * @brief Get the DHCP Option 60 value for a given interface.
 *
 * This function checks if the provided interface name matches the
 * voice support interface name from syscfg. If it matches, it prepares
 * the DHCP Option 60 value using voice capabilities.
 *
 * @param[in] ifName
 *      Name of the network interface.
 * @param[out] OptionValue
 *      Pointer to a buffer that receives the hex-binary encoded option data.
 * @param[in] OptionValueSize
 *      Size of the OptionValue buffer.
 *
 * @return
 *      Returns 0 on success, -1 on failure or if not a voice interface.
*/
int Get_DhcpV4_CustomOption60(const char *ifName, char *OptionValue,size_t OptionValueSize)
{
    if (NULL == ifName || NULL == OptionValue || 0 == OptionValueSize)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }
    char cIfName[32] = {0};
    getVoiceIfname(cIfName, sizeof(cIfName));
    if (0 == strcmp(ifName, cIfName))
    {
        return prepareDhcpOption60(OptionValue, OptionValueSize);
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d: Not a voice interface..\n", __FUNCTION__, __LINE__);
        return -1;
    }

}
/*
 * @brief Get the DHCP Option 43 value for a given interface.
 *
 * This function checks if the provided interface name matches the
 * voice support interface name from syscfg. If it matches, it prepares
 * the DHCP Option 43 value using device information.
 *
 * @param[in] ifName
 *      Name of the network interface.
 * @param[out] OptionValue
 *      Pointer to a buffer that receives the hex-binary encoded option data.
 * @param[in] OptionValueSize
 *      Size of the OptionValue buffer.
 *
 * @return
 *      Returns 0 on success, -1 on failure or if not a voice interface.
*/
int Get_DhcpV4_CustomOption43(const char *ifName, char *OptionValue, size_t OptionValueSize)
{
    if (NULL == ifName || NULL == OptionValue || 0 == OptionValueSize)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    char cIfName[32] = {0};
    getVoiceIfname(cIfName, sizeof(cIfName));
    if (0 == strcmp(ifName, cIfName))
    {
        return prepareDhcpOption43(OptionValue, OptionValueSize);
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d: Not a voice interface..\n", __FUNCTION__, __LINE__);
        return -1;
    }
}
