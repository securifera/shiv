/*
	Slightly modified version of https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/kuhl_m_iis.h

	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/

#pragma once

#include <Windows.h>
#include <string>

typedef enum _IISXMLType {
	IISXMLType_Providers,
	IISXMLType_ApplicationPools,
	IISXMLType_Sites,
	IISXMLType_Locations,
} IISXMLType;

BOOL parse_iis_apphost(std::string filename, BOOL isLocal);
void iis_apphost_genericEnumNodes( IXMLDOMDocument* pXMLDom, PCWSTR path, IISXMLType xmltype, LPCWSTR provider, LPCBYTE data, DWORD szData, BOOL isLocal);
BOOL iis_apphost_provider( IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, LPCWSTR provider, LPCBYTE data, DWORD szData, BOOL isLocal);
void iis_apphost_apppool( IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, BOOL isLocal);
void iis_apphost_site( IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, BOOL isLocal);
void iis_apphost_locations(IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode);

void iis_maybeEncrypted( IXMLDOMDocument* pXMLDom, PCWSTR password, BOOL isLocal);
void iis_apphost_provider_decrypt(PCWSTR keyContainerName, BOOL isMachine, LPCBYTE sessionKey, DWORD szSessionKey, LPCBYTE data, DWORD szData, BOOL isLocal);