/*
	Slightly modified version of https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/modules/kull_m_xml.c

	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/

#include "xml.h"
#include "debug.h"
#include "utils.h"

#pragma comment(lib, "msxml2.lib")

IXMLDOMDocument* CreateAndInitDOM()
{
	IXMLDOMDocument* pDoc = NULL;

	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "Failed to initialize COM library. Error:", hres);
		return FALSE;
	}

	HRESULT hr = CoCreateInstance(CLSID_DOMDocument, NULL, CLSCTX_INPROC_SERVER, IID_IXMLDOMDocument, (void**)&pDoc);
	if (hr == S_OK)
	{
		pDoc->put_async(VARIANT_FALSE);
		pDoc->put_validateOnParse(VARIANT_FALSE);
		pDoc->put_resolveExternals(VARIANT_FALSE);
		pDoc->put_preserveWhiteSpace(VARIANT_FALSE);
	}
	else 
		DbgFprintf(outlogfile, PRINT_ERROR, "CoCreateInstance: 0x%08x\n", hr);

	return pDoc;
}

void ReleaseDom(IXMLDOMDocument* pDoc)
{
	if (pDoc)
		pDoc->Release();

	CoUninitialize();
}

BOOL LoadXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename)
{
	BOOL status = FALSE;
	VARIANT varFileName;
	VARIANT_BOOL varStatus;
	BSTR bFilename;
	HRESULT hr;
	if (filename)
	{
		if (bFilename = SysAllocString(filename))
		{
			VariantInit(&varFileName);
			V_VT(&varFileName) = VT_BSTR;
			V_BSTR(&varFileName) = bFilename;
			hr = pXMLDom->load(varFileName, &varStatus);
			status = (hr == S_OK);
			if (!status)
				DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] IXMLDOMDocument_load: 0x%08x\n", hr);
			SysFreeString(bFilename);
		}
	}
	return status;
}

BOOL SaveXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename)
{
	BOOL status = FALSE;
	VARIANT varFileName;
	BSTR bFilename;
	HRESULT hr;
	if (filename)
	{
		if (bFilename = SysAllocString(filename))
		{
			VariantInit(&varFileName);
			V_VT(&varFileName) = VT_BSTR;
			V_BSTR(&varFileName) = bFilename;
			hr = pXMLDom->save(varFileName);
			status = (hr == S_OK);
			if (!status)
				DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] IXMLDOMDocument_save: 0x%08x\n", hr);
			SysFreeString(bFilename);
		}
	}
	return status;
}

std::string getAttribute(IXMLDOMNode* pNode, std::string s_name)
{
	std::string result;
	IXMLDOMNamedNodeMap* map;
	IXMLDOMNode* nAttr;
	BSTR bstrGeneric;
	long length, i;
	BOOL isMatch = FALSE;

	//Convert to wide
	std::wstring ws(s_name.begin(), s_name.end());
	if (pNode->get_attributes(&map) == S_OK)
	{
		if (map->get_length(&length) == S_OK)
		{
			for (i = 0; (i < length) && !isMatch; i++)
			{
				if (map->get_item(i, &nAttr) == S_OK)
				{
					if (nAttr->get_nodeName(&bstrGeneric) == S_OK)
					{
						isMatch = (_wcsicmp(ws.c_str(), bstrGeneric) == 0);
						SysFreeString(bstrGeneric);
						if (isMatch)
						{
							if (nAttr->get_text( &bstrGeneric) == S_OK)
							{
								std::wstring ws(bstrGeneric, SysStringLen(bstrGeneric));
								result = ws2s(ws);
								//result = std::string(ws.begin(), ws.end());
								SysFreeString(bstrGeneric);
							}
						}
					}
					nAttr->Release();
				}
			}
		}
		map->Release();
	}
	return result;
}

std::string getTextValue(IXMLDOMNode* pNode, PCWSTR name)
{
	std::string result;
	IXMLDOMNode* pSingleNode, * pChild;
	BSTR bstrGeneric;

	if ((pNode->selectSingleNode((BSTR)name, &pSingleNode) == S_OK) && pSingleNode)
	{
		if ((pSingleNode->get_firstChild(&pChild) == S_OK) && pChild)
		{
			if (pChild->get_text(&bstrGeneric) == S_OK)
			{
				std::wstring ws(bstrGeneric, SysStringLen(bstrGeneric));
				result = ws2s(ws);
				//result = std::string(ws.begin(), ws.end());
				SysFreeString(bstrGeneric);
			}
		}
	}
	return result;
}