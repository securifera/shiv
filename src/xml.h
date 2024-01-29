/*
	Slightly modified version of https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/modules/kull_m_xml.h

	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/

#pragma once

#include <msxml2.h>
#include <string>

IXMLDOMDocument* CreateAndInitDOM();
void ReleaseDom(IXMLDOMDocument* pDoc);

BOOL LoadXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename);
BOOL SaveXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename);

std::string  getAttribute(IXMLDOMNode* pNode, std::string name);
std::string getTextValue(IXMLDOMNode * pNode, PCWSTR name);
