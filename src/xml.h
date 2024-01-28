#pragma once

#include <msxml2.h>
#include <string>

IXMLDOMDocument* CreateAndInitDOM();
void ReleaseDom(IXMLDOMDocument* pDoc);

BOOL LoadXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename);
BOOL SaveXMLFile(IXMLDOMDocument* pXMLDom, PCWSTR filename);

std::string  getAttribute(IXMLDOMNode* pNode, std::string name);
std::string getTextValue(IXMLDOMNode * pNode, PCWSTR name);
