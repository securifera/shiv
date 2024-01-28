#include <Wbemidl.h>
#include <string>


wchar_t* convertMultiByteToWide(char* source);
std::string ConvertWCSToMBS(const wchar_t* pstr, long wslen);
std::string ConvertBSTRToMBS(BSTR bstr);
std::string fixedStrLen(std::string& inputStr, size_t fixedlen);

HRESULT basic_conn(IWbemLocator* pLoc, IWbemServices** pSvc, COAUTHIDENTITY** authIdent, wchar_t* target, wchar_t* nmspace, wchar_t* domain, wchar_t* user, wchar_t* pwd);
HRESULT init_com(IWbemLocator** pLoc);
