#include <Windows.h>
#include <Wbemidl.h>
#include <string>


void wmi_exec_cmd(IWbemServices* pSvc, COAUTHIDENTITY* authIdent, std::string cmd);
