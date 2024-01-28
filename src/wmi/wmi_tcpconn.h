#include <string>
#include <Wbemidl.h>


std::string tcpStateToString(int state);
void list_tcp_connections(IWbemServices* pSvc, COAUTHIDENTITY* authIdent);
