//#define _WIN32_DCOM
#include "wmi_exec.h"

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include "debug.h"

#pragma comment(lib, "wbemuuid.lib")


BOOL wmi_exec_cmd(std::string host, std::string cmd)
{
    HRESULT hres;	
	std::string resource = "\\\\";
	resource.append(host);
	resource.append("\\root\\cimv2");


    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Failed to initialize COM library. Error:", hres);
        return FALSE;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------
    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );


    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Failed to initialize security. Error:", hres);
        CoUninitialize();
        return FALSE;                      // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance( CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc); 
    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Failed to create IWbemLocator object. Error:", hres);
        CoUninitialize();
        return FALSE;                 // Program has failed.
    }

    // Step 4: ---------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices *pSvc = NULL;
 
    // Connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    hres = pLoc->ConnectServer( _bstr_t(resource.c_str()), NULL, NULL, 0, NULL, 0, 0, &pSvc );
    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Could not connect. Error:", hres);
        pLoc->Release();
        CoUninitialize();
        return FALSE;                // Program has failed.
    }

    //cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // Step 5: --------------------------------------------------
    // Set security levels for the proxy ------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Could not set proxy blanket. Error:", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // set up to call the Win32_Process::Create method
    BSTR MethodName = SysAllocString(L"Create");
    BSTR ClassName = SysAllocString(L"Win32_Process");

    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    IWbemClassObject* pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

    IWbemClassObject* pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    // Create the values for the in parameters
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(cmd.c_str());

    // Store the value for the in parameters
    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

    //wprintf(L"The command is: %s\n", V_BSTR(&varCommand));

    // Execute Method
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(ClassName, MethodName, 0,
    NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres))
    {
		DbgFprintf(outlogfile, PRINT_ERROR, "Could not execute method. Error:", hres);
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }

    // To see what the method returned,
    // use the following code.  The return value will
    // be in &varReturnValue
    VARIANT varReturnValue;
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);
	DbgFprintf(outlogfile, PRINT_INFO2, "Return value:", varReturnValue);
	
    // Clean up
    //--------------------------
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);
    SysFreeString(ClassName);
    SysFreeString(MethodName);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();

	return TRUE;
}

void exec_cmd(IWbemServices* pSvc, COAUTHIDENTITY* authIdent, std::string cmd)
{
	HRESULT hres;

	if (!pSvc)
		return;

	// set up to call the Win32_Process::Create method
	BSTR MethodName = SysAllocString(L"Create");
	BSTR ClassName = SysAllocString(L"Win32_Process");

	IWbemClassObject* pClass = NULL;
	hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

	IWbemClassObject* pInParamsDefinition = NULL;
	hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

	IWbemClassObject* pClassInstance = NULL;
	hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

	// Create the values for the in parameters
	VARIANT varCommand;
	varCommand.vt = VT_BSTR;
	varCommand.bstrVal = _bstr_t(cmd.c_str());

	// Store the value for the in parameters
	hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

	//wprintf(L"The command is: %s\n", V_BSTR(&varCommand));

	// Execute Method
	IWbemClassObject* pOutParams = NULL;
	hres = pSvc->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

	//if (FAILED(hres))
	//{
	//	DbgFprintf(outlogfile, PRINT_ERROR, "Could not execute method. Error:", hres);
	//	VariantClear(&varCommand);
	//	SysFreeString(ClassName);
	//	SysFreeString(MethodName);
	//	pClass->Release();
	//	pClassInstance->Release();
	//	pInParamsDefinition->Release();
	//	pOutParams->Release();
	//	pSvc->Release();
	//	pLoc->Release();
	//	CoUninitialize();
	//	return FALSE;               // Program has failed.
	//}

	// To see what the method returned,
	// use the following code.  The return value will
	// be in &varReturnValue
	VARIANT varReturnValue;
	hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);
	DbgFprintf(outlogfile, PRINT_INFO2, "Return value:", varReturnValue);

	// Clean up
	//--------------------------
	VariantClear(&varCommand);
	VariantClear(&varReturnValue);
	SysFreeString(ClassName);
	SysFreeString(MethodName);
	pClass->Release();
	pClassInstance->Release();
	pInParamsDefinition->Release();
	pOutParams->Release();
	//pLoc->Release();
	//pSvc->Release();
	//CoUninitialize();
}

void wmi_exec_cmd2(std::string host, std::string domain, std::string user, std::string pwd, std::string cmd)
{
	IWbemLocator* pLoc = NULL;
	IWbemServices* pCimSvc = NULL;
	COAUTHIDENTITY* authIdent = NULL;

	wchar_t* whost = NULL;
	wchar_t* wdomain = NULL;
	wchar_t* wuser = NULL;
	wchar_t* wpwd = NULL;

	if (host.size() > 0)
		whost = convertMultiByteToWide2((char*)host.c_str());

	if (domain.size() > 0)
		wdomain = convertMultiByteToWide2((char*)domain.c_str());

	if (user.size() > 0)
		wuser = convertMultiByteToWide2((char*)user.c_str());

	if (pwd.size() > 0)
		wpwd = convertMultiByteToWide2((char*)pwd.c_str());

	init_com2(&pLoc);
	basic_conn2(pLoc, &pCimSvc, &authIdent, whost, NULL, wdomain, wuser, wpwd);
	exec_cmd(pCimSvc, authIdent, cmd);

	// cleanup WMI COM resources
	if (authIdent) {
		if (authIdent->User)
			free(authIdent->User);
		if (authIdent->Domain)
			free(authIdent->Domain);
		if (authIdent->Password)
			free(authIdent->Password);

		free(authIdent);
	}
	if (pCimSvc)
		pCimSvc->Release();
	if (pLoc)
		pLoc->Release();
	CoUninitialize();

	// cleanup arguments
	if (whost)
		free(whost);
	if (wdomain)
		free(wdomain);
	if (wuser)
		free(wuser);
	if (wpwd)
		free(wpwd);
}