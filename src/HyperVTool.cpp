// HyperV VM tool. Copyright (C) 2024, Nikolai Vorontsov
#include <comdef.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

int Help()
{
	printf("Usage: HyperVTool VM-name Action\n\nwhere Action is Start, Stop, Save\n");
	return 0;
}

int wmain(int argc, const wchar_t** argv)
{
	printf("Hyper-V tool, 2024\n\n");
	if (argc < 3)
		return Help();

	const wchar_t* vm_name = argv[1];
	const wchar_t* command = argv[2];
	if (wcslen(vm_name) == 0 || wcslen(command) == 0)
		return Help();

	// Initialize COM.
	HRESULT hRes = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hRes))
	{
		printf("Failed to initialize COM library. Error code = 0x%08X\n", hRes);
		return 1; // Program has failed.
	}

	// Set general COM security levels.
	hRes = CoInitializeSecurity(
		nullptr,
		-1,                          // COM negotiates service
		nullptr,                     // Authentication services
		nullptr,                     // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
		nullptr,                     // Authentication info
		EOAC_NONE,                   // Additional capabilities
		nullptr                      // Reserved
	);

	if (FAILED(hRes))
	{
		printf("Failed to initialize security. Error code = 0x%08X\n", hRes);
		CoUninitialize();
		return 1; // Program has failed.
	}

	IWbemLocator* pLoc = nullptr;

	// Create a WMI locator to WMI.
	hRes = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hRes) || pLoc == nullptr)
	{
		printf("Failed to create IWbemLocator object. Err code = 0x%08X\n", hRes);
		CoUninitialize();
		return 1; // Program has failed.
	}

	IWbemServices* pSvc = nullptr;

	// Replace "RemoteServerAddress" with the actual address of the remote server.
	// You may also need to provide the "User", "Password", and possibly the "Authority" parameters
	// if the remote server requires authentication.
	hRes = pLoc->ConnectServer(
		//_bstr_t(L"\\\\RemoteServerAddress\\ROOT\\virtualization\\v2"), // WMI namespace
		_bstr_t(L"ROOT\\virtualization\\v2"), // WMI namespace
		nullptr, // User name
		nullptr, // User password
		0,       // Locale
		0,       // Security flags
		nullptr, // Authority (e.g., "kerberos:RemoteServerAddress")
		nullptr, // Context object
		&pSvc    // IWbemServices proxy
	);

	if (FAILED(hRes) || pSvc == nullptr)
	{
		printf("Could not connect. Error code = 0x%08X\n", hRes);
		pLoc->Release();
		CoUninitialize();
		return 1; // Program has failed.
	}

	printf("Connected to ROOT\\virtualization\\v2 WMI namespace\n");

	// Set security levels on the proxy.
	hRes = CoSetProxyBlanket(
		pSvc,                         // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,             // RPC_C_AUTHZ_xxx
		nullptr,                      // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,       // RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE,  // RPC_C_IMP_LEVEL_xxx
		nullptr,                      // Client identity
		EOAC_NONE                     // Proxy capabilities
	);

	if (FAILED(hRes))
	{
		printf("Could not set proxy blanket. Error code = 0x%08X\n)", hRes);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1; // Program has failed.
	}

	// Use the IWbemServices pointer to make requests of WMI.
	// For example, get the name of the operating system.
	IEnumWbemClassObject* pEnumerator = nullptr;
	wchar_t wql_buf[1024];
	wsprintf(wql_buf, L"SELECT * FROM Msvm_ComputerSystem WHERE ElementName='%s'", vm_name);
	hRes = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(wql_buf),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator);

	if (FAILED(hRes) || pEnumerator == nullptr)
	{
		printf("Query for %ls VM failed. Error code = 0x%08X\n", vm_name, hRes);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1; // Program has failed.
	}

	// Get the data from the query.
	while (pEnumerator)
	{
		IWbemClassObject* pclsObj = nullptr;
		ULONG uReturn = 0;
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (FAILED(hRes) || uReturn == 0)
			break;

		// Get the value of the Name property.
		VARIANT vtProp;
		hRes = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		if (FAILED(hRes))
			break;
		printf("VM GUID : %ls\n", vtProp.bstrVal);

		// Save the state of the VM here.
		// Use the RequestStateChange method to save the VM state.
		// This is where you'd use Msvm_VirtualSystemManagementService methods to save the VM state.
		IWbemClassObject* pClass = nullptr;
		hRes = pSvc->GetObject(bstr_t("Msvm_ComputerSystem"), 0, nullptr, &pClass, nullptr);
		if (FAILED(hRes) || pClass == nullptr)
		{
			printf("Can't get Msvm_ComputerSystem object. Error code = 0x%08X\n", hRes);
			break;
		}

		IWbemClassObject* pInParamsDefinition = nullptr;
		hRes = pClass->GetMethod(L"RequestStateChange", 0, &pInParamsDefinition, nullptr);
		if (FAILED(hRes) || pInParamsDefinition == nullptr)
		{
			printf("Can't get RequestStateChange method. Error code = 0x%08X\n", hRes);
			break;
		}

		IWbemClassObject* pClassInstance = nullptr;
		hRes = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
		if (FAILED(hRes) || pClassInstance == nullptr)
		{
			printf("Can't execute SpawnInstance method. Error code = 0x%08X\n", hRes);
			break;
		}

		enum {
			START = 2,
			STOP = 3,
			SAVE_STATE = 32768,
			PAUSE = 32769,
			RESUME = 32770
		};
		VARIANT varCommand;
		VariantInit(&varCommand);
		varCommand.vt = VT_I4;
		if (_wcsicmp(command, L"start") == 0)
			varCommand.lVal = START;
		else if (_wcsicmp(command, L"stop") == 0)
			varCommand.lVal = STOP;
		else if (_wcsicmp(command, L"save") == 0)
			varCommand.lVal = SAVE_STATE;

		hRes = pClassInstance->Put(L"RequestedState", 0, &varCommand, 0);
		if (FAILED(hRes)) {
			printf("Failed to request VM state. Error code = 0x%08X\n", hRes);
			break;
		}

		IWbemClassObject* pOutParams = nullptr;
		hRes = pSvc->ExecMethod(vtProp.bstrVal, bstr_t(L"RequestStateChange"),
			0, nullptr, pClassInstance, &pOutParams, NULL);

		if (FAILED(hRes))
			printf("Failed to %ls VM%ls. Error code = 0x%08X\n", command,
				(varCommand.lVal == SAVE_STATE) ? L" state" : L"", hRes);
		else
			printf("VM state changed successfully.\n");
		if (pOutParams)
			pOutParams->Release();

		VariantClear(&vtProp);

		if (pClassInstance)
			pClassInstance->Release();
		if (pInParamsDefinition)
			pInParamsDefinition->Release();
		if (pClass)
			pClass->Release();

		pclsObj->Release();
	}

	// Cleanup
	pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return 0; // Program successfully completed.
} // int wmain(int argc, const wchar_t** argv)
