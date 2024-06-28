// HyperV VM tool. Copyright (C) 2024, Nikolai Vorontsov
#include <comdef.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

int Help(const wchar_t* extra = nullptr)
{
	if (extra)
		printf("Invalid %ls parameter\n\n", extra);
	printf("Usage: HyperVTool VM-name Action\n\nwhere Action is Start, Stop, Reboot, Reset, Save, Pause, and Resume\n");
	return 0;
}

int wmain(int argc, const wchar_t** argv)
{
	printf("Hyper-V tool, Copyright (C) 2024, VorontSOFT. Version 0.1\n\n");
	if (argc < 3)
		return Help();

	const wchar_t* vm_name = argv[1];
	if (wcslen(vm_name) == 0)
		return Help(L"machine name");

	enum EVmStateCmd
	{
		START = 2,
		STOP = 3,
		REBOOT = 10,
		RESET = 11,
		SAVE_STATE = 32768,
		PAUSE = 32769,
		RESUME = 32770
	};
	int cmd = 0;
	const wchar_t* vm_command = argv[2];
	if (_wcsicmp(vm_command, L"start") == 0)
		cmd = START;
	else if (_wcsicmp(vm_command, L"stop") == 0)
		cmd = STOP;
	else if (_wcsicmp(vm_command, L"reboot") == 0)
		cmd = REBOOT;
	else if (_wcsicmp(vm_command, L"reset") == 0)
		cmd = RESET;
	else if (_wcsicmp(vm_command, L"save") == 0)
		cmd = SAVE_STATE;
	else if (_wcsicmp(vm_command, L"pause") == 0)
		cmd = PAUSE;
	else if (_wcsicmp(vm_command, L"resume") == 0)
		cmd = RESUME;
	else
		return Help(L"action");

	// Initialize COM.
	HRESULT hRes = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hRes))
	{
		printf("Failed to initialize COM library. Error code = 0x%08X\n", hRes);
		return 1; // Program has failed.
	}

	int ret_code = 1;

	// Set general COM security levels.
	hRes = CoInitializeSecurity(nullptr,  // Descriptor
								-1,       // COM negotiates service
								nullptr,  // Authentication services
								nullptr,
								RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
								RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
								nullptr,   // Authentication info
								EOAC_NONE, // Additional capabilities
								nullptr);
	if (FAILED(hRes))
	{
		printf("Failed to initialize security. Error code = 0x%08X\n", hRes);
		goto EXIT1;
	}

	// Create a WMI locator to WMI.
	IWbemLocator* pLoc = nullptr;
	hRes = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hRes) || pLoc == nullptr)
	{
		printf("Failed to create WMI locator object. Error code = 0x%08X\n", hRes);
		goto EXIT1;
	}

	// Replace "RemoteServerAddress" with the actual address of the remote server.
	// You may also need to provide the "User", "Password", and possibly the "Authority" parameters
	// if the remote server requires authentication.
	//const wchar_t* wmi_namespace = L"\\\\RemoteServerAddress\\ROOT\\virtualization\\v2";
	const wchar_t* wmi_namespace = L"ROOT\\virtualization\\v2";
	IWbemServices* pSvc = nullptr;
	hRes = pLoc->ConnectServer(_bstr_t(wmi_namespace), // WMI namespace
							   nullptr, // User name
							   nullptr, // User password
							   0,       // Locale
							   0,       // Security flags
							   nullptr, // Authority (e.g., "kerberos:RemoteServerAddress")
							   nullptr, // Context object
							   &pSvc);  // IWbemServices proxy
	if (FAILED(hRes) || pSvc == nullptr)
	{
		printf("Failed to connect to WMI server. Error code = 0x%08X\n", hRes);
		goto EXIT1;
	}
	// printf("Connected to %ls WMI namespace\n", wmi_namespace);

	// Set security levels on the proxy.
	hRes = CoSetProxyBlanket(pSvc,              // Indicates the proxy to set
							 RPC_C_AUTHN_WINNT, // RPC_C_AUTHN_xxx
							 RPC_C_AUTHZ_NONE,  // RPC_C_AUTHZ_xxx
							 nullptr,           // Server principal name
							 RPC_C_AUTHN_LEVEL_CALL,       // RPC_C_AUTHN_LEVEL_xxx
							 RPC_C_IMP_LEVEL_IMPERSONATE,  // RPC_C_IMP_LEVEL_xxx
							 nullptr,           // Client identity
							 EOAC_NONE);        // Proxy capabilities
	if (FAILED(hRes))
	{
		printf("Failed to set security levels on proxy. Error code = 0x%08X\n)", hRes);
		goto EXIT3;
	}

	// Use the IWbemServices pointer to make requests of WMI.
	// For example, get the name of the operating system.
	IEnumWbemClassObject* pEnumerator = nullptr;
	wchar_t buf[1024];
	wsprintf(buf, L"SELECT * FROM Msvm_ComputerSystem WHERE ElementName='%s'", vm_name);
	hRes = pSvc->ExecQuery(bstr_t("WQL"),
						   bstr_t(buf),
						   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
						   nullptr,
						   &pEnumerator);
	if (FAILED(hRes) || pEnumerator == nullptr)
	{
		printf("Failed to query for %ls VM. Error code = 0x%08X\n", vm_name, hRes);
		goto EXIT3;
	}

	// Get the data from the query.
	while (pEnumerator)
	{
		IWbemClassObject* pclsObj = nullptr;
		ULONG uReturn = 0;
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (FAILED(hRes) || uReturn == 0)
			break;

		// Get the VM GUID.
		VARIANT vtProp;
		VariantInit(&vtProp);
		hRes = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		if (FAILED(hRes))
		{
			printf("Failed to query for VM GUID. Error code = 0x%08X\n", hRes);
			break;
		}
		// printf("VM GUID : %ls\n", vtProp.bstrVal);

		// Change the state of the VM here.
		// Use the RequestStateChange method to change the VM state.
		IWbemClassObject* pClass = nullptr, * pInParamsDefinition = nullptr, * pClassInstance = nullptr;
		hRes = pSvc->GetObject(bstr_t("Msvm_ComputerSystem"), 0, nullptr, &pClass, nullptr);
		SUCCEEDED(hRes) && SUCCEEDED(hRes = pClass->GetMethod(L"RequestStateChange", 0, 
															  &pInParamsDefinition, nullptr));
		SUCCEEDED(hRes) && SUCCEEDED(hRes = pInParamsDefinition->SpawnInstance(0, &pClassInstance));

		VARIANT varCommand;
		varCommand.vt = VT_I4;
		varCommand.lVal = cmd;
		SUCCEEDED(hRes) && SUCCEEDED(hRes = pClassInstance->Put(L"RequestedState", 0, &varCommand, 0));

		// Prepare object path
		wsprintf(buf, L"%s:Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\",Name=\"%s\"",
				 wmi_namespace, vtProp.bstrVal);

		VARIANT varPath;
		VariantInit(&varPath);
		varPath.vt = VT_BSTR;
		varPath.bstrVal = bstr_t(buf);

		SUCCEEDED(hRes) && SUCCEEDED(hRes = pSvc->ExecMethod(varPath.bstrVal, bstr_t(L"RequestStateChange"),
															 0, nullptr, pClassInstance, nullptr, 0));
		if (FAILED(hRes))
			printf("Failed to %ls VM%ls. Error code = 0x%08X\n", vm_command,
				   (varCommand.lVal == SAVE_STATE) ? L" state" : L"", hRes);
		else
			printf("VM state has changed successfully.\n");

		VariantClear(&varPath);
		VariantClear(&vtProp);

		if (pClassInstance)
			pClassInstance->Release();
		if (pInParamsDefinition)
			pInParamsDefinition->Release();
		if (pClass)
			pClass->Release();

		pclsObj->Release();
	}

	ret_code = 0; // Program successfully completed.

	// Final cleanup
	pEnumerator->Release();
EXIT3:
	pSvc->Release();
EXIT2:
	pLoc->Release();
EXIT1:
	CoUninitialize();

	return ret_code;
} // int wmain(int argc, const wchar_t** argv)
