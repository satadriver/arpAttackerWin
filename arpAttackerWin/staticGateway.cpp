
#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include "staticGateway.h"

#include <iostream>
#include <string>
#include "Public.h"
#include "Utils.h"

using namespace std;


//netsh i i show in
//netsh -c "i i" add neighbors 21 192.168.21.1 b0-95-8e-50-9b-eb
//netsh -c "i i" delete neighbors 21



int GetSystemBits()
{
	if(sizeof(unsigned long) == 4)
	{
		return 32;
	}
	else if(sizeof(unsigned long) == 8)
	{
		return 64;
	}
	else
	{
		return -1; //unknown
	}
}


DWORD QueryRegistryValue(HKEY hMainKey, char * szSubKey, char * szKeyName, unsigned char * szKeyValue,DWORD type)
{
	unsigned long iQueryLen = MAX_PATH;
	
	DWORD dwDisPos = REG_OPENED_EXISTING_KEY;
	HKEY hKey = 0;
	int iRes = 0;
	if(hMainKey == 0 || szSubKey == 0 || szKeyName == 0 || szKeyValue == 0)
	{
		return FALSE;
	}

	PVOID dwWow64Value;
	int bits = GetSystemBits();
	if (bits == 64 && hMainKey == HKEY_LOCAL_MACHINE)
	{
		Wow64DisableWow64FsRedirection(&dwWow64Value);
	}

	//KEY_WEITE will cause error like winlogon
	//winlogon :Registry symbolic links should only be used for for application compatibility when absolutely necessary.
	iRes = RegCreateKeyExA(hMainKey, szSubKey, 0, REG_NONE, REG_OPTION_NON_VOLATILE, KEY_READ, 0, &hKey, &dwDisPos);
	if (bits == 64 && hMainKey == HKEY_LOCAL_MACHINE)
	{
		Wow64RevertWow64FsRedirection(&dwWow64Value);
	}

	if (iRes != ERROR_SUCCESS)
	{
		return FALSE;
	}

	//if value is 234 ,it means out buffer is limit.2 is not value
	iRes = RegQueryValueExA(hKey, szKeyName, 0, &type, szKeyValue, &iQueryLen);
	if (iRes == ERROR_SUCCESS)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}



string StaticGateway::getAdapterAlias(string adaptername) {
	unsigned char szalias[MAX_PATH] = { 0 };
	//can not be \\SYSTEM?WHY?
	string subkey = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + adaptername + "\\Connection\\";

	int ret = QueryRegistryValue(HKEY_LOCAL_MACHINE, (char*)subkey.c_str(), "Name", szalias,REG_SZ);
	if (ret)
	{
		return string((char*)szalias);
	}

	return "";
}


//netsh -c "i i" add neighbors 21 192.168.21.1 b0-95-8e-50-9b-eb
int StaticGateway::bindStaticGatewayMac(int index, unsigned int gateip, unsigned char gatemac[MAC_ADDRESS_SIZE]) {
	
	int ret = 0;

	string strip = Utils::formatIP(gateip);
	string strmac = Utils::formatMAC(gatemac);
	char cmd[1024];
	wsprintfA(cmd, "cmd /Q /c netsh -c \"i i\" add neighbors %d %s %s >> ./cmdout.log", index, strip.c_str(),strmac.c_str());

	ret = WinExec(cmd, SW_HIDE);

	printf("bind mac:%s with ip:%s result:%d\r\n", strmac.c_str(), strip.c_str(), GetLastError());

	return ret;
}

//netsh i i show in
//netsh -c "i i" delete neighbors 18
int StaticGateway::freeStaticGatewayMac(int index) {

	int ret = 0;

	char cmd[1024];
	wsprintfA(cmd, "netsh -c \"i i\" delete neighbors %d", index);

	ret = WinExec(cmd, SW_HIDE);

	printf("clear bind ip with mac\r\n");

	return ret;
}