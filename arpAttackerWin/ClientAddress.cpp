


#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include <Nb30.h>
#include <IPHlpApi.h>
#include "Public.h"
#include "connectionManager.h"
#include "ClientAddress.h"

using namespace std;



unsigned char* ClientAddress::isTarget(unsigned int ip) {
	int cnt = gAttackTargetIP.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTargetIP[i].clientIP == 0 || memcmp(gAttackTargetIP[i].clientMAC,
			ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0)
		{
			continue;
		}

		if (ip == gAttackTargetIP[i].clientIP)
		{
			return gAttackTargetIP[i].clientMAC;
		}
	}

	return FALSE;
}



unsigned int ClientAddress::isTarget(unsigned char mac[MAC_ADDRESS_SIZE]) {
	int cnt = gAttackTargetIP.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTargetIP[i].clientIP == 0 || memcmp(gAttackTargetIP[i].clientMAC, 
			ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0)
		{
			continue;
		}

		if (memcmp(mac, gAttackTargetIP[i].clientMAC,MAC_ADDRESS_SIZE) == 0)
		{
			return gAttackTargetIP[i].clientIP;
		}
	}

	return FALSE;
}


int ClientAddress::GetMACFromIP(unsigned int ip, unsigned char mac[]) {
 	unsigned long dwMacLen = MAC_ADDRESS_SIZE;
	int nRetCode = SendARP(ip, gLocalIP, (unsigned long*)mac, &dwMacLen);
	if (nRetCode != NO_ERROR)
	{
		printf("%s line:%d error:%d\n", __FUNCTION__, __LINE__,nRetCode);		//ERROR_BAD_NET_NAME = 67
		return -1;
	}
 	return 0;
}
