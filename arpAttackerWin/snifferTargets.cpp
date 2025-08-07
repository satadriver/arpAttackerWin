
#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include "snifferTargets.h"
#include "Public.h"

#include "ClientAddress.h"
#include <time.h>
#include "config.h"
#include <string>
#include <iostream>
#include "connectionManager.h"
#include <vector>
#include "Packet.h"
#include "Utils.h"


using namespace std;




#define ARP_SNIFFER_WAITTIME 6

int SnifferTargets::GetTarget(void * param, vector <CLIENTADDRESSES> &attackList)
{
	int iRet = 0;

	pcap_t * pcapt = (pcap_t *)param;

	pcap_pkthdr *				lpPcapHdr = 0;
	const unsigned char *		lpPacket = 0;
	iRet = pcap_next_ex(pcapt, &lpPcapHdr, &lpPacket);

	int cnt = ConnectionManager::getSubnetSize();
	for (int i = 0; i < cnt; i++)
	{
		unsigned int startip = ntohl(ntohl(gNetMaskIP) + i);

		if (i == 0xff || startip == gLocalIP || startip == gNetMaskIP || startip == gGatewayIP) {
			continue;
		}

		iRet = ArpCheat::BroadcastARP(pcapt, startip);
		iRet = ArpCheat::BroadcastARP(pcapt, startip);
		iRet = ArpCheat::BroadcastARP(pcapt, startip);

		Sleep(20);
	}

	time_t oldtime = time(0);

	while (time(0) - oldtime < ARP_SNIFFER_WAITTIME)
	{
		iRet = pcap_next_ex(pcapt, &lpPcapHdr, &lpPacket);
		if (iRet == 0)
		{
			continue;
		}
		else if (iRet < 0)
		{
			char * lpError = pcap_geterr(pcapt);
			printf("%s line:%d error\n", __FUNCTION__, __LINE__);
			continue;
		}
		else if (lpPcapHdr->caplen != lpPcapHdr->len || lpPcapHdr->caplen >= MAX_PACKET_SIZE)
		{
			printf("%s line:%d error\n", __FUNCTION__, __LINE__);
			continue;
		}

		int iCapLen = lpPcapHdr->caplen;
		LPMACHEADER lpMac = (LPMACHEADER)lpPacket;

		if (lpMac->Protocol == 0x0608) {
			LPARPHEADER		ARPheader = (LPARPHEADER)((char*)lpMac + sizeof(MACHEADER));
			if (ARPheader->HardWareType == 0x0100 && ARPheader->ProtocolType == 0x0008 && 
				ARPheader->HardWareSize == MAC_ADDRESS_SIZE &&
				ARPheader->ProtocolSize == sizeof(unsigned long)) {
				unsigned int senderip = *(unsigned int *)ARPheader->SenderIP;
				unsigned int recverip = *(unsigned int *)ARPheader->RecverIP;
				if (ARPheader->Opcode == 0x0200)
				{
					iRet = Config::addTarget(attackList, senderip, ARPheader->SenderMac);
				}
			}
		}
	}
	
	return 0;
}




