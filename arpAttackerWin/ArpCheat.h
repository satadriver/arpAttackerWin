#pragma once

#ifndef ARPCHEAT_H
#define ARPCHEAT_H

#include <pcap.h>
#include <pcap/pcap.h>
#include "Public.h"

class ArpCheat {
public:
	static int __stdcall ArpCheatProc(pcap_t * param);

	static int FakeGateway(pcap_t* pcapt, unsigned int ip, unsigned char* mac);

	static int ArpCheat::VirtualProxy(pcap_t * pcapt, unsigned int ip, unsigned char* mac);

	static int ArpCheat::BroadcastARP(pcap_t * pcapt, unsigned int ip);

	static int EchoRARP(pcap_t* pcapt, unsigned int senederip, unsigned char* sendermac,
		unsigned int recverip, unsigned char* recvermac);

	//static int ArpCheat::adjustSelf(pcap_t * pcapt);

	//static int ArpCheat::sendRarp(pcap_t * pcapt, unsigned int ip, unsigned char mac[MAC_ADDRESS_SIZE]);

	//static int ArpCheat::refreshGatewayArpList(pcap_t * pcapt, unsigned int ip, unsigned char mac[MAC_ADDRESS_SIZE]);
};


#endif