#pragma once


#ifndef CONNECTIONMANAGER_H_H_H
#define CONNECTIONMANAGER_H_H_H

#include <iostream>
#include <string>
#include <map>

#include <unordered_map>  
#include "Public.h"
#include "ClientAddress.h"
#include "ArpCheat.h"








class ConnectionManager {
public:
	static int getSubnetSize();
	static unsigned int getSubnet(unsigned int ip);
	static int put(unsigned int clientip, unsigned short clientport, unsigned int serverip, unsigned short serverport, 
		unsigned int protocol, CLIENTADDRESSES ca);
	static CLIENTADDRESSES get(unsigned short clientport, unsigned int serverip, unsigned short serverport, unsigned int protocol);
	static int __stdcall ConnectionManager::clearmap();
};

#endif