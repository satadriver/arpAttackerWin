#pragma once

#ifndef CLIENTADDRESS_H
#define CLIENTADDRESS_H


#include <vector>
#include "Public.h"




class  ClientAddress{
public:
	static int GetMACFromIP(unsigned int ip,unsigned char mac[]);
	static unsigned char* ClientAddress::isTarget(unsigned int ip);
	static unsigned int ClientAddress::isTarget(unsigned char mac[MAC_ADDRESS_SIZE]);
};


#endif