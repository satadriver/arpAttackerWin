#pragma once

#include "Public.h"

BOOL IsRunningInWOW64();

class StaticGateway {
public:
	static int StaticGateway::bindStaticGatewayMac( int index,unsigned int gateip, unsigned char gatemac[MAC_ADDRESS_SIZE]);

	static string StaticGateway::getAdapterAlias(string adaptername);

	static int StaticGateway::freeStaticGatewayMac(int index);
};