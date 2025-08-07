

#include "virtualIP.h"
#include "snifferTargets.h"
#include "connectionManager.h"
#include <iostream>
#include <string>
#include <vector>
#include "Utils.h"
#include <algorithm>



using namespace std;

unsigned int VirtualIP::GetVirtualIP(void * param, vector <CLIENTADDRESSES> &targets) {

	unsigned int virtualIP = 0;
	int ret = SnifferTargets::GetTarget(param, targets);
	if (targets.size() <=0 )
	{
		printf("Not found target,please rescan\r\n");
		return 0;
	}

	//sort(gOnlineObjects.begin(), gOnlineObjects.end());
	//gOnlineObjects.erase(unique(gOnlineObjects.begin(), gOnlineObjects.end()), gOnlineObjects.end());

	int cnt = ConnectionManager::getSubnetSize();
	for (int i = 0; i < cnt; i++) {
		unsigned int ip = ntohl(ntohl(gNetMaskIP) + i);

		if (i == 0xff || ip == gLocalIP || ip == gNetMaskIP || ip == gGatewayIP) {
			continue;
		}	
		unsigned int j = 0;
		for (j = 0;j < targets.size(); j ++)
		{
			if (ip == targets[j].clientIP)
			{
				break;
			}
		}

		if (j >= targets.size())
		{
			virtualIP = ip;
			break;
		}
	}

	if (virtualIP)
	{
		string strip = Utils::formatIP(virtualIP);
		printf("get proxy client ip:%s\r\n", strip.c_str());
	}
	else {
		printf("find proxy client ip error\r\n");
		
	}

	return virtualIP;
	
}