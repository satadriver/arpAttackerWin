

#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include "connectionManager.h"
#include "Public.h"


using namespace std;
using namespace std::tr1;

unordered_map <string, CLIENTADDRESSES> mapHijack;







int ConnectionManager::put(unsigned int clientip,unsigned short clientport,unsigned int serverip,unsigned short serverport,
	unsigned int protocol,CLIENTADDRESSES ca) {
	char szkey[256];
	string mapKeyFormat = "%x_%x_%x_%x_%x";
	wsprintfA(szkey, mapKeyFormat.c_str(), clientip, clientport, serverip, serverport,protocol);
	unordered_map <string, CLIENTADDRESSES>::iterator mapHijackIt = mapHijack.find(szkey);
	if (mapHijackIt == mapHijack.end()) {
		mapHijack.insert(unordered_map<string, CLIENTADDRESSES>::value_type(string(szkey), ca));
		return 0;
	}

	return -1;
}



CLIENTADDRESSES ConnectionManager::get( unsigned short clientport, unsigned int serverip, unsigned short serverport,unsigned int protocol ) {
	for (unsigned int i = 0; i < gAttackTargetIP.size();i ++)
	{
		unsigned int ip = gAttackTargetIP[i].clientIP;
		char szkey[256];
		string mapKeyFormat = "%x_%x_%x_%x_%x";
		wsprintfA(szkey, mapKeyFormat.c_str(), ip, clientport, serverip, serverport,protocol);
		unordered_map <string, CLIENTADDRESSES>::iterator mapHijackIt = mapHijack.find(szkey);
		if (mapHijackIt != mapHijack.end())
		{
			return mapHijackIt->second;
		}
	}

	CLIENTADDRESSES ca = { 0 };
	return ca;
}



unsigned int ConnectionManager::getSubnet(unsigned int ip) {
	return gNetMaskIP;
}


int ConnectionManager::getSubnetSize() {
	return ntohl(~gNetMask) + 1;
}


int __stdcall ConnectionManager::clearmap() {

	try {
		while (1) {
			time_t now = time(0);
			unordered_map <string, CLIENTADDRESSES>::iterator it;
			for (it = mapHijack.begin(); it != mapHijack.end(); ) {
				if (now - it->second.time > MAP_CLEAR_WAITSECONDS) {
					//delete it->second;
					mapHijack.erase(it++);
					continue;
				}
				else {
					it++;
				}
			}

			Sleep(MAP_CLEAR_WAITSECONDS);
		}
	}
	catch (const std::exception& e) {
		printf("%s exception:%s\r\n",__FUNCTION__, e.what());
	}
	return 0;
}