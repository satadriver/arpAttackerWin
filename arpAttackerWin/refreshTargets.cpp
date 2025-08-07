
#define WIN32_LEAN_AND_MEAN  // 减少不必要的头文件
#include <winsock2.h>
#include <windows.h>

#include "refreshTargets.h"


#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include "Public.h"
#include "snifferTargets.h"


int RefreshTargets::refreshTargets(void * param) {
	pcap_t * pcapt = (pcap_t*)param;

	while (TRUE)
	{
		gTotalObjects.clear();
		int ret = SnifferTargets::GetTarget(pcapt, gTotalObjects);
		Sleep(REFRESHTARGETS_DELAY);
	}

}