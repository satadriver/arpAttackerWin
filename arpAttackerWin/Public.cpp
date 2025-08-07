
#include "Public.h"

#include <vector>

using namespace std;

unsigned int gGatewayIP;

unsigned char gGatewayMAC[MAC_ADDRESS_SIZE];

unsigned int gLocalIP;

unsigned char gLocalMAC[MAC_ADDRESS_SIZE];

unsigned int gNetMask;

unsigned int gNetMaskIP;

vector <CLIENTADDRESSES> gAttackTargetIP;

vector <CLIENTADDRESSES> gTotalObjects;

unsigned int gVirtualProxyIP = 0;

char gDevName[MAX_PATH] = { 0 };

int gNetcardIndex = 0;

int gCapSpeed = 1;

int gArpDelay = 30000;

string gCardName = "";

int gMode = 0;