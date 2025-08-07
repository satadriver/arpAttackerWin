#pragma once

#include "ClientAddress.h"
#include "Public.h"
#include <vector>
#include <iostream>
#include <string>



class VirtualIP {
public:
	static unsigned int GetVirtualIP(void * param, vector <CLIENTADDRESSES> &targets);

};
