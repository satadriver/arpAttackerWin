#pragma once

#include <vector>
#include <iostream>
#include <string>
#include "ClientAddress.h"
#include "Public.h"



class SnifferTargets {
public:

	static int SnifferTargets::GetTarget(void * param,vector <CLIENTADDRESSES> &target);
};