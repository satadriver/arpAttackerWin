#pragma once

#ifndef CONFIG_H_H_H
#define CONFIG_H_H_H
#include <string>

#include <vector>
#include "Public.h"



class Config {
public:
	static int getAttackTarget(string fn, vector<CLIENTADDRESSES> &targets,int * speed,int*arpdelay,int *mode);

	static int Config::getAttackTargetFromCmd(char * buf, vector<CLIENTADDRESSES> & targets, int * speed, int * arprepeat);

	static int addTarget(unsigned int ip,vector <CLIENTADDRESSES>& list);

	static int Config::addTarget(vector<CLIENTADDRESSES> & targets, unsigned int recverip, 
		unsigned char *mac);
};


#endif