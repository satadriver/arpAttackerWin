#pragma once

#include <pcap.h>
#include <pcap\\pcap.h>

#include <iostream>
#include <string>
#include <windows.h>

using namespace std;

class Winpcap {
public:
	static pcap_t * init(string devname,int speed);
};