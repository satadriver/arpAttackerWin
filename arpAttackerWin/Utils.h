
#ifndef UTILS_H_H_H
#define UTILS_H_H_H

#include <windows.h>

#include "Public.h"	
#include <iostream>
#include <string>




class Utils {
public:
	static int removespace(char * src, char * dst);
	static DWORD GetSubNet(char * szIP, char * szSubNet);

	static DWORD GetLocalIPAddress();
	static DWORD WriteLogFile(char * pFileName, char * pData);
	static int RecordInFile(char * szFileName, unsigned char * strBuffer, int iCounter);

	static string formatIP(unsigned int);
	static string formatMAC(unsigned char mac[MAC_ADDRESS_SIZE]);
};

#endif