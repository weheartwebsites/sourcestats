#ifndef CLIENT2MASTERPROT_H
#define CLIENT2MASTERPROT_H

#include <string>
#include "DebugLog.h"

using namespace std;

class Client2MasterProt: public DebugLog
{
private:
	bool verbose_m;
	string IpPort_server;
	
	unsigned char region;
	string IpPort;
	string filter;
public:
	Client2MasterProt();
	void set(int argc, char *argv[]);
	
	const char * getIpPort_server(){return IpPort_server.c_str();}
	unsigned char getregion(){return region;}
	const char * getIpPort(){return IpPort.c_str();}
	const char * getfilter(){return filter.c_str();}
	bool getVerbose_m(){return verbose_m;}
	//~Client2MasterProt();
};

#endif // CLIENT2MASTERPROT_H
