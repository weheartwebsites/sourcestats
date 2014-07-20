#ifndef CLIENT2MASTERPROT_H
#define CLIENT2MASTERPROT_H

#include <string>
#include "DebugLog.h"
#include "MasterserverManager.h"

using namespace std;

class Client2MasterProt: public DebugLog
{
private:
	bool verbose_m;
	
	string Hostname_server;
	unsigned char region;
	string Port;
	string filter;
	
	int timeoutSeconds;
	int n_retry;
public:
	Client2MasterProt();
	void set(int argc, char *argv[]);
	
	const char * getHostname_server(){return Hostname_server.c_str();}
	unsigned char getregion(){return region;}
	const char * getPort(){return Port.c_str();}
	const char * getfilter(){return filter.c_str();}
	bool getVerbose_m(){return verbose_m;}
	
	int gettimeoutSeconds(){return timeoutSeconds;}
	int getn_retry(){return n_retry;}
	
	void AddServers(MasterserverManager &);
	int Region_str2int(string);
	//~Client2MasterProt();
};

#endif // CLIENT2MASTERPROT_H
