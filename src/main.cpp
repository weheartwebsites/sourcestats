#include <iostream>
#include "Client2MasterProt.h"
#include "Masterquery.h"

using namespace std;

static MasterserverManager* gMasterManager = MasterserverManager::getInstance();
	
pthread_mutex_t muLog;
pthread_mutex_t muCounts;
Client2MasterProt serverParam_q;


int main(int argc, char *argv[])
{
	serverParam_q.set(argc,argv);
	
	pthread_mutex_init(&muLog, NULL);
	pthread_mutex_init(&muCounts, NULL);
	
	
	serverParam_q.AddServers(*gMasterManager);
	
	Masterquery pQuery;
	
	pQuery.SetGame( serverParam_q.getfilter() );
	
	pQuery.SetMaster( serverParam_q.getservAddr() );
	
	pQuery.EntryPoint();
	
	pthread_exit(NULL);
}
