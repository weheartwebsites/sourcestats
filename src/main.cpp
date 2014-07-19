#include <iostream>
#include "Client2MasterProt.h"
#include "SourceStats.h"

using namespace std;

static SourceStats* gSourceStats = SourceStats::getInstance();
pthread_mutex_t muLog;
Client2MasterProt serverParam_q;

int main(int argc, char *argv[])
{
	serverParam_q.set(argc,argv);
	
	pthread_mutex_init(&muLog, NULL);
	
	gSourceStats->Init();
	gSourceStats->Loop();
}
