#ifndef MASTERSERVERMANAGER_H
#define MASTERSERVERMANAGER_H

#include <vector>
//#include "Masterserver.h"
#include <pthread.h>
#include "const.h"

class MasterserverManager
{
private:
	MasterserverManager() { pthread_mutex_init(&m_masterMutex, NULL); };
	MasterserverManager( const MasterserverManager& cc );
	~MasterserverManager() { };

	static MasterserverManager* gMasterserverManager;

	//std::vector <Masterserver*> m_vMasterserverList;
	std::vector <servAddr*> m_vMasterserverList;
	//servAddr m_stServaddr;
	
	pthread_mutex_t					m_masterMutex;

public:
	static MasterserverManager* getInstance();
	static void Destroy();

	//void				AddServer( Masterserver* mServer );
	void				AddServer( servAddr* mServer );
	
	void				AddServer( const char* sServerstring );
	servAddr			GetServerAdress( void );
};

#endif // MASTERSERVERMANAGER_H
