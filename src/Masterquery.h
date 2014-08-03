#ifndef MASTERQUERY_H
#define MASTERQUERY_H

#include <string>
#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "DebugLog.h"

// this class is responsible for getting all servers for the given game
class Masterquery : public DebugLog
{
public:
	Masterquery();
	~Masterquery();
	
	void				SetMaster( servAddr );
	void				SetGame( const char* );
	void				EntryPoint( void );
	void				Query( void );
	//void				AddEntry( GameserverEntry* );
	void				AddEntry( servAddr* );
	
	mqQuery_state		GetState( void ) { return m_iState; }
	void                Exec( void );
	const char*			GetClassName( void ) { return "Masterquery"; }
	
	static void*	ThreadServerQueries( void *arg );
	
	static void    IncreaseOneThread();
	static void    DecreaseOneThread();
	static int     GetNumberThreads();
	
	virtual void        Log( const char* logMsg );
	virtual bool		IsMasterquery( void ) { return true; }

protected:
	servAddr			RequestMore( boost::asio::ip::udp::socket* socket, servAddr gIp );
	servAddr			ParseMasterReply( const char* recvData, size_t len );

private:
	void				GetMasterIpString( char* );
	void				GetMasterPortString( char* );

	char				gameName[128];
	servAddr			masterAddr;
	mqQuery_state		m_iState;

	//std::vector <GameserverEntry*>			m_vResultlist;
	std::vector <servAddr*>			m_vResultlist;
	static int nActiveThreads;
};

#endif // MASTERQUERY_H
