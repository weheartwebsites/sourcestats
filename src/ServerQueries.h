#ifndef SERVERQUERIES_H
#define SERVERQUERIES_H

#include <string>
#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "GameserverEntry.h"
#include "ThreadedRequest.h"
#include "SourceStats.h"

//const int MAX_RCV_BUFF = 5120;
// this class is responsible for getting all servers for the given game
//class Masterquery : public ThreadedRequest
class ServerQueries : public DebugLog
{
public:
	//Masterquery( ThreadFactory* );
	//~Masterquery();
	void query_A2S_INFO(const char *ip,const char *port);
	void query_A2S_PLAYER(const char *ip,const char *port);
	void query_A2S_RULES(const char *ip,const char *port);
	
	void ParseMasterReply_A2S_INFO(const unsigned char* recvData, size_t len);
	void ParseMasterReply_A2S_PLAYER(const unsigned char* recvData, size_t len);
	void ParseMasterReply_A2S_RULES(const unsigned char* recvData, size_t len);
	
	void get_ChallengeN_A2S_PLAYER(boost::asio::ip::udp::socket* socket,const char *ip,const char *port, unsigned char *challenge_number);
	//void get_ChallengeN_A2S_RULES(boost::asio::ip::udp::socket* socket,const char *ip,const char *port, unsigned char *challenge_number);
	size_t get_ChallengeN_A2S_RULES(boost::asio::ip::udp::socket* socket,const char *ip,const char *port, boost::array<char, 5120> *recv_buf_challenge);
	
	size_t SrcSrv_SplitResponse(boost::asio::ip::udp::socket* socket,boost::array<char, 5120> *rcv_buffer,size_t rcv_len);
	
	void set_id_query(const char *param){id_query = param;}
	const char *get_id_query(){return id_query.c_str();}
	
	
private:
	string id_query;
	
	/*void				SetMaster( servAddr );
	void				SetGame( const char* );
	void				EntryPoint( void );
	void				Query( void );
	void				AddEntry( GameserverEntry* );
	mqQuery_state		GetState( void ) { return m_iState; }
	void				ResetIterator( void );
	GameserverEntry*	GetNextServer( void );
    void                Exec( void );
	const char*			GetClassName( void ) { return "Masterquery"; }

    virtual void        Log( const char* logMsg );
	virtual bool		IsMasterquery( void ) { return true; }

protected:
	servAddr			RequestMore( boost::asio::ip::udp::socket* socket, servAddr gIp );
	servAddr			ParseMasterReply( const char* recvData, size_t len );

private:
	void				GetMasterIpString( char* );
	void				GetMasterPortString( char* );
	void				Finished( void );

	char				gameName[128];
	servAddr			masterAddr;
	mqQuery_state		m_iState;

	std::vector <GameserverEntry*>			m_vResultlist;
	std::vector <GameserverEntry*>::iterator m_geIT;*/
};

#endif // SERVERQUERIES_H
