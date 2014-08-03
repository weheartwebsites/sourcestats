#ifndef SERVERQUERIES_H
#define SERVERQUERIES_H

#include <string>
#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
//#include "GameserverEntry.h"

class ServerQueries : public DebugLog
{
public:
	void query_A2S_INFO(const char *ip,const char *port);
	void query_A2S_PLAYER(const char *ip,const char *port);
	void query_A2S_RULES(const char *ip,const char *port);
	
	void ParseMasterReply_A2S_INFO(const unsigned char* recvData, size_t len);
	void ParseMasterReply_A2S_PLAYER(const unsigned char* recvData, size_t len);
	void ParseMasterReply_A2S_RULES(const unsigned char* recvData, size_t len);
	
	void get_ChallengeN_A2S_PLAYER(boost::asio::ip::udp::socket* socket,const char *ip,const char *port, unsigned char *challenge_number);
	size_t get_ChallengeN_A2S_RULES(boost::asio::ip::udp::socket* socket,const char *ip,const char *port, boost::array<unsigned char, 5120> *recv_buf_challenge);
	
	size_t SrcSrv_SplitResponse(boost::asio::ip::udp::socket* socket,boost::array<unsigned char, 5120> *rcv_buffer,size_t rcv_len);
	
	void set_id_query(const char *param){id_query = param;}
	const char *get_id_query(){return id_query.c_str();}
	
	
private:
	string id_query;
};

#endif // SERVERQUERIES_H
