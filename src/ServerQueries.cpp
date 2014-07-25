#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <stdio.h>
#include <iostream>
#include "Masterquery.h"
#include "Client2MasterProt.h"
#include "ServerQueries.h"

using boost::asio::ip::udp;
extern Client2MasterProt serverParam_q;
extern pthread_mutex_t muLog;


void ServerQueries::query_A2S_INFO(const char *ip,const char *port)
{
	try
	{
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port);
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		udp::socket socket(io_service);
		socket.open(udp::v4());
		
		char queryString[256];
		char logout[128];
		
		snprintf( queryString, 256, "\xFF\xFF\xFF\xFF\x54Source Engine Query%c", 0 );
		
		snprintf(logout, 128, "ServerQueries::query_A2S_INFO() querying '%s:%s' with string(hex-str): 'FF-FF-FF-FF-54-Source Engine Query'", ip, port);
		Log(logout,id_query.c_str());
		
		fd_set read_sockets;
		fd_set except_sockets;
		int rc;
		int natSocket = socket.native();
		struct timeval tv;
		bool packet_received = false;
		int i = 0;
		
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		int num_retry = serverParam_q.getn_retry();
		
		do
		{
			snprintf(logout, 128, "ServerQueries::query_A2S_INFO() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout,id_query.c_str());
			
			socket.send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::query_A2S_INFO() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
				tv.tv_usec=1;
				
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::query_A2S_INFO() There is an ERROR in select.",id_query.c_str());
					pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::query_A2S_INFO() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			i++;
		}
		while((!packet_received) && i <= num_retry);
		
		if(!packet_received)
		{
			Log("ServerQueries::query_A2S_INFO() Error: Packet not received.",id_query.c_str());
			pthread_exit(NULL);
		}
		
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_INFO() Reading packet...",id_query.c_str());
		
		// wait for reply
		size_t len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		
		servAddr gIp;
		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_INFO - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		/*gIp = */ParseMasterReply_A2S_INFO((unsigned char*)recv_buf.data(), len);
		snprintf(logout, 128, "------------------------------------------------------------", ip, port);
		Log(logout,id_query.c_str());
		
		Log("ServerQueries::query_A2S_INFO() parsed reply!",id_query.c_str());
		
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_INFO() exception raised: " << e.what() << std::endl;
	}
}

void ServerQueries::ParseMasterReply_A2S_INFO(const unsigned char* recvData, size_t len)
{
	char logout[128];
	int i=0;

	
	snprintf(logout, 128, "            Header1: %x-%x-%x-%x", (unsigned int)recvData[0], (unsigned int)recvData[1], (unsigned int)recvData[2],(unsigned int)recvData[3]);//Header 1
	Log(logout,id_query.c_str());
	//std::cout << "Header1: " << (unsigned int)recvData[0] << "-" << (unsigned int)recvData[1] << "-" << (unsigned int)recvData[2] << "-" << (unsigned int)recvData[3] << std::endl;

	snprintf(logout, 128, "            Header2: %x", (unsigned int)recvData[4]);//Header 2(byte)
	Log(logout,id_query.c_str());
	//std::cout << "Header2: " << (unsigned int)recvData[4] << std::endl; //Header (byte)
	
	snprintf(logout, 128, "           Procotol: %x", (unsigned int)recvData[5]);
	Log(logout,id_query.c_str());
	//std::cout << "Procotol: " << (unsigned int)recvData[5] << std::endl; //Procotol (byte)
	
	snprintf(logout, 128, "               Name: %s", (recvData + 6));
	Log(logout,id_query.c_str());
	//std::cout << "Name: " << (recvData + 6) << std::endl; //Name (string)
	
	for(i=6; i<len; i++)
	{
		if(recvData[i] == '\0')
		{
			break;
		}
	}
	
	snprintf(logout, 128, "                Map: %s", (recvData + ++i));
	Log(logout,id_query.c_str());
	//std::cout << "Map: " << (recvData + ++i) << std::endl; //Map (string)
	
	for(; i<len; i++)
	{
		if(recvData[i] == '\0')
		{
			break;
		}
	}
	
	snprintf(logout, 128, "             Folder: %s", (recvData + ++i));
	Log(logout,id_query.c_str());
	//std::cout << "Folder: " << (recvData + ++i) << std::endl; //Folder (string)
	
	for(; i<len; i++)
	{
		if(recvData[i] == '\0')
		{
			break;
		}
	}
	
	string game_temp;
	
	game_temp = (const char *)(recvData + ++i);
	
	snprintf(logout, 128, "               Game: %s", game_temp.c_str());
	Log(logout,id_query.c_str());
	////std::cout << "Game: " << (recvData + ++i) << std::endl; //Game (string)
	//std::cout << "Game: " << game_temp << std::endl; //Game (string)
	
	
	for(; i<len; i++)
	{
		if(recvData[i] == '\0')
		{
			break;
		}
	}
	snprintf(logout, 128, "                 ID: %d", (((unsigned int)recvData[++i]) << 8) | ((unsigned int)recvData[++i]));
	Log(logout,id_query.c_str());
	////std::cout << "ID: " << (unsigned int)recvData[++i] << "-" << (unsigned int)recvData[++i] << std::endl; //ID (short)
	//std::cout << "ID: " << ((((unsigned int)recvData[++i]) << 8) | ((unsigned int)recvData[++i])) << std::endl; //ID (short)
	
	snprintf(logout, 128, "            Players: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Players: " << (unsigned int)recvData[++i] << std::endl; //Players (byte)
	
	snprintf(logout, 128, "       Max. Players: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Max. Players: " << (unsigned int)recvData[++i] << std::endl; //Max. Players (byte)
	
	snprintf(logout, 128, "               Bots: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Bots: " << (unsigned int)recvData[++i] << std::endl; //Bots (byte)
	
	snprintf(logout, 128, "        Server type: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Server type: " << (unsigned int)recvData[++i] << std::endl; //Server type (byte)
	
	snprintf(logout, 128, "        Environment: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Environment: " << (unsigned int)recvData[++i] << std::endl; //Environment (byte)
	
	snprintf(logout, 128, "         Visibility: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Visibility: " << (unsigned int)recvData[++i] << std::endl; //Visibility (byte)
		
	snprintf(logout, 128, "                VAC: %x", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "VAC: " << (unsigned int)recvData[++i] << std::endl; //VAC (byte)
	
	if(game_temp == "The Ship")
	{
		snprintf(logout, 128, "     (The Ship)Mode: %x", (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "(The Ship)Mode: " << (unsigned int)recvData[++i] << std::endl; //Mode (byte)
		snprintf(logout, 128, "(The Ship)Witnesses: %x", (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "(The Ship)Witnesses: " << (unsigned int)recvData[++i] << std::endl; //Witnesses (byte)
		snprintf(logout, 128, " (The Ship)Duration: %x", (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "(The Ship)Duration: " << (unsigned int)recvData[++i] << std::endl; //Duration (byte)
	}
	
	snprintf(logout, 128, "            Version: %s", (recvData + i));
	Log(logout,id_query.c_str());
	//std::cout << "Version: " << (recvData + i) << std::endl; //Version (string)

	for(; i<len; i++)
	{
		if(recvData[i] == '\0')
		{
			break;
		}
	}

	unsigned char EDF_temp = recvData[++i];
	
	snprintf(logout, 128, "                EDF: %x", (unsigned int)EDF_temp);
	Log(logout,id_query.c_str());
	//std::cout << "EDF: " << (unsigned int)EDF_temp << std::endl; //EDF (byte)
		
	if ( EDF_temp & 0x80 )
	{
		snprintf(logout, 128, "       Port EDF0x80: %x", ((unsigned int)recvData[++i] << 8) | (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "Port EDF0x80: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //Port (short)
	}	
	
	if ( EDF_temp & 0x10 )
	{
		//snprintf(logout, 128, "SteamID EDF0x10: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i]);
		snprintf(logout, 128, "    SteamID EDF0x10: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[i+1],(unsigned int)recvData[i+2],(unsigned int)recvData[i+3],(unsigned int)recvData[i+4],(unsigned int)recvData[i+5],(unsigned int)recvData[i+6],(unsigned int)recvData[i+7],(unsigned int)recvData[i+8]);
		i += 8;
		Log(logout,id_query.c_str());
		//std::cout << "SteamID EDF0x10: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //SteamID (long long)
	}
	
	if ( EDF_temp & 0x40 )
	{
		snprintf(logout, 128, "       Port EDF0x40: %x", (((unsigned int)recvData[++i]) << 8) | ((unsigned int)recvData[++i]));
		Log(logout,id_query.c_str());
		//std::cout << "Port EDF0x40: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //Port (short)
		snprintf(logout, 128, "       Name EDF0x40: %s", (recvData + ++i));
		Log(logout,id_query.c_str());
		//std::cout << "Name EDF0x40: " << (recvData + ++i) << std::endl; //Name (string)
			
		for(; i<len; i++)
		{
			if(recvData[i] == '\0')
			{
				break;
			}
		}
	}
	
	if ( EDF_temp & 0x20 )
	{
		snprintf(logout, 128, "   Keywords EDF0x20: %s", (recvData + ++i));
		Log(logout,id_query.c_str());
		//std::cout << "Keywords EDF0x20: " << (recvData + ++i) << std::endl; //Keywords (string)
			
		for(; i<len; i++)
		{
			if(recvData[i] == '\0')
			{
				break;
			}
		}
	}
	
	if ( EDF_temp & 0x01 )
	{
		snprintf(logout, 128, "     GameID EDF0x01: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[i+1],(unsigned int)recvData[i+2],(unsigned int)recvData[i+3],(unsigned int)recvData[i+4],(unsigned int)recvData[i+5],(unsigned int)recvData[i+6],(unsigned int)recvData[i+7],(unsigned int)recvData[i+8]);
		i += 8;
		Log(logout,id_query.c_str());
		//std::cout << "GameID EDF0x01: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //GameID (long long)
	}
}

void ServerQueries::get_ChallengeN_A2S_PLAYER(udp::socket* socket,const char *ip,const char *port, unsigned char *challenge_number)
{
	try
	{
		char logout[128];
		char queryString[256];
		
		snprintf(logout, 128, "ServerQueries::get_ChallengeN_A2S_PLAYER() querying ");
		Log(logout,id_query.c_str());
		
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port );
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		fd_set read_sockets;
		fd_set except_sockets;
		int rc;
		int natSocket = socket->native();
		struct timeval tv;
		bool packet_received = false;
		int i = 0;
		
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		int num_retry = serverParam_q.getn_retry();
		
		snprintf(queryString, 256, "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF");
		
		do
		{
			snprintf(logout, 128, "ServerQueries::get_ChallengeN_A2S_PLAYER() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout,id_query.c_str());
		
			socket->send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
			   tv.tv_usec=1;
			   
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::get_ChallengeN_A2S_PLAYER() There is an ERROR in select.",id_query.c_str());
					pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			i++;
		}
		while((!packet_received) && i <= num_retry);
		
		if(!packet_received)
		{
			Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Error: Packet not received.",id_query.c_str());
			
			servAddr gIp_temp;
		
			gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;
		  
			pthread_exit(NULL);
		}
	
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		
		Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Reading packet...",id_query.c_str());
		size_t len = socket->receive_from(boost::asio::buffer(recv_buf), sender_endpoint);
		
		if( len == 9 )
		{
			challenge_number[0] = recv_buf[5];
			challenge_number[1] = recv_buf[6];
			challenge_number[2] = recv_buf[7];
			challenge_number[3] = recv_buf[8];
			
			snprintf(logout, 128, "ServerQueries::get_ChallengeN_A2S_PLAYER() Challenge Number received: %x-%x-%x-%x",challenge_number[0] ,challenge_number[1] ,challenge_number[2] ,challenge_number[3]);
			Log(logout,id_query.c_str());
		}
		else
		{
			Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Error in received packet: Len is not equal to 9",id_query.c_str());
		}
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_INFO() exception raised: " << e.what() << std::endl;
	}
}

void ServerQueries::query_A2S_PLAYER(const char *ip,const char *port)
{
	try
	{
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port);
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		udp::socket socket(io_service);
		socket.open(udp::v4());
		
		char queryString[256];
		char logout[128];
		unsigned char challenge_number[4];
		
		get_ChallengeN_A2S_PLAYER(&socket,ip,port,challenge_number);
		
		snprintf( queryString, 256, "\xFF\xFF\xFF\xFF\x55%c%c%c%c",challenge_number[0],challenge_number[1],challenge_number[2],challenge_number[3]);
		
		snprintf(logout, 128, "ServerQueries::query_A2S_PLAYER() querying '%s:%s' with string(hex): 'FF-FF-FF-FF-55-%x-%x-%x-%x'", ip, port,challenge_number[0],challenge_number[1],challenge_number[2],challenge_number[3]);
		Log(logout,id_query.c_str());
		
		fd_set read_sockets;
		fd_set except_sockets;
		int rc;
		int natSocket = socket.native();
		struct timeval tv;
		bool packet_received = false;
		int i = 0;
		
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		int num_retry = serverParam_q.getn_retry();
		
		do
		{
			snprintf(logout, 128, "ServerQueries::query_A2S_PLAYER() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout,id_query.c_str());
			
			socket.send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::query_A2S_PLAYER() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
				tv.tv_usec=1;
				
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::query_A2S_PLAYER() There is an ERROR in select.",id_query.c_str());
					pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::query_A2S_PLAYER() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			i++;
		}
		while((!packet_received) && i <= num_retry);
		
		if(!packet_received)
		{
			Log("ServerQueries::query_A2S_PLAYER() Error: Packet not received.",id_query.c_str());
			pthread_exit(NULL);
		}
		
		
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_PLAYER() Reading packet...",id_query.c_str());
		
		// wait for reply
		size_t len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		
		
		servAddr gIp;
		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_PLAYER - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		/*gIp = */ParseMasterReply_A2S_PLAYER((unsigned char*)recv_buf.data(), len);
		snprintf(logout, 128, "------------------------------------------------------------", ip, port);
		Log(logout,id_query.c_str());
		
		Log("ServerQueries::query_A2S_PLAYER() parsed reply!",id_query.c_str());
		
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_PLAYER() exception raised: " << e.what() << std::endl;
	}
}

void ServerQueries::ParseMasterReply_A2S_PLAYER(const unsigned char* recvData, size_t len)
{
	char logout[128];
	int j = 6;
	snprintf(logout, 128, "            Header1: %x-%x-%x-%x", (unsigned int)recvData[0], (unsigned int)recvData[1], (unsigned int)recvData[2],(unsigned int)recvData[3]);//Header 1
	Log(logout,id_query.c_str());
	
	snprintf(logout, 128, "            Header2: %x", (unsigned int)recvData[4]);//Header 2
	Log(logout,id_query.c_str());
	
	snprintf(logout, 128, "            Players: %x", (unsigned int)recvData[5]);//Players
	Log(logout,id_query.c_str());
	
	for(unsigned int i=0; i<recvData[5]; i++)
	{
		snprintf(logout, 128, "            Index: %x", (unsigned int)recvData[j++]);//Index
		Log(logout,id_query.c_str());
		
		snprintf(logout, 128, "            Name: %s", recvData + j);//Players
		Log(logout,id_query.c_str());

		for(; j<len; j++)
		{
			if(recvData[j] == '\0')
			{
				break;
			}
		}

		snprintf(logout, 128, "            Score: %x-%x-%x-%x", (unsigned int)recvData[j+1], (unsigned int)recvData[j+2], (unsigned int)recvData[j+3],(unsigned int)recvData[j+4]);//Header 1
		Log(logout,id_query.c_str());
		
		j += 4;
		
		snprintf(logout, 128, "            Duration: %x-%x-%x-%x", (unsigned int)recvData[j+1], (unsigned int)recvData[j+2], (unsigned int)recvData[j+3],(unsigned int)recvData[j+4]);//Header 1
		Log(logout,id_query.c_str());
		
		j += 4;
	}
}

void ServerQueries::query_A2S_RULES(const char *ip,const char *port)
{
	try
	{
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port);
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		udp::socket socket(io_service);
		socket.open(udp::v4());
		
		char queryString[256];
		char logout[128];
		unsigned char challenge_number[4];
		size_t len;
		
		boost::array<char, 5120> recv_buf_challenge;
		len = get_ChallengeN_A2S_RULES(&socket,ip,port,&recv_buf_challenge);
		
		if(recv_buf_challenge[4] == 0x45)
		{
			//The server has bypassed the challenge number
			Log("The server has bypassed the challenge number",id_query.c_str());
			snprintf(logout, 128, "---------- A2S_RULES - Reply from %s:%s -------", ip, port);
			Log(logout,id_query.c_str());
			ParseMasterReply_A2S_RULES((unsigned char*)recv_buf_challenge.data(), len);
			snprintf(logout, 128, "------------------------------------------------------------", ip, port);
			Log(logout,id_query.c_str());
			
			Log("ServerQueries::query_A2S_RULES() parsed reply!",id_query.c_str());
			return;
		}
		else//if(recv_buf[4] == 0x41)
		{
			challenge_number[0] = recv_buf_challenge[5];
			challenge_number[1] = recv_buf_challenge[6];
			challenge_number[2] = recv_buf_challenge[7];
			challenge_number[3] = recv_buf_challenge[8];
		}
		
		snprintf( queryString, 256, "\xFF\xFF\xFF\xFF\x56%c%c%c%c",challenge_number[0],challenge_number[1],challenge_number[2],challenge_number[3]);
		
		snprintf(logout, 128, "ServerQueries::query_A2S_RULES() querying '%s:%s' with string(hex): 'FF-FF-FF-FF-56-%x-%x-%x-%x'", ip, port,challenge_number[0],challenge_number[1],challenge_number[2],challenge_number[3]);
		Log(logout,id_query.c_str());
		
		fd_set read_sockets;
		fd_set except_sockets;
		int rc;
		int natSocket = socket.native();
		struct timeval tv;
		bool packet_received = false;
		int i = 0;
		
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		int num_retry = serverParam_q.getn_retry();
		
		do
		{
			snprintf(logout, 128, "ServerQueries::query_A2S_RULES() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout,id_query.c_str());
			
			socket.send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::query_A2S_RULES() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
				tv.tv_usec=1;
				
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::query_A2S_RULES() There is an ERROR in select.",id_query.c_str());
					pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::query_A2S_RULES() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			i++;
		}
		while((!packet_received) && i <= num_retry);
		
		if(!packet_received)
		{
			Log("ServerQueries::query_A2S_RULES() Error: Packet not received.",id_query.c_str());
			pthread_exit(NULL);
		}
		
		
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_RULES() Reading packet...",id_query.c_str());
		
		// wait for reply
		len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		
		servAddr gIp;
		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_RULES - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		/*gIp = */ParseMasterReply_A2S_RULES((unsigned char*)recv_buf.data(), len);
		snprintf(logout, 128, "------------------------------------------------------------", ip, port);
		Log(logout,id_query.c_str());
		
		Log("ServerQueries::query_A2S_RULES() parsed reply!",id_query.c_str());

	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_RULES() exception raised: " << e.what() << std::endl;
	}
}

void ServerQueries::ParseMasterReply_A2S_RULES(const unsigned char* recvData, size_t len)
{
	char logout[128];
	int j = 7;
	unsigned int rules;
	snprintf(logout, 128, "            Header1: %x-%x-%x-%x", (unsigned int)recvData[0], (unsigned int)recvData[1], (unsigned int)recvData[2],(unsigned int)recvData[3]);//Header 1
	Log(logout,id_query.c_str());
	
	snprintf(logout, 128, "            Header2: %x", (unsigned int)recvData[4]);//Header 2
	Log(logout,id_query.c_str());
	
	//rules = ((unsigned int)recvData[5] << 8) | (unsigned int)recvData[6];
	rules = ((unsigned int)recvData[5]) | ((unsigned int)recvData[6] << 8);
	
	snprintf(logout, 128, "            Rules: %x", rules);//Rules
	Log(logout,id_query.c_str());
	
	for(unsigned int i=0; i<rules; i++)
	{		
		snprintf(logout, 128, "            Name: %s", recvData + j);//Players
		Log(logout,id_query.c_str());

		for(; j<len; j++)
		{
			if(recvData[j] == '\0')
			{
				j++;
				break;
			}
		}

		snprintf(logout, 128, "            Value: %s", recvData + j);//Players
		Log(logout,id_query.c_str());

		for(; j<len; j++)
		{
			if(recvData[j] == '\0')
			{
				j++;
				break;
			}
		}
	}
}

size_t ServerQueries::get_ChallengeN_A2S_RULES(udp::socket* socket,const char *ip,const char *port, boost::array<char, 5120> *recv_buf_challenge)
{
	try
	{
		char logout[128];
		char queryString[256];
		
		snprintf(logout, 128, "ServerQueries::get_ChallengeN_A2S_RULES() querying ");
		Log(logout,id_query.c_str());
		
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port );
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		fd_set read_sockets;
		fd_set except_sockets;
		int rc;
		int natSocket = socket->native();
		struct timeval tv;
		bool packet_received = false;
		int i = 0;
		
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		int num_retry = serverParam_q.getn_retry();
		
		snprintf(queryString, 256, "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF");
		
		do
		{
			snprintf(logout, 128, "ServerQueries::get_ChallengeN_A2S_RULES() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout,id_query.c_str());
		
			socket->send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::get_ChallengeN_A2S_RULES() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
			   tv.tv_usec=1;
			   
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::get_ChallengeN_A2S_RULES() There is an ERROR in select.",id_query.c_str());
					pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::get_ChallengeN_A2S_RULES() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			i++;
		}
		while((!packet_received) && i <= num_retry);
		
		if(!packet_received)
		{
			Log("ServerQueries::get_ChallengeN_A2S_RULES() Error: Packet not received.",id_query.c_str());
			
			servAddr gIp_temp;
		
			gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;
		  
		  	pthread_exit(NULL);
		}
	
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		
		Log("ServerQueries::get_ChallengeN_A2S_RULES() Reading packet...",id_query.c_str());

		size_t len = socket->receive_from(boost::asio::buffer(*recv_buf_challenge), sender_endpoint);
		
		if( len != 9 )
		{
			Log("ServerQueries::get_ChallengeN_A2S_RULES() Error in received packet: Len is not equal to 9",id_query.c_str());
		}
		return len;
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_INFO() exception raised: " << e.what() << std::endl;
	}
}


typedef unsigned char byte;

struct A2S_INFO_response
{
	unsigned char Header;
	unsigned char Protocol;
	string Name;
	string Map;
	string Folder;
	string Game;
	short ID;
	unsigned char Players;
	unsigned char Max_Players;
	unsigned char Bots;
	unsigned char Server_Type;
	unsigned char Environment;
	unsigned char Visibility;
	unsigned char VAC;
	
	unsigned char IfShip_Mode; // If ship
	unsigned char IfShip_Witnesses; // If ship
	unsigned char IfShip_Duration; // If ship
	
	string Version;
	unsigned char ExtraDataFlag;
	
	short EDF80_Port; //Only if if ( EDF & 0x80 ) proves true:
	
	long long EDF10_SteamID; //Only if if ( EDF & 0x10 ) proves true:
	
	short EDF40_Port; //Only if if ( EDF & 0x40 ) proves true:
	string EDF40_Name; //Only if if ( EDF & 0x40 ) proves true:
	
	string EDF20_Keywords;// Only if if ( EDF & 0x20 ) proves true:
	
	long long EDF01_GameID; //Only if if ( EDF & 0x01 ) proves true:
};

struct A2S_INFO_request
{
	byte Header;// = 0x54;
	string Payload;// = "Source Engine Query";

};
