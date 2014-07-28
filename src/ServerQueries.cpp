#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <stdio.h>
#include <iostream>
#include "Masterquery.h"
#include "Client2MasterProt.h"
#include "ServerQueries.h"
//#include "bzlib.h"

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
		
		//boost::array<char, 5120> recv_buf;
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_INFO() Reading packet...",id_query.c_str());
		
		// wait for reply
		size_t len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		if(recv_buf[0] == 0xFE && recv_buf[1] == 0xFF && recv_buf[2] == 0xFF && recv_buf[3] == 0xFF)//Packet is split
		{
			Log("ServerQueries::query_A2S_INFO() The response is split.",id_query.c_str());
			
			len = SrcSrv_SplitResponse(&socket,&recv_buf, len);
			if ( len == -1 )
			{
				Log("ServerQueries::query_A2S_INFO() Error in the split response.",id_query.c_str());
				pthread_exit(NULL);
			}
		}
		
		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_INFO - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		ParseMasterReply_A2S_INFO((unsigned char*)recv_buf.data(), len);
		Log("------------------------------------------------------------",id_query.c_str());
		
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

	snprintf(logout, 128, "            Header2: %c", recvData[4]);//Header 2(byte)
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
	snprintf(logout, 128, "                 ID: %d", ((unsigned int)recvData[++i]) | (((unsigned int)recvData[++i]) << 8));
	Log(logout,id_query.c_str());
	////std::cout << "ID: " << (unsigned int)recvData[++i] << "-" << (unsigned int)recvData[++i] << std::endl; //ID (short)
	//std::cout << "ID: " << ((((unsigned int)recvData[++i]) << 8) | ((unsigned int)recvData[++i])) << std::endl; //ID (short)
	
	snprintf(logout, 128, "            Players: %u", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Players: " << (unsigned int)recvData[++i] << std::endl; //Players (byte)
	
	snprintf(logout, 128, "       Max. Players: %u", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Max. Players: " << (unsigned int)recvData[++i] << std::endl; //Max. Players (byte)
	
	snprintf(logout, 128, "               Bots: %u", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Bots: " << (unsigned int)recvData[++i] << std::endl; //Bots (byte)
	
	snprintf(logout, 128, "        Server type: %c", recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Server type: " << (unsigned int)recvData[++i] << std::endl; //Server type (byte)
	
	snprintf(logout, 128, "        Environment: %c", recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Environment: " << (unsigned int)recvData[++i] << std::endl; //Environment (byte)
	
	snprintf(logout, 128, "         Visibility: %u", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "Visibility: " << (unsigned int)recvData[++i] << std::endl; //Visibility (byte)
		
	snprintf(logout, 128, "                VAC: %u", (unsigned int)recvData[++i]);
	Log(logout,id_query.c_str());
	//std::cout << "VAC: " << (unsigned int)recvData[++i] << std::endl; //VAC (byte)
	
	if(game_temp == "The Ship")
	{
		snprintf(logout, 128, "     (The Ship)Mode: %u", (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "(The Ship)Mode: " << (unsigned int)recvData[++i] << std::endl; //Mode (byte)
		snprintf(logout, 128, "(The Ship)Witnesses: %u", (unsigned int)recvData[++i]);
		Log(logout,id_query.c_str());
		//std::cout << "(The Ship)Witnesses: " << (unsigned int)recvData[++i] << std::endl; //Witnesses (byte)
		snprintf(logout, 128, " (The Ship)Duration: %u", (unsigned int)recvData[++i]);
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
	
	snprintf(logout, 128, "                EDF: %u", (unsigned int)EDF_temp);
	Log(logout,id_query.c_str());
	//std::cout << "EDF: " << (unsigned int)EDF_temp << std::endl; //EDF (byte)
		
	if ( EDF_temp & 0x80 )
	{
		snprintf(logout, 128, "       Port EDF0x80: %u", ((unsigned int)recvData[++i]) | (((unsigned int)recvData[++i]) << 8));
		Log(logout,id_query.c_str());
		//std::cout << "Port EDF0x80: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //Port (short)
	}	
	
	if ( EDF_temp & 0x10 )
	{
		//snprintf(logout, 128, "SteamID EDF0x10: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i],(unsigned int)recvData[++i]);
		//snprintf(logout, 128, "    SteamID EDF0x10: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[i+1],(unsigned int)recvData[i+2],(unsigned int)recvData[i+3],(unsigned int)recvData[i+4],(unsigned int)recvData[i+5],(unsigned int)recvData[i+6],(unsigned int)recvData[i+7],(unsigned int)recvData[i+8]);
		snprintf(logout, 128, "    SteamID EDF0x10: %lld",(long long)recvData[i+1] | (long long)recvData[i+2] << 8 | (long long)recvData[i+3] << 16 | (long long)recvData[i+4] << 24 | (long long)recvData[i+5] << 32 | (long long)recvData[i+6] << 40 | (long long)recvData[i+7] << 48 | (long long)recvData[i+8] << 56);
		i += 8;
		Log(logout,id_query.c_str());
		//std::cout << "SteamID EDF0x10: " << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i] << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i]  << "-"; std::cout << (unsigned int)recvData[++i] << std::endl; //SteamID (long long)
	}
	
	if ( EDF_temp & 0x40 )
	{
		snprintf(logout, 128, "       Port EDF0x40: %u", ((unsigned int)recvData[++i]) | (((unsigned int)recvData[++i]) << 8));
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
		//snprintf(logout, 128, "     GameID EDF0x01: %x-%x-%x-%x-%x-%x-%x-%x",(unsigned int)recvData[i+1],(unsigned int)recvData[i+2],(unsigned int)recvData[i+3],(unsigned int)recvData[i+4],(unsigned int)recvData[i+5],(unsigned int)recvData[i+6],(unsigned int)recvData[i+7],(unsigned int)recvData[i+8]);
		snprintf(logout, 128, "     GameID EDF0x01: %lld",(long long)recvData[i+1] | (long long)recvData[i+2] << 8 | (long long)recvData[i+3] << 16 | (long long)recvData[i+4] << 24 | (long long)recvData[i+5] << 32 | (long long)recvData[i+6] << 40 | (long long)recvData[i+7] << 48 | (long long)recvData[i+8] << 56);
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
			
			/*servAddr gIp_temp;
		
			gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;*/
		  
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
			Log("ServerQueries::get_ChallengeN_A2S_PLAYER() Warning: Packet receive's length is not equal to 9",id_query.c_str());
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
					Log("ServerQueries::query_A2S_PLAYER() Warning: There is an ERROR in select().",id_query.c_str());
					return;
					//pthread_exit(NULL);
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
			Log("ServerQueries::query_A2S_PLAYER() Warning: Packet not received.",id_query.c_str());
			return;
			//pthread_exit(NULL);
		}
		
		
		//boost::array<char, 5120> recv_buf;
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_PLAYER() Reading packet...",id_query.c_str());
		
		// wait for reply
		size_t len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		if(recv_buf[0] == 0xFE && recv_buf[1] == 0xFF && recv_buf[2] == 0xFF && recv_buf[3] == 0xFF)//Packet is split
		{
			Log("ServerQueries::query_A2S_PLAYER() The response is split.",id_query.c_str());
			len = SrcSrv_SplitResponse(&socket,&recv_buf, len);
			if ( len == -1 )
			{
				Log("ServerQueries::query_A2S_PLAYER() Warning: Error in the split response.",id_query.c_str());
				return;
			}
		}
		
		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_PLAYER - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		ParseMasterReply_A2S_PLAYER((unsigned char*)recv_buf.data(), len);
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
	
	snprintf(logout, 128, "            Header2: %c", recvData[4]);//Header 2
	Log(logout,id_query.c_str());
	
	snprintf(logout, 128, "            Players: %u", (unsigned int)recvData[5]);//Players
	Log(logout,id_query.c_str());
	
	for(unsigned int i=0; i<recvData[5]; i++)
	{
		snprintf(logout, 128, "            Index: %u", (unsigned int)recvData[j++]);//Index
		Log(logout,id_query.c_str());
		
		snprintf(logout, 128, "            Name: %s", recvData + j);//Name
		Log(logout,id_query.c_str());

		for(; j<len; j++)
		{
			if(recvData[j] == '\0')
			{
				break;
			}
		}

		//snprintf(logout, 128, "            Score: %x-%x-%x-%x", (unsigned int)recvData[j+1], (unsigned int)recvData[j+2], (unsigned int)recvData[j+3],(unsigned int)recvData[j+4]);//Header 1
		snprintf(logout, 128, "            Score: %u", (long)recvData[j+1], (long)recvData[j+2], (long)recvData[j+3],(long)recvData[j+4]);//Header 1
		Log(logout,id_query.c_str());
		
		j += 4;
		
		snprintf(logout, 128, "            Duration: %l", (long)recvData[j+1] | (long)recvData[j+2] << 8 | (long)recvData[j+3] << 16 | (long)recvData[j+4] << 24);//Header 1
		Log(logout,id_query.c_str());
		
		j += 5;
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
		
		//if(recv_buf_challenge[4] == 0x45)
		if((recv_buf_challenge[0] == 0xFE) || (recv_buf_challenge[0] == 0xFF  && recv_buf_challenge[4] == 0x45))
		{
			//The server has bypassed the challenge number
			if(recv_buf_challenge[0] == 0xFE)
			{
				len = SrcSrv_SplitResponse(&socket,&recv_buf_challenge, len);
				if ( len == -1 )
				{
					Log("ServerQueries::query_A2S_RULES() Warning: Error in the split response.",id_query.c_str());
					return;
				}
			}
			
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
					Log("ServerQueries::query_A2S_RULES() Warning: There is an ERROR in select().",id_query.c_str());
					return;
					//pthread_exit(NULL);
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
			Log("ServerQueries::query_A2S_RULES() Warning: Packet not received.",id_query.c_str());
			return;
			//pthread_exit(NULL);
		}
		
		
		//boost::array<char, 5120> recv_buf;
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("ServerQueries::query_A2S_RULES() Reading packet...",id_query.c_str());
		
		// wait for reply
		len = socket.receive_from(
		boost::asio::buffer(recv_buf), sender_endpoint);
		
		if((unsigned char)recv_buf[0] == 0xFE && (unsigned char)recv_buf[1] == 0xFF && (unsigned char)recv_buf[2] == 0xFF && (unsigned char)recv_buf[3] == 0xFF)//Packet is split
		{
			Log("ServerQueries::query_A2S_RULES() The response is split.",id_query.c_str());
			len = SrcSrv_SplitResponse(&socket,&recv_buf, len);
		}

		
		Log("",id_query.c_str());
		snprintf(logout, 128, "---------- A2S_RULES - Reply from %s:%s -------", ip, port);
		Log(logout,id_query.c_str());
		ParseMasterReply_A2S_RULES((unsigned char*)recv_buf.data(), len);
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
	
	snprintf(logout, 128, "            Header2: %c", recvData[4]);//Header 2
	Log(logout,id_query.c_str());
	
	//rules = ((unsigned int)recvData[5] << 8) | (unsigned int)recvData[6];
	rules = ((unsigned int)recvData[5]) | ((unsigned int)recvData[6] << 8);
	
	snprintf(logout, 128, "            Rules: %u", rules);//Rules
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
			
			/*servAddr gIp_temp;
		
			gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;*/
		  
		  	pthread_exit(NULL);
		}
	
		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		
		Log("ServerQueries::get_ChallengeN_A2S_RULES() Reading packet...",id_query.c_str());

		size_t len = socket->receive_from(boost::asio::buffer(*recv_buf_challenge), sender_endpoint);
		
		/*if( len != 9 )
		{
			Log("ServerQueries::get_ChallengeN_A2S_RULES() Error in received packet: Len is not equal to 9",id_query.c_str());
		}*/
		return len;
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::query_A2S_INFO() exception raised: " << e.what() << std::endl;
	}
}

///IN: rcv_buffer = FE FF FF FF ID Total Number Size (Size CRC) payload...
//OUT: rcv_buffer = FE FF FF FF payload...
/*
		(*rcv_buffer)[0] = Header
		(*rcv_buffer)[1] = Header
		(*rcv_buffer)[2] = Header
		(*rcv_buffer)[3] = Header
		(*rcv_buffer)[4] = ID
		(*rcv_buffer)[5] = ID
		(*rcv_buffer)[6] = ID
		(*rcv_buffer)[7] = ID (if the most significant bit is 1, then the response was compressed with bzip2)
		(*rcv_buffer)[8] = Total
		(*rcv_buffer)[9] = Number (The number of the packet. Starts at 0)
		(*rcv_buffer)[10] = Size
		(*rcv_buffer)[11] = Size
		if (	Number == 0 and is being compressed )
			(*rcv_buffer)[12] = Size
			(*rcv_buffer)[13] = Size
			(*rcv_buffer)[14] = Size
			(*rcv_buffer)[15] = Size
			(*rcv_buffer)[16] = CRC32 sum
			(*rcv_buffer)[17] = CRC32 sum
			(*rcv_buffer)[18] = CRC32 sum
			(*rcv_buffer)[19] = CRC32 sum
		else
			(*rcv_buffer)[12] = Payload...
*/
size_t ServerQueries::SrcSrv_SplitResponse(udp::socket* socket,  boost::array<char, 5120> *rcv_buffer,size_t rcv_len)
{
	try
	{
		char logout[128];
		char queryString[256];
		
		fd_set read_sockets;
		int rc;
		int natSocket = socket->native();
		struct timeval tv;
		bool packet_received;
		size_t t_len = 0;
		int timeout_Seconds = serverParam_q.gettimeoutSeconds();
		//int num_retry = serverParam_q.getn_retry();
		
		unsigned char Total_packets = (*rcv_buffer)[8];
		
		snprintf(logout, 128, "ServerQueries::SrcSrv_SplitResponse() Total number of packets: %u",(unsigned int)Total_packets);
		Log(logout,id_query.c_str());
		
		int res;
		size_t len;
		
		boost::array<char, 5120> recv_bufs_d[(unsigned int)Total_packets];
		size_t len_d[(unsigned int)Total_packets];
		for(unsigned char k=1; k<Total_packets; k++) len_d[k] = -1;
		len_d[0] = rcv_len;
		
		boost::array<char, 5120> recv_buf_temp;
		
		recv_bufs_d[0] = *rcv_buffer;
		
		for(unsigned char z=1; z<Total_packets; z++)
		{
			packet_received = false;
			
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("ServerQueries::SrcSrv_SplitResponse() Waiting response...",id_query.c_str());
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
			   tv.tv_usec=1;
			   
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("ServerQueries::SrcSrv_SplitResponse() There is an ERROR in select.",id_query.c_str());
					return -1;
					//pthread_exit(NULL);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("ServerQueries::SrcSrv_SplitResponse() Packet received.",id_query.c_str());
					packet_received = true;
					break;
				}
				sleep(1);
			}
			
			if(!packet_received)
			{
				Log("ServerQueries::SrcSrv_SplitResponse() Error: Packet not received.",id_query.c_str());
				
				/*servAddr gIp_temp;
			
				gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;*/
			  
			  	return -1;
				//pthread_exit(NULL);
			}
		
			boost::array<char, 5120> recv_buf;
			udp::endpoint sender_endpoint;
			
			Log("ServerQueries::SrcSrv_SplitResponse() Reading packet...",id_query.c_str());
	
			len = socket->receive_from(boost::asio::buffer(recv_buf_temp), sender_endpoint);

			snprintf(logout, 128, "ServerQueries::SrcSrv_SplitResponse() Received packet: %u",(unsigned int)(recv_buf_temp)[9]);
			Log(logout,id_query.c_str());
				
			recv_bufs_d[(unsigned int)(recv_buf_temp)[9]] = recv_buf_temp;
			len_d[(unsigned int)(recv_buf_temp)[9]] = len;
		}
		
		boost::array<char,5120>::iterator it;
		it = rcv_buffer->begin();
		
		for(unsigned char z=0; z<Total_packets; z++)
		{
			if( len_d[(unsigned int)z] == -1)
			{
				snprintf(logout, 128, "ServerQueries::SrcSrv_SplitResponse() Warning: Packet #%u not received",(unsigned int)z);
				Log(logout,id_query.c_str());
			  	return -1;
				//pthread_exit(NULL);
			}
			
			if(recv_bufs_d[z][9] == 0)// The first packet
			{
				//it += 4;
				//t_len += 4;
				if(recv_bufs_d[z][7] & 0x80)// The first packet and is compressed
				{
					unsigned int rcv_size;
					/*res = BZ2_bzBuffToBuffDecompress((it + t_len),// Destination
			                                       &rcv_size, // Destination Lenght
			                                       &recv_bufs_d[z][20], // Source
			                                       len_d[z]-20u, // Source length
			                                       0, // small
			                                       0); // verbosity*/
			      t_len += rcv_size;
				}
				else// The first packet and is not compressed
				{
					//for(int h=0; h<len_d[z]-12; h++)
					for(int h=0; h<len_d[z]-12; h++)
					{
						*(it + t_len) = recv_bufs_d[z][h+12];
						t_len++;
					}
				}
			}
			else// It is not the first packet
			{
				if(recv_bufs_d[z][7] & 0x80)// Not the first packet and is compressed
				{
					unsigned int rcv_size;
					/*res = BZ2_bzBuffToBuffDecompress( it,// Destination
			                                       &rcv_size, // Destination Lenght
			                                       &recv_bufs_d[z][12], // Source
			                                       len_d[z]-12u, // Source length
			                                       0, // small
			                                       0); // verbosity*/
			      t_len += rcv_size;
				}
				else// Not the first packet and is not compressed
				{
					for(int h=0; h<len_d[z]-12; h++)
					{
						*(it + t_len) = recv_bufs_d[z][h+12];
						t_len++;
					}
				}
			}
		}
		snprintf(logout, 128, "ServerQueries::SrcSrv_SplitResponse() Length: %d",t_len);
		Log(logout,id_query.c_str());
		return t_len;
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] ServerQueries::SrcSrv_SplitResponse() exception raised: " << e.what() << std::endl;
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
