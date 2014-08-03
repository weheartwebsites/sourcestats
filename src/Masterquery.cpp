#include "const.h"
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <stdio.h>
#include <iostream>
#include "Masterquery.h"
#include "Client2MasterProt.h"
#include "ServerQueries.h"
#define FINGERPRINT_SIZE 6

using boost::asio::ip::udp;
extern pthread_mutex_t muLog;

extern Client2MasterProt serverParam_q;

int Masterquery::nActiveThreads = 0;
extern pthread_mutex_t muCounts;



void    Masterquery::IncreaseOneThread()
{
	pthread_mutex_lock (&muCounts);
	nActiveThreads++;
	pthread_mutex_unlock (&muCounts);
}
void    Masterquery::DecreaseOneThread()
{
	pthread_mutex_lock (&muCounts);
	nActiveThreads--;
	pthread_mutex_unlock (&muCounts);
}

int     Masterquery::GetNumberThreads()
{
	return nActiveThreads;
}


Masterquery::Masterquery()
{
}

Masterquery::~Masterquery()
{
}

void Masterquery::SetMaster( servAddr mAddr )
{
	char strIp[16];
	char strPort[8];
	char logout[128];
	
	servAddr2Ip( strIp, 16, mAddr );
	servAddr2Port( strPort, 8, mAddr );
	snprintf(logout, 128, "Masterquery::SetMaster() setting master server to '%s:%s'", strIp, strPort);
	Log(logout);
	masterAddr = mAddr;
}

void Masterquery::SetGame( const char* gName )
{
	strncpy( gameName, gName, sizeof(gameName) );
}

void Masterquery::Exec( void )
{
	/*servAddr_thread *servAddr_t = new servAddr_thread;
	pthread_t tThread;
	char tag_tem[25];
	
	//sprintf( servAddr_t->IP, "%s","216.244.85.243");
	//sprintf( servAddr_t->PORT, "%s", "27015" );
	
	sprintf( servAddr_t->IP, "%s","192.69.97.237");
	sprintf( servAddr_t->PORT, "%s", "27067" );
	
	sprintf(tag_tem,"Thread#%d",1);
	servAddr_t->ID_tag = tag_tem;
	
	int ret = pthread_create( &tThread, NULL, Masterquery::ThreadServerQueries, servAddr_t );//*/
	/////////////////////////
	Query();
	if(m_vResultlist.size() > 0)
	{
		char logout[128];
		unsigned int i = 1;
		int numberMax_thread = serverParam_q.getMax_threads();
		snprintf(logout, 128, "Masterquery::Exec Max numbers of threads to create: #%d", numberMax_thread);
		Log(logout);
		//for (std::vector<servAddr*>::iterator it = m_vResultlist.end()-1 ; it != m_vResultlist.begin() && it != m_vResultlist.end()-3000; --it)
		for (std::vector<servAddr*>::iterator it = m_vResultlist.end()-1 ; it != m_vResultlist.begin() ; --it)
		{
			snprintf(logout, 128, "Masterquery::Exec Creating threads#%d for querying the server", i);
			Log(logout);

			servAddr server_addr;
			server_addr =  (**it);

			servAddr_thread *servAddr_t = new servAddr_thread;
			
			char tag_tem[25];
			pthread_t tThread;
			
			servAddr2Ip( servAddr_t->IP, 128,server_addr);
			servAddr2Port( servAddr_t->PORT, 128, server_addr );
			
			sprintf(tag_tem,"Thread#%d",i);
			
			servAddr_t->ID_tag = tag_tem;
    		
    		while(GetNumberThreads() > numberMax_thread)
    		{
    			char logout[128];
	 			snprintf(logout, 128, "Masterquery::Exec WAITING: Number of threads = %d", GetNumberThreads());
				Log(logout);
    			sleep(1);
    		}
			
			Masterquery::IncreaseOneThread();
			if( pthread_create( &tThread, NULL, Masterquery::ThreadServerQueries, servAddr_t ) != 0 )
			{
				Masterquery::DecreaseOneThread();
				snprintf(logout, 128, "Masterquery::Exec Warning: Thread #%u was not created", i);
				Log(logout);
			}			
			i++;
		}
	}
	else
	{
		Log("Masterquery::Exec No addresses stored in Masterquery::m_vResultlist");
		exit(0);
	}//*/
}

void* Masterquery::ThreadServerQueries( void *arg )
{
	servAddr_thread* servAddrpArgs = (servAddr_thread*)arg;
	ServerQueries ServerQuery1;
	DebugLog log1;
	char logout[128];
	
	snprintf(logout, 128, "Masterquery::ThreadServerQueries Initiating ServerQuery1.set_id_query %s:%s",servAddrpArgs->IP,servAddrpArgs->PORT);
	log1.Log(logout,(servAddrpArgs->ID_tag).c_str());
	ServerQuery1.set_id_query((servAddrpArgs->ID_tag).c_str());

	snprintf(logout, 128, "Masterquery::ThreadServerQueries Initiating ServerQuery1.query_A2S_INFO %s:%s",servAddrpArgs->IP,servAddrpArgs->PORT);
	log1.Log(logout,(servAddrpArgs->ID_tag).c_str());
	ServerQuery1.query_A2S_INFO(servAddrpArgs->IP,servAddrpArgs->PORT);
	
	snprintf(logout, 128, "Masterquery::ThreadServerQueries Initiating ServerQuery1.query_A2S_RULES %s:%s",servAddrpArgs->IP,servAddrpArgs->PORT);
	log1.Log(logout,(servAddrpArgs->ID_tag).c_str());
	ServerQuery1.query_A2S_RULES(servAddrpArgs->IP,servAddrpArgs->PORT);
	
	snprintf(logout, 128, "Masterquery::ThreadServerQueries Initiating query_A2S_PLAYER %s:%s",servAddrpArgs->IP,servAddrpArgs->PORT);
	log1.Log(logout,(servAddrpArgs->ID_tag).c_str());
	ServerQuery1.query_A2S_PLAYER(servAddrpArgs->IP,servAddrpArgs->PORT);

	snprintf(logout, 128, "Masterquery::ThreadServerQueries Finishing Masterquery::ThreadServerQueries %s:%s",servAddrpArgs->IP,servAddrpArgs->PORT);
	log1.Log(logout,(servAddrpArgs->ID_tag).c_str());
	
	Masterquery::DecreaseOneThread();
	pthread_exit(NULL);
}

void Masterquery::EntryPoint( void )
{
	Exec();
}

servAddr Masterquery::ParseMasterReply(const char* recvData, size_t len)
{
	size_t read = 0;
	servAddr nullAddr;
	nullAddr.ip1 = 0;
	nullAddr.ip2 = 0;
	nullAddr.ip3 = 0;
	nullAddr.ip4 = 0;
	nullAddr.port = 0;
	
	// checking fingerprint
	unsigned char finger[FINGERPRINT_SIZE];
	memcpy(finger, recvData, sizeof(finger));
	read += sizeof(finger);

	// FF FF FF FF 66 0A
	if (finger[0] != 0xFF || finger[1] != 0xFF || finger[2] != 0xFF || finger[3] != 0xFF || finger[4] != 0x66 || finger[5] != 0xA)
	{
		char sServAddr[128];
		servAddr2String(sServAddr, 128, masterAddr );
		return nullAddr;
	}

	servAddr lastGameAddr;
	size_t entryLen = 0;

	while ( read < len )
	{
		servAddr gIp;
		unsigned short htPort;
		size_t readStart = read;
		
		memcpy(&gIp.ip1, recvData+read, sizeof(gIp.ip1));
		read += sizeof(gIp.ip1);
		memcpy(&gIp.ip2, recvData+read, sizeof(gIp.ip2));
		read += sizeof(gIp.ip2);
		memcpy(&gIp.ip3, recvData+read, sizeof(gIp.ip3));
		read += sizeof(gIp.ip3);
		memcpy(&gIp.ip4, recvData+read, sizeof(gIp.ip4));
		read += sizeof(gIp.ip4);
		memcpy(&htPort, recvData+read, sizeof(htPort));
		read += sizeof(htPort);
		gIp.port = ntohs(htPort);
		
		lastGameAddr = gIp;
		
		// check for end of list, the master server returns 0.0.0.0:0 as address on EOF
		if ( lastGameAddr.ip1 == 0 && lastGameAddr.ip2 == 0 && lastGameAddr.ip3 == 0 && lastGameAddr.ip4 == 0 || lastGameAddr.port == 0 )
		{
			Log("Masterquery::ParseMasterReply() EOF received, giving up!");
			return lastGameAddr;
		}
		entryLen = read - readStart;
		
		// add gameserver to the list for further usage
		//AddEntry(new GameserverEntry(lastGameAddr));
		AddEntry(&lastGameAddr);
	}
	return lastGameAddr;
}

servAddr Masterquery::RequestMore( udp::socket* socket, servAddr gIp )
{
	char output[128];
	char sQuery[32];
	char ip[16];
	char port[8];
	char logout[128];
	
	servAddr2Ip( ip, 16, masterAddr );
	servAddr2Port( port, 8, masterAddr );
	servAddr2String( output, 128, gIp );
	
	snprintf(logout, 128, "Masterquery::RequestMore() using seed %s", output);
	Log(logout);
	char queryString[256];
	
	snprintf(queryString, 256, "1%c%u.%u.%u.%u:%u%c%s",serverParam_q.getregion(), gIp.ip1, gIp.ip2, gIp.ip3, gIp.ip4, gIp.port,0,serverParam_q.getfilter());
	snprintf(logout, 128, "Masterquery::RequestMore() querying '%s:%s' with string: '%s'", ip, port, queryString);
	Log(logout);
	
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
	
	do
	{
		snprintf(logout, 128, "Masterquery::RequestMore() Re-sending(%d) query to the server.",i);
		if(i>0)Log(logout);
		
		socket->send_to(boost::asio::buffer(queryString), receiver_endpoint);
		for(int j=0; j<=timeout_Seconds; j++)
		{
			if(j==0)Log("Masterquery::RequestMore() Waiting response...");
			FD_ZERO(&read_sockets);
			FD_SET(natSocket,&read_sockets);
			
			tv.tv_sec=0;
			tv.tv_usec=1;
			
			rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
			
			if(rc<0)
			{
				Log("Masterquery::RequestMore() There is an ERROR in select.");
				exit(-1);
			}
			
			if (FD_ISSET(natSocket,&read_sockets))
			{
				Log("Masterquery::RequestMore() Packet received.");
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
		Log("Masterquery::RequestMore() Warning: Packet not received.");
		
		servAddr gIp_temp;
		
		gIp_temp.ip1 = 0; gIp_temp.ip2 = 0; gIp_temp.ip3 = 0; gIp_temp.ip4 = 0; gIp_temp.port = 0;
		
		return gIp_temp;
	}

	boost::array<char, 5120> recv_buf;
	udp::endpoint sender_endpoint;
	
	Log("Masterquery::RequestMore() waiting for reply(2)...");
	// wait for reply
	
	size_t len = socket->receive_from(boost::asio::buffer(recv_buf), sender_endpoint);
	
	return ParseMasterReply( recv_buf.data(), len );
}

void Masterquery::Query( void )
{
	try
	{
		char ip[16];
		char port[8];
		
		servAddr2Ip( ip, 16, masterAddr );
		servAddr2Port( port, 8, masterAddr );
		boost::asio::io_service io_service;
		
		udp::resolver resolver(io_service);
		udp::resolver::query query(udp::v4(), ip, port);
		udp::endpoint receiver_endpoint = *resolver.resolve(query);
		
		udp::socket socket(io_service);
		socket.open(udp::v4());
		
		// send 1:0.0.0.0:0 to retrieve all servers
		char queryString[256];
		char logout[128];

		snprintf( queryString, 256, "1%c0.0.0.0:0%c%s%c", serverParam_q.getregion(), 0 ,serverParam_q.getfilter(), 0 );
		
		snprintf(logout, 128, "Masterquery::Query() querying '%s:%s' with string: '%s'", ip, port, queryString);
		Log(logout);

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
			snprintf(logout, 128, "Masterquery::Query() Re-sending(%d) query to the server.",i);
			if(i>0)Log(logout);
			
			socket.send_to(boost::asio::buffer(queryString), receiver_endpoint);
			for(int j=0; j<=timeout_Seconds; j++)
			{
				if(j==0)Log("Masterquery::Query() Waiting response...");
				FD_ZERO(&read_sockets);
				FD_SET(natSocket,&read_sockets);
				
				tv.tv_sec=0;
				tv.tv_usec=1;
				
				rc=select(FD_SETSIZE,&read_sockets, NULL, NULL,&tv);
				
				if(rc<0)
				{
					Log("Masterquery::Query() There is an ERROR in select.");
					exit(-1);
				}
				
				if (FD_ISSET(natSocket,&read_sockets))
				{
					Log("Masterquery::Query() Packet received.");
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
			Log("Masterquery::Query() Error: Packet not received.");
			exit(0);
		}

		boost::array<char, 5120> recv_buf;
		udp::endpoint sender_endpoint;
		Log("Masterquery::Query() waiting for reply...");
		
		// wait for reply
		size_t len = socket.receive_from(boost::asio::buffer(recv_buf), sender_endpoint);
		
		servAddr gIp;
		gIp = ParseMasterReply(recv_buf.data(), len);
		Log("Masterquery::Query() parsed reply!");

		int loops = 0;
		while ( gIp.ip1 != 0 || gIp.ip2 != 0 || gIp.ip3 != 0 || gIp.ip4 != 0 || gIp.port != 0 )
		{
			if ( loops >= 500 )
			{
				Log("Masterquery::Query() hard break");
				break;
			}
			
			loops++;
			Log("Masterquery::Query() requesting more...");
			gIp = RequestMore(&socket, gIp);
		}
		Log("Masterquery::Query() EOF!");
	}
	catch (std::exception& e)
	{
		std::cerr << "[" << time(NULL) << "] Masterquery::Query() exception raised: " << e.what() << std::endl;
	}
}

//void Masterquery::AddEntry( GameserverEntry* pEntry )
void Masterquery::AddEntry( servAddr* pEntry )
{
	char output[128];
	char logout[128];
	//servAddr2String( output, 128, pEntry->GetAddr() );
	servAddr2String( output, 128, *pEntry );
	snprintf(logout, 128, "Masterquery::AddEntry() added new entry with address: '%s'", output);
	Log(logout);
	
	servAddr *pEntry_n = new servAddr;
	*pEntry_n = *pEntry;
	
	m_vResultlist.push_back( pEntry_n );
}

void Masterquery::Log( const char* logMsg )
{
	pthread_mutex_lock (&muLog);
	std::cout << "[" << time(NULL) << "][" << gameName << "] "<< logMsg << std::endl;
	pthread_mutex_unlock (&muLog);
}
