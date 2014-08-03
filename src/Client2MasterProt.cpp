#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <netdb.h>
#include <arpa/inet.h>
#include "Client2MasterProt.h"
#include "const.h"

Client2MasterProt::Client2MasterProt()
{
	verbose_m = false;
	Hostname_server = "0";
	region = '0';
	Port = "0";
	filter = "0";
	timeoutSeconds = 0;
	n_retry = 0;
	max_threads = 0;
}

void Client2MasterProt::set(int argc, char *argv[])
{
	char c;
	char logout[512];
	string conf_path;
	if(argc < 3 || argc > 4)
	{
		snprintf(logout, 512, 
		"Error: Wrong input parameters.\n"
		"Use:     %s -c <Config file path> [-v]\n"
		"Example: %s -c /home/daniel/GitHub_repos/sourcestats_optimized/src/config.conf",argv[0],argv[0]);
		
		Log(logout);
		exit(-1);
	}
	
	while((c = getopt (argc,argv,"c:v")) != EOF)
	switch ((char) c)
	{
		case 'c':
			if (optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() Configuration file path is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				snprintf(logout, 128, "Client2MasterProt::set() Configuration file path: %s", optarg);
				Log(logout);
				conf_path = optarg;
			}
		break;
		case 'v':
			verbose_m = true;
			snprintf(logout, 128, "Client2MasterProt::set() Verbose mode");
			Log(logout);
		break;
	}
	
	char master_server_p[100];
	char master_port_p[6];
	char master_region_p[20];
	char master_filter_p[100];
	char timeout_p[20];
	char retries_p[10];
	char max_threads_p[10];
	char mysql_host_p[100];
	char mysql_user_p[100];
	char mysql_pass_p[100];
	char mysql_db_p[100];

	printf("Reading configuration file: %s",conf_path.c_str());
	CHECK_SYNTAX_CONF(conf_path.c_str())
	GET_DATA_CONF("master_server","master_server",master_server_p,100,conf_path.c_str())
	GET_DATA_CONF("master_port","master_port",master_port_p,6,conf_path.c_str())
	GET_DATA_CONF("master_region","master_region",master_region_p,20,conf_path.c_str())
	GET_DATA_CONF("master_filter","master_filter",master_filter_p,100,conf_path.c_str())
	GET_DATA_CONF("timeout","timeout",timeout_p,20,conf_path.c_str())
	GET_DATA_CONF("retries","retries",retries_p,10,conf_path.c_str())
	GET_DATA_CONF("max_threads","max_threads",max_threads_p,10,conf_path.c_str())
	/*GET_DATA_CONF("mysql_host","mysql_host",mysql_host_p,100,conf_path.c_str())
	GET_DATA_CONF("mysql_user","mysql_user",mysql_user_p,100,conf_path.c_str())
	GET_DATA_CONF("mysql_pass","mysql_pass",mysql_pass_p,100,conf_path.c_str())
	GET_DATA_CONF("mysql_db","mysql_db",mysql_db_p,100,conf_path.c_str())*/
	
	Hostname_server = master_server_p;
	Port = master_port_p;
	region = Region_str2int((string)master_region_p);
	filter = master_filter_p;
	timeoutSeconds = atoi(timeout_p);
	n_retry = atoi(retries_p);
	max_threads = atoi(max_threads_p);
	
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(Hostname_server.c_str())) == NULL)
	{
		Log("Gethostbyname error");
		exit(-1);
	}

	addr_list = (struct in_addr **)he->h_addr_list;
    
	if(addr_list[0] != NULL)
	{
		Ip = inet_ntoa(*addr_list[0]);	
	}
}

void Client2MasterProt::AddServers(MasterserverManager &MasterserverManager_obj)
{
	string IpPort_address_temp;
	IpPort_address_temp = Ip;	
	IpPort_address_temp += ":";
	IpPort_address_temp += Port;
	MasterserverManager_obj.AddServer( IpPort_address_temp.c_str() );
}

servAddr Client2MasterProt::getservAddr()
{
	servAddr stServaddr;
	int ret1,ret2;
	
	ret1 = sscanf( Ip.c_str(), "%u.%u.%u.%u", (unsigned int*)&stServaddr.ip1, (unsigned int*)&stServaddr.ip2, (unsigned int*)&stServaddr.ip3, (unsigned int*)&stServaddr.ip4, (unsigned int*)&stServaddr.port );
	ret2 = sscanf( Port.c_str(), "%u", (unsigned int*)&stServaddr.port );
	
	if ( ret1 != 4 || ret2 != 1 )
	{
		Log("Client2MasterProt::getservAddr() tried to return malformed server ip:port");
		exit(-1);
	}
	
	return stServaddr;
}

int Client2MasterProt::Region_str2int(string param_str)
{
	if(param_str == "us-east")
		return 0x00;
		
	if(param_str == "us-west")
		return 0x01;
		
	if(param_str == "south-america")
		return 0x02;
		
	if(param_str == "europe")
		return 0x03;
		
	if(param_str == "asia")
		return 0x04;
		
	if(param_str == "australia")
		return 0x05;
		
	if(param_str == "middle-east")
		return 0x06;
		
	if(param_str == "africa")
		return 0x07;

	return 0xFF;// "rest", default value
}
