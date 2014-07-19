#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <netdb.h>
#include <arpa/inet.h>
#include "Client2MasterProt.h"

Client2MasterProt::Client2MasterProt()//:verbose_m(false),IpPort_server("0:0"),region('0'),Port("0"),filter("0")
{
	verbose_m = false;
	Hostname_server = "0";
	region = '0';
	Port = "0";
	filter = "0";
}

void Client2MasterProt::set(int argc, char *argv[])
{
	char c;
	char logout[256];
	
	if(argc < 9)
	{
		snprintf(logout, 256, 
		"Error: No input parameters.\n"
		"Use:     %s -i <IP server address> -p <Server Port> -r <Region code (decimal)> -f <Filter>\n"
		"Example: %s -h hl2master.steampowered.com -p 27011 -r us-west -f \"\\type\\d\\secure\\1\"",argv[0],argv[0]);

		Log(logout);
		exit(-1);
	}
	
	while((c = getopt (argc,argv,"h:p:r:f:v")) != EOF)
	switch ((char) c)
	{
		case 'h':
			if (optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() Hostname is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				snprintf(logout, 128, "Client2MasterProt::set() Hostname address: %s", optarg);
				Log(logout);
				Hostname_server = optarg;
			}
		break;
		case 'p':
			if(optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() Port is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				snprintf(logout, 128, "Client2MasterProt::set() Port: %s", optarg);
				Log(logout);
				Port = optarg;
			}
		break;
		case 'r':
			if (optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() Region is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				region = Region_str2int((string)optarg);
				snprintf(logout, 128, "Client2MasterProt::set() Region: %s (%d)", optarg,(unsigned int)region);
				Log(logout);
			}
		break;
		case 'f':
			if(optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() Filter is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				snprintf(logout, 128, "Client2MasterProt::set() Filter: %s", optarg);
				Log(logout);
				filter = optarg;
			}
			
		break;
		case 'v':
			verbose_m = true;
			snprintf(logout, 128, "Client2MasterProt::set() Verbose mode");
			Log(logout);
		break;
	}
}

void Client2MasterProt::AddServers(MasterserverManager &MasterserverManager_obj)
{
	int i;
	struct hostent *he;
	struct in_addr **addr_list;
	string IpPort_address_temp;

	if ((he = gethostbyname(Hostname_server.c_str())) == NULL)
	{
		Log("Gethostbyname error");
		exit(-1);
	}

	addr_list = (struct in_addr **)he->h_addr_list;
    
	for(i = 0; addr_list[i] != NULL; i++)
	{
		IpPort_address_temp = inet_ntoa(*addr_list[i]);	
		IpPort_address_temp += ":";
		IpPort_address_temp += Port;
		MasterserverManager_obj.AddServer( IpPort_address_temp.c_str() );
	}
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
