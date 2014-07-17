#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include "Client2MasterProt.h"

Client2MasterProt::Client2MasterProt()//:verbose_m(false),IpPort_server("0:0"),region('0'),IpPort("0:0"),filter("0")
{
	verbose_m = false;
	IpPort_server = "0:0";
	region = '0';
	IpPort = "0:0";
	filter = "0";
}

void Client2MasterProt::set(int argc, char *argv[])
{
	char c;
	string Port_temp;
	char logout[256];
	
	if(argc < 9)
	{
		snprintf(logout, 256, 
		"Error: No input parameters.\n"
		"Use:     %s -i <IP server address> -p <Server Port> -r <Region code (decimal)> -f <Filter>\n"
		"Example: %s -i 208.64.200.39 -p 27011 -r 02 -f 88",argv[0],argv[0]);
		
		Log(logout);
		exit(-1);
	}
	
	while((c = getopt (argc,argv,"i:p:r:f:v")) != EOF)
	switch ((char) c)
	{
		case 'i':
			if (optarg == NULL)
			{
				snprintf(logout, 128, "Client2MasterProt::set() IP is missing");
				Log(logout);
				exit(0);
			}
			else
			{
				snprintf(logout, 128, "Client2MasterProt::set() IP address: %s", optarg);
				Log(logout);
				IpPort_server = optarg;
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
				Port_temp = optarg;
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
				snprintf(logout, 128, "Client2MasterProt::set() Region: %s", optarg);
				Log(logout);
				if( (region = atoi(optarg)) > 255)
				{
                    region = 0;
				}
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
	
	IpPort_server += ":";
	IpPort_server += Port_temp;
}

