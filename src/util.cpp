#include "const.h"
#include "stdio.h"

void servAddr2String( char* sAddr, size_t size, servAddr stServaddr )
{	
	snprintf( sAddr, size, "%u.%u.%u.%u:%u", stServaddr.ip1, stServaddr.ip2, stServaddr.ip3, stServaddr.ip4, stServaddr.port );	
}

void servAddr2Ip( char* sAddr, size_t size, servAddr stServaddr )
{	
	snprintf( sAddr, size, "%u.%u.%u.%u", stServaddr.ip1, stServaddr.ip2, stServaddr.ip3, stServaddr.ip4 );	
}

void servAddr2Port( char* sAddr, size_t size, servAddr stServaddr )
{	
	snprintf( sAddr, size, "%u", stServaddr.port );	
}

int getConfData(const char *in_variable,char *out_value,int max_size,const char *file_path)
{
    return(readConfData(in_variable,out_value,max_size,file_path,FIND_DATA));
}


int checkSyntaxConf(const char *file_path)
{
    char dummy[1];
    return(readConfData("",dummy,1,file_path,CHECK_SYNTAX));
}


int readConfData(const char *in_variable,char *out_value,int tam_max,const char *file_path,int check_syntax)
{
    FILE *CONF_FILE;
    char conf_line[TAMANO_MAX_BUFFER],  Variable[TAMANO_MAX_BUFFER],  Value[TAMANO_MAX_BUFFER];
    int  linenumber=0,i,res;

    CONF_FILE = fopen(file_path, "r");
 	if (CONF_FILE == NULL)
	{
		printf("Error reading configuration file\n");
		return -1;
	}


    while (fgets(conf_line, TAMANO_MAX_BUFFER, CONF_FILE) != NULL)
	{
	    linenumber++;

	    if((conf_line[strlen(conf_line)-1]!='\n'))
	    {
	        printf("Error in line #%d: Line size exceeds %d or a new line is needed at the end of the file\n",linenumber,MAX_LINE_SIZE);
	        return -1;
	    }
        else
        {
            for(i=0;i<TAMANO_MAX_BUFFER;i++)
            {
                if(conf_line[i]=='=')
                {
                    conf_line[i]=' ';
                }

                if(conf_line[i]=='#')
                {
                    conf_line[i]='\0';
                    break;
                }
            }

            Variable[0]='\0';Value[0]='\0';
            res = sscanf(conf_line,"%s %s",Variable,Value);
            if(res == 1)
            {
                Variable[0]='\0';Value[0]='\0';
                printf("Warning: Linea ignored #%d: wrong syntax\n",linenumber);
            }
            if(!check_syntax)
            {
                if(strcmp(in_variable,Variable)==0)
                {
                    if(strlen(Value) > (tam_max - 1))
                    {
                        printf("Error in Line #%d: Size is bigger than expected\n",linenumber);
                        return -1;
                    }
                    strcpy(out_value,Value);

                    return 0;
                }
            }
        }
	}

    if(fclose(CONF_FILE))
	{
		printf("Error closing the configuration file\n");
		return -1;
	}

	return 1;
}

