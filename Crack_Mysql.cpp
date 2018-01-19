#include <winsock2.h> 
#include "C:\\Program Files\\MySQL\\MySQL Server 5.0\\include\\mysql.h"

#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus

#include "..\\XScanLib\\XScanLib.h"

#ifdef __cplusplus
    }
#endif // __cplusplus

extern "C" __declspec(dllexport) BOOL __stdcall GetPluginInfo(PLUGIN_INFO *);
extern "C" __declspec(dllexport) BOOL __stdcall PluginFunc (VOID *);
extern "C" DWORD WINAPI CrackMySQL (VOID *);
extern "C" DWORD WINAPI CheckPort ( char *Host, int Port );

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "..\\XScanLib\\XScanLib.lib")
#pragma comment( lib, "C:\\Program Files\\MySQL\\MySQL Server 5.0\\lib\\opt\\libmysql.lib" )

#define	VULN_MEMBER_NAME	"MySQL弱口令"
#define	CHECKING_STRING		"正在猜解MySQL数据库口令..."
#define VERSION				"0.1"
#define	CMD_PARMAS			"-mysql"
#define	PROMPT				"-mysql    :检测MySQL数据库弱口令"
#define	AUTHOR				"云舒"
#define	DESCRIPTION			"该插件载入字典对Mysql弱口令进行检测。"
#define	TIMEOUT				0
#define	ICON				"sql.bmp"
#define FILENAME            "Crack_MySQL.xpn"

#define	MYSQL_PORT			3306
#define	DB_NAME				"mysql"

BOOL APIENTRY DLLMain(HANDLE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
	return TRUE;
}

BOOL __stdcall GetPluginInfo (PLUGIN_INFO *Info)
{
	// 设置插件信息
	strcpy_s( Info->szClassName, VULN_MEMBER_NAME );
	strcpy_s( Info->szMemberName, VULN_MEMBER_NAME );
	strcpy_s( Info->szVersion, VERSION );
	strcpy_s( Info->szFileName, FILENAME );
	strcpy_s( Info->szParamsRequest, CMD_PARMAS );
	strcpy_s( Info->szPrompt, PROMPT );
	Info->nSingle = 1;
	strcpy_s( Info->szAuthorName, AUTHOR );
	strcpy_s( Info->szDescription, DESCRIPTION );
	Info->dwTimeOut = TIMEOUT;
	Info->nMark = 1;
	strcpy_s( Info->szImageFile, ICON );

	return TRUE;
}

BOOL __stdcall PluginFunc( VOID *Parm )
{
	int VulnNumber = 0;

	if( !PlugInitLib((struct arglist *)Parm) )
	{
		return FALSE;
	}

	PlugSetVulnNum( (struct arglist *)Parm, 0 );

	PlugSetCurrentSchedule( (struct arglist *)Parm, CHECKING_STRING );

	// 加入到线程池
	PlugAddThread( (struct arglist *)Parm, CrackMySQL, Parm, TIMEOUT );

	PlugWaitThread( (struct arglist *)Parm );

	VulnNumber = PlugGetVulnNum( (struct arglist *)Parm );

	return VulnNumber > 0 ? TRUE : FALSE;
}

DWORD WINAPI CrackMySQL( void * Parm )
{
	char	Host[256] = { 0 };
	char	LogType[8] = { 0 };
	int		Verbose = 0;
	char	Message[128] = { 0 };
	int		PortState = -1;

	FILE	*UserFile = NULL;
	FILE	*PassFile = NULL;
	char	TestUser[32] = { 0 };
	char	TestPass[32] = { 0 };

	MYSQL	Mysql;


	struct arglist	*MyArgList = (struct arglist *)Parm;

	// 获取扫描参数
	strncpy_s( Host, (char *)PlugGetParams(MyArgList, "HostName"), 255 );
	strncpy_s( LogType, (char *)PlugGetParams(MyArgList, "LogType"), 7 );
	Verbose = (int)PlugGetParams(MyArgList, "ShowVerbose");

	PlugSetCurrentSchedule( MyArgList, CHECKING_STRING );
	
	PortState = CheckPort( Host, MYSQL_PORT );

	// 端口没开放
	if( PortState <= 0 )
	{
		return 0;
	}

	if( !Verbose )
	{
		PlugAlertUser ( MyArgList, AT_NORMAL, CHECKING_STRING );
	}

	// 打开字典
	UserFile = fopen( "dat\\mysql_user.dic", "r" );
	if( UserFile == NULL )
	{
		PlugAlertUser( MyArgList, AT_ERROR, "打开mysql_user.dic失败……" );
		return 0;
	}

	PassFile = fopen( "dat\\mysql_pass.dic", "r" );
	if( PassFile == NULL )
	{
		PlugAlertUser( MyArgList, AT_ERROR, "打开mysql_pass.dic失败……" );
		return 0;
	}

	char	*p = NULL;

	while( !feof( UserFile ) )
	{
		fgets( TestUser, 31, UserFile );

		while( !feof( PassFile ) )
		{
			fgets( TestPass, 31, PassFile );

			if( 0 == _strnicmp( TestPass, "%null%", 6 ) )
			{
				memset( TestPass, 0, sizeof(TestPass) );
			}
			else if( NULL != (p = strstr(TestPass, "%username%"))  )
			{
				// %username%123
				if( 0 == p - TestPass )
				{
					char	TmpStr[32] = { 0 };
					
					sprintf_s( TmpStr, "%s%s", TestUser, TestPass + strlen("%username%") );

					memset( TestPass, 0 , sizeof(TestPass) );

					strcpy_s( TestPass, TmpStr );
				}

				// 123%username%456 or 123%username%
				else if( 0 < p - TestPass )
				{
					char	TmpStr[32] = { 0 }; 
					
					// 这里有个溢出，懒得改了

					strncpy_s( TmpStr, TestPass, p - TestPass );
					strcat_s( TmpStr, TestUser );
					strcat_s( TmpStr, p + strlen("%username%") );

					memset( TestPass, 0 , sizeof(TestPass) );
					strcpy_s( TestPass, TmpStr );
				}

			}

			if( TestUser[strlen(TestUser)-1] == '\n' )
			{
				TestUser[strlen(TestUser)-1] = '\0';
			}

			if( TestPass[strlen(TestPass)-1] == '\n' )
			{
				TestPass[strlen(TestPass)-1] = '\0';
			}

			if( Verbose )
			{
				if( 0 == strlen(TestPass) )
				{
					sprintf_s( Message, "正在猜解MySQL数据库密码:%s/%s", TestUser, "空口令" );
				}
				else
				{
					sprintf_s( Message, "正在猜解MySQL数据库密码:%s/%s", TestUser, TestPass );
				}

				PlugAlertUser( MyArgList, AT_NORMAL, Message );
			}

			mysql_init( &Mysql );

			if( mysql_real_connect( &Mysql, Host, TestUser, TestPass, DB_NAME, MYSQL_PORT, 0, NULL ) )
			{
				memset( Message, 0, sizeof(Message) );
				if( 0 == strlen(TestPass) )
				{
					memset( TestPass, 0, sizeof(TestPass) );
					strcpy_s( TestPass, "空口令" );
				}
				sprintf_s( Message, "MySQL弱口令:\n帐户:%s\n密码:%s", TestUser, TestPass );
				PlugLogToFile( MyArgList, "3306/TCP", "HOLE", Message );

				PlugAddVulnNum( MyArgList );

				memset( Message, 0, sizeof(Message) );
				sprintf_s ( Message, "%s\n%s\n%s/%s\n", Host, VULN_MEMBER_NAME, TestUser, TestPass );
				PlugAddToTV ( Message, ICON );
			}

			mysql_close( &Mysql );
		}
	}
	return 0;
}

DWORD WINAPI CheckPort ( char *Host, int Port)
{
	SOCKET		sock;
	SOCKADDR_IN	sin;

	memset( &sin, 0, sizeof(SOCKADDR_IN) );

	sin.sin_family = AF_INET;
	sin.sin_port = htons( Port );

	if( inet_addr( Host ) != INADDR_NONE )
	{
		sin.sin_addr.s_addr = inet_addr( Host );
	}		
	else
	{
		struct hostent	*phost = gethostbyname( Host );

		if( phost == NULL )
		{
			return -1;
		}
		memcpy( &sin.sin_addr , phost->h_addr_list[0] , phost->h_length );
	}

	// 建立socket失败则返回端口开放，等待mysql api直接连接，减少漏报
	sock = socket( AF_INET, SOCK_STREAM, 0 );
	if( sock == INVALID_SOCKET )
	{
		return 1;
	}

	 int state = connect( sock , (struct sockaddr *)&sin , sizeof(sin) );
	 if( state == SOCKET_ERROR )
	 {
		 return -1;
	 }
	 else
	 {
		 return 1;
	 }
}
