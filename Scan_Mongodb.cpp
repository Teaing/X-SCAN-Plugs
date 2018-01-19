#include "C:\\mongo-cxx-driver-legacy\\src\\mongo\\client\\dbclient.h"
#include <winsock2.h> 

#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus

#include "..\\XScanLib\\XScanLib.h"

#ifdef __cplusplus
    }
#endif // __cplusplus

extern "C" __declspec(dllexport) BOOL __stdcall GetPluginInfo(PLUGIN_INFO *);
extern "C" __declspec(dllexport) BOOL __stdcall PluginFunc (VOID *);
extern "C" DWORD WINAPI ScanMongodb (VOID *);
extern "C" DWORD WINAPI CheckPort ( char *Host, int Port );

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "..\\XScanLib\\XScanLib.lib")
#pragma comment(lib, "C:\\mongo-cxx-driver-legacy\\build\\win32\\dynamic-windows\\use-system-boost\\mongoclient.lib")

#define	VULN_MEMBER_NAME	"Mongodb未授权访问"
#define	CHECKING_STRING		"正在检测Mongodb是否存在未授权访问安全问题"
#define VERSION				"0.1"
#define	CMD_PARMAS			"-mongodb"
#define	PROMPT				"-mongodb    :检测Mongodb未授权访问"
#define	AUTHOR				"Tea"
#define	DESCRIPTION			"该插件只对Mongodb进行未授权访问检测。"
#define	TIMEOUT				10000
#define	ICON				"sql.bmp"
#define FILENAME            "Scan_Mongodb.xpn"

#define	Mongodb_PORT		27017


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
	PlugAddThread( (struct arglist *)Parm, ScanMongodb, Parm, TIMEOUT );

	PlugWaitThread( (struct arglist *)Parm );

	VulnNumber = PlugGetVulnNum( (struct arglist *)Parm );

	return VulnNumber > 0 ? TRUE : FALSE;
}

using namespace std;
using namespace mongo;

DWORD WINAPI ScanMongodb( void * Parm )
{
	char	Host[256] = { 0 };
	char	LogType[8] = { 0 };
	int		Verbose = 0;
	char	Message[128] = { 0 };
	int		PortState = -1;
	string		errmsg;

	DBClientConnection conn( false , NULL , 6 );

	struct arglist	*MyArgList = (struct arglist *)Parm;

	// 获取扫描参数
	strncpy_s( Host, (char *)PlugGetParams(MyArgList, "HostName"), 255 );
	strncpy_s( LogType, (char *)PlugGetParams(MyArgList, "LogType"), 7 );
	Verbose = (int)PlugGetParams(MyArgList, "ShowVerbose");

	PlugSetCurrentSchedule( MyArgList, CHECKING_STRING );
	
	PortState = CheckPort( Host, Mongodb_PORT );

	// 端口没开放
	if( PortState <= 0 )
	{
		return 0;
	}

	if( !Verbose )
	{
		PlugAlertUser ( MyArgList, AT_NORMAL, CHECKING_STRING );
	}

	try {
		if (conn.connect(Host, errmsg ) ) 
		{
			list<string> Result_Tmp = conn.getDatabaseNames();
			if (!Result_Tmp.empty())
			{
				sprintf_s( Message, "Mongodb存在未授权访问漏洞!");
				PlugAlertUser( MyArgList, AT_WARNING, Message );
				memset( Message, 0, sizeof(Message) );
				sprintf_s( Message, "Mongodb存在未授权访问漏洞!\n请对Mongodb使用认证!");
				PlugLogToFile( MyArgList, "27017/TCP", "HOLE", Message );
				PlugAddVulnNum( MyArgList );
				memset( Message, 0, sizeof(Message) );
				sprintf_s ( Message, "%s\n%s\n", Host, VULN_MEMBER_NAME);
				PlugAddToTV ( Message, ICON );
			}
		}
	}
	catch (exception& e ) 
	{
	}
	errmsg.clear();
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

	// 建立socket失败则返回端口开放，等待Mongodb api直接连接，减少漏报
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
