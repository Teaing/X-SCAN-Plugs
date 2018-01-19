# X-SCAN-Plugs
X-SCAN Plugs  
1、MYSQL弱口令扫描  
2、MONGODB未授权扫描  

X-SCAN下载：  
http://www.xfocus.net/tools/200507/1057.html  

SDK:  
http://www.xfocus.net/projects/X-Scan/index.html  

已经存在的插件:  
DComRpc.xpn  
提交用户：hhkk  
http://www.xfocus.net/tools/200307/488.html  

Crack_MySQL.cpp  
提交用户：ph4_yunshu  
http://www.xfocus.net/tools/200609/1188.html  

站长大牛的肩上ph4_yunshu  

Crack_Mysql插件:  
Crack_Mysql.cpp插件代码是在ph4_yunshu的基础上面稍微改动编译通过的  
Crack_Mysql.cpp 编译以及扫描的时候都需要libmySQL.dll文件  
Crack_Mysql源码机器编译好的插件及其libmySQL.dll  
http://yunpan.cn/cZEMIp5SkkcKJ （提取码：a280）  
用户名字典：  
dat\\mysql_user.dic  
密码字典：  
dat\\mysql_pass.dic  
libmySQL.dll放扫描器目录  

Scan_Mongodb插件:  
Scan_Mongodb.cpp插件代码里面没有类似conn.close()这种代码,写的时候都没找到有调用，如有其他方法，请告知。  
PS:所以用了"#define	TIMEOUT				10000"扫描超时进行退出  
Scan_Mongodb.cpp 编译以及扫描的时候都需要mongoclient.dll文件  
Scan_Mongodb源码机器编译好的插件及其mongoclient.dll  
http://yunpan.cn/cZEkM7Yt2LKV7 （提取码：d43f）  
