#ifndef __BMS_DEFINE_H__
#define __BMS_DEFINE_H__



struct bms_list {
	struct bms_list *next;
	struct bms_list *prev;
};


enum {
	RPCMETHOD_NONE = 0,
	RPCMETHOD_HB,
	RPCMETHOD_PLUGIN_INSTALL,
	RPCMETHOD_PLUGIN_INSTALL_QUERY,
	RPCMETHOD_PLUGIN_INSTALL_CANCEL,
	RPCMETHOD_PLUGIN_UNINSTALL,
	RPCMETHOD_PLUGIN_STOP,
	RPCMETHOD_PLUGIN_RUN,
	RPCMETHOD_PLUGIN_FACTORY,
	RPCMETHOD_PLUGIN_LIST
};

enum {
	AUTH_NONE = 0,
	AUTH_BOOT,
	AUTH_REGISTER,
	AUTH_SUCCESS
};

struct bms_device {
	unsigned char localMethod;
	char mac[18];
	char rpcMethod[32];
	int session_id;
	int boot_type;
	int status;
	char CheckGateway[34];
	char DevRND[18];
	char tr069Addr[128];
};

typedef struct bms_client {
	struct bms_list cli_list;
	char mac[18];
	unsigned char close;
	unsigned char status;	
	unsigned char method;
	unsigned char haswifi;
	unsigned char pendding;
	unsigned char local_method;	//本地method, 记录web传过来的method
	unsigned char isShortConn;
	int heartbeat;
	int session_id;
	struct sockaddr client_addr;
	char challenge_code[18];
	char gponsn[14];
	char ssid[10];
	char psk[16];
	char userpass[16];
	char password[34];
	char province[8];
	char tr069Addr[128];

	struct bufferevent *bev;
	struct bms_web_request *web;
}BMS_CLIENT_T,*BMS_CLIENT_Tp;

typedef struct bms_web_request {
	struct bms_list web_list;
	char mac[18];
	char plugin_name[48];
	char plugin_version[16];
	char url[128];
	unsigned char active;	//0: 已处理的, 1: 待处理, 2: 已向设备发送请求
	unsigned char method;
	int plugin_size;
	int session_id;

	struct bufferevent *bev;
}BMS_WEB_REQUEST_T,*BMS_WEB_REQUEST_Tp;


#define RESULT_SUCCESS 0
#define RESULT_RETRY_DNS (-1)
#define RESULT_INVALID_INFO (-2)
#define RESULT_API_ERR (-3)
#define RESULT_INVALID_PASSWORD (-4)
#define RESULT_INVALID_CHECKGATEWAY (-5)
#define RESULT_NEED_REAUTH (-6)
#define RESULT_FAIL (-7)
#define RESULT_INVALID_DEVICE (-8)
#define RESULT_INSTALL_TASK_NOT_EXISTED (-101)
#define RESULT_PLUGIN_SIGN_INVALID (-102)
#define RESULT_DOWNLOAD_URL_UNREACHABLE (-103)
#define RESULT_NO_SPACE (-104)
#define RESULT_NO_SPACE (-104)
#define RESULT_BUSY (-105)
#define RESULT_INVALID_VERSION (-106)
#define RESULT_INVALID_SYSTEM (-107)
#define RESULT_NEED_REBOOT (-108)
#define RESULT_DOWNLOAD_FAILED (-109)
#define RESULT_PLUGIN_START_FAILED (-110)
#define RESULT_PLUGIN_INSTALLED (-111)
#define RESULT_PLUGIN_NOT_EXISTED (-112)
#define RESULT_PLUGIN_CANOT_STOP (-113)
#define RESULT_CANOT_FORBID (-114)
#define RESULT_PLUGIN_INSTALL_FAILED (-117)
#define RESULT_HEARBEAT_TIME_CONFIG_FAIL (-118)
#define RESULT_PLUGIN_CANOT_UNINSTALL (-119)
#define RESULT_PLUGIN_ALREADY_RUNNING (-120)
#define RESULT_PLUGIN_RETURN_FORBID_FAIL (-198)
#define RESULT_PLUGIN_PROC_TIMEOUT_STOP (-199)
#define RESULT_OTHER (-200)


#endif

