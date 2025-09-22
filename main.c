#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/un.h>

#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "bms_define.h"
#include "cJSON.h"
#include "debug.h"
#include "md5.h"

#define MYSQL_DATABASE "bms"
#define DB_DEVICE_TABLE "bms_web_device"
#define DB_RECORD_TABLE "bms_web_record"

#define UNIX_SOCKET_PATH "/tmp/.bms.sock"
#define RECV_BUF_LEN 2048

MYSQL *g_mysql_conn = NULL; 

/* 已连接设备链表,通过MAC找到对应的设备然后发控制消息 */
struct bms_list *g_cli_head = NULL;

/* 收到的请求操作链表,按照收到的先后顺序入链,同一类型的操作只执行一次 */
struct bms_list *g_web_request_head = NULL;

unsigned int g_mysql_tick = 0;

struct bms_client * find_client(unsigned char *mac)
{
	struct bms_client *cli = NULL;
	struct bms_list *tmp = g_cli_head;
	
	while(tmp){
		cli = (struct bms_client *)tmp;
		if(!strcmp(cli->mac, mac)){
			return cli;
		}
		tmp = tmp->next;
	}

	return NULL;
}

int delete_client(struct bms_client *cli)
{
	

	return 0;
}

void bms_list_init(struct bms_list *head)
{
	if(head == NULL)
		return;

	head->next = NULL;
	head->prev = NULL;

	return;
}

void bms_list_add(struct bms_list **head, struct bms_list *node)
{
	if(node == NULL)
		return;
	
	node->next = *head;
	*head = node;

	return;
}

void bms_list_delete(struct bms_list **head, struct bms_list *node)
{
	struct bms_list *tmp = *head;
	struct bms_list *next;
	
	if(*head == NULL || node == NULL)
		return;
	printf("TXLDebug,%s[%d]:head=%p,node=%p\n", __func__, __LINE__, *head, node);
	if(*head == node){
		tmp = (*head)->next;
		*head = tmp;
		return;
	}

	next = (*head)->next;
	while(next){
		if(next == node){
			tmp->next = next->next;
			break;
		}
		tmp = next;
		next = tmp->next;
	}

	return;
}

void cli_list_free()
{
	struct bms_list *tmp = g_cli_head;
	struct bms_list *node;
	
	while(tmp){
		node = tmp->next;
		free(tmp);
		tmp = node;
	}

	return;
}

void web_list_free()
{
	struct bms_list *tmp = g_web_request_head;
	struct bms_list *node;
	
	while(tmp){
		node = tmp->next;
		free(tmp);
		tmp = node;
	}

	return;
}

void connect_to_mysql(void)
{
	if (mysql_real_connect(
            g_mysql_conn,      // 连接对象
            "localhost",      // 主机名
            //"root",       	// 用户名
            //"hx123456",       // 密码
            "hx",
            "Hx@123456",
            MYSQL_DATABASE,   // 数据库名
            0,                // 端口 (0 表示默认)
            NULL,             // Unix socket (NULL 表示默认)
            0                 // 客户端标志
        ) == NULL) {
        fprintf(stderr, "连接失败: %s\n", mysql_error(g_mysql_conn));
        mysql_close(g_mysql_conn);
        exit(1);
    }
}

static void signal_handler(evutil_socket_t sig, short events, void *user_data)
{
    struct event_base *base = user_data;
    
    switch (sig) {
        case SIGINT:
            printf("Caught SIGINT! Shutting down...\n");
            break;
        case SIGTERM:
            printf("Caught SIGTERM! Shutting down...\n");
            break;
        default:
            printf("Caught signal %d\n", sig);
            return; // 不处理未知信号
    }
    
    // 终止事件循环
    event_base_loopbreak(base);
}

void close_connection(struct bufferevent *bev)
{
    // 1. 禁用所有事件（读/写）
    bufferevent_disable(bev, EV_READ | EV_WRITE);
    
    // 2. 获取底层 socket 并关闭
    evutil_socket_t fd = bufferevent_getfd(bev);
    
    // 3. 释放 bufferevent 资源（会自动关闭 socket）
    bufferevent_free(bev);
    
    // 4. 可选：直接关闭 socket（如果不需要延迟关闭）
    // close(fd); // 通常不需要，bufferevent_free 会处理
}

/* 回复了设备PONG消息之后,剩下的操作(比如:安装、卸载、查询、停用、启动插件等)在on_write中实现 */
void on_write(struct bufferevent *bev, void *ctx)
{
	char *reply = NULL;
	cJSON* root = NULL;
	cJSON* item = NULL;
	char tmp[128] = {0};
	char md5str[33] = {0};
	char query_cmd[1024] = {0};
	unsigned int msg_len = 0;
	unsigned char data[1024] = {0};
	
	struct bms_client *cli = (struct bms_client *)ctx;

	DBG_LOG(DBG_DEBUG, "%s[%d]:write success\n", __func__, __LINE__);

	/* 没有到HB阶段不会下发指令 */
	if(cli->status != AUTH_SUCCESS){
		return;
	}
	switch(cli->method){
		case RPCMETHOD_PLUGIN_INSTALL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			cJSON_AddStringToObject(root, "Version", "Plugin_Version");
			cJSON_AddStringToObject(root, "Download_url", "url");
			cJSON_AddStringToObject(root, "Plugin_size", "size");
			cJSON_AddStringToObject(root, "OS", "Java");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_INSTALL_QUERY:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install_query");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install_query: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_INSTALL_CANCEL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install_cancel");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install_cancel: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_UNINSTALL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "UnInstall");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:UnInstall: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_STOP:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Stop");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Stop: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_RUN:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Run");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Run: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_FACTORY:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "FactoryPlugin");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", "Plugin_Name");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:FactoryPlugin: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			break;
		case RPCMETHOD_PLUGIN_LIST:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "ListPlugin");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:ListPlugin: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;			
			break;
		case RPCMETHOD_HB:
			DBG_LOG(DBG_DEBUG, "RPCMETHOD_HB,ignore\n");
			break;
		default:
			return;
	}

	/* 更新cli中的method为RPCMETHOD_HB,数据库中的localMethod等到收到设备的回复之后再修改,长连接 */
	cli->method = RPCMETHOD_HB;
	
	bufferevent_write(bev, data, msg_len);

	return;
}

int calcMD5(struct bms_client *cli, char *md5str, char *result, int result_len)
{
	struct MD5Context mc;
	unsigned char digest[16]={0};

	MD5Init(&mc);
	MD5Update(&mc, md5str, strlen(md5str));
	MD5Final(digest, &mc);

	for(int i=0; i<16; i++){
		sprintf(result+(i*2), "%02x", digest[i]);
	}

	return 0;
}

int protocol_process(struct bufferevent *bev, struct bms_client *cli, struct bms_device *bms_dev, unsigned char *buf, unsigned int *len)
{
	char *reply = NULL;
	cJSON* root = NULL;
	cJSON* item = NULL;
	cJSON* request = NULL;
	int result = -1;
	char tmp[128] = {0};
	char md5str[33] = {0};
	char query_cmd[1024] = {0};
	unsigned int msg_len = 0;
	unsigned char data[1024] = {0};

	MYSQL_RES *res = NULL;       // 查询结果集
    MYSQL_ROW row;        // 单行数据
	
	if(bev==NULL || cli==NULL || bms_dev==NULL || buf==NULL || len==NULL){
		DBG_LOG(DBG_ERR, "invalid param!\n");
		return -1;
	}
	
	/* 设备发送报文中带RPCMethod字段 */
	if(strlen(bms_dev->rpcMethod)){
		if(!strcmp(bms_dev->rpcMethod, "BootInitiation")){
			srand((unsigned int)time(NULL));
			for(int i=0; i<2; i++){
				sprintf(cli->challenge_code+(i*8), "%08x", rand());
			}
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return -1;
			}

			/* 通过MAC查询record表,如果没有相应的设备则返回-2 */
			memset(query_cmd, 0, sizeof(query_cmd));
			sprintf(query_cmd, "select * from %s where mac = '%s'", DB_RECORD_TABLE, cli->mac);
			if (mysql_query(g_mysql_conn, query_cmd)) {
		        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
				if(root) cJSON_Delete(root);
				return -1;
		    }
			res = mysql_use_result(g_mysql_conn);
			row = mysql_fetch_row(res);
			if(row[1] == NULL){
				result = RESULT_INVALID_INFO;
			}else{
				result = RESULT_SUCCESS;
			}
			mysql_free_result(res);
			res = NULL;
			
			cJSON_AddNumberToObject(root, "Result", result);
			cJSON_AddNumberToObject(root, "ID", bms_dev->session_id);
			cJSON_AddStringToObject(root, "ChallengeCode", cli->challenge_code);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "reply BootInitiation: %s\n", reply);
			msg_len = htonl(strlen(reply));
			memcpy(buf, &msg_len, 4);
			memcpy(buf+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			*len = msg_len;
			cJSON_Delete(root);
		}else if(!strcmp(bms_dev->rpcMethod, "Register")){
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return -1;
			}

			/* 计算MD5值:ChallengeCode+SN+PONPWD,看设备上报的是否正确 */
			if(cli->haswifi){
				sprintf(tmp, "%s%s%s%s%s%s", cli->challenge_code, cli->gponsn, cli->ssid, cli->psk, cli->userpass, cli->password);
			}else{
				sprintf(tmp, "%s%s%s", cli->challenge_code, cli->gponsn, cli->password);
			}
			calcMD5(cli, tmp, md5str, sizeof(md5str));
			if(!strcmp(md5str, bms_dev->CheckGateway)){
				DBG_LOG(DBG_DEBUG, "checkGateway auth success\n");
				cJSON_AddNumberToObject(root, "Result", RESULT_SUCCESS);
				cJSON_AddNumberToObject(root, "ID", bms_dev->session_id);
				/* 计算CheckPlatform: SN+DevRND */
				if(cli->haswifi){
					sprintf(tmp, "%s%s%s%s%s", cli->gponsn, cli->ssid, cli->psk, cli->userpass, bms_dev->DevRND);
				}else{
					sprintf(tmp, "%s%s", cli->gponsn, bms_dev->DevRND);
				}
				calcMD5(cli, tmp, md5str, sizeof(md5str));
				cJSON_AddStringToObject(root, "CheckPlatform", md5str);
				cJSON_AddNumberToObject(root, "Interval", 21600);
			}else{
				DBG_LOG(DBG_DEBUG, "checkGateway(local:%s,remote:%s) auth failed\n", md5str, bms_dev->CheckGateway);
				cJSON_AddNumberToObject(root, "Result", RESULT_INVALID_CHECKGATEWAY);
				cJSON_AddNumberToObject(root, "ID", bms_dev->session_id);
			}
			
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "reply Register: %s\n", reply);
			msg_len = htonl(strlen(reply));
			memcpy(buf, &msg_len, 4);
			memcpy(buf+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			*len = msg_len;
			cJSON_Delete(root);
		}else if(!strcmp(bms_dev->rpcMethod, "Hb")){
			/* 如果没有待执行的操作,关闭连接 */
			if(cli->local_method == RPCMETHOD_NONE){
				DBG_LOG(DBG_DEBUG, "localMethod is RPCMETHOD_NONE,going to close session\n");
				cli->close = 1;
				return 0;
			}
			/* 回复PONG */
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				return -1;
			}
			cJSON_AddNumberToObject(root, "Result", RESULT_SUCCESS);
			cJSON_AddStringToObject(root, "PONG", "PONG");
			cJSON_AddNumberToObject(root, "Interval", cli->heartbeat);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "reply HB: %s\n", reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			
			bufferevent_write(bev, data, msg_len);
			cJSON_Delete(root);
			root = NULL;

			/* 回复PONG之后返回,其他操作放在on_write中 */
			cli->status = AUTH_SUCCESS;
			memset(query_cmd, 0, sizeof(query_cmd));
			sprintf(query_cmd, "update %s set status=1,tr069='%s' where mac = '%s'", DB_DEVICE_TABLE, cli->tr069Addr, cli->mac);
			if (mysql_query(g_mysql_conn, query_cmd)) {
		        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
				return -1;
		    }
			/* 如果是短连接,在回复了一个heartbeat之后下一次收到HB直接关闭连接 */
			if(cli->isShortConn && cli->local_method == RPCMETHOD_HB){
				cli->local_method = RPCMETHOD_NONE;
			}
		}
	}
	/* 设备发送报文中不带RPCMethod字段 */
	else{
		DBG_LOG(DBG_DEBUG, "recv pkt,localMethod=%d\n", cli->local_method);
		if(cli->session_id != bms_dev->session_id){
			DBG_LOG(DBG_WARN, "session id invalid!\n");
			return -1;
		}
		if(cli->web == NULL || cli->web->method != cli->local_method){
			return 0;
		}
		switch(cli->local_method){
			case RPCMETHOD_PLUGIN_INSTALL:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_INSTALL_QUERY:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				item = cJSON_GetObjectItem(request, "Percent");
				if(item){
					cJSON_AddNumberToObject(root, "Percent", item->valueint);
				}
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_INSTALL_CANCEL:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_UNINSTALL:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_STOP:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_RUN:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_FACTORY:
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				reply = cJSON_PrintUnformatted(root);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			case RPCMETHOD_PLUGIN_LIST:
				DBG_LOG(DBG_DEBUG, "get plugin list\n");
				request = cJSON_Parse(buf+4);
				item = cJSON_GetObjectItem(request, "Result");
				if(item){
					result = item->valueint;
				}
				root = cJSON_CreateObject();
				if (root == NULL) {
					DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
					return -1;
				}
				cJSON_AddNumberToObject(root, "result", result);
				cJSON_AddNumberToObject(root, "ID", cli->web->session_id);
				item = cJSON_GetObjectItem(request, "Plugin");
				if(item){
					cJSON_DetachItemFromObject(request, "Plugin");
					cJSON_AddItemToObject(root, "Plugin", item);
					char *pluginlist = cJSON_PrintUnformatted(item);
					DBG_LOG(DBG_DEBUG, "%s[%d]:pluginlist:%s\n", __func__, __LINE__, pluginlist);
					memset(query_cmd, 0, sizeof(query_cmd));
					sprintf(query_cmd, "update %s set pluginList='%s' where mac='%s'", DB_DEVICE_TABLE, pluginlist, cli->mac);
					DBG_LOG(DBG_DEBUG, "%s[%d]:query_cmd:%s\n", __func__, __LINE__, query_cmd);
					if (mysql_query(g_mysql_conn, query_cmd)) {
				        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
						return -1;
				    }
				}
				reply = cJSON_PrintUnformatted(root);
				
				DBG_LOG(DBG_DEBUG, "%s[%d]:reply to web:%s\n", __func__, __LINE__, reply);
				if(cli->web && cli->web->bev){
					bufferevent_write(cli->web->bev, reply, strlen(reply));
				}
				cJSON_Delete(root);
				cJSON_Delete(request);
				break;
			default:
				break;
		}
		/* 更新localMethod为RPCMETHOD_HB,长连接 */
		cli->method = RPCMETHOD_HB;
		/* 如果是短连接,下一次收到HB的时候直接关闭连接 */
		if(cli->isShortConn){
			cli->local_method = RPCMETHOD_NONE;
		}else{
			cli->local_method = RPCMETHOD_HB;
		}

		cli->pendding = 0;
		cli->web->active = 0;
		cli->web = NULL;
#if 0
		memset(data, 0, sizeof(data));
		sprintf(data, "update device set localMethod=%d where mac='%s'", cli->method, cli->mac);
		if (mysql_query(g_mysql_conn, data)) {
	        DBG_LOG(DBG_ERR, "mysql_query failed: %s\n", mysql_error(g_mysql_conn));
			return -1;
	    }
#endif
	}

	return 0;
}

// 数据读取回调
void on_read(struct bufferevent *bev, void *ctx)
{
	int ret = 0;
	int count = 0;
	cJSON* request = NULL;
	cJSON* root = NULL;
	cJSON* item = NULL;
	char* reply = NULL;
	char query_cmd[1024] = {0};
	unsigned int msg_len = 0;
	unsigned char mac[6] = {0};	
	struct bms_device device = {0};
	unsigned char *data = NULL;
	unsigned char recv_buf[RECV_BUF_LEN] = {0};

	MYSQL_RES *res = NULL;       // 查询结果集
    MYSQL_ROW row;        // 单行数据

	struct bms_client *cli = (struct bms_client *)ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);
    
	/* 报文结构: msg_len + payload, 其中msg_len长度为4字节(big endian),指示payload的长度 */
	/* 检查报文是否完整:报文太大时可能分片了; 将最开始四个字节拷贝出来 */
	if(len < 4) return;

	evbuffer_copyout(input, &msg_len, sizeof(msg_len));
	msg_len = ntohl(msg_len);
	if(len < msg_len+sizeof(msg_len)){
		DBG_LOG(DBG_DEBUG, "msg not completed,return!\n");
		return;
	}

	if(len <= RECV_BUF_LEN){
		data = recv_buf;
	}else{
		data = malloc(len);
	}
    evbuffer_remove(input, data, len);
	DBG_LOG(DBG_DEBUG, "recv message(len=%d):%s!\n", msg_len, data+4);	

	request = cJSON_Parse(data+4);
	if(request){
		item = cJSON_GetObjectItem(request, "RPCMethod");
		if(item){
			DBG_LOG(DBG_DEBUG, "RPCMethod:%s\n", item->valuestring);
			strncpy(device.rpcMethod, item->valuestring, sizeof(device.rpcMethod));
		}

		item = cJSON_GetObjectItem(request, "ID");
		if(item){
			DBG_LOG(DBG_DEBUG, "ID:%d\n", item->valueint);
			device.session_id = item->valueint;
		}
		
		item = cJSON_GetObjectItem(request, "MAC");
		if(item){
			DBG_LOG(DBG_DEBUG, "MAC:%s\n", item->valuestring);
			strncpy(device.mac, item->valuestring, sizeof(device.mac));
		}

		item = cJSON_GetObjectItem(request, "BootType");
		if(item){
			DBG_LOG(DBG_DEBUG, "BootType:%d\n", item->valueint);
			device.boot_type = item->valueint;		
		}

		item = cJSON_GetObjectItem(request, "CheckGateway");
		if(item){
			DBG_LOG(DBG_DEBUG, "CheckGateway:%s\n", item->valuestring);
			strncpy(device.CheckGateway, item->valuestring, sizeof(device.CheckGateway));
		}

		item = cJSON_GetObjectItem(request, "DevRND");
		if(item){
			DBG_LOG(DBG_DEBUG, "DevRND:%s\n", item->valuestring);
			strncpy(device.DevRND, item->valuestring, sizeof(device.DevRND));
		}

		item = cJSON_GetObjectItem(request, "TR069Address");
		if(item){
			DBG_LOG(DBG_DEBUG, "TR069Address:%s\n", item->valuestring);
			strncpy(device.tr069Addr, item->valuestring, sizeof(device.tr069Addr));
			strncpy(cli->tr069Addr, item->valuestring, sizeof(cli->tr069Addr));
		}

		cJSON_Delete(request);
	}

	/* 如果消息中未包含MAC字段,且cli中未记录此连接对应设备的MAC,则认为报文无效,直接返回 */
	if(0 == strlen(device.mac) && 0 == strlen(cli->mac)) goto __exit__;

	if(0 == strlen(cli->mac)){
		/* 在record表中查询是否存在此设备,若不存在返回-2 */
	__retry__:
		sprintf(query_cmd, "select * from %s where mac = '%s'", DB_RECORD_TABLE, device.mac);
	    if (ret = mysql_query(g_mysql_conn, query_cmd)) {
	        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
			if((ret == ER_CLIENT_INTERACTION_TIMEOUT || ret == CR_SERVER_LOST) && count < 3){
				count++;
				mysql_close(g_mysql_conn);
				connect_to_mysql();
				DBG_LOG(DBG_DEBUG, "retry mysql_query\n");
				goto __retry__;
			}
			goto __exit__;
	    }
		g_mysql_tick = 0;

	    res = mysql_use_result(g_mysql_conn);
		row = mysql_fetch_row(res);
	    if (row == NULL) {
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				goto __exit__;
			}
			cJSON_AddNumberToObject(root, "Result", RESULT_INVALID_INFO);
			cJSON_AddNumberToObject(root, "ID", device.session_id);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "device not invlaid:res=%p,reply: %s\n", res, reply);
			memset(data, 0, len+1);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);

			cJSON_Delete(root);
			goto __reply__;
		}else{
			/* 只有在record表中存在的设备才会记录MAC */
			if(row[1]) strncpy(cli->mac, row[1], sizeof(cli->mac));
			if(row[2]) strncpy(cli->gponsn, row[2], sizeof(cli->gponsn));
			if(row[3]) strncpy(cli->ssid, row[3], sizeof(cli->ssid));
			if(row[4]) strncpy(cli->psk, row[4], sizeof(cli->psk));
			if(row[5]) strncpy(cli->userpass, row[5], sizeof(cli->userpass));
			if(row[6]) strncpy(cli->password, row[6], sizeof(cli->password));			
			if(row[7]) cli->haswifi = atoi(row[7]);
			if(row[8]) strncpy(cli->province, row[8], sizeof(cli->province));
			if(row[9]) cli->isShortConn = atoi(row[9]);
			if(row[10]) cli->heartbeat = atoi(row[10]);
			cli->local_method = RPCMETHOD_HB;
			if(g_cli_head == NULL){
				g_cli_head = &cli->cli_list;
			}else{
				bms_list_add(&g_cli_head, &cli->cli_list);
			}
		}
		mysql_free_result(res);
		res = NULL;
	}
#if 0
	/* 在device表中查询是否存在此设备,若不存在则添加 */	
	memset(query_cmd, 0, sizeof(query_cmd));
	sprintf(query_cmd, "select * from %s where mac = '%s'", DB_DEVICE_TABLE, cli->mac);
	if (mysql_query(g_mysql_conn, query_cmd)) {
        DBG_LOG(DBG_DEBUG, "mysql_query failed: %s\n", mysql_error(g_mysql_conn));
		goto __exit__;
    }

    res = mysql_use_result(g_mysql_conn);
	row = mysql_fetch_row(res);
	if(row == NULL){
		mysql_free_result(res);
		res = NULL;
		if(!strcmp(device.rpcMethod, "BootInitiation")){
			DBG_LOG(DBG_DEBUG, "device not existed,add it!\n");
			sprintf(query_cmd, "insert into %s (mac,session_id,RPCMethod,localMethod) values('%s',%d,'%s',%d);", DB_DEVICE_TABLE, device.mac, device.session_id, device.rpcMethod, RPCMETHOD_HB);
			if (mysql_query(g_mysql_conn, query_cmd)) {
		        DBG_LOG(DBG_DEBUG, "mysql_query add device failed: %s\n", mysql_error(g_mysql_conn));
				goto __exit__;
		    }
		}else{
			/* 当设备初次注册时,只处理BootInitiation事件 */
			goto __exit__;
		}
	}else{
		/* 当设备存在时,更新相关字段 */
		mysql_free_result(res);
		res = NULL;
		if(!strcmp(device.rpcMethod, "BootInitiation") || !strcmp(device.rpcMethod, "Register")){
			DBG_LOG(DBG_DEBUG, "device existed,update it!\n");
			sprintf(query_cmd, "update %s set session_id=%d, RPCMethod='%s', tr069Addr='%s' where mac='%s';", DB_DEVICE_TABLE, device.session_id, device.rpcMethod, device.tr069Addr, device.mac);
			if (mysql_query(g_mysql_conn, query_cmd)) {
		        DBG_LOG(DBG_DEBUG, "mysql_query update device failed: %s\n", mysql_error(g_mysql_conn));
				goto __exit__;
		    }
		}else{
			sprintf(query_cmd, "select * from %s where mac = '%s'", DB_DEVICE_TABLE, cli->mac);
			if (mysql_query(g_mysql_conn, query_cmd)) {
		        DBG_LOG(DBG_DEBUG, "mysql_query failed: %s\n", mysql_error(g_mysql_conn));
				goto __exit__;
		    }
			res = mysql_use_result(g_mysql_conn);
			row = mysql_fetch_row(res);
			if(row[8]){
				device.localMethod = atoi(row[8]);
				DBG_LOG(DBG_DEBUG, "from DB(row[8]=%s),localMethod=%d!\n", row[8], device.localMethod);
			}
		}
	}

	if(res) mysql_free_result(res);
#endif

	/* 处理协议报文 */
	msg_len = 0;
	if(0 > protocol_process(bev, cli, &device, data, &msg_len)){
		goto __exit__;
	
	}

__reply__:
	if(cli->close){
		cli->bev = NULL;
		memset(query_cmd, 0, sizeof(query_cmd));
		sprintf(query_cmd, "update %s set status=0 where mac = '%s'", DB_DEVICE_TABLE, cli->mac);
		if (mysql_query(g_mysql_conn, query_cmd)) {
	        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
	    }
		
		close_connection(bev);
		bms_list_delete(&g_cli_head, &cli->cli_list);
		free(cli);		
	}else if(msg_len > 0){
    	bufferevent_write(bev, data, msg_len);
	}
	
__exit__:
	if(len > RECV_BUF_LEN && data)
    	free(data);

	return;
}

// 错误处理
void on_error(struct bufferevent *bev, short events, void *ctx)
{
	char query_cmd[1024] = {0};
	BMS_CLIENT_T *cli = (BMS_CLIENT_T*)ctx;
	DBG_LOG(DBG_DEBUG, "%s[%d]: ctx=%p, event=0x%X!\n", __func__, __LINE__, ctx, events);
	
    if (events & BEV_EVENT_ERROR || events & BEV_EVENT_EOF) {
        close_connection(bev);
		sprintf(query_cmd, "update %s set status=0 where mac = '%s'", DB_DEVICE_TABLE, cli->mac);
		if (mysql_query(g_mysql_conn, query_cmd)) {
	        DBG_LOG(DBG_DEBUG, "%s[%d]:mysql_query failed: %s\n", __func__, __LINE__, mysql_error(g_mysql_conn));
	    }
		bms_list_delete(&g_cli_head, &cli->cli_list);
		free(cli);
    }
}

// 连接回调
void on_connect(struct evconnlistener *listener, evutil_socket_t fd,
                struct sockaddr *addr, int socklen, void *ctx)
{
	char host[64] = {0};
	struct sockaddr_in *inaddr = NULL;
    struct event_base *base = evconnlistener_get_base(listener);

	if(addr->sa_family == AF_INET){
		inaddr = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &inaddr->sin_addr, host, sizeof(host));
		DBG_LOG(DBG_DEBUG, "Welcome %s!\n", host);
	}
	
    // 创建 bufferevent 管理连接
    struct bufferevent *bev = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE);

	struct bms_client *cli = malloc(sizeof(struct bms_client));
	if(cli == NULL){
		DBG_LOG(DBG_ERR, "malloc cli failed!\n");
		bufferevent_free(bev);
		return;
	}
	memset(cli, 0, sizeof(struct bms_client));
	cli->bev = bev;
	memcpy(&cli->client_addr, addr, sizeof(struct sockaddr));
	
    // 设置读写回调
    bufferevent_setcb(bev, on_read, on_write, on_error, cli);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void unix_read(struct bufferevent *bev, void *ctx)
{
	cJSON* request = NULL;
	cJSON* root = NULL;
	cJSON* item = NULL;
	cJSON* temp = NULL;
	char *reply = NULL;
	char message[32] = {0};
	unsigned int msg_len = 0;
	unsigned char mac[6] = {0};
	BMS_WEB_REQUEST_T *web_req = NULL;
	unsigned char data[RECV_BUF_LEN] = {0};

    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);

    evbuffer_remove(input, data, len);
	DBG_LOG(DBG_DEBUG, "recv message(len=%d):%s!\n", len, data);	

	web_req = (BMS_WEB_REQUEST_T*)ctx;
	
	request = cJSON_Parse(data);
	if(request){
		item = cJSON_GetObjectItem(request, "RPCMethod");
		if(item){
			DBG_LOG(DBG_DEBUG, "RPCMethod:%s\n", item->valuestring);
			if(!strcmp(item->valuestring, "Install")){
				web_req->method = RPCMETHOD_PLUGIN_INSTALL;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));

				temp = cJSON_GetObjectItem(request, "Version");
				if(temp == NULL){
					strncpy(message, "Invalid Version", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_version, temp->valuestring, sizeof(web_req->plugin_version));

				temp = cJSON_GetObjectItem(request, "Download_url");
				if(temp == NULL){
					strncpy(message, "Invalid Download_url", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->url, temp->valuestring, sizeof(web_req->url));

				temp = cJSON_GetObjectItem(request, "Plugin_size");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_size", sizeof(message));
					goto __error__;
				}
				web_req->plugin_size = temp->valueint;
			}else if(!strcmp(item->valuestring, "Install_query")){
				web_req->method = RPCMETHOD_PLUGIN_INSTALL_QUERY;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "Install_cancel")){
				web_req->method = RPCMETHOD_PLUGIN_INSTALL_CANCEL;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "UnInstall")){
				web_req->method = RPCMETHOD_PLUGIN_UNINSTALL;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "Stop")){
				web_req->method = RPCMETHOD_PLUGIN_STOP;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "Run")){
				web_req->method = RPCMETHOD_PLUGIN_RUN;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "FactoryPlugin")){
				web_req->method = RPCMETHOD_PLUGIN_FACTORY;
				temp = cJSON_GetObjectItem(request, "Plugin_Name");
				if(temp == NULL){
					strncpy(message, "Invalid Plugin_Name", sizeof(message));
					goto __error__;
				}
				strncpy(web_req->plugin_name, temp->valuestring, sizeof(web_req->plugin_name));
			}else if(!strcmp(item->valuestring, "ListPlugin")){
				web_req->method = RPCMETHOD_PLUGIN_LIST;
			}else{
				DBG_LOG(DBG_DEBUG, "invalid RPCMethod:%s\n", item->valuestring);
			}
		}

		item = cJSON_GetObjectItem(request, "ID");
		if(item == NULL){
			strncpy(message, "Invalid ID", sizeof(message));
			goto __error__;
		}
		DBG_LOG(DBG_DEBUG, "ID:%d\n", item->valueint);
		web_req->session_id = item->valueint;
		
		item = cJSON_GetObjectItem(request, "MAC");
		if(item == NULL){
			strncpy(message, "Invalid MAC", sizeof(message));
			goto __error__;
		}
		DBG_LOG(DBG_DEBUG, "MAC:%s\n", item->valuestring);
		strncpy(web_req->mac, item->valuestring, sizeof(web_req->mac));		
	}

	if(web_req->method == RPCMETHOD_NONE){
		strncpy(message, "Invalid RPCMethod", sizeof(message));
		goto __error__;
	}
	cJSON_Delete(request);

	if(g_web_request_head == NULL){
		g_web_request_head = &web_req->web_list;
	}else{
		bms_list_add(&g_web_request_head, &web_req->web_list);
	}
	DBG_LOG(DBG_DEBUG, "add web_list success(addr:%p,%p)\n", web_req, g_web_request_head);
	return;

__error__:
	if(request) cJSON_Delete(request);

	root = cJSON_CreateObject();
	if(root){
		memset(data, 0, sizeof(data));
		if(web_req)
			cJSON_AddNumberToObject(root, "ID", web_req->session_id);
		else
			cJSON_AddNumberToObject(root, "ID", -1);
		cJSON_AddNumberToObject(root, "result", -1);
		cJSON_AddStringToObject(root, "message", message);
		reply = cJSON_PrintUnformatted(root);
		msg_len = strlen(reply);		
		strcpy(data, reply);
		printf("33333333333:%s,msg_len=%d\n", data, msg_len);
		bufferevent_write(bev, reply, strlen(reply));
		cJSON_Delete(root);
	}else{
		bufferevent_write(bev, "{'result':-1}", 13);
	}
	
	bufferevent_free(bev);
	if(web_req) free(web_req);

	return;
}

void unix_write(struct bufferevent *bev, void *ctx)
{
	DBG_LOG(DBG_DEBUG, "%s[%d]: ctx=%p, response to web!\n", __func__, __LINE__, ctx);
}

void unix_error(struct bufferevent *bev, short events, void *ctx)
{
	struct bms_client * cli = NULL;
	BMS_WEB_REQUEST_T *web = (BMS_WEB_REQUEST_T *)ctx;
	
	DBG_LOG(DBG_DEBUG, "%s[%d]: ctx=%p, event=0x%X!\n", __func__, __LINE__, ctx, events);
	
    if (events & BEV_EVENT_ERROR || events & BEV_EVENT_EOF) {
        close_connection(bev);
		bms_list_delete(&g_web_request_head, &web->web_list);
		if(cli = find_client(web->mac)){
			cli->web = NULL;
		}
		free(web);
    }
}

void unix_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx)
{
	BMS_WEB_REQUEST_T *web = NULL;
	
	DBG_LOG(DBG_DEBUG, "New Unix domain connection!\n");
	
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	web = malloc(sizeof(BMS_WEB_REQUEST_T));
	if(web == NULL){
		DBG_LOG(DBG_ERR, "malloc cli failed!\n");
		bufferevent_free(bev);
		return;
	}
	memset(web, 0, sizeof(BMS_WEB_REQUEST_T));
	web->bev = bev;
	web->active = 1;
	
	bufferevent_setcb(bev, unix_read, unix_write, unix_error, web);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// 定时器回调函数
void periodic_timer_callback(evutil_socket_t fd, short what, void *arg)
{
	char *reply = NULL;
	cJSON* root = NULL;
	cJSON* item = NULL;
	char tmp[128] = {0};
	char md5str[33] = {0};
	unsigned int msg_len = 0;
	unsigned char data[1024] = {0};
	BMS_CLIENT_T *cli = NULL;
	BMS_WEB_REQUEST_T *node = NULL;
	BMS_WEB_REQUEST_T *temp = NULL;
	struct bms_list *cli_list = NULL;
	struct bms_list *head = g_web_request_head;

	//DBG_LOG(DBG_DEBUG, "%s[%d]:timer!\n", __func__, __LINE__);
	while(head){
		temp = (BMS_WEB_REQUEST_T *)head;
		/* 跳过已处理的和正在处理的 */
		if(temp->active == 0 || temp->active == 2){
			head = head->next;
			continue;
		}
		/* 记录第一个未处理的请求 */
		else if(node == NULL){
			DBG_LOG(DBG_TRACE, "%s[%d]:find node(addr:%p,MAC:%s)!\n", __func__, __LINE__, temp,temp->mac);
			cli_list = g_cli_head;
			while(cli_list){
				cli = (BMS_CLIENT_T *)cli_list;
				DBG_LOG(DBG_DEBUG, "[%s %d]:find first request,mac=%s,method=%d!\n", __func__, __LINE__, temp->mac, temp->method);
				if(!strcmp(temp->mac, cli->mac)){
					DBG_LOG(DBG_DEBUG, "[%s %d]:find first request,mac=%s,pendding=%d!\n", __func__, __LINE__, temp->mac, cli->pendding);
					/* 如果该设备有正在处理的请求(超时时间为10秒),则继续处理下一个请求 */
					if(cli->pendding > 0 && cli->pendding < 10){
						cli->pendding++;
						cli_list = NULL;
					}
					break;
				}
				cli_list = cli_list->next;
			}
			/* 检查MAC对应的设备是否能处理请求,不能则继续处理下一个请求 */
			if(cli_list == NULL){
				head = head->next;
				continue;
			}
			
			node = temp;
			node->active = 2;

			cli->web = node;
			cli->pendding = 1;
		}else{
			/* 同一个设备相同的请求只处理一次 */
			if(!strcmp(node->mac, temp->mac) && temp->method == node->method){
				temp->active = 2;
			}
		}
		head = head->next;
	}

	if(node == NULL || cli == NULL || cli->bev == NULL) goto __exit__;
	DBG_LOG(DBG_DEBUG, "[%s %d]:mac=%s!\n", __func__, __LINE__, node->mac);
	cli->local_method = node->method;
	switch(cli->local_method){
		case RPCMETHOD_PLUGIN_INSTALL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			cJSON_AddStringToObject(root, "Version", node->plugin_version);
			cJSON_AddStringToObject(root, "Download_url", node->url);
			cJSON_AddNumberToObject(root, "Plugin_size", node->plugin_size);
			cJSON_AddStringToObject(root, "OS", "0");
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_INSTALL_QUERY:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install_query");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install_query: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_INSTALL_CANCEL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Install_cancel");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Install_cancel: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_UNINSTALL:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "UnInstall");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:UnInstall: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_STOP:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break ;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Stop");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Stop: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_RUN:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "Run");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:Run: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_PLUGIN_FACTORY:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "FactoryPlugin");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			cJSON_AddStringToObject(root, "Plugin_Name", node->plugin_name);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:FactoryPlugin: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			break;
		case RPCMETHOD_PLUGIN_LIST:
			cli->session_id++;
			root = cJSON_CreateObject();
			if (root == NULL) {
				DBG_LOG(DBG_ERR, "[%s %d]:malloc json object failed , leave!\n", __func__, __LINE__);
				break;
			}
			cJSON_AddStringToObject(root, "RPCMethod", "ListPlugin");
			cJSON_AddNumberToObject(root, "ID", cli->session_id);
			reply = cJSON_PrintUnformatted(root);
			DBG_LOG(DBG_DEBUG, "%s[%d]:ListPlugin: %s\n", __func__, __LINE__, reply);
			msg_len = htonl(strlen(reply));
			memcpy(data, &msg_len, 4);
			memcpy(data+4, reply, strlen(reply));
			msg_len = 4+strlen(reply);
			cJSON_Delete(root);
			root = NULL;
			break;
		case RPCMETHOD_HB:
			DBG_LOG(DBG_DEBUG, "RPCMETHOD_HB,ignore\n");
			break;
		default:
			break;
	}

	if(msg_len > 0){
		bufferevent_write(cli->bev, data, msg_len);
	}

__exit__:
	/* 判断是否需要向数据库发送ping保活 */
	if(g_mysql_tick++ >= 21600){
		g_mysql_tick = 0;
		mysql_ping(g_mysql_conn);
		DBG_LOG(DBG_DEBUG, "[%s %d]:send PING to mysql server!\n", __func__, __LINE__);
	}

	return;
}


int main(int argc, char **argv)
{
	MYSQL_RES *res;       // 查询结果集
    MYSQL_ROW row;        // 单行数据
    
	// 1. 初始化连接对象
    g_mysql_conn = mysql_init(NULL);
    if (g_mysql_conn == NULL) {
        fprintf(stderr, "mysql_init() 失败\n");
        exit(1);
    }

    // 2. 连接到数据库
    if (mysql_real_connect(
            g_mysql_conn,      // 连接对象
            "localhost",      // 主机名
            //"root",       	// 用户名
            //"hx123456",       // 密码
            "hx",
            "Hx@123456",
            MYSQL_DATABASE,   // 数据库名
            0,                // 端口 (0 表示默认)
            NULL,             // Unix socket (NULL 表示默认)
            0                 // 客户端标志
        ) == NULL) {
        fprintf(stderr, "连接失败: %s\n", mysql_error(g_mysql_conn));
        mysql_close(g_mysql_conn);
        exit(1);
    }
	DBG_LOG(DBG_DEBUG, "成功连接到 MySQL 数据库！\n");

	unsigned timeout = 5;
	mysql_options(g_mysql_conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

	/* 启动时将所有Device的status字段置为0 */
	if (mysql_query(g_mysql_conn, "UPDATE "DB_DEVICE_TABLE" SET status=0;")) {
        fprintf(stderr, "复位失败: %s\n", mysql_error(g_mysql_conn));
    }
	
#if 0
	// 查询数据
    if (mysql_query(g_mysql_conn, "SELECT * FROM "DB_DEVICE_TABLE)) {
        fprintf(stderr, "查询失败: %s\n", mysql_error(g_mysql_conn));
    }

	// 获取结果集
    res = mysql_use_result(g_mysql_conn);
    if (res == NULL) {
        fprintf(stderr, "获取结果集失败: %s\n", mysql_error(g_mysql_conn));
    }
    
    // 处理结果
    DBG_LOG(DBG_DEBUG, "查询结果:\n");
    DBG_LOG(DBG_DEBUG, "%-14s %-18s %-10s %-10s %-34s %-18s %-7s %-12s %s\n", "MAC", "RPCMethod", "session_id", "boot_type", "CheckGateway", "DevRND", "status", "localMethod", "tr069Addr");
    DBG_LOG(DBG_DEBUG, "------------------------------------------------------------------------------------------------------\n");
    
    while (row = mysql_fetch_row(res)) {
        DBG_LOG(DBG_DEBUG, "%-14s %-18s %-10s %-10s %-34s %-18s %-7s %-12s %s\n", 
               row[0] ? row[0] : "NULL", 
               row[1] ? row[1] : "NULL", 
               row[2] ? row[2] : "NULL",
               row[3] ? row[3] : "NULL", 
               row[4] ? row[4] : "NULL", 
               row[5] ? row[5] : "NULL",
               row[6] ? row[6] : "NULL",
               row[8] ? row[8] : "NULL",
               row[7] ? row[7] : "NULL");
    }
	// 清理资源
	mysql_free_result(res);
#endif
    struct event_base *base = event_base_new();

	// 创建周期性定时器（每隔1秒触发一次）
	struct timeval periodic_delay = {1, 0}; // 1秒
	struct event *periodic_timer = event_new(base, -1, EV_PERSIST, periodic_timer_callback, NULL);	
	if (!periodic_timer) {
		fprintf(stderr, "无法创建周期性定时器\n");
		return EXIT_FAILURE;
	}
	event_add(periodic_timer, &periodic_delay);

	struct event *sigint_event = evsignal_new(base, SIGINT, signal_handler, base);
	if (event_add(sigint_event, NULL)) {
        fprintf(stderr, "Could not add signal events!\n");
        goto __exit__;
    }
	
    // 创建监听器
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(9010),
        .sin_addr.s_addr = INADDR_ANY
    };
    struct evconnlistener *listener = evconnlistener_new_bind(
        base, on_connect, NULL,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
        (struct sockaddr*)&sin, sizeof(sin));


	/* 监听一个域套接字 */
	unlink(UNIX_SOCKET_PATH);
	struct sockaddr_un unix_addr;
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strncpy(unix_addr.sun_path, UNIX_SOCKET_PATH, sizeof(unix_addr.sun_path) - 1);
    
    struct evconnlistener *unix_listener = evconnlistener_new_bind(
        base, 
        unix_accept, 
        "unix", // 传递类型标识
        LEV_OPT_CLOSE_ON_FREE, 
        -1,
        (struct sockaddr*)&unix_addr,
        sizeof(unix_addr)
    );

	if(listener==NULL || unix_listener==NULL){
		fprintf(stderr, "Could not create listener: %s\n", strerror(errno));
		goto __exit__;
	}
		
    event_base_dispatch(base); // 启动事件循环

__exit__:
	DBG_LOG(DBG_DEBUG, "exit,release resource\n");
	if(periodic_timer)
		event_free(periodic_timer);

	if(sigint_event)
		event_free(sigint_event);
	
	if(listener)
		evconnlistener_free(listener);

	if(unix_listener)
		evconnlistener_free(unix_listener);

	if(base)
		event_base_free(base);
	
	mysql_close(g_mysql_conn);
	
    return 0;
}

