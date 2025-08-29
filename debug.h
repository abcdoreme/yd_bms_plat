#ifndef __BMS_DEBUG_H__
#define __BMS_DEBUG_H__
enum{
		DBG_ERR=0,
		DBG_WARN,
		DBG_INFO,
		DBG_DEBUG,
        DBG_TRACE
};

void DBG_LOG(int level, const char *fmt, ...);
#endif

