#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include "debug.h"

void DBG_LOG(int level, const char *fmt, ...)
{
        va_list va;
        if(level > DBG_DEBUG) return;

        va_start(va, fmt);
        vfprintf(stderr, fmt, va);
        va_end(va);
}
