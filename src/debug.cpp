#include <stdio.h>
#include <stdarg.h> 
#include <ctime>
#include <string.h>
#include <stdlib.h>

#include "debug.h"

FILE* outlogfile = stdout;
bool timestamp = false;
unsigned int verbosity = VERBOSITY;

//wrapper around printf to handles levels of verbosity
void DebugFprintf(FILE* f, unsigned int lvl, const char *format, ...)
{
	char time_buf[100];
	memset(time_buf, 0, 100);

	if (lvl <= verbosity) {
		if (f) {

			if (timestamp) {
				// current date/time based on current system
				time_t t = time(0);
				struct tm p;

				// convert now to string form
				localtime_s(&p, &t);
				strftime(time_buf, 100, "%m%d%Y-%H:%M:%S: ", &p);
				fputs(time_buf, f);
			}

			va_list args = NULL;
			va_start(args, format);

			vfprintf(f, format, args);

			va_end(args);
		}
	}
}

void DebugFwprintf(FILE* f, unsigned int lvl, const wchar_t *format, ...)
{
	char time_buf[100];
	memset(time_buf, 0, 100);

	if (lvl <= verbosity) {
		if (f) {

			if (timestamp) {
				// current date/time based on current system
				time_t t = time(0);
				struct tm p;

				// convert now to string form
				localtime_s(&p, &t);
				strftime(time_buf, 100, "%m%d%Y-%H:%M:%S: ", &p);
				fputs(time_buf, f);
			}

			va_list args = NULL;
			va_start(args, format);

			vfwprintf(f, format, args);

			va_end(args);
		}
	}
}

void displayRawData(unsigned char* buf, int len)
{
	for (int i = 0; i < len; i++) {
		if (i > 0 && i % 16 == 0) {
			DbgFprintf(outlogfile, PRINT_INFO3, "\n");
		}
		DbgFprintf(outlogfile, PRINT_INFO3, "%.2x ", buf[i] & 0xFF);
	}
	DbgFprintf(outlogfile, PRINT_INFO3, "\n");
}