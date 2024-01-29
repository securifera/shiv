/**
  BSD 3-Clause License

  Copyright (c) 2019, Securifera, Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
	list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation
	and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
	contributors may be used to endorse or promote products derived from
	this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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