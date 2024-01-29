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

#pragma once

#include <stdio.h>

//debug message functions
#define VERBOSITY 3
#ifdef _DEBUG
#define DbgFprintf(f, lvl, format, ...) DebugFprintf(f, lvl, format, __VA_ARGS__)
#define DbgFwprintf(f, lvl, format, ...) DebugFwprintf(f, lvl, format, __VA_ARGS__)
#else
#define DbgFprintf(...)
#define DbgFwprintf(...)
#endif
void DebugFprintf(FILE* f, unsigned int lvl, const char *format, ...);
void DebugFwprintf(FILE* f, unsigned int lvl, const wchar_t *format, ...);
void displayRawData(unsigned char* buf, int len);

extern unsigned int verbosity;
extern FILE* outlogfile;

//debug verbosity levels
#define PRINT_ERROR	1
#define PRINT_WARN	2
#define PRINT_INFO1	3
#define PRINT_INFO2	4
#define PRINT_WARN2 5
#define PRINT_INFO3	6