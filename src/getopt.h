// 
// https://www.codeproject.com/info/cpol10.aspx
// XGetopt.h  Version 1.2
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef GETOPT_H
#define GETOPT_H

extern int optind, opterr;
extern char *optarg;

int getopt(size_t argc, char *argv[], char *optstring);

#endif