#ifndef GETOPT_H
#define GETOPT_H

extern int optind, opterr;
extern char *optarg;

int getopt(size_t argc, char *argv[], char *optstring);

#endif