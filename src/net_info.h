#pragma once

#include <Windows.h>
#include "process_info.h"

#define AF_INET6        23              // Internetwork Version 6


BOOL get_network_info(std::unordered_map<size_t, ProcessInfo *> *proc_info_map);