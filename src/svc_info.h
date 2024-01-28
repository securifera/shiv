#pragma once

#include <unordered_map>
#include "process_info.h"

BOOL get_service_info(std::unordered_map<size_t, ProcessInfo *> *pid_process_info_map);
