#pragma once

#include "ProcessInfo.hpp"

// Fills user, integrity, arch, startTime, memory counters
void EnrichProcessExtras(ProcessInfo& proc);
