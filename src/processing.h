#pragma once

#include "core_types.h"
#include <pcapplusplus/RawPacket.h>

void processPacket(pcpp::RawPacket &rawPacket, ProcessingContext &ctx);
