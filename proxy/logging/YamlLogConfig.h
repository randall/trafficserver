#pragma once

#include "LogConfig.h"

class YamlLogConfig
{
public:
  static bool populateLogConfig(LogConfig *cfg, const char *cfgFilename);
};
