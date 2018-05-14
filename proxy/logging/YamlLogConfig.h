#pragma once

#include "yaml-cpp/yaml.h"

#include "LogObject.h"
#include "LogConfig.h"

class YamlLogConfig
{
public:
  static bool populateLogConfig(LogConfig* cfg, const char* cfgFilename);
//  static LogFormat* createLogFormat(const YAML::Node &node);
};
