#include "YamlLogConfig.h"

bool loadLogConfig(LogConfig* cfg, const char* cfgFilename);

bool
YamlLogConfig::populateLogConfig(LogConfig* cfg, const char* cfgFilename)
{
  bool result;
  try {
    result = loadLogConfig(cfg, cfgFilename);
  } catch (std::exception& ex) {
    result = false;
  }
  return result;
}

bool loadLogConfig(LogConfig* cfg, const char* cfgFilename)
{
  YAML::Node config = YAML::LoadFile(cfgFilename);
  for (auto it = config.begin(); it != config.end(); ++it) {

  }
  return true;
}

LogFormat*
YamlLogConfig::createLogFormat(const YAML::Node &node)
{
  auto name = node["name"];
  auto format = node["format"];

  if (!node["name"] || !node["format"]) {
    return nullptr;
  }
  new LogFormat(
}
