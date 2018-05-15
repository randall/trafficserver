#include "YamlLogConfig.h"

#include <algorithm> // std::none_of

bool loadLogConfig(LogConfig *cfg, const char *cfgFilename);

bool
YamlLogConfig::populateLogConfig(LogConfig *cfg, const char *cfgFilename)
{
  bool result;
  try {
    result = loadLogConfig(cfg, cfgFilename);
  } catch (std::exception &ex) {
    result = false;
  }
  return result;
}

bool
loadLogConfig(LogConfig *cfg, const char *cfgFilename)
{
  YAML::Node config = YAML::LoadFile(cfgFilename);
  for (auto it = config.begin(); it != config.end(); ++it) {
  }
  return true;
}
/*
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
*/

std::string log_format_keys[]{"name", "format", "interval"};

/*
namespace YAML {
template <>
struct convert<LogFormat*> {
  static bool
  decode(const Node& node, LogFormat& logFormat) {
    for (auto&& item : node) {
      if (std::none_of(log_format_keys, [&item](std::string s) {
        return s == item.first.as<std::string>();
      })) {
        throw std::runtime_error("unsupported key");  //item.first.as<std::string>()
      }
    }
    if (!node["name"] || !node["format"]) {
      return false;
    }
    logFormat = new LogFormat(node["name"])



  }
}

}
*/
