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
  if (!config.IsSequence()) {
   // return ts::Errata::Message(1, 1, "expected sequence");
    return false;
  }

  auto formats = config["formats"];
  for (auto it = formats.begin(); it != formats.end(); ++it) {
    
  }
  return true;
}


std::set<std::string> valid_log_format_keys = {"name", "format", "interval"};

namespace YAML {
template <>
struct convert<LogFormat*> {
  static bool
  decode(const Node& node, LogFormat* logFormat) {
    for (auto&& item : node) {
      if (std::none_of(valid_log_format_keys.begin(), valid_log_format_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("unsupported key " + item.first.as<std::string>());
      }
    }

    if (!node["format"]) {
      throw std::runtime_error("missing 'format' argument");
    }
    std::string format = node["format"].as<std::string>();

    unsigned interval = 0;
    if (node["interval"]) {
      interval = node["interval"].as<unsigned>();
    }
    std::string name;
    if (node["name"]) {
      name = node["name"].as<std::string>();
    }

    logFormat = new LogFormat(name.c_str(), format.c_str(), interval);

    return true;
  }
};

}
