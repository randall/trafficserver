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
    auto fmt = it->as<LogFormat*>();
    if (fmt->valid()) {
      cfg->format_list.add(fmt, false);

      if (is_debug_tag_set("xml")) {
        printf("The following format was added to the global format list\n");
        fmt->display(stdout);
      }
    } else {
      Note("Format named \"%s\" will not be active; not a valid format", fmt->name() ? fmt->name() : "");
      delete fmt;
      // ??? ERROR or just ignore?
    }
  }
  auto filters = config["filters"];
    for (auto it = filters.begin(); it != filters.end(); ++it) {
      auto filter = it->as<LogFilter*>();

      if (filter) {
        cfg->filter_list.add(filter, false);

        if (is_debug_tag_set("xml")) {
          printf("The following filter was added to the global filter list\n");
          filter->display(stdout);
        }
      }
  }
  return true;
}


std::set<std::string> valid_log_format_keys = {"name", "format", "interval"};
std::set<std::string> valid_log_filter_keys = {"name", "action", "condition"};

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

    std::string name;
    if (node["name"]) {
      name = node["name"].as<std::string>();
    }

    // if the format_str contains any of the aggregate operators,
    // we need to ensure that an interval was specified.
    //
    if (LogField::fieldlist_contains_aggregates(format.c_str())) {
      if (!node["interval"]) {
        Note("'interval' attribute missing for LogFormat object"
             " %s that contains aggregate operators: %s",
             name.c_str(), format.c_str());
        return false;
      }
    }

      unsigned interval = 0;
      if (node["interval"]) {
        interval = node["interval"].as<unsigned>();
      }


    logFormat = new LogFormat(name.c_str(), format.c_str(), interval);

    return true;
  }
};

template <>
struct convert<LogFilter*> {
  static bool
  decode(const Node& node, LogFilter* logFilter) {
    for (auto&& item : node) {
      if (std::none_of(valid_log_filter_keys.begin(), valid_log_filter_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("unsupported key " + item.first.as<std::string>());
      }
    }

    // we require all keys for LogFilter
    for (auto&& item : valid_log_filter_keys ) {
      if (!node[item]) {
        throw std::runtime_error("missing '" + item + "' argument");
      }
    }

    // TODO need to convert action enumj
    logFilter = LogFilter::parse(node["name"].as<std::string>().c_str(), LogFilter::REJECT ,node["condition"].as<std::string>().c_str() );

    return true;
  }
};


  
}
