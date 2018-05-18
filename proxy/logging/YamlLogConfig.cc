#include "YamlLogConfig.h"

#include "LogObject.h"

#include <yaml-cpp/yaml.h>
#include <algorithm>

bool loadLogConfig(LogConfig *cfg, const char *cfgFilename);

bool
YamlLogConfig::populateLogConfig(LogConfig *cfg, const char *cfgFilename)
{
  bool result;
  try {
    result = loadLogConfig(cfg, cfgFilename);
  } catch (std::exception &ex) {
    Error("%s", ex.what());
    result = false;
  }
  return result;
}

bool
loadLogConfig(LogConfig *cfg, const char *cfgFilename)
{
  YAML::Node config = YAML::LoadFile(cfgFilename);
  /*
  if (!config.IsSequence()) {
    Error("malformed logging.config file; expected a map");
    return false;
  }
  */
  auto formats = config["formats"];
  for (auto it = formats.begin(); it != formats.end(); ++it) {
    auto fmt = it->as<LogFormat *>();
    if (fmt->valid()) {
      cfg->format_list.add(fmt, false);

      if (is_debug_tag_set("log")) {
        printf("The following format was added to the global format list\n");
        fmt->display(stdout);
      }
    } else {
      Note("Format named \"%s\" will not be active; not a valid format", fmt->name() ? fmt->name() : "");
      // delete fmt;
      // ??? ERROR or just ignore?
    }
  }

  auto filters = config["filters"];
  for (auto it = filters.begin(); it != filters.end(); ++it) {
    auto filter = it->as<LogFilter *>();

    if (filter) {
      cfg->filter_list.add(filter, false);

      if (is_debug_tag_set("xml")) {
        printf("The following filter was added to the global filter list\n");
        filter->display(stdout);
      }
    }
  }

  auto logs = config["logs"];
  for (auto it = logs.begin(); it != logs.end(); ++it) {
    auto obj = it->as<LogObject *>();
    cfg->log_object_manager.manage_object(obj);
  }
  return true;
}

std::set<std::string> valid_log_format_keys = {"name", "format", "interval"};
std::set<std::string> valid_log_filter_keys = {"name", "action", "condition"};
std::set<std::string> valid_log_object_keys = {
  "filename",          "format",          "mode",    "header",         "rolling_enabled", "rolling_interval_sec",
  "rolling_offset_hr", "rolling_size_mb", "filters", "collation_hosts"};

namespace YAML
{
template <> struct convert<LogFormat *> {
  static bool
  decode(const Node &node, LogFormat *logFormat)
  {
    for (auto &&item : node) {
      if (std::none_of(valid_log_format_keys.begin(), valid_log_format_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("format: unsupported key '" + item.first.as<std::string>() + "'");
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
    Note("OK");

    logFormat = new LogFormat(name.c_str(), format.c_str(), interval);
    Note("Format named \"%s\" ", logFormat->name() ? logFormat->name() : "");

    return true;
  }
};

template <> struct convert<LogFilter *> {
  static bool
  decode(const Node &node, LogFilter *logFilter)
  {
    for (auto &&item : node) {
      if (std::none_of(valid_log_filter_keys.begin(), valid_log_filter_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("filter: unsupported key '" + item.first.as<std::string>() + "'");
      }
    }

    // we require all keys for LogFilter
    for (auto &&item : valid_log_filter_keys) {
      if (!node[item]) {
        throw std::runtime_error("missing '" + item + "' argument");
      }
    }

    // TODO need to convert action enumj
    logFilter =
      LogFilter::parse(node["name"].as<std::string>().c_str(), LogFilter::REJECT, node["condition"].as<std::string>().c_str());

    return true;
  }
};

template <> struct convert<LogObject *> {
  static bool
  decode(const Node &node, LogObject *logObject)
  {
    for (auto &&item : node) {
      if (std::none_of(valid_log_object_keys.begin(), valid_log_object_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("log: unsupported key '" + item.first.as<std::string>() + "'");
      }
    }

    if (!node["format"]) {
      throw std::runtime_error("missing 'format' argument");
    }
    std::string format = node["format"].as<std::string>();

    if (!node["filename"]) {
      throw std::runtime_error("missing 'filename' argument");
    }

    std::string header;
    if (node["header"]) {
      header = node["header"].as<std::string>();
    }

    std::string filename = node["filename"].as<std::string>();
    LogFormat *fmt       = Log::config->format_list.find_by_name(format.c_str());
    if (!fmt) {
      Warning("Format %s not in the global format list; cannot create LogObject", format.c_str());
      return false;
    }

    // file format
    //
    LogFileFormat file_type = LOG_FILE_ASCII; // default value
    if (node["mode"]) {
      const char *mode_str = node["mode"].as<std::string>().c_str();
      file_type            = (strncasecmp(mode_str, "bin", 3) == 0 || (mode_str[0] == 'b' && mode_str[1] == 0) ?
                     LOG_FILE_BINARY :
                     (strcasecmp(mode_str, "ascii_pipe") == 0 ? LOG_FILE_PIPE : LOG_FILE_ASCII));
    }

    int obj_rolling_enabled      = 0;
    int obj_rolling_interval_sec = Log::config->rolling_interval_sec;
    int obj_rolling_offset_hr    = Log::config->rolling_offset_hr;
    int obj_rolling_size_mb      = Log::config->rolling_size_mb;

    if (node["rolling_enabled"]) {
      obj_rolling_enabled = node["rolling_enabled"].as<int>();
    }
    if (node["rolling_interval_sec"]) {
      obj_rolling_interval_sec = node["rolling_interval_sec"].as<int>();
    }
    if (node["rolling_offset_hr"]) {
      obj_rolling_offset_hr = node["rolling_offset_hr"].as<int>();
    }
    if (node["rolling_size_mb"]) {
      obj_rolling_interval_sec = node["rolling_size_mb"].as<int>();
    }

    if (!LogRollingEnabledIsValid(obj_rolling_enabled)) {
      Warning("Invalid log rolling value '%d' in log object  TODO", obj_rolling_enabled);
    }

    logObject = new LogObject(fmt, Log::config->logfile_dir, filename.c_str(), file_type, header.c_str(),
                              (Log::RollingEnabledValues)obj_rolling_enabled, Log::config->collation_preproc_threads,
                              obj_rolling_interval_sec, obj_rolling_offset_hr, obj_rolling_size_mb);

    // filters
    //
    auto filters = node["filters"];
    if (filters.IsSequence()) {
      throw std::runtime_error("'filters' should be a list");
    }

    for (auto &&filter : filters) {
      const char *filter_name = filter.as<std::string>().c_str();
      LogFilter *f            = Log::config->filter_list.find_by_name(filter_name);
      if (!f) {
        Warning("Filter %s not in the global filter list; cannot add to this LogObject", filter_name);
      } else {
        logObject->add_filter(f);
      }
    }

    return true;
  }
};

} // namespace YAML
