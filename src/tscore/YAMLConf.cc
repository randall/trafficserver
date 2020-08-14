/** @file

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "tscore/YAMLConf.h"

#include <yaml-cpp/yaml.h>

ts::Rv<YAML::Node>
YAMLConfig::LoadFile(const std::string &filename, const std::string &baseKeyName)
{
  try {
    YAML::Node config{YAML::LoadFile(filename)};
    return YAMLConfig::Load(config, baseKeyName);
  } catch (std::exception &ex) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "exception loading %s: %s", filename.c_str(), ex.what()));
  }
}

ts::Rv<YAML::Node>
YAMLConfig::LoadMap(const YAML::Node &config, const std::string &baseKeyName)
{
  if (config.IsNull()) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message("config is empty"));
  }

  if (!config.IsMap()) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "expected a map at line ", config.Mark().line));
  }

  if (!config[baseKeyName]) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "expected a toplevel '", baseKeyName, "' node"));
  }

  return config[baseKeyName];
}

ts::Rv<YAML::Node>
YAMLConfig::Load(const YAML::Node &config, const std::string &baseKeyName)
{
  if (config.IsNull()) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message("config is empty"));
  }

  if (!config.IsMap()) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "expected a map at line %d", config.Mark().line));
  }

  if (!config[baseKeyName]) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "expected a toplevel '%s' node", baseKeyName));
  }

  YAML::Node node = config[baseKeyName];
  if (!node.IsSequence()) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "expected a sequence at line ", node.Mark().line));
  }
  return node;
}

ts::Rv<YAML::Node>
YAMLConfig::Load(const std::string &contents, const std::string &baseKeyName)
{
  try {
    YAML::Node config{YAML::Load(contents)};
    return YAMLConfig::Load(config, baseKeyName);
  } catch (std::exception &ex) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "%s", ex.what()));
  }
}

ts::Rv<YAML::Node>
YAMLConfig::LoadMap(const std::string &contents, const std::string &baseKeyName)
{
  try {
    YAML::Node config{YAML::Load(contents)};
    return YAMLConfig::LoadMap(config, baseKeyName);
  } catch (std::exception &ex) {
    return ts::Rv<YAML::Node>({}, ts::Errata::Message(1, 1, "%s", ex.what()));
  }
}
