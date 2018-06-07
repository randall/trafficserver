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

#include "yaml-config.h"

#include "ssl-entry.h"

#include <yaml-cpp/yaml.h>

#include "ts/Diags.h"
#include "tsconfig/Errata.h"

ts::Errata
YAMLConfig::loader(const char *cfgFilename)
{
  try {
    YAML::Node config = YAML::LoadFile(cfgFilename);
    auto domains      = config["domains"];

    for (auto it = domains.begin(); it != domains.end(); ++it) {
      auto key    = it->first.as<std::string>();
      auto values = it->second;
      for (auto vit = values.begin(); vit != values.end(); ++vit) {
        auto value        = vit->as<ParsedSSLValues>();
        value.server_name = key;
        items.push_back(value);
      }
    }

  } catch (std::exception &ex) {
    TSDebug("manifest", "ex: %s", ex.what());
    return ts::Errata::Message(1, 1, ex.what());
  }

  return ts::Errata();
}

std::set<std::string> valid_config_keys = {"cert"};

namespace YAML
{
template <> struct convert<ParsedSSLValues> {
  static bool
  decode(const Node &node, ParsedSSLValues &item)
  {
    if (!node["cert"]) {
      return false;
    }
    item.server_cert_name = node["cert"].as<std::string>();
    return true;
  }
};

} // namespace YAML
