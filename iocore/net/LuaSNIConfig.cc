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

#include "LuaSNIConfig.h"

#include <unordered_map>
#include <set>

#include <yaml-cpp/yaml.h>

#include "tsconfig/Errata.h"
#include "ts/string_view.h"
#include "ts/HashFNV.h"
#include "ts/Diags.h"

ts::Errata
LuaSNIConfig::loader(const char *cfgFilename)
{
  try {
    YAML::Node config = YAML::LoadFile(cfgFilename);
    if (!config.IsSequence()) {
      return ts::Errata::Message(1, 1, "expected sequence");
    }

    for (auto it = config.begin(); it != config.end(); ++it) {
      items.push_back(it->as<LuaSNIConfig::Item>());
    }
  } catch (std::exception &ex) {
    return ts::Errata::Message(1, 1, ex.what());
  }

  return ts::Errata();
}

/// Hash functor for @c string_view
inline size_t
TsLuaConfigSVHash(ts::string_view const &sv)
{
  ATSHash64FNV1a h;
  h.update(sv.data(), sv.size());
  return h.get();
}

class TsEnumDescriptor
{
public:
  struct Pair {
    ts::string_view key;
    int value;
  };
  TsEnumDescriptor(std::initializer_list<Pair> pairs) : values{pairs.size(), &TsLuaConfigSVHash}, keys{pairs.size()}
  {
    for (auto &p : pairs) {
      values[p.key] = p.value;
      keys[p.value] = p.key;
    }
  }
  std::unordered_map<ts::string_view, int, size_t (*)(ts::string_view const &)> values;
  std::unordered_map<int, ts::string_view> keys;
  int
  get(ts::string_view key)
  {
    auto it = values.find(key);
    if (it != values.end()) {
      return it->second;
    }
    return -1;
  }
};

TsEnumDescriptor LEVEL_DESCRIPTOR = {{{"NONE", 0}, {"MODERATE", 1}, {"STRICT", 2}}};

std::set<std::string> valid_sni_config_keys = {TS_fqdn,         TS_disable_H2,           TS_verify_client,
                                               TS_tunnel_route, TS_verify_origin_server, TS_client_cert};

namespace YAML
{
template <> struct convert<LuaSNIConfig::Item> {
  static bool
  decode(const Node &node, LuaSNIConfig::Item &item)
  {
    for (auto &&item : node) {
      if (std::none_of(valid_sni_config_keys.begin(), valid_sni_config_keys.end(),
                       [&item](std::string s) { return s == item.first.as<std::string>(); })) {
        throw std::runtime_error("unsupported key " + item.first.as<std::string>());
      }
    }

    if (node[TS_fqdn]) {
      item.fqdn = node[TS_fqdn].as<std::string>();
    }
    if (node[TS_disable_H2]) {
      item.fqdn = node[TS_disable_H2].as<bool>();
    }

    // enum
    if (node[TS_verify_client]) {
      auto value = node[TS_verify_client].as<std::string>();
      int level  = LEVEL_DESCRIPTOR.get(value);
      if (level < 0) {
        throw std::runtime_error("unknown value " + value);
      }
      item.verify_client_level = static_cast<uint8_t>(level);
    }

    if (node[TS_tunnel_route]) {
      item.tunnel_destination = node[TS_tunnel_route].as<std::string>();
    }

    if (node[TS_verify_origin_server]) {
      auto value = node[TS_verify_origin_server].as<std::string>();
      int level  = LEVEL_DESCRIPTOR.get(value);
      if (level < 0) {
        throw std::runtime_error("unknown value " + value);
      }
      item.verify_origin_server = static_cast<uint8_t>(level);
    }

    if (node[TS_client_cert]) {
      item.client_cert = node[TS_client_cert].as<std::string>();
    }
    return true;
  }
};
} // namespace YAML
