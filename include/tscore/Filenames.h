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

#pragma once

namespace ts
{
namespace filename
{
  constexpr const char *RECORDS = "records.config";

  // These still need to have their corresponding records.config settings removed
  constexpr const char *LOGGING  = "logging.yaml";  // YAML-current
  constexpr const char *IP_ALLOW = "ip_allow.yaml"; // YAML-current
  constexpr const char *PARENT   = "parent.config"; // YAML-experimental
  constexpr const char *SNI      = "sni.yaml";      // YAML-current
  constexpr const char *REMAP    = "remap.config";

#if 0
  constexpr const char *PLUGIN  = "plugin.config"; // YAML-new
  constexpr const char *CACHE         = "cache.config";  // YAML-new
  constexpr const char *HOSTING       = "hosting.config";  // YAML-new
  constexpr const char *SOCKS         = "socks.config";  // YAML-new
  constexpr const char *SSL_MULTICERT = "ssl_multicert.config"; // YAML-new
  constexpr const char *SPLITDNS      = "splitdns.config";      // YAML-new
  constexpr const char *STORAGE =     "storage.config"; // YAML-new
  constexpr const char *VOLUME        = "volume.config";  // YAML-new
#else
  // new/renamed files
  constexpr const char *CACHE_OVERRIDE      = "cache_override.yaml";
  constexpr const char *CERTIFICATES_YAML   = "certificates.yaml";
  constexpr const char *GLOBAL_PLUGINS_YAML = "global_plugins.yaml";
  constexpr const char *SOCKS_YAML          = "socks.yaml";
  constexpr const char *SPLITDNS_YAML       = "splitdns.yaml";
  constexpr const char *HOSTING_YAML        = "hosting.yaml";
  constexpr const char *VOLUMES_YAML        = "volumes.yaml"; // combined storage and volume

  constexpr const char *PLUGIN        = GLOBAL_PLUGINS_YAML;
  constexpr const char *CACHE         = CACHE_OVERRIDE;    // YAML-new
  constexpr const char *HOSTING       = HOSTING_YAML;      // YAML-new
  constexpr const char *SOCKS         = SOCKS_YAML;        // YAML-new
  constexpr const char *SSL_MULTICERT = CERTIFICATES_YAML; // YAML-new
  constexpr const char *SPLITDNS      = SPLITDNS_YAML;     // YAML-new
  constexpr const char *STORAGE       = VOLUMES_YAML;      // YAML-new
  constexpr const char *VOLUME        = VOLUMES_YAML;      // YAML-new
#endif

  ///////////////////////////////////////////////////////////////////
  // Various other file names
  constexpr const char *RECORDS_STATS = "records.snap";

} // namespace filename
} // namespace ts
