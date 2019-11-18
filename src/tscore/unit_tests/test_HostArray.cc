/** @file

  A brief file description

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

#include "catch.hpp"

#include "tscore/HostLookup.h"

TEST_CASE("test HostArray", "[libts][HostArray]")
{
  HostArray ha;

  std::string hostname   = "phobos.apple.com.edgesuite.net";
  HostBranch *new_branch = new HostBranch;
  new_branch->key        = hostname;
  new_branch->type       = HostBranch::HOST_TERMINAL;
  new_branch->level_idx  = 1;
  REQUIRE(ha.Insert(hostname, new_branch));
  REQUIRE(ha.size() == 1);

  std::string hostname2   = "apple.com.edgesuite.net";
  HostBranch *new_branch2 = new HostBranch;
  new_branch2->key        = hostname2;
  new_branch2->type       = HostBranch::HOST_TERMINAL;
  new_branch2->level_idx  = 2;
  REQUIRE(ha.Insert(hostname2, new_branch));
  REQUIRE(ha.size() == 2);
}
TEST_CASE("test HostLookup", "[libts][HostLookup]")
{
  std::string name("parent.config");
  HostLookup hl(name);
  std::string h1("aodp.itunes.apple.com");
  hl.NewEntry(h1, true, nullptr);

  std::string h2("phobos.apple.com.edgesuite.net");
  hl.NewEntry(h2, true, nullptr);

  hl.Print();
}
