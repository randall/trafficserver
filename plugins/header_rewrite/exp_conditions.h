/*
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

#include <string>

#include "condition.h"
#include "matcher.h"

// %{proto}
class ConditionProto : public Condition
{
public:
  using MatcherType = Matchers<std::string>;

  ConditionProto() { TSDebug(PLUGIN_NAME_DBG, "Calling CTOR for ConditionProto"); }
  void append_value(std::string &s, const Resources &res) override;

protected:
  bool eval(const Resources &res) override;

private:
  DISALLOW_COPY_AND_ASSIGN(ConditionProto);
};

class ConditionIP : public Condition
{
public:
  using MatcherType = Matchers<std::string>;

  ConditionIP() { TSDebug(PLUGIN_NAME_DBG, "Calling CTOR for ConditionProto"); }
  void append_value(std::string &s, const Resources &res) override;

protected:
  bool eval(const Resources &res) override;

private:
  DISALLOW_COPY_AND_ASSIGN(ConditionIP);
};
