/** @file

  Functions for interfacing to management records

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

#include "MgmtDefs.h"
#include "records/P_RecCore.h"

// Convert to byte units (GB, MB, KB)
void bytesFromInt(RecInt bytes, char *bufVal);

// Convert to MB
void MbytesFromInt(RecInt bytes, char *bufVal);

// Create comma string from int
void commaStrFromInt(RecInt bytes, char *bufVal);

// Create percent string from float
void percentStrFromFloat(RecFloat val, char *bufVal);

// All types converted to/from strings where appropriate
bool varStrFromName(const char *varName, char *bufVal, int bufLen);
bool varSetFromStr(const char *varName, const char *value);

// Converts where applicable to specified type
bool varIntFromName(const char *varName, RecInt *value);
bool varFloatFromName(const char *varName, RecFloat *value);
bool varCounterFromName(const char *varName, RecCounter *value);

// Return the type of the variable named
RecDataT varType(const char *varName);

int setHostnameVar();
void appendDefaultDomain(char *hostname, int bufLength);

bool recordValidityCheck(const char *varName, const char *value);
bool recordRegexCheck(const char *pattern, const char *value);
bool recordRangeCheck(const char *pattern, const char *value);
bool recordIPCheck(const char *pattern, const char *value);
