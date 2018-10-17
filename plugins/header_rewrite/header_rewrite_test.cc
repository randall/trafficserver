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

/*
 * These are misc unit tests for header rewrite
 */

#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <ostream>

#include "parser.h"

const char PLUGIN_NAME[]     = "TEST_header_rewrite";
const char PLUGIN_NAME_DBG[] = "TEST_dbg_header_rewrite";

extern "C" void
TSError(const char *fmt, ...)
{
}

class ParserTest : public Parser
{
public:
  ParserTest(const std::string &line, bool preserve_quotes = false) : Parser(line, preserve_quotes), res(true)
  {
    std::cout << "Finished parser test: " << line << std::endl;
  }
  std::vector<std::string>
  getTokens()
  {
    return _tokens;
  }

  template <typename T, typename U>
  void
  do_parser_check(T x, U y, int line = 0)
  {
    if (x != y) {
      std::cerr << "CHECK FAILED on line " << line << ": " << x << " != " << y << std::endl;
      res = false;
    }
  }

  bool res;
};

#define CHECK_EQ(x, y)                     \
  do {                                     \
    p.do_parser_check((x), (y), __LINE__); \
  } while (false);

#define END_TEST(s) \
  do {              \
    if (!p.res) {   \
      ++errors;     \
    }               \
  } while (false);

int
test_parsing()
{
  int errors = 0;

  {
    ParserTest p("cond      %{READ_REQUEST_HDR_HOOK}");

    CHECK_EQ(p.getTokens().size(), 2U);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{READ_REQUEST_HDR_HOOK}");

    END_TEST();
  }

  {
    ParserTest p("cond %{CLIENT-HEADER:Host}    =a");

    CHECK_EQ(p.getTokens().size(), 4UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:Host}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "a");

    END_TEST();
  }

  {
    ParserTest p(" # COMMENT!");

    CHECK_EQ(p.getTokens().size(), 0UL);
    CHECK_EQ(p.empty(), true);

    END_TEST();
  }

  {
    ParserTest p("# COMMENT");

    CHECK_EQ(p.getTokens().size(), 0UL);
    CHECK_EQ(p.empty(), true);

    END_TEST();
  }

  {
    ParserTest p("cond %{Client-HEADER:Foo} =b");

    CHECK_EQ(p.getTokens().size(), 4UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{Client-HEADER:Foo}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "b");

    END_TEST();
  }

  {
    ParserTest p("cond %{Client-HEADER:Blah}       =        x");

    CHECK_EQ(p.getTokens().size(), 4UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{Client-HEADER:Blah}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "x");

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =  "shouldnt_   exist    _anyway"          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:non_existent_header}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "shouldnt_   exist    _anyway");
    CHECK_EQ(p.getTokens()[4], "[AND]");

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =  "shouldnt_   =    _anyway"          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:non_existent_header}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "shouldnt_   =    _anyway");
    CHECK_EQ(p.getTokens()[4], "[AND]");

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} ="="          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:non_existent_header}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "=");
    CHECK_EQ(p.getTokens()[4], "[AND]");

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =""          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:non_existent_header}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "");
    CHECK_EQ(p.getTokens()[4], "[AND]");

    END_TEST();
  }

  // Same test as above but preserving quotes
  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =""          [AND])", true);

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{CLIENT-HEADER:non_existent_header}");
    CHECK_EQ(p.getTokens()[2], "=");
    CHECK_EQ(p.getTokens()[3], "");
    CHECK_EQ(p.getTokens()[4], "[AND]");

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{PATH} /\/foo\/bar/ [OR])");

    CHECK_EQ(p.getTokens().size(), 4UL);
    CHECK_EQ(p.getTokens()[0], "cond");
    CHECK_EQ(p.getTokens()[1], "%{PATH}");
    CHECK_EQ(p.getTokens()[2], R"(/\/foo\/bar/)");
    CHECK_EQ(p.getTokens()[3], "[OR]");

    END_TEST();
  }

  {
    ParserTest p("add-header X-HeaderRewriteApplied true");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "X-HeaderRewriteApplied");
    CHECK_EQ(p.getTokens()[2], "true");

    END_TEST();
  }

  /* backslash-escape */
  {
    ParserTest p(R"(add-header foo \ \=\<\>\"\#\\)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], R"( =<>"#\)");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header foo \<bar\>)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], "<bar>");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header foo \bar\)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], "bar");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header foo "bar")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], "bar");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header foo "\"bar\"")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], R"("bar")");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header foo "\"\\\"bar\\\"\"")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "foo");
    CHECK_EQ(p.getTokens()[2], R"("\"bar\"")");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header Public-Key-Pins "max-age=3000; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "Public-Key-Pins");
    CHECK_EQ(p.getTokens()[2], R"(max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header Public-Key-Pins max-age\=3000;\ pin-sha256\=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM\=\")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "Public-Key-Pins");
    CHECK_EQ(p.getTokens()[2], R"(max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header Client-IP "%<chi>")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "Client-IP");
    CHECK_EQ(p.getTokens()[2], R"(%<chi>)");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header X-Url "http://trafficserver.apache.org/")");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "X-Url");
    CHECK_EQ(p.getTokens()[2], "http://trafficserver.apache.org/");

    END_TEST();
  }

  {
    ParserTest p(R"(add-header X-Url http://trafficserver.apache.org/)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "X-Url");
    CHECK_EQ(p.getTokens()[2], "http://trafficserver.apache.org/");

    END_TEST();
  }

  // test quote preservation
  {
    ParserTest p(R"(add-header X-Party "let's party like it's " + %{NOW:YEAR} + "!")", true);

    CHECK_EQ(p.getTokens().size(), 7UL);
    CHECK_EQ(p.getTokens()[0], "add-header");
    CHECK_EQ(p.getTokens()[1], "X-Party");
    CHECK_EQ(p.getTokens()[2], R"("let's party like it's ")");
    CHECK_EQ(p.getTokens()[3], "+");
    CHECK_EQ(p.getTokens()[4], "%{NOW:YEAR}");
    CHECK_EQ(p.getTokens()[5], "+");
    CHECK_EQ(p.getTokens()[6], R"("!")");

    END_TEST();
  }

  /*
   * test some failure scenarios
   */

  { /* unterminated quote */
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =" [AND])");

    CHECK_EQ(p.getTokens().size(), 0UL);

    END_TEST();
  }

  { /* quote in a token */
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =a"b [AND])");

    CHECK_EQ(p.getTokens().size(), 0UL);

    END_TEST();
  }

  return errors;
}

int
test_processing()
{
  int errors = 0;
  /*
   * These tests are designed to verify that the processing of the parsed input is correct.
   */
  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} ="="          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.get_op(), "CLIENT-HEADER:non_existent_header");
    CHECK_EQ(p.get_arg(), "==");
    CHECK_EQ(p.is_cond(), true);

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{CLIENT-HEADER:non_existent_header} =  "shouldnt_   =    _anyway"          [AND])");

    CHECK_EQ(p.getTokens().size(), 5UL);
    CHECK_EQ(p.get_op(), "CLIENT-HEADER:non_existent_header");
    CHECK_EQ(p.get_arg(), "=shouldnt_   =    _anyway");
    CHECK_EQ(p.is_cond(), true);

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{PATH} /\.html|\.txt/)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.get_op(), "PATH");
    CHECK_EQ(p.get_arg(), R"(/\.html|\.txt/)");
    CHECK_EQ(p.is_cond(), true);

    END_TEST();
  }

  {
    ParserTest p(R"(cond %{PATH} /\/foo\/bar/)");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.get_op(), "PATH");
    CHECK_EQ(p.get_arg(), R"(/\/foo\/bar/)");
    CHECK_EQ(p.is_cond(), true);

    END_TEST();
  }

  {
    ParserTest p("add-header X-HeaderRewriteApplied true");

    CHECK_EQ(p.getTokens().size(), 3UL);
    CHECK_EQ(p.get_op(), "add-header");
    CHECK_EQ(p.get_arg(), "X-HeaderRewriteApplied");
    CHECK_EQ(p.get_value(), "true");
    CHECK_EQ(p.is_cond(), false);

    END_TEST();
  }

  return errors;
}

int
main()
{
  if (test_parsing() || test_processing()) {
    return 1;
  }

  return 0;
}
