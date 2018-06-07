
#pragma once

#include <string>
#include <deque>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "ts/ts.h"

class SSLEntry
{
public:
  SSLEntry();
  ~SSLEntry() {}

  SSL_CTX *ctx;

  // If the CTX is not already created, use these
  // files to load things up
  std::string certFileName;
  std::string keyFileName;

  TSMutex mutex;
  std::deque<TSVConn> waitingVConns;
};

struct ParsedSSLValues {
  std::string server_priv_key_file;
  std::string server_name;
  std::string server_cert_name;
  std::string action;
};
