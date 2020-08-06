/**

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

#define OPENSSL_THREAD_DEFINES
#include <openssl/ssl.h>

#include "tscore/Diags.h"

struct SSLConfigParams;
struct SSLMultiCertConfigParams;
class SSLNetVConnection;

typedef int ssl_error_t;

#ifndef OPENSSL_IS_BORING
typedef int ssl_curve_id;
#else
typedef uint16_t ssl_curve_id;
#endif

// Return the SSL Curve ID associated to the specified SSL connection
ssl_curve_id SSLGetCurveNID(SSL *ssl);

// Create a new SSL server context fully configured (cert and keys are optional).
// Used by TS API (TSSslServerContextCreate and TSSslServerCertUpdate)
SSL_CTX *SSLCreateServerContext(const SSLConfigParams *params, const SSLMultiCertConfigParams *sslMultiCertSettings,
                                const char *cert_path = nullptr, const char *key_path = nullptr);

// Release SSL_CTX and the associated data. This works for both
// client and server contexts and gracefully accepts nullptr.
// Used by TS API (TSSslContextDestroy)
void SSLReleaseContext(SSL_CTX *ctx);

// Initialize the SSL library.
void SSLInitializeLibrary();

// Initialize SSL library based on configuration settings
void SSLPostConfigInitialize();

// Wrapper functions to SSL I/O routines
ssl_error_t SSLWriteBuffer(SSL *ssl, const void *buf, int64_t nbytes, int64_t &nwritten);
ssl_error_t SSLReadBuffer(SSL *ssl, void *buf, int64_t nbytes, int64_t &nread);
ssl_error_t SSLAccept(SSL *ssl);
ssl_error_t SSLConnect(SSL *ssl);

// Attach a SSL NetVC back pointer to a SSL session.
void SSLNetVCAttach(SSL *ssl, SSLNetVConnection *vc);

// Detach from SSL NetVC back pointer to a SSL session.
void SSLNetVCDetach(SSL *ssl);

// Return the SSLNetVConnection (if any) attached to this SSL session.
SSLNetVConnection *SSLNetVCAccess(const SSL *ssl);

void setClientCertLevel(SSL *ssl, uint8_t certLevel);
void setClientCertCACerts(SSL *ssl, X509_STORE *ca_certs);
void setTLSValidProtocols(SSL *ssl, unsigned long proto_mask, unsigned long max_mask);

namespace ssl
{
namespace detail
{
  struct SCOPED_X509_TRAITS {
    typedef X509 *value_type;
    static value_type
    initValue()
    {
      return nullptr;
    }
    static bool
    isValid(value_type x)
    {
      return x != nullptr;
    }
    static void
    destroy(value_type x)
    {
      X509_free(x);
    }
  };

  struct SCOPED_BIO_TRAITS {
    typedef BIO *value_type;
    static value_type
    initValue()
    {
      return nullptr;
    }
    static bool
    isValid(value_type x)
    {
      return x != nullptr;
    }
    static void
    destroy(value_type x)
    {
      BIO_free(x);
    }
  };
  /* namespace ssl */ // namespace detail
} /* namespace detail */
} // namespace ssl

struct ats_wildcard_matcher {
  ats_wildcard_matcher()
  {
    if (!regex.compile(R"(^\*\.[^\*.]+)")) {
      Fatal("failed to compile TLS wildcard matching regex");
    }
  }

  ~ats_wildcard_matcher() {}
  bool
  match(const char *hostname) const
  {
    return regex.match(hostname) != -1;
  }

private:
  DFA regex;
};

typedef ats_scoped_resource<ssl::detail::SCOPED_X509_TRAITS> scoped_X509;
typedef ats_scoped_resource<ssl::detail::SCOPED_BIO_TRAITS> scoped_BIO;
