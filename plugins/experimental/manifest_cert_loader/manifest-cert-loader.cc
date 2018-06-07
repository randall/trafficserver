/** @file

    SSL dynamic certificate loader
    Loads certificates into a hash table as they are requested

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

#include <cstdio>
#include <memory.h>
#include <cinttypes>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <getopt.h>

#include "domain-tree.h"

#include "yaml-config.h"
#include "ssl-entry.h"
#include "ts/ts.h"

#include "tsconfig/TsValue.h"
#include "ts/ink_inet.h"
#include "ts/ink_config.h"
#include "ts/IpMap.h"

extern "C" {
SSL_CTX *SSLDefaultServerContext();
bool SSL_CTX_add_extra_chain_cert_bio(SSL_CTX *ctx, BIO *bio);
}

/*
SSL_CTX *
SSLDefaultServerContext()
{
  return SSL_CTX_new(SSLv23_server_method());
}

static bool
SSL_CTX_add_extra_chain_cert_bio(SSL_CTX *ctx, BIO *bio)
{
  X509 *cert;

  for (;;) {
    cert = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr);

    if (!cert) {
      // No more the certificates in this file.
      break;
    }

// This transfers ownership of the cert (X509) to the SSL context, if successful.
#ifdef SSL_CTX_add0_chain_cert
    if (!SSL_CTX_add0_chain_cert(ctx, cert)) {
#else
    if (!SSL_CTX_add_extra_chain_cert(ctx, cert)) {
#endif
      X509_free(cert);
      return false;
    }
  }

  return true;
}
*/
using ts::config::Configuration;
using ts::config::Value;

#define PN "manifest-cert-loader"
#define PCP "[" PN " Plugin] "

namespace
{
class CertLookup
{
public:
  DomainNameTree tree;
  IpMap ipmap;
} Lookup;

std::string ConfigPath;

typedef std::pair<IpAddr, IpAddr> IpRange;

using IpRangeQueue = std::deque<IpRange>;

Configuration Config; // global configuration

int Parse_order = 0;

SSLEntry *MakeSSLEntry(ParsedSSLValues const &values, std::deque<std::string> &names);

int
Load_Configuration()
{
  TSDebug(PN, "Load_Conifugration");

  YAMLConfig yc;
  auto zret = yc.loader(ConfigPath.c_str());
  if (!zret.isOK()) {
    TSDebug(PN, "Failed to load certs.yml");
    TSError("failed to load certs.yml");
    return 1;
  }

  TSDebug(PN, "hiiiii: %lu", yc.items.size());

  for (auto item : yc.items) {
    std::deque<std::string> cert_names;
    SSLEntry *entry = MakeSSLEntry(item, cert_names);
    if (!entry) {
      TSError(PCP "failed to create the certificate entry for %s", item.server_name.c_str());
      return 1;
    }

    bool inserted = false;

    // Store in appropriate table
    if (item.server_name.length() > 0) {
      Lookup.tree.insert(item.server_name, entry, Parse_order++);
      inserted = true;
    }

    if (cert_names.size() > 0) {
      for (const auto &cert_name : cert_names) {
        Lookup.tree.insert(cert_name, entry, Parse_order++);
        inserted = true;
      }
    }

    if (!inserted) {
      delete entry;
      TSError(PCP "cert_names is empty and entry not otherwise inserted!");
    }
  }

  TSDebug(PN, "certs.yml done reloading!");
  return 0;
}

SSL_CTX *
Load_Certificate(SSLEntry const *entry, std::deque<std::string> &names)
{
  /* SSLConfigParams *config = SSLConfig::acquire();
  if (config != nullptr)
    */

  SSL_CTX *ctx = SSLDefaultServerContext();
  X509 *cert   = nullptr;
  BIO *bio     = nullptr;

  if (entry->certFileName.length() > 0) {
    // Must load the cert file to fetch the names out later
    bio  = BIO_new_file(entry->certFileName.c_str(), "r");
    cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    // TODO PUT BACK
    //    BIO_free(bio);

    if (!SSL_CTX_use_certificate(ctx, cert)) {
      TSDebug(PN, "Failed to load cert file %s", entry->certFileName.c_str());
      SSL_CTX_free(ctx);
      return nullptr;
    }
  }

  if (entry->keyFileName.length() > 0) {
    if (!SSL_CTX_use_PrivateKey_file(ctx, entry->keyFileName.c_str(), SSL_FILETYPE_PEM)) {
      TSDebug(PN, "Failed to load priv key file %s", entry->keyFileName.c_str());
      SSL_CTX_free(ctx);
      return nullptr;
    }
  }

  // Fetch out the names associated with the certificate
  if (cert == nullptr) {
    TSDebug(PN, "Failed to load file %s", entry->keyFileName.c_str());
    return nullptr;
  }

  // Load up any additional chain certificates
  SSL_CTX_add_extra_chain_cert_bio(ctx, bio);

  if (!SSL_CTX_use_PrivateKey_file(ctx, entry->certFileName.c_str(), SSL_FILETYPE_PEM)) {
    TSDebug(PN, "failed to load server private key from %s", entry->certFileName.c_str());
    X509_free(cert);
    return nullptr;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    TSDebug(PN, "server private key does not match the certificate public key");
    X509_free(cert);
    return nullptr;
  }

  X509_NAME *name = X509_get_subject_name(cert);
  char subjectCn[256];

  if (X509_NAME_get_text_by_NID(name, NID_commonName, subjectCn, sizeof(subjectCn)) >= 0) {
    std::string tmp_name(subjectCn);
    names.push_back(tmp_name);
  }

  // Look for alt names
  GENERAL_NAMES *alt_names = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
  if (alt_names) {
    unsigned count = sk_GENERAL_NAME_num(alt_names);
    for (unsigned i = 0; i < count; i++) {
      GENERAL_NAME *alt_name = sk_GENERAL_NAME_value(alt_names, i);

      if (alt_name->type == GEN_DNS) {
        // Current name is a DNS name, let's check it
        char *name_ptr = (char *)ASN1_STRING_get0_data(alt_name->d.dNSName);
        std::string tmp_name(name_ptr);
        names.push_back(tmp_name);
      }
    }
    sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
  }

  // Do we need to free cert? Did assigning to SSL_CTX increment its ref count
  return ctx;
}

/*
 * Load the config information about the terminal config.
 * Only load the certificate if no server name or ip is specified
 */
SSLEntry *
MakeSSLEntry(ParsedSSLValues const &values, std::deque<std::string> &names)
{
  SSLEntry *retval = nullptr;

  std::string cert_file_path;
  std::string priv_file_path;

  retval = new SSLEntry;
  if (values.server_cert_name.length() > 0) {
    if (values.server_cert_name[0] != '/') {
      cert_file_path = std::string(TSConfigDirGet()) + '/' + values.server_cert_name;
    } else {
      cert_file_path = values.server_cert_name;
    }
    retval->certFileName = cert_file_path;
  }

  if (values.server_priv_key_file.length() > 0) {
    if (values.server_priv_key_file[0] != '/') {
      priv_file_path = std::string(TSConfigDirGet()) + '/' + values.server_priv_key_file;
    } else {
      priv_file_path = values.server_priv_key_file;
    }
    retval->keyFileName = priv_file_path;
  }

  return retval;
}

void *
Load_Certificate_Thread(void *arg)
{
  SSLEntry *entry = reinterpret_cast<SSLEntry *>(arg);
  TSDebug(PN, "Request to load %s", entry->certFileName.c_str());

  TSMutexLock(entry->mutex);

  if (entry->ctx != nullptr) {
    TSDebug(PN, "Context for %s already loaded", entry->certFileName.c_str());
    TSMutexUnlock(entry->mutex);
    return (void *)1;
  }

  // Must load certificate
  std::deque<std::string> cert_names;
  entry->ctx = Load_Certificate(entry, cert_names);
  if (entry->ctx == nullptr) {
    TSDebug(PN, "Failed to get/create context for %s", entry->certFileName.c_str());
  }

  while (entry->waitingVConns.begin() != entry->waitingVConns.end()) {
    TSDebug(PN, "re-enabling waiting connections");
    TSVConn vc = entry->waitingVConns.back();
    entry->waitingVConns.pop_back();
    TSSslConnection sslobj = TSVConnSSLConnectionGet(vc);
    SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
    SSL_set_SSL_CTX(ssl, entry->ctx);
    TSVConnReenable(vc);
  }
  TSMutexUnlock(entry->mutex);

  for (const auto &cert_name : cert_names) {
    TSDebug(PN, "Inserting %s post load", cert_name.c_str());
    Lookup.tree.insert(cert_name, entry, Parse_order++);
  }

  return (void *)1;
}

int
CB_Life_Cycle(TSCont, TSEvent, void *)
{
  TSDebug(PN, "CB_Life_Cycle");

  // By now the SSL library should have been initialized,
  // We can safely parse the config file and load the ctx tables
  Load_Configuration();

  return TS_SUCCESS;
}

int
CB_Pre_Accept(TSCont /*contp*/, TSEvent event, void *edata)
{
  TSVConn ssl_vc = reinterpret_cast<TSVConn>(edata);

  IpAddr ip(TSNetVConnLocalAddrGet(ssl_vc));
  char buff[INET6_ADDRSTRLEN];

  {
    IpAddr ip_client(TSNetVConnRemoteAddrGet(ssl_vc));
    char buff2[INET6_ADDRSTRLEN];

    TSDebug(PN, "Pre accept callback %p - event is %s, target address %s, client address %s", ssl_vc,
            event == TS_EVENT_VCONN_START ? "good" : "bad", ip.toString(buff, sizeof(buff)),
            ip_client.toString(buff2, sizeof(buff2)));
  }

  // Is there a cert already defined for this IP?
  IpEndpoint key_endpoint;
  key_endpoint.assign(ip);

  // Is there a cert already loaded for this IP?
  void *payload;
  if (!Lookup.ipmap.contains(&key_endpoint, &payload)) {
    TSVConnReenable(ssl_vc);
    return TS_SUCCESS;
  }

  // Set the stored cert on this SSL object
  TSSslConnection sslobj = TSVConnSSLConnectionGet(ssl_vc);
  SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
  SSLEntry *entry        = reinterpret_cast<SSLEntry *>(payload);

  TSMutexLock(entry->mutex);

  if (entry->ctx == nullptr) {
    TSDebug(PN, "No context for %s", entry->keyFileName.c_str());

    if (entry->waitingVConns.begin() == entry->waitingVConns.end()) {
      entry->waitingVConns.push_back(ssl_vc);
      TSMutexUnlock(entry->mutex);

      TSThreadCreate(Load_Certificate_Thread, entry);
    } else { // Just add yourself to the queue
      entry->waitingVConns.push_back(ssl_vc);
      TSMutexUnlock(entry->mutex);
    }

    // Return before we re-enable
    return TS_SUCCESS;
  }

  SSL_set_SSL_CTX(ssl, entry->ctx);
  TSMutexUnlock(entry->mutex);
  //  TSDebug(PN, " IP");

  // All done, reactivate things
  TSVConnReenable(ssl_vc);

  return TS_SUCCESS;
}

int
CB_servername(TSCont /*contp*/, TSEvent /*event*/, void *edata)
{
  TSVConn ssl_vc         = reinterpret_cast<TSVConn>(edata);
  TSSslConnection sslobj = TSVConnSSLConnectionGet(ssl_vc);
  SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
  const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

  TSDebug(PN, "SNI callback %s", servername);
  if (servername == nullptr) {
    TSVConnReenable(ssl_vc);
    return TS_SUCCESS;
  }

  // Is there a certificate loaded up for this name?
  DomainNameTree::DomainNameNode *node = Lookup.tree.findFirstMatch(servername);
  if (node == nullptr) {
    TSDebug(PN, "Nothing for %s", servername);
    TSVConnReenable(ssl_vc);
    return TS_SUCCESS;
  }

  if (node->payload == nullptr) {
    TSDebug(PN, "no payload for %s?", servername);
    TSVConnReenable(ssl_vc);
    return TS_SUCCESS;
  }

  SSLEntry *entry = reinterpret_cast<SSLEntry *>(node->payload);

  TSMutexLock(entry->mutex);
  if (entry->ctx == nullptr) {
    // Spawn off a thread to load a potentially expensive certificate
    if (entry->waitingVConns.begin() == entry->waitingVConns.end()) {
      TSDebug(PN, "No context found for %s; spawning thread to load cert", servername);
      entry->waitingVConns.push_back(ssl_vc);
      TSMutexUnlock(entry->mutex);

      TSThreadCreate(Load_Certificate_Thread, entry);
    } else {
      TSDebug(PN, "No context found for %s; waiting for cert", servername);
      // Just add yourself to the queue
      entry->waitingVConns.push_back(ssl_vc);
      TSMutexUnlock(entry->mutex);
    }

    // Won't re-enable until the certificate has been loaded
    return TS_SUCCESS;
  }

  TSDebug(PN, "Found context for %s; setting context", servername);
  SSL_set_SSL_CTX(ssl, entry->ctx);

  TSMutexUnlock(entry->mutex);

  // All done, reactivate things
  TSVConnReenable(ssl_vc);

  return TS_SUCCESS;
}

const char CONTROL_MSG_LOG[]     = "log"; // log all data
const size_t CONTROL_MSG_LOG_LEN = sizeof(CONTROL_MSG_LOG) - 1;

int
CB_lifecycle_msg(TSCont /*contp*/, TSEvent /*event*/, void *edata)
{
  TSDebug(PN, "SUP DOG");
  TSPluginMsg *msgp = static_cast<TSPluginMsg *>(edata);

  if (0 != strcasecmp(PN, msgp->tag)) {
    TSDebug(PN, "SUP DOG2");
    return 0;
  }

  // identify the command
  if (msgp->data_size >= CONTROL_MSG_LOG_LEN &&
      0 == strncasecmp(CONTROL_MSG_LOG, static_cast<const char *>(msgp->data), CONTROL_MSG_LOG_LEN)) {
    TSDebug(PN, "hi '%s' command: %s", CONTROL_MSG_LOG, static_cast<const char *>(msgp->data));
    //        TSCont c = TSContCreate(CB_Command_Log, TSMutexCreate());
    //       TSContDataSet(c, new std::string(static_cast<const char *>(msgp->data), msgp->data_size));
    //      TSContSchedule(c, 0, TS_THREAD_POOL_TASK);
  } else {
    TSError("[%s] Unknown command '%.*s'", PN, static_cast<int>(msgp->data_size), static_cast<const char *>(msgp->data));
  }
  return 0;
}

} // namespace

// Called by ATS as our initialization point
void
TSPluginInit(int argc, const char *argv[])
{
  bool success = false;
  TSPluginRegistrationInfo info;
  TSCont cb_pa                         = nullptr; // pre-accept callback continuation
  TSCont cb_lc                         = nullptr; // life cycle callback continuuation
  TSCont cb_sni                        = nullptr; // SNI callback continuuation
  TSCont cb_msg                        = nullptr;
  static const struct option longopt[] = {
    {const_cast<char *>("config"), required_argument, nullptr, 'c'},
    {nullptr, no_argument, nullptr, '\0'},
  };

  info.plugin_name   = const_cast<char *>("Manifest Certificate Loader");
  info.vendor_name   = const_cast<char *>("Randall Meyer");
  info.support_email = const_cast<char *>("randallmeyer@yahoo.com");

  int opt = 0;
  while (opt >= 0) {
    opt = getopt_long(argc, (char *const *)argv, "c:", longopt, nullptr);
    switch (opt) {
    case 'c':
      ConfigPath = optarg;
      ConfigPath = std::string(TSConfigDirGet()) + '/' + std::string(optarg);
      break;
    }
  }

  if (ConfigPath.length() == 0) {
    static const char *const DEFAULT_CONFIG_PATH = "certs.yml";
    ConfigPath                                   = std::string(TSConfigDirGet()) + '/' + std::string(DEFAULT_CONFIG_PATH);
    TSDebug(PN, "No config path set in arguments, using default: %s", DEFAULT_CONFIG_PATH);
  }

  if (TS_SUCCESS != TSPluginRegister(&info)) {
    TSError(PCP "registration failed");
  } else if (TSTrafficServerVersionGetMajor() < 5) {
    TSError(PCP "requires Traffic Server 5.0 or later");
  } else if (nullptr == (cb_pa = TSContCreate(&CB_Pre_Accept, TSMutexCreate()))) {
    TSError(PCP "Failed to pre-accept callback");
  } else if (nullptr == (cb_lc = TSContCreate(&CB_Life_Cycle, TSMutexCreate()))) {
    TSError(PCP "Failed to lifecycle callback");
  } else if (nullptr == (cb_sni = TSContCreate(&CB_servername, TSMutexCreate()))) {
    TSError(PCP "Failed to create SNI callback");
  } else if (nullptr == (cb_msg = TSContCreate(&CB_lifecycle_msg, TSMutexCreate()))) {
    TSError(PCP "Failed to create SNI callback");
  } else {
    TSLifecycleHookAdd(TS_LIFECYCLE_PORTS_INITIALIZED_HOOK, cb_lc);
    TSHttpHookAdd(TS_VCONN_START_HOOK, cb_pa);
    TSHttpHookAdd(TS_SSL_CERT_HOOK, cb_sni);
    TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, cb_msg);

    success = true;
  }

  if (!success) {
    if (cb_pa) {
      TSContDestroy(cb_pa);
    }
    if (cb_lc) {
      TSContDestroy(cb_lc);
    }
    TSError(PCP "not initialized");
  }
  TSDebug(PN, "Plugin %s", success ? "online" : "offline");

  return;
}
