#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/manifest_cert_loader/manifest_cert_loader.la \
                      iocore/net/libinknet.la

experimental_manifest_cert_loader_manifest_cert_loader_la_SOURCES = \
  experimental/manifest_cert_loader/manifest-cert-loader.cc \
  experimental/manifest_cert_loader/domain-tree.cc \
  experimental/manifest_cert_loader/yaml-config.cc \
  experimental/manifest_cert_loader/ssl-entry.cc

experimental_manifest_cert_loader_manifest_cert_loader_la_LDFLAGS = $(AM_LDFLAGS) $(LIB_BROTLIENC)
experimental_manifest_cert_loader_manifest_cert_loader_la_LIBADD = $(top_builddir)/lib/tsconfig/libtsconfig.la
