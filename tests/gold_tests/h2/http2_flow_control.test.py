"""Verify HTTP/2 flow control behavior."""

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

import re
from enum import Enum
from typing import List, Optional

Test.Summary = __doc__


class Http2FlowControlTest:
    """Define an object to test HTTP/2 flow control behavior."""

    _replay_file: str = 'http2_flow_control.replay.yaml'
    _replay_chunked_file: str = 'http2_flow_control_chunked.replay.yaml'
    _valid_policy_values: List[int] = list(range(0, 3))
    _flow_control_policy: Optional[int] = None
    _flow_control_policy_is_malformed: bool = False

    _default_initial_window_size: int = 65535
    _default_max_concurrent_streams: int = 100
    _default_flow_control_policy: int = 0

    _dns_counter: int = 0
    _server_counter: int = 0
    _ts_counter: int = 0
    _client_counter: int = 0

    IS_OUTBOUND = True
    IS_INBOUND = False

    IS_HTTP2_TO_ORIGIN = True
    IS_HTTP1_TO_ORIGIN = False

    class ServerType(Enum):
        """Define the type of server to use in a TestRun."""

        HTTP1_CONTENT_LENGTH = 0
        HTTP1_CHUNKED = 1
        HTTP2 = 2

    def __init__(
            self,
            description: str,
            initial_window_size: Optional[int] = None,
            max_concurrent_streams: Optional[int] = None,
            flow_control_policy: Optional[int] = None,
            sni_flow_control_policy: Optional[int] = None,
            sni_domain: Optional[str] = None):
        """Declare the various test Processes.

        :param description: A description of the test.

        :param initial_window_size: The value with which to configure the
        proxy.config.http2.initial_window_size_(in|out) ATS parameter in the
        records.yaml file. If the paramenter is None, then no window size
        will be explicitly set and ATS will use the default value.

        :param max_concurrent_streams: The value with which to configure the
        proxy.config.http2.max_concurrent_streams_(in|out) ATS parameter in the
        records.yaml file. If the paramenter is None, then no window size
        will be explicitly set and ATS will use the default value.

        :param flow_control_policy: The value with which to configure the
        proxy.config.http2.flow_control.policy_(in|out) ATS parameter the
        records.yaml file. If the paramenter is None, then no policy
        configuration will be explicitly set and ATS will use the default
        value.

        :param sni_flow_control_policy: The value with which to configure the
        http2_flow_control_policy_in parameter in the sni.yaml file for the
        specified SNI domain. If None, no SNI-specific policy is configured.

        :param sni_domain: The SNI domain name to use for SNI-specific
        configuration. If None, no SNI configuration is used.
        """
        self._description = description

        self._initial_window_size = initial_window_size
        self._expected_initial_stream_window_size = (
            initial_window_size if initial_window_size is not None else self._default_initial_window_size)

        self._max_concurrent_streams = max_concurrent_streams
        self._expected_max_concurrent_streams = (
            max_concurrent_streams if max_concurrent_streams is not None else self._default_max_concurrent_streams)

        self._flow_control_policy = flow_control_policy
        self._sni_flow_control_policy = sni_flow_control_policy
        self._sni_domain = sni_domain

        # For SNI tests, the expected policy is the SNI override if present, otherwise the global policy
        if sni_flow_control_policy is not None and sni_domain is not None:
            self._expected_flow_control_policy = sni_flow_control_policy
        else:
            self._expected_flow_control_policy = (
                flow_control_policy if flow_control_policy is not None else self._default_flow_control_policy)

        self._flow_control_policy_is_malformed = (
            self._flow_control_policy is not None and self._flow_control_policy not in self._valid_policy_values)

        self._sni_flow_control_policy_is_malformed = (
            self._sni_flow_control_policy is not None and self._sni_flow_control_policy not in self._valid_policy_values)

    def _configure_dns(self, tr: 'TestRun') -> 'Process':
        """Configure the DNS."""
        dns = tr.MakeDNServer(f'dns-{Http2FlowControlTest._dns_counter}')
        Http2FlowControlTest._dns_counter += 1
        return dns

    def _configure_server(self, tr: 'TestRun', server_type: ServerType) -> 'Process':
        """Configure the test server."""
        if server_type == self.ServerType.HTTP1_CHUNKED:
            replay_file = self._replay_chunked_file
        elif self._sni_domain is not None:
            # Use the SNI-specific replay file
            replay_file = 'http2_flow_control_sni.replay.yaml'
        else:
            replay_file = self._replay_file

        server = tr.AddVerifierServerProcess(f'server-{Http2FlowControlTest._server_counter}', replay_file)
        Http2FlowControlTest._server_counter += 1
        return server

    def _configure_trafficserver(self, tr: 'TestRun', is_outbound: bool, server_type: ServerType) -> 'Process':
        """Configure a Traffic Server process."""
        ts = tr.MakeATSProcess(f'ts-{Http2FlowControlTest._ts_counter}', enable_tls=True)
        Http2FlowControlTest._ts_counter += 1

        ts.addDefaultSSLFiles()
        ts.Disk.records_config.update(
            {
                'proxy.config.ssl.server.cert.path': f'{ts.Variables.SSLDir}',
                'proxy.config.ssl.server.private_key.path': f'{ts.Variables.SSLDir}',
                'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
                'proxy.config.dns.nameservers': '127.0.0.1:{0}'.format(self._dns.Variables.Port),
                'proxy.config.dns.resolv_conf': 'NULL',
                'proxy.config.http.insert_age_in_response': 0,
                'proxy.config.diags.debug.enabled': 3,
                'proxy.config.diags.debug.tags': 'http',
            })

        if server_type == self.ServerType.HTTP2:
            ts.Disk.records_config.update({
                'proxy.config.ssl.client.alpn_protocols': 'h2,http/1.1',
            })

        if self._initial_window_size is not None:
            if is_outbound:
                configuration = 'proxy.config.http2.initial_window_size_out'
            else:
                configuration = 'proxy.config.http2.initial_window_size_in'
            ts.Disk.records_config.update({
                configuration: self._initial_window_size,
            })

        if self._flow_control_policy is not None:
            if is_outbound:
                configuration = 'proxy.config.http2.flow_control.policy_out'
            else:
                configuration = 'proxy.config.http2.flow_control.policy_in'
            ts.Disk.records_config.update({
                configuration: self._flow_control_policy,
            })

        if self._max_concurrent_streams is not None:
            if is_outbound:
                configuration = 'proxy.config.http2.max_concurrent_streams_out'
            else:
                configuration = 'proxy.config.http2.max_concurrent_streams_in'
            ts.Disk.records_config.update({
                configuration: self._max_concurrent_streams,
            })

        ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

        # Configure SNI-specific flow control policy if specified
        if self._sni_flow_control_policy is not None and self._sni_domain is not None:
            ts.Disk.sni_yaml.AddLines(
                ['sni:', f'- fqdn: {self._sni_domain}', f'  http2_flow_control_policy_in: {self._sni_flow_control_policy}'])

        ts.Disk.remap_config.AddLine(f'map / https://127.0.0.1:{self._server.Variables.https_port}')

        if self._flow_control_policy_is_malformed or self._sni_flow_control_policy_is_malformed:
            if is_outbound:
                configuration = 'proxy.config.http2.flow_control.policy_out'
            else:
                configuration = 'proxy.config.http2.flow_control.policy_in'

            if self._flow_control_policy_is_malformed:
                ts.Disk.diags_log.Content = Testers.ContainsExpression(
                    f"ERROR.*{configuration}", "Expected an error about an invalid flow control policy.")

            if self._sni_flow_control_policy_is_malformed:
                ts.Disk.diags_log.Content = Testers.ContainsExpression(
                    "ERROR.*http2_flow_control_policy_in", "Expected an error about an invalid SNI flow control policy.")

        return ts

    def _configure_client(
        self,
        tr,
    ):
        """Configure a client process.

        :param tr: The TestRun to associate the client with.
        """
        if self._sni_domain is not None:
            # For SNI tests, use the SNI-specific replay file
            tr.AddVerifierClientProcess(
                f'client-{Http2FlowControlTest._client_counter}',
                'http2_flow_control_sni.replay.yaml',
                https_ports=[self._ts.Variables.ssl_port])
        else:
            tr.AddVerifierClientProcess(
                f'client-{Http2FlowControlTest._client_counter}', self._replay_file, https_ports=[self._ts.Variables.ssl_port])
        Http2FlowControlTest._client_counter += 1

    def _configure_log_expectations(self, host):
        """Configure the log expectations for the client or server."""
        hostname = "server" if host == self._server else "client"
        if self._flow_control_policy_is_malformed or self._sni_flow_control_policy_is_malformed:
            # Since we're just testing ATS configuration errors, there's no
            # need to set up client expectations.
            return

        # ATS currently always sends a MAX_CONCURRENT_STREAMS setting.
        host.Streams.stdout += Testers.ContainsExpression(
            f'MAX_CONCURRENT_STREAMS:{self._expected_max_concurrent_streams}',
            f"{hostname} should receive a MAX_CONCURRENT_STREAMS setting.")

        if self._initial_window_size is not None:
            host.Streams.stdout += Testers.ContainsExpression(
                f'INITIAL_WINDOW_SIZE:{self._expected_initial_stream_window_size}',
                f"{hostname} should receive an INITIAL_WINDOW_SIZE setting.")

        if self._expected_flow_control_policy == 0:
            update_window_size = (self._expected_initial_stream_window_size - self._default_initial_window_size)
            if update_window_size > 0:
                host.Streams.stdout += Testers.ContainsExpression(
                    f'WINDOW_UPDATE.*id 0: {update_window_size}', f"{hostname} should receive a session WINDOW_UPDATE.")

        if self._expected_flow_control_policy in (1, 2):
            # Verify the larger window size.

            session_window_size = (self._expected_initial_stream_window_size * self._expected_max_concurrent_streams)

            # ATS will send a WINDOW_UPDATE frame to the client to increase
            # the session window size to the configured value from the default
            # value.
            update_window_size = (session_window_size - self._expected_initial_stream_window_size)

            # A WINDOW_UPDATE can only increase the window size. So make sure that
            # the new window size is greater than the default window size.
            if update_window_size > Http2FlowControlTest._default_initial_window_size:
                host.Streams.stdout += Testers.ContainsExpression(
                    f'WINDOW_UPDATE.*id 0: {update_window_size}', f"{hostname} should receive an initial session WINDOW_UPDATE.")
            else:
                # Our test traffic is large enough that eventually we should
                # send a session WINDOW_UPDATE frame for the smaller window.
                # It's not clear what it will be in advance though. A 100 byte
                # session window may not receive a 100 byte WINDOW_UPDATE frame
                # if the client is sending DATA frames in 10 byte chunks due to
                # a smaller stream window.
                host.Streams.stdout += Testers.ContainsExpression(
                    'WINDOW_UPDATE.*id 0: ', f"{hostname} should receive a session WINDOW_UPDATE.")

            if self._expected_flow_control_policy == 2:
                # Verify the streams window sizes get updated.
                stream_window_1 = session_window_size
                stream_window_2 = int(session_window_size / 2)
                stream_window_3 = int(session_window_size / 3)
                if self._server:
                    # Toward the server, there is a potential race condition
                    # between sending of first-request and the sending of the
                    # SETTINGS frame which reduces the stream window size.
                    # Allow for either scenario.
                    host.Streams.stdout += Testers.ContainsExpression(
                        (f'INITIAL_WINDOW_SIZE:{stream_window_1}.*'
                         f'INITIAL_WINDOW_SIZE:{stream_window_2}.*'),
                        f"{hostname} should stream receive window updates",
                        reflags=re.DOTALL | re.MULTILINE)
                else:
                    host.Streams.stdout += Testers.ContainsExpression(
                        (
                            f'INITIAL_WINDOW_SIZE:{stream_window_1}.*'
                            f'INITIAL_WINDOW_SIZE:{stream_window_2}.*'
                            f'INITIAL_WINDOW_SIZE:{stream_window_3}'),
                        f"{hostname} should stream receive window updates",
                        reflags=re.DOTALL | re.MULTILINE)

        if self._expected_initial_stream_window_size < 1000:
            first_id = 5 if self._server else 3

            if self._server and self._expected_flow_control_policy == 2:
                # Toward the server, there is a potential race condition
                # between sending of first-request and the sending of the
                # SETTINGS frame which reduces the stream window size. Allow
                # for either scenario.
                window_update_size = f'33|{self._expected_initial_stream_window_size}'
            else:
                window_update_size = f'{self._expected_initial_stream_window_size}'
            # For the smaller session window sizes, we expect WINDOW_UPDATE frames.
            host.Streams.stdout += Testers.ContainsExpression(
                f'WINDOW_UPDATE.*id {first_id}: {window_update_size}', f"{hostname} should receive a stream WINDOW_UPDATE.")

            host.Streams.stdout += Testers.ContainsExpression(
                f'WINDOW_UPDATE.*id {first_id + 2}: {window_update_size}', f"{hostname} should receive a stream WINDOW_UPDATE.")

            host.Streams.stdout += Testers.ContainsExpression(
                f'WINDOW_UPDATE.*id {first_id + 4}: {window_update_size}', f"{hostname} should receive a stream WINDOW_UPDATE.")

    def _configure_test_run_common(self, tr, is_outbound: bool, server_type: ServerType) -> None:
        """Perform the common Process configuration."""
        self._dns = self._configure_dns(tr)
        self._server = self._configure_server(tr, server_type)
        self._ts = self._configure_trafficserver(tr, is_outbound, server_type)
        if not self._flow_control_policy_is_malformed and not self._sni_flow_control_policy_is_malformed:
            self._configure_client(tr)
            tr.Processes.Default.StartBefore(self._dns)
            tr.Processes.Default.StartBefore(self._server)
        else:
            tr.Processes.Default.Command = "true"
        tr.Processes.Default.StartBefore(self._ts)
        tr.TimeOut = 20

    def _configure_inbound_http1_to_origin_test_run(self) -> None:
        """Configure the TestRun for inbound stream configuration."""
        tr = Test.AddTestRun(f'{self._description} - inbound, '
                             'HTTP/1 Content-Length origin')
        self._configure_test_run_common(tr, self.IS_INBOUND, self.ServerType.HTTP1_CONTENT_LENGTH)
        self._configure_log_expectations(tr.Processes.Default)

        tr = Test.AddTestRun(f'{self._description} - inbound, '
                             'HTTP/1 chunked origin')
        self._configure_test_run_common(tr, self.IS_INBOUND, self.ServerType.HTTP1_CHUNKED)
        self._configure_log_expectations(tr.Processes.Default)

    def _configure_inbound_http2_to_origin_test_run(self) -> None:
        """Configure the TestRun for inbound stream configuration."""
        tr = Test.AddTestRun(f'{self._description} - inbound, HTTP/2 origin')
        self._configure_test_run_common(tr, self.IS_INBOUND, self.ServerType.HTTP2)
        self._configure_log_expectations(tr.Processes.Default)

    def _configure_outbound_test_run(self) -> None:
        """Configure the TestRun outbound stream configuration."""
        tr = Test.AddTestRun(f'{self._description} - outbound, HTTP/2 origin')
        self._configure_test_run_common(tr, self.IS_OUTBOUND, self.ServerType.HTTP2)
        self._configure_log_expectations(self._server)

    def _configure_sni_inbound_test_run(self) -> None:
        """Configure the TestRun for SNI-specific inbound stream configuration."""
        tr = Test.AddTestRun(f'{self._description} - SNI inbound, HTTP/2 origin')
        self._configure_test_run_common(tr, self.IS_INBOUND, self.ServerType.HTTP2)
        self._configure_log_expectations(tr.Processes.Default)

    def run(self) -> None:
        """Configure the test run for various origin side configurations."""
        if self._sni_domain is not None:
            # Only run SNI-specific tests
            self._configure_sni_inbound_test_run()
        else:
            # Run the standard tests
            self._configure_inbound_http1_to_origin_test_run()
            self._configure_inbound_http2_to_origin_test_run()
            self._configure_outbound_test_run()


#
# Default configuration.
#
test = Http2FlowControlTest("Default Configurations")
test.run()

#
# Configuring max_concurrent_streams_(in|out).
#
test = Http2FlowControlTest(description="Configure max_concurrent_streams", max_concurrent_streams=53)
test.run()

#
# Configuring initial_window_size.
#
test = Http2FlowControlTest(description="Configure a larger initial_window_size_(in|out)", initial_window_size=100123)
test.run()

#
# Configuring flow_control_policy.
#
test = Http2FlowControlTest(description="Configure an unrecognized flow_control.in.policy", flow_control_policy=23)
test.run()

test = Http2FlowControlTest(
    description="Flow control policy 0 (default): small initial_window_size",
    initial_window_size=500,  # The default is 65 KB.
    flow_control_policy=0)
test.run()
test = Http2FlowControlTest(
    description="Flow control policy 1: 100 byte session, 10 byte streams",
    max_concurrent_streams=10,
    initial_window_size=10,
    flow_control_policy=1)
test.run()
test = Http2FlowControlTest(
    description="Flow control policy 2: 100 byte session, dynamic streams",
    max_concurrent_streams=10,
    initial_window_size=10,
    flow_control_policy=2)
test.run()

#
# SNI-specific flow control policy tests.
#
test = Http2FlowControlTest(
    description="SNI flow control policy override: global policy 0, SNI policy 1",
    max_concurrent_streams=10,
    initial_window_size=100,
    flow_control_policy=0,  # Global policy
    sni_flow_control_policy=1,  # SNI-specific override
    sni_domain="sni-policy-test.example.com")  # Match replay file domain
test.run()

test = Http2FlowControlTest(
    description="SNI flow control policy override: global policy 1, SNI policy 2",
    max_concurrent_streams=10,
    initial_window_size=100,
    flow_control_policy=1,  # Global policy
    sni_flow_control_policy=2,  # SNI-specific override
    sni_domain="sni-policy-test.example.com")  # Match replay file domain
test.run()

test = Http2FlowControlTest(
    description="SNI flow control policy override: global policy 2, SNI policy 0",
    max_concurrent_streams=10,
    initial_window_size=100,
    flow_control_policy=2,  # Global policy
    sni_flow_control_policy=0,  # SNI-specific override
    sni_domain="sni-policy-test.example.com")  # Match replay file domain
test.run()

# Test invalid SNI flow control policy
test = Http2FlowControlTest(
    description="SNI flow control policy override: invalid SNI policy",
    max_concurrent_streams=10,
    initial_window_size=100,
    flow_control_policy=0,  # Global policy (valid)
    sni_flow_control_policy=99,  # Invalid SNI policy
    sni_domain="sni-policy-test.example.com")  # Use same domain as replay file
test.run()
