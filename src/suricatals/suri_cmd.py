"""
Copyright(C) 2025 Stamus Networks
Written by Eric Leblond <el@stamus-networks.com>

This file is part of Suricata Language Server.

Suricata Language Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Suricata Language Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import subprocess
import docker
import tempfile
import shutil


class SuriCmd:
    CONFIG_FILE = """
%YAML 1.1
---
stats:
  enabled: no
logging:
  default-log-level: warning
  outputs:
  - console:
      enabled: yes
      type: json
app-layer:
  protocols:
    telnet:
      enabled: yes
    rfb:
      enabled: yes
      detection-ports:
        dp: 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909
    mqtt:
      enabled: yes
      # max-msg-length: 1 MiB
      # subscribe-topic-match-limit: 100
      # unsubscribe-topic-match-limit: 100
      # Maximum number of live MQTT transactions per flow
      # max-tx: 4096
    krb5:
      enabled: yes
    bittorrent-dht:
      enabled: yes
    snmp:
      enabled: yes
    ike:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443

      # Generate JA3/JA4 fingerprints from client hello. If not specified it
      # will be disabled by default, but enabled if rules require it.
      ja3-fingerprints: yes
      ja4-fingerprints: yes

      # What to do when the encrypted communications start:
      # - default: keep tracking TLS session, check for protocol anomalies,
      #            inspect tls_* keywords. Disables inspection of unmodified
      #            'content' signatures.
      # - bypass:  stop processing this flow as much as possible. No further
      #            TLS parsing and inspection. Offload flow bypass to kernel
      #            or hardware if possible.
      # - full:    keep tracking and inspection as normal. Unmodified content
      #            keyword signatures are inspected as well.
      #
      # For best performance, select 'bypass'.
      #
      #encryption-handling: default

    pgsql:
      enabled: yes
      # Stream reassembly size for PostgreSQL. By default, track it completely.
      stream-depth: 0
      # Maximum number of live PostgreSQL transactions per flow
      # max-tx: 1024
    dcerpc:
      enabled: yes
      # Maximum number of live DCERPC transactions per flow
      # max-tx: 1024
    ftp:
      enabled: yes
      # memcap: 64 MiB
    websocket:
      enabled: yes
      # Maximum used payload size, the rest is skipped
      # max-payload-size: 64 KiB
    rdp:
      enabled: yes
    ssh:
      enabled: yes
      #hassh: yes
    doh2:
      enabled: yes
    http2:
      enabled: yes
      # Maximum number of live HTTP2 streams in a flow
      #max-streams: 4096
      # Maximum headers table size
      #max-table-size: 65536
      # Maximum reassembly size for header + continuation frames
      #max-reassembly-size: 102400
    smtp:
      enabled: yes
      raw-extraction: no
      # Maximum number of live SMTP transactions per flow
      # max-tx: 256
      # Configure SMTP-MIME Decoder
      mime:
        # Decode MIME messages from SMTP transactions
        # (may be resource intensive)
        # This field supersedes all others because it turns the entire
        # process on or off
        decode-mime: yes

        # Decode MIME entity bodies (ie. Base64, quoted-printable, etc.)
        decode-base64: yes
        decode-quoted-printable: yes

        # Maximum bytes per header data value stored in the data structure
        # (default is 2000)
        header-value-depth: 2000

        # Extract URLs and save in state data structure
        extract-urls: yes
        # Scheme of URLs to extract
        # (default is [http])
        #extract-urls-schemes: [http, https, ftp, mailto]
        # Log the scheme of URLs that are extracted
        # (default is no)
        #log-url-scheme: yes
        # Set to yes to compute the md5 of the mail body. You will then
        # be able to journalize it.
        body-md5: no
      # Configure inspected-tracker for file_data keyword
      inspected-tracker:
        content-limit: 100000
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    imap:
      enabled: detection-only
    pop3:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
      # Maximum number of live SMB transactions per flow
      # max-tx: 1024

      # Stream reassembly size for SMB streams. By default track it completely.
      #stream-depth: 0

    nfs:
      enabled: yes
      # max-tx: 1024
    tftp:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes

      # Byte Range Containers default settings
      # byterange:
      #   memcap: 100 MiB
      #   timeout: 60

      # memcap:                   Maximum memory capacity for HTTP
      #                           Default is unlimited, values can be 64 MiB, e.g.

      # default-config:           Used when no server-config matches
      #   personality:            List of personalities used by default
      #   request-body-limit:     Limit reassembly of request body for inspection
      #                           by http_client_body & pcre /P option.
      #   response-body-limit:    Limit reassembly of response body for inspection
      #                           by file_data, http_server_body & pcre /Q option.
      #
      #   For advanced options, see the user guide


      # server-config:            List of server configurations to use if address matches
      #   address:                List of IP addresses or networks for this block
      #   personality:            List of personalities used by this block
      #
      #                           Then, all the fields from default-config can be overloaded
      #
      # Currently Available Personalities:
      #   Minimal, Generic, IDS (default), IIS_4_0, IIS_5_0, IIS_5_1, IIS_6_0,
      #   IIS_7_0, IIS_7_5, Apache_2

    # Note: Modbus probe parser is minimalist due to the limited usage in the field.
    # Only Modbus message length (greater than Modbus header length)
    # and protocol ID (equal to 0) are checked in probing parser
    # It is important to enable detection port and define Modbus port
    # to avoid false positives
    modbus:
      # How many unanswered Modbus requests are considered a flood.
      # If the limit is reached, the app-layer-event:modbus.flooded; will match.
      #request-flood: 500

      enabled: yes
      detection-ports:
        dp: 502
      # According to MODBUS Messaging on TCP/IP Implementation Guide V1.0b, it
      # is recommended to keep the TCP connection opened with a remote device
      # and not to open and close it for each MODBUS/TCP transaction. In that
      # case, it is important to set the depth of the stream reassembling as
      # unlimited (stream.reassembly.depth: 0)

      # Stream reassembly size for modbus. By default track it completely.
      stream-depth: 0

    # DNP3
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000

    # SCADA EtherNet/IP and CIP protocol support
    enip:
      enabled: yes
      detection-ports:
        dp: 44818
        sp: 44818

    ntp:
      enabled: yes

    quic:
      enabled: yes

    dhcp:
      enabled: yes

    sip:
      #enabled: yes

    ldap:
      tcp:
        enabled: yes
        detection-ports:
          dp: 389, 3268
      udp:
        enabled: yes
        detection-ports:
          dp: 389, 3268
      # Maximum number of live LDAP transactions per flow
      # max-tx: 1024
security:
  lua:
    allow-rules: yes
engine-analysis:
  rules-fast-pattern: yes
  rules: yes
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    SCANNERS: "127.0.0.1"
    DC_SERVERS: "127.0.0.1"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
"""

    REFERENCE_CONFIG = """
# config reference: system URL

config reference: bugtraq   http://www.securityfocus.com/bid/
config reference: bid	    http://www.securityfocus.com/bid/
config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=
#config reference: cve       http://cvedetails.com/cve/
config reference: secunia   http://www.secunia.com/advisories/

#whitehats is unfortunately gone
config reference: arachNIDS http://www.whitehats.com/info/IDS

config reference: McAfee    http://vil.nai.com/vil/content/v_
config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=
config reference: url       http://
config reference: et        http://doc.emergingthreats.net/
config reference: etpro     http://doc.emergingthreatspro.com/
config reference: telus     http://
config reference: osvdb     http://osvdb.org/show/osvdb/
config reference: threatexpert http://www.threatexpert.com/report.aspx?md5=
config reference: md5	    http://www.threatexpert.com/report.aspx?md5=
config reference: exploitdb http://www.exploit-db.com/exploits/
config reference: openpacket https://www.openpacket.org/capture/grab/
config reference: securitytracker http://securitytracker.com/id?
config reference: secunia   http://secunia.com/advisories/
config reference: xforce    http://xforce.iss.net/xforce/xfdb/
config reference: msft      http://technet.microsoft.com/security/bulletin/
"""

    CLASSIFICATION_CONFIG = """
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic, 2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1


# NEW CLASSIFICATIONS
config classification: rpc-portmap-decode,Decode of an RPC Query,2
config classification: shellcode-detect,Executable code was detected,1
config classification: string-detect,A suspicious string was detected,3
config classification: suspicious-filename-detect,A suspicious filename was detected,2
config classification: suspicious-login,An attempted login using a suspicious username was detected,2
config classification: system-call-detect,A system call was detected,2
config classification: tcp-connection,A TCP connection was detected,4
config classification: trojan-activity,A Network Trojan was detected, 1
config classification: unusual-client-port-connection,A client was using an unusual port,2
config classification: network-scan,Detection of a Network Scan,3
config classification: denial-of-service,Detection of a Denial of Service Attack,2
config classification: non-standard-protocol,Detection of a non-standard protocol or event,2
config classification: protocol-command-decode,Generic Protocol Command Decode,3
config classification: web-application-activity,access to a potentially vulnerable web application,2
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: icmp-event,Generic ICMP event,3
config classification: kickass-porn,SCORE! Get the lotion!,1
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: default-login-attempt,Attempt to login by a default username and password,2

config classification: targeted-activity,Targeted Malicious Activity was Detected,1
config classification: exploit-kit,Exploit Kit Activity Detected,1
config classification: external-ip-check,Device Retrieving External IP Address Detected,2
config classification: domain-c2,Domain Observed Used for C2 Detected,1
config classification: pup-activity,Possibly Unwanted Program Detected,2
config classification: credential-theft,Successful Credential Theft Detected,1
config classification: social-engineering,Possible Social Engineering Attempted,2
config classification: coin-mining,Crypto Currency Mining Activity Detected,2
config classification: command-and-control,Malware Command and Control Activity Detected,1
"""
    SLS_DEFAULT_DOCKER_IMAGE = "jasonish/suricata"

    def __init__(self, suricata_binary="suricata", suricata_config=None):
        self.suricata_binary = suricata_binary
        self.suricata_config = suricata_config
        self.docker = False
        self.docker_image = self.SLS_DEFAULT_DOCKER_IMAGE
        self.docker_client = None
        self.tmpdir = None
        self.returncode = None

    def set_docker_mode(self, docker_image=SLS_DEFAULT_DOCKER_IMAGE):
        self.docker = True
        self.docker_image = docker_image
        self.docker_client = docker.from_env()

    def build_cmd(self, cmd):
        tmpdir = self.get_internal_tmpdir()
        if tmpdir is None:
            return cmd
        suri_cmd = cmd
        # Add common options
        if self.tmpdir:
            suri_cmd += ["-l", tmpdir]
            suri_cmd += ["-c", os.path.join(tmpdir, "suricata.yaml")]
            suri_cmd += ["-S", os.path.join(tmpdir, "file.rules")]
            suri_cmd += ["--data-dir", tmpdir]
        return suri_cmd

    def prepare(self):
        self.tmpdir = tempfile.mkdtemp(prefix="sls_")
        return self

    def get_tmpdir(self):
        return self.tmpdir

    def get_internal_tmpdir(self):
        if self.tmpdir is None:
            return None
        if self.docker:
            return "/tmp/"
        else:
            return self.tmpdir

    def cleanup(self):
        if self.tmpdir:
            shutil.rmtree(self.tmpdir)
        self.tmpdir = None
        self.returncode = None
        return self

    def _run_suricata(self, suri_cmd):
        cmd = [self.suricata_binary] + suri_cmd
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            self.returncode = True
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.returncode = False
            return e.stderr

    def _run_docker(self, suri_cmd):
        if self.docker_client is None:
            raise RuntimeError("Docker client is not initialized")
        if self.tmpdir:
            try:
                outdata = self.docker_client.containers.run(
                    image=self.docker_image,
                    command=suri_cmd,
                    volumes={self.tmpdir: {"bind": "/tmp/", "mode": "rw"}},
                    remove=True,
                    stdout=True,
                    stderr=True,
                ).decode("utf-8")
                self.returncode = True
                return outdata
            except docker.errors.ContainerError as e:
                self.returncode = False
                return e.stderr.decode("utf-8")
        else:
            try:
                outdata = self.docker_client.containers.run(
                    image=self.docker_image,
                    command=suri_cmd,
                    remove=True,
                    stdout=True,
                    stderr=True,
                ).decode("utf-8")
                self.returncode = True
                return outdata
            except docker.errors.ContainerError as e:
                self.returncode = False
                return e.stderr.decode("utf-8")

    def run(self, cmd):
        suri_cmd = self.build_cmd(cmd)
        if self.docker:
            return self._run_docker(suri_cmd)
        else:
            return self._run_suricata(suri_cmd)

    def generate_config(
        self,
        tmpdir,
        config_buffer=None,
        related_files=None,
        reference_config=None,
        classification_config=None,
        extra_conf=None,
    ):
        if not reference_config:
            reference_config = self.REFERENCE_CONFIG
        reference_file = os.path.join(tmpdir, "reference.config")
        with open(reference_file, "w", encoding="utf-8") as rf:
            rf.write(reference_config)

        if not classification_config:
            classification_config = self.CLASSIFICATION_CONFIG
        classification_file = os.path.join(tmpdir, "classification.config")
        with open(classification_file, "w", encoding="utf-8") as cf:
            cf.write(classification_config)

        if not config_buffer:
            if self.suricata_config is None:
                config_buffer = self.CONFIG_FILE
            else:
                with open(self.suricata_config, "r", encoding="utf-8") as conf_file:
                    config_buffer = conf_file.read()
        config_file = os.path.join(tmpdir, "suricata.yaml")
        with open(config_file, "w", encoding="utf-8") as cf:
            # write the config file in temp dir
            internal_tmpdir = self.get_internal_tmpdir()
            if internal_tmpdir is None:
                raise RuntimeError("Temporary directory is not set")
            cf.write(config_buffer)
            cf.write("mpm-algo: ac-bs\n")
            cf.write("default-rule-path: " + internal_tmpdir + "\n")
            cf.write(
                "reference-config-file: " + internal_tmpdir + "/reference.config\n"
            )
            cf.write(
                "classification-file: " + internal_tmpdir + "/classification.config\n"
            )
            if extra_conf:
                cf.write(extra_conf.format(tmpdir=tmpdir))
            cf.write(
                """
engine-analysis:
  rules-fast-pattern: yes
  rules: yes
logging:
  default-log-level: warning
  outputs:
  - console:
      enabled: yes
      type: json
stats:
  enabled: no
outputs:
  - eve-log:
    enabled: no
"""
            )

        related_files = related_files or {}
        for rfile in related_files:
            related_file = os.path.join(tmpdir, rfile)
            with open(related_file, "w", encoding="utf-8") as rf:
                rf.write(related_files[rfile])

        return config_file

    def get_version(self):
        cmd = ["-V"]
        output = self.run(cmd)
        return output.strip()
