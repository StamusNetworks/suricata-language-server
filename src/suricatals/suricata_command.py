"""
Copyright(C) 2025-2026 Stamus Networks SAS
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

import json
import os
import re
import subprocess
import docker
import tempfile
import shutil
import logging

log = logging.getLogger(__name__)


class SuriCmd:
    APP_LAYER_PROTOS = """
        - http:
            extended: yes
        - ftp:
            extended: yes
        - smtp:
            extended: yes
        - tls:
            extended: yes
        - ssh:
            extended: yes
        - smb:
            extended: yes
        - dcerpc:
            extended: yes
        - dns:
            extended: yes
        - modbus:
            extended: yes
        - enip:
            extended: yes
        - dnp3:
            extended: yes
        - nfs:
            extended: yes
        - tftp:
            extended: yes
        - ike:
            extended: yes
        - krb5:
            extended: yes
        - quic:
            extended: yes
        - dhcp:
            extended: yes
        - sip:
            extended: yes
        - rfb:
            extended: yes
        - mqtt:
            extended: yes
        - pgsql:
            extended: yes
        - telnet:
            extended: yes
        - websocket:
            extended: yes
        - ldap:
            extended: yes
        - doh2:
            extended: yes
        - rdp:
            extended: yes
        - http2:
            extended: yes
        - bittorrent-dht:
            extended: yes
        - pop3:
            extended: yes
        - mdns:
            extended: yes
        - snmp:
            extended: yes
        - flow:
            extended: yes
        - files:
            extended: yes
            force-magic: yes
            force-mimetype: yes
            force-hash: [sha1, sha256]
    """
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
profiling:
  rules:
    enabled: yes
    append: no
    filename: rule_perf.json
    sort: ticks
    active: yes
    limit: 1000
    json: yes
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
      ja3-fingerprints: yes
      ja4-fingerprints: yes
    pgsql:
      enabled: yes
      stream-depth: 0
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
    websocket:
      enabled: yes
    rdp:
      enabled: yes
    ssh:
      enabled: yes
      #hassh: yes
    doh2:
      enabled: yes
    http2:
      enabled: yes
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
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
      stream-depth: 0
    nfs:
      enabled: yes
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
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
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
      enabled: yes
    ldap:
      tcp:
        enabled: yes
        detection-ports:
          dp: 389, 3268
      udp:
        enabled: yes
        detection-ports:
          dp: 389, 3268
    mdns:
      enabled: yes
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
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
          enabled: yes
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
        self.image_version = "latest"
        self.image_version_run = "latest"

    def set_docker_mode(
        self, docker_image=SLS_DEFAULT_DOCKER_IMAGE, image_version="latest"
    ):
        """Enable Docker mode for running Suricata in containers.

        Args:
            docker_image: Docker image name, optionally with tag (e.g., 'jasonish/suricata' or 'jasonish/suricata:7.0.0')
            image_version: Docker image tag (default: "latest"), ignored if docker_image includes a tag
        """
        self.docker = True
        # Parse docker_image to separate name from tag if provided
        if ":" in docker_image:
            # Split on last : to handle registry URLs like registry.example.com:5000/image:tag
            parts = docker_image.rsplit(":", 1)
            self.docker_image = parts[0]
            self.image_version = parts[1]
        else:
            self.docker_image = docker_image
            self.image_version = image_version
        self.image_version_run = self.image_version
        self.docker_client = docker.from_env()

    def set_docker_version_for_run(self, image_version="latest"):
        """Temporarily override Docker image version for next run only.

        Args:
            image_version: Docker image tag to use for next run
        """
        self.image_version_run = image_version

    def build_cmd(self, cmd):
        """Build complete Suricata command with common options.

        Args:
            cmd: List of command arguments

        Returns:
            list: Complete command with log dir, config, rules, and data-dir options
        """
        if self.tmpdir is None:
            return cmd
        tmpdir = self.get_internal_tmpdir()
        suri_cmd = cmd
        # Add common options
        if self.tmpdir:
            suri_cmd += ["-l", tmpdir]
            suri_cmd += ["-c", os.path.join(tmpdir, "suricata.yaml")]
            suri_cmd += ["-S", os.path.join(tmpdir, "file.rules")]
            suri_cmd += ["--data-dir", tmpdir]
        return suri_cmd

    def prepare(self):
        """Create temporary directory for Suricata execution.

        Returns:
            self: For method chaining

        Raises:
            RuntimeError: If temporary directory creation fails
        """
        # When in Docker mode, ensure tmpdir is in a Docker-accessible location
        # Nix shell sets TMPDIR to a nix-shell-specific path that Docker cannot mount
        if self.docker and os.environ.get("TMPDIR", "").startswith("/tmp/nix-shell"):
            # Use /tmp directly, which Docker can always mount
            self.tmpdir = tempfile.mkdtemp(prefix="sls_", dir="/tmp")
        else:
            self.tmpdir = tempfile.mkdtemp(prefix="sls_")
        if self.tmpdir is None:
            raise RuntimeError("Failed to create temporary directory")
        return self

    def get_tmpdir(self) -> str:
        """Get temporary directory path, creating it if necessary.

        Returns:
            str: Absolute path to temporary directory

        Raises:
            RuntimeError: If temporary directory cannot be created
        """
        if self.tmpdir is None:
            self.prepare()
        if self.tmpdir is None:
            raise RuntimeError("Temporary directory can not be created")
        return self.tmpdir

    def get_internal_tmpdir(self):
        """Get internal temporary directory path for use in commands.

        In Docker mode, returns container path (/tmp/), otherwise returns host path.

        Returns:
            str: Path to use in Suricata commands

        Raises:
            RuntimeError: If temporary directory is not created
        """
        if self.tmpdir is None:
            raise RuntimeError("Temporary directory is not created")
        if self.docker:
            return "/tmp/"  # NOSONAR(S5443)
        else:
            return self.tmpdir

    def cleanup(self):
        """Remove temporary directory and reset state.

        Returns:
            self: For method chaining
        """
        if self.tmpdir:
            try:
                shutil.rmtree(self.tmpdir)
            except OSError as e:
                # Directory might still be in use or not empty - retry with ignore_errors
                log.warning(
                    "Failed to remove tmpdir %s on first attempt: %s. Retrying with ignore_errors",
                    self.tmpdir,
                    e,
                )
                try:
                    shutil.rmtree(self.tmpdir, ignore_errors=True)
                except OSError:
                    # If it still fails, log but don't crash
                    log.error("Failed to cleanup tmpdir %s", self.tmpdir)
        self.tmpdir = None
        self.returncode = None
        self.image_version_run = self.image_version
        return self

    def _run_suricata(self, suri_cmd):
        cmd = [self.suricata_binary] + suri_cmd
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=True,
                shell=False,
            )
            self.returncode = True
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.returncode = False
            return e.stdout

    def _run_docker(self, suri_cmd):
        if self.docker_client is None:
            raise RuntimeError("Docker client is not initialized")

        volumes = None
        if self.tmpdir:
            volumes = {
                self.tmpdir: {
                    "bind": "/tmp/",  # NOSONAR(S5443)
                    "mode": "rw",
                }
            }

        # Ensure image is available, pull if necessary
        image_name = ":".join([self.docker_image, self.image_version_run])
        try:
            self.docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            log.info("Pulling Docker image: %s", image_name)
            self.docker_client.images.pull(
                self.docker_image, tag=self.image_version_run
            )

        # Create and run container, checking exit code explicitly
        container = self.docker_client.containers.create(
            image=image_name,
            command=suri_cmd,
            volumes=volumes,
            tty=True,
        )

        try:
            container.start()
            result = container.wait()
            exit_code = result.get("StatusCode", 1)

            # Get logs (with tty=True, stdout and stderr are merged)
            logs = container.logs(stdout=True, stderr=True)
            if isinstance(logs, bytes):
                outdata = logs.decode("utf-8")
            else:
                outdata = logs

            # Set returncode based on exit status
            self.returncode = exit_code == 0

            if not self.tmpdir:
                self.image_version_run = self.image_version

            return outdata
        finally:
            # Always remove container
            container.remove()

    def run(self, cmd):
        """Execute Suricata command either locally or in Docker container.

        Args:
            cmd: List of Suricata command arguments

        Returns:
            str: Command output (stdout on success, stderr on failure)
        """
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
        app_layer_protos=False,
    ):
        """Generate Suricata configuration files in temporary directory.

        Creates suricata.yaml, reference.config, classification.config, and any
        related files needed for rule validation.

        Args:
            tmpdir: Directory to write configuration files
            config_buffer: Optional custom Suricata YAML configuration
            related_files: Optional dict mapping filenames to content
            reference_config: Optional reference.config content
            classification_config: Optional classification.config content
            extra_conf: Optional dict of extra YAML configuration to merge
        """
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
                raise RuntimeError("Temporary directory does not exist")
            cf.write(config_buffer)
            if app_layer_protos:
                cf.write(self.APP_LAYER_PROTOS)
            cf.write("mpm-algo: auto\n")
            magic_dir = "/nix/store/" if os.path.isfile("/etc/NIXOS") else "/usr/"
            cf.write(
                "security:\n"
                "  landlock:\n"
                "    enabled: yes\n"
                "    directories:\n"
                "      read:\n"
                f"        - {magic_dir}\n"
                "        - /etc/\n"
            )
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
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
          enabled: yes
profiling:
  rules:
    enabled: yes
    append: no
    filename: rule_perf.json
    sort: ticks
    active: yes
    limit: 1000
    json: yes
"""
                )

        related_files = related_files or {}
        for rfile in related_files:
            related_file = os.path.join(tmpdir, rfile)
            with open(related_file, "w", encoding="utf-8") as rf:
                rf.write(related_files[rfile])

        return config_file

    def get_version(self):
        """Get Suricata version string by running suricata -V.

        Returns:
            str: Raw version output from Suricata

        Raises:
            RuntimeError: If version retrieval fails or Suricata returns error
        """
        cmd = ["-V"]
        output = self.run(cmd)
        if output is None:
            raise RuntimeError("Failed to get Suricata version")
        if self.returncode is False:
            raise RuntimeError("Suricata returned error while getting version")
        return output.strip()

    def get_build_info(self):
        """Get Suricata build information by running suricata --build-info.

        Returns:
            str: Raw build info output from Suricata

        Raises:
            RuntimeError: If build info retrieval fails or Suricata returns error
        """
        cmd = ["--build-info"]
        output = self.run(cmd)
        if output is None:
            raise RuntimeError("Failed to get Suricata build info")
        if self.returncode is False:
            raise RuntimeError("Suricata returned error while getting build info")
        return output.strip()

    @staticmethod
    def _copy_auxiliary_files(rules_content, rules_dir, tmpdir):
        """Copy Lua scripts and dataset files referenced in rules_content from rules_dir into tmpdir."""
        lua_re = re.compile(r"\blua\s*:\s*([^;\s]+\.lua)\s*;")
        dataset_re = re.compile(r"dataset\s*:.*?,\s*(?:load|state)\s+(\S+)\s*;")
        for line in (rules_content or "").splitlines():
            m = lua_re.search(line)
            if m:
                lua_file = m.group(1).strip()
                candidate = os.path.join(rules_dir, lua_file)
                if os.path.exists(candidate):
                    shutil.copyfile(
                        candidate, os.path.join(tmpdir, os.path.basename(lua_file))
                    )
                else:
                    log.warning("Lua file not found: %s", candidate)
            m = dataset_re.search(line)
            if m:
                dataset_file = m.group(1).strip()
                candidate = os.path.join(rules_dir, dataset_file)
                if os.path.exists(candidate):
                    shutil.copyfile(
                        candidate, os.path.join(tmpdir, os.path.basename(dataset_file))
                    )
                else:
                    log.warning("Dataset file not found: %s", candidate)

    def _run_pcap(self, pcap_path, rules_content=None, extra_args=None, rules_dir=None):
        """Set up config, write rules, stage the pcap, and run Suricata against it.

        Caller owns cleanup — always wrap in a try/finally with self.cleanup().

        Args:
            rules_dir: Optional directory to search for Lua scripts and dataset files
                referenced in rules_content. Any such files are automatically copied to tmpdir.

        Returns:
            tuple[str, str]: (tmpdir path, Suricata console output).
        """
        self.prepare()
        tmpdir = self.get_tmpdir()
        self.generate_config(tmpdir, app_layer_protos=True)

        if rules_dir:
            self._copy_auxiliary_files(rules_content, rules_dir, tmpdir)

        rules_file = os.path.join(tmpdir, "file.rules")
        with open(rules_file, "w", encoding="utf-8") as wf:
            wf.write(rules_content if rules_content else "")

        if self.docker:
            pcap_basename = os.path.basename(pcap_path)
            pcap_dest = os.path.join(tmpdir, pcap_basename)
            shutil.copy(pcap_path, pcap_dest)
            internal_pcap = os.path.join(self.get_internal_tmpdir(), pcap_basename)
        else:
            internal_pcap = os.path.abspath(pcap_path)

        cmd = ["-r", internal_pcap]
        if extra_args:
            cmd.extend(extra_args)
        output = self.run(cmd)
        return tmpdir, output

    @staticmethod
    def _resolve_rules(rules_file, rules_content, rules_dir):
        """Resolve rules content and directory from rules_file or explicit arguments.

        rules_file takes precedence: its content is read and its directory used as rules_dir
        unless rules_dir is explicitly provided.
        """
        if rules_file:
            with open(rules_file, "r", encoding="utf-8") as rf:
                rules_content = rf.read()
            if rules_dir is None:
                rules_dir = os.path.dirname(os.path.abspath(rules_file))
        return rules_content, rules_dir

    def read_pcap(
        self,
        pcap_path,
        rules_content=None,
        set_options=None,
        checksum_checks=None,
        rules_dir=None,
        rules_file=None,
    ):
        """Run Suricata on a PCAP file and return eve.json content.

        Args:
            pcap_path: Path to PCAP file to process
            rules_content: Optional rules content to use (string). If None, uses empty rules.
            set_options: Optional list of "key=value" strings passed as --set to Suricata.
            checksum_checks: Optional value for Suricata -k flag ("all" or "none").
            rules_dir: Optional directory to search for Lua scripts and dataset files.
            rules_file: Optional path to a rules file; takes precedence over rules_content
                and automatically sets rules_dir to the file's directory.

        Returns:
            str: Contents of eve.json output from Suricata

        Raises:
            RuntimeError: If PCAP processing fails or no eve.json is generated
        """
        rules_content, rules_dir = self._resolve_rules(
            rules_file, rules_content, rules_dir
        )
        extra_args = []
        for opt in set_options or []:
            extra_args += ["--set", opt]
        if checksum_checks is not None:
            extra_args += ["-k", checksum_checks]
        try:
            tmpdir, _ = self._run_pcap(
                pcap_path,
                rules_content,
                extra_args=extra_args or None,
                rules_dir=rules_dir,
            )
            eve_file = os.path.join(tmpdir, "eve.json")
            if os.path.exists(eve_file):
                with open(eve_file, "r", encoding="utf-8") as ef:
                    return ef.read()
            raise RuntimeError("No eve.json output generated")
        finally:
            self.cleanup()

    @staticmethod
    def _parse_pcap_stats(run_output):
        """Extract pcap processing stats from Suricata's JSON console output.

        Suricata (with -v) emits log lines as JSON with an `engine.message` field.
        Two lines carry the numbers we care about:
          - "time elapsed <s>s"                       (module suricata)
          - "read <files> file, <packets> packets, <bytes> bytes"  (module pcap)

        Returns a dict with any of: seconds, packets, bytes, files. Missing keys
        indicate the line was not found in the output (e.g. Suricata failure).
        """
        stats = {}
        if not run_output:
            return stats
        time_re = re.compile(r"time elapsed ([\d.]+)s")
        pcap_re = re.compile(r"read (\d+) file, (\d+) packets, (\d+) bytes")
        for line in run_output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = event.get("engine", {}).get("message", "")
            m = time_re.search(msg)
            if m:
                stats["seconds"] = float(m.group(1))
                continue
            m = pcap_re.search(msg)
            if m:
                stats["files"] = int(m.group(1))
                stats["packets"] = int(m.group(2))
                stats["bytes"] = int(m.group(3))
        return stats

    def read_pcap_profile(
        self, pcap_path, rules_content=None, top_n=100, rules_dir=None, rules_file=None
    ):
        """Run Suricata on a PCAP with rules profiling active.

        The generated config already enables profiling.rules; this method overrides
        the row limit via --set so Suricata emits exactly top_n entries. Requires a
        Suricata binary compiled with --enable-profiling (the default docker image
        used by SLS ships with profiling enabled).

        Passes -v so Suricata drops its Info-level "time elapsed" and
        "read N file, N packets, N bytes" lines into the console log — used to
        report pcap processing time (loading time is excluded).

        Args:
            pcap_path: Path to PCAP file to process
            rules_content: Optional rules content to use (string). If None, empty rules.
            top_n: Number of top-ticks signatures to record
            rules_dir: Optional directory to search for Lua scripts and dataset files.
            rules_file: Optional path to a rules file; takes precedence over rules_content
                and automatically sets rules_dir to the file's directory.

        Returns:
            tuple[str, dict]: (rule_perf.json content, pcap processing stats).
            Stats dict has keys: seconds, packets, bytes, files (any may be absent
            if Suricata did not emit the corresponding line).

        Raises:
            RuntimeError: If PCAP processing fails or no rule_perf.json is generated
        """
        rules_content, rules_dir = self._resolve_rules(
            rules_file, rules_content, rules_dir
        )
        try:
            tmpdir, run_output = self._run_pcap(
                pcap_path,
                rules_content,
                extra_args=["-v", "--set", f"profiling.rules.limit={top_n}"],
                rules_dir=rules_dir,
            )
            perf_file = os.path.join(tmpdir, "rule_perf.json")
            if not os.path.exists(perf_file):
                raise RuntimeError(
                    "No rule_perf.json output generated; ensure the Suricata build "
                    "has --enable-profiling"
                )
            with open(perf_file, "r", encoding="utf-8") as pf:
                perf_content = pf.read()
            return perf_content, self._parse_pcap_stats(run_output)
        finally:
            self.cleanup()
