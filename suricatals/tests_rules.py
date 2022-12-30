"""
Copyright(C) 2018-2023 Stamus Networks
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

from json.decoder import JSONDecodeError
import subprocess
import tempfile
import shutil
import os
import json
import io
import re
import logging

log = logging.getLogger(__name__)


class TestRules():
    VARIABLE_ERROR = 101
    OPENING_RULE_FILE = 41  # Error when opening a file referenced in the source
    OPENING_DATASET_FILE = 322  # Error when opening a dataset referenced in the source
    RULEFILE_ERRNO = [39, 42]
    USELESS_ERRNO = [40, 43, 44]
    CONFIG_FILE = """
%YAML 1.1
---
logging:
  default-log-level: warning
  outputs:
  - console:
      enabled: yes
      type: json
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
engine-analysis:
  rules-fast-pattern: yes
  rules: yes
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
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
    SURICATA_SYNTAX_CHECK = "Suricata Syntax Check"
    SURICATA_ENGINE_ANALYSIS = "Suricata Engine Analysis"

    def __init__(self, suricata_binary='suricata', suricata_config=None) -> None:
        self.suricata_binary = suricata_binary
        self.suricata_config = suricata_config
        self.suricata_version = self.get_suricata_version()

    def get_suricata_version(self):
        suri_cmd = [self.suricata_binary, '-V']
        suriprocess = subprocess.Popen(suri_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, _) = suriprocess.communicate()
        for line in io.StringIO(outdata.decode('utf-8')):
            mm = re.match(r'This is Suricata version (\d+\.\d+\.\d+)', line)
            if mm is not None:
                return mm.group(1)
        return "6.0.0"

    def json_compat_version(self):
        (major, minor, fix) = self.suricata_version.split('.')
        if int(major) < 6:
            return True
        elif int(major) == 6 and int(minor) == 0 and int(fix) < 4:
            return False
        return True

    def parse_suricata_error_after_7(self, error):
        ret = {
            'errors': [],
            'warnings': [],
        }
        error_stream = io.StringIO(error)
        wait_line = False
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except JSONDecodeError:
                ret['errors'].append({'message': error, 'format': 'raw', 'source': self.SURICATA_SYNTAX_CHECK})
                return ret
            s_err['engine']['source'] = self.SURICATA_SYNTAX_CHECK

            if not s_err['engine']['module'].startswith('detect') and s_err['engine']['module'] not in ['rule-vars']:
                continue
            if s_err['engine']['module'] == 'detect-parse':
                ret['errors'].append(s_err['engine'])
                continue
            elif s_err['engine']['module'] == 'detect-dataset':
                if not wait_line:
                    if s_err['engine']['message'].startswith("bad type"):
                        s_err['engine']['message'] = "dataset: " + s_err['engine']['message']
                    ret['errors'].append(s_err['engine'])
                    wait_line = True
                continue
            elif s_err['engine']['module'] == 'rules-vars':
                ret['errors'].append(s_err['engine'])
                continue
            elif s_err['engine']['module'] == 'detect':
                if 'error parsing signature' in s_err['engine']['message']:
                    message = s_err['engine']['message']
                    s_err['engine']['message'] = s_err['engine']['message'].split(' from file')[0]
                    getsid = re.compile(r"sid *:(\d+)")
                    match = getsid.search(line)
                    if match:
                        s_err['engine']['sid'] = int(match.groups()[0])
                    getline = re.compile(r"at line (\d+)$")
                    match = getline.search(message)
                    if match:
                        line_nb = int(match.groups()[0])
                        if wait_line:
                            if len(ret['errors']):
                                ret['errors'][-1]['line'] = line_nb - 1
                            wait_line = False
                        else:
                            s_err['engine']['line'] = line_nb - 1
                            ret['errors'].append(s_err['engine'])
                        continue
                    wait_line = False
                else:
                    ret['errors'].append(s_err['engine'])
            else:
                if not wait_line:
                    ret['errors'].append(s_err['engine'])
                    wait_line = True
                continue
        return ret

    # pylint: disable=W0613
    def parse_suricata_error_before_7(self, error, single=False):
        ret = {
            'errors': [],
            'warnings': [],
        }
        files_list = []
        ignore_next = False
        error_stream = io.StringIO(error)
        error_type = 'errors'
        for line in error_stream:
            try:
                s_err = json.loads(line)
            except JSONDecodeError:
                ret['errors'].append({'message': error, 'format': 'raw', 'source': self.SURICATA_SYNTAX_CHECK})
                return ret
            s_err['engine']['source'] = self.SURICATA_SYNTAX_CHECK
            errno = s_err['engine']['error_code']
            if errno == self.VARIABLE_ERROR:
                variable = s_err['engine']['message'].split("\"")[1]
                s_err['engine']['message'] = "Custom address variable \"$%s\" is used " \
                    "and need to be defined in probes configuration" % (variable)
                s_err['engine']['suricata_error'] = True
                if self.suricata_config is None:
                    error_type = 'warnings'
                ret[error_type].append(s_err['engine'])
                continue
            elif errno == self.OPENING_DATASET_FILE:
                m = re.match('fopen \'([^:]*)\' failed: No such file or directory', s_err['engine']['message'])
                if m is not None:
                    datasource = m.group(1)
                    s_err['engine']['message'] = 'Dataset source "%s" is a dependency " \
                        "and needs to be added to rulesets' % datasource
                    s_err['engine']['suricata_error'] = True
                    error_type = 'warnings'
                    ret[error_type].append(s_err['engine'])
                    ignore_next = True
                    continue
            elif errno == self.OPENING_RULE_FILE:
                m = re.match('opening hash file ([^:]*): No such file or directory', s_err['engine']['message'])
                if m is not None:
                    filename = m.group(1)
                    filename = filename.rsplit('/', 1)[1]
                    files_list.append(filename)
                    s_err['engine']['message'] = 'External file "%s" is a dependency ' \
                        'and needs to be added to rulesets' % filename
                    s_err['engine']['suricata_error'] = True
                    error_type = 'warnings'
                    ret[error_type].append(s_err['engine'])
                    continue
            elif errno not in self.USELESS_ERRNO:
                # clean error message
                if errno == 39:
                    if 'failed to set up dataset' in s_err['engine']['message']:
                        if ignore_next:
                            continue
                    if ignore_next:
                        ignore_next = False
                        continue
                    if 'error parsing signature' in s_err['engine']['message']:
                        message = s_err['engine']['message']
                        s_err['engine']['message'] = s_err['engine']['message'].split(' from file')[0]
                        getsid = re.compile(r"sid *:(\d+)")
                        match = getsid.search(line)
                        if match:
                            s_err['engine']['sid'] = int(match.groups()[0])
                        getline = re.compile(r"at line (\d+)$")
                        match = getline.search(message)
                        if match:
                            line_nb = int(match.groups()[0])
                            if len(ret[error_type]):
                                ret[error_type][-1]['line'] = line_nb - 1
                            error_type = 'errors'
                            continue
                if errno == 42:
                    s_err['engine']['message'] = s_err['engine']['message'].split(' from')[0]
                ret['errors'].append(s_err['engine'])
        return ret

    def parse_suricata_error(self, error, single=False):
        (major, _, _) = self.suricata_version.split('.')
        if int(major) < 7:
            return self.parse_suricata_error_before_7(error, single)
        else:
            return self.parse_suricata_error_after_7(error)

    def generate_config(self, tmpdir, config_buffer=None, related_files=None,
                        reference_config=None, classification_config=None):
        if not reference_config:
            reference_config = self.REFERENCE_CONFIG
        reference_file = os.path.join(tmpdir, "reference.config")
        with open(reference_file, 'w', encoding='utf-8') as rf:
            rf.write(reference_config)

        if not classification_config:
            classification_config = self.CLASSIFICATION_CONFIG
        classification_file = os.path.join(tmpdir, "classification.config")
        with open(classification_file, 'w', encoding='utf-8') as cf:
            cf.write(classification_config)

        if not config_buffer:
            if self.suricata_config is None:
                config_buffer = self.CONFIG_FILE
            else:
                with open(self.suricata_config, 'r', encoding='utf-8') as conf_file:
                    config_buffer = conf_file.read()
        config_file = os.path.join(tmpdir, "suricata.yaml")
        with open(config_file, 'w', encoding='utf-8') as cf:
            # write the config file in temp dir
            cf.write(config_buffer)
            cf.write("mpm-algo: ac-bs\n")
            cf.write("default-rule-path: " + tmpdir + "\n")
            cf.write("reference-config-file: " + tmpdir + "/reference.config\n")
            cf.write("classification-file: " + tmpdir + "/classification.config\n")
            cf.write("""
engine-analysis:
  rules-fast-pattern: yes
  rules: yes
logging:
  default-log-level: warning
  outputs:
  - console:
      enabled: yes
      type: json
                 """)

        related_files = related_files or {}
        for rfile in related_files:
            related_file = os.path.join(tmpdir, rfile)
            with open(related_file, 'w', encoding='utf-8') as rf:
                rf.write(related_files[rfile])

        return config_file

    def rule_buffer(self, rule_buffer, config_buffer=None, related_files=None,
                    reference_config=None, classification_config=None):
        # create temp directory
        tmpdir = tempfile.mkdtemp()
        # write the rule file in temp dir
        rule_file = os.path.join(tmpdir, "file.rules")
        with open(rule_file, 'w', encoding='utf-8') as rf:
            rf.write(rule_buffer)

        config_file = self.generate_config(tmpdir, config_buffer=config_buffer,
                                           related_files=related_files, reference_config=reference_config,
                                           classification_config=classification_config)

        suri_cmd = [self.suricata_binary, '-T', '-l', tmpdir, '-S', rule_file, '-c', config_file]
        # start suricata in test mode
        suriprocess = subprocess.Popen(suri_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = suriprocess.communicate()
        result = {'status': True, 'errors': "", 'warnings': [], 'info': []}
        # if not a success
        if suriprocess.returncode != 0:
            result['status'] = False
            result['errors'] = errdata.decode('utf-8')
        # analyse potential warnings
        message_stream = io.StringIO(outdata.decode('utf-8'))
        for message in message_stream:
            try:
                struct_msg = json.loads(message)
            except JSONDecodeError:
                continue
            if 'engine' not in struct_msg:
                continue
            # Check for duplicate signatures
            # FIXME implement that for Suricata 7
            error_code = struct_msg['engine'].get('error_code', 0)
            if error_code == 176:
                warning, sig_content = struct_msg['engine']['message'].split('"', 1)
                result['warnings'].append({'message': warning.rstrip(),
                                           'source': self.SURICATA_SYNTAX_CHECK,
                                           'content': sig_content.rstrip('"')})
            # Message for invalid signature
            elif error_code == 276:
                rule, warning = struct_msg['engine']['message'].split(': ', 1)
                rule = int(rule.split(' ')[1])
                result['warnings'].append({'message': warning.rstrip(), 'source': self.SURICATA_SYNTAX_CHECK, 'sid': rule})

        # runs rules analysis to have warnings
        suri_cmd = [self.suricata_binary, '--engine-analysis', '-l', tmpdir, '-S', rule_file, '-c', config_file]
        # start suricata in test mode
        suriprocess = subprocess.Popen(suri_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = suriprocess.communicate()
        engine_analysis = self.parse_engine_analysis(tmpdir)
        for signature in engine_analysis:
            for warning in signature.get('warnings', []):
                result['warnings'].append({'message': warning,
                                           'source': self.SURICATA_ENGINE_ANALYSIS,
                                           'content': signature['content']})
            for info in signature.get('info', []):
                msg = {'message': info, 'source': self.SURICATA_ENGINE_ANALYSIS, 'content': signature['content']}
                result['info'].append(msg)
        mpm_analysis = self.mpm_parse_rules_json(tmpdir)
        result['mpm'] = mpm_analysis
        shutil.rmtree(tmpdir)
        return result

    def check_rule_buffer(self, rule_buffer, config_buffer=None, related_files=None, single=False):
        related_files = related_files or {}
        prov_result = self.rule_buffer(rule_buffer, config_buffer=config_buffer, related_files=related_files)
        if len(prov_result.get('errors', [])):
            res = self.parse_suricata_error(prov_result['errors'], single=single)
            prov_result['errors'] = res['errors']
            if 'warnings' in res:
                prov_result['warnings'] = res['warnings']
        return prov_result

    def parse_engine_analysis(self, log_dir):
        json_path = os.path.join(log_dir, 'rules.json')
        if os.path.isfile(json_path) and self.json_compat_version():
            return self.parse_engine_analysis_v2(json_path)
        return self.parse_engine_analysis_v1(log_dir)

    def parse_engine_analysis_v1(self, log_dir):
        analysis = []
        with open(os.path.join(log_dir, 'rules_analysis.txt'), 'r', encoding='utf-8') as analysis_file:
            in_sid_data = False
            signature = {}
            for line in analysis_file:
                if line.startswith("=="):
                    in_sid_data = True
                    signature = {'sid': line.split(' ')[2]}
                    continue
                elif in_sid_data and len(line) == 1:
                    in_sid_data = False
                    analysis.append(signature)
                    signature = {}
                elif in_sid_data and 'content' not in signature:
                    signature['content'] = line.strip()
                    continue
                elif in_sid_data and 'Warning: ' in line:
                    warning = line.split('Warning: ')[1]
                    if 'warnings' not in signature:
                        signature['warnings'] = []
                    signature['warnings'].append(warning.strip())
                elif in_sid_data and 'Fast Pattern' in line:
                    if 'info' not in signature:
                        signature['info'] = []
                    signature['info'].append(line.strip())
        return analysis

    def parse_engine_analysis_v2(self, json_path):
        analysis = []
        with open(json_path, 'r', encoding='utf-8') as analysis_file:
            for line in analysis_file:
                signature_info = {}
                try:
                    signature_info = json.loads(line)
                except JSONDecodeError:
                    pass
                signature_msg = {'content': signature_info['raw']}
                if 'id' in signature_info:
                    signature_msg['sid'] = signature_info['id']
                if 'flags' in signature_info:
                    if 'toserver' in signature_info['flags'] and 'toclient' in signature_info['flags']:
                        if 'warnings' not in signature_msg:
                            signature_msg['warnings'] = []
                        signature_msg['warnings'].append('Rule inspect server and client side, consider adding a flow keyword')
                if 'warnings' in signature_info:
                    if 'warnings' not in signature_msg:
                        signature_msg['warnings'] = []
                    signature_msg['warnings'].extend(signature_info.get('warnings', []))
                if 'notes' in signature_info:
                    if 'info' not in signature_msg:
                        signature_msg['info'] = []
                    signature_msg['info'].extend(signature_info.get('notes', []))
                if 'engines' in signature_info:
                    app_proto = None
                    multiple_app_proto = False
                    got_raw_match = False
                    got_content = False
                    got_pcre = False
                    for engine in signature_info['engines']:
                        if 'app_proto' in engine:
                            if app_proto is None:
                                app_proto = engine.get('app_proto')
                            else:
                                if app_proto != engine.get('app_proto'):
                                    if app_proto not in ['http', 'http2'] or engine.get('app_proto') not in ['http', 'http2']:
                                        multiple_app_proto = True
                        else:
                            got_raw_match = True
                        for match in engine.get('matches', []):
                            if match['name'] == 'content':
                                got_content = True
                            elif match['name'] == 'pcre':
                                got_pcre = True
                    if got_pcre and not got_content:
                        if 'warnings' not in signature_msg:
                            signature_msg['warnings'] = []
                        signature_msg['warnings'].append('Rule with pcre without content match (possible performance issue)')
                    if app_proto is not None and got_raw_match:
                        if 'warnings' not in signature_msg:
                            signature_msg['warnings'] = []
                        signature_msg['warnings'].append('Application layer "%s" combined with raw match, '
                                                         'consider using a match on application buffer' % (app_proto))
                    if multiple_app_proto:
                        if 'warnings' not in signature_msg:
                            signature_msg['warnings'] = []
                        signature_msg['warnings'].append('Multiple application layers in same signature')
                analysis.append(signature_msg)
        return analysis

    def mpm_parse_rules_json(self, log_dir):
        mpm_data = []
        mpm_analysis = {'buffer': {}, 'sids': {}}
        try:
            with open(os.path.join(log_dir, 'rules.json'), 'r', encoding='utf-8') as rules_json:
                for line in rules_json:
                    # some suricata version have an invalid JSON formatted message
                    try:
                        rule_analysis = json.loads(line)
                    except json.JSONDecodeError:
                        return None
                    if 'mpm' in rule_analysis:
                        rule_analysis['mpm']['id'] = rule_analysis['id']
                        rule_analysis['mpm']['gid'] = rule_analysis['gid']
                        mpm_data.append(rule_analysis['mpm'])
                    else:
                        if 'engines' in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for engine in rule_analysis.get('engines', []):
                                if engine['is_mpm']:
                                    fp_buffer = engine['name']
                                    for match in engine.get('matches', []):
                                        if match.get('name') == 'content':
                                            if match.get('content', {}).get('is_mpm', False):
                                                fp_pattern = match['content']['pattern']
                                                break
                                    if fp_pattern:
                                        break
                            if fp_buffer and fp_pattern:
                                mpm_data.append({'id': rule_analysis['id'], 'gid': rule_analysis['gid'],
                                                 'buffer': fp_buffer, 'pattern': fp_pattern})
                            continue
                        if 'lists' in rule_analysis:
                            fp_buffer = None
                            fp_pattern = None
                            for key in rule_analysis['lists']:
                                fp_buffer = key
                                for match in rule_analysis['lists'][key].get('matches', []):
                                    if match.get('name') == 'content':
                                        if match.get('content', {}).get('is_mpm', False):
                                            fp_pattern = match['content']['pattern']
                                            break
                                if fp_pattern:
                                    break
                            if fp_buffer and fp_pattern:
                                mpm_data.append({'id': rule_analysis['id'], 'gid': rule_analysis['gid'],
                                                 'buffer': fp_buffer, 'pattern': fp_pattern})
                            continue
        except FileNotFoundError:
            return mpm_analysis
        # target to have
        # { 'http.host': { 'grosminet': { 'count': 34, sigs: [{'id': 2, 'gid':1}]} } }
        for sig in mpm_data:
            if sig['buffer'] in mpm_analysis['buffer']:
                if sig['pattern'] in mpm_analysis['buffer'][sig['buffer']]:
                    mpm_analysis['buffer'][sig['buffer']][sig['pattern']]['count'] += 1
                    mpm_analysis['buffer'][sig['buffer']][sig['pattern']]['sigs'].append({'id': sig['id'], 'gid': sig['gid']})
                else:
                    mpm_analysis['buffer'][sig['buffer']][sig['pattern']] = {'count': 1,
                                                                             'sigs': [{'id': sig['id'], 'gid': sig['gid']}]}
            else:
                mpm_analysis['buffer'][sig['buffer']] = {sig['pattern']: {'count': 1,
                                                                          'sigs': [{'id': sig['id'], 'gid': sig['gid']}]}}
            mpm_analysis['sids'][sig['id']] = {'buffer': sig['buffer'], 'pattern': sig['pattern']}
        return mpm_analysis

    def build_keywords_list(self):
        tmpdir = tempfile.mkdtemp()
        config_file = self.generate_config(tmpdir)
        suri_cmd = [self.suricata_binary, '--list-keywords=csv', '-l', tmpdir, '-c', config_file]
        # start suricata in test mode
        suriprocess = subprocess.Popen(suri_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, _) = suriprocess.communicate()
        shutil.rmtree(tmpdir)
        keywords = outdata.decode('utf-8').splitlines()
        keywords.pop(0)
        keywords_list = []
        for keyword in keywords:
            keyword_array = keyword.split(';')
            try:
                detail = 'No option'
                if 'sticky' in keyword_array[3]:
                    detail = 'Sticky Buffer'
                elif keyword_array[3] == 'none':
                    detail = 'No option'
                else:
                    detail = keyword_array[3]
                documentation = keyword_array[1]
                if len(keyword_array) > 5:
                    if 'https' in keyword_array[4]:
                        documentation += "\n\n"
                        documentation += "[Documentation](" + keyword_array[4] + ")"
                        documentation = {'kind': 'markdown', 'value': documentation}
                keyword_item = {'label': keyword_array[0], 'kind': 14, 'detail': detail, 'documentation': documentation}
                if 'content modifier' in keyword_array[3]:
                    keyword_item['tags'] = [1]
                    keyword_item['detail'] = 'Content Modifier'
                keywords_list.append(keyword_item)
            except IndexError:
                pass
        return keywords_list
