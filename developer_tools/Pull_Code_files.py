import sys
import os

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'


import argparse
import codecs
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import fnmatch
import hashlib
import ipaddress
import math
import re
import stat
import subprocess
import uuid
from pathlib import Path

MAX_CODE_FILES = 8
MIN_PART_BYTES = 500_000
DEFAULT_MAX_SOURCE_BYTES = 8 * 1024 * 1024
OUTPUT_FOLDER_NAME = 'freeedr'
IGNORED_DIRS = {
    '.git', 'bin', 'obj', '.vs', '.vscode', '.idea', 'node_modules', 'compiled', 'publish',
    'testresults', 'packages', 'artifacts', 'venv', '.venv',
    '.pytest_cache', '__pycache__', '.gemini', '.ssh', '.aws', '.azure',
    '.claude', '.cursor', '.codex',
}
PRIVATE_DATA_DIRS = {
    'data', 'local', 'logs', 'quarantine', 'control', 'inbox', 'user', 'backup', 'download',
    'results', 'reports', 'cache', 'env',
}
SOURCE_EXTENSIONS = {
    '.ps1', '.psm1', '.psd1', '.cs', '.axaml', '.xaml', '.cmd', '.bat', '.py', '.json', '.jsonl', '.xml',
    '.csproj', '.sln', '.slnx', '.txt', '.md', '.svg', '.manifest', '.config', '.props', '.targets', '.yaml',
    '.yml', '.yar', '.yara', '.iss', '.isl', '.resx', '.css', '.js', '.ts', '.html', '.htm', '.ini', '.toml',
    '.ruleset', '.editorconfig', '.sh',
}
SOURCE_NAMES = {
    '.gitignore', '.gitattributes', '.editorconfig', '.agignore', '.clineignore',
    '.codexignore', '.geminiignore', 'license',
}
ASSET_EXTENSIONS = {
    '.ico', '.png', '.jpg', '.jpeg', '.gif', '.ogg', '.mp3', '.wav', '.dll', '.exe', '.sys', '.msi',
    '.bmp', '.webp', '.zip', '.7z', '.pdb', '.cer', '.nupkg',
}
REPORT_EXTENSIONS = {'.log', '.trx', '.txt', '.xml', '.json', '.html', '.htm', '.md'}
CONFIG_EXTENSIONS = {
    '.json', '.xml', '.csproj', '.sln', '.slnx', '.config', '.props', '.targets', '.ini',
    '.toml', '.ruleset', '.manifest', '.yaml', '.yml',
}
START_HERE = ['AGENTS.md', 'project_structure.txt', 'docs/agents/AGENT_WORKFLOW.md', 'docs/history/STATUS.md']
ENGINE_SCRIPTS = {'edr-common.ps1', 'edr-engine.ps1', 'edr-scan.ps1', 'edr-control.ps1'}
TRAY_SCRIPTS = {'edr-tray.ps1'}
INSTALLER_SCRIPTS = {'install-edr.ps1', 'uninstall-edr.ps1'}
LEGACY_ENCODINGS = {}
MODEL_GUIDANCE = (
    'TARGET: advanced online GUI models with high reasoning settings.\n'
    'Select the model/reasoning in your GUI; this offline exporter cannot set them.\n'
    'GUI context, per-file upload limits and retrieval behavior: NOT VERIFIED for your account.\n'
    'API context specifications are NOT used as GUI upload/context limits.\n'
    'Max reasoning is not evidence that all attachments fit or were read.\n'
    'Ten attachments is this exporter\'s requested cap, not a provider-wide limit.\n'
    'Token figures are rough UTF-8-bytes/4 estimates, NOT tokenizer measurements or guarantees.\n'
    'Conversation, system instructions, reasoning and response need additional capacity.\n'
    'If a confirmed GUI budget is supplied, comparisons are advisory estimates only.\n'
    'No files are silently dropped to meet a guessed model budget.\n'
)
TOKEN_RE = re.compile(
    r'\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}'
    r'|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}'
    r'|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,}'
    r'|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b'
)
TELEGRAM_TOKEN_RE = re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')
PRIVATE_KEY_RE = re.compile(
    r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----.*?'
    r'(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)', re.DOTALL
)
ASSIGNMENT_RE = re.compile(
    r'''(?ix)(?P<prefix>["']?\b[\w.-]*(?:api[_-]?key|password|passwd|secret|token)["']?\s*[:=]\s*)(?P<quote>["'])(?P<value>[^\r\n]*?)(?P=quote)'''
)
BEARER_RE = re.compile(r'(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]{16,}=*')
URL_AUTH_RE = re.compile(r'(https?://)[^\s/:@]+:[^\s/@]+@', re.IGNORECASE)
IDP_HOST_RE = re.compile(r'(?i)\b([a-z0-9][a-z0-9-]*)(\.(?:okta|oktapreview|okta-emea|onelogin|auth0|pingone|'
                         r'pingidentity|onmicrosoft)\.com)\b')
IDP_PLACEHOLDER_TENANTS = {
    'example', 'contoso', 'fabrikam', 'yourcompany', 'your-tenant', 'tenant', 'company', 'mycompany', 'acme',
    'www', 'login', 'developer', 'docs', 'support', 'status',
}
ENTRA_TENANT_RE = re.compile(r'(?i)(login\.microsoftonline\.com/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
USER_PROFILE_RE = re.compile(r'(?i)(\b[A-Z]:(?:\\{1,2}|/)(?:Users|Documents and Settings)(?:\\{1,2}|/))'
                             r'([A-Za-z0-9._-]+)(?![A-Za-z0-9._-])')
PROFILE_PLACEHOLDERS = {
    'user', 'users', 'public', 'default', 'defaultuser0', 'all', 'username', 'example', 'alice', 'bob',
    'test', 'testuser', 'someone', 'someuser', 'other', 'otheruser', 'admin', 'administrator', 'name',
    'victim', 'attacker', 'jdoe',
}
PROFILE_FIXTURE_MAX_LEN = 2
DOMAIN_SID_RE = re.compile(r'\b(S-1-5-21-)(\d+-\d+-\d+)\b')
IP_DATA_EXTENSIONS = {'.json', '.jsonl', '.txt', '.log', '.trx', '.xml', '.csv', ''}
IP_CONTEXT_RE = re.compile(r'(?i)(?<![a-z])ip(?:v4|address)?(?![a-z])|ip(?![a-z])|address|remote|source|client|peer'
                           r'|host|\bban|logon|login|firewall|attacker')
IPV4_RE = re.compile(r'(?<![\w.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})'
                     r'(?![\w]|\.\d)')
WELL_KNOWN_PUBLIC_IPS = {
    '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220',
}
GENERIC_MACHINE_TERMS = {
    'workgroup', 'user', 'users', 'admin', 'administrator', 'system', 'localhost', 'default', 'public', 'test',
    'freeedr', 'windows', 'desktop', 'laptop', 'home',
}
EMAIL_RE = re.compile(r'(?<![\\\w.%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b')
EMAIL_ALLOWED_DOMAIN_RE = re.compile(
    r'(?i)^(?:(?:[a-z0-9-]+\.)*example(?:\.[a-z0-9-]+)*|(?:[a-z0-9-]+\.)*(?:test|invalid|localhost)'
    r'|users\.noreply\.github\.com)$'
)
EMAIL_FIXTURE_RE = re.compile(r'(?i)^[a-z0-9]@[a-z]\.[a-z]{2,3}$')
SECRET_VALUE_PLACEHOLDERS = {
    'example', 'placeholder', 'your_api_key', 'your-api-key', 'changeme', 'xxx', 'xxxx', '***', 'redacted',
    'none', 'null', 'true', 'false', 'test',
}
SECRET_NAME_VALUES = {
    'password', 'passwd', 'token', 'secret', 'api_key', 'apikey', 'access_token', 'refresh_token',
    'id_token', 'bearer', 'basic', 'authorization', 'x-api-key', 'client_secret', 'github_token',
}
SECRET_REFERENCE_RE = re.compile(r'^(?:\$\{|\{\{|\[REDACTED|<|%[\w.-]+%$|\$env:|\$\(|\$[A-Za-z_][\w:]*$)')
BARE_ASSIGNMENT_EXTENSIONS = {'.cmd', '.bat', '.ps1', '.sh', '.ini', '.toml', '.config', '.yml', '.yaml', '.txt',
                              '.iss', '.log', ''}
LOCAL_TERMS_RE = None
REDACTIONS = (
    (PRIVATE_KEY_RE, '[REDACTED-PRIVATE-KEY]'),
    (TOKEN_RE, '[REDACTED-API-TOKEN]'),
    (TELEGRAM_TOKEN_RE, '[REDACTED-TELEGRAM-TOKEN]'),
    (BEARER_RE, r'\1[REDACTED-BEARER-TOKEN]'),
    (URL_AUTH_RE, r'\1[REDACTED-CREDENTIALS]@'),
)


def is_benign_secret_value(value):
    """True only for values that cannot be a secret: empty, a reference/placeholder, or the
    well-known NAME of a token/header. Length and spaces do not make a value benign."""
    stripped = value.strip()
    return (not stripped or SECRET_REFERENCE_RE.match(stripped) is not None
            or stripped.lower() in SECRET_VALUE_PLACEHOLDERS or stripped.lower() in SECRET_NAME_VALUES)


def is_placeholder_tenant(name):
    return name in IDP_PLACEHOLDER_TENANTS or re.fullmatch(r'dev-?\d+', name) is not None


def is_fixture_sid(domain):
    parts = domain.split('-')
    return len(set(domain.replace('-', ''))) <= 2 or all(len(p) < 6 for p in parts)


def is_benign_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return (not address.is_global or value in WELL_KNOWN_PUBLIC_IPS
            or value.endswith('.0') or value.endswith('.255'))


def configure_local_terms(terms):
    """Builds LOCAL_TERMS_RE from local words (longest first so 'name-desktop' wins over 'name')."""
    global LOCAL_TERMS_RE
    cleaned = sorted({t.strip().lower() for t in terms if len(t.strip()) >= 4
                      and t.strip().lower() not in GENERIC_MACHINE_TERMS
                      and not EMAIL_ALLOWED_DOMAIN_RE.match(t.strip())}, key=len, reverse=True)
    LOCAL_TERMS_RE = (re.compile(r'(?i)(?<![\w.-])(?:' + '|'.join(map(re.escape, cleaned)) + r')(?![\w-])')
                      if cleaned else None)
    return cleaned


def local_machine_terms():
    """This PC's computer, user and domain names (read from the environment, never exported). FreeEDR
    events, alerts and fixtures name them ("Proc Exec | <COMPUTERNAME>"), so they are masked everywhere."""
    terms = {os.environ.get(var, '').strip() for var in ('COMPUTERNAME', 'USERNAME', 'USERDOMAIN', 'USERDNSDOMAIN')}
    profile = os.environ.get('USERPROFILE', '').strip()
    if profile:
        terms.add(Path(profile).name)
    return {t for t in terms if t}


def redact_sensitive(text, ext=''):
    count = 0
    for pattern, placeholder in REDACTIONS:
        text, n = pattern.subn(placeholder, text)
        count += n

    def assignment(match):
        nonlocal count
        if is_benign_secret_value(match['value']):
            return match[0]
        count += 1
        return match['prefix'] + match['quote'] + '[REDACTED-SECRET]' + match['quote']

    def bare_assignment(match):
        nonlocal count
        if is_benign_secret_value(match[2]):
            return match[0]
        count += 1
        return match[1] + '[REDACTED-SECRET]'

    def idp_host(match):
        nonlocal count
        if is_placeholder_tenant(match[1].lower()):
            return match[0]
        count += 1
        return '[REDACTED-TENANT]' + match[2]

    def user_profile(match):
        nonlocal count
        name = match[2].lower()
        if name in PROFILE_PLACEHOLDERS or len(name) <= PROFILE_FIXTURE_MAX_LEN:
            return match[0]
        count += 1
        return match[1] + '[REDACTED-USER]'

    def domain_sid(match):
        nonlocal count
        if is_fixture_sid(match[2]):
            return match[0]
        count += 1
        return match[1] + '[REDACTED-DOMAIN]'

    def public_ip(match):
        nonlocal count
        if is_benign_ip(match[1]):
            return match[0]
        count += 1
        return '[REDACTED-PUBLIC-IP]'

    def email(match):
        nonlocal count
        if EMAIL_ALLOWED_DOMAIN_RE.match(match[2]) or EMAIL_FIXTURE_RE.match(match[0]):
            return match[0]
        count += 1
        return '[REDACTED-EMAIL]'

    text = ASSIGNMENT_RE.sub(assignment, text)
    if ext.lower() in BARE_ASSIGNMENT_EXTENSIONS:
        text = re.sub(
            r'(?im)((?:^\s*(?:export\s+|set\s+)?|;\s*)(?:[\w.-]*(?:api[_-]?key|password|passwd|secret|access[_-]?token))\s*=\s*)(?![$%]|\[REDACTED)([^\s;"\'<>()]+)',
            bare_assignment, text,
        )
    text = IDP_HOST_RE.sub(idp_host, text)
    text, n = ENTRA_TENANT_RE.subn(r'\1[REDACTED-TENANT-ID]', text)
    count += n
    text = USER_PROFILE_RE.sub(user_profile, text)
    text = DOMAIN_SID_RE.sub(domain_sid, text)
    if ext.lower() in IP_DATA_EXTENSIONS:
        text = ''.join(IPV4_RE.sub(public_ip, line) if IP_CONTEXT_RE.search(line) else line
                       for line in text.splitlines(keepends=True))
    text = EMAIL_RE.sub(email, text)
    if LOCAL_TERMS_RE is not None:
        text, n = LOCAL_TERMS_RE.subn('[REDACTED-LOCAL-NAME]', text)
        count += n
    return text, count


def get_downloads_directory():
    return Path(os.environ.get('USERPROFILE', str(Path.home()))) / 'Downloads'


def is_secret_or_sensitive(path):
    name = path.name.lower()
    return (name.endswith(('.password.txt', '.pfx', '.p12', '.key.pem', '.key', '.pem', '.pvk',
                           '.crt', '.jks', '.eml', '.xlsx', '.xls', '.csv',
                           '.sqlite', '.db', '.db3', '.dmp', '.mdmp',
                           '.evtx', '.etl', '.hve'))
            or (name.startswith('.env') and not name.endswith('.example'))
            or name in {'preinstall.json', 'managed.json'}
            or name in {'credentials', '.netrc', '.npmrc', 'id_rsa', 'id_ed25519',
                        'credentials.json', 'secrets.json', 'cookies', 'login data'})


def is_link(path):
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0)
                                    & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))


def decode_text(data):
    for bom, encoding in ((codecs.BOM_UTF32_LE, 'utf-32'), (codecs.BOM_UTF32_BE, 'utf-32'),
                          (codecs.BOM_UTF16_LE, 'utf-16'), (codecs.BOM_UTF16_BE, 'utf-16'),
                          (codecs.BOM_UTF8, 'utf-8-sig')):
        if data.startswith(bom):
            return data.decode(encoding), encoding
    if b'\x00' in data:
        sample = data[:4096]
        if len(data) % 2 == 0 and len(sample) >= 4:
            for offset, encoding in ((1, 'utf-16-le'), (0, 'utf-16-be')):
                lane = sample[offset::2]
                if lane.count(0) / len(lane) > 0.6:
                    return data.decode(encoding), encoding
        raise UnicodeError('NUL-containing text without a recognized encoding')
    return data.decode('utf-8'), 'utf-8'


def get_group_name(file_path, project_root):
    parts = tuple(p.lower() for p in file_path.relative_to(project_root).parts)
    name = parts[-1]
    ext = file_path.suffix.lower()
    top = parts[0] if len(parts) > 1 else ''
    if top == 'tests' or (top == 'src' and len(parts) > 2 and parts[1].endswith('.tests')):
        return '06_Tests'
    if top in {'docs', 'ai_agent_prompt'} or ext == '.md' or name == 'project_structure.txt':
        return '00_Specifications_and_Architecture'
    if not top and name in ENGINE_SCRIPTS:
        return '01_Engine_and_Shared_Scripts'
    if not top and name in TRAY_SCRIPTS:
        return '02_Tray_PowerShell'
    if top in {'config', 'rules'}:
        return '03_Detection_Rules_and_Sysmon_Config'
    if (not top and name in INSTALLER_SCRIPTS) or parts[:2] == ('build', 'installer'):
        return '04_Installer'
    if top == 'src':
        return '05_CSharp_Tray'
    if top in {'build', 'developer_tools'} or ext in {'.cmd', '.bat', '.ps1', '.py'}:
        return '07_Build_and_Developer_Tools'
    if ext in CONFIG_EXTENSIONS or name in SOURCE_NAMES:
        return '08_Configuration'
    if ext in ASSET_EXTENSIONS:
        return '09_Assets_and_Binaries'
    return '10_Misc'


@dataclass
class Entry:
    path: str
    status: str
    reason: str = ''
    size: int = 0
    text: str = ''
    encoding: str = ''
    digest: str = ''
    group: str = ''
    bundle: str = '-'
    line: int = 0


def read_entry(path, label, group, legacy_encoding=None, explicit_report=False,
               max_source_bytes=DEFAULT_MAX_SOURCE_BYTES):
    entry = Entry(label, 'TEXT', group=group)
    encoding_origin = 'user-selected' if legacy_encoding else 'repository-declared'
    legacy_encoding = legacy_encoding or LEGACY_ENCODINGS.get(label)
    try:
        if is_link(path):
            entry.status, entry.reason = 'SKIPPED', 'link/reparse point; target not read'
            return entry
        if is_secret_or_sensitive(path):
            entry.status, entry.reason = 'SKIPPED', 'sensitive/private file; contents not read'
            return entry
        before = path.stat()
        entry.size = before.st_size
        ext = path.suffix.lower()
        if ext in ASSET_EXTENSIONS:
            entry.status, entry.reason = 'METADATA', 'asset/certificate/binary; contents not exported'
            return entry
        if (ext not in SOURCE_EXTENSIONS and path.name.lower() not in SOURCE_NAMES
                and not (explicit_report and ext in REPORT_EXTENSIONS)):
            entry.status, entry.reason = 'METADATA', 'unrecognized format; review if needed'
            return entry
        if before.st_size > max_source_bytes:
            entry.status, entry.reason = 'METADATA', (f'{before.st_size:,} bytes exceeds the {max_source_bytes:,}-byte '
                                                      'read limit; not read (raise --max-source-bytes)')
            return entry
        data = path.read_bytes()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise OSError('file changed during read')
        try:
            text, entry.encoding = decode_text(data)
        except UnicodeError:
            if not legacy_encoding or b'\x00' in data:
                raise
            text = data.decode(legacy_encoding, errors='strict')
            entry.encoding = legacy_encoding + f' ({encoding_origin} fallback; verify original encoding)'
        entry.text, redactions = redact_sensitive(text, ext if ext else path.name.lower())
        if redactions:
            entry.status, entry.reason = 'REDACTED', f'{redactions} sensitive pattern(s) removed; review locally'
        entry.digest = hashlib.sha256(entry.text.encode('utf-8')).hexdigest()
    except (OSError, UnicodeError) as exc:
        entry.status, entry.reason = 'ERROR', type(exc).__name__ + '; contents unavailable'
        entry.text = ''
    return entry


def git_snapshot(root):
    def git(*args):
        try:
            result = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                                    timeout=15, check=True)
            return result.stdout.decode('utf-8', errors='strict').strip()
        except (OSError, UnicodeError, subprocess.SubprocessError):
            return None
    head = git('rev-parse', 'HEAD')
    status = git('status', '--porcelain=v1', '--untracked-files=all')
    tracked = git('-c', 'core.quotepath=off', 'ls-files', '-z')
    ignored = git('-c', 'core.quotepath=off', 'ls-files', '-z', '--others', '--ignored',
                  '--exclude-standard', '--directory')
    return {'commit': head or 'unavailable', 'status': status,
            'tracked': [p for p in tracked.split('\0') if p] if tracked else [],
            'ignored': {p.lower() for p in ignored.split('\0') if p} if ignored else set(),
            'available': head is not None and status is not None and tracked is not None and ignored is not None}


def collect_entries(root, focus=(), legacy_encoding=None, ignored=frozenset(), tracked=None,
                    max_source_bytes=DEFAULT_MAX_SOURCE_BYTES):
    """tracked: casefolded set of git-tracked paths, or None when git is unavailable."""
    entries = []
    tracked_dirs = set()
    for item in tracked or ():
        parts = item.split('/')[:-1]
        tracked_dirs.update('/'.join(parts[:i]) + '/' for i in range(1, len(parts) + 1))
    restricted = set()

    def onerror(error):
        try:
            label = Path(error.filename).relative_to(root).as_posix() + '/'
        except (ValueError, TypeError):
            label = '[unreadable directory]'
        entries.append(Entry(label, 'ERROR', 'directory enumeration failed'))
    for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        current_rel = Path(current).relative_to(root).as_posix()
        current_key = '' if current_rel == '.' else current_rel.casefold() + '/'
        for name in sorted(dirs, key=str.casefold):
            path = Path(current) / name
            key = current_key + name.casefold() + '/'
            reason = ''
            try:
                if is_link(path):
                    reason = 'link/reparse point; subtree not read'
                elif name.lower() in IGNORED_DIRS:
                    reason = 'excluded generated/secret/history directory; entire subtree skipped'
                elif key in ignored:
                    reason = 'git-ignored directory (local/private); entire subtree skipped'
                elif name.lower() in PRIVATE_DATA_DIRS or current_key in restricted:
                    if tracked is None:
                        reason = 'private-data folder name and git unavailable; entire subtree skipped'
                    elif key in tracked_dirs:
                        restricted.add(key)
                    else:
                        reason = 'private-data folder with no git-tracked files; entire subtree skipped'
            except OSError:
                reason = 'directory inaccessible; subtree not read'
            if reason:
                dirs.remove(name)
                entries.append(Entry(path.relative_to(root).as_posix() + '/',
                                     'ERROR' if reason.startswith('directory inaccessible') else 'SKIPPED', reason))
        dirs.sort(key=str.casefold)
        for name in sorted(files, key=str.casefold):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            group = get_group_name(path, root)
            if name.lower().endswith('.log'):
                entries.append(Entry(rel, 'SKIPPED', 'local log (git-ignored); opt in with --test-result'))
                continue
            if rel.lower() in ignored and not is_secret_or_sensitive(path):
                entries.append(Entry(rel, 'SKIPPED', 'git-ignored (local/private); contents not read'))
                continue
            if current_key in restricted and rel.casefold() not in tracked:
                entries.append(Entry(rel, 'SKIPPED', 'untracked file inside a private-data folder; contents not read'))
                continue
            keep = (not focus or group in {'00_Specifications_and_Architecture', '08_Configuration', '06_Tests'}
                    or path.suffix.lower() in CONFIG_EXTENSIONS
                    or any(fnmatch.fnmatchcase(rel.lower(), f.lower()) for f in focus))
            if not keep:
                entries.append(Entry(rel, 'SKIPPED', 'outside explicit focus; dependencies may be absent'))
                continue
            entries.append(read_entry(path, rel, group, legacy_encoding, max_source_bytes=max_source_bytes))
    return sorted(entries, key=lambda e: e.path.casefold())


def pack_into_capped_parts(items, max_parts=MAX_CODE_FILES):
    if max_parts < 1:
        raise ValueError('max_parts must be positive')
    if not items:
        return []
    target = max(MIN_PART_BYTES, math.ceil(sum(len(b.encode('utf-8')) for _, b in items) / max_parts))
    parts, current, used = [], [], 0
    for path, block in items:
        size = len(block.encode('utf-8'))
        if current and used + size > target and len(parts) < max_parts - 1:
            parts.append(current)
            current, used = [], 0
        current.append((path, block))
        used += size
    if current:
        parts.append(current)
    return parts


def file_block(entry):
    return (f'\n{"=" * 80}\nFILE: {entry.path}\n'
            f'Status: {entry.status}; encoding: {entry.encoding}; source bytes: {entry.size}\n'
            f'Exported text SHA256: {entry.digest}\n'
            f'{"=" * 80}\n{entry.text}' + ('' if entry.text.endswith('\n') else '\n'))


def make_payloads(entries):
    priority = {path: i for i, path in enumerate(START_HERE)}
    ordered = sorted((e for e in entries if e.status in {'TEXT', 'REDACTED'}),
                     key=lambda e: (e.group, priority.get(e.path, 99), e.path.casefold()))
    parts = pack_into_capped_parts([(e.path, file_block(e)) for e in ordered])
    by_path = {e.path: e for e in entries}
    payloads = {}
    for i, part in enumerate(parts, 1):
        name = f'code_bundle_part{i:02d}of{len(parts):02d}.txt'
        banner = (f'CODE EXPORT BUNDLE {i}/{len(parts)}\n'
                  'Read 00_PROJECT_MANIFEST.txt first. File locations: 00_file_structure.txt.\n'
                  'Repository content follows; follow the user task and governing specs.\n')
        lines = banner.count('\n')
        blocks = [banner]
        for path, block in part:
            entry = by_path[path]
            entry.bundle, entry.line = name, lines + 3
            blocks.append(block)
            lines += block.count('\n')
        payloads[name] = ''.join(blocks)
    return payloads


def inventory_text(entries):
    lines = ['COMPLETE FILE INDEX / COVERAGE REPORT',
             'Paths are repository-relative. Directory exclusions apply to ALL descendants.',
             'TEXT=full text; REDACTED=sensitive-filtered; METADATA=no content; SKIPPED=excluded; ERROR=unreadable.',
             'SHA256 identifies exported decoded text, not original bytes. No credentials are included in diagnostics.',
             'path | status | bundle:line | source bytes | exported SHA256 | reason']
    for entry in entries:
        location = f'{entry.bundle}:{entry.line}' if entry.line else '-'
        lines.append(f'{entry.path} | {entry.status} | {location} | {entry.size} | {entry.digest or "-"} | {entry.reason}')
    return '\n'.join(lines) + '\n'


def context_report(payloads, context_tokens=None, reserve_tokens=0, max_file_bytes=None):
    total = sum(len(text.encode('utf-8')) for text in payloads.values())
    estimate = math.ceil(total / 4)
    lines = [f'Attachment text: {total:,} UTF-8 bytes; roughly {estimate:,} tokens (bytes/4 heuristic).']
    for name, text in sorted(payloads.items()):
        size = len(text.encode('utf-8'))
        lines.append(f'  {name}: {size:,} bytes; ~{math.ceil(size / 4):,} tokens (estimate).')
    if context_tokens is None:
        lines.append('GUI fit: UNKNOWN. Supply --ui-context-tokens only from a verified limit for your exact GUI/model/account.')
    else:
        remaining = max(0, context_tokens - reserve_tokens)
        lines.append(f'User-supplied GUI budget: {context_tokens:,}; reserved for other context/reasoning/output: {reserve_tokens:,}.')
        lines.append(('WARNING: estimated attachment tokens exceed' if estimate > remaining else
                      'Estimate is below') + f' the {remaining:,}-token remaining budget; actual fit is NOT guaranteed.')
    if not reserve_tokens:
        lines.append('No numeric reserve supplied; leave room for conversation, instructions, reasoning and the answer.')
    if max_file_bytes:
        for name, text in payloads.items():
            if len(text.encode('utf-8')) > max_file_bytes:
                lines.append(f'WARNING: {name} exceeds your supplied per-file byte limit; nothing was truncated.')
    lines.append('For focused work use --focus "src/Edr.Engine/*" or --focus "src/Edr.Core/*" (repeatable); '
                 'all specs/configs/tests remain, other dependencies may be absent.')
    return '\n'.join(lines)


def describe_project(root):
    """Project line for the manifest, read from the repository itself so it never goes stale."""
    try:
        props = (root / 'src' / 'Directory.Build.props').read_text(encoding='utf-8-sig')
        match = re.search(r'<TargetFrameworks?>\s*([^<]+?)\s*</TargetFrameworks?>', props)
        framework = match[1] if match else 'unknown (no <TargetFramework> in src/Directory.Build.props)'
    except (OSError, UnicodeError):
        framework = 'unknown (src/Directory.Build.props unreadable)'
    programs = sorted(p.name for p in (root / 'src').glob('Edr.*') if p.is_dir() and not p.name.endswith('.Tests'))
    return ('Project: FreeEDR - free single-PC EDR + Wail2Ban for Windows 11 (Sysmon, YARA, Hayabusa/Sigma, OSV-Scanner, '
            'Velociraptor, Defender ASR); detect-only, Wail2Ban is the only part that blocks. '
            f'C# 14 / Avalonia / NativeAOT, target framework {framework} (read from src/Directory.Build.props); '
            f'projects in src/: {", ".join(programs) or "none found"}. Build pipeline: build/EdrBuild (C#) + Inno Setup.')


def generate_project_manifest(entries, snapshot, timestamp, focus, test_results, warnings, project_line, local_terms):
    counts = Counter(e.status for e in entries)
    roots = sorted({e.path.split('/')[0] for e in entries})
    groups = Counter(e.group for e in entries if e.status in {'TEXT', 'REDACTED'})
    missing_start = [p for p in START_HERE if not any(e.path == p and e.status in {'TEXT', 'REDACTED'} for e in entries)]
    lines = ['FREEEDR PROJECT EXPORT — READ THIS FIRST', f'Export UTC: {timestamp}',
             f'Git commit: {snapshot["commit"]}',
             'Working tree: ' + ('unavailable' if snapshot['status'] is None else 'modified/untracked files present' if snapshot['status'] else 'clean'),
             'Snapshot: live working-tree contents, including uncommitted/untracked files; not an atomic repository snapshot.',
             'Mode: ' + ('FOCUSED (incomplete by request): ' + ', '.join(focus) if focus else 'FULL eligible repository text'),
             project_line,
             '', 'READ ORDER:',
             '1. This manifest, then 00_file_structure.txt (path -> actual bundle + line).',
             '2. AGENTS.md, then project_structure.txt (hard rules, repository map, section 4 ROUTING TABLE: task -> docs).',
             '3. docs/agents/AGENT_WORKFLOW.md (build -> test -> report loop, design rules) and docs/history/STATUS.md',
             '   (known FAILs/WARNs: do not chase them), then ONLY the docs the routing table names for the task.',
             '4. Read the relevant implementation, its callers and its tests (tests/*.Tests.ps1, src/Edr.Core.Tests).',
             '5. In your answer identify files actually examined and coverage gaps; do not claim all attachments were read without checking.',
             'HARD RULES of this repository (project_structure.txt §1, §5):',
             '- After every code change: dev_build.cmd (all gates) and, UNELEVATED, tests\\Run-Tests.ps1; every FAIL/WARN is looked into.',
             '- Never run compiled\\FreeEDR-Setup.exe or FreeEDR-Installer.exe on the owner\'s PC without explicit approval.',
             '- NativeAOT: trim/AOT warnings are errors; tests are Windows PowerShell 5.1, *.ps1 = UTF-8 WITH BOM, *.yar = ASCII without BOM.',
             '- The engine is the Windows service "FreeEDR" (LocalSystem); the tray is unelevated; elevated actions go',
             '  UAC -> FreeEDR-Control.exe -> control\\ -> validation again in the engine (PatternRules).',
             '- The golden model tests (src/Edr.Core.Tests) pin the tray model; refresh with FREEEDR_UPDATE_GOLDEN=1 only on purpose.',
             '- A change to documented behaviour updates the routed doc and docs/history/STATUS.md in the same change.',
             'Tests are source, not evidence of passing runs. Architecture, framework and directory purpose come from the',
             'INCLUDED current specs/project files, not exporter summaries.',
             '', MODEL_GUIDANCE,
             'COVERAGE: ' + ', '.join(f'{key}={value}' for key, value in sorted(counts.items())),
             'Observed top-level entries: ' + ', '.join(roots),
             'Actual text groups: ' + ', '.join(f'{g}={n}' for g, n in sorted(groups.items())),
             'All skipped directories/files, metadata-only assets, errors and redactions: 00_file_structure.txt.',
             'Media pixels/audio and binary contents (compiled\\FreeEDR-Setup.exe, icons) are NOT provided by this text export.',
             'Private files never exported: git-ignored files, tests/results, obj/, build.log, *.log, event logs, keys/certificates,',
             'preinstall.json / managed.json, untracked files in runtime-named folders (data, local, logs, quarantine, ...).',
             'Sensitive filtering is heuristic (tokens, keys, secret-named values, user-profile names, domain SIDs, public IPv4 '
             'addresses in data files, emails, sign-in tenants, this PC\'s computer/user/domain names); review locally before uploading.',
             f'Local names masked: {len(local_terms)} (from this PC\'s environment and --redact-term; the terms themselves are not listed).',
             'Existing test reports: ' + (str(len(test_results)) + ' explicitly requested; may be stale/unrelated to this commit.' if test_results else 'none requested; no tests were run by the exporter.'),
             'Optional report copies: --test-result tests\\results\\last-run.txt (repeatable; encoding and secret checks still apply).',
             'Git state captured before traversal; per-file exported SHA256 is in the index.', '']
    if missing_start:
        warnings.append('Missing entry documents: ' + ', '.join(missing_start))
    if snapshot['status']:
        lines.extend(['LOCAL CHANGE STATUS (no diff or remotes):', snapshot['status'], ''])
    lines.extend('WARNING: ' + warning for warning in warnings)
    lines.append('')
    return '\n'.join(lines)


def run_aggregator(project_root=None, output_parent=None, focus=(), test_results=(),
                   context_tokens=None, reserve_tokens=0, max_file_bytes=None, legacy_encoding=None,
                   dry_run=False, redact_terms=(), max_source_bytes=DEFAULT_MAX_SOURCE_BYTES):
    root = Path(project_root or Path(__file__).resolve().parent.parent).resolve()
    if max_source_bytes <= 0:
        raise ValueError('Invalid source read limit.')
    if not root.is_dir():
        raise ValueError('Repository directory does not exist.')
    output_parent = Path(output_parent or get_downloads_directory() / OUTPUT_FOLDER_NAME).resolve()
    if output_parent == root or root in output_parent.parents:
        raise ValueError('Output must be outside the repository to prevent recursive exports.')
    if context_tokens is not None and (context_tokens <= 0 or reserve_tokens >= context_tokens):
        raise ValueError('Reserve must be smaller than the positive GUI context budget.')
    if reserve_tokens < 0 or (max_file_bytes is not None and max_file_bytes <= 0):
        raise ValueError('Invalid reserve or file limit.')
    if legacy_encoding:
        codecs.lookup(legacy_encoding)
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    local_terms = configure_local_terms(local_machine_terms() | set(redact_terms))
    snapshot = git_snapshot(root)
    tracked_set = {p.casefold() for p in snapshot['tracked']} if snapshot['available'] else None
    entries = collect_entries(root, focus, legacy_encoding, snapshot['ignored'], tracked_set, max_source_bytes)
    known = {e.path.casefold() for e in entries}
    skipped_dirs = [e for e in entries if e.path.endswith('/')]
    for tracked in snapshot['tracked']:
        if tracked and tracked.casefold() not in known:
            parent = next((e for e in skipped_dirs if tracked.casefold().startswith(e.path.casefold())), None)
            entries.append(Entry(tracked, 'SKIPPED' if parent else 'ERROR',
                                 f'under {parent.path}: {parent.reason}' if parent else 'tracked file absent from traversal (possibly locally deleted)'))
    for i, report in enumerate(test_results, 1):
        path = Path(report).absolute()
        entry = read_entry(path, f'[test-results]/{i}_{path.name}', '06_Tests', legacy_encoding, explicit_report=True,
                           max_source_bytes=max_source_bytes)
        if entry.status == 'TEXT':
            entry.reason = 'user-selected existing result; does not prove this snapshot passes'
        entries.append(entry)
    entries.sort(key=lambda e: e.path.casefold())
    warnings = []
    legacy_count = sum('fallback' in e.encoding for e in entries)
    if legacy_count:
        warnings.append(f'{legacy_count} file(s) used declared legacy encodings; exact encoding and its origin are in each file header.')
    if not snapshot['available']:
        warnings.append('Git metadata unavailable; tracked-file completeness could not be checked.')
    after = git_snapshot(root)
    if (snapshot['commit'], snapshot['status']) != (after['commit'], after['status']):
        warnings.append('Git state changed during export; rerun after edits settle.')
    error_count = sum(e.status == 'ERROR' for e in entries)
    if error_count:
        warnings.append(f'INCOMPLETE: {error_count} read/coverage errors; see index. Exit status 2.')
    for entry in entries:
        entry.path = redact_sensitive(entry.path)[0]
        entry.reason = redact_sensitive(entry.reason)[0]
    payloads = make_payloads(entries)
    payloads['00_file_structure.txt'] = inventory_text(entries)
    manifest = generate_project_manifest(entries, snapshot, timestamp, focus, test_results, warnings,
                                         describe_project(root), local_terms)
    manifest = redact_sensitive(manifest)[0]
    report = ''
    for _ in range(12):
        payloads['00_PROJECT_MANIFEST.txt'] = manifest + '\nUPLOAD SIZE REPORT\n' + report + '\n'
        next_report = context_report(payloads, context_tokens, reserve_tokens, max_file_bytes)
        if next_report == report:
            break
        report = next_report
    payloads['00_PROJECT_MANIFEST.txt'] = manifest + '\nUPLOAD SIZE REPORT\n' + report + '\n'
    counts = ', '.join(f'{k}={v}' for k, v in sorted(Counter(e.status for e in entries).items()))
    if dry_run:
        print(f'DRY RUN: nothing written. Would create a new folder under: {output_parent}')
        print(f'Would write {len(payloads)} .txt files (maximum 10): ' + ', '.join(sorted(payloads)))
        print(report)
        print('Coverage: ' + counts)
        for entry in entries:
            if entry.status in {'REDACTED', 'ERROR'}:
                print(f'  {entry.status}: {entry.path} - {entry.reason}')
        for warning in warnings:
            print('WARNING: ' + warning)
        return None, (2 if error_count else 0)
    output_parent.mkdir(parents=True, exist_ok=True)
    destination = output_parent / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ') + '_' + uuid.uuid4().hex[:8])
    destination.mkdir(exist_ok=False)
    for name in sorted(payloads, key=lambda n: (n == '00_PROJECT_MANIFEST.txt', n)):
        with (destination / name).open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(payloads[name])
    print(f'Export: {destination}\nUpload ONLY the {len(payloads)} .txt files in this folder (maximum 10).')
    print(report)
    print('Coverage: ' + counts)
    print('Previous exports preserved. Review the coverage/redaction index before uploading.')
    return destination, (2 if error_count else 0)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description='Export the FreeEDR repository into <=10 text files for advanced online AI GUIs. '
                                                 'Offline; read-only on the repository; preserves older exports.')
    parser.add_argument('--output-parent', type=Path, help=f'Parent for a NEW dated folder; default: ~/Downloads/{OUTPUT_FOLDER_NAME}')
    parser.add_argument('--project-root', type=Path, help='Repository root; default: the parent of developer_tools.')
    parser.add_argument('--focus', action='append', default=[], help='Optional repository-relative glob; repeatable. Keeps all docs/configs/tests.')
    parser.add_argument('--test-result', type=Path, action='append', default=[],
                        help='Include an existing report (e.g. tests\\results\\last-run.txt); never runs tests.')
    parser.add_argument('--ui-context-tokens', type=int, help='Confirmed context budget for your specific GUI/account; no assumed API limit.')
    parser.add_argument('--reserve-tokens', type=int, default=0, help='Capacity YOU reserve for conversation, instructions, reasoning and response.')
    parser.add_argument('--max-file-bytes', type=int, help='Confirmed GUI per-file byte cap; warn without truncation.')
    parser.add_argument('--legacy-encoding', help='Explicit fallback for non-UTF text, e.g. cp1252; strict decoding, recorded in each file header.')
    parser.add_argument('--dry-run', action='store_true', help='Build everything in memory and print the report; write nothing anywhere.')
    parser.add_argument('--redact-term', action='append', default=[],
                        help='Extra local word to mask everywhere (a second user, a host, a LAN name); repeatable, 4+ characters. '
                             'This PC\'s computer, user and domain names are masked automatically.')
    parser.add_argument('--max-source-bytes', type=int, default=DEFAULT_MAX_SOURCE_BYTES,
                        help=f'Text files larger than this are listed but not read (default: {DEFAULT_MAX_SOURCE_BYTES:,}).')
    args = parser.parse_args(argv)
    try:
        _, status = run_aggregator(project_root=args.project_root, output_parent=args.output_parent, focus=args.focus,
                                   test_results=args.test_result, context_tokens=args.ui_context_tokens,
                                   reserve_tokens=args.reserve_tokens, max_file_bytes=args.max_file_bytes,
                                   legacy_encoding=args.legacy_encoding, dry_run=args.dry_run,
                                   redact_terms=args.redact_term, max_source_bytes=args.max_source_bytes)
        return status
    except (OSError, ValueError, LookupError) as exc:
        print(f'Export FAILED ({type(exc).__name__}: {exc}); no previous exports were changed.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
