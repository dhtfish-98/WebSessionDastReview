"""Build and verify the source-only session experiment under an external Build.

All staging, environments, packages, logs, and receipts stay below the caller's
Build directory. The source checkout is read only during this validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
PACKAGE = 'web_session_dast_review'
TOOLS = ['build==1.3.0', 'setuptools==84.0.0', 'wheel==0.48.0']
SAFE_RUN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
EXPECTED_SOURCE = {
    '.gitignore', '.github/workflows/ci.yml', 'MANIFEST.in', 'pyproject.toml',
    'scripts/validate.py',
    'src/web_session_dast_review/__init__.py',
    'src/web_session_dast_review/experiment.py',
    'src/web_session_dast_review/http_probe.py',
    'src/web_session_dast_review/server.py',
    'tests/test_session_matrix.py',
    'tests/test_validator_safety.py',
    '项目文档/DESIGN.md', '项目文档/LICENSE', '项目文档/NOTICE.md',
    '项目文档/ORIGIN.md', '项目文档/README.md',
    '项目文档/SOURCE_MANIFEST.json', '项目文档/VALIDATION.md',
    '项目文档/VERSION_STATUS.md',
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> list[Path]:
    files: list[Path] = []
    for path in PROJECT.rglob('*'):
        rel = path.relative_to(PROJECT)
        if '.git' in rel.parts:
            continue
        if 'Build' in rel.parts or '__pycache__' in rel.parts or any(part.endswith('.egg-info') for part in rel.parts):
            raise RuntimeError(f'generated directory found in source checkout: {rel}')
        if path.suffix in {'.pyc', '.pyo'}:
            raise RuntimeError(f'compiled Python file found in source checkout: {rel}')
        if path.is_symlink():
            raise RuntimeError(f'symlink found in source checkout: {rel}')
        if path.is_file():
            files.append(path)
    return sorted(files)


def run_step(label: str, argv: list[str], cwd: Path, env: dict[str, str], logs: Path, steps: list[dict[str, object]]) -> None:
    process = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = logs / f'{label}.log'
    log.write_text(process.stdout, encoding='utf-8')
    steps.append({'step': label, 'command': argv, 'cwd': str(cwd), 'exit_code': process.returncode, 'log': str(log)})
    if process.returncode:
        raise RuntimeError(f'{label} failed; see {log}')


def assert_tests(log: Path) -> int:
    content = log.read_text()
    match = re.search(r'Ran (\d+) tests in', content)
    if not match or int(match.group(1)) != 15 or not re.search(r'\nOK\s*$', content):
        raise RuntimeError(f'unit test count/result did not match 15 PASS: {log}')
    return int(match.group(1))


def assert_matrix(path: Path) -> int:
    receipt = json.loads(path.read_text())
    if receipt.get('checked_rows') != 36 or receipt.get('raw_session_ids_or_passwords_logged') is not False:
        raise RuntimeError(f'invalid 36-row loopback receipt: {path}')
    variants = {part['variant']: part for part in receipt['variants']}
    if set(variants) != {'weak_baseline', 'fixed'}:
        raise RuntimeError(f'missing weak or fixed variant: {path}')
    for name, variant in variants.items():
        if variant.get('bind_address') != '127.0.0.1' or variant.get('checked_rows') != 18:
            raise RuntimeError(f'invalid loopback scope/row count: {name}')
        if len(variant['request_matrix']) != 18 or len(variant['server_request_log']) != 18:
            raise RuntimeError(f'missing actual server request evidence: {name}')
        if any(row['status'] != row['expected_status'] or row['check'] != 'PASS' for row in variant['request_matrix']):
            raise RuntimeError(f'HTTP status matrix failed: {name}')
    if (variants['weak_baseline']['outcome'], variants['fixed']['outcome']) != (
        'DEMONSTRATED_INTENTIONAL_WEAKNESS', 'PASS_FIXED_CONTROLS'
    ):
        raise RuntimeError('weak/fixed outcomes were not distinguished')
    return 36


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--run-id')
    opts = parser.parse_args()
    base = opts.build_root.resolve()
    if 'Build' not in base.parts or base == PROJECT or PROJECT in base.parents:
        raise SystemExit('--build-root must be outside the source checkout under a Build directory')
    base.mkdir(parents=True, exist_ok=True)
    run_id = opts.run_id or datetime.now(timezone.utc).strftime('run-%Y%m%dT%H%M%SZ')
    if not SAFE_RUN_ID.fullmatch(run_id) or '..' in run_id:
        raise SystemExit('--run-id must be a single safe directory name')
    run_dir = (base / run_id).resolve()
    if run_dir == base or not run_dir.is_relative_to(base):
        raise SystemExit('--run-id must resolve inside --build-root')
    run_dir.mkdir(exist_ok=False)
    logs = run_dir / 'logs'
    logs.mkdir()
    (run_dir / 'tmp').mkdir()
    (run_dir / 'cache').mkdir()
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    env.update({
        'PYTHONDONTWRITEBYTECODE': '1',
        'TMPDIR': str(run_dir / 'tmp'),
        'PIP_CACHE_DIR': str(run_dir / 'cache'),
        'PIP_DISABLE_PIP_VERSION_CHECK': '1',
    })
    steps: list[dict[str, object]] = []
    receipt: dict[str, object] = {
        'schema': 'web-session-dast-validation-v1',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'candidate_version': '0.1.0',
        'python_version': sys.version.split()[0],
        'source_root': str(PROJECT),
        'steps': steps,
        'status': 'FAIL',
    }
    try:
        files = source_files()
        manifest = {str(path.relative_to(PROJECT)): sha(path) for path in files}
        if set(manifest) != EXPECTED_SOURCE:
            raise RuntimeError(f'source file set differs from frozen v0.1.0: missing={sorted(EXPECTED_SOURCE-set(manifest))}; extra={sorted(set(manifest)-EXPECTED_SOURCE)}')
        declared = json.loads((PROJECT / '项目文档/SOURCE_MANIFEST.json').read_text())
        declared_files = {item['path']: item for item in declared['files']}
        if declared['version'] != '0.1.0' or declared['author'] != 'dhtfish98' or set(declared_files) != {name for name in EXPECTED_SOURCE if not name.startswith('项目文档/')}:
            raise RuntimeError('source manifest identity or file set differs from frozen v0.1.0')
        if any(declared_files[name]['sha256'] != manifest[name] or declared_files[name]['bytes'] != (PROJECT / name).stat().st_size for name in declared_files):
            raise RuntimeError('source manifest digest or byte count differs from current source')
        receipt['source_files_sha256'] = manifest
        receipt['source_file_count'] = len(manifest)

        staged = run_dir / 'staged-source'
        staged.mkdir()
        for path in files:
            relative = path.relative_to(PROJECT)
            destination = staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            if sha(destination) != manifest[str(relative)]:
                raise RuntimeError(f'staged source changed: {relative}')

        source_env = run_dir / 'source-env'
        venv.EnvBuilder(with_pip=True).create(source_env)
        python = str(source_env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))
        run_step('install-build-tools', [python, '-m', 'pip', 'install', *TOOLS], run_dir, env, logs, steps)
        source_import = env | {
            'PYTHONPATH': str(PROJECT / 'src'),
            'WEB_SESSION_VALIDATOR_PATH': str(PROJECT / 'scripts/validate.py'),
            'WEB_SESSION_SAFETY_BUILD_ROOT': str(run_dir / 'safety-tests'),
        }
        run_step('source-unittest', [python, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], PROJECT, source_import, logs, steps)
        run_step('source-live-http', [python, '-m', f'{PACKAGE}.experiment', '--output', str(run_dir / 'source-matrix.json')], PROJECT, source_import, logs, steps)

        dist = run_dir / 'dist'
        dist.mkdir()
        run_step('build-distributions', [python, '-m', 'build', '--no-isolation', '--outdir', str(dist), str(staged)], run_dir, env, logs, steps)
        wheels = list(dist.glob('*.whl'))
        sdists = list(dist.glob('*.tar.gz'))
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError('exactly one wheel and one sdist are required')
        wheel, sdist = wheels[0], sdists[0]
        receipt['artifacts'] = {
            path.name: {'sha256': sha(path), 'bytes': path.stat().st_size}
            for path in (wheel, sdist)
        }

        unpacked = run_dir / 'sdist-source'
        unpacked.mkdir()
        with tarfile.open(sdist, 'r:gz') as tf:
            archive: dict[str, bytes] = {}
            for member in tf.getmembers():
                parts = Path(member.name).parts
                if member.isdir():
                    continue
                if not member.isfile() or len(parts) < 2 or parts[0] != f'{PACKAGE}-0.1.0' or '..' in parts:
                    raise RuntimeError('unsafe or unexpected sdist member')
                relative = Path(*parts[1:])
                data = tf.extractfile(member).read()
                archive[str(relative)] = data
                target = unpacked / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        if any(name not in archive or hashlib.sha256(archive[name]).hexdigest() != digest for name, digest in manifest.items()):
            raise RuntimeError('sdist omitted or changed candidate source')
        receipt['sdist_source_files_exact'] = len(manifest)
        sdist_import = env | {
            'PYTHONPATH': str(unpacked / 'src'),
            'WEB_SESSION_VALIDATOR_PATH': str(unpacked / 'scripts/validate.py'),
            'WEB_SESSION_SAFETY_BUILD_ROOT': str(run_dir / 'safety-tests'),
        }
        run_step('sdist-unittest', [python, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], unpacked, sdist_import, logs, steps)
        run_step('sdist-live-http', [python, '-m', f'{PACKAGE}.experiment', '--output', str(run_dir / 'sdist-matrix.json')], unpacked, sdist_import, logs, steps)

        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
            runtime = [name for name in manifest if name.startswith(f'src/{PACKAGE}/') and name.endswith('.py')]
            if len(runtime) != 4 or any(
                name.removeprefix('src/') not in names or hashlib.sha256(zf.read(name.removeprefix('src/'))).hexdigest() != manifest[name]
                for name in runtime
            ):
                raise RuntimeError('wheel runtime modules differ from source')
            if any(name.startswith('tests/') or 'Build/' in name for name in names):
                raise RuntimeError('tests or generated output leaked into wheel')
            metadata = Parser().parsestr(zf.read(next(name for name in names if name.endswith('.dist-info/METADATA'))).decode())
            if (metadata['Name'], metadata['Version'], metadata['Author'], metadata['License-Expression']) != (
                'web-session-dast-review', '0.1.0', 'dhtfish98', 'MIT'
            ):
                raise RuntimeError('wheel name/version/author/license mismatch')
            license_file = next(name for name in names if name.endswith('licenses/项目文档/LICENSE'))
            if zf.read(license_file) != (PROJECT / '项目文档/LICENSE').read_bytes():
                raise RuntimeError('wheel license differs from source')
        receipt['wheel_runtime_files_exact'] = len(runtime)

        consumer_env = run_dir / 'consumer-env'
        venv.EnvBuilder(with_pip=True).create(consumer_env)
        consumer_python = str(consumer_env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))
        run_step('install-wheel', [consumer_python, '-m', 'pip', 'install', '--no-deps', str(wheel)], run_dir, env, logs, steps)
        consumer_tests = run_dir / 'consumer-tests'
        shutil.copytree(PROJECT / 'tests', consumer_tests, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        installed_test_env = env | {
            'WEB_SESSION_VALIDATOR_PATH': str(staged / 'scripts/validate.py'),
            'WEB_SESSION_SAFETY_BUILD_ROOT': str(run_dir / 'safety-tests'),
        }
        run_step('installed-unittest', [consumer_python, '-m', 'unittest', 'discover', '-s', str(consumer_tests), '-v'], run_dir, installed_test_env, logs, steps)
        run_step('installed-live-http', [consumer_python, '-m', f'{PACKAGE}.experiment', '--output', str(run_dir / 'installed-matrix.json')], run_dir, env, logs, steps)
        run_step('installed-version-check', [consumer_python, '-c',
            "import importlib.metadata as m,web_session_dast_review as p; assert (m.version('web-session-dast-review'),p.__version__)==('0.1.0','0.1.0'); print(p.__version__)"],
            run_dir, env, logs, steps)

        receipt['unittest_counts'] = {
            stage: assert_tests(logs / f'{stage}-unittest.log') for stage in ('source', 'sdist', 'installed')
        }
        receipt['http_matrix_rows'] = {
            stage: assert_matrix(run_dir / f'{stage}-matrix.json') for stage in ('source', 'sdist', 'installed')
        }
        receipt['status'] = 'PASS_LOCAL_ENGINEERING'
    except Exception as exc:
        receipt['error'] = str(exc)
    finally:
        receipt['finished_utc'] = datetime.now(timezone.utc).isoformat()
        path = run_dir / 'validation.json'
        path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': receipt['status'], 'receipt': str(path), 'steps': len(steps)}, ensure_ascii=False))
    return 0 if receipt['status'] == 'PASS_LOCAL_ENGINEERING' else 1


if __name__ == '__main__':
    raise SystemExit(main())
