"""Reject run identifiers that could move validation output outside Build."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


class ValidatorOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        checkout = Path(__file__).resolve().parents[1]
        self.validator = Path(os.environ.get('WEB_SESSION_VALIDATOR_PATH', str(checkout / 'scripts/validate.py'))).resolve()
        build = next((parent for parent in checkout.parents if parent.name == 'Build'), None)
        if build is None:
            build = checkout.parent / 'Build'
        default_build_root = build / '验证/WebSessionDastReview-v0.1.0/direct-tests'
        self.build_root = Path(os.environ.get('WEB_SESSION_SAFETY_BUILD_ROOT', str(default_build_root))).resolve()
        self.assertTrue(self.validator.is_file())
        self.assertIn('Build', self.build_root.parts)
        self.build_root.mkdir(parents=True, exist_ok=True)

    def reject(self, run_id: str, expected: str) -> None:
        result = subprocess.run(
            [sys.executable, str(self.validator), '--build-root', str(self.build_root), '--run-id', run_id],
            cwd=self.build_root,
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stdout)

    def test_absolute_run_id_rejected_without_output(self) -> None:
        target = self.build_root.parent / f'absolute-escape-{uuid.uuid4().hex}'
        self.reject(str(target), '--run-id must be a single safe directory name')
        self.assertFalse(target.exists())

    def test_parent_run_id_rejected_without_output(self) -> None:
        name = f'parent-escape-{uuid.uuid4().hex}'
        target = self.build_root.parent / name
        self.reject(f'../{name}', '--run-id must be a single safe directory name')
        self.assertFalse(target.exists())

    def test_symlink_run_id_rejected_after_resolution(self) -> None:
        with tempfile.TemporaryDirectory(prefix='outside-run-', dir=self.build_root.parent) as directory:
            target = Path(directory)
            link = self.build_root / f'linked-run-{uuid.uuid4().hex}'
            link.symlink_to(target, target_is_directory=True)
            try:
                self.reject(link.name, '--run-id must resolve inside --build-root')
                self.assertEqual(list(target.iterdir()), [])
            finally:
                link.unlink()


if __name__ == '__main__':
    unittest.main()
