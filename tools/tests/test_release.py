from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('zarp_release', ROOT / 'tools/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='zarp-release-test-')
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.runtime = self.work / 'runtime'
        self.runtime.mkdir()
        (self.runtime / 'nfqws2').write_bytes(b'verified runtime')
        (self.runtime / 'integrity.json').write_text(json.dumps({
            'schema': 1, 'versions': {'zapret2': 'test'},
            'files': {'nfqws2': hashlib.sha256(b'verified runtime').hexdigest()},
        }))

    def stage(self, platform):
        directory = self.work / ('build-' + platform)
        directory.mkdir()
        package = directory / ('zarp-' + release.version() + '-1' + release.SUFFIXES[platform])
        package.write_bytes(('package for ' + platform).encode())
        package.with_name(package.name + '.sha256').write_text(release.sha256(package) + '  ' + package.name)
        target = self.work / 'artifacts' / platform
        release.stage(platform, directory, self.runtime, target)
        return target

    def test_release_requires_matching_tag(self):
        release.validate_tag(release.version(), 'v' + release.version())
        for tag in ('v999.0.0', 'main', 'v' + release.version() + '-rc.1'):
            with self.assertRaises(ValueError):
                release.validate_tag(release.version(), tag)

    def test_complete_release_has_verified_checksums(self):
        for platform in release.ASSETS:
            self.stage(platform)
        output = self.work / 'release'
        release.collect(self.work / 'artifacts', output)
        lines = (output / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(release.sha256(output / name), digest)
        manifest = json.loads((output / 'release-manifest.json').read_text())
        self.assertEqual(manifest['version'], release.version())
        self.assertEqual({p['platform'] for p in manifest['packages']}, set(release.ASSETS))

    def test_partial_release_is_rejected(self):
        self.stage('ubuntu')
        with self.assertRaises(ValueError):
            release.collect(self.work / 'artifacts', self.work / 'release')

    def test_corrupt_downloaded_artifact_is_rejected(self):
        for platform in release.ASSETS:
            target = self.stage(platform)
        (target / release.ASSETS['arch']).write_bytes(b'corrupted package')
        with self.assertRaises(ValueError):
            release.collect(self.work / 'artifacts', self.work / 'release')

    def test_runtime_tampering_is_rejected_before_staging(self):
        (self.runtime / 'nfqws2').write_bytes(b'modified engine')
        with self.assertRaises(ValueError):
            self.stage('debian')

if __name__ == '__main__':
    unittest.main()
