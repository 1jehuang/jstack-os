import json
from pathlib import Path
import runpy
import tempfile
import unittest

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'files/scripts/jcode-desktop-pss'))


class DesktopPssTests(unittest.TestCase):
    def test_filters_and_sums_pss_not_rss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, name, pss in [(1, 'jcode-desktop', 1024), (2, 'jcode-desktop', 2048),
                                   (3, 'jcode', 100000), (4, 'rustc', 100000),
                                   (5, 'jcode-harness-a', 100000)]:
                path = root / str(pid)
                path.mkdir()
                (path / 'comm').write_text(name + '\n')
                (path / 'smaps_rollup').write_text(f'Rss: 999999 kB\nPss: {pss} kB\nSwapPss: 500 kB\n')
            (root / 'self').mkdir()
            processes, unreadable = MODULE['collect'](root)
            self.assertEqual(processes, [(2048, 2), (1024, 1)])
            self.assertEqual(unreadable, 0)
            result = MODULE['render'](processes, unreadable)
            self.assertTrue(result['text'].endswith('3M'))
            self.assertIn('2 processes', result['tooltip'])
            json.dumps(result)

    def test_exiting_and_invalid_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid in ('1', '2', '3'):
                path = root / pid
                path.mkdir()
                (path / 'comm').write_text('jcode-desktop')
            (root / '2/smaps_rollup').write_text('Pss: invalid kB')
            (root / '3/smaps_rollup').write_text('Rss: 1234 kB')
            self.assertEqual(MODULE['collect'](root), ([], 2))

    def test_empty_partial_and_thresholds(self):
        self.assertEqual(MODULE['render']([])['class'], 'hidden')
        self.assertTrue(MODULE['render']([], 1)['text'].endswith('?'))
        self.assertTrue(MODULE['render']([(1024, 1)], 1)['text'].endswith('1M+'))
        for gib, level in [(1, 'normal'), (2, 'warning'), (4, 'high')]:
            result = MODULE['render']([(gib * 1024**2, 1)])
            self.assertEqual(result['class'], level)
            self.assertTrue(result['text'].endswith(f'{gib:.1f}G'))


if __name__ == '__main__':
    unittest.main()
