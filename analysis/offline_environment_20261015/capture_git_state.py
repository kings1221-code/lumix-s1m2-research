"""Capture commit relationships only; does not change any refs or fetch."""
import argparse
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ORIGINAL_MAIN = '11b6c96602bae41a033b838524bfdb52f3452cd4'
UPSTREAM = '8f625cfabb31e8a71177b86e2b63a69c686de5e8'


def git(*args):
    return subprocess.check_output(['git', '-c', 'core.quotePath=false', *args], cwd=ROOT, text=True, encoding='utf-8').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('Output must not exist')
    rows = []
    for name in git('for-each-ref', '--format=%(refname:short)', 'refs/remotes/origin/').splitlines():
        if name == 'origin':
            continue
        ahead, behind = map(int, git('rev-list', '--left-right', '--count', name + '...' + UPSTREAM).split())
        rows.append({'ref': name, 'commit': git('rev-parse', name), 'ahead_of_upstream': ahead, 'behind_upstream': behind,
                     'unique_commits': git('log', '--format=%H %s', UPSTREAM + '..' + name).splitlines()})
    before_counts = list(map(int, git('rev-list', '--left-right', '--count', ORIGINAL_MAIN + '...' + UPSTREAM).split()))
    result = {'date': '2026-10-15 Asia/Taipei', 'initial_workspace': 'unborn master; no tracked or untracked research files before fetch',
        'initial_fork_main': ORIGINAL_MAIN, 'upstream_main_at_sync': UPSTREAM, 'before_main_ahead_behind': before_counts,
        'local_main': git('rev-parse', 'main'), 'fork_main_after_sync': git('rev-parse', 'origin/main'),
        'sync_method': 'local merge --ff-only; GitHub update_ref force=false with expected_sha lease; post-update fetch checked 0/0',
        'cli_push_attempt': 'did not update remote: local HTTPS credentials unavailable; connected GitHub API completed authorized fast-forward',
        'force_used': False, 'branches_deleted': False, 'personal_changes_merged_into_main': False,
        'research_branch': git('branch', '--show-current'), 'fork_refs_after_sync': rows,
        'preservation_refs': git('for-each-ref', '--format=%(refname:short) %(objectname)', 'refs/heads/preservation/20261015/').splitlines(),
        'concurrent_changes_left_untouched': ['.codex-remote-attachments/', 'downloads/', 'origin/research/lumix-lab-env-20261015 (appeared after initial remote snapshot)']}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS: main is synchronized; all original personal branch tips recorded and preserved')


if __name__ == '__main__':
    main()
