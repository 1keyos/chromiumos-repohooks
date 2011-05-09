# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import re
import sys
import subprocess

from errors import (VerifyException, HookFailure, PrintErrorForProject,
                    PrintErrorsForCommit)


COMMON_INCLUDED_PATHS = [
  # C++ and friends
  r".*\.c$", r".*\.cc$", r".*\.cpp$", r".*\.h$", r".*\.m$", r".*\.mm$",
  r".*\.inl$", r".*\.asm$", r".*\.hxx$", r".*\.hpp$", r".*\.s$", r".*\.S$",
  # Scripts
  r".*\.js$", r".*\.py$", r".*\.sh$", r".*\.rb$", r".*\.pl$", r".*\.pm$",
  # No extension at all, note that ALL CAPS files are black listed in
  # COMMON_EXCLUDED_LIST below.
  r"(^|.*?[\\\/])[^.]+$",
  # Other
  r".*\.java$", r".*\.mk$", r".*\.am$",
]


COMMON_EXCLUDED_PATHS = [
  # avoid doing source file checks for kernel
  r"/src/third_party/kernel/",
  r"/src/third_party/kernel-next/",
  r"/src/third_party/ktop/",
  r"/src/third_party/punybench/",
  r".*\bexperimental[\\\/].*",
  r".*\b[A-Z0-9_]{2,}$",
  r".*[\\\/]debian[\\\/]rules$",
]


# General Helpers


def _run_command(cmd):
  """Executes the passed in command and returns raw stdout output."""
  return subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]


def _get_hooks_dir():
  """Returns the absolute path to the repohooks directory."""
  cmd = ['repo', 'forall', 'chromiumos/repohooks', '-c', 'pwd']
  return _run_command(cmd).strip()


def _match_regex_list(subject, expressions):
  """Try to match a list of regular expressions to a string.

  Args:
    subject: The string to match regexes on
    expressions: A list of regular expressions to check for matches with.

  Returns:
    Whether the passed in subject matches any of the passed in regexes.
  """
  for expr in expressions:
    if (re.search(expr, subject)):
      return True
  return False


def _filter_files(files, include_list, exclude_list=[]):
  """Filter out files based on the conditions passed in.

  Args:
    files: list of filepaths to filter
    include_list: list of regex that when matched with a file path will cause it
        to be added to the output list unless the file is also matched with a
        regex in the exclude_list.
    exclude_list: list of regex that when matched with a file will prevent it
        from being added to the output list, even if it is also matched with a
        regex in the include_list.

  Returns:
    A list of filepaths that contain files matched in the include_list and not
    in the exclude_list.
  """
  filtered = []
  for f in files:
    if (_match_regex_list(f, include_list) and
        not _match_regex_list(f, exclude_list)):
      filtered.append(f)
  return filtered


# Git Helpers


def _get_upstream_branch():
  """Returns the upstream tracking branch of the current branch.

  Raises:
    Error if there is no tracking branch
  """
  current_branch = _run_command(['git', 'symbolic-ref', 'HEAD']).strip()
  current_branch = current_branch.replace('refs/heads/', '')
  if not current_branch:
    raise VerifyException('Need to be on a tracking branch')

  cfg_option = 'branch.' + current_branch + '.%s'
  full_upstream = _run_command(['git', 'config', cfg_option % 'merge']).strip()
  remote = _run_command(['git', 'config', cfg_option % 'remote']).strip()
  if not remote or not full_upstream:
    raise VerifyException('Need to be on a tracking branch')

  return full_upstream.replace('heads', 'remotes/' + remote)


def _get_diff(commit):
  """Returns the diff for this commit."""
  return _run_command(['git', 'show', commit])


def _get_file_diff(file, commit):
  """Returns a list of (linenum, lines) tuples that the commit touched."""
  output = _run_command(['git', 'show', '-p', '--no-ext-diff', commit, file])

  new_lines = []
  line_num = 0
  for line in output.splitlines():
    m = re.match(r'^@@ [0-9\,\+\-]+ \+([0-9]+)\,[0-9]+ @@', line)
    if m:
      line_num = int(m.groups(1)[0])
      continue
    if line.startswith('+') and not line.startswith('++'):
      new_lines.append((line_num, line[1:]))
    if not line.startswith('-'):
      line_num += 1
  return new_lines


def _get_affected_files(commit):
  """Returns list of absolute filepaths that were modified/added."""
  output = _run_command(['git', 'diff', '--name-status', commit + '^!'])
  files = []
  for statusline in output.splitlines():
    m = re.match('^(\w)+\t(.+)$', statusline.rstrip())
    # Ignore deleted files, and return absolute paths of files
    if (m.group(1)[0] != 'D'):
      pwd = os.getcwd()
      files.append(os.path.join(pwd, m.group(2)))
  return files


def _get_commits():
  """Returns a list of commits for this review."""
  cmd = ['git', 'log', '%s..' % _get_upstream_branch(), '--format=%H']
  return _run_command(cmd).split()


def _get_commit_desc(commit):
  """Returns the full commit message of a commit."""
  return _run_command(['git', 'log', '--format=%s%n%n%b', commit + '^!'])


# Common Hooks


def _check_no_long_lines(project, commit):
  """Checks that there aren't any lines longer than maxlen characters in any of
  the text files to be submitted.
  """
  MAX_LEN = 80

  errors = []
  files = _filter_files(_get_affected_files(commit),
                        COMMON_INCLUDED_PATHS,
                        COMMON_EXCLUDED_PATHS)

  for afile in files:
    for line_num, line in _get_file_diff(afile, commit):
      # Allow certain lines to exceed the maxlen rule.
      if (len(line) > MAX_LEN and
          not 'http://' in line and
          not 'https://' in line and
          not line.startswith('#define') and
          not line.startswith('#include') and
          not line.startswith('#import') and
          not line.startswith('#pragma') and
          not line.startswith('#if') and
          not line.startswith('#endif')):
        errors.append('%s, line %s, %s chars' % (afile, line_num, len(line)))
        if len(errors) == 5:  # Just show the first 5 errors.
          break

  if errors:
    msg = 'Found lines longer than %s characters (first 5 shown):' % MAX_LEN
    return HookFailure(msg, errors)


def _check_no_stray_whitespace(project, commit):
  """Checks that there is no stray whitespace at source lines end."""
  errors = []
  files = _filter_files(_get_affected_files(commit),
                                COMMON_INCLUDED_PATHS,
                                COMMON_EXCLUDED_PATHS)

  for afile in files:
    for line_num, line in _get_file_diff(afile, commit):
      if line.rstrip() != line:
        errors.append('%s, line %s' % (afile, line_num))
    if errors:
      return HookFailure('Found line ending with white space in:', errors)


def _check_no_tabs(project, commit):
  """Checks there are no unexpanded tabs."""
  TAB_OK_PATHS = [
      r"/src/platform/u-boot-config/",
      r"/src/third_party/u-boot/",
      r"/src/third_party/u-boot-next/",
      r".*\.ebuild$",
      r".*\.eclass$",
      r".*/[M|m]akefile$"
  ]

  errors = []
  files = _filter_files(_get_affected_files(commit),
                        COMMON_INCLUDED_PATHS,
                        COMMON_EXCLUDED_PATHS + TAB_OK_PATHS)

  for afile in files:
    for line_num, line in _get_file_diff(afile, commit):
      if '\t' in line:
          errors.append('%s, line %s' % (afile, line_num))
  if errors:
    return HookFailure('Found a tab character in:', errors)


def _check_change_has_test_field(project, commit):
  """Check for a non-empty 'TEST=' field in the commit message."""
  TEST_RE = r'\n\s*TEST\s*=[^\n]*\S+'

  if not re.search(TEST_RE, _get_commit_desc(commit)):
    msg = 'Changelist description needs TEST field (after first line)'
    return HookFailure(msg)


def _check_change_has_bug_field(project, commit):
  """Check for a non-empty 'BUG=' field in the commit message."""
  BUG_RE = r'\n\s*BUG\s*=[^\n]*\S+'

  if not re.search(BUG_RE, _get_commit_desc(commit)):
    msg = 'Changelist description needs BUG field (after first line)'
    return HookFailure(msg)


def _check_change_has_proper_changeid(project, commit):
  """Verify that Change-ID is present in last paragraph of commit message."""
  desc = _get_commit_desc(commit)
  loc = desc.rfind('\nChange-Id:')
  if loc == -1 or re.search('\n\s*\n\s*\S+', desc[loc:]):
    return HookFailure('Change-Id must be in last paragraph of description.')


def _check_license(project, commit):
  """Verifies the license header."""
  LICENSE_HEADER = (
     r".*? Copyright \(c\) 20[-0-9]{2,7} The Chromium OS Authors\. All rights "
       r"reserved\." "\n"
     r".*? Use of this source code is governed by a BSD-style license that can "
       "be\n"
     r".*? found in the LICENSE file\."
       "\n"
  )

  license_re = re.compile(LICENSE_HEADER, re.MULTILINE)
  bad_files = []
  files = _filter_files(_get_affected_files(commit),
                        COMMON_INCLUDED_PATHS,
                        COMMON_EXCLUDED_PATHS)

  for f in files:
    contents = open(f).read()
    if len(contents) == 0: continue  # Ignore empty files
    if not license_re.search(contents):
      bad_files.append(f)
  if bad_files:
    return HookFailure('License must match:\n%s\n' % license_re.pattern +
                          'Found a bad license header in these files:',
                          bad_files)


# Project-specific hooks


def _run_checkpatch(project, commit):
  """Runs checkpatch.pl on the given project"""
  hooks_dir = _get_hooks_dir()
  cmd = ['%s/checkpatch.pl' % hooks_dir, '-']
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  output = p.communicate(_get_diff(commit))[0]
  if p.returncode:
    return HookFailure('checkpatch.pl errors/warnings\n\n' + output)


def _run_json_check(project, commit):
  """Checks that all JSON files are syntactically valid."""
  for f in _filter_files(_get_affected_files(commit), [r'.*\.json']):
    try:
      json.load(open(f))
    except Exception, e:
      return HookFailure('Invalid JSON in %s: %s' % (f, e))


# Base


COMMON_HOOKS = [_check_change_has_bug_field,
                _check_change_has_test_field,
                _check_change_has_proper_changeid,
                _check_no_stray_whitespace,
                _check_no_long_lines,
                _check_license,
                _check_no_tabs]


def _setup_project_hooks():
  """Returns a dictionay of callbacks: dict[project] = [callback1, callback2]"""
  return {
    "chromiumos/third_party/kernel": [_run_checkpatch],
    "chromiumos/third_party/kernel-next": [_run_checkpatch],
    "chromeos/autotest-tools": [_run_json_check],
    }


def _run_project_hooks(project, hooks):
  """For each project run its project specific hook from the hooks dictionary.

  Args:
    project: name of project to run hooks for.
    hooks: a dictionary of hooks indexed by project name

  Returns:
    Boolean value of whether any errors were ecountered while running the hooks.
  """
  proj_dir = _run_command(['repo', 'forall', project, '-c', 'pwd']).strip()
  pwd = os.getcwd()
  # hooks assume they are run from the root of the project
  os.chdir(proj_dir)

  project_specific_hooks = []
  if project in hooks:
    project_specific_hooks = hooks[project]

  try:
    commit_list = _get_commits()
  except VerifyException as e:
    PrintErrorForProject(project, HookFailure(str(e)))
    os.chdir(pwd)
    return True

  error_found = False
  for commit in commit_list:
    error_list = []
    for hook in COMMON_HOOKS + project_specific_hooks:
      hook_error = hook(project, commit)
      if hook_error:
        error_list.append(hook_error)
        error_found = True
    if error_list:
      PrintErrorsForCommit(project, commit, _get_commit_desc(commit),
                           error_list)

  os.chdir(pwd)
  return error_found


# Main


def main(project_list, **kwargs):
  hooks = _setup_project_hooks()

  found_error = False
  for project in project_list:
    if _run_project_hooks(project, hooks):
      found_error = True

  if (found_error):
    msg = ('Preupload failed due to errors in project(s). HINTS:\n'
           '- To upload only current project, run \'repo upload .\'\n'
           '- Errors may also be due to old upload hooks.  Please run '
           '\'repo sync chromiumos/repohooks\' to update.')
    print >> sys.stderr, msg
    sys.exit(1)


if __name__ == '__main__':
  main()
