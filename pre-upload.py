#!/usr/bin/env python
# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import ConfigParser
import json
import optparse
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
  # for ebuild trees, ignore any caches and manifest data
  r".*/Manifest$",
  r".*/metadata/[^/]*cache[^/]*/[^/]+/[^/]+$",

  # ignore profiles data (like overlay-tegra2/profiles)
  r".*/overlay-.*/profiles/.*",
]


_CONFIG_FILE = 'PRESUBMIT.cfg'


# Exceptions


class BadInvocation(Exception):
  """An Exception indicating a bad invocation of the program."""
  pass


# General Helpers


def _run_command(cmd, cwd=None, stderr=None):
  """Executes the passed in command and returns raw stdout output.

  Args:
    cmd: The command to run; should be a list of strings.
    cwd: The directory to switch to for running the command.
    stderr: Can be one of None (print stderr to console), subprocess.STDOUT
        (combine stderr with stdout), or subprocess.PIPE (ignore stderr).

  Returns:
    The standard out from the process.
  """
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr, cwd=cwd)
  return p.communicate()[0]


def _get_hooks_dir():
  """Returns the absolute path to the repohooks directory."""
  if __name__ == '__main__':
    # Works when file is run on its own (__file__ is defined)...
    return os.path.abspath(os.path.dirname(__file__))
  else:
    # We need to do this when we're run through repo.  Since repo executes
    # us with execfile(), we don't get __file__ defined.
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
      r"/src/third_party/u-boot/",
      r".*\.ebuild$",
      r".*\.eclass$",
      r".*/[M|m]akefile$",
      r".*\.mk$"
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
  TEST_RE = r'\nTEST=\S+'

  if not re.search(TEST_RE, _get_commit_desc(commit)):
    msg = 'Changelist description needs TEST field (after first line)'
    return HookFailure(msg)


def _check_change_has_bug_field(project, commit):
  """Check for a correctly formatted 'BUG=' field in the commit message."""
  BUG_RE = r'\nBUG=([Nn]one|(chrome-os-partner|chromium|chromium-os):\d+)'

  if not re.search(BUG_RE, _get_commit_desc(commit)):
    msg = ('Changelist description needs BUG field (after first line):\n'
           'BUG=chromium-os:9999 (for public tracker)\n'
           'BUG=chrome-os-partner:9999 (for partner tracker)\n'
           'BUG=chromium:9999 (for browser tracker)\n'
           'BUG=None')
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


def _run_checkpatch(project, commit, options=[]):
  """Runs checkpatch.pl on the given project"""
  hooks_dir = _get_hooks_dir()
  cmd = ['%s/checkpatch.pl' % hooks_dir] + options + ['-']
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  output = p.communicate(_get_diff(commit))[0]
  if p.returncode:
    return HookFailure('checkpatch.pl errors/warnings\n\n' + output)


def _run_checkpatch_no_tree(project, commit):
  return _run_checkpatch(project, commit, ['--no-tree'])


def _run_json_check(project, commit):
  """Checks that all JSON files are syntactically valid."""
  for f in _filter_files(_get_affected_files(commit), [r'.*\.json']):
    try:
      json.load(open(f))
    except Exception, e:
      return HookFailure('Invalid JSON in %s: %s' % (f, e))


# Base


# A list of hooks that are not project-specific
_COMMON_HOOKS = [
    _check_change_has_bug_field,
    _check_change_has_test_field,
    _check_change_has_proper_changeid,
    _check_no_stray_whitespace,
    _check_no_long_lines,
    _check_license,
    _check_no_tabs,
]


# A dictionary of project-specific hooks(callbacks), indexed by project name.
# dict[project] = [callback1, callback2]
_PROJECT_SPECIFIC_HOOKS = {
    "chromiumos/third_party/kernel": [_run_checkpatch],
    "chromiumos/third_party/kernel-next": [_run_checkpatch],
    "chromiumos/third_party/u-boot": [_run_checkpatch_no_tree],
    "chromiumos/platform/u-boot-vboot-integration": [_run_checkpatch_no_tree],
    "chromiumos/platform/ec": [_run_checkpatch_no_tree],
    "chromeos/platform/ec-private": [_run_checkpatch_no_tree],
    "chromeos/autotest-tools": [_run_json_check],
}


# A dictionary of flags (keys) that can appear in the config file, and the hook
# that the flag disables (value)
_DISABLE_FLAGS = {
    'stray_whitespace_check': _check_no_stray_whitespace,
    'long_line_check': _check_no_long_lines,
    'cros_license_check': _check_license,
    'tab_check': _check_no_tabs,
}


def _get_disabled_hooks():
  """Returns a set of hooks disabled by the current project's config file.

  Expects to be called within the project root.
  """
  SECTION = 'Hook Overrides'
  config = ConfigParser.RawConfigParser()
  try:
    config.read(_CONFIG_FILE)
    flags = config.options(SECTION)
  except ConfigParser.Error:
    return set([])

  disable_flags = []
  for flag in flags:
    try:
      if not config.getboolean(SECTION, flag): disable_flags.append(flag)
    except ValueError as e:
      msg = "Error parsing flag \'%s\' in %s file - " % (flag, _CONFIG_FILE)
      print msg + str(e)

  disabled_keys = set(_DISABLE_FLAGS.iterkeys()).intersection(disable_flags)
  return set([_DISABLE_FLAGS[key] for key in disabled_keys])


def _get_project_hooks(project):
  """Returns a list of hooks that need to be run for a project.

  Expects to be called from within the project root.
  """
  disabled_hooks = _get_disabled_hooks()
  hooks = [hook for hook in _COMMON_HOOKS if hook not in disabled_hooks]

  if project in _PROJECT_SPECIFIC_HOOKS:
    hooks.extend(_PROJECT_SPECIFIC_HOOKS[project])

  return hooks


def _run_project_hooks(project, proj_dir=None):
  """For each project run its project specific hook from the hooks dictionary.

  Args:
    project: The name of project to run hooks for.
    proj_dir: If non-None, this is the directory the project is in.  If None,
        we'll ask repo.

  Returns:
    Boolean value of whether any errors were ecountered while running the hooks.
  """
  if proj_dir is None:
    proj_dir = _run_command(['repo', 'forall', project, '-c', 'pwd']).strip()

  pwd = os.getcwd()
  # hooks assume they are run from the root of the project
  os.chdir(proj_dir)

  try:
    commit_list = _get_commits()
  except VerifyException as e:
    PrintErrorForProject(project, HookFailure(str(e)))
    os.chdir(pwd)
    return True

  hooks = _get_project_hooks(project)
  error_found = False
  for commit in commit_list:
    error_list = []
    for hook in hooks:
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
  """Main function invoked directly by repo.

  This function will exit directly upon error so that repo doesn't print some
  obscure error message.

  Args:
    project_list: List of projects to run on.
    kwargs: Leave this here for forward-compatibility.
  """
  found_error = False
  for project in project_list:
    if _run_project_hooks(project):
      found_error = True

  if (found_error):
    msg = ('Preupload failed due to errors in project(s). HINTS:\n'
           '- To disable some source style checks, and for other hints, see '
           '<checkout_dir>/src/repohooks/README\n'
           '- To upload only current project, run \'repo upload .\'')
    print >> sys.stderr, msg
    sys.exit(1)


def _identify_project(path):
  """Identify the repo project associated with the given path.

  Returns:
    A string indicating what project is associated with the path passed in or
    a blank string upon failure.
  """
  return _run_command(['repo', 'forall', '.', '-c', 'echo ${REPO_PROJECT}'],
    stderr=subprocess.PIPE, cwd=path).strip()


def direct_main(args, verbose=False):
  """Run hooks directly (outside of the context of repo).

  # Setup for doctests below.
  # ...note that some tests assume that running pre-upload on this CWD is fine.
  # TODO: Use mock and actually mock out _run_project_hooks() for tests.
  >>> mydir = os.path.dirname(os.path.abspath(__file__))
  >>> olddir = os.getcwd()

  # OK to run w/ no arugments; will run with CWD.
  >>> os.chdir(mydir)
  >>> direct_main(['prog_name'], verbose=True)
  Running hooks on chromiumos/repohooks
  0
  >>> os.chdir(olddir)

  # Run specifying a dir
  >>> direct_main(['prog_name', '--dir=%s' % mydir], verbose=True)
  Running hooks on chromiumos/repohooks
  0

  # Not a problem to use a bogus project; we'll just get default settings.
  >>> direct_main(['prog_name', '--dir=%s' % mydir, '--project=X'],verbose=True)
  Running hooks on X
  0

  # Run with project but no dir
  >>> os.chdir(mydir)
  >>> direct_main(['prog_name', '--project=X'], verbose=True)
  Running hooks on X
  0
  >>> os.chdir(olddir)

  # Try with a non-git CWD
  >>> os.chdir('/tmp')
  >>> direct_main(['prog_name'])
  Traceback (most recent call last):
    ...
  BadInvocation: The current directory is not part of a git project.

  # Check various bad arguments...
  >>> direct_main(['prog_name', 'bogus'])
  Traceback (most recent call last):
    ...
  BadInvocation: Unexpected arguments: bogus
  >>> direct_main(['prog_name', '--project=bogus', '--dir=bogusdir'])
  Traceback (most recent call last):
    ...
  BadInvocation: Invalid dir: bogusdir
  >>> direct_main(['prog_name', '--project=bogus', '--dir=/tmp'])
  Traceback (most recent call last):
    ...
  BadInvocation: Not a git directory: /tmp

  Args:
    args: The value of sys.argv

  Returns:
    0 if no pre-upload failures, 1 if failures.

  Raises:
    BadInvocation: On some types of invocation errors.
  """
  desc = 'Run Chromium OS pre-upload hooks on changes compared to upstream.'
  parser = optparse.OptionParser(description=desc)

  parser.add_option('--dir', default=None,
                    help='The directory that the project lives in.  If not '
                    'specified, use the git project root based on the cwd.')
  parser.add_option('--project', default=None,
                    help='The project repo path; this can affect how the hooks '
                    'get run, since some hooks are project-specific.  For '
                    'chromite this is chromiumos/chromite.  If not specified, '
                    'the repo tool will be used to figure this out based on '
                    'the dir.')

  opts, args = parser.parse_args(args[1:])

  if args:
    raise BadInvocation('Unexpected arguments: %s' % ' '.join(args))

  # Check/normlaize git dir; if unspecified, we'll use the root of the git
  # project from CWD
  if opts.dir is None:
    git_dir = _run_command(['git', 'rev-parse', '--git-dir'],
                           stderr=subprocess.PIPE).strip()
    if not git_dir:
      raise BadInvocation('The current directory is not part of a git project.')
    opts.dir = os.path.dirname(os.path.abspath(git_dir))
  elif not os.path.isdir(opts.dir):
    raise BadInvocation('Invalid dir: %s' % opts.dir)
  elif not os.path.isdir(os.path.join(opts.dir, '.git')):
    raise BadInvocation('Not a git directory: %s' % opts.dir)

  # Identify the project if it wasn't specified; this _requires_ the repo
  # tool to be installed and for the project to be part of a repo checkout.
  if not opts.project:
    opts.project = _identify_project(opts.dir)
    if not opts.project:
      raise BadInvocation("Repo couldn't identify the project of %s" % opts.dir)

  if verbose:
    print "Running hooks on %s" % (opts.project)

  found_error = _run_project_hooks(opts.project, proj_dir=opts.dir)
  if found_error:
    return 1
  return 0


def _test():
  """Run any built-in tests."""
  import doctest
  doctest.testmod()


if __name__ == '__main__':
  if sys.argv[1:2] == ["--test"]:
    _test()
    exit_code = 0
  else:
    prog_name = os.path.basename(sys.argv[0])
    try:
      exit_code = direct_main(sys.argv)
    except BadInvocation, e:
      print >>sys.stderr, "%s: %s" % (prog_name, str(e))
      exit_code = 1
  sys.exit(exit_code)
