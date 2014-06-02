#!/usr/bin/env python
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Presubmit checks to run when doing `repo upload`.

You can add new checks by adding a functions to the HOOKS constants.
"""

from __future__ import print_function

import ConfigParser
import functools
import json
import optparse
import os
import re
import sys
import subprocess

from errors import (VerifyException, HookFailure, PrintErrorForProject,
                    PrintErrorsForCommit)

# If repo imports us, the __name__ will be __builtin__, and the wrapper will
# be in $CHROMEOS_CHECKOUT/.repo/repo/main.py, so we need to go two directories
# up. The same logic also happens to work if we're executed directly.
if __name__ in ('__builtin__', '__main__'):
  sys.path.insert(0, os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))

from chromite.lib import patch
from chromite.licensing import licenses


COMMON_INCLUDED_PATHS = [
    # C++ and friends
    r".*\.c$", r".*\.cc$", r".*\.cpp$", r".*\.h$", r".*\.m$", r".*\.mm$",
    r".*\.inl$", r".*\.asm$", r".*\.hxx$", r".*\.hpp$", r".*\.s$", r".*\.S$",
    # Scripts
    r".*\.js$", r".*\.py$", r".*\.sh$", r".*\.rb$", r".*\.pl$", r".*\.pm$",
    # No extension at all, note that ALL CAPS files are black listed in
    # COMMON_EXCLUDED_LIST below.
    r"(^|.*[\\\/])[^.]+$",
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
    # ignore minified js and jquery
    r".*\.min\.js",
    r".*jquery.*\.js",

    # Ignore license files as the content is often taken verbatim.
    r'.*/licenses/.*',
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
    if re.search(expr, subject):
      return True
  return False


def _filter_files(files, include_list, exclude_list=()):
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


def _verify_header_content(commit, content, fail_msg):
  """Verify that file headers contain specified content.

  Args:
    commit: the affected commit.
    content: the content of the header to be verified.
    fail_msg: the first message to display in case of failure.

  Returns:
    The return value of HookFailure().
  """
  license_re = re.compile(content, re.MULTILINE)
  bad_files = []
  files = _filter_files(_get_affected_files(commit),
                        COMMON_INCLUDED_PATHS,
                        COMMON_EXCLUDED_PATHS)

  for f in files:
    # Ignore non-existant files and symlinks
    if os.path.exists(f) and not os.path.islink(f):
      contents = open(f).read()
      if not contents:
        # Ignore empty files
        continue
      if not license_re.search(contents):
        bad_files.append(f)
  if bad_files:
    msg = "%s:\n%s\n%s" % (fail_msg, license_re.pattern,
                           "Found a bad header in these files:")
    return HookFailure(msg, bad_files)


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


def _get_patch(commit):
  """Returns the patch for this commit."""
  return _run_command(['git', 'format-patch', '--stdout', '-1', commit])


def _try_utf8_decode(data):
  """Attempts to decode a string as UTF-8.

  Returns:
    The decoded Unicode object, or the original string if parsing fails.
  """
  try:
    return unicode(data, 'utf-8', 'strict')
  except UnicodeDecodeError:
    return data


def _get_file_content(path, commit):
  """Returns the content of a file at a specific commit.

  We can't rely on the file as it exists in the filesystem as people might be
  uploading a series of changes which modifies the file multiple times.

  Note: The "content" of a symlink is just the target.  So if you're expecting
  a full file, you should check that first.  One way to detect is that the
  content will not have any newlines.
  """
  return _run_command(['git', 'show', '%s:%s' % (commit, path)])


def _get_file_diff(path, commit):
  """Returns a list of (linenum, lines) tuples that the commit touched."""
  output = _run_command(['git', 'show', '-p', '--pretty=format:',
                         '--no-ext-diff', commit, path])

  new_lines = []
  line_num = 0
  for line in output.splitlines():
    m = re.match(r'^@@ [0-9\,\+\-]+ \+([0-9]+)\,[0-9]+ @@', line)
    if m:
      line_num = int(m.groups(1)[0])
      continue
    if line.startswith('+') and not line.startswith('++'):
      new_lines.append((line_num, _try_utf8_decode(line[1:])))
    if not line.startswith('-'):
      line_num += 1
  return new_lines


def _get_affected_files(commit, include_deletes=False, relative=False):
  """Returns list of absolute filepaths that were modified/added.

  Args:
    commit: The commit
    include_deletes: If true we'll include delete in the list.
    relative: Whether to return full paths to files.

  Returns:
    A list of modified/added (and perhaps deleted) files
  """
  output = _run_command(['git', 'diff', '--name-status', commit + '^!'])
  files = []
  for statusline in output.splitlines():
    m = re.match('^(\w)+\t(.+)$', statusline.rstrip())
    # Ignore deleted files, and return absolute paths of files
    if include_deletes or m.group(1)[0] != 'D':
      f = m.group(2)
      if not relative:
        pwd = os.getcwd()
        f = os.path.join(pwd, f)
      files.append(f)
  return files


def _get_commits():
  """Returns a list of commits for this review."""
  cmd = ['git', 'log', '%s..' % _get_upstream_branch(), '--format=%H']
  return _run_command(cmd).split()


def _get_commit_desc(commit):
  """Returns the full commit message of a commit."""
  return _run_command(['git', 'log', '--format=%s%n%n%b', commit + '^!'])


# Common Hooks


def _check_no_long_lines(_project, commit):
  """Checks that there aren't any lines longer than maxlen characters in any of
  the text files to be submitted.
  """
  MAX_LEN = 80
  SKIP_REGEXP = re.compile('|'.join([
      r'https?://',
      r'^#\s*(define|include|import|pragma|if|endif)\b']))

  errors = []
  files = _filter_files(_get_affected_files(commit),
                        COMMON_INCLUDED_PATHS,
                        COMMON_EXCLUDED_PATHS)

  for afile in files:
    for line_num, line in _get_file_diff(afile, commit):
      # Allow certain lines to exceed the maxlen rule.
      if len(line) <= MAX_LEN or SKIP_REGEXP.search(line):
        continue

      errors.append('%s, line %s, %s chars' % (afile, line_num, len(line)))
      if len(errors) == 5:  # Just show the first 5 errors.
        break

  if errors:
    msg = 'Found lines longer than %s characters (first 5 shown):' % MAX_LEN
    return HookFailure(msg, errors)


def _check_no_stray_whitespace(_project, commit):
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


def _check_no_tabs(_project, commit):
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


def _check_change_has_test_field(_project, commit):
  """Check for a non-empty 'TEST=' field in the commit message."""
  TEST_RE = r'\nTEST=\S+'

  if not re.search(TEST_RE, _get_commit_desc(commit)):
    msg = 'Changelist description needs TEST field (after first line)'
    return HookFailure(msg)


def _check_change_has_valid_cq_depend(_project, commit):
  """Check for a correctly formatted CQ-DEPEND field in the commit message."""
  msg = 'Changelist has invalid CQ-DEPEND target.'
  example = 'Example: CQ-DEPEND=CL:1234, CL:2345'
  try:
    patch.GetPaladinDeps(_get_commit_desc(commit))
  except ValueError as ex:
    return HookFailure(msg, [example, str(ex)])


def _check_change_has_bug_field(_project, commit):
  """Check for a correctly formatted 'BUG=' field in the commit message."""
  OLD_BUG_RE = r'\nBUG=.*chromium-os'
  if re.search(OLD_BUG_RE, _get_commit_desc(commit)):
    msg = ('The chromium-os bug tracker is now deprecated. Please use\n'
           'the chromium tracker in your BUG= line now.')
    return HookFailure(msg)

  BUG_RE = r'\nBUG=([Nn]one|(chrome-os-partner|chromium):\d+)'
  if not re.search(BUG_RE, _get_commit_desc(commit)):
    msg = ('Changelist description needs BUG field (after first line):\n'
           'BUG=chromium:9999 (for public tracker)\n'
           'BUG=chrome-os-partner:9999 (for partner tracker)\n'
           'BUG=None')
    return HookFailure(msg)


def _check_for_uprev(project, commit):
  """Check that we're not missing a revbump of an ebuild in the given commit.

  If the given commit touches files in a directory that has ebuilds somewhere
  up the directory hierarchy, it's very likely that we need an ebuild revbump
  in order for those changes to take effect.

  It's not totally trivial to detect a revbump, so at least detect that an
  ebuild with a revision number in it was touched.  This should handle the
  common case where we use a symlink to do the revbump.

  TODO: it would be nice to enhance this hook to:
  * Handle cases where people revbump with a slightly different syntax.  I see
    one ebuild (puppy) that revbumps with _pN.  This is a false positive.
  * Catches cases where people aren't using symlinks for revbumps.  If they
    edit a revisioned file directly (and are expected to rename it for revbump)
    we'll miss that.  Perhaps we could detect that the file touched is a
    symlink?

  If a project doesn't use symlinks we'll potentially miss a revbump, but we're
  still better off than without this check.

  Args:
    project: The project to look at
    commit: The commit to look at

  Returns:
    A HookFailure or None.
  """
  # If this is the portage-stable overlay, then ignore the check.  It's rare
  # that we're doing anything other than importing files from upstream, so
  # forcing a rev bump makes no sense.
  whitelist = (
      'chromiumos/overlays/portage-stable',
  )
  if project in whitelist:
    return None

  affected_paths = _get_affected_files(commit, include_deletes=True)

  # Don't yell about changes to whitelisted files...
  whitelist = ('ChangeLog', 'Manifest', 'metadata.xml')
  affected_paths = [path for path in affected_paths
                    if os.path.basename(path) not in whitelist]
  if not affected_paths:
    return None

  # If we've touched any file named with a -rN.ebuild then we'll say we're
  # OK right away.  See TODO above about enhancing this.
  touched_revved_ebuild = any(re.search(r'-r\d*\.ebuild$', path)
                              for path in affected_paths)
  if touched_revved_ebuild:
    return None

  # We want to examine the current contents of all directories that are parents
  # of files that were touched (up to the top of the project).
  #
  # ...note: we use the current directory contents even though it may have
  # changed since the commit we're looking at.  This is just a heuristic after
  # all.  Worst case we don't flag a missing revbump.
  project_top = os.getcwd()
  dirs_to_check = set([project_top])
  for path in affected_paths:
    path = os.path.dirname(path)
    while os.path.exists(path) and not os.path.samefile(path, project_top):
      dirs_to_check.add(path)
      path = os.path.dirname(path)

  # Look through each directory.  If it's got an ebuild in it then we'll
  # consider this as a case when we need a revbump.
  for dir_path in dirs_to_check:
    contents = os.listdir(dir_path)
    ebuilds = [os.path.join(dir_path, path)
               for path in contents if path.endswith('.ebuild')]
    ebuilds_9999 = [path for path in ebuilds if path.endswith('-9999.ebuild')]

    # If the -9999.ebuild file was touched the bot will uprev for us.
    # ...we'll use a simple intersection here as a heuristic...
    if set(ebuilds_9999) & set(affected_paths):
      continue

    if ebuilds:
      return HookFailure('Changelist probably needs a revbump of an ebuild\n'
                         'or a -r1.ebuild symlink if this is a new ebuild')

  return None


def _check_ebuild_eapi(project, commit):
  """Make sure we have people use EAPI=4 or newer with custom ebuilds.

  We want to get away from older EAPI's as it makes life confusing and they
  have less builtin error checking.

  Args:
    project: The project to look at
    commit: The commit to look at

  Returns:
    A HookFailure or None.
  """
  # If this is the portage-stable overlay, then ignore the check.  It's rare
  # that we're doing anything other than importing files from upstream, and
  # we shouldn't be rewriting things fundamentally anyways.
  whitelist = (
      'chromiumos/overlays/portage-stable',
  )
  if project in whitelist:
    return None

  BAD_EAPIS = ('0', '1', '2', '3')

  get_eapi = re.compile(r'^\s*EAPI=[\'"]?([^\'"]+)')

  ebuilds_re = [r'\.ebuild$']
  ebuilds = _filter_files(_get_affected_files(commit, relative=True),
                          ebuilds_re)
  bad_ebuilds = []

  for ebuild in ebuilds:
    # If the ebuild does not specify an EAPI, it defaults to 0.
    eapi = '0'

    lines = _get_file_content(ebuild, commit).splitlines()
    if len(lines) == 1:
      # This is most likely a symlink, so skip it entirely.
      continue

    for line in lines:
      m = get_eapi.match(line)
      if m:
        # Once we hit the first EAPI line in this ebuild, stop processing.
        # The spec requires that there only be one and it be first, so
        # checking all possible values is pointless.  We also assume that
        # it's "the" EAPI line and not something in the middle of a heredoc.
        eapi = m.group(1)
        break

    if eapi in BAD_EAPIS:
      bad_ebuilds.append((ebuild, eapi))

  if bad_ebuilds:
    # pylint: disable=C0301
    url = 'http://dev.chromium.org/chromium-os/how-tos-and-troubleshooting/upgrade-ebuild-eapis'
    # pylint: enable=C0301
    return HookFailure(
        'These ebuilds are using old EAPIs.  If these are imported from\n'
        'Gentoo, then you may ignore and upload once with the --no-verify\n'
        'flag.  Otherwise, please update to 4 or newer.\n'
        '\t%s\n'
        'See this guide for more details:\n%s\n' %
        ('\n\t'.join(['%s: EAPI=%s' % x for x in bad_ebuilds]), url))


def _check_ebuild_keywords(_project, commit):
  """Make sure we use the new style KEYWORDS when possible in ebuilds.

  If an ebuild generally does not care about the arch it is running on, then
  ebuilds should flag it with one of:
    KEYWORDS="*"       # A stable ebuild.
    KEYWORDS="~*"      # An unstable ebuild.
    KEYWORDS="-* ..."  # Is known to only work on specific arches.

  Args:
    project: The project to look at
    commit: The commit to look at

  Returns:
    A HookFailure or None.
  """
  WHITELIST = set(('*', '-*', '~*'))

  get_keywords = re.compile(r'^\s*KEYWORDS="(.*)"')

  ebuilds_re = [r'\.ebuild$']
  ebuilds = _filter_files(_get_affected_files(commit, relative=True),
                          ebuilds_re)

  for ebuild in ebuilds:
    for _, line in _get_file_diff(ebuild, commit):
      m = get_keywords.match(line)
      if m:
        keywords = set(m.group(1).split())
        if not keywords or WHITELIST - keywords != WHITELIST:
          continue

        return HookFailure(
            'Please update KEYWORDS to use a glob:\n'
            'If the ebuild should be marked stable (normal for non-9999 '
            'ebuilds):\n'
            '  KEYWORDS="*"\n'
            'If the ebuild should be marked unstable (normal for '
            'cros-workon / 9999 ebuilds):\n'
            '  KEYWORDS="~*"\n'
            'If the ebuild needs to be marked for only specific arches,'
            'then use -* like so:\n'
            '  KEYWORDS="-* arm ..."\n')


def _check_ebuild_licenses(_project, commit):
  """Check if the LICENSE field in the ebuild is correct."""
  affected_paths = _get_affected_files(commit)
  touched_ebuilds = [x for x in affected_paths if x.endswith('.ebuild')]

  # A list of licenses to ignore for now.
  LICENSES_IGNORE = ['||', '(', ')']

  for ebuild in touched_ebuilds:
    # Skip virutal packages.
    if ebuild.split('/')[-3] == 'virtual':
      continue

    try:
      license_types = licenses.GetLicenseTypesFromEbuild(ebuild)
    except ValueError as e:
      return HookFailure(e.message, [ebuild])

    # Also ignore licenses ending with '?'
    for license_type in [x for x in license_types
                         if x not in LICENSES_IGNORE and not x.endswith('?')]:
      try:
        licenses.Licensing.FindLicenseType(license_type)
      except AssertionError as e:
        return HookFailure(e.message, [ebuild])


def _check_ebuild_virtual_pv(project, commit):
  """Enforce the virtual PV policies."""
  # If this is the portage-stable overlay, then ignore the check.
  # We want to import virtuals as-is from upstream Gentoo.
  whitelist = (
      'chromiumos/overlays/portage-stable',
  )
  if project in whitelist:
    return None

  # We assume the repo name is the same as the dir name on disk.
  # It would be dumb to not have them match though.
  project = os.path.basename(project)

  is_variant = lambda x: x.startswith('overlay-variant-')
  is_board = lambda x: x.startswith('overlay-')
  is_private = lambda x: x.endswith('-private')

  get_pv = re.compile(r'(.*?)virtual/([^/]+)/\2-([^/]*)\.ebuild$')

  ebuilds_re = [r'\.ebuild$']
  ebuilds = _filter_files(_get_affected_files(commit, relative=True),
                          ebuilds_re)
  bad_ebuilds = []

  for ebuild in ebuilds:
    m = get_pv.match(ebuild)
    if m:
      overlay = m.group(1)
      if not overlay or not is_board(overlay):
        overlay = project

      pv = m.group(3).split('-', 1)[0]

      if is_private(overlay):
        want_pv = '3.5' if is_variant(overlay) else '3'
      elif is_board(overlay):
        want_pv = '2.5' if is_variant(overlay) else '2'
      else:
        want_pv = '1'

      if pv != want_pv:
        bad_ebuilds.append((ebuild, pv, want_pv))

  if bad_ebuilds:
    # pylint: disable=C0301
    url = 'http://dev.chromium.org/chromium-os/how-tos-and-troubleshooting/portage-build-faq#TOC-Virtuals-and-central-management'
    # pylint: enable=C0301
    return HookFailure(
        'These virtuals have incorrect package versions (PVs). Please adjust:\n'
        '\t%s\n'
        'If this is an upstream Gentoo virtual, then you may ignore this\n'
        'check (and re-run w/--no-verify). Otherwise, please see this\n'
        'page for more details:\n%s\n' %
        ('\n\t'.join(['%s:\n\t\tPV is %s but should be %s' % x
                      for x in bad_ebuilds]), url))


def _check_change_has_proper_changeid(_project, commit):
  """Verify that Change-ID is present in last paragraph of commit message."""
  desc = _get_commit_desc(commit)
  loc = desc.rfind('\nChange-Id:')
  if loc == -1 or re.search('\n\s*\n\s*\S+', desc[loc:]):
    return HookFailure('Change-Id must be in last paragraph of description.')


def _check_license(_project, commit):
  """Verifies the license header."""
  LICENSE_HEADER = (
      r".* Copyright( \(c\))? 20[-0-9]{2,7} The Chromium OS Authors\. "
          "All rights reserved\." "\n"
      r".* Use of this source code is governed by a BSD-style license that can "
          "be\n"
      r".* found in the LICENSE file\."
          "\n"
  )
  FAIL_MSG = "License must match"

  return _verify_header_content(commit, LICENSE_HEADER, FAIL_MSG)


# Project-specific hooks


def _run_checkpatch(_project, commit, options=()):
  """Runs checkpatch.pl on the given project"""
  hooks_dir = _get_hooks_dir()
  cmd = ['%s/checkpatch.pl' % hooks_dir] + list(options) + ['-']
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  output = p.communicate(_get_patch(commit))[0]
  if p.returncode:
    return HookFailure('checkpatch.pl errors/warnings\n\n' + output)


def _run_checkpatch_no_tree(project, commit):
  return _run_checkpatch(project, commit, ['--no-tree'])


def _run_checkpatch_ec(project, commit):
  """Runs checkpatch with options for Chromium EC projects."""
  return _run_checkpatch(project, commit, ['--no-tree',
                                           '--ignore=MSLEEP,VOLATILE'])


def _kernel_configcheck(_project, commit):
  """Makes sure kernel config changes are not mixed with code changes"""
  files = _get_affected_files(commit)
  if not len(_filter_files(files, [r'chromeos/config'])) in [0, len(files)]:
    return HookFailure('Changes to chromeos/config/ and regular files must '
                       'be in separate commits:\n%s' % '\n'.join(files))


def _run_json_check(_project, commit):
  """Checks that all JSON files are syntactically valid."""
  for f in _filter_files(_get_affected_files(commit), [r'.*\.json']):
    try:
      json.load(open(f))
    except Exception, e:
      return HookFailure('Invalid JSON in %s: %s' % (f, e))


def _check_manifests(_project, commit):
  """Make sure Manifest files only have DIST lines"""
  paths = []

  for path in _get_affected_files(commit):
    if os.path.basename(path) != 'Manifest':
      continue
    if not os.path.exists(path):
      continue

    with open(path, 'r') as f:
      for line in f.readlines():
        if not line.startswith('DIST '):
          paths.append(path)
          break

  if paths:
    return HookFailure('Please remove lines that do not start with DIST:\n%s' %
                       ('\n'.join(paths),))


def _check_change_has_branch_field(_project, commit):
  """Check for a non-empty 'BRANCH=' field in the commit message."""
  BRANCH_RE = r'\nBRANCH=\S+'

  if not re.search(BRANCH_RE, _get_commit_desc(commit)):
    msg = ('Changelist description needs BRANCH field (after first line)\n'
           'E.g. BRANCH=none or BRANCH=link,snow')
    return HookFailure(msg)


def _check_change_has_signoff_field(_project, commit):
  """Check for a non-empty 'Signed-off-by:' field in the commit message."""
  SIGNOFF_RE = r'\nSigned-off-by: \S+'

  if not re.search(SIGNOFF_RE, _get_commit_desc(commit)):
    msg = ('Changelist description needs Signed-off-by: field\n'
           'E.g. Signed-off-by: My Name <me@chromium.org>')
    return HookFailure(msg)


def _run_project_hook_script(script, project, commit):
  """Runs a project hook script.

  The script is run with the following environment variables set:
    PRESUBMIT_PROJECT: The affected project
    PRESUBMIT_COMMIT: The affected commit
    PRESUBMIT_FILES: A newline-separated list of affected files

  The script is considered to fail if the exit code is non-zero.  It should
  write an error message to stdout.
  """
  env = dict(os.environ)
  env['PRESUBMIT_PROJECT'] = project
  env['PRESUBMIT_COMMIT'] = commit

  # Put affected files in an environment variable
  files = _get_affected_files(commit)
  env['PRESUBMIT_FILES'] = '\n'.join(files)

  process = subprocess.Popen(script, env=env, shell=True,
                             stdin=open(os.devnull),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
  stdout, _ = process.communicate()
  if process.wait():
    if stdout:
      stdout = re.sub('(?m)^', '  ', stdout)
    return HookFailure('Hook script "%s" failed with code %d%s' %
                       (script, process.returncode,
                        ':\n' + stdout if stdout else ''))


def _moved_to_platform2(project, _commit):
  """Forbids commits to legacy repo in src/platform."""
  return HookFailure('%s has been moved to platform2. This change should be '
                     'made there.' % project)


# Base


# A list of hooks that are not project-specific
_COMMON_HOOKS = [
    _check_change_has_bug_field,
    _check_change_has_valid_cq_depend,
    _check_change_has_test_field,
    _check_change_has_proper_changeid,
    _check_ebuild_eapi,
    _check_ebuild_keywords,
    _check_ebuild_licenses,
    _check_ebuild_virtual_pv,
    _check_no_stray_whitespace,
    _check_no_long_lines,
    _check_license,
    _check_no_tabs,
    _check_for_uprev,
]


# A dictionary of project-specific hooks(callbacks), indexed by project name.
# dict[project] = [callback1, callback2]
_PROJECT_SPECIFIC_HOOKS = {
    "chromeos/autotest-tools": [_run_json_check],
    "chromeos/overlays/chromeos-overlay": [_check_manifests],
    "chromeos/overlays/chromeos-partner-overlay": [_check_manifests],
    "chromeos/platform/ec-private": [_run_checkpatch_ec,
                                     _check_change_has_branch_field],
    "chromeos/third_party/intel-framework": [_check_change_has_branch_field],
    "chromeos/vendor/kernel-exynos-staging": [_run_checkpatch,
                                              _kernel_configcheck],
    "chromeos/vendor/u-boot-exynos": [_run_checkpatch_no_tree],
    "chromiumos/overlays/board-overlays": [_check_manifests],
    "chromiumos/overlays/chromiumos-overlay": [_check_manifests],
    "chromiumos/overlays/portage-stable": [_check_manifests],
    # TODO(bsimonnet): remove this check once src/platform/common-mk has been
    # removed from the manifest (crbug.com/379236).
    "chromiumos/platform/common-mk": [_moved_to_platform2],
    # TODO(bsimonnet): remove this check once src/platform/libchromeos has been
    # removed from the manifest (crbug.com/379939)
    "chromiumos/platform/libchromeos": [_moved_to_platform2],
    "chromiumos/platform/ec": [_run_checkpatch_ec,
                               _check_change_has_branch_field],
    "chromiumos/platform/mosys": [_check_change_has_branch_field],
    "chromiumos/platform/vboot_reference": [_check_change_has_branch_field],
    "chromiumos/third_party/coreboot": [_check_change_has_signoff_field],
    "chromiumos/third_party/flashrom": [_check_change_has_branch_field],
    "chromiumos/third_party/kernel": [_run_checkpatch, _kernel_configcheck],
    "chromiumos/third_party/kernel-next": [_run_checkpatch,
                                           _kernel_configcheck],
    "chromiumos/third_party/u-boot": [_run_checkpatch_no_tree],
}


# A dictionary of flags (keys) that can appear in the config file, and the hook
# that the flag disables (value)
_DISABLE_FLAGS = {
    'stray_whitespace_check': _check_no_stray_whitespace,
    'long_line_check': _check_no_long_lines,
    'cros_license_check': _check_license,
    'tab_check': _check_no_tabs,
    'branch_check': _check_change_has_branch_field,
    'signoff_check': _check_change_has_signoff_field,
    'bug_field_check': _check_change_has_bug_field,
    'test_field_check': _check_change_has_test_field,
}


def _get_disabled_hooks(config):
  """Returns a set of hooks disabled by the current project's config file.

  Expects to be called within the project root.

  Args:
    config: A ConfigParser for the project's config file.
  """
  SECTION = 'Hook Overrides'
  if not config.has_section(SECTION):
    return set()

  disable_flags = []
  for flag in config.options(SECTION):
    try:
      if not config.getboolean(SECTION, flag):
        disable_flags.append(flag)
    except ValueError as e:
      msg = "Error parsing flag \'%s\' in %s file - " % (flag, _CONFIG_FILE)
      print(msg + str(e))

  disabled_keys = set(_DISABLE_FLAGS.iterkeys()).intersection(disable_flags)
  return set([_DISABLE_FLAGS[key] for key in disabled_keys])


def _get_project_hook_scripts(config):
  """Returns a list of project-specific hook scripts.

  Args:
    config: A ConfigParser for the project's config file.
  """
  SECTION = 'Hook Scripts'
  if not config.has_section(SECTION):
    return []

  hook_names_values = config.items(SECTION)
  hook_names_values.sort(key=lambda x: x[0])
  return [x[1] for x in hook_names_values]


def _get_project_hooks(project):
  """Returns a list of hooks that need to be run for a project.

  Expects to be called from within the project root.
  """
  config = ConfigParser.RawConfigParser()
  try:
    config.read(_CONFIG_FILE)
  except ConfigParser.Error:
    # Just use an empty config file
    config = ConfigParser.RawConfigParser()

  disabled_hooks = _get_disabled_hooks(config)
  hooks = [hook for hook in _COMMON_HOOKS if hook not in disabled_hooks]

  if project in _PROJECT_SPECIFIC_HOOKS:
    hooks.extend(hook for hook in _PROJECT_SPECIFIC_HOOKS[project]
                 if hook not in disabled_hooks)

  for script in _get_project_hook_scripts(config):
    hooks.append(functools.partial(_run_project_hook_script, script))

  return hooks


def _run_project_hooks(project, proj_dir=None, commit_list=None):
  """For each project run its project specific hook from the hooks dictionary.

  Args:
    project: The name of project to run hooks for.
    proj_dir: If non-None, this is the directory the project is in.  If None,
        we'll ask repo.
    commit_list: A list of commits to run hooks against.  If None or empty list
        then we'll automatically get the list of commits that would be uploaded.

  Returns:
    Boolean value of whether any errors were ecountered while running the hooks.
  """
  if proj_dir is None:
    proj_dirs = _run_command(['repo', 'forall', project, '-c', 'pwd']).split()
    if len(proj_dirs) == 0:
      print('%s cannot be found.' % project, file=sys.stderr)
      print('Please specify a valid project.', file=sys.stderr)
      return True
    if len(proj_dirs) > 1:
      print('%s is associated with multiple directories.' % project,
            file=sys.stderr)
      print('Please specify a directory to help disambiguate.', file=sys.stderr)
      return True
    proj_dir = proj_dirs[0]

  pwd = os.getcwd()
  # hooks assume they are run from the root of the project
  os.chdir(proj_dir)

  if not commit_list:
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


def main(project_list, worktree_list=None, **_kwargs):
  """Main function invoked directly by repo.

  This function will exit directly upon error so that repo doesn't print some
  obscure error message.

  Args:
    project_list: List of projects to run on.
    worktree_list: A list of directories. It should be the same length as
      project_list, so that each entry in project_list matches with a directory
      in worktree_list. If None, we will attempt to calculate the directories
      automatically.
    kwargs: Leave this here for forward-compatibility.
  """
  found_error = False
  if not worktree_list:
    worktree_list = [None] * len(project_list)
  for project, worktree in zip(project_list, worktree_list):
    if _run_project_hooks(project, proj_dir=worktree):
      found_error = True

  if found_error:
    msg = ('Preupload failed due to errors in project(s). HINTS:\n'
           '- To disable some source style checks, and for other hints, see '
           '<checkout_dir>/src/repohooks/README\n'
           '- To upload only current project, run \'repo upload .\'')
    print(msg, file=sys.stderr)
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
    verbose: Log verbose info while running

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
  parser.add_option('--rerun-since', default=None,
                    help='Rerun hooks on old commits since the given date.  '
                    'The date should match git log\'s concept of a date.  '
                    'e.g. 2012-06-20')

  parser.usage = "pre-upload.py [options] [commits]"

  opts, args = parser.parse_args(args[1:])

  if opts.rerun_since:
    if args:
      raise BadInvocation('Can\'t pass commits and use rerun-since: %s' %
                          ' '.join(args))

    cmd = ['git', 'log', '--since="%s"' % opts.rerun_since, '--pretty=%H']
    all_commits = _run_command(cmd).splitlines()
    bot_commits = _run_command(cmd + ['--author=chrome-bot']).splitlines()

    # Eliminate chrome-bot commits but keep ordering the same...
    bot_commits = set(bot_commits)
    args = [c for c in all_commits if c not in bot_commits]


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
    print("Running hooks on %s" % (opts.project))

  found_error = _run_project_hooks(opts.project, proj_dir=opts.dir,
                                   commit_list=args)
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
    except BadInvocation, err:
      print("%s: %s" % (prog_name, str(err)), file=sys.stderr)
      exit_code = 1
  sys.exit(exit_code)
