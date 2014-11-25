#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unittests for pre-upload.py."""

from __future__ import print_function

import mox
import os
import sys

import errors

# pylint: disable=W0212
# We access private members of the pre_upload module all over the place.

# If repo imports us, the __name__ will be __builtin__, and the wrapper will
# be in $CHROMEOS_CHECKOUT/.repo/repo/main.py, so we need to go two directories
# up. The same logic also happens to work if we're executed directly.
if __name__ in ('__builtin__', '__main__'):
  sys.path.insert(0, os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))

from chromite.lib import cros_test_lib
from chromite.lib import git
from chromite.lib import osutils


pre_upload = __import__('pre-upload')


class TryUTF8DecodeTest(cros_test_lib.TestCase):
  """Verify we sanely handle unicode content."""

  def runTest(self):
    self.assertEquals(u'', pre_upload._try_utf8_decode(''))
    self.assertEquals(u'abc', pre_upload._try_utf8_decode('abc'))
    self.assertEquals(u'你好布萊恩', pre_upload._try_utf8_decode('你好布萊恩'))
    # Invalid UTF-8
    self.assertEquals('\x80', pre_upload._try_utf8_decode('\x80'))


class CheckNoLongLinesTest(cros_test_lib.MoxTestCase):
  """Tests for _check_no_long_lines."""

  def setUp(self):
    self.mox.StubOutWithMock(pre_upload, '_filter_files')
    self.mox.StubOutWithMock(pre_upload, '_get_affected_files')
    self.mox.StubOutWithMock(pre_upload, '_get_file_diff')
    pre_upload._get_affected_files(mox.IgnoreArg()).AndReturn(['x.py'])
    pre_upload._filter_files(
        ['x.py'], mox.IgnoreArg(), mox.IgnoreArg()).AndReturn(['x.py'])

  def runTest(self):
    pre_upload._get_file_diff(mox.IgnoreArg(), mox.IgnoreArg()).AndReturn(
        [(1, u"x" * 80),                      # OK
         (2, "\x80" * 80),                    # OK
         (3, u"x" * 81),                      # Too long
         (4, "\x80" * 81),                    # Too long
         (5, u"See http://" + (u"x" * 80)),   # OK (URL)
         (6, u"See https://" + (u"x" * 80)),  # OK (URL)
         (7, u"#  define " + (u"x" * 80)),    # OK (compiler directive)
         (8, u"#define" + (u"x" * 74)),       # Too long
        ])
    self.mox.ReplayAll()
    failure = pre_upload._check_no_long_lines('PROJECT', 'COMMIT')
    self.assertTrue(failure)
    self.assertEquals('Found lines longer than 80 characters (first 5 shown):',
                      failure.msg)
    self.assertEquals(['x.py, line %d, 81 chars' % line
                       for line in [3, 4, 8]],
                      failure.items)


class CheckProjectPrefix(cros_test_lib.MockTempDirTestCase):
  """Tests for _check_project_prefix."""

  def setUp(self):
    self.orig_cwd = os.getcwd()
    os.chdir(self.tempdir)
    self.file_mock = self.PatchObject(pre_upload, '_get_affected_files')
    self.desc_mock = self.PatchObject(pre_upload, '_get_commit_desc')

  def tearDown(self):
    os.chdir(self.orig_cwd)

  def _WriteAliasFile(self, filename, project):
    """Writes a project name to a file, creating directories if needed."""
    os.makedirs(os.path.dirname(filename))
    osutils.WriteFile(filename, project)

  def testInvalidPrefix(self):
    """Report an error when the prefix doesn't match the base directory."""
    self.file_mock.return_value = ['foo/foo.cc', 'foo/subdir/baz.cc']
    self.desc_mock.return_value = 'bar: Some commit'
    failure = pre_upload._check_project_prefix('PROJECT', 'COMMIT')
    self.assertTrue(failure)
    self.assertEquals(('The commit title for changes affecting only foo' +
                       ' should start with "foo: "'), failure.msg)

  def testValidPrefix(self):
    """Use a prefix that matches the base directory."""
    self.file_mock.return_value = ['foo/foo.cc', 'foo/subdir/baz.cc']
    self.desc_mock.return_value = 'foo: Change some files.'
    self.assertFalse(pre_upload._check_project_prefix('PROJECT', 'COMMIT'))

  def testAliasFile(self):
    """Use .project_alias to override the project name."""
    self._WriteAliasFile('foo/.project_alias', 'project')
    self.file_mock.return_value = ['foo/foo.cc', 'foo/subdir/bar.cc']
    self.desc_mock.return_value = 'project: Use an alias.'
    self.assertFalse(pre_upload._check_project_prefix('PROJECT', 'COMMIT'))

  def testAliasFileWithSubdirs(self):
    """Check that .project_alias is used when only modifying subdirectories."""
    self._WriteAliasFile('foo/.project_alias', 'project')
    self.file_mock.return_value = [
        'foo/subdir/foo.cc',
        'foo/subdir/bar.cc'
        'foo/subdir/blah/baz.cc'
    ]
    self.desc_mock.return_value = 'project: Alias with subdirs.'
    self.assertFalse(pre_upload._check_project_prefix('PROJECT', 'COMMIT'))


class CheckKernelConfig(cros_test_lib.MoxTestCase):
  """Tests for _kernel_configcheck."""

  def runTest(self):
    # Mixed changes, should fail
    self.mox.StubOutWithMock(pre_upload, '_get_affected_files')
    pre_upload._get_affected_files(mox.IgnoreArg()).AndReturn(
        ['/kernel/files/chromeos/config/base.config',
         '/kernel/files/arch/arm/mach-exynos/mach-exynos5-dt.c'
        ])
    self.mox.ReplayAll()
    failure = pre_upload._kernel_configcheck('PROJECT', 'COMMIT')
    self.assertTrue(failure)

    # Code-only changes, should pass
    self.mox.UnsetStubs()
    self.mox.StubOutWithMock(pre_upload, '_get_affected_files')
    pre_upload._get_affected_files(mox.IgnoreArg()).AndReturn(
        ['/kernel/files/Makefile',
         '/kernel/files/arch/arm/mach-exynos/mach-exynos5-dt.c'
        ])
    self.mox.ReplayAll()
    failure = pre_upload._kernel_configcheck('PROJECT', 'COMMIT')
    self.assertFalse(failure)

    # Config-only changes, should pass
    self.mox.UnsetStubs()
    self.mox.StubOutWithMock(pre_upload, '_get_affected_files')
    pre_upload._get_affected_files(mox.IgnoreArg()).AndReturn(
        ['/kernel/files/chromeos/config/base.config',
        ])
    self.mox.ReplayAll()
    failure = pre_upload._kernel_configcheck('PROJECT', 'COMMIT')
    self.assertFalse(failure)


class CheckEbuildEapi(cros_test_lib.MockTestCase):
  """Tests for _check_ebuild_eapi."""

  PORTAGE_STABLE = 'chromiumos/overlays/portage-stable'

  def setUp(self):
    self.file_mock = self.PatchObject(pre_upload, '_get_affected_files')
    self.content_mock = self.PatchObject(pre_upload, '_get_file_content')
    self.diff_mock = self.PatchObject(pre_upload, '_get_file_diff',
                                      side_effect=Exception())

  def testSkipUpstreamOverlays(self):
    """Skip ebuilds found in upstream overlays."""
    self.file_mock.side_effect = Exception()
    ret = pre_upload._check_ebuild_eapi(self.PORTAGE_STABLE, 'HEAD')
    self.assertEqual(ret, None)

    # Make sure our condition above triggers.
    self.assertRaises(Exception, pre_upload._check_ebuild_eapi, 'o', 'HEAD')

  def testSkipNonEbuilds(self):
    """Skip non-ebuild files."""
    self.content_mock.side_effect = Exception()

    self.file_mock.return_value = ['some-file', 'ebuild/dir', 'an.ebuild~']
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertEqual(ret, None)

    # Make sure our condition above triggers.
    self.file_mock.return_value.append('a/real.ebuild')
    self.assertRaises(Exception, pre_upload._check_ebuild_eapi, 'o', 'HEAD')

  def testSkipSymlink(self):
    """Skip files that are just symlinks."""
    self.file_mock.return_value = ['a-r1.ebuild']
    self.content_mock.return_value = 'a.ebuild'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertEqual(ret, None)

  def testRejectEapiImplicit0Content(self):
    """Reject ebuilds that do not declare EAPI (so it's 0)."""
    self.file_mock.return_value = ['a.ebuild']

    self.content_mock.return_value = """# Header
IUSE="foo"
src_compile() { }
"""
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testRejectExplicitEapi1Content(self):
    """Reject ebuilds that do declare old EAPI explicitly."""
    self.file_mock.return_value = ['a.ebuild']

    template = """# Header
EAPI=%s
IUSE="foo"
src_compile() { }
"""
    # Make sure we only check the first EAPI= setting.
    self.content_mock.return_value = template % '1\nEAPI=4'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance(ret, errors.HookFailure))

    # Verify we handle double quotes too.
    self.content_mock.return_value = template % '"1"'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance(ret, errors.HookFailure))

    # Verify we handle single quotes too.
    self.content_mock.return_value = template % "'1'"
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testAcceptExplicitEapi4Content(self):
    """Accept ebuilds that do declare new EAPI explicitly."""
    self.file_mock.return_value = ['a.ebuild']

    template = """# Header
EAPI=%s
IUSE="foo"
src_compile() { }
"""
    # Make sure we only check the first EAPI= setting.
    self.content_mock.return_value = template % '4\nEAPI=1'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertEqual(ret, None)

    # Verify we handle double quotes too.
    self.content_mock.return_value = template % '"5"'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertEqual(ret, None)

    # Verify we handle single quotes too.
    self.content_mock.return_value = template % "'5-hdepend'"
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertEqual(ret, None)


class CheckEbuildKeywords(cros_test_lib.MockTestCase):
  """Tests for _check_ebuild_keywords."""

  def setUp(self):
    self.file_mock = self.PatchObject(pre_upload, '_get_affected_files')
    self.content_mock = self.PatchObject(pre_upload, '_get_file_content')

  def testNoEbuilds(self):
    """If no ebuilds are found, do not scan."""
    self.file_mock.return_value = ['a.file', 'ebuild-is-not.foo']

    ret = pre_upload._check_ebuild_keywords('overlay', 'HEAD')
    self.assertEqual(ret, None)

    self.assertEqual(self.content_mock.call_count, 0)

  def testSomeEbuilds(self):
    """If ebuilds are found, only scan them."""
    self.file_mock.return_value = ['a.file', 'blah', 'foo.ebuild', 'cow']
    self.content_mock.return_value = ''

    ret = pre_upload._check_ebuild_keywords('overlay', 'HEAD')
    self.assertEqual(ret, None)

    self.assertEqual(self.content_mock.call_count, 1)

  def _CheckContent(self, content, fails):
    """Test helper for inputs/outputs.

    Args:
      content: The ebuild content to test.
      fails: Whether |content| should trigger a hook failure.
    """
    self.file_mock.return_value = ['a.ebuild']
    self.content_mock.return_value = content

    ret = pre_upload._check_ebuild_keywords('overlay', 'HEAD')
    if fails:
      self.assertTrue(isinstance(ret, errors.HookFailure))
    else:
      self.assertEqual(ret, None)

    self.assertEqual(self.content_mock.call_count, 1)

  def testEmpty(self):
    """Check KEYWORDS= is accepted."""
    self._CheckContent('# HEADER\nKEYWORDS=\nblah\n', False)

  def testEmptyQuotes(self):
    """Check KEYWORDS="" is accepted."""
    self._CheckContent('# HEADER\nKEYWORDS="    "\nblah\n', False)

  def testStableGlob(self):
    """Check KEYWORDS=* is accepted."""
    self._CheckContent('# HEADER\nKEYWORDS="\t*\t"\nblah\n', False)

  def testUnstableGlob(self):
    """Check KEYWORDS=~* is accepted."""
    self._CheckContent('# HEADER\nKEYWORDS="~* "\nblah\n', False)

  def testRestrictedGlob(self):
    """Check KEYWORDS=-* is accepted."""
    self._CheckContent('# HEADER\nKEYWORDS="\t-* arm"\nblah\n', False)

  def testMissingGlobs(self):
    """Reject KEYWORDS missing any globs."""
    self._CheckContent('# HEADER\nKEYWORDS="~arm x86"\nblah\n', True)


class CheckEbuildVirtualPv(cros_test_lib.MockTestCase):
  """Tests for _check_ebuild_virtual_pv."""

  PORTAGE_STABLE = 'chromiumos/overlays/portage-stable'
  CHROMIUMOS_OVERLAY = 'chromiumos/overlays/chromiumos'
  BOARD_OVERLAY = 'chromiumos/overlays/board-overlays'
  PRIVATE_OVERLAY = 'chromeos/overlays/overlay-link-private'
  PRIVATE_VARIANT_OVERLAY = ('chromeos/overlays/'
                             'overlay-variant-daisy-spring-private')

  def setUp(self):
    self.file_mock = self.PatchObject(pre_upload, '_get_affected_files')

  def testNoVirtuals(self):
    """Skip non virtual packages."""
    self.file_mock.return_value = ['some/package/package-3.ebuild']
    ret = pre_upload._check_ebuild_virtual_pv('overlay', 'H')
    self.assertEqual(ret, None)

  def testCommonVirtuals(self):
    """Non-board overlays should use PV=1."""
    template = 'virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '1']
    ret = pre_upload._check_ebuild_virtual_pv(self.CHROMIUMOS_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '2']
    ret = pre_upload._check_ebuild_virtual_pv(self.CHROMIUMOS_OVERLAY, 'H')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testPublicBoardVirtuals(self):
    """Public board overlays should use PV=2."""
    template = 'overlay-lumpy/virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '2']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '2.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testPublicBoardVariantVirtuals(self):
    """Public board variant overlays should use PV=2.5."""
    template = 'overlay-variant-lumpy-foo/virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '2.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '3']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testPrivateBoardVirtuals(self):
    """Private board overlays should use PV=3."""
    template = 'virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '3']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '3.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_OVERLAY, 'H')
    self.assertTrue(isinstance(ret, errors.HookFailure))

  def testPrivateBoardVariantVirtuals(self):
    """Private board variant overlays should use PV=3.5."""
    template = 'virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '3.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_VARIANT_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '4']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_VARIANT_OVERLAY, 'H')
    self.assertTrue(isinstance(ret, errors.HookFailure))


class CheckLicenseCopyrightHeader(cros_test_lib.MockTestCase):
  """Tests for _check_license."""

  def setUp(self):
    self.file_mock = self.PatchObject(pre_upload, '_get_affected_files')
    self.content_mock = self.PatchObject(pre_upload, '_get_file_content')

  def testOldHeaders(self):
    """Accept old header styles."""
    HEADERS = (
        ('#!/bin/sh\n'
         '# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.\n'
         '# Use of this source code is governed by a BSD-style license that'
         ' can be\n'
         '# found in the LICENSE file.\n'),
        ('// Copyright 2010-13 The Chromium OS Authors. All rights reserved.\n'
         '// Use of this source code is governed by a BSD-style license that'
         ' can be\n'
         '// found in the LICENSE file.\n'),
    )
    self.file_mock.return_value = ['file']
    for header in HEADERS:
      self.content_mock.return_value = header
      self.assertEqual(None, pre_upload._check_license('proj', 'sha1'))

  def testRejectC(self):
    """Reject the (c) in newer headers."""
    HEADERS = (
        ('// Copyright (c) 2015 The Chromium OS Authors. All rights reserved.\n'
         '// Use of this source code is governed by a BSD-style license that'
         ' can be\n'
         '// found in the LICENSE file.\n'),
        ('// Copyright (c) 2020 The Chromium OS Authors. All rights reserved.\n'
         '// Use of this source code is governed by a BSD-style license that'
         ' can be\n'
         '// found in the LICENSE file.\n'),
    )
    self.file_mock.return_value = ['file']
    for header in HEADERS:
      self.content_mock.return_value = header
      self.assertNotEqual(None, pre_upload._check_license('proj', 'sha1'))


class CommitMessageTestCase(cros_test_lib.MockTestCase):
  """Test case for funcs that check commit messages."""

  def setUp(self):
    self.msg_mock = self.PatchObject(pre_upload, '_get_commit_desc')

  @staticmethod
  def CheckMessage(_project, _commit):
    raise AssertionError('Test class must declare CheckMessage')
    # This dummy return is to silence pylint warning W1111 so we don't have to
    # enable it for all the call sites below.
    return 1 # pylint: disable=W0101

  def assertMessageAccepted(self, msg, project='project', commit='1234'):
    """Assert _check_change_has_bug_field accepts |msg|."""
    self.msg_mock.return_value = msg
    ret = self.CheckMessage(project, commit)
    self.assertEqual(ret, None)

  def assertMessageRejected(self, msg, project='project', commit='1234'):
    """Assert _check_change_has_bug_field rejects |msg|."""
    self.msg_mock.return_value = msg
    ret = self.CheckMessage(project, commit)
    self.assertTrue(isinstance(ret, errors.HookFailure))


class CheckCommitMessageBug(CommitMessageTestCase):
  """Tests for _check_change_has_bug_field."""

  @staticmethod
  def CheckMessage(project, commit):
    return pre_upload._check_change_has_bug_field(project, commit)

  def testNormal(self):
    """Accept a commit message w/a valid BUG."""
    self.assertMessageAccepted('\nBUG=chromium:1234\n')
    self.assertMessageAccepted('\nBUG=chrome-os-partner:1234\n')

  def testNone(self):
    """Accept BUG=None."""
    self.assertMessageAccepted('\nBUG=None\n')
    self.assertMessageAccepted('\nBUG=none\n')
    self.assertMessageRejected('\nBUG=NONE\n')

  def testBlank(self):
    """Reject blank values."""
    self.assertMessageRejected('\nBUG=\n')
    self.assertMessageRejected('\nBUG=    \n')

  def testNotFirstLine(self):
    """Reject the first line."""
    self.assertMessageRejected('BUG=None\n\n\n')

  def testNotInline(self):
    """Reject not at the start of line."""
    self.assertMessageRejected('\n BUG=None\n')
    self.assertMessageRejected('\n\tBUG=None\n')

  def testOldTrackers(self):
    """Reject commit messages using old trackers."""
    self.assertMessageRejected('\nBUG=chromium-os:1234\n')

  def testNoTrackers(self):
    """Reject commit messages w/invalid trackers."""
    self.assertMessageRejected('\nBUG=booga:1234\n')

  def testMissing(self):
    """Reject commit messages w/no BUG line."""
    self.assertMessageRejected('foo\n')

  def testCase(self):
    """Reject bug lines that are not BUG."""
    self.assertMessageRejected('\nbug=none\n')


class CheckCommitMessageCqDepend(CommitMessageTestCase):
  """Tests for _check_change_has_valid_cq_depend."""

  @staticmethod
  def CheckMessage(project, commit):
    return pre_upload._check_change_has_valid_cq_depend(project, commit)

  def testNormal(self):
    """Accept valid CQ-DEPENDs line."""
    self.assertMessageAccepted('\nCQ-DEPEND=CL:1234\n')

  def testInvalid(self):
    """Reject invalid CQ-DEPENDs line."""
    self.assertMessageRejected('\nCQ-DEPEND=CL=1234\n')
    self.assertMessageRejected('\nCQ-DEPEND=None\n')


class CheckCommitMessageTest(CommitMessageTestCase):
  """Tests for _check_change_has_test_field."""

  @staticmethod
  def CheckMessage(project, commit):
    return pre_upload._check_change_has_test_field(project, commit)

  def testNormal(self):
    """Accept a commit message w/a valid TEST."""
    self.assertMessageAccepted('\nTEST=i did it\n')

  def testNone(self):
    """Accept TEST=None."""
    self.assertMessageAccepted('\nTEST=None\n')
    self.assertMessageAccepted('\nTEST=none\n')

  def testBlank(self):
    """Reject blank values."""
    self.assertMessageRejected('\nTEST=\n')
    self.assertMessageRejected('\nTEST=     \n')

  def testNotFirstLine(self):
    """Reject the first line."""
    self.assertMessageRejected('TEST=None\n\n\n')

  def testNotInline(self):
    """Reject not at the start of line."""
    self.assertMessageRejected('\n TEST=None\n')
    self.assertMessageRejected('\n\tTEST=None\n')

  def testMissing(self):
    """Reject commit messages w/no TEST line."""
    self.assertMessageRejected('foo\n')

  def testCase(self):
    """Reject bug lines that are not TEST."""
    self.assertMessageRejected('\ntest=none\n')


class CheckCommitMessageChangeId(CommitMessageTestCase):
  """Tests for _check_change_has_proper_changeid."""

  @staticmethod
  def CheckMessage(project, commit):
    return pre_upload._check_change_has_proper_changeid(project, commit)

  def testNormal(self):
    """Accept a commit message w/a valid Change-Id."""
    self.assertMessageAccepted('foo\n\nChange-Id: I1234\n')

  def testBlank(self):
    """Reject blank values."""
    self.assertMessageRejected('\nChange-Id:\n')
    self.assertMessageRejected('\nChange-Id:       \n')

  def testNotFirstLine(self):
    """Reject the first line."""
    self.assertMessageRejected('TEST=None\n\n\n')

  def testNotInline(self):
    """Reject not at the start of line."""
    self.assertMessageRejected('\n Change-Id: I1234\n')
    self.assertMessageRejected('\n\tChange-Id: I1234\n')

  def testMissing(self):
    """Reject commit messages missing the line."""
    self.assertMessageRejected('foo\n')

  def testCase(self):
    """Reject bug lines that are not Change-Id."""
    self.assertMessageRejected('\nchange-id: I1234\n')
    self.assertMessageRejected('\nChange-id: I1234\n')
    self.assertMessageRejected('\nChange-ID: I1234\n')

  def testEnd(self):
    """Reject Change-Id's that are not last."""
    self.assertMessageRejected('\nChange-Id: I1234\nbar\n')

  def testSobTag(self):
    """Permit s-o-b tags to follow the Change-Id."""
    self.assertMessageAccepted('foo\n\nChange-Id: I1234\nSigned-off-by: Hi\n')


class CheckCommitMessageStyle(CommitMessageTestCase):
  """Tests for _check_commit_message_style."""

  @staticmethod
  def CheckMessage(project, commit):
    return pre_upload._check_commit_message_style(project, commit)

  def testNormal(self):
    """Accept valid commit messages."""
    self.assertMessageAccepted('one sentence.\n')
    self.assertMessageAccepted('some.module: do it!\n')
    self.assertMessageAccepted('one line\n\nmore stuff here.')

  def testNoBlankSecondLine(self):
    """Reject messages that have stuff on the second line."""
    self.assertMessageRejected('one sentence.\nbad fish!\n')

  def testFirstLineMultipleSentences(self):
    """Reject messages that have more than one sentence in the summary."""
    self.assertMessageRejected('one sentence. two sentence!\n')

  def testFirstLineTooLone(self):
    """Reject first lines that are too long."""
    self.assertMessageRejected('o' * 200)


class HelpersTest(cros_test_lib.MockTestCase):
  """Various tests for utility functions."""

  def _SetupGetAffectedFiles(self):
    self.PatchObject(git, 'RawDiff', return_value=[
        # A modified normal file.
        git.RawDiffEntry(src_mode='100644', dst_mode='100644', src_sha='abc',
                         dst_sha='abc', status='M', score=None,
                         src_file='buildbot/constants.py', dst_file=None),
        # A new symlink file.
        git.RawDiffEntry(src_mode='000000', dst_mode='120000', src_sha='abc',
                         dst_sha='abc', status='A', score=None,
                         src_file='scripts/cros_env_whitelist', dst_file=None),
        # A deleted file.
        git.RawDiffEntry(src_mode='100644', dst_mode='000000', src_sha='abc',
                         dst_sha='000000', status='D', score=None,
                         src_file='scripts/sync_sonic.py', dst_file=None),
    ])

  def testGetAffectedFilesNoDeletesNoRelative(self):
    """Verify _get_affected_files() works w/no delete & not relative."""
    self._SetupGetAffectedFiles()
    path = os.getcwd()
    files = pre_upload._get_affected_files('HEAD', include_deletes=False,
                                           relative=False)
    exp_files = [os.path.join(path, 'buildbot/constants.py')]
    self.assertEquals(files, exp_files)

  def testGetAffectedFilesDeletesNoRelative(self):
    """Verify _get_affected_files() works w/delete & not relative."""
    self._SetupGetAffectedFiles()
    path = os.getcwd()
    files = pre_upload._get_affected_files('HEAD', include_deletes=True,
                                           relative=False)
    exp_files = [os.path.join(path, 'buildbot/constants.py'),
                 os.path.join(path, 'scripts/sync_sonic.py')]
    self.assertEquals(files, exp_files)

  def testGetAffectedFilesNoDeletesRelative(self):
    """Verify _get_affected_files() works w/no delete & relative."""
    self._SetupGetAffectedFiles()
    files = pre_upload._get_affected_files('HEAD', include_deletes=False,
                                           relative=True)
    exp_files = ['buildbot/constants.py']
    self.assertEquals(files, exp_files)

  def testGetAffectedFilesDeletesRelative(self):
    """Verify _get_affected_files() works w/delete & relative."""
    self._SetupGetAffectedFiles()
    path = os.getcwd()
    files = pre_upload._get_affected_files('HEAD', include_deletes=True,
                                           relative=True)
    exp_files = ['buildbot/constants.py', 'scripts/sync_sonic.py']
    self.assertEquals(files, exp_files)


if __name__ == '__main__':
  cros_test_lib.main()
