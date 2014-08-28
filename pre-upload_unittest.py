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
    self.assertTrue(isinstance (ret, errors.HookFailure))

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
    self.assertTrue(isinstance (ret, errors.HookFailure))

    # Verify we handle double quotes too.
    self.content_mock.return_value = template % '"1"'
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance (ret, errors.HookFailure))

    # Verify we handle single quotes too.
    self.content_mock.return_value = template % "'1'"
    ret = pre_upload._check_ebuild_eapi('overlay', 'HEAD')
    self.assertTrue(isinstance (ret, errors.HookFailure))

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
    self.assertTrue(isinstance (ret, errors.HookFailure))

  def testPublicBoardVirtuals(self):
    """Public board overlays should use PV=2."""
    template = 'overlay-lumpy/virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '2']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '2.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertTrue(isinstance (ret, errors.HookFailure))

  def testPublicBoardVariantVirtuals(self):
    """Public board variant overlays should use PV=2.5."""
    template = 'overlay-variant-lumpy-foo/virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '2.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '3']
    ret = pre_upload._check_ebuild_virtual_pv(self.BOARD_OVERLAY, 'H')
    self.assertTrue(isinstance (ret, errors.HookFailure))

  def testPrivateBoardVirtuals(self):
    """Private board overlays should use PV=3."""
    template = 'virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '3']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '3.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_OVERLAY, 'H')
    self.assertTrue(isinstance (ret, errors.HookFailure))

  def testPrivateBoardVariantVirtuals(self):
    """Private board variant overlays should use PV=3.5."""
    template = 'virtual/foo/foo-%s.ebuild'
    self.file_mock.return_value = [template % '3.5']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_VARIANT_OVERLAY, 'H')
    self.assertEqual(ret, None)

    self.file_mock.return_value = [template % '4']
    ret = pre_upload._check_ebuild_virtual_pv(self.PRIVATE_VARIANT_OVERLAY, 'H')
    self.assertTrue(isinstance (ret, errors.HookFailure))


class CheckGitOutputParsing(cros_test_lib.MockTestCase):
  """Tests for git output parsing."""

  def testParseAffectedFiles(self):
    """Test parsing git diff --raw output."""
    # Sample from git diff --raw.
    sample_git_output = '\n'.join([
        ":100644 100644 ff03961... a198e8b... M\tMakefile",
        ":100644 000000 e69de29... 0000000... D\tP1/P2",
        ":100755 100644 454d5ef... 0000000... C86\tP3\tP4",
        ":100755 100644 454d5ef... 0000000... R86\tP5\tP6/P7",
        ":100755 120644 454d5ef... 0000000... M\tIsASymlink",
    ])
    expected_modified_files_no_deletes = ['Makefile', 'P4', 'P6/P7']
    expected_modified_files_with_deletes = ['Makefile', 'P1/P2', 'P4', 'P6/P7']
    result = pre_upload._parse_affected_files(sample_git_output,
                                              include_deletes=True,
                                              relative=True)
    self.assertEqual(result, expected_modified_files_with_deletes)
    result = pre_upload._parse_affected_files(sample_git_output,
                                              include_deletes=False,
                                              relative=True)
    self.assertEqual(result, expected_modified_files_no_deletes)


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


if __name__ == '__main__':
  cros_test_lib.main()
