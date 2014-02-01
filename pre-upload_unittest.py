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


if __name__ == '__main__':
  cros_test_lib.main()
