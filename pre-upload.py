# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess

# Helpers

def _get_hooks_dir():
  """Returns the absolute path to the repohooks directory"""
  cmd = ['repo', 'forall', 'chromiumos/repohooks', '-c', 'pwd']
  return subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0].strip()

def _get_diff():
  """Returns the diff for this project"""

  # TODO(msb) iterate over each commit
  cmd = ['git', 'show', 'HEAD']
  return subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]

# Hooks

def _run_checkpatch(project):
  """Runs checkpatch.pl on the given project"""
  hooks_dir = _get_hooks_dir()
  cmd = ['%s/checkpatch.pl' % hooks_dir, '-']
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  output = p.communicate(_get_diff())[0]
  if p.returncode:
    raise Exception('checkpatch.pl errors/warnings\n\n' + output)

# Base

def _setup_project_hooks():
  """Returns a dictionay of callbacks: dict[project] = [callback1, callback2]"""
  return {
    "chromiumos/third_party/kernel": [_run_checkpatch]
    }

def _run_project_hooks(project, hooks):
  """For each project run its project specific hook from the hooks dictionary"""
  cmd = ['repo', 'forall', project, '-c', 'pwd']
  proj_dir = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
  proj_dir = proj_dir.strip()
  if project in hooks:
    pwd = os.getcwd()
    # hooks assume they are run from the root of the project
    os.chdir(proj_dir)
    for hook in hooks[project]:
        hook(project)
    os.chdir(pwd)

# Main

def main(project_list, **kwargs):
  hooks = _setup_project_hooks()
  for project in project_list:
    _run_project_hooks(project, hooks)

if __name__ == '__main__':
  main()
