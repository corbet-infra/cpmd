# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-3.0-or-later
# One value out of a sops file, never printed: `lookup('corbet.crfs.sops', '/path/file.yml', 'key')`.
from __future__ import annotations

DOCUMENTATION = r"""
name: sops
author: Julian Y. Richard Corbet
short_description: read ONE value from a sops-encrypted file
description:
  - Runs C(sops --decrypt --extract) for a single key path and returns the value. The value must be one
    non-empty line unless O(multiline=true). Nothing else of the file is decrypted into the process.
  - Use it with C(no_log) on every task that handles the result.
options:
  _terms:
    description: The sops file (absolute, or relative to O(secrets_dir)) and the key path.
    required: true
  secrets_dir:
    description: Directory for relative file names.
    default: ''
    env:
      - name: CRFS_SECRETS_DIR
  multiline:
    description: Allow a multi-line value (PEM).
    type: bool
    default: false
notes:
  - The key path is either a plain key (C(ssh_password)) or a dotted path with list indexes (C(boxes.3.ssh_password)).
"""

EXAMPLES = r"""
- ansible.builtin.set_fact:
    rustfs_root_password: "{{ lookup('corbet.crfs.sops', '/path/to/cluster.sops.yml', 'rustfs_secret_key') }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: The value.
  type: list
  elements: str
"""

import os
import re
import subprocess

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase


def sops_extract(path, keypath, multiline=False):
    parts = []
    for tok in keypath.split("."):
        if re.fullmatch(r"\d+", tok):
            parts.append("[%s]" % tok)
        elif re.fullmatch(r"[A-Za-z0-9_-]+", tok):
            parts.append('["%s"]' % tok)
        else:
            raise AnsibleLookupError("sops: bad key path element %r" % tok)
    r = subprocess.run(["sops", "--decrypt", "--extract", "".join(parts), path], capture_output=True, text=True)
    if r.returncode != 0:
        raise AnsibleLookupError("sops could not extract %s from %s" % (keypath, os.path.basename(path)))
    v = r.stdout.rstrip("\n")
    if not v or ("\n" in v and not multiline):
        raise AnsibleLookupError("sops value %s of %s is empty or has several lines" % (keypath, os.path.basename(path)))
    return v


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        if len(terms) != 2:
            raise AnsibleLookupError("sops lookup takes exactly two terms: file and key")
        base = os.path.expanduser(self.get_option("secrets_dir") or "")
        fn = os.path.expanduser(terms[0])
        if not os.path.isabs(fn) and not base:
            raise AnsibleLookupError("relative sops file name %r needs secrets_dir / CRFS_SECRETS_DIR" % fn)
        path = fn if os.path.isabs(fn) else os.path.join(base, fn)
        return [sops_extract(path, terms[1], self.get_option("multiline"))]
