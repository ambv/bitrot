#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013 by Łukasz Langa
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import atexit
import datetime
import hashlib
import os
import sqlite3
import sys


CHUNK_SIZE = 16384
DOT_THRESHOLD = 200
VERSION = (0, 1, 0)


def sha1(path):
    digest = hashlib.sha1()
    with open(path) as f:
        d = f.read(CHUNK_SIZE)
        while d:
            digest.update(d)
            d = f.read(CHUNK_SIZE)
    return digest.hexdigest()


def get_sqlite3_cursor(path):
    conn = sqlite3.connect(path)
    atexit.register(conn.close)
    cur = conn.cursor()
    for name, in cur.execute('SELECT name FROM sqlite_master'):
        if name == 'bitrot':
            break
    else:
        cur.execute('CREATE TABLE bitrot (path TEXT PRIMARY KEY, '
                    'mtime INTEGER, hash TEXT, timestamp TEXT)')
    return conn


def run():
    current_dir = b'.'   # sic, relative path
    bitrot_db = os.path.join(current_dir, b'.bitrot.db')
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    new_count = 0
    update_count = 0
    error_count = 0
    dot_count = 0
    for path, _, files in os.walk(current_dir):
        for f in files:
            dot_count = (dot_count + 1) % DOT_THRESHOLD
            if not dot_count:
                sys.stdout.write('.')
                sys.stdout.flush()
            p = os.path.join(path, f)
            if p == bitrot_db:
                continue
            new_mtime = int(os.stat(p).st_mtime)
            new_sha1 = sha1(p)
            update_ts = datetime.datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S%z"
            )
            p_uni = p.decode('utf8')
            cur.execute('SELECT mtime, hash, timestamp FROM bitrot WHERE '
                        'path=?', (p_uni,))
            row = cur.fetchone()
            if not row:
                new_count += 1
                cur.execute('INSERT INTO bitrot VALUES (?, ?, ?, ?)',
                    (p_uni, new_mtime, new_sha1, update_ts))
                conn.commit()
                continue
            stored_mtime, stored_sha1, update_ts = row
            if int(stored_mtime) != new_mtime:
                update_count += 1
                cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                           'WHERE path=?',
                           (new_mtime, new_sha1, update_ts, p_uni))
                conn.commit()
            elif stored_sha1 != new_sha1:
                error_count += 1
                print("\rerror: SHA1 mismatch for {}: expected {}, got {}."
                      " Original info from {}.".format(
                          p, stored_sha1, new_sha1, update_ts
                      ),
                      file=sys.stderr,
                )
    cur.execute('SELECT COUNT(path) FROM bitrot')
    all_count = cur.fetchone()[0]
    print("\nFinished. {} errors found.".format(error_count))
    print("{} entries in the database, {} new, {} updated.".format(
              all_count, new_count, update_count
    ))
    if error_count:
        sys.exit(1)


if __name__ == '__main__':
    run()
