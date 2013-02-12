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

import argparse
import atexit
import datetime
import hashlib
import os
import sqlite3
import sys


CHUNK_SIZE = 16384
DOT_THRESHOLD = 200
VERSION = (0, 2, 1)


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


def run(verbosity=1):
    current_dir = b'.'   # sic, relative path
    bitrot_db = os.path.join(current_dir, b'.bitrot.db')
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    new_paths = []
    updated_paths = []
    error_count = 0
    dot_count = 0
    missing_paths = set()
    cur.execute('SELECT path FROM bitrot')
    row = cur.fetchone()
    while row:
        missing_paths.add(row[0])
        row = cur.fetchone()
    for path, _, files in os.walk(current_dir):
        for f in files:
            if verbosity and not dot_count:
                sys.stdout.write('.')
                sys.stdout.flush()
            dot_count = (dot_count + 1) % DOT_THRESHOLD
            p = os.path.join(path, f)
            if p == bitrot_db:
                continue
            new_mtime = int(os.stat(p).st_mtime)
            new_sha1 = sha1(p)
            update_ts = datetime.datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S%z"
            )
            p_uni = p.decode('utf8')
            missing_paths.discard(p_uni)
            cur.execute('SELECT mtime, hash, timestamp FROM bitrot WHERE '
                        'path=?', (p_uni,))
            row = cur.fetchone()
            if not row:
                new_paths.append(p)
                cur.execute('INSERT INTO bitrot VALUES (?, ?, ?, ?)',
                    (p_uni, new_mtime, new_sha1, update_ts))
                conn.commit()
                continue
            stored_mtime, stored_sha1, update_ts = row
            if int(stored_mtime) != new_mtime:
                updated_paths.append(p)
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
    for path in missing_paths:
        cur.execute('DELETE FROM bitrot WHERE path=?', (path,))
        conn.commit()
    cur.execute('SELECT COUNT(path) FROM bitrot')
    all_count = cur.fetchone()[0]
    if verbosity:
        print("\rFinished. {} errors found.".format(error_count))
        if verbosity == 1:
            print("{} entries in the database, {} new, {} updated, {} missing."
                  "".format(all_count, len(new_paths), len(updated_paths),
                            len(missing_paths)))
        elif verbosity > 1:
            print("{} entries in the database.".format(all_count), end=' ')
            if new_paths:
                print("{} entries new:".format(len(new_paths)))
                new_paths.sort()
                for path in new_paths:
                    print(" ", path)
            if updated_paths:
                print("{} entries updated:".format(len(updated_paths)))
                updated_paths.sort()
                for path in updated_paths:
                    print(" ", path)
            if missing_paths:
                print("{} entries missing:".format(len(missing_paths)))
                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                    print(" ", path)
            if not any((new_paths, updated_paths, missing_paths)):
                print()
    if error_count:
        sys.exit(1)


def run_from_command_line():
    parser = argparse.ArgumentParser(prog='bitrot')
    parser.add_argument('-q', '--quiet', action='store_true',
        help='don\'t print anything besides checksum errors')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='list new, updated and missing entries')
    parser.add_argument('--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    args = parser.parse_args()
    verbosity = 1
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    run(verbosity=verbosity)


if __name__ == '__main__':
    run_from_command_line()
