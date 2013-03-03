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
import stat
import sys


CHUNK_SIZE = 16384
DOT_THRESHOLD = 200
VERSION = (0, 4, 0)


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
    renamed_paths = []
    error_count = 0
    total_size = 0
    current_size = 0
    missing_paths = set()
    cur.execute('SELECT path FROM bitrot')
    row = cur.fetchone()
    while row:
        missing_paths.add(row[0])
        row = cur.fetchone()
    paths = []
    for path, _, files in os.walk(current_dir):
        for f in files:
            p = os.path.join(path, f)
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode) or p == bitrot_db:
                continue
            paths.append(p)
            total_size += st.st_size
    paths.sort()
    for p in paths:
        st = os.stat(p)
        new_mtime = int(st.st_mtime)
        current_size += st.st_size
        if verbosity:
            sys.stdout.write('\r{:>6.1%}'.format(current_size/total_size))
            sys.stdout.flush()
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
            cur.execute('SELECT mtime, path, timestamp FROM bitrot WHERE '
                        'hash=?', (new_sha1,))
            rows = cur.fetchall()
            for row in rows:
                stored_mtime, stored_path, update_ts = row
                if not os.path.exists(stored_path):
                    renamed_paths.append((stored_path, p_uni))
                    missing_paths.discard(stored_path)
                    cur.execute('UPDATE bitrot SET mtime=?, path=?, '
                                'timestamp=? WHERE hash=?',
                                (new_mtime, p_uni, update_ts, new_sha1))
                    conn.commit()
                    break
            else:
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
            print("{} entries in the database, {} new, {} updated, "
                  "{} renamed, {} missing.".format(all_count, len(new_paths),
                      len(updated_paths), len(renamed_paths), len(missing_paths)
            ))
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
            if renamed_paths:
                print("{} entries renamed:".format(len(renamed_paths)))
                renamed_paths.sort()
                for path in renamed_paths:
                    print(" from", path[0], "to", path[1])
            if missing_paths:
                print("{} entries missing:".format(len(missing_paths)))
                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                    print(" ", path)
            if not any((new_paths, updated_paths, missing_paths)):
                print()
    if error_count:
        sys.exit(1)


def stable_sum():
    current_dir = b'.'   # sic, relative path
    bitrot_db = os.path.join(current_dir, b'.bitrot.db')
    digest = hashlib.sha512()
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    cur.execute('SELECT hash FROM bitrot ORDER BY path')
    row = cur.fetchone()
    while row:
        digest.update(row[0])
        row = cur.fetchone()
    return digest.hexdigest()


def run_from_command_line():
    parser = argparse.ArgumentParser(prog='bitrot')
    parser.add_argument('-q', '--quiet', action='store_true',
        help='don\'t print anything besides checksum errors')
    parser.add_argument('-s', '--sum', action='store_true',
        help='using only the data already gathered, return a SHA-512 sum '
             'of hashes of all the entries in the database. No timestamps '
             'are used in calculation.')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='list new, updated and missing entries')
    parser.add_argument('--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    args = parser.parse_args()
    if args.sum:
        try:
            print(stable_sum())
        except RuntimeError as e:
            print(unicode(e).encode('utf8'), file=sys.stderr)
    else:
        verbosity = 1
        if args.quiet:
            verbosity = 0
        elif args.verbose:
            verbosity = 2
        run(verbosity=verbosity)


if __name__ == '__main__':
    run_from_command_line()
