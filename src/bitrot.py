#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013 by Łukasz Langa

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
import errno
import functools
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time


DEFAULT_CHUNK_SIZE = 16384
DOT_THRESHOLD = 200
VERSION = (0, 6, 0)


def sha1(path, chunk_size):
    digest = hashlib.sha1()
    with open(path) as f:
        d = f.read(chunk_size)
        while d:
            digest.update(d)
            d = f.read(chunk_size)
    return digest.hexdigest()


def throttled_commit(conn, commit_interval, last_commit_time):
    if time.time() - last_commit_time > commit_interval:
        conn.commit()
        last_commit_time = time.time()
    return last_commit_time


def get_sqlite3_cursor(path, copy=False):
    if copy:
        if not os.path.exists(path):
            raise ValueError("error: bitrot database at {} does not exist."
                             "".format(path))
        db_copy = tempfile.NamedTemporaryFile(prefix='bitrot_', suffix='.db',
                                              delete=False)
        with open(path, 'rb') as db_orig:
            try:
                shutil.copyfileobj(db_orig, db_copy)
            finally:
                db_copy.close()
        path = db_copy.name
        atexit.register(os.unlink, path)
    conn = sqlite3.connect(path)
    atexit.register(conn.close)
    cur = conn.cursor()
    tables = set(t for t, in cur.execute('SELECT name FROM sqlite_master'))
    if 'bitrot' not in tables:
        cur.execute('CREATE TABLE bitrot (path TEXT PRIMARY KEY, '
                    'mtime INTEGER, hash TEXT, timestamp TEXT)')
    if 'bitrot_hash_idx' not in tables:
        cur.execute('CREATE INDEX bitrot_hash_idx ON bitrot (hash)')
    atexit.register(conn.commit)
    return conn


def run(verbosity=1, test=False, follow_links=False, commit_interval=300,
        chunk_size=DEFAULT_CHUNK_SIZE):
    current_dir = b'.'   # sic, relative path
    bitrot_db = os.path.join(current_dir, b'.bitrot.db')
    conn = get_sqlite3_cursor(bitrot_db, copy=test)
    cur = conn.cursor()
    new_paths = []
    updated_paths = []
    renamed_paths = []
    error_count = 0
    total_size = 0
    current_size = 0
    last_reported_size = ''
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
            p_uni = p.decode('utf8')
            try:
                if follow_links or p_uni in missing_paths:
                    st = os.stat(p)
                else:
                    st = os.lstat(p)
            except OSError as ex:
                if ex.errno != errno.ENOENT:
                    raise
            else:
                if not stat.S_ISREG(st.st_mode) or p == bitrot_db:
                    continue
                paths.append(p)
                total_size += st.st_size
    paths.sort()
    last_commit_time = 0
    tcommit = functools.partial(throttled_commit, conn, commit_interval)
    for p in paths:
        st = os.stat(p)
        new_mtime = int(st.st_mtime)
        current_size += st.st_size
        if verbosity:
            size_fmt = '\r{:>6.1%}'.format(current_size/(total_size or 1))
            if size_fmt != last_reported_size:
                sys.stdout.write(size_fmt)
                sys.stdout.flush()
                last_reported_size = size_fmt
        p_uni = p.decode('utf8')
        missing_paths.discard(p_uni)
        try:
            new_sha1 = sha1(p, chunk_size)
        except (IOError, OSError) as e:
            if verbosity:
                print(
                    '\rwarning: cannot compute hash of {} [{}]'.format(
                        p, errno.errorcode[e.args[0]],
                    ),
                    file=sys.stderr,
                )
            continue
        update_ts = datetime.datetime.utcnow().strftime(
            '%Y-%m-%d %H:%M:%S%z'
        )
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

                    last_commit_time = tcommit(last_commit_time)
                    break
            else:
                new_paths.append(p)
                cur.execute(
                    'INSERT INTO bitrot VALUES (?, ?, ?, ?)',
                    (p_uni, new_mtime, new_sha1, update_ts),
                )
                last_commit_time = tcommit(last_commit_time)
            continue
        stored_mtime, stored_sha1, update_ts = row
        if int(stored_mtime) != new_mtime:
            updated_paths.append(p)
            cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                        'WHERE path=?',
                        (new_mtime, new_sha1, update_ts, p_uni))
            last_commit_time = tcommit(last_commit_time)
        elif stored_sha1 != new_sha1:
            error_count += 1
            print(
                '\rerror: SHA1 mismatch for {}: expected {}, got {}.'
                ' Original info from {}.'.format(
                    p, stored_sha1, new_sha1, update_ts
                ),
                file=sys.stderr,
            )
    for path in missing_paths:
        cur.execute('DELETE FROM bitrot WHERE path=?', (path,))
        last_commit_time = tcommit(last_commit_time)
    conn.commit()
    cur.execute('SELECT COUNT(path) FROM bitrot')
    all_count = cur.fetchone()[0]
    if verbosity:
        print('\rFinished. {:.2f} MiB of data read. {} errors found.'
              ''.format(total_size/1024/1024, error_count))
        if verbosity == 1:
            print(
                '{} entries in the database, {} new, {} updated, '
                '{} renamed, {} missing.'.format(
                    all_count, len(new_paths), len(updated_paths),
                    len(renamed_paths), len(missing_paths),
                ),
            )
        elif verbosity > 1:
            print('{} entries in the database.'.format(all_count), end=' ')
            if new_paths:
                print('{} entries new:'.format(len(new_paths)))
                new_paths.sort()
                for path in new_paths:
                    print(' ', path)
            if updated_paths:
                print('{} entries updated:'.format(len(updated_paths)))
                updated_paths.sort()
                for path in updated_paths:
                    print(' ', path)
            if renamed_paths:
                print('{} entries renamed:'.format(len(renamed_paths)))
                renamed_paths.sort()
                for path in renamed_paths:
                    print(' from', path[0], 'to', path[1])
            if missing_paths:
                print('{} entries missing:'.format(len(missing_paths)))
                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                    print(' ', path)
            if not any((new_paths, updated_paths, missing_paths)):
                print()
        if test:
            print('warning: database file not updated on disk (test mode).')
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
    parser.add_argument(
        '-l', '--follow-links', action='store_true',
        help='follow symbolic links and store target files\' hashes. Once '
             'a path is present in the database, it will be checked against '
             'changes in content even if it becomes a symbolic link. In '
             'other words, if you run `bitrot -l`, on subsequent runs '
             'symbolic links registered during the first run will be '
             'properly followed and checked even if you run without `-l`.')
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='don\'t print anything besides checksum errors')
    parser.add_argument(
        '-s', '--sum', action='store_true',
        help='using only the data already gathered, return a SHA-512 sum '
             'of hashes of all the entries in the database. No timestamps '
             'are used in calculation.')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='list new, updated and missing entries')
    parser.add_argument(
        '-t', '--test', action='store_true',
        help='just test against an existing database, don\'t update anything')
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    parser.add_argument(
        '--commit-interval', type=float, default=300,
        help='min time in seconds between commits '
             '(0 commits on every operation)')
    parser.add_argument(
        '--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
        help='read files this many bytes at a time')
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
        run(
            verbosity=verbosity,
            test=args.test,
            follow_links=args.follow_links,
            commit_interval=args.commit_interval,
            chunk_size=args.chunk_size,
        )


if __name__ == '__main__':
    run_from_command_line()
