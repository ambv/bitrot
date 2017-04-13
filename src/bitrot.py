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
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import smtplib
from fnmatch import fnmatch
import email.utils
from email.mime.text import MIMEText
from datetime import timedelta
#import re

DEFAULT_CHUNK_SIZE = 16384  # block size in HFS+; 4X the block size in ext4
DOT_THRESHOLD = 200
VERSION = (0, 9, 2)
IGNORED_FILE_SYSTEM_ERRORS = {errno.ENOENT, errno.EACCES}
FSENCODING = sys.getfilesystemencoding()
DEFAULT_HASH_FUNCTION = "SHA512"

if sys.version[0] == '2':
    str = type(u'text')
    # use `bytes` for bytestrings

def writeToLog(stringToWrite=""):
    log_path = get_path(ext=b'log')
    stringToWrite = cleanString(stringToWrite)
    with open(log_path, 'a') as logFile:
        logFile.write(stringToWrite)
        logFile.close()

def sendMail(stringToSend="", log=1, verbosity=1):
    msg = MIMEText(stringToSend)

    FROMADDR = 'author@gmail.com'
    TOADDR  = 'recipient@gmail.com'
    msg['To'] = email.utils.formataddr(('Recipient', 'recipient@gmail.com'))
    msg['From'] = email.utils.formataddr(('Author', 'recipient@gmail.com'))
    USERNAME = 'authorUsername'
    PASSWORD = 'authorPassword'

    try:
        msg['Subject'] = 'FIM Error'
        # The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(USERNAME,PASSWORD)
        server.sendmail(FROMADDR, TOADDR, msg.as_string())
        server.quit()
    except Exception as err:
        print('Email sending error:', err)
        if (log):
            writeToLog(stringToWrite='\nEmail sending error: {}'.format(err))


        


def cleanString(stringToClean=""):
    #stringToClean=re.sub(r'[\\/*?:"<>|]',"",stringToClean)
    stringToClean = ''.join([x for x in stringToClean if ord(x) < 128])
    return stringToClean

def hash(path, chunk_size,hashing_function="",log=1):
    if (not isValidHashingFunction(stringToValidate=hashing_function)):
        hashing_function = DEFAULT_HASH_FUNCTION
    if   (hashing_function.upper() == "MD5"):
        digest=hashlib.md5()
    elif (hashing_function.upper() == "SHA1"):
        digest=hashlib.sha1()
    elif (hashing_function.upper() == "SHA224"):
        digest=hashlib.sha224()
    elif (hashing_function.upper() == "SHA384"):
        digest=hashlib.sha384()
    elif (hashing_function.upper() == "SHA256"):
        digest=hashlib.sha256()
    elif (hashing_function.upper() == "SHA512"):
        digest=hashlib.sha512() 
    else:
        if (log):
            writeToLog(stringToWrite='\nInvalid hash function detected.')
        raise Exception('Invalid hash function detected.')

    with open(path, 'rb') as f:
        d = f.read(chunk_size)
        while d:
            digest.update(d)
            d = f.read(chunk_size)
    return digest.hexdigest()


def ts():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S%z')


def get_sqlite3_cursor(path, copy=False):
    path = path.decode(FSENCODING)
    if copy:
        if not os.path.exists(path):
            raise ValueError("Error: bitrot database at {} does not exist."
                             "".format(path))
            if (self.log):
                writeToLog(stringToWrite="Error: bitrot database at {} does not exist.\n"
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


def list_existing_paths(directory, expected=(), ignored=(), 
                        verbosity=1, follow_links=False, log=1):
    """list_existing_paths('/dir') -> ([path1, path2, ...], total_size)

    Returns a tuple with a list with existing files in `directory` and their
    `total_size`.

    Doesn't add entries listed in `ignored`.  Doesn't add symlinks if
    `follow_links` is False (the default).  All entries present in `expected`
    must be files (can't be directories or symlinks).
    """
    paths = []
    total_size = 0
    for path, _, files in os.walk(directory):
        for f in files:
            p = os.path.join(path, f)
            try:
                p_uni = p.decode(FSENCODING)
            except UnicodeDecodeError:
                binary_stderr = getattr(sys.stderr, 'buffer', sys.stderr)
                warnings.append(p)
                binary_stderr.write(b"\rWarning: cannot decode file name: ")
                binary_stderr.write(p)
                binary_stderr.write(b"\n")
                if (log):
                    writeToLog(stringToWrite="\nWarning: cannot decode file name: {}".format(p))
                continue

            try:
                if follow_links or p_uni in expected:
                    st = os.stat(p)
                else:
                    st = os.lstat(p)
            except OSError as ex:
                if ex.errno not in IGNORED_FILE_SYSTEM_ERRORS:
                    raise
            else:
                if not stat.S_ISREG(st.st_mode) or any([fnmatch(p, exc) for exc in ignored]):
                    if verbosity > 1:
                        #print('Ignoring file: {}'.format(p))
                        print('Ignoring file: {}'.format(p.decode(FSENCODING)))
                        if (log):
                            #writeToLog(stringToWrite="\nIgnoring file: {}".format(p))
                            writeToLog(stringToWrite="\nIgnoring file: {}".format(p.decode(FSENCODING)))

                    continue
                paths.append(p)
                total_size += st.st_size
    paths.sort()
    return paths, total_size


class BitrotException(Exception):
    pass


class Bitrot(object):
    def __init__(
        self, verbosity=1, email = False, log = False, test=False, follow_links=False, commit_interval=300,
        chunk_size=DEFAULT_CHUNK_SIZE, file_list=None, exclude_list=[],  no_time=False, hashing_function=""
    ):
        self.verbosity = verbosity
        self.test = test
        self.follow_links = follow_links
        self.commit_interval = commit_interval
        self.chunk_size = chunk_size
        self.file_list = file_list
        self.exclude_list = exclude_list
        self._last_reported_size = ''
        self._last_commit_ts = 0
        self.email = email
        self.log = log
        self.no_time = no_time
        self.startTime = time.clock()
        self.hashing_function = hashing_function

    def maybe_commit(self, conn):
        if time.time() < self._last_commit_ts + self.commit_interval:
            # no time for commit yet!
            return

        conn.commit()
        self._last_commit_ts = time.time()

    def run(self):
        check_sha512_integrity(verbosity=self.verbosity, log=self.log)

        bitrot_sha512 = get_path(ext=b'sha512')
        bitrot_log = get_path(ext=b'log')
        bitrot_db = get_path()
      
        try:
            conn = get_sqlite3_cursor(bitrot_db, copy=self.test)
        except ValueError:
            raise BitrotException(
                2,
                'No database exists so cannot test. Run the tool once first.',
            )
            if (self.log):
                writeToLog(stringToWrite="\nNo database exists so cannot test. Run the tool once first.")

        cur = conn.cursor()
        new_paths = []
        updated_paths = []
        renamed_paths = []
        errors = []
        warnings = []
        current_size = 0
        missing_paths = self.select_all_paths(cur)
        if self.file_list:
            paths = [line.rstrip('\n').encode(FSENCODING)
                for line in self.file_list.readlines()]
            total_size = sum([os.path.getsize(filename) for filename in paths])
        else:
            paths, total_size = list_existing_paths(
                b'.', expected=missing_paths, 
                ignored=[bitrot_db, bitrot_sha512,bitrot_log] + self.exclude_list,
                follow_links=self.follow_links,
                verbosity=self.verbosity,
                log=self.log
            )


        for p in paths:
            p_uni = p.decode(FSENCODING)
            try:
                st = os.stat(p)
            except OSError as ex:
                if ex.errno in IGNORED_FILE_SYSTEM_ERRORS:
                    # The file disappeared between listing existing paths and
                    # this run or is (temporarily?) locked with different
                    # permissions. We'll just skip it for now.
                    warnings.append(p)
                    print(
                        '\rWarning: `{}` is currently unavailable for '
                        'reading: {}'.format(
                            #p_uni, ex,
                            p.decode(FSENCODING), ex,
                        ),
                        file=sys.stderr,
                    )
                    if (self.log):
                        #writeToLog(stringToWrite='\nWarning: `{}` is currently unavailable for reading: {}'.format(p_uni, ex))
                        writeToLog(stringToWrite='\nWarning: `{}` is currently unavailable for reading: {}'.format(p.decode(FSENCODING), ex))
                    continue

                raise   # Not expected? https://github.com/ambv/bitrot/issues/

            new_mtime = int(st.st_mtime)
            current_size += st.st_size
            if self.verbosity:
                self.report_progress(current_size, total_size, p_uni)

            missing_paths.discard(p_uni)
            try:
                new_hash = hash(p, self.chunk_size,self.hashing_function,log=self.log)
            except (IOError, OSError) as e:
                warnings.append(p)
                print(
                    '\rWarning: cannot compute hash of {} [{}]'.format(
                        #p, errno.errorcode[e.args[0]],
                        p.decode(FSENCODING),errno.errorcode[e.args[0]],
                    ),
                    file=sys.stderr,
                )
                if (self.log):
                    writeToLog(stringToWrite='\n\nWarning: cannot compute hash of {} [{}]'.format(
                            #p, errno.errorcode[e.args[0]]))
                            p.decode(FSENCODING), errno.errorcode[e.args[0]]))
                continue

            cur.execute('SELECT mtime, hash, timestamp FROM bitrot WHERE '
                        'path=?', (p_uni,))
            row = cur.fetchone()
            if not row:
                stored_path = self.handle_unknown_path(
                    cur, p_uni, new_mtime, new_hash
                )
                self.maybe_commit(conn)

                if p_uni == stored_path:
                    new_paths.append(p)   # FIXME: shouldn't that be p_uni instead of p?
                else:
                    renamed_paths.append((stored_path, p_uni))
                    missing_paths.discard(stored_path)
                continue
            stored_mtime, stored_hash, stored_ts = row
            if (int(stored_mtime) != new_mtime) and (self.no_time == False):
                updated_paths.append(p)
                cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                            'WHERE path=?',
                            (new_mtime, new_hash, ts(), p_uni))
                self.maybe_commit(conn)
                continue
            if stored_hash != new_hash:
                errors.append(p)

                if (isValidHashingFunction(stringToValidate=self.hashing_function)):
                    hashingFunctionString = self.hashing_function
                else:
                    hashingFunctionString = DEFAULT_HASH_FUNCTION
                    
                print(
                    '\rError: {} mismatch for {}\nExpected: {}\nGot:      {}'
                    '\nLast good hash checked on {}\n'.format(
                    #p, stored_hash, new_hash, stored_ts
                    hashingFunctionString,p.decode(FSENCODING), stored_hash, new_hash, stored_ts
                    ),
                    file=sys.stderr,
                )
                if (self.log):
                    writeToLog(stringToWrite=
                        '\n\nError: {} mismatch for {}\nExpected: {}\nGot:          {}'
                        '\nLast good hash checked on {}\n'.format(
                        #p, stored_hash, new_hash, stored_ts
                        hashingFunctionString,p.decode(FSENCODING), stored_hash, new_hash, stored_ts))
                if (self.email):
                        sendMail('Error {} mismatch for {} \nExpected {}\nGot          {}\nLast good hash checked on {}'.format(hashingFunctionString,p.decode(FSENCODING),
                        stored_hash,new_hash,stored_ts),log=self.log,verbosity=self.verbosity)
                    
        for path in missing_paths:
            cur.execute('DELETE FROM bitrot WHERE path=?', (path,))

        conn.commit()

        if self.verbosity:
            cur.execute('SELECT COUNT(path) FROM bitrot')
            all_count = cur.fetchone()[0]
            self.report_done(
                total_size,
                all_count,
                len(errors),
                len(warnings),
                new_paths,
                updated_paths,
                renamed_paths,
                missing_paths,
            )

        update_sha512_integrity(verbosity=self.verbosity, log=self.log)


        if self.verbosity:
            elapsedTime = (time.clock() - self.startTime)
            
            if (elapsedTime > 3600):
                elapsedTime /= 3600
                if ((int)(elapsedTime) == 1):
                    print('Time elapsed: 1 hour.')
                    if (self.log):
                        writeToLog(stringToWrite='\nTime elapsed: 1 hour.')
                else:
                    print('Time elapsed: {:.1f} hours.'.format(elapsedTime))
                    if (self.log):
                        writeToLog(stringToWrite='\nTime elapsed: {:.1f} hours.'.format(elapsedTime))

            elif (elapsedTime > 60):
                elapsedTime /= 60
                if ((int)(elapsedTime) == 1):
                    print('Time elapsed: 1 minute.')
                    if (self.log):
                        writeToLog(stringToWrite='\nTime elapsed: 1 minute.')
                else:
                    print('Time elapsed: {:.0f} minutes.'.format(elapsedTime))
                    if (self.log):
                        writeToLog(stringToWrite='\nTime elapsed: {:.0f} minutes.'.format(elapsedTime))

            else:
                if ((int)(elapsedTime) == 1):
                    print('Time elapsed: 1 second.')
                    if (self.log):
                        writeToLog(stringToWrite='\nTime elapsed: 1 second.')
                else:
                    print('Time elapsed: {:.0f} seconds.'.format(elapsedTime))
                    if (self.log):
                         writeToLog(stringToWrite='\nTime elapsed: {:.1f} seconds.'.format(elapsedTime))

        if warnings:
            if len(warnings) == 1:
                print('Warning: there was 1 warning found.')
                if (self.log):
                    writeToLog(stringToWrite='\nWarning: There was 1 warning found.')
            else:
                print('Warning: there were {} warnings found.'.format(len(warnings)))
                if (self.log):
                    writeToLog(stringToWrite='\nWarning: There were {} warnings found.'.format(len(warnings)))

        if errors:
            if len(errors) == 1:
                raise BitrotException(
                    1, 'There was 1 error found.',
                )
            else:
                raise BitrotException(
                    1, 'There were {} errors found.'.format(len(errors)), errors,
                )


    def select_all_paths(self, cur):
        result = set()
        cur.execute('SELECT path FROM bitrot')
        row = cur.fetchone()
        while row:
            result.add(row[0])
            row = cur.fetchone()
        return result

    def report_progress(self, current_size, total_size, current_path):
        size_fmt = '\r{:>6.1%}'.format(current_size/(total_size or 1))
        if size_fmt == self._last_reported_size:
            return

        # show current file in progress too
        terminal_size = shutil.get_terminal_size()
        # but is it too big for terminal window?
        cols = terminal_size.columns
        max_path_size = cols - len(size_fmt) - 1

        #without this line, weird character in the filename could cause strange printing output
        current_path = cleanString(stringToClean=current_path)

        if len(current_path) > max_path_size:
            # show first half and last half, separated by ellipsis
            # e.g. averylongpathnameaveryl...ameaverylongpathname
            half_mps = (max_path_size - 3) // 2
            current_path = current_path[:half_mps] + '...' + current_path[-half_mps:]
        else:
            # pad out with spaces, otherwise previous filenames won't be erased
            current_path += ' ' * (max_path_size - len(current_path))
            
        sys.stdout.write(size_fmt + ' ' + current_path)
        sys.stdout.flush()
        self._last_reported_size = size_fmt


    def report_done(
        self, total_size, all_count, error_count, warning_count, new_paths, updated_paths,
        renamed_paths, missing_paths):
        if (error_count == 1):
            print('\rFinished. {:.2f} MiB of data read. 1 error found. '.format(total_size/1024/1024),end="")
            if (self.log):
                writeToLog(stringToWrite='\n\nFinished. {:.2f} MiB of data read. '.format(total_size/1024/1024))
        else:
            print('\rFinished. {:.2f} MiB of data read. {} errors found. '.format(total_size/1024/1024, error_count),end="")
            if (self.log):
                writeToLog(stringToWrite='\n\nFinished. {:.2f} MiB of data read. {} errors found. '.format(total_size/1024/1024, error_count))

        if (warning_count == 1):
            print('1 warning found.')
            if (self.log):
                writeToLog(stringToWrite='1 warning found')
        else:
            print('{} warnings found.'.format(warning_count))
            if (self.log):
                writeToLog(stringToWrite='{} warnings found.'.format(warning_count))


        if self.verbosity == 1:
            if (all_count == 1):
                print(
                    '1 entry in the database, {} new, {} updated, '
                    '{} renamed, {} missing.'.format(
                        len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths)))
                if (self.log):
                    writeToLog(stringToWrite=
                    '\n1 entry in the database, {} new, {} updated, '
                    '{} renamed, {} missing.'.format(
                        len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths)))
            else:
                print(
                '{} entries in the database, {} new, {} updated, '
                '{} renamed, {} missing.'.format(
                    all_count, len(new_paths), len(updated_paths),
                    len(renamed_paths), len(missing_paths)))
                if (self.log):
                    writeToLog(stringToWrite=
                    '\n{} entries in the database, {} new, {} updated, '
                    '{} renamed, {} missing.'.format(
                        all_count, len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths)))

        elif self.verbosity > 1:
            if (all_count == 1):
                print('1 entry in the database.')
                if (self.log):
                    writeToLog(stringToWrite='1 entry in the database.')
            else:
                print('{} entries in the database.'.format(all_count), end=' ')
                if (self.log):
                    writeToLog(stringToWrite='\n{} entries in the database.'.format(all_count))

            if new_paths:
                if (len(new_paths) == 1):
                    print('\n1 new entry:')
                    if (self.log):
                        writeToLog(stringToWrite='\n1 new entry:')
                else:
                    print('\n{} new entries:'.format(len(new_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n{} new entries:'.format(len(new_paths)))

                new_paths.sort()
                for path in new_paths:
                    print(' ', path.decode(FSENCODING))
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path.decode(FSENCODING)))

            if updated_paths:
                if (len(updated_paths) == 1):
                    print('1 entry updated:')
                    if (self.log):
                        writeToLog(stringToWrite='\n1 entry updated:')
                else:
                    print('{} entries updated:'.format(len(updated_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n{} entries updated:'.format(len(updated_paths)))

                updated_paths.sort()
                for path in updated_paths:
                    print(' ', path.decode(FSENCODING))
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path.decode(FSENCODING)))

            if renamed_paths:
                if (len(renamed_paths) == 1):
                    print('1 entry renamed:')
                    if (self.log):
                        writeToLog(stringToWrite='\n1 entry renamed:')
                else:
                    print('{} entries renamed:'.format(len(renamed_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n{} entries renamed:'.format(len(renamed_paths)))

                renamed_paths.sort()
                for path in renamed_paths:
                    print(
                        '  from',
                        #path[0].decode(FSENCODING),
                        path[0],
                        'to',
                        #path[1].decode(FSENCODING),
                        path[1],
                    )
                    if (self.log):
                        writeToLog(stringToWrite='\n from {} to {}'.format(path[0],path[1]))
                    
            if missing_paths:
                if (len(missing_paths) == 1):
                    print('1 entry missing:')
                    if (self.log):
                        writeToLog(stringToWrite='\n1 entry missing:')
                else:
                    print('{} entries missing:'.format(len(missing_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n{} entries missing:'.format(len(missing_paths)))

                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                    print(' ', path)
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path))
                        
            if not any((new_paths, updated_paths, missing_paths)):
                print()
        if self.test and self.verbosity:
            print('Database file not updated on disk (test mode).')
            if (self.log):
                writeToLog(stringToWrite='\nDatabase file not updated on disk (test mode).')

    def handle_unknown_path(self, cur, new_path, new_mtime, new_sha1):
        """Either add a new entry to the database or update the existing entry
        on rename.

        Returns `new_path` if the entry was indeed new or the `stored_path` (e.g.
        outdated path) if there was a rename.
        """
        cur.execute('SELECT mtime, path, timestamp FROM bitrot WHERE hash=?',
                    (new_sha1,))
        rows = cur.fetchall()
        for row in rows:
            stored_mtime, stored_path, stored_ts = row
            if os.path.exists(stored_path):
                # file still exists, move on
                continue

            # update the path in the database
            cur.execute(
                'UPDATE bitrot SET mtime=?, path=?, timestamp=? WHERE path=?',
                (new_mtime, new_path, ts(), stored_path),
            )

            return stored_path

        # no rename, just a new file with the same hash
        cur.execute(
            'INSERT INTO bitrot VALUES (?, ?, ?, ?)',
            (new_path, new_mtime, new_sha1, ts()),
        )
        return new_path

def get_path(directory=b'.', ext=b'db'):
    """Compose the path to the selected bitrot file."""
    return os.path.join(directory, b'.bitrot.' + ext)


def stable_sum(bitrot_db=None):
    """Calculates a stable SHA512 of all entries in the database.

    Useful for comparing if two directories hold the same data, as it ignores
    timing information."""
    if bitrot_db is None:
        bitrot_db = get_path()
    digest = hashlib.sha512()
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    cur.execute('SELECT hash FROM bitrot ORDER BY path')
    row = cur.fetchone()
    while row:
        digest.update(row[0].encode('ascii'))
        row = cur.fetchone()
    return digest.hexdigest()

def check_sha512_integrity(verbosity=1, log=1):
    sha512_path = get_path(ext=b'sha512')
    if not os.path.exists(sha512_path):
        return

    if verbosity:
        print('Checking bitrot.db integrity... ', end='')
        if (log):
            writeToLog(stringToWrite='\nChecking bitrot.db integrity... ')
        sys.stdout.flush()
    with open(sha512_path, 'rb') as f:
        old_sha512 = f.read().strip()
    bitrot_db = get_path()
    digest = hashlib.sha512()
    with open(bitrot_db, 'rb') as f:
        digest.update(f.read())
    new_sha512 = digest.hexdigest().encode('ascii')
    if new_sha512 != old_sha512:
        if len(old_sha512) == 128:
            print(
                "\nError: SHA512 of the file is different, bitrot.db might "
                "be corrupt.",
            )
            if (log):
                writeToLog(stringToWrite=
                "\nError: SHA512 of the file is different, bitrot.db might "
                "be corrupt.",
            )
        else:
            print(
                "\nError: SHA512 of the file is different but bitrot.sha512 "
                "has a suspicious length. It might be corrupt.",
            )
            if (log):
                writeToLog(stringToWrite=
                "\nError: SHA512 of the file is different but bitrot.sha512 "
                "has a suspicious length. It might be corrupt.",
            )
        print(
            "If you'd like to continue anyway, delete the .bitrot.sha512 "
            "file and try again.",
            file=sys.stderr,
        )
        if (log):
            writeToLog(stringToWrite=
            "\nIf you'd like to continue anyway, delete the .bitrot.sha512 file and try again.")
            writeToLog(stringToWrite="\nbitrot.db integrity check failed, cannot continue.")

        raise BitrotException(
            3, 'bitrot.db integrity check failed, cannot continue.',
        )

    if verbosity:
        print('ok.')
        if (log):
            writeToLog(stringToWrite='ok.')


def update_sha512_integrity(verbosity=1, log=1):
    old_sha512 = 0
    sha512_path = get_path(ext=b'sha512')

    if os.path.exists(sha512_path):
        with open(sha512_path, 'rb') as f:
            old_sha512 = f.read().strip()
    bitrot_db = get_path()
    digest = hashlib.sha512()
    with open(bitrot_db, 'rb') as f:
        digest.update(f.read())
    new_sha512 = digest.hexdigest().encode('ascii')
    if new_sha512 != old_sha512:
        if verbosity:
            print('Updating bitrot.sha512... ', end='')
            if (log):
                writeToLog(stringToWrite='\nUpdating bitrot.sha512... ')
            sys.stdout.flush()
        with open(sha512_path, 'wb') as f:
            f.write(new_sha512)
        if verbosity:
            print('done.')
            if (log):
                writeToLog(stringToWrite='done.')

def isValidHashingFunction(stringToValidate=""):
    if  (stringToValidate.upper() == "SHA1"
      or stringToValidate.upper() == "SHA224"
      or stringToValidate.upper() == "SHA384"
      or stringToValidate.upper() == "SHA256"
      or stringToValidate.upper() == "SHA512"
      or stringToValidate.upper() == "MD5"):
        return True
    else:
        return False

def run_from_command_line():
    global FSENCODING
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
        '--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    parser.add_argument(
        '--commit-interval', type=float, default=300,
        help='min time in seconds between commits '
             '(0 commits on every operation)')
    parser.add_argument(
        '--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
        help='read files this many bytes at a time')
    parser.add_argument(
        '--fsencoding', default='',
        help='override the codec to decode filenames, otherwise taken from '
             'the LANG environment variables')
    parser.add_argument(
        '-f', '--file-list', default='',
        help='only read the files listed in this file (use - for stdin)')
    parser.add_argument(
        '-t', '--test', action='store_true',
        help='just test against an existing database, don\'t update anything')
    parser.add_argument(
        '-a', '--hashing-function', default='',
        help='Doesnt compare dates, only hashes. Also enables test-only mode')
    parser.add_argument(
        '-x', '--exclude-list', default='',
        help="don't read the files listed in this file - wildcards are allowed")
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='list new, updated and missing entries')
    parser.add_argument(
        '-n', '--no-time', action='store_true',
        help='Doesnt compare dates, only hashes. Also enables test-only mode')
    parser.add_argument(
        '-e', '--email', action='store_true',
        help='email file integirty errors')
    parser.add_argument(
        '-g', '--log', action='store_true',
        help='logs activity')

    
    args = parser.parse_args()
    if args.sum:
        try:
            print(stable_sum())
        except RuntimeError as e:
            print(str(e).encode('utf8'), file=sys.stderr)
    else:
        verbosity = 1
        if args.quiet:
            verbosity = 0
        elif args.verbose:
            verbosity = 2
        if (args.log):
            log_path = get_path(ext=b'log')
            if os.path.exists(log_path):
                writeToLog(stringToWrite='\n')
                writeToLog(stringToWrite='======================================================\n')
            writeToLog(stringToWrite='Log started at ')
            writeToLog(stringToWrite=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        if args.no_time:
            no_time = 1
            args.test = 1
        if args.file_list == '-':
            if verbosity:
                print('Using stdin for file list')
                if (args.log):
                   writeToLog(stringToWrite='\nUsing stdin for file list') 
            file_list = sys.stdin
        elif args.file_list:
            if verbosity:
                print('Opening file list in', args.file_list)
                if (args.log):
                    writeToLog(stringToWrite='\nOpening file list in ')
                    writeToLog(stringToWrite=args.file_list)
            file_list = open(args.file_list)
        else:
            file_list = None
        if args.exclude_list:
            if verbosity:
                print('Opening exclude list in', args.exclude_list)
                if (args.log):
                    writeToLog(stringToWrite='\nOpening exclude list in')
                    writeToLog(stringToWrite=args.exclude_list)
            exclude_list = [line.rstrip('\n').encode(FSENCODING) for line in open(args.exclude_list)]
        else:
            exclude_list = []
        bt = Bitrot(
            verbosity=verbosity,
            hashing_function=args.hashing_function.upper(),
            test=args.test,
            email=args.email,
            log = args.log,
            no_time = args.no_time,
            follow_links=args.follow_links,
            commit_interval=args.commit_interval,
            chunk_size=args.chunk_size,
            file_list=file_list,
            exclude_list=exclude_list,
        )
        if args.fsencoding:
            FSENCODING = args.fsencoding
        if (args.hashing_function):
            #combined = '\t'.join(hashlib.algorithms_available)
            #if (args.hashing_function in combined):
            #word_to_check = args.hashing_function
            #wordlist = hashlib.algorithms_available
            #result = any(word_to_check in word for word in wordlist)
            #algorithms_available = hashlib.algorithms_available
            #search = args.hashing_function
            #result = next((True for algorithms_available in algorithms_available if search in algorithms_available), False)
                if (isValidHashingFunction(stringToValidate=args.hashing_function) == True):
                    hashing_function = args.hashing_function
                    print('Using {} for hashing function'.format(args.hashing_function))   
                    if (args.log):
                       writeToLog(stringToWrite='\nUsing {} for hashing function'.format(args.hashing_function))
                else:
                    print("Invalid hashing function specified: {}. Using default SHA1".format(args.hashing_function))
                    if (args.log):
                        writeToLog(stringToWrite="\nInvalid hashing function specified: {}. Using default SHA1".format(args.hashing_function))
        else:
            hashing_function = None
        try:
            bt.run()
        except BitrotException as bre:
            print('Error:', bre.args[1], file=sys.stderr)
            if (args.log):
                writeToLog(stringToWrite='\nError: ')
                writeToLog(stringToWrite=bre.args[1])
            sys.exit(bre.args[0])

        if file_list:
            file_list.close() # should be harmless if file_list == sys.stdin

if __name__ == '__main__':
    run_from_command_line()
