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
#from datetime import timedelta
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
import binascii
#import re

DEFAULT_CHUNK_SIZE = 16384  # block size in HFS+; 4X the block size in ext4
DOT_THRESHOLD = 2
VERSION = (0, 9, 3)
IGNORED_FILE_SYSTEM_ERRORS = {errno.ENOENT, errno.EACCES}
FSENCODING = sys.getfilesystemencoding()
DEFAULT_HASH_FUNCTION = "SHA512"
RECENT = 3

if sys.version[0] == '2':
    str = type(u'text')
    # use `bytes` for bytestrings

def sendMail(stringToSend="", log=1, verbosity=1, subject=""):
    msg = MIMEText(stringToSend)

    FROMADDR = 'author@gmail.com'
    TOADDR  = 'recipient@gmail.com'
    msg['To'] = email.utils.formataddr(('Recipient', 'recipient@gmail.com'))
    msg['From'] = email.utils.formataddr(('Author', 'recipient@gmail.com'))
    USERNAME = 'authorUsername'
    PASSWORD = 'authorPassword'
    
    try:
        msg['Subject'] = subject
        # The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(USERNAME,PASSWORD)
        server.sendmail(FROMADDR, TOADDR, msg.as_string())
        server.quit()
    except Exception as err:
        print('Email sending error:', err)
        if (log):
            writeToLog(stringToWrite='\n\nEmail sending error: {}'.format(err))

def isValidHashingFunction(stringToValidate=""):
    if  (stringToValidate == "SHA1"
      or stringToValidate == "SHA224"
      or stringToValidate == "SHA384"
      or stringToValidate == "SHA256"
      or stringToValidate == "SHA512"
      or stringToValidate == "MD5"):
        return True
    else:
        return False

def calculateUnits(total_size = 0):
        if (total_size/1024/1024/1024/1024/1024/1024/1024/1024 >= 1):
            sizeUnits = "YB"
            total_size = total_size/1024/1024/1024/1024/1024/1024/1024/1024
        elif (total_size/1024/1024/1024/1024/1024/1024/1024 >= 1):
            sizeUnits = "ZB"
            total_size = total_size/1024/1024/1024/1024/1024/1024/1024
        elif (total_size/1024/1024/1024/1024/1024/1024 >= 1):
            sizeUnits = "EB"
            total_size = total_size/1024/1024/1024/1024/1024/1024
        elif (total_size/1024/1024/1024/1024/1024 >= 1):
            sizeUnits = "PB"
            total_size = total_size/1024/1024/1024/1024/1024
        elif (total_size/1024/1024/1024/1024 >= 1):
            sizeUnits = "TB"
            total_size = total_size/1024/1024/1024/1024
        elif (total_size/1024/1024/1024 >= 1):
            sizeUnits = "GB"
            total_size = total_size/1024/1024/1024
        elif (total_size/1024/1024 >= 1):
            sizeUnits = "MB"
            total_size = total_size/1024/1024
        elif (total_size/1024 >= 1):
            sizeUnits = "KB"
            total_size = total_size/1024
        else:
            sizeUnits = "B"
            total_size = total_size
        return sizeUnits, total_size

def CRC32_from_file(filename):
    buf = open(filename,'rb').read()
    buf = (binascii.crc32(buf) & 0xFFFFFFFF)
    return "%08X" % buf

def cleanString(stringToClean=""):
    #stringToClean=re.sub(r'[\\/*?:"<>|]',"",stringToClean)
    stringToClean = ''.join([x for x in stringToClean if ord(x) < 128])
    return stringToClean

def isDirtyString(stringToCheck=""):
    comparisonString = stringToCheck
    cleanedString = cleanString(stringToCheck)
    if (cleanedString == comparisonString):
        return False
    else:
        return True

def ts():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S%z')

def get_sqlite3_cursor(path, copy=False):
    path = path.decode(FSENCODING)
    if copy:
        if not os.path.exists(path):
            raise ValueError("Error: bitrot database at {} does not exist."
                             "".format(path))
            if (self.log):
                writeToLog(stringToWrite="\nError: bitrot database at {} does not exist."
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


def fix_existing_paths(directory, verbosity = 1, log=1, fix=True, warnings = (), fixedRenameList = (), fixedRenameCounter = 0):
#   Use os.getcwd() instead of "." since it doesn't seem to be resolved the way you want. This will be illustrated in the diagnostics function.
#   Use relative path renaming by os.chdir(root). Of course using correct absolute paths also works, but IMHO relative paths are just more elegant.
#   Pass an unambiguous string into os.walk() as others have mentioned.
#   Also note that topdown=False in os.walk() doesn't matter. Since you are not renaming directories, the directory structure will be invariant during os.walk().

    for root, dirs, files in os.walk(directory, topdown=False):
        for f in files:

            if (isDirtyString(f)):
                try:
                    # chdir before renaming
                    #os.chdir(root)
                    #fullfilename=os.path.abspath(f)
                    #os.rename(f, cleanString(f))  # relative path, more elegant
                    os.rename(os.path.join(root, f), os.path.join(root, cleanString(f)))
                    p_uni = cleanString(f)
                    writeToLog("Test")
                except Exception as ex:
                    warnings.append(f)
                    print(
                        '\rCan\'t rename: {} due to warning: `{}`'.format(
                            f,ex,
                        ),
                        file=sys.stderr,
                    )
                    if (log):
                        writeToLog(stringToWrite='\rCan\'t rename: {} due to warning: `{}`'.format(f,ex))
                    continue
                else:
                    fixedRenameList.append([])
                    fixedRenameList.append([])
                    fixedRenameList[fixedRenameCounter].append(f)
                    fixedRenameList[fixedRenameCounter].append(f)
                    fixedRenameCounter += 1

        for d in dirs:
            if (isDirtyString(d)):
                try:
                    # chdir before renaming
                    #os.chdir(root)
                    #fullfilename=os.path.abspath(d)
                    os.rename(os.path.join(root, d), os.path.join(root, cleanString(d)))
                    #os.rename(d, cleanString(d))  # relative path, more elegant
                    p_uni = cleanString(d)
                except Exception as ex:
                    warnings.append(d)
                    print(
                        '\rCan\'t rename: {} due to warning: `{}`'.format(
                            d,ex,
                        ),
                        file=sys.stderr,
                    )
                    if (log):
                        writeToLog(stringToWrite='\rCan\'t rename: {} due to warning: `{}`'.format(d,ex))
                    continue
                else:
                    fixedRenameList.append([])
                    fixedRenameList.append([])
                    fixedRenameList[fixedRenameCounter].append(d)
                    fixedRenameList[fixedRenameCounter].append(d)
                    fixedRenameCounter += 1
    return fixedRenameList, fixedRenameCounter

def list_existing_paths(directory, expected=(), ignored=(), included=(), 
                        verbosity=1, follow_links=False, log=1, fix=False, warnings = ()):
    """list_existing_paths('/dir') -> ([path1, path2, ...], total_size)

    Returns a tuple with a list with existing files in `directory` and their
    `total_size`.

    Doesn't add entries listed in `ignored`.  Doesn't add symlinks if
    `follow_links` is False (the default).  All entries present in `expected`
    must be files (can't be directories or symlinks).
    """
    paths = []
    total_size = 0
    ignoredList = []
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
                # split path /dir1/dir2/file.txt into
                # ['dir1', 'dir2', 'file.txt']
                # and match on any of these components
                # so we could use 'dir*', '*2', '*.txt', etc. to exclude anything
                exclude_this = [fnmatch(file.encode(FSENCODING), wildcard) 
                                for file in p.decode(FSENCODING).split(os.path.sep)
                                for wildcard in ignored]
                include_this = [fnmatch(file.encode(FSENCODING), wildcard) 
                                for file in p.decode(FSENCODING).split(os.path.sep)
                                for wildcard in included]                

                if not stat.S_ISREG(st.st_mode) or any(exclude_this) or any([fnmatch(p, exc) for exc in ignored]) or (included and not any([fnmatch(p, exc) for exc in included]) and not any(include_this)):
                #if not stat.S_ISREG(st.st_mode) or any([fnmatch(p, exc) for exc in ignored]):
                    ignoredList.append(p.decode(FSENCODING))
                    #if verbosity > 2:
                        #print('Ignoring file: {}'.format(p))
                        #print('Ignoring file: {}'.format(p.decode(FSENCODING)))
                        #if (log):
                            #writeToLog(stringToWrite="\nIgnoring file: {}".format(p))
                            #writeToLog(stringToWrite="\nIgnoring file: {}".format(p.decode(FSENCODING)))
                    continue
                paths.append(p)
                total_size += st.st_size
    paths.sort()
    return paths, total_size, ignoredList

class BitrotException(Exception):
    pass

class Bitrot(object):
    def __init__(
        self, verbosity=1, email = False, log = False, test=0, follow_links=False, commit_interval=300,
        chunk_size=DEFAULT_CHUNK_SIZE, include_list=[], exclude_list=[], hashing_function="", sfv="MD5", fix=False
    ):
        self.verbosity = verbosity
        self.test = test
        self.follow_links = follow_links
        self.commit_interval = commit_interval
        self.chunk_size = chunk_size
        self.include_list = include_list
        self.exclude_list = exclude_list
        self._last_reported_size = ''
        self._last_commit_ts = 0
        self.email = email
        self.log = log
        self.startTime = time.time()
        self.hashing_function = hashing_function
        self.sfv = sfv
        self.fix = fix

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
        bitrot_sfv = get_path(ext=b'sfv')
        bitrot_md5 = get_path(ext=b'md5')

        #bitrot_db = os.path.basename(get_path())
        #bitrot_sha512 = os.path.basename(get_path(ext=b'sha512'))
        #bitrot_log = os.path.basename(get_path(ext=b'log'))

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
        emails = []
        tooOldList = []
        warnings = []
        fixedRenameList = []
        fixedRenameCounter = 0
        fixedPropertiesList = []
        fixedPropertiesCounter = 0
        current_size = 0
                
        missing_paths = self.select_all_paths(cur)
        #if self.include_list:
        #    paths = [line.rstrip('\n').encode(FSENCODING)
        #        for line in self.include_list.readlines()]
        #    total_size = sum([os.path.getsize(filename) for filename in paths])
        #else:

       

        if (self.fix == True):
            fixedRenameList, fixedRenameCounter = fix_existing_paths(
            os.getcwd(),# pass an unambiguous string instead of: b'.'  
            verbosity=self.verbosity,
            log=self.log,
            fix=self.fix,
            warnings=warnings,
            fixedRenameList = fixedRenameList,
            fixedRenameCounter = fixedRenameCounter
        )


        paths, total_size, ignoredList = list_existing_paths(
            b'.', 
            expected=missing_paths, 
            ignored=[bitrot_db, bitrot_sha512,bitrot_log,bitrot_sfv,bitrot_md5] + self.exclude_list,
            included=self.include_list,
            follow_links=self.follow_links,
            verbosity=self.verbosity,
            log=self.log,
            fix=self.fix,
            warnings=warnings,

        )

        FIMErrorCounter = 0;
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
            new_atime = int(st.st_atime)
            a = datetime.datetime.now()

            if not (new_mtime):
                if (self.fix):
                    nowTime = time.mktime(a.timetuple())
                    if not (new_atime):
                        #Accessed time was also bad
                        print("doom")
                        os.utime(p, (nowTime,nowTime))
                    else:
                        os.utime(p, (new_atime,nowTime))
                    fixedPropertiesList.append([])
                    fixedPropertiesList.append([])
                    fixedPropertiesList[fixedPropertiesCounter].append(p_uni)
                    fixedPropertiesCounter += 1
                else:
                    try:
                        b = datetime.datetime.fromtimestamp(new_mtime)
                    except Exception as ex:
                        warnings.append(p)
                        print(
                            '\rWarning: `{}` has an invalid modification date. Try running with -f to fix.Received error: {}'.format(
                                p.decode(FSENCODING), ex,
                            ),
                            file=sys.stderr,
                        )
                        if (self.log):
                            writeToLog(stringToWrite='\nWarning: `{}` has an invalid modification date. Try running with -f to fix. Received error: {}'.format(p.decode(FSENCODING), ex))
            else:
                b = datetime.datetime.fromtimestamp(new_mtime)
            if (self.test >= 3):
                delta = a - b
                if (delta.days >= RECENT):
                    tooOldList.append(p_uni)
                    missing_paths.discard(p_uni)
                    total_size -= st.st_size
                continue

            current_size += st.st_size
            if self.verbosity:
                self.report_progress(current_size, total_size, p_uni)

            missing_paths.discard(p_uni)
            try:
                new_hash = hash(p, self.chunk_size,self.hashing_function,log=self.log,sfv=self.sfv)
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

            if (int(stored_mtime) != new_mtime) and not (self.test >= 2):
                updated_paths.append(p)
                cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                            'WHERE path=?',
                            (new_mtime, new_hash, ts(), p_uni))
                self.maybe_commit(conn)
                continue
            if stored_hash != new_hash:
                errors.append(p)
                emails.append([])
                emails.append([])
                emails[FIMErrorCounter].append(self.hashing_function)
                emails[FIMErrorCounter].append(p.decode(FSENCODING))
                emails[FIMErrorCounter].append(stored_hash)
                emails[FIMErrorCounter].append(new_hash)
                emails[FIMErrorCounter].append(stored_ts)

                print(
                    '\rError: {} mismatch for {}\nExpected: {}\nGot:      {}'
                    '\nLast good hash checked on {}\n'.format(
                    #p, stored_hash, new_hash, stored_ts
                    self.hashing_function,p.decode(FSENCODING), stored_hash, new_hash, stored_ts
                    ),
                    file=sys.stderr,
                )
                if (self.log):
                    writeToLog(stringToWrite=
                        '\n\nError: {} mismatch for {}\nExpected: {}\nGot:          {}'
                        '\nLast good hash checked on {}'.format(
                        #p, stored_hash, new_hash, stored_ts
                        self.hashing_function,p.decode(FSENCODING), stored_hash, new_hash, stored_ts))   
                FIMErrorCounter += 1    

        if (self.email):
            if (FIMErrorCounter >= 1):
                emailToSendString=""
                for i in range(0, FIMErrorCounter):
                    emailToSendString +="Error {} mismatch for {} \nExpected {}\nGot:          {}\n".format(emails[i][0],emails[i][1],emails[i][2],emails[i][3])
                    emailToSendString +="Last good hash checked on {}\n\n".format(emails[i][4])
                sendMail(emailToSendString,log=self.log,verbosity=self.verbosity, subject="FIM Error")
            
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
                tooOldList,
                ignoredList,
                fixedRenameList,
                fixedRenameCounter,
                fixedPropertiesList,
                fixedPropertiesCounter,
            )



        update_sha512_integrity(verbosity=self.verbosity, log=self.log)

        if self.verbosity:
            recordTimeElapsed(startTime = self.startTime, log = self.log)

        if warnings:
            if len(warnings) == 1:
                print('Warning: There was 1 warning found.')
                if (self.log):
                    writeToLog(stringToWrite='\nWarning: There was 1 warning found.')
            else:
                print('Warning: There were {} warnings found.'.format(len(warnings)))
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
        renamed_paths, missing_paths, tooOldList, ignoredList, fixedRenameList, fixedRenameCounter,
        fixedPropertiesList, fixedPropertiesCounter):

        sizeUnits , total_size = calculateUnits(total_size=total_size)
        totalFixed = fixedRenameCounter + fixedPropertiesCounter
        if (error_count == 1):
                print('\rFinished. {:.2f} {} of data read. 1 error found. '.format(total_size,sizeUnits),end="")
                if (self.log):
                    writeToLog(stringToWrite='\n\nFinished. {:.2f} {} of data read. '.format(total_size,sizeUnits))
        else:
            print('\rFinished. {:.2f} {} of data read. {} errors found. '.format(total_size, sizeUnits, error_count),end="")
            if (self.log):
                writeToLog(stringToWrite='\n\nFinished. {:.2f} MiB of data read. {} errors found. '.format(total_size, error_count, sizeUnits))

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
                    '{} renamed, {} missing, {} fixed.'.format(
                        len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths), totalFixed))
                if (self.log):
                    writeToLog(stringToWrite=
                    '\n1 entry in the database, {} new, {} updated, '
                    '{} renamed, {} missing, {} fixed'.format(
                        len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths), totalFixed))
            else:
                print(
                '{} entries in the database, {} new, {} updated, '
                '{} renamed, {} missing, {} fixed.'.format(
                    all_count, len(new_paths), len(updated_paths),
                    len(renamed_paths), len(missing_paths), totalFixed))
                if (self.log):
                    writeToLog(stringToWrite=
                    '\n{} entries in the database, {} new, {} updated, '
                    '{} renamed, {} missing, {} fixed.'.format(
                        all_count, len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths), totalFixed))

        elif self.verbosity > 1:
            if (all_count == 1):
                print('1 entry in the database.')
                if (self.log):
                    writeToLog(stringToWrite='1 entry in the database.')
            else:
                print('{} entries in the database.'.format(all_count), end=' ')
                if (self.log):
                    writeToLog(stringToWrite='\n{} entries in the database.'.format(all_count))

        if self.verbosity >= 3:
            if (ignoredList):
                if (len(ignoredList) == 1):
                    print("\n1 files excluded: ")
                    if (self.log):
                        writeToLog("\n\n1 files excluded: ")
                    for row in ignoredList:
                        print("  {}".format(row))
                        if (self.log):
                            writeToLog("  \n{}".format(row))
                else:
                    print("\n{} files excluded: ".format(len(ignoredList)))
                    if (self.log):
                        writeToLog("\n\n{} files excluded: ".format(len(ignoredList)))
                    for row in ignoredList:
                        print("  {}".format(row))
                        if (self.log):
                            writeToLog("  \n{}".format(row))

                if (tooOldList):
                    if (len(tooOldList) == 1):
                        print("\n1 non-recent files ignored: ")
                        if (self.log):
                            writeToLog("\n\n1 non-recent files ignored: ")
                        for row in tooOldList:
                            print("  {}".format(row))
                            if (self.log):
                                writeToLog("  \n{}".format(row))
                    else:
                        print("\n{} non-recent files ignored:".format(len(tooOldList)))
                        if (self.log):
                            writeToLog("\n\n{} non-recent files ignored".format(len(tooOldList)))
                        for row in tooOldList:
                            print("  {}".format(row))
                            if (self.log):
                                writeToLog("  \n{}".format(row))

        if self.verbosity >= 2:
            if new_paths:
                if (len(new_paths) == 1):
                    print('\n1 new entry:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 new entry:')
                else:
                    print('\n{} new entries:'.format(len(new_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} new entries:'.format(len(new_paths)))

                new_paths.sort()
                for path in new_paths:
                    print(' ', path.decode(FSENCODING))
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path.decode(FSENCODING)))

            if updated_paths:
                if (len(updated_paths) == 1):
                    print('\n1 entry updated:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 entry updated:')
                else:
                    print('\n{} entries updated:'.format(len(updated_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} entries updated:'.format(len(updated_paths)))

                updated_paths.sort()
                for path in updated_paths:
                    print(' ', path.decode(FSENCODING))
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path.decode(FSENCODING)))

            if renamed_paths:
                if (len(renamed_paths) == 1):
                    print('\n1 entry renamed:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 entry renamed:')
                else:
                    print('\n{} entries renamed:'.format(len(renamed_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} entries renamed:'.format(len(renamed_paths)))

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
                    print('\n1 entry missing:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 entry missing:')
                else:
                    print('\n{} entries missing:'.format(len(missing_paths)))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} entries missing:'.format(len(missing_paths)))

                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                    print(' ', path)
                    if (self.log):
                        writeToLog(stringToWrite='\n {}'.format(path))

            if fixedRenameList:
                if (len(fixedRenameList) == 1):
                    print('\n1 filename fixed:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 filename fixed:')
                else:
                    print('\n{} filenames fixed:'.format(fixedRenameCounter))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} filenames fixed:'.format(fixedRenameCounter))

                for i in range(0, fixedRenameCounter):
                    print('  renamed `{}` to `{}`'.format(fixedRenameList[i][0],fixedRenameList[i][1]))
                    if (self.log):
                        writeToLog(stringToWrite='\n  `{}` to `{}`'.format(fixedRenameList[i][0],fixedRenameList[i][1]))
           
            if fixedPropertiesList:
                if (len(fixedPropertiesList) == 1):
                    print('\n1 file property fixed:')
                    if (self.log):
                        writeToLog(stringToWrite='\n\n1 file property fixed:')
                else:
                    print('\n{} file properties fixed:'.format(fixedPropertiesCounter))
                    if (self.log):
                        writeToLog(stringToWrite='\n\n{} file properties fixed:'.format(fixedPropertiesCounter))

                for i in range(0, fixedPropertiesCounter):
                    print('  Added missing modification time to {}'.format(fixedPropertiesList[i][0]))
                    if (self.log):
                        writeToLog(stringToWrite='  Added missing modification time to {}'.format(fixedPropertiesList[i][0]))
            
                        
        if any((new_paths, updated_paths, missing_paths, renamed_paths, ignoredList, tooOldList)):
            if (self.log):
                writeToLog(stringToWrite='\n')

        if self.test and self.verbosity:
            print('\nDatabase file not updated on disk (test mode).')
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

    bitrot_db = get_path()
    if not os.path.exists(bitrot_db):
        return

    if verbosity:
        print('Checking bitrot.db integrity... ', end='')
        if (log):
            writeToLog(stringToWrite='\nChecking bitrot.db integrity... ')
        sys.stdout.flush()
    with open(sha512_path, 'rb') as f:
        old_sha512 = f.read().strip()
    
    digest = hashlib.sha512()
    with open(bitrot_db, 'rb') as f:
        digest.update(f.read())
    new_sha512 = digest.hexdigest().encode('ascii')
    if new_sha512 != old_sha512:
        if len(old_sha512) == 128:
            print(
                "\nError: SHA512 of the database file is different, bitrot.db might "
                "be corrupt.",
            )
            if (log):
                writeToLog(stringToWrite=
                "\nError: SHA512 of the database file is different, bitrot.db might "
                "be corrupt.",
            )
        else:
            print(
                "\nError: SHA512 of the database file is different, but bitrot.sha512 "
                "has a suspicious length. It might be corrupt.",
            )
            if (log):
                writeToLog(stringToWrite=
                "\nError: SHA512 of the database file is different, but bitrot.sha512 "
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

def recordTimeElapsed(startTime=0, log=1):
    elapsedTime = (time.time() - startTime)  
    if (elapsedTime > 3600):
        elapsedTime /= 3600
        if ((int)(elapsedTime) == 1):
            print('Time elapsed: 1 hour.')
            if (log):
                writeToLog(stringToWrite='\nTime elapsed: 1 hour.')
        else:
            print('Time elapsed: {:.1f} hours.'.format(elapsedTime))
            if (log):
                writeToLog(stringToWrite='\nTime elapsed: {:.1f} hours.'.format(elapsedTime))

    elif (elapsedTime > 60):
        elapsedTime /= 60
        if ((int)(elapsedTime) == 1):
            print('Time elapsed: 1 minute.')
            if (log):
                writeToLog(stringToWrite='\nTime elapsed: 1 minute.')
        else:
            print('Time elapsed: {:.0f} minutes.'.format(elapsedTime))
            if (log):
                writeToLog(stringToWrite='\nTime elapsed: {:.0f} minutes.'.format(elapsedTime))

    else:
        if ((int)(elapsedTime) == 1):
            print('Time elapsed: 1 second.')
            if (log):
                writeToLog(stringToWrite='\nTime elapsed: 1 second.')
        else:
            print('Time elapsed: {:.0f} seconds.'.format(elapsedTime))
            if (log):
                 writeToLog(stringToWrite='\nTime elapsed: {:.1f} seconds.'.format(elapsedTime))

def writeToLog(stringToWrite=""):
    log_path = get_path(ext=b'log')
    stringToWrite = cleanString(stringToWrite)
    with open(log_path, 'a') as logFile:
        logFile.write(stringToWrite)
        logFile.close()

def writeToSFV(stringToWrite="", sfv=""):
    if (sfv == "MD5"):
        sfv_path = get_path(ext=b'md5')
    elif (sfv == "SFV"):
        sfv_path = get_path(ext=b'sfv')
    with open(sfv_path, 'a') as sfvFile:
        sfvFile.write(stringToWrite)
        sfvFile.close()

def hash(path, chunk_size,hashing_function="",log=1,sfv=""):
    if   (hashing_function == "MD5"):
        digest=hashlib.md5()          
    elif (hashing_function == "SHA1"):
        digest=hashlib.sha1()
    elif (hashing_function == "SHA224"):
        digest=hashlib.sha224()
    elif (hashing_function == "SHA384"):
        digest=hashlib.sha384()
    elif (hashing_function == "SHA256"):
        digest=hashlib.sha256()
    elif (hashing_function == "SHA512"):
        digest=hashlib.sha512() 
    else:
        #You should never get here
        if (log):
            writeToLog(stringToWrite='\nInvalid hash function detected.')
        raise Exception('Invalid hash function detected.')

    with open(path, 'rb') as f:
        d = f.read(chunk_size)
        while d:
            digest.update(d)
            d = f.read(chunk_size)

    if (sfv != ""):
        strippedPathString = str(pathStripper(path,sfv))
        if (sfv == "MD5" and hashing_function.upper() == "MD5"):
            sfvDigest = digest.hexdigest()
            writeToSFV(stringToWrite="{} {}\n".format(sfvDigest,strippedPathString),sfv=sfv) 
        elif (sfv == "MD5"):
            sfvDigest = hashlib.md5()
            with open(path, 'rb') as f2:
                d2 = f2.read(chunk_size)
                while d2:
                    sfvDigest.update(d2)
                    d2 = f2.read(chunk_size)
            writeToSFV(stringToWrite="{} {}\n".format(sfvDigest.hexdigest(),strippedPathString),sfv=sfv) 
        elif (sfv == "SFV"):
            crc=CRC32_from_file(path)
            writeToSFV(stringToWrite="{} {}\n".format(strippedPathString,crc),sfv=sfv) 

    return digest.hexdigest()

def pathStripper(pathToStrip="",sfv=""):
    pathToStripString = cleanString(str(pathToStrip))
    pathToStripString = pathToStripString.replace("b'.\\\\", "")
    pathToStripString = pathToStripString.replace("\\\\", "\\")
    pathToStripString = pathToStripString[:-1]
    if (sfv == "MD5"):
        pathToStripString = "*" + pathToStripString
    return pathToStripString

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
        '-i', '--include-list', default='',
        help='only read the files listed in this file (use - for stdin)')
        # .\Directory\1.hi
    parser.add_argument(
        '-t', '--test', default=0,
        help='Level 0: normal operations.\n'
        'Level 1: just test against an existing database, don\'t update anything.\n.'
        'Level 2: Doesnt compare dates, only hashes.\n'
        'Level 3: Only compares recently modified data.\n')
    parser.add_argument(
        '-a', '--hashing-function', default='',
        help='Specifies the hashing function to use')
    parser.add_argument(
        '-x', '--exclude-list', default='',
        help="don't read the files listed in this file - wildcards are allowed")
        #Samples: 
        # *DirectoryA
        # DirectoryB*
        # DirectoryC
        # *DirectoryD*
        # *FileA
        # FileB*
        # FileC
        # .\RelativeDirectoryE\*
        # .\RelativeDirectoryF\DirectoryG\*
        # *DirectoryH\DirectoryJ\*
        # .\RelativeDirectoryK\DirectoryL\FileD
        # .\RelativeDirectoryK\DirectoryL\FileD*
        # *DirectoryM\DirectoryN\FileE.txt
        # *DirectoryO\DirectoryP\FileF*
    parser.add_argument(
        '-v', '--verbose', default=1,
        help='Level 0: Don\'t print anything besides checksum errors.\n'
        'Level 1: Normal amount of verbosity.\n'
        'Level 2: List new, updated and missing entries.\n'
        'Level 3: List new, updated and missing entries, and ignored files.\n')
    parser.add_argument(
        '-e', '--email', action='store_true',
        help='email file integirty errors')
    parser.add_argument(
        '-g', '--log', action='store_true',
        help='logs activity')
    parser.add_argument(
        '-c', '--sfv', default='',
        help='Also generates an MD5 or SFV file when given either of these as a parameter')
    parser.add_argument(
        '-f', '--fix', action='store_true',
        help='Fixes files by removing invalid characters and adding missing modification times')

    args = parser.parse_args()
    if args.sum:
        try:
            print(stable_sum())
        except RuntimeError as e:
            print(str(e).encode(FSENCODING), file=sys.stderr)
    else:
        verbosity = 1
        if args.verbose:
            try:
                verbosity = int(args.verbose)
            except Exception as err:
                print("Invalid verbosity option selected: {}. Using default level 1.".format(args.verbose))
                if (args.log):
                     writeToLog("\nInvalid test option selected: {}. Using default level 1.".format(args.verbose))
                verbosity = 1
                pass
            if (verbosity != 0 and verbosity != 1 and verbosity != 2 and verbosity != 3):
                print("Invalid verbosity option selected: {}. Using default level 1.".format(args.verbose))
                if (args.log):
                     writeToLog("\nInvalid test option selected: {}. Using default level 1.".format(args.verbose))
                verbosity = 1

        if (args.log):
            log_path = get_path(ext=b'log')
            if (verbosity):
                if os.path.exists(log_path):
                    writeToLog(stringToWrite='\n')
                    writeToLog(stringToWrite='======================================================\n')
                writeToLog(stringToWrite='Log started at ')
                writeToLog(stringToWrite=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))

        if args.include_list == '-':
            if verbosity:
                print('Using stdin for file list')
                if (args.log):
                   writeToLog(stringToWrite='\nUsing stdin for file list') 
            include_list = sys.stdin
        elif args.include_list:
            if verbosity:
                print('Opening file inclusion list at ', args.include_list)
                if (args.log):
                    writeToLog(stringToWrite='\nOpening file inclusion list at {}'.format(args.include_list))
            #include_list = open(args.include)
            include_list = [line.rstrip('\n').encode(FSENCODING) for line in open(args.include_list)]
        else:
            include_list = []
        if args.exclude_list:
            if verbosity:
                print('Opening exclude list in', args.exclude_list)
                if (args.log):
                    writeToLog(stringToWrite='\nOpening exclude list in')
                    writeToLog(stringToWrite=args.exclude_list)
            exclude_list = [line.rstrip('\n').encode(FSENCODING) for line in open(args.exclude_list)]
        else:
            exclude_list = []

        if (args.hashing_function):
            #combined = '\t'.join(hashlib.algorithms_available)
            #if (args.hashing_function in combined):

            #word_to_check = args.hashing_function
            #wordlist = hashlib.algorithms_available
            #result = any(word_to_check in word for word in wordlist)

            #algorithms_available = hashlib.algorithms_available
            #search = args.hashing_function
            #result = next((True for algorithms_available in algorithms_available if search in algorithms_available), False)
            if (isValidHashingFunction(stringToValidate=args.hashing_function.upper()) == True):
                hashing_function = args.hashing_function.upper()
                if (verbosity):
                    print('Using {} for hashing function.'.format(hashing_function))   
                    if (args.log):
                       writeToLog(stringToWrite='\nUsing {} for hashing function.'.format(hashing_function))
            else:
                if (verbosity):
                    print("Invalid hashing function specified: {}. Using default {}.".format(args.hashing_function,DEFAULT_HASH_FUNCTION))
                    if (args.log):
                        writeToLog(stringToWrite="\nInvalid hashing function specified: {}. Using default {}.".format(args.hashing_function,DEFAULT_HASH_FUNCTION))
                hashing_function = DEFAULT_HASH_FUNCTION
        else:
            hashing_function = DEFAULT_HASH_FUNCTION

        sfv_path = get_path(ext=b'sfv')
        md5_path = get_path(ext=b'md5')
        try:
            os.remove(sfv_path)
        except Exception as err:
            pass
        try:
            os.remove(md5_path)
        except Exception as err:
            pass
        if (args.sfv):
            if (args.sfv.upper() == "MD5" or args.sfv.upper() == "SFV"): 
                sfv = args.sfv.upper() 
                if (verbosity):
                    print('Will generate an {} file.'.format(sfv))   
                    if (args.log):
                       writeToLog('\nWill generate an {} file.'.format(sfv)) 
            else:
                if (verbosity):
                    print("Invalid SFV/MD5 filetype specified: {}. Will not generate any additional file.".format(args.sfv))
                    if (args.log):
                        writeToLog("\nInvalid SFV/MD5 filetype specified: {}. Will not generate any additional file.".format(args.sfv))
                sfv = ""
        else:
            sfv = ""

        test = 0
        try:
            test = int(args.test)
            if (test):
                if (verbosity):
                    if (test == 1):
                        print("Just testing against an existing database, won\'t update anything.")
                        if (args.log):
                            writeToLog("\nJust testing against an existing database, won\'t update anything.")
                    elif (test == 2):
                        print("Won\'t compare dates, only hashes")
                        if (args.log):
                            writeToLog("\nWon\'t compare dates, only hashes")
                    elif (test == 3):
                        print("Only comparing recently modified data.")
                        if (args.log):
                            writeToLog("\nOnly comparing recently modified data.")
                    else:
                        print("Invalid test option selected: {}. Using default level 0.".format(args.test))
                        if (args.log):
                             writeToLog("\nInvalid test option selected: {}. Using default level 0.".format(args.test))
                        test = 0
        except Exception as err:
            if (verbosity):
                print("Invalid test option selected: {}. Using default level 0.".format(args.test))
                if (args.log):
                     writeToLog("\nInvalid test option selected: {}. Using default level 0.".format(args.test))
            test = 0
            pass

        bt = Bitrot(
            verbosity = verbosity,
            hashing_function = hashing_function,
            test = test,
            email = args.email,
            log = args.log,
            follow_links = args.follow_links,
            commit_interval = args.commit_interval,
            chunk_size = args.chunk_size,
            include_list = include_list,
            exclude_list = exclude_list,
            sfv = sfv,
            fix = args.fix,
        )
        if args.fsencoding:
            FSENCODING = args.fsencoding

        try:
            bt.run()
        except BitrotException as bre:
            print('Error:', bre.args[1], file=sys.stderr)
            if (args.log):
                writeToLog(stringToWrite='\nError: ')
                writeToLog(stringToWrite=bre.args[1])
            sys.exit(bre.args[0])

        #if include_list:
        #    include_list.close() # should be harmless if include_list == sys.stdin

if __name__ == '__main__':
    run_from_command_line()
