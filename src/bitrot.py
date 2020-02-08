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
from datetime import timedelta
import errno
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import progressbar
import smtplib
from fnmatch import fnmatch
import email.utils
from email.mime.text import MIMEText
#import binascii
#from zlib import crc32
import zlib
import re
import unicodedata

DEFAULT_CHUNK_SIZE = 1048576 # used to be 16384 - block size in HFS+; 4X the block size in ext4
DOT_THRESHOLD = 2
VERSION = (0, 9, 5)
IGNORED_FILE_SYSTEM_ERRORS = {errno.ENOENT, errno.EACCES, errno.EINVAL}
FSENCODING = sys.getfilesystemencoding()
DEFAULT_HASH_FUNCTION = "SHA512"
SOURCE_DIR='.'
SOURCE_DIR_PATH = '.'
DESTINATION_DIR=SOURCE_DIR

if sys.version[0] == '2':
    str = type(u'text')
    # use \'bytes\' for bytestrings

def sendMail(stringToSend="", log=True, verbosity=1, subject=""):
    msg = MIMEText(stringToSend)

	FROMADDR = 'DoesntMatter'
    TOADDR  = 'REDACTED@gmail.com'
    msg['To'] = email.utils.formataddr(('Recipient', 'recipient@gmail.com'))
    msg['From'] = email.utils.formataddr(('REDACTED', 'DoesntMatter'))
    USERNAME = 'REDACTED'
    PASSWORD = 'REDACTED'

    try:
        msg['Subject'] = subject
        # The actual mail send
        server = smtplib.SMTP('smtp.mail.com:587')
        server.starttls()
        server.login(USERNAME,PASSWORD)
        server.sendmail(FROMADDR, TOADDR, msg.as_string())
        server.quit()
    except Exception as err:
        printAndOrLog('Email sending error: {}'.format(err))

def normalize_path(path):
    if FSENCODING == 'utf-8' or FSENCODING == 'UTF-8':
        return unicodedata.normalize('NFKC', str(path))
    else:
        return path

def printAndOrLog(stringToProcess,log=True):
    print(stringToProcess)
    if (log):
        writeToLog('\n')
        writeToLog(stringToProcess)

def writeToLog(stringToWrite=""):
    log_path = get_path(SOURCE_DIR_PATH,ext=b'log')
    stringToWrite = cleanString(stringToWrite)
    try:
        with open(log_path, 'a') as logFile:
            logFile.write(stringToWrite)
            logFile.close()
    except Exception as err:
        print("Could not open log: \'{}\'. Received error: {}".format(log_path, err))

def writeToSFV(stringToWrite="", sfv="",log=True):
    if (sfv == "MD5"):
        sfv_path = get_path(SOURCE_DIR_PATH,ext=b'md5')
    elif (sfv == "SFV"):
        sfv_path = get_path(SOURCE_DIR_PATH,ext=b'sfv')
    try:
        with open(sfv_path, 'a') as sfvFile:
            sfvFile.write(stringToWrite)
            sfvFile.close()
    except Exception as err:
        printAndOrLog("Could not open checksum file: \'{}\'. Received error: {}".format(sfv_path, err),log)

def hash(path, chunk_size,algorithm="",log=True,sfv=""):
#0 byte files:
# md5 d41d8cd98f00b204e9800998ecf8427e
# LM  aad3b435b51404eeaad3b435b51404ee
# NTLM    31d6cfe0d16ae931b73c59d7e0c089c0
# sha1    da39a3ee5e6b4b0d3255bfef95601890afd80709
# sha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# sha384  38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
# sha512  cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
# md5(md5())  74be16979710d4c4e7c6647856088456
# MySQL4.1+   be1bdec0aa74b4dcb079943e70528096cca985f8
# ripemd160   9c1185a5c5e9fc54612808977ee8f548b2258d31
# whirlpool   19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3
# adler32 00000001
# crc32   00000000
# crc32b  00000000
# fnv1a32 811c9dc5
# fnv1a64 cbf29ce484222325
# fnv132  811c9dc5
# fnv164  cbf29ce484222325
# gost    ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d
# gost-crypto 981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0
# haval128,3  c68f39913f901f3ddf44c707357a7d70
# haval128,4  ee6bbf4d6a46a679b3a856c88538bb98
# haval128,5  184b8482a0c050dca54b59c7f05bf5dd
# haval160,3  d353c3ae22a25401d257643836d7231a9a95f953
# haval160,4  1d33aae1be4146dbaaca0b6e70d7a11f10801525
# haval160,5  255158cfc1eed1a7be7c55ddd64d9790415b933b
# haval192,3  e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e
# haval192,4  4a8372945afa55c7dead800311272523ca19d42ea47b72da
# haval192,5  4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85
# haval224,3  c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d
# haval224,4  3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e
# haval224,5  4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e
# haval256,3  4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17
# haval256,4  c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b
# haval256,5  be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330
# joaat   00000000
# md2 8350e5a3e24c153df2275c9f80692773
# md4 31d6cfe0d16ae931b73c59d7e0c089c0
# ripemd128   cdf26213a150dc3ecb610f18f6b38b46
# ripemd256   02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d
# ripemd320   22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8
# sha224  d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
# snefru  8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881
# snefru256   8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881
# tiger128,3  3293ac630c13f0245f92bbb1766e1616
# tiger128,4  24cc78a7f6ff3546e7984e59695ca13d
# tiger160,3  3293ac630c13f0245f92bbb1766e16167a4e5849
# tiger160,4  24cc78a7f6ff3546e7984e59695ca13d804e0b68
# tiger192,3  3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3
# tiger192,4  24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194
    if (algorithm == "MD5"):
        if(os.stat(path).st_size) == 0:
            return "d41d8cd98f00b204e9800998ecf8427e"
        else:
            digest=hashlib.md5()          
    elif (algorithm == "SHA1"):
        if(os.stat(path).st_size) == 0:
            return "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        else:
            digest=hashlib.sha1()
    elif (algorithm == "SHA224"):
        if(os.stat(path).st_size) == 0:
            return "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        else:
            digest=hashlib.sha224()
    elif (algorithm == "SHA384"):
        if(os.stat(path).st_size) == 0:
            return "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        else:
            digest=hashlib.sha384()
    elif (algorithm == "SHA256"):
        if(os.stat(path).st_size) == 0:
            return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        else:
            digest=hashlib.sha256()
    elif (algorithm == "SHA512"):
        if(os.stat(path).st_size) == 0:
            return "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        else:
            digest=hashlib.sha512() 
    else:
        #You should never get here
        printAndOrLog('Invalid hash function detected.',log)
        raise Exception('Invalid hash function detected.')
    try:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                d = f.read(chunk_size)
                while d:
                    digest.update(d)
                    d = f.read(chunk_size)
                f.close
    except Exception as err:
        printAndOrLog("Could not open file: \'{}\'. Received error: {}".format(path, err),log)

    if (sfv != ""):
        if (sfv == "MD5" and algorithm.upper() == "MD5"):
            sfvDigest = digest.hexdigest()
            writeToSFV(stringToWrite="{} {}\n".format(sfvDigest,"*"+normalize_path(path)),sfv=sfv,log=log) 
        elif (sfv == "MD5"):
            sfvDigest = hashlib.md5()
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f2:
                        d2 = f2.read(chunk_size)
                        while d2:
                            sfvDigest.update(d2)
                            d2 = f2.read(chunk_size)
                        f2.close
            except Exception as err:
                printAndOrLog("Could not open file: \'{}\'. Received error: {}".format(path, err),log)
            writeToSFV(stringToWrite="{} {}\n".format(sfvDigest.hexdigest(),"*"+normalize_path(path)),sfv=sfv,log=log) 
        elif (sfv == "SFV"):
            try:
                if os.path.exists(path):
                    with open(path, 'rb') as f2:
                        d2 = f2.read(chunk_size)
                        crcvalue = 0
                        while d2:
                            #zlib is faster
                            #import timeit
                            #print("b:", timeit.timeit("binascii.crc32(data)", setup="import binascii, zlib; data=b'X'*4096", number=100000))
                            #print("z:", timeit.timeit("zlib.crc32(data)",     setup="import binascii, zlib; data=b'X'*4096", number=100000))
                            #Result:
                            #b: 1.0176826480001182
                            #z: 0.4006126120002591
                            
                            crcvalue = (zlib.crc32(d2, crcvalue) & 0xFFFFFFFF)
                            #crcvalue = (binascii.crc32(d2,crcvalue) & 0xFFFFFFFF)
                            d2 = f2.read(chunk_size)
                        f2.close()
            except Exception as err:
                printAndOrLog("Could not open SFV file: \'{}\'. Received error: {}".format(path, err),log)
            writeToSFV(stringToWrite="{} {}\n".format(path, "%08X" % crcvalue),sfv=sfv,log=log) 
    return digest.hexdigest()

def is_int(val):
    if type(val) == int:
        return True
    else:
        if val.is_integer():
            return True
        else:
            return False

def isValidHashingFunction(stringToValidate=""):
    hashFunctions = ["SHA1", "SHA224", "SHA384", "SHA256", "MD5"]
    if stringToValidate in hashFunctions:
        return True
    else:
        return False
    
#    if  (stringToValidate.upper() == "SHA1"
#      or stringToValidate.upper() == "SHA224"
#      or stringToValidate.upper() == "SHA384"
#      or stringToValidate.upper() == "SHA256"
#      or stringToValidate.upper() == "SHA512"
#      or stringToValidate.upper() == "MD5"):
#        return True
#    else:
#        return False


def calculateUnits(total_size = 0):
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        size = 0
    
        #  Divides total size until it is less than 1024
        while total_size >= 1024:
            total_size = total_size/1024
            size = size + 1  # Size is used as the index for Units
        
        sizeUnits = units[size]
            
#        if (total_size/1024/1024/1024/1024/1024/1024/1024/1024 >= 1):
#            sizeUnits = "YB"
#            total_size = total_size/1024/1024/1024/1024/1024/1024/1024/1024
#        elif (total_size/1024/1024/1024/1024/1024/1024/1024 >= 1):
#            sizeUnits = "ZB"
#            total_size = total_size/1024/1024/1024/1024/1024/1024/1024
#        elif (total_size/1024/1024/1024/1024/1024/1024 >= 1):
#            sizeUnits = "EB"
#            total_size = total_size/1024/1024/1024/1024/1024/1024
#        elif (total_size/1024/1024/1024/1024/1024 >= 1):
#            sizeUnits = "PB"
#            total_size = total_size/1024/1024/1024/1024/1024
#        elif (total_size/1024/1024/1024/1024 >= 1):
#            sizeUnits = "TB"
#            total_size = total_size/1024/1024/1024/1024
#        elif (total_size/1024/1024/1024 >= 1):
#            sizeUnits = "GB"
#            total_size = total_size/1024/1024/1024
#        elif (total_size/1024/1024 >= 1):
#            sizeUnits = "MB"
#            total_size = total_size/1024/1024
#        elif (total_size/1024 >= 1):
#            sizeUnits = "KB"
#            total_size = total_size/1024
#        else:
#            sizeUnits = "B"
#            total_size = total_size
        return sizeUnits, total_size



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
            raise ValueError("Error: bitrot database at {} does not exist.".format(path))
            printAndOrLog("Error: bitrot database at {} does not exist.".format(path),log)
        db_copy = tempfile.NamedTemporaryFile(prefix='bitrot_', suffix='.db',
                                              delete=False)
        try:
            if os.path.exists(path):
                with open(path, 'rb') as db_orig:
                    try:
                        shutil.copyfileobj(db_orig, db_copy)
                    finally:
                        db_copy.close()
                        db_orig.close()
        # except IOError as e:
        #     if e.errno == errno.EACCES:
        except Exception as e:
            printAndOrLog("Could not open database file: \'{}\'. Received error: {}".format(bitrot_db, e),log)
            raise Exception("Could not open database file: \'{}\'. Received error: {}".format(bitrot_db, e))


        path = db_copy.name
        atexit.register(os.unlink, path)
    try:
        conn = sqlite3.connect(path)
    except Exception as err:
           printAndOrLog("Could not connect to database: \'{}\'. Received error: {}".format(path, err),log)
           raise Exception("Could not connect to database: \'{}\'. Received error: {}".format(path, err))
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


def fix_existing_paths(directory=SOURCE_DIR, verbosity = 1, log=True, fix=5, warnings = (), fixedRenameList = (), fixedRenameCounter = 0):
#   Use os.getcwd() instead of "." since it doesn't seem to be resolved the way you want. This will be illustrated in the diagnostics function.
#   Use relative path renaming by os.chdir(root). Of course using correct absolute paths also works, but IMHO relative paths are just more elegant.
#   Pass an unambiguous string into os.walk() as others have mentioned.
#   Also note that topdown=False in os.walk() doesn't matter. Since you are not renaming directories, the directory structure will be invariant during os.walk().
    progressCounter=0
    print("Scanning file and directory names to fix... Please wait...")
    if verbosity:
            bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
    for root, dirs, files in os.walk(directory, topdown=False):
        for f in files:
            if (isDirtyString(f)):
                if (fix == 3) or (fix == 5):
                    warnings.append(f)
                    printAndOrLog('Warning: Invalid character detected in filename\'{}\''.format(os.path.join(root, f)),log)
                try:
                    # chdir before renaming
                    #os.chdir(root)
                    #fullfilename=os.path.abspath(f)
                    #os.rename(f, cleanString(f))  # relative path, more elegant
                    pBackup = f
                    if (fix == 4) or (fix == 6):
                        os.rename(os.path.join(root, f), os.path.join(root, cleanString(f)))
                    p = cleanString(f)

                except Exception as ex:
                    warnings.append(f)
                    printAndOrLog('Can\'t rename: {} due to warning: \'{}\''.format(os.path.join(root, f),ex),log)
                    continue
                else:
                    fixedRenameList.append([])
                    fixedRenameList.append([])
                    fixedRenameList[fixedRenameCounter].append(os.path.join(root, pBackup))
                    fixedRenameList[fixedRenameCounter].append(os.path.join(root, p))
                    fixedRenameCounter += 1
                    if verbosity:
                        progressCounter+=1
                        bar.update(progressCounter)
            
        for d in dirs:
            if (isDirtyString(d)):
                try:
                    # chdir before renaming
                    #os.chdir(root)
                    #fullfilename=os.path.abspath(d)
                    pBackup = d
                    if (fix == 4) or (fix == 6):
                        os.rename(os.path.join(root, d), os.path.join(root, cleanString(d)))
                    #os.rename(d, cleanString(d))  # relative path, more elegant
                    pi = cleanString(d)

                except Exception as ex:
                    warnings.append(d)
                    printAndOrLog('Can\'t rename: {} due to warning: \'{}\''.format(os.path.join(root, d),ex),log)
                    continue
                else:
                    fixedRenameList.append([])
                    fixedRenameList.append([])
                    fixedRenameList[fixedRenameCounter].append(os.path.join(root, pBackup))
                    fixedRenameList[fixedRenameCounter].append(os.path.join(root, pi))
                    fixedRenameCounter += 1
                    if verbosity:
                        progressCounter+=1
                        bar.update(progressCounter)
    if verbosity:
        bar.finish()
    return fixedRenameList, fixedRenameCounter

def list_existing_paths(directory=SOURCE_DIR, expected=(), ignored=(), included=(), 
                        verbosity=1, follow_links=False, log=True, fix=0, normalize=False, warnings = ()):
    """list_existing_paths('/dir') -> ([path1, path2, ...], total_size)

    Returns a tuple with a list with existing files in \'directory\' and their
    \'total_size\'.

    Doesn't add entries listed in \'ignored\'.  Doesn't add symlinks if
    \'follow_links\' is False (the default).  All entries present in \'expected\'
    must be files (can't be directories or symlinks).
    """

    paths = set()
    total_size = 0
    ignoredList = []
    progressCounter=0
    if verbosity:
        print("Mapping all files... Please wait...")
        bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
    for path, _, files in os.walk("."):
        for f in files:
            p = os.path.join(path, f)
            try:
                #p_uni = p.decode(FSENCODING)
                p_uni = p.encode(FSENCODING)

            except UnicodeDecodeError:
                binary_stderr = getattr(sys.stderr, 'buffer', sys.stderr)
                warnings.append(p)
                binary_stderr.write(b"\rWarning: cannot decode file name: ")
                binary_stderr.write(p)
                binary_stderr.write(b"\n")
                printAndOrLog("Warning: cannot decode file name: {}".format(p),log)
                continue
            try:
                if follow_links or p_uni in expected:
                    st = os.stat(p)
                else:
                    st = os.lstat(p)
            except OSError as ex:
                if ex.errno not in IGNORED_FILE_SYSTEM_ERRORS:
                    raise ("Unhandled file system error: []}".format(ex.errno))
            else:
                # split path /dir1/dir2/file.txt into
                # ['dir1', 'dir2', 'file.txt']
                # and match on any of these components
                # so we could use 'dir*', '*2', '*.txt', etc. to exclude anything
                exclude_this = [fnmatch(file.encode(FSENCODING), wildcard) 
                                for file in p.split(os.path.sep)
                                for wildcard in ignored]
                include_this = [fnmatch(file.encode(FSENCODING), wildcard) 
                                for file in p.split(os.path.sep)
                                for wildcard in included]              
                if not stat.S_ISREG(st.st_mode) or any(exclude_this) or any([fnmatch(p.encode(FSENCODING), exc) for exc in ignored]) or (included and not any([fnmatch(p.encode(FSENCODING), exc) for exc in included]) and not any(include_this)):
                #if not stat.S_ISREG(st.st_mode) or any([fnmatch(p, exc) for exc in ignored]):
                    ignoredList.append(p)
                    #if verbosity > 2:
                        #print('Ignoring file: {}'.format(p))
                        #print('Ignoring file: {}'.format(p.decode(FSENCODING)))
                        #if (log):
                            #writeToLog("\nIgnoring file: {}".format(p))
                            #writeToLog("\nIgnoring file: {}".format(p.decode(FSENCODING)))
                    continue
                else:
                    if (normalize):
                        oldMatch = ""
                        for filePath in paths:
                            if normalize_path(p) == normalize_path(filePath):
                                oldMatch = filePath
                                break
                        if oldMatch != "":
                            oldFile = os.stat(oldMatch)
                            new_mtime = int(st.st_mtime)
                            old_mtime = int(oldFile.st_mtime)
                            new_atime = int(st.st_atime)
                            old_atime = int(oldFile.st_atime)
                            now_date = datetime.datetime.now()
                            if not new_mtime or not new_atime:
                                nowTime = time.mktime(now_date.timetuple())
                            if not old_mtime or not old_atime:
                                nowTime = time.mktime(now_date.timetuple())
                            if not new_mtime and not new_atime:
                                new_mtime = int(nowTime)
                                new_atime = int(nowTime)
                            elif not (new_mtime):
                                new_mtime = int(nowTime)
                            elif not (new_atime):
                                new_atime = int(nowTime)
                            if not old_mtime and not old_atime:
                                old_mtime = int(nowTime)
                                old_atime = int(nowTime)
                            elif not (old_mtime):
                                old_mtime = int(nowTime)
                            elif not (old_atime):
                                old_atime = int(nowTime)

                            new_mtime_date = datetime.datetime.fromtimestamp(new_mtime)
                            new_atime_date = datetime.datetime.fromtimestamp(new_atime)
                            old_mtime_date = datetime.datetime.fromtimestamp(old_mtime)
                            old_atime_date = datetime.datetime.fromtimestamp(old_atime)

                            delta_new_mtime_date = now_date - new_mtime_date
                            delta_new_atime_date = now_date - new_atime_date

                            delta_old_mtime_date = now_date - old_mtime_date
                            delta_old_atime_date = now_date - old_atime_date

                            if delta_new_mtime_date < delta_old_mtime_date:
                                paths.add(p)
                                paths.discard(filePath)
                                if verbosity:
                                    progressCounter+=1
                                    bar.update(progressCounter)
                                total_size += st.st_size
                            elif delta_new_atime_date < delta_old_atime_date:
                                paths.add(p)
                                paths.discard(filePath)
                                if verbosity:
                                    progressCounter+=1
                                    bar.update(progressCounter)
                                total_size += st.st_size
                            else:
                                pass
                        else:
                            paths.add(p)
                            if verbosity:
                                progressCounter+=1
                                bar.update(progressCounter)
                            total_size += st.st_size
                    else:
                        paths.add(p)
                        if verbosity:
                            progressCounter+=1
                            bar.update(progressCounter)
                        total_size += st.st_size
    if verbosity:
        bar.finish()
    return paths, total_size, ignoredList


class CustomETA(progressbar.widgets.ETA):

    def __call__(self, progress, data):
        # Run `ETA.__call__` to update `data`. This adds the `eta_seconds`
        formatted = progressbar.widgets.ETA.__call__(self, progress, data)

        # ETA might not be available, if the maximum length is not available
        # for example
        if data.get('eta'):
            # By using divmod we can split the timedelta to hours and the
            # remaining timedelta
            hours, delta = divmod(
                timedelta(seconds=int(data['eta_seconds'])),
                timedelta(hours=1),
            )
            data['eta'] = ' {hours}{delta_truncated}'.format(
                hours=hours,
                # Strip the 0 hours from the timedelta
                delta_truncated=str(delta).lstrip('0'),
            )
            return progressbar.widgets.Timer.__call__(self, progress, data, format=self.format)
        else:
            return formatted


class BitrotException(Exception):
    pass

class Bitrot(object):
    def __init__(
        self, verbosity=1, email = False, log = False, test=0, recent = 0, follow_links=False, commit_interval=300,
        chunk_size=DEFAULT_CHUNK_SIZE, include_list=[], exclude_list=[], algorithm="", sfv="MD5", fix=0, normalize=False
    ):
        self.verbosity = verbosity
        self.test = test
        self.recent = recent
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
        self.algorithm = algorithm
        self.sfv = sfv
        self.fix = fix
        self.normalize=normalize

    def maybe_commit(self, conn):
        if time.time() < self._last_commit_ts + self.commit_interval:
            # no time for commit yet!
            return

        conn.commit()
        self._last_commit_ts = time.time()

    def run(self):
        check_sha512_integrity(verbosity=self.verbosity, log=self.log)

        bitrot_sha512 = get_path(SOURCE_DIR_PATH,ext=b'sha512')
        bitrot_log = get_path(SOURCE_DIR_PATH,ext=b'log')
        bitrot_db = get_path(SOURCE_DIR_PATH,b'db')
        bitrot_sfv = get_path(SOURCE_DIR_PATH,ext=b'sfv')
        bitrot_md5 = get_path(SOURCE_DIR_PATH,ext=b'md5')
        progressCounter=0


        #bitrot_db = os.path.basename(get_path())
        #bitrot_sha512 = os.path.basename(get_path(ext=b'sha512'))
        #bitrot_log = os.path.basename(get_path(ext=b'log'))

        try:
            conn = get_sqlite3_cursor(bitrot_db, copy=self.test)
        except ValueError:
            raise BitrotException(2,'No database exists so cannot test. Run the tool once first.')
            if (log):
                printAndOrLog("No database exists so cannot test. Run the tool once first.",self.log)

        cur = conn.cursor()
        new_paths = []
        existing_paths = []
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
        hashes = self.select_all_hashes(cur)

        if (SOURCE_DIR != DESTINATION_DIR):
            os.chdir(DESTINATION_DIR)

        if (self.fix >= 1):
            fixedRenameList, fixedRenameCounter = fix_existing_paths(
            #os.getcwd(),# pass an unambiguous string instead of: b'.'  
            SOURCE_DIR,
            verbosity=self.verbosity,
            log=self.log,
            fix=self.fix,
            warnings=warnings,
            fixedRenameList = fixedRenameList,
            fixedRenameCounter = fixedRenameCounter
        )

        paths, total_size, ignoredList = list_existing_paths(
            SOURCE_DIR,
            expected=missing_paths, 
            ignored=[bitrot_db, bitrot_sha512,bitrot_log,bitrot_sfv,bitrot_md5] + self.exclude_list,
            included=self.include_list,
            follow_links=self.follow_links,
            verbosity=self.verbosity,
            log=self.log,
            fix=self.fix,
            normalize=self.normalize,
            warnings=warnings,

        )

        FIMErrorCounter = 0;
        if self.verbosity:
            print("Hashing all files... Please wait...")
            format_custom_text = progressbar.FormatCustomText(
                '%(f)s',
                dict(
                    f='',
                )
            )
            bar = progressbar.ProgressBar(max_value=len(paths),widgets=[format_custom_text,
                CustomETA(format_not_started='%(value)2d/%(max_value)d|%(percentage)3d%%|Elapsed:%(elapsed)8s', format_finished='%(value)01d/%(max_value)d|%(percentage)3d%%|Elapsed:%(elapsed)8s', format='%(value)01d/%(max_value)d|%(percentage)3d%%|Elapsed:%(elapsed)8s|ETA:%(eta)8s', format_zero='%(value)01d/%(max_value)d|%(percentage)3d%%|Elapsed:%(elapsed)8s', format_NA='%(value)01d/%(max_value)d|%(percentage)3d%%|Elapsed:%(elapsed)8s'),
                progressbar.Bar(marker='#', left='|', right='|', fill=' ', fill_left=True),               
                ])
          
        for p in sorted(paths):
            p_uni = p.encode(FSENCODING)

            try:
                st = os.stat(p)
            except OSError as ex:
                if ex.errno in IGNORED_FILE_SYSTEM_ERRORS:
                    # The file disappeared between listing existing paths and
                    # this run or is (temporarily?) locked with different
                    # permissions. We'll just skip it for now.
                    warnings.append(p)
                    #writeToLog('\nWarning: \'{}\' is currently unavailable for reading: {}'.format(p_uni, ex))
                    printAndOrLog('Warning: \'{}\' is currently unavailable for reading: {}'.format(p, ex),self.log)
                    continue

                raise ("Unhandled file system error: []}".format(ex.errno))
            if self.verbosity:
                progressCounter+=1
                bar.update(progressCounter) 
            new_mtime = int(st.st_mtime)
            new_atime = int(st.st_atime)
            new_mtime_orig = new_mtime
            new_atime_orig = new_atime
            a = datetime.datetime.now()
            
            #Used for testing bad file timestamps
            #os.utime(p, (0,0))
            #continue
            
            if not new_mtime or not new_atime:
                nowTime = time.mktime(a.timetuple())
            if not new_mtime and not new_atime:
                new_mtime = int(nowTime)
                new_atime = int(nowTime)
                if (self.fix  == 1) or (self.fix  == 5):
                    warnings.append(p)
                    printAndOrLog('Warning: \'{}\' has an invalid access and modification date. Try running with -f to fix.'.format(p),self.log)
            elif not (new_mtime):
                new_mtime = int(nowTime)
                if (self.fix  == 1) or (self.fix  == 5):
                    warnings.append(p)
                    printAndOrLog('Warning: \'{}\' has an invalid modification date. Try running with -f to fix.'.format(p),self.log)
            elif not (new_atime):
                new_atime = int(nowTime)
                if (self.fix  == 1) or (self.fix  == 5):
                    warnings.append(p)
                    printAndOrLog('Warning: \'{}\' has an invalid access date. Try running with -f to fix.'.format(p),self.log)

            b = datetime.datetime.fromtimestamp(new_mtime)
            c = datetime.datetime.fromtimestamp(new_atime)

            if (self.recent >= 1):
                delta = a - b
                delta2= a - c
                if (delta.days > self.recent or delta2.days > self.recent):
                    tooOldList.append(p)
                    missing_paths.discard(normalize_path(p_uni.decode(FSENCODING)))
                    total_size -= st.st_size
                    continue

            fixPropertyFailed = False

            if not new_mtime_orig and not new_atime_orig:
                if (self.fix  == 2) or (self.fix  == 6):
                    try:
                        os.utime(p, (nowTime,nowTime))
                    except Exception as ex:
                        warnings.append(f)
                        fixPropertyFailed = True
                        printAndOrLog('Can\'t rename: {} due to warning: \'{}\''.format(p,ex),self.log)
            elif not (new_mtime_orig):
                if (self.fix  == 2) or (self.fix  == 6):
                    try:
                        os.utime(p, (new_atime,nowTime))
                    except Exception as ex:
                        warnings.append(p)
                        fixPropertyFailed = True
                        printAndOrLog('Can\'t rename: {} due to warning: \'{}\''.format(p,ex),self.log)
            elif not (new_atime_orig):
                if (self.fix  == 2) or (self.fix  == 6):
                    try:
                        os.utime(p, (nowTime,new_mtime))
                    except Exception as ex:
                        warnings.append(f)
                        fixPropertyFailed = True
                        printAndOrLog('Can\'t rename: {} due to warning: \'{}\''.format(p,ex),self.log)

            if not new_mtime_orig or not new_atime_orig:
                if (fixPropertyFailed == False):
                    if (self.fix  == 1) or (self.fix  == 5) or (self.fix  == 2) or (self.fix  == 6):
                            fixedPropertiesList.append([])
                            fixedPropertiesList.append([])
                            fixedPropertiesList[fixedPropertiesCounter].append(p)
                            fixedPropertiesCounter += 1

            current_size += st.st_size
            if self.verbosity:
                format_custom_text.update_mapping(f=self.progressFormat(progressCounter,len(paths),p_uni))              

            missing_paths.discard(normalize_path(p_uni.decode(FSENCODING)))

            try:
                new_hash = hash(p, self.chunk_size,self.algorithm,log=self.log,sfv=self.sfv)
            except (IOError, OSError) as e:
                warnings.append(p)
                printAndOrLog('Warning: Cannot compute hash of {} [{}]'.format(
                            #p, errno.errorcode[e.args[0]]))
                            p.encode(FSENCODING), errno.errorcode[e.args[0]]),self.log)
                continue
            cur.execute('SELECT mtime, hash, timestamp FROM bitrot WHERE '
                        'path=?', (normalize_path(p_uni.decode(FSENCODING)),))
            row = cur.fetchone()

            if not row:
                stored_path = self.handle_unknown_path(
                    cur, normalize_path(p_uni.decode(FSENCODING)), new_mtime, new_hash, paths, hashes
                )
                self.maybe_commit(conn)

                if normalize_path(p_uni.decode(FSENCODING)) == normalize_path(stored_path):
                    new_paths.append(p)
                else:
                    renamed_paths.append((stored_path, p))
                    missing_paths.discard(stored_path)
                continue
            else:
                existing_paths.append(p)

            stored_mtime, stored_hash, stored_ts = row
            if (int(stored_mtime) != new_mtime) and not (self.test == 2):
                updated_paths.append(p)
                cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                            'WHERE path=?',
                            (new_mtime, new_hash, ts(), normalize_path(p_uni.decode(FSENCODING))))
                self.maybe_commit(conn)
                continue

            if stored_hash != new_hash:
                errors.append(p)
                emails.append([])
                emails.append([])
                emails[FIMErrorCounter].append(self.algorithm)
                emails[FIMErrorCounter].append(p.encode(FSENCODING))
                emails[FIMErrorCounter].append(stored_hash)
                emails[FIMErrorCounter].append(new_hash)
                emails[FIMErrorCounter].append(stored_ts)
                printAndOrLog(
                        '\n\nError: {} mismatch for {}\nExpected: {}\nGot:      {}'
                        '\nLast good hash checked on {}'.format(
                        #p, stored_hash, new_hash, stored_ts
                        self.algorithm,p.encode(FSENCODING), stored_hash, new_hash, stored_ts),self.log)   
                FIMErrorCounter += 1 
        if self.verbosity:    
            format_custom_text.update_mapping(f="")
            bar.finish()

        if (self.email):
            if (FIMErrorCounter >= 1):
                emailToSendString=""
                for i in range(0, FIMErrorCounter):
                    emailToSendString +="Error: {} mismatch for {} \nExpected: {}\nGot:      {}\n".format(emails[i][0],emails[i][1],emails[i][2],emails[i][3])
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
                paths,
                existing_paths,
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
                self.log
            )

        if not self.test:
            cur.execute('vacuum')


        update_sha512_integrity(verbosity=self.verbosity, log=self.log)

        if self.verbosity:
            recordTimeElapsed(startTime = self.startTime, log = self.log)

        # if warnings:
        #     if len(warnings) == 1:
        #         printAndOrLog('Warning: There was 1 warning found.',self.log)
        #     else:
        #         printAndOrLog('Warning: There were {} warnings found.'.format(len(warnings)),self.log)

        # if errors:
        #     if len(errors) == 1:
        #         raise BitrotException(1, 'There was 1 error found.')
        #     else:
        #         raise BitrotException(1, 'There were {} errors found.'.format(len(errors)), errors)

    def select_all_paths(self, cur):
        result = set()
        cur.execute('SELECT path FROM bitrot')
        row = cur.fetchone()
        while row:
            result.add(row[0])
            row = cur.fetchone()
        return result

    def select_all_hashes(self, cur):
        result = {}
        cur.execute('SELECT hash, path FROM bitrot')
        row = cur.fetchone()
        while row: 
            rhash, rpath = row
            result.setdefault(rhash, set()).add(rpath)
            row = cur.fetchone()
        return result

    def progressFormat(self, currentPosition,totalPosition,current_path): 
        current_path = cleanString(stringToClean=current_path.decode(FSENCODING))
        terminal_size = shutil.get_terminal_size()
        cols = terminal_size.columns
        max_path_size =  int(shutil.get_terminal_size().columns/2)
        if len(current_path) > max_path_size:
            # show first half and last half, separated by ellipsis
            # e.g. averylongpathnameaveryl...ameaverylongpathname
            half_mps = (max_path_size - 3) // 2
            current_path = current_path[:half_mps] + '...' + current_path[-half_mps:]
        else:
            # pad out with spaces, otherwise previous filenames won't be erased
            current_path += ' ' * (max_path_size - len(current_path))
        current_path = current_path + '|'
        return current_path

    def report_done(
        self, total_size, all_count, error_count, warning_count, paths, existing_paths, new_paths, updated_paths,
        renamed_paths, missing_paths, tooOldList, ignoredList, fixedRenameList, fixedRenameCounter,
        fixedPropertiesList, fixedPropertiesCounter, log):

        sizeUnits , total_size = calculateUnits(total_size=total_size)
        totalFixed = fixedRenameCounter + fixedPropertiesCounter

        printAndOrLog('Finished. {:.2f} {} of data read.'.format(total_size,sizeUnits),log)
        
        if (error_count == 1):
            printAndOrLog('1 error found.',log)
        else:
            printAndOrLog('{} errors found.'.format(error_count),log)

        if (warning_count == 1):
            printAndOrLog('1 warning found.',log)
        else:
           printAndOrLog('{} warnings found.'.format(warning_count),log)

        if self.verbosity >= 1:
            if (all_count == 1):
                printAndOrLog(
                    '\n1 entry in the database, {} existing, {} new, {} updated, '
                    '{} renamed, {} missing, {} skipped, {} fixed'.format(
                        len(existing_paths), len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths), len(tooOldList), totalFixed),log)
            else:
                printAndOrLog(
                    '\n{} entries in the database, {} existing, {} new, {} updated, '
                    '{} renamed, {} missing, {} skipped, {} fixed.'.format(
                        all_count, len(existing_paths), len(new_paths), len(updated_paths),
                        len(renamed_paths), len(missing_paths), len(tooOldList), totalFixed),log)

        if self.verbosity >= 5:
            if (existing_paths):
                if (len(existing_paths) == 1):
                    printAndOrLog('1 existing entry:',log)
                else:
                    printAndOrLog('{} existing entries:'.format(len(paths)),log)
                existing_paths.sort()
                for path in existing_paths:
                    printAndOrLog('{}'.format(path),log)

        if self.verbosity >= 4:
            if (ignoredList):
                if (len(ignoredList) == 1):
                    printAndOrLog("1 files excluded: ",log)
                    for row in ignoredList:
                        printAndOrLog("{}".format(row),log)
                else:
                    printAndOrLog("{} files excluded: ".format(len(ignoredList)),log)
                    for row in ignoredList:
                        printAndOrLog("{}".format(row),log)

                if (tooOldList):
                    if (len(tooOldList) == 1):
                        printAndOrLog("1 non-recent files ignored: ",log)
                        for row in tooOldList:
                            printAndOrLog("{}".format(row),log)
                    else:
                        printAndOrLog("{} non-recent files ignored".format(len(tooOldList)),log)
                        for row in tooOldList:
                            printAndOrLog("{}".format(row),log)

        if self.verbosity >= 3:
            if new_paths:
                if (len(new_paths) == 1):
                    printAndOrLog('1 new entry:',log)
                else:
                    printAndOrLog('{} new entries:'.format(len(new_paths)),log)

                new_paths.sort()
                for path in new_paths:
                    printAndOrLog('{}'.format(path),log)

            if updated_paths:
                if (len(updated_paths) == 1):
                   printAndOrLog('1 entry updated:',log)
                else:
                    printAndOrLog('{} entries updated:'.format(len(updated_paths)),log)

                updated_paths.sort()
                for path in updated_paths:
                    printAndOrLog(' {}'.format(path),log)

            if renamed_paths:
                if (len(renamed_paths) == 1):
                    printAndOrLog('1 entry renamed:',log)
                else:
                    printAndOrLog('{} entries renamed:'.format(len(renamed_paths)),log)

                renamed_paths.sort()
                for path in renamed_paths:
                    printAndOrLog(' from {} to {}'.format(path[0],path[1]),log)
                    
        if self.verbosity >= 2:
            if missing_paths:
                if (len(missing_paths) == 1):
                    printAndOrLog('1 entry missing:',log)
                else:
                    printAndOrLog('{} entries missing:'.format(len(missing_paths)),log)

                missing_paths = sorted(missing_paths)
                for path in missing_paths:
                   printAndOrLog('{}'.format(path,log))

        if fixedRenameList:
            if ((self.fix == 4) or (self.fix == 6)) and (self.verbosity >= 1):
                if (len(fixedRenameList) == 1):
                    printAndOrLog('1 filename fixed:',log)
                else:
                    printAndOrLog('{} filenames fixed:'.format(fixedRenameCounter),log)

                for i in range(0, fixedRenameCounter):
                    printAndOrLog('  \'{}\' to \'{}\''.format(fixedRenameList[i][0],fixedRenameList[i][1]),log)
       
        if fixedPropertiesList:
            if ((self.fix == 2) or (self.fix == 6)) and (self.verbosity >= 1):
                if (len(fixedPropertiesList) == 1):
                    printAndOrLog('1 file property fixed:',log)
                else:
                    printAndOrLog('{} file properties fixed:'.format(fixedPropertiesCounter),log)

                for i in range(0, fixedPropertiesCounter):
                    printAndOrLog('  Added missing access or modification timestamp to {}'.format(fixedPropertiesList[i][0]),log)
            
                        
        #if any((new_paths, updated_paths, missing_paths, renamed_paths, ignoredList, tooOldList)):
        #    if (self.log):
        #        writeToLog('\n')

        if self.test and self.verbosity:
            printAndOrLog('Database file not updated on disk (test mode).',log)

    def handle_unknown_path(self, cur, new_path, new_mtime, new_hash, paths, hashes):
            """Either add a new entry to the database or update the existing entry
            on rename.
            Returns `new_path` if the entry was indeed new or the `stored_path` (e.g.
            outdated path) if there was a rename.
            """
            try: # if the path isn't in the database
                found = [path for path in hashes[new_hash] if path not in paths]
                renamed = found.pop()
                # update the path in the database
                cur.execute(
                    'UPDATE bitrot SET mtime=?, path=?, timestamp=? WHERE path=?',
                    (new_mtime, normalize_path(new_path), ts(), normalize_path(renamed)),
                )

                return renamed
            
            # From hashes[new_hash] or found.pop() 
            except (KeyError,IndexError):
                cur.execute(
                    'INSERT INTO bitrot VALUES (?, ?, ?, ?)',
                    (normalize_path(new_path), new_mtime, new_hash, ts()),
                )
                return normalize_path(new_path)

def get_path(directory=b'.', ext=b'db'):
    """Compose the path to the selected bitrot file."""
    directory = os.fsencode(directory)
    ext = os.fsencode(ext)
    return os.path.join(directory, b'.bitrot.' + ext)

def stable_sum(bitrot_db=None):
    """Calculates a stable SHA512 of all entries in the database.

    Useful for comparing if two directories hold the same data, as it ignores
    timing information."""
    if bitrot_db is None:
        bitrot_db = get_path(SOURCE_DIR_PATH,'db')
    digest = hashlib.sha512()
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    cur.execute('SELECT hash FROM bitrot ORDER BY path')
    row = cur.fetchone()
    while row:
        digest.update(row[0].encode('ascii'))
        row = cur.fetchone()
    return digest.hexdigest()

def check_sha512_integrity(verbosity=1, log=True):
    sha512_path = get_path(SOURCE_DIR_PATH,ext=b'sha512')

    if verbosity:
        printAndOrLog('Checking bitrot.db integrity... ',log)
        sys.stdout.flush()
    try:
        if os.path.exists(sha512_path):
            with open(sha512_path, 'rb') as f:
                old_sha512 = f.read().strip()
                f.close()
    # except IOError as e:
    #     if e.errno == errno.EACCES:
    except Exception as e:
        printAndOrLog("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e),log)
        raise ("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e))    
   
    if not os.path.exists(sha512_path):
        return

    bitrot_db = get_path(SOURCE_DIR_PATH,'db')
    digest = hashlib.sha512()

    try:
        if os.path.exists(bitrot_db):
            with open(bitrot_db, 'rb') as f:
                digest.update(f.read())
                f.close()
    # except IOError as e:
    #     if e.errno == errno.EACCES:
    except Exception as e:
        printAndOrLog("Could not open database file: \'{}\'. Received error: {}".format(bitrot_db, e),log)
        raise Exception("Could not open database file: \'{}\'. Received error: {}".format(bitrot_db, e))   

    if not os.path.exists(bitrot_db):
        return

    new_sha512 = digest.hexdigest().encode('ascii')
    if new_sha512 != old_sha512:
        if len(old_sha512) == 128:
            printAndOrLog(
                "\nError: SHA512 of the database file \'{}\' is different, bitrot.db might "
                "be corrupt.".format(bitrot_db),log)
        else:
            printAndOrLog(
                "\nError: SHA512 of the database file \'{}\' is different, but bitrot.sha512 "
                "has a suspicious length. It might be corrupt.".format(bitrot_db),log)
        printAndOrLog("If you'd like to continue anyway, delete the .bitrot.sha512 file and try again.",log)
        printAndOrLog("bitrot.db integrity check failed, cannot continue.",log)

        raise BitrotException(3, 'bitrot.db integrity check failed, cannot continue.',)

    if verbosity:
        printAndOrLog('OK.',log)

def update_sha512_integrity(verbosity=1, log=True):
    old_sha512 = 0
    sha512_path = get_path(SOURCE_DIR_PATH,ext=b'sha512')

    if os.path.exists(sha512_path):
        try:
            with open(sha512_path, 'rb') as f:
                old_sha512 = f.read().strip()
                f.close()
        # except IOError as e:
        #     if e.errno == errno.EACCES:
        except Exception as e:
            printAndOrLog("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e),log)
            raise Exception("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e))    

    bitrot_db = get_path(SOURCE_DIR_PATH,'db')
    digest = hashlib.sha512()
    if os.path.exists(bitrot_db):
        try:
            with open(bitrot_db, 'rb') as f:
                digest.update(f.read())
                f.close()
        except Exception as err:
            printAndOrLog("Could not open database file: \'{}\'. Received error: {}".format(bitrot_db, err),log)
    new_sha512 = digest.hexdigest().encode('ascii')
    if new_sha512 != old_sha512:
        if verbosity:
            printAndOrLog('Updating bitrot.sha512... ',log)
            sys.stdout.flush()
        
        try:
            with open(sha512_path, 'wb') as f:
                f.write(new_sha512)
                f.close()
        # except IOError as e:
        #     if e.errno == errno.EACCES:
        except Exception as e:
            printAndOrLog("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e),log)
            raise Exception("Could not open integrity file: \'{}\'. Received error: {}".format(sha512_path, e))    

        if verbosity:
            printAndOrLog('done.',log)

def recordTimeElapsed(startTime=0, log=True):
    elapsedTime = (time.time() - startTime)  
    if (elapsedTime > 3600):
        elapsedTime /= 3600
        if ((int)(elapsedTime) == 1):
            printAndOrLog('Time elapsed: 1 hour.',log)
        else:
            printAndOrLog('Time elapsed: {:.1f} hours.'.format(elapsedTime),log)

    elif (elapsedTime > 60):
        elapsedTime /= 60
        if ((int)(elapsedTime) == 1):
            printAndOrLog('Time elapsed: 1 minute.',log)
        else:
            printAndOrLog('Time elapsed: {:.0f} minutes.'.format(elapsedTime),log)

    else:
        if ((int)(elapsedTime) == 1):
            printAndOrLog('Time elapsed: 1 second.',log)
        else:
            printAndOrLog('Time elapsed: {:.1f} seconds.'.format(elapsedTime),log)

def run_from_command_line():
    global FSENCODING
    global SOURCE_DIR
    global DESTINATION_DIR
    global SOURCE_DIR_PATH
    SOURCE_DIR='.'
    parser = argparse.ArgumentParser(prog='bitrot')
    parser.add_argument(
        '-l', '--follow-links', action='store_true',
        help='follow symbolic links and store target files\' hashes. Once '
             'a path is present in the database, it will be checked against '
             'changes in content even if it becomes a symbolic link. In '
             'other words, if you run \'bitrot -l\', on subsequent runs '
             'symbolic links registered during the first run will be '
             'properly followed and checked even if you run without \'-l\'.')
    parser.add_argument(
        '--sum', action='store_true',
        help='using only the data already gathered, return a SHA-512 sum '
             'of hashes of all the entries in the database. No timestamps '
             'are used in calculation.')
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    parser.add_argument(
        '--commit-interval', type=float, default=300,
        help='min time in seconds between commits '
             '(0 commits on every operation).')
    parser.add_argument(
        '--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
        help='read files this many bytes at a time.')
    parser.add_argument(
        '--fsencoding', default='',
        help='override the codec to decode filenames, otherwise taken from '
             'the LANG environment variables.')
    parser.add_argument(
        '-i', '--include-list', default='',
        help='only read the files listed in this file.')
        # .\Directory\1.hi
    parser.add_argument(
        '-t', '--test', default=0,
        help='Level 0: normal operations.\n'
        'Level 1: Just test against an existing database, don\'t update anything.\n.'
        'Level 2: Doesnt compare dates, only hashes. No timestamps are used in the calculation.\n'
        'You can compare to another directory using --destination.')
    parser.add_argument(
        '-a', '--algorithm', default='',
        help='Specifies the hashing algorithm to use.')
    parser.add_argument(
        '-r','--recent', default=0,
        help='Only deal with files < X days old.')
    parser.add_argument(
        '-x', '--exclude-list', default='',
        help="don't read the files listed in this file - wildcards are allowed.")
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
        'Level 2: List missing entries.\n'
        'Level 3: List missing, fixed, new, renamed, and updated entries.\n'
        'Level 4: List missing, fixed, new, renamed, updated entries, and ignored files.\n'
        'Level 5: List missing, fixed, new, renamed, updated entries, ignored files, and existing files\n.')
    parser.add_argument(
        '-n', '--normalize', action='store_true',
        help='Only allow one unique normalized file into the DB at a time.')
    parser.add_argument(
        '-e', '--email', default=1,
        help='email file integrity errors')
    parser.add_argument(
        '-g', '--log', default=1,
        help='logs activity')
    parser.add_argument(
        '--sfv', default='',
        help='Also generates an MD5 or SFV file when given either of these as a parameter')
    parser.add_argument(
        '-f', '--fix', default=0,
        help='Level 0: will not check for problem files.\n'
        'Level 1: Will report files that have missing access and modification timestamps.\n'
        'Level 2: Fixes files that have missing access and modification timestamps.\n'
        'Level 3: Will report files that have invalid characters.\n'
        'Level 4: Fixes files by removing invalid characters. NOT RECOMMENDED.\n'
        'Level 5: Will report files that have missing access and modification timestamps and invalid characters.\n'
        'Level 6: Fixes files by removing invalid characters and adding missing access and modification times. NOT RECOMMENDED.')
    parser.add_argument(
        '-s', '--source', default='',
        help="Root of source folder. Default is current directory.")
    parser.add_argument(
        '-d', '--destination', default='',
        help="Root of destination folder. Default is current directory.")

    args = parser.parse_args()

    try:
        if not args.source:
            SOURCE_DIR = '.'
        else:
            os.chdir(args.source)
            SOURCE_DIR_PATH = args.source
    except Exception as err:
            SOURCE_DIR = '.'

    verbosity = 1
    if (args.verbose):
        try:
            verbosity = int(args.verbose)
            if (verbosity == 2):
                printAndOrLog("Verbosity option selected: {}. List missing entries.".format(args.verbose),args.log)
            elif (verbosity == 3):
                printAndOrLog("Verbosity option selected: {}. List missing, fixed, new, renamed, and updated entries.".format(args.verbose),args.log)
            elif (verbosity == 4):
                printAndOrLog("Verbosity option selected: {}. List missing, fixed, new, renamed, updated entries, and ignored files.".format(args.verbose),args.log)
            elif (verbosity == 5):
                printAndOrLog("Verbosity option selected: {}. List missing, fixed, new, renamed, updated entries, ignored files, and existing files.".format(args.verbose),args.log)
            elif not (verbosity == 0) and not (verbosity == 1):
                printAndOrLog("Invalid test option selected: {}. Using default level 1.".format(args.verbose),args.log)
                verbosity = 1
        except Exception as err:
            printAndOrLog("Invalid test option selected: {}. Using default level 1.".format(args.verbose),args.log)
            verbosity = 1

    if (args.log):
        log_path = get_path(SOURCE_DIR_PATH,ext=b'log')
        if (verbosity):
            writeToLog('\n=============================\n')
            writeToLog('Log started at ')
            writeToLog(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))

    try:
        if not args.source:
            if verbosity:
                printAndOrLog('Using current directory for file list.',args.log)
        else:
            if verbosity:
                printAndOrLog('Source directory \'{}\'.'.format(args.source),args.log)
    except Exception as err:
            if verbosity:
                printAndOrLog("Invalid source directory: \'{}\'. Using current directory. Received error: {}".format(args.source, err),args.log)

    if args.sum:
        try:
            print("Hash of {} is \n{}".format(SOURCE_DIR_PATH,stable_sum()))
            exit()
        except RuntimeError as e:
            print(str(e).encode(FSENCODING), file=sys.stderr)

    test = 0
    if (args.test):
        try:
            test = int(args.test)
            if (verbosity):
                if (test == 0):
                    printAndOrLog("Testing-only disabled.",args.log)
                elif (test == 1):
                    printAndOrLog("Just testing against an existing database, won\'t update anything.",args.log)
                elif (test == 2):
                    printAndOrLog("Won\'t compare dates, only hashes",args.log)
                else:
                    printAndOrLog("Invalid test option selected: {}. Using default level 0: testing-only disabled.".format(args.test),args.log)
                    test = 0
        except Exception as err:
            printAndOrLog("Invalid test option selected: {}. Using default level 0: testing-only disabled.".format(args.test),args.log)
            test = 0

    DESTINATION_DIR = SOURCE_DIR
    try:
        if not args.destination:
            if verbosity:
                printAndOrLog('Using current directory for destination file list.',args.log)
        else:
            if (test == 0 and args.destination):
                if verbosity:
                    printAndOrLog("Setting destination only works in testing mode. Please see --test.",args.log)
                    printAndOrLog('Using current directory for destination file list.',args.log)
            else:
                DESTINATION_DIR = args.destination
                if verbosity:
                    printAndOrLog('Destination directory \'{}\'.'.format(args.destination),args.log)
    except Exception as err:
            printAndOrLog("Invalid Destination directory: \'{}\'. Using current directory. Received error: {}".format(args.destination, err),args.log) 

    include_list = []
    if args.include_list:
        if verbosity:
            printAndOrLog('Opening file inclusion list at \'{}\'.'.format(args.include_list),args.log)
        try:
            #include_list = [line.rstrip('\n').encode(FSENCODING) for line in open(args.include_list)]
            with open(args.include_list) as includeFile:
                for line in includeFile:
                    line = line.rstrip('\n').encode(FSENCODING)
                    include_list.append(line)
                includeFile.close() # should be harmless if include_list == sys.stdin

        except Exception as err:
            printAndOrLog("Invalid inclusion list specified: \'{}\'. Not using an inclusion list. Received error: {}".format(args.include_list, err),args.log)
            include_list = []
    else:
        include_list = []
    exclude_list = []
    if args.exclude_list:
        if verbosity:
            printAndOrLog('Opening file exclusion list at \'{}\'.'.format(args.exclude_list),args.log)
        try:
            # exclude_list = [line.rstrip('\n').encode(FSENCODING) for line in open(args.exclude_list)]
            with open(args.exclude_list) as excludeFile:
                for line in excludeFile:
                    line = line.rstrip('\n').encode(FSENCODING)
                    exclude_list.append(line)
                excludeFile.close() # should be harmless if include_list == sys.stdin
        except Exception as err:
            printAndOrLog("Invalid exclusion list specified: \'{}\'. Not using an exclusion list. Received error: {}".format(args.exclude_list, err),args.log)
            exclude_list = []
    else:
        exclude_list = []

    if (args.algorithm):
        #combined = '\t'.join(hashlib.algorithms_available)
        #if (args.algorithm in combined):

        #word_to_check = args.algorithm
        #wordlist = hashlib.algorithms_available
        #result = any(word_to_check in word for word in wordlist)

        #algorithms_available = hashlib.algorithms_available
        #search = args.algorithm
        #result = next((True for algorithms_available in algorithms_available if search in algorithms_available), False)
        if (isValidHashingFunction(stringToValidate=args.algorithm) == True):
            algorithm = args.algorithm.upper()
            if (verbosity):
                printAndOrLog('Using {} for hashing function.'.format(algorithm),args.log)
        else:
            if (verbosity):
                printAndOrLog("Invalid hashing function specified: {}. Using default {}.".format(args.algorithm,DEFAULT_HASH_FUNCTION),args.log)
            algorithm = DEFAULT_HASH_FUNCTION
    else:
        algorithm = DEFAULT_HASH_FUNCTION
    sfv_path = get_path(SOURCE_DIR_PATH,ext=b'sfv')
    md5_path = get_path(SOURCE_DIR_PATH,ext=b'md5')
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
                printAndOrLog('Will generate an {} file.'.format(sfv),args.log) 
        else:
            if (verbosity):
                printAndOrLog("Invalid SFV/MD5 filetype specified: {}. Will not generate any additional file.".format(args.sfv),args.log)
            sfv = ""
    else:
        sfv = ""


    recent = 0;
    if (args.recent):
        try:
            recent = int(args.recent)
            if (recent):
                if (verbosity):
                    printAndOrLog("Only processing files <= {} days old.".format(args.recent),args.log)
            else:
                if (verbosity):
                    printAndOrLog("Invalid recent option selected: {}. Processing all files, not just recent ones.".format(args.recent),args.log)
                recent = 0
        except Exception as err:
            printAndOrLog("Invalid recent option selected: {}. Processing all files, not just recent ones.".format(args.recent),args.log)
            recent = 0
 
    normalize=False
    if (args.normalize):
        printAndOrLog("Only allowing one similarly named normalized file into the database.",args.log)
        normalize=True

    fix = 0
    if (args.fix):
        try:
            fix = int(args.fix)
            if (fix == 0):
                if (verbosity):
                    printAndOrLog("Will not check problem files.",args.log)
            elif (fix == 1):
                if (verbosity):
                    printAndOrLog("Will report files that have missing access and modification timestamps.",args.log)
            elif (fix == 2):
                if (verbosity):
                    printAndOrLog("Fixes files that have missing access and modification timestamps.",args.log)
            elif (fix == 3):
                if (verbosity):
                    printAndOrLog("Will report files that have invalid characters",args.log)
            elif (fix == 4):
                if (verbosity):
                    printAndOrLog("Fixes files by removing invalid characters. NOT RECOMMENDED.",args.log)
            elif (fix == 5):
                if (verbosity):
                    printAndOrLog("Will report files that have missing access and modification timestamps and invalid characters.",args.log)
            elif (fix == 6):
                if (verbosity):
                    printAndOrLog("Fixes files by removing invalid characters and adding missing access and modification times. NOT RECOMMENDED.",args.log)
            else:
                if (verbosity):
                    printAndOrLog("Invalid test option selected: {}. Using default level; will report files that have missing access and modification timestamps and invalid characters.".format(args.fix),args.log)
                    fix = 5
        except Exception as err:
            printAndOrLog("Invalid test option selected: {}. Using default level; will report files that have missing access and modification timestamps and invalid characters.".format(args.fix),args.log)
            fix = 5


    bt = Bitrot(
        verbosity = verbosity,
        algorithm = algorithm,
        test = test,
        recent = recent,
        email = args.email,
        log = args.log,
        follow_links = args.follow_links,
        commit_interval = args.commit_interval,
        chunk_size = args.chunk_size,
        include_list = include_list,
        exclude_list = exclude_list,
        sfv = sfv,
        fix = fix,
        normalize=normalize,
    )
    if args.fsencoding:
        FSENCODING = args.fsencoding

    try:
        bt.run()
    except BitrotException as bre:
        printAndOrLog('Error: {}'.format(bre.args[1]),args.log)
        sys.exit(bre.args[0])

if __name__ == '__main__':
    run_from_command_line()
