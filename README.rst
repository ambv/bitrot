======
bitrot
======

Detects bit rotten files on the hard drive to save your precious photo
and music collection from slow decay.

Usage
-----

Go to the desired directory and simply invoke::

  $ bitrot

This will start digging through your directory structure recursively
indexing all files found. The index is stored in a ``.bitrot.db`` file
which is a SQLite 3 database.

Next time you run ``bitrot`` it will add new files and update the index
for files with a changed modification date. Most importantly however, it
will report all errors, e.g. files that changed on the hard drive but
still have the same modification date.

All paths stored in ``.bitrot.db`` are relative so it's safe to rescan
a folder after moving it to another drive. Just remember to move it in
a way that doesn't touch modification dates. Otherwise the checksum
database is useless.

Performance
-----------

Obviously depends on how fast the underlying drive is.  Historically
the script was single-threaded because back in 2013 checksum
calculations on a single core still outran typical drives, including
the mobile SSDs of the day.  In 2020 this is no longer the case so the
script now uses a process pool to calculate SHA1 hashes and perform
`stat()` calls.

No rigorous performance tests have been done.  Scanning a ~1000 file
directory totalling ~5 GB takes 2.2s on a 2018 MacBook Pro 15" with
a AP0512M SSD.  Back in 2013, that same feat on a 2015 MacBook Air with
a SM0256G SSD took over 20 seconds.

On that same 2018 MacBook Pro 15", scanning a 60+ GB music library takes
24 seconds.  Back in 2013, with a typical 5400 RPM laptop hard drive
it took around 15 minutes.  How times have changed!

Tests
-----

There's a simple but comprehensive test scenario using
`pytest <https://pypi.org/p/pytest>`_ and
`pytest-order <https://pypi.org/p/pytest-order>`.

Install::

  $ python3 -m venv .venv
  $ . .venv/bin/activate
  (.venv)$ pip install -e .[test]

Run::

  (.venv)$ pytest -x
  ==================== test session starts ====================
  platform darwin -- Python 3.10.12, pytest-7.4.0, pluggy-1.2.0
  rootdir: /Users/ambv/Documents/Python/bitrot
  plugins: order-1.1.0
  collected 12 items

  tests/test_bitrot.py ............                      [100%]

  ==================== 12 passed in 15.05s ====================

Change Log
----------

1.0.1
~~~~~

* officially remove Python 2 support that was broken since 1.0.0
  anyway; now the package works with Python 3.8+ because of a few
  features

1.0.0
~~~~~

* significantly sped up execution on solid state drives by using
  a process pool executor to calculate SHA1 hashes and perform `stat()`
  calls; use `-w1` if your runs on slow magnetic drives were
  negatively affected by this change

* sped up execution by pre-loading all SQLite-stored hashes to memory
  and doing comparisons using Python sets

* all UTF-8 filenames are now normalized to NFKD in the database to
  enable cross-operating system checks

* the SQLite database is now vacuumed to minimize its size

* bugfix: additional Python 3 fixes when Unicode names were encountered

0.9.2
~~~~~

* bugfix: one place in the code incorrectly hardcoded UTF-8 as the
  filesystem encoding

0.9.1
~~~~~

* bugfix: print the path that failed to decode with FSENCODING

* bugfix: when using -q, don't hide warnings about files that can't be
  statted or read

* bugfix: -s is no longer broken on Python 3

0.9.0
~~~~~

* bugfix: bitrot.db checksum checking messages now obey --quiet

* Python 3 compatibility

0.8.0
~~~~~

* bitrot now keeps track of its own database's bitrot by storing
  a checksum of .bitrot.db in .bitrot.sha512

* bugfix: now properly uses the filesystem encoding to decode file names
  for use with the .bitrotdb database. Report and original patch by
  pallinger.

0.7.1
~~~~~

* bugfix: SHA1 computation now works correctly on Windows; previously
  opened files in text-mode. This fix will change hashes of files
  containing some specific bytes like 0x1A.

0.7.0
~~~~~

* when a file changes or is renamed, the timestamp of the last check is
  updated, too

* bugfix: files that disappeared during the run are now properly ignored

* bugfix: files that are locked or with otherwise denied access are
  skipped. If they were read before, they will be considered "missing"
  in the report.

* bugfix: if there are multiple files with the same content in the
  scanned directory tree, renames are now handled properly for them

* refactored some horrible code to be a little less horrible

0.6.0
~~~~~

* more control over performance with ``--commit-interval`` and
  ``--chunk-size`` command-line arguments

* bugfix: symbolic links are now properly skipped (or can be followed if
  ``--follow-links`` is passed)

* bugfix: files that cannot be opened are now gracefully skipped

* bugfix: fixed a rare division by zero when run in an empty directory

0.5.1
~~~~~

* bugfix: warn about test mode only in test mode

0.5.0
~~~~~

* ``--test`` command-line argument for testing the state without
  updating the database on disk (works for testing databases you don't
  have write access to)

* size of the data read is reported upon finish

* minor performance updates

0.4.0
~~~~~

* renames are now reported as such

* all non-regular files (e.g. symbolic links, pipes, sockets) are now
  skipped

* progress presented in percentage

0.3.0
~~~~~

* ``--sum`` command-line argument for easy comparison of multiple
  databases

0.2.1
~~~~~

* fixed regression from 0.2.0 where new files caused a ``KeyError``
  exception

0.2.0
~~~~~

* ``--verbose`` and ``--quiet`` command-line arguments

* if a file is no longer there, its entry is removed from the database

0.1.0
~~~~~

* First published version.

Authors
-------

Glued together by `Łukasz Langa <mailto:lukasz@langa.pl>`_. Multiple
improvements by
`Ben Shepherd <mailto:bjashepherd@gmail.com>`_,
`Jean-Louis Fuchs <mailto:ganwell@fangorn.ch>`_,
`Marcus Linderoth <marcus@thingsquare.com>`_,
`p1r473 <mailto:subwayjared@gmail.com>`_,
`Peter Hofmann <mailto:scm@uninformativ.de>`_,
`Phil Lundrigan <mailto:philipbl@cs.utah.edu>`_,
`Reid Williams <rwilliams@ideo.com>`_,
`Stan Senotrusov <senotrusov@gmail.com>`_,
`Yang Zhang <mailto:yaaang@gmail.com>`_, and
`Zhuoyun Wei <wzyboy@wzyboy.org>`_.
