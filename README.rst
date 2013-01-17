======
bitrot
======

Detects bit rotten files on the hard drive to save your precious photo and
music collection from slow decay.

Usage
-----

Go to the desired directory and simply invoke::

  $ bitrot

This will start digging through your directory structure recursively indexing
all files found. The index is stored in a ``.bitrot.db`` file which is a SQLite
3 database.

Next time you run ``bitrot`` it will add new files and update the index for
files with a changed modification date. Most importantly however, it will
report all errors, e.g. files that changed on the hard drive but still have the
same modification date.

Performance
-----------

Obviously depends on how fast the underlying drive is. No rigorous performance
tests have been done. For informational purposes, on my typical 5400 RPM laptop
hard drive scanning a 60+ GB music library takes around 20 minutes. On an OCZ
Vertex 3 SSD drive ``bitrot`` is able to scan a 100 GB Aperture library in
under 10 minutes. Both tests on HFS+.

Change Log
----------

0.1.0
~~~~~

* First published version.

Authors
-------

Glued together by `Łukasz Langa <mailto:lukasz@langa.pl>`_.
