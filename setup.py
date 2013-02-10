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

import os
import sys
from setuptools import setup, find_packages

reload(sys)
sys.setdefaultencoding('utf8')

current_dir = os.path.abspath(os.path.dirname(__file__))
ld_file = open(os.path.join(current_dir, 'README.rst'))
try:
    long_description = ld_file.read()
finally:
    ld_file.close()
# We let it die a horrible tracebacking death if reading the file fails.
# We couldn't sensibly recover anyway: we need the long description.

sys.path.insert(0, current_dir + os.sep + 'src')
from bitrot import VERSION
release = ".".join(str(num) for num in VERSION)

setup(
    name = 'bitrot',
    version = release,
    author = 'Łukasz Langa',
    author_email = 'lukasz@langa.pl',
    description = ("Detects bit rotten files on the hard drive to save your "
                   "precious photo and music collection from slow decay."),
    long_description = long_description,
    url = 'https://github.com/ambv/bitrot/',
    keywords = 'file checksum database',
    platforms = ['any'],
    license = 'MIT',
    package_dir = {'': 'src'},
    packages = find_packages('src'),
    py_modules = ['bitrot'],
    scripts = ['bin/bitrot'],
    include_package_data = True,
    zip_safe = False, # if only because of the readme file
    install_requires = [
    ],

    classifiers = [
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Programming Language :: Python',
        'Topic :: System :: Filesystems',
        'Topic :: System :: Monitoring',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ]
    )
