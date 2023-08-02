"""
NOTE: those tests are ordered and require pytest-order to run correctly.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from textwrap import dedent

import pytest


TMP = Path("/tmp/")


ReturnCode = int
StdOut = list[str]
StdErr = list[str]


def bitrot(*args: str) -> tuple[ReturnCode, StdOut, StdErr]:
    cmd = [sys.executable, "-m", "bitrot"]
    cmd.extend(args)
    res = subprocess.run(shlex.join(cmd), shell=True, capture_output=True)
    stdout = (res.stdout or b"").decode("utf8")
    stderr = (res.stderr or b"").decode("utf8")
    return res.returncode, lines(stdout), lines(stderr)


def bash(script, empty_dir: bool = False) -> bool:
    username = getpass.getuser()
    test_dir = TMP / f"bitrot-dir-{username}"
    if empty_dir and test_dir.is_dir():
        os.chdir(TMP)
        shutil.rmtree(test_dir)
    test_dir.mkdir(exist_ok=True)
    os.chdir(test_dir)

    preamble = """
        set -euxo pipefail
        LC_ALL=en_US.UTF-8
        LANG=en_US.UTF-8
        """

    if script:
        # We need to wait a second for modification timestamps to differ so that
        # the ordering of the output stays the same every run of the tests.
        preamble += """
        sleep 1
        """

    script_path = TMP / "bitrot-test.bash"
    script_path.write_text(dedent(preamble + script))
    script_path.chmod(0o755)

    out = subprocess.run(["bash", str(script_path)], capture_output=True)
    if out.returncode:
        print(f"Non-zero return code {out.returncode} when running {script_path}")
        if out.stdout:
            print(out.stdout)
        if out.stderr:
            print(out.stderr)
        return False
    return True


def lines(s: str) -> list[str]:
    r"""Only return non-empty lines that weren't killed by \r."""
    return [
        line.rstrip()
        for line in s.splitlines(keepends=True)
        if line and line.rstrip() and line[-1] != "\r"
    ]


@pytest.mark.order(1)
def test_command_exists() -> None:
    rc, out, err = bitrot("--help")
    assert rc == 0
    assert not err
    assert out[0].startswith("usage:")

    assert bash("", empty_dir=True)


@pytest.mark.order(2)
def test_new_files_in_a_tree_dir() -> None:
    assert bash(
        """
        mkdir -p nonemptydirs/dir2/
        touch nonemptydirs/dir2/new-file-{a,b}.txt
        echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    # assert out[0] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[1] == "2 entries in the database. 2 entries new:"
    assert out[2] == "  ./nonemptydirs/dir2/new-file-a.txt"
    assert out[3] == "  ./nonemptydirs/dir2/new-file-b.txt"
    assert out[4] == "Updating bitrot.sha512... done."


@pytest.mark.order(3)
def test_modified_files_in_a_tree_dir() -> None:
    assert bash(
        """
        echo $RANDOM >> nonemptydirs/dir2/new-file-a.txt
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "2 entries in the database. 1 entries updated:"
    assert out[3] == "  ./nonemptydirs/dir2/new-file-a.txt"
    assert out[4] == "Updating bitrot.sha512... done."


@pytest.mark.order(4)
def test_renamed_files_in_a_tree_dir() -> None:
    assert bash(
        """
        mv nonemptydirs/dir2/new-file-a.txt nonemptydirs/dir2/new-file-a.txt2
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "2 entries in the database. 1 entries renamed:"
    o3 = " from ./nonemptydirs/dir2/new-file-a.txt to ./nonemptydirs/dir2/new-file-a.txt2"
    assert out[3] == o3
    assert out[4] == "Updating bitrot.sha512... done."


@pytest.mark.order(5)
def test_deleted_files_in_a_tree_dir() -> None:
    assert bash(
        """
        rm  nonemptydirs/dir2/new-file-a.txt2
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "1 entries in the database. 1 entries missing:"
    assert out[3] == "  ./nonemptydirs/dir2/new-file-a.txt2"
    assert out[4] == "Updating bitrot.sha512... done."


@pytest.mark.order(5)
def test_new_files_and_modified_files_in_a_tree_dir() -> None:
    assert bash(
        """
        for fil in {a,b,c,d,e,f,g}; do
            echo $fil >> more-files-$fil.txt
        done
        echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "8 entries in the database. 7 entries new:"
    assert out[3] == "  ./more-files-a.txt"
    assert out[4] == "  ./more-files-b.txt"
    assert out[5] == "  ./more-files-c.txt"
    assert out[6] == "  ./more-files-d.txt"
    assert out[7] == "  ./more-files-e.txt"
    assert out[8] == "  ./more-files-f.txt"
    assert out[9] == "  ./more-files-g.txt"
    assert out[10] == "1 entries updated:"
    assert out[11] == "  ./nonemptydirs/dir2/new-file-b.txt"
    assert out[12] == "Updating bitrot.sha512... done."


@pytest.mark.order(6)
def test_new_files_modified_deleted_and_moved_in_a_tree_dir() -> None:
    assert bash(
        """
        for fil in {a,b,c,d,e,f,g}; do
            echo $fil $RANDOM >> nonemptydirs/pl-more-files-$fil.txt
        done
        echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
        mv more-files-a.txt more-files-a.txt2
        rm more-files-g.txt
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "14 entries in the database. 7 entries new:"
    assert out[3] == "  ./nonemptydirs/pl-more-files-a.txt"
    assert out[4] == "  ./nonemptydirs/pl-more-files-b.txt"
    assert out[5] == "  ./nonemptydirs/pl-more-files-c.txt"
    assert out[6] == "  ./nonemptydirs/pl-more-files-d.txt"
    assert out[7] == "  ./nonemptydirs/pl-more-files-e.txt"
    assert out[8] == "  ./nonemptydirs/pl-more-files-f.txt"
    assert out[9] == "  ./nonemptydirs/pl-more-files-g.txt"
    assert out[10] == "1 entries updated:"
    assert out[11] == "  ./nonemptydirs/dir2/new-file-b.txt"
    assert out[12] == "1 entries renamed:"
    assert out[13] == " from ./more-files-a.txt to ./more-files-a.txt2"
    assert out[14] == "1 entries missing:"
    assert out[15] == "  ./more-files-g.txt"
    assert out[16] == "Updating bitrot.sha512... done."


@pytest.mark.order(7)
def test_new_files_modified_deleted_and_moved_in_a_tree_dir_2() -> None:
    assert bash(
        """
        for fil in {a,b,c,d,e,f,g}; do
            echo  $RANDOM >> nonemptydirs/pl2-more-files-$fil.txt
        done
        echo  $RANDOM >> nonemptydirs/pl-more-files-a.txt
        mv nonemptydirs/pl-more-files-b.txt  nonemptydirs/pl-more-files-b.txt2
        cp nonemptydirs/pl-more-files-g.txt  nonemptydirs/pl2-more-files-g.txt2
        cp nonemptydirs/pl-more-files-d.txt  nonemptydirs/pl2-more-files-d.txt2
        rm more-files-f.txt nonemptydirs/pl-more-files-c.txt
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "21 entries in the database. 9 entries new:"
    assert out[3] == "  ./nonemptydirs/pl2-more-files-a.txt"
    assert out[4] == "  ./nonemptydirs/pl2-more-files-b.txt"
    assert out[5] == "  ./nonemptydirs/pl2-more-files-c.txt"
    assert out[6] == "  ./nonemptydirs/pl2-more-files-d.txt"
    assert out[7] == "  ./nonemptydirs/pl2-more-files-d.txt2"
    assert out[8] == "  ./nonemptydirs/pl2-more-files-e.txt"
    assert out[9] == "  ./nonemptydirs/pl2-more-files-f.txt"
    assert out[10] == "  ./nonemptydirs/pl2-more-files-g.txt"
    assert out[11] == "  ./nonemptydirs/pl2-more-files-g.txt2"
    assert out[12] == "1 entries updated:"
    assert out[13] == "  ./nonemptydirs/pl-more-files-a.txt"
    assert out[14] == "1 entries renamed:"
    o15 = " from ./nonemptydirs/pl-more-files-b.txt to ./nonemptydirs/pl-more-files-b.txt2"
    assert out[15] == o15
    assert out[16] == "2 entries missing:"
    assert out[17] == "  ./more-files-f.txt"
    assert out[18] == "  ./nonemptydirs/pl-more-files-c.txt"
    assert out[19] == "Updating bitrot.sha512... done."


@pytest.mark.order(8)
def test_3278_files() -> None:
    assert bash(
        """
        mkdir -p alotfiles/here; cd alotfiles/here
        # create a 320KB file
        dd if=/dev/urandom of=masterfile bs=1 count=327680
        # split it in 3277 files (instantly) + masterfile = 3278
        split -b 100 -a 10 masterfile
        """
    )
    rc, out, err = bitrot()
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    o2 = "3299 entries in the database, 3278 new, 0 updated, 0 renamed, 0 missing."
    assert out[2] == o2


@pytest.mark.order(9)
def test_3278_files_2() -> None:
    assert bash(
        """
        mv alotfiles/here alotfiles/here-moved
        """
    )
    rc, out, err = bitrot()
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    o2 = "3299 entries in the database, 0 new, 0 updated, 3278 renamed, 0 missing."
    assert out[2] == o2


@pytest.mark.order(10)
def test_rotten_file() -> None:
    assert bash(
        """
        touch non-rotten-file
        dd if=/dev/zero of=rotten-file bs=1k count=1000 &>/dev/null
        # let's make sure they share the same timestamp
        touch -r non-rotten-file rotten-file
        """
    )
    rc, out, err = bitrot("-v")
    assert rc == 0
    assert not err
    assert out[0] == "Checking bitrot.db integrity... ok."
    # assert out[1] == "Finished. 0.00 MiB of data read. 0 errors found."
    assert out[2] == "3301 entries in the database. 2 entries new:"
    assert out[3] == "  ./non-rotten-file"
    assert out[4] == "  ./rotten-file"


@pytest.mark.order(11)
def test_rotten_file_2() -> None:
    assert bash(
        """
        # modify the rotten file...
        dd if=/dev/urandom of=rotten-file bs=1k count=10 seek=1k conv=notrunc &>/dev/null
        # ...but revert the modification date
        touch -r non-rotten-file rotten-file
        """
    )
    rc, out, err = bitrot("-q")
    assert rc == 1
    assert not out
    e = (
        "error: SHA1 mismatch for ./rotten-file: expected"
        " 8fee1653e234fee8513245d3cb3e3c06d071493e, got"
    )
    assert err[0].startswith(e)
    assert err[1] == "error: There were 1 errors found."
