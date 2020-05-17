#!/usr/bin/env bats

LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8

cmd='python -m bitrot'
test_dir=/tmp/bitrot_dir-$USER
mkdir -p $test_dir
cd $test_dir || exit 

@test "bitrot command exists" {
    run $cmd --help

    [ "$status" -eq 0 ]
}

@test "bitrot detects new files in a tree dir" {
    mkdir -p nonemptydirs/dir2/
    touch nonemptydirs/dir2/new-file-{a,b}.txt
    echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
    run $cmd -v

    [ "$status" -eq 0 ]
    # [[ ${lines[0]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[1]}   = "2 entries in the database. 2 entries new:" ]]
    [[ ${lines[2]}   = "  ./nonemptydirs/dir2/new-file-a.txt" ]]
    [[ ${lines[3]}   = "  ./nonemptydirs/dir2/new-file-b.txt" ]]
    [[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]
}

@test "bitrot detects modified files in a tree dir" {
    sleep 2
    echo $RANDOM >> nonemptydirs/dir2/new-file-a.txt
    run $cmd -v

    [ "$status" -eq 0 ]
    [[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "2 entries in the database. 1 entries updated:" ]]
    [[ ${lines[3]}   = "  ./nonemptydirs/dir2/new-file-a.txt" ]]
    [[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]
}

@test "bitrot detects renamed files in a tree dir" {
    sleep 1
    mv nonemptydirs/dir2/new-file-a.txt nonemptydirs/dir2/new-file-a.txt2
    run $cmd -v

    [ "$status" -eq 0 ]
    [[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "2 entries in the database. 1 entries renamed:" ]]
    [[ ${lines[3]}   = " from ./nonemptydirs/dir2/new-file-a.txt to ./nonemptydirs/dir2/new-file-a.txt2" ]]
    [[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]
}

@test "bitrot detects delete files in a tree dir" {
    sleep 1
    rm  nonemptydirs/dir2/new-file-a.txt2
    run $cmd -v

    [ "$status" -eq 0 ]
    [[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "1 entries in the database. 1 entries missing:" ]]
    [[ ${lines[3]}   = "  ./nonemptydirs/dir2/new-file-a.txt2" ]]
    [[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]
}


@test "bitrot detects new files and modified in a tree dir " {
    sleep 1
    touch more-files-{a,b,c,d,e,f,g}.txt
    echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
    run $cmd -v

    [ "$status" -eq 0 ]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "8 entries in the database. 7 entries new:" ]]
    [[ ${lines[3]}   = "  ./more-files-a.txt" ]]
    [[ ${lines[4]}   = "  ./more-files-b.txt" ]]
    [[ ${lines[5]}   = "  ./more-files-c.txt" ]]
    [[ ${lines[6]}   = "  ./more-files-d.txt" ]]
    [[ ${lines[7]}   = "  ./more-files-e.txt" ]]
    [[ ${lines[8]}   = "  ./more-files-f.txt" ]]
    [[ ${lines[9]}   = "  ./more-files-g.txt" ]]
    [[ ${lines[10]}  = "1 entries updated:" ]]
    [[ ${lines[11]}  = "  ./nonemptydirs/dir2/new-file-b.txt" ]]
    [[ ${lines[12]}  = "Updating bitrot.sha512... done." ]]
}

@test "bitrot detects new files, modified, deleted and moved in a tree dir " {
    sleep 1
    for fil in {a,b,c,d,e,f,g}; do
        echo  $RANDOM >> nonemptydirs/pl-more-files-$fil.txt
    done
    echo $RANDOM >> nonemptydirs/dir2/new-file-b.txt
    mv more-files-a.txt more-files-a.txt2
    rm more-files-g.txt
    run $cmd -v

    [ "$status" -eq 0 ]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "14 entries in the database. 7 entries new:" ]]
    [[ ${lines[3]}   = "  ./nonemptydirs/pl-more-files-a.txt" ]]
    [[ ${lines[4]}   = "  ./nonemptydirs/pl-more-files-b.txt" ]]
    [[ ${lines[5]}   = "  ./nonemptydirs/pl-more-files-c.txt" ]]
    [[ ${lines[6]}   = "  ./nonemptydirs/pl-more-files-d.txt" ]]
    [[ ${lines[7]}   = "  ./nonemptydirs/pl-more-files-e.txt" ]]
    [[ ${lines[8]}   = "  ./nonemptydirs/pl-more-files-f.txt" ]]
    [[ ${lines[9]}   = "  ./nonemptydirs/pl-more-files-g.txt" ]]
    [[ ${lines[10]}  = "1 entries updated:" ]]
    [[ ${lines[11]}  = "  ./nonemptydirs/dir2/new-file-b.txt" ]]
    [[ ${lines[12]}  = "1 entries renamed:" ]]
    [[ ${lines[13]}  = " from ./more-files-a.txt to ./more-files-a.txt2" ]]
    [[ ${lines[14]}  = "1 entries missing:" ]]
    [[ ${lines[15]}  = "  ./more-files-g.txt" ]]
    [[ ${lines[16]}  = "Updating bitrot.sha512... done." ]]
}


@test "bitrot detects new files, modified, deleted and moved in a tree dir 2" {
    sleep 1
    for fil in {a,b,c,d,e,f,g}; do
        echo  $RANDOM >> nonemptydirs/pl2-more-files-$fil.txt
    done
    echo  $RANDOM >> nonemptydirs/pl-more-files-a.txt
    mv nonemptydirs/pl-more-files-b.txt  nonemptydirs/pl-more-files-b.txt2
    cp nonemptydirs/pl-more-files-g.txt  nonemptydirs/pl2-more-files-g.txt2
    cp nonemptydirs/pl-more-files-d.txt  nonemptydirs/pl2-more-files-d.txt2
    rm more-files-f.txt nonemptydirs/pl-more-files-c.txt 
    run $cmd -v

    [ "$status" -eq 0 ]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "21 entries in the database. 9 entries new:" ]]
    [[ ${lines[3]}   = "  ./nonemptydirs/pl2-more-files-a.txt" ]]
    [[ ${lines[4]}   = "  ./nonemptydirs/pl2-more-files-b.txt" ]]
    [[ ${lines[5]}   = "  ./nonemptydirs/pl2-more-files-c.txt" ]]
    [[ ${lines[6]}   = "  ./nonemptydirs/pl2-more-files-d.txt" ]]
    [[ ${lines[7]}   = "  ./nonemptydirs/pl2-more-files-d.txt2" ]]
    [[ ${lines[8]}   = "  ./nonemptydirs/pl2-more-files-e.txt" ]]
    [[ ${lines[9]}   = "  ./nonemptydirs/pl2-more-files-f.txt" ]]
    [[ ${lines[10]}  = "  ./nonemptydirs/pl2-more-files-g.txt" ]]
    [[ ${lines[11]}  = "  ./nonemptydirs/pl2-more-files-g.txt2" ]]
    [[ ${lines[12]}  = "1 entries updated:" ]]
    [[ ${lines[13]}  = "  ./nonemptydirs/pl-more-files-a.txt" ]]
    [[ ${lines[14]}  = "1 entries renamed:" ]]
    [[ ${lines[15]}  = " from ./nonemptydirs/pl-more-files-b.txt to ./nonemptydirs/pl-more-files-b.txt2" ]]
    [[ ${lines[16]}  = "2 entries missing:" ]]
    [[ ${lines[17]}  = "  ./more-files-f.txt" ]]
    [[ ${lines[18]}  = "  ./nonemptydirs/pl-more-files-c.txt" ]]
    [[ ${lines[19]}  = "Updating bitrot.sha512... done." ]]
}


@test "bitrot can operate with 3278 files easily in a dir (1)" {
    sleep 1
    mkdir -p alotfiles/here; cd alotfiles/here
    # create a 320KB file
    dd if=/dev/urandom of=masterfile bs=1 count=327680
    # split it in 3277 files (instantly) + masterfile = 3278
    split -b 100 -a 10 masterfile
    cd $test_dir
    run $cmd 

    [ "$status" -eq 0 ]
    [[ ${lines[2]} = "3299 entries in the database, 3278 new, 0 updated, 0 renamed, 0 missing." ]]
}

@test "bitrot can operate with 3278 files easily in a dir (2)" {
    sleep 1
    mv alotfiles/here alotfiles/here-moved
    run $cmd 

    [ "$status" -eq 0 ]
    [[ ${lines[2]}   = "3299 entries in the database, 0 new, 0 updated, 3278 renamed, 0 missing." ]]
}

@test "bitrot can detect rotten bits in a dir (1)" {
    sleep 1
    touch non-rotten-file
    dd if=/dev/zero of=rotten-file bs=1k count=1000 &>/dev/null
    # let's make sure they share the same timestamp
    touch -r non-rotten-file rotten-file
    run $cmd -v

    [ "$status" -eq 0 ]
    [[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
    # [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
    [[ ${lines[2]}   = "3301 entries in the database, 2 entries new:" ]]
    [[ ${lines[3]}   = "  ./non-rotten-file" ]]
    [[ ${lines[4]}   = "  ./rotten-file" ]]
}

@test "bitrot can detect rotten bits in a dir (2)" {
    sleep 1
    # modify the rotten file... 
    dd if=/dev/urandom of=rotten-file bs=1k count=10 seek=1k conv=notrunc &>/dev/null 
    # ...but revert the modification date 
    touch -r non-rotten-file rotten-file
    run $cmd -q

    [ "$status" -eq 1 ]
    [[ ${lines[0]} = *"error: SHA1 mismatch for ./rotten-file: expected"* ]]
    [[ ${lines[1]} = "error: There were 1 errors found." ]]
}

@test "Clean everything" {
    run chmod -Rf a+w $test_dir
    run rm -rf $test_dir
}