#!/usr/bin/env bats

#WARNING!
#Be careful don't use ((, cause (( $status == pp )) && echo Really WRONG!
#the issue is that (( 0 == letters )) is always true ... :(

load test_helper


# r=~/.local/bin/bitrot

r=~/Clones/bitrot/src/bitrot.py

test_dir=/tmp/bitrot_dir-$USER
mkdir -p  $test_dir
cd $test_dir || exit 

###########
#  BASIC  #
###########

@test "bitrot detects new files in a tree dir" {
mkdir -p notemptydirs/dir2/
touch notemptydirs/dir2/new-file-{a,b}.txt
echo $RANDOM >> notemptydirs/dir2/new-file-b.txt
run $r -v
# check_fail "${lines[@]}"

(( $status == 0 ))
# [[ ${lines[0]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[1]}   = "2 entries in the database. 2 entries new:" ]]
[[ ${lines[2]}   = "  ./notemptydirs/dir2/new-file-a.txt" ]]
[[ ${lines[3]}   = "  ./notemptydirs/dir2/new-file-b.txt" ]]
[[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]

}


@test "bitrot detects modified files in a tree dir" {
sleep 1
echo $RANDOM >> notemptydirs/dir2/new-file-a.txt
run $r -v
# check_fail "${lines[@]}"

(( $status == 0 ))
[[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
# [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[2]}   = "2 entries in the database. 1 entries updated:" ]]
[[ ${lines[3]}   = "  ./notemptydirs/dir2/new-file-a.txt" ]]
[[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]

}

@test "bitrot detects renamed files in a tree dir" {
sleep 1
mv notemptydirs/dir2/new-file-a.txt notemptydirs/dir2/new-file-a.txt2
run $r -v
# check_fail "${lines[@]}"

(( $status == 0 ))
[[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
# [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[2]}   = "2 entries in the database. 1 entries renamed:" ]]
[[ ${lines[3]}   = " from ./notemptydirs/dir2/new-file-a.txt to ./notemptydirs/dir2/new-file-a.txt2" ]]
[[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]

}

@test "bitrot detects delete files in a tree dir" {
sleep 1
rm  notemptydirs/dir2/new-file-a.txt2
run $r -v
# check_fail "${lines[@]}"

(( $status == 0 ))
[[ ${lines[0]}   = "Checking bitrot.db integrity... ok." ]]
# [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[2]}   = "1 entries in the database. 1 entries missing:" ]]
[[ ${lines[3]}   = "  ./notemptydirs/dir2/new-file-a.txt2" ]]
[[ ${lines[4]}   = "Updating bitrot.sha512... done." ]]

}


@test "bitrot detects new files and modified in a tree dir " {
sleep 1
touch more-files-{a,b,c,d,e,f,g}.txt
echo $RANDOM >> notemptydirs/dir2/new-file-b.txt
run $r -v
#check_fail "${lines[@]}"

(( $status == 0 ))

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
[[ ${lines[11]}  = "  ./notemptydirs/dir2/new-file-b.txt" ]]
[[ ${lines[12]}  = "Updating bitrot.sha512... done." ]]
}

@test "bitrot detects new files, modified, deleted and moved in a tree dir " {
sleep 1
for fil in  {a,b,c,d,e,f,g}; do
echo  $RANDOM >> notemptydirs/pl-more-files-$fil.txt
done
echo $RANDOM >> notemptydirs/dir2/new-file-b.txt
mv more-files-a.txt more-files-a.txt2
rm more-files-g.txt
run $r -v

(( $status == 0 ))

# [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[2]}   = "14 entries in the database. 7 entries new:" ]]
[[ ${lines[3]}   = "  ./notemptydirs/pl-more-files-a.txt" ]]
[[ ${lines[4]}   = "  ./notemptydirs/pl-more-files-b.txt" ]]
[[ ${lines[5]}   = "  ./notemptydirs/pl-more-files-c.txt" ]]
[[ ${lines[6]}   = "  ./notemptydirs/pl-more-files-d.txt" ]]
[[ ${lines[7]}   = "  ./notemptydirs/pl-more-files-e.txt" ]]
[[ ${lines[8]}   = "  ./notemptydirs/pl-more-files-f.txt" ]]
[[ ${lines[9]}   = "  ./notemptydirs/pl-more-files-g.txt" ]]
[[ ${lines[10]}  = "1 entries updated:" ]]
[[ ${lines[11]}  = "  ./notemptydirs/dir2/new-file-b.txt" ]]
[[ ${lines[12]}  = "1 entries renamed:" ]]
[[ ${lines[13]}  = " from ./more-files-a.txt to ./more-files-a.txt2" ]]
[[ ${lines[14]}  = "1 entries missing:" ]]
[[ ${lines[15]}  = "  ./more-files-g.txt" ]]
[[ ${lines[16]}  = "Updating bitrot.sha512... done." ]]
}


@test "bitrot detects new files, modified, deleted and moved in a tree dir 2" {
sleep 1
for fil in  {a,b,c,d,e,f,g}; do
echo  $RANDOM >> notemptydirs/pl2-more-files-$fil.txt
done
echo  $RANDOM >> notemptydirs/pl-more-files-a.txt

mv notemptydirs/pl-more-files-b.txt  notemptydirs/pl-more-files-b.txt2
cp notemptydirs/pl-more-files-g.txt  notemptydirs/pl2-more-files-g.txt2
cp notemptydirs/pl-more-files-d.txt  notemptydirs/pl2-more-files-d.txt2

rm more-files-f.txt notemptydirs/pl-more-files-c.txt 

run $r -v

(( $status == 0 ))

# [[ ${lines[1]}   = "Finished. 0.00 MiB of data read. 0 errors found." ]]
[[ ${lines[2]}   = "21 entries in the database. 9 entries new:" ]]
[[ ${lines[3]}   = "  ./notemptydirs/pl2-more-files-a.txt" ]]
[[ ${lines[4]}   = "  ./notemptydirs/pl2-more-files-b.txt" ]]
[[ ${lines[5]}   = "  ./notemptydirs/pl2-more-files-c.txt" ]]
[[ ${lines[6]}   = "  ./notemptydirs/pl2-more-files-d.txt" ]]
[[ ${lines[7]}   = "  ./notemptydirs/pl2-more-files-d.txt2" ]]
[[ ${lines[8]}   = "  ./notemptydirs/pl2-more-files-e.txt" ]]
[[ ${lines[9]}   = "  ./notemptydirs/pl2-more-files-f.txt" ]]
[[ ${lines[10]}  = "  ./notemptydirs/pl2-more-files-g.txt" ]]
[[ ${lines[11]}  = "  ./notemptydirs/pl2-more-files-g.txt2" ]]
[[ ${lines[12]}  = "1 entries updated:" ]]
[[ ${lines[13]}  = "  ./notemptydirs/pl-more-files-a.txt" ]]
[[ ${lines[14]}  = "1 entries renamed:" ]]
[[ ${lines[15]}  = " from ./notemptydirs/pl-more-files-b.txt to ./notemptydirs/pl-more-files-b.txt2" ]]
[[ ${lines[16]}  = "2 entries missing:" ]]
[[ ${lines[17]}  = "  ./more-files-f.txt" ]]
[[ ${lines[18]}  = "  ./notemptydirs/pl-more-files-c.txt" ]]
[[ ${lines[19]}  = "Updating bitrot.sha512... done." ]]
}


@test "bitrot can operate with 3278 files easily in a dir" {
sleep 1
mkdir -p alotfiles/here; cd alotfiles/here
#create a 320KB file
dd if=/dev/urandom of=masterfile bs=1 count=327680
#split it in 3277 files (instantly) + masterfile = 3278
split -b 100 -a 10 masterfile
cd $test_dir
run $r 

(( $status == 0 ))
[[ ${lines[2]} = "3299 entries in the database, 3278 new, 0 updated, 0 renamed, 0 missing." ]]

}

@test "bitrot can operate with 3278 files easily in a dir 2 " {
sleep 1
mv alotfiles/here alotfiles/here-moved
run $r 
# check_fail "${lines[@]}"

(( $status == 0 ))
[[ ${lines[2]}   = "3299 entries in the database, 0 new, 0 updated, 3278 renamed, 0 missing." ]]

}

@test "bitrot can detetect a bitrot in a dir !  " {
sleep 1
generate_bitrot ./bitrot-file 10 2 $r
run $r -q

check_fail "${lines[@]}"

(( $status == 1 ))
[[ ${lines[0]} = *"error: SHA1 mismatch for ./bitrot-file: expected"* ]]
[[ ${lines[1]} = "error: There were 1 errors found." ]]
}


@test "Clean everything" {
run chmod -f a+w *
\rm -rf * $test_dir $BITROT_BACKUPS
}

