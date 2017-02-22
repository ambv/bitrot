#!/usr/bin/env bash

# LC_ALL=en_US.UTF-8
# LANGUAGE=en_US.UTF-8
LANG=C

check_fail() {
    local temp=/tmp/bats.log
    > $temp
    for line; do
        echo "$line" >> $temp
    done
    # cat /tmp/.bitrot.log >> $temp
}


generate_bitrot() {
    local dest=$1 temp=/tmp/temp-base
    local -i count=$(($2*100)) percent=${3:-5}
    local cmd=$4
    mkdir -p "${dest%/*}"
    local dir_base=${dest%%/*}
    touch "$dest" $temp
    #let's make sure they shared the same timestamp
    touch "$dest" -r $temp
    
    dd if=/dev/zero of="$dest" bs=1k count=$count &>/dev/null
    run $cmd 
    #modify it and change modify date to base-file, simulate real bitrot so
    dd seek=1k if=/dev/urandom of="$dest" bs=1k count=$((count*percent/100)) conv=notrunc &>/dev/null 
    touch "$dest" -r $temp
    \rm -f $tmp
    run $cmd 
}

generate_bitrots() {
    local dest=$1 dest2=$2 temp=/tmp/temp-base
    local -i count=$(($3*100)) percent=${4:-5}
    mkdir -p "${dest%/*}"
    mkdir -p "${dest2%/*}"
    local dir_base=${dest%/*}
    local dir_base2=${dest2%/*}
    touch "$dest2" "$dest" $temp
    #let's make sure they shared the same timestamp
    touch "$dest" -r $temp
    touch "$dest2" -r $temp
    
    dd if=/dev/zero of="$dest" bs=1k count=$count &>/dev/null
    dd if=/dev/zero of="$dest2" bs=1k count=$count &>/dev/null
    run $r "$dir_base" "$dir_base2"
    #modify it and change modify date to base-file, simulate bitrot so
    dd seek=1k if=/dev/urandom of="$dest" bs=1k count=$((count*percent/100)) conv=notrunc &>/dev/null 
    dd seek=1k if=/dev/urandom of="$dest2" bs=1k count=$((count*percent/100)) conv=notrunc &>/dev/null 
    touch "$dest" -r $temp
    touch "$dest2" -r $temp
    \rm -f $tmp
    echo $status > /tmp/status
    run $r "$dir_base" "$dir_base2"
    echo $status >> /tmp/status
}

