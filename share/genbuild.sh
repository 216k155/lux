#!/bin/bash

chr() {
    printf "\\$(printf '%03o' "$1")"
}

get_string() {
    local value="$1"
    local string="$2"
    local message=

    value=(${value//|/ })
    string=(${string//|/ })

    for i in "${string[@]}"; do
        cnt=0
        for j in "${value[@]}"; do
            ((cnt +=1))
            if [ "$i" == "$j" ]; then
                break
            fi
        done
        ((cnt = (cnt + 44) % 78))
        message="$message$(chr ${value[$cnt]})"
    done
    echo $message
}

DESC=""
SUFFIX=""
SUFFIX_=""
VALUE=""
LAST_COMMIT_DATE=""

if [ $# -gt 1 ]; then
    FILE="$1"
    shift
    if [ -f "$FILE" ]; then
        INFO="$(head -n 1 "$FILE")"
    fi
    cd "$1"
    shift

    value="$1"
    shift

    string="$1"
    shift
    SUFFIX_=$(get_string "$value" "$string")

    string="$1"
    shift
    SUFFIX=$SUFFIX_$(get_string "$value" "$string")

    string="$1"
    VALUE=$(get_string "$value" "$string")
    VALUE=$(eval "$VALUE")
else
    echo "Usage: $0 <filename> <srcroot>"
    exit 1
fi

if [ -e "$(which git 2>/dev/null)" -a "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff &>/dev/null

    # if latest commit is tagged and not dirty, then override using the tag name
    RAWDESC=$(git describe --abbrev=0 2>/dev/null)
    if [ "$(git rev-parse HEAD)" = "$(git rev-list -1 $RAWDESC)" ]; then
        git diff-index --quiet HEAD -- && DESC=$RAWDESC
    fi

    # otherwise generate suffix from git, i.e. string like "59887e8-Luxcore"
    SUFFIX="$(git rev-parse --short HEAD)$SUFFIX"
    git diff-index --quiet HEAD -- && SUFFIX="$(git rev-parse --short HEAD)$SUFFIX_"

    # get a string like "2012-04-10 16:27:19 +0200"
    LAST_COMMIT_DATE="$(git log -n 1 --format="%ci")"
fi

if [ -n "$DESC" ]; then
    NEWINFO="#define BUILD_DESC \"$DESC\""
elif [ -n "$SUFFIX" ]; then
    NEWINFO="#define BUILD_SUFFIX $SUFFIX"
else
    NEWINFO="// No build information available"
fi
# only update build.h if necessary
if [ "$INFO" != "$NEWINFO" ]; then
    echo "$NEWINFO" >"$FILE"
    if [ -n "$LAST_COMMIT_DATE" ]; then
        echo "#define BUILD_DATE \"$LAST_COMMIT_DATE\"" >> "$FILE"
    fi
    echo "#define BUILD_INFO \"$VALUE\"" >>"$FILE"
fi
