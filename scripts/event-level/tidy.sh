# The event level's retention, run as root by launchd every ten minutes
# (ai.nuanu.immunity.core.event-tidy) and by rotated.sh each time rotatelogs starts a new log file:
#   /bin/sh tidy.sh <log folder> <most bytes of log>
# A log file holds at most an hour, or 128 MiB. One not written to for a day holds only lines
# older than a day, and is deleted. Then, while the log files together are larger than the
# cap, the one written longest ago is deleted. The one written last is the one being written
# and is deleted neither way: after a Mac slept for more than a day, it too was last written a
# day ago. So the log is larger than its cap by at most the file being written and what
# is written while this runs. Files are taken in the order they were last written, not by
# name: a clock set back gives a new file an earlier name.
#
# Each deletion is a line in `removed`: when, the file's name, its size, and `age` or `cap`, so
# the reader can say when lines went before it read them or before their day was over. What
# eslogger and these scripts print, and `removed` itself, are kept small: a file of it over
# 64 KiB is replaced by its last 16 KiB, through a new file and a rename. Only files of these
# names in the log folder are touched. The programs this starts are themselves program starts
# eslogger records, so a level that runs writes a line at least every ten minutes on a Mac
# that is awake.
#
# Since each start is a line in the log, a pass asks about all the log files at once: one `ls`
# for the order they were last written in, and one `stat` for when each was last written and
# its size. One more `stat` gives the sizes of what eslogger and these scripts print. Besides
# these it starts `date`, `mkdir` and `rmdir` for the time and the lock, `rm` for each file it
# deletes, and `tail` and `mv` for each file it trims. So the number of programs a pass starts
# does not grow with the number of log files, and no shipped detection rule matches any of them
# by its start. `find` is not used: a published discovery rule matches its start by the name of
# the program alone.
#
# Two runs at once, the job's and the hook's, never both delete: each first makes the folder
# `tidy.lock` in the log folder, which only one can make, and removes it when it ends. A run that
# finds it made deletes nothing and ends without an error: the run that holds it brings the log
# under its cap, and the next new file or the job's next run starts another. A lock older than
# ten minutes was left by a run that was killed, and is taken over. mkdir is the lock because
# every macOS has it, in every version.
umask 077
if [ "$#" -ne 2 ] || [ ! -d "$1" ]; then
    echo "tidy.sh: usage: tidy.sh <log folder> <most bytes of log>" >&2
    exit 64
fi
# The cap: digits, no leading zero, and at most 16 of them, so the shell's 64-bit arithmetic
# compares it as it is. Anything else deletes nothing to keep the log under it.
case $2 in
'' | *[!0-9]* | 0?*)
    echo "tidy.sh: the most bytes of log is a whole number without a leading zero, not $2" >&2
    exit 64
    ;;
esac
if [ "${#2}" -gt 16 ]; then
    echo "tidy.sh: the most bytes of log has more than 16 digits: $2" >&2
    exit 64
fi
# Below the smallest cap the installer writes, 1 GiB, a cap would empty the log of all but the
# file being written: refused like any other, and nothing is deleted.
if [ "$2" -lt 1073741824 ]; then
    echo "tidy.sh: the most bytes of log is below 1 GiB (1073741824): $2" >&2
    exit 64
fi
log=$1
# The cap comes from the tidy job's launch daemon, which belongs to root and which only the
# installer writes, as an argument of the job or read by rotated.sh. No file or setting a
# program running as the user can change sets it: a cap such a program could shrink would let
# it empty the log, and that is quieting.
cap=$2

cd "$log" || exit 66
now=$(/bin/date +%s)
# The lock. Nothing is printed when it is held: what this prints goes to scripts.err, which
# Immunity Core reads as the scripts failing. A lock last written more than 600 seconds before
# `now` is taken over, counted as the age of a log file is counted below.
if ! /bin/mkdir tidy.lock 2>/dev/null; then
    held=$(/usr/bin/stat -f %m tidy.lock 2>/dev/null) || exit 0
    [ "$((now - held))" -gt 600 ] || exit 0
    /bin/rmdir tidy.lock 2>/dev/null
    /bin/mkdir tidy.lock 2>/dev/null || exit 0
fi
trap '/bin/rmdir tidy.lock 2>/dev/null' EXIT
trap 'exit 75' HUP INT TERM

# remove <name> <bytes> <age or cap>
remove() {
    /bin/rm -f "$1" || return 1
    echo "$now $1 $2 $3" >>removed
}

# Oldest first by when each was last written, to the nanosecond; the last that is still there
# is the one being written. The collector's names hold no space, newline or pattern character.
files=$(/bin/ls -1tr -- exec-*.jsonl 2>/dev/null)
# A line for each in the order of the names: when it was last written, in whole seconds, its
# size and its name. A name may hold a space; the two numbers before it never do.
stats=$(/usr/bin/stat -f '%m %z %N' -- exec-*.jsonl 2>/dev/null)
nl='
'
set -f
newest=
for f in $files; do
    [ -f "$f" ] && newest=$f
done

# fields <line of stats>: sets `written`, `size` and `f`.
fields() {
    written=${1%% *}
    size=${1#* }
    size=${size%% *}
    f=${1#* * }
}

# known <name>: sets `written` and `size` from the line of that name; false when there is none.
known() {
    IFS=$nl
    set -- "$1" $stats
    unset IFS
    name=$1
    shift
    for line; do
        [ "${line#* * }" = "$name" ] || continue
        fields "$line"
        return 0
    done
    return 1
}

# By age, in the order of the names. `find -mmin +1440`, used here before, held when the age in
# whole seconds, rounded up to whole minutes, was more than 1440 minutes, which is when it was
# more than 86400 seconds. Both count from the time last written in whole seconds. `now` is read
# before any file is looked at, and find read its own later, so no file is older here than find
# found it, and none is deleted sooner.
IFS=$nl
set -- $stats
unset IFS
for line; do
    fields "$line"
    [ -f "$f" ] && [ "$f" != "$newest" ] || continue
    if [ "$((now - written))" -gt 86400 ]; then
        remove "$f" "$size" age
    fi
done

# By the cap, over the files still there, with the sizes read above.
total=0
for f in $files; do
    [ -f "$f" ] && known "$f" || continue
    total=$((total + size))
done
for f in $files; do
    [ "$total" -gt "$cap" ] || break
    [ "$f" != "$newest" ] || break
    [ -f "$f" ] && known "$f" || continue
    remove "$f" "$size" cap || break
    total=$((total - size))
done

# What eslogger and these scripts print, and `removed`: a line for each that is there, its size
# and its name.
said=$(/usr/bin/stat -f '%z %N' -- eslogger.err scripts.err removed 2>/dev/null)
IFS=$nl
set -- $said
unset IFS
for line; do
    size=${line%% *}
    f=${line#* }
    if [ "$size" -gt 65536 ]; then
        /usr/bin/tail -c 16384 "$f" >"$f.new" && /bin/mv -f "$f.new" "$f"
    fi
done
