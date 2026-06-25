#!/bin/bash
# Generate one pptx per source file into assembly.out/, numbered 0-based so the
# prefix matches the module number:
#
#   00__about.pptx  01__module1.pptx  02__module2.pptx ... 10__module10.pptx
#
# The shared assembler ($ES_HOME/utils/presentations/slides-assembler.sh) numbers
# 1-based (01__about, 02__module1, ...). We leave that shared tool untouched and
# just renumber its output down by one here.
set -euo pipefail
cd "$(dirname "$0")"

# 1. Build all decks with the shared assembler (produces 01__*, 02__*, ...).
"$ES_HOME"/utils/presentations/slides-assembler.sh slide-list.txt

# 2. Renumber assembly.out from 1-based to 0-based (ascending, so lower numbers
#    are freed first and never collide).
cd assembly.out
for f in [0-9][0-9]__*; do
    [ -e "$f" ] || continue            # no matches -> skip
    n=${f%%__*}                        # leading NN
    rest=${f#*__}                      # name after __
    new=$(printf '%02d__%s' "$((10#$n - 1))" "$rest")
    [ "$f" = "$new" ] || mv -f -- "$f" "$new"
done

echo "Done. Decks in $(pwd):"
ls -1 [0-9][0-9]__*
