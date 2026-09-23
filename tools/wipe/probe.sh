#!/bin/sh
#
# Щуп механизма затирания памяти: разбор порождённого кода и полоса
#
# Доводы: [собиратель] [ключи]. Собиратель по умолчанию c++, ключи - пустые; так проверяются
# clang на macOS и FreeBSD, GCC на Linux и MinGW, lcc на Эльбрусе. Пример:
#
#   sh tools/wipe/probe.sh g++ "-march=native"
#   sh tools/wipe/probe.sh /usr/bin/c++ "-arch arm64"
#
# Для каждого из пяти способов затирания (probe.cpp) печатается число команд функции,
# где ключ на стеке отживает своё, число вызовов memset и число строк с нулём либо
# вектором в порождённом коде; голый memset (keyA) обязан показать отсутствие
# затирания, остальные - его наличие. Затем печатается полоса затирания 16 КиБ.
#
# Ловушка: с -flto ключ -S даёт не машинный код, а промежуточное представление, и
# разбор пуст. Под -flto смотреть код надо иначе: у clang на macOS -Wl,-object_path_lto
# и otool -tvV, у GCC -save-temps и файл *.ltrans*.s; полоса же под -flto меряется этим
# щупом как есть
#
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CXX=${1:-c++}
FLAGS=${2:-}
WORK=${TMPDIR:-/tmp}/ants-wipe-probe
mkdir -p "$WORK"
echo "== $($CXX --version 2>&1 | head -1) $FLAGS"
# Порождённый код
$CXX -O3 -std=c++17 $FLAGS -S -o "$WORK/probe.s" "$HERE/probe.cpp" || exit 1
for f in keyA keyB keyC keyD keyE; do
	# Тело функции: метка в первом поле (clang дописывает пометку), конец по .cfi_endproc либо .size
	body=$(awk -v fn="$f" '($1 == fn":" || $1 == "_"fn":") {on=1; next} on && ($1 == ".cfi_endproc" || $1 == ".size" || $0 ~ ("\\.size[[:space:]]+_?" fn ",")) {on=0} on' "$WORK/probe.s" | grep -v -E '^[[:space:]]*[.#;!]|^[[:space:]]*$|^[A-Za-z_.$][A-Za-z0-9_.$]*:' )
	n=$(echo "$body" | grep -c .)
	ms=$(echo "$body" | grep -c -E 'memset|bzero')
	z=$(echo "$body" | grep -c -E 'xzr|wzr|movi|stos|\$0,|xmm|ymm|pxor|xorps')
	echo "$f: команд $n, вызовов memset $ms, строк с нулём либо вектором $z"
done
# Полоса
$CXX -O3 -std=c++17 $FLAGS -o "$WORK/probe" "$HERE/probe.cpp" || exit 1
"$WORK/probe"
