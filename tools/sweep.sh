#!/bin/zsh
#
# Заглушение заслонов движка по очереди: какие из них набор проверок не ловит
#
# Каждый отказ вида "return this->abort(...)" по очереди подменяется молчаливым успехом,
# после чего собирается набор проверок связи. Прошёл набор целиком - значит заслон этот
# не трогает ни одна проверка, и требование, им стерегомое, числится непроверенным.
#
# Две ловушки, стоившие ложных показаний при первом прогоне:
#
# 1. Строку с меткой "default:" подменять целиком НЕЛЬЗЯ - метка пропадает, разбор идёт
#    мимо переключателя и попадает под соседний заслон, а тот отвечает тем же отказом.
#    Такие места помечаются ложно непокрытыми; их подменять надо, метку сохраняя.
#
# 2. Отказы с извещением о внутреннем отказе (INTERNAL) и о нехватке памяти стерегут свою
#    же беду, а не оплошность собеседника: набором они и не должны покрываться.
#
#
# Восстановление исходника обязано обновлять метку времени: подмена и возврат укладываются
# в одну секунду, и собиратель возврата не замечает - следующий приговор читался бы с
# СТАРОГО двоичного файла
#
set -u
ROOT=${0:A:h:h}
SRC=$ROOT/src/internal/engine/engine.cpp
BAK=/tmp/sweep-engine.bak
OUT=/tmp/sweep-report.txt
cp "$SRC" "$BAK"
: > "$OUT"
SITES=(${(f)"$(grep -n 'return this->abort(' $SRC | cut -d: -f1)"})
TOTAL=${#SITES[@]}
echo "заслонов: $TOTAL" | tee -a "$OUT"
IDX=0
for L in $SITES; do
	IDX=$((IDX+1))
	cp "$BAK" "$SRC"; touch "$SRC"
	# заменяем строку отказа на молчаливый успех, отступ сохраняем
	python3 - "$SRC" "$L" <<'PY'
import sys
p, n = sys.argv[1], int(sys.argv[2])
lines = open(p, encoding='utf-8').read().split('\n')
line = lines[n-1]
indent = line[:len(line) - len(line.lstrip('\t'))]
lines[n-1] = indent + 'return context::error_t::NONE;'
open(p, 'w', encoding='utf-8').write('\n'.join(lines))
PY
	if ! (cd $ROOT/build && cmake --build . -j8 >/dev/null 2>&1); then
		echo "[$IDX/$TOTAL] строка $L: НЕ СОБИРАЕТСЯ" | tee -a "$OUT"
		continue
	fi
	if (cd $ROOT/build && ./tests/context/context >/dev/null 2>&1); then
		WHAT=$(sed -n "${L}p" "$BAK" | sed 's/^[[:space:]]*//')
		echo "[$IDX/$TOTAL] строка $L: НЕ ПОКРЫТ -- $WHAT" | tee -a "$OUT"
	else
		echo "[$IDX/$TOTAL] строка $L: покрыт" >> "$OUT"
	fi
	if [ $((IDX % 20)) -eq 0 ]; then echo "... пройдено $IDX из $TOTAL"; fi
done
cp "$BAK" "$SRC"; touch "$SRC"
(cd $ROOT/build && cmake --build . -j8 >/dev/null 2>&1)
echo "=== ИТОГ ===" | tee -a "$OUT"
grep -c "покрыт$" "$OUT" | sed 's/^/покрытых: /'
grep -c "НЕ ПОКРЫТ" "$OUT" | sed 's/^/непокрытых: /'
grep -c "НЕ СОБИРАЕТСЯ" "$OUT" | sed 's/^/несобираемых: /'
