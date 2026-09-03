#!/bin/zsh
#
# Заглушение заслонов разборщиков по очереди: какие из них набор проверок не ловит
#
# Всякий отказ вида "return error_t::ЧТО-ТО;" подменяется молчаливым успехом, а всякий
# "return false;" - истиной, после чего собирается набор. Сперва гоняется набор самого
# модуля - он быстр; и лишь когда тот прошёл, гоняется весь набор целиком, ибо заслон
# мог трогаться проверками связи, а не своими.
#
# Ловушка, учтённая устройством: метки "default:" и "case ...:" сохраняются, иначе разбор
# идёт мимо переключателя и попадает под соседний заслон с тем же отказом - место
# пометилось бы непокрытым ложно.
#
#
# Восстановление исходника обязано обновлять метку времени: подмена и возврат укладываются
# в одну секунду, и собиратель возврата не замечает - следующий приговор читался бы с
# СТАРОГО двоичного файла
#
set -u
ROOT=${0:A:h:h}
#
# Одиночность обязательна: два прогона разом правят один исходник, и восстановление
# одного затирает работу другого. Замок снимается при выходе всяким путём
#
LOCK=/tmp/nts-sweep.lock
if ! mkdir "$LOCK" 2>/dev/null; then
	echo "разбор уже идёт: $LOCK" >&2
	exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM
OUT=${1:-/tmp/sweep2-report.txt}
ONLY=${2:-}
#
# Отсев ведётся по имени исходника без расширения. Имя, ни с чем не сошедшееся, прошло бы
# молча: прогон пропустил бы все пары подряд и отчитался бы пустым итогом, неотличимым от
# набора без единого непокрытого заслона
#
: > "$OUT"
# пары «исходник:двоичный файл набора»
PAIRS=(
	"src/extension/extension.cpp:tests/extension/extension"
	"src/hello/hello.cpp:tests/hello/hello"
	"src/message/message.cpp:tests/message/message"
	"src/record/record.cpp:tests/record/record"
	"src/asn1/asn1.cpp:tests/asn1/asn1"
	"src/x509/x509.cpp:tests/x509/x509"
	"src/x509/signature.cpp:tests/x509/signature"
	"src/field/field.cpp:tests/field/field"
	"src/handshake/handshake.cpp:tests/handshake/handshake"
	"src/pem/pem.cpp:tests/pem/pem"
	"src/trust/trust.cpp:tests/trust/trust"
	"src/session/session.cpp:tests/session/session"
	"src/protect/protect.cpp:tests/protect/protect"
)
#
# Срок ожидания обязателен: подменённый заслон вправе оставить разбор в бесконечном
# круге, и зависший набор ничем себя не обнаружит - прогон встанет молча. Срыв по сроку
# числится покрытием: подмена, лишившая разбор остановки, - это и есть его беда
#
watch() {
	perl -e 'alarm shift; exec @ARGV' "$@"
}
for PAIR in $PAIRS; do
	SRC=$ROOT/${PAIR%%:*}
	BIN=$ROOT/build/${PAIR##*:}
	NAME=${${PAIR%%:*}:t:r}
	if [ -n "$ONLY" ] && [ "$NAME" != "$ONLY" ]; then continue; fi
	FOUND=1
	if [ ! -f "$BIN" ]; then echo "$NAME: набора нет, пропущен" | tee -a "$OUT"; continue; fi
	BAK=/tmp/sweep2-$NAME.bak
	cp "$SRC" "$BAK"
	# отказы успеха подменять бессмысленно: подмена вышла бы тождественной, и место
	# пометилось бы непокрытым ложно, отняв на пустую сверку целый прогон набора
	SITES=(${(f)"$(grep -nE 'return (error_t::|false;)' $SRC | grep -v 'return error_t::NONE;' | cut -d: -f1)"})
	TOTAL=${#SITES[@]}
	echo "=== $NAME: заслонов $TOTAL ===" | tee -a "$OUT"
	IDX=0
	for L in $SITES; do
		IDX=$((IDX+1))
		cp "$BAK" "$SRC"; touch "$SRC"
		python3 - "$SRC" "$L" <<'PY'
import sys, re
p, n = sys.argv[1], int(sys.argv[2])
lines = open(p, encoding='utf-8').read().split('\n')
line = lines[n-1]
indent = line[:len(line) - len(line.lstrip('\t'))]
body = line.strip()
# сохраняем метку переключателя, если она есть
label = ''
m = re.match(r'((?:default|case [^:]+):\s*)(return .*)$', body)
if m:
	label, body = m.group(1), m.group(2)
if body.startswith('return false'):
	body = 'return true;'
else:
	body = re.sub(r'return error_t::[A-Za-z_]+;', 'return error_t::NONE;', body)
lines[n-1] = indent + label + body
open(p, 'w', encoding='utf-8').write('\n'.join(lines))
PY
		if ! (cd $ROOT/build && watch 300 cmake --build . -j8 >/dev/null 2>&1); then
			echo "[$NAME $IDX/$TOTAL] строка $L: НЕ СОБИРАЕТСЯ" >> "$OUT"
			continue
		fi
		if ! watch 60 $BIN >/dev/null 2>&1; then
			echo "[$NAME $IDX/$TOTAL] строка $L: покрыт своим набором" >> "$OUT"
			continue
		fi
		if ! (cd $ROOT/build && watch 300 ctest >/dev/null 2>&1); then
			echo "[$NAME $IDX/$TOTAL] строка $L: покрыт чужим набором" >> "$OUT"
			continue
		fi
		WHAT=$(sed -n "${L}p" "$BAK" | sed 's/^[[:space:]]*//')
		echo "[$NAME $IDX/$TOTAL] строка $L: НЕ ПОКРЫТ -- $WHAT" | tee -a "$OUT"
	done
	cp "$BAK" "$SRC"; touch "$SRC"
	echo "... $NAME пройден" 
done
(cd $ROOT/build && cmake --build . -j8 >/dev/null 2>&1)
if [ -z "${FOUND:-}" ]; then
	echo "имя '$ONLY' ни с чем не сошлось: разбор не шёл" | tee -a "$OUT" >&2
	exit 1
fi
echo "=== ИТОГ ===" | tee -a "$OUT"
