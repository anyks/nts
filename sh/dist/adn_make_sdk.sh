#!/bin/bash
# Сборка SDK-контейнера .adn из раскладки A-NTS: раскладка -> контейнер -> три меры.
# Вызов: adn_make_sdk.sh <каталог-раскладки> <каталог-вывода> [имя-контейнера]
# Имя по умолчанию - basename каталога-раскладки. Контейнер ложится как <вывод>/<имя>.adn.
# Раскладку готовит sh/dist/build_stage.sh (или распаковка tar.gz архива).
#
# Три меры (рецепт Danube, цикл 3.2.0+):
#   1. DIAGNOSTIC = OK 100%;
#   2. обратная распаковка - число файлов равно числу файлов раскладки;
#   3. md5 модуля до сборки == md5 модуля после обратной распаковки.
# Жёсткие ворота - меры 1 и 3; число файлов сообщается и сверяется.
#
# Ловушки оснастки:
#   - INTRACT -dest это КАТАЛОГ, а не файл: контейнер пишется как <dest>/<name>.adn.
#   - SDK собирается БЕЗ пароля (ключевые контейнеры открываются ключами получателей).
#   - модуль ищется по имени: у macOS-фреймворка он внутри Versions/A, у Unix - lib/anyks.
#   - EXTRACT возвращает rc=0 и на отказе (битая ссылка): мерим последствие, не код возврата.
DAN="/Users/forman/Work/GIT/crisper/danube2/build-rel/dan"

LAYOUT="${1:-}"
OUTDIR="${2:-}"
NAME="${3:-}"

if [ -z "$LAYOUT" ] || [ -z "$OUTDIR" ]; then
	echo "adn_make_sdk: отказ - нужны каталог-раскладки и каталог-вывода"
	echo "вызов: adn_make_sdk.sh <раскладка> <вывод> [имя]"
	exit 2
fi
if [ ! -d "$LAYOUT" ]; then
	echo "adn_make_sdk: отказ - раскладка не каталог: $LAYOUT"
	exit 2
fi
if [ ! -x "$DAN" ]; then
	echo "adn_make_sdk: отказ - нет исполняемого dan: $DAN"
	exit 2
fi
LAYOUT=$(cd "$LAYOUT" && pwd)
[ -n "$NAME" ] || NAME=$(basename "$LAYOUT")
mkdir -p "$OUTDIR" || { echo "adn_make_sdk: отказ - каталог-вывод не создан"; exit 2; }
OUTDIR=$(cd "$OUTDIR" && pwd)

# Ищем модуль библиотеки: двоичный файл SDK. Приоритет - фреймворк macOS,
# затем dylib/so с суффиксами старших версий.
MODULE=""
for cand in \
	"usr/local/lib/anyks/nts.framework/Versions/A/nts" \
	"usr/local/lib/anyks/libnts.dylib" \
	"usr/local/lib/anyks/libnts.so" \
	"usr/local/lib/anyks/libnts.so.1" \
	"usr/lib/anyks/libnts.so" \
	"usr/lib/anyks/libnts.so.1" \
	"usr/lib/amd64/anyks/libnts.so" \
	"usr/lib/amd64/anyks/libnts.so.1" \
	"usr/pkg/lib/anyks/libnts.so" \
	"usr/pkg/lib/anyks/libnts.so.1"; do
	if [ -f "$LAYOUT/$cand" ]; then
		MODULE="$cand"
		break
	fi
done
# Запасной поиск: любое libnts.* в дереве раскладки. Импорт-либы Windows
# (.dll.a/.lib) и статику (.a) исключаем: модуль - .dll/.so/.dylib.
if [ -z "$MODULE" ]; then
	MODULE=$(cd "$LAYOUT" && find . -type f -name 'libnts.*' ! -name '*.dll.a' ! -name '*.lib' ! -name '*.a' | sed 's#^\./##' | head -1)
fi
if [ -z "$MODULE" ] || [ ! -f "$LAYOUT/$MODULE" ]; then
	echo "adn_make_sdk: отказ - модуль библиотеки не найден в раскладке $LAYOUT"
	exit 3
fi
MD5_BEFORE=$(md5 -q "$LAYOUT/$MODULE" 2>/dev/null || md5sum "$LAYOUT/$MODULE" | awk '{print $1}')
echo "adn_make_sdk: раскладка=$LAYOUT"
echo "adn_make_sdk: модуль=$MODULE md5=$MD5_BEFORE"

# Число файлов раскладки - ожидание меры 2 (служебные .DS_Store не считаем)
EXPECT=$(cd "$LAYOUT" && find . -type f ! -name '.DS_Store' | wc -l | tr -d ' ')

# Временный каталог обратной распаковки - свой, сносим по завершении
VERIFY=$(mktemp -d "${TMPDIR:-/tmp}/nts_adn_verify.XXXXXX")
cleanup(){ rm -rf "$VERIFY"; }
trap cleanup EXIT

# Сборка контейнера: -dest каталог, имя задаёт -name, пароль не передаём
echo "adn_make_sdk: INTRACT name=$NAME workers=0 (без пароля)"
"$DAN" -method INTRACT -name "$NAME" -src "$LAYOUT" -dest "$OUTDIR" -workers 0 > "$VERIFY/intract.log" 2>&1
CONT="$OUTDIR/$NAME.adn"
if [ ! -f "$CONT" ]; then
	echo "adn_make_sdk: отказ - контейнер не собран: $CONT"
	tail -6 "$VERIFY/intract.log"
	exit 4
fi

# Мера 1: DIAGNOSTIC обязан ответить OK 100%
DIAG=$("$DAN" -method DIAGNOSTIC -danube "$CONT" 2>&1)
if ! printf '%s' "$DIAG" | grep -aq 'OK' || ! printf '%s' "$DIAG" | grep -aq '100%'; then
	echo "adn_make_sdk: отказ - DIAGNOSTIC не OK 100%"
	printf '%s\n' "$DIAG" | grep -a 'status\|Error\|error' | head -4
	exit 5
fi
echo "adn_make_sdk: мера 1 DIAGNOSTIC = OK 100%"

# Мера 2: обратная распаковка, число файлов равно раскладке (мерим последствие, не rc)
"$DAN" -method EXTRACT -danube "$CONT" -dest "$VERIFY" > "$VERIFY/extract.log" 2>&1
FILES=$(find "$VERIFY" -type f ! -name 'intract.log' ! -name 'extract.log' | wc -l | tr -d ' ')
echo "adn_make_sdk: мера 2 обратная распаковка = $FILES файлов (раскладка $EXPECT)"
if [ "$FILES" != "$EXPECT" ]; then
	echo "adn_make_sdk: отказ - распаковано $FILES файлов, в раскладке $EXPECT"
	tail -6 "$VERIFY/extract.log"
	exit 6
fi

# Мера 3: md5 модуля после распаковки == md5 до сборки
if [ ! -f "$VERIFY/$MODULE" ]; then
	echo "adn_make_sdk: отказ - модуль не распакован: $MODULE (битая ссылка?)"
	exit 7
fi
MD5_AFTER=$(md5 -q "$VERIFY/$MODULE" 2>/dev/null || md5sum "$VERIFY/$MODULE" | awk '{print $1}')
if [ "$MD5_BEFORE" != "$MD5_AFTER" ]; then
	echo "adn_make_sdk: отказ - md5 модуля разошёлся: до=$MD5_BEFORE после=$MD5_AFTER"
	exit 8
fi
echo "adn_make_sdk: мера 3 md5 модуля до==после = $MD5_AFTER"

SIZE=$(stat -f%z "$CONT" 2>/dev/null || stat -c%s "$CONT")
CMD5=$(md5 -q "$CONT" 2>/dev/null || md5sum "$CONT" | awk '{print $1}')
echo "adn_make_sdk: ГОТОВО $CONT"
echo "adn_make_sdk: размер=$SIZE md5=$CMD5 файлов=$FILES"
exit 0
