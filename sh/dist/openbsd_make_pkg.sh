#!/usr/bin/env bash

##
 # Сборка двоичного пакета OpenBSD (устанавливается командой pkg_add)
 #
 # Пакет раскладывается в /usr/local. Драйвер собирает раскладку силами
 # build_stage.sh (два прохода сборки с полным ctest в каждом).
 #
 # Сценарий установки ставит ссылку soname библиотеки в /usr/local/lib:
 # конфигурации /etc/ld.so.conf у загрузчика OpenBSD нет, каталоги поиска
 # фиксированы, и библиотека экосистемы добирается до них ссылкой
 #
 # Установка: doas pkg_add -D unsigned ./nts-<версия>.tgz
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Определяем является ли операционная система OpenBSD
if ! [ "$OS" = "OpenBSD" ]; then
	echo "Error: Only for OpenBSD"
	exit 1
fi

# Имя пакета
readonly PACKAGE_NAME="nts"
# Префикс установки пакетов
readonly PREFIX="/usr/local"

# Адрес электронной почты
readonly PACKAGE_EMAIL="info@anyks.com"
# URL-адрес сайта
readonly PACKAGE_URL="https://anyks.com"
# Краткое описание пакета
readonly PACKAGE_SUMMARY="Network Transport Security"
# Описание пакета
readonly PACKAGE_DESCRIPTION="A network transport security library: TLS 1.0-1.3, DTLS 1.0-1.3, QUIC, Noise, HPKE/ECH and the crypto primitives behind them."

# Каталог раскладки
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"
# Каталог служебных файлов пакета
readonly META_DIR="$SOURCE_DIR/${PACKAGE_NAME}_meta"

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Очищаем каталог служебных файлов
rm -rf "$META_DIR"
mkdir -p "$META_DIR" || exit 1

# Полное описание пакета
printf "%s\n\nLicense: LicenseRef-A-NTS-1.0, see %s/share/licenses/%s/LICENSE\nHomepage: %s\n" "$PACKAGE_DESCRIPTION" "$PREFIX" "$PACKAGE_NAME" "$PACKAGE_URL" > "$META_DIR/desc"

# Сообщение, выводимое при установке пакета
cat > "$META_DIR/display" <<EOF
$PACKAGE_NAME $VERSION is distributed under the A-NTS License 1.0
(LicenseRef-A-NTS-1.0). The license text:

    $PREFIX/share/licenses/$PACKAGE_NAME/LICENSE
EOF

##
 # Приведение общей библиотеки к виду OpenBSD
 #
 # У OpenBSD общая библиотека зовётся libимя.so.старшая.младшая: pkg_create
 # отвергает трёхциферное имя и теряется в лишних кандидатах libимя.so.* -
 # файл переименовывается к двухциферному имени, ссылки soname и имени
 # разработчика убираются. Ссылки не нужны: загрузчик сам дорезолвит имя
 # soname по старшей цифре, а ключ -lnts берёт единственный файл
 ##
readonly SHARED_MAJOR=$(echo "$VERSION" | awk -F '\\.' '{print $1}')
readonly SHARED_VERSION="$SHARED_MAJOR.$(echo "$VERSION" | awk -F '\\.' '{print $2}')"
LIB_FULL=$(cd "$STAGE_ROOT$PREFIX/lib/anyks" && find . -maxdepth 1 -name "lib$PACKAGE_NAME.so.*" ! -type l | sed 's!^\./!!' | sort | tail -1)
if [ -z "$LIB_FULL" ]; then
	echo "Error: shared library lib$PACKAGE_NAME.so.* is not found"
	exit 1
fi
# Переименовываем файл с полным номером версии к двухциферному имени OpenBSD
mv "$STAGE_ROOT$PREFIX/lib/anyks/$LIB_FULL" "$STAGE_ROOT$PREFIX/lib/anyks/lib$PACKAGE_NAME.so.$SHARED_VERSION" || exit 1
# Убираем ссылки прежних имён: pkg_create требует единственный кандидат libимя.so.*
find "$STAGE_ROOT$PREFIX/lib/anyks" -maxdepth 1 -type l -name "lib$PACKAGE_NAME.so*" -exec rm -f {} +
# Правим имя библиотеки в файлах CMake раскладки
for f in "$STAGE_ROOT$PREFIX/lib/cmake/$PACKAGE_NAME/"*.cmake; do
	sed -i "s/lib$PACKAGE_NAME.so.$VERSION/lib$PACKAGE_NAME.so.$SHARED_VERSION/g" "$f"
done
readonly SHARED_LIB="lib$PACKAGE_NAME.so.$SHARED_VERSION"

##
 # Перечень файлов пакета
 #
 # Динамическая библиотека помечается @lib с номером подстановкой
 # ${LIBимя_VERSION} - pkg_create отвергает номер, записанный числом. Свои
 # каталоги пишутся с косой чертой на конце и удаляются вместе с пакетом.
 # Ссылка экосистемного псевдонима cmake-каталога пишется обычной записью
 # и упаковывается как ссылка, а не каталог. Библиотека лежит вне путей
 # поиска по умолчанию: ссылка soname в каталоге по умолчанию ставится
 # командой @exec-add и снимается @unexec-delete (конфигурации /etc/ld.so.conf
 # у загрузчика OpenBSD нет)
 ##
{
	echo "@comment \$OpenBSD\$"
	echo "@lib lib/anyks/lib$PACKAGE_NAME.so.\${LIB${PACKAGE_NAME}_VERSION}"
	(cd "$STAGE_ROOT$PREFIX" && find "include/anyks" "lib/anyks" "lib/cmake" "share/licenses/$PACKAGE_NAME" ! -name "$SHARED_LIB" | sort | while read -r f; do
		if [ -d "$f" ] && [ ! -L "$f" ]; then echo "$f/"; else echo "$f"; fi
	done)
	echo "@exec-add ln -fhs %D/lib/anyks/$SHARED_LIB %D/lib/lib$PACKAGE_NAME.so.$SHARED_MAJOR || true"
	echo "@unexec-delete rm -f %D/lib/lib$PACKAGE_NAME.so.$SHARED_MAJOR || true"
} > "$META_DIR/plist"

# Создаем имя архива
readonly PKG_FILE="$SOURCE_DIR/$PACKAGE_NAME-$VERSION.tgz"
# Удаляем прежний пакет
rm -f "$PKG_FILE"

# Выполняем сборку пакета
pkg_create \
 -A "$(uname -m)" \
 -d "$META_DIR/desc" \
 -D COMMENT="$PACKAGE_SUMMARY" \
 -D FULLPKGPATH="security/$PACKAGE_NAME" \
 -D PORTSDIR="/usr/ports" \
 -D HOMEPAGE="$PACKAGE_URL" \
 -D MAINTAINER="ANYKS <$PACKAGE_EMAIL>" \
 -D LIB${PACKAGE_NAME}_VERSION="$SHARED_VERSION" \
 -M "$META_DIR/display" \
 -B "$STAGE_ROOT" \
 -f "$META_DIR/plist" \
 -p "$PREFIX" \
 "$PKG_FILE" || exit 1

# Удаляем временные каталоги
rm -rf "$META_DIR"

# Выводим сообщение об удачной сборке
echo "Successfully created package $(basename "$PKG_FILE")"
echo "To install the library, please perform a:"
echo ""
echo "$ doas pkg_add -D unsigned ./$(basename "$PKG_FILE")"
echo ""
