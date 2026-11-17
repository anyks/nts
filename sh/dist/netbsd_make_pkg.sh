#!/usr/bin/env bash

##
 # Сборка двоичного пакета NetBSD (pkg_install, устанавливается командой pkg_add)
 #
 # Пакет раскладывается в /usr/pkg. Драйвер собирает раскладку силами
 # build_stage.sh (два прохода сборки с полным ctest в каждом).
 #
 # Сценарий установки дописывает /usr/pkg/lib/anyks в /etc/ld.so.conf -
 # загрузчик ld.elf_so читает этот файл без вложенных каталогов
 #
 # Установка: pkg_add ./nts-<версия>.tgz
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Определяем является ли операционная система NetBSD
if ! [ "$OS" = "NetBSD" ]; then
	echo "Error: Only for NetBSD"
	exit 1
fi

# Имя пакета
readonly PACKAGE_NAME="nts"
# Префикс установки пакетов
readonly PREFIX="/usr/pkg"

# Адрес электронной почты
readonly PACKAGE_EMAIL="info@anyks.com"
# URL-адрес сайта
readonly PACKAGE_URL="https://anyks.com"
# Краткое описание пакета
readonly PACKAGE_SUMMARY="Network Transport Security"
# Описание пакета
readonly PACKAGE_DESCRIPTION="A network transport security library: TLS 1.0-1.3, DTLS 1.0-1.3, QUIC, Noise, HPKE/ECH and the crypto primitives behind them."

# Утилита pkg_create лежит в /usr/sbin, которого нет в PATH сеанса ssh
PKG_CREATE=$(command -v pkg_create > /dev/null 2>&1 && command -v pkg_create || echo "/usr/sbin/pkg_create")

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

# Краткое описание пакета
echo "$PACKAGE_SUMMARY" > "$META_DIR/comment"
# Полное описание пакета
printf "%s\n\nLicense: LicenseRef-A-NTS-1.0, see %s/share/licenses/%s/LICENSE\nHomepage: %s\n" "$PACKAGE_DESCRIPTION" "$PREFIX" "$PACKAGE_NAME" "$PACKAGE_URL" > "$META_DIR/desc"

##
 # Сведения о сборке
 #
 # pkg_add сверяет OPSYS, OS_VERSION и MACHINE_ARCH с системой и отказывает в установке
 # пакета чужой системы. LICENSE - имя лицензии в понимании pkgsrc: при CHECK_LICENSE=yes
 # в pkg_install.conf пакет встанет, лишь если имя это внесено в ACCEPTABLE_LICENSES
 ##
cat > "$META_DIR/build-info" <<EOF
OPSYS=NetBSD
OS_VERSION=$(uname -r)
MACHINE_ARCH=$(uname -p)
PKGTOOLS_VERSION=$(/usr/sbin/pkg_admin -V)
LICENSE=a-nts-license
HOMEPAGE=$PACKAGE_URL
MAINTAINER=$PACKAGE_EMAIL
EOF

# Сообщение, выводимое при установке пакета
cat > "$META_DIR/display" <<EOF
===========================================================================
$PACKAGE_NAME $VERSION is distributed under the A-NTS License 1.0
(LicenseRef-A-NTS-1.0). The license text:

    $PREFIX/share/licenses/$PACKAGE_NAME/LICENSE
===========================================================================
EOF

# Сценарий установки: дописывает каталог библиотек экосистемы anyks в /etc/ld.so.conf
cat > "$META_DIR/install" <<'EOF'
#!/bin/sh
if [ "$2" = "POST-INSTALL" ]; then
	grep -qs "^/usr/pkg/lib/anyks$" /etc/ld.so.conf 2> /dev/null || echo "/usr/pkg/lib/anyks" >> /etc/ld.so.conf
	/sbin/ldconfig > /dev/null 2>&1
fi
exit 0
EOF
# Сценарий удаления: снимает дописанную строку из /etc/ld.so.conf
cat > "$META_DIR/deinstall" <<'EOF'
#!/bin/sh
if [ "$2" = "DEINSTALL" ]; then
	if [ -f /etc/ld.so.conf ]; then
		sed -i '' '/^\/usr\/pkg\/lib\/anyks$/d' /etc/ld.so.conf
	fi
	/sbin/ldconfig > /dev/null 2>&1
fi
exit 0
EOF

# Перечень файлов пакета (ссылки - тоже содержимое; опустевшие каталоги pkg_delete удаляет сам)
{
	echo "@name $PACKAGE_NAME-$VERSION"
	echo "@cwd $PREFIX"
	(cd "$STAGE_ROOT$PREFIX" && find . ! -type d | sed 's!^\./!!' | sort)
} > "$META_DIR/plist"

# Создаем имя архива
readonly PKG_FILE="$SOURCE_DIR/$PACKAGE_NAME-$VERSION.tgz"
# Удаляем прежний пакет
rm -f "$PKG_FILE"

# Выполняем сборку пакета
"$PKG_CREATE" \
 -B "$META_DIR/build-info" \
 -c "$META_DIR/comment" \
 -d "$META_DIR/desc" \
 -D "$META_DIR/display" \
 -i "$META_DIR/install" \
 -k "$META_DIR/deinstall" \
 -f "$META_DIR/plist" \
 -I "$PREFIX" \
 -p "$STAGE_ROOT$PREFIX" \
 -u root -g wheel \
 "$PKG_FILE" || exit 1

# Удаляем временные каталоги
rm -rf "$META_DIR"

# Выводим сообщение об удачной сборке
echo "Successfully created package $(basename "$PKG_FILE")"
echo "To install the library, please perform a:"
echo ""
echo "$ sudo pkg_add ./$(basename "$PKG_FILE")"
echo ""
