#!/usr/bin/env bash

##
 # Сборка архива tar.gz для любой системы, кроме MS Windows
 #
 # Архив несёт ту же раскладку, что и пакет системы: заголовки, статическую и
 # динамическую библиотеки, cmake-файлы для find_package(nts), фреймворк (macOS)
 # и текст лицензии. Пути внутри архива отсчитываются от корня, и после
 # распаковки в / библиотеку находит find_package(nts) так же, как после
 # установки пакета:
 #
 #   $ sudo tar --no-same-owner -xzf nts_<версия>_<система>_<архитектура>.tar.gz -C /
 #
 # Ключ --no-same-owner (его понимают GNU tar, bsdtar и BusyBox) отдаёт файлы
 # тому, кто распаковывает, - root, - каким бы ни был владелец, записанный
 # в архиве.
 #
 # Перед упаковкой гоняется полный ctest в обоих проходах сборки - см.
 # build_stage.sh
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Имя пакета
readonly PACKAGE_NAME="nts"

# Название системы в имени архива и префикс установки (тот же выбор, что в build_stage.sh)
OS_NAME="$OS"
PREFIX="/usr/local"
case "$OS" in
	Linux)
		PREFIX="/usr"
		# Название берётся у самой системы вместе с версией (Ubuntu24.10, Alpine3.24.1)
		OS_NAME=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"' | awk '{print $1}')
		OS_NAME="${OS_NAME}$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')"
	;;
	Darwin)
		OS_NAME="MacOSX"
	;;
	NetBSD)
		PREFIX="/usr/pkg"
	;;
	SunOS)
		PREFIX="/usr"
		# Solaris и illumos (OpenIndiana) различаются по uname -v
		if uname -v | grep -q "illumos"; then
			OS_NAME="illumos"
		else
			OS_NAME="Solaris"
		fi
	;;
esac

# Получаем архитектуру машины
SYSTEM_ARCHITECTURE=$(uname -m)
# У NetBSD `uname -m` называет порт платы (evbarm - и 32-, и 64-разрядный ARM), а набор команд - `uname -p` (aarch64)
if [ "$OS" = "NetBSD" ]; then
	case "$SYSTEM_ARCHITECTURE" in
		evb*) SYSTEM_ARCHITECTURE=$(uname -p);;
	esac
fi
if [ "$SYSTEM_ARCHITECTURE" = "x86_64" ] || [ "$SYSTEM_ARCHITECTURE" = "i86pc" ]; then
	SYSTEM_ARCHITECTURE="amd64"
fi

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Каталог раскладки и имя архива
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"
readonly ARCH_NAME="${PACKAGE_NAME}_${VERSION}_${OS_NAME}_${SYSTEM_ARCHITECTURE}.tar.gz"

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

##
 # Перечень содержимого архива
 #
 # В архив идут файлы, ссылки и собственные каталоги библиотеки, но не каталоги
 # системы (/usr, /usr/local, /usr/local/lib и другие): распакованные от имени
 # root, их записи переписали бы права и владельца уже существующих каталогов,
 # а у macOS /usr/local нередко принадлежит пользователю
 ##
cd "$STAGE_ROOT" || exit 1
{
	find . ! -type d
	find ".$PREFIX/include/anyks" ".$PREFIX/lib/anyks" ".$PREFIX/share/licenses/$PACKAGE_NAME" -type d
} | sed 's!^\./!!' | sort > "$SOURCE_DIR/${PACKAGE_NAME}_tar.list"

##
 # Выполняем создание архива
 #
 # Владельцем файлов в архиве пишется root, где tar это умеет: bsdtar (macOS,
 # FreeBSD, DragonFly, NetBSD, OpenIndiana) и GNU tar. BusyBox (Alpine, OpenWRT)
 # и tar OpenBSD пишут владельцем собиравшего, и распакованные без
 # --no-same-owner файлы достались бы ему
 ##
if [ "$OS" = "Linux" ] || [ "$OS" = "SunOS" ]; then
	ROOT_GROUP="root"
else
	ROOT_GROUP="wheel"
fi
TAR_OUT="$SOURCE_DIR/$ARCH_NAME"
TAR_LIST="$SOURCE_DIR/${PACKAGE_NAME}_tar.list"
# Утилита bsdtar: отдельной командой (FreeBSD, DragonFly, macOS, OpenIndiana) либо под именем tar (NetBSD)
BSDTAR=""
if command -v bsdtar > /dev/null 2>&1; then
	BSDTAR="bsdtar"
elif tar --version 2> /dev/null | grep -q "bsdtar"; then
	BSDTAR="tar"
fi
if [ -n "$BSDTAR" ]; then
	$BSDTAR --uid 0 --gid 0 --uname root --gname "$ROOT_GROUP" -n -czf "$TAR_OUT" -T "$TAR_LIST" || exit 1
elif command -v gtar > /dev/null 2>&1; then
	gtar --owner=root:0 --group="$ROOT_GROUP":0 --no-recursion -czf "$TAR_OUT" -T "$TAR_LIST" || exit 1
elif tar --version 2> /dev/null | grep -q "GNU tar"; then
	tar --owner=root:0 --group="$ROOT_GROUP":0 --no-recursion -czf "$TAR_OUT" -T "$TAR_LIST" || exit 1
else
	# Ключа отказа от обхода каталогов у этих tar нет: передаются одни файлы, каталоги
	# распаковка создаёт сама, иначе содержимое каталогов легло бы в архив повторно
	tar -cf - $(for f in $(cat "$TAR_LIST"); do [ -d "$f" ] && [ ! -L "$f" ] || echo "$f"; done) | gzip -9 > "$TAR_OUT" || exit 1
fi
rm -f "$TAR_LIST"

# Переходим в корневой каталог обратно
cd "$SOURCE_DIR" || exit 1

# Раскладка не сносится: её берут драйверы .adn и .pkg

# Выводим сообщение об удачной сборке
echo "Successfully created archive $ARCH_NAME"
echo "To install the library, please perform a:"
echo ""
# Родной tar Solaris и illumos ключа --no-same-owner не знает, там распаковывает GNU tar
if [ "$OS" = "SunOS" ]; then
	echo "$ sudo gtar --no-same-owner -xzf $ARCH_NAME -C /"
# У tar OpenBSD ключа --no-same-owner нет, а владельца он восстанавливает только по ключу -p
elif [ "$OS" = "OpenBSD" ]; then
	echo "$ doas tar -xzf $ARCH_NAME -C /"
else
	echo "$ sudo tar --no-same-owner -xzf $ARCH_NAME -C /"
fi
echo ""
