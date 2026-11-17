#!/usr/bin/env bash

##
 # Сборка пакета apk для Alpine Linux (устанавливается командой apk add)
 #
 # Пакет собирается командой apk mkpkg из apk-tools 3 в формате v3. Драйвер
 # собирает раскладку установки силами build_stage.sh (два прохода сборки
 # с полным ctest в каждом) и сворачивает её из каталога раскладки.
 #
 # Загрузчик musl у Alpine не читает /etc/ld.so.conf: сценарий установки
 # дописывает /usr/lib/anyks в файл путей загрузчика
 # /etc/ld-musl-<архитектура>.path, если тот существует.
 #
 # Пакет не подписан: apk ставит его с ключом --allow-untrusted
 #
 # Установка: apk add --allow-untrusted ./nts-<версия>-r<выпуск>.apk
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Определяем является ли операционная система Linux
if ! [ "$OS" = "Linux" ]; then
	echo "Error: Only for Linux (Alpine)"
	exit 1
fi

# Определяем является ли система пакетов apk
if ! command -v apk > /dev/null 2>&1; then
	echo "Error: apk package manager is not found"
	exit 1
fi

##
 # Проба команды mkpkg у apk
 #
 # Справки утилита не несёт, потому пробуется настоящая сборка пробного пакета
 ##
has_mkpkg(){
	local probe=$(mktemp -d)
	mkdir -p "$probe/root" || return 1
	env LD_LIBRARY_PATH="$2" "$1" mkpkg -I "name:probe" -I "version:0-r0" -F "$probe/root" -o "$probe/probe.apk" > /dev/null 2>&1
	local rc=$?
	rm -rf "$probe"
	[ $rc -eq 0 ]
}

##
 # Выбор apk с командой mkpkg
 #
 # Системный apk Alpine несёт mkpkg, урезанный apk OpenWrt - нет; тогда берётся
 # полный apk-tools, собранный прежде (тур Danube оставил /root/Work/danube_
 # apk-tools на стенде). Готовый apk задаётся и явно: APK=/путь/к/apk.
 # Выводит две строки: путь к apk и каталог его библиотек (пустой у системного)
 ##
find_apk(){
	# Если apk указан явно
	if [ -n "$APK" ]; then
		has_mkpkg "$APK" "" && printf "%s\n\n" "$APK"
		return
	fi
	# Если системный apk умеет mkpkg (Alpine)
	if has_mkpkg "$(command -v apk)" ""; then
		printf "%s\n\n" "$(command -v apk)"
		return
	fi
	# Если полный apk-tools уже собран прежним туром на стенде
	if [ -x "/root/Work/danube_apk-tools/src/apk" ] && has_mkpkg "/root/Work/danube_apk-tools/src/apk" "/root/Work/danube_apk-tools/src"; then
		printf "%s\n%s\n" "/root/Work/danube_apk-tools/src/apk" "/root/Work/danube_apk-tools/src"
	fi
}

# Разрешаем инструмент упаковки
readonly APK_BIN=$(find_apk | sed -n '1p')
# Разрешаем каталог библиотек инструмента
readonly APK_LIBS=$(find_apk | sed -n '2p')
# Если полный apk-tools не найден
if [ -z "$APK_BIN" ]; then
	echo "Error: apk with mkpkg is not found, set APK=/path/to/apk"
	exit 1
fi

# Имя пакета
readonly PACKAGE_NAME="nts"

# Адрес электронной почты
readonly PACKAGE_EMAIL="info@anyks.com"
# URL-адрес сайта
readonly PACKAGE_URL="https://anyks.com"
# Описание приложения
readonly PACKAGE_DESCRIPTION="NTS - network transport security library"

# Выполняем получение номера релиза
RELEASE_NUMBER="$1"
# Если номер релиза не установлен
if [ ! -n "$RELEASE_NUMBER" ]; then
	# Устанавливаем номер релиза по умолчанию
	RELEASE_NUMBER="1"
fi

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

##
 # Зависимости пакета - пакеты, которым принадлежат библиотеки, нужные нашей
 #
 # Имена их у систем разные, потому они спрашиваются у самой системы,
 # а не пишутся списком
 ##
DEPENDENCIES=""
for lib in $(ldd "$STAGE_ROOT/usr/lib/anyks/lib$PACKAGE_NAME.so" 2> /dev/null | awk '/=>/ {print $3} !/=>/ && /^\t\// {print $1}' | sort -u); do
	# Получаем пакет, которому принадлежит библиотека (путь ld-musl вида /lib/ld-musl-x86_64.so.1 тоже учитывается)
	owner=$(apk info --who-owns "$(readlink -f "$lib")" 2> /dev/null | sed -n 's/.* is owned by \(.*\)-[^-]*-r[0-9]*$/\1/p')
	if [ -z "$owner" ]; then
		owner=$(apk info --who-owns "$lib" 2> /dev/null | sed -n 's/.* is owned by \(.*\)-[^-]*-r[0-9]*$/\1/p')
	fi
	if [ -n "$owner" ] && ! echo " $DEPENDENCIES " | grep -q " $owner "; then
		echo "Add dependent package: $owner ($lib)"
		DEPENDENCIES="$DEPENDENCIES $owner"
	fi
done
DEPENDENCIES=$(echo $DEPENDENCIES)

# Сценарий установки: дописывает каталог библиотек экосистемы anyks в файл
# путей загрузчика musl - /etc/ld.so.conf.d он не читает
cat > "$META_DIR/post-install" <<EOF
#!/bin/sh
for path_file in /etc/ld-musl-*.path; do
	[ -f "\$path_file" ] || continue
	case ":\$(cat "\$path_file"):" in
		*:/usr/lib/anyks:*) ;;
		*) echo ":/usr/lib/anyks" >> "\$path_file" ;;
	esac
done
echo "$PACKAGE_NAME $VERSION is distributed under the A-NTS License 1.0 (LicenseRef-A-NTS-1.0)."
echo "The license text: /usr/share/licenses/$PACKAGE_NAME/LICENSE"
exit 0
EOF

# Сценарий удаления: снимает дописанный каталог библиотек из файла путей
cat > "$META_DIR/pre-deinstall" <<EOF
#!/bin/sh
for path_file in /etc/ld-musl-*.path; do
	[ -f "\$path_file" ] || continue
	sed -i 's#:/usr/lib/anyks##g; s#/usr/lib/anyks:##g' "\$path_file"
done
exit 0
EOF

# Получаем архитектуру пакетов системы
readonly SYSTEM_ARCHITECTURE=$(apk --print-arch)

# Создаем имя пакета
readonly PKG_FILE="$SOURCE_DIR/${PACKAGE_NAME}-${VERSION}-r${RELEASE_NUMBER}.apk"
# Удаляем прежний пакет
rm -f "$PKG_FILE"

# Выполняем сборку пакета полным apk-tools (системный apk OpenWrt урезан)
env LD_LIBRARY_PATH="$APK_LIBS" "$APK_BIN" mkpkg \
 --info "name:$PACKAGE_NAME" \
 --info "version:$VERSION-r$RELEASE_NUMBER" \
 --info "description:$PACKAGE_DESCRIPTION" \
 --info "arch:$SYSTEM_ARCHITECTURE" \
 --info "license:LicenseRef-A-NTS-1.0" \
 --info "origin:$PACKAGE_NAME" \
 --info "maintainer:ANYKS <$PACKAGE_EMAIL>" \
 --info "url:$PACKAGE_URL" \
 --info "depends:$DEPENDENCIES" \
 --script "post-install:$META_DIR/post-install" \
 --script "pre-deinstall:$META_DIR/pre-deinstall" \
 --files "$STAGE_ROOT" \
 --output "$PKG_FILE" || exit 1

# Удаляем временные каталоги
rm -rf "$META_DIR"

# Выводим сообщение об удачной сборке
echo "Successfully created package $(basename "$PKG_FILE")"
echo "To install the library, please perform a:"
echo ""
echo "$ apk add --allow-untrusted ./$(basename "$PKG_FILE")"
echo ""
