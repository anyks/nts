#!/usr/bin/env bash

##
 # Сборка пакета deb для Linux
 #
 # Драйвер собирает раскладку установки силами build_stage.sh (два прохода
 # сборки с полным ctest в каждом), накрывает её каталогом DEBIAN
 # (control, copyright, postinst, postrm) и сворачивает утилитой dpkg-deb.
 # После установки ручная линковка -lnts обеспечивается записью
 # /etc/ld.so.conf.d/anyks-nts.conf и вызовом ldconfig из postinst
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -a | awk '{print $1}')

# Определяем является ли операционная система Linux
if ! [ $OS = "Linux" ]; then
	echo "Error: Only for Linux"
	exit 1
fi

# Имя пакета (не итоговое)
readonly PACKAGE_NAME="nts"

# Каталог раскладки
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"

# Выполняем получение номера релиза
RELEASE_NUMBER="$1"
# Если номер релиза не установлен
if [ ! -n "$RELEASE_NUMBER" ]; then
	# Устанавливаем номер релиза по умолчанию
	RELEASE_NUMBER="1"
fi

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Задаем необходимые параметры
WORK_PREFIX="$SOURCE_DIR/pkg-${PACKAGE_NAME}"
PACKAGE_SOURCE_DIR="$ROOT/../package/Linux/deb"
PACKAGE_DEST_DIR="$WORK_PREFIX/DEBIAN"
CONTROL_NAME="control"

# Получаем архитектуру машины
SYSTEM_ARCHITECTURE=$(dpkg --print-architecture)

# Получаем имя ОС
OS_NAME=$(cat /etc/os-release | grep VERSION_CODENAME)
OS_NAME=${OS_NAME##*=}

# Получаем версию библиотеки пакета
get_lib_version () {
	local LIB_VER=$(dpkg -s $1 2> /dev/null | grep '^Version: ')
	LIB_VER=${LIB_VER%-*}
	LIB_VER=${LIB_VER:9}

	echo "$LIB_VER"
}

# Получаем список нужных нам библиотек
readonly DEPENDENCIES_LIST=$(cat "$PACKAGE_SOURCE_DIR/dependent_pkg")

# Список зависимостей
DEPENDENCIES=""
# Проходим в цикле по списку и добавляем в зависимость
for pkg in $DEPENDENCIES_LIST; do
	echo "Check dependent package: ${pkg}"
	LIB_VER=$(get_lib_version ${pkg})
	# Если библиотека используется в данной ОС, то добавляем в зависимость пакета
	if ! [ "${LIB_VER}" = "" ]; then
		echo "Add dependent package: ${pkg}"
		if [ "$DEPENDENCIES" = "" ]; then
			DEPENDENCIES="${pkg} (>= ${LIB_VER})"
		else
			DEPENDENCIES="$DEPENDENCIES, ${pkg} (>= ${LIB_VER})"
		fi
	fi
done

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Копируем раскладку экосистемы anyks в сборочный каталог пакета
rm -rf "$WORK_PREFIX"
cp -a "$STAGE_ROOT/usr" "$WORK_PREFIX" || exit 1

# Копируем лицензию: по правилам Debian она лежит в /usr/share/doc/<пакет>/copyright
mkdir -p "$WORK_PREFIX/usr/share/doc/$PACKAGE_NAME" || exit 1
cp "$SOURCE_DIR/LICENSE" "$WORK_PREFIX/usr/share/doc/$PACKAGE_NAME/copyright" || exit 1

# Создаем директории для сборки deb пакета
mkdir -p "$PACKAGE_DEST_DIR" || exit 1

# Копируем в нее все необходимые файлы
# /DEBIAN/control
cp "$PACKAGE_SOURCE_DIR/$CONTROL_NAME" "$PACKAGE_DEST_DIR" || exit 1
# /DEBIAN/copyright
cp "$PACKAGE_SOURCE_DIR/copyright" "$PACKAGE_DEST_DIR" || exit 1
# /DEBIAN/postinst
cp "$PACKAGE_SOURCE_DIR/postinst" "$PACKAGE_DEST_DIR" || exit 1
# /DEBIAN/postrm
cp "$PACKAGE_SOURCE_DIR/postrm" "$PACKAGE_DEST_DIR" || exit 1

# Делаем сценарии пакета исполняемыми
chmod 755 "$PACKAGE_DEST_DIR/postinst" "$PACKAGE_DEST_DIR/postrm"

# Определяем размер установленного пакета
size=$(du -s -k "$WORK_PREFIX")
size=${size//[^0-9]/}

# Заполняем поля в файле control необходимыми значениями
sed -i "s%@version@%${VERSION}-${RELEASE_NUMBER}%g" "$PACKAGE_DEST_DIR/$CONTROL_NAME"
sed -i "s%@package@%${PACKAGE_NAME}%g" "$PACKAGE_DEST_DIR/$CONTROL_NAME"
sed -i "s%@architecture@%${SYSTEM_ARCHITECTURE}%g" "$PACKAGE_DEST_DIR/$CONTROL_NAME"
sed -i "s%@dependencies@%${DEPENDENCIES}%g" "$PACKAGE_DEST_DIR/$CONTROL_NAME"
sed -i "s%@size@%${size}%g" "$PACKAGE_DEST_DIR/$CONTROL_NAME"

# Подсчитываем контрольные суммы файлов пакета
(cd "$WORK_PREFIX" && find . -type f ! -path "./DEBIAN/*" -exec md5sum {} \; > "DEBIAN/md5sums")

# Создаем deb пакет
fakeroot dpkg-deb --build "$WORK_PREFIX" || exit 1

# Устанавливаем имя deb пакета foo_VVV-RRR_AAA.deb
if [ "${OS_NAME}" = "" ]; then
	deb_name="${PACKAGE_NAME}_${VERSION}-${RELEASE_NUMBER}_${SYSTEM_ARCHITECTURE}.deb"
else
	deb_name="${PACKAGE_NAME}_${VERSION}-${RELEASE_NUMBER}~${OS_NAME}_${SYSTEM_ARCHITECTURE}.deb"
fi
mv "${WORK_PREFIX}.deb" "$SOURCE_DIR/$deb_name" || exit 1

# Очищаем сборочную директорию
rm -rf "$WORK_PREFIX"

# Выводим сообщение об удачной сборке
echo "Successfully created package $deb_name"
