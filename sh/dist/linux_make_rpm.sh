#!/usr/bin/env bash

##
 # Сборка пакета rpm для Linux
 #
 # Драйвер собирает раскладку установки силами build_stage.sh (два прохода
 # сборки с полным ctest в каждом) и сворачивает её утилитой rpmbuild
 # по спецификации sh/package/Linux/rpm/nts.spec. После установки ручная
 # линковка -lnts обеспечивается записью /etc/ld.so.conf.d/anyks-nts.conf
 # и вызовом ldconfig из сценариев пакета
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -a | awk '{print $1}')

# Определяем является ли операционная система Linux
if ! [ "$OS" = "Linux" ]; then
	echo "Error: Only for Linux"
	exit 1
fi

# Имя пакета (не итоговое)
readonly PACKAGE_NAME="nts"

# Каталог раскладки
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"

# Получаем текущее значение даты
readonly CURRENT_DATE=$(LC_ALL=en_US.UTF-8 date +"%a %h %d %Y")

# Адрес электронной почты
readonly PACKAGE_EMAIL="info@anyks.com"
# URL-адрес сайта
readonly PACKAGE_URL="https://anyks.com"
# Название продавца
readonly PACKAGE_DISTRIBUTION="ANYKS - NTS"
# Название приложения
readonly PACKAGE_SUMMARY="Network Transport Security"
# Описание приложения
readonly PACKAGE_DESCRIPTION="A network transport security library: TLS 1.0-1.3, DTLS 1.0-1.3, QUIC, Noise, HPKE/ECH and the crypto primitives behind them."

# Выполняем получение номера релиза
RELEASE_NUMBER="$1"
# Если номер релиза не установлен
if [ ! -n "$RELEASE_NUMBER" ]; then
	# Устанавливаем номер релиза по умолчанию
	RELEASE_NUMBER="1"
fi

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Задаём параметры сборки
SPEC_NAME="${PACKAGE_NAME}.spec"
PACKAGE_SOURCE_DIR="$ROOT/../package/Linux/rpm"
# Задаём адрес сборочной дирректории
readonly WORK_PREFIX="$SOURCE_DIR/pkg-${PACKAGE_NAME}"

# Получаем архитектуру машины
SYSTEM_ARCHITECTURE=$(uname -m)

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Создаем необходимые каталоги
mkdir -p "$WORK_PREFIX"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Копируем необходимые файлы
cp "$PACKAGE_SOURCE_DIR/$SPEC_NAME" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"

# Заполняем поля в файле спецификации необходимыми значениями
sed -i "s!@stage@!${STAGE_ROOT}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@url@!${PACKAGE_URL}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@name@!${PACKAGE_NAME}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@version@!${VERSION}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@date@!${CURRENT_DATE}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@email@!${PACKAGE_EMAIL}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@summary@!${PACKAGE_SUMMARY}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@release_number@!${RELEASE_NUMBER}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@description@!${PACKAGE_DESCRIPTION}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@architecture@!${SYSTEM_ARCHITECTURE}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@distribution@!${PACKAGE_DISTRIBUTION}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"

# Запоминаем поля каталогов в файле спецификации необходимыми значениями
sed -i "s!@root@!${ROOT}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"
sed -i "s!@prefix@!${WORK_PREFIX}!g" "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp"

# Создаем RPM пакет
rpmbuild --buildroot="$WORK_PREFIX" --target="$SYSTEM_ARCHITECTURE" --define='noclean 1' --rmspec "$PACKAGE_SOURCE_DIR/$SPEC_NAME.tmp" -bb || exit 1

# Получаем название операционной системы
OS_NAME=$(cat /etc/os-release | grep "^NAME")
OS_NAME=${OS_NAME##*=}
OS_NAME=`echo $OS_NAME | awk '{print $1}'`
VERSION_ID=$(cat /etc/os-release | grep VERSION_ID)
VERSION_ID=${VERSION_ID##*=}
OS_NAME="${OS_NAME}${VERSION_ID}"
OS_NAME=`echo "${OS_NAME//\"}"`

# Выполняем поиск созданного RPM архива
readonly PACKAGE="$SOURCE_DIR/${PACKAGE_NAME}-${VERSION}-${RELEASE_NUMBER}.${SYSTEM_ARCHITECTURE}.rpm"

# Компенсируем название архитектуры процессора
if [ "${SYSTEM_ARCHITECTURE}" = "x86_64" ]; then
	SYSTEM_ARCHITECTURE="amd64"
fi

# Если название операционной системы получено
if [ "${OS_NAME}" = "" ]; then
	mv "$PACKAGE" "$SOURCE_DIR/${PACKAGE_NAME}-${VERSION}-${RELEASE_NUMBER}.${SYSTEM_ARCHITECTURE}.rpm"
# Если название операционной системы не получено
else
	mv "$PACKAGE" "$SOURCE_DIR/${PACKAGE_NAME}-${VERSION}-${RELEASE_NUMBER}.${OS_NAME}_${SYSTEM_ARCHITECTURE}.rpm"
fi

# Очищаем сборочную дирректорию
rm -rf "$WORK_PREFIX"

# Выводим сообщение об удачной сборке
echo "Successfully created rpm package"
