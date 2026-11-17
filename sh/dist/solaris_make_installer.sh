#!/usr/bin/env bash

##
 # Сборка пакета p5p для Solaris и illumos (IPS, устанавливается командой pkg install -g)
 #
 # Драйвер собирает раскладку установки силами build_stage.sh (два прохода
 # сборки с полным ctest в каждом; под Solaris библиотеки ставятся в
 # /usr/lib/amd64/anyks и собираются 64-разрядным gcc), затем гонит цепочку
 # IPS: pkgsend generate -> pkgmogrify -> pkgdepend -> pkglint -> pkgrepo ->
 # pkgsend publish -> pkgsign -> pkgrecv -a.
 #
 # Сценарий postinstall ставится в пакет и расширяет путь 64-битного
 # загрузчика (crle -64) каталогом /usr/lib/amd64/anyks
 #
 # Установка: pkg install -g ./nts_<версия>-1_<архитектура>.p5p nts
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -a | awk '{print $1}')

# Определяем является ли операционная система Solaris или illumos
if ! [ "$OS" = "SunOS" ]; then
	echo "Error: Only for Solaris"
	exit 1
fi

# Статус конвейера манифестов: отказ pkgsend или pkgfmt рвёт цепочку сборки
set -o pipefail

# Имя пакета
readonly PACKAGE_NAME="nts"

# Издатель пакета
readonly PACKAGE_PUBLISHER="anyks"

# Краткое описание пакета
readonly PACKAGE_SUMMARY="Network Transport Security"
# Описание пакета
readonly PACKAGE_DESCRIPTION="A network transport security library: TLS 1.0-1.3, DTLS 1.0-1.3, QUIC, Noise, HPKE/ECH and the crypto primitives behind them."

# Каталог раскладки
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"
# Каталог манифестов
readonly MANIFEST_PREFIX="$SOURCE_DIR/${PACKAGE_NAME}_manifest"

# Собираем раскладку двумя проходами с полным ctest (64-разрядный gcc задаёт сам драйвер)
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Получаем мажорное значение версии
readonly VERSION_P=$(echo "$VERSION" | awk -F '\\.' '{print $1}')
# Получаем минорное значение версии
readonly VERSION_U=$(echo "$VERSION" | awk -F '\\.' '{print $2}')
# Получаем релизное значение версии
readonly VERSION_R=$(echo "$VERSION" | awk -F '\\.' '{print $3}')

# Получаем архитектуру процессора
SYSTEM_ARCHITECTURE=$(uname -p)
if [ "$SYSTEM_ARCHITECTURE" = "i386" ]; then
	SYSTEM_ARCHITECTURE="amd64"
fi

# Создаём название пакета установки
readonly PKG_NAME="${PACKAGE_NAME}_${VERSION}-1_${SYSTEM_ARCHITECTURE}.p5p"

# Копируем каталог со сценарием последующей установки
mkdir -p "$STAGE_ROOT/usr/sbin" || exit 1
cp "$ROOT/../package/Solaris/postinstall" "$STAGE_ROOT/usr/sbin/postinstall-$PACKAGE_NAME" || exit 1
chmod 755 "$STAGE_ROOT/usr/sbin/postinstall-$PACKAGE_NAME"

# Выполняем удаление директории для хранения манифестов
rm -rf "$MANIFEST_PREFIX"

# Создаем директории для хранения манифестов
mkdir -p "$MANIFEST_PREFIX" || exit 1

# Генерируем Manifest файл
pkgsend generate "$STAGE_ROOT" | pkgfmt > "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m.1" || exit 1

# Создаём файл информационных данных
touch "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Формируем имя пакета и издателя
echo "set name=pkg.fmri value=$PACKAGE_NAME@$VERSION" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Формируем название пакета
echo "set name=pkg.summary value=\"$PACKAGE_SUMMARY\"" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Формируем описание пакета
echo "set name=pkg.description value=\"$PACKAGE_DESCRIPTION\"" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Добавляем человекочитаемое значение версии пакета
echo "set name=pkg.human-version value=\"P$VERSION_P-u$VERSION_U-r$VERSION_R\"" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Формируем название архитектуры процессора
echo "set name=variant.arch value=\$(ARCH)" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Формируем категорию размещения пакета
echo "set name=info.classification value=\"org.opensolaris.category.2008:System/Libraries\"" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Выполняем установку лицензии: pkg показывает её командой pkg info --license и требует принять при установке
echo "license usr/share/licenses/$PACKAGE_NAME/LICENSE license=LicenseRef-A-NTS-1.0 must-display=true must-accept=true" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Удаляем из манифеста системные каталоги - они уже есть в системе
echo "<transform dir path=usr\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
echo "<transform dir path=usr/sbin\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
echo "<transform dir path=usr/share\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
echo "<transform dir path=usr/include\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
echo "<transform dir path=usr/lib\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
echo "<transform dir path=usr/lib/amd64\$ -> drop>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"
# Выполняем изменение прав доступа на исполняемый сценарий
echo "<transform file path=usr/sbin/postinstall-$PACKAGE_NAME -> edit mode (0?644|0?755|644|755) 0555>" >> "$MANIFEST_PREFIX/$PACKAGE_NAME.mog"

# Комбинируем наш манифест с информационным файлом
pkgmogrify -DARCH=$(uname -p) "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m.1" "$MANIFEST_PREFIX/$PACKAGE_NAME.mog" | pkgfmt > "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m.2" || exit 1
# Выполняем генерацию итогового значения манифеста
pkgdepend generate -md "$STAGE_ROOT" "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m.2" | pkgfmt > "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m" || exit 1

# Выполняем резолвинг сгенерированного манифеста
pkgdepend resolve -m "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m" || exit 1

# Проверяем соответствие зависимостям
pkglint "$MANIFEST_PREFIX/$PACKAGE_NAME.p5m.res" || exit 1

# Выполняем создание репозитория под проект
pkgrepo create "$MANIFEST_PREFIX/$PACKAGE_NAME-repository" || exit 1

# Переходим в каталог с репозиторием
cd "$MANIFEST_PREFIX" || exit 1

# Выполняем установку автора репозитория
pkgrepo -s "$PACKAGE_NAME-repository" set publisher/prefix="$PACKAGE_PUBLISHER" || exit 1
# Выполняем публикацию проекта в репозитории
pkgsend -s "$PACKAGE_NAME-repository" publish -d "$STAGE_ROOT" "$PACKAGE_NAME.p5m.res" || exit 1

# Проверяем созданный репозиторий. Отчёт об отсутствии зависимостей
# (system/library и родня) для одиночного пакета - норма: системные пакеты
# приходят из образа Solaris при установке, их в локальном репозитории нет,
# поэтому отказ проверки сборку не останавливает
pkgrepo verify -s "$PACKAGE_NAME-repository"
# Выводим список пакетов в репозитории
pkgrepo list -s "$PACKAGE_NAME-repository"

# Выполняем подпись репозитория
pkgsign -s "$PACKAGE_NAME-repository" -a sha256 '*' || exit 1

# Выполняем генерацию пакета установки
pkgrecv -s "$PACKAGE_NAME-repository" -a -d "$SOURCE_DIR/$PKG_NAME" "$PACKAGE_NAME" || exit 1

# Возвращаемся в корень проекта
cd "$SOURCE_DIR" || exit 1

# Очищаем каталог манифестов
rm -rf "$MANIFEST_PREFIX"

# Выводим сообщение об удачной сборке
echo "Successfully created package $PKG_NAME"
echo "To install the library, please perform a:"
echo ""
echo "$ sudo pkg install -g ./$PKG_NAME $PACKAGE_NAME"
echo ""
