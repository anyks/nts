#!/usr/bin/env bash

##
 # Сборка установочного пакета .pkg для macOS
 #
 # Драйвер собирает раскладку установки силами build_stage.sh (два прохода
 # сборки с полным ctest в каждом), накрывает её метаданными установщика
 # (Distribution, welcome/conclusion, postinstall, uninstall) и сворачивает
 # цепочкой pkgbuild + productbuild в дистрибутив
 # nts-macos-installer-<архитектура>-<версия>.pkg
 #
 # Идентификатор пакета com.anyks.nts, зонтичный заголовок фреймворка nts.hpp.
 # Подпись и нотаризация продуктом не занимаются: подписывает владелец
 # командой productsign при выпуске релиза
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Определяем является ли операционная система macOS
if ! [ "$OS" = "Darwin" ]; then
	echo "Error: Only for macOS"
	exit 1
fi

# Имя пакета (не итоговое)
readonly PACKAGE_NAME="nts"

# Идентификатор пакета
readonly PACKAGE_ID="com.anyks.nts"

# Получаем архитектуру машины
readonly SYSTEM_ARCHITECTURE=$(uname -m)

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Итоговое имя пакета
readonly PKG_NAME="${PACKAGE_NAME}-macos-installer-${SYSTEM_ARCHITECTURE}-${VERSION}.pkg"

# Каталоги работы
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"
readonly TARGET_DIR="$SOURCE_DIR/${PACKAGE_NAME}_pkg_target"
readonly PACKAGE_SOURCE_DIR="$ROOT/../package/MacOS"

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Очищаем целевой каталог прошлой сборки
rm -rf "$TARGET_DIR" || exit 1

# Создаём целевой каталог
mkdir -p "$TARGET_DIR/package" "$TARGET_DIR/pkg" || exit 1

# Копируем метаданные установщика в целевой каталог
cp -R "$PACKAGE_SOURCE_DIR/darwin" "$TARGET_DIR/" || exit 1
chmod -R 755 "$TARGET_DIR/darwin/scripts" "$TARGET_DIR/darwin/Resources" || exit 1
chmod 755 "$TARGET_DIR/darwin/Distribution" || exit 1

# Заполняем поля метаданных значениями продукта
sed -i '' -e "s/__VERSION__/${VERSION}/g" "$TARGET_DIR/darwin/scripts/postinstall"
sed -i '' -e "s/__VERSION__/${VERSION}/g" -e "s/__PRODUCT__/${PACKAGE_NAME}/g" "$TARGET_DIR/darwin/Resources/uninstall.sh"
sed -i '' -e "s/__VERSION__/${VERSION}/g" -e "s/__PRODUCT__/${PACKAGE_NAME}/g" "$TARGET_DIR/darwin/Distribution"
sed -i '' -e "s/__VERSION__/${VERSION}/g" -e "s/__PRODUCT__/${PACKAGE_NAME}/g" "$TARGET_DIR/darwin/Resources/welcome.html"
sed -i '' -e "s/__VERSION__/${VERSION}/g" -e "s/__PRODUCT__/${PACKAGE_NAME}/g" "$TARGET_DIR/darwin/Resources/conclusion.html"

# Текст лицензии для окна принятия условий установщика
cp "$SOURCE_DIR/LICENSE" "$TARGET_DIR/darwin/Resources/LICENSE.txt" || exit 1

# Сценарий удаления ложится в раскладку рядом с лицензиями
mkdir -p "$STAGE_ROOT/usr/local/share/$PACKAGE_NAME" || exit 1
cp "$TARGET_DIR/darwin/Resources/uninstall.sh" "$STAGE_ROOT/usr/local/share/$PACKAGE_NAME/" || exit 1
chmod 755 "$STAGE_ROOT/usr/local/share/$PACKAGE_NAME/uninstall.sh"

##
 # Собираем внутренний пакет из раскладки
 #
 # Корень пакета - сама раскладка с префиксом /usr/local, сценарии -
 # postinstall проверки ссылки поиска find_package(nts)
 ##
pkgbuild \
 --identifier "$PACKAGE_ID" \
 --version "$VERSION" \
 --scripts "$TARGET_DIR/darwin/scripts" \
 --root "$STAGE_ROOT" \
 "$TARGET_DIR/package/${PACKAGE_NAME}.pkg" > /dev/null 2>&1 || exit 1

# Собираем дистрибутив установщика из внутреннего пакета
productbuild \
 --distribution "$TARGET_DIR/darwin/Distribution" \
 --resources "$TARGET_DIR/darwin/Resources" \
 --package-path "$TARGET_DIR/package" \
 "$SOURCE_DIR/$PKG_NAME" > /dev/null 2>&1 || exit 1

# Очищаем целевой каталог сборки
rm -rf "$TARGET_DIR"

# Выводим сообщение об удачной сборке
echo "Successfully created $PKG_NAME"
echo "To install the library, please perform a:"
echo ""
echo "$ sudo installer -pkg $PKG_NAME -target /"
echo ""
