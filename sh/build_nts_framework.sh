#!/usr/bin/env bash

set -e

# Аргументы
FRAMEWORK_NAME="$1"
BUILD_DIR="$2"
INSTALL_DIR="$3"
SOURCE_INCLUDE_DIR="$4"
LIB_FILES_INPUT="$5"
FRAMEWORK_VERSION="$6"

FRAMEWORK_PATH="${INSTALL_DIR}/${FRAMEWORK_NAME}.framework"
VERSIONS_A_PATH="${FRAMEWORK_PATH}/Versions/A"

echo "Собираем фреймворк: ${FRAMEWORK_NAME}"

# 1. Очистка
rm -rf "${FRAMEWORK_PATH}"
mkdir -p "${VERSIONS_A_PATH}/Headers"
mkdir -p "${VERSIONS_A_PATH}/Modules"
mkdir -p "${VERSIONS_A_PATH}/Resources"

# 2. Объединение библиотек
COMBINED_LIB="${VERSIONS_A_PATH}/${FRAMEWORK_NAME}"

if [ -z "$LIB_FILES_INPUT" ]; then
    echo "Ошибка: не передано ни одной библиотеки" >&2
    exit 1
fi

# Преобразуем строку в массив
read -ra LIB_ARRAY <<< "$LIB_FILES_INPUT"

echo "Объединяем ${#LIB_ARRAY[@]} библиотек(и)..."
for lib in "${LIB_ARRAY[@]}"; do
    if [ ! -f "$lib" ]; then
        echo "Ошибка: библиотека не найдена: ${lib}" >&2
        exit 1
    fi
    echo "   - ${lib}"
done

# Объединяем libtool'ом - штатное средство macOS
libtool -static -o "${COMBINED_LIB}" ${LIB_ARRAY[@]}

# 3. Заголовки
if [ -d "${SOURCE_INCLUDE_DIR}" ]; then
    cp -R "${SOURCE_INCLUDE_DIR}/"* "${VERSIONS_A_PATH}/Headers/"
fi

# 4. Зонтичный заголовок: общего nts.hpp в дереве нет, собираем перечень
#    заголовков модулей сортировкой - фреймворк подключается одним включением
UMBRELLA_HEADER="${VERSIONS_A_PATH}/Headers/${FRAMEWORK_NAME}.hpp"
{
    echo "/**"
    echo " * @file ${FRAMEWORK_NAME}.hpp"
    echo " *"
    echo " * @brief Зонтичный заголовок фреймворка ${FRAMEWORK_NAME}: включает все модули библиотеки"
    echo " *"
    echo " */"
    echo ""
    echo "#pragma once"
    echo ""
    cd "${VERSIONS_A_PATH}/Headers"
    for header in $(find . -mindepth 2 -maxdepth 2 -name '*.hpp' | sort); do
        echo "#include \"${header#./}\""
    done
    cd - > /dev/null
} > "${UMBRELLA_HEADER}"

# 5. Info.plist
cat > "${VERSIONS_A_PATH}/Resources/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.anyks.${FRAMEWORK_NAME}</string>
    <key>CFBundleName</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundleVersion</key>
    <string>${FRAMEWORK_VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${FRAMEWORK_VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
EOF

# 6. module.modulemap: каталог-зонтик вместо одиночного зонтичного заголовка -
#    заголовки библиотеки включают друг друга путями ("sys/global.hpp"), а карта
#    заголовков фреймворка мапит только плоские имена; каталог-зонтик собирает
#    модуль из всего дерева Headers
cat > "${VERSIONS_A_PATH}/Modules/module.modulemap" <<EOF
framework module ${FRAMEWORK_NAME} {
    umbrella directory "Headers"
    export *
    module * { export * }
}
EOF

# 7. Символические ссылки
cd "${FRAMEWORK_PATH}/Versions"
ln -sf A Current
cd - > /dev/null

cd "${FRAMEWORK_PATH}"
ln -sf Versions/Current/Headers Headers
ln -sf Versions/Current/Modules Modules
ln -sf Versions/Current/Resources Resources
ln -sf Versions/Current/${FRAMEWORK_NAME} ${FRAMEWORK_NAME}
cd - > /dev/null

# 8. Подпись
codesign --force --deep --sign - "${FRAMEWORK_PATH}"

echo "Фреймворк собран: ${FRAMEWORK_PATH}"
