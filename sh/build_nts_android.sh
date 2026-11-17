#!/usr/bin/env bash

set -e

# Аргументы
SOURCE_DIR="$1"
BUILD_ROOT="$2"
OUTPUT_PATH="$3"
PLATFORM="$4"
LIBRARY_VERSION="$5"

# Путь к NDK: переменные ANDROID_NDK либо ANDROID_NDK_HOME, либо каталог по умолчанию brew
if [ -n "${ANDROID_NDK:-}" ] && [ -d "${ANDROID_NDK}" ]; then
    NDK_DIR="${ANDROID_NDK}"
elif [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "${ANDROID_NDK_HOME}" ]; then
    NDK_DIR="${ANDROID_NDK_HOME}"
elif [ -d "/opt/homebrew/share/android-ndk" ]; then
    NDK_DIR="/opt/homebrew/share/android-ndk"
else
    echo "Ошибка: NDK не найден - задайте ANDROID_NDK или ANDROID_NDK_HOME" >&2
    exit 1
fi

TOOLCHAIN="${NDK_DIR}/build/cmake/android.toolchain.cmake"

# Изделия: 64-разрядные устройство и эмулятор. 32-разрядные изделия Android
# архитектурно исключены - арифметика библиотеки требует машинного слова в 64
# разряда (static_assert в src/math/number.cpp), 32-разрядных устройств в
# обороте Google Play с 2019 года нет
ABIS=("arm64-v8a" "x86_64")

echo "Собираем AAR: nts (${PLATFORM})"

# Семплы и тесты в срезы не входят
SAMPLE_OPTS=$(grep -oE 'option\((CMAKE_BUILD_[A-Z_]*SAMPLE)' "${SOURCE_DIR}/CMakeLists.txt" | cut -d'(' -f2 | sed 's/$/=OFF/' | tr '\n' ' ')

# 1. Сборка статической библиотеки по каждому изделию
for ABI in "${ABIS[@]}"; do
    echo "Изделие ${ABI}..."
    cmake -S "${SOURCE_DIR}" -B "${BUILD_ROOT}/${ABI}" \
        -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
        -DANDROID_ABI="${ABI}" \
        -DANDROID_PLATFORM="${PLATFORM}" \
        -DCMAKE_BUILD_TESTS=OFF ${SAMPLE_OPTS} > /dev/null
    cmake --build "${BUILD_ROOT}/${ABI}" --target nts -j"$(sysctl -n hw.ncpu)" > /dev/null
done

# 2. Сборка пакета prefab: заголовки, библиотеки изделий и описания
STAGE="${BUILD_ROOT}/prefab"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/prefab/modules/nts/include"

# Заголовки одним деревом
cp -R "${SOURCE_DIR}/include/"* "${STAGE}/prefab/modules/nts/include/"

# Библиотеки по изделиям
for ABI in "${ABIS[@]}"; do
    mkdir -p "${STAGE}/prefab/modules/nts/libs/${ABI}"
    cp "${BUILD_ROOT}/${ABI}/libnts.a" "${STAGE}/prefab/modules/nts/libs/${ABI}/"
done

# Описание модуля prefab: статическая библиотека nts, потребитель получает nts::nts
cat > "${STAGE}/prefab/modules/nts/module.json" <<EOF
{
    "name": "nts",
    "version": "${LIBRARY_VERSION}",
    "dependencies": [],
    "export": {
        "include_dirs": ["include"]
    },
    "library": {
        "static": "libs/arm64-v8a/libnts.a"
    }
}
EOF

# Описание пакета prefab
cat > "${STAGE}/prefab/prefab.json" <<EOF
{
    "name": "nts",
    "schema_version": 2,
    "version": "${LIBRARY_VERSION}",
    "dependencies": [],
    "modules": ["nts"]
}
EOF

# Манифест пакета
cat > "${STAGE}/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.anyks.nts" />
EOF

# 3. Упаковка AAR
rm -rf "${OUTPUT_PATH}"
mkdir -p "$(dirname "${OUTPUT_PATH}")"
(cd "${STAGE}" && zip -q -r "${OUTPUT_PATH}" AndroidManifest.xml prefab)

echo "AAR собран: ${OUTPUT_PATH}"
