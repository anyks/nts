#!/usr/bin/env bash

set -e

# Аргументы
SOURCE_DIR="$1"
BUILD_ROOT="$2"
OUTPUT_PATH="$3"
DEPLOYMENT_TARGET="$4"

# Каталоги сборки двух срезов
DEVICE_DIR="${BUILD_ROOT}/device"
SIMULATOR_DIR="${BUILD_ROOT}/simulator"

echo "Собираем XCFramework: nts"

# Семплы и тесты в срезы не входят: исполняемые файлы консольного вида на
# устройстве iOS не запускаются, срезу нужна лишь библиотека и фреймворк
SAMPLE_OPTS=$(grep -oE 'option\((CMAKE_BUILD_[A-Z_]*SAMPLE)' "${SOURCE_DIR}/CMakeLists.txt" | cut -d'(' -f2 | sed 's/$/=OFF/' | tr '\n' ' ')

# 1. Срез устройства
echo "Срез устройства (iphoneos, arm64)..."
cmake -S "${SOURCE_DIR}" -B "${DEVICE_DIR}" \
    -DCMAKE_SYSTEM_NAME=IOS \
    -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
    -DCMAKE_BUILD_TESTS=OFF ${SAMPLE_OPTS} > /dev/null
cmake --build "${DEVICE_DIR}" --target framework -j"$(sysctl -n hw.ncpu)" > /dev/null

# 2. Срез симулятора: два изделия - arm64 для машин Apple Silicon и x86_64
#    для симуляторов на Intel
echo "Срез симулятора (iphonesimulator, arm64 и x86_64)..."
cmake -S "${SOURCE_DIR}" -B "${SIMULATOR_DIR}" \
    -DCMAKE_SYSTEM_NAME=IOS \
    -DCMAKE_OSX_SYSROOT=iphonesimulator \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
    -DCMAKE_BUILD_TESTS=OFF ${SAMPLE_OPTS} > /dev/null
cmake --build "${SIMULATOR_DIR}" --target framework -j"$(sysctl -n hw.ncpu)" > /dev/null

# 3. Сборка XCFramework из двух фреймворков
rm -rf "${OUTPUT_PATH}"
xcodebuild -create-xcframework \
    -framework "${DEVICE_DIR}/dist/nts.framework" \
    -framework "${SIMULATOR_DIR}/dist/nts.framework" \
    -output "${OUTPUT_PATH}"

echo "XCFramework собран: ${OUTPUT_PATH}"
