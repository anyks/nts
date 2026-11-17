#!/usr/bin/env bash

##
 # Сборка установщика install.exe для Windows (Inno Setup)
 #
 # Драйвер работает в окружении MSYS2 (MINGW64/UCRT64/CLANG64/CLANGARM64):
 # собирает раскладку силами build_stage.sh (два прохода сборки с полным
 # ctest в каждом; dll кладётся в bin, статическая и импортная библиотеки -
 # в lib/anyks, cmake-файлы - в lib/cmake/{anyks/nts, nts} копией), берёт
 # библиотеки времени исполнения собирателя по зависимостям dll и
 # компилирует установщик утилитой iscc по сценарию
 # sh/package/Windows/install.iss.
 #
 # Установщик кладёт раскладку в Program Files\anyks\nts и добавляет каталог
 # bin с dll в PATH (ChangesEnvironment)
 #
 # Сборка установщика: bash sh/dist/windows_make_installer.sh [iscc-путь]
 # Установка: SetupNts-<версия>-<архитектура>.exe
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
OS=$(uname -a | awk '{print $1}')

# Компенсируем название OS Windows
# Окружения MSYS2: MINGW64 и UCRT64 (gcc x86-64), CLANG64 (clang x86-64), CLANGARM64 (clang ARM64)
if [[ $OS =~ ^(MINGW64|UCRT64|CLANG64|CLANGARM64|MSYS)_NT ]]; then
	OS="Windows"
fi

# Определяем является ли операционная система Microsoft Windows
if ! [ "$OS" = "Windows" ]; then
	echo "Error: Only for Windows"
	exit 1
fi

# Имя пакета (не итоговое)
readonly PACKAGE_NAME="nts"

# Каталоги сборки установщика
readonly SETUP_DIR="$SOURCE_DIR/${PACKAGE_NAME}_setup"
readonly INSTALLER_DIR="$SOURCE_DIR/${PACKAGE_NAME}_installer"
readonly STAGE_ROOT="$SOURCE_DIR/${PACKAGE_NAME}_dist"

# Поиск утилиты компиляции установщика Inno Setup
ISCC_BIN="${1:-}"
if [ -z "$ISCC_BIN" ]; then
	for cand in "/c/Program Files/Inno Setup 7/ISCC.exe" "/c/Program Files (x86)/Inno Setup 7/ISCC.exe" "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" "/c/Program Files/Inno Setup 6/ISCC.exe"; do
		if [ -f "$cand" ]; then
			ISCC_BIN="$cand"
			break
		fi
	done
fi
if [ -z "$ISCC_BIN" ]; then
	ISCC_BIN=$(command -v iscc 2> /dev/null)
fi
if [ -z "$ISCC_BIN" ]; then
	echo "Error: Inno Setup compiler (iscc) is not found; pass its path as the first argument"
	exit 1
fi

# Архитектура установщика и суффикс имени по окружению MSYS2
case "$(uname -a | awk '{print $1}')" in
	CLANGARM64_*)
		ARCH="arm64"
		SUFFIX="-arm64"
	;;
	*)
		ARCH="x64compatible"
		SUFFIX="-x64"
	;;
esac

# Собираем раскладку двумя проходами с полным ctest
bash "$ROOT/build_stage.sh" "$STAGE_ROOT" || exit 1

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)

# Очищаем каталоги прошлой сборки
rm -rf "$SETUP_DIR" "$INSTALLER_DIR"

# Создаём каталоги сборки установщика
mkdir -p "$SETUP_DIR/stage" "$INSTALLER_DIR" || exit 1

# Копируем раскладку установщика целиком
cp -R "$STAGE_ROOT/." "$SETUP_DIR/stage/" || exit 1

##
 # Библиотеки времени исполнения собирателя
 #
 # Зависимости dll спрашиваются у самой системы: у MinGW это libstdc++-6.dll,
 # libgcc_s_seh-1.dll и libwinpthread-1.dll, у MSVC таких нет - статические
 # библиотеки времени исполнения у него вшиты
 ##
if [ -f "$SETUP_DIR/stage/bin/lib$PACKAGE_NAME.dll" ]; then
	for lib in $(ldd "$SETUP_DIR/stage/bin/lib$PACKAGE_NAME.dll" 2> /dev/null | awk '/=>/ {print $3}' | sort -u); do
		case "$lib" in
			*/windows/system*|/c/WINDOWS/*) continue;;
		esac
		if [ -f "$lib" ]; then
			echo "Add runtime library: $(basename "$lib")"
			cp "$lib" "$SETUP_DIR/stage/bin/" || exit 1
		fi
	done
fi

# Копируем текст лицензии для окна принятия условий
cp "$SOURCE_DIR/LICENSE" "$SETUP_DIR/LICENSE.txt" || exit 1

# Копируем сценарий установщика
cp "$ROOT/../package/Windows/install.iss" "$SETUP_DIR/install.iss" || exit 1

# Заполняем поля сценария установщика значениями пакета
# Внутри .iss пути обязаны быть Windows-видными: cygpath -m даёт их с прямыми слэшами,
# которые Inno Setup понимает
SETUP_WIN=$(cygpath -m "$SETUP_DIR" 2> /dev/null || echo "$SETUP_DIR")
INSTALLER_WIN=$(cygpath -m "$INSTALLER_DIR" 2> /dev/null || echo "$INSTALLER_DIR")
sed -i "s|@version@|${VERSION}|g" "$SETUP_DIR/install.iss"
sed -i "s|@pwd@|${SETUP_WIN}|g" "$SETUP_DIR/install.iss"
sed -i "s|@installerDir@|${INSTALLER_WIN}|g" "$SETUP_DIR/install.iss"
sed -i "s|@arch@|${ARCH}|g" "$SETUP_DIR/install.iss"
sed -i "s|@suffix@|${SUFFIX}|g" "$SETUP_DIR/install.iss"

# Компилируем установщик
"$ISCC_BIN" "$SETUP_DIR/install.iss" > /dev/null || exit 1

# Очищаем каталог сборки установщика
rm -rf "$SETUP_DIR"

# Получаем имя созданного установщика
readonly EXE_FILE=$(ls "$INSTALLER_DIR"/Setup*.exe 2> /dev/null | head -1)

# Выводим сообщение об удачной сборке
echo "Successfully created installer $(basename "$EXE_FILE")"
echo "To install the library, please run the installer and then use:"
echo ""
echo "cmake -DCMAKE_PREFIX_PATH=\"C:/Program Files/anyks/nts\" ..."
echo ""
