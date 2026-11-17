#!/usr/bin/env bash

##
 # Раскладка установки A-NTS для системных пакетов
 #
 # Делает два прохода сборки в Release: сначала динамическую библиотеку
 # (-DCMAKE_SHARED_BUILD_LIB=YES), затем статическую. После каждого прохода
 # гоняется полный ctest - упаковка начинается только на зелёных тестах.
 # Установка идёт штатным cmake --install в раскладку экосистемы anyks:
 #   <префикс>/include/anyks/nts      - заголовки
 #   <префикс>/lib/anyks              - libnts.so/.dylib + libnts.a
 #   <префикс>/lib/cmake/nts          - ntsConfig / ntsTargets / ntsConfigVersion
 #   <префикс>/lib/cmake/anyks/nts     - ссылка ../nts экосистемного поддерева
 #   <префикс>/lib/anyks/nts.framework - фреймворк (только macOS)
 #   <префикс>/share/licenses/nts     - текст лицензии
 # Под Solaris библиотеки ставятся в lib/amd64/anyks силами самого CMake.
 #
 # Вызов: build_stage.sh <каталог-раскладки>
 # Раскладка собирается как <каталог>/<префикс>/...; префикс выбирается
 # по системе запуска: /usr у Linux и Solaris, /usr/pkg у NetBSD,
 # /usr/local у macOS, FreeBSD, DragonFly и OpenBSD.
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Имя пакета (не итоговое)
readonly PACKAGE_NAME="nts"

# Каталог раскладки
STAGE_ROOT="${1:-}"

if [ -z "$STAGE_ROOT" ]; then
	echo "Error: stage directory is required"
	echo "Usage: build_stage.sh <stage-directory>"
	exit 1
fi

# Количество ядер для сборки
NUMPROC=1

# Префикс установки: у Windows раскладка без префикса - установщик кладёт её в Program Files
PREFIX="/"

##
 # Параметры системы: префикс установки и число ядер
 #
 # Окружения MSYS2: MINGW64 и UCRT64 (gcc x86-64), CLANG64 (clang x86-64),
 # CLANGARM64 (clang ARM64) дают uname вида MINGW64_NT-*
 ##
case "$OS" in
	Linux)
		PREFIX="/usr"
		NUMPROC=$(nproc)
	;;
	MINGW64_*|UCRT64_*|CLANG64_*|CLANGARM64_*|MSYS_*|CYGWIN_*)
		NUMPROC=$(nproc)
	;;
	Darwin)
		PREFIX="/usr/local"
		NUMPROC=$(sysctl -n hw.logicalcpu)
	;;
	FreeBSD|OpenBSD)
		PREFIX="/usr/local"
		NUMPROC=$(sysctl -n hw.ncpu)
	;;
	DragonFly)
		PREFIX="/usr/local"
		NUMPROC=$(sysctl -n hw.ncpu)
		# Основной собиратель системы (gcc 8.3) код не осиливает, берём самый свежий GCC из портов
		if [ -z "$CXX" ]; then
			GCC_VERSION=$(ls /usr/local/bin | sed -n 's/^g++\([0-9][0-9]*\)$/\1/p' | sort -n | tail -1)
			if [ -z "$GCC_VERSION" ]; then
				echo "Error: GCC from ports is not installed (pkg install gcc14)"
				exit 1
			fi
			export CC="/usr/local/bin/gcc$GCC_VERSION"
			export CXX="/usr/local/bin/g++$GCC_VERSION"
		fi
	;;
	NetBSD)
		PREFIX="/usr/pkg"
		# Утилита sysctl лежит в /sbin, которого нет в PATH сеанса ssh
		NUMPROC=$(/sbin/sysctl -n hw.ncpu)
	;;
	SunOS)
		PREFIX="/usr"
		NUMPROC=$(psrinfo | wc -l | tr -d " ")
		# Собираем 64-разрядную библиотеку
		export CC="gcc -m64"
	;;
	*)
		echo "Error: Operating system \"$OS\" is not supported"
		exit 1
	;;
esac

# Каталог библиотек раскладки: под Solaris 64-битные библиотеки живут в lib/amd64
if [ "$OS" = "SunOS" ]; then
	LIB_DIR="lib/amd64/anyks"
else
	LIB_DIR="lib/anyks"
fi

# Получаем версию проекта из главного файла CMake
readonly VERSION=$(sed -n 's/^project(nts VERSION \([0-9.]*\) LANGUAGES.*/\1/p' "$SOURCE_DIR/CMakeLists.txt" | head -1)
if [ -z "$VERSION" ]; then
	echo "Error: project version is not found in CMakeLists.txt"
	exit 1
fi

# Каталоги двух проходов сборки
readonly BUILD_SHARED_DIR="$SOURCE_DIR/build-pkg-shared"
readonly BUILD_STATIC_DIR="$SOURCE_DIR/build-pkg-static"

# Каталог раскладки с префиксом системы
readonly STAGE="$STAGE_ROOT$PREFIX"

# Очистка каталогов прошлой сборки
rm -rf "$STAGE_ROOT" "$BUILD_SHARED_DIR" "$BUILD_STATIC_DIR" || exit 1

# Выполняем создание временного каталога
mkdir -p "$STAGE" || exit 1

##
 # Первый проход: динамическая библиотека
 #
 # Экспорт цели nts::nts берётся из этого прохода: потребители find_package(nts)
 # линкуются с libnts.so/.dylib, статическая библиотека ставится рядом для
 # ручной линковки
 ##
cmake -S "$SOURCE_DIR" -B "$BUILD_SHARED_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_TESTS=ON -DCMAKE_SHARED_BUILD_LIB=YES $NTS_CMAKE_ARGS || exit 1

cmake --build "$BUILD_SHARED_DIR" -j "$NUMPROC" || exit 1

# Гоняем полный набор тестов динамической библиотеки
if ! (cd "$BUILD_SHARED_DIR" && ctest --output-on-failure); then
	echo "Error: shared library tests are failed"
	exit 1
fi

# Устанавливаем динамическую библиотеку с заголовками и cmake-файлами
cmake --install "$BUILD_SHARED_DIR" --prefix "$STAGE" || exit 1

##
 # Второй проход: статическая библиотека
 #
 # Из прохода берутся libnts.a и, под macOS, фреймворк: он собирается
 # объединением статических библиотек
 ##
cmake -S "$SOURCE_DIR" -B "$BUILD_STATIC_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_TESTS=ON $NTS_CMAKE_ARGS || exit 1

cmake --build "$BUILD_STATIC_DIR" -j "$NUMPROC" || exit 1

# Гоняем полный набор тестов статической библиотеки
if ! (cd "$BUILD_STATIC_DIR" && ctest --output-on-failure); then
	echo "Error: static library tests are failed"
	exit 1
fi

# Копируем собранную статическую библиотеку в раскладку
STATIC_LIB=$(find "$BUILD_STATIC_DIR" -name "lib$PACKAGE_NAME.a" -type f | head -1)
if [ -z "$STATIC_LIB" ]; then
	echo "Error: static library lib$PACKAGE_NAME.a is not found"
	exit 1
fi
cp "$STATIC_LIB" "$STAGE/$LIB_DIR/" || exit 1

# Под macOS собираем и кладём фреймворк с зонтичным заголовком
if [ "$OS" = "Darwin" ]; then
	cmake --build "$BUILD_STATIC_DIR" --target framework || exit 1
	cp -R "$BUILD_STATIC_DIR/dist/$PACKAGE_NAME.framework" "$STAGE/$LIB_DIR/" || exit 1
fi

# Копируем текст лицензии в раскладку
mkdir -p "$STAGE/share/licenses/$PACKAGE_NAME" || exit 1
cp "$SOURCE_DIR/LICENSE" "$STAGE/share/licenses/$PACKAGE_NAME/" || exit 1

# Удаляем сборочные каталоги
rm -rf "$BUILD_SHARED_DIR" "$BUILD_STATIC_DIR"

# Выставляем права доступа
find "$STAGE_ROOT" -type d -exec chmod 755 {} \;
find "$STAGE_ROOT" -type f -exec chmod 644 {} \;
find "$STAGE/$LIB_DIR" -type f -name "*.so*" -exec chmod 755 {} \;
find "$STAGE/$LIB_DIR" -type f -name "*.dylib*" -exec chmod 755 {} \;
find "$STAGE/$LIB_DIR" -type f -name "*.a" -exec chmod 644 {} \;
if [ "$OS" = "Darwin" ]; then
	chmod 755 "$STAGE/$LIB_DIR/$PACKAGE_NAME.framework/Versions/A/$PACKAGE_NAME"
fi

# Выводим сообщение об удачной сборке раскладки
echo "Successfully created stage layout in $STAGE_ROOT"
echo "Prefix: $PREFIX, version: $VERSION"
