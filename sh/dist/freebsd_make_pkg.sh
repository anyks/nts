#!/usr/bin/env bash

##
 # Сборка двоичного пакета FreeBSD и DragonFly BSD (формат pkg, устанавливается командой pkg add)
 #
 # Пакет раскладывается в /usr/local. Драйвер собирает раскладку силами
 # build_stage.sh (два прохода сборки с полным ctest в каждом).
 #
 # У DragonFly основной собиратель - gcc 8.3, код им не собрать: берётся самый
 # свежий GCC из портов (gcc11...gcc15), если CC и CXX не заданы явно.
 #
 # Сценарий установки регистрирует /usr/local/lib/anyks у загрузчика:
 # запись /etc/ld.so.conf.d/anyks-nts.conf и пересборка кеша ldconfig
 #
 # Установка: pkg add ./nts-<версия>.pkg
 ##

# Получаем корневую дирректорию
readonly ROOT=$(cd "$(dirname "$0")" && pwd)

# Корень исходников проекта
readonly SOURCE_DIR=$(cd "$ROOT/../.." && pwd)

# Получаем версию OS
readonly OS=$(uname -s)

# Определяем является ли операционная система FreeBSD или DragonFly
if ! [ "$OS" = "FreeBSD" ] && ! [ "$OS" = "DragonFly" ]; then
	echo "Error: Only for FreeBSD and DragonFly BSD"
	exit 1
fi

# Имя пакета
readonly PACKAGE_NAME="nts"
# Префикс установки пакетов
readonly PREFIX="/usr/local"

# Адрес электронной почты
readonly PACKAGE_EMAIL="info@anyks.com"
# URL-адрес сайта
readonly PACKAGE_URL="https://anyks.com"
# Краткое описание приложения
readonly PACKAGE_SUMMARY="Network Transport Security"
# Описание приложения
readonly PACKAGE_DESCRIPTION="A network transport security library: TLS 1.0-1.3, DTLS 1.0-1.3, QUIC, Noise, HPKE/ECH and the crypto primitives behind them."

# Если у DragonFly собиратель не задан, берём самый свежий GCC из портов
if [ "$OS" = "DragonFly" ] && [ -z "$CXX" ]; then
	GCC_VERSION=$(ls /usr/local/bin | sed -n 's/^g++\([0-9][0-9]*\)$/\1/p' | sort -n | tail -1)
	if [ -z "$GCC_VERSION" ]; then
		echo "Error: GCC from ports is not installed (pkg install gcc14)"
		exit 1
	fi
	export CC="/usr/local/bin/gcc$GCC_VERSION"
	export CXX="/usr/local/bin/g++$GCC_VERSION"
fi

# Получаем пакет, которому принадлежит библиотека C++ собирателя: он станет зависимостью пакета (у clang системы FreeBSD такого пакета нет)
COMPILER_PKG=""
if [ "$OS" = "DragonFly" ]; then
	COMPILER_PKG=$(pkg which -q "$("$CXX" -print-file-name=libstdc++.so)" 2> /dev/null)
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

# Перечень файлов пакета (каталоги свои помечаются @dir и удаляются вместе с пакетом;
# ссылки cmake-поиска и старших версий библиотеки - тоже содержимое пакета)
{
	(cd "$STAGE_ROOT" && find ".$PREFIX" ! -type d | sed 's!^\.!!' | sort)
	(cd "$STAGE_ROOT" && find ".$PREFIX/include/anyks" ".$PREFIX/lib/anyks" ".$PREFIX/lib/cmake" ".$PREFIX/share/licenses/$PACKAGE_NAME" -type d | sed 's!^\.!@dir !' | sort -r)
} > "$META_DIR/plist"

# Зависимость пакета от GCC, чьей библиотекой C++ пользуется библиотека
DEPS=""
if [ -n "$COMPILER_PKG" ]; then
	DEPS=$(pkg query "  \"%n\": { origin: \"%o\", version: \"%v\" }" "$COMPILER_PKG")
fi

# Манифест пакета: сценарии установки регистрируют каталог библиотек у загрузчика
cat > "$META_DIR/manifest" <<EOF
name: "$PACKAGE_NAME"
version: "$VERSION"
origin: "security/$PACKAGE_NAME"
comment: "$PACKAGE_SUMMARY"
desc: "$PACKAGE_DESCRIPTION"
www: "$PACKAGE_URL"
maintainer: "$PACKAGE_EMAIL"
prefix: "$PREFIX"
licenselogic: "single"
licenses: [ "LicenseRef-A-NTS-1.0" ]
categories: [ "security" ]
deps: {
$DEPS
}
scripts: {
  post-install: <<EOS
mkdir -p /etc/ld.so.conf.d
grep -qs "^$PREFIX/lib/anyks\$" /etc/ld.so.conf.d/anyks-$PACKAGE_NAME.conf || echo "$PREFIX/lib/anyks" > /etc/ld.so.conf.d/anyks-$PACKAGE_NAME.conf
ldconfig -R > /dev/null 2>&1 || ldconfig > /dev/null 2>&1
EOS
  pre-deinstall: <<EOS
rm -f /etc/ld.so.conf.d/anyks-$PACKAGE_NAME.conf
ldconfig -R > /dev/null 2>&1 || ldconfig > /dev/null 2>&1
EOS
}
messages: [
  { message: <<EOM
$PACKAGE_NAME $VERSION is distributed under the A-NTS License 1.0
(LicenseRef-A-NTS-1.0). The license text:

    $PREFIX/share/licenses/$PACKAGE_NAME/LICENSE
EOM
  }
]
EOF

##
 # Выполняем сборку пакета
 #
 # У DragonFly два отступления. Сжатие xz: zstd, какой pkg берёт по умолчанию, у pkg
 # DragonFly не встроен. Библиотеки GCC исключаются из требуемых: пакет GCC из портов
 # кладёт их в свой каталог (/usr/local/lib/gcc14) и в перечне предоставляемых не
 # объявляет, и pkg add отказывал в установке с "Missing shlib dependency: libgcc_s.so.1".
 # Их обеспечивает сам пакет GCC, объявленный зависимостью
 ##
if [ "$OS" = "DragonFly" ]; then
	pkg -o SHLIB_REQUIRE_IGNORE_GLOB="libgcc_s.so.*,libstdc++.so.*" create -f txz -M "$META_DIR/manifest" -p "$META_DIR/plist" -r "$STAGE_ROOT" -o "$SOURCE_DIR/" || exit 1
else
	pkg create -M "$META_DIR/manifest" -p "$META_DIR/plist" -r "$STAGE_ROOT" -o "$SOURCE_DIR/" || exit 1
fi

# Удаляем временные каталоги
rm -rf "$META_DIR"

# Получаем имя созданного пакета
readonly PKG_FILE=$(ls "$SOURCE_DIR/$PACKAGE_NAME-$VERSION".* 2> /dev/null | head -1)

# Выводим сообщение об удачной сборке
echo "Successfully created package $(basename "$PKG_FILE")"
echo "To install the library, please perform a:"
echo ""
echo "$ sudo pkg add ./$(basename "$PKG_FILE")"
echo ""
