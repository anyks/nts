#!/bin/sh

# Удаление библиотеки nts, поставленной пакетом macOS
#
# Сносит раскладку экосистемы anyks: заголовки, библиотеки, cmake-файлы,
# фреймворк и учётные записи приёмника пакетов. Сам каталог anyks остаётся:
# в нём лежат и другие библиотеки экосистемы

echo "Uninstall nts __VERSION__ started"

# Убираем файлы библиотеки
rm -rf /usr/local/include/anyks/nts
rm -f /usr/local/lib/anyks/libnts.a /usr/local/lib/anyks/libnts.dylib /usr/local/lib/anyks/libnts.*.dylib
rm -rf /usr/local/lib/anyks/nts.framework
rm -rf /usr/local/lib/cmake/anyks/nts
rm -f /usr/local/lib/cmake/nts
rm -rf /usr/local/share/licenses/nts
rm -f /usr/local/share/nts/uninstall.sh
rmdir /usr/local/lib/cmake/anyks /usr/local/share/nts 2> /dev/null

# Забываем поставленный пакет по его идентификатору
pkgutil --forget com.anyks.nts > /dev/null 2>&1

echo "Uninstall nts __VERSION__ finished"

exit 0
