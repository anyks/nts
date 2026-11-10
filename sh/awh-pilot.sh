#!/usr/bin/env bash

##
 # Приёмка пилотного встраивания A-NTS потребителем AWH по образцу ног парка
 #
 # Запуск из корня выгрузки anyks-tls на принимаемом хэше:
 #   sh/awh-pilot.sh [РАБОЧИЙ_КАТАЛОГ] [--tests]
 #
 # Шаги: сборка Release с установкой, сторонний потребитель через find_package(nts
 # CONFIG) с лупбеком TLS 1.3 на профиле AWH и проверкой хранилища тайн; ключ --tests
 # добавляет полный ctest. Итог печатается строкой образца ног:
 #   успех=N расхождение=0 зависание=0 падение=0
 #
 # РАБОЧИЙ_КАТАЛОГ по умолчанию - /tmp/awh-pilot-<хэш>; исходник берётся из каталога
 # скрипта, сборка и установка в рабочий каталог дерева не пишут
 ##

# Корневая дирректория выгрузки anyks-tls
readonly SOURCE=$(cd "$(dirname "$0")/.." && pwd)

# Рабочий каталог по умолчанию
readonly DEFWORK=/tmp

# Счёт успешных шагов приёмки
OK=0
# Счёт расхождений приёмки
DIFF=0
# Счёт зависаний приёмки
HANG=0
# Счёт падений приёмки
FALL=0

# Рабочий каталог приёмки
WORK=$DEFWORK
# Признак прогона полного набора проверок
TESTS=0

##
 # Разбор доводов запуска: первый довод - рабочий каталог, ключ --tests - полный ctest
 ##
for arg in "$@"; do
	# Если запрошен полный набор проверок
	if [ "$arg" = "--tests" ]; then
		# Запоминаем признак прогона проверок
		TESTS=1
	# Иначе довод задаёт рабочий каталог
	else
		# Запоминаем рабочий каталог
		WORK=$arg
	fi
done

# Если git в выгрузке не найден
if ! git -C "$SOURCE" rev-parse HEAD >/dev/null 2>&1; then
	# Выводим сообщение об отказе и выходим
	echo "$SOURCE is not a git checkout"
	exit 2
fi

# Принимаемый хэш выгрузки
readonly HASH=$(git -C "$SOURCE" rev-parse --short HEAD)

# Полный путь рабочего каталога приёмки
WORK=$WORK/awh-pilot-$HASH

# Готовим рабочий каталог приёмки
mkdir -p "$WORK" || exit 2

# Каталог установки пакета
readonly PREFIX=$WORK/prefix

# Выводим заголовок приёмки
echo "== awh-pilot: hash $HASH, work $WORK"

##
 # Шаг 1: сборка библиотеки Release с установкой
 ##
echo "-- step 1: build + install (Release)"
# Если настройка или сборка либо установка не прошли
if ! cmake -S "$SOURCE" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null ||
   ! cmake --build "$WORK/build" >/dev/null ||
   ! cmake --install "$WORK/build" >/dev/null; then
	# Отмечаем падение сборки
	FALL=$((FALL + 1))
	# Выводим итог приёмки и выходим
	echo "успех=$OK расхождение=$DIFF зависание=$HANG падение=$FALL"
	exit 1
fi
# Отмечаем успешную сборку с установкой
OK=$((OK + 1))

##
 # Шаг 2: сторонний потребитель через find_package с лупбеком на профиле AWH
 ##
echo "-- step 2: find_package consumer smoke"
# Готовим каталог потребителя
mkdir -p "$WORK/smoke" || exit 2

# Запись сборки стороннего потребителя
cat > "$WORK/smoke/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.15)
project(awh-pilot-smoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(nts 1.0 CONFIG REQUIRED)
add_executable(awh-pilot-smoke main.cpp)
target_link_libraries(awh-pilot-smoke PRIVATE nts::nts)
EOF

# Запись тела стороннего потребителя: издание, хранилище тайн, лупбек профиля AWH
cat > "$WORK/smoke/main.cpp" <<'EOF'
#include <cstdio>
#include <cstdint>
#include <new>
#include <string>
#include <vector>
#include <client/client.hpp>
#include <extension/extension.hpp>
#include <pem/pem.hpp>
#include <protect/protect.hpp>
#include <server/server.hpp>
#include <sys/global.hpp>
#include <sys/vault.hpp>
#include <sys/version.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Функция чтения файла корпуса целиком
 *
 * @param path путь читаемого файла корпуса
 * @return     прочитанные байты файла, пустые при отказе
 *
 */
static std::vector <uint8_t> reading(const char * path) noexcept {
	// Открываем файл корпуса на чтение
	std::FILE * stream = std::fopen(path, "rb");
	// Прочитанные байты файла корпуса
	std::vector <uint8_t> result;
	/**
	 * Выполняем чтение файла порциями
	 */
	if(stream != nullptr){
		// Буфер очередной порции чтения
		uint8_t buffer[4096];
		// Длина очередной порции чтения
		size_t portion = 0;
		/**
		 * Выполняем перебор порций чтения
		 */
		while((portion = std::fread(buffer, 1, sizeof(buffer), stream)) > 0)
			// Дописываем очередную порцию чтения
			result.insert(result.end(), buffer, buffer + portion);
		// Закрываем файл корпуса
		std::fclose(stream);
	}
	// Выводим прочитанные байты файла корпуса
	return result;
}

/**
 * @brief Функция передачи байтов между сторонами связи
 *
 * @param client связь стороны клиента
 * @param server связь стороны сервера
 * @return       признак того, что байты между сторонами передавались
 *
 */
static bool pump(client::context_t & client, server::context_t & server) noexcept {
	// Признак того, что байты между сторонами передавались
	bool moved = false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Получаем байты, отправляемые клиентом
		view_t data = client.output();
		/**
		 * Выполняем перенос байтов клиента серверу
		 */
		if(data.size > 0){
			// Переносимые байты клиента
			const std::vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(buffer.size());
			// Выполняем подачу отправленных байтов серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Получаем байты, отправляемые сервером
		data = server.output();
		/**
		 * Выполняем перенос байтов сервера клиенту
		 */
		if(data.size > 0){
			// Переносимые байты сервера
			const std::vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя сервера
			server.consume(buffer.size());
			// Выполняем подачу отправленных байтов клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим признак того, что байты между сторонами не передавались
		return false;
	}
	// Выводим признак того, что байты между сторонами передавались
	return moved;
}

/**
 * @brief Функция проведения рукопожатия сторон связи
 *
 * @param client связь стороны клиента
 * @param server связь стороны сервера
 * @return       признак установленности связи обеими сторонами
 *
 */
static bool converse(client::context_t & client, server::context_t & server) noexcept {
	/**
	 * Выполняем передачу байтов между сторонами, пока им есть что сказать
	 */
	for(size_t i = 0; (i < 16) && pump(client, server); i++)
		// Продолжаем передачу байтов между сторонами связи
		continue;
	// Выводим признак установленности связи обеими сторонами
	return client.established() && server.established();
}

/**
 * @brief Функция обмена прикладными данными в обе стороны
 *
 * @param client связь стороны клиента
 * @param server связь стороны сервера
 * @return       признак того, что данные дошли в обе стороны без искажения
 *
 */
static bool barter(client::context_t & client, server::context_t & server) noexcept {
	// Прикладные данные, отправляемые клиентом
	const std::string request = "pilot request over the established connection";
	// Если отправить прикладные данные клиентом не удалось
	if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
		// Выводим отказ обмена
		return false;
	// Выполняем передачу байтов между сторонами связи
	converse(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	std::vector <uint8_t> received;
	// Если получить принятые сервером прикладные данные не удалось
	if((server.read(received) != context::error_t::NONE) || (std::string(received.begin(), received.end()) != request))
		// Выводим отказ обмена
		return false;
	// Прикладные данные, отправляемые сервером
	const std::string answer = "pilot answer over the established connection";
	// Если отправить прикладные данные сервером не удалось
	if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
		// Выводим отказ обмена
		return false;
	// Выполняем передачу байтов между сторонами связи
	converse(client, server);
	// Если получить принятые клиентом прикладные данные не удалось
	if((client.read(received) != context::error_t::NONE) || (std::string(received.begin(), received.end()) != answer))
		// Выводим отказ обмена
		return false;
	// Выводим успешность обмена
	return true;
}

/**
 * @brief Точка входа стороннего потребителя пакета
 *
 * @param argc длина массива параметров
 * @param argv массив параметров: путь каталога корпуса тестов
 * @return     код возврата, нулевой у успешного прохождения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Если путь каталога корпуса не подан
	if(argc < 2){
		// Выводим подсказку запуска
		std::printf("usage: awh-pilot-smoke CORPUS\n");
		// Выходим с признаком отказа запуска
		return 2;
	}
	// Путь каталога корпуса тестов
	const std::string corpus = argv[1];
	// Выводим издание пакета, доступное потребителю
	std::printf("ok version %s %u\n", sys::version(), static_cast <unsigned> (sys::number()));
	// Участок укрытого хранилища тайн
	sys::secret_t secret;
	/**
	 * Выполняем проверку заведения, записи и затирания участка хранилища
	 */
	if(!secret.reserve(32) || (secret.size() != 32) || (secret.data() == nullptr)){
		// Выводим отказ заведения участка хранилища
		std::printf("vault reserve failed\n");
		// Выходим с признаком отказа
		return 1;
	}
	/**
	 * Выполняем запись байтов в участок хранилища
	 */
	for(size_t i = 0; i < secret.size(); i++)
		// Записываем очередной байт участка хранилища
		secret.data()[i] = static_cast <uint8_t> (i);
	// Если записанный байт не читается обратно
	if(secret.data()[7] != 7){
		// Выводим отказ записи участка хранилища
		std::printf("vault write failed\n");
		// Выходим с признаком отказа
		return 1;
	}
	// Выполняем затирание участка хранилища
	secret.wipe();
	// Если затирание участка хранилища не прошло
	if(secret.data()[7] != 0){
		// Выводим отказ затирания участка хранилища
		std::printf("vault wipe failed\n");
		// Выходим с признаком отказа
		return 1;
	}
	// Выводим успешность проверки хранилища тайн
	std::printf("ok vault\n");
	// Секретный ключ подлинности сервера из корпуса
	const std::vector <uint8_t> key = reading((corpus + "/ed25519.pem").c_str());
	// Сертификат подлинности сервера из корпуса
	const std::vector <uint8_t> cert = reading((corpus + "/ed25519.crt").c_str());
	// Если ключ либо сертификат корпуса не прочитаны
	if(key.empty() || cert.empty()){
		// Выводим отказ чтения корпуса
		std::printf("corpus not found: %s\n", corpus.c_str());
		// Выходим с признаком отказа
		return 1;
	}
	// Подлинность стороны сервера
	context::credential_t credential;
	// Устанавливаем секретный ключ подлинности сервера
	credential.secret = key;
	// Если цепочка сертификатов из записи PEM не разобрана
	if(pem::certificates(std::string(cert.begin(), cert.end()), credential.chain) != pem::error_t::NONE){
		// Выводим отказ разбора сертификата
		std::printf("certificate parse failed\n");
		// Выходим с признаком отказа
		return 1;
	}
	// Перечень наборов шифрования профиля AWH
	const std::vector <protect::suite_t> suites = {
		protect::suite_t::AES_128_GCM_SHA256,
		protect::suite_t::AES_256_GCM_SHA384,
		protect::suite_t::CHACHA20_POLY1305_SHA256
	};
	// Перечень групп обмена профиля AWH
	const std::vector <extension::group_t> groups = {
		extension::group_t::X25519,
		extension::group_t::SECP256R1,
		extension::group_t::SECP384R1
	};
	// Перечень схем подписи профиля AWH
	const std::vector <extension::scheme_t> schemes = {
		extension::scheme_t::RSA_PSS_RSAE_SHA256,
		extension::scheme_t::RSA_PSS_RSAE_SHA384,
		extension::scheme_t::RSA_PSS_RSAE_SHA512,
		extension::scheme_t::ECDSA_SECP256R1_SHA256,
		extension::scheme_t::ECDSA_SECP384R1_SHA384,
		extension::scheme_t::ED25519
	};
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем перечень наборов шифрования обеим сторонам
	client.suites(suites);
	// Устанавливаем перечень наборов шифрования серверу
	server.suites(suites);
	// Устанавливаем перечень групп обмена обеим сторонам
	client.groups(groups);
	// Устанавливаем перечень групп обмена серверу
	server.groups(groups);
	// Устанавливаем перечень схем подписи обеим сторонам
	client.schemes(schemes);
	// Устанавливаем перечень схем подписи серверу
	server.schemes(schemes);
	// Устанавливаем пределы изданий кодами TLS обеим сторонам
	client.versions(0x0303, 0x0304);
	// Устанавливаем пределы изданий серверу
	server.versions(0x0303, 0x0304);
	// Устанавливаем подлинность стороны сервера
	server.credential(credential);
	/**
	 * Выполняем запуск сторон связи
	 */
	if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
		// Выводим отказ запуска сторон связи
		std::printf("start failed: %d %d\n", static_cast <int> (client.error()), static_cast <int> (server.error()));
		// Выходим с признаком отказа
		return 1;
	}
	/**
	 * Выполняем рукопожатие сторон связи
	 */
	if(!converse(client, server)){
		// Выводим отказ рукопожатия сторон связи
		std::printf("handshake failed: %d %d\n", static_cast <int> (client.error()), static_cast <int> (server.error()));
		// Выходим с признаком отказа
		return 1;
	}
	// Выводим согласованный набор шифрования связи
	std::printf("ok handshake suite 0x%04X\n", static_cast <unsigned> (static_cast <uint16_t> (client.suite())));
	// Если обмен прикладными данными не прошёл
	if(!barter(client, server)){
		// Выводим отказ обмена прикладными данными
		std::printf("exchange failed\n");
		// Выходим с признаком отказа
		return 1;
	}
	// Выводим успешность обмена прикладными данными
	std::printf("ok exchange\n");
	// Выводим признак прохождения проверки целиком
	std::printf("PASSED\n");
	// Выходим с признаком успеха
	return 0;
}
EOF

# Если настройка либо сборка потребителя не прошли
if ! cmake -S "$WORK/smoke" -B "$WORK/smoke-build" -DCMAKE_PREFIX_PATH="$PREFIX" >/dev/null ||
   ! cmake --build "$WORK/smoke-build" >/dev/null; then
	# Отмечаем падение потребителя
	FALL=$((FALL + 1))
	# Выводим итог приёмки и выходим
	echo "успех=$OK расхождение=$DIFF зависание=$HANG падение=$FALL"
	exit 1
fi

# Запускаем потребителя под сторожем на случай зависания
"$WORK/smoke-build/awh-pilot-smoke" "$SOURCE/tests/corpus" > "$WORK/smoke.log" 2>&1 &
# Опознаватель запущенного потребителя
readonly SMOKE=$!
# Сторож потребителя: снимает процесс по истечении трёх минут
	(sleep 180 && kill -TERM "$SMOKE" 2>/dev/null) &
# Опознаватель сторожа потребителя
readonly WATCH=$!
# Код возврата потребителя
CODE=0
# Ожидаем завершения потребителя, код возврата берём напрямую у wait
wait "$SMOKE"
CODE=$?
# Снимаем сторожа потребителя
kill "$WATCH" 2>/dev/null
# Выводим журнал прогона потребителя
cat "$WORK/smoke.log"
# Если потребитель снят сторожем
if [ "$CODE" -eq 143 ]; then
	# Отмечаем зависание потребителя
	HANG=$((HANG + 1))
# Иначе если потребитель завершился с отказом
elif [ "$CODE" -ne 0 ]; then
	# Отмечаем падение потребителя
	FALL=$((FALL + 1))
# Иначе если итоговая строка прохождения в журнале отсутствует
elif ! grep -q "PASSED" "$WORK/smoke.log"; then
	# Отмечаем расхождение итога потребителя
	DIFF=$((DIFF + 1))
# Иначе потребитель прошёл целиком
else
	# Отмечаем успешность потребителя: издание, хранилище, рукопожатие, обмен
	OK=$((OK + 4))
fi

##
 # Шаг 3 (по ключу --tests): полный набор проверок ctest
 ##
# Если полный набор проверок не запрошен
if [ "$TESTS" -eq 0 ]; then
	# Выводим итог приёмки
	echo "успех=$OK расхождение=$DIFF зависание=$HANG падение=$FALL"
	# Выходим с итогом приёмки
	[ "$DIFF" -eq 0 ] && [ "$HANG" -eq 0 ] && [ "$FALL" -eq 0 ]
	exit
fi

echo "-- step 3: ctest"
# Если настройка либо сборка проверок не прошли
if ! cmake -S "$SOURCE" -B "$WORK/build-tests" -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_TESTS=ON >/dev/null ||
   ! cmake --build "$WORK/build-tests" >/dev/null; then
	# Отмечаем падение сборки проверок
	FALL=$((FALL + 1))
	# Выводим итог приёмки и выходим
	echo "успех=$OK расхождение=$DIFF зависание=$HANG падение=$FALL"
	exit 1
fi
# Запускаем проверки потребителя под сторожем на случай зависания
ctest --test-dir "$WORK/build-tests" --output-on-failure > "$WORK/ctest.log" 2>&1 &
# Опознаватель запущенных проверок
readonly CT=$!
# Сторож проверок: снимает прогон по истечении часа
	(sleep 3600 && kill -TERM "$CT" 2>/dev/null) &
# Опознаватель сторожа проверок
readonly CTWATCH=$!
# Ожидаем завершения проверок, код возврата берём напрямую у wait
wait "$CT"
CODE=$?
# Снимаем сторожа проверок
kill "$CTWATCH" 2>/dev/null
# Выводим сводку прогона проверок
grep -E "tests passed|Failed" "$WORK/ctest.log" | tail -3
# Если проверки сняты сторожем
if [ "$CODE" -eq 143 ]; then
	# Отмечаем зависание проверок
	HANG=$((HANG + 1))
# Иначе если проверки завершились с отказом
elif [ "$CODE" -ne 0 ]; then
	# Отмечаем число непрошедших проверок расхождениями
	DIFF=$((DIFF + 1))
# Иначе проверки прошли
else
	# Отмечаем успешность набора проверок
	OK=$((OK + 1))
fi

# Выводим итог приёмки
echo "успех=$OK расхождение=$DIFF зависание=$HANG падение=$FALL"
# Выходим с итогом приёмки
[ "$DIFF" -eq 0 ] && [ "$HANG" -eq 0 ] && [ "$FALL" -eq 0 ]
