/**
 * @file audit.cpp
 * @date 2026-09-09
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Закрепляющие проверки находок аудита кода (круг 1, 09.09.2026): всякая находка,
 *        подтверждённая щупом, повторяется здесь и обязана оставаться исправленной
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/stat.h>
#include <main.hpp>
#include <openssl.hpp>
#include <identity.hpp>
#include <gost.hpp>
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <ech/ech.hpp>
#include <trust/trust.hpp>
#include <keys/keys.hpp>
#include <cipher/aes.hpp>
#include <cipher/gcm.hpp>
#include <cipher/poly1305.hpp>
#include <cipher/mode.hpp>
#include <digest/argon2.hpp>
#include <digest/hmac.hpp>
#include <digest/sha2.hpp>
#include <digest/sha1.hpp>
#include <digest/md5.hpp>
#include <digest/streebog.hpp>
#include <hpke/hpke.hpp>
#include <sign/rsa.hpp>
#include <sign/ecdsa.hpp>
#include <curve/curve.hpp>
#include <cipher/kuznyechik.hpp>
#include <noise/symmetric.hpp>
#include <fingerprint/fingerprint.hpp>
#include <alert/alert.hpp>
#include <session/session.hpp>
#include <protect/protect.hpp>
#include <internal/engine/engine.hpp>
#include <internal/flight/flight.hpp>
#include <noise/handshake.hpp>
#include <datagram/datagram.hpp>
#include <x509/x509.hpp>
#include <x509/signature.hpp>
#include <math/integer.hpp>
#include <asn1/asn1.hpp>
#include <ocsp/ocsp.hpp>
#include <posix.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Путь к набору ключей
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла
	 * @return     содержимое
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		// Объявляем file и конструируем (std::string(CORPUS) + "/" + name, std::ios:…)
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Проверяем, что «!file.is_open()»
		if(!file.is_open())
			// Возвращаем значение «vector <uint8_t> ()»
			return vector <uint8_t> ();
		// Возвращаем значение «vector <uint8_t> ((std::istreambuf_iterator <char> (fil…»
		return vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	}
	/**
	 * @brief Функция чтения подлинности из набора
	 *
	 * @param name   имя
	 * @param result подлинность
	 * @return       признак успешности
	 *
	 */
	static bool keyfile(const char * name, context::credential_t & result) noexcept {
		// Секрет читается из корпуса по имени ключа
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Присваиваем const vector <uint8_t> chain значение результат вызова corpus()
		const vector <uint8_t> chain = corpus((std::string(name) + ".crt").c_str());
		// Проверяем, что «result.secret.empty() || chain.empty()»
		if(result.secret.empty() || chain.empty())
			// Возвращаем значение «false»
			return false;
		// Возвращаем значение «(pem::certificates(string(chain.begin(), chain.end()),…»
		return (pem::certificates(string(chain.begin(), chain.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция передачи байтов между сторонами
	 *
	 * @param client клиент
	 * @param server сервер
	 * @return       признак передачи
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Объявляем moved и инициализируем значение «false»
		bool moved = false;
		// Объявляем data и инициализируем результат вызова client.output()
		view_t data = client.output();
		// Проверяем, что «data.size > 0»
		if(data.size > 0){
			// Объявляем buffer — буфер обмена и конструируем из data.data, data.data + data.size
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Вызываем client.consume(buffer.size())
			client.consume(buffer.size());
			// Вызываем server.push(view_t(buffer.data(), buffer.size()))
			server.push(view_t(buffer.data(), buffer.size()));
			// Отмечаем перенос подлинности
			moved = true;
		}
		// Вывод сервера забирается целиком
		data = server.output();
		// Проверяем, что «data.size > 0»
		if(data.size > 0){
			// Объявляем buffer — буфер обмена и конструируем из data.data, data.data + data.size
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Вызываем server.consume(buffer.size())
			server.consume(buffer.size());
			// Вызываем client.push(view_t(buffer.data(), buffer.size()))
			client.push(view_t(buffer.data(), buffer.size()));
			// Отмечаем перенос подлинности
			moved = true;
		}
		// Возвращаем значение «moved»
		return moved;
	}
	/**
	 * @brief Функция проведения связи до тишины
	 *
	 * @param client клиент
	 * @param server сервер
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		/** Перебираем: size_t i = 0 при условии (i < 16) && pump(client, server) */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Функция изъятия отправляемых байтов стороны
	 *
	 * @param side сторона
	 * @return     байты
	 *
	 */
	template <typename T>
	static vector <uint8_t> take(T & side) noexcept {
		// Объявляем data и инициализируем результат вызова side.output()
		const view_t data = side.output();
		// Объявляем result — результат и конструируем из data.data, data.data + data.size
		vector <uint8_t> result(data.data, data.data + data.size);
		// Вызываем side.consume(result.size())
		side.consume(result.size());
		// Возвращаем значение «result»
		return result;
	}
	/**
	 * @brief Функция забора всех дейтаграмм из очереди стороны
	 *
	 * @param side сторона
	 * @return     дейтаграммы по порядку
	 *
	 */
	template <typename T>
	static vector <vector <uint8_t>> drain(T & side) noexcept {
		// Объявляем result — результат
		vector <vector <uint8_t>> result;
		/** Перебираем: vector <uint8_t> item = take(side) при условии !item.empty() */
		for(vector <uint8_t> item = take(side); !item.empty(); item = take(side))
			// Добавляем элемент в конец накопителя
			result.push_back(item);
		// Возвращаем значение «result»
		return result;
	}
	/**
	 * @brief Функция выработки билета первой связью
	 *
	 * @param credential подлинность сервера
	 * @param suites     наборы либо пусто
	 * @param accepted   билет клиента
	 * @param issued     билеты сервера
	 * @return           признак успешности
	 *
	 */
	static bool ticketed(const context::credential_t & credential, const vector <protect::suite_t> & suites, context::ticket_t & accepted, vector <context::ticket_t> & issued) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём подлинность стороны
		server.credential(credential);
		// Продвигаем состояние стороны
		server.advance(true, 16384);
		// Проверяем, что «!suites.empty()»
		if(!suites.empty()){
			// Ограничиваем наборы шифров стороны
			client.suites(suites);
			// Ограничиваем наборы шифров стороны
			server.suites(suites);
		}
		// Проверяем, что «(server.start() != context::error_t::NONE) || (client.start…»
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Возвращаем значение «false»
			return false;
		// Проводим связь сторон до тишины
		converse(client, server);
		// Проверяем, что «!client.established() || !server.established()»
		if(!client.established() || !server.established())
			// Возвращаем значение «false»
			return false;
		// Проверяем, что «server.issue() != context::error_t::NONE»
		if(server.issue() != context::error_t::NONE)
			// Возвращаем значение «false»
			return false;
		// Проводим связь сторон до тишины
		converse(client, server);
		// Проверяем, что «client.tickets().empty()»
		if(client.tickets().empty())
			// Возвращаем значение «false»
			return false;
		// Билеты, выданные сервером
		issued = server.tickets();
		// Первый билет, принятый клиентом
		accepted = client.tickets()[0];
		// Возвращаем значение «true»
		return true;
	}
	/**
	 * Случайное значение просьбы о повторе (раздел 4.1.3 RFC 8446)
	 */
	static const uint8_t RETRY[32] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};
};

/**
 * Билет 1.3 предъявлен серверу лишь 1.2 с запросом подлинности клиента: приветствие обязано лежать в
 * переписке издания 1.2, иначе подпись владения ключом клиента не покрывает его (decrypt_error)
 */
TEST(AuditTest, TicketHistory){
	// Подлинность стороны и её копия для переноса
	context::credential_t credential, mine;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	ASSERT_TRUE(keyfile("ec384", mine));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Запрашиваем подлинность клиента
	server.request(true);
	// Задаём подлинность стороны
	client.credential(mine);
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (client.alert().description);
	// Проверяем равенство client.version() и 0x0303
	EXPECT_EQ(client.version(), 0x0303);
}

/**
 * Перевыбор набора под хеш билета: набор издания 1.2 с тем же хешем не годится рукопожатию 1.3
 */
TEST(AuditTest, TicketReselect){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256}, accepted, issued));
	// Присваиваем const vector <protect::suite_t> suites значение значение «{protect::suite_t::AES_256_GCM_SHA384, protect::suite_t…»
	const vector <protect::suite_t> suites = {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256};
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Ограничиваем наборы шифров стороны
	server.suites(suites);
	// Возобновляем связь клиента по билету
	server.resume(issued);
	// Ограничиваем наборы шифров стороны
	client.suites(suites);
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем равенство server.suite() и protect::suite_t::AES_128_GCM_SHA256
	EXPECT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	// Сервер разделил секреты со стороной
	EXPECT_TRUE(server.shared());
}

/**
 * Запись упреждения в полные 16384 байта, ушедшая до просьбы о повторе, пропускается, а не
 * обрывает связь record_overflow (раздел 4.2.10 RFC 8446)
 */
TEST(AuditTest, EarlyBeforeRetry){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Возобновляем связь клиента по билету
	server.resume(issued);
	// Продвигаем состояние стороны
	server.advance(true, 16384);
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Продвигаем состояние стороны
	client.advance(true, 16384);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Объявляем payload — полезная нагрузка и заполняем накопитель (16384, 'A')
	const vector <uint8_t> payload(16384, 'A');
	// Требуем равенство client.write(view_t(payload.data(),… и context::error_t::NONE
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
	// Проверяем ложность «client.accepted()»
	EXPECT_FALSE(client.accepted());
}

/**
 * Билет серверу неведом, клиент шлёт 16384 байта упреждения по своему билету: бюджет пропуска
 * берётся от своей настройки, а не от нулевого объёма чужого билета - связь устанавливается
 */
TEST(AuditTest, StaleTicketBudget){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Продвигаем состояние стороны
	server.advance(true, 16384);
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Продвигаем состояние стороны
	client.advance(true, 16384);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Объявляем payload — полезная нагрузка и заполняем накопитель (16384, 'A')
	const vector <uint8_t> payload(16384, 'A');
	// Требуем равенство client.write(view_t(payload.data(),… и context::error_t::NONE
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
	// Проверяем ложность «server.shared()»
	EXPECT_FALSE(server.shared());
	EXPECT_FALSE(client.accepted());
}

/**
 * Просьба о повторе с меткой возврата состояния без доли ключа поверх записей законна (разделы
 * 4.1.4 и 4.2.2 RFC 8446): клиент отвечает вторым приветствием
 */
TEST(AuditTest, CookieOnlyRetry){
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Требуем равенство client.start() и context::error_t::NONE
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> wire значение результат вызова take()
	const vector <uint8_t> wire = take(client);
	// Объявляем messages
	handshake::reader_t messages;
	// Требуем равенство messages.push(view_t(wire.data() +… и handshake::error_t::NONE
	ASSERT_EQ(messages.push(view_t(wire.data() + 5, wire.size() - 5)), handshake::error_t::NONE);
	// Заголовок сообщения рукопожатия
	handshake::header_t header;
	// Объявляем body
	view_t body;
	// Требуем равенство messages.next(header, body) и handshake::error_t::NONE
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	// Объявляем greeting
	hello::client_t greeting;
	// Требуем равенство hello::parse(body, greeting) и hello::error_t::NONE
	ASSERT_EQ(hello::parse(body, greeting), hello::error_t::NONE);
	// Объявляем answer
	hello::server_t answer;
	// Издание ответа: TLS 1.2
	answer.version = 0x0303;
	// Сессия ответа повторяет сессию приветствия
	answer.session = greeting.session;
	// Набор ответа: первый из приветствия
	answer.suite = greeting.suites[0];
	// Способ сжатия: без сжатия
	answer.method = 0x00;
	// Копируем sizeof(RETRY из RETRY в answer.random
	::memcpy(answer.random, RETRY, sizeof(RETRY));
	// Объявляем version — версии протокола
	vector <uint8_t> version;
	// Формируем расширение версий протокола (0x0304)
	extension::version(0x0304, version);
	// Добавляем элемент в конец накопителя
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
	// Присваиваем const vector <uint8_t> label значение значение «{0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}»
	const vector <uint8_t> label = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
	// Добавляем элемент в конец накопителя
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
	// Объявляем greeted — приветствие
	vector <uint8_t> greeted;
	// Требуем равенство hello::build(answer, greeted) и hello::error_t::NONE
	ASSERT_EQ(hello::build(answer, greeted), hello::error_t::NONE);
	// Объявляем writer
	handshake::writer_t writer;
	// Требуем равенство writer.push(handshake::type_t::SERV… и handshake::error_t::NONE
	ASSERT_EQ(writer.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())), handshake::error_t::NONE);
	// Объявляем records
	record::writer_t records;
	// Требуем равенство records.push(record::type_t::HANDSH… и record::error_t::NONE
	ASSERT_EQ(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()), record::error_t::NONE);
	// Проверяем равенство client.push(records.data()) и context::error_t::NONE)
	EXPECT_EQ(client.push(records.data()), context::error_t::NONE) << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
	// Проверяем неравенство client.state() и context::state_t::FAILED
	EXPECT_NE(client.state(), context::state_t::FAILED);
	// Проверяем: take(client).size() больше static_cast <size_t> (0)
	EXPECT_GT(take(client).size(), static_cast <size_t> (0));
	// Просьба без доли и без метки - отказ
	client::context_t other;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(other);
	// Требуем равенство other.start() и context::error_t::NONE
	ASSERT_EQ(other.start(), context::error_t::NONE);
	// Забираем отправляемые стороной байты, отбрасывая результат
	(void) take(other);
	// Вызываем answer.extensions.pop_back()
	answer.extensions.pop_back();
	// Вызываем greeted.clear()
	greeted.clear();
	// Требуем равенство hello::build(answer, greeted) и hello::error_t::NONE
	ASSERT_EQ(hello::build(answer, greeted), hello::error_t::NONE);
	// Объявляем again
	handshake::writer_t again;
	// Требуем равенство again.push(handshake::type_t::SERVE… и handshake::error_t::NONE
	ASSERT_EQ(again.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())), handshake::error_t::NONE);
	// Объявляем bare
	record::writer_t bare;
	// Требуем равенство bare.push(record::type_t::HANDSHAKE… и record::error_t::NONE
	ASSERT_EQ(bare.push(record::type_t::HANDSHAKE, record::version_t::TLS12, again.data()), record::error_t::NONE);
	// Проверяем неравенство other.push(bare.data()) и context::error_t::NONE
	EXPECT_NE(other.push(bare.data()), context::error_t::NONE);
}

/**
 * Совместимостная запись change_cipher_spec между просьбой о повторе и вторым приветствием
 * (приложение D.4 RFC 8446): сервер пропускает её, а не рвёт связь
 */
TEST(AuditTest, CcsAfterRetry){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> first значение результат вызова take()
	const vector <uint8_t> first = take(client);
	// Требуем равенство server.push(view_t(first.data(), fi… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(first.data(), first.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> retry значение результат вызова take()
	const vector <uint8_t> retry = take(server);
	// Требуем равенство client.push(view_t(retry.data(), re… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> second значение результат вызова take()
	const vector <uint8_t> second = take(client);
	// Присваиваем const uint8_t ccs[] значение значение «{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}»
	const uint8_t ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
	// Проверяем равенство server.push(view_t(ccs, sizeof(ccs)… и context::error_t::NONE)
	EXPECT_EQ(server.push(view_t(ccs, sizeof(ccs))), context::error_t::NONE) << static_cast <int> (server.alert().description);
	// Проверяем неравенство server.state() и context::state_t::FAILED
	EXPECT_NE(server.state(), context::state_t::FAILED);
	// Требуем равенство server.push(view_t(second.data(), s… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(second.data(), second.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established());
	// До первого приветствия та же запись по-прежнему отвергается
	server::context_t fresh;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(fresh);
	// Задаём подлинность стороны
	fresh.credential(credential);
	// Требуем равенство fresh.start() и context::error_t::NONE
	ASSERT_EQ(fresh.start(), context::error_t::NONE);
	// Проверяем неравенство fresh.push(view_t(ccs, sizeof(ccs))) и context::error_t::NONE
	EXPECT_NE(fresh.push(view_t(ccs, sizeof(ccs))), context::error_t::NONE);
}

/**
 * Приветствие сервера издания 1.2 без блока расширений разбирается (раздел 7.4.1.3 RFC 5246)
 */
TEST(AuditTest, ServerHelloBare){
	// Присваиваем vector <uint8_t> bare значение значение «{0x03, 0x03}»
	vector <uint8_t> bare = {0x03, 0x03};
	// Вызываем bare.insert(bare.end(), 32, 0x11)
	bare.insert(bare.end(), 32, 0x11);
	// Добавляем элемент в конец накопителя
	bare.push_back(0x00);
	bare.push_back(0x13); bare.push_back(0x01);
	bare.push_back(0x00);
	// Объявляем answer
	hello::server_t answer;
	// Проверяем равенство hello::parse(view_t(bare.data(), ba… и hello::error_t::NONE
	EXPECT_EQ(hello::parse(view_t(bare.data(), bare.size()), answer), hello::error_t::NONE);
	// Ответ без расширений
	EXPECT_TRUE(answer.extensions.empty());
	// С пустым блоком - тоже
	bare.push_back(0x00); bare.push_back(0x00);
	// Проверяем равенство hello::parse(view_t(bare.data(), ba… и hello::error_t::NONE
	EXPECT_EQ(hello::parse(view_t(bare.data(), bare.size()), answer), hello::error_t::NONE);
}

/**
 * Две записи host_name в server_name отвергаются (раздел 3 RFC 6066), одна принимается
 */
TEST(AuditTest, NameTwice){
	// Объявляем first и инициализируем значение «"a.example", second = "b.example"»
	const string first = "a.example", second = "b.example";
	// Объявляем body — тело сообщения
	vector <uint8_t> body;
	// Объявляем лямбду entry — захвата тела отклика
	const auto entry = [&body](const string & name){
		// Добавляем элемент в конец накопителя
		body.push_back(0x00);
		body.push_back(static_cast <uint8_t> (name.size() >> 8));
		body.push_back(static_cast <uint8_t> (name.size() & 0xFF));
		// Вызываем body.insert(body.end(), name.begin(), name.end())
		body.insert(body.end(), name.begin(), name.end());
	};
	// Вызываем entry(first)
	entry(first);
	// Присваиваем vector <uint8_t> data значение значение «{0x00, static_cast <uint8_t> (body.size())}»
	vector <uint8_t> data = {0x00, static_cast <uint8_t> (body.size())};
	// Вызываем data.insert(data.end(), body.begin(), body.end())
	data.insert(data.end(), body.begin(), body.end());
	// Объявляем name
	view_t name;
	// Проверяем равенство extension::name(view_t(data.data(),… и extension::error_t::NONE
	EXPECT_EQ(extension::name(view_t(data.data(), data.size()), name), extension::error_t::NONE);
	// Вызываем entry(second)
	entry(second);
	// Вывод сервера забирается целиком
	data = {0x00, static_cast <uint8_t> (body.size())};
	// Вызываем data.insert(data.end(), body.begin(), body.end())
	data.insert(data.end(), body.begin(), body.end());
	// Проверяем неравенство extension::name(view_t(data.data(),… и extension::error_t::NONE
	EXPECT_NE(extension::name(view_t(data.data(), data.size()), name), extension::error_t::NONE);
}

/**
 * Пустой опознаватель PSK и пустая доля key_exchange сервера отвергаются (разделы 4.2.11 и 4.2.8 RFC 8446)
 */
TEST(AuditTest, EmptyBodies){
	// identities: перечень из одной пустой identity с возрастом, привязки пустые
	const vector <uint8_t> psk = {0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	// Объявляем identities — личности
	vector <extension::identity_t> identities;
	// Объявляем binders — связки подлинности ECH
	vector <view_t> binders;
	// Объявляем truncation и инициализируем значение «0»
	size_t truncation = 0;
	// Проверяем равенство extension::identities(view_t(psk.da… и extension::error_t::EMPTY
	EXPECT_EQ(extension::identities(view_t(psk.data(), psk.size()), identities, binders, truncation), extension::error_t::EMPTY);
	// share: группа X25519 с пустым ключом
	const vector <uint8_t> share = {0x00, 0x1D, 0x00, 0x00};
	// Объявляем item
	extension::share_t item;
	// Проверяем равенство extension::share(view_t(share.data(… и extension::error_t::EMPTY
	EXPECT_EQ(extension::share(view_t(share.data(), share.size()), item), extension::error_t::EMPTY);
}

/**
 * Перечень ECH: конфигурация с обязательным неизвестным расширением и конфигурация с ключом не в длину
 * KEM пропускаются, годная следом берётся (разделы 4.2 и 6.1.1 RFC 9849); битый перечень расширений - отказ
 */
TEST(AuditTest, EchConfigs){
	// Объявляем лямбду make — фабрики наборов шифров
	const auto make = [](const uint8_t id, const size_t keysize, const vector <uint8_t> & extensions, vector <uint8_t> & raw){
		// Объявляем config
		ech::config_t config;
		// Опознаватель конфигурации ECH
		config.id = id;
		// Длина открытого ключа конфигурации
		config.length = 64;
		// Способ инкапсуляции конфигурации
		config.kem = hpke::kem_t::X25519_HKDF_SHA256;
		// Заполняем накопитель значением
		config.key.assign(keysize, 0x42);
		// Добавляем элемент в конец накопителя
		config.suites.push_back(ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM));
		// Открытое имя конфигурации
		config.name = "public.example";
		// Расширения конфигурации
		config.extensions = extensions;
		// Возвращаем значение «(ech::build(config, raw) == ech::error_t::NONE)»
		return (ech::build(config, raw) == ech::error_t::NONE);
	};
	// Объявляем shortkey и good
	vector <uint8_t> mandatory, shortkey, good;
	// Составление записи конфигурации ECH
	ASSERT_TRUE(make(1, 32, vector <uint8_t> {0x80, 0x01, 0x00, 0x00}, mandatory));
	ASSERT_TRUE(make(2, 31, vector <uint8_t> (), shortkey));
	ASSERT_TRUE(make(3, 32, vector <uint8_t> {0x00, 0x01, 0x00, 0x00}, good));
	// Объявляем list — список
	vector <uint8_t> list;
	// Вызываем list.insert(list.end(), mandatory.begin(), mandatory.end())
	list.insert(list.end(), mandatory.begin(), mandatory.end());
	list.insert(list.end(), shortkey.begin(), shortkey.end());
	list.insert(list.end(), good.begin(), good.end());
	list.insert(list.begin(), static_cast <uint8_t> (list.size() & 0xFF));
	list.insert(list.begin(), static_cast <uint8_t> ((list.size() - 1) >> 8));
	// Объявляем configs — конфигурации ECH
	vector <ech::config_t> configs;
	// Требуем равенство ech::parse(view_t(list.data(), list… и ech::error_t::NONE
	ASSERT_EQ(ech::parse(view_t(list.data(), list.size()), configs), ech::error_t::NONE);
	ASSERT_EQ(configs.size(), static_cast <size_t> (1));
	// Проверяем равенство configs[0].id и 3
	EXPECT_EQ(configs[0].id, 3);
	// Битый перечень расширений
	vector <uint8_t> broken;
	// Составление записи конфигурации ECH
	ASSERT_TRUE(make(4, 32, vector <uint8_t> {0x00, 0x01}, broken));
	// Присваиваем vector <uint8_t> alone значение значение «{static_cast <uint8_t> (broken.size() >> 8), static_cas…»
	vector <uint8_t> alone = {static_cast <uint8_t> (broken.size() >> 8), static_cast <uint8_t> (broken.size() & 0xFF)};
	// Вызываем alone.insert(alone.end(), broken.begin(), broken.end())
	alone.insert(alone.end(), broken.begin(), broken.end());
	// Проверяем неравенство ech::parse(view_t(alone.data(), alo… и ech::error_t::NONE
	EXPECT_NE(ech::parse(view_t(alone.data(), alone.size()), configs), ech::error_t::NONE);
	// Клиент с таким перечнем заводится по годной конфигурации
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Задаём имя проверки
	client.name("secret.example");
	// Проверяем равенство client.ech(list) и context::error_t::NONE
	EXPECT_EQ(client.ech(list), context::error_t::NONE);
	EXPECT_EQ(client.start(), context::error_t::NONE);
}

/**
 * Адрес IPv6 со сжатием в конце («2001:db8::») отвечает записи subjectAltName
 */
TEST(AuditTest, AddressTail){
	// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
	const vector <uint8_t> text = corpus("audit/ipv6.crt");
	// Требуем ложность «text.empty()»
	ASSERT_FALSE(text.empty());
	// Объявляем chain — цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Требуем равенство pem::certificates(string(text.begin… и pem::error_t::NONE
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	ASSERT_EQ(chain.size(), static_cast <size_t> (1));
	// Объявляем der и конструируем (chain[0].data(), chain[0].size())
	const view_t der(chain[0].data(), chain[0].size());
	// Проверяем равенство trust::belongs(der, "2001:db8::") и trust::error_t::NONE
	EXPECT_EQ(trust::belongs(der, "2001:db8::"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "2001:db8:0:0:0:0:0:0"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "fe80::1"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "10.0.0.1"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "::"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "2001:db8::1"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "2001:db8:::"), trust::error_t::NAME);
}

/**
 * Назначение листа по роли: сертификат лишь для clientAuth годен клиенту и не годен серверу
 */
TEST(AuditTest, Purpose){
	// Объявляем лямбду load — загрузки данных набора
	const auto load = [](const char * name, vector <uint8_t> & result){
		// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
		const vector <uint8_t> text = corpus(name);
		// Объявляем chain — цепочка сертификатов
		vector <vector <uint8_t>> chain;
		// Проверяем, что «text.empty() || (pem::certificates(string(text.begin(), tex…»
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Возвращаем значение «false»
			return false;
		// Первый сертификат цепочки
		result = chain[0];
		// Возвращаем значение «true»
		return true;
	};
	// Объявляем middle и root
	vector <uint8_t> leaf, middle, root;
	// Сертификат eku-client.crt из корпуса
	ASSERT_TRUE(load("audit/eku-client.crt", leaf));
	ASSERT_TRUE(load("audit/eku-mid.crt", middle));
	ASSERT_TRUE(load("audit/eku-root.crt", root));
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Присваиваем const vector <vector <uint8_t>> chain значение значение «{leaf, middle}»
	const vector <vector <uint8_t>> chain = {leaf, middle};
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Проверяем равенство trust::verify(chain, store, moment) и trust::error_t::NONE
	EXPECT_EQ(trust::verify(chain, store, moment), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(chain, store, moment, trust::role_t::ANY), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(chain, store, moment, trust::role_t::CLIENT), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(chain, store, moment, trust::role_t::SERVER), trust::error_t::PURPOSE);
}

/**
 * Число итераций PBKDF2 из недоверенной записи ограничено: ключ с 10^7 + 1 итерациями отвергается
 * сразу, а не разбирается часами
 */
TEST(AuditTest, Iterations){
	// Проверяем, что «::system("openssl version >/dev/null 2>&1") != 0»
	if(::system("openssl version >/dev/null 2>&1") != 0){
		// Пропускаем проверку: openssl недоступен
		GTEST_SKIP() << "openssl недоступен";
	}
	// Объявляем path и инициализируем значение «"/tmp/ants-audit-iter-" + std::to_string(static_cast <u…»
	const std::string path = "/tmp/ants-audit-iter-" + std::to_string(static_cast <unsigned> (::getpid())) + ".pem";
	// Выработка записи у openssl сама стоит секунды: итерации считаются при шифровании
	if(::system(("openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 10000001 -passout pass:secret -in " + std::string(CORPUS) + "/ec256.pem -out " + path + " >/dev/null 2>&1").c_str()) != 0){
		// Пропускаем проверку: openssl без -iter
		GTEST_SKIP() << "openssl без -iter";
	}
	// Объявляем file и конструируем (path)
	std::ifstream file(path);
	// Объявляем text и конструируем ((std::istreambuf_iterator <char> (file)), s…)
	const std::string text((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	// Вызываем ::remove(path.c_str())
	::remove(path.c_str());
	// Требуем ложность «text.empty()»
	ASSERT_FALSE(text.empty());
	// Объявляем key
	keys::key_t key;
	// Присваиваем const uint8_t password[6] значение значение «{'s', 'e', 'c', 'r', 'e', 't'}»
	const uint8_t password[6] = {'s', 'e', 'c', 'r', 'e', 't'};
	// Проверяем равенство keys::decode(text, view_t(password,… и keys::error_t::CIPHER
	EXPECT_EQ(keys::decode(text, view_t(password, sizeof(password)), key), keys::error_t::CIPHER);
}

/**
 * Предел открытого текста GCM (раздел 5.2.1.1 NIST SP 800-38D): кусок, выводящий за 2^39 - 256 разрядов,
 * отвергается до шифрования - гамма не замыкается на J0
 */
TEST(AuditTest, GcmMost){
	// Объявляем aes
	cipher::aes_t aes;
	// Присваиваем const uint8_t key[16] значение значение «{0}»
	const uint8_t key[16] = {0};
	// Ключ шифра AES установлен
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	// Объявляем gcm
	cipher::gcm_t gcm;
	// Присваиваем const uint8_t nonce[12] значение значение «{0}»
	const uint8_t nonce[12] = {0};
	// Режим GCM заведён с ключом и синхропосылкой
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	// Присваиваем uint8_t buffer[16] значение значение «{0}, out[16]»
	uint8_t buffer[16] = {0}, out[16];
	// Кусок, объявленный длиной сверх предела, отвергается до чтения байтов
	EXPECT_FALSE(gcm.encrypt(view_t(buffer, (static_cast <size_t> (1) << 36)), out));
	// Присоединённые данные сверх 2^61 байт - тоже
	cipher::gcm_t other;
	// Режим GCM заведён с ключом и синхропосылкой
	ASSERT_TRUE(other.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	// Проверяем ложность «other.associate(view_t(buffer, (static_cast <size_t> (1)»
	EXPECT_FALSE(other.associate(view_t(buffer, (static_cast <size_t> (1) << 61) + 1)));
	// Обычный кусок идёт
	cipher::gcm_t plain;
	// Режим GCM заведён с ключом и синхропосылкой
	ASSERT_TRUE(plain.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	// Зашифрование открытого текста
	EXPECT_TRUE(plain.encrypt(view_t(buffer, sizeof(buffer)), out));
}

/**
 * Круг 2: второе приветствие за просьбой о повторе без pre_shared_key ведёт к полному рукопожатию -
 * состояние билета первого приветствия сброшено (раздел 4.1.2 RFC 8446)
 */
TEST(AuditTest, PskAfterRetry){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	// Объявляем first
	client::context_t first;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(first);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Возобновляем связь клиента по билету
	server.resume(issued);
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Возобновляем связь клиента по билету
	first.resume(accepted);
	// Разбираем группы параметров
	first.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> hello значение результат вызова take()
	const vector <uint8_t> hello = take(first);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Сервер разделил секреты со стороной
	EXPECT_TRUE(server.shared());
	// Забираем отправляемые стороной байты, отбрасывая результат
	(void) take(server);
	// Второе приветствие от стороны без билета по запрошенной группе
	client::context_t second;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(second);
	// Разбираем группы параметров
	second.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Требуем равенство second.start() и context::error_t::NONE
	ASSERT_EQ(second.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> again значение результат вызова take()
	const vector <uint8_t> again = take(second);
	// Требуем равенство server.push(view_t(again.data(), ag… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	// Проверяем ложность «server.shared()»
	EXPECT_FALSE(server.shared());
	// Приветствие сервера без pre_shared_key: полное рукопожатие (переписка второй стороны с просьбой о повторе не сходится - это не проверяется)
	const vector <uint8_t> answer = take(server);
	// Требуем: answer.size() больше static_cast <size_t> (5)
	ASSERT_GT(answer.size(), static_cast <size_t> (5));
	// Объявляем messages
	handshake::reader_t messages;
	// Подача записи ответа в разборщик сообщений
	ASSERT_EQ(messages.push(view_t(answer.data() + 5, ((static_cast <size_t> (answer[3]) << 8) | answer[4]))), handshake::error_t::NONE);
	// Заголовок сообщения рукопожатия
	handshake::header_t header;
	// Объявляем body
	view_t body;
	// Требуем равенство messages.next(header, body) и handshake::error_t::NONE
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	// Объявляем greeted
	hello::server_t greeted;
	// Требуем равенство hello::parse(body, greeted) и hello::error_t::NONE
	ASSERT_EQ(hello::parse(body, greeted), hello::error_t::NONE);
	// Проверяем равенство hello::extension(greeted.extensions… и nullptr
	EXPECT_EQ(hello::extension(greeted.extensions, 0x0029), nullptr);
}

/**
 * Круг 2: билет связи DTLS 1.2 не возобновляет связь изданием DTLS 1.0 (раздел 3.4 RFC 5077) - идёт полное рукопожатие
 */
TEST(AuditTest, TicketEdition){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём транспорт движку
		client.transport(context::transport_t::DATAGRAMS);
		// Задаём транспорт движку
		server.transport(context::transport_t::DATAGRAMS);
		// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
		const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
		// Задаём адрес стороны
		server.address(view_t(peer, sizeof(peer)));
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		// Разбираем группы параметров
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Разбираем группы параметров
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0302, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Требуем равенство client.version() и 0x0303
		ASSERT_EQ(client.version(), 0x0303);
		// Требуем ложность «client.tickets().empty()»
		ASSERT_FALSE(client.tickets().empty());
		// Билеты, выданные сервером
		issued = server.tickets();
		// Первый билет, принятый клиентом
		accepted = client.tickets()[0];
	}
	// Тот же билет предъявляется связью DTLS 1.0: сервер обязан вести полное рукопожатие, а не возобновлять набором GCM
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Требуем равенство client.versions(0x0302, 0x0302) и context::error_t::NONE
	ASSERT_EQ(client.versions(0x0302, 0x0302), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0302, 0x0303), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Возобновляем связь клиента по билету
	server.resume(issued);
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем ложность «server.shared()»
	EXPECT_FALSE(server.shared());
	// Проверяем равенство client.version() и 0x0302
	EXPECT_EQ(client.version(), 0x0302);
	EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
}

/**
 * Круг 2: ссылка ech_outer_extensions на само ech_outer_extensions негодна (раздел 5.1 RFC 9849)
 */
TEST(AuditTest, OuterReference){
	// Объявляем donor
	client::context_t donor;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(donor);
	// Задаём имя проверки
	donor.name("secret.example");
	// Требуем равенство donor.start() и context::error_t::NONE
	ASSERT_EQ(donor.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> wire значение результат вызова take()
	const vector <uint8_t> wire = take(donor);
	// Объявляем messages
	handshake::reader_t messages;
	// Требуем равенство messages.push(view_t(wire.data() +… и handshake::error_t::NONE
	ASSERT_EQ(messages.push(view_t(wire.data() + 5, wire.size() - 5)), handshake::error_t::NONE);
	// Заголовок сообщения рукопожатия
	handshake::header_t header;
	// Объявляем body
	view_t body;
	// Требуем равенство messages.next(header, body) и handshake::error_t::NONE
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	// Объявляем inner
	hello::client_t inner;
	// Требуем равенство hello::parse(body, inner) и hello::error_t::NONE
	ASSERT_EQ(hello::parse(body, inner), hello::error_t::NONE);
	// Объявляем compact — сжатое представление
	vector <uint8_t> compact;
	// Проверяем равенство ech::encode(inner, vector <uint16_t… и ech::error_t::OUTER
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0xFD00}, 5, compact), ech::error_t::OUTER);
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0xFE0D}, 5, compact), ech::error_t::OUTER);
}

/**
 * Круг 2: ограничения имён издателя применяются и некритичным расширением (раздел 6.1.4 RFC 5280):
 * лист evil.com под промежуточным с permitted DNS:.example.com отвергается
 */
TEST(AuditTest, NameConstraints){
	// Объявляем лямбду load — загрузки данных набора
	const auto load = [](const char * name, vector <uint8_t> & result){
		// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
		const vector <uint8_t> text = corpus(name);
		// Объявляем chain — цепочка сертификатов
		vector <vector <uint8_t>> chain;
		// Проверяем, что «text.empty() || (pem::certificates(string(text.begin(), tex…»
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Возвращаем значение «false»
			return false;
		// Первый сертификат цепочки
		result = chain[0];
		// Возвращаем значение «true»
		return true;
	};
	// Объявляем middle и root
	vector <uint8_t> leaf, middle, root;
	// Сертификат nc-leaf.crt из корпуса
	ASSERT_TRUE(load("audit/nc-leaf.crt", leaf));
	ASSERT_TRUE(load("audit/nc-mid.crt", middle));
	ASSERT_TRUE(load("audit/nc-root.crt", root));
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::CONSTRAINED
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment, trust::role_t::SERVER), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment), trust::error_t::CONSTRAINED);
	// Разбор самих ограничений
	x509::certificate_t issuer;
	// Требуем равенство issuer.parse(view_t(middle.data(),… и x509::error_t::NONE
	ASSERT_EQ(issuer.parse(view_t(middle.data(), middle.size())), x509::error_t::NONE);
	// Объявляем extension и инициализируем результат вызова issuer.extension()
	const x509::extension_t * extension = issuer.extension("2.5.29.30");
	// Требуем неравенство extension и nullptr
	ASSERT_NE(extension, nullptr);
	// Объявляем excluded
	vector <x509::alternative_t> permitted, excluded;
	// Требуем равенство x509::constraints(*extension, permi… и x509::error_t::NONE
	ASSERT_EQ(x509::constraints(*extension, permitted, excluded), x509::error_t::NONE);
	ASSERT_EQ(permitted.size(), static_cast <size_t> (1));
	// Проверяем равенство permitted[0].kind и x509::kind_t::DNS
	EXPECT_EQ(permitted[0].kind, x509::kind_t::DNS);
	EXPECT_EQ(permitted[0].value, ".example.com");
	// Исключённые имена пусты
	EXPECT_TRUE(excluded.empty());
}

/**
 * Круг 2: критичное extendedKeyUsage промежуточного издателя (codeSigning) не даёт цепочке служить серверу
 */
TEST(AuditTest, IssuerPurpose){
	// Объявляем лямбду load — загрузки данных набора
	const auto load = [](const char * name, vector <uint8_t> & result){
		// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
		const vector <uint8_t> text = corpus(name);
		// Объявляем chain — цепочка сертификатов
		vector <vector <uint8_t>> chain;
		// Проверяем, что «text.empty() || (pem::certificates(string(text.begin(), tex…»
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Возвращаем значение «false»
			return false;
		// Первый сертификат цепочки
		result = chain[0];
		// Возвращаем значение «true»
		return true;
	};
	// Объявляем middle и root
	vector <uint8_t> leaf, middle, root;
	// Сертификат eku-leaf-server.crt из корпуса
	ASSERT_TRUE(load("audit/eku-leaf-server.crt", leaf));
	ASSERT_TRUE(load("audit/eku-mid-codesign.crt", middle));
	ASSERT_TRUE(load("audit/nc-root.crt", root));
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::PURPOSE
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment, trust::role_t::SERVER), trust::error_t::PURPOSE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment), trust::error_t::PURPOSE);
}

/**
 * Круг 2: одиночное двоеточие в конце адреса IPv6 не сжатие («1:», «2001:db8:0:0:0:0:0:»)
 */
TEST(AuditTest, AddressColon){
	// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
	const vector <uint8_t> text = corpus("audit/ipv6.crt");
	// Требуем ложность «text.empty()»
	ASSERT_FALSE(text.empty());
	// Объявляем chain — цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Требуем равенство pem::certificates(string(text.begin… и pem::error_t::NONE
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	// Объявляем der и конструируем (chain[0].data(), chain[0].size())
	const view_t der(chain[0].data(), chain[0].size());
	// Проверяем равенство trust::belongs(der, "2001:db8:0:0:0… и trust::error_t::NAME
	EXPECT_EQ(trust::belongs(der, "2001:db8:0:0:0:0:0:"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "1:"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "2001:db8::"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "::"), trust::error_t::NAME);
}

/**
 * Круг 2: GeneralizedTime с годом до 1950 разбирается (раздел 4.1.2.5 RFC 5280)
 */
TEST(AuditTest, OldTime){
	// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
	const vector <uint8_t> text = corpus("audit/old.crt");
	// Требуем ложность «text.empty()»
	ASSERT_FALSE(text.empty());
	// Объявляем chain — цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Требуем равенство pem::certificates(string(text.begin… и pem::error_t::NONE
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	// Объявляем certificate
	x509::certificate_t certificate;
	// Проверяем равенство certificate.parse(view_t(chain[0].d… и x509::error_t::NONE
	EXPECT_EQ(certificate.parse(view_t(chain[0].data(), chain[0].size())), x509::error_t::NONE);
	// Объявляем before и инициализируем значение «0, after = 0»
	int64_t before = 0, after = 0;
	// Вызываем certificate.validity(before, after)
	certificate.validity(before, after);
	// Проверяем: before меньше static_cast <int64_t> (-631152000)
	EXPECT_LT(before, static_cast <int64_t> (-631152000));
}

/**
 * Круг 2: открытая запись APPLICATION эпохи 0 у DTLS 1.3 роняется, а не доставляется приложению
 */
TEST(AuditTest, PlainInjection){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established());
	// Открытая запись прикладных данных: заголовок DTLS и тело
	const string text = "PLAINTEXT-INJECTED";
	// Заголовок сообщения рукопожатия
	datagram::header_t header;
	// Вид записи: данные
	header.type = record::type_t::APPLICATION;
	// Пора записи нулевая
	header.epoch = 0;
	// Номер записи: 77
	header.sequence = 77;
	// Длина записи по длине текста
	header.size = text.size();
	// Объявляем forged — подделанная дейтаграмма и конструируем из datagram::DATAGRAM_PLAIN_HEADER + t…
	vector <uint8_t> forged(datagram::DATAGRAM_PLAIN_HEADER + text.size(), 0);
	// Объявляем length и инициализируем значение «0»
	size_t length = 0;
	// Собираем дейтаграмму из «header»
	datagram::build(header, forged.data(), length);
	// Вызываем ::memcpy(forged.data() + length, text.data(), text.size())
	::memcpy(forged.data() + length, text.data(), text.size());
	// Проверяем равенство server.push(view_t(forged.data(), f… и context::error_t::NONE
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Объявляем received — принятые байты
	vector <uint8_t> received;
	// Проверяем равенство server.read(received) и context::error_t::NONE
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	// Принятые записи пусты
	EXPECT_TRUE(received.empty());
	// Проверяем равенство server.state() и context::state_t::ESTABLISHED
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
	// Защищённые данные ходят по-прежнему
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Проверяем равенство server.read(received) и context::error_t::NONE
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
}

/**
 * Круг 2: открытые пустые подтверждения не расходуют попыток повтора - девять штук не рвут рукопожатие
 */
TEST(AuditTest, AckNudge){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Доля ключа лишь по GC512C: приветствие обязано уместиться в одну дейтаграмму, проверка ведёт дейтаграммы по одной
	client.shares(vector <extension::group_t> {extension::group_t::GC512C});
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первое приветствие - серверу, ответ - метка возврата состояния без часов; второе приветствие даёт залп с часами
	const vector <uint8_t> hello = take(client);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> retry значение результат вызова take()
	const vector <uint8_t> retry = take(server);
	// Требуем ложность «retry.empty()»
	ASSERT_FALSE(retry.empty());
	// Требуем равенство client.push(view_t(retry.data(), re… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> again значение результат вызова take()
	const vector <uint8_t> again = take(client);
	// Требуем равенство server.push(view_t(again.data(), ag… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	// Присваиваем const vector <vector <uint8_t>> flight значение результат вызова drain()
	const vector <vector <uint8_t>> flight = drain(server);
	// Требуем ложность «flight.empty()»
	ASSERT_FALSE(flight.empty());
	// Требуем неравенство server.timeout() и static_cast <uint32_t> (0)
	ASSERT_NE(server.timeout(), static_cast <uint32_t> (0));
	// Девять открытых пустых подтверждений за один срок: повтор залпа не более одного (круг 4)
	size_t resent = 0;
	/** Перебираем: size_t i = 0 при условии i < 9 */
	for(size_t i = 0; i < 9; i++){
		// Заголовок сообщения рукопожатия
		datagram::header_t header;
		// Вид записи: подтверждение
		header.type = record::type_t::ACK;
		// Пора записи нулевая
		header.epoch = 0;
		// Номер записи от сотни с шагом
		header.sequence = (100 + i);
		// Длина записи: два байта
		header.size = 2;
		// Объявляем nudge — подталкивание очереди и конструируем из datagram::DATAGRAM_PLAIN_HEADER + 2…
		vector <uint8_t> nudge(datagram::DATAGRAM_PLAIN_HEADER + 2, 0);
		// Объявляем length и инициализируем значение «0»
		size_t length = 0;
		// Собираем дейтаграмму из «header»
		datagram::build(header, nudge.data(), length);
		// Проверяем равенство server.push(view_t(nudge.data(), nu… и context::error_t::NONE)
		EXPECT_EQ(server.push(view_t(nudge.data(), nudge.size())), context::error_t::NONE) << i;
		// Если сервер ещё отправляет, считаем повторную передачу
		if(!drain(server).empty()) resent++;
	}
	// Проверяем равенство resent и static_cast <size_t> (1)
	EXPECT_EQ(resent, static_cast <size_t> (1));
	// Проверяем неравенство server.state() и context::state_t::FAILED
	EXPECT_NE(server.state(), context::state_t::FAILED);
	EXPECT_NE(server.error(), context::error_t::TIMEOUT);
	/**
	 * Рукопожатие доходит до конца
	 */
	for(size_t i = 0; i < flight.size(); i++)
		// Требуем равенство client.push(view_t(flight[i].data()… и context::error_t::NONE
		ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Круг 2: переполнение переноса Poly1305 на двухблочном пути - свидетель, найденный аудитом, сходится с OpenSSL
 */
TEST(AuditTest, PolyWitness){
	// Присваиваем static const char * KEY значение значение «"390ac60f3cc7bf0b983d9103f87e430f0000000000000000000000…»
	static const char * KEY = "390ac60f3cc7bf0b983d9103f87e430f00000000000000000000000000000000";
	// Присваиваем static const char * MESSAGE значение значение «"3c978b215eea9a79a094109b03e8d6784608f34741edb0dfac3aa0…»
	static const char * MESSAGE = "3c978b215eea9a79a094109b03e8d6784608f34741edb0dfac3aa02f833ef70effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
	// Присваиваем static const char * TAG значение значение «"5d6ea518365b6c615f1d89be734804e2"»
	static const char * TAG = "5d6ea518365b6c615f1d89be734804e2";
	// Объявляем key размером 32, message размером 64, expected размером 16 и tag размером 16
	uint8_t key[32], message[64], expected[16], tag[16];
	/** Раскодируем шестнадцатеричную строку ключа в массив key */
	for(size_t i = 0; i < 32; i++){ unsigned v = 0; ::sscanf(KEY + i * 2, "%2x", &v); key[i] = static_cast <uint8_t> (v); }
	/** Раскодируем шестнадцатеричную строку сообщения в массив message */
	for(size_t i = 0; i < 64; i++){ unsigned v = 0; ::sscanf(MESSAGE + i * 2, "%2x", &v); message[i] = static_cast <uint8_t> (v); }
	/** Раскодируем шестнадцатеричную строку метки в массив expected */
	for(size_t i = 0; i < 16; i++){ unsigned v = 0; ::sscanf(TAG + i * 2, "%2x", &v); expected[i] = static_cast <uint8_t> (v); }
	// Объявляем poly
	cipher::poly1305_t poly;
	// Ключ Poly1305 установлен
	ASSERT_TRUE(poly.start(view_t(key, sizeof(key))));
	ASSERT_TRUE(poly.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(poly.finish(tag));
	// Проверяем равенство ::memcmp(tag, expected, sizeof(tag)) и 0
	EXPECT_EQ(::memcmp(tag, expected, sizeof(tag)), 0);
	// Тот же итог кусками по одному блоку: одноблочный путь
	cipher::poly1305_t single;
	// Ключ Poly1305 установлен
	ASSERT_TRUE(single.start(view_t(key, sizeof(key))));
	/** Перебираем: size_t i = 0 при условии i < 4 */
	for(size_t i = 0; i < 4; i++)
		// Подача куска сообщения в Poly1305
		ASSERT_TRUE(single.update(view_t(message + i * 16, 16)));
	ASSERT_TRUE(single.finish(tag));
	// Проверяем равенство ::memcmp(tag, expected, sizeof(tag)) и 0
	EXPECT_EQ(::memcmp(tag, expected, sizeof(tag)), 0);
}

/**
 * Круг 2: одновызовное снятие защиты GCM тоже блюдёт предел открытого текста
 */
TEST(AuditTest, GcmMostOneShot){
	// Объявляем aes
	cipher::aes_t aes;
	// Присваиваем const uint8_t key[16] значение значение «{0}»
	const uint8_t key[16] = {0};
	// Ключ шифра AES установлен
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	// Объявляем gcm
	cipher::gcm_t gcm;
	// Присваиваем const uint8_t nonce[12] значение значение «{0}»
	const uint8_t nonce[12] = {0};
	// Режим GCM заведён с ключом и синхропосылкой
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	// Присваиваем uint8_t buffer[16] значение значение «{0}, out[16], tag[16] = {0}»
	uint8_t buffer[16] = {0}, out[16], tag[16] = {0};
	// Проверяем ложность «gcm.decrypt(view_t(), view_t(buffer, (static_cast <size…»
	EXPECT_FALSE(gcm.decrypt(view_t(), view_t(buffer, (static_cast <size_t> (1) << 36)), out, view_t(tag, sizeof(tag))));
}

/**
 * Круг 2: совпадение итога со вторым сомножителем у mulmod(secret) и с модулем у power(bits) не портит итога
 */
TEST(AuditTest, IntegerAlias){
	// Объявляем a, b, m, expected и check
	math::integer_t a, b, m, expected, check;
	// Присваиваем const uint8_t modulus[8] значение значение «{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc5}»
	const uint8_t modulus[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc5};
	// Модуль загружен в структуру
	ASSERT_TRUE(m.load(view_t(modulus, sizeof(modulus))));
	// Формируем машинное слово
	a.word(123456789);
	// Формируем машинное слово
	b.word(987654321);
	// Произведение по модулю эталонным путём
	ASSERT_TRUE(expected.mulmod(a, b, m, true));
	ASSERT_TRUE(b.mulmod(a, b, m, true));
	// Итог совпал с эталонным произведением
	EXPECT_TRUE(b.equal(expected));
	// Объявляем e
	math::integer_t e;
	// Формируем машинное слово
	e.word(65537);
	// Возведение в степень по модулю эталонным путём
	ASSERT_TRUE(expected.power(a, e, m, static_cast <size_t> (17)));
	ASSERT_TRUE(check.power(a, e, m, false));
	// Итог совпал с контрольным значением
	EXPECT_TRUE(expected.equal(check));
	// Объявляем alias
	math::integer_t alias;
	// Модуль загружен в структуру
	ASSERT_TRUE(alias.load(view_t(modulus, sizeof(modulus))));
	ASSERT_TRUE(alias.power(a, e, alias, static_cast <size_t> (17)));
	// Итог на совмещённом месте совпал с эталонным
	EXPECT_TRUE(alias.equal(expected));
}

/**
 * Круг 3: набор шифрования за просьбой о повторе сохраняется (§4.1.4 RFC 8446): билет с хешем ниже по
 * предпочтению сервера при HRR возобновляет связь, а не рвёт её internal_error
 */
TEST(AuditTest, SuiteAfterRetry){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем accepted
	context::ticket_t accepted;
	// Объявляем issued — накопитель изданных билетов
	vector <context::ticket_t> issued;
	// Подлинность с билетом стороны
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256}, accepted, issued));
	// Присваиваем const vector <protect::suite_t> suites значение значение «{protect::suite_t::AES_256_GCM_SHA384, protect::suite_t…»
	const vector <protect::suite_t> suites = {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::AES_128_GCM_SHA256};
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Ограничиваем наборы шифров стороны
	server.suites(suites);
	// Возобновляем связь клиента по билету
	server.resume(issued);
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Ограничиваем наборы шифров стороны
	client.suites(suites);
	// Возобновляем связь клиента по билету
	client.resume(accepted);
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	// Вырабатываем доли разделения секрета
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем равенство server.suite() и protect::suite_t::AES_128_GCM_SHA256
	EXPECT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	// Сервер разделил секреты со стороной
	EXPECT_TRUE(server.shared());
}

/**
 * Круг 3: билет перемещается, а не копируется, и ключ у источника затирается
 */
TEST(AuditTest, TicketMove){
	// Объявляем source
	context::ticket_t source;
	// Заполняем накопитель значением
	source.secret.assign(32, 0x5A);
	// Заполняем накопитель значением
	source.identity.assign(8, 0x11);
	// Объявляем moved и конструируем (::move(source))
	context::ticket_t moved(::move(source));
	// Проверяем равенство moved.secret.size() и static_cast <size_t> (32)
	EXPECT_EQ(moved.secret.size(), static_cast <size_t> (32));
	// Секрет источника переноса пуст
	EXPECT_TRUE(source.secret.empty());
	// Объявляем assigned
	context::ticket_t assigned;
	// Заполняем накопитель значением
	assigned.secret.assign(16, 0x33);
	// Перенос подлинности в новое место
	assigned = ::move(moved);
	// Проверяем равенство assigned.secret.size() и static_cast <size_t> (32)
	EXPECT_EQ(assigned.secret.size(), static_cast <size_t> (32));
	// Секрет перенесённой подлинности пуст
	EXPECT_TRUE(moved.secret.empty());
	EXPECT_TRUE(std::is_nothrow_move_constructible <context::ticket_t>::value);
	EXPECT_TRUE(std::is_nothrow_move_assignable <context::ticket_t>::value);
}

/**
 * Круг 3: DTLS 1.3 - запись при неподтверждённой своей смене ключей и задолженной ответной не отказывает
 * STATE, данные уходят, долг оплачивается после подтверждения (разделы 4.6.3 RFC 8446, 8 RFC 9147)
 */
TEST(AuditTest, OwedUpdate){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established());
	// Клиент меняет ключи и ждёт подтверждения; сервер просит смену у клиента
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	ASSERT_EQ(server.update(true), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> asked значение результат вызова take()
	const vector <uint8_t> asked = take(server);
	// Требуем равенство client.push(view_t(asked.data(), as… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(asked.data(), asked.size())), context::error_t::NONE);
	// Запись при задолженной смене и своей неподтверждённой - уходит
	const string text = "после смены";
	// Проверяем равенство client.write(view_t(reinterpret_cas… и context::error_t::NONE
	EXPECT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Объявляем received — принятые байты
	vector <uint8_t> received;
	// Проверяем равенство server.read(received) и context::error_t::NONE
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
	// Долг оплачен после подтверждения: обе стороны живы и данные ходят в обе стороны
	const string back = "обратно";
	// Проверяем равенство server.write(view_t(reinterpret_cas… и context::error_t::NONE
	EXPECT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (back.data()), back.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Вызываем received.clear()
	received.clear();
	// Проверяем равенство client.read(received) и context::error_t::NONE
	EXPECT_EQ(client.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), back);
	EXPECT_EQ(client.state(), context::state_t::ESTABLISHED);
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
}

/**
 * Круг 3, X.509: критичное nameConstraints признаётся; ограничения судят общее имя без SAN, признак emailAddress,
 * поле subject по directoryName; у якоря из запаса применяются и ограничения, и назначение
 */
TEST(AuditTest, ConstraintsRound3){
	// Объявляем лямбду load — загрузки данных набора
	const auto load = [](const char * name, vector <uint8_t> & result){
		// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
		const vector <uint8_t> text = corpus(name);
		// Объявляем chain — цепочка сертификатов
		vector <vector <uint8_t>> chain;
		// Проверяем, что «text.empty() || (pem::certificates(string(text.begin(), tex…»
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Возвращаем значение «false»
			return false;
		// Первый сертификат цепочки
		result = chain[0];
		// Возвращаем значение «true»
		return true;
	};
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Объявляем rootnc, rooteku, midcrit, lok, midnc, lcn, midmail, lmail, middn, ldn, lanchor и leku
	vector <uint8_t> root, rootnc, rooteku, midcrit, lok, midnc, lcn, midmail, lmail, middn, ldn, lanchor, leku;
	// Сертификат r3-root.crt из корпуса
	ASSERT_TRUE(load("audit/r3-root.crt", root));
	ASSERT_TRUE(load("audit/r3-root-nc.crt", rootnc));
	ASSERT_TRUE(load("audit/r3-root-eku.crt", rooteku));
	ASSERT_TRUE(load("audit/r3-mid-crit.crt", midcrit));
	ASSERT_TRUE(load("audit/r3-l-ok.crt", lok));
	ASSERT_TRUE(load("audit/r3-mid-nc.crt", midnc));
	ASSERT_TRUE(load("audit/r3-l-cn.crt", lcn));
	ASSERT_TRUE(load("audit/r3-mid-mail.crt", midmail));
	ASSERT_TRUE(load("audit/r3-l-mail.crt", lmail));
	ASSERT_TRUE(load("audit/r3-mid-dn.crt", middn));
	ASSERT_TRUE(load("audit/r3-l-dn.crt", ldn));
	ASSERT_TRUE(load("audit/r3-l-anchor.crt", lanchor));
	ASSERT_TRUE(load("audit/r3-l-eku.crt", leku));
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Критичное ограничение - цепочка годна
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {lok, midcrit}, store, moment, trust::role_t::SERVER), trust::error_t::NONE);
	// Общее имя без SAN под ограничением
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {lcn, midnc}, store, moment, trust::role_t::SERVER), trust::error_t::CONSTRAINED);
	// Признак emailAddress владельца под ограничением rfc822Name
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {lmail, midmail}, store, moment), trust::error_t::CONSTRAINED);
	// Поле subject под запрещённым directoryName
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {ldn, middn}, store, moment), trust::error_t::CONSTRAINED);
	// Якорь с ограничением и якорь с чужим назначением
	trust::store_t bounded;
	// Корневой сертификат с пределами имени в хранилище
	ASSERT_TRUE(bounded.add(view_t(rootnc.data(), rootnc.size())));
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::AUTHORITY
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {lanchor}, bounded, moment), trust::error_t::AUTHORITY);
	// Объявляем purposed
	trust::store_t purposed;
	// Корневой сертификат с назначениями в хранилище
	ASSERT_TRUE(purposed.add(view_t(rooteku.data(), rooteku.size())));
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::AUTHORITY
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leku}, purposed, moment, trust::role_t::SERVER), trust::error_t::AUTHORITY);
}

/**
 * Круг 3, DTLS 1.2: чужая открытая запись смены набора с негодным телом по установленной связи роняется, связь жива
 */
TEST(AuditTest, ChangeSpoof){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established());
	// Открытая запись смены набора руками: datagram::build() смену не складывает (круг 7)
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x02};
	// Проверяем равенство server.push(view_t(forged.data(), f… и context::error_t::NONE
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
	EXPECT_EQ(client.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(client.state(), context::state_t::ESTABLISHED);
	// Объявляем text и инициализируем значение «"жива"»
	const string text = "жива";
	// Требуем равенство client.write(view_t(reinterpret_cas… и context::error_t::NONE
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Объявляем received — принятые байты
	vector <uint8_t> received;
	// Проверяем равенство server.read(received) и context::error_t::NONE
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
}

/**
 * Круг 3, DTLS: чужая открытая запись с номером 2^48 - 1 не закрывает настоящие открытые записи, а повтор
 * раздробленного залпа собеседника даёт не более одного повтора своего залпа на срок
 */
TEST(AuditTest, PoisonedWindow){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Отравление: открытый мусор с наибольшим номером клиенту до ответа сервера
	datagram::header_t header;
	// Вид записи: рукопожатие
	header.type = record::type_t::HANDSHAKE;
	// Пора записи нулевая
	header.epoch = 0;
	// Номер записи: наибольший 48-разрядный
	header.sequence = 0xFFFFFFFFFFFFULL;
	// Длина записи: двадцать байтов
	header.size = 20;
	// Объявляем poison — отравленная дейтаграмма и заполняем накопитель (datagram::DATAGRAM_PLAIN_HEADER + 2…)
	vector <uint8_t> poison(datagram::DATAGRAM_PLAIN_HEADER + 20, 0xEE);
	// Объявляем length и инициализируем значение «0»
	size_t length = 0;
	// Собираем дейтаграмму из «header»
	datagram::build(header, poison.data(), length);
	// Проверяем равенство client.push(view_t(poison.data(), p… и context::error_t::NONE
	EXPECT_EQ(client.push(view_t(poison.data(), poison.size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Круг 3 (шифры): пустой кусок после неполного блока не зовёт копирование с нулевым указателем,
 * а итог совпадает с подачей одним куском
 */
TEST(AuditTest, EmptyPiece){
	// Объявляем key размером 32, message размером 21, one размером 16 и two размером 16
	uint8_t key[32], message[21], one[16], two[16];
	/** Заполняем массив key линейной последовательностью */
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (i * 7 + 1);
	/** Заполняем массив message порядковыми номерами байт */
	for(size_t i = 0; i < sizeof(message); i++) message[i] = static_cast <uint8_t> (i);
	// Объявляем whole и pieces
	cipher::poly1305_t whole, pieces;
	// Оба режима заведены с одним ключом
	ASSERT_TRUE(whole.start(view_t(key, sizeof(key))) && pieces.start(view_t(key, sizeof(key))));
	ASSERT_TRUE(whole.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(pieces.update(view_t(message, 5)));
	ASSERT_TRUE(pieces.update(view_t()));
	ASSERT_TRUE(pieces.update(view_t(message + 5, sizeof(message) - 5)));
	ASSERT_TRUE(whole.finish(one) && pieces.finish(two));
	// Проверяем равенство ::memcmp(one, two, sizeof(one)) и 0
	EXPECT_EQ(::memcmp(one, two, sizeof(one)), 0);
	// Объявляем aes
	cipher::aes_t aes;
	// Ключ шифра AES установлен
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	// Присваиваем uint8_t nonce[12] значение значение «{0}»
	uint8_t nonce[12] = {0};
	// Объявляем solid и split
	cipher::gcm_t solid, split;
	// Режим GCM заведён с ключом и синхропосылкой
	ASSERT_TRUE(solid.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	ASSERT_TRUE(split.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	ASSERT_TRUE(solid.associate(view_t(message, sizeof(message))));
	ASSERT_TRUE(split.associate(view_t(message, 5)));
	ASSERT_TRUE(split.associate(view_t()));
	ASSERT_TRUE(split.associate(view_t(message + 5, sizeof(message) - 5)));
	// Объявляем outOne размером 21 и outTwo размером 21
	uint8_t outOne[21], outTwo[21];
	// Зашифрование сообщения целиком
	ASSERT_TRUE(solid.encrypt(view_t(message, sizeof(message)), outOne));
	ASSERT_TRUE(split.encrypt(view_t(message, 5), outTwo));
	ASSERT_TRUE(split.encrypt(view_t(), nullptr));
	ASSERT_TRUE(split.encrypt(view_t(message + 5, sizeof(message) - 5), outTwo + 5));
	ASSERT_TRUE(solid.finish(one) && split.finish(two));
	// Проверяем равенство ::memcmp(outOne, outTwo, sizeof(out… и 0
	EXPECT_EQ(::memcmp(outOne, outTwo, sizeof(outOne)), 0);
	EXPECT_EQ(::memcmp(one, two, sizeof(one)), 0);
}

/**
 * Круг 3 (шифры): длины Argon2 вне 32 разрядов отвергаются до расчёта (RFC 9106 раздел 3.1)
 */
TEST(AuditTest, ArgonBounds){
	// Объявляем params и конструируем (digest::argon_t::ARGON2ID, 64, 1, 1)
	digest::argon_params_t params(digest::argon_t::ARGON2ID, 64, 1, 1);
	// Присваиваем uint8_t password[8] значение значение «{1, 2, 3, 4, 5, 6, 7, 8}, salt[8] = {8, 7, 6, 5, 4, 3,…»
	uint8_t password[8] = {1, 2, 3, 4, 5, 6, 7, 8}, salt[8] = {8, 7, 6, 5, 4, 3, 2, 1}, tag[32];
	// Объявляем huge и конструируем (password, static_cast <size_t> (1) << 32)
	const view_t huge(password, static_cast <size_t> (1) << 32);
	// Проверяем ложность «digest::argon2(params, view_t(password, sizeof(password…»
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), view_t(), tag, huge.size));
	EXPECT_FALSE(digest::argon2(params, huge, view_t(salt, sizeof(salt)), view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), huge, view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), huge, view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), huge, tag, sizeof(tag)));
	// Выработка ключа Argon2 по параметрам
	EXPECT_TRUE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), view_t(), tag, sizeof(tag)));
}

/**
 * Круг 3 (математика): приведение за постоянное время совпадает с делением столбиком на
 * случайных числах всей ёмкости, на нуле, на модуле и на числе с одним старшим разрядом
 */
TEST(AuditTest, Residue){
	// Объявляем modulus, value, slow и fast
	math::integer_t modulus, value, slow, fast;
	// Случайные нечётные модули разной ширины
	const size_t widths[] = {64, 65, 511, 512, 521, 1024, 1536, 2048, 4096, 8191};
	/** Перебираем width по widths */
	for(size_t width : widths){
		/** Перебираем раунды повторения для каждой ширины */
		for(size_t round = 0; round < 8; round++){
			// Случайный модуль заданной ширины
			ASSERT_TRUE(modulus.random(width));
			// Модуль нечётный и не меньше трёх
			uint8_t low[1];
			// Вывод модуля в байты
			ASSERT_TRUE(modulus.store(low, 1) || true);
			// Объявляем one и odd
			math::integer_t one, odd;
			// Формируем машинное слово
			one.word(1);
			// Сложение нечётного модуля с единицей
			ASSERT_TRUE(odd.add(modulus, one));
			// Если число чётное, приводим его к нечётному добавлением модуля
			if(!odd.odd()) odd.add(modulus, one), odd.add(odd, one);
			if(odd.bits() < 2) continue;
			// Число всей ёмкости
			ASSERT_TRUE(value.random(math::INTEGER_BITS));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			// Быстрый путь совпал с медленным
			EXPECT_TRUE(slow.equal(fast)) << width;
			// Число вдвое шире модуля
			ASSERT_TRUE(value.random((width * 2 > math::INTEGER_BITS) ? math::INTEGER_BITS : width * 2));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			// Быстрый путь совпал с медленным
			EXPECT_TRUE(slow.equal(fast)) << width;
			// Число короче модуля
			ASSERT_TRUE(value.random(width / 2 + 1));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			// Быстрый путь совпал с медленным
			EXPECT_TRUE(slow.equal(fast)) << width;
		}
	}
	// Единица и ноль
	math::integer_t one; one.word(1);
	// Объявляем seven — число семь, затем seven.word(7)
	math::integer_t seven; seven.word(7);
	// Остаток по малому модулю быстрым путём
	ASSERT_TRUE(fast.residue(one, seven)); EXPECT_TRUE(fast.equal(one));
	// Вызываем value.clear()
	value.clear();
	// Остаток по малому модулю быстрым путём
	ASSERT_TRUE(fast.residue(value, seven)); EXPECT_TRUE(fast.zero());
	// Само значение, равное модулю, даёт ноль
	ASSERT_TRUE(fast.residue(seven, seven)); EXPECT_TRUE(fast.zero());
	// Чётный модуль отвергается
	math::integer_t eight; eight.word(8);
	// Проверяем ложность «fast.residue(one, eight)»
	EXPECT_FALSE(fast.residue(one, eight));
}

/**
 * Круг 3 (математика): ослепляющее число RSA всегда меньше модуля - секретное действие на ключе
 * с модулем 512 разрядов чуть выше 2^511 не отказывает ни разу за тысячи вызовов
 */
TEST(AuditTest, BlindRange){
	// Объявляем rsa
	sign::rsa_t rsa;
	// Присваиваем const vector <uint8_t> key значение результат вызова corpus()
	const vector <uint8_t> key = corpus("audit/rsa-low.der");
	// Требуем ложность «key.empty()»
	ASSERT_FALSE(key.empty());
	// Разбор ключа RSA из записи
	ASSERT_TRUE(rsa.decode(view_t(key.data(), key.size())));
	// Объявляем input размером 16, enciphered размером 64 и deciphered размером 64
	uint8_t input[16], enciphered[64], deciphered[64];
	/** Заполняем массив input смещённой последовательностью */
	for(size_t i = 0; i < sizeof(input); i++) input[i] = static_cast <uint8_t> (0x21 + i);
	// Зашифрование RSA открытым ключом
	ASSERT_TRUE(rsa.encipher(view_t(input, sizeof(input)), enciphered));
	/** Перебираем: size_t round = 0 при условии round < 2000 */
	for(size_t round = 0; round < 2000; round++){
		// Расшифрование RSA секретным ключом
		ASSERT_TRUE(rsa.decipher(view_t(enciphered, sizeof(enciphered)), deciphered)) << round;
		// Требуем равенство ::memcmp(deciphered + sizeof(deciph… и 0
		ASSERT_EQ(::memcmp(deciphered + sizeof(deciphered) - sizeof(input), input, sizeof(input)), 0);
	}
}

/**
 * Круг 4 (записи): подтверждение на номер записи первой передачи, пришедшее после повтора залпа,
 * подтверждает кусок - часы останавливаются, лишнего повтора нет
 */
TEST(AuditTest, FormerAck){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Доля ключа лишь по GC512C: приветствие обязано уместиться в одну дейтаграмму, проверка ведёт дейтаграммы по одной
	client.shares(vector <extension::group_t> {extension::group_t::GC512C});
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Приветствие клиента серверу, метка возврата состояния, второе приветствие; первый залп сервера задерживается в пути
	const vector <uint8_t> hello = take(client);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> retry значение результат вызова take()
	const vector <uint8_t> retry = take(server);
	// Требуем равенство client.push(view_t(retry.data(), re… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> again значение результат вызова take()
	const vector <uint8_t> again = take(client);
	// Требуем равенство server.push(view_t(again.data(), ag… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	// Присваиваем const vector <vector <uint8_t>> first значение результат вызова drain()
	const vector <vector <uint8_t>> first = drain(server);
	// Требуем ложность «first.empty()»
	ASSERT_FALSE(first.empty());
	// Требуем неравенство server.timeout() и static_cast <uint32_t> (0)
	ASSERT_NE(server.timeout(), static_cast <uint32_t> (0));
	// Срок истёк: сервер повторяет залп новыми номерами записей
	ASSERT_EQ(server.elapsed(), context::error_t::NONE);
	// Присваиваем const vector <vector <uint8_t>> second значение результат вызова drain()
	const vector <vector <uint8_t>> second = drain(server);
	// Требуем ложность «second.empty()»
	ASSERT_FALSE(second.empty());
	/**
	 * Клиент получает задержавшийся первый залп и отвечает своим залпом с подтверждением прежних номеров
	 */
	for(size_t i = 0; i < first.size(); i++)
		// Требуем равенство client.push(view_t(first[i].data(),… и context::error_t::NONE
		ASSERT_EQ(client.push(view_t(first[i].data(), first[i].size())), context::error_t::NONE);
	// Присваиваем const vector <vector <uint8_t>> reply значение результат вызова drain()
	const vector <vector <uint8_t>> reply = drain(client);
	// Требуем ложность «reply.empty()»
	ASSERT_FALSE(reply.empty());
	/** Перебираем: size_t i = 0 при условии i < reply.size() */
	for(size_t i = 0; i < reply.size(); i++)
		// Требуем равенство server.push(view_t(reply[i].data(),… и context::error_t::NONE
		ASSERT_EQ(server.push(view_t(reply[i].data(), reply[i].size())), context::error_t::NONE);
	// Забираем все дейтаграммы стороны, отбрасывая результат
	(void) drain(server);
	// Связь установлена обеими сторонами, а часы сервера остановлены: залп подтверждён по прежним номерам
	EXPECT_TRUE(server.established()) << static_cast <int> (server.error());
	// Проверяем равенство server.timeout() и static_cast <uint32_t> (0)
	EXPECT_EQ(server.timeout(), static_cast <uint32_t> (0));
}

/**
 * @brief Функция чтения сертификата набора записью DER
 *
 * @param name имя файла
 * @return     запись DER либо пустой накопитель
 *
 */
static vector <uint8_t> certified(const char * name) noexcept {
	// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
	const vector <uint8_t> text = corpus(name);
	// Объявляем chain — цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Проверяем, что «text.empty() || (pem::certificates(string(text.begin(), tex…»
	if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
		// Возвращаем значение «vector <uint8_t> ()»
		return vector <uint8_t> ();
	// Возвращаем значение «chain[0]»
	return chain[0];
}

/**
 * Круг 4 (X.509): звено с подписью SHA-1 либо ключом RSA короче 2048 разрядов отвергается (WEAK)
 */
TEST(AuditTest, WeakChain){
	// Присваиваем const vector <uint8_t> root значение результат вызова certified()
	const vector <uint8_t> root = certified("audit/weak-root.crt"), sha1 = certified("audit/weak-sha1.crt"), rsa = certified("audit/weak-rsa.crt"), ok = certified("audit/weak-ok.crt");
	// Требуем ложность «root.empty() || sha1.empty() || rsa.empty() || ok.empty…»
	ASSERT_FALSE(root.empty() || sha1.empty() || rsa.empty() || ok.empty());
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::NONE
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {ok}, store, moment), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {sha1}, store, moment), trust::error_t::WEAK);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {rsa}, store, moment), trust::error_t::WEAK);
}

/**
 * Круг 4 (X.509): directoryName из subjectAltName судится ограничениями того же уровня, что и поле subject;
 * общее имя, не похожее на имя узла, под ограничения dNSName не подпадает; почта под permitted email
 */
TEST(AuditTest, DirectoryConstraints){
	// Присваиваем const vector <uint8_t> root значение результат вызова certified()
	const vector <uint8_t> root = certified("audit/r4-root.crt");
	// Требуем ложность «root.empty()»
	ASSERT_FALSE(root.empty());
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Исключённое поддерево C=RU: лист с SAN dirName /C=RU/CN=hidden - отказ
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r4-leafA.crt"), certified("audit/r4-mid-ex.crt")}, store, moment), trust::error_t::CONSTRAINED);
	// Дозволенное поддерево C=RU: subject /C=RU/CN=b и SAN dirName /C=RU/CN=b2 - годно
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r4-leafB.crt"), certified("audit/r4-mid-pe.crt")}, store, moment), trust::error_t::NONE);
	// Дозволено DNS .example.com: клиентский лист с CN «Ivan Petrov» без SAN - имя человека не судится как узел
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r4-leafC.crt"), certified("audit/r4-mid-dns.crt")}, store, moment, trust::role_t::CLIENT), trust::error_t::NONE);
	// Дозволена почта .example.com: user@example.com вне поддерева (ведущая точка - лишь подчинённые узлы, как у openssl), длинный подчинённый узел годен
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r4-leafD.crt"), certified("audit/r4-mid-mail.crt")}, store, moment), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r4-leafE.crt"), certified("audit/r4-mid-mail.crt")}, store, moment), trust::error_t::NONE);
}

/**
 * Круг 4 (математика): детерминированная подпись ECDSA по RFC 6979 на кривой с порядком от 0x80…
 * (ГОСТ paramSetB) не срывается: кандидат k отбрасывается в половине попыток, попыток довольно
 */
TEST(AuditTest, SigningAttempts){
	// Объявляем curve
	curve::curve_t curve;
	// Параметры кривой ГОСТ по опознавателю
	ASSERT_TRUE(curve::parameters(string("1.2.643.7.1.2.1.2.2"), curve));
	// Объявляем ecdsa
	sign::ecdsa_t ecdsa;
	// Кривая подписи установлена
	ASSERT_TRUE(ecdsa.start(curve));
	// Объявляем secret размером 64
	uint8_t secret[64];
	// Выработка пары ключей подписи
	ASSERT_TRUE(ecdsa.generate(secret, sizeof(secret)));
	// Объявляем digest размером 32 и signature размером 256
	uint8_t digest[32], signature[256];
	/** Перебираем: size_t i = 0 при условии i < 400 */
	for(size_t i = 0; i < 400; i++){
		/** Заполняем массив digest псевдослучайной последовательностью */
		for(size_t j = 0; j < sizeof(digest); j++) digest[j] = static_cast <uint8_t> ((i * 131 + j * 17) & 0xFF);
		// Выработка подписи сообщения
		ASSERT_TRUE(ecdsa.make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), signature)) << i;
	}
}

/**
 * Круг 4 (шифры): имитовставка закрывается после снятия - повторное снятие и подача отвергаются
 */
TEST(AuditTest, ImitationClosed){
	// Объявляем key размером 32
	uint8_t key[32];
	/** Заполняем массив key порядковыми номерами байт */
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (i);
	// Объявляем base
	cipher::kuznyechik_t base;
	// Ключ блочного шифра установлен
	ASSERT_TRUE(base.key(view_t(key, sizeof(key))));
	// Объявляем mode
	cipher::imitation_t mode;
	// Режим шифрования заведён
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	// Присваиваем uint8_t message[40] значение значение «{0}, one[16], two[16]»
	uint8_t message[40] = {0}, one[16], two[16];
	// Подача сообщения в режим
	ASSERT_TRUE(mode.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(mode.finish(one, sizeof(one)));
	// Проверяем ложность «mode.finish(two, sizeof(two))»
	EXPECT_FALSE(mode.finish(two, sizeof(two)));
	EXPECT_FALSE(mode.update(view_t(message, sizeof(message))));
	EXPECT_FALSE(mode.ready());
}

/**
 * Круг 4 (шифры): вскрытие Noise на месте (итог поверх входа) даёт тот же хеш рукопожатия, что и в отдельное место
 */
TEST(AuditTest, NoiseAlias){
	// Объявляем name и инициализируем значение «"Noise_NN_25519_ChaChaPoly_SHA256"»
	const string name = "Noise_NN_25519_ChaChaPoly_SHA256";
	// Объявляем key размером 32
	uint8_t key[32];
	/** Заполняем массив key смещённой последовательностью */
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (0x40 + i);
	// Объявляем sender, apart и inplace
	noise::symmetric_t sender, apart, inplace;
	// Объявляем suite и конструируем (noise::dh_t::X25519, noise::aead_t::CHACHAP…)
	const noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256);
	// Отправитель заведён с именем
	ASSERT_TRUE(sender.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && sender.key(view_t(key, sizeof(key))));
	ASSERT_TRUE(apart.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && apart.key(view_t(key, sizeof(key))));
	ASSERT_TRUE(inplace.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && inplace.key(view_t(key, sizeof(key))));
	// Объявляем text и инициализируем значение «"сообщение длиннее блока для вскрытия на месте"»
	const string text = "сообщение длиннее блока для вскрытия на месте";
	// Объявляем sealed размером 128 и opened размером 128
	uint8_t sealed[128], opened[128];
	// Объявляем size и инициализируем результат вызова sizeof()
	size_t size = sizeof(sealed);
	// Запечатывание текста отправителем
	ASSERT_TRUE(sender.seal(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), sealed, size));
	// Объявляем mirror размером 128
	uint8_t mirror[128];
	// Копируем size из sealed в mirror
	::memcpy(mirror, sealed, size);
	// Объявляем got и инициализируем результат вызова sizeof()
	size_t got = sizeof(opened);
	// Распечатывание в отдельное место
	ASSERT_TRUE(apart.open(view_t(sealed, size), opened, got));
	// Объявляем here и инициализируем результат вызова sizeof()
	size_t here = sizeof(mirror);
	// Распечатывание на месте
	ASSERT_TRUE(inplace.open(view_t(mirror, size), mirror, here));
	// Проверяем равенство got и here
	EXPECT_EQ(got, here);
	EXPECT_EQ(::memcmp(opened, mirror, got), 0);
	// Объявляем first размером 64, second размером 64 и third размером 64
	uint8_t first[64], second[64], third[64];
	// Итоги хешей сторон совпали
	ASSERT_TRUE(sender.digest(first) && apart.digest(second) && inplace.digest(third));
	// Проверяем равенство ::memcmp(first, second, 32) и 0
	EXPECT_EQ(::memcmp(first, second, 32), 0);
	EXPECT_EQ(::memcmp(first, third, 32), 0);
}

/**
 * Круг 4 (разборщики): профиль отпечатка с принятого приветствия снимается и поверх дейтаграмм
 */
TEST(AuditTest, ServerProfileDatagram){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established());
	// Объявляем profile
	fingerprint::profile_t profile;
	// Проверяем равенство server.profile(profile) и context::error_t::NONE
	EXPECT_EQ(server.profile(profile), context::error_t::NONE);
	// Проверяем ложность «profile.suites.empty()»
	EXPECT_FALSE(profile.suites.empty());
}

/**
 * Круг 4 (движок): предупреждение изданий до 1.3 (unrecognized_name уровня warning перед ServerHello)
 * связь не рвёт - рукопожатие доходит до конца (раздел 7.2.2 RFC 5246, раздел 3 RFC 6066)
 */
TEST(AuditTest, WarningAlert){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> hello значение результат вызова take()
	const vector <uint8_t> hello = take(client);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Присваиваем vector <uint8_t> flight значение результат вызова take()
	vector <uint8_t> flight = take(server);
	// Требуем ложность «flight.empty()»
	ASSERT_FALSE(flight.empty());
	// Предупреждение unrecognized_name (112) уровня warning (1) перед залпом сервера
	const uint8_t warning[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x70};
	// Вызываем flight.insert(flight.begin(), warning, warning + sizeof(warning))
	flight.insert(flight.begin(), warning, warning + sizeof(warning));
	// Проверяем равенство client.push(view_t(flight.data(), f… и context::error_t::NONE
	EXPECT_EQ(client.push(view_t(flight.data(), flight.size())), context::error_t::NONE);
	// Проверяем неравенство client.state() и context::state_t::FAILED
	EXPECT_NE(client.state(), context::state_t::FAILED);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Смертельный уровень рвёт связь по-прежнему
	client::context_t other;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(other);
	// Объявляем another
	server::context_t another;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(another);
	// Задаём подлинность стороны
	another.credential(credential);
	// Требуем равенство another.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(another.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(another.start(), context::error_t::NONE);
	ASSERT_EQ(other.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> greeting значение результат вызова take()
	const vector <uint8_t> greeting = take(other);
	// Требуем равенство another.push(view_t(greeting.data()… и context::error_t::NONE
	ASSERT_EQ(another.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	// Присваиваем vector <uint8_t> reply значение результат вызова take()
	vector <uint8_t> reply = take(another);
	// Присваиваем const uint8_t fatal[] значение значение «{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70}»
	const uint8_t fatal[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70};
	// Вызываем reply.insert(reply.begin(), fatal, fatal + sizeof(fatal))
	reply.insert(reply.begin(), fatal, fatal + sizeof(fatal));
	// Проверяем равенство other.push(view_t(reply.data(), rep… и context::error_t::ALERT
	EXPECT_EQ(other.push(view_t(reply.data(), reply.size())), context::error_t::ALERT);
	EXPECT_EQ(other.state(), context::state_t::FAILED);
}

/**
 * Круг 4 (движок): клиент 1.2 с обменом ключами RSA и запросом состояния доводит рукопожатие, когда сервер
 * объявил status_request, но CertificateStatus не прислал (раздел 8 RFC 6066: MAY)
 */
TEST(AuditTest, StatusAbsent){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа rsa2048
	ASSERT_TRUE(keyfile("rsa2048", credential));
	// Присваиваем const vector <uint8_t> answer значение результат вызова corpus()
	const vector <uint8_t> answer = corpus("ocsp/rsa2048.good.der");
	// Требуем ложность «answer.empty()»
	ASSERT_FALSE(answer.empty());
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Получаем статус операции
	server.status(answer);
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::RSA_AES_128_GCM_SHA256});
	// Получаем статус операции
	client.status(true);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> hello значение результат вызова take()
	const vector <uint8_t> hello = take(client);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> flight значение результат вызова take()
	const vector <uint8_t> flight = take(server);
	// Требуем ложность «flight.empty()»
	ASSERT_FALSE(flight.empty());
	// Вырезаем запись с сообщением CertificateStatus (вид 22)
	vector <uint8_t> trimmed;
	// Объявляем cut и инициализируем значение «false»
	bool cut = false;
	/** Перебираем по условию «size_t offset = 0; (offset + 5) <= flight.size(…» */
	for(size_t offset = 0; (offset + 5) <= flight.size();){
		// Объявляем length и инициализируем значение «((static_cast <size_t> (flight[offset + 3]) << 8) | fli…»
		const size_t length = ((static_cast <size_t> (flight[offset + 3]) << 8) | flight[offset + 4]);
		// Требуем: offset + 5 + length не больше flight.size()
		ASSERT_LE(offset + 5 + length, flight.size());
		// Проверяем, что «(flight[offset] == 0x16) && (length > 0) && (flight[offset…»
		if((flight[offset] == 0x16) && (length > 0) && (flight[offset + 5] == 22))
			// Отмечаем обрыв записи
			cut = true;
		else
			trimmed.insert(trimmed.end(), flight.begin() + offset, flight.begin() + offset + 5 + length);
		// Прибавляем к offset «(5 + length)»
		offset += (5 + length);
	}
	// Запись оборвана как задумано
	ASSERT_TRUE(cut);
	// Клиент принимает залп без CertificateStatus и идёт дальше: прежде он рвал связь ORDER/unexpected_message
	EXPECT_EQ(client.push(view_t(trimmed.data(), trimmed.size())), context::error_t::NONE);
	// Проверяем неравенство client.state() и context::state_t::FAILED
	EXPECT_NE(client.state(), context::state_t::FAILED);
	EXPECT_NE(client.error(), context::error_t::ORDER);
	// Переписка разошлась с сервером (он CertificateStatus слал): завершение не сойдётся у сервера, не у клиента
	converse(client, server);
	// Проверяем неравенство client.error() и context::error_t::ORDER
	EXPECT_NE(client.error(), context::error_t::ORDER);
	EXPECT_NE(client.alert().description, alert::description_t::UNEXPECTED);
}

/**
 * Круг 4 (движок): запрос сердцебиения поверх дейтаграмм обязан уместиться в дейтаграмму - иначе LIMIT
 */
TEST(AuditTest, Heartroom){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Профиль с расширением heartbeat (режим 1) от клиента-донора
	fingerprint::profile_t profile;
	{
		// Объявляем donor
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Доля ключа лишь по GC512C: приветствие донора обязано уместиться в одну дейтаграмму
		donor.shares(vector <extension::group_t> {extension::group_t::GC512C});
		// Задаём транспорт движку
		donor.transport(context::transport_t::DATAGRAMS);
		// Задаём имя проверки
		donor.name("example.com");
		// Требуем равенство donor.start() и context::error_t::NONE
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		// Объявляем extension
		fingerprint::extension_t extension;
		// Вид расширения: heartbeat (0x000F)
		extension.type = 0x000F;
		// Тело расширения: один байт
		extension.data = vector <uint8_t> {0x01};
		// Добавляем элемент в конец накопителя
		profile.extensions.push_back(extension);
	}
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Задаём имя проверки
	client.name("example.com");
	// Требуем равенство client.profile(profile) и context::error_t::NONE
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Вызываем client.mtu(600)
	client.mtu(600);
	// Объявляем large — большой накопитель и заполняем накопитель (1000, 0x5A), small(300, 0x5A)
	vector <uint8_t> large(1000, 0x5A), small(300, 0x5A);
	// Проверяем равенство client.heartbeat(view_t(large.data(… и context::error_t::LIMIT
	EXPECT_EQ(client.heartbeat(view_t(large.data(), large.size())), context::error_t::LIMIT);
	EXPECT_EQ(client.heartbeat(view_t(small.data(), small.size())), context::error_t::NONE);
}

/**
 * Круг 5 (движок): по согласованному изданию 1.3 извещение уровня warning с любым описанием, кроме
 * close_notify/user_canceled, рвёт связь (раздел 6.2 RFC 8446) - признак «до согласования» это
 * нулевое издание, а не NPN
 */
TEST(AuditTest, WarningModern){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Присваиваем const uint8_t DESCRIPTIONS[] значение значение «{51, 42, 109, 255}»
	const uint8_t DESCRIPTIONS[] = {51, 42, 109, 255};
	/** Перебираем: size_t i = 0 при условии i < sizeof(DESCRIPTIONS) */
	for(size_t i = 0; i < sizeof(DESCRIPTIONS); i++){
		// Объявляем client и конструируем (false), server(true)
		internal::engine_t client(false), server(true);
		// Задаём имя проверки
		client.name("example.com");
		// Задаём подлинность стороны
		server.credential(credential);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/** Перебираем: size_t round = 0 при условии round < 16 */
		for(size_t round = 0; round < 16; round++){
			// Объявляем moved и инициализируем значение «false»
			bool moved = false;
			// Объявляем data и инициализируем результат вызова client.output()
			view_t data = client.output();
			// Выполняем «if(data.size > 0){ vector <uint8_t> buffer(data.data, d…», затем client.consume(buffer.size())
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); moved = true; }
			// Вывод сервера забирается целиком
			data = server.output();
			// Выполняем «if(data.size > 0){ vector <uint8_t> buffer(data.data, d…», затем server.consume(buffer.size())
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); moved = true; }
			if(!moved) break;
		}
		// Требуем равенство client.state() и context::state_t::ESTABLISHED
		ASSERT_EQ(client.state(), context::state_t::ESTABLISHED);
		ASSERT_EQ(client.version(), 0x0304);
		// Запечатываем извещение уровня warning ключами клиента
		uint8_t traffic[64];
		// Объявляем width и инициализируем значение «0»
		size_t width = 0;
		// Секрет прикладного уровня клиента получен
		ASSERT_TRUE(client.secret(context::level_t::APPLICATION, context::direction_t::WRITE, traffic, width));
		// Объявляем key размером protect::PROTECT_KEY и iv размером protect::PROTECT_VECTOR
		uint8_t key[protect::PROTECT_KEY], iv[protect::PROTECT_VECTOR];
		// Требуем равенство session::material(view_t(traffic, w… и session::error_t::NONE
		ASSERT_EQ(session::material(view_t(traffic, width), client.suite(), key, iv), session::error_t::NONE);
		// Объявляем protection
		protect::protection_t protection;
		// Защита записей заведена с ключом клиента
		ASSERT_TRUE(protection.start(client.suite(), view_t(key, protect::key(client.suite())), view_t(iv, protect::block(client.suite()))));
		/** Гоняем защиту записей подряд идущими порядковыми номерами */
		for(uint64_t sequence = 0; sequence < client.sequence(false); sequence++){ vector <uint8_t> junk; protection.seal(record::type_t::APPLICATION, view_t(iv, 1), junk, 0); }
		// Присваиваем const uint8_t alert[2] значение значение «{0x01, DESCRIPTIONS[i]}»
		const uint8_t alert[2] = {0x01, DESCRIPTIONS[i]};
		// Объявляем sealed — защищённые данные
		vector <uint8_t> sealed;
		// Требуем равенство protection.seal(record::type_t::ALE… и protect::error_t::NONE
		ASSERT_EQ(protection.seal(record::type_t::ALERT, view_t(alert, 2), sealed, 0), protect::error_t::NONE);
		// Проверяем равенство server.push(view_t(sealed.data(), s… и context::error_t::ALERT)
		EXPECT_EQ(server.push(view_t(sealed.data(), sealed.size())), context::error_t::ALERT) << static_cast <int> (DESCRIPTIONS[i]);
		EXPECT_EQ(server.state(), context::state_t::FAILED) << static_cast <int> (DESCRIPTIONS[i]);
		EXPECT_EQ(static_cast <uint8_t> (server.alert().description), DESCRIPTIONS[i]);
	}
}

/**
 * Круг 5 (движок): клиент, объявивший peer_not_allowed_to_send (режим 2), на запрос сердцебиения сервера не отвечает
 */
TEST(AuditTest, HeartbeatForbidden){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	/** Перебираем: uint8_t mode = 1 при условии mode <= 2 */
	for(uint8_t mode = 1; mode <= 2; mode++){
		// Объявляем profile
		fingerprint::profile_t profile;
		{
			// Объявляем donor
			client::context_t donor;
			// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
			gosting(donor);
			// Задаём имя проверки
			donor.name("example.com");
			// Требуем равенство donor.start() и context::error_t::NONE
			ASSERT_EQ(donor.start(), context::error_t::NONE);
			ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
			// Объявляем extension
			fingerprint::extension_t extension;
			// Вид расширения: heartbeat (0x000F)
			extension.type = 0x000F;
			// Тело расширения: режим стороны
			extension.data = vector <uint8_t> {mode};
			// Добавляем элемент в конец накопителя
			profile.extensions.push_back(extension);
		}
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём имя проверки
		client.name("example.com");
		// Требуем равенство client.profile(profile) и context::error_t::NONE
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Сервер шлёт запрос сердцебиения: при режиме 2 клиента ему это не дозволено (SETTINGS), при режиме 1 клиент отвечает
		const string payload = "запрос сервера";
		// Проверяем равенство server.heartbeat(view_t(reinterpret… и ((mode == 1) ? context::error_t::NO…
		EXPECT_EQ(server.heartbeat(view_t(reinterpret_cast <const uint8_t *> (payload.data()), payload.size())), ((mode == 1) ? context::error_t::NONE : context::error_t::SETTINGS)) << static_cast <int> (mode);
		// Проводим связь сторон до тишины
		converse(client, server);
		// При режиме 1 ответ пришёл, при режиме 2 - нет
				EXPECT_EQ(server.pulses(), static_cast <size_t> ((mode == 1) ? 1 : 0)) << static_cast <int> (mode);
	}
}

/**
 * Круг 5 (движок): сервер, служащий ECH, не пропускает молча негодные записи клиента без ECH -
 * порченое завершение клиента рвёт связь bad_record_mac (раздел 5.2 RFC 8446)
 */
TEST(AuditTest, EchNoSkip){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.ech(vector <uint8_t> (), "pu… и context::error_t::NONE
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> hello значение результат вызова take()
	const vector <uint8_t> hello = take(client);
	// Требуем равенство server.push(view_t(hello.data(), he… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> flight значение результат вызова take()
	const vector <uint8_t> flight = take(server);
	// Требуем равенство client.push(view_t(flight.data(), f… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(flight.data(), flight.size())), context::error_t::NONE);
	// Присваиваем vector <uint8_t> finished значение результат вызова take()
	vector <uint8_t> finished = take(client);
	// Требуем: finished.size() больше static_cast <size_t> (6)
	ASSERT_GT(finished.size(), static_cast <size_t> (6));
	// Портим последний байт защищённой записи завершения
	finished.back() ^= 0x01;
	// Проверяем равенство server.push(view_t(finished.data(),… и context::error_t::PROTECTION
	EXPECT_EQ(server.push(view_t(finished.data(), finished.size())), context::error_t::PROTECTION);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.alert().description, alert::description_t::MAC);
}

/**
 * Круг 5 (записи): подтверждение дробится по месту в дейтаграмме - при MTU 256 и сорока принятых
 * записях ни одна дейтаграмма не шире MTU (раздел 4.4 RFC 9147)
 */
TEST(AuditTest, AckSplit){
	// Объявляем flight
	internal::flight_t flight;
	// Вызываем flight.mtu(256)
	flight.mtu(256);
	// Объявляем count и инициализируем значение «40»
	const size_t count = 40;
	/** Перебираем: size_t i = 0 при условии i < count */
	for(size_t i = 0; i < count; i++){
		// Объявляем fragment
		datagram::fragment_t fragment;
		// Вид сообщения части: CERTIFICATE
		fragment.type = handshake::type_t::CERTIFICATE;
		// Номер сообщения части
		fragment.sequence = 1;
		// Полная длина сообщения по числу частей
		fragment.size = (count * 10);
		// Сдвиг части по десять байтов
		fragment.offset = (i * 10);
		// Длина части: десять байтов
		fragment.length = 10;
		// Объявляем piece — фрагмент дейтаграммы и заполняем накопитель (datagram::DATAGRAM_FRAGMENT_HEADER…)
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 10, 0x41);
		// Требуем равенство datagram::build(fragment, piece.dat… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		// Заголовок сообщения рукопожатия
		datagram::header_t header;
		// Заголовок записи раздельный
		header.unified = false;
		// Вид записи: рукопожатие
		header.type = record::type_t::HANDSHAKE;
		// Пора записи нулевая
		header.epoch = 0;
		// Номер записи по номеру части
		header.sequence = i;
		// Длина записи по длине куска
		header.size = piece.size();
		// Объявляем head размером datagram::DATAGRAM_PLAIN_HEADER
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		// Объявляем length и инициализируем значение «0»
		size_t length = 0;
		// Требуем равенство datagram::build(header, head, lengt… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		// Объявляем wire — проволочные данные и конструируем из head, head + length
		vector <uint8_t> wire(head, head + length);
		// Вызываем wire.insert(wire.end(), piece.begin(), piece.end())
		wire.insert(wire.end(), piece.begin(), piece.end());
		// Объявляем opened — открытые записи
		vector <internal::opened_t> opened;
		// Требуем равенство flight.receive(view_t(wire.data(),… и context::error_t::NONE
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		/** Перебираем: size_t j = 0 при условии j < opened.size() */
		for(size_t j = 0; j < opened.size(); j++)
			// Проверяем, что «opened[j].type == record::type_t::HANDSHAKE»
			if(opened[j].type == record::type_t::HANDSHAKE)
				// Вызываем flight.fragments(view_t(opened[j].content.data(), opened…)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	// Требуем равенство flight.complete(false) и context::error_t::NONE
	ASSERT_EQ(flight.complete(false), context::error_t::NONE);
	// Объявляем datagrams и инициализируем значение «0, widest = 0»
	size_t datagrams = 0, widest = 0;
	/** Перебираем: view_t out = flight.output() при условии out.size > 0 */
	for(view_t out = flight.output(); out.size > 0; out = flight.output()){
		// Увеличиваем счётчик полученных дейтаграмм
		datagrams++;
		// Наибольшая длина записи из увиденных
		widest = ((out.size > widest) ? out.size : widest);
		// Забираем обработанные стороной байты
		flight.consume();
	}
	// Проверяем: datagrams не меньше static_cast <size_t> (3)
	EXPECT_GE(datagrams, static_cast <size_t> (3));
	// Проверяем: widest не больше static_cast <size_t> (256)
	EXPECT_LE(widest, static_cast <size_t> (256));
}

/**
 * Круг 5 (шифры): узор Noise с двумя предсообщениями (KK) - отказ чтения до заведения своего постоянного ключа
 * не портит хеш: после дозаведения ключа чтение того же сообщения удаётся
 */
TEST(AuditTest, NoiseReady){
	// Объявляем name и инициализируем значение «"Noise_KK_25519_ChaChaPoly_SHA256"»
	const string name = "Noise_KK_25519_ChaChaPoly_SHA256";
	// Объявляем pattern и конструируем (reinterpret_cast <const uint8_t *> (name.da…)
	const view_t pattern(reinterpret_cast <const uint8_t *> (name.data()), name.size());
	// Объявляем si размером 32, pi размером 32, sr размером 32 и pr размером 32
	uint8_t si[32], pi[32], sr[32], pr[32];
	// Пары ключей сторон Noise выработаны
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi) && noise::generate(noise::dh_t::X25519, sr, pr));
	// Объявляем initiator и responder
	noise::handshake_t initiator, responder;
	// Инициатор Noise заведён по узору
	ASSERT_TRUE(initiator.start(pattern, noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(initiator.statics(view_t(si, 32)) && initiator.remote(view_t(pr, 32)));
	// Объявляем message размером noise::MESSAGE и payload размером noise::MESSAGE
	uint8_t message[noise::MESSAGE], payload[noise::MESSAGE];
	// Объявляем size и инициализируем результат вызова sizeof()
	size_t size = sizeof(message);
	// Запись сообщения инициатора
	ASSERT_TRUE(initiator.write(view_t(), message, size));
	ASSERT_TRUE(responder.start(pattern, noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(responder.remote(view_t(pi, 32)));
	// Чтение до заведения своего ключа отвергается, состояние не портится
	size_t length = sizeof(payload);
	// Проверяем ложность «responder.read(view_t(message, size), payload, length)»
	EXPECT_FALSE(responder.read(view_t(message, size), payload, length));
	// Статический ключ отвечающего установлен
	ASSERT_TRUE(responder.statics(view_t(sr, 32)));
	// Длина полезной нагрузки
	length = sizeof(payload);
	// Чтение сообщения отвечающим
	EXPECT_TRUE(responder.read(view_t(message, size), payload, length));
}

/**
 * Круг 5 (X.509): якорь с самоподписью SHA-1 годен (самоподпись не судится), подпись RSASSA-PSS с SHA-1 у звена слаба
 */
TEST(AuditTest, WeakEdges){
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	{
		// Хранилище доверия
		trust::store_t store;
		// Присваиваем const vector <uint8_t> root значение результат вызова certified()
		const vector <uint8_t> root = certified("audit/r5-a-root.crt");
		// Корневой сертификат в хранилище доверия
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::NONE
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-a-leaf.crt")}, store, moment), trust::error_t::NONE);
	}
	{
		// Хранилище доверия
		trust::store_t store;
		// Присваиваем const vector <uint8_t> root значение результат вызова certified()
		const vector <uint8_t> root = certified("audit/r5-c-root.crt");
		// Корневой сертификат в хранилище доверия
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::WEAK
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-c-leaf.crt")}, store, moment), trust::error_t::WEAK);
	}
}

/**
 * Круг 5 (движок): профиль отпечатка с изданием 1.2 при заданных конфигурациях ECH отвергается (SETTINGS),
 * а при обратном порядке издание 1.2 в приветствие не идёт - связь под ECH устанавливается принятой
 */
TEST(AuditTest, EchProfile){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем profile
	fingerprint::profile_t profile;
	{
		// Объявляем donor
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём имя проверки
		donor.name("example.com");
		// Требуем равенство donor.start() и context::error_t::NONE
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		// Объявляем found и инициализируем значение «false»
		bool found = false;
		/** Перебираем: size_t i = 0 при условии i < profile.extensions.size() */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Проверяем, что «profile.extensions[i].type == 0x002B»
			if(profile.extensions[i].type == 0x002B){
				// Издания расширения: TLS 1.3 и 1.2
				profile.extensions[i].versions = vector <uint16_t> {0x0304, 0x0303};
				// Отмечаем находку расширения
				found = true;
			}
		}
		// Расширение найдено в профиле
		ASSERT_TRUE(found);
	}
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.ech(vector <uint8_t> (), "pu… и context::error_t::NONE
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	// ECH, затем профиль с 1.2 - отказ
	client::context_t first;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(first);
	// Задаём имя проверки
	first.name("secret.example");
	// Требуем равенство first.ech(server.ech()) и context::error_t::NONE
	ASSERT_EQ(first.ech(server.ech()), context::error_t::NONE);
	// Проверяем равенство first.profile(profile) и context::error_t::SETTINGS
	EXPECT_EQ(first.profile(profile), context::error_t::SETTINGS);
	// Отвергнутый профиль связи не коснулся: перечень наборов приветствия тот же, что у клиента без профиля
	client::context_t bare;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(bare);
	// Задаём имя проверки
	bare.name("secret.example");
	// Требуем равенство bare.ech(server.ech()) и context::error_t::NONE
	ASSERT_EQ(bare.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	ASSERT_EQ(bare.start(), context::error_t::NONE);
	// Объявляем seen и plain
	fingerprint::profile_t seen, plain;
	// Требуем равенство fingerprint::parse(first.output(),… и fingerprint::error_t::NONE
	ASSERT_EQ(fingerprint::parse(first.output(), seen), fingerprint::error_t::NONE);
	ASSERT_EQ(fingerprint::parse(bare.output(), plain), fingerprint::error_t::NONE);
	// Проверяем равенство seen.suites.size() и plain.suites.size()
	EXPECT_EQ(seen.suites.size(), plain.suites.size());
	// Профиль, затем ECH - издание 1.2 в приветствие не идёт, ECH принят
	client::context_t second;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(second);
	// Задаём имя проверки
	second.name("secret.example");
	// Требуем равенство second.profile(profile) и context::error_t::NONE
	ASSERT_EQ(second.profile(profile), context::error_t::NONE);
	ASSERT_EQ(second.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(second.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(second, server);
	// Связь второй стороны и сервера установлена
	EXPECT_TRUE(second.established() && server.established()) << static_cast <int> (second.error()) << " " << static_cast <int> (server.error());
	EXPECT_TRUE(second.shrouded());
}

/**
 * Круг 5 (X.509): отличительные имена сличаются по разделу 7.1 RFC 5280 - подмена UTF8String на
 * PrintableString не обходит исключённое поддерево; звено, лежащее в запасе, замыкает цепочку -
 * истёкший прежний корень над доверенным промежуточным не судится
 */
TEST(AuditTest, NamesAndAnchors){
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	{
		// Хранилище доверия
		trust::store_t store;
		// Присваиваем const vector <uint8_t> root значение результат вызова certified()
		const vector <uint8_t> root = certified("audit/r5-b-root.crt");
		// Корневой сертификат в хранилище доверия
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		// Присваиваем const vector <uint8_t> middle значение результат вызова certified()
		const vector <uint8_t> middle = certified("audit/r5-b-mid.crt");
		// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::CONSTRAINED
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-b-leaf-utf8.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-b-leaf-print.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	}
	{
		// Хранилище доверия
		trust::store_t store;
		// Присваиваем const vector <uint8_t> middle значение результат вызова certified()
		const vector <uint8_t> middle = certified("audit/r5-m-mid.crt");
		// Корневой сертификат в хранилище доверия
		ASSERT_TRUE(store.add(view_t(middle.data(), middle.size())));
		// Присваиваем const vector <uint8_t> leaf значение результат вызова certified()
		const vector <uint8_t> leaf = certified("audit/r5-m-leaf.crt"), root = certified("audit/r5-m-root.crt");
		// Без истёкшего корня и с ним итог один: доверенное промежуточное замыкает цепочку
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment), trust::error_t::NONE);
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle, root}, store, moment), trust::error_t::NONE);
	}
}

/**
 * Круг 5 (математика): обращение по модулю при совпадении итога с модулем (алиасинг) верно
 */
TEST(AuditTest, InvertAlias){
	// Объявляем modulus, value и expected
	math::integer_t modulus, value, expected;
	// Формируем машинное слово
	modulus.word(1000003);
	// Формируем машинное слово
	value.word(6);
	// Обращение по модулю эталонным путём
	ASSERT_TRUE(expected.invert(value, modulus));
	// Требуем ложность «expected.zero()»
	ASSERT_FALSE(expected.zero());
	// Итог поверх модуля
	math::integer_t aliased;
	// Формируем машинное слово
	aliased.word(1000003);
	// Обращение на совмещённом месте
	ASSERT_TRUE(aliased.invert(value, aliased));
	// Итог на совмещённом месте совпал с эталонным
	EXPECT_TRUE(aliased.equal(expected));
	// Итог поверх значения
	math::integer_t other;
	// Формируем машинное слово
	other.word(6);
	// Обращение значения на себя
	ASSERT_TRUE(other.invert(other, modulus));
	// Итог совпал с эталонным обращением
	EXPECT_TRUE(other.equal(expected));
}

/**
 * Круг 6 (X.509): разделители в свёртке RDN экранируются - значение «y;2.5.4.3=x» не выдаёт себя за два
 * признака под permitted dirName {CN=x+O=y}; ключ id-RSASSA-PSS под подписью PKCS #1 v1.5 негоден
 */
TEST(AuditTest, FoldedEscape){
	// Объявляем moment и инициализируем значение «1800000000»
	const int64_t moment = 1800000000;
	// Хранилище доверия
	trust::store_t store;
	// Присваиваем const vector <uint8_t> root значение результат вызова certified()
	const vector <uint8_t> root = certified("audit/r6-root.crt"), middle = certified("audit/r6-mid.crt");
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::NONE
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-ok.crt"), middle}, store, moment), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-evil.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-other.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	// Ключ, объявленный id-RSASSA-PSS, подпись sha256WithRSAEncryption не проверяет
	const vector <uint8_t> der = certified("ca-rsa.crt");
	// Требуем ложность «der.empty()»
	ASSERT_FALSE(der.empty());
	// Объявляем certificate
	x509::certificate_t certificate;
	// Требуем равенство certificate.parse(view_t(der.data()… и x509::error_t::NONE
	ASSERT_EQ(certificate.parse(view_t(der.data(), der.size())), x509::error_t::NONE);
	// Объявляем unused и инициализируем значение «0»
	uint8_t unused = 0;
	// Объявляем signature и инициализируем результат вызова certificate.sign()
	const view_t signature = certificate.sign(unused);
	// Проверяем равенство x509::verify(certificate.body(), si… и x509::error_t::NONE
	EXPECT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), certificate.settings(), certificate.key()), x509::error_t::NONE);
	// Объявляем forged и инициализируем результат вызова certificate.key()
	x509::key_t forged = certificate.key();
	// Алгоритм подделки: RSASSA-PSS
	forged.algorithm = "1.2.840.113549.1.1.10";
	// Проверяем неравенство x509::verify(certificate.body(), si… и x509::error_t::NONE
	EXPECT_NE(x509::verify(certificate.body(), signature, certificate.algorithms(), certificate.settings(), forged), x509::error_t::NONE);
}

/**
 * Круг 6 (движок): заведение связи поверх дейтаграмм не портит настройку наборов - следующая связь потоком
 * предлагает наборы ГОСТ снова
 */
TEST(AuditTest, SuitesKept){
	// Объявляем engine и конструируем (false)
	internal::engine_t engine(false);
	// Задаём имя проверки
	engine.name("example.com");
	// Ограничиваем наборы шифров стороны
	engine.suites(vector <protect::suite_t> {protect::suite_t::KUZNYECHIK_MGM_L, protect::suite_t::AES_128_GCM_SHA256});
	// Задаём транспорт движку
	engine.transport(context::transport_t::DATAGRAMS);
	// Требуем равенство engine.start() и context::error_t::NONE
	ASSERT_EQ(engine.start(), context::error_t::NONE);
	// Вызываем engine.clear()
	engine.clear();
	// Задаём транспорт движку
	engine.transport(context::transport_t::RECORDS);
	// Требуем равенство engine.start() и context::error_t::NONE
	ASSERT_EQ(engine.start(), context::error_t::NONE);
	// Объявляем profile
	fingerprint::profile_t profile;
	// Требуем равенство fingerprint::parse(engine.output(),… и fingerprint::error_t::NONE
	ASSERT_EQ(fingerprint::parse(engine.output(), profile), fingerprint::error_t::NONE);
	// Проверяем равенство profile.suites.size() и static_cast <size_t> (2)
	EXPECT_EQ(profile.suites.size(), static_cast <size_t> (2));
}

/**
 * Круг 6 (разборщики): имя узла в server_name - печатаемый ASCII без точки на конце (раздел 3 RFC 6066)
 */
TEST(AuditTest, HostBytes){
	// Объявляем лямбду body — формирования тела запроса
	const auto body = [](const string & host){
		// Объявляем result — результат
		vector <uint8_t> result;
		// Объявляем length и инициализируем значение «(3 + host.size())»
		const size_t length = (3 + host.size());
		// Добавляем элемент в конец накопителя
		result.push_back(static_cast <uint8_t> (length >> 8));
		result.push_back(static_cast <uint8_t> (length));
		result.push_back(0);
		result.push_back(static_cast <uint8_t> (host.size() >> 8));
		result.push_back(static_cast <uint8_t> (host.size()));
		// Вызываем result.insert(result.end(), host.begin(), host.end())
		result.insert(result.end(), host.begin(), host.end());
		// Возвращаем значение «result»
		return result;
	};
	// Объявляем name
	view_t name;
	// Присваиваем vector <uint8_t> good значение результат вызова body()
	vector <uint8_t> good = body("a.example");
	// Проверяем равенство extension::name(view_t(good.data(),… и extension::error_t::NONE
	EXPECT_EQ(extension::name(view_t(good.data(), good.size()), name), extension::error_t::NONE);
	// Присваиваем vector <uint8_t> nul значение результат вызова body()
	vector <uint8_t> nul = body(string("a.com\0evil", 10));
	// Проверяем равенство extension::name(view_t(nul.data(),… и extension::error_t::FORMAT
	EXPECT_EQ(extension::name(view_t(nul.data(), nul.size()), name), extension::error_t::FORMAT);
	// Присваиваем vector <uint8_t> dot значение результат вызова body()
	vector <uint8_t> dot = body("a.example.");
	// Проверяем равенство extension::name(view_t(dot.data(),… и extension::error_t::FORMAT
	EXPECT_EQ(extension::name(view_t(dot.data(), dot.size()), name), extension::error_t::FORMAT);
	// Присваиваем vector <uint8_t> space значение результат вызова body()
	vector <uint8_t> space = body("a b");
	// Проверяем равенство extension::name(view_t(space.data()… и extension::error_t::FORMAT
	EXPECT_EQ(extension::name(view_t(space.data(), space.size()), name), extension::error_t::FORMAT);
}

/**
 * Круг 6 (записи): подделка кусками по байту через один не раздувает покрытие сборки - куски сверх
 * предела областей отбрасываются, а честная сборка подряд идёт как прежде
 */
TEST(AuditTest, SpansCapped){
	// Объявляем flight
	internal::flight_t flight;
	// Объявляем total и инициализируем значение «4000»
	const size_t total = 4000;
	// Объявляем sequence и инициализируем значение «0»
	size_t sequence = 0;
	/**
	 * Куски по одному байту через один: областей больше предела
	 */
	for(size_t offset = 0; offset < total; offset += 2){
		// Объявляем fragment
		datagram::fragment_t fragment;
		// Вид сообщения части: CERTIFICATE
		fragment.type = handshake::type_t::CERTIFICATE;
		// Номер сообщения части
		fragment.sequence = 1;
		// Полная длина сообщения
		fragment.size = total;
		// Сдвиг части
		fragment.offset = offset;
		// Длина части: один байт
		fragment.length = 1;
		// Объявляем piece — фрагмент дейтаграммы и заполняем накопитель (datagram::DATAGRAM_FRAGMENT_HEADER…)
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 1, 0x41);
		// Требуем равенство datagram::build(fragment, piece.dat… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		// Заголовок сообщения рукопожатия
		datagram::header_t header;
		// Заголовок записи раздельный
		header.unified = false;
		// Вид записи: рукопожатие
		header.type = record::type_t::HANDSHAKE;
		// Пора записи нулевая
		header.epoch = 0;
		// Номер записи со счётчика с шагом
		header.sequence = sequence++;
		// Длина записи по длине куска
		header.size = piece.size();
		// Объявляем head размером datagram::DATAGRAM_PLAIN_HEADER
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		// Объявляем length и инициализируем значение «0»
		size_t length = 0;
		// Требуем равенство datagram::build(header, head, lengt… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		// Объявляем wire — проволочные данные и конструируем из head, head + length
		vector <uint8_t> wire(head, head + length);
		// Вызываем wire.insert(wire.end(), piece.begin(), piece.end())
		wire.insert(wire.end(), piece.begin(), piece.end());
		// Объявляем opened — открытые записи
		vector <internal::opened_t> opened;
		// Требуем равенство flight.receive(view_t(wire.data(),… и context::error_t::NONE
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		/** Перебираем: size_t j = 0 при условии j < opened.size() */
		for(size_t j = 0; j < opened.size(); j++)
			// Проверяем, что «opened[j].type == record::type_t::HANDSHAKE»
			if(opened[j].type == record::type_t::HANDSHAKE)
				// Вызываем flight.fragments(view_t(opened[j].content.data(), opened…)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	// Проверяем: flight.discarded(datagram::reason_t… не меньше static_cast <uint64_t> (total / 2 -…
	EXPECT_GE(flight.discarded(datagram::reason_t::FRAMING), static_cast <uint64_t> (total / 2 - datagram::DATAGRAM_SPANS));
}

/**
 * Круг 6 (шифры): раскол Noise выполняется однажды - повтор отвергается (Noise r34 §5.3)
 */
TEST(AuditTest, SplitOnce){
	// Объявляем name и инициализируем значение «"Noise_NN_25519_ChaChaPoly_SHA256"»
	const string name = "Noise_NN_25519_ChaChaPoly_SHA256";
	// Объявляем pattern и конструируем (reinterpret_cast <const uint8_t *> (name.da…)
	const view_t pattern(reinterpret_cast <const uint8_t *> (name.data()), name.size());
	// Объявляем initiator и responder
	noise::handshake_t initiator, responder;
	// Инициатор Noise заведён по узору
	ASSERT_TRUE(initiator.start(pattern, noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(responder.start(pattern, noise::role_t::RESPONDER, view_t()));
	// Объявляем message размером noise::MESSAGE и payload размером noise::MESSAGE
	uint8_t message[noise::MESSAGE], payload[noise::MESSAGE];
	// Объявляем size и инициализируем результат вызова sizeof()
	size_t size = sizeof(message), length = sizeof(payload);
	// Запись сообщения инициатора
	ASSERT_TRUE(initiator.write(view_t(), message, size));
	ASSERT_TRUE(responder.read(view_t(message, size), payload, length));
	// Длина сообщения и полезной нагрузки
	size = sizeof(message); length = sizeof(payload);
	// Запись ответа отвечающего
	ASSERT_TRUE(responder.write(view_t(), message, size));
	ASSERT_TRUE(initiator.read(view_t(message, size), payload, length));
	// Объявляем one, two, three и four
	noise::cipher_t one, two, three, four;
	// Разделение ключей связи инициатором
	ASSERT_TRUE(initiator.split(one, two));
	// Проверяем ложность «initiator.split(three, four)»
	EXPECT_FALSE(initiator.split(three, four));
}

/**
 * Круг 7 (движок): после просьбы о повторе второе приветствие, предлагающее лишь издание 1.2,
 * отвергается illegal_parameter (раздел 4.1.4 RFC 8446), а не ведёт рукопожатие 1.2
 */
TEST(AuditTest, DowngradeAfterRetry){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Присваиваем const vector <protect::suite_t> suites значение значение «{protect::suite_t::AES_128_GCM_SHA256, protect::suite_t…»
	const vector <protect::suite_t> suites = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256};
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Ограничиваем наборы шифров стороны
	server.suites(suites);
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Объявляем first
	client::context_t first;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(first);
	// Ограничиваем наборы шифров стороны
	first.suites(suites);
	// Разбираем группы параметров
	first.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	// Вырабатываем доли разделения секрета
	first.shares(vector <extension::group_t> {extension::group_t::X25519});
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> opening значение результат вызова take()
	const vector <uint8_t> opening = take(first);
	// Требуем равенство server.push(view_t(opening.data(),… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(opening.data(), opening.size())), context::error_t::NONE);
	// Просьба о повторе отправлена
	EXPECT_FALSE(take(server).empty());
	// Проверяем равенство server.state() и context::state_t::HANDSHAKE
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Второе приветствие от клиента, зажатого на издании 1.2
	client::context_t second;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(second);
	// Ограничиваем наборы шифров стороны
	second.suites(suites);
	// Ограничиваем версии протокола стороны
	second.versions(0x0303, 0x0303);
	// Требуем равенство second.start() и context::error_t::NONE
	ASSERT_EQ(second.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> again значение результат вызова take()
	const vector <uint8_t> again = take(second);
	// Проверяем равенство server.push(view_t(again.data(), ag… и context::error_t::VERSION
	EXPECT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::VERSION);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.error(), context::error_t::VERSION);
	// Ответ - одно лишь извещение illegal_parameter, не ServerHello 1.2
	const vector <uint8_t> reply = take(server);
	// Требуем: reply.size() не меньше static_cast <size_t> (7)
	ASSERT_GE(reply.size(), static_cast <size_t> (7));
	// Проверяем равенство reply[0] и static_cast <uint8_t> (record::type…
	EXPECT_EQ(reply[0], static_cast <uint8_t> (record::type_t::ALERT));
	EXPECT_EQ(reply[6], static_cast <uint8_t> (alert::description_t::PARAMETER));
}

/**
 * Круг 7 (движок): пустой перечень наборов оставляет умолчание и в настройке (`_catalog`),
 * а не опустошает её - регрессия правки круга 6
 */
TEST(AuditTest, SuitesEmptyKept){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> ());
	// Проверяем равенство server.start() и context::error_t::NONE
	EXPECT_EQ(server.start(), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Заведение поверх дейтаграмм тоже держится умолчания
	server::context_t datagrams;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(datagrams);
	// Задаём подлинность стороны
	datagrams.credential(credential);
	// Задаём транспорт движку
	datagrams.transport(context::transport_t::DATAGRAMS);
	// Ограничиваем наборы шифров стороны
	datagrams.suites(vector <protect::suite_t> ());
	// Присваиваем static const uint8_t ADDRESS[4] значение значение «{10, 0, 0, 1}»
	static const uint8_t ADDRESS[4] = {10, 0, 0, 1};
	// Задаём адрес стороны
	datagrams.address(view_t(ADDRESS, sizeof(ADDRESS)));
	// Проверяем равенство datagrams.start() и context::error_t::NONE
	EXPECT_EQ(datagrams.start(), context::error_t::NONE);
}

/**
 * Круг 7 (движок): место ответа OCSP вне дозволенной длины цепочки отвергается молча,
 * а не растит перечень по чужому числу (length_error сквозь noexcept, SIZE_MAX + 1)
 */
TEST(AuditTest, StapleIndex){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Объявляем response и заполняем накопитель (16, 0x30)
	const vector <uint8_t> response(16, 0x30);
	// Получаем статус операции
	server.status(response, static_cast <size_t> (-1));
	server.status(response, static_cast <size_t> (1) << 40);
	server.status(response, trust::TRUST_DEPTH);
	server.status(response, 0);
	// Проверяем равенство server.start() и context::error_t::NONE
	EXPECT_EQ(server.start(), context::error_t::NONE);
}

/**
 * Круг 7 (движок): второе приветствие за просьбой о повторе судится своим содержимым -
 * имя узла и протокол приложения первого приветствия не переживают его (RFC 8446 §4.1.2)
 */
TEST(AuditTest, RetryReset){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны с именем узла
	ASSERT_TRUE(identity("example.com", credential));
	// Объявляем client и конструируем (false), server(true)
	internal::engine_t client(false), server(true);
	// Задаём транспорт движку
	client.transport(context::transport_t::RECORDS);
	// Задаём транспорт движку
	server.transport(context::transport_t::RECORDS);
	// Задаём имя проверки
	client.name("example.com");
	// Вызываем client.protocols(vector <string> {"h2"})
	client.protocols(vector <string> {"h2"});
	// Вызываем server.protocols(vector <string> {"h2"})
	server.protocols(vector <string> {"h2"});
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Вырабатываем доли разделения секрета
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Задаём подлинность стороны
	server.credential(credential);
	// Подлинность ГОСТ: схемы ГОСТ объявляют обе стороны, умолчания движка - классика без ГОСТ
	client.schemes(gostlists::SCHEMES);
	// Вызываем server.schemes(gostlists::SCHEMES)
	server.schemes(gostlists::SCHEMES);
	// Требуем равенство client.start() и context::error_t::NONE
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> opening значение результат вызова take()
	const vector <uint8_t> opening = take(client);
	// Требуем равенство server.push(view_t(opening.data(),… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(opening.data(), opening.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> retry значение результат вызова take()
	const vector <uint8_t> retry = take(server);
	// Требуем равенство client.push(view_t(retry.data(), re… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Имя и протокол выведены из первого приветствия
	EXPECT_EQ(server.name(), "example.com");
	EXPECT_EQ(server.protocol(), "h2");
	// Присваиваем const vector <uint8_t> flight значение результат вызова take()
	const vector <uint8_t> flight = take(client);
	// Разыскиваем тело второго приветствия в залпе клиента
	vector <uint8_t> body;
	/** Перебираем по условию «size_t offset = 0; (offset + 5) <= flight.size(…» */
	for(size_t offset = 0; (offset + 5) <= flight.size() && body.empty();){
		// Объявляем length и инициализируем значение «(static_cast <size_t> (flight[offset + 3]) << 8) | flig…»
		const size_t length = (static_cast <size_t> (flight[offset + 3]) << 8) | flight[offset + 4];
		// Проверяем, что «(flight[offset] == 0x16) && ((offset + 5 + length) <= fligh…»
		if((flight[offset] == 0x16) && ((offset + 5 + length) <= flight.size()) && (flight[offset + 5] == 0x01)){
			// Объявляем inner и инициализируем значение «(static_cast <size_t> (flight[offset + 6]) << 16) | (st…»
			const size_t inner = (static_cast <size_t> (flight[offset + 6]) << 16) | (static_cast <size_t> (flight[offset + 7]) << 8) | flight[offset + 8];
			// Вызываем body.assign(flight.begin() + offset + 9, flight.begin() + offset…)
			body.assign(flight.begin() + offset + 9, flight.begin() + offset + 9 + inner);
		}
		// Прибавляем к offset «(5 + length)»
		offset += (5 + length);
	}
	// Требуем ложность «body.empty()»
	ASSERT_FALSE(body.empty());
	// Объявляем greeting
	hello::client_t greeting;
	// Требуем равенство hello::parse(view_t(body.data(), bo… и hello::error_t::NONE
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), greeting), hello::error_t::NONE);
	// Снимаем со второго приветствия имя узла и протокол приложения
	vector <hello::extension_t> kept;
	/** Перебираем: size_t i = 0 при условии i < greeting.extensions.size() */
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		// Проверяем, что «(greeting.extensions[i].type != static_cast <uint16_t> (ext…»
		if((greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::NAME)) && (greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::PROTOCOLS)))
			// Добавляем элемент в конец накопителя
			kept.push_back(greeting.extensions[i]);
	// Расширения приветствия из сохранённых
	greeting.extensions = kept;
	// Объявляем rebuilt — восстановленные данные
	vector <uint8_t> rebuilt;
	// Требуем равенство hello::build(greeting, rebuilt) и hello::error_t::NONE
	ASSERT_EQ(hello::build(greeting, rebuilt), hello::error_t::NONE);
	// Объявляем writer
	handshake::writer_t writer;
	// Передаём байты стороне
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	// Объявляем message и инициализируем результат вызова writer.data()
	const view_t message = writer.data();
	// Присваиваем vector <uint8_t> wire значение значение «{0x16, 0x03, 0x03, static_cast <uint8_t> (message.size…»
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	// Вызываем wire.insert(wire.end(), message.data, message.data + message…)
	wire.insert(wire.end(), message.data, message.data + message.size);
	// Второе приветствие без имени и протокола принято (RFC 7301 §3.2 потоком их не требует)
	EXPECT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
	// Имя сервера не запрошено
	EXPECT_TRUE(server.name().empty());
	EXPECT_TRUE(server.protocol().empty());
}

/**
 * Круг 8 (движок): предел длины записи (record_size_limit) первого приветствия не переживает
 * просьбу о повторе - второе приветствие без расширения снимает его (RFC 8449 §4)
 */
TEST(AuditTest, RetryLimitReset){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны с именем узла
	ASSERT_TRUE(identity("example.com", credential));
	// Объявляем client и конструируем (false), server(true)
	internal::engine_t client(false), server(true);
	// Задаём транспорт движку
	client.transport(context::transport_t::RECORDS);
	// Задаём транспорт движку
	server.transport(context::transport_t::RECORDS);
	// Задаём имя проверки
	client.name("example.com");
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Вырабатываем доли разделения секрета
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	// Разбираем группы параметров
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Задаём подлинность стороны
	server.credential(credential);
	// Подлинность ГОСТ: схемы ГОСТ объявляют обе стороны, умолчания движка - классика без ГОСТ
	client.schemes(gostlists::SCHEMES);
	// Вызываем server.schemes(gostlists::SCHEMES)
	server.schemes(gostlists::SCHEMES);
	// Требуем равенство client.start() и context::error_t::NONE
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Первое приветствие с пределом записи 300 байтов
	const vector <uint8_t> opening = take(client);
	// Объявляем first
	hello::client_t first;
	// Требуем равенство hello::parse(view_t(opening.data()… и hello::error_t::NONE
	ASSERT_EQ(hello::parse(view_t(opening.data() + 9, opening.size() - 9), first), hello::error_t::NONE);
	// Присваиваем const uint8_t limit[2] значение значение «{0x01, 0x2C}»
	const uint8_t limit[2] = {0x01, 0x2C};
	// Вызываем first.extensions.insert(first.extensions.begin(), hello::extension_t(static_cast <uint…)
	first.extensions.insert(first.extensions.begin(), hello::extension_t(static_cast <uint16_t> (extension::type_t::LIMIT), view_t(limit, sizeof(limit))));
	// Объявляем rebuilt — восстановленные данные
	vector <uint8_t> rebuilt;
	// Требуем равенство hello::build(first, rebuilt) и hello::error_t::NONE
	ASSERT_EQ(hello::build(first, rebuilt), hello::error_t::NONE);
	// Объявляем writer
	handshake::writer_t writer;
	// Передаём байты стороне
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	// Объявляем message и инициализируем результат вызова writer.data()
	view_t message = writer.data();
	// Присваиваем vector <uint8_t> wire значение значение «{0x16, 0x03, 0x03, static_cast <uint8_t> (message.size…»
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	// Вызываем wire.insert(wire.end(), message.data, message.data + message…)
	wire.insert(wire.end(), message.data, message.data + message.size);
	// Требуем равенство server.push(view_t(wire.data(), wir… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
	// Предел первого приветствия принят сервером: 300 без октета вида
	EXPECT_EQ(server.ceiling(), static_cast <size_t> (299));
	// Просьба о повторе клиенту, второе приветствие без предела (переписка клиента здесь не важна: судится состояние сервера)
	const vector <uint8_t> retry = take(server);
	// Требуем равенство client.push(view_t(retry.data(), re… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> again значение результат вызова take()
	const vector <uint8_t> again = take(client);
	// Требуем равенство server.push(view_t(again.data(), ag… и context::error_t::NONE
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	// Предел первого приветствия снят вторым
	EXPECT_EQ(server.ceiling(), record::RECORD_PLAINTEXT);
}

/**
 * Круг 7 (движок): подделанная открытая смена набора клиенту DTLS 1.2 посреди залпа сервера
 * роняется молча (раздел 4.1.2.7 RFC 6347), рукопожатие доходит до конца
 */
TEST(AuditTest, ChangeMidflight){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Вызываем server.mtu(300)
	server.mtu(300);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Приветствие, просьба подтверждения адреса, приветствие с меткой
	vector <vector <uint8_t>> parts = drain(client);
	/** Перебираем: size_t i = 0 при условии i < parts.size() */
	for(size_t i = 0; i < parts.size(); i++)
		// Требуем равенство server.push(view_t(parts[i].data(),… и context::error_t::NONE
		ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	// Части записей, откачанные со стороны
	parts = drain(server);
	/** Перебираем: size_t i = 0 при условии i < parts.size() */
	for(size_t i = 0; i < parts.size(); i++)
		// Требуем равенство client.push(view_t(parts[i].data(),… и context::error_t::NONE
		ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	// Части записей, откачанные со стороны
	parts = drain(client);
	/** Перебираем: size_t i = 0 при условии i < parts.size() */
	for(size_t i = 0; i < parts.size(); i++)
		// Требуем равенство server.push(view_t(parts[i].data(),… и context::error_t::NONE
		ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	// Залп сервера дробится по MTU: клиенту отдаётся лишь первая дейтаграмма
	parts = drain(server);
	// Требуем: parts.size() не меньше static_cast <size_t> (2)
	ASSERT_GE(parts.size(), static_cast <size_t> (2));
	// Требуем равенство client.push(view_t(parts[0].data(),… и context::error_t::NONE
	ASSERT_EQ(client.push(view_t(parts[0].data(), parts[0].size())), context::error_t::NONE);
	// Проверяем равенство client.version() и 0x0303
	EXPECT_EQ(client.version(), 0x0303);
	// Подделанная открытая смена набора посреди залпа
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x01};
	// Проверяем равенство client.push(view_t(forged.data(), f… и context::error_t::NONE
	EXPECT_EQ(client.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(client.state(), context::state_t::HANDSHAKE);
	// Вывод клиента опустошён
	EXPECT_TRUE(client.output().size == 0);
	/**
	 * Остаток залпа и рукопожатие до конца
	 */
	for(size_t i = 1; i < parts.size(); i++)
		// Требуем равенство client.push(view_t(parts[i].data(),… и context::error_t::NONE
		ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established());
}

/**
 * Круг 7 (движок): профиль обозревателя с GREASE ECH плюс настоящие конфигурации ECH - во
 * внешнем приветствии одно расширение ECH, связь устанавливается с принятым ECH
 */
TEST(AuditTest, EchGreaseProfile){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем profile
	fingerprint::profile_t profile;
	{
		// Объявляем donor
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём имя проверки
		donor.name("example.com");
		// Вызываем donor.grease(true)
		donor.grease(true);
		// Требуем равенство donor.start() и context::error_t::NONE
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		// Объявляем found и инициализируем значение «false»
		bool found = false;
		/** Перебираем: size_t i = 0 при условии i < profile.extensions.size() */
		for(size_t i = 0; i < profile.extensions.size(); i++)
			// Отмечаем находку расширения
			found = (found || (profile.extensions[i].type == 0xFE0D));
		// Расширение найдено в профиле
		ASSERT_TRUE(found);
	}
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.ech(vector <uint8_t> (), "pu… и context::error_t::NONE
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Задаём имя проверки
	client.name("secret.example");
	// Требуем равенство client.profile(profile) и context::error_t::NONE
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Во внешнем приветствии ровно одно расширение ECH
	hello::client_t greeting;
	// Объявляем opening и инициализируем результат вызова client.output()
	const view_t opening = client.output();
	// Требуем: opening.size не меньше static_cast <size_t> (9)
	ASSERT_GE(opening.size, static_cast <size_t> (9));
	// Требуем равенство hello::parse(view_t(opening.data +… и hello::error_t::NONE
	ASSERT_EQ(hello::parse(view_t(opening.data + 9, opening.size - 9), greeting), hello::error_t::NONE);
	// Объявляем count и инициализируем значение «0»
	size_t count = 0;
	/** Перебираем: size_t i = 0 при условии i < greeting.extensions.size() */
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		// Прибавляем к count «((greeting.extensions[i].type == 0xFE0D…»
		count += ((greeting.extensions[i].type == 0xFE0D) ? 1 : 0);
	// Проверяем равенство count и static_cast <size_t> (1)
	EXPECT_EQ(count, static_cast <size_t> (1));
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established());
	EXPECT_TRUE(client.shrouded());
	EXPECT_TRUE(server.shrouded());
}

/**
 * Круг 7 (записи): за установленной связью DTLS 1.3 чужой открытый кусок рукопожатия со
 * старым номером сообщения не повторяет ждущий залп и не подтверждается - роняется молча
 */
TEST(AuditTest, PlainRepeat){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Задаём подлинность стороны
	server.credential(credential);
	// Присваиваем static const uint8_t ADDRESS[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(ADDRESS, sizeof(ADDRESS)));
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	ASSERT_TRUE(client.established() && server.established());
	// Забираем все дейтаграммы стороны, отбрасывая результат
	(void) drain(client);
	// Забираем все дейтаграммы стороны, отбрасывая результат
	(void) drain(server);
	// Сервер выдал билет: залп ждёт подтверждения клиента
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Требуем ложность «drain(server).empty()»
	ASSERT_FALSE(drain(server).empty());
	// Чужая открытая дейтаграмма: кусок приветствия с номером сообщения 0
	datagram::fragment_t fragment;
	// Вид сообщения части: приветствие клиента
	fragment.type = handshake::type_t::CLIENT;
	// Полная длина сообщения: один байт
	fragment.size = 1;
	// Номер сообщения части
	fragment.sequence = 0;
	// Сдвиг части
	fragment.offset = 0;
	// Длина части: один байт
	fragment.length = 1;
	// Заголовок сообщения рукопожатия
	datagram::header_t header;
	// Заголовок записи раздельный
	header.unified = false;
	// Вид записи: рукопожатие
	header.type = record::type_t::HANDSHAKE;
	// Пора записи нулевая
	header.epoch = 0;
	// Номер записи с переполнением младших разрядов
	header.sequence = 0x0000FFFF0001ULL;
	// Длина записи: заголовок части и тело
	header.size = (datagram::DATAGRAM_FRAGMENT_HEADER + 1);
	// Объявляем junk — пустая дейтаграмма и заполняем накопитель (datagram::DATAGRAM_PLAIN_HEADER + h…)
	vector <uint8_t> junk(datagram::DATAGRAM_PLAIN_HEADER + header.size, 0x41);
	// Объявляем length и инициализируем значение «0»
	size_t length = 0;
	// Требуем равенство datagram::build(header, junk.data()… и datagram::error_t::NONE
	ASSERT_EQ(datagram::build(header, junk.data(), length), datagram::error_t::NONE);
	ASSERT_EQ(datagram::build(fragment, junk.data() + length), datagram::error_t::NONE);
	// Объявляем before и инициализируем результат вызова server.discarded()
	const uint64_t before = server.discarded(datagram::reason_t::PLAIN);
	// Проверяем равенство server.push(view_t(junk.data(), jun… и context::error_t::NONE
	EXPECT_EQ(server.push(view_t(junk.data(), junk.size())), context::error_t::NONE);
	// Ни повтора залпа, ни подтверждения
	EXPECT_TRUE(drain(server).empty());
	// Проверяем равенство server.discarded(datagram::reason_t… и before + 1
	EXPECT_EQ(server.discarded(datagram::reason_t::PLAIN), before + 1);
	// Связь сервера установлена
	EXPECT_TRUE(server.established());
}

/**
 * Круг 7 (записи): перенос дейтаграммами режет куски рукопожатия по пределу собеседника
 * (RFC 8449 §4, RFC 6066 §4), а не только по MTU
 */
TEST(AuditTest, LimitCarve){
	// Объявляем flight
	internal::flight_t flight;
	// Вызываем flight.mtu(1400)
	flight.mtu(1400);
	// Вызываем flight.limit(512)
	flight.limit(512);
	// Сообщение рукопожатия в 1500 байтов: заголовок и тело
	vector <uint8_t> message(handshake::HANDSHAKE_HEADER + 1500, 0x5A);
	// Вид сообщения: CERTIFICATE
	message[0] = static_cast <uint8_t> (handshake::type_t::CERTIFICATE);
	// Старший байт длины тела нулевой
	message[1] = 0x00;
	// Старший байт длины тела
	message[2] = static_cast <uint8_t> (1500 >> 8);
	// Младший байт длины тела
	message[3] = static_cast <uint8_t> (1500 & 0xFF);
	// Требуем равенство flight.emit(record::type_t::HANDSHA… и context::error_t::NONE
	ASSERT_EQ(flight.emit(record::type_t::HANDSHAKE, view_t(message.data(), message.size())), context::error_t::NONE);
	ASSERT_EQ(flight.dispatch(false), context::error_t::NONE);
	// Объявляем records и инициализируем значение «0»
	size_t records = 0;
	/**
	 * Выполняем перебор дейтаграмм и записей в них
	 */
	while(flight.output().size > 0){
		// Объявляем data и инициализируем результат вызова flight.output()
		const view_t data = flight.output();
		/** Перебираем по условию «size_t offset = 0; offset < data.size;» */
		for(size_t offset = 0; offset < data.size;){
			// Заголовок сообщения рукопожатия
			datagram::header_t header;
			// Требуем равенство datagram::parse(view_t(data.data +… и datagram::error_t::NONE
			ASSERT_EQ(datagram::parse(view_t(data.data + offset, data.size - offset), header), datagram::error_t::NONE);
			// Проверяем: header.size не больше static_cast <size_t> (512)
			EXPECT_LE(header.size, static_cast <size_t> (512));
			// Прибавляем к offset «(datagram::DATAGRAM_PLAIN_HEADER + head…»
			offset += (datagram::DATAGRAM_PLAIN_HEADER + header.size);
			// Увеличиваем счётчик разобранных записей
			records++;
		}
		// Забираем обработанные стороной байты
		flight.consume();
	}
	// Проверяем: records не меньше static_cast <size_t> (3)
	EXPECT_GE(records, static_cast <size_t> (3));
}

/**
 * Круг 7 (записи): клиент DTLS 1.2 с договорённым max_fragment_length против openssl s_server -
 * чужая открытая запись шире предела роняется молча (связь жива), а свои записи не шире предела
 */
TEST(AuditTest, PlainOversizeLimit){
	// Объявляем toolkit и инициализируем результат вызова inspect()
	const toolkit_t toolkit = inspect();
	// Проверяем, что «!toolkit.present || !toolkit.dtls12 || !toolkit.listening»
	if(!toolkit.present || !toolkit.dtls12 || !toolkit.listening)
		// Пропускаем проверку: openssl без DTLS 1.2
		GTEST_SKIP() << "openssl без DTLS 1.2";
	// Объявляем crt и инициализируем результат вызова string()
	const string crt = string(CORPUS) + "/ec256.crt", key = string(CORPUS) + "/ec256.pem";
	// Объявляем number и инициализируем результат вызова vacant()
	const uint16_t number = vacant(true);
	// Объявляем log и инициализируем значение «"/tmp/ants-audit-limit-" + to_string(number) + ".log"»
	const string log = "/tmp/ants-audit-limit-" + to_string(number) + ".log";
	// Объявляем holder и инициализируем значение «"/tmp/ants-audit-limit-" + to_string(number) + ".fifo"»
	const string holder = "/tmp/ants-audit-limit-" + to_string(number) + ".fifo";
	// Вызываем ::remove(log.c_str())
	::remove(log.c_str());
	::remove(holder.c_str());
	// Требуем равенство fifo(holder.c_str()) и 0
	ASSERT_EQ(fifo(holder.c_str()), 0);
	// Сервер инструмента запущен
	ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1_2 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -mtu 1400" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
	// Объявляем sentinel и конструируем (log + ".pid")
	sentinel_t sentinel(log + ".pid");
	// Объявляем text
	string text;
	// Метка приёма в журнале сервера
	ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
	// Объявляем bound и инициализируем значение «0»
	uint16_t bound = 0;
	// Объявляем fd и инициализируем результат вызова socketing()
	const int fd = socketing(0, bound);
	// Требуем: fd не меньше 0
	ASSERT_GE(fd, 0);
	// Объявляем sockaddr_in размером peer
	struct sockaddr_in peer;
	// Заполняем область &peer (sizeof(peer) нулевым байтом
	::memset(&peer, 0, sizeof(peer));
	// Семейство адресов: IPv4
	peer.sin_family = AF_INET;
	// Адрес петли
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	// Номер порта сетевым порядком
	peer.sin_port = htons(number);
	// Профиль с донора поверх дейтаграмм с дописанным max_fragment_length (код 1: 512 байтов)
	fingerprint::profile_t profile;
	{
		// Объявляем donor
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём транспорт движку
		donor.transport(context::transport_t::DATAGRAMS);
		// Ограничиваем наборы шифров стороны
		donor.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Разбираем группы параметров
		donor.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
		// Задаём имя проверки
		donor.name("localhost");
		// Требуем равенство donor.start() и context::error_t::NONE
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile, true), fingerprint::error_t::NONE);
		// Объявляем extension
		fingerprint::extension_t extension;
		// Вид расширения: часть записи
		extension.type = static_cast <uint16_t> (extension::type_t::FRAGMENT);
		// Тело расширения: один байт
		extension.data = {0x01};
		// Добавляем элемент в конец накопителя
		profile.extensions.push_back(extension);
	}
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Разбираем группы параметров
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Задаём имя проверки
	client.name("localhost");
	// Требуем равенство client.profile(profile) и context::error_t::NONE
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Перекачка дейтаграмм через сокет
	ASSERT_TRUE(relay(client, fd, peer, 400));
	ASSERT_TRUE(client.established());
	// Чужая открытая запись рукопожатия в 700 байтов содержимого номером далеко впереди окна
	datagram::fragment_t fragment;
	// Вид сообщения части: CERTIFICATE
	fragment.type = handshake::type_t::CERTIFICATE;
	// Полная длина сообщения: семьсот байтов
	fragment.size = 700;
	// Номер сообщения части
	fragment.sequence = 40;
	// Сдвиг части
	fragment.offset = 0;
	// Длина части: семьсот байтов
	fragment.length = 700;
	// Заголовок сообщения рукопожатия
	datagram::header_t header;
	// Заголовок записи раздельный
	header.unified = false;
	// Вид записи: рукопожатие
	header.type = record::type_t::HANDSHAKE;
	// Пора записи нулевая
	header.epoch = 0;
	// Номер записи у переполнения
	header.sequence = 0x0000FFFFFFFFULL;
	// Длина записи: заголовок части и тело
	header.size = (datagram::DATAGRAM_FRAGMENT_HEADER + 700);
	// Объявляем junk — пустая дейтаграмма и заполняем накопитель (datagram::DATAGRAM_PLAIN_HEADER + h…)
	vector <uint8_t> junk(datagram::DATAGRAM_PLAIN_HEADER + header.size, 0x41);
	// Объявляем length и инициализируем значение «0»
	size_t length = 0;
	// Требуем равенство datagram::build(header, junk.data()… и datagram::error_t::NONE
	ASSERT_EQ(datagram::build(header, junk.data(), length, true), datagram::error_t::NONE);
	ASSERT_EQ(datagram::build(fragment, junk.data() + length), datagram::error_t::NONE);
	// Объявляем before и инициализируем результат вызова client.discarded()
	const uint64_t before = client.discarded(datagram::reason_t::LENGTH);
	// Проверяем равенство client.push(view_t(junk.data(), jun… и context::error_t::NONE
	EXPECT_EQ(client.push(view_t(junk.data(), junk.size())), context::error_t::NONE);
	// Связь клиента установлена
	EXPECT_TRUE(client.established());
	// Проверяем равенство client.discarded(datagram::reason_t… и before + 1
	EXPECT_EQ(client.discarded(datagram::reason_t::LENGTH), before + 1);
	// Своя запись прикладных данных в 700 байтов режется по пределу 512
	const vector <uint8_t> payload(700, 'Z');
	// Требуем равенство client.write(view_t(payload.data(),… и context::error_t::NONE
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	// Объявляем datagrams и инициализируем значение «0»
	size_t datagrams = 0;
	/** Повторяем, пока «client.output().size > 0» */
	while(client.output().size > 0){
		// Объявляем data и инициализируем результат вызова client.output()
		const view_t data = client.output();
		// Проверяем: data.size не больше static_cast <size_t> (512 + datagra…
		EXPECT_LE(data.size, static_cast <size_t> (512 + datagram::DATAGRAM_PLAIN_HEADER + 8 + 16));
		// Отправляем дейтаграмму на адрес стороны
		(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), sizeof(peer));
		// Забираем обработанные стороной байты
		client.consume(data.size);
		// Увеличиваем счётчик полученных дейтаграмм
		datagrams++;
	}
	// Проверяем: datagrams не меньше static_cast <size_t> (2)
	EXPECT_GE(datagrams, static_cast <size_t> (2));
	// Сервер данные принял и связи не рвал
	(void) client.close();
	// Вызываем relay(client, fd, peer, 2)
	relay(client, fd, peer, 2);
	// Вызываем closing(fd)
	closing(fd);
	// Вызываем sentinel.halt()
	sentinel.halt();
	// Даём обмену стихнуть
	(void) settle(log, text);
	// Журнал сервера: данные приняты, извещения record_overflow нет
	bool delivered = false, overflowed = false;
	// Объявляем culprit
	string culprit;
	{
		// Объявляем file и конструируем (log)
		std::ifstream file(log);
		// Объявляем line
		string line;
		/** Повторяем, пока «std::getline(file, line)» */
		while(std::getline(file, line)){
			// Отмечаем доставку метки в журнал
			delivered = (delivered || (line.find("ZZZZ") != string::npos));
			// Отмечаем переполнение записи в журнале
			overflowed = (overflowed || (line.find("record_overflow") != string::npos) || (line.find("data length too long") != string::npos));
			// Прибавляем к culprit «(((line.find("record_overflow") != stri…»
			culprit += (((line.find("record_overflow") != string::npos) || (line.find("data length too long") != string::npos)) ? (line + "\n") : string());
		}
	}
	// Метка доставлена в журнал
	EXPECT_TRUE(delivered);
	// Проверяем ложность «overflowed)»
	EXPECT_FALSE(overflowed) << culprit;
	// Вызываем ::remove(log.c_str())
	::remove(log.c_str());
	::remove(holder.c_str());
}

/**
 * Круг 7 (шифры): кусок длиной без места портит подачу - хеш и имитовставка не снимаются,
 * а не выдаются от пустого сообщения (договор тот же, что у kdf с круга 6)
 */
TEST(AuditTest, HashSpoiled){
	// Объявляем out размером 64
	uint8_t out[64];
	// Объявляем hasher и конструируем (digest::hash_t::SHA256)
	digest::hasher_t hasher(digest::hash_t::SHA256);
	// Вызываем hasher.update(view_t(nullptr, 5))
	hasher.update(view_t(nullptr, 5));
	// Проверяем ложность «hasher.finish(out, 32)»
	EXPECT_FALSE(hasher.finish(out, 32));
	// Вызываем hasher.reset(digest::hash_t::SHA256)
	hasher.reset(digest::hash_t::SHA256);
	// Итог хеша получен
	EXPECT_TRUE(hasher.finish(out, 32));
	// Объявляем mac
	digest::mac_t mac;
	// Присваиваем const uint8_t key[16] значение значение «{1}»
	const uint8_t key[16] = {1};
	// Код подлинности заведён с ключом
	ASSERT_TRUE(mac.start(digest::hash_t::SHA256, view_t(key, sizeof(key))));
	// Вызываем mac.update(view_t(nullptr, 5))
	mac.update(view_t(nullptr, 5));
	// Проверяем ложность «mac.finish(out, 32)»
	EXPECT_FALSE(mac.finish(out, 32));
	// Код подлинности заведён с ключом
	ASSERT_TRUE(mac.start(digest::hash_t::SHA256, view_t(key, sizeof(key))));
	// Итог кода подлинности получен
	EXPECT_TRUE(mac.finish(out, 32));
	// Круг 8: тот же договор у самих примитивов и их свободных функций
	EXPECT_FALSE(digest::sha2(digest::sha_t::SHA256, view_t(nullptr, 5), out, 32));
	EXPECT_FALSE(digest::sha1(view_t(nullptr, 5), out, 20));
	EXPECT_FALSE(digest::md5(view_t(nullptr, 5), out, 16));
	EXPECT_FALSE(digest::streebog(digest::type_t::SHORT, view_t(nullptr, 5), out, 32, digest::order_t::STREAM));
	// Хеш пустого сообщения получен
	EXPECT_TRUE(digest::sha2(digest::sha_t::SHA256, view_t(nullptr, 0), out, 32));
	EXPECT_TRUE(digest::sha1(view_t(nullptr, 0), out, 20));
	EXPECT_TRUE(digest::md5(view_t(nullptr, 0), out, 16));
	EXPECT_TRUE(digest::streebog(digest::type_t::SHORT, view_t(nullptr, 0), out, 32, digest::order_t::STREAM));
}

/**
 * Круг 7 (шифры): заранее разделённый ключ HPKE короче 32 байтов отвергается (RFC 9180 §9.5)
 */
TEST(AuditTest, HpkePskShort){
	// Объявляем suite и конструируем (hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_…)
	const hpke::suite_t suite(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM);
	// Присваиваем const uint8_t shared[32] значение значение «{7}»
	const uint8_t shared[32] = {7};
	// Присваиваем const uint8_t identity[4] значение значение «{1, 2, 3, 4}»
	const uint8_t identity[4] = {1, 2, 3, 4};
	// Присваиваем const uint8_t brief[4] значение значение «{5, 6, 7, 8}»
	const uint8_t brief[4] = {5, 6, 7, 8};
	// Присваиваем const uint8_t enough[32] значение значение «{9}»
	const uint8_t enough[32] = {9};
	// Объявляем own и ephemeral
	hpke::key_t own, ephemeral;
	// Требуем равенство own.derive(hpke::kem_t::X25519_HKDF… и hpke::error_t::NONE
	ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, view_t(shared, sizeof(shared))), hpke::error_t::NONE);
	ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, view_t(enough, sizeof(enough))), hpke::error_t::NONE);
	// Объявляем enc размером hpke::X25519_SIZE
	uint8_t enc[hpke::X25519_SIZE];
	// Объявляем sending
	hpke::context_t sending;
	// Проверяем равенство hpke::sender(suite, hpke::regime_t:… и hpke::error_t::PSK
	EXPECT_EQ(hpke::sender(suite, hpke::regime_t::PSK, own.point(), view_t(), hpke::shared_t(view_t(brief, sizeof(brief)), view_t(identity, sizeof(identity))), nullptr, ephemeral, enc, sending), hpke::error_t::PSK);
	EXPECT_EQ(hpke::sender(suite, hpke::regime_t::PSK, own.point(), view_t(), hpke::shared_t(view_t(enough, sizeof(enough)), view_t(identity, sizeof(identity))), nullptr, ephemeral, enc, sending), hpke::error_t::NONE);
}

/**
 * Круг 7 (математика): открытый показатель RSA шире 33 разрядов отвергается - чужой ключ с
 * показателем в ширину модуля делал проверку подписи ценою секретного действия
 */
TEST(AuditTest, RsaExponentWide){
	// Объявляем modulus — модуль и заполняем накопитель (256, 0xFF)
	vector <uint8_t> modulus(256, 0xFF);
	// Старший байт модуля выставлен
	modulus[0] = 0xC3;
	// Присваиваем const uint8_t narrow[5] значение значение «{0x01, 0x00, 0x00, 0x00, 0x01}»
	const uint8_t narrow[5] = {0x01, 0x00, 0x00, 0x00, 0x01};
	// Присваиваем const uint8_t wide[6] значение значение «{0x01, 0x00, 0x00, 0x00, 0x00, 0x01}»
	const uint8_t wide[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x01};
	// Объявляем rsa
	sign::rsa_t rsa;
	// Ключ RSA из частей установлен
	EXPECT_TRUE(rsa.key(view_t(modulus.data(), modulus.size()), view_t(narrow, sizeof(narrow))));
	// Проверяем ложность «rsa.key(view_t(modulus.data(), modulus.size()), view_t(…»
	EXPECT_FALSE(rsa.key(view_t(modulus.data(), modulus.size()), view_t(wide, sizeof(wide))));
	// Круг 8: выработка ключа держится того же предела - иначе библиотека порождала бы ключи, которых сама не читает
	EXPECT_FALSE(rsa.generate(2048, (static_cast <uint64_t> (1) << 40) + 1));
}

/**
 * Круг 7 (X.509): накопитель записчика ASN.1 отдаётся целиком и при незакрытом элементе, и после отказа
 * записи - data() там пуст, и затирание секретного содержимого на пути отказа через него не работало вовсе;
 * рост буфера затирает прежнюю память сам (asn1::Writer::grow), а revert() у PEM берёт место до перебора -
 * это закреплено кодом и щупом audit7/x509/probe1 (ноль освобождённых блоков с секретом в четырёх случаях)
 */
TEST(AuditTest, WriterBuffer){
	// Объявляем writer
	asn1::writer_t writer;
	// Присваиваем static const uint8_t SECRET[8] значение значение «{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}»
	static const uint8_t SECRET[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
	// Открытие метки последовательности
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	ASSERT_TRUE(writer.octets(view_t(SECRET, sizeof(SECRET))));
	// Элемент не закрыт: записи нет, а накопитель с секретом есть
	EXPECT_EQ(writer.data().size, 0u);
	// Требуем равенство writer.buffer().size и 11u
	ASSERT_EQ(writer.buffer().size, 11u);
	// Проверяем равенство ::memcmp(writer.buffer().data + 3,… и 0
	EXPECT_EQ(::memcmp(writer.buffer().data + 3, SECRET, sizeof(SECRET)), 0);
	// Закрытие метки последовательности
	ASSERT_TRUE(writer.close());
	// Проверяем равенство writer.data().size и 12u
	EXPECT_EQ(writer.data().size, 12u);
	// Лишнее закрытие - отказ записи: data() пуст, накопитель по-прежнему отдаётся
	EXPECT_FALSE(writer.close());
	// Проверяем неравенство writer.err() и asn1::error_t::NONE
	EXPECT_NE(writer.err(), asn1::error_t::NONE);
	// Проверяем равенство writer.data().size и 0u
	EXPECT_EQ(writer.data().size, 0u);
	// Требуем равенство writer.buffer().size и 12u
	ASSERT_EQ(writer.buffer().size, 12u);
	// Проверяем равенство ::memcmp(writer.buffer().data + 4,… и 0
	EXPECT_EQ(::memcmp(writer.buffer().data + 4, SECRET, sizeof(SECRET)), 0);
	// Рост буфера переносит запись без потерь: длинное содержимое перевыделяет память
	asn1::writer_t large;
	// Объявляем body — тело сообщения и заполняем накопитель (5000, 0x5A)
	const vector <uint8_t> body(5000, 0x5A);
	// Открытие метки последовательности
	ASSERT_TRUE(large.open(asn1::tag_t::SEQUENCE));
	ASSERT_TRUE(large.octets(view_t(body.data(), body.size())));
	ASSERT_TRUE(large.octets(view_t(SECRET, sizeof(SECRET))));
	ASSERT_TRUE(large.close());
	// Требуем равенство large.data().size и 4u + 4u + body.size() + 2u + sizeof…
	ASSERT_EQ(large.data().size, 4u + 4u + body.size() + 2u + sizeof(SECRET));
	// Проверяем равенство ::memcmp(large.data().data + large.… и 0
	EXPECT_EQ(::memcmp(large.data().data + large.data().size - sizeof(SECRET), SECRET, sizeof(SECRET)), 0);
}

/**
 * Круг 7 (X.509): ответ OCSP судится той же политикой стойкости, что и цепочка (x509::weak): подпись ответа
 * SHA-1 и делегированный ответчик с ключом RSA-1024 отвергаются (WEAK), ответ SHA-256 от издателя принимается
 */
TEST(AuditTest, OcspWeak){
	// Присваиваем const vector <uint8_t> root значение результат вызова certified()
	const vector <uint8_t> root = certified("audit/r7-root.crt"), leaf = certified("audit/r7-ocsp-leaf.crt");
	// Требуем ложность «root.empty()»
	ASSERT_FALSE(root.empty());
	ASSERT_FALSE(leaf.empty());
	// Выполняем «const struct { const char * name;», затем ocsp::error_t expected
	const struct { const char * name; ocsp::error_t expected; } CASES[] = {
		// Файл отклика OCSP и ожидаемый статус его разбора
		{"audit/r7-ocsp-sha256.der", ocsp::error_t::NONE},
		{"audit/r7-ocsp-sha1.der", ocsp::error_t::WEAK},
		{"audit/r7-ocsp-deleg1024.der", ocsp::error_t::WEAK}
	};
	/** Перебираем: size_t i = 0 при условии i < (sizeof(CASES) / sizeof(CASES[0… */
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Присваиваем const vector <uint8_t> der значение результат вызова corpus()
		const vector <uint8_t> der = corpus(CASES[i].name);
		// Требуем ложность «der.empty())»
		ASSERT_FALSE(der.empty()) << CASES[i].name;
		// Объявляем response
		ocsp::response_t response;
		// Требуем равенство response.parse(view_t(der.data(), d… и ocsp::error_t::NONE)
		ASSERT_EQ(response.parse(view_t(der.data(), der.size())), ocsp::error_t::NONE) << CASES[i].name;
		// Объявляем status и инициализируем значение «ocsp::status_t::NONE»
		ocsp::status_t status = ocsp::status_t::NONE;
		// Проверяем равенство ocsp::verify(response, view_t(leaf.… и CASES[i].expected)
		EXPECT_EQ(ocsp::verify(response, view_t(leaf.data(), leaf.size()), view_t(root.data(), root.size()), 0, 0, view_t(), status), CASES[i].expected) << CASES[i].name;
	}
	// Политика едина: те же помощники судят и звено цепочки
	x509::certificate_t anchor;
	// Требуем равенство anchor.parse(view_t(root.data(), ro… и x509::error_t::NONE
	ASSERT_EQ(anchor.parse(view_t(root.data(), root.size())), x509::error_t::NONE);
	// Проверяем ложность «x509::weak(anchor, false)»
	EXPECT_FALSE(x509::weak(anchor, false));
	// Алгоритм признан слабым
	EXPECT_TRUE(x509::weak("1.2.840.113549.1.1.5", view_t()));
	EXPECT_TRUE(x509::weak("1.2.840.113549.1.1.10", view_t()));
	// Проверяем ложность «x509::weak("1.2.840.113549.1.1.11", view_t())»
	EXPECT_FALSE(x509::weak("1.2.840.113549.1.1.11", view_t()));
}

/**
 * Круг 7 (X.509): дефис посреди метки PEM дозволен грамматикой раздела 3 RFC 7468, и посторонняя запись с
 * такой меткой не отвергает весь текст вместе с сертификатом рядом; дефис на краю и два разделителя подряд - LABEL
 */
TEST(AuditTest, PemDashLabel){
	// Присваиваем const vector <uint8_t> text значение результат вызова corpus()
	const vector <uint8_t> text = corpus("audit/r7-root.crt");
	// Требуем ложность «text.empty()»
	ASSERT_FALSE(text.empty());
	// Объявляем certificate и конструируем (text.begin(), text.end())
	const string certificate(text.begin(), text.end());
	// Объявляем chain — цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Проверяем равенство pem::certificates("-----BEGIN X-Y--… и pem::error_t::NONE
	EXPECT_EQ(pem::certificates("-----BEGIN X-Y-----\nQUJD\n-----END X-Y-----\n" + certificate, chain), pem::error_t::NONE);
	EXPECT_EQ(chain.size(), 1u);
	// Объявляем block
	pem::block_t block;
	// Содержимое блока: три байта
	block.data = vector <uint8_t> (3, 0x41);
	// Объявляем out
	string out;
	// Метка блока с дефисом
	block.label = "X-Y";
	// Проверяем равенство pem::encode(block, out) и pem::error_t::NONE
	EXPECT_EQ(pem::encode(block, out), pem::error_t::NONE);
	// Метка блока с пробелом
	block.label = "X-Y Z-W";
	// Проверяем равенство pem::encode(block, out) и pem::error_t::NONE
	EXPECT_EQ(pem::encode(block, out), pem::error_t::NONE);
	// Присваиваем const char * const BROKEN[] значение значение «{"-XY", "XY-", "X--Y", "X- Y", "X -Y", "-"}»
	const char * const BROKEN[] = {"-XY", "XY-", "X--Y", "X- Y", "X -Y", "-"};
	/** Перебираем: size_t i = 0 при условии i < (sizeof(BROKEN) / sizeof(BROKEN… */
	for(size_t i = 0; i < (sizeof(BROKEN) / sizeof(BROKEN[0])); i++){
		// Метка блока из набора гнилых
		block.label = BROKEN[i];
		// Проверяем равенство pem::encode(block, out) и pem::error_t::LABEL)
		EXPECT_EQ(pem::encode(block, out), pem::error_t::LABEL) << BROKEN[i];
	}
	// Объявляем blocks — блоки PEM
	vector <pem::block_t> blocks;
	// Проверяем равенство pem::decode("-----BEGIN X--Y-----\n… и pem::error_t::LABEL
	EXPECT_EQ(pem::decode("-----BEGIN X--Y-----\nQUJD\n-----END X--Y-----\n", blocks), pem::error_t::LABEL);
}

/**
 * Круг 7 (X.509): имя «*.example.com» лежит в запрещённом поддереве secure.example.com (решение 6 trust.cpp),
 * ибо belongs() тем же именем кроет secure.example.com; против запрещённого поддерева под чужим хвостом и
 * против дозволенного example.com имя со звёздочкой сличается буквально и годно
 */
TEST(AuditTest, WildcardExcluded){
	// Присваиваем const vector <uint8_t> root значение результат вызова certified()
	const vector <uint8_t> root = certified("audit/r7-root.crt"), mid = certified("audit/r7-mid.crt"), other = certified("audit/r7-mid-other.crt");
	// Присваиваем const vector <uint8_t> star значение результат вызова certified()
	const vector <uint8_t> star = certified("audit/r7-leaf-star.crt"), secure = certified("audit/r7-leaf-secure.crt");
	// Требуем ложность «root.empty() || mid.empty() || other.empty() || star.em…»
	ASSERT_FALSE(root.empty() || mid.empty() || other.empty() || star.empty() || secure.empty());
	// Хранилище доверия
	trust::store_t store;
	// Корневой сертификат в хранилище доверия
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Объявляем moment и инициализируем значение «1789400000»
	const int64_t moment = 1789400000;
	// Проверяем равенство trust::verify(vector <vector <uint8… и trust::error_t::CONSTRAINED
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {secure, mid}, store, moment, trust::role_t::SERVER), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {star, mid}, store, moment, trust::role_t::SERVER), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {star, other}, store, moment, trust::role_t::SERVER), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(view_t(star.data(), star.size()), "secure.example.com"), trust::error_t::NONE);
}

/**
 * Круг 7 (X.509): directoryName [4] в subjectAltName и в nameConstraints разбирается строго как Name -
 * содержимое не-SEQUENCE либо лишний элемент внутри обёртки отвергаются, годное имя принимается видом DIRECTORY
 */
TEST(AuditTest, DirectoryNameStrict){
	// Присваиваем static const uint8_t JUNK[4] значение значение «{'j', 'u', 'n', 'k'}»
	static const uint8_t JUNK[4] = {'j', 'u', 'n', 'k'};
	// Негодное содержимое [4]: строка байтов вместо последовательности имени
	asn1::writer_t bad;
	// Открываем хранилище доверия
	bad.open(asn1::tag_t::SEQUENCE);
	bad.open(asn1::cls_t::CONTEXT, 4);
	// Вызываем bad.octets(view_t(JUNK, sizeof(JUNK)))
	bad.octets(view_t(JUNK, sizeof(JUNK)));
	// Закрываем хранилище доверия
	bad.close();
	bad.close();
	// Требуем равенство bad.err() и asn1::error_t::NONE
	ASSERT_EQ(bad.err(), asn1::error_t::NONE);
	// Объявляем extension
	x509::extension_t extension;
	// Опознаватель расширения: альтернативные имена
	extension.oid = "2.5.29.17";
	// Расширение некритичное
	extension.critical = false;
	// Тело расширения из гнилой записи
	extension.value = bad.data();
	// Объявляем names — имена
	vector <x509::alternative_t> names;
	// Проверяем неравенство x509::alternatives(extension, names) и x509::error_t::NONE
	EXPECT_NE(x509::alternatives(extension, names), x509::error_t::NONE);
	// Перечень имён пуст
	EXPECT_TRUE(names.empty());
	// Лишний элемент внутри обёртки [4] за годным именем
	asn1::writer_t extra;
	// Открываем хранилище доверия
	extra.open(asn1::tag_t::SEQUENCE);
	extra.open(asn1::cls_t::CONTEXT, 4);
	extra.open(asn1::tag_t::SEQUENCE);
	// Закрываем хранилище доверия
	extra.close();
	// Вызываем extra.integer(1)
	extra.integer(1);
	// Закрываем хранилище доверия
	extra.close();
	extra.close();
	// Требуем равенство extra.err() и asn1::error_t::NONE
	ASSERT_EQ(extra.err(), asn1::error_t::NONE);
	// Тело расширения из лишней записи
	extension.value = extra.data();
	// Проверяем неравенство x509::alternatives(extension, names) и x509::error_t::NONE
	EXPECT_NE(x509::alternatives(extension, names), x509::error_t::NONE);
	// Годное имя CN=x
	asn1::writer_t good;
	// Открываем хранилище доверия
	good.open(asn1::tag_t::SEQUENCE);
	good.open(asn1::cls_t::CONTEXT, 4);
	good.open(asn1::tag_t::SEQUENCE);
	good.open(asn1::tag_t::SET);
	good.open(asn1::tag_t::SEQUENCE);
	// Вызываем good.oid("2.5.4.3")
	good.oid("2.5.4.3");
	// Вызываем good.text(asn1::tag_t::PRINTABLE_STRING, "x")
	good.text(asn1::tag_t::PRINTABLE_STRING, "x");
	// Закрываем хранилище доверия
	good.close();
	good.close();
	good.close();
	good.close();
	good.close();
	// Требуем равенство good.err() и asn1::error_t::NONE
	ASSERT_EQ(good.err(), asn1::error_t::NONE);
	// Тело расширения из годной записи
	extension.value = good.data();
	// Требуем равенство x509::alternatives(extension, names) и x509::error_t::NONE
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::NONE);
	ASSERT_EQ(names.size(), 1u);
	// Проверяем равенство names[0].kind и x509::kind_t::DIRECTORY
	EXPECT_EQ(names[0].kind, x509::kind_t::DIRECTORY);
	// То же для ограничений имён: excludedSubtrees с негодным directoryName
	asn1::writer_t bounds;
	// Открываем хранилище доверия
	bounds.open(asn1::tag_t::SEQUENCE);
	bounds.open(asn1::cls_t::CONTEXT, 1);
	bounds.open(asn1::tag_t::SEQUENCE);
	bounds.open(asn1::cls_t::CONTEXT, 4);
	// Вызываем bounds.octets(view_t(JUNK, sizeof(JUNK)))
	bounds.octets(view_t(JUNK, sizeof(JUNK)));
	// Закрываем хранилище доверия
	bounds.close();
	bounds.close();
	bounds.close();
	bounds.close();
	// Требуем равенство bounds.err() и asn1::error_t::NONE
	ASSERT_EQ(bounds.err(), asn1::error_t::NONE);
	// Опознаватель расширения: пределы имени
	extension.oid = "2.5.29.30";
	// Тело расширения из записи пределов
	extension.value = bounds.data();
	// Объявляем excluded
	vector <x509::alternative_t> permitted, excluded;
	// Проверяем неравенство x509::constraints(extension, permit… и x509::error_t::NONE
	EXPECT_NE(x509::constraints(extension, permitted, excluded), x509::error_t::NONE);
}

/**
 * Круг 7 (X.509): у настроек RSASSA-PSS остаток явной обёртки [0] hashAlgorithm и [1] maskGenAlgorithm обязан
 * быть пуст, как у [2] и [3]: запись [0] { SEQUENCE{sha256}, INTEGER 5 } отвергается, годная - принимается
 */
TEST(AuditTest, PssParamsTail){
	// Присваиваем static const char * MESSAGE значение значение «"A-NTS audit round 7"»
	static const char * MESSAGE = "A-NTS audit round 7";
	// Присваиваем static const char * SIGNATURE значение значение «"03d62e2bdeeb40cc565f4dd07961a23502a8a4ec7d2e94dbecbf79…»
	static const char * SIGNATURE = "03d62e2bdeeb40cc565f4dd07961a23502a8a4ec7d2e94dbecbf7976cdcf3f620b5e96e16459985e7f4f33e0d566e622ac750c5ebc12979b9f8b7f387997c77541eb4fc2d8050149638d10c66ead56be464705fdfdd73ab1c64ff9d195e8a928285a3c718ad45d6559098ff0362bf58b5d11cd0df815cb1044dbb22351c82bfcb40197539be735432b4f3061cf6ef7e1913fe7cbb84122ea2db2b3b04ea42f75c7e98a19ca8423a774af0f310f33be3ebd1e782afbb9d87b7658080ff62776e5c69f7fe16a86faa6b68c59958258b95ae9c3953d5b20aa5f99d92d765c504e9c908029c5d5100ffa56dcbf7ee77e431220690688900f4c7284bbc9fbb5a56be6";
	// Объявляем signature — подпись
	vector <uint8_t> signature;
	/** Перебираем: size_t i = 0 при условии SIGNATURE[i] != '\0' */
	for(size_t i = 0; SIGNATURE[i] != '\0'; i += 2)
		// Добавляем элемент в конец накопителя
		signature.push_back(static_cast <uint8_t> (::strtoul(string(SIGNATURE + i, 2).c_str(), nullptr, 16)));
	// Требуем равенство signature.size() и 256u
	ASSERT_EQ(signature.size(), 256u);
	// Присваиваем const vector <uint8_t> der значение результат вызова certified()
	const vector <uint8_t> der = certified("rsa2048.crt");
	// Требуем ложность «der.empty()»
	ASSERT_FALSE(der.empty());
	// Объявляем certificate
	x509::certificate_t certificate;
	// Требуем равенство certificate.parse(view_t(der.data()… и x509::error_t::NONE
	ASSERT_EQ(certificate.parse(view_t(der.data(), der.size())), x509::error_t::NONE);
	// Объявляем content и конструируем (reinterpret_cast <const uint8_t *> (MESSAGE…)
	const view_t content(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE));
	/**
	 * Настройки: sha256, MGF1 с sha256, соль 32 байта; при tail внутрь [0] дописывается лишнее число
	 */
	for(size_t round = 0; round < 2; round++){
		// Объявляем tail и инициализируем значение «(round == 1)»
		const bool tail = (round == 1);
		// Объявляем writer
		asn1::writer_t writer;
		// Открываем хранилище доверия
		writer.open(asn1::tag_t::SEQUENCE);
		writer.open(asn1::cls_t::CONTEXT, 0);
		writer.open(asn1::tag_t::SEQUENCE);
		// Вызываем writer.oid("2.16.840.1.101.3.4.2.1")
		writer.oid("2.16.840.1.101.3.4.2.1");
		// Вызываем writer.nothing()
		writer.nothing();
		// Закрываем хранилище доверия
		writer.close();
		// Проверяем, что «tail»
		if(tail)
			// Вызываем writer.integer(5)
			writer.integer(5);
		// Закрываем хранилище доверия
		writer.close();
		// Открываем хранилище доверия
		writer.open(asn1::cls_t::CONTEXT, 1);
		writer.open(asn1::tag_t::SEQUENCE);
		// Вызываем writer.oid("1.2.840.113549.1.1.8")
		writer.oid("1.2.840.113549.1.1.8");
		// Открываем хранилище доверия
		writer.open(asn1::tag_t::SEQUENCE);
		// Вызываем writer.oid("2.16.840.1.101.3.4.2.1")
		writer.oid("2.16.840.1.101.3.4.2.1");
		// Вызываем writer.nothing()
		writer.nothing();
		// Закрываем хранилище доверия
		writer.close();
		writer.close();
		writer.close();
		// Открываем хранилище доверия
		writer.open(asn1::cls_t::CONTEXT, 2);
		// Вызываем writer.integer(32)
		writer.integer(32);
		// Закрываем хранилище доверия
		writer.close();
		writer.close();
		// Требуем равенство writer.err() и asn1::error_t::NONE
		ASSERT_EQ(writer.err(), asn1::error_t::NONE);
		// Проверяем равенство x509::verify(content, view_t(signat… и (tail ? x509::error_t::SIGNATURE :…
		EXPECT_EQ(x509::verify(content, view_t(signature.data(), signature.size()), "1.2.840.113549.1.1.10", writer.data(), certificate.key()), (tail ? x509::error_t::SIGNATURE : x509::error_t::NONE)) << (tail ? "tail" : "clean");
	}
}

/**
 * Круг 8 (движок): приветствие с key_share без supported_groups отвергается missing_extension
 * (RFC 8446 §9.2), а не ведёт полное рукопожатие
 */
TEST(AuditTest, KeyShareNoGroups){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство client.start() и context::error_t::NONE
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Присваиваем const vector <uint8_t> opening значение результат вызова take()
	const vector <uint8_t> opening = take(client);
	// Объявляем greeting
	hello::client_t greeting;
	// Требуем равенство hello::parse(view_t(opening.data()… и hello::error_t::NONE
	ASSERT_EQ(hello::parse(view_t(opening.data() + 9, opening.size() - 9), greeting), hello::error_t::NONE);
	// Снимаем supported_groups, key_share остаётся
	vector <hello::extension_t> kept;
	/** Перебираем: size_t i = 0 при условии i < greeting.extensions.size() */
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		// Проверяем, что «greeting.extensions[i].type != static_cast <uint16_t> (exte…»
		if(greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::GROUPS))
			// Добавляем элемент в конец накопителя
			kept.push_back(greeting.extensions[i]);
	// Требуем: kept.size() меньше greeting.extensions.size()
	ASSERT_LT(kept.size(), greeting.extensions.size());
	// Расширения приветствия из сохранённых
	greeting.extensions = kept;
	// Объявляем rebuilt — восстановленные данные
	vector <uint8_t> rebuilt;
	// Требуем равенство hello::build(greeting, rebuilt) и hello::error_t::NONE
	ASSERT_EQ(hello::build(greeting, rebuilt), hello::error_t::NONE);
	// Объявляем writer
	handshake::writer_t writer;
	// Передаём байты стороне
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	// Объявляем message и инициализируем результат вызова writer.data()
	const view_t message = writer.data();
	// Присваиваем vector <uint8_t> wire значение значение «{0x16, 0x03, 0x03, static_cast <uint8_t> (message.size…»
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	// Вызываем wire.insert(wire.end(), message.data, message.data + message…)
	wire.insert(wire.end(), message.data, message.data + message.size);
	// Проверяем равенство server.push(view_t(wire.data(), wir… и context::error_t::GROUP
	EXPECT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::GROUP);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.alert().description, alert::description_t::MISSING);
}

/**
 * Круг 8 (записи): записи подтверждения режутся по пределу собеседника, а не только по MTU
 */
TEST(AuditTest, AckLimit){
	// Объявляем flight
	internal::flight_t flight;
	// Вызываем flight.mtu(1400)
	flight.mtu(1400);
	// Вызываем flight.limit(64)
	flight.limit(64);
	/**
	 * Двадцать открытых записей с кусками одного сообщения: каждая подлежит подтверждению
	 */
	for(size_t sequence = 0; sequence < 20; sequence++){
		// Объявляем fragment
		datagram::fragment_t fragment;
		// Вид сообщения части: CERTIFICATE
		fragment.type = handshake::type_t::CERTIFICATE;
		// Номер сообщения части
		fragment.sequence = 1;
		// Полная длина сообщения: двести байтов
		fragment.size = 200;
		// Сдвиг части по десять байтов
		fragment.offset = (sequence * 10);
		// Длина части: десять байтов
		fragment.length = 10;
		// Объявляем piece — фрагмент дейтаграммы и заполняем накопитель (datagram::DATAGRAM_FRAGMENT_HEADER…)
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 10, 0x41);
		// Требуем равенство datagram::build(fragment, piece.dat… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		// Заголовок сообщения рукопожатия
		datagram::header_t header;
		// Заголовок записи раздельный
		header.unified = false;
		// Вид записи: рукопожатие
		header.type = record::type_t::HANDSHAKE;
		// Пора записи нулевая
		header.epoch = 0;
		// Номер записи со счётчика
		header.sequence = sequence;
		// Длина записи по длине куска
		header.size = piece.size();
		// Объявляем head размером datagram::DATAGRAM_PLAIN_HEADER
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		// Объявляем length и инициализируем значение «0»
		size_t length = 0;
		// Требуем равенство datagram::build(header, head, lengt… и datagram::error_t::NONE
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		// Объявляем wire — проволочные данные и конструируем из head, head + length
		vector <uint8_t> wire(head, head + length);
		// Вызываем wire.insert(wire.end(), piece.begin(), piece.end())
		wire.insert(wire.end(), piece.begin(), piece.end());
		// Объявляем opened — открытые записи
		vector <internal::opened_t> opened;
		// Требуем равенство flight.receive(view_t(wire.data(),… и context::error_t::NONE
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		/** Перебираем: size_t j = 0 при условии j < opened.size() */
		for(size_t j = 0; j < opened.size(); j++)
			// Проверяем, что «opened[j].type == record::type_t::HANDSHAKE»
			if(opened[j].type == record::type_t::HANDSHAKE)
				// Вызываем flight.fragments(view_t(opened[j].content.data(), opened…)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	// Требуем равенство flight.complete(false) и context::error_t::NONE
	ASSERT_EQ(flight.complete(false), context::error_t::NONE);
	// Объявляем records и инициализируем значение «0»
	size_t records = 0;
	/** Повторяем, пока «flight.output().size > 0» */
	while(flight.output().size > 0){
		// Объявляем data и инициализируем результат вызова flight.output()
		const view_t data = flight.output();
		/** Перебираем по условию «size_t offset = 0; offset < data.size;» */
		for(size_t offset = 0; offset < data.size;){
			// Заголовок сообщения рукопожатия
			datagram::header_t header;
			// Требуем равенство datagram::parse(view_t(data.data +… и datagram::error_t::NONE
			ASSERT_EQ(datagram::parse(view_t(data.data + offset, data.size - offset), header), datagram::error_t::NONE);
			// Проверяем: header.size не больше static_cast <size_t> (64)
			EXPECT_LE(header.size, static_cast <size_t> (64));
			// Прибавляем к offset «(datagram::DATAGRAM_PLAIN_HEADER + head…»
			offset += (datagram::DATAGRAM_PLAIN_HEADER + header.size);
			// Увеличиваем счётчик разобранных записей
			records++;
		}
		// Забираем обработанные стороной байты
		flight.consume();
	}
	// Проверяем: records не меньше static_cast <size_t> (2)
	EXPECT_GE(records, static_cast <size_t> (2));
}

/**
 * Круг 8 (движок): негодная открытая смена набора серверу DTLS 1.2, ждущему залп клиента,
 * роняется молча, а не рвёт рукопожатие
 */
TEST(AuditTest, ChangeBadBody){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём транспорт движку
	client.transport(context::transport_t::DATAGRAMS);
	// Задаём транспорт движку
	server.transport(context::transport_t::DATAGRAMS);
	// Присваиваем const uint8_t peer[] значение значение «{10, 0, 0, 1, 0x12, 0x34}»
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	// Задаём адрес стороны
	server.address(view_t(peer, sizeof(peer)));
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Три обмена: приветствие, просьба, приветствие с меткой, залп сервера
	vector <vector <uint8_t>> parts;
	/** Перебираем: size_t round = 0 при условии round < 2 */
	for(size_t round = 0; round < 2; round++){
		// Части записей, откачанные со стороны
		parts = drain(client);
		/** Перебираем: size_t i = 0 при условии i < parts.size() */
		for(size_t i = 0; i < parts.size(); i++)
			// Требуем равенство server.push(view_t(parts[i].data(),… и context::error_t::NONE
			ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
		// Части записей, откачанные со стороны
		parts = drain(server);
		/** Перебираем: size_t i = 0 при условии i < parts.size() */
		for(size_t i = 0; i < parts.size(); i++)
			// Требуем равенство client.push(view_t(parts[i].data(),… и context::error_t::NONE
			ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	}
	// Сервер ждёт залп клиента: подделанная открытая смена с негодным телом
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x02};
	// Проверяем равенство server.push(view_t(forged.data(), f… и context::error_t::NONE
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Связь обеих сторон установлена
	EXPECT_TRUE(client.established() && server.established());
}

/**
 * Круг 8 (движок): давность первичного удостоверения не продлевается перевыдачей билета
 * (RFC 5077 §5.6): через 12 суток от первого рукопожатия сервер отвечает полным рукопожатием,
 * а клиент билет с устаревшим удостоверением не предъявляет
 */
TEST(AuditTest, AuthenticationAge){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем vault — хранилище секрета и заполняем накопитель (48, 0x5C)
	const vector <uint8_t> vault(48, 0x5C);
	// Объявляем origin и инициализируем значение «1700000000»
	const int64_t origin = 1700000000;
	// Объявляем day и инициализируем значение «86400»
	const int64_t day = 86400;
	// Объявляем ticket
	context::ticket_t ticket;
	// Первое рукопожатие TLS 1.2 с проверкой подлинности клиента
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Собираем хранилище секрета
		server.vault(vault);
		// Задаём подлинность стороны
		client.credential(credential);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Вызываем server.lifetime(7 * day)
		server.lifetime(7 * day);
		// Вызываем server.moment(origin)
		server.moment(origin);
		// Вызываем client.moment(origin)
		client.moment(origin);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Требуем равенство client.tickets().size() и static_cast <size_t> (1)
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Первый билет клиента
		ticket = client.tickets()[0];
		// Проверяем равенство ticket.authenticated и origin
		EXPECT_EQ(ticket.authenticated, origin);
	}
	// Возобновление через 6 суток: билет свеж, удостоверение свежо - сокращённое рукопожатие с перевыдачей
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Собираем хранилище секрета
		server.vault(vault);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Вызываем server.lifetime(7 * day)
		server.lifetime(7 * day);
		// Вызываем server.moment(origin + 6 * day)
		server.moment(origin + 6 * day);
		// Вызываем client.moment(origin + 6 * day)
		client.moment(origin + 6 * day);
		// Возобновляем связь клиента по билету
		client.resume(ticket);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Клиент разделил секреты со стороной
		EXPECT_TRUE(client.shared());
		// Требуем равенство client.tickets().size() и static_cast <size_t> (1)
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Первый билет клиента
		ticket = client.tickets()[0];
		// Перевыданный билет несёт прежний миг удостоверения
		EXPECT_EQ(ticket.authenticated, origin);
	}
	// Ещё через 6 суток (12 от удостоверения): клиент билет не предъявляет - полное рукопожатие
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Собираем хранилище секрета
		server.vault(vault);
		// Задаём подлинность стороны
		client.credential(credential);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Вызываем server.moment(origin + 12 * day)
		server.moment(origin + 12 * day);
		// Вызываем client.moment(origin + 12 * day)
		client.moment(origin + 12 * day);
		// Возобновляем связь клиента по билету
		client.resume(ticket);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем ложность «client.shared()»
		EXPECT_FALSE(client.shared());
	}
	// Сервер сам судит давность: билет с подделанным свежим мигом удостоверения у клиента, состояние сервера помнит прежний
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Собираем хранилище секрета
		server.vault(vault);
		// Задаём подлинность стороны
		client.credential(credential);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Вызываем server.moment(origin + 12 * day)
		server.moment(origin + 12 * day);
		// Вызываем client.moment(origin + 12 * day)
		client.moment(origin + 12 * day);
		// Объявляем forged и инициализируем значение «ticket»
		context::ticket_t forged = ticket;
		// Момент подделки: за минуту до конца срока
		forged.moment = (origin + 12 * day - 60);
		// Момент подлинности подделки: за минуту до конца срока
		forged.authenticated = (origin + 12 * day - 60);
		// Возобновляем связь клиента по билету
		client.resume(forged);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем ложность «client.shared()»
		EXPECT_FALSE(client.shared());
	}
}

/**
 * Круг 8 (движок): билет годен лишь изданию выдачи - клиент с билетом, помеченным изданием
 * DTLS 1.0, отвергает сокращённое рукопожатие издания 1.2 (RFC 5246 §E.1)
 */
TEST(AuditTest, TicketEditionMismatch){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем vault — хранилище секрета и заполняем накопитель (48, 0x5C)
	const vector <uint8_t> vault(48, 0x5C);
	// Объявляем ticket
	context::ticket_t ticket;
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров стороны
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Ограничиваем наборы шифров стороны
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Собираем хранилище секрета
		server.vault(vault);
		// Требуем равенство server.start() и context::error_t::NONE
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь сторон до тишины
		converse(client, server);
		// Связь обеих сторон установлена
		ASSERT_TRUE(client.established() && server.established());
		// Требуем равенство client.tickets().size() и static_cast <size_t> (1)
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Первый билет клиента
		ticket = client.tickets()[0];
		// Проверяем ложность «ticket.ancient»
		EXPECT_FALSE(ticket.ancient);
	}
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Ограничиваем наборы шифров стороны
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Ограничиваем наборы шифров стороны
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Требуем равенство client.versions(0x0303, 0x0303) и context::error_t::NONE
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Задаём подлинность стороны
	server.credential(credential);
	// Собираем хранилище секрета
	server.vault(vault);
	// Билет помечен устаревшим
	ticket.ancient = true;
	// Возобновляем связь клиента по билету
	client.resume(ticket);
	// Требуем равенство server.start() и context::error_t::NONE
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим связь сторон до тишины
	converse(client, server);
	// Проверяем равенство client.state() и context::state_t::FAILED
	EXPECT_EQ(client.state(), context::state_t::FAILED);
	EXPECT_EQ(client.error(), context::error_t::VERSION);
}

/**
 * Круг 9: Engine::issue() не затирал ключ выдаваемого билета (resumption-PSK) на пути bad_alloc -
 * secret объявлялся ВНУТРИ try, и внешний catch того try места уже не видел. Правка: объявление
 * поднято на уровень функции (до try), внешний catch(bad_alloc) затирает secret. Достижимость
 * внешнего catch замерена отдельно (щуп audit9/engineB, при advance+grease на малых запасах голода).
 * Само затирание стекового секрета тестом не наблюдаемо (стек-алиасинг кадра), потому пин статический:
 * читает исходник issue() и закрепляет ФОРМУ правки - объявление до try и затирание во внешнем catch.
 * Мутация (вернуть объявление внутрь try либо убрать wipe из внешнего catch) роняет пин.
 */
TEST(AuditTest, IssueTicketSecretScopedBeforeTry){
	// Объявляем file и конструируем (ANTS_ENGINE_SRC, std::ios::binary)
	std::ifstream file(ANTS_ENGINE_SRC, std::ios::binary);
	// Исходник движка открыт
	ASSERT_TRUE(file.is_open()) << "нет исходника движка: " << ANTS_ENGINE_SRC;
	// Объявляем source и конструируем ((std::istreambuf_iterator <char> (file)), s…)
	const std::string source((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	// Вырезаем тело issue() по сигнатуре и сопоставлению скобок
	const size_t sign = source.find("Engine::issue() noexcept {");
	// Требуем неравенство sign и std::string::npos)
	ASSERT_NE(sign, std::string::npos) << "сигнатура issue() не найдена";
	// Объявляем open и инициализируем результат вызова source.find()
	const size_t open = source.find('{', sign);
	// Объявляем depth и инициализируем значение «0, close = std::string::npos»
	size_t depth = 0, close = std::string::npos;
	/** Перебираем: size_t i = open при условии i < source.size() */
	for(size_t i = open; i < source.size(); i++){
		// Если «source[i] == '{'», выполняем «depth++»
		if(source[i] == '{') depth++;
		else if(source[i] == '}'){ depth--; if(depth == 0){ close = i; break; } }
	}
	// Требуем неравенство close и std::string::npos)
	ASSERT_NE(close, std::string::npos) << "тело issue() не закрыто";
	// Объявляем body и инициализируем результат вызова source.substr()
	const std::string body = source.substr(open, close - open + 1);
	// Объявление ключа билета обязано стоять ДО try (уровень функции), иначе внешний catch его не видит
	const size_t decl = body.find("uint8_t secret[schedule::SCHEDULE_WIDEST];");
	// Объявляем attempt и инициализируем результат вызова body.find()
	const size_t attempt = body.find("try {");
	// Требуем неравенство decl и std::string::npos)
	ASSERT_NE(decl, std::string::npos) << "объявление secret[] не найдено";
	ASSERT_NE(attempt, std::string::npos) << "try не найден";
	// Проверяем: decl меньше attempt)
	EXPECT_LT(decl, attempt) << "secret[] объявлен внутри try - внешний catch(bad_alloc) его не затрёт (регрессия круга 9)";
	// Внешний catch(bad_alloc) issue() (последний в теле) обязан затирать secret
	const size_t outer = body.rfind("catch(const bad_alloc &)");
	// Требуем неравенство outer и std::string::npos)
	ASSERT_NE(outer, std::string::npos) << "внешний catch(bad_alloc) не найден";
	// Объявляем tail и инициализируем результат вызова body.substr()
	const std::string tail = body.substr(outer);
	// Вызов затирания найден в исходнике
	EXPECT_NE(tail.find("purge(secret"), std::string::npos) << "внешний catch(bad_alloc) не затирает ключ билета (регрессия круга 9; с круга 32 затирание идёт через purge() по классу SECRETS)";
}

/**
 * Круг 13 (движок, по независимому щупу Heartbleed CVE-2014-0160): по установленной связи 1.2 запись
 * сердцебиения с солгавшей длиной нагрузки роняется молча обоими рубежами pulse() - объявленная
 * длина не больше пришедшего содержимого (рубеж 1) и ответ умещается в одну запись собеседника
 * (рубеж 2); честная нагрузка отвечается. Снятие рубежа 1 даёт ответ на умеренную ложь - утечку
 */
TEST(AuditTest, HeartbeatBleed){
	// Подлинность стороны
	context::credential_t credential;
	// Подлинность стороны из файла ключа ec256
	ASSERT_TRUE(keyfile("ec256", credential));
	// Профиль клиента с расширением heartbeat в режиме peer_allowed_to_send
	fingerprint::profile_t profile;
	{
		// Объявляем donor
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём имя проверки
		donor.name("example.com");
		// Требуем равенство donor.start() и context::error_t::NONE
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		// Объявляем extension
		fingerprint::extension_t extension;
		// Вид расширения: heartbeat (0x000F)
		extension.type = 0x000F;
		// Тело расширения: один байт
		extension.data = vector <uint8_t> {0x01};
		// Добавляем элемент в конец накопителя
		profile.extensions.push_back(extension);
	}
	// Заполнение ответа сердцебиения: раздел 4 RFC 6520, не короче 16 байтов
	static constexpr size_t PADDING = 16;
	/**
	 * Четыре нагрузки: честная, умеренная ложь, ложь до предела, честная длина сверх записи собеседника
	 */
	for(size_t item = 0; item < 4; item++){
		// Объявляем client и конструируем (false), server(true)
		internal::engine_t client(false), server(true);
		// Задаём имя проверки
		client.name("example.com");
		// Требуем равенство client.profile(profile) и context::error_t::NONE
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		// Задаём подлинность стороны
		server.credential(credential);
		// Требуем равенство server.versions(0x0303, 0x0303) и context::error_t::NONE
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/** Перебираем: size_t round = 0 при условии round < 16 */
		for(size_t round = 0; round < 16; round++){
			// Объявляем moved и инициализируем значение «false»
			bool moved = false;
			// Объявляем data и инициализируем результат вызова client.output()
			view_t data = client.output();
			// Выполняем «if(data.size > 0){ vector <uint8_t> buffer(data.data, d…», затем client.consume(buffer.size())
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); moved = true; }
			// Вывод сервера забирается целиком
			data = server.output();
			// Выполняем «if(data.size > 0){ vector <uint8_t> buffer(data.data, d…», затем server.consume(buffer.size())
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); moved = true; }
			if(!moved) break;
		}
		// Требуем равенство server.state() и context::state_t::ESTABLISHED)
		ASSERT_EQ(server.state(), context::state_t::ESTABLISHED) << item;
		ASSERT_EQ(server.version(), 0x0303) << item;
		ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << item;
		// Открытое содержимое записи сердцебиения: вид, длина, нагрузка, заполнение
		vector <uint8_t> content;
		// Объявляемая длина нагрузки
		size_t length = 0;
		// Настоящая нагрузка
		const std::string payload = "heartbeat payload";
		/** Разбираем варианты «item» */
		switch(item){
			// Честная: длина равна нагрузке
			case 0: length = payload.size(); content.assign(3 + payload.size() + PADDING, 0x00); break;
			// Умеренная ложь: объявлено на десять байтов больше, чем пришло (Heartbleed по существу)
			case 1: length = (payload.size() + 10); content.assign(3 + payload.size() + PADDING, 0x00); break;
			// Ложь до предела: 0xFFFF при пяти байтах содержимого (буквальный Heartbleed)
			case 2: length = 0xFFFF; content.assign(5, 0x00); break;
			// Честная длина, но ответ не уместится в запись собеседника: рубеж 2
			case 3: length = 20000; content.assign(3 + 20000 + PADDING, 0x00); break;
		}
		// Вид содержимого: данные
		content[0] = 0x01;
		// Старший байт длины содержимого
		content[1] = static_cast <uint8_t> ((length >> 8) & 0xFF);
		// Младший байт длины содержимого
		content[2] = static_cast <uint8_t> (length & 0xFF);
		// Проверяем, что «content.size() >= (3 + payload.size())»
		if(content.size() >= (3 + payload.size()))
			// Вызываем ::memcpy(content.data() + 3, payload.data(), payload.size())
			::memcpy(content.data() + 3, payload.data(), payload.size());
		// Запись подаётся уже расшифрованной: бьём в логику после снятия защиты
		ASSERT_EQ(server.pulse(view_t(content.data(), content.size())), context::error_t::NONE) << item;
		// Связь жива, ошибки нет
		EXPECT_EQ(server.state(), context::state_t::ESTABLISHED) << item;
		EXPECT_EQ(server.error(), context::error_t::NONE) << item;
		// Честная нагрузка отвечается записью вида 24; всякая ложь - молчанием
		if(item == 0){
			// Требуем: server.output().size больше static_cast <size_t> (5))
			ASSERT_GT(server.output().size, static_cast <size_t> (5)) << item;
			// Проверяем равенство server.output().data[0] и 0x18)
			EXPECT_EQ(server.output().data[0], 0x18) << item;
		} else {
			// Проверяем равенство server.output().size и static_cast <size_t> (0))
			EXPECT_EQ(server.output().size, static_cast <size_t> (0)) << item;
		}
	}
}

/**
 * Признак сборки с ограждением адресов: чтение буфера контейнера за его размером там
 * считается переполнением, и с него снимается отрава перед сличением
 */
#if defined(__SANITIZE_ADDRESS__)
	/** Признак сборки с ограждением адресов */
	#define ANTS_AUDIT_ASAN 1
/** Ветвление сборки: defined(__has_feature) */
#elif defined(__has_feature)
	/** Ветвление сборки: __has_feature(address_sanitizer) */
	#if __has_feature(address_sanitizer)
		/** Признак сборки с ограждением адресов */
		#define ANTS_AUDIT_ASAN 1
	#endif
#endif

/**
 * Снятие отравы с области под ограждением адресов
 */
#if defined(ANTS_AUDIT_ASAN)
	#include <sanitizer/asan_interface.h>
	/** Снятие отравы области под ограждением адресов */
	#define ANTS_AUDIT_UNPOISON(data, size) ASAN_UNPOISON_MEMORY_REGION(data, size)
/** Ветвь без ограждения адресов */
#else
	/** Снятие отравы области под ограждением адресов */
	#define ANTS_AUDIT_UNPOISON(data, size) ((void) 0)
#endif

/**
 * Заглядывание в закрытые накопители движка законным способом языка: явное порождение
 * шаблона не подчиняется ограничениям доступа (пункт 12 [temp.explicit] C++17), а
 * дружественная функция, порождённая вместе с ним, отдаёт указатель на закрытый член.
 * Производственного кода это не касается: ни друзей, ни открытых доступов движку не
 * добавлено, и снять пин можно, ничего в движке не трогая
 */
namespace {
	/**
	 * @brief Шаблон порождения дружественной функции, отдающей указатель на член
	 *
	 */
	template <typename Tag, typename Tag::type Member>
	struct Peek {
		/**
		 * @brief Дружественная функция: указатель на член по метке
		 *
		 */
		friend typename Tag::type peek(Tag){ return Member; }
	};
	/**
	 * @brief Метка накопителя принятых прикладных данных движка
	 *
	 */
	struct PlainTag {
		// Вид указателя на член
		typedef vector <uint8_t> internal::Engine::* type;
		// Объявление дружественной функции
		friend type peek(PlainTag);
	};
	/**
	 * @brief Метка накопителя открытого содержимого записи движка
	 *
	 */
	struct OpenedTag {
		// Вид указателя на член
		typedef vector <uint8_t> internal::Engine::* type;
		// Объявление дружественной функции
		friend type peek(OpenedTag);
	};
	/**
	 * Явные порождения: доступ к закрытым членам здесь дозволен языком
	 */
	template struct Peek <PlainTag, &internal::Engine::_plain>;
	template struct Peek <OpenedTag, &internal::Engine::_opened>;
	/**
	 * @brief Функция счёта нулевых байтов области
	 *
	 * @param data область байтов
	 * @param size длина области
	 * @return     число нулевых байтов
	 *
	 */
	static size_t zeros(const uint8_t * data, const size_t size) noexcept {
		// Число нулевых байтов
		size_t result = 0;
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Учитываем нулевой байт
			result += ((data[i] == 0) ? 1 : 0);
		// Выводим число нулевых байтов
		return result;
	}
};

/**
 * Проверка затирания открытого текста принятых записей по классу PLAINTEXT (решения 20
 * и 21 шапки движка): прикладные данные вскрываются прямо в накопитель прикладных
 * данных и выдаются потребителю обменом накопителей - копий открытого текста в движке
 * после read нет; без класса прежний накопитель потребителя, взятый обменом, и накопитель
 * открытого содержимого последней записи рукопожатия держат байты как есть (умолчание,
 * как у OpenSSL без SSL_OP_CLEANSE_PLAINTEXT), с классом - оба нулевые
 */
TEST(AuditTest, PlaintextCleansing){
	// Подлинность стороны сервера
	context::credential_t credential;
	// Выполняем чтение подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Прикладные данные без нулевых байтов
	vector <uint8_t> payload(700);
	/**
	 * Выполняем заполнение прикладных данных
	 */
	for(size_t i = 0; i < payload.size(); i++)
		// Заполняем байт ненулевым значением
		payload[i] = static_cast <uint8_t> (0x21 + (i % 90));
	/**
	 * Выполняем перебор режимов: без класса и с классом
	 */
	for(uint8_t mode = 0; mode < 2; mode++){
		// Движки сторон связи
		internal::engine_t client(false), server(true);
		// Устанавливаем имя узла клиенту
		client.name("example.com");
		// Устанавливаем подлинность серверу
		server.credential(credential);
		// Если режим с классом открытого текста
		if(mode == 1)
			// Устанавливаем классы затирания серверу
			server.wiping(vector <context::wiping_t> {context::wiping_t::SECRETS, context::wiping_t::PLAINTEXT});
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем проведение рукопожатия сторон связи
		 */
		for(size_t round = 0; round < 16; round++){
			// Признак передачи байтов
			bool moved = false;
			// Байты клиента серверу
			view_t data = client.output();
			// Если байты есть
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); moved = true; }
			// Байты сервера клиенту
			data = server.output();
			// Если байты есть
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); moved = true; }
			// Если передавать нечего
			if(!moved) break;
		}
		// Проверяем установленность связи стороной сервера
		ASSERT_EQ(server.state(), context::state_t::ESTABLISHED) << "режим " << static_cast <int> (mode);
		// Накопитель принятых прикладных данных движка
		vector <uint8_t> & plain = (server.*peek(PlainTag()));
		// Накопитель открытого содержимого записи движка
		vector <uint8_t> & opened = (server.*peek(OpenedTag()));
		/**
		 * Последняя запись рукопожатия клиента (Finished) вскрыта прямо в накопитель
		 * прикладных данных и перенесена в накопитель открытого содержимого (решение 21):
		 * по завершении подачи он затёрт лишь с классом
		 */
		ASSERT_GT(opened.size(), static_cast <size_t> (0)) << "режим " << static_cast <int> (mode);
		// Число нулевых байтов в накопителе открытого содержимого
		const size_t cleared = zeros(opened.data(), opened.size());
		// Проверяем: накопитель прикладных данных после отзыва пуст, память его остаётся с движком
		ASSERT_TRUE(plain.empty()) << "режим " << static_cast <int> (mode);
		// Требуем: plain.capacity() не меньше opened.size())
		ASSERT_GE(plain.capacity(), opened.size()) << "режим " << static_cast <int> (mode);
		// Снимаем отраву с буфера накопителя за его размером
		ANTS_AUDIT_UNPOISON(plain.data(), opened.size());
		// Число нулевых байтов в отозванном хвосте накопителя прикладных данных
		const size_t retracted = zeros(plain.data(), opened.size());
		// Если режим без класса
		if(mode == 0){
			// Проверяем сохранность открытого содержимого: затирания нет (нули заголовка сообщения не в счёт)
			EXPECT_LT(cleared, opened.size()) << "без класса PLAINTEXT открытое содержимое затёрто";
			// Проверяем сохранность отозванного хвоста: затирания нет
			EXPECT_LT(retracted, opened.size()) << "без класса PLAINTEXT отозванный хвост затёрт";
		// Если режим с классом
		} else {
			// Проверяем затирание открытого содержимого целиком
			EXPECT_EQ(cleared, opened.size()) << "с классом PLAINTEXT открытое содержимое не затёрто";
			// Проверяем затирание отозванного хвоста целиком
			EXPECT_EQ(retracted, opened.size()) << "с классом PLAINTEXT отозванный хвост не затёрт";
		}
		// Выполняем отправку прикладных данных клиентом
		ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
		// Байты клиента серверу
		const view_t data = client.output();
		// Проверяем наличие записи
		ASSERT_GT(data.size, static_cast <size_t> (0));
		// Копия записи
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		// Выполняем снятие записи с накопителя клиента
		client.consume(buffer.size());
		// Выполняем подачу записи серверу
		ASSERT_EQ(server.push(view_t(buffer.data(), buffer.size())), context::error_t::NONE) << "режим " << static_cast <int> (mode);
		// Проверяем: прикладные данные лежат в накопителе прикладных данных без копии
		ASSERT_EQ(plain.size(), payload.size()) << "режим " << static_cast <int> (mode);
		// Проверяем: накопитель открытого содержимого прикладных данных не держит
		ASSERT_TRUE(opened.empty()) << "режим " << static_cast <int> (mode);
		// Накопитель принятых данных
		vector <uint8_t> received;
		// Выполняем получение принятых сервером прикладных данных
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем схождение принятых данных с отправленными
		ASSERT_EQ(received, payload) << "режим " << static_cast <int> (mode);
		// Проверяем: выдача обменом - открытого текста в движке не осталось
		ASSERT_TRUE(plain.empty()) << "режим " << static_cast <int> (mode);
		/**
		 * Повторная выдача: потребитель отдаёт обменом накопитель с прежними данными,
		 * движок берёт его под следующие записи и затирает лишь с классом
		 */
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем: данных к выдаче не было
		ASSERT_TRUE(received.empty()) << "режим " << static_cast <int> (mode);
		// Проверяем опустошение накопителя прикладных данных
		ASSERT_TRUE(plain.empty()) << "режим " << static_cast <int> (mode);
		// Проверяем: память прежнего накопителя потребителя осталась с движком
		ASSERT_GE(plain.capacity(), payload.size()) << "режим " << static_cast <int> (mode);
		// Снимаем отраву с буфера накопителя за его размером
		ANTS_AUDIT_UNPOISON(plain.data(), payload.size());
		// Число нулевых байтов в буфере прикладных данных
		const size_t blanked = zeros(plain.data(), payload.size());
		// Если режим без класса
		if(mode == 0)
			// Проверяем сохранность прежних байтов в буфере: затирания нет
			EXPECT_EQ(blanked, static_cast <size_t> (0)) << "без класса PLAINTEXT буфер прикладных данных затёрт";
		// Если режим с классом
		else
			// Проверяем затирание буфера прикладных данных целиком
			EXPECT_EQ(blanked, payload.size()) << "с классом PLAINTEXT буфер прикладных данных не затёрт";
	}
}

/**
 * Пин формы решения 20 шапки движка: голых вызовов wipe() в движке нет - всякое
 * затирание секретов идёт через purge() по классу SECRETS, накопителей открытого
 * текста через cleanse() по классу PLAINTEXT; сами purge() и cleanse() - два
 * единственных места с голым wipe()
 */
TEST(AuditTest, SecretsViaPurge){
	// Открываем исходник движка
	std::ifstream file(ANTS_ENGINE_SRC, std::ios::binary);
	// Проверяем открытие исходника
	ASSERT_TRUE(file.is_open()) << "нет исходника движка: " << ANTS_ENGINE_SRC;
	// Исходник целиком
	const std::string source((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	// Число голых вызовов wipe() в начале оператора
	size_t bare = 0;
	// Число вызовов через purge()
	size_t purged = 0;
	// Число вызовов через cleanse()
	size_t cleansed = 0;
	// Начало очередной строки
	size_t offset = 0;
	/**
	 * Выполняем перебор строк исходника
	 */
	while(offset < source.size()){
		// Конец строки
		size_t end = source.find('\n', offset);
		// Если конца строки нет
		if(end == std::string::npos) end = source.size();
		// Строка
		const std::string line = source.substr(offset, end - offset);
		// Начало содержимого строки без отступа
		const size_t start = line.find_first_not_of('\t');
		// Если строка не пуста
		if(start != std::string::npos){
			// Если строка - голый вызов wipe()
			if(line.compare(start, 5, "wipe(") == 0) bare++;
			// Если строка - вызов purge()
			else if(line.compare(start, 12, "this->purge(") == 0) purged++;
			// Если строка - вызов cleanse()
			else if(line.compare(start, 14, "this->cleanse(") == 0) cleansed++;
		}
		// Переходим к следующей строке
		offset = (end + 1);
	}
	// Проверяем: голых wipe() ровно два - тела purge() и cleanse()
	EXPECT_EQ(bare, static_cast <size_t> (2)) << "голый wipe() вне purge()/cleanse() - затирание мимо классов (решение 20)";
	// Проверяем наличие затираний секретов через purge()
	EXPECT_GE(purged, static_cast <size_t> (80)) << "затирания секретов движка идут не через purge()";
	// Проверяем наличие затираний открытого текста через cleanse()
	EXPECT_GE(cleansed, static_cast <size_t> (5)) << "затирания накопителей открытого текста идут не через cleanse()";
	// Тело purge(): голый wipe() внутри
	const size_t purge = source.find("Engine::purge(void * data, const size_t size) const noexcept {");
	// Проверяем наличие purge()
	ASSERT_NE(purge, std::string::npos) << "purge() не найден";
	// Проверяем голый wipe() в purge()
	EXPECT_NE(source.find("wipe(data, size);", purge), std::string::npos) << "purge() не затирает";
	// Проверяем условие класса SECRETS в purge()
	EXPECT_NE(source.find("if(this->_scrubbing)", purge), std::string::npos) << "purge() не смотрит на класс SECRETS";
	// Тело cleanse() над накопителем: делегирует cleanse() над областью
	const size_t vectored = source.find("Engine::cleanse(vector <uint8_t> & data) const noexcept {");
	// Проверяем наличие cleanse() над накопителем
	ASSERT_NE(vectored, std::string::npos) << "cleanse() над накопителем не найден";
	// Проверяем делегирование cleanse() над областью
	EXPECT_NE(source.find("this->cleanse(data.data(), data.size());", vectored), std::string::npos) << "cleanse() над накопителем не делегирует cleanse() над областью";
	// Тело cleanse() над областью: голый wipe() внутри (решение 21 - отзыв хвоста накопителя прикладных данных)
	const size_t cleanse = source.find("Engine::cleanse(uint8_t * data, const size_t size) const noexcept {");
	// Проверяем наличие cleanse() над областью
	ASSERT_NE(cleanse, std::string::npos) << "cleanse() над областью не найден";
	// Проверяем условие класса PLAINTEXT в cleanse()
	EXPECT_NE(source.find("if(this->_cleansing && (data != nullptr) && (size > 0))", cleanse), std::string::npos) << "cleanse() не смотрит на класс PLAINTEXT";
	// Проверяем голый wipe() в cleanse() над областью
	EXPECT_NE(source.find("wipe(data, size);", cleanse), std::string::npos) << "cleanse() не затирает";
}
