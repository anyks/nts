/**
 * @file heartbeat.cpp
 * @date 2026-09-08
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
 * @brief Исходный файл проверок терпимости к сердцебиению RFC 6520 (расширение 0x000F из профилей
 *        отпечатков, запись вида 24): с предложенным расширением запись роняется молча без ответа,
 *        без него - unexpected_message; чужой эталон gnutls-serv --heartbeat
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <functional>
#include <algorithm>
#include <unistd.h>

/**
 * Заголовочные файлы проверок
 */
#include <main.hpp>
#include <openssl.hpp>

/**
 * Заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Каталог образцов ключей
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные помощники проверок
 *
 */
namespace {
	/**
	 * @brief Метод чтения файла образцов
	 *
	 * @param name имя файла
	 *
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Файл образца
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт, читаем его целиком
		if(file.is_open())
			// Читаем содержимое
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое
		return result;
	}
	/**
	 * @brief Метод загрузки ключа и цепочки из образцов
	 *
	 * @param name   имя пары файлов
	 * @param result полномочия сервера
	 *
	 * @return       признак успешной загрузки
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		// Читаем закрытый ключ
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем цепочку
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если чего-то нет
		if(result.secret.empty() || text.empty())
			// Выводим отказ
			return false;
		// Очищаем цепочку
		result.chain.clear();
		// Разбираем цепочку из PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод снятия профиля с приветствия донора и дописывания расширения предела
	 *
	 * @param result профиль
	 * @param types  виды дописываемых расширений по порядку
	 * @param bodies тела расширений по порядку
	 *
	 * @return       признак готовности профиля
	 *
	 */
	bool profiling(fingerprint::profile_t & result, const vector <uint16_t> & types, const vector <vector <uint8_t>> & bodies) noexcept {
		// Клиент-донор
		client::context_t donor;
		// Имя узла донора
		donor.name("example.com");
		// Если приветствие донора не составлено
		if(donor.start() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Если приветствие донора не разобрано
		if(fingerprint::parse(donor.output(), result) != fingerprint::error_t::NONE)
			// Выводим отказ
			return false;
		/**
		 * Выполняем дописывание расширений
		 */
		for(size_t i = 0; i < types.size(); i++){
			// Расширение предела
			fingerprint::extension_t extension;
			// Вид и тело
			extension.type = types[i];
			extension.data = bodies[i];
			// Дописываем расширение
			result.extensions.push_back(extension);
		}
		// Выводим успешность
		return true;
	}
	/**
	 * Вид расширения heartbeat (RFC 6520)
	 */
	static constexpr uint16_t HEARTBEAT = 0x000F;
};

/**
 * @brief Метод проведения связи издания 1.2 с искажением открытого вывода сервера по дороге
 *
 * @param types   виды расширений предела у клиента
 * @param bodies  тела расширений предела
 * @param distort искажение первого вывода сервера (приветствие и цепочка открыты у 1.2)
 * @param client  клиент по итогу
 *
 */
static void hostile(const vector <uint16_t> & types, const vector <vector <uint8_t>> & bodies, const std::function <void (vector <uint8_t> &, const size_t)> & distort, client::context_t & client){
	// Полномочия и профиль
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t profile;
	ASSERT_TRUE(profiling(profile, types, bodies));
	// Сервер
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Номер вывода сервера
	size_t flight = 0;
	/**
	 * Выполняем обмен, искажая каждый вывод сервера по дороге
	 */
	for(size_t i = 0; i < 16; i++){
		// Признак переноса
		bool moved = false;
		// Вывод клиента уходит серверу как есть
		{
			const view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		}
		// Вывод сервера искажается
		{
			const view_t data = server.output();
			if(data.size > 0){
				vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				distort(buffer, flight++);
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		}
		// Если тишина, выходим
		if(!moved)
			break;
	}
}

/**
 * @brief Метод вклейки открытой записи сердцебиения (вид 24) во второй вывод сервера издания 1.2
 *
 * @param buffer вывод сервера
 * @param flight номер вывода
 * @param glued  признак того, что вклейка легла
 *
 */
static void beating(vector <uint8_t> & buffer, const size_t flight, bool & glued){
	// Только второй вывод: билет идёт открытым до смены набора
	if(flight != 1)
		return;
	// Запись HeartbeatRequest: тип 1, длина нагрузки 4, нагрузка, набивка 16 байтов (раздел 4 RFC 6520)
	static const uint8_t BEAT[] = {0x18, 0x03, 0x03, 0x00, 0x17, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	// Вклеиваем перед первой записью вывода
	buffer.insert(buffer.begin(), BEAT, BEAT + sizeof(BEAT));
	glued = true;
}

/**
 * Проверка терпимости: профиль с heartbeat против нашего сервера - связь устанавливается, ответа
 * на расширение нет; открытая запись вида 24 в выводе сервера 1.2 роняется молча, данные идут
 */
TEST(HeartbeatTest, Tolerated){
	// Клиент и признак вклейки
	client::context_t client;
	bool glued = false;
	// Связь с профилем heartbeat и вклейкой записи сердцебиения
	hostile({HEARTBEAT}, {vector <uint8_t> {0x01}}, [&glued](vector <uint8_t> & buffer, const size_t flight){ beating(buffer, flight, glued); }, client);
	// Вклейка легла, связь установлена, ошибки нет
	ASSERT_TRUE(glued);
	EXPECT_TRUE(client.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
	EXPECT_EQ(client.error(), context::error_t::NONE);
}

/**
 * Проверка строгости: без предложенного heartbeat та же запись вида 24 - unexpected_message
 */
TEST(HeartbeatTest, Unasked){
	// Клиент и признак вклейки
	client::context_t client;
	bool glued = false;
	// Связь без heartbeat в профиле и с вклейкой
	hostile({}, {}, [&glued](vector <uint8_t> & buffer, const size_t flight){ beating(buffer, flight, glued); }, client);
	// Вклейка легла, клиент отверг запись
	ASSERT_TRUE(glued);
	EXPECT_FALSE(client.established());
	EXPECT_EQ(client.error(), context::error_t::RECORD);
	EXPECT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
}

/**
 * Проверка сервера: клиент с heartbeat в профиле, вклейка записи вида 24 в вывод клиента 1.2 после
 * приветствия - сервер роняет её молча; без предложения - unexpected_message
 */
TEST(HeartbeatTest, Server){
	// Наличие предложения
	static const bool OFFERED[] = {true, false};
	/**
	 * Выполняем перебор
	 */
	for(size_t i = 0; i < 2; i++){
		// Полномочия и профиль
		context::credential_t credential;
		ASSERT_TRUE(keyfile("ec256", credential));
		fingerprint::profile_t profile;
		ASSERT_TRUE(profiling(profile, (OFFERED[i] ? vector <uint16_t> {HEARTBEAT} : vector <uint16_t> {}), (OFFERED[i] ? vector <vector <uint8_t>> {{0x01}} : vector <vector <uint8_t>> {})));
		// Стороны
		client::context_t client;
		server::context_t server;
		client.name("example.com");
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		server.credential(credential);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента серверу с вклейкой записи сердцебиения после него
		{
			const view_t hello = client.output();
			vector <uint8_t> buffer(hello.data, hello.data + hello.size);
			client.consume(buffer.size());
			bool glued = false;
			beating(buffer, 1, glued);
			// Вклейка идёт после приветствия: сначала приветствие, потом запись
			vector <uint8_t> ordered(buffer.begin() + 28, buffer.end());
			ordered.insert(ordered.end(), buffer.begin(), buffer.begin() + 28);
			server.push(view_t(ordered.data(), ordered.size()));
		}
		// Итог
		if(OFFERED[i]){
			EXPECT_NE(server.state(), context::state_t::FAILED) << i;
			EXPECT_EQ(server.error(), context::error_t::NONE) << i;
		} else {
			EXPECT_EQ(server.state(), context::state_t::FAILED) << i;
			EXPECT_EQ(server.alert().description, alert::description_t::UNEXPECTED) << i;
		}
	}
}

/**
 * Проверка чужим эталоном gnutls: gnutls-serv --heartbeat против клиента по профилю с heartbeat -
 * рукопожатие и эхо идут, запросы сердцебиения (если сервер их шлёт) роняются молча
 */
TEST(HeartbeatTest, Gnutls){
	// Если gnutls-serv нет
	if(::system("gnutls-serv --version >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "gnutls-serv недоступен";
	}
	// Полномочия
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Порт и журнал
	const uint16_t number = vacant(false);
	ASSERT_NE(number, 0);
	const std::string log = "/tmp/ants-heartbeat-gnutls-" + std::to_string(number) + ".log";
	// Запускаем сервер с сердцебиением в режиме эха
	ASSERT_TRUE(launch("gnutls-serv --port " + std::to_string(number) + " --x509certfile " + crt + " --x509keyfile " + key + " --echo --heartbeat --disable-client-cert --priority NORMAL:+VERS-TLS1.2 > " + log + " 2>&1", log, log + ".pid"));
	sentinel_t sentinel(log + ".pid");
	// Подключаемся
	const int fd = dial(number);
	ASSERT_GE(fd, 0) << "порт " << number;
	// Профиль с heartbeat
	fingerprint::profile_t profile;
	ASSERT_TRUE(profiling(profile, {HEARTBEAT}, {vector <uint8_t> {0x01}}));
	client::context_t client;
	client.name("localhost");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Рукопожатие
	for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
		relay(client, fd);
	if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
	ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
	// Эхо
	const std::string message = "сердцебиение роняется, эхо идёт\n";
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size())), context::error_t::NONE);
	vector <uint8_t> echo;
	for(size_t i = 0; (i < 16) && (echo.size() < message.size()); i++){
		relay(client, fd);
		vector <uint8_t> piece;
		ASSERT_EQ(client.read(piece), context::error_t::NONE) << "отказ " << static_cast <int> (client.error());
		echo.insert(echo.end(), piece.begin(), piece.end());
	}
	EXPECT_EQ(string(echo.begin(), echo.end()), message);
	closing(fd);
	sentinel.halt();
	std::string journal;
	(void) settle(log, journal);
	::remove(log.c_str());
}

/**
 * Запрос и ответ по установленной связи 1.2 обеими сторонами: нагрузка возвращается слово в слово,
 * ответ считается, второй запрос до ответа отвергается, без расширения запрос отвергается
 */
TEST(HeartbeatTest, Ping){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t profile;
	ASSERT_TRUE(profiling(profile, {HEARTBEAT}, {vector <uint8_t> {0x01}}));
	client::context_t client;
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// До установления связи запрос отвергается
	EXPECT_EQ(client.heartbeat(view_t()), context::error_t::STATE);
	for(size_t i = 0; (i < 16) && !(client.established() && server.established()); i++){
		view_t data = client.output();
		if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); }
		data = server.output();
		if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); }
	}
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Клиент шлёт запрос, сервер отвечает
	const std::string payload = "нагрузка сердцебиения";
	ASSERT_EQ(client.heartbeat(view_t(reinterpret_cast <const uint8_t *> (payload.data()), payload.size())), context::error_t::NONE);
	EXPECT_EQ(client.heartbeat(view_t()), context::error_t::STATE);
	{
		const view_t data = client.output();
		ASSERT_GT(data.size, static_cast <size_t> (5));
		// Запись вида 24 на проводе
		EXPECT_EQ(data.data[0], 0x18);
		vector <uint8_t> buffer(data.data, data.data + data.size);
		client.consume(buffer.size());
		server.push(view_t(buffer.data(), buffer.size()));
	}
	EXPECT_EQ(server.error(), context::error_t::NONE);
	{
		const view_t data = server.output();
		ASSERT_GT(data.size, static_cast <size_t> (5)) << "сервер не ответил";
		EXPECT_EQ(data.data[0], 0x18);
		vector <uint8_t> buffer(data.data, data.data + data.size);
		server.consume(buffer.size());
		client.push(view_t(buffer.data(), buffer.size()));
	}
	EXPECT_EQ(client.pulses(), static_cast <size_t> (1));
	EXPECT_EQ(server.pulses(), static_cast <size_t> (0));
	// Сервер шлёт запрос, клиент отвечает
	ASSERT_EQ(server.heartbeat(view_t()), context::error_t::NONE);
	{
		const view_t data = server.output();
		vector <uint8_t> buffer(data.data, data.data + data.size);
		server.consume(buffer.size());
		client.push(view_t(buffer.data(), buffer.size()));
	}
	{
		const view_t data = client.output();
		ASSERT_GT(data.size, static_cast <size_t> (5)) << "клиент не ответил";
		vector <uint8_t> buffer(data.data, data.data + data.size);
		client.consume(buffer.size());
		server.push(view_t(buffer.data(), buffer.size()));
	}
	EXPECT_EQ(server.pulses(), static_cast <size_t> (1));
	// Второй запрос после ответа дозволен
	EXPECT_EQ(client.heartbeat(view_t()), context::error_t::NONE);
	// Прикладные данные ходят по-прежнему
	const std::string message = "после сердцебиения";
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size())), context::error_t::NONE);
	{
		const view_t data = client.output();
		vector <uint8_t> buffer(data.data, data.data + data.size);
		client.consume(buffer.size());
		server.push(view_t(buffer.data(), buffer.size()));
	}
	vector <uint8_t> received;
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(std::string(received.begin(), received.end()), message);
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
	EXPECT_EQ(client.state(), context::state_t::ESTABLISHED);
	// Без расширения запрос отвергается настройками
	{
		client::context_t plain;
		server::context_t host;
		plain.name("example.com");
		host.credential(credential);
		ASSERT_EQ(host.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(host.start(), context::error_t::NONE);
		ASSERT_EQ(plain.start(), context::error_t::NONE);
		for(size_t i = 0; (i < 16) && !(plain.established() && host.established()); i++){
			view_t data = plain.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); plain.consume(buffer.size()); host.push(view_t(buffer.data(), buffer.size())); }
			data = host.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); host.consume(buffer.size()); plain.push(view_t(buffer.data(), buffer.size())); }
		}
		ASSERT_TRUE(plain.established() && host.established());
		EXPECT_EQ(plain.heartbeat(view_t()), context::error_t::SETTINGS);
		EXPECT_EQ(host.heartbeat(view_t()), context::error_t::SETTINGS);
	}
}
