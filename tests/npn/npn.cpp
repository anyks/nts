/**
 * @file npn.cpp
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
 * @brief Исходный файл проверок выработки следующего протокола NPN (draft-agl-tls-nextprotoneg,
 *        расширение 0x3374, сообщение NextProtocol): издание 1.2, взаимоисключение с ALPN,
 *        возобновление, издание 1.3 и дейтаграммы, профиль отпечатка, негодное приветствие,
 *        чужой эталон openssl и пайок памяти
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
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора для чтения
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Объявляем накопитель содержимого файла
		vector <uint8_t> result;
		// Проверяем, что файл набора открыт
		if(file.is_open())
			// Считываем содержимое файла набора целиком
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Возвращаем содержимое файла набора
		return result;
	}
	/**
	 * @brief Функция составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		// Считываем секретный ключ набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Считываем сертификат набора
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Проверяем, что оба файла набора прочитаны
		if(result.secret.empty() || text.empty())
			// Прерываем составление подлинности с отказом
			return false;
		// Очищаем цепочку сертификатов подлинности
		result.chain.clear();
		// Составляем цепочку сертификатов и возвращаем признак успеха
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Объявляем признак передачи байтов
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Получаем исходящие байты клиента
			view_t data = client.output();
			// Проверяем наличие исходящих байтов у клиента
			if(data.size > 0){
				// Копируем исходящие байты клиента в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Потребляем исходящие байты у клиента
				client.consume(buffer.size());
				// Передаём байты буфера серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов от клиента
				moved = true;
			}
			// Получаем исходящие байты сервера
			data = server.output();
			// Проверяем наличие исходящих байтов у сервера
			if(data.size > 0){
				// Копируем исходящие байты сервера в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Потребляем исходящие байты у сервера
				server.consume(buffer.size());
				// Передаём байты буфера клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов от сервера
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Возвращаем отказ при нехватке памяти
			return false;
		}
		// Возвращаем признак передачи байтов между сторонами
		return moved;
	}
	/**
	 * @brief Функция проведения рукопожатия сторон связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Функция обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Объявляем контрольный запрос клиента
		const string request = "Запрос по связи с выработкой NPN";
		// Отправляем запрос от клиента серверу
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Прерываем обмен с отказом при ошибке отправки
			return false;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Объявляем накопитель принятых данных
		vector <uint8_t> received;
		// Проверяем приём запроса сервером без искажения
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Прерываем обмен с отказом при искажении запроса
			return false;
		// Объявляем контрольный ответ сервера
		const string answer = "Ответ по связи с выработкой NPN";
		// Отправляем ответ от сервера клиенту
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Прерываем обмен с отказом при ошибке отправки
			return false;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем приём ответа клиентом без искажения
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Прерываем обмен с отказом при искажении ответа
			return false;
		// Возвращаем признак удачного обмена данными
		return true;
	}
	/**
	 * @brief Функция настройки сторон под издание 1.2 с выработкой NPN у обеих
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param mine       протоколы клиента
	 * @param theirs     протоколы сервера
	 * @param legacy     зажать ли обе стороны на издании 1.2
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const vector <string> & mine, const vector <string> & theirs, const bool legacy) noexcept {
		// Устанавливаем серверу подлинность
		server.credential(credential);
		// Задаём клиенту перечень протоколов
		client.protocols(mine);
		// Задаём серверу перечень протоколов
		server.protocols(theirs);
		// Включаем выработку у клиента
		client.negotiation(true);
		// Включаем выработку у сервера
		server.negotiation(true);
		// Проверяем необходимость зажать обе стороны на издании 1.2
		if(legacy){
			// Зажимаем клиента на издании 1.2
			(void) client.versions(0x0303, 0x0303);
			// Зажимаем сервер на издании 1.2
			(void) server.versions(0x0303, 0x0303);
		}
	}
	/**
	 * @brief Функция поиска расширения в снимке приветствия
	 *
	 * @param data     байты приветствия с обвязкой записи
	 * @param type     вид расширения
	 * @param datagram признак записи дейтаграммы
	 * @return         признак присутствия расширения
	 *
	 */
	bool carried(const view_t & data, const uint16_t type, const bool datagram) noexcept {
		// Объявляем профиль отпечатка приветствия
		fingerprint::profile_t profile;
		// Разбираем снимок приветствия в профиль отпечатка
		if(fingerprint::parse(data, profile, datagram) != fingerprint::error_t::NONE)
			// Возвращаем отсутствие расширения при ошибке разбора
			return false;
		/** Перебираем: виды расширений профиля, пока не встретится искомое */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Сравниваем вид очередного расширения с искомым
			if(profile.extensions[i].type == type)
				// Возвращаем признак нахождения расширения
				return true;
		}
		// Возвращаем признак отсутствия расширения
		return false;
	}
	/**
	 * @brief Функция составления приветствия клиента издания 1.2 с расширением NPN заданного тела
	 *
	 * @param body   тело расширения NPN
	 * @param result накопитель, в который помещается запись приветствия
	 * @return       признак успешности составления
	 *
	 */
	bool greeting(const vector <uint8_t> & body, vector <uint8_t> & result) noexcept {
		// Объявляем приветствие клиента
		hello::client_t hello;
		// Устанавливаем приветствию версию издания 1.2
		hello.version = 0x0303;
		::memset(hello.random, 0x42, sizeof(hello.random));
		// Добавляем приветствию набор шифров
		hello.suites.push_back(static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256));
		// Добавляем приветствию способ обмена ключами
		hello.methods.push_back(0x00);
		// Объявляем накопители тел расширений
		vector <uint8_t> schemes, groups;
		// Составляем тела расширений схем подписи и групп
		if((extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes) != extension::error_t::NONE) || (extension::groups(vector <extension::group_t> {extension::group_t::X25519}, groups) != extension::error_t::NONE))
			// Прерываем составление приветствия с отказом
			return false;
		// Добавляем приветствию расширение схем подписи
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NEGOTIATION), view_t(body.data(), body.size())));
		// Объявляем накопитель тела приветствия
		vector <uint8_t> plain;
		// Собираем тело приветствия из записи
		if(hello::build(hello, plain) != hello::error_t::NONE)
			// Прерываем составление приветствия с отказом
			return false;
		// Объявляем сборщик записей рукопожатия
		handshake::writer_t writer;
		// Заворачиваем тело приветствия в запись рукопожатия
		if(writer.push(handshake::type_t::CLIENT, view_t(plain.data(), plain.size())) != handshake::error_t::NONE)
			// Прерываем составление приветствия с отказом
			return false;
		// Объявляем сборщик записей связи
		record::writer_t records;
		// Заворачиваем запись рукопожатия в запись связи
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Прерываем составление приветствия с отказом
			return false;
		// Получаем итоговые байты записи связи
		const view_t data = records.data();
		// Помещаем итоговые байты в накопитель результата
		result.assign(data.data, data.data + data.size);
		// Возвращаем признак удачного составления приветствия
		return true;
	}
};

/**
 * Проверка обмена изданием 1.2: клиент без ALPN берёт первый объявленный, клиент со своими
 * протоколами против сервера без перечня берёт первый свой; протокол и признак у обеих сторон
 */
TEST(NpnTest, Loopback){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.2 с выработкой
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1", "spdy/3"}, true);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем наличие расширения выработки в приветствии клиента
		EXPECT_TRUE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем признак выработки у обеих сторон
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		// Проверяем выработанный протокол клиента
		EXPECT_EQ(client.protocol(), "http/1.1");
		EXPECT_EQ(server.protocol(), "http/1.1");
		// Проверяем обмен прикладными данными между сторонами
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны: у клиента свои протоколы, у сервера перечня нет
		arrange(client, server, credential, vector <string> {"h2", "http/1.1"}, vector <string> (), true);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		// Проверяем признак выработки у обеих сторон
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		// Проверяем выработанный протокол клиента
		EXPECT_EQ(client.protocol(), "h2");
		EXPECT_EQ(server.protocol(), "h2");
		// Проверяем обмен прикладными данными между сторонами
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Без протоколов у обеих сторон выработка идёт с пустым именем (как у BoringSSL): связь установлена, протокол пуст
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны без перечней протоколов у обеих
		arrange(client, server, credential, vector <string> (), vector <string> (), true);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем признак выработки у обеих сторон
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		EXPECT_TRUE(client.protocol().empty() && server.protocol().empty());
		// Проверяем обмен прикладными данными между сторонами
		ASSERT_TRUE(barter(client, server));
	}
}

/**
 * Проверка взаимоисключения с ALPN: при выбранном ALPN расширение NPN не идёт, протокол
 * взят ALPN; без выработки у сервера расширение не идёт вовсе
 */
TEST(NpnTest, Alpn){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны с перечнями протоколов у обеих
		arrange(client, server, credential, vector <string> {"h2", "http/1.1"}, vector <string> {"http/1.1", "h2"}, true);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем отсутствие выработки при выбранном ALPN
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		// Проверяем протокол, взятый ALPN у клиента
		EXPECT_EQ(client.protocol(), "http/1.1");
		EXPECT_EQ(server.protocol(), "http/1.1");
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны без перечня протоколов у клиента
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1"}, true);
		// Отключаем выработку у сервера
		server.negotiation(false);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем отсутствие выработки у обеих сторон
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		// Проверяем пустоту протокола у клиента
		EXPECT_TRUE(client.protocol().empty());
	}
}

/**
 * Проверка возобновления билетом издания 1.2: выработка идёт снова
 */
TEST(NpnTest, Resumed){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем контрольный запас билетов сервера
	const vector <uint8_t> vault(32, 0x44);
	// Объявляем связь клиента
	client::context_t client;
	// Объявляем связь сервера
	server::context_t server;
	// Настраиваем стороны на издание 1.2 с выработкой
	arrange(client, server, credential, vector <string> (), vector <string> {"spdy/3"}, true);
	// Устанавливаем серверу запас билетов
	server.vault(vault);
	// Запускаем сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи у обеих сторон
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем выработанный протокол клиента
	EXPECT_EQ(client.protocol(), "spdy/3");
	// Проверяем получение клиентом билета возобновления
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Объявляем связь возобновляющего клиента
	client::context_t resuming;
	// Объявляем связь возобновляемого сервера
	server::context_t resumed;
	// Настраиваем стороны для возобновления связи
	arrange(resuming, resumed, credential, vector <string> (), vector <string> {"spdy/3"}, true);
	// Устанавливаем возобновляемому серверу запас билетов
	resumed.vault(vault);
	// Передаём возобновляющему клиенту билет прежней связи
	resuming.resume(client.tickets()[0]);
	// Передаём возобновляемому серверу собственные билеты
	resumed.resume(server.tickets());
	// Запускаем возобновляемый сервер
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(resuming, resumed);
	// Проверяем установление возобновлённой связи у обеих сторон
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.shared() && resumed.shared()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	// Проверяем повторную выработку у обеих сторон
	EXPECT_TRUE(resuming.negotiated() && resumed.negotiated());
	// Проверяем протокол возобновляющего клиента
	EXPECT_EQ(resuming.protocol(), "spdy/3");
	EXPECT_EQ(resumed.protocol(), "spdy/3");
	// Проверяем обмен прикладными данными по возобновлённой связи
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка издания 1.3 и дейтаграмм: изданию 1.3 расширение предложено, а сервер молчит;
 * зажатой на 1.3 связи и дейтаграммам расширение не предлагается
 */
TEST(NpnTest, Modern){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.3
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1"}, false);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем предложение расширения выработки в приветствии клиента
		EXPECT_TRUE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи у обеих сторон
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем молчание сервера о выработке
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		// Проверяем пустоту протокола у клиента
		EXPECT_TRUE(client.protocol().empty());
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Включаем выработку у клиента
		client.negotiation(true);
		// Зажимаем клиента на издании 1.3
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем отсутствие расширения выработки в приветствии клиента
		EXPECT_FALSE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Включаем выработку у клиента
		client.negotiation(true);
		// Переводим клиента на записи дейтаграмм
		client.transport(context::transport_t::DATAGRAMS);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем отсутствие расширения выработки в дейтаграмме клиента
		EXPECT_FALSE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), true));
	}
}

/**
 * Проверка профиля отпечатка: снимок с 0x3374 предлагает расширение сам, виды расширений
 * сходятся, и выработка идёт против сервера издания 1.2
 */
TEST(NpnTest, Profile){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем эталонный профиль отпечатка
	fingerprint::profile_t source;
	{
		// Объявляем связь донора снимка
		client::context_t donor;
		// Задаём донору имя сервера
		donor.name("example.com");
		// Включаем выработку у донора
		donor.negotiation(true);
		// Запускаем донора
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	// Объявляем признак нахождения расширения
	bool found = false;
	/** Перебираем: виды расширений эталонного профиля, пока не встретится выработка */
	for(size_t i = 0; i < source.extensions.size(); i++)
		// Отмечаем нахождение расширения выработки
		found = (found || (source.extensions[i].type == static_cast <uint16_t> (extension::type_t::NEGOTIATION)));
	// Проверяем наличие расширения выработки в эталоне
	ASSERT_TRUE(found);
	// Объявляем связь клиента
	client::context_t client;
	// Объявляем связь сервера
	server::context_t server;
	// Задаём клиенту имя сервера
	client.name("example.com");
	// Устанавливаем клиенту эталонный профиль
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Устанавливаем серверу подлинность
	server.credential(credential);
	// Задаём серверу перечень протоколов
	server.protocols(vector <string> {"http/1.1"});
	// Включаем выработку у сервера
	server.negotiation(true);
	// Зажимаем сервер на издании 1.2
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Объявляем профиль снимка клиента
	fingerprint::profile_t made;
	// Разбираем приветствие клиента в профиль снимка
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	/** Перебираем: виды расширений снимка клиента, сравнивая с эталоном */
	for(size_t i = 0; i < made.extensions.size(); i++)
		// Сравниваем вид расширения снимка с эталонным
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи у обеих сторон
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем признак выработки у обеих сторон
	EXPECT_TRUE(client.negotiated() && server.negotiated());
	// Проверяем выработанный протокол клиента
	EXPECT_EQ(client.protocol(), "http/1.1");
}

/**
 * Проверка приветствия клиента с непустым телом NPN: decode_error, а контрольное пустое тело
 * тем же приветствием сервером принимается
 */
TEST(NpnTest, Greedy){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем накопители контрольного и жадного приветствий
	vector <uint8_t> control, greedy;
	// Составляем контрольное приветствие с пустым телом выработки
	ASSERT_TRUE(greeting(vector <uint8_t> (), control));
	ASSERT_TRUE(greeting(vector <uint8_t> {0x00}, greedy));
	{
		// Объявляем связь сервера
		server::context_t server;
		// Устанавливаем серверу подлинность
		server.credential(credential);
		// Включаем выработку у сервера
		server.negotiation(true);
		// Задаём серверу перечень протоколов
		server.protocols(vector <string> {"http/1.1"});
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(server.push(view_t(control.data(), control.size())), context::error_t::NONE);
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// Проверяем наличие ответных байтов у сервера
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Проверяем, что ответ сервера — запись рукопожатия
		EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x16));
	}
	{
		// Объявляем связь сервера
		server::context_t server;
		// Устанавливаем серверу подлинность
		server.credential(credential);
		// Включаем выработку у сервера
		server.negotiation(true);
		// Задаём серверу перечень протоколов
		server.protocols(vector <string> {"http/1.1"});
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Подаём серверу приветствие с непустым телом
		(void) server.push(view_t(greedy.data(), greedy.size()));
		// Проверяем ошибку разбора сообщения у сервера
		EXPECT_EQ(server.error(), context::error_t::MESSAGE);
		EXPECT_EQ(server.alert().description, alert::description_t::DECODE);
		// Проверяем наличие ответных байтов у сервера
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Проверяем, что ответ сервера — запись извещения
		EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x15));
	}
}

/**
 * Проверка разборщика и сборщика перечня NPN: пустое имя, обрезание, круг записи
 */
TEST(NpnTest, Refusals){
	// Таблица проверочных векторов перечня выработки
	static const uint8_t HOLLOW[] = {0x02, 'h', '2', 0x00}, CUT[] = {0x03, 'h', '2'};
	// Объявляем накопитель имён протоколов
	vector <string> names;
	// Проверяем отказ разбора пустого имени протокола
	EXPECT_EQ(extension::negotiation(view_t(HOLLOW, sizeof(HOLLOW)), names), extension::error_t::EMPTY);
	// Очищаем накопитель имён протоколов
	names.clear();
	// Проверяем отказ разбора обрезанного вектора
	EXPECT_EQ(extension::negotiation(view_t(CUT, sizeof(CUT)), names), extension::error_t::HUNGRY);
	// Очищаем накопитель имён протоколов
	names.clear();
	// Проверяем приём пустого перечня протоколов
	EXPECT_EQ(extension::negotiation(view_t(nullptr, 0), names), extension::error_t::NONE);
	// Проверяем пустоту накопителя имён
	EXPECT_TRUE(names.empty());
	// Объявляем накопитель тела перечня
	vector <uint8_t> body;
	// Составляем тело перечня из двух имён протоколов
	ASSERT_EQ(extension::negotiation(vector <string> {"h2", "http/1.1"}, body), extension::error_t::NONE);
	// Проверяем размер тела перечня
	EXPECT_EQ(body.size(), static_cast <size_t> (1 + 2 + 1 + 8));
	// Очищаем накопитель имён протоколов
	names.clear();
	// Разбираем составленное тело перечня
	ASSERT_EQ(extension::negotiation(view_t(body.data(), body.size()), names), extension::error_t::NONE);
	ASSERT_EQ(names.size(), static_cast <size_t> (2));
	// Проверяем первое разобранное имя протокола
	EXPECT_EQ(names[0], "h2");
	EXPECT_EQ(names[1], "http/1.1");
	// Очищаем накопитель тела перечня
	body.clear();
	// Проверяем отказ сборки пустого имени протокола
	EXPECT_EQ(extension::negotiation(vector <string> {""}, body), extension::error_t::EMPTY);
	EXPECT_EQ(extension::negotiation(vector <string> {string(256, 'a')}, body), extension::error_t::EMPTY);
}

/**
 * Проверка чужого эталона: наш клиент против s_server -nextprotoneg без ALPN выбирает своим
 * порядком среди объявленных; наш сервер против s_client -nextprotoneg - журнал показывает
 * выбранный протокол
 */
TEST(NpnTest, Openssl){
	// Запрашиваем сведения о внешнем эталоне
	const toolkit_t toolkit = inspect();
	// Проверяем наличие внешнего эталона
	if(!toolkit.present){
		// Пропускаем проверку при недоступности эталона
		GTEST_SKIP() << "openssl недоступен";
	}
	// Проверяем наличие выработки у команд эталона
	if(!listed("s_server", "nextprotoneg") || !listed("s_client", "nextprotoneg")){
		// Пропускаем проверку при отсутствии выработки у эталона
		GTEST_SKIP() << "openssl собран без NPN";
	}
	// Проверяем издание 1.2 и расширенный главный секрет у эталона
	if(!toolkit.tls12 || !toolkit.master){
		// Пропускаем проверку при несоответствии эталона
		GTEST_SKIP() << "openssl без TLS 1.2 либо без расширенного главного секрета (старше 1.1.0)";
	}
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем пути к сертификату и ключу набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Занимаем свободный порт проверки
		const uint16_t number = vacant(false);
		// Проверяем, что порт занят
		ASSERT_NE(number, 0);
		// Объявляем путь к журналу сервера эталона
		const std::string log = "/tmp/ants-npn-server-" + std::to_string(number) + ".log";
		// Запускаем внешний сервер с выработкой протоколов
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -cert " + crt + " -key " + key + " -nextprotoneg spdy/3,http/1.1 -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Объявляем стража остановки сервера
		sentinel_t sentinel(log + ".pid");
		// Соединяемся с портом внешнего сервера
		const int fd = dial(number);
		// Проверяем установление соединения
		ASSERT_GE(fd, 0) << "порт " << number;
		// Объявляем связь клиента
		client::context_t client;
		// Задаём клиенту наборы шифров
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Задаём клиенту группы
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
		// Задаём клиенту перечень протоколов
		client.protocols(vector <string> {"h2", "http/1.1", "spdy/3"});
		// Включаем выработку у клиента
		client.negotiation(true);
		// Задаём клиенту имя сервера
		client.name("localhost");
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/** Повторяем: передачу байтов, пока связь не установится и не сорвётся */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты между клиентом и сервером
			relay(client, fd);
		// Фиксируем неудачу со снимком журнала при несостоявшейся связи
		if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		// Проверяем установление связи клиентом
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// s_server без -alpn ведёт лишь NPN: выбор своим порядком среди объявленных - http/1.1 раньше spdy/3
		EXPECT_TRUE(client.negotiated());
		// Проверяем протокол, выбранный своим порядком
		EXPECT_EQ(client.protocol(), "http/1.1");
		// Объявляем контрольный запрос к серверу
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем запрос внешнему серверу
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Объявляем накопитель ответа сервера
		vector <uint8_t> reply;
		/** Повторяем: чтение ответа, пока накопитель не получит данные */
		for(size_t i = 0; (i < 16) && reply.empty(); i++){
			// Передаём байты между клиентом и сервером
			relay(client, fd);
			// Считываем ответ внешнего сервера
			ASSERT_EQ(client.read(reply), context::error_t::NONE);
		}
		// Проверяем успешный ответ сервера
		ASSERT_NE(string(reply.begin(), reply.end()).find("HTTP/1.0 200"), string::npos);
		// Закрываем соединение с сервером
		closing(fd);
		// Останавливаем внешний сервер
		sentinel.halt();
		// Объявляем накопитель журнала сервера
		std::string journal;
		// Дожидаемся остановки сервера и снимаем журнал
		(void) settle(log, journal);
		::remove(log.c_str());
	}
	{
		// Объявляем номер порта проверки
		uint16_t number = 0;
		// Открываем ловца соединений на свободном порту
		const int listener = harbour(number);
		// Проверяем открытие ловца соединений
		ASSERT_GE(listener, 0);
		// Объявляем путь к журналу клиента эталона
		const std::string log = "/tmp/ants-npn-client-" + std::to_string(number) + ".log";
		// Запускаем внешнего клиента с выработкой протоколов
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -nextprotoneg spdy/3,http/1.1 -CAfile " + crt + " -servername localhost </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Объявляем стража остановки клиента
		sentinel_t sentinel(log + ".pid");
		// Принимаем соединение от внешнего клиента
		const int fd = greeted(listener);
		// Проверяем принятие соединения
		ASSERT_GE(fd, 0);
		// Объявляем связь сервера
		server::context_t server;
		// Задаём серверу наборы шифров
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Задаём серверу группы
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Зажимаем сервер на издании 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Устанавливаем серверу подлинность
		server.credential(credential);
		// Задаём серверу перечень протоколов
		server.protocols(vector <string> {"http/1.1", "spdy/3"});
		// Включаем выработку у сервера
		server.negotiation(true);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Обслуживаем внешнего клиента до завершения связи
		const bool complete = serve(server, fd);
		// Проверяем бесконфликтное обслуживание клиента
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
		// Проверяем отсутствие ошибки у сервера
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// s_client выбирает первый объявленный сервером из своих: http/1.1
		EXPECT_TRUE(server.negotiated());
		// Проверяем протокол, выбранный клиентом эталона
		EXPECT_EQ(server.protocol(), "http/1.1");
		// Завершаем связь с внешним клиентом
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем соединение с клиентом
		closing(fd);
		closing(listener);
		// Объявляем накопитель журнала клиента
		std::string text;
		// Дожидаемся остановки клиента и снимаем журнал
		ASSERT_TRUE(settle(log, text)) << text;
		// Проверяем выбранный протокол в журнале эталона
		EXPECT_NE(text.find("Next protocol: (1) http/1.1"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь с выработкой NPN либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(NpnTest, Starved){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора в подлинность сервера
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем признак пойманной нехватки памяти
	bool starved = false;
	// Объявляем признак состоявшейся связи
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.2 с выработкой
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1", "spdy/3"}, true);
		// Объявляем коды итогов сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Устанавливаем запас выделений на круг
			starve::ration_t ration(budget);
			// Запускаем сервер на круге
			first = server.start();
			// Запускаем клиента на круге
			second = client.start();
			// Проверяем бесконфликтный запуск обеих сторон
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие сторон
				converse(client, server);
				// Снимаем итог сервера после рукопожатия
				first = server.error();
				// Снимаем итог клиента после рукопожатия
				second = client.error();
			}
		}
		// Отмечаем пойманную нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		// Проверяем законность итогов обеих сторон
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем законность итогов на круге
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Отмечаем состоявшуюся связь
		complete = (client.established() && server.established());
		// Проверяем состоявшуюся связь
		if(complete){
			// Проверяем признак выработки у обеих сторон
			EXPECT_TRUE(client.negotiated() && server.negotiated());
			// Проверяем выработанный протокол клиента
			EXPECT_EQ(client.protocol(), "http/1.1");
		}
	}
	// Проверяем, что нехватка памяти была поймана
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
