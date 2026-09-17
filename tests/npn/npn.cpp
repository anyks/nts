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
#include <unistd.h>

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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		vector <uint8_t> result;
		if(file.is_open())
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		return result;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		result.secret = corpus((std::string(name) + ".pem").c_str());
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		if(result.secret.empty() || text.empty())
			return false;
		result.chain.clear();
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
			data = server.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			return false;
		}
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи
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
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		const string request = "Запрос по связи с выработкой NPN";
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		vector <uint8_t> received;
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			return false;
		const string answer = "Ответ по связи с выработкой NPN";
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			return false;
		return true;
	}
	/**
	 * @brief Метод настройки сторон под издание 1.2 с выработкой NPN у обеих
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
		server.credential(credential);
		client.protocols(mine);
		server.protocols(theirs);
		client.negotiation(true);
		server.negotiation(true);
		if(legacy){
			(void) client.versions(0x0303, 0x0303);
			(void) server.versions(0x0303, 0x0303);
		}
	}
	/**
	 * @brief Метод поиска расширения в снимке приветствия
	 *
	 * @param data     байты приветствия с обвязкой записи
	 * @param type     вид расширения
	 * @param datagram признак записи дейтаграммы
	 *
	 * @return         признак присутствия расширения
	 *
	 */
	bool carried(const view_t & data, const uint16_t type, const bool datagram) noexcept {
		fingerprint::profile_t profile;
		if(fingerprint::parse(data, profile, datagram) != fingerprint::error_t::NONE)
			return false;
		for(size_t i = 0; i < profile.extensions.size(); i++){
			if(profile.extensions[i].type == type)
				return true;
		}
		return false;
	}
	/**
	 * @brief Метод составления приветствия клиента издания 1.2 с расширением NPN заданного тела
	 *
	 * @param body   тело расширения NPN
	 * @param result накопитель, в который помещается запись приветствия
	 *
	 * @return       признак успешности составления
	 *
	 */
	bool greeting(const vector <uint8_t> & body, vector <uint8_t> & result) noexcept {
		hello::client_t hello;
		hello.version = 0x0303;
		::memset(hello.random, 0x42, sizeof(hello.random));
		hello.suites.push_back(static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256));
		hello.methods.push_back(0x00);
		vector <uint8_t> schemes, groups;
		if((extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes) != extension::error_t::NONE) || (extension::groups(vector <extension::group_t> {extension::group_t::X25519}, groups) != extension::error_t::NONE))
			return false;
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NEGOTIATION), view_t(body.data(), body.size())));
		vector <uint8_t> plain;
		if(hello::build(hello, plain) != hello::error_t::NONE)
			return false;
		handshake::writer_t writer;
		if(writer.push(handshake::type_t::CLIENT, view_t(plain.data(), plain.size())) != handshake::error_t::NONE)
			return false;
		record::writer_t records;
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			return false;
		const view_t data = records.data();
		result.assign(data.data, data.data + data.size);
		return true;
	}
};

/**
 * Проверка обмена изданием 1.2: клиент без ALPN берёт первый объявленный, клиент со своими
 * протоколами против сервера без перечня берёт первый свой; протокол и признак у обеих сторон
 */
TEST(NpnTest, Loopback){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1", "spdy/3"}, true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		EXPECT_TRUE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		EXPECT_EQ(client.protocol(), "http/1.1");
		EXPECT_EQ(server.protocol(), "http/1.1");
		ASSERT_TRUE(barter(client, server));
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> {"h2", "http/1.1"}, vector <string> (), true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		EXPECT_EQ(client.protocol(), "h2");
		EXPECT_EQ(server.protocol(), "h2");
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Без протоколов у обеих сторон выработка идёт с пустым именем (как у BoringSSL): связь установлена, протокол пуст
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> (), vector <string> (), true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(client.negotiated() && server.negotiated());
		EXPECT_TRUE(client.protocol().empty() && server.protocol().empty());
		ASSERT_TRUE(barter(client, server));
	}
}

/**
 * Проверка взаимоисключения с ALPN: при выбранном ALPN расширение NPN не идёт, протокол
 * взят ALPN; без выработки у сервера расширение не идёт вовсе
 */
TEST(NpnTest, Alpn){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> {"h2", "http/1.1"}, vector <string> {"http/1.1", "h2"}, true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		EXPECT_EQ(client.protocol(), "http/1.1");
		EXPECT_EQ(server.protocol(), "http/1.1");
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1"}, true);
		server.negotiation(false);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		EXPECT_TRUE(client.protocol().empty());
	}
}

/**
 * Проверка возобновления билетом издания 1.2: выработка идёт снова
 */
TEST(NpnTest, Resumed){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <uint8_t> vault(32, 0x44);
	client::context_t client;
	server::context_t server;
	arrange(client, server, credential, vector <string> (), vector <string> {"spdy/3"}, true);
	server.vault(vault);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	EXPECT_EQ(client.protocol(), "spdy/3");
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	client::context_t resuming;
	server::context_t resumed;
	arrange(resuming, resumed, credential, vector <string> (), vector <string> {"spdy/3"}, true);
	resumed.vault(vault);
	resuming.resume(client.tickets()[0]);
	resumed.resume(server.tickets());
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	converse(resuming, resumed);
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.shared() && resumed.shared()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	EXPECT_TRUE(resuming.negotiated() && resumed.negotiated());
	EXPECT_EQ(resuming.protocol(), "spdy/3");
	EXPECT_EQ(resumed.protocol(), "spdy/3");
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка издания 1.3 и дейтаграмм: изданию 1.3 расширение предложено, а сервер молчит;
 * зажатой на 1.3 связи и дейтаграммам расширение не предлагается
 */
TEST(NpnTest, Modern){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1"}, false);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		EXPECT_TRUE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.negotiated() || server.negotiated());
		EXPECT_TRUE(client.protocol().empty());
	}
	{
		client::context_t client;
		client.negotiation(true);
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		EXPECT_FALSE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), false));
	}
	{
		client::context_t client;
		client.negotiation(true);
		client.transport(context::transport_t::DATAGRAMS);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		EXPECT_FALSE(carried(client.output(), static_cast <uint16_t> (extension::type_t::NEGOTIATION), true));
	}
}

/**
 * Проверка профиля отпечатка: снимок с 0x3374 предлагает расширение сам, виды расширений
 * сходятся, и выработка идёт против сервера издания 1.2
 */
TEST(NpnTest, Profile){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t source;
	{
		client::context_t donor;
		donor.name("example.com");
		donor.negotiation(true);
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	bool found = false;
	for(size_t i = 0; i < source.extensions.size(); i++)
		found = (found || (source.extensions[i].type == static_cast <uint16_t> (extension::type_t::NEGOTIATION)));
	ASSERT_TRUE(found);
	client::context_t client;
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	server.credential(credential);
	server.protocols(vector <string> {"http/1.1"});
	server.negotiation(true);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	fingerprint::profile_t made;
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	for(size_t i = 0; i < made.extensions.size(); i++)
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_TRUE(client.negotiated() && server.negotiated());
	EXPECT_EQ(client.protocol(), "http/1.1");
}

/**
 * Проверка приветствия клиента с непустым телом NPN: decode_error, а контрольное пустое тело
 * тем же приветствием сервером принимается
 */
TEST(NpnTest, Greedy){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	vector <uint8_t> control, greedy;
	ASSERT_TRUE(greeting(vector <uint8_t> (), control));
	ASSERT_TRUE(greeting(vector <uint8_t> {0x00}, greedy));
	{
		server::context_t server;
		server.credential(credential);
		server.negotiation(true);
		server.protocols(vector <string> {"http/1.1"});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(server.push(view_t(control.data(), control.size())), context::error_t::NONE);
		ASSERT_EQ(server.error(), context::error_t::NONE);
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x16));
	}
	{
		server::context_t server;
		server.credential(credential);
		server.negotiation(true);
		server.protocols(vector <string> {"http/1.1"});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		(void) server.push(view_t(greedy.data(), greedy.size()));
		EXPECT_EQ(server.error(), context::error_t::MESSAGE);
		EXPECT_EQ(server.alert().description, alert::description_t::DECODE);
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x15));
	}
}

/**
 * Проверка разборщика и сборщика перечня NPN: пустое имя, обрезание, круг записи
 */
TEST(NpnTest, Refusals){
	static const uint8_t HOLLOW[] = {0x02, 'h', '2', 0x00}, CUT[] = {0x03, 'h', '2'};
	vector <string> names;
	EXPECT_EQ(extension::negotiation(view_t(HOLLOW, sizeof(HOLLOW)), names), extension::error_t::EMPTY);
	names.clear();
	EXPECT_EQ(extension::negotiation(view_t(CUT, sizeof(CUT)), names), extension::error_t::HUNGRY);
	names.clear();
	EXPECT_EQ(extension::negotiation(view_t(nullptr, 0), names), extension::error_t::NONE);
	EXPECT_TRUE(names.empty());
	vector <uint8_t> body;
	ASSERT_EQ(extension::negotiation(vector <string> {"h2", "http/1.1"}, body), extension::error_t::NONE);
	EXPECT_EQ(body.size(), static_cast <size_t> (1 + 2 + 1 + 8));
	names.clear();
	ASSERT_EQ(extension::negotiation(view_t(body.data(), body.size()), names), extension::error_t::NONE);
	ASSERT_EQ(names.size(), static_cast <size_t> (2));
	EXPECT_EQ(names[0], "h2");
	EXPECT_EQ(names[1], "http/1.1");
	body.clear();
	EXPECT_EQ(extension::negotiation(vector <string> {""}, body), extension::error_t::EMPTY);
	EXPECT_EQ(extension::negotiation(vector <string> {string(256, 'a')}, body), extension::error_t::EMPTY);
}

/**
 * Проверка чужого эталона: наш клиент против s_server -nextprotoneg без ALPN выбирает своим
 * порядком среди объявленных; наш сервер против s_client -nextprotoneg - журнал показывает
 * выбранный протокол
 */
TEST(NpnTest, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	if(!listed("s_server", "nextprotoneg") || !listed("s_client", "nextprotoneg")){
		GTEST_SKIP() << "openssl собран без NPN";
	}
	if(!toolkit.tls12 || !toolkit.master){
		GTEST_SKIP() << "openssl без TLS 1.2 либо без расширенного главного секрета (старше 1.1.0)";
	}
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		const uint16_t number = vacant(false);
		ASSERT_NE(number, 0);
		const std::string log = "/tmp/ants-npn-server-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -cert " + crt + " -key " + key + " -nextprotoneg spdy/3,http/1.1 -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = dial(number);
		ASSERT_GE(fd, 0) << "порт " << number;
		client::context_t client;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
		client.protocols(vector <string> {"h2", "http/1.1", "spdy/3"});
		client.negotiation(true);
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			relay(client, fd);
		if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// s_server без -alpn ведёт лишь NPN: выбор своим порядком среди объявленных - http/1.1 раньше spdy/3
		EXPECT_TRUE(client.negotiated());
		EXPECT_EQ(client.protocol(), "http/1.1");
		const string request = "GET / HTTP/1.0\r\n\r\n";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		vector <uint8_t> reply;
		for(size_t i = 0; (i < 16) && reply.empty(); i++){
			relay(client, fd);
			ASSERT_EQ(client.read(reply), context::error_t::NONE);
		}
		ASSERT_NE(string(reply.begin(), reply.end()).find("HTTP/1.0 200"), string::npos);
		closing(fd);
		sentinel.halt();
		std::string journal;
		(void) settle(log, journal);
		::remove(log.c_str());
	}
	{
		uint16_t number = 0;
		const int listener = harbour(number);
		ASSERT_GE(listener, 0);
		const std::string log = "/tmp/ants-npn-client-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -nextprotoneg spdy/3,http/1.1 -CAfile " + crt + " -servername localhost </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0);
		server::context_t server;
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.protocols(vector <string> {"http/1.1", "spdy/3"});
		server.negotiation(true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		const bool complete = serve(server, fd);
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// s_client выбирает первый объявленный сервером из своих: http/1.1
		EXPECT_TRUE(server.negotiated());
		EXPECT_EQ(server.protocol(), "http/1.1");
		ASSERT_TRUE(farewell(server, fd));
		closing(fd);
		closing(listener);
		std::string text;
		ASSERT_TRUE(settle(log, text)) << text;
		EXPECT_NE(text.find("Next protocol: (1) http/1.1"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь с выработкой NPN либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(NpnTest, Starved){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	bool starved = false;
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, vector <string> (), vector <string> {"http/1.1", "spdy/3"}, true);
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			starve::ration_t ration(budget);
			first = server.start();
			second = client.start();
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				converse(client, server);
				first = server.error();
				second = client.error();
			}
		}
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		complete = (client.established() && server.established());
		if(complete){
			EXPECT_TRUE(client.negotiated() && server.negotiated());
			EXPECT_EQ(client.protocol(), "http/1.1");
		}
	}
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
