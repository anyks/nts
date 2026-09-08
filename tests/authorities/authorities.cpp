/**
 * @file authorities.cpp
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
 * @brief Исходный файл проверок перечня доверенных удостоверяющих центров в запросе
 *        подлинности (раздел 4.2.4 RFC 8446, раздел 7.4.4 RFC 5246): обоими изданиями,
 *        враждебный сервер, разборщик перечня, чужой эталон openssl и пайок памяти
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
#include <adversary.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <x509/x509.hpp>
#include <alert/alert.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <extension/extension.hpp>

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
	 * @brief Метод составления подлинности стороны из ключей набора (identity.hpp вырабатывает ГОСТ)
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
	 * @brief Метод получения имени владельца сертификата набора как записано
	 *
	 * @param name имя сертификата набора
	 *
	 * @return     DER-запись имени владельца либо пусто
	 *
	 */
	vector <uint8_t> subject(const char * name) noexcept {
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		vector <vector <uint8_t>> chain;
		if(text.empty() || (pem::certificates(std::string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			return vector <uint8_t> ();
		x509::certificate_t certificate;
		if(certificate.parse(view_t(chain[0].data(), chain[0].size())) != x509::error_t::NONE)
			return vector <uint8_t> ();
		const view_t element = certificate.subjects().element;
		return vector <uint8_t> (element.data, element.data + element.size);
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
	 * @brief Метод настройки сторон: подлинности обеих, запрос подлинности и перечень центров у сервера
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param mine   подлинность сервера
	 * @param theirs подлинность клиента
	 * @param names  перечень имён центров, пустой - не задаётся
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & mine, const context::credential_t & theirs, const vector <vector <uint8_t>> & names) noexcept {
		server.credential(mine);
		server.request(true);
		client.credential(theirs);
		if(!names.empty())
			server.authorities(names);
	}
};

/**
 * Проверка обмена изданием 1.3: перечень доходит в запросе подлинности, равен имени
 * владельца сертификата центра, подлинность клиента проходит; без перечня - пусто
 */
TEST(AuthoritiesTest, Loopback){
	context::credential_t mine, theirs;
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("rsa2048", theirs));
	const vector <uint8_t> root = subject("ca-ec"), other = subject("ca-rsa");
	ASSERT_FALSE(root.empty() || other.empty());
	EXPECT_EQ(root[0], static_cast <uint8_t> (0x30));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> {root, other});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		ASSERT_EQ(client.authorities().size(), static_cast <size_t> (2));
		EXPECT_EQ(client.authorities()[0], root);
		EXPECT_EQ(client.authorities()[1], other);
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		EXPECT_EQ(server.peer()[0], theirs.chain[0]);
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> ());
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_TRUE(client.authorities().empty());
	}
	{
		// Без запроса подлинности перечень не идёт вовсе
		client::context_t client;
		server::context_t server;
		server.credential(mine);
		server.authorities(vector <vector <uint8_t>> {root});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_TRUE(client.authorities().empty());
	}
}

/**
 * Проверка издания 1.2: перечень идёт полем запроса подлинности
 */
TEST(AuthoritiesTest, Legacy){
	context::credential_t mine, theirs;
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("rsa2048", theirs));
	const vector <uint8_t> root = subject("ca-ec");
	ASSERT_FALSE(root.empty());
	for(size_t named = 0; named < 2; named++){
		client::context_t client;
		server::context_t server;
		arrange(client, server, mine, theirs, ((named == 1) ? vector <vector <uint8_t>> {root} : vector <vector <uint8_t>> ()));
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << named << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		ASSERT_EQ(client.authorities().size(), named);
		if(named == 1)
			EXPECT_EQ(client.authorities()[0], root);
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
	}
}

/**
 * Проверка враждебного сервера: пустой перечень, пустое имя, хвост и имя не SEQUENCE в
 * запросе подлинности - decode_error
 */
TEST(AuthoritiesTest, Lying){
	static const distortion_t MALFORMED[] = {distortion_t::MALCA, distortion_t::HOLLOWCA, distortion_t::TRAILCA, distortion_t::NOTSEQCA};
	/**
	 * Выполняем перебор негодных перечней
	 */
	for(size_t i = 0; i < (sizeof(MALFORMED) / sizeof(MALFORMED[0])); i++){
		// Враждебный сервер набора проверок говорит лишь наборами ГОСТ
		client::context_t client;
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		ASSERT_EQ(client.start(), context::error_t::NONE);
		ASSERT_TRUE(adversary(client, MALFORMED[i])) << i;
		EXPECT_EQ(client.error(), context::error_t::MESSAGE) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::DECODE) << i;
		EXPECT_FALSE(client.established()) << i;
		EXPECT_TRUE(client.authorities().empty()) << i;
	}
}

/**
 * Проверка отказов: негодное имя у сервера - SETTINGS при заведении; разборщик и сборщик
 * перечня на пустоте, не SEQUENCE и обрезании
 */
TEST(AuthoritiesTest, Refusals){
	context::credential_t mine;
	ASSERT_TRUE(keyfile("ec256", mine));
	{
		server::context_t server;
		server.credential(mine);
		server.request(true);
		server.authorities(vector <vector <uint8_t>> {vector <uint8_t> ()});
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		server::context_t server;
		server.credential(mine);
		server.request(true);
		server.authorities(vector <vector <uint8_t>> {vector <uint8_t> {0x31, 0x00}});
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	static const uint8_t EMPTYLIST[] = {0x00, 0x00}, HOLLOWLIST[] = {0x00, 0x02, 0x00, 0x00}, TRAILLIST[] = {0x00, 0x03, 0x00, 0x01, 0x30, 0xFF}, NOTSEQ[] = {0x00, 0x03, 0x00, 0x01, 0x31};
	vector <vector <uint8_t>> names;
	EXPECT_EQ(extension::authorities(view_t(EMPTYLIST, sizeof(EMPTYLIST)), names), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(view_t(HOLLOWLIST, sizeof(HOLLOWLIST)), names), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(view_t(TRAILLIST, sizeof(TRAILLIST)), names), extension::error_t::TRAILING);
	EXPECT_EQ(extension::authorities(view_t(NOTSEQ, sizeof(NOTSEQ)), names), extension::error_t::EMPTY);
	const vector <uint8_t> root = subject("ca-ec"), other = subject("ca-rsa");
	vector <uint8_t> list;
	ASSERT_EQ(extension::authorities(vector <vector <uint8_t>> {root, other}, list), extension::error_t::NONE);
	/**
	 * Отказ: обрезание перечня на всякой длине
	 */
	for(size_t i = 0; i < list.size(); i++){
		names.clear();
		EXPECT_NE(extension::authorities(view_t(list.data(), i), names), extension::error_t::NONE) << "длина " << i;
	}
	names.clear();
	ASSERT_EQ(extension::authorities(view_t(list.data(), list.size()), names), extension::error_t::NONE);
	ASSERT_EQ(names.size(), static_cast <size_t> (2));
	EXPECT_EQ(names[0], root);
	EXPECT_EQ(names[1], other);
	vector <uint8_t> rebuilt;
	EXPECT_EQ(extension::authorities(vector <vector <uint8_t>> (), rebuilt), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(vector <vector <uint8_t>> {vector <uint8_t> {0x31}}, rebuilt), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(vector <vector <uint8_t>> {vector <uint8_t> (0x10000, 0x30)}, rebuilt), extension::error_t::EMPTY);
}

/**
 * Проверка чужого эталона: наш клиент против s_server -Verify -CAfile (перечень несёт
 * владельца файла центров), наш сервер против s_client с сертификатом (журнал показывает
 * приемлемые имена центров)
 */
TEST(AuthoritiesTest, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	if(!toolkit.tls13){
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <uint8_t> owner = subject("ec256");
	ASSERT_FALSE(owner.empty());
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		const uint16_t number = vacant(false);
		ASSERT_NE(number, 0);
		const std::string log = "/tmp/ants-authorities-server-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = dial(number);
		ASSERT_GE(fd, 0) << "порт " << number;
		client::context_t client;
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		client.credential(credential);
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			relay(client, fd);
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// s_server с -CAfile объявляет владельца файла центров приемлемым издателем
		ASSERT_EQ(client.authorities().size(), static_cast <size_t> (1));
		EXPECT_EQ(client.authorities()[0], owner);
		::close(fd);
		sentinel.halt();
		std::string journal;
		(void) settle(log, journal);
		::remove(log.c_str());
	}
	{
		uint16_t number = 0;
		const int listener = harbour(number);
		ASSERT_GE(listener, 0);
		const std::string log = "/tmp/ants-authorities-client-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -cert " + crt + " -key " + key + " -CAfile " + crt + " -servername localhost </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0);
		server::context_t server;
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		server.credential(credential);
		server.request(true);
		server.authorities(vector <vector <uint8_t>> {owner});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		const bool complete = serve(server, fd);
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
		ASSERT_EQ(server.error(), context::error_t::NONE);
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		ASSERT_TRUE(farewell(server, fd));
		::close(fd);
		::close(listener);
		std::string text;
		ASSERT_TRUE(settle(log, text)) << text;
		// s_client печатает перечень приемлемых центров из запроса подлинности
		EXPECT_NE(text.find("Acceptable client certificate CA names"), std::string::npos) << text;
		EXPECT_EQ(text.find("No client certificate CA names sent"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь с перечнем центров либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(AuthoritiesTest, Starved){
	context::credential_t mine, theirs;
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("ec384", theirs));
	const vector <uint8_t> root = subject("ca-ec");
	ASSERT_FALSE(root.empty());
	bool starved = false;
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		client::context_t client;
		server::context_t server;
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> {root});
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
			ASSERT_EQ(client.authorities().size(), static_cast <size_t> (1));
			EXPECT_EQ(client.authorities()[0], root);
		}
	}
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
