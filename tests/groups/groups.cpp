/**
 * @file groups.cpp
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
 * @brief Проверки групп обмена, прежде отложенных: X448, secp521r1, secp256k1 и конечное
 *        поле RFC 7919 (ffdhe2048 … ffdhe8192) - записи долей, рукопожатия обоих изданий,
 *        правила издания, подпись ECDSA на P-521 и сличение с системным openssl обеими ролями
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
#include <cstring>
#include <cstdlib>
#include <posix.hpp>
#include <sys/stat.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

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
	 * @brief Описание проверяемой группы
	 *
	 */
	typedef struct Entry {
		// Группа
		extension::group_t group;
		// Имя у openssl
		const char * name;
		// Длина доли ключа
		size_t length;
		// Признак несжатой точки 0x04 впереди доли
		bool uncompressed;
	} entry_t;
	/**
	 * Группы издания 1.3
	 */
	static const entry_t MODERN[] = {
		{extension::group_t::X448,      "x448",      56,   false},
		{extension::group_t::SECP521R1, "secp521r1", 133,  true},
		{extension::group_t::FFDHE2048, "ffdhe2048", 256,  false},
		{extension::group_t::FFDHE3072, "ffdhe3072", 384,  false},
		{extension::group_t::FFDHE4096, "ffdhe4096", 512,  false},
		{extension::group_t::FFDHE6144, "ffdhe6144", 768,  false},
		{extension::group_t::FFDHE8192, "ffdhe8192", 1024, false}
	};
	/**
	 * Группы издания 1.2
	 */
	static const entry_t LEGACY[] = {
		{extension::group_t::X448,      "x448",      56,  false},
		{extension::group_t::SECP521R1, "secp521r1", 133, true},
		{extension::group_t::SECP256K1, "secp256k1", 65,  true}
	};
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое либо пустой перечень
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		if(!file.is_open())
			return vector <uint8_t> ();
		return vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	}
	/**
	 * @brief Метод чтения подлинности из набора: ключ PEM и цепочка сертификатов
	 *
	 * @param name   имя подлинности в наборе
	 * @param result подлинность
	 * @return       признак успешности чтения
	 *
	 */
	static bool identity(const char * name, context::credential_t & result) noexcept {
		result.secret = corpus((std::string(name) + ".pem").c_str());
		const vector <uint8_t> chain = corpus((std::string(name) + ".crt").c_str());
		if(result.secret.empty() || chain.empty())
			return false;
		return (pem::certificates(string(chain.begin(), chain.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		bool moved = false;
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
		} catch(...) {
			return false;
		}
		return moved;
	}
	/**
	 * @brief Метод проведения связи до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Метод получения перечня долей приветствия клиента без их изъятия
	 *
	 * @param client связь стороны клиента
	 * @param result доли расширения key_share: группа и ключ своей копией (просмотры в разобранный профиль пережили бы его)
	 * @return       признак успешности разбора приветствия
	 *
	 */
	static bool offered(client::context_t & client, vector <pair <extension::group_t, vector <uint8_t>>> & result) noexcept {
		fingerprint::profile_t profile;
		if(fingerprint::parse(client.output(), profile) != fingerprint::error_t::NONE)
			return false;
		result.clear();
		for(size_t i = 0; i < profile.extensions.size(); i++){
			if(profile.extensions[i].type == 0x0033){
				for(size_t j = 0; j < profile.extensions[i].shares.size(); j++)
					result.push_back(make_pair(static_cast <extension::group_t> (profile.extensions[i].shares[j].group), profile.extensions[i].shares[j].key));
			}
		}
		return true;
	}
	/**
	 * @brief Метод проверки обмена прикладными данными по установленной связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что данные дошли в обе стороны
	 *
	 */
	static bool exchanged(client::context_t & client, server::context_t & server) noexcept {
		const string request = "Запрос по отложенной группе", reply = "Ответ по отложенной группе";
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		vector <uint8_t> received;
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			return false;
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (reply.data()), reply.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		received.clear();
		return ((client.read(received) == context::error_t::NONE) && (string(received.begin(), received.end()) == reply));
	}
	/**
	 * @brief Метод проверки поддержки группы у системного openssl
	 *
	 * @param name имя группы
	 * @return     признак поддержки
	 *
	 */
	static bool groupable(const char * name, const bool legacy, const std::string & crt, const std::string & key) noexcept {
		// Признак по делу, а не по подкоманде list: openssl договаривается с собой по этой группе (у 3.0 list -tls-groups нет вовсе)
		const toolkit_t toolkit = inspect();
		const uint16_t number = vacant(false);
		if(number == 0)
			return false;
		const std::string base = "/tmp/ants-groups-self-" + std::to_string(number);
		const std::string holder = base + ".fifo", log = base + ".server.log", out = base + ".client.log";
		::remove(holder.c_str());
		if(fifo(holder.c_str()) != 0)
			return false;
		const std::string edition = (legacy ? "-tls1_2" : "-tls1_3");
		const bool started = launch("openssl s_server" + accepting(toolkit, number) + " " + edition + " -cert " + crt + " -key " + key + " -groups " + name + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder);
		bool agreed = false;
		if(started){
			sentinel_t sentinel(log + ".pid");
			std::string text;
			if(awaited(log, "ACCEPT", text)){
				(void) shell("(printf 'Q\n' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " " + edition + " -groups " + name + " -CAfile " + crt + " -servername localhost >" + out + " 2>&1 &); sleep 3; pkill -f 'openssl s_client -connect 127.0.0.1:" + std::to_string(number) + "' >/dev/null 2>&1; true");
				std::ifstream file(out);
				std::string line;
				while(std::getline(file, line))
					agreed = (agreed || (line.find("Verify return code: 0 (ok)") != std::string::npos));
			}
			sentinel.halt();
		}
		::remove(holder.c_str());
		::remove(log.c_str());
		::remove(out.c_str());
		return agreed;
	}
	/**
	 * @brief Метод рукопожатия своего клиента против openssl s_server
	 *
	 * @param arguments доводы s_server
	 * @param groups    группы клиента
	 * @param shares    доли клиента
	 * @param legacy    признак издания 1.2
	 * @param schemes   схемы подписи клиента либо пусто
	 * @param authority файл сертификата сервера
	 * @param expected  ожидаемая группа
	 * @param log       журнал сервера
	 * @return          признак установленной связи с обменом
	 *
	 */
	static bool against(const std::string & arguments, const vector <extension::group_t> & groups, const vector <extension::group_t> & shares, const bool legacy, const vector <extension::scheme_t> & schemes, const extension::group_t expected, std::string & journal) noexcept {
		const toolkit_t toolkit = inspect();
		const uint16_t number = vacant(false);
		if(number == 0)
			return false;
		const std::string log = "/tmp/ants-groups-server-" + std::to_string(number) + ".log";
		if(!launch("openssl s_server" + accepting(toolkit, number) + " " + arguments + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"))
			return false;
		sentinel_t sentinel(log + ".pid");
		const int fd = dial(number);
		if(fd < 0)
			return false;
		client::context_t client;
		client.groups(groups);
		if(!shares.empty())
			client.shares(shares);
		if(!schemes.empty())
			client.schemes(schemes);
		if(legacy)
			client.versions(0x0303, 0x0303);
		client.name("localhost");
		bool ok = (client.start() == context::error_t::NONE);
		for(size_t i = 0; ok && (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			relay(client, fd);
		ok = (ok && client.established() && (client.group() == expected));
		if(ok){
			const string request = "GET / HTTP/1.0\r\n\r\n";
			ok = (client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) == context::error_t::NONE);
			vector <uint8_t> answer;
			for(size_t i = 0; ok && (i < 16) && answer.empty(); i++){
				relay(client, fd);
				ok = (client.read(answer) == context::error_t::NONE);
			}
			ok = (ok && (string(answer.begin(), answer.end()).find("HTTP/1.0 200") != string::npos));
		}
		if(!ok)
			journal = "отказ " + std::to_string(static_cast <int> (client.error())) + " извещение " + std::to_string(static_cast <int> (client.alert().description)) + " группа " + std::to_string(static_cast <int> (client.group()));
		closing(fd);
		sentinel.halt();
		std::string text;
		(void) settle(log, text);
		journal += "\n" + text;
		::remove(log.c_str());
		return ok;
	}
	/**
	 * @brief Метод рукопожатия openssl s_client против своего сервера
	 *
	 * @param arguments  доводы s_client
	 * @param groups     группы сервера
	 * @param credential подлинность сервера
	 * @param legacy     признак издания 1.2
	 * @param expected   ожидаемая группа
	 * @param journal    журнал клиента
	 * @return           признак установленной связи
	 *
	 */
	static bool served(const std::string & arguments, const vector <extension::group_t> & groups, const context::credential_t & credential, const bool legacy, const extension::group_t expected, std::string & journal) noexcept {
		uint16_t number = 0;
		const int listener = harbour(number);
		if(listener < 0)
			return false;
		const std::string log = "/tmp/ants-groups-client-" + std::to_string(number) + ".log";
		const std::string holder = "/tmp/ants-groups-client-" + std::to_string(number) + ".fifo";
		::remove(holder.c_str());
		if(fifo(holder.c_str()) != 0)
			return false;
		if(!launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " " + arguments + " -servername localhost -verify_return_error <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder))
			return false;
		sentinel_t sentinel(log + ".pid");
		const int fd = greeted(listener);
		if(fd < 0)
			return false;
		server::context_t server;
		server.groups(groups);
		server.credential(credential);
		if(legacy)
			server.versions(0x0303, 0x0303);
		bool ok = (server.start() == context::error_t::NONE);
		ok = (ok && serve(server, fd) && server.established() && (server.group() == expected));
		if(!ok)
			journal = "отказ " + std::to_string(static_cast <int> (server.error())) + " группа " + std::to_string(static_cast <int> (server.group()));
		(void) farewell(server, fd);
		closing(fd);
		closing(listener);
		std::string text;
		(void) settle(log, text);
		journal += "\n" + text;
		::remove(log.c_str());
		::remove(holder.c_str());
		return (ok && (text.find("Verify return code: 0 (ok)") != std::string::npos));
	}
};

/**
 * Записи долей: длина по группе, несжатая точка у кривых NIST, ключ длиной в модуль у конечного поля
 */
TEST(GroupsTest, Shares){
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		client::context_t client;
		client.groups(vector <extension::group_t> {MODERN[i].group});
		client.shares(vector <extension::group_t> {MODERN[i].group});
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE) << MODERN[i].name;
		vector <pair <extension::group_t, vector <uint8_t>>> shares;
		ASSERT_TRUE(offered(client, shares)) << MODERN[i].name;
		ASSERT_EQ(shares.size(), static_cast <size_t> (1)) << MODERN[i].name;
		EXPECT_EQ(shares[0].first, MODERN[i].group) << MODERN[i].name;
		EXPECT_EQ(shares[0].second.size(), MODERN[i].length) << MODERN[i].name;
		EXPECT_EQ(extension::length(MODERN[i].group), MODERN[i].length) << MODERN[i].name;
		if(MODERN[i].uncompressed)
			EXPECT_EQ(shares[0].second[0], 0x04) << MODERN[i].name << " байты " << static_cast <int> (shares[0].second[0]) << " " << static_cast <int> (shares[0].second[1]) << " " << static_cast <int> (shares[0].second[2]) << " длина " << shares[0].second.size() << " хвост " << static_cast <int> (shares[0].second[shares[0].second.size() - 2]) << " " << static_cast <int> (shares[0].second[shares[0].second.size() - 1]);
	}
	EXPECT_EQ(extension::length(extension::group_t::SECP256K1), static_cast <size_t> (65));
	EXPECT_EQ(extension::finite(extension::group_t::FFDHE2048), static_cast <size_t> (256));
	EXPECT_EQ(extension::finite(extension::group_t::X448), static_cast <size_t> (0));
	EXPECT_STREQ(extension::curve(extension::group_t::SECP521R1), "1.3.132.0.35");
	EXPECT_STREQ(extension::curve(extension::group_t::SECP256K1), "1.3.132.0.10");
	EXPECT_STREQ(extension::curve(extension::group_t::X448), "1.3.101.111");
	EXPECT_EQ(extension::hash(extension::scheme_t::ECDSA_SECP521R1_SHA512), digest::hash_t::SHA512);
}

/**
 * Рукопожатие 1.3 по каждой из семи групп своими сторонами с обменом данными
 */
TEST(GroupsTest, Modern){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519});
		client.shares(vector <extension::group_t> {MODERN[i].group});
		client.name("localhost");
		server.groups(vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << MODERN[i].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.group(), MODERN[i].group) << MODERN[i].name;
		EXPECT_EQ(server.group(), MODERN[i].group) << MODERN[i].name;
		EXPECT_TRUE(exchanged(client, server)) << MODERN[i].name;
	}
}

/**
 * Рукопожатие 1.2 по X448, secp521r1 и secp256k1 своими сторонами: ECDHE в ServerKeyExchange
 */
TEST(GroupsTest, Legacy){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	for(size_t i = 0; i < (sizeof(LEGACY) / sizeof(LEGACY[0])); i++){
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519});
		client.name("localhost");
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		server.groups(vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << LEGACY[i].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.group(), LEGACY[i].group) << LEGACY[i].name;
		EXPECT_EQ(server.group(), LEGACY[i].group) << LEGACY[i].name;
		EXPECT_TRUE(exchanged(client, server)) << LEGACY[i].name;
	}
}

/**
 * Правила издания: secp256k1 изданием 1.3 сервер не выбирает даже с долей клиента, конечное
 * поле изданием 1.2 не выбирает без наборов DHE - связь идёт по следующей группе
 */
TEST(GroupsTest, Editions){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		client.shares(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		client.name("localhost");
		server.groups(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		vector <pair <extension::group_t, vector <uint8_t>>> shares;
		ASSERT_TRUE(offered(client, shares));
		ASSERT_EQ(shares.size(), static_cast <size_t> (2));
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(server.group(), extension::group_t::X25519);
		EXPECT_EQ(client.group(), extension::group_t::X25519);
	}
	{
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::FFDHE2048, extension::group_t::SECP256R1});
		client.name("localhost");
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		server.groups(vector <extension::group_t> {extension::group_t::FFDHE2048, extension::group_t::SECP256R1});
		server.credential(credential);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(server.group(), extension::group_t::SECP256R1);
		EXPECT_EQ(client.group(), extension::group_t::SECP256R1);
	}
	{
		// Сервер только с secp256k1 изданием 1.3: общей группы нет, рукопожатие отвергается
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::SECP256K1});
		client.shares(vector <extension::group_t> {extension::group_t::SECP256K1});
		client.name("localhost");
		server.groups(vector <extension::group_t> {extension::group_t::SECP256K1});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		EXPECT_FALSE(server.established());
		EXPECT_FALSE(client.established());
	}
}

/**
 * Подпись ECDSA на P-521 с SHA-512 (0x0603): подлинность ec521 в обоих изданиях
 */
TEST(GroupsTest, Ecdsa521){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec521", credential));
	for(size_t legacy = 0; legacy < 2; legacy++){
		client::context_t client;
		server::context_t server;
		client.name("localhost");
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		server.credential(credential);
		server.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		if(legacy == 1){
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
			ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
			client.groups(vector <extension::group_t> {extension::group_t::SECP521R1});
			server.groups(vector <extension::group_t> {extension::group_t::SECP521R1});
		}
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << legacy << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (client.alert().description);
		EXPECT_TRUE(exchanged(client, server)) << legacy;
	}
	// Схема 0x0603 не годится ключу P-256: сервер с ec256 при единственной схеме клиента отвергает рукопожатие
	{
		context::credential_t other;
		ASSERT_TRUE(identity("ec256", other));
		client::context_t client;
		server::context_t server;
		client.name("localhost");
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		server.credential(other);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		EXPECT_FALSE(client.established());
	}
}

/**
 * Сличение с openssl изданием 1.3: свой клиент против s_server и s_client против своего сервера по каждой группе
 */
TEST(GroupsTest, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present || !toolkit.tls13 || !toolkit.serverGroups || !toolkit.clientGroups){
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -groups";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		if(!groupable(MODERN[i].name, false, crt, key)){
			std::cerr << "[ SKIP     ] openssl не ведёт группу " << MODERN[i].name << " сам с собой: пропуск вслух" << std::endl;
			continue;
		}
		std::string journal;
		if(!against("-tls1_3 -cert " + crt + " -key " + key + " -groups " + MODERN[i].name, vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519}, vector <extension::group_t> {MODERN[i].group}, false, vector <extension::scheme_t> (), MODERN[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				std::cerr << "[ SKIP     ] openssl s_server не принял группу " << MODERN[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << MODERN[i].name << " " << journal;
		}
		journal.clear();
		if(!served("-tls1_3 -CAfile " + crt + " -groups " + std::string(MODERN[i].name) + ":X25519", vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519}, credential, false, MODERN[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				std::cerr << "[ SKIP     ] openssl s_client не принял группы " << MODERN[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << MODERN[i].name << " " << journal;
		}
	}
}

/**
 * Сличение с openssl изданием 1.2: X448, secp521r1 и secp256k1 в ServerKeyExchange обеими ролями
 */
TEST(GroupsTest, OpensslLegacy){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present || !toolkit.tls12 || !toolkit.serverGroups || !toolkit.clientGroups){
		GTEST_SKIP() << "openssl без TLS 1.2 либо без -groups";
	}
	// Связь 1.2 без extended_master_secret отвергается намеренно (принятое решение): LibreSSL его не ведёт
	if(!toolkit.master){
		GTEST_SKIP() << "openssl без extended_master_secret (LibreSSL): связь 1.2 без него не ведётся намеренно";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	for(size_t i = 0; i < (sizeof(LEGACY) / sizeof(LEGACY[0])); i++){
		if(!groupable(LEGACY[i].name, true, crt, key)){
			std::cerr << "[ SKIP     ] openssl не ведёт группу " << LEGACY[i].name << " изданием 1.2 сам с собой: пропуск вслух" << std::endl;
			continue;
		}
		std::string journal;
		// Изданию 1.2 openssl требует кривую сертификата ECDSA (P-256) в перечне групп собеседника, иначе «no shared cipher»
		if(!against("-tls1_2 -cert " + crt + " -key " + key + " -groups " + LEGACY[i].name, vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519, extension::group_t::SECP256R1}, vector <extension::group_t> (), true, vector <extension::scheme_t> (), LEGACY[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				std::cerr << "[ SKIP     ] openssl s_server не принял группу " << LEGACY[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << LEGACY[i].name << " " << journal;
		}
		// Имя prime256v1: LibreSSL не знает псевдонима secp256r1
		journal.clear();
		if(!served("-tls1_2 -CAfile " + crt + " -groups " + std::string(LEGACY[i].name) + ":X25519:prime256v1", vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519, extension::group_t::SECP256R1}, credential, true, LEGACY[i].group, journal)){
			// Если инструмент отказал на своих доводах - пропуск вслух, иначе отказ
			if(journal.find("Failed to set") != std::string::npos)
				std::cerr << "[ SKIP     ] openssl s_client не принял группы " << LEGACY[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << LEGACY[i].name << " " << journal;
		}
	}
}

/**
 * Сличение подписи ECDSA P-521 с openssl: s_server с ec521 и s_client с -sigalgs ECDSA+SHA512
 */
TEST(GroupsTest, OpensslEcdsa521){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present || !toolkit.tls13 || !listed("s_server", "sigalgs") || !listed("s_client", "sigalgs")){
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -sigalgs";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec521", credential));
	const std::string crt = std::string(CORPUS) + "/ec521.crt", key = std::string(CORPUS) + "/ec521.pem";
	std::string journal;
	if(!against("-tls1_3 -cert " + crt + " -key " + key + " -sigalgs ECDSA+SHA512", vector <extension::group_t> {extension::group_t::X25519}, vector <extension::group_t> {extension::group_t::X25519}, false, vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512}, extension::group_t::X25519, journal)){
		if(journal.find("Failed to set") != std::string::npos)
			std::cerr << "[ SKIP     ] openssl s_server не принял -sigalgs: пропуск вслух" << std::endl;
		else
			ADD_FAILURE() << journal;
	}
	journal.clear();
	if(!served("-tls1_3 -CAfile " + crt + " -sigalgs ECDSA+SHA512", vector <extension::group_t> {extension::group_t::X25519}, credential, false, extension::group_t::X25519, journal)){
		if(journal.find("Failed to set") != std::string::npos)
			std::cerr << "[ SKIP     ] openssl s_client не принял -sigalgs: пропуск вслух" << std::endl;
		else
			ADD_FAILURE() << journal;
	} else
		EXPECT_NE(journal.find("Peer signing digest: SHA512"), std::string::npos) << journal;
}
