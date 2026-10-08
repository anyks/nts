/**
 * @file hybrid.cpp
 * @date 2026-09-07
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
 * @brief Проверки гибридной группы X25519MLKEM768 (0x11EC) в рукопожатии TLS 1.3
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <extension/extension.hpp>
#include <agreement/mlkem.hpp>
#include <agreement/x25519.hpp>
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
	 * Длина доли клиента гибридной группы
	 */
	static const size_t OFFER = (agreement::encapsulation(agreement::kem_t::MLKEM768) + agreement::X25519_SIZE);
	/**
	 * Длина доли сервера гибридной группы
	 */
	static const size_t ANSWER = (agreement::ciphertext(agreement::kem_t::MLKEM768) + agreement::X25519_SIZE);
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
		// Признак передачи
		bool moved = false;
		try {
			// Байты клиента
			view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
			// Байты сервера
			data = server.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		} catch(const bad_alloc &) {
			return false;
		}
		return moved;
	}
	/**
	 * @brief Метод передачи байтов клиента серверу без ответа
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool forth(client::context_t & client, server::context_t & server) noexcept {
		const view_t data = client.output();
		if(data.size == 0)
			return false;
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		client.consume(buffer.size());
		server.push(view_t(buffer.data(), buffer.size()));
		return true;
	}
	/**
	 * @brief Метод передачи байтов сервера клиенту без ответа
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool back(client::context_t & client, server::context_t & server) noexcept {
		const view_t data = server.output();
		if(data.size == 0)
			return false;
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		server.consume(buffer.size());
		client.push(view_t(buffer.data(), buffer.size()));
		return true;
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
	 * @brief Метод снятия приветствия клиента с отправляемых байтов без их изъятия
	 *
	 * @param client связь стороны клиента
	 * @param result профиль приветствия
	 * @return       признак успешности
	 *
	 */
	static bool captured(client::context_t & client, fingerprint::profile_t & result) noexcept {
		return (fingerprint::parse(client.output(), result) == fingerprint::error_t::NONE);
	}
	/**
	 * @brief Метод получения перечня долей приветствия
	 *
	 * @param profile профиль приветствия
	 * @return        доли расширения key_share либо пустой перечень
	 *
	 */
	static vector <extension::share_t> offersof(const fingerprint::profile_t & profile) noexcept {
		for(size_t i = 0; i < profile.extensions.size(); i++){
			if(profile.extensions[i].type == 0x0033){
				vector <extension::share_t> result;
				for(size_t j = 0; j < profile.extensions[i].shares.size(); j++)
					result.push_back(extension::share_t(static_cast <extension::group_t> (profile.extensions[i].shares[j].group), view_t(profile.extensions[i].shares[j].key.data(), profile.extensions[i].shares[j].key.size())));
				return result;
			}
		}
		return vector <extension::share_t> ();
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
		const string request = "Запрос по гибридной группе", reply = "Ответ по гибридной группе";
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
	 * @brief Метод получения пути к bssl
	 *
	 * @return путь либо пустая строка
	 *
	 */
	static std::string bssltool() noexcept {
		const char * given = ::getenv("ANTS_BSSL");
		if((given != nullptr) && (::access(given, X_OK) == 0))
			return std::string(given);
		if(shell("command -v bssl >/dev/null 2>&1") == 0)
			return std::string("bssl");
		return std::string();
	}
	/**
	 * @brief Метод проверки поддержки группы у openssl
	 *
	 * @return признак того, что openssl знает X25519MLKEM768
	 *
	 */
	static bool kemready() noexcept {
		return (shell("(openssl list -tls-groups 2>/dev/null | tr ':' '\\n' | grep -qw X25519MLKEM768) >/dev/null 2>&1") == 0);
	}
	/**
	 * @brief Метод составления приветствия по образцу Chrome с долей гибридной группы
	 *
	 * @param body тело приветствия
	 * @return     признак успешности
	 *
	 */
	static bool chromehello(vector <uint8_t> & body) {
		hello::client_t greeting;
		greeting.version = 0x0303;
		for(size_t i = 0; i < 32; i++) greeting.random[i] = static_cast <uint8_t> (i * 7 + 1);
		greeting.session.assign(32, 0x5A);
		const uint16_t suites[] = {0x2A2A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x009D, 0x002F, 0x0035};
		for(size_t i = 0; i < (sizeof(suites) / sizeof(suites[0])); i++)
			greeting.suites.push_back(suites[i]);
		greeting.methods.push_back(0);
		static vector <uint8_t> name, share, groups, versions, schemes, modes, formats, protocols, padding;
		name.clear(); share.clear(); groups.clear(); versions.clear(); schemes.clear(); modes.clear(); formats.clear(); protocols.clear(); padding.clear();
		static const uint8_t STUB[1] = {0x00};
		static vector <uint8_t> kemkey, curvekey;
		kemkey.assign(OFFER, 0x00);
		curvekey.assign(32, 0x00);
		for(size_t i = 0; i < kemkey.size(); i++) kemkey[i] = static_cast <uint8_t> (i * 3 + 11);
		for(size_t i = 0; i < curvekey.size(); i++) curvekey[i] = static_cast <uint8_t> (i + 100);
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> ("example.com"), 11), name) != extension::error_t::NONE) return false;
		if(extension::shares(vector <extension::share_t> {extension::share_t(static_cast <extension::group_t> (0x2A2A), view_t(STUB, 1)), extension::share_t(extension::group_t::X25519MLKEM768, view_t(kemkey.data(), kemkey.size())), extension::share_t(extension::group_t::X25519, view_t(curvekey.data(), curvekey.size()))}, share) != extension::error_t::NONE) return false;
		if(extension::groups(vector <extension::group_t> {static_cast <extension::group_t> (0x2A2A), extension::group_t::X25519MLKEM768, extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1}, groups) != extension::error_t::NONE) return false;
		if(extension::versions(vector <uint16_t> {0x2A2A, 0x0304, 0x0303}, versions) != extension::error_t::NONE) return false;
		if(extension::schemes(vector <extension::scheme_t> {static_cast <extension::scheme_t> (0x0403), static_cast <extension::scheme_t> (0x0804), static_cast <extension::scheme_t> (0x0401), static_cast <extension::scheme_t> (0x0503), static_cast <extension::scheme_t> (0x0805), static_cast <extension::scheme_t> (0x0501), static_cast <extension::scheme_t> (0x0806), static_cast <extension::scheme_t> (0x0601)}, schemes) != extension::error_t::NONE) return false;
		if(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes) != extension::error_t::NONE) return false;
		if(extension::formats(vector <uint8_t> {0x00}, formats) != extension::error_t::NONE) return false;
		if(extension::protocols(vector <string> {"h2", "http/1.1"}, protocols) != extension::error_t::NONE) return false;
		padding.assign(100, 0x00);
		greeting.extensions.push_back(hello::extension_t(0x2A2A, view_t(nullptr, 0)));
		greeting.extensions.push_back(hello::extension_t(0x0000, view_t(name.data(), name.size())));
		greeting.extensions.push_back(hello::extension_t(0x0033, view_t(share.data(), share.size())));
		greeting.extensions.push_back(hello::extension_t(0x0010, view_t(protocols.data(), protocols.size())));
		greeting.extensions.push_back(hello::extension_t(0x0017, view_t(nullptr, 0)));
		greeting.extensions.push_back(hello::extension_t(0x002D, view_t(modes.data(), modes.size())));
		greeting.extensions.push_back(hello::extension_t(0x000D, view_t(schemes.data(), schemes.size())));
		greeting.extensions.push_back(hello::extension_t(0x002B, view_t(versions.data(), versions.size())));
		greeting.extensions.push_back(hello::extension_t(0x000B, view_t(formats.data(), formats.size())));
		greeting.extensions.push_back(hello::extension_t(0x000A, view_t(groups.data(), groups.size())));
		greeting.extensions.push_back(hello::extension_t(0x3A3A, view_t(STUB, 1)));
		greeting.extensions.push_back(hello::extension_t(0x0015, view_t(padding.data(), padding.size())));
		return (hello::build(greeting, body) == hello::error_t::NONE);
	}
	/**
	 * @brief Метод обёртывания тела приветствия записью TLS
	 *
	 * @param body тело приветствия
	 * @return     запись
	 *
	 */
	static vector <uint8_t> wrapped(const vector <uint8_t> & body) {
		vector <uint8_t> result;
		const size_t message = (body.size() + 4);
		result.push_back(0x16);
		result.push_back(0x03); result.push_back(0x01);
		result.push_back(static_cast <uint8_t> (message >> 8)); result.push_back(static_cast <uint8_t> (message));
		result.push_back(0x01);
		result.push_back(static_cast <uint8_t> (body.size() >> 16)); result.push_back(static_cast <uint8_t> (body.size() >> 8)); result.push_back(static_cast <uint8_t> (body.size()));
		result.insert(result.end(), body.begin(), body.end());
		return result;
	}
}

/**
 * Петля: клиент с долей гибридной группы, сервер её выбирает; доли сторон по длине
 */
TEST(HybridTest, Loopback){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
	client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
	client.name("localhost");
	server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	fingerprint::profile_t offer;
	ASSERT_TRUE(captured(client, offer));
	const vector <extension::share_t> offered = offersof(offer);
	ASSERT_EQ(offered.size(), static_cast <size_t> (1));
	EXPECT_EQ(offered[0].group, extension::group_t::X25519MLKEM768);
	EXPECT_EQ(offered[0].key.size, OFFER);
	// Ключ инкапсуляции в доле годен
	EXPECT_TRUE(agreement::validate(agreement::kem_t::MLKEM768, view_t(offered[0].key.data, agreement::encapsulation(agreement::kem_t::MLKEM768))));
	// Первая передача: приветствие уходит серверу
	ASSERT_TRUE(forth(client, server));
	// Ответ сервера: доля сервера длиной шифртекста и точки
	const view_t answer = server.output();
	ASSERT_GT(answer.size, ANSWER);
	{
		// Разыскиваем группу 0x11EC с длиной доли сервера в приветствии сервера
		bool found = false;
		for(size_t i = 0; (i + 4) <= answer.size; i++){
			if((answer.data[i] == 0x11) && (answer.data[i + 1] == 0xEC) && (answer.data[i + 2] == static_cast <uint8_t> (ANSWER >> 8)) && (answer.data[i + 3] == static_cast <uint8_t> (ANSWER)))
				found = true;
		}
		EXPECT_TRUE(found);
	}
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Согласованная группа у обеих сторон - гибрид
	EXPECT_EQ(client.group(), extension::group_t::X25519MLKEM768);
	EXPECT_EQ(server.group(), extension::group_t::X25519MLKEM768);
	EXPECT_TRUE(exchanged(client, server));
}

/**
 * Просьба о повторе: клиент шлёт долю X25519, сервер ведёт лишь гибрид; повторное
 * приветствие несёт одну долю гибрида. Сервер без гибрида берёт X25519 у клиента с обеими
 */
TEST(HybridTest, Retry){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::X25519MLKEM768});
		client.shares(vector <extension::group_t> {extension::group_t::X25519});
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие и просьба о повторе
		ASSERT_TRUE(forth(client, server));
		ASSERT_TRUE(back(client, server));
		// Повторное приветствие клиента
		fingerprint::profile_t again;
		ASSERT_TRUE(captured(client, again));
		const vector <extension::share_t> offered = offersof(again);
		ASSERT_EQ(offered.size(), static_cast <size_t> (1));
		EXPECT_EQ(offered[0].group, extension::group_t::X25519MLKEM768);
		EXPECT_EQ(offered[0].key.size, OFFER);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(exchanged(client, server));
	}
	{
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t offer;
		ASSERT_TRUE(captured(client, offer));
		const vector <extension::share_t> offered = offersof(offer);
		ASSERT_EQ(offered.size(), static_cast <size_t> (2));
		EXPECT_EQ(offered[0].key.size, OFFER);
		EXPECT_EQ(offered[1].key.size, static_cast <size_t> (32));
		// До установления группа не выбрана
		EXPECT_EQ(client.group(), extension::group_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Согласованная группа - X25519
		EXPECT_EQ(client.group(), extension::group_t::X25519);
		EXPECT_EQ(server.group(), extension::group_t::X25519);
		EXPECT_TRUE(exchanged(client, server));
	}
}

/**
 * Профиль по образцу Chrome: доли GREASE, гибрида и X25519 идут порядком снимка свежими
 * ключами записанных длин; связь устанавливается и с сервером гибрида, и с сервером X25519
 */
TEST(HybridTest, Profile){
	vector <uint8_t> body;
	ASSERT_TRUE(chromehello(body));
	const vector <uint8_t> record = wrapped(body);
	fingerprint::profile_t source;
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	const vector <extension::share_t> recorded = offersof(source);
	ASSERT_EQ(recorded.size(), static_cast <size_t> (3));
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	for(size_t round = 0; round < 2; round++){
		client::context_t client;
		server::context_t server;
		client.name("example.com");
		ASSERT_EQ(client.profile(source), context::error_t::NONE);
		server.groups(vector <extension::group_t> {(round == 0) ? extension::group_t::X25519MLKEM768 : extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t made;
		ASSERT_TRUE(captured(client, made));
		const vector <extension::share_t> offered = offersof(made);
		string listed;
		for(size_t i = 0; i < offered.size(); i++) listed += (std::to_string(static_cast <uint16_t> (offered[i].group)) + "/" + std::to_string(offered[i].key.size) + " ");
		ASSERT_EQ(offered.size(), static_cast <size_t> (3)) << listed;
		EXPECT_TRUE(fingerprint::grease(static_cast <uint16_t> (offered[0].group)));
		EXPECT_EQ(offered[0].key.size, static_cast <size_t> (1));
		EXPECT_EQ(offered[1].group, extension::group_t::X25519MLKEM768);
		EXPECT_EQ(offered[1].key.size, OFFER);
		EXPECT_EQ(offered[2].group, extension::group_t::X25519);
		EXPECT_EQ(offered[2].key.size, static_cast <size_t> (32));
		// Ключи свежие, не из снимка
		EXPECT_NE(::memcmp(offered[1].key.data, recorded[1].key.data, OFFER), 0);
		EXPECT_NE(::memcmp(offered[2].key.data, recorded[2].key.data, 32), 0);
		EXPECT_TRUE(agreement::validate(agreement::kem_t::MLKEM768, view_t(offered[1].key.data, agreement::encapsulation(agreement::kem_t::MLKEM768))));
		// Порядок групп снимка сохранён
		bool grouped = false;
		for(size_t i = 0; i < made.extensions.size(); i++){
			if(made.extensions[i].type == 0x000A){
				ASSERT_EQ(made.extensions[i].groups.size(), static_cast <size_t> (5));
				EXPECT_EQ(made.extensions[i].groups[1], extension::group_t::X25519MLKEM768);
				EXPECT_EQ(made.extensions[i].groups[2], extension::group_t::X25519);
				grouped = true;
			}
		}
		EXPECT_TRUE(grouped);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << "круг " << round << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		EXPECT_TRUE(exchanged(client, server));
	}
}

/**
 * Голодание: связь по гибридной группе при ограниченном запасе выделений отвечает лишь
 * NONE либо MEMORY, не падает и при достаточном запасе устанавливается
 */
/**
 * Проверка гибридов NIST по RFC 10024: SecP256r1MLKEM768 (0x11EB, доля 65 + 1184,
 * ответ 65 + 1088) и SecP384r1MLKEM1024 (0x11ED, доля 97 + 1568, ответ 97 + 1568), кривая впереди;
 * связь, согласованная группа, данные; повтор приветствия с долей X25519
 */
TEST(HybridTest, Nist){
	// Группы, длины долей и ответов
	static const extension::group_t GROUPS[] = {extension::group_t::SECP256R1MLKEM768, extension::group_t::SECP384R1MLKEM1024};
	static const size_t OFFERS[] = {65 + 1184, 97 + 1568}, ANSWERS[] = {65 + 1088, 97 + 1568};
	static const uint8_t CODES[][2] = {{0x11, 0xEB}, {0x11, 0xED}};
	/**
	 * Выполняем перебор групп
	 */
	for(size_t i = 0; i < 2; i++){
		context::credential_t credential;
		ASSERT_TRUE(identity("ec256", credential));
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
		client.shares(vector <extension::group_t> {GROUPS[i]});
		client.name("localhost");
		server.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t offer;
		ASSERT_TRUE(captured(client, offer));
		const vector <extension::share_t> offered = offersof(offer);
		ASSERT_EQ(offered.size(), static_cast <size_t> (1)) << i;
		EXPECT_EQ(offered[0].group, GROUPS[i]) << i;
		EXPECT_EQ(offered[0].key.size, OFFERS[i]) << i;
		// Кривая впереди: точка в несжатом виде, за ней ключ инкапсуляции
		EXPECT_EQ(offered[0].key.data[0], 0x04) << i;
		EXPECT_TRUE(agreement::validate(((i == 0) ? agreement::kem_t::MLKEM768 : agreement::kem_t::MLKEM1024), view_t(offered[0].key.data + ((i == 0) ? 65 : 97), OFFERS[i] - ((i == 0) ? 65 : 97)))) << i;
		ASSERT_TRUE(forth(client, server));
		const view_t answer = server.output();
		ASSERT_GT(answer.size, ANSWERS[i]) << i;
		{
			bool found = false;
			for(size_t k = 0; (k + 5) <= answer.size; k++){
				if((answer.data[k] == CODES[i][0]) && (answer.data[k + 1] == CODES[i][1]) && (answer.data[k + 2] == static_cast <uint8_t> (ANSWERS[i] >> 8)) && (answer.data[k + 3] == static_cast <uint8_t> (ANSWERS[i] & 0xFF)) && (answer.data[k + 4] == 0x04))
					found = true;
			}
			EXPECT_TRUE(found) << i;
		}
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << i << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.group(), GROUPS[i]) << i;
		EXPECT_EQ(server.group(), GROUPS[i]) << i;
		EXPECT_TRUE(exchanged(client, server)) << i;
	}
	// Длины долей клиента у открытого API совпадают с проводом
	EXPECT_EQ(extension::length(extension::group_t::SECP256R1MLKEM768), OFFERS[0]);
	EXPECT_EQ(extension::length(extension::group_t::SECP384R1MLKEM1024), OFFERS[1]);
	EXPECT_EQ(extension::length(extension::group_t::X25519MLKEM768), OFFER);
	// Повтор приветствия: доля X25519, сервер лишь с SecP256r1MLKEM768
	{
		context::credential_t credential;
		ASSERT_TRUE(identity("ec256", credential));
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1MLKEM768});
		client.shares(vector <extension::group_t> {extension::group_t::X25519});
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		ASSERT_TRUE(forth(client, server));
		ASSERT_TRUE(back(client, server));
		fingerprint::profile_t again;
		ASSERT_TRUE(captured(client, again));
		const vector <extension::share_t> offered = offersof(again);
		ASSERT_EQ(offered.size(), static_cast <size_t> (1));
		EXPECT_EQ(offered[0].group, extension::group_t::SECP256R1MLKEM768);
		EXPECT_EQ(offered[0].key.size, OFFERS[0]);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.group(), extension::group_t::SECP256R1MLKEM768);
		EXPECT_TRUE(exchanged(client, server));
	}
}

/**
 * Проверка стражи длины доли гибрида NIST у сервера: приветствие с долей 0x11EB короче положенного
 * (100 байтов) и с долей длиннее (1250) отвергается, связь не устанавливается
 */
TEST(HybridTest, NistMalformed){
	static const size_t SIZES[] = {100, 1250};
	/**
	 * Выполняем перебор длин
	 */
	for(size_t i = 0; i < 2; i++){
		context::credential_t credential;
		ASSERT_TRUE(identity("ec256", credential));
		// Приветствие с одной долей негодной длины
		hello::client_t greeting;
		greeting.version = 0x0303;
		for(size_t k = 0; k < 32; k++) greeting.random[k] = static_cast <uint8_t> (k * 5 + 3);
		greeting.suites.push_back(0x1301);
		greeting.methods.push_back(0);
		vector <uint8_t> name, share, groups, versions, schemes, modes;
		vector <uint8_t> key(SIZES[i], 0x00);
		key[0] = 0x04;
		for(size_t k = 1; k < key.size(); k++) key[k] = static_cast <uint8_t> (k * 7 + 1);
		ASSERT_EQ(extension::name(view_t(reinterpret_cast <const uint8_t *> ("localhost"), 9), name), extension::error_t::NONE);
		ASSERT_EQ(extension::shares(vector <extension::share_t> {extension::share_t(extension::group_t::SECP256R1MLKEM768, view_t(key.data(), key.size()))}, share), extension::error_t::NONE);
		ASSERT_EQ(extension::groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768, extension::group_t::X25519}, groups), extension::error_t::NONE);
		ASSERT_EQ(extension::versions(vector <uint16_t> {0x0304}, versions), extension::error_t::NONE);
		ASSERT_EQ(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes), extension::error_t::NONE);
		ASSERT_EQ(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes), extension::error_t::NONE);
		greeting.extensions.push_back(hello::extension_t(0x0000, view_t(name.data(), name.size())));
		greeting.extensions.push_back(hello::extension_t(0x000A, view_t(groups.data(), groups.size())));
		greeting.extensions.push_back(hello::extension_t(0x000D, view_t(schemes.data(), schemes.size())));
		greeting.extensions.push_back(hello::extension_t(0x002B, view_t(versions.data(), versions.size())));
		greeting.extensions.push_back(hello::extension_t(0x002D, view_t(modes.data(), modes.size())));
		greeting.extensions.push_back(hello::extension_t(0x0033, view_t(share.data(), share.size())));
		vector <uint8_t> body;
		ASSERT_EQ(hello::build(greeting, body), hello::error_t::NONE);
		const vector <uint8_t> record = wrapped(body);
		server::context_t server;
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		(void) server.push(view_t(record.data(), record.size()));
		EXPECT_FALSE(server.established()) << SIZES[i];
		EXPECT_EQ(server.state(), context::state_t::FAILED) << SIZES[i] << " " << static_cast <int> (server.error());
	}
}

/**
 * Сличение гибридов NIST с openssl 3.5+: наш клиент против s_server с группой и наш сервер
 * против s_client с группой, обе группы
 */
TEST(HybridTest, NistOpenssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present || !toolkit.tls13 || !listed("s_server", "groups")){
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -groups";
	}
	if(shell("(openssl list -tls-groups 2>/dev/null | tr ':' '\\n' | grep -qw SecP256r1MLKEM768) >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "openssl без SecP256r1MLKEM768 (нужен openssl 3.5+)";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	static const char * NAMES[] = {"SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
	static const extension::group_t GROUPS[] = {extension::group_t::SECP256R1MLKEM768, extension::group_t::SECP384R1MLKEM1024};
	/**
	 * Выполняем перебор групп
	 */
	for(size_t i = 0; i < 2; i++){
		{
			const uint16_t number = vacant(false);
			ASSERT_NE(number, 0);
			const std::string log = "/tmp/ants-nist-server-" + std::to_string(number) + ".log";
			ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -groups " + NAMES[i] + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
			sentinel_t sentinel(log + ".pid");
			const int fd = dial(number);
			ASSERT_GE(fd, 0) << "порт " << number;
			client::context_t client;
			client.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
			client.shares(vector <extension::group_t> {GROUPS[i]});
			client.name("localhost");
			ASSERT_EQ(client.start(), context::error_t::NONE);
			for(size_t k = 0; (k < 8) && !client.established() && (client.state() != context::state_t::FAILED); k++)
				relay(client, fd);
			if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
			ASSERT_TRUE(client.established()) << NAMES[i] << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			EXPECT_EQ(client.group(), GROUPS[i]) << NAMES[i];
			const string request = "GET / HTTP/1.0\r\n\r\n";
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			vector <uint8_t> reply;
			for(size_t k = 0; (k < 16) && reply.empty(); k++){
				relay(client, fd);
				ASSERT_EQ(client.read(reply), context::error_t::NONE);
			}
			EXPECT_NE(string(reply.begin(), reply.end()).find("HTTP/1.0 200"), string::npos) << NAMES[i];
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
			const std::string log = "/tmp/ants-nist-client-" + std::to_string(number) + ".log";
			ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -servername localhost -groups " + NAMES[i] + " -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
			sentinel_t sentinel(log + ".pid");
			const int fd = greeted(listener);
			ASSERT_GE(fd, 0);
			server::context_t server;
			server.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
			server.credential(credential);
			ASSERT_EQ(server.start(), context::error_t::NONE);
			const bool complete = serve(server, fd);
			ASSERT_TRUE(complete) << NAMES[i] << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
			ASSERT_EQ(server.error(), context::error_t::NONE);
			EXPECT_EQ(server.group(), GROUPS[i]) << NAMES[i];
			ASSERT_TRUE(farewell(server, fd));
			closing(fd);
			closing(listener);
			std::string text;
			ASSERT_TRUE(settle(log, text)) << text;
			EXPECT_NE(text.find(std::string("Negotiated TLS1.3 group: ") + NAMES[i]), std::string::npos) << text;
			::remove(log.c_str());
		}
	}
}

TEST(HybridTest, Starved){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	bool starved = false, complete = false;
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 100) ? 1 : 53)){
		client::context_t client;
		server::context_t server;
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		server.credential(credential);
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			starve::ration_t ration(budget);
			first = server.start();
			second = client.start();
			if((first == context::error_t::NONE) && (second == context::error_t::NONE))
				converse(client, server);
		}
		const context::error_t outcomes[4] = {first, second, client.error(), server.error()};
		for(size_t i = 0; i < 4; i++){
			ASSERT_TRUE((outcomes[i] == context::error_t::NONE) || (outcomes[i] == context::error_t::MEMORY)) << "запас " << budget << " шаг " << i << " отказ " << static_cast <int> (outcomes[i]);
			starved = (starved || (outcomes[i] == context::error_t::MEMORY));
		}
		complete = (client.established() && server.established());
	}
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}

/**
 * Сличение с openssl 3.5+: наш клиент против s_server с группой X25519MLKEM768 и s_client
 * с той же группой против нашего сервера
 */
TEST(HybridTest, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	if(!toolkit.tls13 || !toolkit.serverGroups || !toolkit.clientGroups || !kemready()){
		GTEST_SKIP() << "openssl без TLS 1.3, без -groups либо без X25519MLKEM768 (нужен openssl 3.5+)";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		const uint16_t number = vacant(false);
		ASSERT_NE(number, 0);
		const std::string log = "/tmp/ants-hybrid-server-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -groups X25519MLKEM768 -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = dial(number);
		ASSERT_GE(fd, 0) << "порт " << number;
		client::context_t client;
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			relay(client, fd);
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		const string request = "GET / HTTP/1.0\r\n\r\n";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		vector <uint8_t> answer;
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			relay(client, fd);
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		const string text(answer.begin(), answer.end());
		EXPECT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
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
		const std::string log = "/tmp/ants-hybrid-client-" + std::to_string(number) + ".log";
		const std::string holder = "/tmp/ants-hybrid-client-" + std::to_string(number) + ".fifo";
		::remove(holder.c_str());
		ASSERT_EQ(fifo(holder.c_str()), 0);
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -servername localhost -groups X25519MLKEM768:X25519 -verify_return_error <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		sentinel_t sentinel(log + ".pid");
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0);
		server::context_t server;
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_TRUE(serve(server, fd)) << "отказ " << static_cast <int> (server.error());
		ASSERT_TRUE(server.established());
		ASSERT_TRUE(farewell(server, fd));
		closing(fd);
		closing(listener);
		std::string text;
		ASSERT_TRUE(settle(log, text)) << text;
		EXPECT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		EXPECT_NE(text.find("X25519MLKEM768"), std::string::npos) << text;
		::remove(log.c_str());
		::remove(holder.c_str());
	}
}

/**
 * Сличение с BoringSSL: наш клиент против bssl server с кривой X25519MLKEM768 и bssl client
 * против нашего сервера
 */
TEST(HybridTest, Boringssl){
	const std::string tool = bssltool();
	if(tool.empty()){
		GTEST_SKIP() << "bssl (BoringSSL) недоступен: задайте ANTS_BSSL";
	}
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		const uint16_t number = vacant(false);
		ASSERT_NE(number, 0);
		const std::string log = "/tmp/ants-hybrid-bssl-server-" + std::to_string(number) + ".log";
		ASSERT_TRUE(launch(tool + " server -accept " + std::to_string(number) + " -cert " + crt + " -key " + key + " -curves X25519MLKEM768 -www </dev/null >" + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		const int fd = dial(number);
		ASSERT_GE(fd, 0) << "порт " << number;
		client::context_t client;
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			relay(client, fd);
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		const string request = "GET / HTTP/1.0\r\n\r\n";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		vector <uint8_t> answer;
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			relay(client, fd);
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		const string text(answer.begin(), answer.end());
		EXPECT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
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
		const std::string log = "/tmp/ants-hybrid-bssl-client-" + std::to_string(number) + ".log";
		const std::string holder = "/tmp/ants-hybrid-bssl-client-" + std::to_string(number) + ".fifo";
		::remove(holder.c_str());
		ASSERT_EQ(fifo(holder.c_str()), 0);
		ASSERT_TRUE(launch(tool + " client -connect 127.0.0.1:" + std::to_string(number) + " -curves X25519MLKEM768:X25519 -root-certs " + crt + " -server-name localhost <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		sentinel_t sentinel(log + ".pid");
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0);
		server::context_t server;
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_TRUE(serve(server, fd)) << "отказ " << static_cast <int> (server.error());
		ASSERT_TRUE(server.established());
		ASSERT_TRUE(farewell(server, fd));
		closing(fd);
		closing(listener);
		std::string text;
		ASSERT_TRUE(settle(log, text)) << text;
		EXPECT_NE(text.find("X25519MLKEM768"), std::string::npos) << text;
		::remove(log.c_str());
		::remove(holder.c_str());
	}
}
