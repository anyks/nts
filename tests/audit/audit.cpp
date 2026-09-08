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
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <identity.hpp>
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
#include <datagram/datagram.hpp>
#include <x509/x509.hpp>
#include <math/integer.hpp>
#include <unistd.h>

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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла
	 * @return     содержимое
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		if(!file.is_open())
			return vector <uint8_t> ();
		return vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	}
	/**
	 * @brief Метод чтения подлинности из набора
	 *
	 * @param name   имя
	 * @param result подлинность
	 * @return       признак успешности
	 *
	 */
	static bool keyfile(const char * name, context::credential_t & result) noexcept {
		result.secret = corpus((std::string(name) + ".pem").c_str());
		const vector <uint8_t> chain = corpus((std::string(name) + ".crt").c_str());
		if(result.secret.empty() || chain.empty())
			return false;
		return (pem::certificates(string(chain.begin(), chain.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод передачи байтов между сторонами
	 *
	 * @param client клиент
	 * @param server сервер
	 * @return       признак передачи
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		bool moved = false;
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
		return moved;
	}
	/**
	 * @brief Метод проведения связи до тишины
	 *
	 * @param client клиент
	 * @param server сервер
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Метод изъятия отправляемых байтов стороны
	 *
	 * @param side сторона
	 * @return     байты
	 *
	 */
	template <typename T>
	static vector <uint8_t> take(T & side) noexcept {
		const view_t data = side.output();
		vector <uint8_t> result(data.data, data.data + data.size);
		side.consume(result.size());
		return result;
	}
	/**
	 * @brief Метод выработки билета первой связью
	 *
	 * @param credential подлинность сервера
	 * @param suites     наборы либо пусто
	 * @param accepted   билет клиента
	 * @param issued     билеты сервера
	 * @return           признак успешности
	 *
	 */
	static bool ticketed(const context::credential_t & credential, const vector <protect::suite_t> & suites, context::ticket_t & accepted, vector <context::ticket_t> & issued) noexcept {
		client::context_t client;
		server::context_t server;
		server.credential(credential);
		server.advance(true, 16384);
		if(!suites.empty()){
			client.suites(suites);
			server.suites(suites);
		}
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			return false;
		converse(client, server);
		if(!client.established() || !server.established())
			return false;
		if(server.issue() != context::error_t::NONE)
			return false;
		converse(client, server);
		if(client.tickets().empty())
			return false;
		issued = server.tickets();
		accepted = client.tickets()[0];
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
	context::credential_t credential, mine;
	ASSERT_TRUE(keyfile("ec256", credential));
	ASSERT_TRUE(keyfile("ec384", mine));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	server.request(true);
	client.credential(mine);
	client.resume(accepted);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (client.alert().description);
	EXPECT_EQ(client.version(), 0x0303);
}

/**
 * Перевыбор набора под хеш билета: набор издания 1.2 с тем же хешем не годится рукопожатию 1.3
 */
TEST(AuditTest, TicketReselect){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256}, accepted, issued));
	const vector <protect::suite_t> suites = {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256};
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	server.suites(suites);
	server.resume(issued);
	client.suites(suites);
	client.resume(accepted);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	EXPECT_TRUE(server.shared());
}

/**
 * Запись упреждения в полные 16384 байта, ушедшая до просьбы о повторе, пропускается, а не
 * обрывает связь record_overflow (раздел 4.2.10 RFC 8446)
 */
TEST(AuditTest, EarlyBeforeRetry){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	server.resume(issued);
	server.advance(true, 16384);
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	client.resume(accepted);
	client.advance(true, 16384);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> payload(16384, 'A');
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
	EXPECT_FALSE(client.accepted());
}

/**
 * Билет серверу неведом, клиент шлёт 16384 байта упреждения по своему билету: бюджет пропуска
 * берётся от своей настройки, а не от нулевого объёма чужого билета - связь устанавливается
 */
TEST(AuditTest, StaleTicketBudget){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	server.advance(true, 16384);
	client.resume(accepted);
	client.advance(true, 16384);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> payload(16384, 'A');
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
	EXPECT_FALSE(server.shared());
	EXPECT_FALSE(client.accepted());
}

/**
 * Просьба о повторе с меткой возврата состояния без доли ключа поверх записей законна (разделы
 * 4.1.4 и 4.2.2 RFC 8446): клиент отвечает вторым приветствием
 */
TEST(AuditTest, CookieOnlyRetry){
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> wire = take(client);
	handshake::reader_t messages;
	ASSERT_EQ(messages.push(view_t(wire.data() + 5, wire.size() - 5)), handshake::error_t::NONE);
	handshake::header_t header;
	view_t body;
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	hello::client_t greeting;
	ASSERT_EQ(hello::parse(body, greeting), hello::error_t::NONE);
	hello::server_t answer;
	answer.version = 0x0303;
	answer.session = greeting.session;
	answer.suite = greeting.suites[0];
	answer.method = 0x00;
	::memcpy(answer.random, RETRY, sizeof(RETRY));
	vector <uint8_t> version;
	extension::version(0x0304, version);
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
	const vector <uint8_t> label = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
	vector <uint8_t> greeted;
	ASSERT_EQ(hello::build(answer, greeted), hello::error_t::NONE);
	handshake::writer_t writer;
	ASSERT_EQ(writer.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())), handshake::error_t::NONE);
	record::writer_t records;
	ASSERT_EQ(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()), record::error_t::NONE);
	EXPECT_EQ(client.push(records.data()), context::error_t::NONE) << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
	EXPECT_NE(client.state(), context::state_t::FAILED);
	EXPECT_GT(take(client).size(), static_cast <size_t> (0));
	// Просьба без доли и без метки - отказ
	client::context_t other;
	ASSERT_EQ(other.start(), context::error_t::NONE);
	(void) take(other);
	answer.extensions.pop_back();
	greeted.clear();
	ASSERT_EQ(hello::build(answer, greeted), hello::error_t::NONE);
	handshake::writer_t again;
	ASSERT_EQ(again.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())), handshake::error_t::NONE);
	record::writer_t bare;
	ASSERT_EQ(bare.push(record::type_t::HANDSHAKE, record::version_t::TLS12, again.data()), record::error_t::NONE);
	EXPECT_NE(other.push(bare.data()), context::error_t::NONE);
}

/**
 * Совместимостная запись change_cipher_spec между просьбой о повторе и вторым приветствием
 * (приложение D.4 RFC 8446): сервер пропускает её, а не рвёт связь
 */
TEST(AuditTest, CcsAfterRetry){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> first = take(client);
	ASSERT_EQ(server.push(view_t(first.data(), first.size())), context::error_t::NONE);
	const vector <uint8_t> retry = take(server);
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	const vector <uint8_t> second = take(client);
	const uint8_t ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
	EXPECT_EQ(server.push(view_t(ccs, sizeof(ccs))), context::error_t::NONE) << static_cast <int> (server.alert().description);
	EXPECT_NE(server.state(), context::state_t::FAILED);
	ASSERT_EQ(server.push(view_t(second.data(), second.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established());
	// До первого приветствия та же запись по-прежнему отвергается
	server::context_t fresh;
	fresh.credential(credential);
	ASSERT_EQ(fresh.start(), context::error_t::NONE);
	EXPECT_NE(fresh.push(view_t(ccs, sizeof(ccs))), context::error_t::NONE);
}

/**
 * Приветствие сервера издания 1.2 без блока расширений разбирается (раздел 7.4.1.3 RFC 5246)
 */
TEST(AuditTest, ServerHelloBare){
	vector <uint8_t> bare = {0x03, 0x03};
	bare.insert(bare.end(), 32, 0x11);
	bare.push_back(0x00);
	bare.push_back(0x13); bare.push_back(0x01);
	bare.push_back(0x00);
	hello::server_t answer;
	EXPECT_EQ(hello::parse(view_t(bare.data(), bare.size()), answer), hello::error_t::NONE);
	EXPECT_TRUE(answer.extensions.empty());
	// С пустым блоком - тоже
	bare.push_back(0x00); bare.push_back(0x00);
	EXPECT_EQ(hello::parse(view_t(bare.data(), bare.size()), answer), hello::error_t::NONE);
}

/**
 * Две записи host_name в server_name отвергаются (раздел 3 RFC 6066), одна принимается
 */
TEST(AuditTest, NameTwice){
	const string first = "a.example", second = "b.example";
	vector <uint8_t> body;
	const auto entry = [&body](const string & name){
		body.push_back(0x00);
		body.push_back(static_cast <uint8_t> (name.size() >> 8));
		body.push_back(static_cast <uint8_t> (name.size() & 0xFF));
		body.insert(body.end(), name.begin(), name.end());
	};
	entry(first);
	vector <uint8_t> data = {0x00, static_cast <uint8_t> (body.size())};
	data.insert(data.end(), body.begin(), body.end());
	view_t name;
	EXPECT_EQ(extension::name(view_t(data.data(), data.size()), name), extension::error_t::NONE);
	entry(second);
	data = {0x00, static_cast <uint8_t> (body.size())};
	data.insert(data.end(), body.begin(), body.end());
	EXPECT_NE(extension::name(view_t(data.data(), data.size()), name), extension::error_t::NONE);
}

/**
 * Пустой опознаватель PSK и пустая доля key_exchange сервера отвергаются (разделы 4.2.11 и 4.2.8 RFC 8446)
 */
TEST(AuditTest, EmptyBodies){
	// identities: перечень из одной пустой identity с возрастом, привязки пустые
	const vector <uint8_t> psk = {0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	vector <extension::identity_t> identities;
	vector <view_t> binders;
	size_t truncation = 0;
	EXPECT_EQ(extension::identities(view_t(psk.data(), psk.size()), identities, binders, truncation), extension::error_t::EMPTY);
	// share: группа X25519 с пустым ключом
	const vector <uint8_t> share = {0x00, 0x1D, 0x00, 0x00};
	extension::share_t item;
	EXPECT_EQ(extension::share(view_t(share.data(), share.size()), item), extension::error_t::EMPTY);
}

/**
 * Перечень ECH: конфигурация с обязательным неизвестным расширением и конфигурация с ключом не в длину
 * KEM пропускаются, годная следом берётся (разделы 4.2 и 6.1.1 RFC 9849); битый перечень расширений - отказ
 */
TEST(AuditTest, EchConfigs){
	const auto make = [](const uint8_t id, const size_t keysize, const vector <uint8_t> & extensions, vector <uint8_t> & raw){
		ech::config_t config;
		config.id = id;
		config.length = 64;
		config.kem = hpke::kem_t::X25519_HKDF_SHA256;
		config.key.assign(keysize, 0x42);
		config.suites.push_back(ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM));
		config.name = "public.example";
		config.extensions = extensions;
		return (ech::build(config, raw) == ech::error_t::NONE);
	};
	vector <uint8_t> mandatory, shortkey, good;
	ASSERT_TRUE(make(1, 32, vector <uint8_t> {0x80, 0x01, 0x00, 0x00}, mandatory));
	ASSERT_TRUE(make(2, 31, vector <uint8_t> (), shortkey));
	ASSERT_TRUE(make(3, 32, vector <uint8_t> {0x00, 0x01, 0x00, 0x00}, good));
	vector <uint8_t> list;
	list.insert(list.end(), mandatory.begin(), mandatory.end());
	list.insert(list.end(), shortkey.begin(), shortkey.end());
	list.insert(list.end(), good.begin(), good.end());
	list.insert(list.begin(), static_cast <uint8_t> (list.size() & 0xFF));
	list.insert(list.begin(), static_cast <uint8_t> ((list.size() - 1) >> 8));
	vector <ech::config_t> configs;
	ASSERT_EQ(ech::parse(view_t(list.data(), list.size()), configs), ech::error_t::NONE);
	ASSERT_EQ(configs.size(), static_cast <size_t> (1));
	EXPECT_EQ(configs[0].id, 3);
	// Битый перечень расширений
	vector <uint8_t> broken;
	ASSERT_TRUE(make(4, 32, vector <uint8_t> {0x00, 0x01}, broken));
	vector <uint8_t> alone = {static_cast <uint8_t> (broken.size() >> 8), static_cast <uint8_t> (broken.size() & 0xFF)};
	alone.insert(alone.end(), broken.begin(), broken.end());
	EXPECT_NE(ech::parse(view_t(alone.data(), alone.size()), configs), ech::error_t::NONE);
	// Клиент с таким перечнем заводится по годной конфигурации
	client::context_t client;
	client.name("secret.example");
	EXPECT_EQ(client.ech(list), context::error_t::NONE);
	EXPECT_EQ(client.start(), context::error_t::NONE);
}

/**
 * Адрес IPv6 со сжатием в конце («2001:db8::») отвечает записи subjectAltName
 */
TEST(AuditTest, AddressTail){
	const vector <uint8_t> text = corpus("audit/ipv6.crt");
	ASSERT_FALSE(text.empty());
	vector <vector <uint8_t>> chain;
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	ASSERT_EQ(chain.size(), static_cast <size_t> (1));
	const view_t der(chain[0].data(), chain[0].size());
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
	const auto load = [](const char * name, vector <uint8_t> & result){
		const vector <uint8_t> text = corpus(name);
		vector <vector <uint8_t>> chain;
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			return false;
		result = chain[0];
		return true;
	};
	vector <uint8_t> leaf, middle, root;
	ASSERT_TRUE(load("audit/eku-client.crt", leaf));
	ASSERT_TRUE(load("audit/eku-mid.crt", middle));
	ASSERT_TRUE(load("audit/eku-root.crt", root));
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	const vector <vector <uint8_t>> chain = {leaf, middle};
	const int64_t moment = 1800000000;
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
	if(::system("openssl version >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "openssl недоступен";
	}
	const std::string path = "/tmp/ants-audit-iter-" + std::to_string(static_cast <unsigned> (::getpid())) + ".pem";
	// Выработка записи у openssl сама стоит секунды: итерации считаются при шифровании
	if(::system(("openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 10000001 -passout pass:secret -in " + std::string(CORPUS) + "/ec256.pem -out " + path + " >/dev/null 2>&1").c_str()) != 0){
		GTEST_SKIP() << "openssl без -iter";
	}
	std::ifstream file(path);
	const std::string text((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	::remove(path.c_str());
	ASSERT_FALSE(text.empty());
	keys::key_t key;
	const uint8_t password[6] = {'s', 'e', 'c', 'r', 'e', 't'};
	EXPECT_EQ(keys::decode(text, view_t(password, sizeof(password)), key), keys::error_t::CIPHER);
}

/**
 * Предел открытого текста GCM (раздел 5.2.1.1 NIST SP 800-38D): кусок, выводящий за 2^39 - 256 разрядов,
 * отвергается до шифрования - гамма не замыкается на J0
 */
TEST(AuditTest, GcmMost){
	cipher::aes_t aes;
	const uint8_t key[16] = {0};
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	cipher::gcm_t gcm;
	const uint8_t nonce[12] = {0};
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	uint8_t buffer[16] = {0}, out[16];
	// Кусок, объявленный длиной сверх предела, отвергается до чтения байтов
	EXPECT_FALSE(gcm.encrypt(view_t(buffer, (static_cast <size_t> (1) << 36)), out));
	// Присоединённые данные сверх 2^61 байт - тоже
	cipher::gcm_t other;
	ASSERT_TRUE(other.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	EXPECT_FALSE(other.associate(view_t(buffer, (static_cast <size_t> (1) << 61) + 1)));
	// Обычный кусок идёт
	cipher::gcm_t plain;
	ASSERT_TRUE(plain.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	EXPECT_TRUE(plain.encrypt(view_t(buffer, sizeof(buffer)), out));
}

/**
 * Круг 2: второе приветствие за просьбой о повторе без pre_shared_key ведёт к полному рукопожатию -
 * состояние билета первого приветствия сброшено (раздел 4.1.2 RFC 8446)
 */
TEST(AuditTest, PskAfterRetry){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> (), accepted, issued));
	client::context_t first;
	server::context_t server;
	server.credential(credential);
	server.resume(issued);
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	first.resume(accepted);
	first.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	const vector <uint8_t> hello = take(first);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	EXPECT_TRUE(server.shared());
	(void) take(server);
	// Второе приветствие от стороны без билета по запрошенной группе
	client::context_t second;
	second.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	ASSERT_EQ(second.start(), context::error_t::NONE);
	const vector <uint8_t> again = take(second);
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	EXPECT_FALSE(server.shared());
	// Приветствие сервера без pre_shared_key: полное рукопожатие (переписка второй стороны с просьбой о повторе не сходится - это не проверяется)
	const vector <uint8_t> answer = take(server);
	ASSERT_GT(answer.size(), static_cast <size_t> (5));
	handshake::reader_t messages;
	ASSERT_EQ(messages.push(view_t(answer.data() + 5, ((static_cast <size_t> (answer[3]) << 8) | answer[4]))), handshake::error_t::NONE);
	handshake::header_t header;
	view_t body;
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	hello::server_t greeted;
	ASSERT_EQ(hello::parse(body, greeted), hello::error_t::NONE);
	EXPECT_EQ(hello::extension(greeted.extensions, 0x0029), nullptr);
}

/**
 * Круг 2: билет связи DTLS 1.2 не возобновляет связь изданием DTLS 1.0 (раздел 3.4 RFC 5077) - идёт полное рукопожатие
 */
TEST(AuditTest, TicketEdition){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	{
		client::context_t client;
		server::context_t server;
		client.transport(context::transport_t::DATAGRAMS);
		server.transport(context::transport_t::DATAGRAMS);
		const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
		server.address(view_t(peer, sizeof(peer)));
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0302, 0x0303), context::error_t::NONE);
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		ASSERT_EQ(client.version(), 0x0303);
		ASSERT_FALSE(client.tickets().empty());
		issued = server.tickets();
		accepted = client.tickets()[0];
	}
	// Тот же билет предъявляется связью DTLS 1.0: сервер обязан вести полное рукопожатие, а не возобновлять набором GCM
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
	client.groups(vector <extension::group_t> {extension::group_t::X25519});
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	ASSERT_EQ(client.versions(0x0302, 0x0302), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0302, 0x0303), context::error_t::NONE);
	server.credential(credential);
	server.resume(issued);
	client.resume(accepted);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_FALSE(server.shared());
	EXPECT_EQ(client.version(), 0x0302);
	EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
}

/**
 * Круг 2: ссылка ech_outer_extensions на само ech_outer_extensions негодна (раздел 5.1 RFC 9849)
 */
TEST(AuditTest, OuterReference){
	client::context_t donor;
	donor.name("secret.example");
	ASSERT_EQ(donor.start(), context::error_t::NONE);
	const vector <uint8_t> wire = take(donor);
	handshake::reader_t messages;
	ASSERT_EQ(messages.push(view_t(wire.data() + 5, wire.size() - 5)), handshake::error_t::NONE);
	handshake::header_t header;
	view_t body;
	ASSERT_EQ(messages.next(header, body), handshake::error_t::NONE);
	hello::client_t inner;
	ASSERT_EQ(hello::parse(body, inner), hello::error_t::NONE);
	vector <uint8_t> compact;
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0xFD00}, 5, compact), ech::error_t::OUTER);
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0xFE0D}, 5, compact), ech::error_t::OUTER);
}

/**
 * Круг 2: ограничения имён издателя применяются и некритичным расширением (раздел 6.1.4 RFC 5280):
 * лист evil.com под промежуточным с permitted DNS:.example.com отвергается
 */
TEST(AuditTest, NameConstraints){
	const auto load = [](const char * name, vector <uint8_t> & result){
		const vector <uint8_t> text = corpus(name);
		vector <vector <uint8_t>> chain;
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			return false;
		result = chain[0];
		return true;
	};
	vector <uint8_t> leaf, middle, root;
	ASSERT_TRUE(load("audit/nc-leaf.crt", leaf));
	ASSERT_TRUE(load("audit/nc-mid.crt", middle));
	ASSERT_TRUE(load("audit/nc-root.crt", root));
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	const int64_t moment = 1800000000;
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment, trust::role_t::SERVER), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment), trust::error_t::CONSTRAINED);
	// Разбор самих ограничений
	x509::certificate_t issuer;
	ASSERT_EQ(issuer.parse(view_t(middle.data(), middle.size())), x509::error_t::NONE);
	const x509::extension_t * extension = issuer.extension("2.5.29.30");
	ASSERT_NE(extension, nullptr);
	vector <x509::alternative_t> permitted, excluded;
	ASSERT_EQ(x509::constraints(*extension, permitted, excluded), x509::error_t::NONE);
	ASSERT_EQ(permitted.size(), static_cast <size_t> (1));
	EXPECT_EQ(permitted[0].kind, x509::kind_t::DNS);
	EXPECT_EQ(permitted[0].value, ".example.com");
	EXPECT_TRUE(excluded.empty());
}

/**
 * Круг 2: критичное extendedKeyUsage промежуточного издателя (codeSigning) не даёт цепочке служить серверу
 */
TEST(AuditTest, IssuerPurpose){
	const auto load = [](const char * name, vector <uint8_t> & result){
		const vector <uint8_t> text = corpus(name);
		vector <vector <uint8_t>> chain;
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			return false;
		result = chain[0];
		return true;
	};
	vector <uint8_t> leaf, middle, root;
	ASSERT_TRUE(load("audit/eku-leaf-server.crt", leaf));
	ASSERT_TRUE(load("audit/eku-mid-codesign.crt", middle));
	ASSERT_TRUE(load("audit/nc-root.crt", root));
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	const int64_t moment = 1800000000;
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment, trust::role_t::SERVER), trust::error_t::PURPOSE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, middle}, store, moment), trust::error_t::PURPOSE);
}

/**
 * Круг 2: одиночное двоеточие в конце адреса IPv6 не сжатие («1:», «2001:db8:0:0:0:0:0:»)
 */
TEST(AuditTest, AddressColon){
	const vector <uint8_t> text = corpus("audit/ipv6.crt");
	ASSERT_FALSE(text.empty());
	vector <vector <uint8_t>> chain;
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	const view_t der(chain[0].data(), chain[0].size());
	EXPECT_EQ(trust::belongs(der, "2001:db8:0:0:0:0:0:"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "1:"), trust::error_t::NAME);
	EXPECT_EQ(trust::belongs(der, "2001:db8::"), trust::error_t::NONE);
	EXPECT_EQ(trust::belongs(der, "::"), trust::error_t::NAME);
}

/**
 * Круг 2: GeneralizedTime с годом до 1950 разбирается (раздел 4.1.2.5 RFC 5280)
 */
TEST(AuditTest, OldTime){
	const vector <uint8_t> text = corpus("audit/old.crt");
	ASSERT_FALSE(text.empty());
	vector <vector <uint8_t>> chain;
	ASSERT_EQ(pem::certificates(string(text.begin(), text.end()), chain), pem::error_t::NONE);
	x509::certificate_t certificate;
	EXPECT_EQ(certificate.parse(view_t(chain[0].data(), chain[0].size())), x509::error_t::NONE);
	int64_t before = 0, after = 0;
	certificate.validity(before, after);
	EXPECT_LT(before, static_cast <int64_t> (-631152000));
}

/**
 * Круг 2: открытая запись APPLICATION эпохи 0 у DTLS 1.3 роняется, а не доставляется приложению
 */
TEST(AuditTest, PlainInjection){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	// Открытая запись прикладных данных: заголовок DTLS и тело
	const string text = "PLAINTEXT-INJECTED";
	datagram::header_t header;
	header.type = record::type_t::APPLICATION;
	header.epoch = 0;
	header.sequence = 77;
	header.size = text.size();
	vector <uint8_t> forged(datagram::DATAGRAM_PLAIN_HEADER + text.size(), 0);
	size_t length = 0;
	datagram::build(header, forged.data(), length);
	::memcpy(forged.data() + length, text.data(), text.size());
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	vector <uint8_t> received;
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_TRUE(received.empty());
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
	// Защищённые данные ходят по-прежнему
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
}

/**
 * Круг 2: открытые пустые подтверждения не расходуют попыток повтора - девять штук не рвут рукопожатие
 */
TEST(AuditTest, AckNudge){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первое приветствие - серверу, его залп ждёт завершения клиента
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	const vector <uint8_t> flight = take(server);
	ASSERT_FALSE(flight.empty());
	// Девять открытых пустых подтверждений
	for(size_t i = 0; i < 9; i++){
		datagram::header_t header;
		header.type = record::type_t::ACK;
		header.epoch = 0;
		header.sequence = (100 + i);
		header.size = 2;
		vector <uint8_t> nudge(datagram::DATAGRAM_PLAIN_HEADER + 2, 0);
		size_t length = 0;
		datagram::build(header, nudge.data(), length);
		EXPECT_EQ(server.push(view_t(nudge.data(), nudge.size())), context::error_t::NONE) << i;
		(void) take(server);
	}
	EXPECT_NE(server.state(), context::state_t::FAILED);
	EXPECT_NE(server.error(), context::error_t::TIMEOUT);
	// Рукопожатие доходит до конца
	ASSERT_EQ(client.push(view_t(flight.data(), flight.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Круг 2: переполнение переноса Poly1305 на двухблочном пути - свидетель, найденный аудитом, сходится с OpenSSL
 */
TEST(AuditTest, PolyWitness){
	static const char * KEY = "390ac60f3cc7bf0b983d9103f87e430f00000000000000000000000000000000";
	static const char * MESSAGE = "3c978b215eea9a79a094109b03e8d6784608f34741edb0dfac3aa02f833ef70effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
	static const char * TAG = "5d6ea518365b6c615f1d89be734804e2";
	uint8_t key[32], message[64], expected[16], tag[16];
	for(size_t i = 0; i < 32; i++){ unsigned v = 0; ::sscanf(KEY + i * 2, "%2x", &v); key[i] = static_cast <uint8_t> (v); }
	for(size_t i = 0; i < 64; i++){ unsigned v = 0; ::sscanf(MESSAGE + i * 2, "%2x", &v); message[i] = static_cast <uint8_t> (v); }
	for(size_t i = 0; i < 16; i++){ unsigned v = 0; ::sscanf(TAG + i * 2, "%2x", &v); expected[i] = static_cast <uint8_t> (v); }
	cipher::poly1305_t poly;
	ASSERT_TRUE(poly.start(view_t(key, sizeof(key))));
	ASSERT_TRUE(poly.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(poly.finish(tag));
	EXPECT_EQ(::memcmp(tag, expected, sizeof(tag)), 0);
	// Тот же итог кусками по одному блоку: одноблочный путь
	cipher::poly1305_t single;
	ASSERT_TRUE(single.start(view_t(key, sizeof(key))));
	for(size_t i = 0; i < 4; i++)
		ASSERT_TRUE(single.update(view_t(message + i * 16, 16)));
	ASSERT_TRUE(single.finish(tag));
	EXPECT_EQ(::memcmp(tag, expected, sizeof(tag)), 0);
}

/**
 * Круг 2: одновызовное снятие защиты GCM тоже блюдёт предел открытого текста
 */
TEST(AuditTest, GcmMostOneShot){
	cipher::aes_t aes;
	const uint8_t key[16] = {0};
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	cipher::gcm_t gcm;
	const uint8_t nonce[12] = {0};
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	uint8_t buffer[16] = {0}, out[16], tag[16] = {0};
	EXPECT_FALSE(gcm.decrypt(view_t(), view_t(buffer, (static_cast <size_t> (1) << 36)), out, view_t(tag, sizeof(tag))));
}

/**
 * Круг 2: совпадение итога со вторым сомножителем у mulmod(secret) и с модулем у power(bits) не портит итога
 */
TEST(AuditTest, IntegerAlias){
	math::integer_t a, b, m, expected, check;
	const uint8_t modulus[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc5};
	ASSERT_TRUE(m.load(view_t(modulus, sizeof(modulus))));
	a.word(123456789);
	b.word(987654321);
	ASSERT_TRUE(expected.mulmod(a, b, m, true));
	ASSERT_TRUE(b.mulmod(a, b, m, true));
	EXPECT_TRUE(b.equal(expected));
	math::integer_t e;
	e.word(65537);
	ASSERT_TRUE(expected.power(a, e, m, static_cast <size_t> (17)));
	ASSERT_TRUE(check.power(a, e, m, false));
	EXPECT_TRUE(expected.equal(check));
	math::integer_t alias;
	ASSERT_TRUE(alias.load(view_t(modulus, sizeof(modulus))));
	ASSERT_TRUE(alias.power(a, e, alias, static_cast <size_t> (17)));
	EXPECT_TRUE(alias.equal(expected));
}

/**
 * Круг 3: набор шифрования за просьбой о повторе сохраняется (§4.1.4 RFC 8446): билет с хешем ниже по
 * предпочтению сервера при HRR возобновляет связь, а не рвёт её internal_error
 */
TEST(AuditTest, SuiteAfterRetry){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	context::ticket_t accepted;
	vector <context::ticket_t> issued;
	ASSERT_TRUE(ticketed(credential, vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256}, accepted, issued));
	const vector <protect::suite_t> suites = {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::AES_128_GCM_SHA256};
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	server.suites(suites);
	server.resume(issued);
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	client.suites(suites);
	client.resume(accepted);
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	EXPECT_TRUE(server.shared());
}

/**
 * Круг 3: билет перемещается, а не копируется, и ключ у источника затирается
 */
TEST(AuditTest, TicketMove){
	context::ticket_t source;
	source.secret.assign(32, 0x5A);
	source.identity.assign(8, 0x11);
	context::ticket_t moved(::move(source));
	EXPECT_EQ(moved.secret.size(), static_cast <size_t> (32));
	EXPECT_TRUE(source.secret.empty());
	context::ticket_t assigned;
	assigned.secret.assign(16, 0x33);
	assigned = ::move(moved);
	EXPECT_EQ(assigned.secret.size(), static_cast <size_t> (32));
	EXPECT_TRUE(moved.secret.empty());
	EXPECT_TRUE(std::is_nothrow_move_constructible <context::ticket_t>::value);
	EXPECT_TRUE(std::is_nothrow_move_assignable <context::ticket_t>::value);
}

/**
 * Круг 3: DTLS 1.3 - запись при неподтверждённой своей смене ключей и задолженной ответной не отказывает
 * STATE, данные уходят, долг оплачивается после подтверждения (разделы 4.6.3 RFC 8446, 8 RFC 9147)
 */
TEST(AuditTest, OwedUpdate){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	// Клиент меняет ключи и ждёт подтверждения; сервер просит смену у клиента
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	ASSERT_EQ(server.update(true), context::error_t::NONE);
	const vector <uint8_t> asked = take(server);
	ASSERT_EQ(client.push(view_t(asked.data(), asked.size())), context::error_t::NONE);
	// Запись при задолженной смене и своей неподтверждённой - уходит
	const string text = "после смены";
	EXPECT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	converse(client, server);
	vector <uint8_t> received;
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
	// Долг оплачен после подтверждения: обе стороны живы и данные ходят в обе стороны
	const string back = "обратно";
	EXPECT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (back.data()), back.size())), context::error_t::NONE);
	converse(client, server);
	received.clear();
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
	const auto load = [](const char * name, vector <uint8_t> & result){
		const vector <uint8_t> text = corpus(name);
		vector <vector <uint8_t>> chain;
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			return false;
		result = chain[0];
		return true;
	};
	const int64_t moment = 1800000000;
	vector <uint8_t> root, rootnc, rooteku, midcrit, lok, midnc, lcn, midmail, lmail, middn, ldn, lanchor, leku;
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
	trust::store_t store;
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
	ASSERT_TRUE(bounded.add(view_t(rootnc.data(), rootnc.size())));
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {lanchor}, bounded, moment), trust::error_t::AUTHORITY);
	trust::store_t purposed;
	ASSERT_TRUE(purposed.add(view_t(rooteku.data(), rooteku.size())));
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leku}, purposed, moment, trust::role_t::SERVER), trust::error_t::AUTHORITY);
}

/**
 * Круг 3, DTLS 1.2: чужая открытая запись смены набора с негодным телом по установленной связи роняется, связь жива
 */
TEST(AuditTest, ChangeSpoof){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	datagram::header_t header;
	header.type = record::type_t::CHANGE;
	header.epoch = 0;
	header.sequence = 999;
	header.size = 1;
	vector <uint8_t> forged(datagram::DATAGRAM_PLAIN_HEADER + 1, 0);
	size_t length = 0;
	datagram::build(header, forged.data(), length);
	forged[length] = 0x02;
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::ESTABLISHED);
	EXPECT_EQ(client.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(client.state(), context::state_t::ESTABLISHED);
	const string text = "жива";
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
	converse(client, server);
	vector <uint8_t> received;
	EXPECT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), text);
}

/**
 * Круг 3, DTLS: чужая открытая запись с номером 2^48 - 1 не закрывает настоящие открытые записи, а повтор
 * раздробленного залпа собеседника даёт не более одного повтора своего залпа на срок
 */
TEST(AuditTest, PoisonedWindow){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	server.credential(credential);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Отравление: открытый мусор с наибольшим номером клиенту до ответа сервера
	datagram::header_t header;
	header.type = record::type_t::HANDSHAKE;
	header.epoch = 0;
	header.sequence = 0xFFFFFFFFFFFFULL;
	header.size = 20;
	vector <uint8_t> poison(datagram::DATAGRAM_PLAIN_HEADER + 20, 0xEE);
	size_t length = 0;
	datagram::build(header, poison.data(), length);
	EXPECT_EQ(client.push(view_t(poison.data(), poison.size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}
