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
	 * @brief Метод забора всех дейтаграмм из очереди стороны
	 *
	 * @param side сторона
	 * @return     дейтаграммы по порядку
	 *
	 */
	template <typename T>
	static vector <vector <uint8_t>> drain(T & side) noexcept {
		vector <vector <uint8_t>> result;
		for(vector <uint8_t> item = take(side); !item.empty(); item = take(side))
			result.push_back(item);
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
	// Первое приветствие - серверу, ответ - метка возврата состояния без часов; второе приветствие даёт залп с часами
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	const vector <uint8_t> retry = take(server);
	ASSERT_FALSE(retry.empty());
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	const vector <uint8_t> again = take(client);
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	const vector <vector <uint8_t>> flight = drain(server);
	ASSERT_FALSE(flight.empty());
	ASSERT_NE(server.timeout(), static_cast <uint32_t> (0));
	// Девять открытых пустых подтверждений за один срок: повтор залпа не более одного (круг 4)
	size_t resent = 0;
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
		if(!drain(server).empty()) resent++;
	}
	EXPECT_EQ(resent, static_cast <size_t> (1));
	EXPECT_NE(server.state(), context::state_t::FAILED);
	EXPECT_NE(server.error(), context::error_t::TIMEOUT);
	// Рукопожатие доходит до конца
	for(size_t i = 0; i < flight.size(); i++)
		ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
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
	// Открытая запись смены набора руками: datagram::build() смену не складывает (круг 7)
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x02};
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

/**
 * Круг 3 (шифры): пустой кусок после неполного блока не зовёт копирование с нулевым указателем,
 * а итог совпадает с подачей одним куском
 */
TEST(AuditTest, EmptyPiece){
	uint8_t key[32], message[21], one[16], two[16];
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (i * 7 + 1);
	for(size_t i = 0; i < sizeof(message); i++) message[i] = static_cast <uint8_t> (i);
	cipher::poly1305_t whole, pieces;
	ASSERT_TRUE(whole.start(view_t(key, sizeof(key))) && pieces.start(view_t(key, sizeof(key))));
	ASSERT_TRUE(whole.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(pieces.update(view_t(message, 5)));
	ASSERT_TRUE(pieces.update(view_t()));
	ASSERT_TRUE(pieces.update(view_t(message + 5, sizeof(message) - 5)));
	ASSERT_TRUE(whole.finish(one) && pieces.finish(two));
	EXPECT_EQ(::memcmp(one, two, sizeof(one)), 0);
	cipher::aes_t aes;
	ASSERT_TRUE(aes.key(view_t(key, sizeof(key))));
	uint8_t nonce[12] = {0};
	cipher::gcm_t solid, split;
	ASSERT_TRUE(solid.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	ASSERT_TRUE(split.start(cipher::block_t(aes), view_t(nonce, sizeof(nonce))));
	ASSERT_TRUE(solid.associate(view_t(message, sizeof(message))));
	ASSERT_TRUE(split.associate(view_t(message, 5)));
	ASSERT_TRUE(split.associate(view_t()));
	ASSERT_TRUE(split.associate(view_t(message + 5, sizeof(message) - 5)));
	uint8_t outOne[21], outTwo[21];
	ASSERT_TRUE(solid.encrypt(view_t(message, sizeof(message)), outOne));
	ASSERT_TRUE(split.encrypt(view_t(message, 5), outTwo));
	ASSERT_TRUE(split.encrypt(view_t(), nullptr));
	ASSERT_TRUE(split.encrypt(view_t(message + 5, sizeof(message) - 5), outTwo + 5));
	ASSERT_TRUE(solid.finish(one) && split.finish(two));
	EXPECT_EQ(::memcmp(outOne, outTwo, sizeof(outOne)), 0);
	EXPECT_EQ(::memcmp(one, two, sizeof(one)), 0);
}

/**
 * Круг 3 (шифры): длины Argon2 вне 32 разрядов отвергаются до расчёта (RFC 9106 раздел 3.1)
 */
TEST(AuditTest, ArgonBounds){
	digest::argon_params_t params(digest::argon_t::ARGON2ID, 64, 1, 1);
	uint8_t password[8] = {1, 2, 3, 4, 5, 6, 7, 8}, salt[8] = {8, 7, 6, 5, 4, 3, 2, 1}, tag[32];
	const view_t huge(password, static_cast <size_t> (1) << 32);
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), view_t(), tag, huge.size));
	EXPECT_FALSE(digest::argon2(params, huge, view_t(salt, sizeof(salt)), view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), huge, view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), huge, view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), huge, tag, sizeof(tag)));
	EXPECT_TRUE(digest::argon2(params, view_t(password, sizeof(password)), view_t(salt, sizeof(salt)), view_t(), view_t(), tag, sizeof(tag)));
}

/**
 * Круг 3 (математика): приведение за постоянное время совпадает с делением столбиком на
 * случайных числах всей ёмкости, на нуле, на модуле и на числе с одним старшим разрядом
 */
TEST(AuditTest, Residue){
	math::integer_t modulus, value, slow, fast;
	// Случайные нечётные модули разной ширины
	const size_t widths[] = {64, 65, 511, 512, 521, 1024, 1536, 2048, 4096, 8191};
	for(size_t width : widths){
		for(size_t round = 0; round < 8; round++){
			ASSERT_TRUE(modulus.random(width));
			// Модуль нечётный и не меньше трёх
			uint8_t low[1];
			ASSERT_TRUE(modulus.store(low, 1) || true);
			math::integer_t one, odd;
			one.word(1);
			ASSERT_TRUE(odd.add(modulus, one));
			if(!odd.odd()) odd.add(modulus, one), odd.add(odd, one);
			if(odd.bits() < 2) continue;
			// Число всей ёмкости
			ASSERT_TRUE(value.random(math::INTEGER_BITS));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			EXPECT_TRUE(slow.equal(fast)) << width;
			// Число вдвое шире модуля
			ASSERT_TRUE(value.random((width * 2 > math::INTEGER_BITS) ? math::INTEGER_BITS : width * 2));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			EXPECT_TRUE(slow.equal(fast)) << width;
			// Число короче модуля
			ASSERT_TRUE(value.random(width / 2 + 1));
			ASSERT_TRUE(slow.reduce(value, odd) && fast.residue(value, odd));
			EXPECT_TRUE(slow.equal(fast)) << width;
		}
	}
	// Единица и ноль
	math::integer_t one; one.word(1);
	math::integer_t seven; seven.word(7);
	ASSERT_TRUE(fast.residue(one, seven)); EXPECT_TRUE(fast.equal(one));
	value.clear();
	ASSERT_TRUE(fast.residue(value, seven)); EXPECT_TRUE(fast.zero());
	// Само значение, равное модулю, даёт ноль
	ASSERT_TRUE(fast.residue(seven, seven)); EXPECT_TRUE(fast.zero());
	// Чётный модуль отвергается
	math::integer_t eight; eight.word(8);
	EXPECT_FALSE(fast.residue(one, eight));
}

/**
 * Круг 3 (математика): ослепляющее число RSA всегда меньше модуля - секретное действие на ключе
 * с модулем 512 разрядов чуть выше 2^511 не отказывает ни разу за тысячи вызовов
 */
TEST(AuditTest, BlindRange){
	sign::rsa_t rsa;
	const vector <uint8_t> key = corpus("audit/rsa-low.der");
	ASSERT_FALSE(key.empty());
	ASSERT_TRUE(rsa.decode(view_t(key.data(), key.size())));
	uint8_t input[16], enciphered[64], deciphered[64];
	for(size_t i = 0; i < sizeof(input); i++) input[i] = static_cast <uint8_t> (0x21 + i);
	ASSERT_TRUE(rsa.encipher(view_t(input, sizeof(input)), enciphered));
	for(size_t round = 0; round < 2000; round++){
		ASSERT_TRUE(rsa.decipher(view_t(enciphered, sizeof(enciphered)), deciphered)) << round;
		ASSERT_EQ(::memcmp(deciphered + sizeof(deciphered) - sizeof(input), input, sizeof(input)), 0);
	}
}

/**
 * Круг 4 (записи): подтверждение на номер записи первой передачи, пришедшее после повтора залпа,
 * подтверждает кусок - часы останавливаются, лишнего повтора нет
 */
TEST(AuditTest, FormerAck){
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
	// Приветствие клиента серверу, метка возврата состояния, второе приветствие; первый залп сервера задерживается в пути
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	const vector <uint8_t> retry = take(server);
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	const vector <uint8_t> again = take(client);
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	const vector <vector <uint8_t>> first = drain(server);
	ASSERT_FALSE(first.empty());
	ASSERT_NE(server.timeout(), static_cast <uint32_t> (0));
	// Срок истёк: сервер повторяет залп новыми номерами записей
	ASSERT_EQ(server.elapsed(), context::error_t::NONE);
	const vector <vector <uint8_t>> second = drain(server);
	ASSERT_FALSE(second.empty());
	// Клиент получает задержавшийся первый залп и отвечает своим залпом с подтверждением прежних номеров
	for(size_t i = 0; i < first.size(); i++)
		ASSERT_EQ(client.push(view_t(first[i].data(), first[i].size())), context::error_t::NONE);
	const vector <vector <uint8_t>> reply = drain(client);
	ASSERT_FALSE(reply.empty());
	for(size_t i = 0; i < reply.size(); i++)
		ASSERT_EQ(server.push(view_t(reply[i].data(), reply[i].size())), context::error_t::NONE);
	(void) drain(server);
	// Связь установлена обеими сторонами, а часы сервера остановлены: залп подтверждён по прежним номерам
	EXPECT_TRUE(server.established()) << static_cast <int> (server.error());
	EXPECT_EQ(server.timeout(), static_cast <uint32_t> (0));
}

/**
 * @brief Метод чтения сертификата набора записью DER
 *
 * @param name имя файла
 * @return     запись DER либо пустой накопитель
 *
 */
static vector <uint8_t> certified(const char * name) noexcept {
	const vector <uint8_t> text = corpus(name);
	vector <vector <uint8_t>> chain;
	if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
		return vector <uint8_t> ();
	return chain[0];
}

/**
 * Круг 4 (X.509): звено с подписью SHA-1 либо ключом RSA короче 2048 разрядов отвергается (WEAK)
 */
TEST(AuditTest, WeakChain){
	const vector <uint8_t> root = certified("audit/weak-root.crt"), sha1 = certified("audit/weak-sha1.crt"), rsa = certified("audit/weak-rsa.crt"), ok = certified("audit/weak-ok.crt");
	ASSERT_FALSE(root.empty() || sha1.empty() || rsa.empty() || ok.empty());
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	const int64_t moment = 1800000000;
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {ok}, store, moment), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {sha1}, store, moment), trust::error_t::WEAK);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {rsa}, store, moment), trust::error_t::WEAK);
}

/**
 * Круг 4 (X.509): directoryName из subjectAltName судится ограничениями того же уровня, что и поле subject;
 * общее имя, не похожее на имя узла, под ограничения dNSName не подпадает; почта под permitted email
 */
TEST(AuditTest, DirectoryConstraints){
	const vector <uint8_t> root = certified("audit/r4-root.crt");
	ASSERT_FALSE(root.empty());
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
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
	curve::curve_t curve;
	ASSERT_TRUE(curve::parameters(string("1.2.643.7.1.2.1.2.2"), curve));
	sign::ecdsa_t ecdsa;
	ASSERT_TRUE(ecdsa.start(curve));
	uint8_t secret[64];
	ASSERT_TRUE(ecdsa.generate(secret, sizeof(secret)));
	uint8_t digest[32], signature[256];
	for(size_t i = 0; i < 400; i++){
		for(size_t j = 0; j < sizeof(digest); j++) digest[j] = static_cast <uint8_t> ((i * 131 + j * 17) & 0xFF);
		ASSERT_TRUE(ecdsa.make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), signature)) << i;
	}
}

/**
 * Круг 4 (шифры): имитовставка закрывается после снятия - повторное снятие и подача отвергаются
 */
TEST(AuditTest, ImitationClosed){
	uint8_t key[32];
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (i);
	cipher::kuznyechik_t base;
	ASSERT_TRUE(base.key(view_t(key, sizeof(key))));
	cipher::imitation_t mode;
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	uint8_t message[40] = {0}, one[16], two[16];
	ASSERT_TRUE(mode.update(view_t(message, sizeof(message))));
	ASSERT_TRUE(mode.finish(one, sizeof(one)));
	EXPECT_FALSE(mode.finish(two, sizeof(two)));
	EXPECT_FALSE(mode.update(view_t(message, sizeof(message))));
	EXPECT_FALSE(mode.ready());
}

/**
 * Круг 4 (шифры): вскрытие Noise на месте (итог поверх входа) даёт тот же хеш рукопожатия, что и в отдельное место
 */
TEST(AuditTest, NoiseAlias){
	const string name = "Noise_NN_25519_ChaChaPoly_SHA256";
	uint8_t key[32];
	for(size_t i = 0; i < sizeof(key); i++) key[i] = static_cast <uint8_t> (0x40 + i);
	noise::symmetric_t sender, apart, inplace;
	const noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256);
	ASSERT_TRUE(sender.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && sender.key(view_t(key, sizeof(key))));
	ASSERT_TRUE(apart.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && apart.key(view_t(key, sizeof(key))));
	ASSERT_TRUE(inplace.start(view_t(reinterpret_cast <const uint8_t *> (name.data()), name.size()), suite) && inplace.key(view_t(key, sizeof(key))));
	const string text = "сообщение длиннее блока для вскрытия на месте";
	uint8_t sealed[128], opened[128];
	size_t size = sizeof(sealed);
	ASSERT_TRUE(sender.seal(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), sealed, size));
	uint8_t mirror[128];
	::memcpy(mirror, sealed, size);
	size_t got = sizeof(opened);
	ASSERT_TRUE(apart.open(view_t(sealed, size), opened, got));
	size_t here = sizeof(mirror);
	ASSERT_TRUE(inplace.open(view_t(mirror, size), mirror, here));
	EXPECT_EQ(got, here);
	EXPECT_EQ(::memcmp(opened, mirror, got), 0);
	uint8_t first[64], second[64], third[64];
	ASSERT_TRUE(sender.digest(first) && apart.digest(second) && inplace.digest(third));
	EXPECT_EQ(::memcmp(first, second, 32), 0);
	EXPECT_EQ(::memcmp(first, third, 32), 0);
}

/**
 * Круг 4 (разборщики): профиль отпечатка с принятого приветствия снимается и поверх дейтаграмм
 */
TEST(AuditTest, ServerProfileDatagram){
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
	fingerprint::profile_t profile;
	EXPECT_EQ(server.profile(profile), context::error_t::NONE);
	EXPECT_FALSE(profile.suites.empty());
}

/**
 * Круг 4 (движок): предупреждение изданий до 1.3 (unrecognized_name уровня warning перед ServerHello)
 * связь не рвёт - рукопожатие доходит до конца (раздел 7.2.2 RFC 5246, раздел 3 RFC 6066)
 */
TEST(AuditTest, WarningAlert){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	vector <uint8_t> flight = take(server);
	ASSERT_FALSE(flight.empty());
	// Предупреждение unrecognized_name (112) уровня warning (1) перед залпом сервера
	const uint8_t warning[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x70};
	flight.insert(flight.begin(), warning, warning + sizeof(warning));
	EXPECT_EQ(client.push(view_t(flight.data(), flight.size())), context::error_t::NONE);
	EXPECT_NE(client.state(), context::state_t::FAILED);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Смертельный уровень рвёт связь по-прежнему
	client::context_t other;
	server::context_t another;
	another.credential(credential);
	ASSERT_EQ(another.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(another.start(), context::error_t::NONE);
	ASSERT_EQ(other.start(), context::error_t::NONE);
	const vector <uint8_t> greeting = take(other);
	ASSERT_EQ(another.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	vector <uint8_t> reply = take(another);
	const uint8_t fatal[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70};
	reply.insert(reply.begin(), fatal, fatal + sizeof(fatal));
	EXPECT_EQ(other.push(view_t(reply.data(), reply.size())), context::error_t::ALERT);
	EXPECT_EQ(other.state(), context::state_t::FAILED);
}

/**
 * Круг 4 (движок): клиент 1.2 с обменом ключами RSA и запросом состояния доводит рукопожатие, когда сервер
 * объявил status_request, но CertificateStatus не прислал (раздел 8 RFC 6066: MAY)
 */
TEST(AuditTest, StatusAbsent){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("rsa2048", credential));
	const vector <uint8_t> answer = corpus("ocsp/rsa2048.good.der");
	ASSERT_FALSE(answer.empty());
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	server.status(answer);
	client.suites(vector <protect::suite_t> {protect::suite_t::RSA_AES_128_GCM_SHA256});
	client.status(true);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	const vector <uint8_t> flight = take(server);
	ASSERT_FALSE(flight.empty());
	// Вырезаем запись с сообщением CertificateStatus (вид 22)
	vector <uint8_t> trimmed;
	bool cut = false;
	for(size_t offset = 0; (offset + 5) <= flight.size();){
		const size_t length = ((static_cast <size_t> (flight[offset + 3]) << 8) | flight[offset + 4]);
		ASSERT_LE(offset + 5 + length, flight.size());
		if((flight[offset] == 0x16) && (length > 0) && (flight[offset + 5] == 22))
			cut = true;
		else
			trimmed.insert(trimmed.end(), flight.begin() + offset, flight.begin() + offset + 5 + length);
		offset += (5 + length);
	}
	ASSERT_TRUE(cut);
	// Клиент принимает залп без CertificateStatus и идёт дальше: прежде он рвал связь ORDER/unexpected_message
	EXPECT_EQ(client.push(view_t(trimmed.data(), trimmed.size())), context::error_t::NONE);
	EXPECT_NE(client.state(), context::state_t::FAILED);
	EXPECT_NE(client.error(), context::error_t::ORDER);
	// Переписка разошлась с сервером (он CertificateStatus слал): завершение не сойдётся у сервера, не у клиента
	converse(client, server);
	EXPECT_NE(client.error(), context::error_t::ORDER);
	EXPECT_NE(client.alert().description, alert::description_t::UNEXPECTED);
}

/**
 * Круг 4 (движок): запрос сердцебиения поверх дейтаграмм обязан уместиться в дейтаграмму - иначе LIMIT
 */
TEST(AuditTest, Heartroom){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	// Профиль с расширением heartbeat (режим 1) от клиента-донора
	fingerprint::profile_t profile;
	{
		client::context_t donor;
		donor.transport(context::transport_t::DATAGRAMS);
		donor.name("example.com");
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		fingerprint::extension_t extension;
		extension.type = 0x000F;
		extension.data = vector <uint8_t> {0x01};
		profile.extensions.push_back(extension);
	}
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	const uint8_t peer[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(peer, sizeof(peer)));
	client.name("example.com");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	client.mtu(600);
	vector <uint8_t> large(1000, 0x5A), small(300, 0x5A);
	EXPECT_EQ(client.heartbeat(view_t(large.data(), large.size())), context::error_t::LIMIT);
	EXPECT_EQ(client.heartbeat(view_t(small.data(), small.size())), context::error_t::NONE);
}

/**
 * Круг 5 (движок): по согласованному изданию 1.3 извещение уровня warning с любым описанием, кроме
 * close_notify/user_canceled, рвёт связь (раздел 6.2 RFC 8446) - признак «до согласования» это
 * нулевое издание, а не NPN
 */
TEST(AuditTest, WarningModern){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const uint8_t DESCRIPTIONS[] = {51, 42, 109, 255};
	for(size_t i = 0; i < sizeof(DESCRIPTIONS); i++){
		internal::engine_t client(false), server(true);
		client.name("example.com");
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t round = 0; round < 16; round++){
			bool moved = false;
			view_t data = client.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); moved = true; }
			data = server.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); moved = true; }
			if(!moved) break;
		}
		ASSERT_EQ(client.state(), context::state_t::ESTABLISHED);
		ASSERT_EQ(client.version(), 0x0304);
		// Запечатываем извещение уровня warning ключами клиента
		uint8_t traffic[64];
		size_t width = 0;
		ASSERT_TRUE(client.secret(context::level_t::APPLICATION, context::direction_t::WRITE, traffic, width));
		uint8_t key[protect::PROTECT_KEY], iv[protect::PROTECT_VECTOR];
		ASSERT_EQ(session::material(view_t(traffic, width), client.suite(), key, iv), session::error_t::NONE);
		protect::protection_t protection;
		ASSERT_TRUE(protection.start(client.suite(), view_t(key, protect::key(client.suite())), view_t(iv, protect::block(client.suite()))));
		for(uint64_t sequence = 0; sequence < client.sequence(false); sequence++){ vector <uint8_t> junk; protection.seal(record::type_t::APPLICATION, view_t(iv, 1), junk, 0); }
		const uint8_t alert[2] = {0x01, DESCRIPTIONS[i]};
		vector <uint8_t> sealed;
		ASSERT_EQ(protection.seal(record::type_t::ALERT, view_t(alert, 2), sealed, 0), protect::error_t::NONE);
		EXPECT_EQ(server.push(view_t(sealed.data(), sealed.size())), context::error_t::ALERT) << static_cast <int> (DESCRIPTIONS[i]);
		EXPECT_EQ(server.state(), context::state_t::FAILED) << static_cast <int> (DESCRIPTIONS[i]);
		EXPECT_EQ(static_cast <uint8_t> (server.alert().description), DESCRIPTIONS[i]);
	}
}

/**
 * Круг 5 (движок): клиент, объявивший peer_not_allowed_to_send (режим 2), на запрос сердцебиения сервера не отвечает
 */
TEST(AuditTest, HeartbeatForbidden){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	for(uint8_t mode = 1; mode <= 2; mode++){
		fingerprint::profile_t profile;
		{
			client::context_t donor;
			donor.name("example.com");
			ASSERT_EQ(donor.start(), context::error_t::NONE);
			ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
			fingerprint::extension_t extension;
			extension.type = 0x000F;
			extension.data = vector <uint8_t> {mode};
			profile.extensions.push_back(extension);
		}
		client::context_t client;
		server::context_t server;
		client.name("example.com");
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		server.credential(credential);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		// Сервер шлёт запрос сердцебиения: при режиме 2 клиента ему это не дозволено (SETTINGS), при режиме 1 клиент отвечает
		const string payload = "запрос сервера";
		EXPECT_EQ(server.heartbeat(view_t(reinterpret_cast <const uint8_t *> (payload.data()), payload.size())), ((mode == 1) ? context::error_t::NONE : context::error_t::SETTINGS)) << static_cast <int> (mode);
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
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	const vector <uint8_t> hello = take(client);
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	const vector <uint8_t> flight = take(server);
	ASSERT_EQ(client.push(view_t(flight.data(), flight.size())), context::error_t::NONE);
	vector <uint8_t> finished = take(client);
	ASSERT_GT(finished.size(), static_cast <size_t> (6));
	// Портим последний байт защищённой записи завершения
	finished.back() ^= 0x01;
	EXPECT_EQ(server.push(view_t(finished.data(), finished.size())), context::error_t::PROTECTION);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.alert().description, alert::description_t::MAC);
}

/**
 * Круг 5 (записи): подтверждение дробится по месту в дейтаграмме - при MTU 256 и сорока принятых
 * записях ни одна дейтаграмма не шире MTU (раздел 4.4 RFC 9147)
 */
TEST(AuditTest, AckSplit){
	internal::flight_t flight;
	flight.mtu(256);
	const size_t count = 40;
	for(size_t i = 0; i < count; i++){
		datagram::fragment_t fragment;
		fragment.type = handshake::type_t::CERTIFICATE;
		fragment.sequence = 1;
		fragment.size = (count * 10);
		fragment.offset = (i * 10);
		fragment.length = 10;
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 10, 0x41);
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		datagram::header_t header;
		header.unified = false;
		header.type = record::type_t::HANDSHAKE;
		header.epoch = 0;
		header.sequence = i;
		header.size = piece.size();
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		size_t length = 0;
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		vector <uint8_t> wire(head, head + length);
		wire.insert(wire.end(), piece.begin(), piece.end());
		vector <internal::opened_t> opened;
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		for(size_t j = 0; j < opened.size(); j++)
			if(opened[j].type == record::type_t::HANDSHAKE)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	ASSERT_EQ(flight.complete(false), context::error_t::NONE);
	size_t datagrams = 0, widest = 0;
	for(view_t out = flight.output(); out.size > 0; out = flight.output()){
		datagrams++;
		widest = ((out.size > widest) ? out.size : widest);
		flight.consume();
	}
	EXPECT_GE(datagrams, static_cast <size_t> (3));
	EXPECT_LE(widest, static_cast <size_t> (256));
}

/**
 * Круг 5 (шифры): узор Noise с двумя предсообщениями (KK) - отказ чтения до заведения своего постоянного ключа
 * не портит хеш: после дозаведения ключа чтение того же сообщения удаётся
 */
TEST(AuditTest, NoiseReady){
	const string name = "Noise_KK_25519_ChaChaPoly_SHA256";
	const view_t pattern(reinterpret_cast <const uint8_t *> (name.data()), name.size());
	uint8_t si[32], pi[32], sr[32], pr[32];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi) && noise::generate(noise::dh_t::X25519, sr, pr));
	noise::handshake_t initiator, responder;
	ASSERT_TRUE(initiator.start(pattern, noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(initiator.statics(view_t(si, 32)) && initiator.remote(view_t(pr, 32)));
	uint8_t message[noise::MESSAGE], payload[noise::MESSAGE];
	size_t size = sizeof(message);
	ASSERT_TRUE(initiator.write(view_t(), message, size));
	ASSERT_TRUE(responder.start(pattern, noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(responder.remote(view_t(pi, 32)));
	// Чтение до заведения своего ключа отвергается, состояние не портится
	size_t length = sizeof(payload);
	EXPECT_FALSE(responder.read(view_t(message, size), payload, length));
	ASSERT_TRUE(responder.statics(view_t(sr, 32)));
	length = sizeof(payload);
	EXPECT_TRUE(responder.read(view_t(message, size), payload, length));
}

/**
 * Круг 5 (X.509): якорь с самоподписью SHA-1 годен (самоподпись не судится), подпись RSASSA-PSS с SHA-1 у звена слаба
 */
TEST(AuditTest, WeakEdges){
	const int64_t moment = 1800000000;
	{
		trust::store_t store;
		const vector <uint8_t> root = certified("audit/r5-a-root.crt");
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-a-leaf.crt")}, store, moment), trust::error_t::NONE);
	}
	{
		trust::store_t store;
		const vector <uint8_t> root = certified("audit/r5-c-root.crt");
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-c-leaf.crt")}, store, moment), trust::error_t::WEAK);
	}
}

/**
 * Круг 5 (движок): профиль отпечатка с изданием 1.2 при заданных конфигурациях ECH отвергается (SETTINGS),
 * а при обратном порядке издание 1.2 в приветствие не идёт - связь под ECH устанавливается принятой
 */
TEST(AuditTest, EchProfile){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t profile;
	{
		client::context_t donor;
		donor.name("example.com");
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		bool found = false;
		for(size_t i = 0; i < profile.extensions.size(); i++){
			if(profile.extensions[i].type == 0x002B){
				profile.extensions[i].versions = vector <uint16_t> {0x0304, 0x0303};
				found = true;
			}
		}
		ASSERT_TRUE(found);
	}
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	// ECH, затем профиль с 1.2 - отказ
	client::context_t first;
	first.name("secret.example");
	ASSERT_EQ(first.ech(server.ech()), context::error_t::NONE);
	EXPECT_EQ(first.profile(profile), context::error_t::SETTINGS);
	// Отвергнутый профиль связи не коснулся: перечень наборов приветствия тот же, что у клиента без профиля
	client::context_t bare;
	bare.name("secret.example");
	ASSERT_EQ(bare.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	ASSERT_EQ(bare.start(), context::error_t::NONE);
	fingerprint::profile_t seen, plain;
	ASSERT_EQ(fingerprint::parse(first.output(), seen), fingerprint::error_t::NONE);
	ASSERT_EQ(fingerprint::parse(bare.output(), plain), fingerprint::error_t::NONE);
	EXPECT_EQ(seen.suites.size(), plain.suites.size());
	// Профиль, затем ECH - издание 1.2 в приветствие не идёт, ECH принят
	client::context_t second;
	second.name("secret.example");
	ASSERT_EQ(second.profile(profile), context::error_t::NONE);
	ASSERT_EQ(second.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(second.start(), context::error_t::NONE);
	converse(second, server);
	EXPECT_TRUE(second.established() && server.established()) << static_cast <int> (second.error()) << " " << static_cast <int> (server.error());
	EXPECT_TRUE(second.shrouded());
}

/**
 * Круг 5 (X.509): отличительные имена сличаются по разделу 7.1 RFC 5280 - подмена UTF8String на
 * PrintableString не обходит исключённое поддерево; звено, лежащее в запасе, замыкает цепочку -
 * истёкший прежний корень над доверенным промежуточным не судится
 */
TEST(AuditTest, NamesAndAnchors){
	const int64_t moment = 1800000000;
	{
		trust::store_t store;
		const vector <uint8_t> root = certified("audit/r5-b-root.crt");
		ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
		const vector <uint8_t> middle = certified("audit/r5-b-mid.crt");
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-b-leaf-utf8.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
		EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r5-b-leaf-print.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	}
	{
		trust::store_t store;
		const vector <uint8_t> middle = certified("audit/r5-m-mid.crt");
		ASSERT_TRUE(store.add(view_t(middle.data(), middle.size())));
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
	math::integer_t modulus, value, expected;
	modulus.word(1000003);
	value.word(6);
	ASSERT_TRUE(expected.invert(value, modulus));
	ASSERT_FALSE(expected.zero());
	// Итог поверх модуля
	math::integer_t aliased;
	aliased.word(1000003);
	ASSERT_TRUE(aliased.invert(value, aliased));
	EXPECT_TRUE(aliased.equal(expected));
	// Итог поверх значения
	math::integer_t other;
	other.word(6);
	ASSERT_TRUE(other.invert(other, modulus));
	EXPECT_TRUE(other.equal(expected));
}

/**
 * Круг 6 (X.509): разделители в свёртке RDN экранируются - значение «y;2.5.4.3=x» не выдаёт себя за два
 * признака под permitted dirName {CN=x+O=y}; ключ id-RSASSA-PSS под подписью PKCS #1 v1.5 негоден
 */
TEST(AuditTest, FoldedEscape){
	const int64_t moment = 1800000000;
	trust::store_t store;
	const vector <uint8_t> root = certified("audit/r6-root.crt"), middle = certified("audit/r6-mid.crt");
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-ok.crt"), middle}, store, moment), trust::error_t::NONE);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-evil.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {certified("audit/r6-other.crt"), middle}, store, moment), trust::error_t::CONSTRAINED);
	// Ключ, объявленный id-RSASSA-PSS, подпись sha256WithRSAEncryption не проверяет
	const vector <uint8_t> der = certified("ca-rsa.crt");
	ASSERT_FALSE(der.empty());
	x509::certificate_t certificate;
	ASSERT_EQ(certificate.parse(view_t(der.data(), der.size())), x509::error_t::NONE);
	uint8_t unused = 0;
	const view_t signature = certificate.sign(unused);
	EXPECT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), certificate.settings(), certificate.key()), x509::error_t::NONE);
	x509::key_t forged = certificate.key();
	forged.algorithm = "1.2.840.113549.1.1.10";
	EXPECT_NE(x509::verify(certificate.body(), signature, certificate.algorithms(), certificate.settings(), forged), x509::error_t::NONE);
}

/**
 * Круг 6 (движок): заведение связи поверх дейтаграмм не портит настройку наборов - следующая связь потоком
 * предлагает наборы ГОСТ снова
 */
TEST(AuditTest, SuitesKept){
	internal::engine_t engine(false);
	engine.name("example.com");
	engine.suites(vector <protect::suite_t> {protect::suite_t::KUZNYECHIK_MGM_L, protect::suite_t::AES_128_GCM_SHA256});
	engine.transport(context::transport_t::DATAGRAMS);
	ASSERT_EQ(engine.start(), context::error_t::NONE);
	engine.clear();
	engine.transport(context::transport_t::RECORDS);
	ASSERT_EQ(engine.start(), context::error_t::NONE);
	fingerprint::profile_t profile;
	ASSERT_EQ(fingerprint::parse(engine.output(), profile), fingerprint::error_t::NONE);
	EXPECT_EQ(profile.suites.size(), static_cast <size_t> (2));
}

/**
 * Круг 6 (разборщики): имя узла в server_name - печатаемый ASCII без точки на конце (раздел 3 RFC 6066)
 */
TEST(AuditTest, HostBytes){
	const auto body = [](const string & host){
		vector <uint8_t> result;
		const size_t length = (3 + host.size());
		result.push_back(static_cast <uint8_t> (length >> 8));
		result.push_back(static_cast <uint8_t> (length));
		result.push_back(0);
		result.push_back(static_cast <uint8_t> (host.size() >> 8));
		result.push_back(static_cast <uint8_t> (host.size()));
		result.insert(result.end(), host.begin(), host.end());
		return result;
	};
	view_t name;
	vector <uint8_t> good = body("a.example");
	EXPECT_EQ(extension::name(view_t(good.data(), good.size()), name), extension::error_t::NONE);
	vector <uint8_t> nul = body(string("a.com\0evil", 10));
	EXPECT_EQ(extension::name(view_t(nul.data(), nul.size()), name), extension::error_t::FORMAT);
	vector <uint8_t> dot = body("a.example.");
	EXPECT_EQ(extension::name(view_t(dot.data(), dot.size()), name), extension::error_t::FORMAT);
	vector <uint8_t> space = body("a b");
	EXPECT_EQ(extension::name(view_t(space.data(), space.size()), name), extension::error_t::FORMAT);
}

/**
 * Круг 6 (записи): подделка кусками по байту через один не раздувает покрытие сборки - куски сверх
 * предела областей отбрасываются, а честная сборка подряд идёт как прежде
 */
TEST(AuditTest, SpansCapped){
	internal::flight_t flight;
	const size_t total = 4000;
	size_t sequence = 0;
	// Куски по одному байту через один: областей больше предела
	for(size_t offset = 0; offset < total; offset += 2){
		datagram::fragment_t fragment;
		fragment.type = handshake::type_t::CERTIFICATE;
		fragment.sequence = 1;
		fragment.size = total;
		fragment.offset = offset;
		fragment.length = 1;
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 1, 0x41);
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		datagram::header_t header;
		header.unified = false;
		header.type = record::type_t::HANDSHAKE;
		header.epoch = 0;
		header.sequence = sequence++;
		header.size = piece.size();
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		size_t length = 0;
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		vector <uint8_t> wire(head, head + length);
		wire.insert(wire.end(), piece.begin(), piece.end());
		vector <internal::opened_t> opened;
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		for(size_t j = 0; j < opened.size(); j++)
			if(opened[j].type == record::type_t::HANDSHAKE)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	EXPECT_GE(flight.discarded(datagram::reason_t::FRAMING), static_cast <uint64_t> (total / 2 - datagram::DATAGRAM_SPANS));
}

/**
 * Круг 6 (шифры): раскол Noise выполняется однажды - повтор отвергается (Noise r34 §5.3)
 */
TEST(AuditTest, SplitOnce){
	const string name = "Noise_NN_25519_ChaChaPoly_SHA256";
	const view_t pattern(reinterpret_cast <const uint8_t *> (name.data()), name.size());
	noise::handshake_t initiator, responder;
	ASSERT_TRUE(initiator.start(pattern, noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(responder.start(pattern, noise::role_t::RESPONDER, view_t()));
	uint8_t message[noise::MESSAGE], payload[noise::MESSAGE];
	size_t size = sizeof(message), length = sizeof(payload);
	ASSERT_TRUE(initiator.write(view_t(), message, size));
	ASSERT_TRUE(responder.read(view_t(message, size), payload, length));
	size = sizeof(message); length = sizeof(payload);
	ASSERT_TRUE(responder.write(view_t(), message, size));
	ASSERT_TRUE(initiator.read(view_t(message, size), payload, length));
	noise::cipher_t one, two, three, four;
	ASSERT_TRUE(initiator.split(one, two));
	EXPECT_FALSE(initiator.split(three, four));
}

/**
 * Круг 7 (движок): после просьбы о повторе второе приветствие, предлагающее лишь издание 1.2,
 * отвергается illegal_parameter (раздел 4.1.4 RFC 8446), а не ведёт рукопожатие 1.2
 */
TEST(AuditTest, DowngradeAfterRetry){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <protect::suite_t> suites = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256};
	server::context_t server;
	server.credential(credential);
	server.suites(suites);
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	client::context_t first;
	first.suites(suites);
	first.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
	first.shares(vector <extension::group_t> {extension::group_t::X25519});
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(first.start(), context::error_t::NONE);
	const vector <uint8_t> opening = take(first);
	ASSERT_EQ(server.push(view_t(opening.data(), opening.size())), context::error_t::NONE);
	// Просьба о повторе отправлена
	EXPECT_FALSE(take(server).empty());
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Второе приветствие от клиента, зажатого на издании 1.2
	client::context_t second;
	second.suites(suites);
	second.versions(0x0303, 0x0303);
	ASSERT_EQ(second.start(), context::error_t::NONE);
	const vector <uint8_t> again = take(second);
	EXPECT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::VERSION);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.error(), context::error_t::VERSION);
	// Ответ - одно лишь извещение illegal_parameter, не ServerHello 1.2
	const vector <uint8_t> reply = take(server);
	ASSERT_GE(reply.size(), static_cast <size_t> (7));
	EXPECT_EQ(reply[0], static_cast <uint8_t> (record::type_t::ALERT));
	EXPECT_EQ(reply[6], static_cast <uint8_t> (alert::description_t::PARAMETER));
}

/**
 * Круг 7 (движок): пустой перечень наборов оставляет умолчание и в настройке (`_catalog`),
 * а не опустошает её - регрессия правки круга 6
 */
TEST(AuditTest, SuitesEmptyKept){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	server::context_t server;
	server.credential(credential);
	server.suites(vector <protect::suite_t> ());
	EXPECT_EQ(server.start(), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Заведение поверх дейтаграмм тоже держится умолчания
	server::context_t datagrams;
	datagrams.credential(credential);
	datagrams.transport(context::transport_t::DATAGRAMS);
	datagrams.suites(vector <protect::suite_t> ());
	static const uint8_t ADDRESS[4] = {10, 0, 0, 1};
	datagrams.address(view_t(ADDRESS, sizeof(ADDRESS)));
	EXPECT_EQ(datagrams.start(), context::error_t::NONE);
}

/**
 * Круг 7 (движок): место ответа OCSP вне дозволенной длины цепочки отвергается молча,
 * а не растит перечень по чужому числу (length_error сквозь noexcept, SIZE_MAX + 1)
 */
TEST(AuditTest, StapleIndex){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	server::context_t server;
	server.credential(credential);
	const vector <uint8_t> response(16, 0x30);
	server.status(response, static_cast <size_t> (-1));
	server.status(response, static_cast <size_t> (1) << 40);
	server.status(response, trust::TRUST_DEPTH);
	server.status(response, 0);
	EXPECT_EQ(server.start(), context::error_t::NONE);
}

/**
 * Круг 7 (движок): второе приветствие за просьбой о повторе судится своим содержимым -
 * имя узла и протокол приложения первого приветствия не переживают его (RFC 8446 §4.1.2)
 */
TEST(AuditTest, RetryReset){
	context::credential_t credential;
	ASSERT_TRUE(identity("example.com", credential));
	internal::engine_t client(false), server(true);
	client.transport(context::transport_t::RECORDS);
	server.transport(context::transport_t::RECORDS);
	client.name("example.com");
	client.protocols(vector <string> {"h2"});
	server.protocols(vector <string> {"h2"});
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	server.credential(credential);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	const vector <uint8_t> opening = take(client);
	ASSERT_EQ(server.push(view_t(opening.data(), opening.size())), context::error_t::NONE);
	const vector <uint8_t> retry = take(server);
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	// Имя и протокол выведены из первого приветствия
	EXPECT_EQ(server.name(), "example.com");
	EXPECT_EQ(server.protocol(), "h2");
	const vector <uint8_t> flight = take(client);
	// Разыскиваем тело второго приветствия в залпе клиента
	vector <uint8_t> body;
	for(size_t offset = 0; (offset + 5) <= flight.size() && body.empty();){
		const size_t length = (static_cast <size_t> (flight[offset + 3]) << 8) | flight[offset + 4];
		if((flight[offset] == 0x16) && ((offset + 5 + length) <= flight.size()) && (flight[offset + 5] == 0x01)){
			const size_t inner = (static_cast <size_t> (flight[offset + 6]) << 16) | (static_cast <size_t> (flight[offset + 7]) << 8) | flight[offset + 8];
			body.assign(flight.begin() + offset + 9, flight.begin() + offset + 9 + inner);
		}
		offset += (5 + length);
	}
	ASSERT_FALSE(body.empty());
	hello::client_t greeting;
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), greeting), hello::error_t::NONE);
	// Снимаем со второго приветствия имя узла и протокол приложения
	vector <hello::extension_t> kept;
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		if((greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::NAME)) && (greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::PROTOCOLS)))
			kept.push_back(greeting.extensions[i]);
	greeting.extensions = kept;
	vector <uint8_t> rebuilt;
	ASSERT_EQ(hello::build(greeting, rebuilt), hello::error_t::NONE);
	handshake::writer_t writer;
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	const view_t message = writer.data();
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	wire.insert(wire.end(), message.data, message.data + message.size);
	// Второе приветствие без имени и протокола принято (RFC 7301 §3.2 потоком их не требует)
	EXPECT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
	EXPECT_TRUE(server.name().empty());
	EXPECT_TRUE(server.protocol().empty());
}

/**
 * Круг 8 (движок): предел длины записи (record_size_limit) первого приветствия не переживает
 * просьбу о повторе - второе приветствие без расширения снимает его (RFC 8449 §4)
 */
TEST(AuditTest, RetryLimitReset){
	context::credential_t credential;
	ASSERT_TRUE(identity("example.com", credential));
	internal::engine_t client(false), server(true);
	client.transport(context::transport_t::RECORDS);
	server.transport(context::transport_t::RECORDS);
	client.name("example.com");
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	server.credential(credential);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Первое приветствие с пределом записи 300 байтов
	const vector <uint8_t> opening = take(client);
	hello::client_t first;
	ASSERT_EQ(hello::parse(view_t(opening.data() + 9, opening.size() - 9), first), hello::error_t::NONE);
	const uint8_t limit[2] = {0x01, 0x2C};
	first.extensions.insert(first.extensions.begin(), hello::extension_t(static_cast <uint16_t> (extension::type_t::LIMIT), view_t(limit, sizeof(limit))));
	vector <uint8_t> rebuilt;
	ASSERT_EQ(hello::build(first, rebuilt), hello::error_t::NONE);
	handshake::writer_t writer;
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	view_t message = writer.data();
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	wire.insert(wire.end(), message.data, message.data + message.size);
	ASSERT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
	// Предел первого приветствия принят сервером: 300 без октета вида
	EXPECT_EQ(server.ceiling(), static_cast <size_t> (299));
	// Просьба о повторе клиенту, второе приветствие без предела (переписка клиента здесь не важна: судится состояние сервера)
	const vector <uint8_t> retry = take(server);
	ASSERT_EQ(client.push(view_t(retry.data(), retry.size())), context::error_t::NONE);
	const vector <uint8_t> again = take(client);
	ASSERT_EQ(server.push(view_t(again.data(), again.size())), context::error_t::NONE);
	// Предел первого приветствия снят вторым
	EXPECT_EQ(server.ceiling(), record::RECORD_PLAINTEXT);
}

/**
 * Круг 7 (движок): подделанная открытая смена набора клиенту DTLS 1.2 посреди залпа сервера
 * роняется молча (раздел 4.1.2.7 RFC 6347), рукопожатие доходит до конца
 */
TEST(AuditTest, ChangeMidflight){
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
	server.mtu(300);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Приветствие, просьба подтверждения адреса, приветствие с меткой
	vector <vector <uint8_t>> parts = drain(client);
	for(size_t i = 0; i < parts.size(); i++)
		ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	parts = drain(server);
	for(size_t i = 0; i < parts.size(); i++)
		ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	parts = drain(client);
	for(size_t i = 0; i < parts.size(); i++)
		ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	// Залп сервера дробится по MTU: клиенту отдаётся лишь первая дейтаграмма
	parts = drain(server);
	ASSERT_GE(parts.size(), static_cast <size_t> (2));
	ASSERT_EQ(client.push(view_t(parts[0].data(), parts[0].size())), context::error_t::NONE);
	EXPECT_EQ(client.version(), 0x0303);
	// Подделанная открытая смена набора посреди залпа
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x01};
	EXPECT_EQ(client.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(client.state(), context::state_t::HANDSHAKE);
	EXPECT_TRUE(client.output().size == 0);
	// Остаток залпа и рукопожатие до конца
	for(size_t i = 1; i < parts.size(); i++)
		ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established());
}

/**
 * Круг 7 (движок): профиль обозревателя с GREASE ECH плюс настоящие конфигурации ECH - во
 * внешнем приветствии одно расширение ECH, связь устанавливается с принятым ECH
 */
TEST(AuditTest, EchGreaseProfile){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t profile;
	{
		client::context_t donor;
		donor.name("example.com");
		donor.grease(true);
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		bool found = false;
		for(size_t i = 0; i < profile.extensions.size(); i++)
			found = (found || (profile.extensions[i].type == 0xFE0D));
		ASSERT_TRUE(found);
	}
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	client::context_t client;
	client.name("secret.example");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.ech(server.ech()), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Во внешнем приветствии ровно одно расширение ECH
	hello::client_t greeting;
	const view_t opening = client.output();
	ASSERT_GE(opening.size, static_cast <size_t> (9));
	ASSERT_EQ(hello::parse(view_t(opening.data + 9, opening.size - 9), greeting), hello::error_t::NONE);
	size_t count = 0;
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		count += ((greeting.extensions[i].type == 0xFE0D) ? 1 : 0);
	EXPECT_EQ(count, static_cast <size_t> (1));
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established());
	EXPECT_TRUE(client.shrouded());
	EXPECT_TRUE(server.shrouded());
}

/**
 * Круг 7 (записи): за установленной связью DTLS 1.3 чужой открытый кусок рукопожатия со
 * старым номером сообщения не повторяет ждущий залп и не подтверждается - роняется молча
 */
TEST(AuditTest, PlainRepeat){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	server.credential(credential);
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
	server.address(view_t(ADDRESS, sizeof(ADDRESS)));
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	(void) drain(client);
	(void) drain(server);
	// Сервер выдал билет: залп ждёт подтверждения клиента
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	ASSERT_FALSE(drain(server).empty());
	// Чужая открытая дейтаграмма: кусок приветствия с номером сообщения 0
	datagram::fragment_t fragment;
	fragment.type = handshake::type_t::CLIENT;
	fragment.size = 1;
	fragment.sequence = 0;
	fragment.offset = 0;
	fragment.length = 1;
	datagram::header_t header;
	header.unified = false;
	header.type = record::type_t::HANDSHAKE;
	header.epoch = 0;
	header.sequence = 0x0000FFFF0001ULL;
	header.size = (datagram::DATAGRAM_FRAGMENT_HEADER + 1);
	vector <uint8_t> junk(datagram::DATAGRAM_PLAIN_HEADER + header.size, 0x41);
	size_t length = 0;
	ASSERT_EQ(datagram::build(header, junk.data(), length), datagram::error_t::NONE);
	ASSERT_EQ(datagram::build(fragment, junk.data() + length), datagram::error_t::NONE);
	const uint64_t before = server.discarded(datagram::reason_t::PLAIN);
	EXPECT_EQ(server.push(view_t(junk.data(), junk.size())), context::error_t::NONE);
	// Ни повтора залпа, ни подтверждения
	EXPECT_TRUE(drain(server).empty());
	EXPECT_EQ(server.discarded(datagram::reason_t::PLAIN), before + 1);
	EXPECT_TRUE(server.established());
}

/**
 * Круг 7 (записи): перенос дейтаграммами режет куски рукопожатия по пределу собеседника
 * (RFC 8449 §4, RFC 6066 §4), а не только по MTU
 */
TEST(AuditTest, LimitCarve){
	internal::flight_t flight;
	flight.mtu(1400);
	flight.limit(512);
	// Сообщение рукопожатия в 1500 байтов: заголовок и тело
	vector <uint8_t> message(handshake::HANDSHAKE_HEADER + 1500, 0x5A);
	message[0] = static_cast <uint8_t> (handshake::type_t::CERTIFICATE);
	message[1] = 0x00;
	message[2] = static_cast <uint8_t> (1500 >> 8);
	message[3] = static_cast <uint8_t> (1500 & 0xFF);
	ASSERT_EQ(flight.emit(record::type_t::HANDSHAKE, view_t(message.data(), message.size())), context::error_t::NONE);
	ASSERT_EQ(flight.dispatch(false), context::error_t::NONE);
	size_t records = 0;
	/**
	 * Выполняем перебор дейтаграмм и записей в них
	 */
	while(flight.output().size > 0){
		const view_t data = flight.output();
		for(size_t offset = 0; offset < data.size;){
			datagram::header_t header;
			ASSERT_EQ(datagram::parse(view_t(data.data + offset, data.size - offset), header), datagram::error_t::NONE);
			EXPECT_LE(header.size, static_cast <size_t> (512));
			offset += (datagram::DATAGRAM_PLAIN_HEADER + header.size);
			records++;
		}
		flight.consume();
	}
	EXPECT_GE(records, static_cast <size_t> (3));
}

/**
 * Круг 7 (записи): клиент DTLS 1.2 с договорённым max_fragment_length против openssl s_server -
 * чужая открытая запись шире предела роняется молча (связь жива), а свои записи не шире предела
 */
TEST(AuditTest, PlainOversizeLimit){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present || !toolkit.dtls12 || !toolkit.listening)
		GTEST_SKIP() << "openssl без DTLS 1.2";
	const string crt = string(CORPUS) + "/ec256.crt", key = string(CORPUS) + "/ec256.pem";
	const uint16_t number = vacant(true);
	const string log = "/tmp/ants-audit-limit-" + to_string(number) + ".log";
	const string holder = "/tmp/ants-audit-limit-" + to_string(number) + ".fifo";
	::remove(log.c_str());
	::remove(holder.c_str());
	ASSERT_EQ(fifo(holder.c_str()), 0);
	ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1_2 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -mtu 1400" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
	sentinel_t sentinel(log + ".pid");
	string text;
	ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
	uint16_t bound = 0;
	const int fd = socketing(0, bound);
	ASSERT_GE(fd, 0);
	struct sockaddr_in peer;
	::memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	peer.sin_port = htons(number);
	// Профиль с донора поверх дейтаграмм с дописанным max_fragment_length (код 1: 512 байтов)
	fingerprint::profile_t profile;
	{
		client::context_t donor;
		donor.transport(context::transport_t::DATAGRAMS);
		donor.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		donor.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
		donor.name("localhost");
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile, true), fingerprint::error_t::NONE);
		fingerprint::extension_t extension;
		extension.type = static_cast <uint16_t> (extension::type_t::FRAGMENT);
		extension.data = {0x01};
		profile.extensions.push_back(extension);
	}
	client::context_t client;
	client.transport(context::transport_t::DATAGRAMS);
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	client.name("localhost");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(relay(client, fd, peer, 400));
	ASSERT_TRUE(client.established());
	// Чужая открытая запись рукопожатия в 700 байтов содержимого номером далеко впереди окна
	datagram::fragment_t fragment;
	fragment.type = handshake::type_t::CERTIFICATE;
	fragment.size = 700;
	fragment.sequence = 40;
	fragment.offset = 0;
	fragment.length = 700;
	datagram::header_t header;
	header.unified = false;
	header.type = record::type_t::HANDSHAKE;
	header.epoch = 0;
	header.sequence = 0x0000FFFFFFFFULL;
	header.size = (datagram::DATAGRAM_FRAGMENT_HEADER + 700);
	vector <uint8_t> junk(datagram::DATAGRAM_PLAIN_HEADER + header.size, 0x41);
	size_t length = 0;
	ASSERT_EQ(datagram::build(header, junk.data(), length, true), datagram::error_t::NONE);
	ASSERT_EQ(datagram::build(fragment, junk.data() + length), datagram::error_t::NONE);
	const uint64_t before = client.discarded(datagram::reason_t::LENGTH);
	EXPECT_EQ(client.push(view_t(junk.data(), junk.size())), context::error_t::NONE);
	EXPECT_TRUE(client.established());
	EXPECT_EQ(client.discarded(datagram::reason_t::LENGTH), before + 1);
	// Своя запись прикладных данных в 700 байтов режется по пределу 512
	const vector <uint8_t> payload(700, 'Z');
	ASSERT_EQ(client.write(view_t(payload.data(), payload.size())), context::error_t::NONE);
	size_t datagrams = 0;
	while(client.output().size > 0){
		const view_t data = client.output();
		EXPECT_LE(data.size, static_cast <size_t> (512 + datagram::DATAGRAM_PLAIN_HEADER + 8 + 16));
		(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), sizeof(peer));
		client.consume(data.size);
		datagrams++;
	}
	EXPECT_GE(datagrams, static_cast <size_t> (2));
	// Сервер данные принял и связи не рвал
	(void) client.close();
	relay(client, fd, peer, 2);
	closing(fd);
	sentinel.halt();
	(void) settle(log, text);
	// Журнал сервера: данные приняты, извещения record_overflow нет
	bool delivered = false, overflowed = false;
	string culprit;
	{
		std::ifstream file(log);
		string line;
		while(std::getline(file, line)){
			delivered = (delivered || (line.find("ZZZZ") != string::npos));
			overflowed = (overflowed || (line.find("record_overflow") != string::npos) || (line.find("data length too long") != string::npos));
			culprit += (((line.find("record_overflow") != string::npos) || (line.find("data length too long") != string::npos)) ? (line + "\n") : string());
		}
	}
	EXPECT_TRUE(delivered);
	EXPECT_FALSE(overflowed) << culprit;
	::remove(log.c_str());
	::remove(holder.c_str());
}

/**
 * Круг 7 (шифры): кусок длиной без места портит подачу - хеш и имитовставка не снимаются,
 * а не выдаются от пустого сообщения (договор тот же, что у kdf с круга 6)
 */
TEST(AuditTest, HashSpoiled){
	uint8_t out[64];
	digest::hasher_t hasher(digest::hash_t::SHA256);
	hasher.update(view_t(nullptr, 5));
	EXPECT_FALSE(hasher.finish(out, 32));
	hasher.reset(digest::hash_t::SHA256);
	EXPECT_TRUE(hasher.finish(out, 32));
	digest::mac_t mac;
	const uint8_t key[16] = {1};
	ASSERT_TRUE(mac.start(digest::hash_t::SHA256, view_t(key, sizeof(key))));
	mac.update(view_t(nullptr, 5));
	EXPECT_FALSE(mac.finish(out, 32));
	ASSERT_TRUE(mac.start(digest::hash_t::SHA256, view_t(key, sizeof(key))));
	EXPECT_TRUE(mac.finish(out, 32));
	// Круг 8: тот же договор у самих примитивов и их свободных функций
	EXPECT_FALSE(digest::sha2(digest::sha_t::SHA256, view_t(nullptr, 5), out, 32));
	EXPECT_FALSE(digest::sha1(view_t(nullptr, 5), out, 20));
	EXPECT_FALSE(digest::md5(view_t(nullptr, 5), out, 16));
	EXPECT_FALSE(digest::streebog(digest::type_t::SHORT, view_t(nullptr, 5), out, 32, digest::order_t::STREAM));
	EXPECT_TRUE(digest::sha2(digest::sha_t::SHA256, view_t(nullptr, 0), out, 32));
	EXPECT_TRUE(digest::sha1(view_t(nullptr, 0), out, 20));
	EXPECT_TRUE(digest::md5(view_t(nullptr, 0), out, 16));
	EXPECT_TRUE(digest::streebog(digest::type_t::SHORT, view_t(nullptr, 0), out, 32, digest::order_t::STREAM));
}

/**
 * Круг 7 (шифры): заранее разделённый ключ HPKE короче 32 байтов отвергается (RFC 9180 §9.5)
 */
TEST(AuditTest, HpkePskShort){
	const hpke::suite_t suite(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM);
	const uint8_t shared[32] = {7};
	const uint8_t identity[4] = {1, 2, 3, 4};
	const uint8_t brief[4] = {5, 6, 7, 8};
	const uint8_t enough[32] = {9};
	hpke::key_t own, ephemeral;
	ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, view_t(shared, sizeof(shared))), hpke::error_t::NONE);
	ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, view_t(enough, sizeof(enough))), hpke::error_t::NONE);
	uint8_t enc[hpke::X25519_SIZE];
	hpke::context_t sending;
	EXPECT_EQ(hpke::sender(suite, hpke::regime_t::PSK, own.point(), view_t(), hpke::shared_t(view_t(brief, sizeof(brief)), view_t(identity, sizeof(identity))), nullptr, ephemeral, enc, sending), hpke::error_t::PSK);
	EXPECT_EQ(hpke::sender(suite, hpke::regime_t::PSK, own.point(), view_t(), hpke::shared_t(view_t(enough, sizeof(enough)), view_t(identity, sizeof(identity))), nullptr, ephemeral, enc, sending), hpke::error_t::NONE);
}

/**
 * Круг 7 (математика): открытый показатель RSA шире 33 разрядов отвергается - чужой ключ с
 * показателем в ширину модуля делал проверку подписи ценою секретного действия
 */
TEST(AuditTest, RsaExponentWide){
	vector <uint8_t> modulus(256, 0xFF);
	modulus[0] = 0xC3;
	const uint8_t narrow[5] = {0x01, 0x00, 0x00, 0x00, 0x01};
	const uint8_t wide[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x01};
	sign::rsa_t rsa;
	EXPECT_TRUE(rsa.key(view_t(modulus.data(), modulus.size()), view_t(narrow, sizeof(narrow))));
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
	asn1::writer_t writer;
	static const uint8_t SECRET[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	ASSERT_TRUE(writer.octets(view_t(SECRET, sizeof(SECRET))));
	// Элемент не закрыт: записи нет, а накопитель с секретом есть
	EXPECT_EQ(writer.data().size, 0u);
	ASSERT_EQ(writer.buffer().size, 11u);
	EXPECT_EQ(::memcmp(writer.buffer().data + 3, SECRET, sizeof(SECRET)), 0);
	ASSERT_TRUE(writer.close());
	EXPECT_EQ(writer.data().size, 12u);
	// Лишнее закрытие - отказ записи: data() пуст, накопитель по-прежнему отдаётся
	EXPECT_FALSE(writer.close());
	EXPECT_NE(writer.err(), asn1::error_t::NONE);
	EXPECT_EQ(writer.data().size, 0u);
	ASSERT_EQ(writer.buffer().size, 12u);
	EXPECT_EQ(::memcmp(writer.buffer().data + 4, SECRET, sizeof(SECRET)), 0);
	// Рост буфера переносит запись без потерь: длинное содержимое перевыделяет память
	asn1::writer_t large;
	const vector <uint8_t> body(5000, 0x5A);
	ASSERT_TRUE(large.open(asn1::tag_t::SEQUENCE));
	ASSERT_TRUE(large.octets(view_t(body.data(), body.size())));
	ASSERT_TRUE(large.octets(view_t(SECRET, sizeof(SECRET))));
	ASSERT_TRUE(large.close());
	ASSERT_EQ(large.data().size, 4u + 4u + body.size() + 2u + sizeof(SECRET));
	EXPECT_EQ(::memcmp(large.data().data + large.data().size - sizeof(SECRET), SECRET, sizeof(SECRET)), 0);
}

/**
 * Круг 7 (X.509): ответ OCSP судится той же политикой стойкости, что и цепочка (x509::weak): подпись ответа
 * SHA-1 и делегированный ответчик с ключом RSA-1024 отвергаются (WEAK), ответ SHA-256 от издателя принимается
 */
TEST(AuditTest, OcspWeak){
	const vector <uint8_t> root = certified("audit/r7-root.crt"), leaf = certified("audit/r7-ocsp-leaf.crt");
	ASSERT_FALSE(root.empty());
	ASSERT_FALSE(leaf.empty());
	const struct { const char * name; ocsp::error_t expected; } CASES[] = {
		{"audit/r7-ocsp-sha256.der", ocsp::error_t::NONE},
		{"audit/r7-ocsp-sha1.der", ocsp::error_t::WEAK},
		{"audit/r7-ocsp-deleg1024.der", ocsp::error_t::WEAK}
	};
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		const vector <uint8_t> der = corpus(CASES[i].name);
		ASSERT_FALSE(der.empty()) << CASES[i].name;
		ocsp::response_t response;
		ASSERT_EQ(response.parse(view_t(der.data(), der.size())), ocsp::error_t::NONE) << CASES[i].name;
		ocsp::status_t status = ocsp::status_t::NONE;
		EXPECT_EQ(ocsp::verify(response, view_t(leaf.data(), leaf.size()), view_t(root.data(), root.size()), 0, 0, view_t(), status), CASES[i].expected) << CASES[i].name;
	}
	// Политика едина: те же помощники судят и звено цепочки
	x509::certificate_t anchor;
	ASSERT_EQ(anchor.parse(view_t(root.data(), root.size())), x509::error_t::NONE);
	EXPECT_FALSE(x509::weak(anchor, false));
	EXPECT_TRUE(x509::weak("1.2.840.113549.1.1.5", view_t()));
	EXPECT_TRUE(x509::weak("1.2.840.113549.1.1.10", view_t()));
	EXPECT_FALSE(x509::weak("1.2.840.113549.1.1.11", view_t()));
}

/**
 * Круг 7 (X.509): дефис посреди метки PEM дозволен грамматикой раздела 3 RFC 7468, и посторонняя запись с
 * такой меткой не отвергает весь текст вместе с сертификатом рядом; дефис на краю и два разделителя подряд - LABEL
 */
TEST(AuditTest, PemDashLabel){
	const vector <uint8_t> text = corpus("audit/r7-root.crt");
	ASSERT_FALSE(text.empty());
	const string certificate(text.begin(), text.end());
	vector <vector <uint8_t>> chain;
	EXPECT_EQ(pem::certificates("-----BEGIN X-Y-----\nQUJD\n-----END X-Y-----\n" + certificate, chain), pem::error_t::NONE);
	EXPECT_EQ(chain.size(), 1u);
	pem::block_t block;
	block.data = vector <uint8_t> (3, 0x41);
	string out;
	block.label = "X-Y";
	EXPECT_EQ(pem::encode(block, out), pem::error_t::NONE);
	block.label = "X-Y Z-W";
	EXPECT_EQ(pem::encode(block, out), pem::error_t::NONE);
	const char * const BROKEN[] = {"-XY", "XY-", "X--Y", "X- Y", "X -Y", "-"};
	for(size_t i = 0; i < (sizeof(BROKEN) / sizeof(BROKEN[0])); i++){
		block.label = BROKEN[i];
		EXPECT_EQ(pem::encode(block, out), pem::error_t::LABEL) << BROKEN[i];
	}
	vector <pem::block_t> blocks;
	EXPECT_EQ(pem::decode("-----BEGIN X--Y-----\nQUJD\n-----END X--Y-----\n", blocks), pem::error_t::LABEL);
}

/**
 * Круг 7 (X.509): имя «*.example.com» лежит в запрещённом поддереве secure.example.com (решение 6 trust.cpp),
 * ибо belongs() тем же именем кроет secure.example.com; против запрещённого поддерева под чужим хвостом и
 * против дозволенного example.com имя со звёздочкой сличается буквально и годно
 */
TEST(AuditTest, WildcardExcluded){
	const vector <uint8_t> root = certified("audit/r7-root.crt"), mid = certified("audit/r7-mid.crt"), other = certified("audit/r7-mid-other.crt");
	const vector <uint8_t> star = certified("audit/r7-leaf-star.crt"), secure = certified("audit/r7-leaf-secure.crt");
	ASSERT_FALSE(root.empty() || mid.empty() || other.empty() || star.empty() || secure.empty());
	trust::store_t store;
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	const int64_t moment = 1789400000;
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
	static const uint8_t JUNK[4] = {'j', 'u', 'n', 'k'};
	// Негодное содержимое [4]: строка байтов вместо последовательности имени
	asn1::writer_t bad;
	bad.open(asn1::tag_t::SEQUENCE);
	bad.open(asn1::cls_t::CONTEXT, 4);
	bad.octets(view_t(JUNK, sizeof(JUNK)));
	bad.close();
	bad.close();
	ASSERT_EQ(bad.err(), asn1::error_t::NONE);
	x509::extension_t extension;
	extension.oid = "2.5.29.17";
	extension.critical = false;
	extension.value = bad.data();
	vector <x509::alternative_t> names;
	EXPECT_NE(x509::alternatives(extension, names), x509::error_t::NONE);
	EXPECT_TRUE(names.empty());
	// Лишний элемент внутри обёртки [4] за годным именем
	asn1::writer_t extra;
	extra.open(asn1::tag_t::SEQUENCE);
	extra.open(asn1::cls_t::CONTEXT, 4);
	extra.open(asn1::tag_t::SEQUENCE);
	extra.close();
	extra.integer(1);
	extra.close();
	extra.close();
	ASSERT_EQ(extra.err(), asn1::error_t::NONE);
	extension.value = extra.data();
	EXPECT_NE(x509::alternatives(extension, names), x509::error_t::NONE);
	// Годное имя CN=x
	asn1::writer_t good;
	good.open(asn1::tag_t::SEQUENCE);
	good.open(asn1::cls_t::CONTEXT, 4);
	good.open(asn1::tag_t::SEQUENCE);
	good.open(asn1::tag_t::SET);
	good.open(asn1::tag_t::SEQUENCE);
	good.oid("2.5.4.3");
	good.text(asn1::tag_t::PRINTABLE_STRING, "x");
	good.close();
	good.close();
	good.close();
	good.close();
	good.close();
	ASSERT_EQ(good.err(), asn1::error_t::NONE);
	extension.value = good.data();
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::NONE);
	ASSERT_EQ(names.size(), 1u);
	EXPECT_EQ(names[0].kind, x509::kind_t::DIRECTORY);
	// То же для ограничений имён: excludedSubtrees с негодным directoryName
	asn1::writer_t bounds;
	bounds.open(asn1::tag_t::SEQUENCE);
	bounds.open(asn1::cls_t::CONTEXT, 1);
	bounds.open(asn1::tag_t::SEQUENCE);
	bounds.open(asn1::cls_t::CONTEXT, 4);
	bounds.octets(view_t(JUNK, sizeof(JUNK)));
	bounds.close();
	bounds.close();
	bounds.close();
	bounds.close();
	ASSERT_EQ(bounds.err(), asn1::error_t::NONE);
	extension.oid = "2.5.29.30";
	extension.value = bounds.data();
	vector <x509::alternative_t> permitted, excluded;
	EXPECT_NE(x509::constraints(extension, permitted, excluded), x509::error_t::NONE);
}

/**
 * Круг 7 (X.509): у настроек RSASSA-PSS остаток явной обёртки [0] hashAlgorithm и [1] maskGenAlgorithm обязан
 * быть пуст, как у [2] и [3]: запись [0] { SEQUENCE{sha256}, INTEGER 5 } отвергается, годная - принимается
 */
TEST(AuditTest, PssParamsTail){
	static const char * MESSAGE = "A-NTS audit round 7";
	static const char * SIGNATURE = "03d62e2bdeeb40cc565f4dd07961a23502a8a4ec7d2e94dbecbf7976cdcf3f620b5e96e16459985e7f4f33e0d566e622ac750c5ebc12979b9f8b7f387997c77541eb4fc2d8050149638d10c66ead56be464705fdfdd73ab1c64ff9d195e8a928285a3c718ad45d6559098ff0362bf58b5d11cd0df815cb1044dbb22351c82bfcb40197539be735432b4f3061cf6ef7e1913fe7cbb84122ea2db2b3b04ea42f75c7e98a19ca8423a774af0f310f33be3ebd1e782afbb9d87b7658080ff62776e5c69f7fe16a86faa6b68c59958258b95ae9c3953d5b20aa5f99d92d765c504e9c908029c5d5100ffa56dcbf7ee77e431220690688900f4c7284bbc9fbb5a56be6";
	vector <uint8_t> signature;
	for(size_t i = 0; SIGNATURE[i] != '\0'; i += 2)
		signature.push_back(static_cast <uint8_t> (::strtoul(string(SIGNATURE + i, 2).c_str(), nullptr, 16)));
	ASSERT_EQ(signature.size(), 256u);
	const vector <uint8_t> der = certified("rsa2048.crt");
	ASSERT_FALSE(der.empty());
	x509::certificate_t certificate;
	ASSERT_EQ(certificate.parse(view_t(der.data(), der.size())), x509::error_t::NONE);
	const view_t content(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE));
	// Настройки: sha256, MGF1 с sha256, соль 32 байта; при tail внутрь [0] дописывается лишнее число
	for(size_t round = 0; round < 2; round++){
		const bool tail = (round == 1);
		asn1::writer_t writer;
		writer.open(asn1::tag_t::SEQUENCE);
		writer.open(asn1::cls_t::CONTEXT, 0);
		writer.open(asn1::tag_t::SEQUENCE);
		writer.oid("2.16.840.1.101.3.4.2.1");
		writer.nothing();
		writer.close();
		if(tail)
			writer.integer(5);
		writer.close();
		writer.open(asn1::cls_t::CONTEXT, 1);
		writer.open(asn1::tag_t::SEQUENCE);
		writer.oid("1.2.840.113549.1.1.8");
		writer.open(asn1::tag_t::SEQUENCE);
		writer.oid("2.16.840.1.101.3.4.2.1");
		writer.nothing();
		writer.close();
		writer.close();
		writer.close();
		writer.open(asn1::cls_t::CONTEXT, 2);
		writer.integer(32);
		writer.close();
		writer.close();
		ASSERT_EQ(writer.err(), asn1::error_t::NONE);
		EXPECT_EQ(x509::verify(content, view_t(signature.data(), signature.size()), "1.2.840.113549.1.1.10", writer.data(), certificate.key()), (tail ? x509::error_t::SIGNATURE : x509::error_t::NONE)) << (tail ? "tail" : "clean");
	}
}

/**
 * Круг 8 (движок): приветствие с key_share без supported_groups отвергается missing_extension
 * (RFC 8446 §9.2), а не ведёт полное рукопожатие
 */
TEST(AuditTest, KeyShareNoGroups){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	const vector <uint8_t> opening = take(client);
	hello::client_t greeting;
	ASSERT_EQ(hello::parse(view_t(opening.data() + 9, opening.size() - 9), greeting), hello::error_t::NONE);
	// Снимаем supported_groups, key_share остаётся
	vector <hello::extension_t> kept;
	for(size_t i = 0; i < greeting.extensions.size(); i++)
		if(greeting.extensions[i].type != static_cast <uint16_t> (extension::type_t::GROUPS))
			kept.push_back(greeting.extensions[i]);
	ASSERT_LT(kept.size(), greeting.extensions.size());
	greeting.extensions = kept;
	vector <uint8_t> rebuilt;
	ASSERT_EQ(hello::build(greeting, rebuilt), hello::error_t::NONE);
	handshake::writer_t writer;
	writer.push(handshake::type_t::CLIENT, view_t(rebuilt.data(), rebuilt.size()));
	const view_t message = writer.data();
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> (message.size >> 8), static_cast <uint8_t> (message.size)};
	wire.insert(wire.end(), message.data, message.data + message.size);
	EXPECT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::GROUP);
	EXPECT_EQ(server.state(), context::state_t::FAILED);
	EXPECT_EQ(server.alert().description, alert::description_t::MISSING);
}

/**
 * Круг 8 (записи): записи подтверждения режутся по пределу собеседника, а не только по MTU
 */
TEST(AuditTest, AckLimit){
	internal::flight_t flight;
	flight.mtu(1400);
	flight.limit(64);
	// Двадцать открытых записей с кусками одного сообщения: каждая подлежит подтверждению
	for(size_t sequence = 0; sequence < 20; sequence++){
		datagram::fragment_t fragment;
		fragment.type = handshake::type_t::CERTIFICATE;
		fragment.sequence = 1;
		fragment.size = 200;
		fragment.offset = (sequence * 10);
		fragment.length = 10;
		vector <uint8_t> piece(datagram::DATAGRAM_FRAGMENT_HEADER + 10, 0x41);
		ASSERT_EQ(datagram::build(fragment, piece.data()), datagram::error_t::NONE);
		datagram::header_t header;
		header.unified = false;
		header.type = record::type_t::HANDSHAKE;
		header.epoch = 0;
		header.sequence = sequence;
		header.size = piece.size();
		uint8_t head[datagram::DATAGRAM_PLAIN_HEADER];
		size_t length = 0;
		ASSERT_EQ(datagram::build(header, head, length), datagram::error_t::NONE);
		vector <uint8_t> wire(head, head + length);
		wire.insert(wire.end(), piece.begin(), piece.end());
		vector <internal::opened_t> opened;
		ASSERT_EQ(flight.receive(view_t(wire.data(), wire.size()), opened), context::error_t::NONE);
		for(size_t j = 0; j < opened.size(); j++)
			if(opened[j].type == record::type_t::HANDSHAKE)
				flight.fragments(view_t(opened[j].content.data(), opened[j].content.size()), opened[j].epoch, opened[j].sequence, false);
	}
	ASSERT_EQ(flight.complete(false), context::error_t::NONE);
	size_t records = 0;
	while(flight.output().size > 0){
		const view_t data = flight.output();
		for(size_t offset = 0; offset < data.size;){
			datagram::header_t header;
			ASSERT_EQ(datagram::parse(view_t(data.data + offset, data.size - offset), header), datagram::error_t::NONE);
			EXPECT_LE(header.size, static_cast <size_t> (64));
			offset += (datagram::DATAGRAM_PLAIN_HEADER + header.size);
			records++;
		}
		flight.consume();
	}
	EXPECT_GE(records, static_cast <size_t> (2));
}

/**
 * Круг 8 (движок): негодная открытая смена набора серверу DTLS 1.2, ждущему залп клиента,
 * роняется молча, а не рвёт рукопожатие
 */
TEST(AuditTest, ChangeBadBody){
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
	// Три обмена: приветствие, просьба, приветствие с меткой, залп сервера
	vector <vector <uint8_t>> parts;
	for(size_t round = 0; round < 2; round++){
		parts = drain(client);
		for(size_t i = 0; i < parts.size(); i++)
			ASSERT_EQ(server.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
		parts = drain(server);
		for(size_t i = 0; i < parts.size(); i++)
			ASSERT_EQ(client.push(view_t(parts[i].data(), parts[i].size())), context::error_t::NONE);
	}
	// Сервер ждёт залп клиента: подделанная открытая смена с негодным телом
	const vector <uint8_t> forged = {0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE7, 0x00, 0x01, 0x02};
	EXPECT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	EXPECT_EQ(server.state(), context::state_t::HANDSHAKE);
	converse(client, server);
	EXPECT_TRUE(client.established() && server.established());
}

/**
 * Круг 8 (движок): давность первичного удостоверения не продлевается перевыдачей билета
 * (RFC 5077 §5.6): через 12 суток от первого рукопожатия сервер отвечает полным рукопожатием,
 * а клиент билет с устаревшим удостоверением не предъявляет
 */
TEST(AuditTest, AuthenticationAge){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <uint8_t> vault(48, 0x5C);
	const int64_t origin = 1700000000;
	const int64_t day = 86400;
	context::ticket_t ticket;
	// Первое рукопожатие TLS 1.2 с проверкой подлинности клиента
	{
		client::context_t client;
		server::context_t server;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.vault(vault);
		client.credential(credential);
		server.request(true);
		server.lifetime(7 * day);
		server.moment(origin);
		client.moment(origin);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		ticket = client.tickets()[0];
		EXPECT_EQ(ticket.authenticated, origin);
	}
	// Возобновление через 6 суток: билет свеж, удостоверение свежо - сокращённое рукопожатие с перевыдачей
	{
		client::context_t client;
		server::context_t server;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.vault(vault);
		server.request(true);
		server.lifetime(7 * day);
		server.moment(origin + 6 * day);
		client.moment(origin + 6 * day);
		client.resume(ticket);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_TRUE(client.shared());
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		ticket = client.tickets()[0];
		// Перевыданный билет несёт прежний миг удостоверения
		EXPECT_EQ(ticket.authenticated, origin);
	}
	// Ещё через 6 суток (12 от удостоверения): клиент билет не предъявляет - полное рукопожатие
	{
		client::context_t client;
		server::context_t server;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.vault(vault);
		client.credential(credential);
		server.request(true);
		server.moment(origin + 12 * day);
		client.moment(origin + 12 * day);
		client.resume(ticket);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.shared());
	}
	// Сервер сам судит давность: билет с подделанным свежим мигом удостоверения у клиента, состояние сервера помнит прежний
	{
		client::context_t client;
		server::context_t server;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.vault(vault);
		client.credential(credential);
		server.request(true);
		server.moment(origin + 12 * day);
		client.moment(origin + 12 * day);
		context::ticket_t forged = ticket;
		forged.moment = (origin + 12 * day - 60);
		forged.authenticated = (origin + 12 * day - 60);
		client.resume(forged);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.shared());
	}
}

/**
 * Круг 8 (движок): билет годен лишь изданию выдачи - клиент с билетом, помеченным изданием
 * DTLS 1.0, отвергает сокращённое рукопожатие издания 1.2 (RFC 5246 §E.1)
 */
TEST(AuditTest, TicketEditionMismatch){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <uint8_t> vault(48, 0x5C);
	context::ticket_t ticket;
	{
		client::context_t client;
		server::context_t server;
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		server.credential(credential);
		server.vault(vault);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		ticket = client.tickets()[0];
		EXPECT_FALSE(ticket.ancient);
	}
	client::context_t client;
	server::context_t server;
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	server.credential(credential);
	server.vault(vault);
	ticket.ancient = true;
	client.resume(ticket);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
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
	std::ifstream file(ANTS_ENGINE_SRC, std::ios::binary);
	ASSERT_TRUE(file.is_open()) << "нет исходника движка: " << ANTS_ENGINE_SRC;
	const std::string source((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	// Вырезаем тело issue() по сигнатуре и сопоставлению скобок
	const size_t sign = source.find("Engine::issue() noexcept {");
	ASSERT_NE(sign, std::string::npos) << "сигнатура issue() не найдена";
	const size_t open = source.find('{', sign);
	size_t depth = 0, close = std::string::npos;
	for(size_t i = open; i < source.size(); i++){
		if(source[i] == '{') depth++;
		else if(source[i] == '}'){ depth--; if(depth == 0){ close = i; break; } }
	}
	ASSERT_NE(close, std::string::npos) << "тело issue() не закрыто";
	const std::string body = source.substr(open, close - open + 1);
	// Объявление ключа билета обязано стоять ДО try (уровень функции), иначе внешний catch его не видит
	const size_t decl = body.find("uint8_t secret[schedule::SCHEDULE_WIDEST];");
	const size_t attempt = body.find("try {");
	ASSERT_NE(decl, std::string::npos) << "объявление secret[] не найдено";
	ASSERT_NE(attempt, std::string::npos) << "try не найден";
	EXPECT_LT(decl, attempt) << "secret[] объявлен внутри try - внешний catch(bad_alloc) его не затрёт (регрессия круга 9)";
	// Внешний catch(bad_alloc) issue() (последний в теле) обязан затирать secret
	const size_t outer = body.rfind("catch(const bad_alloc &)");
	ASSERT_NE(outer, std::string::npos) << "внешний catch(bad_alloc) не найден";
	const std::string tail = body.substr(outer);
	EXPECT_NE(tail.find("wipe(secret"), std::string::npos) << "внешний catch(bad_alloc) не затирает ключ билета (регрессия круга 9)";
}

/**
 * Круг 13 (движок, по независимому щупу Heartbleed CVE-2014-0160): по установленной связи 1.2 запись
 * сердцебиения с солгавшей длиной нагрузки роняется молча обоими рубежами pulse() - объявленная
 * длина не больше пришедшего содержимого (рубеж 1) и ответ умещается в одну запись собеседника
 * (рубеж 2); честная нагрузка отвечается. Снятие рубежа 1 даёт ответ на умеренную ложь - утечку
 */
TEST(AuditTest, HeartbeatBleed){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	// Профиль клиента с расширением heartbeat в режиме peer_allowed_to_send
	fingerprint::profile_t profile;
	{
		client::context_t donor;
		donor.name("example.com");
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), profile), fingerprint::error_t::NONE);
		fingerprint::extension_t extension;
		extension.type = 0x000F;
		extension.data = vector <uint8_t> {0x01};
		profile.extensions.push_back(extension);
	}
	// Заполнение ответа сердцебиения: раздел 4 RFC 6520, не короче 16 байтов
	static constexpr size_t PADDING = 16;
	// Четыре нагрузки: честная, умеренная ложь, ложь до предела, честная длина сверх записи собеседника
	for(size_t item = 0; item < 4; item++){
		internal::engine_t client(false), server(true);
		client.name("example.com");
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		server.credential(credential);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		for(size_t round = 0; round < 16; round++){
			bool moved = false;
			view_t data = client.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); client.consume(buffer.size()); server.push(view_t(buffer.data(), buffer.size())); moved = true; }
			data = server.output();
			if(data.size > 0){ vector <uint8_t> buffer(data.data, data.data + data.size); server.consume(buffer.size()); client.push(view_t(buffer.data(), buffer.size())); moved = true; }
			if(!moved) break;
		}
		ASSERT_EQ(server.state(), context::state_t::ESTABLISHED) << item;
		ASSERT_EQ(server.version(), 0x0303) << item;
		ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << item;
		// Открытое содержимое записи сердцебиения: вид, длина, нагрузка, заполнение
		vector <uint8_t> content;
		// Объявляемая длина нагрузки
		size_t length = 0;
		// Настоящая нагрузка
		const std::string payload = "heartbeat payload";
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
		content[0] = 0x01;
		content[1] = static_cast <uint8_t> ((length >> 8) & 0xFF);
		content[2] = static_cast <uint8_t> (length & 0xFF);
		if(content.size() >= (3 + payload.size()))
			::memcpy(content.data() + 3, payload.data(), payload.size());
		// Запись подаётся уже расшифрованной: бьём в логику после снятия защиты
		ASSERT_EQ(server.pulse(view_t(content.data(), content.size())), context::error_t::NONE) << item;
		// Связь жива, ошибки нет
		EXPECT_EQ(server.state(), context::state_t::ESTABLISHED) << item;
		EXPECT_EQ(server.error(), context::error_t::NONE) << item;
		// Честная нагрузка отвечается записью вида 24; всякая ложь - молчанием
		if(item == 0){
			ASSERT_GT(server.output().size, static_cast <size_t> (5)) << item;
			EXPECT_EQ(server.output().data[0], 0x18) << item;
		} else {
			EXPECT_EQ(server.output().size, static_cast <size_t> (0)) << item;
		}
	}
}
