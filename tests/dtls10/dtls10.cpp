/**
 * @file dtls10.cpp
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
 * @brief Исходный файл проверок издания DTLS 1.0 (RFC 4347 поверх TLS 1.1): PRF на MD5 ⊕ SHA-1,
 *        подписи без схем, наборы CBC-SHA1, издание 0xFEFF в записях, выбор издания, подлинность
 *        клиента, билеты, чужой эталон openssl -dtls1 и пайок памяти
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
#include <sys/stat.h>
#include <sockets.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <alert/alert.hpp>
#include <digest/hmac.hpp>
#include <digest/hash.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <protect/protect.hpp>
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
	 * Издания протокола в кодах TLS
	 */
	static constexpr uint16_t TLS11 = 0x0302, TLS12 = 0x0303;
	/**
	 * Адрес собеседника для метки возврата состояния сервера
	 */
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
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
	 * @brief Метод переноса дейтаграмм одной стороны другой
	 *
	 * @param from сторона, чьи дейтаграммы забираются
	 * @param to   сторона, которой они подаются
	 *
	 * @return     признак того, что дейтаграммы переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to) noexcept {
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			while(from.output().size > 0){
				const view_t data = from.output();
				const vector <uint8_t> datagram(data.data, data.data + data.size);
				from.consume(data.size);
				to.push(view_t(datagram.data(), datagram.size()));
				moved = true;
			}
		/**
		 * Если памяти под перенос не хватило
		 */
		} catch(const bad_alloc &) {
			return false;
		}
		return moved;
	}
	/**
	 * @brief Метод проведения обмена дейтаграммами сторон связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем перенос дейтаграмм, пока сторонам есть что сказать
		 */
		for(size_t round = 0; round < 64; round++){
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				break;
			bool moved = carry(client, server);
			moved = (carry(server, client) || moved);
			if(moved)
				continue;
			bool fired = false;
			if(client.timeout() > 0){
				client.elapsed();
				fired = true;
			}
			if(server.timeout() > 0){
				server.elapsed();
				fired = true;
			}
			if(!fired)
				break;
		}
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
		const string request = "ping from the client over DTLS 1.0";
		const string response = "pong from the server over DTLS 1.0";
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			return false;
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (response.data()), response.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		vector <uint8_t> received;
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			return false;
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != response))
			return false;
		return true;
	}
	/**
	 * @brief Метод настройки сторон поверх дейтаграмм с пределами изданий
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param credential подлинность сервера
	 * @param lowest     нижний предел издания клиента и сервера
	 * @param highest    верхний предел издания клиента и сервера
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const context::credential_t & credential, const uint16_t lowest, const uint16_t highest) noexcept {
		client.transport(context::transport_t::DATAGRAMS);
		server.transport(context::transport_t::DATAGRAMS);
		client.suites(vector <protect::suite_t> {suite});
		server.suites(vector <protect::suite_t> {suite});
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		server.credential(credential);
		server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		(void) client.versions(lowest, highest);
		(void) server.versions(lowest, highest);
	}
	/**
	 * @brief Метод разбора шестнадцатеричной записи
	 *
	 * @param text запись
	 *
	 * @return     байты
	 *
	 */
	vector <uint8_t> decode(const char * text) noexcept {
		vector <uint8_t> result;
		for(size_t i = 0; (text[i] != '\0') && (text[i + 1] != '\0'); i += 2)
			result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
		return result;
	}
	/**
	 * Наборы шифрования, годные изданию 1.1, с ключами набора
	 */
	typedef struct Entry {
		protect::suite_t suite;
		const char * key;
		const char * title;
	} entry_t;
	static const entry_t SUITES[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, "ec256", "ECDHE-ECDSA-AES128-SHA"},
		{protect::suite_t::ECDHE_ECDSA_AES_256_CBC_SHA, "ec256", "ECDHE-ECDSA-AES256-SHA"},
		{protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA, "rsa2048", "ECDHE-RSA-AES128-SHA"},
		{protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA, "rsa2048", "ECDHE-RSA-AES256-SHA"},
		{protect::suite_t::RSA_AES_128_CBC_SHA, "rsa2048", "AES128-SHA"},
		{protect::suite_t::RSA_AES_256_CBC_SHA, "rsa2048", "AES256-SHA"}
	};
};

/**
 * Проверка PRF издания 1.1 против openssl kdf TLS1-PRF с MD5-SHA1: секрет делится пополам
 * между P_MD5 и P_SHA1, ответ снят с openssl 3.6.3 (`openssl kdf -keylen 16 -kdfopt
 * digest:MD5-SHA1 -kdfopt hexsecret:0102030405060708090a0b0c0d0e0f10 -kdfopt seed:'test label'
 * -kdfopt hexseed:00112233 TLS1-PRF`)
 */
TEST(Dtls10Test, Prf){
	const vector <uint8_t> secret = decode("0102030405060708090a0b0c0d0e0f10"), tail = decode("00112233");
	const vector <uint8_t> expected = decode("EF59D2E6F17E0DB1E54F0EA614B41B63");
	static const char LABEL[] = "test label";
	uint8_t result[16];
	ASSERT_TRUE(digest::legacy(view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), result, sizeof(result)));
	EXPECT_EQ(vector <uint8_t> (result, result + sizeof(result)), expected);
	// Нечётная длина секрета: середина входит в обе половины
	const vector <uint8_t> odd = decode("0102030405060708090a0b0c0d0e0f");
	uint8_t first[16], second[16], third[16];
	ASSERT_TRUE(digest::prf(digest::hash_t::MD5, view_t(odd.data(), 8), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), first, sizeof(first)));
	ASSERT_TRUE(digest::prf(digest::hash_t::SHA1, view_t(odd.data() + 7, 8), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), second, sizeof(second)));
	ASSERT_TRUE(digest::legacy(view_t(odd.data(), odd.size()), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), third, sizeof(third)));
	for(size_t i = 0; i < sizeof(third); i++)
		EXPECT_EQ(third[i], static_cast <uint8_t> (first[i] ^ second[i])) << i;
	// Отказы: пустой секрет, пустое место, нулевая и непомерная длина
	EXPECT_FALSE(digest::legacy(view_t(), view_t(), view_t(), result, sizeof(result)));
	EXPECT_FALSE(digest::legacy(view_t(secret.data(), secret.size()), view_t(), view_t(), nullptr, sizeof(result)));
	EXPECT_FALSE(digest::legacy(view_t(secret.data(), secret.size()), view_t(), view_t(), result, 0));
	uint8_t huge[600];
	EXPECT_FALSE(digest::legacy(view_t(secret.data(), secret.size()), view_t(), view_t(), huge, sizeof(huge)));
}

/**
 * Проверка обмена изданием DTLS 1.0: все наборы CBC-SHA1 с ECDHE и RSA, издание 0x0302 у обеих
 * сторон, данные в обе стороны, билет и возобновление
 */
TEST(Dtls10Test, Loopback){
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		context::credential_t credential;
		ASSERT_TRUE(keyfile(SUITES[s].key, credential)) << SUITES[s].title;
		client::context_t client;
		server::context_t server;
		arrange(client, server, SUITES[s].suite, credential, TLS11, TLS11);
		const vector <uint8_t> vault(32, 0x55);
		server.vault(vault);
		ASSERT_EQ(server.start(), context::error_t::NONE) << SUITES[s].title;
		ASSERT_EQ(client.start(), context::error_t::NONE) << SUITES[s].title;
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << SUITES[s].title << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		EXPECT_EQ(client.version(), TLS11) << SUITES[s].title;
		EXPECT_EQ(server.version(), TLS11) << SUITES[s].title;
		EXPECT_EQ(client.suite(), SUITES[s].suite);
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
		ASSERT_TRUE(barter(client, server)) << SUITES[s].title;
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << SUITES[s].title;
		client::context_t resuming;
		server::context_t resumed;
		arrange(resuming, resumed, SUITES[s].suite, credential, TLS11, TLS11);
		resumed.vault(vault);
		resuming.resume(client.tickets()[0]);
		resumed.resume(server.tickets());
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		converse(resuming, resumed);
		ASSERT_TRUE(resuming.established() && resumed.established()) << SUITES[s].title << " " << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		EXPECT_TRUE(resuming.shared() && resumed.shared()) << SUITES[s].title;
		EXPECT_EQ(resuming.version(), TLS11);
		ASSERT_TRUE(barter(resuming, resumed)) << SUITES[s].title;
	}
}

/**
 * Проверка выбора издания: клиент до 1.2 против сервера только 1.0 - 1.0 (заголовок 0xFEFD и
 * перечень изданий с 0xFEFF); клиент только 1.0 против сервера от 1.2 - protocol_version;
 * AEAD-набор при 1.0 - handshake_failure; потоком 0x0302 - SETTINGS
 */
TEST(Dtls10Test, Choice){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS12);
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t profile;
		ASSERT_EQ(fingerprint::parse(client.output(), profile, true), fingerprint::error_t::NONE);
		EXPECT_EQ(profile.version, static_cast <uint16_t> (0xFEFD));
		bool listed = false;
		for(size_t i = 0; i < profile.extensions.size(); i++){
			if(profile.extensions[i].type == static_cast <uint16_t> (extension::type_t::VERSIONS)){
				for(size_t j = 0; j < profile.extensions[i].versions.size(); j++)
					listed = (listed || (profile.extensions[i].versions[j] == 0xFEFF));
			}
		}
		EXPECT_TRUE(listed);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.version(), TLS11);
		EXPECT_EQ(server.version(), TLS11);
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Обе стороны от 1.0 до 1.2: выбирается 1.2
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS12);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_EQ(client.version(), TLS12);
		EXPECT_EQ(server.version(), TLS12);
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS11);
		ASSERT_EQ(server.versions(TLS12, TLS12), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t profile;
		ASSERT_EQ(fingerprint::parse(client.output(), profile, true), fingerprint::error_t::NONE);
		EXPECT_EQ(profile.version, static_cast <uint16_t> (0xFEFF));
		converse(client, server);
		EXPECT_FALSE(client.established() || server.established());
		EXPECT_EQ(server.error(), context::error_t::VERSION);
		EXPECT_EQ(server.alert().description, alert::description_t::VERSION);
	}
	{
		// Набору AEAD издание 1.1 не положено: зажатому на 1.0 клиенту с одним лишь GCM предлагать нечего - SETTINGS при заведении
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS11);
		EXPECT_EQ(client.start(), context::error_t::SETTINGS);
		// Сервер, зажатый на 1.0 с одним лишь GCM, не сходится изданием с клиентом от 1.0 до 1.2: protocol_version
		client::context_t other;
		server::context_t another;
		arrange(other, another, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS12);
		ASSERT_EQ(another.versions(TLS11, TLS11), context::error_t::NONE);
		ASSERT_EQ(another.start(), context::error_t::NONE);
		ASSERT_EQ(other.start(), context::error_t::NONE);
		converse(other, another);
		EXPECT_FALSE(other.established() || another.established());
		EXPECT_EQ(another.error(), context::error_t::VERSION);
	}
	{
		// Клиент от 1.0 до 1.2 с GCM впереди CBC против сервера только 1.0 с тем же порядком: изданию 1.1 сервер выбирает CBC, минуя GCM
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS12);
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.version(), TLS11);
		EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		EXPECT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		ASSERT_TRUE(barter(client, server));
	}
	{
		client::context_t client;
		ASSERT_EQ(client.versions(TLS11, TLS12), context::error_t::NONE);
		EXPECT_EQ(client.start(), context::error_t::SETTINGS);
		client::context_t another;
		EXPECT_EQ(another.versions(0x0301, TLS12), context::error_t::SETTINGS);
	}
}

/**
 * Проверка подлинности клиента изданием 1.1: подпись владения ключом без схемы - MD5 ‖ SHA-1 у
 * RSA и SHA-1 у ECDSA, запрос подлинности без перечня схем
 */
TEST(Dtls10Test, Mutual){
	static const char * KEYS[] = {"ec256", "rsa2048"};
	for(size_t k = 0; k < 2; k++){
		context::credential_t mine, theirs;
		ASSERT_TRUE(keyfile("ec256", mine));
		ASSERT_TRUE(keyfile(KEYS[k], theirs));
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, mine, TLS11, TLS11);
		server.request(true);
		client.credential(theirs);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << KEYS[k] << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		EXPECT_EQ(server.peer()[0], theirs.chain[0]);
		ASSERT_TRUE(barter(client, server));
	}
}

/**
 * Проверка чужого эталона: наш клиент против openssl s_server -dtls1, наш сервер против
 * s_client -dtls1; наборы лишь под @SECLEVEL=0
 */
/**
 * @brief Метод проверки, ведёт ли openssl стенда живой DTLS 1.0 сам с собой
 *
 * @details Признак по делу, а не по версии: s_server -dtls1 со stdin на FIFO против s_client -dtls1
 *          с -ign_eof; договорились - у клиента строка «Cipher    : ECDHE-ECDSA-AES128-SHA»
 *
 * @return признак того, что openssl договорился сам с собой
 *
 */
static bool dtlsable() noexcept {
	// Порт, журналы и держатель stdin сервера
	const uint16_t number = vacant(true);
	// Если порта нет
	if(number == 0)
		// Выводим отказ
		return false;
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	const std::string base = "/tmp/ants-dtls10-self-" + std::to_string(number);
	const std::string holder = base + ".fifo", log = base + ".server.log", out = base + ".client.log";
	::remove(holder.c_str());
	// Если FIFO завести не удалось
	if(fifo(holder.c_str()) != 0)
		// Выводим отказ
		return false;
	// Поднимаем сервер openssl
	const toolkit_t toolkit = inspect();
	const bool started = launch("openssl s_server" + accepting(toolkit, number) + " -dtls1 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder);
	// Итог
	bool agreed = false;
	// Если сервер поднялся
	if(started){
		sentinel_t sentinel(log + ".pid");
		// Дожидаемся готовности сервера
		std::string text;
		if(!awaited(log, "ACCEPT", text)){
			sentinel.halt();
			::remove(holder.c_str());
			::remove(log.c_str());
			return false;
		}
		// Клиент openssl против него
		(void) shell("(printf 'ping' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1 -CAfile " + crt + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300 -servername localhost -ign_eof -verify_return_error >" + out + " 2>&1 &); sleep 3; pkill -f 'openssl s_client -connect 127.0.0.1:" + std::to_string(number) + "' >/dev/null 2>&1; true");
		// Ищем договорённый набор у клиента
		std::ifstream file(out);
		std::string line;
		while(std::getline(file, line))
			agreed = (agreed || (line.find("Cipher    : ECDHE-ECDSA-AES128-SHA") != std::string::npos) || (line.find("Cipher is ECDHE-ECDSA-AES128-SHA") != std::string::npos));
		sentinel.halt();
	}
	// Прибираем
	::remove(holder.c_str());
	::remove(log.c_str());
	::remove(out.c_str());
	// Выводим итог
	return agreed;
}

TEST(Dtls10Test, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	if(!listed("s_server", "dtls1") || !listed("s_client", "dtls1")){
		GTEST_SKIP() << "openssl без DTLS 1.0";
	}
	if(!toolkit.tls12 || !toolkit.master){
		GTEST_SKIP() << "openssl без TLS 1.2 либо без расширенного главного секрета (старше 1.1.0)";
	}
	if(shell("openssl ciphers -s 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "openssl без ECDHE-ECDSA-AES128-SHA";
	}
	// Свойство оснастки, не номер версии: openssl 3.5.7 на Fedora не ведёт DTLS 1.0 сам с собой (нет годной схемы подписи), 3.6.3 на macOS ведёт
	if(!dtlsable()){
		GTEST_SKIP() << "openssl на этом стенде не договаривается сам с собой по -dtls1 (сборка либо политика без DTLS 1.0)";
	}
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		const uint16_t number = vacant(true);
		ASSERT_NE(number, 0);
		const std::string log = "/tmp/ants-dtls10-server-" + std::to_string(number) + ".log";
		const std::string holder = "/tmp/ants-dtls10-server-" + std::to_string(number) + ".fifo";
		::remove(holder.c_str());
		ASSERT_EQ(fifo(holder.c_str()), 0);
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		sentinel_t sentinel(log + ".pid");
		std::string text;
		ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
		uint16_t bound = 0;
		const int fd = socketing(0, bound);
		ASSERT_GE(fd, 0);
		struct sockaddr_in peer;
		::memset(&peer, 0, sizeof(peer));
		peer.sin_family = AF_INET;
		peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		peer.sin_port = htons(number);
		client::context_t client;
		client.transport(context::transport_t::DATAGRAMS);
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		ASSERT_EQ(client.versions(TLS11, TLS11), context::error_t::NONE);
		client.mtu(300);
		client.name("localhost");
		ASSERT_EQ(client.start(), context::error_t::NONE);
		const bool complete = relay(client, fd, peer, 400);
		if(!complete){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		EXPECT_EQ(client.version(), TLS11);
		EXPECT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		closing(fd);
		sentinel.halt();
		(void) settle(log, text);
		::remove(log.c_str());
		::remove(holder.c_str());
	}
	{
		uint16_t number = 0;
		const int fd = socketing(0, number);
		ASSERT_GE(fd, 0);
		const std::string log = "/tmp/ants-dtls10-client-" + std::to_string(number) + ".log";
		const string request = "hello from openssl over dtls 1.0\n";
		ASSERT_TRUE(launch("printf '" + request + "' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1 -CAfile " + crt + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300 -servername localhost -verify_return_error -ign_eof >" + log + " 2>&1", log, log + ".pid", std::string()));
		sentinel_t sentinel(log + ".pid");
		struct sockaddr_in peer;
		socklen_t length = sizeof(peer);
		uint8_t buffer[65536];
		ssize_t received = -1;
		for(size_t i = 0; (i < 150) && (received <= 0); i++)
			received = receivingfrom(fd, buffer, sizeof(buffer), reinterpret_cast <struct sockaddr *> (&peer), &length);
		ASSERT_GT(received, 0);
		server::context_t server;
		server.transport(context::transport_t::DATAGRAMS);
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		server.credential(credential);
		server.mtu(300);
		const uint8_t * bytes = reinterpret_cast <const uint8_t *> (&peer);
		ASSERT_TRUE(server.address(view_t(bytes, sizeof(peer))));
		ASSERT_EQ(server.start(), context::error_t::NONE);
		server.push(view_t(buffer, static_cast <size_t> (received)));
		// Принятые прикладные данные
		vector <uint8_t> plaintext;
		/**
		 * Выполняем обмен дейтаграммами с s_client, пока связь не установится и данные не придут
		 */
		for(size_t i = 0; (i < 400) && (server.state() != context::state_t::FAILED) && (server.state() != context::state_t::CLOSED) && plaintext.empty(); i++){
			while(server.output().size > 0){
				const view_t data = server.output();
				(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
				server.consume(data.size);
			}
			received = receiving(fd, buffer, sizeof(buffer));
			if(received > 0)
				server.push(view_t(buffer, static_cast <size_t> (received)));
			else if(server.timeout() > 0)
				server.elapsed();
			if(server.established())
				(void) server.read(plaintext);
		}
		if(!server.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		ASSERT_TRUE(server.established()) << "отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description) << " состояние " << static_cast <int> (server.state());
		EXPECT_EQ(server.version(), TLS11);
		EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		EXPECT_EQ(string(plaintext.begin(), plaintext.end()), request);
		closing(fd);
		sentinel.halt();
		std::string text;
		(void) settle(log, text);
		EXPECT_NE(text.find("Protocol  : DTLSv1"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь изданием DTLS 1.0 либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(Dtls10Test, Starved){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	bool starved = false;
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		client::context_t client;
		server::context_t server;
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS11);
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
		if(complete)
			EXPECT_EQ(client.version(), TLS11);
	}
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
