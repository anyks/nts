/**
 * @file sct.cpp
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
 * @brief Исходный файл проверок меток времени подписанного сертификата SCT (RFC 6962,
 *        раздел 4.4.2.1 RFC 8446): запрос и ответ обоими изданиями, профиль отпечатка,
 *        враждебные стороны, разборщик перечня, чужой эталон openssl и пайок памяти
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
#include <identity.hpp>
#include <adversary.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <alert/alert.hpp>
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
	 * @brief Метод составления подлинности стороны из цепочки набора в три звена
	 *
	 * @param kind   вид ключа: ec либо rsa
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool chained(const char * kind, context::credential_t & result) noexcept {
		result.secret = corpus((std::string("leaf-") + kind + ".key").c_str());
		const vector <uint8_t> text = corpus((std::string("chain-") + kind + ".pem").c_str());
		if(result.secret.empty() || text.empty())
			return false;
		result.chain.clear();
		return ((pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE) && (result.chain.size() == 3));
	}
	/**
	 * @brief Метод составления правдоподобной метки времени: издание 1, журнал, миг, без расширений, подпись ecdsa_secp256r1_sha256
	 *
	 * @param seed байт, которым заполняются журнал и подпись
	 *
	 * @return     метка времени как записана
	 *
	 */
	vector <uint8_t> stamp(const uint8_t seed) noexcept {
		vector <uint8_t> result;
		result.push_back(0x00);
		result.insert(result.end(), 32, seed);
		static const uint8_t MOMENT[] = {0x00, 0x00, 0x01, 0x8F, 0x00, 0x00, 0x00, 0x00};
		result.insert(result.end(), MOMENT, MOMENT + sizeof(MOMENT));
		result.push_back(0x00);
		result.push_back(0x00);
		result.push_back(0x04);
		result.push_back(0x03);
		result.push_back(0x00);
		result.push_back(0x40);
		result.insert(result.end(), 64, static_cast <uint8_t> (seed ^ 0x5A));
		return result;
	}
	/**
	 * @brief Метод составления перечня меток времени из двух записей
	 *
	 * @return перечень как записан
	 *
	 */
	vector <uint8_t> listing() noexcept {
		vector <uint8_t> result;
		(void) extension::timestamps(vector <vector <uint8_t>> {stamp(0x11), stamp(0x22)}, result);
		return result;
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
	 * @brief Метод настройки сторон: подлинность сервера, запрос у клиента и перечень у сервера по заказу
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param asking     запрашивает ли клиент метки времени
	 * @param list       перечень меток времени сервера, пустой - не задаётся
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const bool asking, const vector <uint8_t> & list) noexcept {
		server.credential(credential);
		client.timestamps(asking);
		if(!list.empty())
			server.timestamps(list);
	}
};

/**
 * Проверка обмена изданием 1.3: перечень идёт записью листа по запросу, разбирается на
 * записи; без запроса сервер молчит; без перечня у сервера ответа нет
 */
TEST(SctTest, Loopback){
	context::credential_t credential;
	ASSERT_TRUE(chained("ec", credential));
	const vector <uint8_t> list = listing();
	ASSERT_FALSE(list.empty());
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, true, list);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (3));
		EXPECT_EQ(client.timestamps(), list);
		vector <vector <uint8_t>> entries;
		ASSERT_EQ(extension::timestamps(view_t(client.timestamps().data(), client.timestamps().size()), entries), extension::error_t::NONE);
		ASSERT_EQ(entries.size(), static_cast <size_t> (2));
		EXPECT_EQ(entries[0], stamp(0x11));
		EXPECT_EQ(entries[1], stamp(0x22));
		// Возобновление без сертификата перечня не несёт
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		client::context_t resuming;
		server::context_t resumed;
		arrange(resuming, resumed, credential, true, list);
		resuming.resume(client.tickets()[0]);
		resumed.resume(server.tickets());
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		converse(resuming, resumed);
		ASSERT_TRUE(resuming.established() && resumed.established() && resuming.shared());
		EXPECT_TRUE(resuming.timestamps().empty());
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, false, list);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_TRUE(client.timestamps().empty());
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, true, vector <uint8_t> ());
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_TRUE(client.timestamps().empty());
	}
}

/**
 * Проверка издания 1.2: перечень идёт приветствием сервера по запросу; при возобновлении
 * билетом не идёт
 */
TEST(SctTest, Legacy){
	context::credential_t credential;
	ASSERT_TRUE(chained("ec", credential));
	const vector <uint8_t> list = listing();
	client::context_t client;
	server::context_t server;
	arrange(client, server, credential, true, list);
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	const vector <uint8_t> vault(32, 0x33);
	server.vault(vault);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_EQ(client.timestamps(), list);
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	client::context_t resuming;
	server::context_t resumed;
	arrange(resuming, resumed, credential, true, list);
	ASSERT_EQ(resuming.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(resumed.versions(0x0303, 0x0303), context::error_t::NONE);
	resumed.vault(vault);
	resuming.resume(client.tickets()[0]);
	resumed.resume(server.tickets());
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	converse(resuming, resumed);
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.shared() && resumed.shared());
	EXPECT_TRUE(resuming.timestamps().empty());
}

/**
 * Проверка профиля отпечатка: снимок приветствия с расширением 18 включает запрос сам, и
 * приветствие по профилю сходится с ним видами расширений
 */
TEST(SctTest, Profile){
	context::credential_t credential;
	ASSERT_TRUE(chained("ec", credential));
	const vector <uint8_t> list = listing();
	fingerprint::profile_t source;
	{
		client::context_t donor;
		donor.name("example.com");
		donor.timestamps(true);
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	bool found = false;
	/**
	 * Выполняем перебор расширений снимка
	 */
	for(size_t i = 0; i < source.extensions.size(); i++){
		if(source.extensions[i].type == static_cast <uint16_t> (extension::type_t::TIMESTAMPS)){
			found = true;
			EXPECT_TRUE(source.extensions[i].data.empty());
		}
	}
	ASSERT_TRUE(found);
	client::context_t client;
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	server.credential(credential);
	server.timestamps(list);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	fingerprint::profile_t made;
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	/**
	 * Выполняем сличение видов расширений снимка и сложенного приветствия
	 */
	for(size_t i = 0; i < made.extensions.size(); i++)
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_EQ(client.timestamps(), list);
}

/**
 * Проверка враждебного сервера: пустой перечень, пустая запись и хвост - decode_error;
 * перечень без запроса - unsupported_extension; перечень в приветствии сервера издания 1.3 -
 * illegal_parameter
 */
TEST(SctTest, Lying){
	// Враждебный сервер набора проверок подписывает владение ключом ГОСТ: подлинность и набор ему под стать
	context::credential_t credential;
	ASSERT_TRUE(identity("anyks.com", credential));
	static const distortion_t MALFORMED[] = {distortion_t::MALSCT, distortion_t::HOLLOWSCT, distortion_t::TRAILSCT};
	/**
	 * Выполняем перебор негодных перечней
	 */
	for(size_t i = 0; i < (sizeof(MALFORMED) / sizeof(MALFORMED[0])); i++){
		client::context_t client;
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		client.timestamps(true);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		ASSERT_TRUE(adversary(client, MALFORMED[i], &credential)) << i;
		EXPECT_EQ(client.error(), context::error_t::TIMESTAMPS) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::DECODE) << i;
		EXPECT_FALSE(client.established()) << i;
		EXPECT_TRUE(client.timestamps().empty()) << i;
	}
	{
		client::context_t client;
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		ASSERT_EQ(client.start(), context::error_t::NONE);
		ASSERT_TRUE(adversary(client, distortion_t::UNASKEDSCT, &credential));
		EXPECT_EQ(client.error(), context::error_t::EXTENSION);
		EXPECT_EQ(client.alert().description, alert::description_t::EXTENSION);
		EXPECT_FALSE(client.established());
	}
	{
		client::context_t client;
		client.timestamps(true);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		ASSERT_TRUE(adversary(client, distortion_t::SCTHELLO));
		EXPECT_EQ(client.error(), context::error_t::MESSAGE);
		EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER);
		EXPECT_FALSE(client.established());
	}
}

/**
 * Проверка враждебного клиента: непустое тело запроса - decode_error
 */
TEST(SctTest, Greedy){
	// Враждебный клиент набора проверок говорит лишь наборами ГОСТ
	context::credential_t credential;
	ASSERT_TRUE(identity("anyks.com", credential));
	server::context_t server;
	server.credential(credential);
	server.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	server.timestamps(listing());
	ASSERT_EQ(server.start(), context::error_t::NONE);
	(void) intruder(server, distortion_t::GREEDYSCT, &credential);
	EXPECT_EQ(server.error(), context::error_t::MESSAGE);
	EXPECT_EQ(server.alert().description, alert::description_t::DECODE);
	EXPECT_FALSE(server.established());
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x15));
}

/**
 * Проверка отказов: негодный перечень у сервера - SETTINGS при заведении; разборщик и
 * сборщик перечня на пустоте и обрезании
 */
TEST(SctTest, Refusals){
	context::credential_t credential;
	ASSERT_TRUE(chained("ec", credential));
	static const uint8_t EMPTYLIST[] = {0x00, 0x00}, HOLLOWLIST[] = {0x00, 0x02, 0x00, 0x00}, TRAILLIST[] = {0x00, 0x03, 0x00, 0x01, 0xAA, 0xFF};
	{
		server::context_t server;
		server.credential(credential);
		server.timestamps(vector <uint8_t> (EMPTYLIST, EMPTYLIST + sizeof(EMPTYLIST)));
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		server::context_t server;
		server.credential(credential);
		server.timestamps(vector <uint8_t> (HOLLOWLIST, HOLLOWLIST + sizeof(HOLLOWLIST)));
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		server::context_t server;
		server.credential(credential);
		server.timestamps(vector <uint8_t> (TRAILLIST, TRAILLIST + sizeof(TRAILLIST)));
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	vector <vector <uint8_t>> entries;
	EXPECT_EQ(extension::timestamps(view_t(EMPTYLIST, sizeof(EMPTYLIST)), entries), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(view_t(HOLLOWLIST, sizeof(HOLLOWLIST)), entries), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(view_t(TRAILLIST, sizeof(TRAILLIST)), entries), extension::error_t::TRAILING);
	const vector <uint8_t> list = listing();
	/**
	 * Отказ: обрезание перечня на всякой длине
	 */
	for(size_t i = 0; i < list.size(); i++){
		entries.clear();
		EXPECT_NE(extension::timestamps(view_t(list.data(), i), entries), extension::error_t::NONE) << "длина " << i;
	}
	entries.clear();
	ASSERT_EQ(extension::timestamps(view_t(list.data(), list.size()), entries), extension::error_t::NONE);
	EXPECT_EQ(entries.size(), static_cast <size_t> (2));
	vector <uint8_t> rebuilt;
	ASSERT_EQ(extension::timestamps(entries, rebuilt), extension::error_t::NONE);
	EXPECT_EQ(rebuilt, list);
	rebuilt.clear();
	EXPECT_EQ(extension::timestamps(vector <vector <uint8_t>> (), rebuilt), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(vector <vector <uint8_t>> {vector <uint8_t> ()}, rebuilt), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(vector <vector <uint8_t>> {vector <uint8_t> (0x10000, 0xAA)}, rebuilt), extension::error_t::EMPTY);
}

/**
 * Проверка чужого эталона: наш сервер против openssl s_client -ct, журнал показывает
 * принятые метки. Наш клиент против s_server не годится: OpenSSL выдаёт SCT по TLS лишь
 * из журналов CT, которых у стенда нет, - записано вслух
 */
TEST(SctTest, Openssl){
	const toolkit_t toolkit = inspect();
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	if(!toolkit.tls13){
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	if(!listed("s_client", "ct")){
		GTEST_SKIP() << "openssl без ключа -ct (собран без CT)";
	}
	context::credential_t credential;
	ASSERT_TRUE(chained("ec", credential));
	const std::string root = std::string(CORPUS) + "/ca-ec.crt";
	uint16_t number = 0;
	const int listener = harbour(number);
	ASSERT_GE(listener, 0);
	const std::string log = "/tmp/ants-sct-client-" + std::to_string(number) + ".log";
	/**
	 * s_client -ct без файла журналов CT падает до подключения: журнал заводится свой, с
	 * ключом, порождённым openssl на месте; метки к нему не относятся, и s_client честно
	 * отчитывается о них как о непроверенных
	 */
	const std::string logs = "/tmp/ants-sct-ctlog-" + std::to_string(number) + ".conf", pubkey = logs + ".key";
	// Конвейер целиком в подоболочке: shell() перенаправляет ввод последнего звена из /dev/null
	ASSERT_EQ(shell("(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -pubout -outform DER 2>/dev/null | openssl base64 -A) > " + pubkey), 0);
	{
		std::ifstream reader(pubkey);
		std::string encoded((std::istreambuf_iterator <char> (reader)), std::istreambuf_iterator <char> ());
		ASSERT_FALSE(encoded.empty());
		std::ofstream writer(logs);
		writer << "enabled_logs = ants\n[ants]\ndescription = A-NTS test log\nkey = " << encoded << "\n";
	}
	ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -ct -ctlogfile " + logs + " -CAfile " + root + " -servername test.anyks.com </dev/null >" + log + " 2>&1", log, log + ".pid"));
	sentinel_t sentinel(log + ".pid");
	const int fd = greeted(listener);
	ASSERT_GE(fd, 0);
	server::context_t server;
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	server.credential(credential);
	server.timestamps(listing());
	ASSERT_EQ(server.start(), context::error_t::NONE);
	const bool complete = serve(server, fd);
	ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
	ASSERT_EQ(server.error(), context::error_t::NONE);
	ASSERT_TRUE(farewell(server, fd));
	closing(fd);
	closing(listener);
	std::string text;
	ASSERT_TRUE(settle(log, text)) << text;
	// s_client -ct печатает принятые метки: заголовок SCT validation и по записи на метку
	EXPECT_NE(text.find("SCT validation status"), std::string::npos) << text;
	EXPECT_NE(text.find("Signed Certificate Timestamp"), std::string::npos) << text;
	::remove(log.c_str());
	::remove(logs.c_str());
	::remove(pubkey.c_str());
}

/**
 * Проверка под пайком памяти: связь с запросом и перечнем либо устанавливается, либо
 * честно отвечает нехваткой памяти
 */
TEST(SctTest, Starved){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const vector <uint8_t> list = listing();
	bool starved = false;
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, true, list);
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
			EXPECT_EQ(client.timestamps(), list);
	}
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
