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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Объявляем буфер результата
		vector <uint8_t> result;
		// Если файл открылся
		if(file.is_open())
			// Читаем содержимое файла целиком
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
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
		// Считываем секретный ключ
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Считываем сертификат
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если файлы не прочитались
		if(result.secret.empty() || text.empty())
			// Выводим отрицательный результат - файлы не прочитались
			return false;
		// Очищаем цепочку сертификатов
		result.chain.clear();
		// Составляем цепочку из PEM-текста
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция переноса дейтаграмм одной стороны другой
	 *
	 * @param from сторона, чьи дейтаграммы забираются
	 * @param to   сторона, которой они подаются
	 * @return     признак того, что дейтаграммы переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to) noexcept {
		// Объявляем признак переноса
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			/**
			 * Перебираем: исходящие дейтаграммы стороны, пока они есть
			 */
			while(from.output().size > 0){
				// Получаем очередную дейтаграмму
				const view_t data = from.output();
				// Копируем дейтаграмму в буфер
				const vector <uint8_t> datagram(data.data, data.data + data.size);
				// Убираем дейтаграмму из вывода
				from.consume(data.size);
				// Передаём дейтаграмму другой стороне
				to.push(view_t(datagram.data(), datagram.size()));
				// Отмечаем, что перенос был
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Сообщаем о нехватке памяти
			return false;
		}
		// Выводим признак переноса
		return moved;
	}
	/**
	 * @brief Функция проведения обмена дейтаграммами сторон связи
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
			// Прерываем обмен при отказе стороны
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				break;
			// Переносим дейтаграммы клиента серверу
			bool moved = carry(client, server);
			// Переносим дейтаграммы сервера клиенту
			moved = (carry(server, client) || moved);
			// Если перенос был
			if(moved)
				continue;
			// Объявляем признак срабатывания таймеров
			bool fired = false;
			// Если у клиента ждёт таймер
			if(client.timeout() > 0){
				// Сдвигаем время клиента
				client.elapsed();
				// Отмечаем срабатывание
				fired = true;
			}
			// Если у сервера ждёт таймер
			if(server.timeout() > 0){
				// Сдвигаем время сервера
				server.elapsed();
				// Отмечаем срабатывание
				fired = true;
			}
			// Если таймеры не сработали
			if(!fired)
				break;
		}
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
		// Формируем запрос клиента
		const string request = "ping from the client over DTLS 1.0";
		// Формируем ответ сервера
		const string response = "pong from the server over DTLS 1.0";
		// Передаём запрос от клиента
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отрицательный результат - запрос не передан
			return false;
		// Передаём ответ от сервера
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (response.data()), response.size())) != context::error_t::NONE)
			// Выводим отрицательный результат - ответ не передан
			return false;
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Объявляем буфер принятых данных
		vector <uint8_t> received;
		// Проверяем доставку запроса серверу
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отрицательный результат - запрос не доставлен
			return false;
		// Проверяем доставку ответа клиенту
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != response))
			// Выводим отрицательный результат - ответ не доставлен
			return false;
		// Выводим успех
		return true;
	}
	/**
	 * @brief Функция настройки сторон поверх дейтаграмм с пределами изданий
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
		// Задаём клиенту дейтаграммы
		client.transport(context::transport_t::DATAGRAMS);
		// Задаём серверу дейтаграммы
		server.transport(context::transport_t::DATAGRAMS);
		// Задаём клиенту набор шифрования
		client.suites(vector <protect::suite_t> {suite});
		// Задаём серверу набор шифрования
		server.suites(vector <protect::suite_t> {suite});
		// Задаём клиенту группу
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Задаём серверу группу
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Задаём серверу подлинность
		server.credential(credential);
		// Задаём серверу адрес собеседника
		server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		// Задаём клиенту пределы изданий
		(void) client.versions(lowest, highest);
		// Задаём серверу пределы изданий
		(void) server.versions(lowest, highest);
	}
	/**
	 * @brief Функция разбора шестнадцатеричной записи
	 *
	 * @param text запись
	 * @return     байты
	 *
	 */
	vector <uint8_t> decode(const char * text) noexcept {
		// Объявляем буфер результата
		vector <uint8_t> result;
		/**
		 * Перебираем: пары шестнадцатеричных знаков записи, пока они не кончатся
		 */
		for(size_t i = 0; (text[i] != '\0') && (text[i + 1] != '\0'); i += 2)
			// Добавляем разобранный байт
			result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
		// Выводим байты записи
		return result;
	}
	/**
	 * Наборы шифрования, годные изданию 1.1, с ключами набора
	 */
	typedef struct Entry {
		// Набор шифрования
		protect::suite_t suite;
		// Имя ключа набора
		const char * key;
		// Название набора
		const char * title;
	} entry_t;
	// Наборы, годные изданию 1.1, с ключами набора
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
	// Составляем секрет и затравку
	const vector <uint8_t> secret = decode("0102030405060708090a0b0c0d0e0f10"), tail = decode("00112233");
	// Задаём ожидаемый ответ
	const vector <uint8_t> expected = decode("EF59D2E6F17E0DB1E54F0EA614B41B63");
	// Задаём метку
	static const char LABEL[] = "test label";
	// Объявляем буфер результата
	uint8_t result[16];
	// Проверяем PRF издания 1.1 против эталона
	ASSERT_TRUE(digest::legacy(view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), result, sizeof(result)));
	// Сверяем результат с эталоном
	EXPECT_EQ(vector <uint8_t> (result, result + sizeof(result)), expected);
	// Нечётная длина секрета: середина входит в обе половины
	const vector <uint8_t> odd = decode("0102030405060708090a0b0c0d0e0f");
	// Объявляем буферы половинных проверок
	uint8_t first[16], second[16], third[16];
	// Считаем левую половину на MD5
	ASSERT_TRUE(digest::prf(digest::hash_t::MD5, view_t(odd.data(), 8), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), first, sizeof(first)));
	// Считаем правую половину на SHA1
	ASSERT_TRUE(digest::prf(digest::hash_t::SHA1, view_t(odd.data() + 7, 8), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), second, sizeof(second)));
	// Считаем целый секрет нечётной длины
	ASSERT_TRUE(digest::legacy(view_t(odd.data(), odd.size()), view_t(reinterpret_cast <const uint8_t *> (LABEL), sizeof(LABEL) - 1), view_t(tail.data(), tail.size()), third, sizeof(third)));
	/**
	 * Перебираем: байты результата, пока они не кончатся
	 */
	for(size_t i = 0; i < sizeof(third); i++)
		// Сверяем сумму половин с целым
		EXPECT_EQ(third[i], static_cast <uint8_t> (first[i] ^ second[i])) << i;
	// Отказы: пустой секрет, пустое место, нулевая и непомерная длина
	EXPECT_FALSE(digest::legacy(view_t(), view_t(), view_t(), result, sizeof(result)));
	EXPECT_FALSE(digest::legacy(view_t(secret.data(), secret.size()), view_t(), view_t(), nullptr, sizeof(result)));
	EXPECT_FALSE(digest::legacy(view_t(secret.data(), secret.size()), view_t(), view_t(), result, 0));
	// Объявляем буфер непомерной длины
	uint8_t huge[600];
	// Проверяем отказ на непомерной длине
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
		// Объявляем подлинность сервера
		context::credential_t credential;
		// Считываем ключи набора
		ASSERT_TRUE(keyfile(SUITES[s].key, credential)) << SUITES[s].title;
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.1
		arrange(client, server, SUITES[s].suite, credential, TLS11, TLS11);
		// Задаём тайник сессий
		const vector <uint8_t> vault(32, 0x55);
		// Передаём тайник серверу
		server.vault(vault);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE) << SUITES[s].title;
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << SUITES[s].title;
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established()) << SUITES[s].title << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		// Проверяем издание у клиента
		EXPECT_EQ(client.version(), TLS11) << SUITES[s].title;
		// Проверяем издание у сервера
		EXPECT_EQ(server.version(), TLS11) << SUITES[s].title;
		// Проверяем договорённый набор
		EXPECT_EQ(client.suite(), SUITES[s].suite);
		// Проверяем цепочку сервера
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server)) << SUITES[s].title;
		// Проверяем получение билета
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << SUITES[s].title;
		// Объявляем связь возобновляющего клиента
		client::context_t resuming;
		// Объявляем связь возобновляемого сервера
		server::context_t resumed;
		// Настраиваем стороны возобновления
		arrange(resuming, resumed, SUITES[s].suite, credential, TLS11, TLS11);
		// Передаём тайник серверу
		resumed.vault(vault);
		// Передаём билет клиенту
		resuming.resume(client.tickets()[0]);
		// Передаём билеты серверу
		resumed.resume(server.tickets());
		// Запускаем сервер
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		// Запускаем клиента
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Обмениваемся дейтаграммами
		converse(resuming, resumed);
		// Проверяем установление связи
		ASSERT_TRUE(resuming.established() && resumed.established()) << SUITES[s].title << " " << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		// Проверяем общий секрет
		EXPECT_TRUE(resuming.shared() && resumed.shared()) << SUITES[s].title;
		// Проверяем издание связи
		EXPECT_EQ(resuming.version(), TLS11);
		// Проверяем обмен данными
		ASSERT_TRUE(barter(resuming, resumed)) << SUITES[s].title;
	}
}

/**
 * Проверка выбора издания: клиент до 1.2 против сервера только 1.0 - 1.0 (заголовок 0xFEFD и
 * перечень изданий с 0xFEFF); клиент только 1.0 против сервера от 1.2 - protocol_version;
 * AEAD-набор при 1.0 - handshake_failure; потоком 0x0302 - SETTINGS
 */
TEST(Dtls10Test, Choice){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны: клиент до издания 1.2, сервер только 1.1
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS12);
		// Зажимаем сервер на издание 1.1
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль заголовка клиента
		fingerprint::profile_t profile;
		// Разбираем заголовок клиента
		ASSERT_EQ(fingerprint::parse(client.output(), profile, true), fingerprint::error_t::NONE);
		// Проверяем заголовок издания 1.0
		EXPECT_EQ(profile.version, static_cast <uint16_t> (0xFEFD));
		// Объявляем признак перечня изданий
		bool listed = false;
		/**
		 * Перебираем: расширения профиля, пока они не кончатся
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Ищем перечень изданий
			if(profile.extensions[i].type == static_cast <uint16_t> (extension::type_t::VERSIONS)){
				/**
				 * Перебираем: издания перечня, пока они не кончатся
				 */
				for(size_t j = 0; j < profile.extensions[i].versions.size(); j++)
					// Отмечаем наличие издания 1.0
					listed = (listed || (profile.extensions[i].versions[j] == 0xFEFF));
			}
		}
		// Проверяем наличие издания 1.0 в перечне
		EXPECT_TRUE(listed);
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем издание у клиента
		EXPECT_EQ(client.version(), TLS11);
		// Проверяем издание у сервера
		EXPECT_EQ(server.version(), TLS11);
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Обе стороны от 1.0 до 1.2: выбирается 1.2
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны от издания 1.1 до 1.2
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS12);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем издание у клиента
		EXPECT_EQ(client.version(), TLS12);
		EXPECT_EQ(server.version(), TLS12);
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.1
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS11);
		// Зажимаем сервер на издание 1.2
		ASSERT_EQ(server.versions(TLS12, TLS12), context::error_t::NONE);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль заголовка клиента
		fingerprint::profile_t profile;
		// Разбираем заголовок клиента
		ASSERT_EQ(fingerprint::parse(client.output(), profile, true), fingerprint::error_t::NONE);
		// Проверяем заголовок издания 1.2
		EXPECT_EQ(profile.version, static_cast <uint16_t> (0xFEFF));
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем отказ установления
		EXPECT_FALSE(client.established() || server.established());
		// Проверяем причину отказа
		EXPECT_EQ(server.error(), context::error_t::VERSION);
		EXPECT_EQ(server.alert().description, alert::description_t::VERSION);
	}
	{
		// Набору AEAD издание 1.1 не положено: зажатому на 1.0 клиенту с одним лишь GCM предлагать нечего - SETTINGS при заведении
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на GCM при издании 1.1
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS11);
		// Проверяем отказ заведения
		EXPECT_EQ(client.start(), context::error_t::SETTINGS);
		// Сервер, зажатый на 1.0 с одним лишь GCM, не сходится изданием с клиентом от 1.0 до 1.2: protocol_version
		client::context_t other;
		// Объявляем связь другого сервера
		server::context_t another;
		// Настраиваем стороны: клиент от 1.1 до 1.2, сервер на GCM
		arrange(other, another, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS12);
		// Зажимаем сервер на издание 1.1
		ASSERT_EQ(another.versions(TLS11, TLS11), context::error_t::NONE);
		ASSERT_EQ(another.start(), context::error_t::NONE);
		ASSERT_EQ(other.start(), context::error_t::NONE);
		// Обмениваемся дейтаграммами
		converse(other, another);
		// Проверяем отказ установления
		EXPECT_FALSE(other.established() || another.established());
		// Проверяем причину отказа
		EXPECT_EQ(another.error(), context::error_t::VERSION);
	}
	{
		// Клиент от 1.0 до 1.2 с GCM впереди CBC против сервера только 1.0 с тем же порядком: изданию 1.1 сервер выбирает CBC, минуя GCM
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны от издания 1.1 до 1.2
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, TLS11, TLS12);
		// Ставим клиенту GCM впереди CBC
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		// Ставим серверу GCM впереди CBC
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		// Зажимаем сервер на издание 1.1
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем издание у клиента
		EXPECT_EQ(client.version(), TLS11);
		EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		EXPECT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Объявляем связь клиента
		client::context_t client;
		// Задаём клиенту пределы изданий
		ASSERT_EQ(client.versions(TLS11, TLS12), context::error_t::NONE);
		// Проверяем отказ заведения
		EXPECT_EQ(client.start(), context::error_t::SETTINGS);
		// Объявляем другую связь клиента
		client::context_t another;
		// Проверяем отказ на несуразном пределе
		EXPECT_EQ(another.versions(0x0301, TLS12), context::error_t::SETTINGS);
	}
}

/**
 * Проверка подлинности клиента изданием 1.1: подпись владения ключом без схемы - MD5 ‖ SHA-1 у
 * RSA и SHA-1 у ECDSA, запрос подлинности без перечня схем
 */
TEST(Dtls10Test, Mutual){
	// Задаём ключи подлинности сторон
	static const char * KEYS[] = {"ec256", "rsa2048"};
	/**
	 * Перебираем: ключи подлинности клиента, пока они не кончатся
	 */
	for(size_t k = 0; k < 2; k++){
		// Объявляем подлинности сторон
		context::credential_t mine, theirs;
		// Считываем подлинность сервера
		ASSERT_TRUE(keyfile("ec256", mine));
		// Считываем подлинность клиента
		ASSERT_TRUE(keyfile(KEYS[k], theirs));
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.1
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, mine, TLS11, TLS11);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Задаём клиенту подлинность
		client.credential(theirs);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Обмениваемся дейтаграммами
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established()) << KEYS[k] << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		// Проверяем цепочку клиента
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		// Сверяем сертификат клиента
		EXPECT_EQ(server.peer()[0], theirs.chain[0]);
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server));
	}
}

/**
 * Проверка чужого эталона: наш клиент против openssl s_server -dtls1, наш сервер против
 * s_client -dtls1; наборы лишь под @SECLEVEL=0
 */
/**
 * @brief Функция проверки, ведёт ли openssl стенда живой DTLS 1.0 сам с собой
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
		// Выводим отрицательный результат - порта нет
		return false;
	// Составляем пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Составляем основу имён стенда
	const std::string base = "/tmp/ants-dtls10-self-" + std::to_string(number);
	// Составляем имена держателя и журналов
	const std::string holder = base + ".fifo", log = base + ".server.log", out = base + ".client.log";
	::remove(holder.c_str());
	// Если FIFO завести не удалось
	if(fifo(holder.c_str()) != 0)
		// Выводим отрицательный результат - FIFO завести не удалось
		return false;
	// Поднимаем сервер openssl
	const toolkit_t toolkit = inspect();
	// Поднимаем сервер openssl
	const bool started = launch("openssl s_server" + accepting(toolkit, number) + " -dtls1 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder);
	// Итог
	bool agreed = false;
	// Если сервер поднялся
	if(started){
		// Ставим стража серверу
		sentinel_t sentinel(log + ".pid");
		// Дожидаемся готовности сервера
		std::string text;
		// Дожидаемся готовности сервера
		if(!awaited(log, "ACCEPT", text)){
			// Останавливаем сервер
			sentinel.halt();
			::remove(holder.c_str());
			::remove(log.c_str());
			// Выводим отрицательный результат - сервер не готов
			return false;
		}
		// Клиент openssl против него
		(void) shell("(printf 'ping' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1 -CAfile " + crt + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300 -servername localhost -ign_eof -verify_return_error >" + out + " 2>&1 &); sleep 3; pkill -f 'openssl s_client -connect 127.0.0.1:" + std::to_string(number) + "' >/dev/null 2>&1; true");
		// Ищем договорённый набор у клиента
		std::ifstream file(out);
		// Объявляем строку журнала
		std::string line;
		/**
		 * Перебираем: строки журнала клиента, пока они не кончатся
		 */
		while(std::getline(file, line))
			// Ищем договорённый набор
			agreed = (agreed || (line.find("Cipher    : ECDHE-ECDSA-AES128-SHA") != std::string::npos) || (line.find("Cipher is ECDHE-ECDSA-AES128-SHA") != std::string::npos));
		// Останавливаем сервер
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
	// Осматриваем оснастку openssl
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем: оснастка openssl не найдена
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если стенд без DTLS 1.0
	if(!listed("s_server", "dtls1") || !listed("s_client", "dtls1")){
		// Пропускаем: оснастка openssl не ведёт DTLS 1.0
		GTEST_SKIP() << "openssl без DTLS 1.0";
	}
	// Если нет TLS 1.2 либо главного секрета
	if(!toolkit.tls12 || !toolkit.master){
		// Пропускаем: нужны TLS 1.2 и расширенный главный секрет
		GTEST_SKIP() << "openssl без TLS 1.2 либо без расширенного главного секрета (старше 1.1.0)";
	}
	// Если набора нет в оснастке
	if(shell("openssl ciphers -s 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' >/dev/null 2>&1") != 0){
		// Пропускаем: набора ECDHE-ECDSA-AES128-SHA нет в оснастке
		GTEST_SKIP() << "openssl без ECDHE-ECDSA-AES128-SHA";
	}
	// Свойство оснастки, не номер версии: openssl 3.5.7 на Fedora не ведёт DTLS 1.0 сам с собой (нет годной схемы подписи), 3.6.3 на macOS ведёт
	// Если openssl не договаривается сам с собой
	if(!dtlsable()){
		// Пропускаем: стенд не договаривается по DTLS 1.0 сам с собой
		GTEST_SKIP() << "openssl на этом стенде не договаривается сам с собой по -dtls1 (сборка либо политика без DTLS 1.0)";
	}
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Составляем пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Ищем вольный порт
		const uint16_t number = vacant(true);
		// Проверяем, что порт нашёлся
		ASSERT_NE(number, 0);
		// Составляем имя журнала сервера
		const std::string log = "/tmp/ants-dtls10-server-" + std::to_string(number) + ".log";
		// Составляем имя держателя
		const std::string holder = "/tmp/ants-dtls10-server-" + std::to_string(number) + ".fifo";
		// Убираем остатки держателя
		::remove(holder.c_str());
		// Заводим держатель
		ASSERT_EQ(fifo(holder.c_str()), 0);
		// Поднимаем сервер openssl
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1 -listen -no_ticket -cert " + crt + " -key " + key + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		// Ставим стража серверу
		sentinel_t sentinel(log + ".pid");
		// Объявляем буфер журнала
		std::string text;
		// Дожидаемся готовности сервера
		ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
		// Объявляем привязанный порт
		uint16_t bound = 0;
		// Заводим сокет
		const int fd = socketing(0, bound);
		// Проверяем сокет
		ASSERT_GE(fd, 0);
		// Объявляем адрес собеседника
		struct sockaddr_in peer;
		// Очищаем адрес собеседника
		::memset(&peer, 0, sizeof(peer));
		// Задаём семейство адреса
		peer.sin_family = AF_INET;
		// Задаём обратный адрес
		peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		// Задаём порт сервера
		peer.sin_port = htons(number);
		// Объявляем связь клиента
		client::context_t client;
		// Задаём клиенту дейтаграммы
		client.transport(context::transport_t::DATAGRAMS);
		// Задаём клиенту набор шифрования
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		// Задаём клиенту группу
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Зажимаем клиента на издание 1.1
		ASSERT_EQ(client.versions(TLS11, TLS11), context::error_t::NONE);
		// Задаём клиенту предел дейтаграммы
		client.mtu(300);
		// Задаём имя сервера
		client.name("localhost");
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Ведём обмен до установления связи
		const bool complete = relay(client, fd, peer, 400);
		// Если связь не установилась
		if(!complete){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		// Проверяем установление связи
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Проверяем издание у клиента
		EXPECT_EQ(client.version(), TLS11);
		// Проверяем договорённый набор
		EXPECT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		// Закрываем сокет
		closing(fd);
		// Останавливаем сервер
		sentinel.halt();
		// Снимаем журнал сервера
		(void) settle(log, text);
		// Убираем журнал сервера
		::remove(log.c_str());
		// Убираем держатель
		::remove(holder.c_str());
	}
	{
		// Объявляем номер порта
		uint16_t number = 0;
		// Заводим сокет
		const int fd = socketing(0, number);
		// Проверяем сокет
		ASSERT_GE(fd, 0);
		// Составляем имя журнала клиента
		const std::string log = "/tmp/ants-dtls10-client-" + std::to_string(number) + ".log";
		// Задаём запрос клиента
		const string request = "hello from openssl over dtls 1.0\n";
		// Поднимаем клиента openssl
		ASSERT_TRUE(launch("printf '" + request + "' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1 -CAfile " + crt + " -cipher 'ECDHE-ECDSA-AES128-SHA@SECLEVEL=0' -mtu 300 -servername localhost -verify_return_error -ign_eof >" + log + " 2>&1", log, log + ".pid", std::string()));
		// Ставим стража клиенту
		sentinel_t sentinel(log + ".pid");
		// Объявляем адрес собеседника
		struct sockaddr_in peer;
		// Объявляем длину адреса
		socklen_t length = sizeof(peer);
		// Объявляем буфер дейтаграмм
		uint8_t buffer[65536];
		// Объявляем длину принятого
		ssize_t received = -1;
		/**
		 * Перебираем: попытки приёма, пока данные не придут либо попытки не кончатся
		 */
		for(size_t i = 0; (i < 150) && (received <= 0); i++)
			// Принимаем дейтаграмму клиента
			received = receivingfrom(fd, buffer, sizeof(buffer), reinterpret_cast <struct sockaddr *> (&peer), &length);
		// Проверяем, что данные пришли
		ASSERT_GT(received, 0);
		// Объявляем связь сервера
		server::context_t server;
		// Задаём серверу дейтаграммы
		server.transport(context::transport_t::DATAGRAMS);
		// Задаём серверу набор шифрования
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA});
		// Задаём серверу группу
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Зажимаем сервер на издание 1.1
		ASSERT_EQ(server.versions(TLS11, TLS11), context::error_t::NONE);
		// Задаём серверу подлинность
		server.credential(credential);
		// Задаём серверу предел дейтаграммы
		server.mtu(300);
		// Получаем байты адреса собеседника
		const uint8_t * bytes = reinterpret_cast <const uint8_t *> (&peer);
		// Задаём серверу адрес собеседника
		ASSERT_TRUE(server.address(view_t(bytes, sizeof(peer))));
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Передаём серверу принятую дейтаграмму
		server.push(view_t(buffer, static_cast <size_t> (received)));
		// Принятые прикладные данные
		vector <uint8_t> plaintext;
		/**
		 * Выполняем обмен дейтаграммами с s_client, пока связь не установится и данные не придут
		 */
		for(size_t i = 0; (i < 400) && (server.state() != context::state_t::FAILED) && (server.state() != context::state_t::CLOSED) && plaintext.empty(); i++){
			/**
			 * Перебираем: шаги обмена, пока связь не установится и данные не придут
			 */
			while(server.output().size > 0){
				// Получаем исходящую дейтаграмму сервера
				const view_t data = server.output();
				// Отправляем дейтаграмму клиенту
				(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
				// Убираем дейтаграмму из вывода
				server.consume(data.size);
			}
			// Принимаем дейтаграмму клиента
			received = receiving(fd, buffer, sizeof(buffer));
			// Если данные пришли
			if(received > 0)
				// Передаём данные серверу
				server.push(view_t(buffer, static_cast <size_t> (received)));
			else if(server.timeout() > 0)
				// Сдвигаем время сервера
				server.elapsed();
			// Если связь установилась
			if(server.established())
				// Читаем прикладные данные
				(void) server.read(plaintext);
		}
		// Если связь не установилась
		if(!server.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
		// Проверяем установление связи
		ASSERT_TRUE(server.established()) << "отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description) << " состояние " << static_cast <int> (server.state());
		// Проверяем издание у сервера
		EXPECT_EQ(server.version(), TLS11);
		EXPECT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA);
		EXPECT_EQ(string(plaintext.begin(), plaintext.end()), request);
		// Закрываем сокет
		closing(fd);
		// Останавливаем клиента
		sentinel.halt();
		// Объявляем буфер журнала
		std::string text;
		// Снимаем журнал клиента
		(void) settle(log, text);
		// Проверяем протокол у клиента
		EXPECT_NE(text.find("Protocol  : DTLSv1"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь изданием DTLS 1.0 либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(Dtls10Test, Starved){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Считываем ключи набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем признак нехватки памяти
	bool starved = false;
	// Объявляем признак установления связи
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Объявляем связь клиента
		client::context_t client;
		// Объявляем связь сервера
		server::context_t server;
		// Настраиваем стороны на издание 1.1
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA, credential, TLS11, TLS11);
		// Объявляем итоги сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Задаём запас выделений
			starve::ration_t ration(budget);
			// Запускаем сервер
			first = server.start();
			// Запускаем клиента
			second = client.start();
			// Если обе стороны завелись
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Обмениваемся дейтаграммами
				converse(client, server);
				// Снимаем итог сервера
				first = server.error();
				// Снимаем итог клиента
				second = client.error();
			}
		}
		// Отмечаем нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		// Составляем признак законности итогов
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем законность итогов
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Проверяем установление связи
		complete = (client.established() && server.established());
		// Если связь установилась
		if(complete)
			// Проверяем издание у клиента
			EXPECT_EQ(client.version(), TLS11);
	}
	// Проверяем, что нехватка памяти была
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
