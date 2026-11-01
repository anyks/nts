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
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <adversary.hpp>
#include <gost.hpp>
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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора для чтения
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Объявляем буфер содержимого файла
		vector <uint8_t> result;
		// Проверяем, что файл набора открылся
		if(file.is_open())
			// Считываем содержимое файла набора целиком
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Возвращаем содержимое файла набора
		return result;
	}
	/**
	 * @brief Функция составления подлинности стороны из ключей набора (identity.hpp вырабатывает ГОСТ)
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		// Загружаем секретный ключ стороны из набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Загружаем сертификат стороны из набора
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Проверяем, что ключ и сертификат набора прочитались
		if(result.secret.empty() || text.empty())
			// Сообщаем о неудаче составления подлинности
			return false;
		// Очищаем цепочку сертификатов подлинности
		result.chain.clear();
		// Разбираем сертификаты и возвращаем признак успеха
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция получения имени владельца сертификата набора как записано
	 *
	 * @param name имя сертификата набора
	 * @return     DER-запись имени владельца либо пусто
	 *
	 */
	vector <uint8_t> subject(const char * name) noexcept {
		// Загружаем сертификат набора для разбора
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Объявляем цепочку разобранных сертификатов
		vector <vector <uint8_t>> chain;
		// Проверяем, что сертификат набора разобрался в непустую цепочку
		if(text.empty() || (pem::certificates(std::string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Возвращаем пустую запись имени
			return vector <uint8_t> ();
		// Объявляем разборщик сертификата
		x509::certificate_t certificate;
		// Разбираем сертификат цепочки и проверяем итог
		if(certificate.parse(view_t(chain[0].data(), chain[0].size())) != x509::error_t::NONE)
			// Возвращаем пустую запись имени
			return vector <uint8_t> ();
		// Извлекаем запись имени владельца сертификата
		const view_t element = certificate.subjects().element;
		// Возвращаем запись имени владельца
		return vector <uint8_t> (element.data, element.data + element.size);
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
			// Получаем исходящие байты стороны клиента
			view_t data = client.output();
			// Проверяем, что сторона клиента имеет, что сказать
			if(data.size > 0){
				// Копируем исходящие байты клиента в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сообщаем стороне клиента о выдаче байт
				client.consume(buffer.size());
				// Передаём байты стороне сервера
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем, что байты между сторонами передавались
				moved = true;
			}
			// Получаем исходящие байты стороны сервера
			data = server.output();
			// Проверяем, что сторона сервера имеет, что сказать
			if(data.size > 0){
				// Копируем исходящие байты сервера в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сообщаем стороне сервера о выдаче байт
				server.consume(buffer.size());
				// Передаём байты стороне клиента
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем, что байты между сторонами передавались
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Сообщаем о неудаче передачи байтов
			return false;
		}
		// Возвращаем признак передачи байтов
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
	 * @brief Функция настройки сторон: подлинности обеих, запрос подлинности и перечень центров у сервера
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param mine   подлинность сервера
	 * @param theirs подлинность клиента
	 * @param names  перечень имён центров, пустой - не задаётся
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & mine, const context::credential_t & theirs, const vector <vector <uint8_t>> & names) noexcept {
		// Назначаем подлинность стороне сервера
		server.credential(mine);
		// Включаем запрос подлинности у сервера
		server.request(true);
		// Назначаем подлинность стороне клиента
		client.credential(theirs);
		// Проверяем, что перечень центров задан
		if(!names.empty())
			// Назначаем перечень центров стороне сервера
			server.authorities(names);
	}
};

/**
 * Проверка обмена изданием 1.3: перечень доходит в запросе подлинности, равен имени
 * владельца сертификата центра, подлинность клиента проходит; без перечня - пусто
 */
TEST(AuthoritiesTest, Loopback){
	// Объявляем подлинности сторон связи
	context::credential_t mine, theirs;
	// Составляем подлинность сервера из ключа набора
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("rsa2048", theirs));
	// Извлекаем имена владельцев центров набора
	const vector <uint8_t> root = subject("ca-ec"), other = subject("ca-rsa");
	// Проверяем, что имена центров извлечены
	ASSERT_FALSE(root.empty() || other.empty());
	// Проверяем, что имя центра начинается с записи SEQUENCE
	EXPECT_EQ(root[0], static_cast <uint8_t> (0x30));
	{
		// Объявляем связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны: подлинности, запрос и перечень центров
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> {root, other});
		// Запускаем связь стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон связи
		converse(client, server);
		// Проверяем, что обе стороны связи установили связь
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем, что перечень центров дошёл до клиента двумя именами
		ASSERT_EQ(client.authorities().size(), static_cast <size_t> (2));
		// Проверяем, что первое имя центра дошло до клиента
		EXPECT_EQ(client.authorities()[0], root);
		EXPECT_EQ(client.authorities()[1], other);
		// Проверяем, что сервер принял подлинность клиента
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		// Проверяем, что сервер получил сертификат подлинности клиента
		EXPECT_EQ(server.peer()[0], theirs.chain[0]);
	}
	{
		// Объявляем связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи без перечня центров
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> ());
		// Запускаем связь стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон связи
		converse(client, server);
		// Проверяем, что обе стороны связи установили связь
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что перечень центров не дошёл до клиента
		EXPECT_TRUE(client.authorities().empty());
	}
	{
		// Без запроса подлинности перечень не идёт вовсе
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Назначаем подлинность стороне сервера
		server.credential(mine);
		// Назначаем перечень центров стороне сервера без запроса подлинности
		server.authorities(vector <vector <uint8_t>> {root});
		// Запускаем связь стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон связи
		converse(client, server);
		// Проверяем, что обе стороны связи установили связь
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что перечень центров не дошёл до клиента
		EXPECT_TRUE(client.authorities().empty());
	}
}

/**
 * Проверка издания 1.2: перечень идёт полем запроса подлинности
 */
TEST(AuthoritiesTest, Legacy){
	// Объявляем подлинности сторон связи
	context::credential_t mine, theirs;
	// Составляем подлинность сервера из ключа набора
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("rsa2048", theirs));
	// Извлекаем имя владельца центра набора
	const vector <uint8_t> root = subject("ca-ec");
	// Проверяем, что имя центра извлечено
	ASSERT_FALSE(root.empty());
	/**
	 * Перебираем: заданный и пустой перечень центров
	 */
	for(size_t named = 0; named < 2; named++){
		// Объявляем связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи с перечнем по условию итерации
		arrange(client, server, mine, theirs, ((named == 1) ? vector <vector <uint8_t>> {root} : vector <vector <uint8_t>> ()));
		// Ограничиваем издание протокола стороны клиента изданием 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон связи
		converse(client, server);
		// Проверяем, что обе стороны связи установили связь
		ASSERT_TRUE(client.established() && server.established()) << named << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем, что перечень центров дошёл до клиента по условию итерации
		ASSERT_EQ(client.authorities().size(), named);
		// Проверяем, что перечень центров задан
		if(named == 1)
			// Проверяем, что имя центра дошло до клиента
			EXPECT_EQ(client.authorities()[0], root);
		// Проверяем, что подлинность клиента дошла до сервера
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
	}
}

/**
 * Проверка враждебного сервера: пустой перечень, пустое имя, хвост и имя не SEQUENCE в
 * запросе подлинности - decode_error
 */
TEST(AuthoritiesTest, Lying){
	// Задаём таблицу видов искажённых перечней центров
	static const distortion_t MALFORMED[] = {distortion_t::MALCA, distortion_t::HOLLOWCA, distortion_t::TRAILCA, distortion_t::NOTSEQCA};
	/**
	 * Выполняем перебор негодных перечней
	 */
	for(size_t i = 0; i < (sizeof(MALFORMED) / sizeof(MALFORMED[0])); i++){
		// Враждебный сервер набора проверок говорит лишь наборами ГОСТ
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Ограничиваем наборы шифров связи клиента набором ГОСТ
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		// Запускаем связь стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Подменяем ответ враждебного сервера негодным перечнем
		ASSERT_TRUE(adversary(client, MALFORMED[i])) << i;
		// Проверяем, что связь клиента отказалась от сообщения
		EXPECT_EQ(client.error(), context::error_t::MESSAGE) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::DECODE) << i;
		// Проверяем, что связь клиента не установилась
		EXPECT_FALSE(client.established()) << i;
		// Проверяем, что перечень центров у клиента остался пустым
		EXPECT_TRUE(client.authorities().empty()) << i;
	}
}

/**
 * Проверка отказов: негодное имя у сервера - SETTINGS при заведении; разборщик и сборщик
 * перечня на пустоте, не SEQUENCE и обрезании
 */
TEST(AuthoritiesTest, Refusals){
	// Объявляем подлинность стороны сервера
	context::credential_t mine;
	// Составляем подлинность сервера из ключа набора
	ASSERT_TRUE(keyfile("ec256", mine));
	{
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Назначаем подлинность стороне сервера
		server.credential(mine);
		// Включаем запрос подлинности у сервера
		server.request(true);
		// Назначаем перечень центров с пустым именем
		server.authorities(vector <vector <uint8_t>> {vector <uint8_t> ()});
		// Проверяем, что сервер отказывает в заведении
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Назначаем подлинность стороне сервера
		server.credential(mine);
		// Включаем запрос подлинности у сервера
		server.request(true);
		// Назначаем перечень центров с именем не SEQUENCE
		server.authorities(vector <vector <uint8_t>> {vector <uint8_t> {0x31, 0x00}});
		// Проверяем, что сервер отказывает в заведении
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	// Задаём проверочные байтовые образы перечней центров
	static const uint8_t EMPTYLIST[] = {0x00, 0x00}, HOLLOWLIST[] = {0x00, 0x02, 0x00, 0x00}, TRAILLIST[] = {0x00, 0x03, 0x00, 0x01, 0x30, 0xFF}, NOTSEQ[] = {0x00, 0x03, 0x00, 0x01, 0x31};
	// Объявляем перечень разобранных имён центров
	vector <vector <uint8_t>> names;
	// Проверяем отказ разборщика перечня на пустоте
	EXPECT_EQ(extension::authorities(view_t(EMPTYLIST, sizeof(EMPTYLIST)), names), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(view_t(HOLLOWLIST, sizeof(HOLLOWLIST)), names), extension::error_t::EMPTY);
	EXPECT_EQ(extension::authorities(view_t(TRAILLIST, sizeof(TRAILLIST)), names), extension::error_t::TRAILING);
	EXPECT_EQ(extension::authorities(view_t(NOTSEQ, sizeof(NOTSEQ)), names), extension::error_t::EMPTY);
	// Извлекаем имена владельцев центров набора
	const vector <uint8_t> root = subject("ca-ec"), other = subject("ca-rsa");
	// Объявляем буфер собранного перечня
	vector <uint8_t> list;
	// Собираем перечень из имён центров и проверяем итог
	ASSERT_EQ(extension::authorities(vector <vector <uint8_t>> {root, other}, list), extension::error_t::NONE);
	/**
	 * Отказ: обрезание перечня на всякой длине
	 */
	for(size_t i = 0; i < list.size(); i++){
		// Очищаем перечень разобранных имён
		names.clear();
		// Проверяем, что обрезанный перечень отвергается
		EXPECT_NE(extension::authorities(view_t(list.data(), i), names), extension::error_t::NONE) << "длина " << i;
	}
	// Очищаем перечень разобранных имён
	names.clear();
	// Разбираем полный перечень и проверяем итог
	ASSERT_EQ(extension::authorities(view_t(list.data(), list.size()), names), extension::error_t::NONE);
	ASSERT_EQ(names.size(), static_cast <size_t> (2));
	// Проверяем, что первое имя центра разобралось из перечня
	EXPECT_EQ(names[0], root);
	EXPECT_EQ(names[1], other);
	// Объявляем буфер пересобранного перечня
	vector <uint8_t> rebuilt;
	// Проверяем отказ сборщика перечня на пустоте
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
	// Запрашиваем сведения о чужом эталоне
	const toolkit_t toolkit = inspect();
	// Проверяем, что чужой эталон доступен
	if(!toolkit.present){
		// Пропускаем проверку без доступного чужого эталона
		GTEST_SKIP() << "openssl недоступен";
	}
	// Проверяем, что чужой эталон поддерживает издание 1.3
	if(!toolkit.tls13){
		// Пропускаем проверку без издания 1.3 у чужого эталона
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Объявляем подлинность стороны сервера
	context::credential_t credential;
	// Составляем подлинность сервера из ключа набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Извлекаем имя владельца сертификата набора
	const vector <uint8_t> owner = subject("ec256");
	// Проверяем, что имя владельца извлечено
	ASSERT_FALSE(owner.empty());
	// Составляем пути к сертификату и ключу набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Запрашиваем вакантный порт стенда
		const uint16_t number = vacant(false);
		// Проверяем, что порт стенда получен
		ASSERT_NE(number, 0);
		// Составляем путь к журналу чужого эталона
		const std::string log = "/tmp/ants-authorities-server-" + std::to_string(number) + ".log";
		// Запускаем чужой эталон в роли сервера с запросом подлинности
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Объявляем стража процесса чужого эталона
		sentinel_t sentinel(log + ".pid");
		// Налаживаем соединение с портом стенда
		const int fd = dial(number);
		// Проверяем, что соединение с портом налажено
		ASSERT_GE(fd, 0) << "порт " << number;
		// Объявляем связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Ограничиваем наборы шифров связи клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Ограничиваем группы связи клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Назначаем подлинность стороне клиента
		client.credential(credential);
		// Назначаем имя хоста стороне клиента
		client.name("localhost");
		// Запускаем связь стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Перебираем: попытки рукопожатия, пока связь не установлена и не отказала
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты между клиентом и чужим эталоном
			relay(client, fd);
		// Проверяем, что связь клиента с чужим эталоном установилась
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// s_server с -CAfile объявляет владельца файла центров приемлемым издателем
		ASSERT_EQ(client.authorities().size(), static_cast <size_t> (1));
		// Проверяем, что до клиента дошло имя владельца центра
		EXPECT_EQ(client.authorities()[0], owner);
		// Завершаем соединение с портом стенда
		closing(fd);
		// Останавливаем процесс чужого эталона
		sentinel.halt();
		// Объявляем буфер журнала чужого эталона
		std::string journal;
		// Дожидаемся завершения процесса чужого эталона и читаем журнал
		(void) settle(log, journal);
		::remove(log.c_str());
	}
	{
		// Объявляем номер порта стенда
		uint16_t number = 0;
		// Открываем прослушиватель порта стенда
		const int listener = harbour(number);
		// Проверяем, что прослушиватель порта открыт
		ASSERT_GE(listener, 0);
		// Составляем путь к журналу чужого эталона
		const std::string log = "/tmp/ants-authorities-client-" + std::to_string(number) + ".log";
		// Запускаем чужой эталон в роли клиента с подлинностью
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -cert " + crt + " -key " + key + " -CAfile " + crt + " -servername localhost </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Объявляем стража процесса чужого эталона
		sentinel_t sentinel(log + ".pid");
		// Принимаем соединение чужого эталона
		const int fd = greeted(listener);
		// Проверяем, что соединение чужого эталона принято
		ASSERT_GE(fd, 0);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Ограничиваем наборы шифров связи сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Ограничиваем группы связи сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Назначаем подлинность стороне сервера
		server.credential(credential);
		// Включаем запрос подлинности у сервера
		server.request(true);
		// Назначаем перечень центров стороне сервера
		server.authorities(vector <vector <uint8_t>> {owner});
		// Запускаем связь стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Обслуживаем соединение чужого эталона до завершения
		const bool complete = serve(server, fd);
		// Проверяем, что соединение чужого эталона завершилось
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
		// Проверяем, что связь сервера завершилась без отказа
		ASSERT_EQ(server.error(), context::error_t::NONE);
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		// Проверяем, что обслуживание чужого эталона завершилось штатно
		ASSERT_TRUE(farewell(server, fd));
		// Завершаем соединение с портом стенда
		closing(fd);
		closing(listener);
		// Объявляем буфер журнала чужого эталона
		std::string text;
		// Дожидаемся завершения процесса чужого эталона и читаем журнал
		ASSERT_TRUE(settle(log, text)) << text;
		// s_client печатает перечень приемлемых центров из запроса подлинности
		EXPECT_NE(text.find("Acceptable client certificate CA names"), std::string::npos) << text;
		// Проверяем, что журнал не сообщает о пустом перечне центров
		EXPECT_EQ(text.find("No client certificate CA names sent"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка под пайком памяти: связь с перечнем центров либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(AuthoritiesTest, Starved){
	// Объявляем подлинности сторон связи
	context::credential_t mine, theirs;
	// Составляем подлинность сервера из ключа набора
	ASSERT_TRUE(keyfile("ec256", mine));
	ASSERT_TRUE(keyfile("ec384", theirs));
	// Извлекаем имя владельца центра набора
	const vector <uint8_t> root = subject("ca-ec");
	// Проверяем, что имя центра извлечено
	ASSERT_FALSE(root.empty());
	// Объявляем признак встреченной нехватки памяти
	bool starved = false;
	// Объявляем признак установленной связи
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Объявляем связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны: подлинности, запрос и перечень центров
		arrange(client, server, mine, theirs, vector <vector <uint8_t>> {root});
		// Объявляем итоги заведения сторон связи
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Объявляем пайок выделений стенда
			starve::ration_t ration(budget);
			// Заводим связь стороны сервера под пайком
			first = server.start();
			// Заводим связь стороны клиента под пайком
			second = client.start();
			// Проверяем, что обе стороны завелись под пайком
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие сторон связи
				converse(client, server);
				// Снимаем итог заведения стороны сервера
				first = server.error();
				// Снимаем итог заведения стороны клиента
				second = client.error();
			}
		}
		// Отмечаем встреченную нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		// Составляем признак законности итогов заведения сторон
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем, что итоги заведения сторон законны
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Отмечаем установление связи под пайком
		complete = (client.established() && server.established());
		// Проверяем, что связь под пайком установилась
		if(complete){
			// Проверяем, что перечень центров дошёл до клиента одним именем
			ASSERT_EQ(client.authorities().size(), static_cast <size_t> (1));
			// Проверяем, что до клиента дошло имя владельца центра
			EXPECT_EQ(client.authorities()[0], root);
		}
	}
	// Проверяем, что нехватка памяти встречалась
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
