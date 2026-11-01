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
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <identity.hpp>
#include <gost.hpp>
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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора на чтение
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла набора
		vector <uint8_t> result;
		// Проверяем успех открытия
		if(file.is_open())
			// Считываем содержимое файла
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Возвращаем содержимое файла
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
		// Считываем секретный ключ набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Считываем сертификат набора
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Проверяем непустоту ключей
		if(result.secret.empty() || text.empty())
			// Возвращаем признак неудачи
			return false;
		// Очищаем цепочку сертификатов
		result.chain.clear();
		// Разбираем цепочку сертификатов и возвращаем признак успеха
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция составления подлинности стороны из цепочки набора в три звена
	 *
	 * @param kind   вид ключа: ec либо rsa
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool chained(const char * kind, context::credential_t & result) noexcept {
		// Считываем секретный ключ листа
		result.secret = corpus((std::string("leaf-") + kind + ".key").c_str());
		// Считываем цепочку из трёх звеньев
		const vector <uint8_t> text = corpus((std::string("chain-") + kind + ".pem").c_str());
		// Проверяем непустоту ключей
		if(result.secret.empty() || text.empty())
			// Возвращаем признак неудачи
			return false;
		// Очищаем цепочку сертификатов
		result.chain.clear();
		// Разбираем цепочку и проверяем число звеньев
		return ((pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE) && (result.chain.size() == 3));
	}
	/**
	 * @brief Функция составления правдоподобной метки времени: издание 1, журнал, миг, без расширений, подпись ecdsa_secp256r1_sha256
	 *
	 * @param seed байт, которым заполняются журнал и подпись
	 * @return     метка времени как записана
	 *
	 */
	vector <uint8_t> stamp(const uint8_t seed) noexcept {
		// Собираемая метка времени
		vector <uint8_t> result;
		// Записываем издание метки
		result.push_back(0x00);
		// Дописываем идентификатор журнала
		result.insert(result.end(), 32, seed);
		// Момент времени метки
		static const uint8_t MOMENT[] = {0x00, 0x00, 0x01, 0x8F, 0x00, 0x00, 0x00, 0x00};
		// Дописываем момент времени
		result.insert(result.end(), MOMENT, MOMENT + sizeof(MOMENT));
		// Дописываем нулевую длину расширений
		result.push_back(0x00);
		result.push_back(0x00);
		result.push_back(0x04);
		result.push_back(0x03);
		result.push_back(0x00);
		result.push_back(0x40);
		// Дописываем подпись на 64 байта
		result.insert(result.end(), 64, static_cast <uint8_t> (seed ^ 0x5A));
		// Возвращаем метку времени
		return result;
	}
	/**
	 * @brief Функция составления перечня меток времени из двух записей
	 *
	 * @return перечень как записан
	 *
	 */
	vector <uint8_t> listing() noexcept {
		// Собираемый перечень меток
		vector <uint8_t> result;
		// Собираем перечень из двух меток
		(void) extension::timestamps(vector <vector <uint8_t>> {stamp(0x11), stamp(0x22)}, result);
		// Возвращаем перечень меток
		return result;
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
		// Признак передачи байтов
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Запрашиваем вывод стороны клиента
			view_t data = client.output();
			// Проверяем наличие байтов
			if(data.size > 0){
				// Копия байтов вывода
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сообщаем клиенту о потреблённых байтах
				client.consume(buffer.size());
				// Передаём байты стороне сервера
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов
				moved = true;
			}
			// Запрашиваем вывод стороны сервера
			data = server.output();
			// Проверяем наличие байтов
			if(data.size > 0){
				// Копия байтов вывода
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сообщаем серверу о потреблённых байтах
				server.consume(buffer.size());
				// Передаём байты стороне клиента
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Возвращаем признак неудачи
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
	 * @brief Функция настройки сторон: подлинность сервера, запрос у клиента и перечень у сервера по заказу
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param asking     запрашивает ли клиент метки времени
	 * @param list       перечень меток времени сервера, пустой - не задаётся
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const bool asking, const vector <uint8_t> & list) noexcept {
		// Задаём подлинность сервера
		server.credential(credential);
		// Задаём запрос меток у клиента
		client.timestamps(asking);
		// Проверяем непустоту перечня сервера
		if(!list.empty())
			// Задаём перечень меток серверу
			server.timestamps(list);
	}
};

/**
 * Проверка обмена изданием 1.3: перечень идёт записью листа по запросу, разбирается на
 * записи; без запроса сервер молчит; без перечня у сервера ответа нет
 */
TEST(SctTest, Loopback){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из цепочки набора
	ASSERT_TRUE(chained("ec", credential));
	// Перечень меток времени
	const vector <uint8_t> list = listing();
	// Проверяем непустоту перечня
	ASSERT_FALSE(list.empty());
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, true, list);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем число сертификатов стороны клиента
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (3));
		// Проверяем совпадение перечня с заданным
		EXPECT_EQ(client.timestamps(), list);
		// Разобранные записи перечня
		vector <vector <uint8_t>> entries;
		// Разбираем перечень на записи
		ASSERT_EQ(extension::timestamps(view_t(client.timestamps().data(), client.timestamps().size()), entries), extension::error_t::NONE);
		ASSERT_EQ(entries.size(), static_cast <size_t> (2));
		// Сверяем первую запись с меткой
		EXPECT_EQ(entries[0], stamp(0x11));
		EXPECT_EQ(entries[1], stamp(0x22));
		// Возобновление без сертификата перечня не несёт
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем выдачу билета
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Связь возобновляющего клиента
		client::context_t resuming;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(resuming);
		// Связь возобновлённого сервера
		server::context_t resumed;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(resumed);
		// Настраиваем стороны связи
		arrange(resuming, resumed, credential, true, list);
		// Задаём билет клиенту
		resuming.resume(client.tickets()[0]);
		// Задаём билеты серверу
		resumed.resume(server.tickets());
		// Запускаем сервер
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(resuming, resumed);
		// Проверяем установление связи и общий секрет
		ASSERT_TRUE(resuming.established() && resumed.established() && resuming.shared());
		// Проверяем пустоту перечня при возобновлении
		EXPECT_TRUE(resuming.timestamps().empty());
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи без запроса меток
		arrange(client, server, credential, false, list);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем пустоту перечня без запроса
		EXPECT_TRUE(client.timestamps().empty());
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи без перечня сервера
		arrange(client, server, credential, true, vector <uint8_t> ());
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем пустоту перечня без перечня сервера
		EXPECT_TRUE(client.timestamps().empty());
	}
}

/**
 * Проверка издания 1.2: перечень идёт приветствием сервера по запросу; при возобновлении
 * билетом не идёт
 */
TEST(SctTest, Legacy){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из цепочки набора
	ASSERT_TRUE(chained("ec", credential));
	// Перечень меток времени
	const vector <uint8_t> list = listing();
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Настраиваем стороны связи
	arrange(client, server, credential, true, list);
	// Задаём издание 1.2 стороне клиента
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Объявляем хранилище билетов
	const vector <uint8_t> vault(32, 0x33);
	// Задаём хранилище серверу
	server.vault(vault);
	// Запускаем сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем совпадение перечня с заданным
	EXPECT_EQ(client.timestamps(), list);
	// Проверяем выдачу билета
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Связь возобновляющего клиента
	client::context_t resuming;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(resuming);
	// Связь возобновлённого сервера
	server::context_t resumed;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(resumed);
	// Настраиваем стороны связи
	arrange(resuming, resumed, credential, true, list);
	// Задаём издание 1.2 стороне клиента
	ASSERT_EQ(resuming.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(resumed.versions(0x0303, 0x0303), context::error_t::NONE);
	// Задаём хранилище серверу
	resumed.vault(vault);
	// Задаём билет клиенту
	resuming.resume(client.tickets()[0]);
	// Задаём билеты серверу
	resumed.resume(server.tickets());
	// Запускаем сервер
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(resuming, resumed);
	// Проверяем установление связи
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.shared() && resumed.shared());
	// Проверяем пустоту перечня при возобновлении
	EXPECT_TRUE(resuming.timestamps().empty());
}

/**
 * Проверка профиля отпечатка: снимок приветствия с расширением 18 включает запрос сам, и
 * приветствие по профилю сходится с ним видами расширений
 */
TEST(SctTest, Profile){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из цепочки набора
	ASSERT_TRUE(chained("ec", credential));
	// Перечень меток времени
	const vector <uint8_t> list = listing();
	// Снимок профиля отпечатка
	fingerprint::profile_t source;
	{
		// Связь стороны донора
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём имя сервера донору
		donor.name("example.com");
		// Запрашиваем метки у донора
		donor.timestamps(true);
		// Запускаем донора
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	// Признак нахождения расширения меток
	bool found = false;
	/**
	 * Выполняем перебор расширений снимка
	 */
	for(size_t i = 0; i < source.extensions.size(); i++){
		// Проверяем вид расширения на запрос меток
		if(source.extensions[i].type == static_cast <uint16_t> (extension::type_t::TIMESTAMPS)){
			// Отмечаем нахождение расширения
			found = true;
			// Проверяем пустоту тела расширения
			EXPECT_TRUE(source.extensions[i].data.empty());
		}
	}
	// Проверяем нахождение расширения запроса
	ASSERT_TRUE(found);
	// Связь стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём имя сервера клиенту
	client.name("example.com");
	// Задаём профиль отпечатка клиенту
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Задаём подлинность серверу
	server.credential(credential);
	// Задаём перечень меток серверу
	server.timestamps(list);
	// Запускаем сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профиль сложенного приветствия
	fingerprint::profile_t made;
	// Разбираем приветствие клиента
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	/**
	 * Выполняем сличение видов расширений снимка и сложенного приветствия
	 */
	for(size_t i = 0; i < made.extensions.size(); i++)
		// Сверяем вид расширения снимка и сложенного приветствия
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем совпадение перечня с заданным
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
	// Составляем подлинность враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credential));
	// Таблица негодных перечней
	static const distortion_t MALFORMED[] = {distortion_t::MALSCT, distortion_t::HOLLOWSCT, distortion_t::TRAILSCT};
	/**
	 * Выполняем перебор негодных перечней
	 */
	for(size_t i = 0; i < (sizeof(MALFORMED) / sizeof(MALFORMED[0])); i++){
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Оставляем лишь наборы ГОСТ
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		// Запрашиваем метки у клиента
		client.timestamps(true);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим враждебное рукопожатие
		ASSERT_TRUE(adversary(client, MALFORMED[i], &credential)) << i;
		// Проверяем отказ по меткам времени
		EXPECT_EQ(client.error(), context::error_t::TIMESTAMPS) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::DECODE) << i;
		// Проверяем неустановление связи
		EXPECT_FALSE(client.established()) << i;
		// Проверяем пустоту перечня
		EXPECT_TRUE(client.timestamps().empty()) << i;
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Оставляем лишь наборы ГОСТ
		client.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим враждебное рукопожатие без запроса
		ASSERT_TRUE(adversary(client, distortion_t::UNASKEDSCT, &credential));
		// Проверяем отказ по расширению
		EXPECT_EQ(client.error(), context::error_t::EXTENSION);
		EXPECT_EQ(client.alert().description, alert::description_t::EXTENSION);
		// Проверяем неустановление связи
		EXPECT_FALSE(client.established());
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Запрашиваем метки у клиента
		client.timestamps(true);
		// Запускаем клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим враждебное рукопожатие с перечнем в приветствии
		ASSERT_TRUE(adversary(client, distortion_t::SCTHELLO));
		// Проверяем отказ по сообщению
		EXPECT_EQ(client.error(), context::error_t::MESSAGE);
		EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER);
		// Проверяем неустановление связи
		EXPECT_FALSE(client.established());
	}
}

/**
 * Проверка враждебного клиента: непустое тело запроса - decode_error
 */
TEST(SctTest, Greedy){
	// Враждебный клиент набора проверок говорит лишь наборами ГОСТ
	context::credential_t credential;
	// Составляем подлинность враждебного клиента
	ASSERT_TRUE(identity("anyks.com", credential));
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём подлинность серверу
	server.credential(credential);
	// Оставляем лишь наборы ГОСТ
	server.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	// Задаём перечень меток серверу
	server.timestamps(listing());
	// Запускаем сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Проводим враждебное рукопожатие
	(void) intruder(server, distortion_t::GREEDYSCT, &credential);
	// Проверяем отказ по сообщению
	EXPECT_EQ(server.error(), context::error_t::MESSAGE);
	EXPECT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановление связи
	EXPECT_FALSE(server.established());
	// Проверяем непустоту вывода сервера
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Проверяем запись предупреждения в выводе
	EXPECT_EQ(server.output().data[0], static_cast <uint8_t> (0x15));
}

/**
 * Проверка отказов: негодный перечень у сервера - SETTINGS при заведении; разборщик и
 * сборщик перечня на пустоте и обрезании
 */
TEST(SctTest, Refusals){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из цепочки набора
	ASSERT_TRUE(chained("ec", credential));
	// Таблица негодных перечней разборщика
	static const uint8_t EMPTYLIST[] = {0x00, 0x00}, HOLLOWLIST[] = {0x00, 0x02, 0x00, 0x00}, TRAILLIST[] = {0x00, 0x03, 0x00, 0x01, 0xAA, 0xFF};
	{
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём подлинность серверу
		server.credential(credential);
		// Задаём пустой перечень серверу
		server.timestamps(vector <uint8_t> (EMPTYLIST, EMPTYLIST + sizeof(EMPTYLIST)));
		// Проверяем отказ заведения перечня
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём подлинность серверу
		server.credential(credential);
		// Задаём перечень с пустой записью
		server.timestamps(vector <uint8_t> (HOLLOWLIST, HOLLOWLIST + sizeof(HOLLOWLIST)));
		// Проверяем отказ заведения перечня
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	{
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Задаём подлинность серверу
		server.credential(credential);
		// Задаём перечень с хвостом
		server.timestamps(vector <uint8_t> (TRAILLIST, TRAILLIST + sizeof(TRAILLIST)));
		// Проверяем отказ заведения перечня
		EXPECT_EQ(server.start(), context::error_t::SETTINGS);
	}
	// Разобранные записи перечня
	vector <vector <uint8_t>> entries;
	// Проверяем отказ разборщика на пустом перечне
	EXPECT_EQ(extension::timestamps(view_t(EMPTYLIST, sizeof(EMPTYLIST)), entries), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(view_t(HOLLOWLIST, sizeof(HOLLOWLIST)), entries), extension::error_t::EMPTY);
	EXPECT_EQ(extension::timestamps(view_t(TRAILLIST, sizeof(TRAILLIST)), entries), extension::error_t::TRAILING);
	// Перечень из двух меток
	const vector <uint8_t> list = listing();
	/**
	 * Отказ: обрезание перечня на всякой длине
	 */
	for(size_t i = 0; i < list.size(); i++){
		// Очищаем разобранные записи
		entries.clear();
		// Проверяем отказ разборщика на обрезании
		EXPECT_NE(extension::timestamps(view_t(list.data(), i), entries), extension::error_t::NONE) << "длина " << i;
	}
	// Очищаем разобранные записи
	entries.clear();
	// Проверяем разбор полного перечня
	ASSERT_EQ(extension::timestamps(view_t(list.data(), list.size()), entries), extension::error_t::NONE);
	// Проверяем число разобранных записей
	EXPECT_EQ(entries.size(), static_cast <size_t> (2));
	// Собранный перечень меток
	vector <uint8_t> rebuilt;
	// Собираем перечень из записей
	ASSERT_EQ(extension::timestamps(entries, rebuilt), extension::error_t::NONE);
	// Сверяем собранный перечень с исходным
	EXPECT_EQ(rebuilt, list);
	// Очищаем собранный перечень
	rebuilt.clear();
	// Проверяем отказ сборщика на пустом перечне
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
	// Сводка о системном openssl
	const toolkit_t toolkit = inspect();
	// Проверяем доступность openssl
	if(!toolkit.present){
		// Пропускаем проверку без openssl
		GTEST_SKIP() << "openssl недоступен";
	}
	// Проверяем поддержку TLS 1.3
	if(!toolkit.tls13){
		// Пропускаем проверку без TLS 1.3
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Проверяем наличие ключа ct у s_client
	if(!listed("s_client", "ct")){
		// Пропускаем проверку без ключа ct
		GTEST_SKIP() << "openssl без ключа -ct (собран без CT)";
	}
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из цепочки набора
	ASSERT_TRUE(chained("ec", credential));
	// Путь к корневому сертификату набора
	const std::string root = std::string(CORPUS) + "/ca-ec.crt";
	// Номер порта прослушки
	uint16_t number = 0;
	// Открываем прослушку на местном адресе
	const int listener = harbour(number);
	// Проверяем успех открытия
	ASSERT_GE(listener, 0);
	// Путь к журналу вывода s_client
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
		// Поток чтения ключа журнала
		std::ifstream reader(pubkey);
		// Закодированный ключ журнала
		std::string encoded((std::istreambuf_iterator <char> (reader)), std::istreambuf_iterator <char> ());
		// Проверяем непустоту ключа
		ASSERT_FALSE(encoded.empty());
		// Поток записи описания журнала
		std::ofstream writer(logs);
		// Записываем описание журнала с ключом
		writer << "enabled_logs = ants\n[ants]\ndescription = A-NTS test log\nkey = " << encoded << "\n";
	}
	// Порождаем ключ журнала и запускаем s_client
	ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -ct -ctlogfile " + logs + " -CAfile " + root + " -servername test.anyks.com </dev/null >" + log + " 2>&1", log, log + ".pid"));
	// Страж завершения s_client
	sentinel_t sentinel(log + ".pid");
	// Принимаем подключение на прослушке
	const int fd = greeted(listener);
	// Проверяем успех принятия
	ASSERT_GE(fd, 0);
	// Связь стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Оставляем лишь набор с AES-128-GCM
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Оставляем лишь группу X25519
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Задаём подлинность серверу
	server.credential(credential);
	// Задаём перечень меток серверу
	server.timestamps(listing());
	// Запускаем сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Обслуживаем подключение
	const bool complete = serve(server, fd);
	// Проверяем полноту обслуживания
	ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
	// Проверяем чистоту завершения сервера
	ASSERT_EQ(server.error(), context::error_t::NONE);
	// Проверяем корректное завершение сервером
	ASSERT_TRUE(farewell(server, fd));
	// Закрываем подключение
	closing(fd);
	closing(listener);
	// Текст журнала вывода
	std::string text;
	// Дожидаемся вывода s_client
	ASSERT_TRUE(settle(log, text)) << text;
	// s_client -ct печатает принятые метки: заголовок SCT validation и по записи на метку
	EXPECT_NE(text.find("SCT validation status"), std::string::npos) << text;
	EXPECT_NE(text.find("Signed Certificate Timestamp"), std::string::npos) << text;
	// Удаляем журнал вывода
	::remove(log.c_str());
	::remove(logs.c_str());
	::remove(pubkey.c_str());
}

/**
 * Проверка под пайком памяти: связь с запросом и перечнем либо устанавливается, либо
 * честно отвечает нехваткой памяти
 */
TEST(SctTest, Starved){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность из ключей набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Перечень меток времени
	const vector <uint8_t> list = listing();
	// Признак обнаруженной нехватки памяти
	bool starved = false;
	// Признак завершённости связи
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Связь стороны клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Связь стороны сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, true, list);
		// Итоги сторон сервера и клиента
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Пайок памяти на текущий запас
			starve::ration_t ration(budget);
			// Запускаем сервер под пайком
			first = server.start();
			// Запускаем клиента под пайком
			second = client.start();
			// Проверяем чистоту запуска сторон
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие сторон
				converse(client, server);
				// Запоминаем итог сервера
				first = server.error();
				// Запоминаем итог клиента
				second = client.error();
			}
		}
		// Отмечаем обнаружение нехватки памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		// Проверяем законность итогов сторон
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем законность итогов при текущем запасе
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Запоминаем завершённость связи
		complete = (client.established() && server.established());
		// Проверяем завершённость связи
		if(complete)
			// Сверяем перечень с заданным при завершённости
			EXPECT_EQ(client.timestamps(), list);
	}
	// Проверяем обнаружение нехватки памяти
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
