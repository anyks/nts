/**
 * @file alps.cpp
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
 * @brief Исходный файл проверок прикладных настроек ALPS (draft-vvv-tls-alps): обмен
 *        настройками обеими точками кода, наследование билетом при упреждении, профиль
 *        отпечатка с ALPS, отказы враждебных сторон и пайок памяти
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

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <identity.hpp>
#include <gost.hpp>
#include <adversary.hpp>
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
		// Открываем файл набора
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Объявляем список байтов
		vector <uint8_t> result;
		// Проверяем, что файл открыт
		if(file.is_open())
			// Заполняем заданным байтом
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла набора
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
		// Загружаем содержимое из файла набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Объявляем список байтов
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Проверяем, что данные не пусты
		if(result.secret.empty() || text.empty())
			// Возвращаем признак неудачи
			return false;
		// Очищаем цепочку сертификатов
		result.chain.clear();
		// Возвращаем признак успешности проверки
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция составления области байтов из текста
	 *
	 * @param text текст
	 * @return     область байтов
	 *
	 */
	vector <uint8_t> bytes(const char * text) noexcept {
		// Выводим область байтов из текста
		return vector <uint8_t> (text, text + ::strlen(text));
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
		// Заводим признак передачи байтов
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Объявляем область байтов
			view_t data = client.output();
			// Если вывод стороны не пуст
			if(data.size > 0){
				// Объявляем список байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сокращаем исходящие данные клиента
				client.consume(buffer.size());
				// Передаём байты серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем перенос данных
				moved = true;
			}
			// Запоминаем исходящие данные стороны
			data = server.output();
			// Если вывод стороны не пуст
			if(data.size > 0){
				// Объявляем список байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Сокращаем исходящие данные сервера
				server.consume(buffer.size());
				// Передаём байты клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем перенос данных
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Возвращаем признак неудачи
			return false;
		}
		// Выводим признак того, что байты передавались
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
	 * @brief Функция обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Задаём текст запроса
		const string request = "Запрос по связи с прикладными настройками";
		// Если запись запроса клиентом удалась
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Возвращаем признак неудачи
			return false;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Объявляем список байтов
		vector <uint8_t> received;
		// Если чтение запроса сервером удалось и текст совпал
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Возвращаем признак неудачи
			return false;
		// Задаём текст ответа
		const string answer = "Ответ по связи с прикладными настройками";
		// Если запись ответа сервером удалась
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Возвращаем признак неудачи
			return false;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Если чтение ответа клиентом удалось и текст совпал
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Возвращаем признак неудачи
			return false;
		// Возвращаем признак успеха
		return true;
	}
	/**
	 * @brief Функция настройки сторон под ALPS: протокол h2 у обеих, настройки по заказу
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param mine       настройки клиента для h2 либо nullptr, когда не объявляются
	 * @param theirs     настройки сервера для h2 либо nullptr, когда не объявляются
	 * @param type       точка кода обеих сторон
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const char * mine, const char * theirs, const extension::type_t type) noexcept {
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Задаём прикладные протоколы клиента
		client.protocols(vector <string> {"h2", "http/1.1"});
		// Задаём прикладные протоколы сервера
		server.protocols(vector <string> {"h2"});
		// Если отпечаток своей стороны задан
		if(mine != nullptr)
			// Задаём прикладные настройки клиента
			client.settings("h2", bytes(mine));
		// Если отпечаток чужой стороны задан
		if(theirs != nullptr)
			// Задаём прикладные настройки сервера
			server.settings("h2", bytes(theirs));
		// Задаём кодовую точку клиента
		client.codepoint(type);
		// Задаём кодовую точку сервера
		server.codepoint(type);
	}
	/**
	 * Точки кода ALPS
	 */
	static const extension::type_t POINTS[] = {extension::type_t::SETTINGS, extension::type_t::SETTINGS_OLD};
};

/**
 * Проверка обмена настройками обеими точками кода: настройки доходят в обе стороны,
 * а возобновление без упреждения договаривает их заново
 */
TEST(AlpsTest, Loopback){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	/**
	 * Выполняем перебор точек кода
	 */
	for(size_t p = 0; p < (sizeof(POINTS) / sizeof(POINTS[0])); p++){
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", "server-h2", POINTS[p]);
		// Кодовая точка договорена обеими сторонами
		ASSERT_EQ(client.codepoint(), POINTS[p]);
		ASSERT_EQ(server.codepoint(), POINTS[p]);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << p << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Прикладной протокол согласован по договору
		EXPECT_EQ(client.protocol(), "h2");
		// Проверяем договор прикладных настроек
		EXPECT_TRUE(client.settled());
		EXPECT_TRUE(server.settled());
		// Проверяем обслуживание подключения
		EXPECT_EQ(client.settings(), bytes("server-h2"));
		EXPECT_EQ(server.settings(), bytes("client-h2"));
		// Проверяем обмен прикладными данными
		ASSERT_TRUE(barter(client, server));
		// Проверяем обслуживание подключения
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем размер
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Проверяем снятие журнала процесса
		EXPECT_TRUE(client.tickets()[0].settled);
		// Прикладные настройки сняты с билета без изменений
		EXPECT_EQ(client.tickets()[0].settings, bytes("client-h2"));
		EXPECT_EQ(client.tickets()[0].obtained, bytes("server-h2"));
		// Создаём контекст клиента
		client::context_t resuming;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(resuming);
		// Создаём контекст сервера
		server::context_t resumed;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(resumed);
		// Настраиваем стороны связи
		arrange(resuming, resumed, credential, "client-h2-again", "server-h2-again", POINTS[p]);
		// Возобновляем связь по билету возобновляемого клиента
		resuming.resume(client.tickets()[0]);
		// Возобновляем связь по билету возобновляемого сервера
		resumed.resume(server.tickets());
		// Проверяем успешность запуска
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(resuming, resumed);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(resuming.established() && resumed.established());
		ASSERT_TRUE(resuming.shared() && resumed.shared());
		// Проверяем договор прикладных настроек
		EXPECT_TRUE(resuming.settled() && resumed.settled());
		// Проверяем обслуживание подключения
		EXPECT_EQ(resuming.settings(), bytes("server-h2-again"));
		EXPECT_EQ(resumed.settings(), bytes("client-h2-again"));
		// Проверяем обмен прикладными данными
		ASSERT_TRUE(barter(resuming, resumed));
	}
}

/**
 * Проверка расхождения точек кода: связь идёт без настроек молча, а ручка точки кода
 * различает этот случай снаружи
 */
TEST(AlpsTest, Codepoints){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Создаём контекст клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Создаём контекст сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Настраиваем стороны связи
	arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS_OLD);
	// Задаём кодовую точку сервера
	server.codepoint(extension::type_t::SETTINGS);
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Прикладной протокол согласован по договору
	EXPECT_EQ(client.protocol(), "h2");
	// Проверяем договор прикладных настроек
	EXPECT_FALSE(client.settled());
	EXPECT_FALSE(server.settled());
	// Проверяем пустоту
	EXPECT_TRUE(client.settings().empty());
	EXPECT_TRUE(server.settings().empty());
	// Проверяем обслуживание подключения
	EXPECT_NE(client.codepoint(), server.codepoint());
	// Проверяем обмен прикладными данными
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка отсутствия настроек у одной из сторон: без настроек сервера либо без настроек
 * клиента для выбранного протокола ALPS не согласуется
 */
TEST(AlpsTest, Absent){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", nullptr, extension::type_t::SETTINGS);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем договор прикладных настроек
		EXPECT_FALSE(client.settled() || server.settled());
	}
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", nullptr, extension::type_t::SETTINGS);
		// Задаём прикладные протоколы сервера
		server.protocols(vector <string> {"http/1.1"});
		// Задаём прикладные настройки сервера
		server.settings("http/1.1", bytes("server-http"));
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Прикладной протокол согласован по договору
		EXPECT_EQ(client.protocol(), "http/1.1");
		// Проверяем договор прикладных настроек
		EXPECT_FALSE(client.settled() || server.settled());
	}
}

/**
 * Проверка пустых настроек: пустые настройки согласуются наравне с непустыми, и
 * согласование видно лишь через settled()
 */
TEST(AlpsTest, Empty){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Создаём контекст клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Создаём контекст сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Настраиваем стороны связи
	arrange(client, server, credential, "", "", extension::type_t::SETTINGS);
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем договор прикладных настроек
	EXPECT_TRUE(client.settled() && server.settled());
	EXPECT_TRUE(client.settings().empty() && server.settings().empty());
	// Проверяем обмен прикладными данными
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка враждебного сервера: настройки в защищённых расширениях без прикладного
 * протокола обрывают связь извещением illegal_parameter
 */
TEST(AlpsTest, Lying){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("rsa2048", credential));
	// Создаём контекст клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Задаём прикладные протоколы клиента
	client.protocols(vector <string> {"h2"});
	// Задаём прикладные настройки клиента
	client.settings("h2", bytes("client-h2"));
	// Проверяем успешность запуска
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проверяем истинность условия
	ASSERT_TRUE(adversary(client, distortion_t::SETTLING, &credential));
	// Проверяем итоговую ошибку
	EXPECT_EQ(client.error(), context::error_t::MESSAGE);
	EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем установление связи обеими сторонами
	EXPECT_FALSE(client.established());
	EXPECT_FALSE(client.settled());
}

/**
 * Проверка враждебного клиента: предложив ALPS и получив настройки сервера, он шлёт
 * завершение без защищённых расширений - сервер отвечает unexpected_message
 */
TEST(AlpsTest, Missing){
	// Враждебный клиент набора проверок говорит лишь наборами ГОСТ: подлинность и набор ему под стать
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("anyks.com", credential));
	// Создаём контекст сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Устанавливаем подлинность сервера
	server.credential(credential);
	// Задаём наборы шифрования сервера
	server.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	// Задаём прикладные протоколы сервера
	server.protocols(vector <string> {"h2"});
	// Задаём прикладные настройки сервера
	server.settings("h2", bytes("server-h2"));
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Проверяем обслуживание подключения
	ASSERT_TRUE(intruder(server, distortion_t::TACITURN, &credential));
	// Проверяем итоговую ошибку
	EXPECT_EQ(server.error(), context::error_t::ORDER);
	EXPECT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем установление связи обеими сторонами
	EXPECT_FALSE(server.established());
	// Проверяем договор прикладных настроек
	EXPECT_TRUE(server.settled());
	// Пустой перечень протоколов с настройками черновиком запрещён: decode_error
	server::context_t another;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(another);
	// Устанавливаем подлинность другой стороны
	another.credential(credential);
	// Задаём наборы шифрования другой стороны
	another.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	// Задаём прикладные протоколы другой стороны
	another.protocols(vector <string> {"h2"});
	// Задаём прикладные настройки другой стороны
	another.settings("h2", bytes("server-h2"));
	// Проверяем успешность запуска
	ASSERT_EQ(another.start(), context::error_t::NONE);
	// Прогоняем нарушителя
	(void) intruder(another, distortion_t::VOIDSETTLED, &credential);
	// Проверяем итоговую ошибку
	EXPECT_EQ(another.error(), context::error_t::MESSAGE);
	EXPECT_EQ(another.alert().description, alert::description_t::DECODE);
	// Проверяем установление связи обеими сторонами
	EXPECT_FALSE(another.established() || another.settled());
	// Отказ принят ещё приветствием: наружу ушло одно извещение, а не приветствие сервера
	ASSERT_GT(another.output().size, static_cast <size_t> (0));
	// Наружу ушло извещение, а не приветствие
	EXPECT_EQ(another.output().data[0], static_cast <uint8_t> (0x15));
}

/**
 * Проверка наследования билетом: при принятых упреждающих данных обе стороны берут
 * настройки из билета, а расширение и сообщение клиента по связи не идут
 */
TEST(AlpsTest, Resumed){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Создаём контекст клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Создаём контекст сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Настраиваем стороны связи
	arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
	// Разрешаем упреждающие данные сервера
	server.advance(true);
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем обслуживание подключения
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем размер
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Проверяем, что полученное значение больше ожидаемого
	ASSERT_GT(client.tickets()[0].advance, static_cast <uint32_t> (0));
	// Создаём контекст клиента
	client::context_t resuming;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(resuming);
	// Создаём контекст сервера
	server::context_t resumed;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(resumed);
	// Настраиваем стороны связи
	arrange(resuming, resumed, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
	// Разрешаем упреждающие данные возобновляемого сервера
	resumed.advance(true);
	// Разрешаем упреждающие данные возобновляемого клиента
	resuming.advance(true);
	// Возобновляем связь по билету возобновляемого клиента
	resuming.resume(client.tickets()[0]);
	// Возобновляем связь по билету возобновляемого сервера
	resumed.resume(server.tickets());
	// Проверяем успешность запуска
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Задаём текст запроса
	const string request = "Упреждающие данные по связи с унаследованными настройками";
	// Проверяем размер
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(resuming, resumed);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.accepted() && resumed.accepted());
	// Проверяем договор прикладных настроек
	EXPECT_TRUE(resuming.settled() && resumed.settled());
	// Проверяем обслуживание подключения
	EXPECT_EQ(resuming.settings(), bytes("server-h2"));
	EXPECT_EQ(resumed.settings(), bytes("client-h2"));
	// Объявляем список байтов
	vector <uint8_t> received;
	// Чтение возобновлённой стороны прошло без ошибки
	ASSERT_EQ(resumed.read(received), context::error_t::NONE);
	// Принятый текст совпал с отправленным
	EXPECT_EQ(string(received.begin(), received.end()), request);
	// Проверяем обмен прикладными данными
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка расхождения настроек с билетом: сменившиеся настройки клиента не дают
 * предложить упреждение, сменившиеся настройки сервера - принять его; ALPS при этом
 * договаривается заново
 */
TEST(AlpsTest, Mismatch){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	/**
	 * Выполняем перебор сторон, сменивших настройки: клиент, сервер, обе
	 */
	for(size_t side = 0; side < 3; side++){
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		// Разрешаем упреждающие данные сервера
		server.advance(true);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем обслуживание подключения
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем размер
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Создаём контекст клиента
		client::context_t resuming;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(resuming);
		// Создаём контекст сервера
		server::context_t resumed;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(resumed);
		// Отмечаем стороны, подающие и принимающие настройки
		const bool mine = ((side == 0) || (side == 2)), theirs = ((side == 1) || (side == 2));
		// Настраиваем стороны связи
		arrange(resuming, resumed, credential, (mine ? "client-h2-changed" : "client-h2"), (theirs ? "server-h2-changed" : "server-h2"), extension::type_t::SETTINGS);
		// Разрешаем упреждающие данные возобновляемого сервера
		resumed.advance(true);
		// Разрешаем упреждающие данные возобновляемого клиента
		resuming.advance(true);
		// Возобновляем связь по билету возобновляемого клиента
		resuming.resume(client.tickets()[0]);
		// Возобновляем связь по билету возобновляемого сервера
		resumed.resume(server.tickets());
		// Проверяем успешность запуска
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Смена настроек клиентом упреждение не предлагает вовсе, смена сервером - отвергает предложенное
		EXPECT_EQ(resuming.earlying(), !mine) << side;
		// Проводим рукопожатие сторон
		converse(resuming, resumed);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(resuming.established() && resumed.established()) << side << " " << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		ASSERT_TRUE(resuming.shared() && resumed.shared()) << side;
		// Проверяем принятие упреждающих данных
		EXPECT_FALSE(resuming.accepted() || resumed.accepted()) << side;
		// Проверяем договор прикладных настроек
		EXPECT_TRUE(resuming.settled() && resumed.settled()) << side;
		// Проверяем обслуживание подключения
		EXPECT_EQ(resuming.settings(), bytes(theirs ? "server-h2-changed" : "server-h2")) << side;
		EXPECT_EQ(resumed.settings(), bytes(mine ? "client-h2-changed" : "client-h2")) << side;
		// Проверяем обмен прикладными данными
		ASSERT_TRUE(barter(resuming, resumed)) << side;
	}
	// Без настроек у нового клиента при билете с согласованными настройками упреждение тоже не идёт
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		// Разрешаем упреждающие данные сервера
		server.advance(true);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем обслуживание подключения
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем размер
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Создаём контекст клиента
		client::context_t resuming;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(resuming);
		// Создаём контекст сервера
		server::context_t resumed;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(resumed);
		// Настраиваем стороны связи
		arrange(resuming, resumed, credential, nullptr, "server-h2", extension::type_t::SETTINGS);
		// Разрешаем упреждающие данные возобновляемого сервера
		resumed.advance(true);
		// Разрешаем упреждающие данные возобновляемого клиента
		resuming.advance(true);
		// Возобновляем связь по билету возобновляемого клиента
		resuming.resume(client.tickets()[0]);
		// Возобновляем связь по билету возобновляемого сервера
		resumed.resume(server.tickets());
		// Проверяем успешность запуска
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Проверяем отправку упреждающих данных
		EXPECT_FALSE(resuming.earlying());
		// Проводим рукопожатие сторон
		converse(resuming, resumed);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(resuming.established() && resumed.established());
		// Проверяем принятие упреждающих данных
		EXPECT_FALSE(resuming.accepted() || resumed.accepted());
		EXPECT_FALSE(resuming.settled() || resumed.settled());
	}
}

/**
 * Проверка профиля отпечатка с ALPS: снимок приветствия с прежней точкой кода выставляет
 * точку сам, протоколы снимка объявляются с пустыми настройками, и сервер с той же точкой
 * договаривает ALPS
 */
TEST(AlpsTest, Profile){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Объявляем профиль отпечатка
	fingerprint::profile_t source;
	{
		// Создаём контекст клиента
		client::context_t donor;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(donor);
		// Задаём имя донора
		donor.name("example.com");
		// Задаём прикладные протоколы донора
		donor.protocols(vector <string> {"h2", "http/1.1"});
		// Задаём прикладные настройки донора
		donor.settings("h2", bytes("donor-h2"));
		// Задаём кодовую точку донора
		donor.codepoint(extension::type_t::SETTINGS_OLD);
		// Проверяем успешность запуска
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	// Заводим признак нахождения расширения
	bool found = false;
	/**
	 * Выполняем перебор расширений снимка
	 */
	for(size_t i = 0; i < source.extensions.size(); i++){
		// Если расширение имеет вид ALPS
		if(source.extensions[i].type == static_cast <uint16_t> (extension::type_t::SETTINGS_OLD)){
			// Отмечаем находку расширения ALPS
			found = true;
			// Проверяем размер
			ASSERT_EQ(source.extensions[i].protocols.size(), static_cast <size_t> (1));
			// В снимке ровно один протокол
			EXPECT_EQ(source.extensions[i].protocols[0], "h2");
		}
		// Проверяем несовпадение полученного значения с ожидаемым
		EXPECT_NE(source.extensions[i].type, static_cast <uint16_t> (extension::type_t::SETTINGS));
	}
	// Проверяем истинность условия
	ASSERT_TRUE(found);
	// Создаём контекст клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Создаём контекст сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Задаём имя клиента
	client.name("example.com");
	// Профиль принят клиентом
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Старая кодовая точка устояла в профиле
	EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS_OLD);
	// Устанавливаем подлинность сервера
	server.credential(credential);
	// Задаём прикладные протоколы сервера
	server.protocols(vector <string> {"h2"});
	// Задаём прикладные настройки сервера
	server.settings("h2", bytes("server-h2"));
	// Задаём кодовую точку сервера
	server.codepoint(extension::type_t::SETTINGS_OLD);
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Объявляем профиль отпечатка
	fingerprint::profile_t made;
	// Проверяем разбор
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	/**
	 * Выполняем сличение видов и тел расширений снимка и сложенного приветствия
	 */
	for(size_t i = 0; i < made.extensions.size(); i++){
		// Виды расширений совпали со снимком
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
		// Если расширение имеет вид ALPS
		if((made.extensions[i].type == static_cast <uint16_t> (extension::type_t::SETTINGS_OLD)) || (made.extensions[i].type == static_cast <uint16_t> (extension::type_t::PROTOCOLS)))
			// Тела служебных расширений совпали со снимком
			EXPECT_EQ(made.extensions[i].data, source.extensions[i].data) << i;
	}
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Прикладной протокол согласован по договору
	EXPECT_EQ(client.protocol(), "h2");
	// Проверяем договор прикладных настроек
	EXPECT_TRUE(client.settled() && server.settled());
	// Проверяем обслуживание подключения
	EXPECT_EQ(client.settings(), bytes("server-h2"));
	// Проверяем пустоту
	EXPECT_TRUE(server.settings().empty());
	// Проверяем обмен прикладными данными
	ASSERT_TRUE(barter(client, server));
	// Профиль с ALPS против сервера иной точки кода: связь без настроек
	client::context_t other;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(other);
	// Создаём контекст сервера
	server::context_t another;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(another);
	// Задаём имя другой стороны
	other.name("example.com");
	// Профиль принят другой стороной
	ASSERT_EQ(other.profile(source), context::error_t::NONE);
	// Устанавливаем подлинность другой стороны
	another.credential(credential);
	// Задаём прикладные протоколы другой стороны
	another.protocols(vector <string> {"h2"});
	// Задаём прикладные настройки другой стороны
	another.settings("h2", bytes("server-h2"));
	// Проверяем успешность запуска
	ASSERT_EQ(another.start(), context::error_t::NONE);
	ASSERT_EQ(other.start(), context::error_t::NONE);
	// Проводим рукопожатие сторон
	converse(other, another);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(other.established() && another.established());
	// Проверяем договор прикладных настроек
	EXPECT_FALSE(other.settled() || another.settled());
}

/**
 * Проверка записи билета с полями ALPS: круг записи и чтения, издание 3, обрезание
 */
TEST(AlpsTest, Ticket){
	// Объявляем билет
	context::ticket_t ticket;
	// Заполняем поле билета
	ticket.suite = protect::suite_t::AES_128_GCM_SHA256;
	// Заполняем поле билета
	ticket.protocol = "h2";
	// Заполняем поле билета
	ticket.settled = true;
	// Задаём байтовое содержимое
	ticket.settings = bytes("mine");
	// Задаём байтовое содержимое
	ticket.obtained = bytes("theirs");
	// Заполняем поле билета
	ticket.identity.assign(8, 0x11);
	// Заполняем поле билета
	ticket.secret.assign(32, 0x22);
	// Объявляем список байтов
	vector <uint8_t> encoded;
	// Проверяем кодирование
	ASSERT_EQ(context::encode(ticket, encoded), context::error_t::NONE);
	// Проверяем кодирование
	EXPECT_EQ(encoded[0], static_cast <uint8_t> (0x04));
	// Объявляем билет
	context::ticket_t decoded;
	// Проверяем кодирование
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	// Проверяем декодирование
	EXPECT_TRUE(decoded.settled);
	// Проверяем декодирование
	EXPECT_EQ(decoded.settings, ticket.settings);
	EXPECT_EQ(decoded.obtained, ticket.obtained);
	EXPECT_EQ(decoded.protocol, "h2");
	/**
	 * Отказ: обрезание записи на всякой длине
	 */
	for(size_t i = 1; i < encoded.size(); i++)
		// Проверяем кодирование
		ASSERT_EQ(context::decode(view_t(encoded.data(), i), decoded), context::error_t::TICKET) << "длина " << i;
	// Признак согласования вне 0..1
	vector <uint8_t> broken = encoded;
	// Искажаем байт буфера
	broken[encoded.size() - ticket.settings.size() - ticket.obtained.size() - 5] = 0x02;
	// Проверяем декодирование
	EXPECT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	// Прежнее издание записи отвергается
	broken = encoded;
	// Портим первый байт записи
	broken[0] = 0x02;
	// Проверяем декодирование
	EXPECT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	// Пустой билет: настройки не согласованы
	const context::ticket_t blank;
	// Проверяем снятие журнала процесса
	EXPECT_FALSE(blank.settled);
	// Проверяем кодирование
	ASSERT_EQ(context::encode(blank, encoded), context::error_t::NONE);
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	// Проверяем декодирование
	EXPECT_FALSE(decoded.settled);
	// Проверяем пустоту
	EXPECT_TRUE(decoded.settings.empty() && decoded.obtained.empty());
}

/**
 * Проверка отказов: настройки для протокола вне перечня, непомерное имя протокола,
 * чужой вид расширения точкой кода, издание 1.2 без ALPS
 */
TEST(AlpsTest, Refusals){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Задаём прикладные протоколы клиента
		client.protocols(vector <string> {"h2"});
		// Задаём прикладные настройки клиента
		client.settings("http/1.1", bytes("x"));
		// Проверяем успешность запуска
		EXPECT_EQ(client.start(), context::error_t::PROTOCOL);
	}
	{
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Задаём прикладные протоколы сервера
		server.protocols(vector <string> {"h2"});
		// Задаём прикладные настройки сервера
		server.settings("h3", bytes("x"));
		// Проверяем успешность запуска
		EXPECT_EQ(server.start(), context::error_t::PROTOCOL);
	}
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Задаём строку максимальной длины
		const string longest(256, 'a');
		// Задаём прикладные протоколы клиента
		client.protocols(vector <string> {longest});
		// Задаём прикладные настройки клиента
		client.settings(longest, bytes("x"));
		// Проверяем успешность запуска
		EXPECT_EQ(client.start(), context::error_t::PROTOCOL);
	}
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Задаём кодовую точку клиента
		client.codepoint(extension::type_t::SETTINGS_OLD);
		client.codepoint(extension::type_t::NAME);
		// Первая кодовая точка устояла
		EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS_OLD);
		// Задаём кодовую точку клиента
		client.codepoint(extension::type_t::SETTINGS);
		// Вторая кодовая точка сменила первую
		EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS);
	}
	{
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		// Издание ограничено обеими сторонами
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль отпечатка
		fingerprint::profile_t made;
		// Проверяем разбор
		ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
		/**
		 * Выполняем перебор расширений приветствия издания 1.2
		 */
		for(size_t i = 0; i < made.extensions.size(); i++)
			// Проверяем несовпадение полученного значения с ожидаемым
			EXPECT_NE(made.extensions[i].type, static_cast <uint16_t> (extension::type_t::SETTINGS)) << i;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем договор прикладных настроек
		EXPECT_FALSE(client.settled() || server.settled());
	}
	{
		// Повтор по тому же протоколу заменяет настройки
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "first", "server-h2", extension::type_t::SETTINGS);
		// Задаём прикладные настройки клиента
		client.settings("h2", bytes("second"));
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем обслуживание подключения
		EXPECT_EQ(server.settings(), bytes("second"));
	}
}

/**
 * Проверка под пайком памяти: связь с настройками либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(AlpsTest, Starved){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(keyfile("ec256", credential));
	// Заводим признак голодания памяти
	bool starved = false;
	// Заводим признак завершения прогона
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Создаём контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Создаём контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Настраиваем стороны связи
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		// Заводим ошибки обеих сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Ограничиваем доступную память
			starve::ration_t ration(budget);
			// Запускаем сторону и запоминаем итог
			first = server.start();
			// Запускаем сторону и запоминаем итог
			second = client.start();
			// Проверяем результат поиска
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие сторон
				converse(client, server);
				// Запоминаем итоговую ошибку стороны
				first = server.error();
				// Запоминаем итоговую ошибку стороны
				second = client.error();
			}
		}
		// Отмечаем отказ нехватки памяти любой стороны
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		// Отмечаем законность исходов обеих сторон
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем истинность условия
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Отмечаем установление связи обеих сторон
		complete = (client.established() && server.established());
		// Проверяем завершение связи
		if(complete){
			// Проверяем договор прикладных настроек
			EXPECT_TRUE(client.settled() && server.settled());
			// Проверяем обслуживание подключения
			EXPECT_EQ(client.settings(), bytes("server-h2"));
			EXPECT_EQ(server.settings(), bytes("client-h2"));
		}
	}
	// Проверяем истинность условия
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
