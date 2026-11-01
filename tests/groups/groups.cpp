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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое либо пустой перечень
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора для двоичного чтения
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Проверяем открытие файла
		if(!file.is_open())
			// Возвращаем пустой перечень при недоступности файла
			return vector <uint8_t> ();
		// Возвращаем содержимое файла целиком
		return vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	}
	/**
	 * @brief Функция чтения подлинности из набора: ключ PEM и цепочка сертификатов
	 *
	 * @param name   имя подлинности в наборе
	 * @param result подлинность
	 * @return       признак успешности чтения
	 *
	 */
	static bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем ключ подлинности из набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем цепочку сертификатов из набора
		const vector <uint8_t> chain = corpus((std::string(name) + ".crt").c_str());
		// Проверяем наличие ключа и цепочки
		if(result.secret.empty() || chain.empty())
			// Возвращаем признак неудачи чтения
			return false;
		// Разбираем цепочку сертификатов
		return (pem::certificates(string(chain.begin(), chain.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Объявляем признак передачи байтов
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Получаем вывод клиента
			view_t data = client.output();
			// Проверяем наличие байтов у клиента
			if(data.size > 0){
				// Копируем байты клиента в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Извлекаем байты из вывода клиента
				client.consume(buffer.size());
				// Передаём байты серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов
				moved = true;
			}
			// Получаем вывод сервера
			data = server.output();
			// Проверяем наличие байтов у сервера
			if(data.size > 0){
				// Копируем байты сервера в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Извлекаем байты из вывода сервера
				server.consume(buffer.size());
				// Передаём байты клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу байтов
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(...) {
			// Возвращаем признак ошибки передачи
			return false;
		}
		// Возвращаем признак передачи байтов
		return moved;
	}
	/**
	 * @brief Функция проведения связи до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Перебираем: шаги передачи байтов между сторонами, пока связь не замолчит, не более шестнадцати шагов
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Функция получения перечня долей приветствия клиента без их изъятия
	 *
	 * @param client связь стороны клиента
	 * @param result доли расширения key_share: группа и ключ своей копией (просмотры в разобранный профиль пережили бы его)
	 * @return       признак успешности разбора приветствия
	 *
	 */
	static bool offered(client::context_t & client, vector <pair <extension::group_t, vector <uint8_t>>> & result) noexcept {
		// Объявляем разобранный профиль приветствия
		fingerprint::profile_t profile;
		// Разбираем приветствие клиента
		if(fingerprint::parse(client.output(), profile) != fingerprint::error_t::NONE)
			// Возвращаем признак неудачи разбора
			return false;
		// Очищаем перечень долей
		result.clear();
		/**
		 * Перебираем: расширения разобранного профиля приветствия
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Проверяем расширение key_share
			if(profile.extensions[i].type == 0x0033){
				/**
				 * Перебираем: доли расширения key_share
				 */
				for(size_t j = 0; j < profile.extensions[i].shares.size(); j++)
					// Запоминаем группу и ключ доли своей копией
					result.push_back(make_pair(static_cast <extension::group_t> (profile.extensions[i].shares[j].group), profile.extensions[i].shares[j].key));
			}
		}
		// Возвращаем признак успеха разбора
		return true;
	}
	/**
	 * @brief Функция проверки обмена прикладными данными по установленной связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что данные дошли в обе стороны
	 *
	 */
	static bool exchanged(client::context_t & client, server::context_t & server) noexcept {
		// Объявляем прикладные данные запроса и ответа
		const string request = "Запрос по отложенной группе", reply = "Ответ по отложенной группе";
		// Отправляем запрос от клиента
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Возвращаем признак неудачи отправки
			return false;
		// Проводим связь до тишины
		converse(client, server);
		// Объявляем буфер принятых данных
		vector <uint8_t> received;
		// Проверяем получение запроса сервером
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Возвращаем признак неудачи приёма
			return false;
		// Отправляем ответ от сервера
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (reply.data()), reply.size())) != context::error_t::NONE)
			// Возвращаем признак неудачи отправки
			return false;
		// Проводим связь до тишины
		converse(client, server);
		// Очищаем буфер принятых данных
		received.clear();
		// Проверяем получение ответа клиентом
		return ((client.read(received) == context::error_t::NONE) && (string(received.begin(), received.end()) == reply));
	}
	/**
	 * @brief Функция проверки поддержки группы у системного openssl
	 *
	 * @param name имя группы
	 * @return     признак поддержки
	 *
	 */
	static bool groupable(const char * name, const bool legacy, const std::string & crt, const std::string & key) noexcept {
		// Признак по делу, а не по подкоманде list: openssl договаривается с собой по этой группе (у 3.0 list -tls-groups нет вовсе)
		const toolkit_t toolkit = inspect();
		// Занимаем свободный порт
		const uint16_t number = vacant(false);
		// Проверяем занятие порта
		if(number == 0)
			// Возвращаем признак неудачи
			return false;
		// Объявляем основу имён временных файлов
		const std::string base = "/tmp/ants-groups-self-" + std::to_string(number);
		// Объявляем имена канала и журналов
		const std::string holder = base + ".fifo", log = base + ".server.log", out = base + ".client.log";
		::remove(holder.c_str());
		// Создаём именованный канал
		if(fifo(holder.c_str()) != 0)
			// Возвращаем признак неудачи создания канала
			return false;
		// Объявляем довод издания протокола
		const std::string edition = (legacy ? "-tls1_2" : "-tls1_3");
		// Запускаем системный сервер с заданной группой
		const bool started = launch("openssl s_server" + accepting(toolkit, number) + " " + edition + " -cert " + crt + " -key " + key + " -groups " + name + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder);
		// Объявляем признак договорённости о группе
		bool agreed = false;
		// Проверяем запуск сервера
		if(started){
			// Объявляем страж остановки сервера
			sentinel_t sentinel(log + ".pid");
			// Объявляем буфер журнала сервера
			std::string text;
			// Дожидаемся готовности сервера к приёму
			if(awaited(log, "ACCEPT", text)){
				// Запускаем системного клиента против своего сервера
				(void) shell("(printf 'Q\n' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " " + edition + " -groups " + name + " -CAfile " + crt + " -servername localhost >" + out + " 2>&1 &); sleep 3; pkill -f 'openssl s_client -connect 127.0.0.1:" + std::to_string(number) + "' >/dev/null 2>&1; true");
				// Открываем журнал системного клиента
				std::ifstream file(out);
				// Объявляем буфер строки журнала
				std::string line;
				/**
				 * Перебираем: строки журнала клиента, пока они читаются
				 */
				while(std::getline(file, line))
					// Ищем в журнале признак успешной проверки подлинности
					agreed = (agreed || (line.find("Verify return code: 0 (ok)") != std::string::npos));
			}
			// Останавливаем системный сервер
			sentinel.halt();
		}
		::remove(holder.c_str());
		::remove(log.c_str());
		::remove(out.c_str());
		// Возвращаем признак договорённости о группе
		return agreed;
	}
	/**
	 * @brief Функция рукопожатия своего клиента против openssl s_server
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
		// Осматриваем системный инструмент
		const toolkit_t toolkit = inspect();
		// Занимаем свободный порт
		const uint16_t number = vacant(false);
		// Проверяем занятие порта
		if(number == 0)
			// Возвращаем признак неудачи
			return false;
		// Объявляем имя журнала сервера
		const std::string log = "/tmp/ants-groups-server-" + std::to_string(number) + ".log";
		// Запускаем системный сервер с заданными доводами
		if(!launch("openssl s_server" + accepting(toolkit, number) + " " + arguments + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"))
			// Возвращаем признак неудачи запуска
			return false;
		// Объявляем страж остановки сервера
		sentinel_t sentinel(log + ".pid");
		// Соединяемся с портом сервера
		const int fd = dial(number);
		// Проверяем соединение с сервером
		if(fd < 0)
			// Возвращаем признак неудачи соединения
			return false;
		// Объявляем контекст своего клиента
		client::context_t client;
		// Задаём группы клиента
		client.groups(groups);
		// Проверяем задание долей
		if(!shares.empty())
			// Задаём доли клиента
			client.shares(shares);
		// Проверяем задание схем подписи
		if(!schemes.empty())
			// Задаём схемы подписи клиента
			client.schemes(schemes);
		// Проверяем признак издания 1.2
		if(legacy)
			// Ограничиваем клиента изданием 1.2
			client.versions(0x0303, 0x0303);
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Запускаем рукопожатие клиента
		bool ok = (client.start() == context::error_t::NONE);
		/**
		 * Перебираем: шаги рукопожатия, пока связь не установится либо не откажет
		 */
		for(size_t i = 0; ok && (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты между клиентом и сервером
			relay(client, fd);
		// Проверяем установление связи и выбранную группу
		ok = (ok && client.established() && (client.group() == expected));
		// Проверяем установление связи
		if(ok){
			// Объявляем прикладной запрос к серверу
			const string request = "GET / HTTP/1.0\r\n\r\n";
			// Отправляем запрос системному серверу
			ok = (client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) == context::error_t::NONE);
			// Объявляем буфер ответа сервера
			vector <uint8_t> answer;
			/**
			 * Перебираем: шаги приёма ответа, пока буфер пуст
			 */
			for(size_t i = 0; ok && (i < 16) && answer.empty(); i++){
				// Передаём байты между клиентом и сервером
				relay(client, fd);
				// Принимаем ответ системного сервера
				ok = (client.read(answer) == context::error_t::NONE);
			}
			// Проверяем успешный ответ сервера
			ok = (ok && (string(answer.begin(), answer.end()).find("HTTP/1.0 200") != string::npos));
		}
		// Проверяем неудачу связи
		if(!ok)
			// Собираем журнал отказа
			journal = "отказ " + std::to_string(static_cast <int> (client.error())) + " извещение " + std::to_string(static_cast <int> (client.alert().description)) + " группа " + std::to_string(static_cast <int> (client.group()));
		// Закрываем соединение с сервером
		closing(fd);
		// Останавливаем системный сервер
		sentinel.halt();
		// Объявляем буфер журнала сервера
		std::string text;
		// Снимаем системный сервер и читаем его журнал
		(void) settle(log, text);
		// Дополняем журнал записью сервера
		journal += "\n" + text;
		::remove(log.c_str());
		// Возвращаем признак успеха
		return ok;
	}
	/**
	 * @brief Функция рукопожатия openssl s_client против своего сервера
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
		// Объявляем номер порта
		uint16_t number = 0;
		// Открываем слушающий сокет
		const int listener = harbour(number);
		// Проверяем открытие слушающего сокета
		if(listener < 0)
			// Возвращаем признак неудачи
			return false;
		// Объявляем имя журнала клиента
		const std::string log = "/tmp/ants-groups-client-" + std::to_string(number) + ".log";
		// Объявляем имя канала клиента
		const std::string holder = "/tmp/ants-groups-client-" + std::to_string(number) + ".fifo";
		::remove(holder.c_str());
		// Создаём именованный канал
		if(fifo(holder.c_str()) != 0)
			// Возвращаем признак неудачи создания канала
			return false;
		// Запускаем системного клиента с заданными доводами
		if(!launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " " + arguments + " -servername localhost -verify_return_error <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder))
			// Возвращаем признак неудачи запуска
			return false;
		// Объявляем страж остановки клиента
		sentinel_t sentinel(log + ".pid");
		// Принимаем соединение системного клиента
		const int fd = greeted(listener);
		// Проверяем принятие соединения
		if(fd < 0)
			// Возвращаем признак неудачи принятия
			return false;
		// Объявляем контекст своего сервера
		server::context_t server;
		// Задаём группы сервера
		server.groups(groups);
		// Задаём подлинность сервера
		server.credential(credential);
		// Проверяем признак издания 1.2
		if(legacy)
			// Ограничиваем сервер изданием 1.2
			server.versions(0x0303, 0x0303);
		// Запускаем рукопожатие сервера
		bool ok = (server.start() == context::error_t::NONE);
		// Проводим связь и проверяем выбранную группу
		ok = (ok && serve(server, fd) && server.established() && (server.group() == expected));
		// Проверяем неудачу связи
		if(!ok)
			// Собираем журнал отказа
			journal = "отказ " + std::to_string(static_cast <int> (server.error())) + " группа " + std::to_string(static_cast <int> (server.group()));
		// Прощаемся с системным клиентом
		(void) farewell(server, fd);
		// Закрываем соединение с клиентом
		closing(fd);
		closing(listener);
		// Объявляем буфер журнала клиента
		std::string text;
		// Снимаем системного клиента и читаем его журнал
		(void) settle(log, text);
		// Дополняем журнал записью клиента
		journal += "\n" + text;
		::remove(log.c_str());
		::remove(holder.c_str());
		// Проверяем успех связи и доверие системного клиента
		return (ok && (text.find("Verify return code: 0 (ok)") != std::string::npos));
	}
};

/**
 * Записи долей: длина по группе, несжатая точка у кривых NIST, ключ длиной в модуль у конечного поля
 */
TEST(GroupsTest, Shares){
	/**
	 * Перебираем: проверочные группы издания 1.3
	 */
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		// Объявляем контекст клиента
		client::context_t client;
		// Задаём единственную группу клиенту
		client.groups(vector <extension::group_t> {MODERN[i].group});
		// Задаём долю группы клиенту
		client.shares(vector <extension::group_t> {MODERN[i].group});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Проверяем запуск рукопожатия клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << MODERN[i].name;
		// Объявляем перечень долей приветствия
		vector <pair <extension::group_t, vector <uint8_t>>> shares;
		// Разбираем доли приветствия клиента
		ASSERT_TRUE(offered(client, shares)) << MODERN[i].name;
		// Проверяем единственность доли
		ASSERT_EQ(shares.size(), static_cast <size_t> (1)) << MODERN[i].name;
		// Проверяем группу доли
		EXPECT_EQ(shares[0].first, MODERN[i].group) << MODERN[i].name;
		EXPECT_EQ(shares[0].second.size(), MODERN[i].length) << MODERN[i].name;
		EXPECT_EQ(extension::length(MODERN[i].group), MODERN[i].length) << MODERN[i].name;
		// Проверяем признак несжатой точки
		if(MODERN[i].uncompressed)
			// Проверяем несжатую точку впереди доли
			EXPECT_EQ(shares[0].second[0], 0x04) << MODERN[i].name << " байты " << static_cast <int> (shares[0].second[0]) << " " << static_cast <int> (shares[0].second[1]) << " " << static_cast <int> (shares[0].second[2]) << " длина " << shares[0].second.size() << " хвост " << static_cast <int> (shares[0].second[shares[0].second.size() - 2]) << " " << static_cast <int> (shares[0].second[shares[0].second.size() - 1]);
	}
	// Проверяем длину доли кривой secp256k1
	EXPECT_EQ(extension::length(extension::group_t::SECP256K1), static_cast <size_t> (65));
	EXPECT_EQ(extension::finite(extension::group_t::FFDHE2048), static_cast <size_t> (256));
	EXPECT_EQ(extension::finite(extension::group_t::X448), static_cast <size_t> (0));
	// Проверяем идентификатор кривой secp521r1
	EXPECT_STREQ(extension::curve(extension::group_t::SECP521R1), "1.3.132.0.35");
	EXPECT_STREQ(extension::curve(extension::group_t::SECP256K1), "1.3.132.0.10");
	EXPECT_STREQ(extension::curve(extension::group_t::X448), "1.3.101.111");
	// Проверяем хэш схемы подписи на кривой P-521
	EXPECT_EQ(extension::hash(extension::scheme_t::ECDSA_SECP521R1_SHA512), digest::hash_t::SHA512);
}

/**
 * Рукопожатие 1.3 по каждой из семи групп своими сторонами с обменом данными
 */
TEST(GroupsTest, Modern){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec256 из набора
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Перебираем: проверочные группы издания 1.3
	 */
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём группы клиенту
		client.groups(vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519});
		// Задаём долю проверяемой группы клиенту
		client.shares(vector <extension::group_t> {MODERN[i].group});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Задаём группы серверу
		server.groups(vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519});
		// Задаём подлинность серверу
		server.credential(credential);
		// Запускаем рукопожатие сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << MODERN[i].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем выбранную группу у клиента
		EXPECT_EQ(client.group(), MODERN[i].group) << MODERN[i].name;
		EXPECT_EQ(server.group(), MODERN[i].group) << MODERN[i].name;
		// Проверяем обмен прикладными данными
		EXPECT_TRUE(exchanged(client, server)) << MODERN[i].name;
	}
}

/**
 * Рукопожатие 1.2 по X448, secp521r1 и secp256k1 своими сторонами: ECDHE в ServerKeyExchange
 */
TEST(GroupsTest, Legacy){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec256 из набора
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Перебираем: проверочные группы издания 1.2
	 */
	for(size_t i = 0; i < (sizeof(LEGACY) / sizeof(LEGACY[0])); i++){
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём группы клиенту
		client.groups(vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Ограничиваем клиента изданием 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём группы серверу
		server.groups(vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519});
		// Задаём подлинность серверу
		server.credential(credential);
		// Ограничиваем сервер изданием 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << LEGACY[i].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем выбранную группу у клиента
		EXPECT_EQ(client.group(), LEGACY[i].group) << LEGACY[i].name;
		EXPECT_EQ(server.group(), LEGACY[i].group) << LEGACY[i].name;
		// Проверяем обмен прикладными данными
		EXPECT_TRUE(exchanged(client, server)) << LEGACY[i].name;
	}
}

/**
 * Правила издания: secp256k1 изданием 1.3 сервер не выбирает даже с долей клиента, конечное
 * поле изданием 1.2 не выбирает без наборов DHE - связь идёт по следующей группе
 */
TEST(GroupsTest, Editions){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec256 из набора
	ASSERT_TRUE(identity("ec256", credential));
	{
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём группы клиенту
		client.groups(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		// Задаём доли клиенту
		client.shares(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Задаём группы серверу
		server.groups(vector <extension::group_t> {extension::group_t::SECP256K1, extension::group_t::X25519});
		// Задаём подлинность серверу
		server.credential(credential);
		// Запускаем рукопожатие сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем перечень долей приветствия
		vector <pair <extension::group_t, vector <uint8_t>>> shares;
		// Разбираем доли приветствия клиента
		ASSERT_TRUE(offered(client, shares));
		// Проверяем число долей
		ASSERT_EQ(shares.size(), static_cast <size_t> (2));
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем группу, выбранную сервером
		EXPECT_EQ(server.group(), extension::group_t::X25519);
		EXPECT_EQ(client.group(), extension::group_t::X25519);
	}
	{
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём группы клиенту
		client.groups(vector <extension::group_t> {extension::group_t::FFDHE2048, extension::group_t::SECP256R1});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Ограничиваем клиента изданием 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Задаём группы серверу
		server.groups(vector <extension::group_t> {extension::group_t::FFDHE2048, extension::group_t::SECP256R1});
		// Задаём подлинность серверу
		server.credential(credential);
		// Ограничиваем сервер изданием 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем группу, выбранную сервером
		EXPECT_EQ(server.group(), extension::group_t::SECP256R1);
		EXPECT_EQ(client.group(), extension::group_t::SECP256R1);
	}
	{
		// Сервер только с secp256k1 изданием 1.3: общей группы нет, рукопожатие отвергается
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём единственную группу клиенту
		client.groups(vector <extension::group_t> {extension::group_t::SECP256K1});
		// Задаём единственную долю клиенту
		client.shares(vector <extension::group_t> {extension::group_t::SECP256K1});
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Задаём единственную группу серверу
		server.groups(vector <extension::group_t> {extension::group_t::SECP256K1});
		// Задаём подлинность серверу
		server.credential(credential);
		// Запускаем рукопожатие сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем отказ связи у сервера
		EXPECT_FALSE(server.established());
		EXPECT_FALSE(client.established());
	}
}

/**
 * Подпись ECDSA на P-521 с SHA-512 (0x0603): подлинность ec521 в обоих изданиях
 */
TEST(GroupsTest, Ecdsa521){
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec521 из набора
	ASSERT_TRUE(identity("ec521", credential));
	/**
	 * Перебираем: издания протокола 1.3 и 1.2
	 */
	for(size_t legacy = 0; legacy < 2; legacy++){
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Задаём схемы подписи клиенту
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		// Задаём подлинность серверу
		server.credential(credential);
		// Задаём схемы подписи серверу
		server.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		// Проверяем издание 1.2
		if(legacy == 1){
			// Ограничиваем клиента изданием 1.2
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
			ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
			// Задаём единственную группу клиенту
			client.groups(vector <extension::group_t> {extension::group_t::SECP521R1});
			// Задаём единственную группу серверу
			server.groups(vector <extension::group_t> {extension::group_t::SECP521R1});
		}
		// Запускаем рукопожатие сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << legacy << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Проверяем обмен прикладными данными
		EXPECT_TRUE(exchanged(client, server)) << legacy;
	}
	// Схема 0x0603 не годится ключу P-256: сервер с ec256 при единственной схеме клиента отвергает рукопожатие
	{
		// Объявляем подлинность сервера
		context::credential_t other;
		// Читаем подлинность ec256 из набора
		ASSERT_TRUE(identity("ec256", other));
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем контекст сервера
		server::context_t server;
		// Задаём имя сервера клиенту
		client.name("localhost");
		// Задаём схемы подписи клиенту
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512});
		// Задаём подлинность серверу
		server.credential(other);
		// Запускаем рукопожатие сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим связь до тишины
		converse(client, server);
		// Проверяем отказ связи у клиента
		EXPECT_FALSE(client.established());
	}
}

/**
 * Сличение с openssl изданием 1.3: свой клиент против s_server и s_client против своего сервера по каждой группе
 */
TEST(GroupsTest, Openssl){
	// Осматриваем системный инструмент
	const toolkit_t toolkit = inspect();
	// Проверяем наличие издания 1.3 и доводов групп
	if(!toolkit.present || !toolkit.tls13 || !toolkit.serverGroups || !toolkit.clientGroups){
		// Пропускаем проверку без издания 1.3 либо доводов групп
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -groups";
	}
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec256 из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Объявляем пути к подлинности набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	/**
	 * Перебираем: проверочные группы издания 1.3
	 */
	for(size_t i = 0; i < (sizeof(MODERN) / sizeof(MODERN[0])); i++){
		// Проверяем ведение группы системным инструментом
		if(!groupable(MODERN[i].name, false, crt, key)){
			// Сообщаем вслух о пропуске группы
			std::cerr << "[ SKIP     ] openssl не ведёт группу " << MODERN[i].name << " сам с собой: пропуск вслух" << std::endl;
			continue;
		}
		// Объявляем журнал связи
		std::string journal;
		// Проверяем связь своего клиента против системного сервера
		if(!against("-tls1_3 -cert " + crt + " -key " + key + " -groups " + MODERN[i].name, vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519}, vector <extension::group_t> {MODERN[i].group}, false, vector <extension::scheme_t> (), MODERN[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				// Сообщаем вслух о пропуске группы
				std::cerr << "[ SKIP     ] openssl s_server не принял группу " << MODERN[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << MODERN[i].name << " " << journal;
		}
		// Очищаем журнал связи
		journal.clear();
		// Проверяем связь своего сервера против системного клиента
		if(!served("-tls1_3 -CAfile " + crt + " -groups " + std::string(MODERN[i].name) + ":X25519", vector <extension::group_t> {MODERN[i].group, extension::group_t::X25519}, credential, false, MODERN[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				// Сообщаем вслух о пропуске групп
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
	// Осматриваем системный инструмент
	const toolkit_t toolkit = inspect();
	// Проверяем наличие издания 1.2 и доводов групп
	if(!toolkit.present || !toolkit.tls12 || !toolkit.serverGroups || !toolkit.clientGroups){
		// Пропускаем проверку без издания 1.2 либо доводов групп
		GTEST_SKIP() << "openssl без TLS 1.2 либо без -groups";
	}
	// Связь 1.2 без extended_master_secret отвергается намеренно (принятое решение): LibreSSL его не ведёт
	if(!toolkit.master){
		// Пропускаем проверку при отсутствии расширения владыки связи
		GTEST_SKIP() << "openssl без extended_master_secret (LibreSSL): связь 1.2 без него не ведётся намеренно";
	}
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec256 из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Объявляем пути к подлинности набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	/**
	 * Перебираем: проверочные группы издания 1.2
	 */
	for(size_t i = 0; i < (sizeof(LEGACY) / sizeof(LEGACY[0])); i++){
		// Проверяем ведение группы системным инструментом
		if(!groupable(LEGACY[i].name, true, crt, key)){
			// Сообщаем вслух о пропуске группы
			std::cerr << "[ SKIP     ] openssl не ведёт группу " << LEGACY[i].name << " изданием 1.2 сам с собой: пропуск вслух" << std::endl;
			continue;
		}
		// Объявляем журнал связи
		std::string journal;
		// Изданию 1.2 openssl требует кривую сертификата ECDSA (P-256) в перечне групп собеседника, иначе «no shared cipher»
		if(!against("-tls1_2 -cert " + crt + " -key " + key + " -groups " + LEGACY[i].name, vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519, extension::group_t::SECP256R1}, vector <extension::group_t> (), true, vector <extension::scheme_t> (), LEGACY[i].group, journal)){
			if(journal.find("Failed to set") != std::string::npos)
				// Сообщаем вслух о пропуске группы
				std::cerr << "[ SKIP     ] openssl s_server не принял группу " << LEGACY[i].name << ": пропуск вслух" << std::endl;
			else
				ADD_FAILURE() << LEGACY[i].name << " " << journal;
		}
		// Имя prime256v1: LibreSSL не знает псевдонима secp256r1
		journal.clear();
		// Проверяем связь своего сервера против системного клиента
		if(!served("-tls1_2 -CAfile " + crt + " -groups " + std::string(LEGACY[i].name) + ":X25519:prime256v1", vector <extension::group_t> {LEGACY[i].group, extension::group_t::X25519, extension::group_t::SECP256R1}, credential, true, LEGACY[i].group, journal)){
			// Если инструмент отказал на своих доводах - пропуск вслух, иначе отказ
			if(journal.find("Failed to set") != std::string::npos)
				// Сообщаем вслух о пропуске групп
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
	// Осматриваем системный инструмент
	const toolkit_t toolkit = inspect();
	// Проверяем наличие издания 1.3 и доводов схем подписи
	if(!toolkit.present || !toolkit.tls13 || !listed("s_server", "sigalgs") || !listed("s_client", "sigalgs")){
		// Пропускаем проверку без издания 1.3 либо доводов схем подписи
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -sigalgs";
	}
	// Объявляем подлинность сервера
	context::credential_t credential;
	// Читаем подлинность ec521 из набора
	ASSERT_TRUE(identity("ec521", credential));
	// Объявляем пути к подлинности набора
	const std::string crt = std::string(CORPUS) + "/ec521.crt", key = std::string(CORPUS) + "/ec521.pem";
	// Объявляем журнал связи
	std::string journal;
	// Проверяем связь своего клиента против системного сервера
	if(!against("-tls1_3 -cert " + crt + " -key " + key + " -sigalgs ECDSA+SHA512", vector <extension::group_t> {extension::group_t::X25519}, vector <extension::group_t> {extension::group_t::X25519}, false, vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP521R1_SHA512}, extension::group_t::X25519, journal)){
		if(journal.find("Failed to set") != std::string::npos)
			// Сообщаем вслух о пропуске доводов
			std::cerr << "[ SKIP     ] openssl s_server не принял -sigalgs: пропуск вслух" << std::endl;
		else
			ADD_FAILURE() << journal;
	}
	// Очищаем журнал связи
	journal.clear();
	// Проверяем связь своего сервера против системного клиента
	if(!served("-tls1_3 -CAfile " + crt + " -sigalgs ECDSA+SHA512", vector <extension::group_t> {extension::group_t::X25519}, credential, false, extension::group_t::X25519, journal)){
		if(journal.find("Failed to set") != std::string::npos)
			// Сообщаем вслух о пропуске доводов
			std::cerr << "[ SKIP     ] openssl s_client не принял -sigalgs: пропуск вслух" << std::endl;
		else
			ADD_FAILURE() << journal;
	} else
		EXPECT_NE(journal.find("Peer signing digest: SHA512"), std::string::npos) << journal;
}

/**
 * Умолчания связи против openssl s_server с его умолчаниями: связь без просьбы о повторе,
 * группа - гибрид X25519MLKEM768, если openssl его знает, иначе X25519 по второй доле
 */
TEST(GroupsTest, OpensslDefaults){
	// Осматриваем системный инструмент
	const toolkit_t toolkit = inspect();
	// Проверяем наличие издания 1.3
	if(!toolkit.present || !toolkit.tls13){
		// Пропускаем проверку без издания 1.3
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Объявляем пути к подлинности набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Гибрид берётся, когда openssl его знает; иначе сервер без ML-KEM берёт долю X25519
	const bool hybrid = (shell("(openssl list -tls-groups 2>/dev/null | tr ':' '\\n' | grep -qw X25519MLKEM768) >/dev/null 2>&1") == 0);
	// Определяем ожидаемую группу по известности гибрида
	const extension::group_t expected = (hybrid ? extension::group_t::X25519MLKEM768 : extension::group_t::X25519);
	// Объявляем журнал связи
	std::string journal;
	// Пустые перечни оставляют умолчания клиента; -msg кладёт сообщения рукопожатия в журнал сервера
	const bool ok = against("-tls1_3 -cert " + crt + " -key " + key + " -msg", vector <extension::group_t> (), vector <extension::group_t> (), false, vector <extension::scheme_t> (), expected, journal);
	// Проверяем успех связи умолчаниями
	EXPECT_TRUE(ok) << journal;
	// Приветствие клиента в журнале одно: просьбы о повторе не было
	size_t hellos = 0;
	/**
	 * Перебираем: вхождения приветствия клиента в журнале, пока они находятся
	 */
	for(size_t pos = journal.find("ClientHello"); pos != std::string::npos; pos = journal.find("ClientHello", pos + 11))
		// Считаем найденные приветствия
		hellos++;
	// Проверяем единственность приветствия клиента
	EXPECT_EQ(hellos, static_cast <size_t> (1)) << journal;
}
