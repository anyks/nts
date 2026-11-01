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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое либо пустой перечень
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Проверяем, что файл открыт
		if(!file.is_open())
			// Файла нет: выводим пустой перечень
			return vector <uint8_t> ();
		// Выводим содержимое файла целиком
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
		// Загружаем содержимое из файла набора
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Объявляем список байтов
		const vector <uint8_t> chain = corpus((std::string(name) + ".crt").c_str());
		// Проверяем, что данные не пусты
		if(result.secret.empty() || chain.empty())
			// Возвращаем признак неудачи
			return false;
		// Возвращаем признак успешности проверки
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
		// Признак передачи
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Байты клиента
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
			// Байты сервера
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
	 * @brief Функция передачи байтов клиента серверу без ответа
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool forth(client::context_t & client, server::context_t & server) noexcept {
		// Берём вывод клиента
		const view_t data = client.output();
		// Если вывод стороны опустошён
		if(data.size == 0)
			// Возвращаем признак неудачи
			return false;
		// Объявляем список байтов
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		// Сокращаем исходящие данные клиента
		client.consume(buffer.size());
		// Передаём байты серверу
		server.push(view_t(buffer.data(), buffer.size()));
		// Возвращаем признак успеха
		return true;
	}
	/**
	 * @brief Функция передачи байтов сервера клиенту без ответа
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool back(client::context_t & client, server::context_t & server) noexcept {
		// Берём вывод сервера
		const view_t data = server.output();
		// Если вывод стороны опустошён
		if(data.size == 0)
			// Возвращаем признак неудачи
			return false;
		// Объявляем список байтов
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		// Сокращаем исходящие данные сервера
		server.consume(buffer.size());
		// Передаём байты клиенту
		client.push(view_t(buffer.data(), buffer.size()));
		// Возвращаем признак успеха
		return true;
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
		 * Перебираем: передачи байтов между сторонами при условии, что они двигают данные и их меньше шестнадцати
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Функция снятия приветствия клиента с отправляемых байтов без их изъятия
	 *
	 * @param client связь стороны клиента
	 * @param result профиль приветствия
	 * @return       признак успешности
	 *
	 */
	static bool captured(client::context_t & client, fingerprint::profile_t & result) noexcept {
		// Возвращаем признак успешности проверки
		return (fingerprint::parse(client.output(), result) == fingerprint::error_t::NONE);
	}
	/**
	 * @brief Функция получения перечня долей приветствия
	 *
	 * @param profile профиль приветствия
	 * @return        доли расширения key_share либо пустой перечень
	 *
	 */
	static vector <extension::share_t> offersof(const fingerprint::profile_t & profile) noexcept {
		/**
		 * Перебираем: расширения профиля при условии, что они не кончились
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Если расширение имеет вид key_share (0x0033)
			if(profile.extensions[i].type == 0x0033){
				// Объявляем список долей
				vector <extension::share_t> result;
				/**
				 * Перебираем: доли расширения профиля при условии, что они не кончились
				 */
				for(size_t j = 0; j < profile.extensions[i].shares.size(); j++)
					// Добавляем элемент в список
					result.push_back(extension::share_t(static_cast <extension::group_t> (profile.extensions[i].shares[j].group), view_t(profile.extensions[i].shares[j].key.data(), profile.extensions[i].shares[j].key.size())));
				// Выводим доли расширения согласования ключей
				return result;
			}
		}
		// Расширения согласования ключей нет: выводим пустой перечень
		return vector <extension::share_t> ();
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
		// Задаём текст запроса
		const string request = "Запрос по гибридной группе", reply = "Ответ по гибридной группе";
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
		// Если запись ответа сервером удалась
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (reply.data()), reply.size())) != context::error_t::NONE)
			// Возвращаем признак неудачи
			return false;
		// Проводим рукопожатие сторон
		converse(client, server);
		// Очищаем
		received.clear();
		// Возвращаем признак успешности проверки
		return ((client.read(received) == context::error_t::NONE) && (string(received.begin(), received.end()) == reply));
	}
	/**
	 * @brief Функция получения пути к bssl
	 *
	 * @return путь либо пустая строка
	 *
	 */
	static std::string bssltool() noexcept {
		// Ищем переменную пути инструмента
		const char * given = ::getenv("ANTS_BSSL");
		// Если путь задан и исполняем
		if((given != nullptr) && (::access(given, X_OK) == 0))
			// Заданный путь годный, выводим его
			return std::string(given);
		// Если инструмент bssl доступен
		if(shell("command -v bssl >/dev/null 2>&1") == 0)
			// bssl в путях поиска, выводим его имя
			return std::string("bssl");
		// Пути к bssl нет, выводим пустую строку
		return std::string();
	}
	/**
	 * @brief Функция проверки поддержки группы у openssl
	 *
	 * @return признак того, что openssl знает X25519MLKEM768
	 *
	 */
	static bool kemready() noexcept {
		// Возвращаем признак успешности проверки
		return (shell("(openssl list -tls-groups 2>/dev/null | tr ':' '\\n' | grep -qw X25519MLKEM768) >/dev/null 2>&1") == 0);
	}
	/**
	 * @brief Функция составления приветствия по образцу Chrome с долей гибридной группы
	 *
	 * @param body тело приветствия
	 * @return     признак успешности
	 *
	 */
	static bool chromehello(vector <uint8_t> & body) {
		// Заводим приветствие клиента
		hello::client_t greeting;
		// Заполняем поле приветствия
		greeting.version = 0x0303;
		/**
		 * Перебираем: байты случайности приветствия при условии, что их меньше тридцати двух
		 */
		for(size_t i = 0; i < 32; i++) greeting.random[i] = static_cast <uint8_t> (i * 7 + 1);
		// Заполняем заданным байтом
		greeting.session.assign(32, 0x5A);
		// Задаём таблицу наборов шифрования
		const uint16_t suites[] = {0x2A2A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x009D, 0x002F, 0x0035};
		/**
		 * Перебираем: наборы шифрования при условии, что они не кончились
		 */
		for(size_t i = 0; i < (sizeof(suites) / sizeof(suites[0])); i++)
			// Добавляем элемент в список
			greeting.suites.push_back(suites[i]);
		// Добавляем элемент в список
		greeting.methods.push_back(0);
		// Объявляем статический буфер байтов
		static vector <uint8_t> name, share, groups, versions, schemes, modes, formats, protocols, padding;
		// Очищаем
		name.clear(); share.clear(); groups.clear(); versions.clear(); schemes.clear(); modes.clear(); formats.clear(); protocols.clear(); padding.clear();
		// Задаём проверочные байты
		static const uint8_t STUB[1] = {0x00};
		// Объявляем статический буфер байтов
		static vector <uint8_t> kemkey, curvekey;
		// Заполняем заданным байтом
		kemkey.assign(OFFER, 0x00);
		// Заполняем заданным байтом
		curvekey.assign(32, 0x00);
		/**
		 * Перебираем: байты ключа гибридной группы при условии, что они не кончились
		 */
		for(size_t i = 0; i < kemkey.size(); i++) kemkey[i] = static_cast <uint8_t> (i * 3 + 11);
		/**
		 * Перебираем: байты ключа классической группы при условии, что они не кончились
		 */
		for(size_t i = 0; i < curvekey.size(); i++) curvekey[i] = static_cast <uint8_t> (i + 100);
		// Если имя example.com разобралось
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> ("example.com"), 11), name) != extension::error_t::NONE) return false;
		if(extension::shares(vector <extension::share_t> {extension::share_t(static_cast <extension::group_t> (0x2A2A), view_t(STUB, 1)), extension::share_t(extension::group_t::X25519MLKEM768, view_t(kemkey.data(), kemkey.size())), extension::share_t(extension::group_t::X25519, view_t(curvekey.data(), curvekey.size()))}, share) != extension::error_t::NONE) return false;
		if(extension::groups(vector <extension::group_t> {static_cast <extension::group_t> (0x2A2A), extension::group_t::X25519MLKEM768, extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1}, groups) != extension::error_t::NONE) return false;
		if(extension::versions(vector <uint16_t> {0x2A2A, 0x0304, 0x0303}, versions) != extension::error_t::NONE) return false;
		if(extension::schemes(vector <extension::scheme_t> {static_cast <extension::scheme_t> (0x0403), static_cast <extension::scheme_t> (0x0804), static_cast <extension::scheme_t> (0x0401), static_cast <extension::scheme_t> (0x0503), static_cast <extension::scheme_t> (0x0805), static_cast <extension::scheme_t> (0x0501), static_cast <extension::scheme_t> (0x0806), static_cast <extension::scheme_t> (0x0601)}, schemes) != extension::error_t::NONE) return false;
		if(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes) != extension::error_t::NONE) return false;
		if(extension::formats(vector <uint8_t> {0x00}, formats) != extension::error_t::NONE) return false;
		if(extension::protocols(vector <string> {"h2", "http/1.1"}, protocols) != extension::error_t::NONE) return false;
		// Заполняем заданным байтом
		padding.assign(100, 0x00);
		// Добавляем элемент в список
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
		// Возвращаем признак успешности проверки
		return (hello::build(greeting, body) == hello::error_t::NONE);
	}
	/**
	 * @brief Функция обёртывания тела приветствия записью TLS
	 *
	 * @param body тело приветствия
	 * @return     запись
	 *
	 */
	static vector <uint8_t> wrapped(const vector <uint8_t> & body) {
		// Объявляем список байтов
		vector <uint8_t> result;
		// Считаем длину сообщения с обвязкой
		const size_t message = (body.size() + 4);
		// Добавляем элемент в список
		result.push_back(0x16);
		result.push_back(0x03); result.push_back(0x01);
		result.push_back(static_cast <uint8_t> (message >> 8)); result.push_back(static_cast <uint8_t> (message));
		result.push_back(0x01);
		result.push_back(static_cast <uint8_t> (body.size() >> 16)); result.push_back(static_cast <uint8_t> (body.size() >> 8)); result.push_back(static_cast <uint8_t> (body.size()));
		// Вставляем байты в список
		result.insert(result.end(), body.begin(), body.end());
		// Выводим запись рукопожатия с заголовком
		return result;
	}
}

/**
 * Петля: клиент с долей гибридной группы, сервер её выбирает; доли сторон по длине
 */
TEST(HybridTest, Loopback){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Создаём контекст клиента
	client::context_t client;
	// Создаём контекст сервера
	server::context_t server;
	// Задаём группы клиента
	client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
	// Задаём доли клиента
	client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
	// Задаём имя клиента
	client.name("localhost");
	// Задаём группы сервера
	server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
	// Устанавливаем подлинность сервера
	server.credential(credential);
	// Проверяем успешность запуска
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Объявляем профиль отпечатка
	fingerprint::profile_t offer;
	// Проверяем снятие приветствия
	ASSERT_TRUE(captured(client, offer));
	// Объявляем список долей
	const vector <extension::share_t> offered = offersof(offer);
	// Проверяем размер
	ASSERT_EQ(offered.size(), static_cast <size_t> (1));
	// Доля гибридной группы и её размер сходятся
	EXPECT_EQ(offered[0].group, extension::group_t::X25519MLKEM768);
	EXPECT_EQ(offered[0].key.size, OFFER);
	// Ключ инкапсуляции в доле годен
	EXPECT_TRUE(agreement::validate(agreement::kem_t::MLKEM768, view_t(offered[0].key.data, agreement::encapsulation(agreement::kem_t::MLKEM768))));
	// Первая передача: приветствие уходит серверу
	ASSERT_TRUE(forth(client, server));
	// Ответ сервера: доля сервера длиной шифртекста и точки
	const view_t answer = server.output();
	// Проверяем, что полученное значение больше ожидаемого
	ASSERT_GT(answer.size, ANSWER);
	{
		// Разыскиваем группу 0x11EC с длиной доли сервера в приветствии сервера
		bool found = false;
		/**
		 * Перебираем: байты ответа сервера при условии, что в остатке есть код с длиной доли
		 */
		for(size_t i = 0; (i + 4) <= answer.size; i++){
			// Если байты ответа совпали с кодом гибридной группы
			if((answer.data[i] == 0x11) && (answer.data[i + 1] == 0xEC) && (answer.data[i + 2] == static_cast <uint8_t> (ANSWER >> 8)) && (answer.data[i + 3] == static_cast <uint8_t> (ANSWER)))
				// Отмечаем находку гибридной группы
				found = true;
		}
		// Проверяем истинность условия
		EXPECT_TRUE(found);
	}
	// Проводим рукопожатие сторон
	converse(client, server);
	// Проверяем установление связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Согласованная группа у обеих сторон - гибрид
	EXPECT_EQ(client.group(), extension::group_t::X25519MLKEM768);
	EXPECT_EQ(server.group(), extension::group_t::X25519MLKEM768);
	// Проверяем обмен данными в обе стороны
	EXPECT_TRUE(exchanged(client, server));
}

/**
 * Просьба о повторе: клиент шлёт долю X25519, сервер ведёт лишь гибрид; повторное
 * приветствие несёт одну долю гибрида. Сервер без гибрида берёт X25519 у клиента с обеими
 */
TEST(HybridTest, Retry){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	{
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::X25519MLKEM768});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519});
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие и просьба о повторе
		ASSERT_TRUE(forth(client, server));
		ASSERT_TRUE(back(client, server));
		// Повторное приветствие клиента
		fingerprint::profile_t again;
		// Проверяем снятие приветствия
		ASSERT_TRUE(captured(client, again));
		// Объявляем список долей
		const vector <extension::share_t> offered = offersof(again);
		// Проверяем размер
		ASSERT_EQ(offered.size(), static_cast <size_t> (1));
		// Доля гибридной группы и её размер снова сходятся
		EXPECT_EQ(offered[0].group, extension::group_t::X25519MLKEM768);
		EXPECT_EQ(offered[0].key.size, OFFER);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем обмен данными в обе стороны
		EXPECT_TRUE(exchanged(client, server));
	}
	{
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль отпечатка
		fingerprint::profile_t offer;
		// Проверяем снятие приветствия
		ASSERT_TRUE(captured(client, offer));
		// Объявляем список долей
		const vector <extension::share_t> offered = offersof(offer);
		// Проверяем размер
		ASSERT_EQ(offered.size(), static_cast <size_t> (2));
		// Размеры долей сходятся: гибридная и классическая
		EXPECT_EQ(offered[0].key.size, OFFER);
		EXPECT_EQ(offered[1].key.size, static_cast <size_t> (32));
		// До установления группа не выбрана
		EXPECT_EQ(client.group(), extension::group_t::NONE);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Согласованная группа - X25519
		EXPECT_EQ(client.group(), extension::group_t::X25519);
		EXPECT_EQ(server.group(), extension::group_t::X25519);
		// Проверяем обмен данными в обе стороны
		EXPECT_TRUE(exchanged(client, server));
	}
}

/**
 * Профиль по образцу Chrome: доли GREASE, гибрида и X25519 идут порядком снимка свежими
 * ключами записанных длин; связь устанавливается и с сервером гибрида, и с сервером X25519
 */
TEST(HybridTest, Profile){
	// Объявляем список байтов
	vector <uint8_t> body;
	// Проверяем истинность условия
	ASSERT_TRUE(chromehello(body));
	// Объявляем список байтов
	const vector <uint8_t> record = wrapped(body);
	// Объявляем профиль отпечатка
	fingerprint::profile_t source;
	// Проверяем разбор
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Объявляем список долей
	const vector <extension::share_t> recorded = offersof(source);
	// Проверяем размер
	ASSERT_EQ(recorded.size(), static_cast <size_t> (3));
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Перебираем: круги связи при условии, что их меньше двух
	 */
	for(size_t round = 0; round < 2; round++){
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём имя клиента
		client.name("example.com");
		// Профиль принят клиентом
		ASSERT_EQ(client.profile(source), context::error_t::NONE);
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {(round == 0) ? extension::group_t::X25519MLKEM768 : extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль отпечатка
		fingerprint::profile_t made;
		// Проверяем снятие приветствия
		ASSERT_TRUE(captured(client, made));
		// Объявляем список долей
		const vector <extension::share_t> offered = offersof(made);
		// Объявляем строку
		string listed;
		/**
		 * Перебираем: предложенные доли при условии, что они не кончились
		 */
		for(size_t i = 0; i < offered.size(); i++) listed += (std::to_string(static_cast <uint16_t> (offered[i].group)) + "/" + std::to_string(offered[i].key.size) + " ");
		// Проверяем размер
		ASSERT_EQ(offered.size(), static_cast <size_t> (3)) << listed;
		// Проверяем принадлежность группы диапазону маскировки
		EXPECT_TRUE(fingerprint::grease(static_cast <uint16_t> (offered[0].group)));
		// Маскировочная доля байтовая, дальше гибридная
		EXPECT_EQ(offered[0].key.size, static_cast <size_t> (1));
		EXPECT_EQ(offered[1].group, extension::group_t::X25519MLKEM768);
		EXPECT_EQ(offered[1].key.size, OFFER);
		EXPECT_EQ(offered[2].group, extension::group_t::X25519);
		EXPECT_EQ(offered[2].key.size, static_cast <size_t> (32));
		// Ключи свежие, не из снимка
		EXPECT_NE(::memcmp(offered[1].key.data, recorded[1].key.data, OFFER), 0);
		EXPECT_NE(::memcmp(offered[2].key.data, recorded[2].key.data, 32), 0);
		// Проверяем корректность открытого ключа
		EXPECT_TRUE(agreement::validate(agreement::kem_t::MLKEM768, view_t(offered[1].key.data, agreement::encapsulation(agreement::kem_t::MLKEM768))));
		// Порядок групп снимка сохранён
		bool grouped = false;
		/**
		 * Перебираем: расширения составленного приветствия при условии, что они не кончились
		 */
		for(size_t i = 0; i < made.extensions.size(); i++){
			// Если расширение имеет вид supported_groups (0x000A)
			if(made.extensions[i].type == 0x000A){
				// Проверяем размер
				ASSERT_EQ(made.extensions[i].groups.size(), static_cast <size_t> (5));
				// Перечень групп собран с маскировкой вокруг гибридной
				EXPECT_EQ(made.extensions[i].groups[1], extension::group_t::X25519MLKEM768);
				EXPECT_EQ(made.extensions[i].groups[2], extension::group_t::X25519);
				// Отмечаем наличие перечня групп
				grouped = true;
			}
		}
		// Проверяем истинность условия
		EXPECT_TRUE(grouped);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << "круг " << round << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		// Проверяем обмен данными в обе стороны
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
	// Задаём таблицу проверочных констант
	static const size_t OFFERS[] = {65 + 1184, 97 + 1568}, ANSWERS[] = {65 + 1088, 97 + 1568};
	// Задаём проверочные байты
	static const uint8_t CODES[][2] = {{0x11, 0xEB}, {0x11, 0xED}};
	/**
	 * Выполняем перебор групп
	 */
	for(size_t i = 0; i < 2; i++){
		// Объявляем подлинность стороны
		context::credential_t credential;
		// Проверяем составление подлинности из набора
		ASSERT_TRUE(identity("ec256", credential));
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {GROUPS[i]});
		// Задаём имя клиента
		client.name("localhost");
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Объявляем профиль отпечатка
		fingerprint::profile_t offer;
		// Проверяем снятие приветствия
		ASSERT_TRUE(captured(client, offer));
		// Объявляем список долей
		const vector <extension::share_t> offered = offersof(offer);
		// Проверяем размер
		ASSERT_EQ(offered.size(), static_cast <size_t> (1)) << i;
		// Группа и размер доли сходятся с таблицей
		EXPECT_EQ(offered[0].group, GROUPS[i]) << i;
		EXPECT_EQ(offered[0].key.size, OFFERS[i]) << i;
		// Кривая впереди: точка в несжатом виде, за ней ключ инкапсуляции
		EXPECT_EQ(offered[0].key.data[0], 0x04) << i;
		// Проверяем корректность открытого ключа
		EXPECT_TRUE(agreement::validate(((i == 0) ? agreement::kem_t::MLKEM768 : agreement::kem_t::MLKEM1024), view_t(offered[0].key.data + ((i == 0) ? 65 : 97), OFFERS[i] - ((i == 0) ? 65 : 97)))) << i;
		// Проверяем завершение рукопожатия
		ASSERT_TRUE(forth(client, server));
		// Берём вывод сервера
		const view_t answer = server.output();
		// Проверяем, что полученное значение больше ожидаемого
		ASSERT_GT(answer.size, ANSWERS[i]) << i;
		{
			// Заводим признак нахождения расширения
			bool found = false;
			/**
			 * Перебираем: байты ответа сервера при условии, что в остатке есть код с длиной и меткой
			 */
			for(size_t k = 0; (k + 5) <= answer.size; k++){
				// Если байты ответа совпали с кодом группы
				if((answer.data[k] == CODES[i][0]) && (answer.data[k + 1] == CODES[i][1]) && (answer.data[k + 2] == static_cast <uint8_t> (ANSWERS[i] >> 8)) && (answer.data[k + 3] == static_cast <uint8_t> (ANSWERS[i] & 0xFF)) && (answer.data[k + 4] == 0x04))
					// Отмечаем находку группы
					found = true;
			}
			// Проверяем истинность условия
			EXPECT_TRUE(found) << i;
		}
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << i << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Группа связи сходится у обеих сторон
		EXPECT_EQ(client.group(), GROUPS[i]) << i;
		EXPECT_EQ(server.group(), GROUPS[i]) << i;
		// Проверяем обмен данными в обе стороны
		EXPECT_TRUE(exchanged(client, server)) << i;
	}
	// Длины долей клиента у открытого API совпадают с проводом
	EXPECT_EQ(extension::length(extension::group_t::SECP256R1MLKEM768), OFFERS[0]);
	EXPECT_EQ(extension::length(extension::group_t::SECP384R1MLKEM1024), OFFERS[1]);
	EXPECT_EQ(extension::length(extension::group_t::X25519MLKEM768), OFFER);
	// Повтор приветствия: доля X25519, сервер лишь с SecP256r1MLKEM768
	{
		// Объявляем подлинность стороны
		context::credential_t credential;
		// Проверяем составление подлинности из набора
		ASSERT_TRUE(identity("ec256", credential));
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1MLKEM768});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519});
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем завершение рукопожатия
		ASSERT_TRUE(forth(client, server));
		ASSERT_TRUE(back(client, server));
		// Объявляем профиль отпечатка
		fingerprint::profile_t again;
		// Проверяем снятие приветствия
		ASSERT_TRUE(captured(client, again));
		// Объявляем список долей
		const vector <extension::share_t> offered = offersof(again);
		// Проверяем размер
		ASSERT_EQ(offered.size(), static_cast <size_t> (1));
		// Доля гибрида на кривой NIST и её размер сходятся
		EXPECT_EQ(offered[0].group, extension::group_t::SECP256R1MLKEM768);
		EXPECT_EQ(offered[0].key.size, OFFERS[0]);
		// Проводим рукопожатие сторон
		converse(client, server);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Группа связи сходится с договорённой
		EXPECT_EQ(client.group(), extension::group_t::SECP256R1MLKEM768);
		// Проверяем обмен данными в обе стороны
		EXPECT_TRUE(exchanged(client, server));
	}
}

/**
 * Проверка стражи длины доли гибрида NIST у сервера: приветствие с долей 0x11EB короче положенного
 * (100 байтов) и с долей длиннее (1250) отвергается, связь не устанавливается
 */
TEST(HybridTest, NistMalformed){
	// Задаём таблицу проверочных констант
	static const size_t SIZES[] = {100, 1250};
	/**
	 * Выполняем перебор длин
	 */
	for(size_t i = 0; i < 2; i++){
		// Объявляем подлинность стороны
		context::credential_t credential;
		// Проверяем составление подлинности из набора
		ASSERT_TRUE(identity("ec256", credential));
		// Приветствие с одной долей негодной длины
		hello::client_t greeting;
		// Заполняем поле приветствия
		greeting.version = 0x0303;
		/**
		 * Перебираем: байты случайности приветствия при условии, что их меньше тридцати двух
		 */
		for(size_t k = 0; k < 32; k++) greeting.random[k] = static_cast <uint8_t> (k * 5 + 3);
		// Добавляем элемент в список
		greeting.suites.push_back(0x1301);
		// Добавляем элемент в список
		greeting.methods.push_back(0);
		// Объявляем список байтов
		vector <uint8_t> name, share, groups, versions, schemes, modes;
		// Объявляем список байтов
		vector <uint8_t> key(SIZES[i], 0x00);
		// Портим первый байт ключа
		key[0] = 0x04;
		/**
		 * Перебираем: байты ключа доли при условии, что они не кончились
		 */
		for(size_t k = 1; k < key.size(); k++) key[k] = static_cast <uint8_t> (k * 7 + 1);
		// Проверяем составление имени
		ASSERT_EQ(extension::name(view_t(reinterpret_cast <const uint8_t *> ("localhost"), 9), name), extension::error_t::NONE);
		ASSERT_EQ(extension::shares(vector <extension::share_t> {extension::share_t(extension::group_t::SECP256R1MLKEM768, view_t(key.data(), key.size()))}, share), extension::error_t::NONE);
		ASSERT_EQ(extension::groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768, extension::group_t::X25519}, groups), extension::error_t::NONE);
		ASSERT_EQ(extension::versions(vector <uint16_t> {0x0304}, versions), extension::error_t::NONE);
		ASSERT_EQ(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes), extension::error_t::NONE);
		ASSERT_EQ(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes), extension::error_t::NONE);
		// Добавляем элемент в список
		greeting.extensions.push_back(hello::extension_t(0x0000, view_t(name.data(), name.size())));
		greeting.extensions.push_back(hello::extension_t(0x000A, view_t(groups.data(), groups.size())));
		greeting.extensions.push_back(hello::extension_t(0x000D, view_t(schemes.data(), schemes.size())));
		greeting.extensions.push_back(hello::extension_t(0x002B, view_t(versions.data(), versions.size())));
		greeting.extensions.push_back(hello::extension_t(0x002D, view_t(modes.data(), modes.size())));
		greeting.extensions.push_back(hello::extension_t(0x0033, view_t(share.data(), share.size())));
		// Объявляем список байтов
		vector <uint8_t> body;
		// Проверяем составление
		ASSERT_EQ(hello::build(greeting, body), hello::error_t::NONE);
		// Объявляем список байтов
		const vector <uint8_t> record = wrapped(body);
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::SECP256R1MLKEM768, extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Передаём байты серверу
		(void) server.push(view_t(record.data(), record.size()));
		// Проверяем установление связи обеими сторонами
		EXPECT_FALSE(server.established()) << SIZES[i];
		// Проверяем итоговую ошибку
		EXPECT_EQ(server.state(), context::state_t::FAILED) << SIZES[i] << " " << static_cast <int> (server.error());
	}
}

/**
 * Сличение гибридов NIST с openssl 3.5+: наш клиент против s_server с группой и наш сервер
 * против s_client с группой, обе группы
 */
TEST(HybridTest, NistOpenssl){
	// Заводим набор инструмента
	const toolkit_t toolkit = inspect();
	// Проверяем наличие нужных возможностей инструмента
	if(!toolkit.present || !toolkit.tls13 || !listed("s_server", "groups")){
		// Пропускаем проверку: недоступен внешний инструмент
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -groups";
	}
	// Если инструмент знает гибридную группу
	if(shell("(openssl list -tls-groups 2>/dev/null | tr ':' '\\n' | grep -qw SecP256r1MLKEM768) >/dev/null 2>&1") != 0){
		// Пропускаем проверку: недоступен внешний инструмент
		GTEST_SKIP() << "openssl без SecP256r1MLKEM768 (нужен openssl 3.5+)";
	}
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Задаём пути файлов набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Задаём таблицу названий групп
	static const char * NAMES[] = {"SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
	// Задаём таблицу групп
	static const extension::group_t GROUPS[] = {extension::group_t::SECP256R1MLKEM768, extension::group_t::SECP384R1MLKEM1024};
	/**
	 * Выполняем перебор групп
	 */
	for(size_t i = 0; i < 2; i++){
		{
			// Занимаем вольный порт
			const uint16_t number = vacant(false);
			// Проверяем несовпадение полученного значения с ожидаемым
			ASSERT_NE(number, 0);
			// Задаём путь журнала прогона
			const std::string log = "/tmp/ants-nist-server-" + std::to_string(number) + ".log";
			// Проверяем обслуживание подключения
			ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -groups " + NAMES[i] + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
			// Запускаем страж внешнего процесса
			sentinel_t sentinel(log + ".pid");
			// Соединяемся с сервером инструмента
			const int fd = dial(number);
			// Проверяем, что полученное значение не меньше ожидаемого
			ASSERT_GE(fd, 0) << "порт " << number;
			// Создаём контекст клиента
			client::context_t client;
			// Задаём группы клиента
			client.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
			// Задаём доли клиента
			client.shares(vector <extension::group_t> {GROUPS[i]});
			// Задаём имя клиента
			client.name("localhost");
			// Проверяем успешность запуска
			ASSERT_EQ(client.start(), context::error_t::NONE);
			/**
			 * Перебираем: шаги рукопожатия с сервером при условии, что клиент не установлен и не отказал
			 */
			for(size_t k = 0; (k < 8) && !client.established() && (client.state() != context::state_t::FAILED); k++)
				// Передаём байты между стороной и сокетом
				relay(client, fd);
			// Если связь клиента не установилась, журнал в отказ
			if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
			// Проверяем установление связи обеими сторонами
			ASSERT_TRUE(client.established()) << NAMES[i] << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			// Группа связи сходится с договорённой
			EXPECT_EQ(client.group(), GROUPS[i]) << NAMES[i];
			// Задаём текст запроса
			const string request = "GET / HTTP/1.0\r\n\r\n";
			// Проверяем размер
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Объявляем список байтов
			vector <uint8_t> reply;
			/**
			 * Перебираем: шаги обмена данными с сервером при условии, что ответ ещё не получен
			 */
			for(size_t k = 0; (k < 16) && reply.empty(); k++){
				// Передаём байты между стороной и сокетом
				relay(client, fd);
				// Чтение ответа прошло без ошибки
				ASSERT_EQ(client.read(reply), context::error_t::NONE);
			}
			// Проверяем несовпадение полученного значения с ожидаемым
			EXPECT_NE(string(reply.begin(), reply.end()).find("HTTP/1.0 200"), string::npos) << NAMES[i];
			// Закрываем соединение
			closing(fd);
			// Останавливаем страж процесса
			sentinel.halt();
			// Объявляем строку
			std::string journal;
			// Снимаем журнал процесса
			(void) settle(log, journal);
			// Удаляем файл журнала
			::remove(log.c_str());
		}
		{
			// Заводим номер порта
			uint16_t number = 0;
			// Заводим слушающий сокет
			const int listener = harbour(number);
			// Проверяем, что полученное значение не меньше ожидаемого
			ASSERT_GE(listener, 0);
			// Задаём путь журнала прогона
			const std::string log = "/tmp/ants-nist-client-" + std::to_string(number) + ".log";
			// Проверяем составление имени
			ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -servername localhost -groups " + NAMES[i] + " -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
			// Запускаем страж внешнего процесса
			sentinel_t sentinel(log + ".pid");
			// Принимаем подключение инструмента
			const int fd = greeted(listener);
			// Проверяем, что полученное значение не меньше ожидаемого
			ASSERT_GE(fd, 0);
			// Создаём контекст сервера
			server::context_t server;
			// Задаём группы сервера
			server.groups(vector <extension::group_t> {GROUPS[i], extension::group_t::X25519});
			// Устанавливаем подлинность сервера
			server.credential(credential);
			// Проверяем успешность запуска
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Обслуживаем подключение до конца
			const bool complete = serve(server, fd);
			// Проверяем итоговую ошибку
			ASSERT_TRUE(complete) << NAMES[i] << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
			// Проверяем итоговую ошибку
			ASSERT_EQ(server.error(), context::error_t::NONE);
			// Проверяем обслуживание подключения
			EXPECT_EQ(server.group(), GROUPS[i]) << NAMES[i];
			// Проверяем обслуживание подключения
			ASSERT_TRUE(farewell(server, fd));
			// Закрываем соединение
			closing(fd);
			closing(listener);
			// Объявляем строку
			std::string text;
			// Проверяем снятие журнала процесса
			ASSERT_TRUE(settle(log, text)) << text;
			// Проверяем несовпадение полученного значения с ожидаемым
			EXPECT_NE(text.find(std::string("Negotiated TLS1.3 group: ") + NAMES[i]), std::string::npos) << text;
			// Удаляем файл журнала
			::remove(log.c_str());
		}
	}
}

TEST(HybridTest, Starved){
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Заводим признаки голодания и завершения
	bool starved = false, complete = false;
	/**
	 * Перебираем: запасы памяти при условии, что связь ещё не завершена
	 */
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 100) ? 1 : 53)){
		// Создаём контекст клиента
		client::context_t client;
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Устанавливаем подлинность сервера
		server.credential(credential);
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
			if((first == context::error_t::NONE) && (second == context::error_t::NONE))
				// Проводим рукопожатие сторон
				converse(client, server);
		}
		// Собираем итоги обеих сторон связи
		const context::error_t outcomes[4] = {first, second, client.error(), server.error()};
		/**
		 * Перебираем: итоги четырёх обращений к сторонам связи при условии, что они не кончились
		 */
		for(size_t i = 0; i < 4; i++){
			// Проверяем истинность условия
			ASSERT_TRUE((outcomes[i] == context::error_t::NONE) || (outcomes[i] == context::error_t::MEMORY)) << "запас " << budget << " шаг " << i << " отказ " << static_cast <int> (outcomes[i]);
			// Отмечаем отказ нехватки памяти любой стороны
			starved = (starved || (outcomes[i] == context::error_t::MEMORY));
		}
		// Отмечаем установление связи обеих сторон
		complete = (client.established() && server.established());
	}
	// Проверяем истинность условия
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}

/**
 * Сличение с openssl 3.5+: наш клиент против s_server с группой X25519MLKEM768 и s_client
 * с той же группой против нашего сервера
 */
TEST(HybridTest, Openssl){
	// Заводим набор инструмента
	const toolkit_t toolkit = inspect();
	// Проверяем наличие нужных возможностей инструмента
	if(!toolkit.present){
		// Пропускаем проверку: недоступен внешний инструмент
		GTEST_SKIP() << "openssl недоступен";
	}
	// Проверяем наличие нужных возможностей инструмента
	if(!toolkit.tls13 || !toolkit.serverGroups || !toolkit.clientGroups || !kemready()){
		// Пропускаем проверку: недоступен внешний инструмент
		GTEST_SKIP() << "openssl без TLS 1.3, без -groups либо без X25519MLKEM768 (нужен openssl 3.5+)";
	}
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Задаём пути файлов набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Занимаем вольный порт
		const uint16_t number = vacant(false);
		// Проверяем несовпадение полученного значения с ожидаемым
		ASSERT_NE(number, 0);
		// Задаём путь журнала прогона
		const std::string log = "/tmp/ants-hybrid-server-" + std::to_string(number) + ".log";
		// Проверяем обслуживание подключения
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -groups X25519MLKEM768 -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Запускаем страж внешнего процесса
		sentinel_t sentinel(log + ".pid");
		// Соединяемся с сервером инструмента
		const int fd = dial(number);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(fd, 0) << "порт " << number;
		// Создаём контекст клиента
		client::context_t client;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Задаём имя клиента
		client.name("localhost");
		// Проверяем успешность запуска
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Перебираем: шаги рукопожатия с сервером при условии, что клиент не установлен и не отказал
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты между стороной и сокетом
			relay(client, fd);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Задаём текст запроса
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Проверяем размер
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Объявляем список байтов
		vector <uint8_t> answer;
		/**
		 * Перебираем: шаги обмена данными с сервером при условии, что ответ ещё не получен
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём байты между стороной и сокетом
			relay(client, fd);
			// Чтение ответа прошло без ошибки
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Задаём строку максимальной длины
		const string text(answer.begin(), answer.end());
		// Проверяем несовпадение полученного значения с ожидаемым
		EXPECT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
		// Закрываем соединение
		closing(fd);
		// Останавливаем страж процесса
		sentinel.halt();
		// Объявляем строку
		std::string journal;
		// Снимаем журнал процесса
		(void) settle(log, journal);
		// Удаляем файл журнала
		::remove(log.c_str());
	}
	{
		// Заводим номер порта
		uint16_t number = 0;
		// Заводим слушающий сокет
		const int listener = harbour(number);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(listener, 0);
		// Задаём путь журнала прогона
		const std::string log = "/tmp/ants-hybrid-client-" + std::to_string(number) + ".log";
		// Задаём путь журнала прогона
		const std::string holder = "/tmp/ants-hybrid-client-" + std::to_string(number) + ".fifo";
		// Удаляем файл журнала
		::remove(holder.c_str());
		// Держатель журнала заведён
		ASSERT_EQ(fifo(holder.c_str()), 0);
		// Проверяем составление имени
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -servername localhost -groups X25519MLKEM768:X25519 -verify_return_error <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		// Запускаем страж внешнего процесса
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение инструмента
		const int fd = greeted(listener);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(fd, 0);
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Проверяем итоговую ошибку
		ASSERT_TRUE(serve(server, fd)) << "отказ " << static_cast <int> (server.error());
		ASSERT_TRUE(server.established());
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем соединение
		closing(fd);
		closing(listener);
		// Объявляем строку
		std::string text;
		// Проверяем снятие журнала процесса
		ASSERT_TRUE(settle(log, text)) << text;
		// Проверяем несовпадение полученного значения с ожидаемым
		EXPECT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		EXPECT_NE(text.find("X25519MLKEM768"), std::string::npos) << text;
		// Удаляем файл журнала
		::remove(log.c_str());
		::remove(holder.c_str());
	}
}

/**
 * Сличение с BoringSSL: наш клиент против bssl server с кривой X25519MLKEM768 и bssl client
 * против нашего сервера
 */
TEST(HybridTest, Boringssl){
	// Задаём строковую константу
	const std::string tool = bssltool();
	// Проверяем, что данные не пусты
	if(tool.empty()){
		// Пропускаем проверку: недоступен внешний инструмент
		GTEST_SKIP() << "bssl (BoringSSL) недоступен: задайте ANTS_BSSL";
	}
	// Объявляем подлинность стороны
	context::credential_t credential;
	// Проверяем составление подлинности из набора
	ASSERT_TRUE(identity("ec256", credential));
	// Задаём пути файлов набора
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Занимаем вольный порт
		const uint16_t number = vacant(false);
		// Проверяем несовпадение полученного значения с ожидаемым
		ASSERT_NE(number, 0);
		// Задаём путь журнала прогона
		const std::string log = "/tmp/ants-hybrid-bssl-server-" + std::to_string(number) + ".log";
		// Проверяем обслуживание подключения
		ASSERT_TRUE(launch(tool + " server -accept " + std::to_string(number) + " -cert " + crt + " -key " + key + " -curves X25519MLKEM768 -www </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Запускаем страж внешнего процесса
		sentinel_t sentinel(log + ".pid");
		// Соединяемся с сервером инструмента
		const int fd = dial(number);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(fd, 0) << "порт " << number;
		// Создаём контекст клиента
		client::context_t client;
		// Задаём группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Задаём доли клиента
		client.shares(vector <extension::group_t> {extension::group_t::X25519MLKEM768});
		// Задаём имя клиента
		client.name("localhost");
		// Проверяем успешность запуска
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Перебираем: шаги рукопожатия с сервером при условии, что клиент не установлен и не отказал
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты между стороной и сокетом
			relay(client, fd);
		// Проверяем установление связи обеими сторонами
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Задаём текст запроса
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Проверяем размер
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Объявляем список байтов
		vector <uint8_t> answer;
		/**
		 * Перебираем: шаги обмена данными с сервером при условии, что ответ ещё не получен
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём байты между стороной и сокетом
			relay(client, fd);
			// Чтение ответа прошло без ошибки
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Задаём строку максимальной длины
		const string text(answer.begin(), answer.end());
		// Проверяем несовпадение полученного значения с ожидаемым
		EXPECT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
		// Закрываем соединение
		closing(fd);
		// Останавливаем страж процесса
		sentinel.halt();
		// Объявляем строку
		std::string journal;
		// Снимаем журнал процесса
		(void) settle(log, journal);
		// Удаляем файл журнала
		::remove(log.c_str());
	}
	{
		// Заводим номер порта
		uint16_t number = 0;
		// Заводим слушающий сокет
		const int listener = harbour(number);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(listener, 0);
		// Задаём путь журнала прогона
		const std::string log = "/tmp/ants-hybrid-bssl-client-" + std::to_string(number) + ".log";
		// Задаём путь журнала прогона
		const std::string holder = "/tmp/ants-hybrid-bssl-client-" + std::to_string(number) + ".fifo";
		// Удаляем файл журнала
		::remove(holder.c_str());
		// Держатель журнала заведён
		ASSERT_EQ(fifo(holder.c_str()), 0);
		// Проверяем составление имени
		ASSERT_TRUE(launch(tool + " client -connect 127.0.0.1:" + std::to_string(number) + " -curves X25519MLKEM768:X25519 -root-certs " + crt + " -server-name localhost <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		// Запускаем страж внешнего процесса
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение инструмента
		const int fd = greeted(listener);
		// Проверяем, что полученное значение не меньше ожидаемого
		ASSERT_GE(fd, 0);
		// Создаём контекст сервера
		server::context_t server;
		// Задаём группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519MLKEM768, extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем успешность запуска
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Проверяем итоговую ошибку
		ASSERT_TRUE(serve(server, fd)) << "отказ " << static_cast <int> (server.error());
		ASSERT_TRUE(server.established());
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем соединение
		closing(fd);
		closing(listener);
		// Объявляем строку
		std::string text;
		// Проверяем снятие журнала процесса
		ASSERT_TRUE(settle(log, text)) << text;
		// Проверяем несовпадение полученного значения с ожидаемым
		EXPECT_NE(text.find("X25519MLKEM768"), std::string::npos) << text;
		// Удаляем файл журнала
		::remove(log.c_str());
		::remove(holder.c_str());
	}
}
