/**
 * @file fingerprint.cpp
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
 * @brief Проверки модуля отпечатков приветствия: разбор, JA3, JA4, PeetPrint, Akamai,
 *        снимок, хранилище, отказы и нехватка памяти
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
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Подключаем заголовочные файлы проверок
 */
#include <starve.hpp>
#include <openssl.hpp>
#include <gtest/gtest.h>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Пример JA4 из описания FoxIO: наборы в порядке провода
	 */
	static const uint16_t FOX_SUITES[] = {
		0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035
	};
	/**
	 * Пример JA4 из описания FoxIO: схемы подписи в порядке провода
	 */
	static const uint16_t FOX_SCHEMES[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};
	/**
	 * Пример JA4 из описания FoxIO: ожидаемые отпечатки
	 */
	static const char * FOX_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1";
	static const char * FOX_JA4R = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";
	static const char * FOX_JA4O = "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601";
	/**
	 * Пример JA3 из описания JA3: строка и её хеш
	 */
	static const char * JA3_TEXT = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
	static const char * JA3_HASH = "ada70206e40642a3e4461f35503241d5";
	/**
	 * Пример JA3: наборы в порядке провода
	 */
	static const uint16_t JA3_SUITES[] = {0x002F, 0x0035, 0x0005, 0x000A, 0xC009, 0xC00A, 0xC013, 0xC014, 0x0032, 0x0038, 0x0013, 0x0004};

	/**
	 * @brief Метод составления записи рукопожатия из тела приветствия
	 *
	 * @param body     тело приветствия
	 * @param datagram признак заголовков поверх дейтаграмм
	 * @param edition  издание слоя записей
	 * @return         запись рукопожатия
	 *
	 */
	static vector <uint8_t> wrapped(const vector <uint8_t> & body, const bool datagram, const uint16_t edition) {
		// Составляемая запись
		vector <uint8_t> result;
		// Длина сообщения с заголовком
		const size_t message = (body.size() + (datagram ? 12 : 4));
		// Дописываем вид записи
		result.push_back(0x16);
		// Дописываем издание записи
		result.push_back(static_cast <uint8_t> (edition >> 8));
		result.push_back(static_cast <uint8_t> (edition));
		// Если запись идёт поверх дейтаграмм
		if(datagram){
			// Дописываем пору и порядковый номер записи
			static const uint8_t HEADER[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
			// Дописываем пору и номер
			result.insert(result.end(), HEADER, HEADER + sizeof(HEADER));
		}
		// Дописываем длину записи
		result.push_back(static_cast <uint8_t> (message >> 8));
		result.push_back(static_cast <uint8_t> (message));
		// Дописываем вид сообщения
		result.push_back(0x01);
		// Дописываем длину тела
		result.push_back(static_cast <uint8_t> (body.size() >> 16));
		result.push_back(static_cast <uint8_t> (body.size() >> 8));
		result.push_back(static_cast <uint8_t> (body.size()));
		// Если сообщение идёт поверх дейтаграмм
		if(datagram){
			// Дописываем порядковый номер сообщения
			result.push_back(0x00);
			result.push_back(0x03);
			// Дописываем смещение куска
			result.push_back(0x00);
			result.push_back(0x00);
			result.push_back(0x00);
			// Дописываем длину куска
			result.push_back(static_cast <uint8_t> (body.size() >> 16));
			result.push_back(static_cast <uint8_t> (body.size() >> 8));
			result.push_back(static_cast <uint8_t> (body.size()));
		}
		// Дописываем тело
		result.insert(result.end(), body.begin(), body.end());
		// Выводим запись
		return result;
	}
	/**
	 * @brief Метод составления приветствия по примеру FoxIO с GREASE на местах Chrome
	 *
	 * @param body составляемое тело приветствия
	 * @return     результат составления
	 *
	 */
	static bool foxhello(vector <uint8_t> & body) {
		// Составляемое приветствие
		hello::client_t greeting;
		// Издание приветствия
		greeting.version = 0x0303;
		// Случайное значение
		::memset(greeting.random, 0x42, sizeof(greeting.random));
		// Опознаватель связи
		greeting.session.assign(32, 0x11);
		// Набор GREASE впереди
		greeting.suites.push_back(0x2A2A);
		/**
		 * Выполняем перебор наборов примера
		 */
		for(size_t i = 0; i < (sizeof(FOX_SUITES) / sizeof(FOX_SUITES[0])); i++)
			// Добавляем набор
			greeting.suites.push_back(FOX_SUITES[i]);
		// Способ сжатия
		greeting.methods.push_back(0);
		// Тела расширений
		static vector <uint8_t> compress, name, share, protocols, settings, modes, schemes, status, versions, formats, groups, padding, renegotiation;
		// Очищаем накопители: составители дописывают в конец
		compress.clear(); name.clear(); share.clear(); protocols.clear(); settings.clear(); modes.clear(); schemes.clear(); versions.clear(); formats.clear(); groups.clear();
		// Алгоритмы сжатия: brotli
		EXPECT_EQ(extension::algorithms(vector <uint16_t> {0x0002}, compress), extension::error_t::NONE);
		// Имя узла
		static const char HOST[] = "example.com";
		// Составляем имя узла
		EXPECT_EQ(extension::name(view_t(reinterpret_cast <const uint8_t *> (HOST), sizeof(HOST) - 1), name), extension::error_t::NONE);
		// Доля ключа X25519 и доля GREASE
		static const uint8_t KEY[32] = {0x01};
		static const uint8_t STUB[1] = {0x00};
		// Составляем доли ключа
		EXPECT_EQ(extension::shares(vector <extension::share_t> {extension::share_t(static_cast <extension::group_t> (0x2A2A), view_t(STUB, 1)), extension::share_t(extension::group_t::X25519, view_t(KEY, 32))}, share), extension::error_t::NONE);
		// Прикладные протоколы
		EXPECT_EQ(extension::protocols(vector <string> {"h2", "http/1.1"}, protocols), extension::error_t::NONE);
		// Прикладные настройки
		EXPECT_EQ(extension::protocols(vector <string> {"h2"}, settings), extension::error_t::NONE);
		// Способы обмена ключом
		EXPECT_EQ(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes), extension::error_t::NONE);
		// Схемы подписи
		vector <extension::scheme_t> list;
		/**
		 * Выполняем перебор схем примера
		 */
		for(size_t i = 0; i < (sizeof(FOX_SCHEMES) / sizeof(FOX_SCHEMES[0])); i++)
			// Добавляем схему
			list.push_back(static_cast <extension::scheme_t> (FOX_SCHEMES[i]));
		// Составляем схемы подписи
		EXPECT_EQ(extension::schemes(list, schemes), extension::error_t::NONE);
		// Запрос состояния сертификата
		status = vector <uint8_t> {0x01, 0x00, 0x00, 0x00, 0x00};
		// Издания протокола с GREASE впереди
		EXPECT_EQ(extension::versions(vector <uint16_t> {0x2A2A, 0x0304, 0x0303}, versions), extension::error_t::NONE);
		// Записи точек
		EXPECT_EQ(extension::formats(vector <uint8_t> {0x00}, formats), extension::error_t::NONE);
		// Группы с GREASE впереди
		EXPECT_EQ(extension::groups(vector <extension::group_t> {static_cast <extension::group_t> (0x2A2A), extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1}, groups), extension::error_t::NONE);
		// Заполнение
		padding.assign(200, 0x00);
		// Безопасное пересогласование
		renegotiation = vector <uint8_t> {0x00};
		// Расширение GREASE впереди
		greeting.extensions.push_back(hello::extension_t(0x2A2A, view_t(nullptr, 0)));
		// Расширения в порядке примера JA4_o
		greeting.extensions.push_back(hello::extension_t(0x001B, view_t(compress.data(), compress.size())));
		greeting.extensions.push_back(hello::extension_t(0x0000, view_t(name.data(), name.size())));
		greeting.extensions.push_back(hello::extension_t(0x0033, view_t(share.data(), share.size())));
		greeting.extensions.push_back(hello::extension_t(0x0010, view_t(protocols.data(), protocols.size())));
		greeting.extensions.push_back(hello::extension_t(0x4469, view_t(settings.data(), settings.size())));
		greeting.extensions.push_back(hello::extension_t(0x0017, view_t(nullptr, 0)));
		greeting.extensions.push_back(hello::extension_t(0x002D, view_t(modes.data(), modes.size())));
		greeting.extensions.push_back(hello::extension_t(0x000D, view_t(schemes.data(), schemes.size())));
		greeting.extensions.push_back(hello::extension_t(0x0005, view_t(status.data(), status.size())));
		greeting.extensions.push_back(hello::extension_t(0x0023, view_t(nullptr, 0)));
		greeting.extensions.push_back(hello::extension_t(0x0012, view_t(nullptr, 0)));
		greeting.extensions.push_back(hello::extension_t(0x002B, view_t(versions.data(), versions.size())));
		greeting.extensions.push_back(hello::extension_t(0xFF01, view_t(renegotiation.data(), renegotiation.size())));
		greeting.extensions.push_back(hello::extension_t(0x000B, view_t(formats.data(), formats.size())));
		greeting.extensions.push_back(hello::extension_t(0x000A, view_t(groups.data(), groups.size())));
		// Второе расширение GREASE с телом в один байт
		greeting.extensions.push_back(hello::extension_t(0x3A3A, view_t(STUB, 1)));
		// Заполнение последним
		greeting.extensions.push_back(hello::extension_t(0x0015, view_t(padding.data(), padding.size())));
		// Выводим итог составления
		return (hello::build(greeting, body) == hello::error_t::NONE);
	}
	/**
	 * @brief Метод составления приветствия по примеру JA3
	 *
	 * @param body составляемое тело приветствия
	 * @return     результат составления
	 *
	 */
	static bool oldhello(vector <uint8_t> & body) {
		// Составляемое приветствие
		hello::client_t greeting;
		// Издание приветствия TLS 1.0
		greeting.version = 0x0301;
		// Случайное значение
		::memset(greeting.random, 0x07, sizeof(greeting.random));
		/**
		 * Выполняем перебор наборов примера
		 */
		for(size_t i = 0; i < (sizeof(JA3_SUITES) / sizeof(JA3_SUITES[0])); i++)
			// Добавляем набор
			greeting.suites.push_back(JA3_SUITES[i]);
		// Способ сжатия
		greeting.methods.push_back(0);
		// Тела расширений
		static vector <uint8_t> name, groups, formats;
		// Очищаем накопители: составители дописывают в конец
		name.clear(); groups.clear(); formats.clear();
		// Имя узла
		static const char HOST[] = "ja3.example";
		// Составляем имя узла
		EXPECT_EQ(extension::name(view_t(reinterpret_cast <const uint8_t *> (HOST), sizeof(HOST) - 1), name), extension::error_t::NONE);
		// Группы 23, 24, 25
		EXPECT_EQ(extension::groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::SECP384R1, static_cast <extension::group_t> (0x0019)}, groups), extension::error_t::NONE);
		// Записи точек
		EXPECT_EQ(extension::formats(vector <uint8_t> {0x00}, formats), extension::error_t::NONE);
		// Расширения в порядке примера
		greeting.extensions.push_back(hello::extension_t(0x0000, view_t(name.data(), name.size())));
		greeting.extensions.push_back(hello::extension_t(0x000A, view_t(groups.data(), groups.size())));
		greeting.extensions.push_back(hello::extension_t(0x000B, view_t(formats.data(), formats.size())));
		// Выводим итог составления
		return (hello::build(greeting, body) == hello::error_t::NONE);
	}
	/**
	 * @brief Метод составления начала потока HTTP/2 как у Chrome
	 *
	 * @return байты потока
	 *
	 */
	static vector <uint8_t> chromestream() {
		// Составляемый поток
		vector <uint8_t> result;
		// Предисловие
		static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
		// Дописываем предисловие
		result.insert(result.end(), PREFACE, PREFACE + sizeof(PREFACE) - 1);
		// Кадр настроек: 1:65536, 2:0, 4:6291456, 6:262144
		static const uint8_t SETTINGS[] = {
			0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
			0x00, 0x06, 0x00, 0x04, 0x00, 0x00
		};
		// Дописываем кадр настроек
		result.insert(result.end(), SETTINGS, SETTINGS + sizeof(SETTINGS));
		// Кадр прибавки окна 15663105
		static const uint8_t WINDOW[] = {0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0x00, 0x01};
		// Дописываем кадр прибавки окна
		result.insert(result.end(), WINDOW, WINDOW + sizeof(WINDOW));
		// Кадр заголовков потока 1: :method GET (индекс 2), :authority буквально, :scheme https (7), :path / (4), accept (19 с значением)
		static const uint8_t HEADERS[] = {
			0x00, 0x00, 0x13, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
			0x82,
			0x41, 0x04, 'h', 'o', 's', 't',
			0x87,
			0x84,
			0x53, 0x03, '*', '/', '*',
			0x00, 0x01, 'x', 0x01, 'y'
		};
		// Дописываем кадр заголовков
		result.insert(result.end(), HEADERS, HEADERS + sizeof(HEADERS));
		// Выводим поток
		return result;
	}
	/**
	 * Путь к набору ключей
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора на чтение
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла набора
		vector <uint8_t> result;
		// Если файл набора открыт
		if(file.is_open())
			// Переносим содержимое файла набора
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла набора
		return result;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	static bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Получаем байты, отправляемые клиентом
			view_t data = client.output();
			// Если клиенту есть что отправить серверу
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
			// Получаем байты, отправляемые сервером
			data = server.output();
			// Если серверу есть что отправить клиенту
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя сервера
				server.consume(buffer.size());
				// Выполняем подачу отправленных байтов клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что байты между сторонами не передавались
			return false;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи записями
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	}
	/**
	 * @brief Метод снятия приветствия клиента с отправляемых байтов без их изъятия
	 *
	 * @param client связь стороны клиента
	 * @param result профиль, в который помещается разбор приветствия
	 * @return       признак успешности снятия
	 *
	 */
	static bool captured(client::context_t & client, fingerprint::profile_t & result) noexcept {
		// Получаем байты, отправляемые клиентом
		const view_t sending = client.output();
		// Выводим итог разбора записи с приветствием
		return (fingerprint::parse(sending, result) == fingerprint::error_t::NONE);
	}
	/**
	 * @brief Метод проверки присутствия расширения в профиле
	 *
	 * @param profile профиль приветствия
	 * @param type    вид расширения по проводу
	 * @return        признак присутствия
	 *
	 */
	static bool seek_type(const fingerprint::profile_t & profile, const uint16_t type) noexcept {
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Если вид совпал
			if(profile.extensions[i].type == type)
				// Выводим присутствие
				return true;
		}
		// Выводим отсутствие
		return false;
	}
	/**
	 * @brief Метод сличения отпечатков двух профилей без учёта случайных полей
	 *
	 * @param source исходный профиль
	 * @param made   профиль, сложенный связью
	 * @param why    место, в которое помещается причина расхождения
	 * @return       признак совпадения отпечатков
	 *
	 */
	static bool matched(const fingerprint::profile_t & source, const fingerprint::profile_t & made, string & why) noexcept {
		// Отпечатки профилей
		fingerprint::imprint_t before, after;
		// Если отпечатки вычислить не удалось
		if((fingerprint::imprint(source, before) != fingerprint::error_t::NONE) || (fingerprint::imprint(made, after) != fingerprint::error_t::NONE)){
			// Запоминаем причину
			why = "отпечатки не вычислены";
			// Выводим расхождение
			return false;
		}
		// Если JA3 разошлись
		if(before.ja3 != after.ja3){
			// Запоминаем причину
			why = ("JA3: " + before.ja3 + " против " + after.ja3);
			// Выводим расхождение
			return false;
		}
		// Если JA4 разошлись
		if(before.ja4 != after.ja4){
			// Запоминаем причину
			why = ("JA4: " + before.ja4 + " против " + after.ja4);
			// Выводим расхождение
			return false;
		}
		// Если JA4_r разошлись
		if(before.ja4r != after.ja4r){
			// Запоминаем причину
			why = ("JA4_r: " + before.ja4r + " против " + after.ja4r);
			// Выводим расхождение
			return false;
		}
		// Если JA4_o разошлись
		if(before.ja4o != after.ja4o){
			// Запоминаем причину
			why = ("JA4_o: " + before.ja4o + " против " + after.ja4o);
			// Выводим расхождение
			return false;
		}
		// Если PeetPrint разошлись
		if(before.peetprint != after.peetprint){
			// Запоминаем причину
			why = ("PeetPrint: " + before.peetprint + " против " + after.peetprint);
			// Выводим расхождение
			return false;
		}
		// Выводим совпадение
		return true;
	}
}

/**
 * Проверка распознавания значений GREASE
 */
TEST(FingerprintTest, Grease){
	/**
	 * Выполняем перебор старших половин байта
	 */
	for(uint16_t high = 0; high < 16; high++){
		// Значение GREASE
		const uint16_t value = static_cast <uint16_t> (((high << 4) | 0x0A) * 0x0101);
		// Проверяем распознавание
		EXPECT_TRUE(fingerprint::grease(value)) << value;
	}
	// Проверяем чужие значения
	EXPECT_FALSE(fingerprint::grease(0x0A0B));
	EXPECT_FALSE(fingerprint::grease(0x1A0A));
	EXPECT_FALSE(fingerprint::grease(0x1301));
	EXPECT_FALSE(fingerprint::grease(0x0000));
	EXPECT_FALSE(fingerprint::grease(0xFF01));
}

/**
 * Проверка примера JA4 от FoxIO: приветствие с GREASE на местах Chrome
 */
TEST(FingerprintTest, Ja4){
	// Тело приветствия
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль приветствия
	fingerprint::profile_t profile;
	// Разбираем запись
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), profile), fingerprint::error_t::NONE);
	// Проверяем поля профиля
	EXPECT_TRUE(profile.grease);
	EXPECT_FALSE(profile.datagram);
	EXPECT_EQ(profile.record, 0x0301);
	EXPECT_EQ(profile.version, 0x0303);
	EXPECT_EQ(profile.length, static_cast <uint32_t> (body.size()));
	EXPECT_EQ(profile.session.size(), static_cast <size_t> (32));
	EXPECT_EQ(profile.suites.size(), static_cast <size_t> (16));
	EXPECT_EQ(profile.extensions.size(), static_cast <size_t> (18));
	EXPECT_EQ(profile.random[0], 0x42);
	// Проверяем разбор тел расширений
	EXPECT_EQ(profile.extensions[2].names.size(), static_cast <size_t> (1));
	EXPECT_EQ(profile.extensions[2].names[0], "example.com");
	EXPECT_EQ(profile.extensions[3].shares.size(), static_cast <size_t> (2));
	EXPECT_EQ(profile.extensions[3].shares[1].group, extension::group_t::X25519);
	EXPECT_EQ(profile.extensions[3].shares[1].key.size(), static_cast <size_t> (32));
	EXPECT_EQ(profile.extensions[4].protocols.size(), static_cast <size_t> (2));
	EXPECT_EQ(profile.extensions[4].protocols[1], "http/1.1");
	EXPECT_EQ(profile.extensions[5].protocols.size(), static_cast <size_t> (1));
	EXPECT_EQ(profile.extensions[7].modes.size(), static_cast <size_t> (1));
	EXPECT_EQ(profile.extensions[8].schemes.size(), static_cast <size_t> (8));
	EXPECT_EQ(profile.extensions[9].value, static_cast <uint32_t> (1));
	EXPECT_EQ(profile.extensions[12].versions.size(), static_cast <size_t> (3));
	EXPECT_EQ(profile.extensions[14].formats.size(), static_cast <size_t> (1));
	EXPECT_EQ(profile.extensions[15].groups.size(), static_cast <size_t> (4));
	EXPECT_TRUE(profile.extensions[16].grease);
	EXPECT_EQ(profile.extensions[17].value, static_cast <uint32_t> (200));
	EXPECT_EQ(profile.extensions[1].algorithms.size(), static_cast <size_t> (1));
	EXPECT_EQ(profile.extensions[1].algorithms[0], extension::compression_t::BROTLI);
	// Отпечатки профиля
	fingerprint::imprint_t imprint;
	// Вычисляем отпечатки
	ASSERT_EQ(fingerprint::imprint(profile, imprint), fingerprint::error_t::NONE);
	// Проверяем отпечатки JA4 по описанию FoxIO
	EXPECT_EQ(imprint.ja4, FOX_JA4);
	EXPECT_EQ(imprint.ja4r, FOX_JA4R);
	EXPECT_EQ(imprint.ja4o, FOX_JA4O);
	// Проверяем согласуемое издание
	EXPECT_EQ(imprint.negotiated, 0x0304);
	EXPECT_EQ(imprint.record, 0x0301);
	// Проверяем записи случайного значения и опознавателя
	EXPECT_EQ(imprint.random.size(), static_cast <size_t> (64));
	EXPECT_EQ(imprint.session.size(), static_cast <size_t> (64));
	EXPECT_EQ(imprint.random.substr(0, 4), "4242");
	// Проверяем JA3: GREASE снят, десятичная запись
	EXPECT_EQ(imprint.ja3.substr(0, 4), "771,");
	EXPECT_EQ(imprint.ja3hash.size(), static_cast <size_t> (32));
	EXPECT_EQ(imprint.ja3.find("GREASE"), string::npos);
	EXPECT_EQ(imprint.ja3.find("10794"), string::npos);
	// Проверяем PeetPrint: GREASE словом, восемь разделов
	EXPECT_NE(imprint.peetprint.find("GREASE-772-771|"), string::npos);
	EXPECT_EQ(imprint.peethash.size(), static_cast <size_t> (32));
	// Число разделов PeetPrint
	size_t sections = 1;
	/**
	 * Выполняем перебор знаков PeetPrint
	 */
	for(size_t i = 0; i < imprint.peetprint.size(); i++)
		// Считаем разделители
		sections += ((imprint.peetprint[i] == '|') ? 1 : 0);
	// Проверяем число разделов
	EXPECT_EQ(sections, static_cast <size_t> (8));
	// Проверяем оценку обозревателя
	EXPECT_TRUE(fingerprint::browser(imprint));
	// Печать профиля
	string text;
	// Печатаем профиль
	ASSERT_EQ(fingerprint::print(profile, text), fingerprint::error_t::NONE);
	// Проверяем печать
	EXPECT_NE(text.find("grease: yes"), string::npos);
	EXPECT_NE(text.find("name=example.com"), string::npos);
	EXPECT_NE(text.find("protocols=h2,http/1.1"), string::npos);
	EXPECT_NE(text.find("0x2a2a GREASE"), string::npos);
}

/**
 * Проверка примера JA3 из его описания
 */
TEST(FingerprintTest, Ja3){
	// Тело приветствия
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(oldhello(body));
	// Профиль приветствия из голого сообщения с заголовком
	fingerprint::profile_t profile;
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Голое сообщение: запись без заголовка
	const vector <uint8_t> message(record.begin() + 5, record.end());
	// Разбираем голое сообщение
	ASSERT_EQ(fingerprint::parse(view_t(message.data(), message.size()), profile), fingerprint::error_t::NONE);
	// Проверяем поля профиля
	EXPECT_FALSE(profile.grease);
	EXPECT_EQ(profile.record, 0);
	EXPECT_EQ(profile.version, 0x0301);
	EXPECT_TRUE(profile.session.empty());
	// Отпечатки профиля
	fingerprint::imprint_t imprint;
	// Вычисляем отпечатки
	ASSERT_EQ(fingerprint::imprint(profile, imprint), fingerprint::error_t::NONE);
	// Проверяем JA3 по описанию
	EXPECT_EQ(imprint.ja3, JA3_TEXT);
	EXPECT_EQ(imprint.ja3hash, JA3_HASH);
	// Проверяем JA4 без 1.3: издание приветствия, без ALPN, три расширения
	EXPECT_EQ(imprint.ja4.substr(0, 11), "t10d120300_");
	EXPECT_EQ(imprint.negotiated, 0x0301);
	// Проверяем оценку обозревателя
	EXPECT_FALSE(fingerprint::browser(imprint));
}

/**
 * Проверка разбора поверх дейтаграмм
 */
TEST(FingerprintTest, Datagram){
	// Тело приветствия
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(oldhello(body));
	// Запись поверх дейтаграмм с меткой возврата: тело потокового устройства получает метку
	hello::client_t greeting;
	// Разбираем тело потокового устройства
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), greeting), hello::error_t::NONE);
	// Издание DTLS 1.2
	greeting.version = 0xFEFD;
	// Метка возврата
	greeting.cookie.assign(16, 0xAB);
	// Тело поверх дейтаграмм
	vector <uint8_t> datagram;
	// Составляем тело
	ASSERT_EQ(hello::build(greeting, datagram, true), hello::error_t::NONE);
	// Запись поверх дейтаграмм
	const vector <uint8_t> record = wrapped(datagram, true, 0xFEFF);
	// Профиль приветствия
	fingerprint::profile_t profile;
	// Разбираем запись с распознаванием устройства
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), profile), fingerprint::error_t::NONE);
	// Проверяем поля профиля
	EXPECT_TRUE(profile.datagram);
	EXPECT_EQ(profile.record, 0xFEFF);
	EXPECT_EQ(profile.version, 0xFEFD);
	EXPECT_EQ(profile.sequence, static_cast <uint64_t> (7));
	EXPECT_EQ(profile.message, 3);
	EXPECT_EQ(profile.cookie.size(), static_cast <size_t> (16));
	// Отпечатки профиля
	fingerprint::imprint_t imprint;
	// Вычисляем отпечатки
	ASSERT_EQ(fingerprint::imprint(profile, imprint), fingerprint::error_t::NONE);
	// Проверяем перенос и издание JA4
	EXPECT_EQ(imprint.ja4.substr(0, 4), "dd2d");
	// Голое сообщение поверх дейтаграмм требует заданного устройства
	const vector <uint8_t> message(record.begin() + 13, record.end());
	// Разбираем голое сообщение
	ASSERT_EQ(fingerprint::parse(view_t(message.data(), message.size()), profile, true), fingerprint::error_t::NONE);
	// Проверяем поля профиля
	EXPECT_EQ(profile.record, 0);
	EXPECT_EQ(profile.message, 3);
	// Голое сообщение поверх дейтаграмм под потоковым устройством не разбирается
	EXPECT_NE(fingerprint::parse(view_t(message.data(), message.size()), profile, false), fingerprint::error_t::NONE);
	// Запись поверх дейтаграмм под потоковым устройством отвергается
	EXPECT_EQ(fingerprint::parse(view_t(record.data(), record.size()), profile, false), fingerprint::error_t::RECORD);
}

/**
 * Проверка отказов разбора
 */
TEST(FingerprintTest, Refusals){
	// Тело приветствия
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0303);
	// Профиль приветствия
	fingerprint::profile_t profile;
	// Пустой вход
	EXPECT_EQ(fingerprint::parse(view_t(nullptr, 0), profile), fingerprint::error_t::HUNGRY);
	/**
	 * Выполняем перебор длин усечения
	 */
	for(size_t size = 1; size < record.size(); size++)
		// Усечённая запись не разбирается
		EXPECT_NE(fingerprint::parse(view_t(record.data(), size), profile), fingerprint::error_t::NONE) << size;
	// Лишний байт за записью
	vector <uint8_t> longer = record;
	// Дописываем байт
	longer.push_back(0x00);
	// Запись с хвостом разбирается: хвост есть следующая запись
	EXPECT_EQ(fingerprint::parse(view_t(longer.data(), longer.size()), profile), fingerprint::error_t::NONE);
	// Запись чужого вида
	vector <uint8_t> broken = record;
	// Портим вид записи
	broken[0] = 0x17;
	// Запись чужого вида отвергается
	EXPECT_EQ(fingerprint::parse(view_t(broken.data(), broken.size()), profile), fingerprint::error_t::RECORD);
	// Возвращаем вид записи
	broken[0] = 0x16;
	// Портим вид сообщения
	broken[5] = 0x02;
	// Сообщение чужого вида отвергается
	EXPECT_EQ(fingerprint::parse(view_t(broken.data(), broken.size()), profile), fingerprint::error_t::MESSAGE);
	// Возвращаем вид сообщения
	broken[5] = 0x01;
	// Портим длину перечня наборов: смещение за заголовками, изданием, случайным и опознавателем
	broken[5 + 4 + 2 + 32 + 1 + 32] = 0xFF;
	// Порченый перечень наборов отвергается
	EXPECT_NE(fingerprint::parse(view_t(broken.data(), broken.size()), profile), fingerprint::error_t::NONE);
	// Профиль после отказа пуст
	EXPECT_TRUE(profile.suites.empty());
	// Пустой профиль отпечатков не даёт
	fingerprint::imprint_t imprint;
	// Вычисляем отпечатки
	EXPECT_EQ(fingerprint::imprint(profile, imprint), fingerprint::error_t::EMPTY);
	// Печать пустого профиля
	string text;
	// Печатаем профиль
	EXPECT_EQ(fingerprint::print(profile, text), fingerprint::error_t::EMPTY);
	// Снимок пустого профиля
	vector <uint8_t> snapshot;
	// Составляем снимок
	EXPECT_EQ(fingerprint::dump(profile, snapshot), fingerprint::error_t::EMPTY);
	// Порченое тело расширения: перечень групп нечётной длины
	hello::client_t greeting;
	// Разбираем тело
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), greeting), hello::error_t::NONE);
	// Порченое тело групп
	static const uint8_t ODD[] = {0x00, 0x03, 0x00, 0x1D, 0x00};
	/**
	 * Выполняем перебор расширений
	 */
	for(size_t i = 0; i < greeting.extensions.size(); i++){
		// Если расширение есть перечень групп
		if(greeting.extensions[i].type == 0x000A)
			// Подменяем тело
			greeting.extensions[i].data = view_t(ODD, sizeof(ODD));
	}
	// Тело с порченым расширением
	vector <uint8_t> damaged;
	// Составляем тело
	ASSERT_EQ(hello::build(greeting, damaged), hello::error_t::NONE);
	// Запись с порченым расширением
	const vector <uint8_t> spoiled = wrapped(damaged, false, 0x0303);
	// Порченое расширение отвергается
	EXPECT_EQ(fingerprint::parse(view_t(spoiled.data(), spoiled.size()), profile), fingerprint::error_t::EXTENSION);
}

/**
 * Проверка снимка профиля и хранилища
 */
TEST(FingerprintTest, Snapshot){
	// Тела приветствий
	vector <uint8_t> first, second;
	// Составляем приветствия
	ASSERT_TRUE(foxhello(first));
	ASSERT_TRUE(oldhello(second));
	// Профили приветствий
	fingerprint::profile_t fox, old, loaded;
	// Разбираем приветствия
	// Записи рукопожатия
	const vector <uint8_t> foxrecord = wrapped(first, false, 0x0303), oldrecord = wrapped(second, false, 0x0301);
	// Разбираем записи
	ASSERT_EQ(fingerprint::parse(view_t(foxrecord.data(), foxrecord.size()), fox), fingerprint::error_t::NONE);
	ASSERT_EQ(fingerprint::parse(view_t(oldrecord.data(), oldrecord.size()), old), fingerprint::error_t::NONE);
	// Снимок профиля
	vector <uint8_t> snapshot;
	// Составляем снимок
	ASSERT_EQ(fingerprint::dump(fox, snapshot), fingerprint::error_t::NONE);
	// Проверяем метку снимка
	EXPECT_EQ(::memcmp(snapshot.data(), "ANTSFP", 6), 0);
	// Читаем снимок
	ASSERT_EQ(fingerprint::load(view_t(snapshot.data(), snapshot.size()), loaded), fingerprint::error_t::NONE);
	// Отпечатки исходного и прочитанного профилей
	fingerprint::imprint_t before, after;
	// Вычисляем отпечатки
	ASSERT_EQ(fingerprint::imprint(fox, before), fingerprint::error_t::NONE);
	ASSERT_EQ(fingerprint::imprint(loaded, after), fingerprint::error_t::NONE);
	// Проверяем совпадение отпечатков и полей
	EXPECT_EQ(before.ja4r, after.ja4r);
	EXPECT_EQ(before.ja3, after.ja3);
	EXPECT_EQ(before.peetprint, after.peetprint);
	EXPECT_EQ(before.random, after.random);
	EXPECT_EQ(before.session, after.session);
	EXPECT_EQ(loaded.length, fox.length);
	EXPECT_EQ(loaded.extensions.size(), fox.extensions.size());
	EXPECT_EQ(loaded.extensions[2].names, fox.extensions[2].names);
	EXPECT_EQ(loaded.grease, fox.grease);
	// Повторный снимок прочитанного профиля совпадает байт в байт
	vector <uint8_t> again;
	// Составляем снимок
	ASSERT_EQ(fingerprint::dump(loaded, again), fingerprint::error_t::NONE);
	// Проверяем совпадение снимков
	EXPECT_EQ(again, snapshot);
	/**
	 * Выполняем перебор длин усечения снимка
	 */
	for(size_t size = 0; size < snapshot.size(); size++)
		// Усечённый снимок не читается
		EXPECT_NE(fingerprint::load(view_t(snapshot.data(), size), loaded), fingerprint::error_t::NONE) << size;
	// Снимок с хвостом
	vector <uint8_t> longer = snapshot;
	// Дописываем байт
	longer.push_back(0x00);
	// Снимок с хвостом отвергается
	EXPECT_EQ(fingerprint::load(view_t(longer.data(), longer.size()), loaded), fingerprint::error_t::FORMAT);
	// Снимок чужого издания
	vector <uint8_t> edition = snapshot;
	// Портим издание
	edition[6] = 0x7F;
	// Снимок чужого издания отвергается
	EXPECT_EQ(fingerprint::load(view_t(edition.data(), edition.size()), loaded), fingerprint::error_t::VERSION);
	// Снимок с чужой меткой
	vector <uint8_t> stamp = snapshot;
	// Портим метку
	stamp[0] = 'B';
	// Снимок с чужой меткой отвергается
	EXPECT_EQ(fingerprint::load(view_t(stamp.data(), stamp.size()), loaded), fingerprint::error_t::FORMAT);
	// Хранилище профилей
	fingerprint::store_t store;
	// Проверяем пустоту хранилища
	EXPECT_TRUE(store.empty());
	// Добавляем профили
	const fingerprint::id_t one = store.add(fox), two = store.add(old);
	// Проверяем опознаватели
	EXPECT_EQ(one, 1);
	EXPECT_EQ(two, 2);
	EXPECT_EQ(store.size(), static_cast <size_t> (2));
	// Пустой профиль не добавляется
	EXPECT_EQ(store.add(fingerprint::profile_t()), 0);
	// Проверяем получение профилей
	ASSERT_NE(store.get(one), nullptr);
	EXPECT_EQ(store.get(one)->suites.size(), fox.suites.size());
	EXPECT_EQ(store.get(3), nullptr);
	EXPECT_EQ(store.get(0), nullptr);
	// Перечень опознавателей
	vector <fingerprint::id_t> list;
	// Получаем перечень
	ASSERT_EQ(store.list(list), fingerprint::error_t::NONE);
	// Проверяем перечень
	EXPECT_EQ(list, (vector <fingerprint::id_t> {1, 2}));
	// Снимок хранилища
	vector <uint8_t> bundle;
	// Составляем снимок
	ASSERT_EQ(store.dump(bundle), fingerprint::error_t::NONE);
	// Удаляем первый профиль
	EXPECT_TRUE(store.remove(one));
	EXPECT_FALSE(store.remove(one));
	EXPECT_EQ(store.size(), static_cast <size_t> (1));
	// Освободившийся опознаватель выдаётся вновь
	EXPECT_EQ(store.add(fox), 1);
	// Другое хранилище читает снимок
	fingerprint::store_t other;
	// Читаем снимок
	ASSERT_EQ(other.load(view_t(bundle.data(), bundle.size())), fingerprint::error_t::NONE);
	// Проверяем прочитанное
	EXPECT_EQ(other.size(), static_cast <size_t> (2));
	ASSERT_NE(other.get(2), nullptr);
	EXPECT_EQ(other.get(2)->version, 0x0301);
	// Повторный снимок совпадает байт в байт
	vector <uint8_t> twice;
	// Составляем снимок
	ASSERT_EQ(other.dump(twice), fingerprint::error_t::NONE);
	// Проверяем совпадение
	EXPECT_EQ(twice, bundle);
	/**
	 * Выполняем перебор длин усечения снимка хранилища
	 */
	for(size_t size = 0; size < bundle.size(); size++)
		// Усечённый снимок не читается
		EXPECT_NE(other.load(view_t(bundle.data(), size)), fingerprint::error_t::NONE) << size;
	// Хранилище после отказа не тронуто
	EXPECT_EQ(other.size(), static_cast <size_t> (2));
	// Пустое хранилище снимка не даёт
	store.clear();
	EXPECT_TRUE(store.empty());
	EXPECT_EQ(store.dump(bundle), fingerprint::error_t::EMPTY);
}

/**
 * Проверка отпечатка Akamai по началу потока HTTP/2
 */
TEST(FingerprintTest, Akamai){
	// Поток как у Chrome
	const vector <uint8_t> data = chromestream();
	// Признаки потока
	fingerprint::stream_t stream;
	// Разбираем поток
	ASSERT_EQ(fingerprint::parse(view_t(data.data(), data.size()), stream), fingerprint::error_t::NONE);
	// Проверяем признаки
	EXPECT_EQ(stream.settings.size(), static_cast <size_t> (4));
	EXPECT_EQ(stream.window, static_cast <uint32_t> (15663105));
	EXPECT_EQ(stream.pseudo, "masp");
	// Отпечаток Akamai
	string akamai;
	// Вычисляем отпечаток
	ASSERT_EQ(fingerprint::akamai(stream, akamai), fingerprint::error_t::NONE);
	// Проверяем отпечаток Chrome
	EXPECT_EQ(akamai, "1:65536;2:0;4:6291456;6:262144|15663105||m,a,s,p");
	// Поток без предисловия отвергается
	EXPECT_EQ(fingerprint::parse(view_t(data.data() + 1, data.size() - 1), stream), fingerprint::error_t::RECORD);
	// Усечённый поток без кадра настроек пуст
	EXPECT_EQ(fingerprint::parse(view_t(data.data(), 24 + 9), stream), fingerprint::error_t::EMPTY);
	// Отпечаток без настроек не вычисляется
	EXPECT_EQ(fingerprint::akamai(stream, akamai), fingerprint::error_t::EMPTY);
	// Поток с кадром приоритета
	vector <uint8_t> prioritized(data.begin(), data.begin() + 24 + 9 + 24);
	// Кадр приоритета потока 3: исключительно от 0 с весом 201
	static const uint8_t PRIORITY[] = {0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x00, 0x00, 0x00, 0xC8};
	// Дописываем кадр приоритета
	prioritized.insert(prioritized.end(), PRIORITY, PRIORITY + sizeof(PRIORITY));
	// Разбираем поток
	ASSERT_EQ(fingerprint::parse(view_t(prioritized.data(), prioritized.size()), stream), fingerprint::error_t::NONE);
	// Вычисляем отпечаток
	ASSERT_EQ(fingerprint::akamai(stream, akamai), fingerprint::error_t::NONE);
	// Проверяем отпечаток с приоритетом
	EXPECT_EQ(akamai, "1:65536;2:0;4:6291456;6:262144|0|3:1:0:201|");
}

/**
 * Проверка поведения при нехватке памяти
 */
TEST(FingerprintTest, Starved){
	// Тело приветствия
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0303);
	// Поток HTTP/2
	const vector <uint8_t> data = chromestream();
	// Признак того, что нехватка памяти встретилась
	bool starved = false;
	// Признак того, что на щедром запасе всё удалось
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Отказы шагов
		fingerprint::error_t parsed = fingerprint::error_t::NONE, imprinted = fingerprint::error_t::NONE, dumped = fingerprint::error_t::NONE, loaded = fingerprint::error_t::NONE, printed = fingerprint::error_t::NONE, streamed = fingerprint::error_t::NONE, hashed = fingerprint::error_t::NONE;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Профили
			fingerprint::profile_t profile, copy;
			// Отпечатки
			fingerprint::imprint_t imprint;
			// Снимок, печать, поток
			vector <uint8_t> snapshot;
			string text, akamai;
			fingerprint::stream_t stream;
			// Разбираем запись
			parsed = fingerprint::parse(view_t(record.data(), record.size()), profile);
			// Если запись разобрана
			if(parsed == fingerprint::error_t::NONE){
				// Вычисляем отпечатки
				imprinted = fingerprint::imprint(profile, imprint);
				// Составляем снимок
				dumped = fingerprint::dump(profile, snapshot);
				// Если снимок составлен
				if(dumped == fingerprint::error_t::NONE)
					// Читаем снимок
					loaded = fingerprint::load(view_t(snapshot.data(), snapshot.size()), copy);
				// Печатаем профиль
				printed = fingerprint::print(profile, text);
			}
			// Разбираем поток
			streamed = fingerprint::parse(view_t(data.data(), data.size()), stream);
			// Если поток разобран
			if(streamed == fingerprint::error_t::NONE)
				// Вычисляем отпечаток
				hashed = fingerprint::akamai(stream, akamai);
		}
		// Отказы шагов
		const fingerprint::error_t outcomes[] = {parsed, imprinted, dumped, loaded, printed, streamed, hashed};
		/**
		 * Выполняем перебор отказов
		 */
		for(size_t i = 0; i < (sizeof(outcomes) / sizeof(outcomes[0])); i++){
			// Всякий отказ либо NONE, либо MEMORY
			ASSERT_TRUE((outcomes[i] == fingerprint::error_t::NONE) || (outcomes[i] == fingerprint::error_t::MEMORY)) << "запас " << budget << " шаг " << i << " отказ " << static_cast <int> (outcomes[i]);
			// Запоминаем встречу нехватки
			starved = (starved || (outcomes[i] == fingerprint::error_t::MEMORY));
		}
		// Полный успех всех шагов
		complete = ((parsed == fingerprint::error_t::NONE) && (imprinted == fingerprint::error_t::NONE) && (dumped == fingerprint::error_t::NONE) && (loaded == fingerprint::error_t::NONE) && (printed == fingerprint::error_t::NONE) && (streamed == fingerprint::error_t::NONE) && (hashed == fingerprint::error_t::NONE));
	}
	// Нехватка памяти встречена и полный успех достигнут
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}


/**
 * Проверка складывания приветствия по профилю: отпечатки сложенного приветствия равны снимку
 */
TEST(ProfileTest, Loopback){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Имя узла у клиента: профиль несёт SNI
	client.name("example.com");
	// Профиль ставится до заведения
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Подлинность сервера
	server.credential(credential);
	// Прикладные протоколы сервера
	server.protocols(vector <string> {"h2"});
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профиль сложенного приветствия
	fingerprint::profile_t made;
	// Снимаем сложенное приветствие
	ASSERT_TRUE(captured(client, made));
	// Причина расхождения
	string why;
	// Отпечатки сложенного приветствия равны снимку
	EXPECT_TRUE(matched(source, made, why)) << why;
	// Случайное значение и опознаватель связи свежие, длина опознавателя та же
	EXPECT_NE(::memcmp(made.random, source.random, fingerprint::FINGERPRINT_RANDOM), 0);
	EXPECT_EQ(made.session.size(), source.session.size());
	EXPECT_NE(made.session, source.session);
	// Значения GREASE свои, а места те же
	EXPECT_TRUE(fingerprint::grease(static_cast <uint16_t> (made.suites[0])));
	EXPECT_TRUE(made.extensions[0].grease);
	EXPECT_TRUE(made.extensions[16].grease);
	EXPECT_NE(made.extensions[0].type, made.extensions[16].type);
	EXPECT_EQ(made.extensions[16].data.size(), static_cast <size_t> (1));
	// Издание, способы сжатия и число расширений те же
	EXPECT_EQ(made.version, source.version);
	EXPECT_EQ(made.methods, source.methods);
	EXPECT_EQ(made.extensions.size(), source.extensions.size());
	// Доля ключа X25519 своя и свежая, доля GREASE на месте
	EXPECT_EQ(made.extensions[3].shares.size(), static_cast <size_t> (2));
	EXPECT_TRUE(fingerprint::grease(static_cast <uint16_t> (made.extensions[3].shares[0].group)));
	EXPECT_EQ(made.extensions[3].shares[1].group, extension::group_t::X25519);
	EXPECT_NE(made.extensions[3].shares[1].key, source.extensions[3].shares[1].key);
	// Имя узла своё
	EXPECT_EQ(made.extensions[2].names[0], "example.com");
	// Издания GREASE первым, затем 1.3 и 1.2
	EXPECT_TRUE(fingerprint::grease(made.extensions[12].versions[0]));
	EXPECT_EQ(made.extensions[12].versions[1], 0x0304);
	// Заполнение на своём месте: приветствие ровно 512 байтов с обвязкой
	EXPECT_EQ(made.extensions[17].type, 0x0015);
	EXPECT_EQ(made.length + 4, static_cast <uint32_t> (512));
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем выбранный набор: сервер выбирает из ведомых наборов профиля по своему порядку
	EXPECT_EQ(client.suite(), protect::suite_t::AES_256_GCM_SHA384);
	// Проверяем прикладной протокол: протоколы взяты из профиля
	EXPECT_EQ(client.protocol(), "h2");
	// Сервер отдаёт профиль принятого приветствия
	fingerprint::profile_t seen;
	// Снимаем профиль на сервере
	ASSERT_EQ(server.profile(seen), context::error_t::NONE);
	// Отпечатки принятого приветствия равны снимку
	EXPECT_TRUE(matched(source, seen, why)) << why;
	// Сырые байты приветствия у сервера начинаются сообщением приветствия
	ASSERT_GT(server.greeting().size, static_cast <size_t> (4));
	EXPECT_EQ(server.greeting().data[0], 0x01);
	// Профиль после заведения не ставится
	EXPECT_EQ(client.profile(source), context::error_t::STATE);
}

/**
 * Проверка складывания приветствия по профилю через просьбу о повторе
 */
TEST(ProfileTest, Retry){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Имя узла
	client.name("example.com");
	// Профиль
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Сервер ведёт лишь P-256: доли по ней клиент не шлёт, идёт просьба о повторе
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Подлинность сервера
	server.credential(credential);
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профили первого и второго приветствий
	fingerprint::profile_t first, second;
	// Снимаем первое приветствие
	ASSERT_TRUE(captured(client, first));
	// Передаём приветствие серверу и просьбу о повторе клиенту
	ASSERT_TRUE(pump(client, server));
	// Снимаем второе приветствие
	ASSERT_TRUE(captured(client, second));
	// Причина расхождения
	string why;
	// Отпечатки обоих приветствий равны снимку
	EXPECT_TRUE(matched(source, first, why)) << why;
	EXPECT_TRUE(matched(source, second, why)) << why;
	// Значения GREASE и опознаватель связи те же у обоих приветствий
	EXPECT_EQ(first.suites[0], second.suites[0]);
	EXPECT_EQ(first.extensions[0].type, second.extensions[0].type);
	EXPECT_EQ(first.extensions[16].type, second.extensions[16].type);
	EXPECT_EQ(first.session, second.session);
	EXPECT_EQ(::memcmp(first.random, second.random, fingerprint::FINGERPRINT_RANDOM), 0);
	// Второе приветствие несёт долю лишь по P-256 (раздел 4.2.8 RFC 8446)
	EXPECT_EQ(second.extensions[3].shares.size(), static_cast <size_t> (1));
	EXPECT_EQ(second.extensions[3].shares[0].group, extension::group_t::SECP256R1);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Проверка отказов установки профиля
 */
TEST(ProfileTest, Refusals){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Пустой профиль отвергается
	EXPECT_EQ(client.profile(fingerprint::profile_t()), context::error_t::SETTINGS);
	// Профиль без единого ведомого набора отвергается
	fingerprint::profile_t alien = source;
	// Наборы, связи неведомые
	alien.suites = vector <protect::suite_t> {static_cast <protect::suite_t> (0xC0AC), static_cast <protect::suite_t> (0xC0AD)};
	// Проверяем отказ
	EXPECT_EQ(client.profile(alien), context::error_t::SETTINGS);
	// Профиль без единой ведомой группы отвергается
	alien = source;
	/**
	 * Выполняем перебор расширений
	 */
	for(size_t i = 0; i < alien.extensions.size(); i++){
		// Если расширение есть перечень групп
		if(alien.extensions[i].type == 0x000A)
			// Подменяем группы неведомыми
			alien.extensions[i].groups = vector <extension::group_t> {static_cast <extension::group_t> (0x11EC)};
	}
	// Проверяем отказ
	EXPECT_EQ(client.profile(alien), context::error_t::SETTINGS);
	// Профиль сервера не снимается до приёма приветствия
	fingerprint::profile_t seen;
	// Проверяем отказ
	EXPECT_EQ(server.profile(seen), context::error_t::STATE);
	EXPECT_EQ(server.greeting().size, static_cast <size_t> (0));
	// Имя узла
	client.name("example.com");
	// Годный профиль ставится
	EXPECT_EQ(client.profile(source), context::error_t::NONE);
	// Профиль перекрывает ручку GREASE: она на места не влияет
	client.grease(true);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профиль сложенного приветствия
	fingerprint::profile_t made;
	// Снимаем приветствие
	ASSERT_TRUE(captured(client, made));
	// Число расширений по профилю, а не по ручке
	EXPECT_EQ(made.extensions.size(), source.extensions.size());
	// Профиль без имени узла: расширение имени не идёт
	client::context_t nameless;
	// Ставим профиль
	ASSERT_EQ(nameless.profile(source), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(nameless.start(), context::error_t::NONE);
	// Снимаем приветствие
	ASSERT_TRUE(captured(nameless, made));
	// Расширений на одно меньше, имени узла нет
	EXPECT_EQ(made.extensions.size(), source.extensions.size() - 1);
	EXPECT_EQ(seek_type(made, 0x0000), false);
	// Профиль без опознавателя связи: приветствие идёт без опознавателя
	vector <uint8_t> plain;
	// Составляем приветствие примера JA3
	ASSERT_TRUE(oldhello(plain));
	// Запись рукопожатия
	const vector <uint8_t> older = wrapped(plain, false, 0x0301);
	// Профиль примера JA3
	fingerprint::profile_t bare;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(older.data(), older.size()), bare), fingerprint::error_t::NONE);
	// Связь стороны клиента
	client::context_t sessionless;
	// Ставим профиль: у него нет TLS 1.3, пределы изданий берутся из приветствия
	ASSERT_EQ(sessionless.profile(bare), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(sessionless.start(), context::error_t::NONE);
	// Снимаем приветствие
	ASSERT_TRUE(captured(sessionless, made));
	// Опознаватель связи пуст, как у снимка
	EXPECT_TRUE(made.session.empty());
	EXPECT_EQ(made.version, 0x0301);
}

/**
 * Проверка складывания приветствия по профилю с неведомыми группами и наборами: доля опускается, набор идёт как есть
 */
TEST(ProfileTest, Unknown){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Добавляем группу X25519MLKEM768 первой и долю по ней, как у Chrome, и неведомый набор первым
	source.suites.insert(source.suites.begin() + 1, static_cast <protect::suite_t> (0xC0AC));
	/**
	 * Выполняем перебор расширений
	 */
	for(size_t i = 0; i < source.extensions.size(); i++){
		// Если расширение есть перечень групп
		if(source.extensions[i].type == 0x000A)
			// Вставляем группу ML-KEM за GREASE
			source.extensions[i].groups.insert(source.extensions[i].groups.begin() + 1, static_cast <extension::group_t> (0x11EC));
		// Если расширение есть перечень долей
		if(source.extensions[i].type == 0x0033){
			// Доля ML-KEM
			fingerprint::share_t share;
			// Группа доли
			share.group = static_cast <extension::group_t> (0x11EC);
			// Ключ доли длиной 1216 байтов
			share.key.assign(1216, 0x33);
			// Вставляем долю за GREASE
			source.extensions[i].shares.insert(source.extensions[i].shares.begin() + 1, share);
		}
	}
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Имя узла
	client.name("example.com");
	// Профиль
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	// Подлинность сервера
	server.credential(credential);
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профиль сложенного приветствия
	fingerprint::profile_t made;
	// Снимаем приветствие
	ASSERT_TRUE(captured(client, made));
	// Неведомый набор идёт как есть на своём месте
	EXPECT_EQ(static_cast <uint16_t> (made.suites[1]), 0xC0AC);
	// Группа ML-KEM в перечне на своём месте, доля по ней опущена
	EXPECT_EQ(static_cast <uint16_t> (made.extensions[15].groups[1]), 0x11EC);
	EXPECT_EQ(made.extensions[3].shares.size(), static_cast <size_t> (2));
	EXPECT_EQ(made.extensions[3].shares[1].group, extension::group_t::X25519);
	// Проводим рукопожатие: сервер выбирает ведомый набор и группу
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Проверка рукопожатия по профилю с системным openssl и отказа при выборе неведомого набора
 */
TEST(ProfileTest, Openssl){
	// Способности системного openssl
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3
	if(!toolkit.tls13){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	/**
	 * Выполняем перебор случаев: рукопожатие по профилю и выбор сервером неведомого набора
	 */
	for(size_t alien = 0; alien < 2; alien++){
		// Если у openssl нет набора, связи неведомого
		if((alien == 1) && (shell("openssl ciphers ALL 2>/dev/null | grep -q ECDHE-ECDSA-AES128-CCM") != 0))
			// Переходим к следующему случаю
			continue;
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-fingerprint-server-" + std::to_string(number) + ".log";
		// Наборы сервера: неведомый связи набор ECDHE-ECDSA-AES128-CCM (0xC0AC) издания 1.2
		const std::string suites = ((alien == 1) ? " -cipher ECDHE-ECDSA-AES128-CCM -tls1_2" : "");
		// Запускаем сервер openssl в один приём с ответом HTTP
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -cert " + crt + " -key " + key + suites + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера openssl
		sentinel_t sentinel(log + ".pid");
		// Подключаемся к серверу openssl
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0) << "порт " << number;
		// Связь стороны клиента
		client::context_t client;
		// Профиль с неведомым набором первым среди ведомых
		fingerprint::profile_t profile = source;
		// Если сервер выбирает неведомый набор
		if(alien == 1)
			// Вставляем неведомый набор за GREASE
			profile.suites.insert(profile.suites.begin() + 1, static_cast <protect::suite_t> (0xC0AC));
		// Имя узла
		client.name("localhost");
		// Профиль
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до установления связи либо отказа
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты
			relay(client, fd);
		// Если сервер выбрал неведомый набор
		if(alien == 1){
			// Связь обрывается отказом исполнения профиля
			EXPECT_EQ(client.state(), context::state_t::FAILED);
			EXPECT_EQ(client.error(), context::error_t::PROFILE);
		// Если рукопожатие по профилю
		} else {
			// Проверяем установленность связи
			ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			// Запрос HTTP серверу openssl
			const string request = "GET / HTTP/1.0\r\n\r\n";
			// Отправляем запрос
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Накопитель ответа
			vector <uint8_t> answer;
			/**
			 * Выполняем передачу байтов до получения ответа
			 */
			for(size_t i = 0; (i < 16) && answer.empty(); i++){
				// Передаём байты
				relay(client, fd);
				// Читаем принятые данные
				ASSERT_EQ(client.read(answer), context::error_t::NONE);
			}
			// Текст ответа
			const string text(answer.begin(), answer.end());
			// Проверяем, что ответ HTTP получен
			ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
		}
		// Закрываем сокет
		::close(fd);
		// Снимаем сервер до удаления журнала
		sentinel.halt();
		// Журнал сервера
		std::string journal;
		// Дожидаемся отметки завершения снятого сервера
		(void) settle(log, journal);
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка поведения складывания по профилю при нехватке памяти
 */
TEST(ProfileTest, Starved){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Признак того, что нехватка памяти встретилась
	bool starved = false;
	// Признак того, что на щедром запасе всё удалось
	bool complete = false;
	// Имя узла складывается до ограничения запаса: строка из литерала под старым ABI libstdc++ выделяет память в теле проверки
	const string host = "example.com";
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Отказы установки профиля и заведения
		context::error_t set = context::error_t::NONE, started = context::error_t::NONE;
		// Признак установления связи
		bool established = false;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Связи сторон
			client::context_t client;
			server::context_t server;
			// Имя узла
			client.name(host);
			// Ставим профиль
			set = client.profile(source);
			// Если профиль поставлен
			if(set == context::error_t::NONE){
				// Подлинность сервера
				server.credential(credential);
				// Заводим сервер
				started = server.start();
				// Если сервер заведён
				if(started == context::error_t::NONE)
					// Заводим клиента
					started = client.start();
				// Если стороны заведены
				if(started == context::error_t::NONE){
					// Проводим рукопожатие
					converse(client, server);
					// Запоминаем установленность связи
					established = (client.established() && server.established());
					// Если связь не установилась: отказ клиента либо NONE, либо MEMORY
					if(!established)
						// Проверяем отказ клиента
						ASSERT_TRUE((client.error() == context::error_t::NONE) || (client.error() == context::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (client.error());
				}
			}
		}
		// Всякий отказ либо NONE, либо MEMORY
		ASSERT_TRUE((set == context::error_t::NONE) || (set == context::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (set);
		ASSERT_TRUE((started == context::error_t::NONE) || (started == context::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (started);
		// Запоминаем встречу нехватки
		starved = (starved || (set == context::error_t::MEMORY) || (started == context::error_t::MEMORY) || !established);
		// Полный успех
		complete = established;
	}
	// Нехватка памяти встречена и полный успех достигнут
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}


/**
 * Проверка отказа PROFILE: сервер выбрал набор профиля, связи неведомый (приветствие сервера подделано)
 */
TEST(ProfileTest, Alien){
	// Тело приветствия примера
	vector <uint8_t> body;
	// Составляем приветствие
	ASSERT_TRUE(foxhello(body));
	// Запись рукопожатия
	const vector <uint8_t> record = wrapped(body, false, 0x0301);
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок
	ASSERT_EQ(fingerprint::parse(view_t(record.data(), record.size()), source), fingerprint::error_t::NONE);
	// Неведомый набор первым за GREASE
	source.suites.insert(source.suites.begin() + 1, static_cast <protect::suite_t> (0xC0AC));
	/**
	 * Выполняем перебор случаев: издание 1.3 и издание 1.2
	 */
	for(size_t legacy = 0; legacy < 2; legacy++){
		// Связь стороны клиента
		client::context_t client;
		// Имя узла
		client.name("example.com");
		// Профиль
		ASSERT_EQ(client.profile(source), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Профиль сложенного приветствия
		fingerprint::profile_t made;
		// Снимаем приветствие
		ASSERT_TRUE(captured(client, made));
		// Снимаем отправленные байты
		client.consume(client.output().size);
		// Приветствие сервера с неведомым набором
		hello::server_t answer;
		// Издание приветствия
		answer.version = 0x0303;
		// Случайное значение
		::memset(answer.random, 0x55, sizeof(answer.random));
		// Опознаватель связи повторяется
		answer.session = made.session;
		// Неведомый набор
		answer.suite = 0xC0AC;
		// Способ сжатия
		answer.method = 0;
		// Тела расширений
		vector <uint8_t> version, share;
		// Если издание 1.3
		if(legacy == 0){
			// Издание 1.3
			ASSERT_EQ(extension::version(0x0304, version), extension::error_t::NONE);
			// Доля сервера по X25519
			static const uint8_t KEY[32] = {0x09};
			// Составляем долю
			ASSERT_EQ(extension::share(extension::share_t(extension::group_t::X25519, view_t(KEY, 32)), share), extension::error_t::NONE);
			// Добавляем расширения
			answer.extensions.push_back(hello::extension_t(0x002B, view_t(version.data(), version.size())));
			answer.extensions.push_back(hello::extension_t(0x0033, view_t(share.data(), share.size())));
		}
		// Тело приветствия сервера
		vector <uint8_t> reply;
		// Составляем приветствие сервера
		ASSERT_EQ(hello::build(answer, reply), hello::error_t::NONE);
		// Запись с приветствием сервера
		vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> ((reply.size() + 4) >> 8), static_cast <uint8_t> (reply.size() + 4), 0x02, static_cast <uint8_t> (reply.size() >> 16), static_cast <uint8_t> (reply.size() >> 8), static_cast <uint8_t> (reply.size())};
		// Дописываем тело
		wire.insert(wire.end(), reply.begin(), reply.end());
		// Подаём приветствие сервера клиенту
		(void) client.push(view_t(wire.data(), wire.size()));
		// Связь обрывается отказом исполнения профиля
		EXPECT_EQ(client.state(), context::state_t::FAILED) << "издание " << legacy;
		EXPECT_EQ(client.error(), context::error_t::PROFILE) << "издание " << legacy << " отказ " << static_cast <int> (client.error());
	}
	// Тот же подделанный ответ без профиля: обычный отказ SUITE, а не PROFILE
	client::context_t plain;
	// Имя узла
	plain.name("example.com");
	// Заводим клиента
	ASSERT_EQ(plain.start(), context::error_t::NONE);
	// Снимаем отправленные байты
	plain.consume(plain.output().size);
	// Приветствие сервера с неведомым набором
	hello::server_t answer;
	// Издание приветствия
	answer.version = 0x0303;
	// Случайное значение
	::memset(answer.random, 0x55, sizeof(answer.random));
	// Неведомый набор
	answer.suite = 0xC0AC;
	// Тело издания
	vector <uint8_t> version;
	// Издание 1.3
	ASSERT_EQ(extension::version(0x0304, version), extension::error_t::NONE);
	// Добавляем расширение
	answer.extensions.push_back(hello::extension_t(0x002B, view_t(version.data(), version.size())));
	// Тело приветствия сервера
	vector <uint8_t> reply;
	// Составляем приветствие сервера
	ASSERT_EQ(hello::build(answer, reply), hello::error_t::NONE);
	// Запись с приветствием сервера
	vector <uint8_t> wire = {0x16, 0x03, 0x03, static_cast <uint8_t> ((reply.size() + 4) >> 8), static_cast <uint8_t> (reply.size() + 4), 0x02, static_cast <uint8_t> (reply.size() >> 16), static_cast <uint8_t> (reply.size() >> 8), static_cast <uint8_t> (reply.size())};
	// Дописываем тело
	wire.insert(wire.end(), reply.begin(), reply.end());
	// Подаём приветствие сервера клиенту
	(void) plain.push(view_t(wire.data(), wire.size()));
	// Связь обрывается обычным отказом набора
	EXPECT_EQ(plain.state(), context::state_t::FAILED);
	EXPECT_NE(plain.error(), context::error_t::PROFILE);
}
