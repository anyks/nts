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
 * @brief Образец отпечатков приветствия: снимок приветствия обозревателя, отпечатки JA3, JA4 и
 *        PeetPrint, применение снимка клиентом «как есть» и снятие отпечатка сервером
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
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * Путь к набору ключей
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь к файлу
	 * @return     содержимое файла
	 *
	 */
	static vector <uint8_t> slurp(const string & path) noexcept {
		// Открываем файл на чтение
		ifstream file(path, ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое
			result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		// Выводим содержимое
		return result;
	}
	/**
	 * @brief Функция составления приветствия, похожего на приветствие Chrome, когда снимка нет под рукой
	 *
	 * @param result запись рукопожатия с приветствием
	 * @return       результат составления
	 *
	 */
	static bool chromelike(vector <uint8_t> & result) noexcept {
		// Составляемое приветствие
		hello::client_t greeting;
		// Издание приветствия
		greeting.version = 0x0303;
		// Случайное значение и опознаватель связи: у снимка они значения не имеют
		::memset(greeting.random, 0x11, sizeof(greeting.random));
		// Опознаватель связи
		greeting.session.assign(32, 0x22);
		// Наборы в порядке Chrome с GREASE впереди
		greeting.suites = {0x2A2A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035};
		// Способ сжатия
		greeting.methods.push_back(0);
		// Тела расширений
		vector <uint8_t> name, groups, formats, schemes, protocols, versions, modes, share, compress, settings, padding, status, renegotiation, stub;
		// Имя узла
		static const char HOST[] = "example.com";
		// Составляем тела расширений
		bool composed = (extension::name(view_t(reinterpret_cast <const uint8_t *> (HOST), sizeof(HOST) - 1), name) == extension::error_t::NONE);
		// Составляем тело групп обмена
		composed = (composed && (extension::groups(vector <extension::group_t> {static_cast <extension::group_t> (0x2A2A), extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1}, groups) == extension::error_t::NONE));
		// Составляем тело форматов точек
		composed = (composed && (extension::formats(vector <uint8_t> {0x00}, formats) == extension::error_t::NONE));
		// Составляем тело схем подписи
		composed = (composed && (extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA256, extension::scheme_t::RSA_PKCS1_SHA256, extension::scheme_t::ECDSA_SECP384R1_SHA384, extension::scheme_t::RSA_PSS_RSAE_SHA384, extension::scheme_t::RSA_PKCS1_SHA384, extension::scheme_t::RSA_PSS_RSAE_SHA512, extension::scheme_t::RSA_PKCS1_SHA512}, schemes) == extension::error_t::NONE));
		// Составляем тело протоколов прикладного уровня
		composed = (composed && (extension::protocols(vector <string> {"h2", "http/1.1"}, protocols) == extension::error_t::NONE));
		// Составляем тело протоколов настроек
		composed = (composed && (extension::protocols(vector <string> {"h2"}, settings) == extension::error_t::NONE));
		// Составляем тело версий
		composed = (composed && (extension::versions(vector <uint16_t> {0x2A2A, 0x0304, 0x0303}, versions) == extension::error_t::NONE));
		// Составляем тело режимов PSK
		composed = (composed && (extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, modes) == extension::error_t::NONE));
		// Составляем тело алгоритмов сжатия
		composed = (composed && (extension::algorithms(vector <uint16_t> {0x0002}, compress) == extension::error_t::NONE));
		// Ключ доли и заглушки
		static const uint8_t KEY[32] = {0x01};
		// Заглушка доли ключа
		static const uint8_t STUB[1] = {0x00};
		// Составляем доли ключа
		composed = (composed && (extension::shares(vector <extension::share_t> {extension::share_t(static_cast <extension::group_t> (0x2A2A), view_t(STUB, 1)), extension::share_t(extension::group_t::X25519, view_t(KEY, 32))}, share) == extension::error_t::NONE));
		// Если тела составить не удалось
		if(!composed)
			// Выводим отрицательный результат - тела составить не удалось
			return false;
		// Запрос состояния сертификата
		status = {0x01, 0x00, 0x00, 0x00, 0x00};
		// Безопасное пересогласование
		renegotiation = {0x00};
		// Заполнение
		padding.assign(180, 0x00);
		// Заглушка второго GREASE
		stub = {0x00};
		// Расширения в порядке Chrome
		greeting.extensions.push_back(hello::extension_t(0x2A2A, view_t(nullptr, 0)));
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
		greeting.extensions.push_back(hello::extension_t(0x3A3A, view_t(stub.data(), stub.size())));
		greeting.extensions.push_back(hello::extension_t(0x0015, view_t(padding.data(), padding.size())));
		// Тело приветствия
		vector <uint8_t> body;
		// Если приветствие составить не удалось
		if(hello::build(greeting, body) != hello::error_t::NONE)
			// Выводим отрицательный результат - приветствие не составлено
			return false;
		// Длина сообщения с обвязкой
		const size_t length = (body.size() + 4);
		// Составляем запись рукопожатия
		result = {0x16, 0x03, 0x01, static_cast <uint8_t> (length >> 8), static_cast <uint8_t> (length), 0x01, static_cast <uint8_t> (body.size() >> 16), static_cast <uint8_t> (body.size() >> 8), static_cast <uint8_t> (body.size())};
		// Дописываем тело
		result.insert(result.end(), body.begin(), body.end());
		// Сообщаем об успешном составлении записи
		return true;
	}
	/**
	 * @brief Функция печати отпечатков профиля
	 *
	 * @param title   заголовок
	 * @param profile профиль
	 * @return        результат печати
	 *
	 */
	static bool report(const char * title, const fingerprint::profile_t & profile) noexcept {
		// Отпечатки профиля
		fingerprint::imprint_t imprint;
		// Если отпечатки вычислить не удалось
		if(fingerprint::imprint(profile, imprint) != fingerprint::error_t::NONE)
			// Выводим отрицательный результат - отпечатки не вычислены
			return false;
		// Печатаем отпечатки
		cout << title << endl;
		// Печатаем JA3
		cout << "  JA3:       " << imprint.ja3hash << endl;
		// Печатаем JA4
		cout << "  JA4:       " << imprint.ja4 << endl;
		// Печатаем JA4_r
		cout << "  JA4_r:     " << imprint.ja4r << endl;
		// Печатаем PeetPrint
		cout << "  PeetPrint: " << imprint.peethash << endl;
		// Печатаем random
		cout << "  random:    " << imprint.random.substr(0, 16) << "…" << endl;
		// Печатаем сходство с обозревателем
		cout << "  browser:   " << (fingerprint::browser(imprint) ? "похоже на обозреватель" : "не похоже на обозреватель") << endl;
		// Сообщаем об успешном отчёте
		return true;
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
		// Байты клиента
		view_t data = client.output();
		// Если клиенту есть что отправить
		if(data.size > 0){
			// Переносим байты
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем байты с накопителя
			client.consume(buffer.size());
			// Подаём байты серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем передачу
			moved = true;
		}
		// Байты сервера
		data = server.output();
		// Если серверу есть что отправить
		if(data.size > 0){
			// Переносим байты
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем байты с накопителя
			server.consume(buffer.size());
			// Подаём байты клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем передачу
			moved = true;
		}
		// Выводим признак передачи
		return moved;
	}
}

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы: путь к снимку приветствия (запись рукопожатия либо снимок `fingerprint::dump`)
 * @return     код завершения
 *
 */
int main(const int argc, const char * argv[]){
	// Байты снимка приветствия
	vector <uint8_t> capture;
	// Если путь к снимку задан
	if(argc > 1)
		// Читаем снимок из файла
		capture = slurp(argv[1]);
	// Если снимка нет: складываем приветствие, похожее на приветствие Chrome
	if(capture.empty() && !chromelike(capture)){
		// Сообщаем об отказе
		cerr << "Приветствие составить не удалось" << endl;
		// Выходим с отказом
		return 1;
	}
	// Профиль снимка
	fingerprint::profile_t source;
	// Разбираем снимок: сперва как запись рукопожатия, затем как снимок профиля
	if((fingerprint::parse(view_t(capture.data(), capture.size()), source) != fingerprint::error_t::NONE) && (fingerprint::load(view_t(capture.data(), capture.size()), source) != fingerprint::error_t::NONE)){
		// Сообщаем об отказе
		cerr << "Снимок не разобран" << endl;
		// Выходим с отказом
		return 1;
	}
	// Печать профиля
	string text;
	// Печатаем профиль
	if(fingerprint::print(source, text) == fingerprint::error_t::NONE)
		// Выводим печать
		cout << text << endl;
	// Печатаем отпечатки снимка
	if(!report("Снимок:", source))
		// Выходим с отказом
		return 1;
	// Переносимый снимок профиля
	vector <uint8_t> snapshot;
	// Составляем снимок
	if(fingerprint::dump(source, snapshot) == fingerprint::error_t::NONE)
		// Печатаем размер снимка
		cout << "Снимок профиля: " << snapshot.size() << " байтов" << endl;
	// Подлинность сервера
	context::credential_t credential;
	// Читаем ключ сервера
	credential.secret = slurp(string(CORPUS) + "/ec256.pem");
	// Сертификат сервера
	const vector <uint8_t> certificate = slurp(string(CORPUS) + "/ec256.crt");
	// Если цепочку разобрать не удалось
	if(credential.secret.empty() || (pem::certificates(string(certificate.begin(), certificate.end()), credential.chain) != pem::error_t::NONE)){
		// Сообщаем об отказе
		cerr << "Подлинность сервера не прочитана" << endl;
		// Выходим с отказом
		return 1;
	}
	// Связи сторон
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Имя узла у клиента: профиль несёт имя, а само имя своё
	client.name("example.com");
	// Профиль ставится до заведения связи
	if(client.profile(source) != context::error_t::NONE){
		// Сообщаем об отказе
		cerr << "Профиль не принят: нет ни одного ведомого набора либо группы" << endl;
		// Выходим с отказом
		return 1;
	}
	// Подлинность сервера
	server.credential(credential);
	// Прикладные протоколы сервера
	server.protocols(vector <string> {"h2"});
	// Заводим стороны
	if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
		// Сообщаем об отказе
		cerr << "Стороны не заведены" << endl;
		// Выходим с отказом
		return 1;
	}
	// Профиль сложенного приветствия
	fingerprint::profile_t made;
	// Снимаем сложенное приветствие до отправки
	if(fingerprint::parse(client.output(), made) == fingerprint::error_t::NONE)
		// Печатаем отпечатки сложенного приветствия
		report("Приветствие, сложенное по профилю:", made);
	/**
	 * Выполняем рукопожатие
	 */
	for(size_t i = 0; (i < 16) && pump(client, server); i++)
		// Продолжаем передачу
		continue;
	// Если связь не установилась
	if(!client.established() || !server.established()){
		// Сообщаем об отказе
		cerr << "Связь не установилась: отказ клиента " << static_cast <int> (client.error()) << ", сервера " << static_cast <int> (server.error()) << endl;
		// Выходим с отказом
		return 1;
	}
	// Профиль, увиденный сервером
	fingerprint::profile_t seen;
	// Снимаем профиль на сервере
	if(server.profile(seen) == context::error_t::NONE)
		// Печатаем отпечатки, увиденные сервером
		report("Приветствие, принятое сервером:", seen);
	// Печатаем итог связи
	cout << "Связь установлена: набор 0x" << hex << static_cast <int> (client.suite()) << dec << ", протокол " << client.protocol() << endl;
	// Выходим успешно
	return 0;
}
