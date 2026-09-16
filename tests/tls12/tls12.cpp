/**
 * @file tls12.cpp
 * @date 2026-09-05
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
 * @brief Исходный файл проверок рукопожатия TLS 1.2 (RFC 5246): порождающая функция по
 *        известным векторам, петлевое рукопожатие по шести наборам ECDHE и трём группам,
 *        взаимная подлинность, расширенный главный секрет, заслон понижения издания,
 *        пересогласование, пределы изданий, порча записи, издание заголовка записи,
 *        расхождение переписки, явная часть одноразового значения и повтор записи,
 *        исчерпание записей на ключе, предел длины записи, подделанные сообщения
 *        рукопожатия, обмен с настоящим openssl, нехватка памяти и векторы рукопожатий,
 *        снятые с шести изданий openssl (сервер, клиент, расшифровка завершений)
 *
 * @note Эталоном служат векторы порождающей функции TLS 1.2 из обсуждения рабочей группы
 *       TLS IETF (2008) и системный openssl; ключи и сертификаты берутся из tests/corpus
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <protect/protect.hpp>
#include <extension/extension.hpp>
#include <digest/hmac.hpp>
#include <digest/hash.hpp>
#include <x509/x509.hpp>
#include <x509/signature.hpp>
#include <agreement/x25519.hpp>
#include <sign/rsa.hpp>
#include <field/field.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

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
	 * @brief Метод разбора области байтов из шестнадцатеричной записи
	 *
	 * @param text шестнадцатеричная запись области байтов
	 *
	 * @return     разобранная область байтов
	 *
	 */
	vector <uint8_t> decode(const char * text) noexcept {
		// Разобранная область байтов
		vector <uint8_t> result;
		/**
		 * Выполняем перебор пар символов записи
		 */
		for(size_t i = 0; text[i] != '\0' && text[i + 1] != '\0'; i += 2)
			// Добавляем очередной разобранный байт
			result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
		// Выводим разобранную область байтов
		return result;
	}
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
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
	 * @param name   имя ключа набора: rsa2048, ec256, ec384 либо ed25519
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool identity(const char * name, context::credential_t & result) noexcept {
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
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
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
	 * @brief Метод передачи байтов от клиента серверу без ответа
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты передавались
	 *
	 */
	bool deliver(client::context_t & client, server::context_t & server) noexcept {
		// Получаем байты, отправляемые клиентом
		const view_t data = client.output();
		// Если клиенту нечего отправить
		if(data.size == 0)
			// Выводим отсутствие передачи
			return false;
		// Выполняем перенос отправляемых байтов
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(buffer.size());
		// Выполняем подачу отправленных байтов серверу
		server.push(view_t(buffer.data(), buffer.size()));
		// Выводим признак передачи
		return true;
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
			// Продолжаем передачу байтов между сторонами связи
			continue;
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
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос прикладного протокола изданием TLS 1.2 по набору ECDHE";
		// Если отправить прикладные данные клиентом не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если получить принятые сервером прикладные данные не удалось
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ прикладного протокола изданием TLS 1.2 по набору ECDHE";
		// Если отправить прикладные данные сервером не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Если получить принятые клиентом прикладные данные не удалось
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Выводим отказ обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Описание набора шифрования издания TLS 1.2
	 *
	 */
	static const struct Suite {
		// Набор шифрования
		protect::suite_t suite;
		// Имя набора у openssl
		const char * title;
		// Имя ключа набора, отвечающего набору
		const char * key;
	} SUITES[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256,       "ECDHE-ECDSA-AES128-GCM-SHA256",  "ec256"},
		{protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384,       "ECDHE-ECDSA-AES256-GCM-SHA384",  "ec384"},
		{protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20-POLY1305",  "ec256"},
		{protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256,         "ECDHE-RSA-AES128-GCM-SHA256",    "rsa2048"},
		{protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384,         "ECDHE-RSA-AES256-GCM-SHA384",    "rsa2048"},
		{protect::suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256,   "ECDHE-RSA-CHACHA20-POLY1305",    "rsa2048"}
	};
	/**
	 * Группы обмена издания TLS 1.2
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1};
	/**
	 * @brief Метод настройки сторон под набор, группу и подлинность
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования
	 * @param group      группа обмена
	 * @param credential подлинность сторон
	 * @param mutual     запрашивается ли подлинность клиента
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual) noexcept {
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {suite});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {suite});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {group});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {group});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Если запрашивается подлинность клиента
		if(mutual){
			// Запрашиваем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
	}
	/**
	 * @brief Метод составления приветствия клиента издания TLS 1.2 руками
	 *
	 * @param master       объявляется ли расширенный главный секрет
	 * @param suite        предлагаемый набор шифрования
	 * @param result       накопитель, в который складывается запись приветствия
	 * @param renegotiated объявляется ли непустое расширение renegotiation_info
	 * @param group        предлагаемая группа обмена
	 *
	 * @return             признак успешности составления приветствия
	 *
	 */
	bool greeting(const bool master, const protect::suite_t suite, vector <uint8_t> & result, const bool renegotiated, const extension::group_t group) noexcept {
		// Составляемое приветствие клиента
		hello::client_t hello;
		// Издание TLS 1.2 заголовком, без перечня изданий - как у чужого клиента
		hello.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения
		 */
		for(size_t i = 0; i < sizeof(hello.random); i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (i);
		// Набор шифрования
		hello.suites = {static_cast <uint16_t> (suite)};
		// Способ сжатия
		hello.methods = {0x00};
		// Тела расширений
		vector <uint8_t> groups, schemes;
		// Если группы либо схемы составить не удалось
		if((extension::groups(vector <extension::group_t> {group}, groups) != extension::error_t::NONE) || (extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA256}, schemes) != extension::error_t::NONE))
			// Выводим отказ
			return false;
		// Добавляем группы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		// Добавляем схемы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Если расширенный главный секрет объявляется
		if(master)
			// Добавляем пустое расширение расширенного главного секрета
			hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Тело непустого расширения renegotiation_info: перечень из одного байта
		static const uint8_t renegotiation[2] = {0x01, 0xAA};
		// Если непустое расширение renegotiation_info объявляется
		if(renegotiated)
			// Добавляем расширение, помнящее связь, которой сервер не вёл
			hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::RENEGOTIATION), view_t(renegotiation, sizeof(renegotiation))));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело приветствия составить не удалось
		if(hello::build(hello, body) != hello::error_t::NONE)
			// Выводим отказ
			return false;
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ
			return false;
		// Нарезчик записей
		record::writer_t records;
		// Если запись составить не удалось
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Получаем запись
		const view_t data = records.data();
		// Переносим запись
		result.assign(data.data, data.data + data.size);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод нарезки потока байтов на записи протокола по их заголовкам
	 *
	 * @param data   нарезаемый поток байтов
	 * @param result перечень, в который складываются записи вместе с заголовками
	 *
	 * @return       признак того, что поток нарезан целиком хоть на одну запись
	 *
	 */
	bool slice(const view_t & data, vector <vector <uint8_t>> & result) noexcept {
		// Смещение очередной записи в потоке
		size_t offset = 0;
		/**
		 * Выполняем перебор записей потока
		 */
		while(offset < data.size){
			// Заголовок очередной записи
			record::header_t header;
			// Если заголовок записи разобрать не удалось
			if(record::parse(view_t(data.data + offset, data.size - offset), header) != record::error_t::NONE)
				// Выводим отказ нарезки
				return false;
			// Длина записи вместе с заголовком
			const size_t total = (record::RECORD_HEADER + header.size);
			// Если запись оборвана
			if((offset + total) > data.size)
				// Выводим отказ нарезки
				return false;
			// Складываем запись в перечень
			result.push_back(vector <uint8_t> (data.data + offset, data.data + offset + total));
			// Переходим к следующей записи
			offset += total;
		}
		// Выводим признак того, что записи нарезаны
		return !result.empty();
	}
	/**
	 * @brief Метод составления открытой записи с сообщением рукопожатия
	 *
	 * @param type   вид сообщения рукопожатия
	 * @param body   тело сообщения рукопожатия
	 * @param result накопитель, в который складывается запись
	 *
	 * @return       признак успешности составления записи
	 *
	 */
	bool framed(const handshake::type_t type, const view_t & body, vector <uint8_t> & result) noexcept {
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение составить не удалось
		if(writer.push(type, body) != handshake::error_t::NONE)
			// Выводим отказ
			return false;
		// Нарезчик записей
		record::writer_t records;
		// Если запись составить не удалось
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Получаем запись
		const view_t data = records.data();
		// Переносим запись
		result.assign(data.data, data.data + data.size);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод подачи перечня записей связи одним потоком
	 *
	 * @param pieces перечень подаваемых записей
	 * @param result накопитель, в который складывается поток
	 *
	 */
	void join(const vector <vector <uint8_t>> & pieces, vector <uint8_t> & result) noexcept {
		// Сбрасываем накопитель
		result.clear();
		/**
		 * Выполняем перебор записей перечня
		 */
		for(size_t i = 0; i < pieces.size(); i++)
			// Дописываем очередную запись в поток
			result.insert(result.end(), pieces[i].begin(), pieces[i].end());
	}
	/**
	 * @brief Метод получения залпа сервера в ответ на приветствие клиента записями
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param result перечень, в который складываются записи залпа
	 *
	 * @return       признак того, что залп получен и нарезан
	 *
	 */
	bool volley(client::context_t & client, server::context_t & server, vector <vector <uint8_t>> & result) noexcept {
		// Если приветствие клиента серверу не передалось
		if(!deliver(client, server))
			// Выводим отказ
			return false;
		// Залп сервера
		const view_t flight = server.output();
		// Нарезаем залп на записи
		const bool sliced = slice(flight, result);
		// Снимаем залп с накопителя сервера
		server.consume(flight.size);
		// Выводим итог нарезки
		return sliced;
	}
	/**
	 * @brief Метод правки длины записи и длины сообщения рукопожатия в ней на заданное число байтов
	 *
	 * @param piece запись, в которой одно сообщение рукопожатия, правимая на месте
	 * @param delta число байтов, на которое выросли запись и сообщение
	 *
	 */
	void lengthen(vector <uint8_t> & piece, const size_t delta) noexcept {
		// Длина записи
		const size_t record = (static_cast <size_t> ((piece[3] << 8) | piece[4]) + delta);
		// Длина сообщения рукопожатия
		const size_t message = (static_cast <size_t> ((piece[6] << 16) | (piece[7] << 8) | piece[8]) + delta);
		// Записываем длину записи
		piece[3] = static_cast <uint8_t> ((record >> 8) & 0xFF);
		// Младший байт длины записи
		piece[4] = static_cast <uint8_t> (record & 0xFF);
		// Записываем длину сообщения
		piece[6] = static_cast <uint8_t> ((message >> 16) & 0xFF);
		// Средний байт длины сообщения
		piece[7] = static_cast <uint8_t> ((message >> 8) & 0xFF);
		// Младший байт длины сообщения
		piece[8] = static_cast <uint8_t> (message & 0xFF);
	}
	/**
	 * @brief Метод чтения файла целиком по пути
	 *
	 * @param path путь к файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> slurp(const std::string & path) noexcept {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое файла
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
		return result;
	}
	/**
	 * Издания openssl, с которых сняты векторы рукопожатий
	 */
	static const char * EDITIONS[] = {"3.0.15", "3.0.20", "3.3.1", "3.4.0", "3.5.0", "3.5.7"};
	/**
	 * Сценарий снятого вектора рукопожатия
	 */
	static const struct Scenario {
		// Имя каталога сценария
		const char * name;
		// Ожидаемый выбранный набор шифрования
		uint16_t suite;
		// Признак взаимной подлинности
		bool mutual;
		// Признак ожидаемого расширенного главного секрета
		bool master;
		// Признак порядка сервера при выборе набора
		bool preference;
	} SCENARIOS[] = {
		{"ecdsa-aes128-gcm",  0xC02B, false, true,  true},
		{"ecdsa-aes256-gcm",  0xC02C, false, true,  true},
		{"ecdsa-chacha20",    0xCCA9, false, true,  true},
		{"rsa-aes128-gcm",    0xC02F, false, true,  true},
		{"rsa-aes256-gcm",    0xC030, false, true,  true},
		{"rsa-chacha20",      0xCCA8, false, true,  true},
		{"mutual",            0xC02B, true,  true,  true},
		{"no-ems",            0xC02B, false, false, true},
		{"no-renegotiation",  0xC02B, false, true,  true},
		{"preference-server", 0xC02C, false, true,  true},
		{"preference-client", 0xC02B, false, true,  false},
		{"cbc-sha256",        0xC023, false, true,  true}
	};
	/**
	 * @brief Сведения о векторе из его описания README.md
	 *
	 */
	typedef struct Brief {
		// Выбранный набор по описанию
		uint16_t suite;
		// Признак расширенного главного секрета по описанию
		bool master;
		// Группа обмена ключами по описанию
		extension::group_t group;
		// Имя ключа набора: ec256 либо rsa2048
		std::string key;
		/**
		 * Конструктор
		 */
		Brief() noexcept : suite(0), master(false), group(extension::group_t::NONE) {}
	} brief_t;
	/**
	 * @brief Метод получения кода набора по имени openssl
	 *
	 * @param title имя набора в записи openssl
	 *
	 * @return      код набора либо ноль
	 *
	 */
	uint16_t coded(const std::string & title) noexcept {
		/**
		 * Выполняем перебор наборов первого круга
		 */
		for(size_t i = 0; i < (sizeof(SUITES) / sizeof(SUITES[0])); i++){
			// Если имя совпало
			if(title == SUITES[i].title)
				// Выводим код набора
				return static_cast <uint16_t> (SUITES[i].suite);
		}
		// Набор CBC у связи не поддержан, но описанием ожидается
		if(title == "ECDHE-ECDSA-AES128-SHA256")
			// Выводим код набора CBC
			return 0xC023;
		// Набор неизвестен
		return 0;
	}
	/**
	 * @brief Метод проверки начала строки
	 *
	 * @param line   проверяемая строка
	 * @param prefix ожидаемое начало
	 *
	 * @return       признак того, что строка начинается с ожидаемого
	 *
	 */
	bool starts(const std::string & line, const char * prefix) noexcept {
		// Выводим итог сличения начала строки байт в байт
		return (line.compare(0, ::strlen(prefix), prefix) == 0);
	}
	/**
	 * @brief Метод разбора описания вектора README.md
	 *
	 * @param path   путь к каталогу вектора
	 * @param result сведения о векторе
	 *
	 * @return       признак успешности разбора
	 *
	 */
	bool describe(const std::string & path, brief_t & result) noexcept {
		// Читаем описание вектора
		const vector <uint8_t> text = slurp(path + "/README.md");
		// Если описание пусто
		if(text.empty())
			// Выводим отказ
			return false;
		// Описание в виде строки
		const std::string readme(text.begin(), text.end());
		// Начало строки описания
		size_t offset = 0;
		/**
		 * Выполняем перебор строк описания
		 */
		while(offset < readme.size()){
			// Ищем конец строки
			size_t end = readme.find('\n', offset);
			// Если конца строки нет
			if(end == std::string::npos)
				// Строка идёт до конца описания
				end = readme.size();
			// Строка описания
			const std::string line = readme.substr(offset, end - offset);
			// Переходим к следующей строке
			offset = (end + 1);
			// Если строка несёт набор
			if(starts(line, "Набор: ") || starts(line, "Выбрано на деле: "))
				// Запоминаем код набора по имени
				result.suite = coded(line.substr(line.find(": ") + 2));
			// Если строка несёт сертификат
			else if(starts(line, "Сертификат: ")){
				// Имя файла сертификата
				const std::string name = line.substr(line.find(": ") + 2);
				// Запоминаем имя ключа без расширения
				result.key = name.substr(0, name.find('.'));
			// Если строка несёт признак расширенного главного секрета
			} else if(starts(line, "EMS в обмене: "))
				// Запоминаем признак
				result.master = (line.find("да") != std::string::npos);
			// Если строка несёт обмен ключами
			else if((line.find("Обмен ключами:") != std::string::npos) || (line.find("(обмен") != std::string::npos)){
				// Если обмен шёл по X25519
				if(line.find("X25519") != std::string::npos)
					// Запоминаем группу
					result.group = extension::group_t::X25519;
				// Если обмен шёл по P-256
				else if(line.find("prime256v1") != std::string::npos)
					// Запоминаем группу
					result.group = extension::group_t::SECP256R1;
				// Если обмен шёл по P-384
				else if(line.find("secp384r1") != std::string::npos)
					// Запоминаем группу
					result.group = extension::group_t::SECP384R1;
			}
		}
		// Выводим полноту описания
		return ((result.suite != 0) && !result.key.empty() && (result.group != extension::group_t::NONE));
	}
	/**
	 * @brief Поток одной стороны, снятый с провода
	 *
	 */
	typedef struct Stream {
		// Открытые сообщения рукопожатия целиком, с заголовками
		vector <vector <uint8_t>> messages;
		// Заголовок первой защищённой записи за ChangeCipherSpec
		record::header_t header;
		// Содержимое первой защищённой записи
		vector <uint8_t> sealed;
		// Признак встреченного ChangeCipherSpec
		bool changed;
		/**
		 * Конструктор
		 */
		Stream() noexcept : changed(false) {}
	} stream_t;
	/**
	 * @brief Метод разбора потока по проводу на сообщения и защищённую запись
	 *
	 * @param wire   поток записей по проводу
	 * @param result разобранный поток
	 *
	 * @return       признак успешности разбора
	 *
	 */
	bool unwind(const vector <uint8_t> & wire, stream_t & result, const bool strict) noexcept {
		// Сборщик записей
		record::reader_t records;
		// Если поток в сборщик не лёг
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Сборщик сообщений рукопожатия
		handshake::reader_t messages;
		// Заголовок записи
		record::header_t header;
		// Содержимое записи
		view_t payload;
		/**
		 * Выполняем перебор записей потока
		 */
		while(records.next(header, payload) == record::error_t::NONE){
			// Если это смена набора шифрования
			if(header.type == record::type_t::CHANGE){
				// Запоминаем смену
				result.changed = true;
				// Переходим к следующей записи
				continue;
			}
			// Если это не запись рукопожатия
			if(header.type != record::type_t::HANDSHAKE){
				// За защищённым завершением идёт лишь извещение закрытия; без строгости извещение кончает разбор и до смены набора
				if(result.changed || !strict)
					// Разбор окончен
					break;
				// До смены набора иных записей быть не должно
				return false;
			}
			// Если набор уже сменён
			if(result.changed){
				// Запоминаем заголовок защищённой записи
				result.header = header;
				// Запоминаем содержимое защищённой записи
				result.sealed.assign(payload.data, payload.data + payload.size);
				// Разбор окончен
				break;
			}
			// Если содержимое в сборщик сообщений не легло
			if(messages.push(payload) != handshake::error_t::NONE)
				// Выводим отказ
				return false;
			// Заголовок сообщения
			handshake::header_t head;
			// Тело сообщения
			view_t body;
			/**
			 * Выполняем перебор собранных сообщений
			 */
			while(messages.next(head, body) == handshake::error_t::NONE){
				// Сообщение целиком
				vector <uint8_t> message(handshake::HANDSHAKE_HEADER + body.size, 0);
				// Если заголовок не сложился
				if(handshake::build(head, message.data()) != handshake::error_t::NONE)
					// Выводим отказ
					return false;
				// Переносим тело сообщения
				::memcpy(message.data() + handshake::HANDSHAKE_HEADER, body.data, body.size);
				// Запоминаем сообщение
				result.messages.push_back(message);
			}
		}
		// Поток обязан нести открытые сообщения, смену набора и защищённое завершение; без строгости - хоть открытые сообщения
		return (strict ? (result.changed && !result.sealed.empty() && !result.messages.empty()) : !result.messages.empty());
	}
	/**
	 * @brief Метод получения вида сообщения рукопожатия
	 *
	 * @param message сообщение целиком
	 *
	 * @return        вид сообщения либо NONE
	 *
	 */
	handshake::type_t kind(const vector <uint8_t> & message) noexcept {
		// Заголовок сообщения
		handshake::header_t header;
		// Если заголовок разобран
		if(handshake::parse(view_t(message.data(), message.size()), header) == handshake::error_t::NONE)
			// Выводим вид сообщения
			return header.type;
		// Вид не установлен
		return handshake::type_t::NONE;
	}
	/**
	 * @brief Метод получения тела сообщения рукопожатия
	 *
	 * @param message сообщение целиком
	 *
	 * @return        тело сообщения без заголовка
	 *
	 */
	view_t inner(const vector <uint8_t> & message) noexcept {
		// Если сообщение короче заголовка
		if(message.size() < handshake::HANDSHAKE_HEADER)
			// Выводим пустое тело
			return view_t(nullptr, 0);
		// Выводим тело сообщения
		return view_t(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER);
	}
	/**
	 * @brief Метод розыска сообщения заданного вида в перечне
	 *
	 * @param messages перечень сообщений
	 * @param type     искомый вид
	 *
	 * @return         указатель на сообщение либо nullptr
	 *
	 */
	const vector <uint8_t> * seek(const vector <vector <uint8_t>> & messages, const handshake::type_t type) noexcept {
		/**
		 * Выполняем перебор сообщений
		 */
		for(size_t i = 0; i < messages.size(); i++){
			// Если вид совпал
			if(kind(messages[i]) == type)
				// Выводим сообщение
				return &messages[i];
		}
		// Сообщения нет
		return nullptr;
	}
	/**
	 * @brief Обмен ключами сервера ServerKeyExchange в разобранном виде
	 *
	 */
	typedef struct Exchange {
		// Группа обмена ключами
		extension::group_t group;
		// Схема подписи
		uint16_t scheme;
		// Параметры ECDHE как они подписаны
		view_t parameters;
		// Подпись параметров
		view_t signature;
		/**
		 * Конструктор
		 */
		Exchange() noexcept : group(extension::group_t::NONE), scheme(0) {}
	} exchange_t;
	/**
	 * @brief Метод разбора тела ServerKeyExchange по разделу 5.4 RFC 8422
	 *
	 * @param data   тело сообщения
	 * @param result разобранный обмен
	 *
	 * @return       признак успешности разбора
	 *
	 */
	bool dissect(const view_t & data, exchange_t & result) noexcept {
		// Тело обязано вместить вид кривой, её номер и длину точки
		if((data.data == nullptr) || (data.size < 4) || (data.data[0] != 0x03))
			// Выводим отказ
			return false;
		// Длина точки
		const size_t point = data.data[3];
		// Если тело не вмещает точку, схему и длину подписи
		if(data.size < (4 + point + 4))
			// Выводим отказ
			return false;
		// Запоминаем группу
		result.group = static_cast <extension::group_t> ((static_cast <uint16_t> (data.data[1]) << 8) | data.data[2]);
		// Запоминаем подписанные параметры
		result.parameters = view_t(data.data, 4 + point);
		// Смещение схемы подписи
		const size_t offset = (4 + point);
		// Запоминаем схему подписи
		result.scheme = ((static_cast <uint16_t> (data.data[offset]) << 8) | data.data[offset + 1]);
		// Длина подписи
		const size_t length = ((static_cast <size_t> (data.data[offset + 2]) << 8) | data.data[offset + 3]);
		// Если подпись за тело выходит либо за ней идут лишние байты
		if((offset + 4 + length) != data.size)
			// Выводим отказ
			return false;
		// Запоминаем подпись
		result.signature = view_t(data.data + offset + 4, length);
		// Выводим успех
		return true;
	}
	/**
	 * @brief Метод проверки подписи схемой TLS 1.2 ключом сертификата
	 *
	 * @param key       открытый ключ сертификата
	 * @param scheme    схема подписи из сообщения
	 * @param content   подписанное содержимое
	 * @param signature подпись
	 *
	 * @return          признак того, что подпись сошлась
	 *
	 */
	bool attested(const x509::key_t & key, const uint16_t scheme, const view_t & content, const view_t & signature) noexcept {
		// Если это подпись PKCS #1 v1.5 (младший байт 0x01)
		if((scheme & 0xFF) == 0x01){
			// Опознаватель алгоритма sha*WithRSAEncryption
			const char * algorithm = ((scheme == 0x0401) ? "1.2.840.113549.1.1.11" : ((scheme == 0x0501) ? "1.2.840.113549.1.1.12" : ((scheme == 0x0601) ? "1.2.840.113549.1.1.13" : nullptr)));
			// Если схема неизвестна
			if(algorithm == nullptr)
				// Выводим отказ
				return false;
			// Выводим итог проверки тем же путём, что и у подписи сертификата
			return (x509::verify(content, signature, algorithm, key) == x509::error_t::NONE);
		}
		// Хеш схемы
		const digest::hash_t algorithm = extension::hash(static_cast <extension::scheme_t> (scheme));
		// Если схема связи неизвестна
		if(algorithm == digest::hash_t::NONE)
			// Выводим отказ
			return false;
		// Выводим итог проверки: DER у ECDSA, RSASSA-PSS с солью длиною в хеш у RSA
		return (x509::check(key, algorithm, content, signature) == x509::error_t::NONE);
	}
	/**
	 * @brief Метод извлечения первого сертификата DER из сообщения Certificate
	 *
	 * @param data тело сообщения Certificate
	 *
	 * @return     первый сертификат цепочки либо пустая область
	 *
	 */
	view_t leaf(const view_t & data) noexcept {
		// Тело обязано вместить длину цепочки и длину сертификата
		if((data.data == nullptr) || (data.size < 6))
			// Выводим пустую область
			return view_t(nullptr, 0);
		// Длина цепочки
		const size_t chain = ((static_cast <size_t> (data.data[0]) << 16) | (static_cast <size_t> (data.data[1]) << 8) | data.data[2]);
		// Длина первого сертификата
		const size_t length = ((static_cast <size_t> (data.data[3]) << 16) | (static_cast <size_t> (data.data[4]) << 8) | data.data[5]);
		// Если длины за тело выходят
		if(((chain + 3) != data.size) || ((length + 3) > chain))
			// Выводим пустую область
			return view_t(nullptr, 0);
		// Выводим первый сертификат
		return view_t(data.data + 6, length);
	}
	/**
	 * @brief Метод разбора ключевого файла CLIENT_RANDOM
	 *
	 * @param path   путь к каталогу вектора
	 * @param random случайное значение клиента (32 байта)
	 * @param master главный секрет (48 байтов)
	 *
	 * @return       признак успешности разбора
	 *
	 */
	bool keylog(const std::string & path, vector <uint8_t> & random, vector <uint8_t> & master) noexcept {
		// Открываем ключевой файл
		std::ifstream file(path + "/keylog.txt");
		// Метка, случайное значение и секрет в шестнадцатеричной записи
		std::string label, hexRandom, hexMaster;
		/**
		 * Выполняем перебор строк ключевого файла до метки CLIENT_RANDOM
		 */
		while(file >> label){
			// Если это искомая метка
			if(label == "CLIENT_RANDOM"){
				// Читаем случайное значение и секрет
				file >> hexRandom >> hexMaster;
				// Разбираем случайное значение
				random = decode(hexRandom.c_str());
				// Разбираем главный секрет
				master = decode(hexMaster.c_str());
				// Выводим полноту разбора
				return ((random.size() == 32) && (master.size() == 48));
			}
		}
		// Метки в файле нет
		return false;
	}
	/**
	 * @brief Метод вычисления verify_data завершения по разделу 7.4.9 RFC 5246
	 *
	 * @param suite      набор шифрования
	 * @param master     главный секрет
	 * @param label      метка стороны: client finished либо server finished
	 * @param transcript сообщения рукопожатия по порядку
	 * @param result     вычисленный verify_data (12 байтов)
	 *
	 * @return           признак успешности вычисления
	 *
	 */
	bool completion(const protect::suite_t suite, const vector <uint8_t> & master, const char * label, const vector <vector <uint8_t>> & transcript, uint8_t * result) noexcept {
		// Хеш набора
		const digest::hash_t algorithm = protect::hash(suite);
		// Хешер переписки
		digest::hasher_t hasher(algorithm);
		/**
		 * Выполняем перебор сообщений переписки
		 */
		for(size_t i = 0; i < transcript.size(); i++)
			// Добавляем сообщение в хеш
			hasher.update(view_t(transcript[i].data(), transcript[i].size()));
		// Хеш переписки
		uint8_t digest[64];
		// Если хеш не сложился
		if(!hasher.finish(digest, digest::length(algorithm)))
			// Выводим отказ
			return false;
		// Выводим итог порождающей функции
		return digest::prf(algorithm, view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(digest, digest::length(algorithm)), result, 12);
	}
	/**
	 * @brief Метод выведения ключевого материала стороны по разделу 6.3 RFC 5246
	 *
	 * @param suite      набор шифрования
	 * @param master     главный секрет
	 * @param client     случайное значение клиента
	 * @param server     случайное значение сервера
	 * @param protection защита, заводимая ключом стороны
	 * @param own        признак ключа клиента (иначе - ключа сервера)
	 *
	 * @return           признак успешности заведения защиты
	 *
	 */
	bool keyed(const protect::suite_t suite, const vector <uint8_t> & master, const vector <uint8_t> & client, const vector <uint8_t> & server, protect::protection_t & protection, const bool own, const bool etm) noexcept {
		// Длина ключа набора
		const size_t width = protect::key(suite);
		// Длина неявной части вектора набора: ноль у наборов CBC
		const size_t size = protect::block(suite);
		// Длина ключа имитовставки: ноль у наборов AEAD
		const size_t stamp = digest::length(protect::mac(suite));
		// Если набор связи неизвестен
		if(width == 0)
			// Выводим отказ
			return false;
		// Затравка: случайное значение сервера, затем клиента
		uint8_t seed[64];
		// Переносим случайное значение сервера
		::memcpy(seed, server.data(), 32);
		// Переносим случайное значение клиента
		::memcpy(seed + 32, client.data(), 32);
		// Метка расширения ключей
		const char * label = "key expansion";
		// Ключевой материал: ключи имитовставки, ключ клиента, ключ сервера, вектор клиента, вектор сервера
		uint8_t material[(protect::PROTECT_MAC + protect::PROTECT_KEY + protect::PROTECT_VECTOR) * 2];
		// Если материал не выведен
		if(!digest::prf(protect::hash(suite), view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed, sizeof(seed)), material, (stamp + width + size) * 2))
			// Выводим отказ
			return false;
		// Ключ имитовставки стороны
		const view_t mac(material + (own ? 0 : stamp), stamp);
		// Ключ стороны
		const view_t key(material + (stamp * 2) + (own ? 0 : width), width);
		// Вектор стороны
		const view_t vector(material + (stamp * 2) + (width * 2) + (own ? 0 : size), size);
		// Если защиту завести не удалось
		if(!protection.start(suite, key, vector, mac))
			// Выводим отказ
			return false;
		// Устанавливаем порядок RFC 7366
		protection.etm(etm);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод составления пути к каталогу вектора
	 *
	 * @param edition  издание openssl
	 * @param scenario имя сценария
	 *
	 * @return         путь к каталогу вектора
	 *
	 */
	std::string place(const char * edition, const char * scenario) noexcept {
		// Выводим путь к каталогу вектора
		return (std::string(CORPUS) + "/tls12/tls12-OpenSSL-" + edition + "/" + scenario);
	}
	/**
	 * @brief Метод проверки наличия каталога вектора
	 *
	 * @param path путь к каталогу вектора
	 *
	 * @return     признак наличия каталога
	 *
	 */
	bool exists(const std::string & path) noexcept {
		// Сведения о пути
		struct stat info;
		// Выводим признак того, что путь есть и это каталог
		return ((::stat(path.c_str(), &info) == 0) && S_ISDIR(info.st_mode));
	}
	/**
	 * @brief Метод суждения о пропуске отсутствующего вектора
	 *
	 * @param edition  издание openssl
	 * @param scenario сценарий
	 *
	 * @return         признак того, что отсутствие вектора ожидаемо
	 *
	 */
	bool omitted(const char * edition, const Scenario & scenario) noexcept {
		// Ключ -no_ems появился в OpenSSL 3.3: у 3.0.x сценария no-ems нет
		return ((::strcmp(scenario.name, "no-ems") == 0) && (::strncmp(edition, "3.0.", 4) == 0));
	}
};

/**
 * Проверка порождающей функции TLS 1.2 (раздел 5 RFC 5246) по известным векторам.
 * Источник: векторы «TLS 1.2 PRF test vectors», разосланные в рабочую группу TLS IETF
 * в 2008 году (обсуждение draft-ietf-tls-rfc4346-bis), сто байтов на SHA-256 и сто сорок
 * восемь на SHA-384; вектор SHA-256 сверен ещё и независимой реализацией по определению
 * P_hash - хвост «…97fce34f79…» сходится у обеих, а запись «…97fcf8a1d…» из задания
 * оказалась опиской переписчика
 */
TEST(Tls12Test, Prf){
	// Секрет вектора SHA-256
	const vector <uint8_t> secret = decode("9bbe436ba940f017b17652849a71db35");
	// Затравка вектора SHA-256
	const vector <uint8_t> seed = decode("a0ba9f936cda311827a6f796ffd5198c");
	// Ожидаемая последовательность SHA-256
	const vector <uint8_t> expected = decode("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");
	// Метка вектора
	const char * label = "test label";
	// Место итога
	uint8_t result[148];
	// Вырабатываем последовательность SHA-256
	ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed.data(), seed.size()), result, 100));
	// Сличаем последовательность
	ASSERT_EQ(vector <uint8_t> (result, result + 100), expected);
	// Секрет вектора SHA-384
	const vector <uint8_t> secret384 = decode("b80b733d6ceefcdc71566ea48e5567df");
	// Затравка вектора SHA-384
	const vector <uint8_t> seed384 = decode("cd665cf6a8447dd6ff8b27555edb7465");
	// Ожидаемая последовательность SHA-384
	const vector <uint8_t> expected384 = decode("7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f");
	// Вырабатываем последовательность SHA-384
	ASSERT_TRUE(digest::prf(digest::hash_t::SHA384, view_t(secret384.data(), secret384.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed384.data(), seed384.size()), result, 148));
	// Сличаем последовательность
	ASSERT_EQ(vector <uint8_t> (result, result + 148), expected384);
	// Неведомый хеш отвергается
	ASSERT_FALSE(digest::prf(digest::hash_t::NONE, view_t(secret.data(), secret.size()), view_t(nullptr, 0), view_t(seed.data(), seed.size()), result, 16));
	// Отсутствие места отвергается
	ASSERT_FALSE(digest::prf(digest::hash_t::SHA256, view_t(secret.data(), secret.size()), view_t(nullptr, 0), view_t(seed.data(), seed.size()), nullptr, 16));
}

/**
 * Проверка петлевого рукопожатия TLS 1.2 по шести наборам и трём группам со взаимной
 * подлинностью и обменом данными; издание 1.3 у обеих сторон дозволено, а выбирается 1.2
 * оттого, что клиент ограничен изданием 1.2
 */
TEST(Tls12Test, Loopback){
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Подлинность сторон
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(SUITES[s].key, credential));
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны со взаимной подлинностью
			arrange(client, server, SUITES[s].suite, GROUPS[g], credential, true);
			// Клиент ведёт лишь издание 1.2
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Проводим рукопожатие
			converse(client, server);
			// Проверяем установленность связи клиентом
			ASSERT_TRUE(client.established()) << SUITES[s].title << " " << naming(GROUPS[g]) << " отказы " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
			// Проверяем установленность связи сервером
			ASSERT_TRUE(server.established()) << SUITES[s].title << " " << naming(GROUPS[g]);
			// Проверяем издание
			ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
			// Проверяем издание сервера
			ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
			// Проверяем набор
			ASSERT_EQ(client.suite(), SUITES[s].suite);
			// Проверяем набор сервера
			ASSERT_EQ(server.suite(), SUITES[s].suite);
			// Проверяем подлинность сервера у клиента
			ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
			// Проверяем подлинность клиента у сервера
			ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
			// Проверяем обмен данными
			ASSERT_TRUE(barter(client, server)) << SUITES[s].title << " " << naming(GROUPS[g]);
			// Счётчик записей клиента: завершение и запрос прикладных данных
			ASSERT_EQ(client.sequence(), static_cast <uint64_t> (2));
			// Счётчик принятых сервером записей тот же
			ASSERT_EQ(server.sequence(true), static_cast <uint64_t> (2));
			// Смена ключей изданию 1.2 неведома
			ASSERT_EQ(client.update(true), context::error_t::STATE);
			// Билеты изданию 1.2 связью не выдаются
			ASSERT_EQ(server.issue(), context::error_t::STATE);
			// Закрываем связь
			ASSERT_EQ(client.close(), context::error_t::NONE);
			// Передаём закрытие
			converse(client, server);
			// Сервер ответил закрытием
			ASSERT_EQ(server.state(), context::state_t::CLOSED);
		}
	}
}

/**
 * Проверка сервера без подлинности клиента и клиента без своей подлинности: пустая
 * цепочка клиента изданием 1.2 принимается, а сервер и без запроса ведёт связь
 */
TEST(Tls12Test, Unilateral){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор: без запроса подлинности и с запросом при пустой цепочке клиента
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны без подлинности клиента
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// На втором круге подлинность запрашивается, а у клиента её нет
		server.request(item == 1);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established()) << item << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Цепочка клиента пуста
		ASSERT_TRUE(server.peer().empty());
		// Издание 1.2
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
		// Обмен данными
		ASSERT_TRUE(barter(client, server));
	}
}

/**
 * Проверка пределов изданий: сервер «только 1.3» против клиента «только 1.2» -
 * protocol_version; клиент «только 1.2» против сервера 1.2…1.3 - издание 1.2 с заслоном
 * понижения в случайном значении сервера; сервер с пределом 1.3, но без наборов 1.3,
 * заслона не кладёт и с клиентом 1.2…1.3 сходится изданием 1.2; негодные пределы отвергаются
 */
TEST(Tls12Test, Limits){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, false);
		// Сервер ведёт лишь издание 1.3
		ASSERT_EQ(server.versions(0x0304, 0x0304), context::error_t::NONE);
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Сервер оборвал связь несовпадением издания
		ASSERT_EQ(server.error(), context::error_t::VERSION);
		// Извещение protocol_version
		ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
		// Клиент принял извещение
		ASSERT_EQ(client.error(), context::error_t::ALERT);
		// Извещение у клиента то же
		ASSERT_EQ(client.alert().description, alert::description_t::VERSION);
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с наборами обоих изданий
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Клиент ведёт лишь издание 1.2, сервер - от 1.2 до 1.3
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу
		ASSERT_TRUE(deliver(client, server));
		// Ответ сервера: приветствие идёт первой записью
		const view_t answer = server.output();
		// Заслон понижения RFC 8446 §4.1.3
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
		// Проверяем длину ответа
		ASSERT_GT(answer.size, static_cast <size_t> (5 + 4 + 2 + 32));
		/**
		 * Раздел 4.1.3 RFC 8446: сервер, знающий 1.3, кладёт заслон всякому выбору 1.2, а
		 * клиент, предлагавший одно лишь издание 1.2, заслона 1.3 не судит
		 */
		ASSERT_EQ(::memcmp(answer.data + 5 + 4 + 2 + 32 - 8, downgrade, 8), 0);
		// Проводим рукопожатие дальше
		converse(client, server);
		// Связь установлена изданием 1.2
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем издание
		ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
		// Набор издания 1.2
		ASSERT_EQ(client.suite(), protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256);
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Наборы обоих изданий у обеих сторон
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Сервер ведёт лишь издание 1.2, клиент предлагает и 1.3
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу
		ASSERT_TRUE(deliver(client, server));
		// Ответ сервера
		const view_t answer = server.output();
		// Заслон понижения RFC 8446 §4.1.3
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
		// Проверяем длину ответа
		ASSERT_GT(answer.size, static_cast <size_t> (5 + 4 + 2 + 32));
		// Сервер одного лишь издания 1.2 заслона не кладёт: выбор 1.2 у него законен
		ASSERT_NE(::memcmp(answer.data + 5 + 4 + 2 + 32 - 8, downgrade, 8), 0);
		// Проводим рукопожатие дальше
		converse(client, server);
		// Связь установлена изданием 1.2
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем издание
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Клиент несёт наборы обоих изданий и предлагает 1.3
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Сервер знает издание 1.3 по пределам, но наборов его не несёт - выбирает 1.2
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу
		ASSERT_TRUE(deliver(client, server));
		// Ответ сервера
		const view_t answer = server.output();
		// Заслон понижения RFC 8446 §4.1.3
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
		// Проверяем длину ответа
		ASSERT_GT(answer.size, static_cast <size_t> (5 + 4 + 2 + 32));
		/**
		 * Раздел 4.1.3 RFC 8446: заслон кладёт сервер, СПОСОБНЫЙ к изданию 1.3; сервер без
		 * единого набора 1.3 к нему не способен, выбор 1.2 у него единственно возможный, и
		 * заслона он не кладёт - иначе клиент, предлагавший 1.3, оборвал бы законную связь
		 */
		ASSERT_NE(::memcmp(answer.data + 5 + 4 + 2 + 32 - 8, downgrade, 8), 0);
		// Проводим рукопожатие дальше
		converse(client, server);
		// Связь установлена изданием 1.2 без обрыва
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем издание
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
		// Обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Обе стороны с наборами обоих изданий: издание 1.3 предпочтительнее
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена изданием 1.3
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем издание
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0304));
		// Набор издания 1.3
		ASSERT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
		// Обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Умолчание: от 1.2 до 1.3
		ASSERT_EQ(client.lowest(), static_cast <uint16_t> (0x0303));
		// Верхний предел
		ASSERT_EQ(client.highest(), static_cast <uint16_t> (0x0304));
		// Издание 1.1 (DTLS 1.0 по RFC 4347) пределом принимается, но потоком связь с ним не заводится
		ASSERT_EQ(client.versions(0x0302, 0x0304), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
		// Ниже 1.1 - никогда
		ASSERT_EQ(client.versions(0x0301, 0x0304), context::error_t::SETTINGS);
		// Возвращаем умолчание пределов
		ASSERT_EQ(client.versions(0x0303, 0x0304), context::error_t::NONE);
		// Выше 1.3 изданий нет
		ASSERT_EQ(client.versions(0x0303, 0x0305), context::error_t::SETTINGS);
		// Перевёрнутые пределы
		ASSERT_EQ(client.versions(0x0304, 0x0303), context::error_t::SETTINGS);
		// Пределы не тронуты отказами
		ASSERT_EQ(client.lowest(), static_cast <uint16_t> (0x0303));
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// На живой связи пределы не переставляются
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::STATE);
		// Издание до согласования не известно
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0));
	}
}

/**
 * Проверка заслона понижения у клиента: сервер «только 1.2» заслона не кладёт, а
 * подделанный заслон в случайном значении обрывает клиента, предлагавшего 1.3,
 * извещением illegal_parameter; клиент «только 1.2» на заслон 1.3 не смотрит
 */
TEST(Tls12Test, Downgrade){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор: клиент 1.2…1.3 и клиент только 1.2
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// На втором круге и клиент ведёт лишь издание 1.2
		if(item == 1){
			// Ограничиваем клиента
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// На первом круге клиент несёт и набор издания 1.3: без него издание 1.3 не предлагается
		} else {
			// Устанавливаем наборы обоих изданий
			client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256});
		}
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу
		ASSERT_TRUE(deliver(client, server));
		// Ответ сервера
		const view_t answer = server.output();
		// Переносим ответ
		vector <uint8_t> forged(answer.data, answer.data + answer.size);
		// Снимаем ответ с накопителя
		server.consume(forged.size());
		// Заслон понижения
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
		// Сервер одного лишь издания 1.2 заслона не кладёт
		ASSERT_NE(::memcmp(forged.data() + 5 + 4 + 2 + 32 - 8, downgrade, 8), 0);
		// Подделываем заслон в случайном значении сервера
		::memcpy(forged.data() + 5 + 4 + 2 + 32 - 8, downgrade, 8);
		// Подаём ответ клиенту
		client.push(view_t(forged.data(), forged.size()));
		// Если клиент предлагал издание 1.3
		if(item == 0){
			// Клиент оборвал связь понижением издания
			ASSERT_EQ(client.error(), context::error_t::VERSION);
			// Извещение illegal_parameter
			ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
		// Если клиент ведёт лишь издание 1.2: заслон 1.3 его не касается, подпись обмена не сойдётся
		} else {
			// Клиент не оборвался на заслоне
			ASSERT_NE(client.error(), context::error_t::VERSION);
			// Случайное значение вошло в подпись обмена ключами: подпись не сошлась
			ASSERT_EQ(client.error(), context::error_t::SIGNATURE);
		}
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
}

/**
 * Проверка обязательности расширенного главного секрета (RFC 7627): чужой клиент без
 * расширения отвергается извещением handshake_failure, с расширением - принимается до
 * конца приветствия сервера
 */
TEST(Tls12Test, Master){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор: без расширения и с расширением
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Запись приветствия чужого клиента
		vector <uint8_t> wire;
		// Составляем приветствие руками
		ASSERT_TRUE(greeting(item == 1, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, wire, false, extension::group_t::SECP256R1));
		// Подаём приветствие серверу
		server.push(view_t(wire.data(), wire.size()));
		// Если расширения нет
		if(item == 0){
			// Сервер оборвал связь отсутствием расширенного главного секрета
			ASSERT_EQ(server.error(), context::error_t::MASTER);
			// Извещение handshake_failure
			ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
		// Если расширение есть
		} else {
			// Сервер ответил без отказа
			ASSERT_EQ(server.error(), context::error_t::NONE);
			// Издание 1.2 согласовано
			ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
			// Сервер выслал приветствие, цепочку, обмен и конец приветствия
			ASSERT_GT(server.output().size, static_cast <size_t> (100));
		}
	}
}

/**
 * Проверка порядка выбора набора сервером изданием 1.2: порядком сервера (умолчание)
 * либо порядком клиента; издания 1.3 настройка не касается - там выбор порядком сервера
 * как прежде
 */
TEST(Tls12Test, Preference){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор: порядком сервера и порядком клиента
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Наборы клиента: ChaCha20 первым
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Наборы сервера: AES первым
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Порядок выбора
		server.preference(item == 0);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << item << " отказы " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
		// Набор по порядку стороны, ведущей выбор
		ASSERT_EQ(server.suite(), ((item == 0) ? protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256 : protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256)) << item;
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Наборы клиента издания 1.3
		client.suites(vector <protect::suite_t> {protect::suite_t::CHACHA20_POLY1305_SHA256, protect::suite_t::AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::CHACHA20_POLY1305_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Порядок сервера
		server.preference(true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// В издании 1.3 выбор идёт порядком сервера как прежде: настройка его не касается
		ASSERT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Наборы клиента издания 1.3
		client.suites(vector <protect::suite_t> {protect::suite_t::CHACHA20_POLY1305_SHA256, protect::suite_t::AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::CHACHA20_POLY1305_SHA256});
		// Подлинность сервера
		server.credential(credential);
		// Порядок клиента
		server.preference(false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// В издании 1.3 настройка порядка не действует: выбор порядком сервера
		ASSERT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	}
}

/**
 * Проверка порчи записи: изменённый байт защищённой записи прикладных данных обрывает
 * приёмную сторону извещением bad_record_mac, а связь остаётся оборванной
 */
TEST(Tls12Test, Corruption){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов AES-GCM и ChaCha20-Poly1305
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, ((item == 0) ? protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384 : protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256), extension::group_t::SECP384R1, credential, false);
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// Прикладные данные
		const string request = "Запись, которую испортят по дороге";
		// Отправляем данные
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Запись клиента
		const view_t data = client.output();
		// Переносим запись
		vector <uint8_t> forged(data.data, data.data + data.size);
		// Снимаем запись
		client.consume(forged.size());
		// Портим последний байт метки целостности
		forged.back() = static_cast <uint8_t> (forged.back() ^ 0x01);
		// Подаём испорченную запись серверу
		ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::PROTECTION);
		// Извещение bad_record_mac
		ASSERT_EQ(server.alert().description, alert::description_t::MAC);
		// Связь оборвана
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Дальнейшая подача отвергается
		ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::STATE);
		// Извещение дошло до клиента
		converse(client, server);
		// Клиент оборван извещением
		ASSERT_EQ(client.error(), context::error_t::ALERT);
	}
}

/**
 * Проверка отказа сообщениям издания 1.3 в связи издания 1.2: смена ключей, сжатая
 * цепочка и билет, поданные открытой записью по ходу рукопожатия, обрывают клиента
 * извещением unexpected_message
 */
TEST(Tls12Test, Alien){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Виды чужих сообщений
	static const handshake::type_t ALIENS[] = {handshake::type_t::UPDATE, handshake::type_t::COMPRESSED, handshake::type_t::TICKET, handshake::type_t::EXTENSIONS};
	/**
	 * Выполняем перебор чужих сообщений
	 */
	for(size_t item = 0; item < (sizeof(ALIENS) / sizeof(ALIENS[0])); item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствия сторон
		ASSERT_TRUE(pump(client, server));
		// Клиент разобрал приветствие сервера изданием 1.2
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
		// Тело чужого сообщения
		const uint8_t body[1] = {0x00};
		// Составитель сообщения
		handshake::writer_t writer;
		// Составляем чужое сообщение
		ASSERT_EQ(writer.push(ALIENS[item], view_t(body, sizeof(body))), handshake::error_t::NONE);
		// Нарезчик записей
		record::writer_t records;
		// Составляем открытую запись
		ASSERT_EQ(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()), record::error_t::NONE);
		/**
		 * Билет сеанса RFC 5077 клиенту в этом месте положен: сервер обещал его приветствием,
		 * а клиент уже отослал свой залп и ждёт смены набора - потому негодное тело билета
		 * отвергается decode_error, а не unexpected_message; прочие сообщения - не в свой черёд
		 */
		const bool ticket = (ALIENS[item] == handshake::type_t::TICKET);
		// Подаём запись клиенту
		ASSERT_EQ(client.push(records.data()), (ticket ? context::error_t::MESSAGE : context::error_t::ORDER)) << item;
		// Извещение unexpected_message либо decode_error у билета
		ASSERT_EQ(client.alert().description, (ticket ? alert::description_t::DECODE : alert::description_t::UNEXPECTED));
	}
}

/**
 * Проверка сшивки состояния сертификата (RFC 6066) изданием 1.2: ответ идёт отдельным
 * сообщением CertificateStatus за цепочкой, и клиент его выдаёт как есть
 */
TEST(Tls12Test, Status){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Ответ о состоянии самоподписанного листа
	const vector <uint8_t> answer = corpus("ocsp/ec256.good.der");
	// Ответ прочитан
	ASSERT_FALSE(answer.empty());
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, false);
	// Клиент ведёт лишь издание 1.2
	ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
	// Сервер сшивает ответ
	server.status(answer);
	// Клиент запрашивает состояние
	client.status(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Ответ дошёл до клиента как есть
	ASSERT_EQ(client.status(), answer);
}

/**
 * Проверка обмена с настоящим openssl изданием 1.2: наш клиент против s_server -tls1_2
 * по шести наборам и трём группам со взаимной подлинностью, s_client -tls1_2 против
 * нашего сервера, s_client без предела против нашего сервера «только 1.2», s_server
 * -tls1_2 против нашего клиента «только 1.3» и пересогласование клиентом openssl:
 * предупреждение no_renegotiation без обрыва с нашей стороны
 */
TEST(Tls12Test, Openssl){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.2 с ECDHE (проба возможности, не по номеру издания)
	if(!toolkit.tls12){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.2";
	}
	// Если openssl без расширенного главного секрета
	if(!toolkit.master){
		// Пропускаем проверку вслух: связь без RFC 7627 не ведётся намеренно (отказ MASTER)
		GTEST_SKIP() << "s_client не предлагает extended_master_secret (RFC 7627; нет у OpenSSL 1.0.2 и у LibreSSL): связь без него не ведётся намеренно";
	}
	/**
	 * Выполняем перебор наборов шифрования: наш клиент против s_server
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Если набор недоступен openssl
		if(shell(std::string("openssl ciphers -s -tls1_2 ") + SUITES[s].title + " >/dev/null 2>&1") != 0){
			// Сообщаем о пропуске вслух
			std::cout << "openssl без " << SUITES[s].title << ": сличение пропущено" << std::endl;
			// Переходим к следующему набору
			continue;
		}
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(SUITES[s].key, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + SUITES[s].key + ".crt", key = std::string(CORPUS) + "/" + SUITES[s].key + ".pem";
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
			// Если openssl без кривой X25519 (появилась в 1.1.0)
			if((GROUPS[g] == extension::group_t::X25519) && !toolkit.x25519){
				// Сообщаем о пропуске вслух
				std::cout << "openssl без X25519: сличение по группе пропущено" << std::endl;
				// Переходим к следующей группе
				continue;
			}
			// Свободный порт
			const uint16_t number = vacant(false);
			// Проверяем наличие порта
			ASSERT_NE(number, 0);
			// Журнал сервера openssl
			const std::string log = "/tmp/ants-tls12-server-" + std::to_string(number) + ".log";
			/**
			 * Раздел 5.1.1 RFC 8422: у openssl изданием 1.2 кривая ключа сертификата клиента
			 * обязана входить в группы сервера, иначе отвечает «wrong curve»; группа обмена
			 * идёт первой, кривые сертификатов следом
			 */
			ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -no_ticket -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -cipher " + SUITES[s].title + grouping(toolkit, true, GROUPS[g]) + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
			// Сторож сервера openssl: снимается по номеру и при отказе посреди проверки
			sentinel_t sentinel(log + ".pid");
			// Подключаемся к серверу openssl
			const int fd = dial(number);
			// Проверяем подключение
			ASSERT_GE(fd, 0) << "порт " << number;
			// Связь стороны клиента
			client::context_t client;
			// Наборы клиента
			client.suites(vector <protect::suite_t> {SUITES[s].suite});
			/**
			 * Раздел 5.1.1 RFC 8422: в издании 1.2 кривая ключа сертификата обязана входить в
			 * поддерживаемые группы клиента, иначе openssl отвечает «no shared cipher»; группа
			 * обмена идёт первой, кривые сертификатов - следом
			 */
			client.groups(vector <extension::group_t> {GROUPS[g], extension::group_t::SECP256R1, extension::group_t::SECP384R1});
			// Подлинность клиента тем же ключом
			client.credential(credential);
			// Имя узла
			client.name("localhost");
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			/**
			 * Выполняем передачу байтов до установления связи
			 */
			for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
				// Передаём байты
				relay(client, fd);
			// Проверяем установленность связи
			ASSERT_TRUE(client.established()) << SUITES[s].title << " " << naming(GROUPS[g]) << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			// Издание 1.2
			ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
			// Проверяем набор
			ASSERT_EQ(client.suite(), SUITES[s].suite);
			// Проверяем цепочку сервера
			ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
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
			ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << SUITES[s].title << " " << naming(GROUPS[g]);
			// Сервер openssl видит издание 1.2
			ASSERT_NE(text.find("TLSv1.2"), string::npos) << text;
			// Закрываем сокет
			::close(fd);
			// Снимаем сервер до удаления журнала: иначе отметка завершения воссоздаст файл
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
	 * Выполняем перебор наборов шифрования: s_client -tls1_2 против нашего сервера
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Если набор недоступен openssl
		if(shell(std::string("openssl ciphers -s -tls1_2 ") + SUITES[s].title + " >/dev/null 2>&1") != 0)
			// Переходим к следующему набору
			continue;
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(SUITES[s].key, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + SUITES[s].key + ".crt", key = std::string(CORPUS) + "/" + SUITES[s].key + ".pem";
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
			// Если openssl без кривой X25519 (появилась в 1.1.0)
			if((GROUPS[g] == extension::group_t::X25519) && !toolkit.x25519){
				// Сообщаем о пропуске вслух
				std::cout << "openssl без X25519: сличение по группе пропущено" << std::endl;
				// Переходим к следующей группе
				continue;
			}
			// Порт сервера
			uint16_t number = 0;
			// Слушающий сокет
			const int listener = harbour(number);
			// Проверяем сокет
			ASSERT_GE(listener, 0);
			// Журнал клиента openssl
			const std::string log = "/tmp/ants-tls12-client-" + std::to_string(number) + ".log";
			// Запускаем клиента openssl изданием 1.2 со своей подлинностью
			/**
			 * Раздел 5.1.1 RFC 8422: кривая ключа сертификата обязана входить в поддерживаемые
			 * группы клиента openssl - группа обмена идёт первой, кривые сертификатов следом
			 */
			ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -CAfile " + crt + " -cert " + crt + " -key " + key + " -cipher " + SUITES[s].title + grouping(toolkit, false, GROUPS[g]) + " -servername localhost -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
			// Сторож клиента openssl
			sentinel_t sentinel(log + ".pid");
			// Принимаем подключение с пределом ожидания приёма
			const int fd = greeted(listener);
			// Проверяем подключение
			ASSERT_GE(fd, 0);
			// Связь стороны сервера
			server::context_t server;
			// Наборы сервера
			server.suites(vector <protect::suite_t> {SUITES[s].suite});
			// Группы сервера
			server.groups(vector <extension::group_t> {GROUPS[g]});
			// Подлинность сервера
			server.credential(credential);
			// Запрашиваем подлинность клиента
			server.request(true);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Ведём связь до конца рукопожатия
			const bool complete = serve(server, fd);
			// Проверяем, что рукопожатие дошло до конца
			ASSERT_TRUE(complete) << SUITES[s].title << " " << naming(GROUPS[g]) << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
			// Отказа не было
			ASSERT_EQ(server.error(), context::error_t::NONE);
			// Издание 1.2
			ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
			// Проверяем набор
			ASSERT_EQ(server.suite(), SUITES[s].suite);
			// Проверяем подлинность клиента
			ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
			// Закрываем связь, коли она ещё открыта
			ASSERT_TRUE(farewell(server, fd));
			// Закрываем сокеты
			::close(fd);
			// Закрываем слушающий сокет
			::close(listener);
			// Текст журнала клиента
			std::string text;
			// Клиент обязан завершиться
			ASSERT_TRUE(settle(log, text)) << text;
			// Проверка подлинности сервера у клиента сошлась
			ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
			// Издание 1.2
			ASSERT_NE(text.find("Protocol  : TLSv1.2"), std::string::npos) << text;
			// Набор тот же
			ASSERT_NE(text.find(std::string("Cipher    : ") + SUITES[s].title), std::string::npos) << text;
			// Удаляем журнал
			::remove(log.c_str());
		}
	}
	{
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ec256", credential));
		// Путь к сертификату
		const std::string crt = std::string(CORPUS) + "/ec256.crt";
		// Порт сервера
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-tls12-any-" + std::to_string(number) + ".log";
		// Запускаем клиента openssl без предела издания против нашего сервера «только 1.2»
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -CAfile " + crt + " -servername localhost -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож клиента openssl
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение
		const int fd = ::accept(listener, nullptr, nullptr);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём связь до конца рукопожатия
		ASSERT_TRUE(serve(server, fd)) << static_cast <int> (server.error());
		// Издание 1.2
		ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
		// Закрываем связь, коли она ещё открыта
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем сокеты
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Текст журнала клиента
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(settle(log, text)) << text;
		// Издание 1.2 у клиента openssl без предела
		ASSERT_NE(text.find("Protocol  : TLSv1.2"), std::string::npos) << text;
		// Проверка подлинности сошлась
		ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
	{
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ec256", credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-tls12-only13-" + std::to_string(number) + ".log";
		// Запускаем сервер openssl изданием 1.2
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -cert " + crt + " -key " + key + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера openssl
		sentinel_t sentinel(log + ".pid");
		// Подключаемся к серверу openssl
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны клиента
		client::context_t client;
		// Клиент ведёт лишь издание 1.3
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
		// Имя узла
		client.name("localhost");
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до обрыва связи
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты
			relay(client, fd);
		// Связь не установлена
		ASSERT_FALSE(client.established());
		// Сервер openssl ответил извещением protocol_version либо клиент оборвался сам
		ASSERT_TRUE((client.error() == context::error_t::ALERT) || (client.error() == context::error_t::VERSION)) << static_cast <int> (client.error());
		// Извещение protocol_version
		ASSERT_EQ(client.alert().description, alert::description_t::VERSION);
		// Закрываем сокет
		::close(fd);
		// Снимаем сервер до удаления журнала: иначе отметка завершения воссоздаст файл
		sentinel.halt();
		// Журнал сервера
		std::string text;
		// Дожидаемся отметки завершения снятого сервера
		(void) settle(log, text);
		// Удаляем журнал
		::remove(log.c_str());
	}
	{
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ec256", credential));
		// Путь к сертификату
		const std::string crt = std::string(CORPUS) + "/ec256.crt";
		// Порт сервера
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-tls12-reneg-" + std::to_string(number) + ".log";
		/**
		 * Клиент openssl получает на вход команду R: за рукопожатием он затевает
		 * пересогласование новым приветствием, а наш сервер отвечает no_renegotiation
		 */
		ASSERT_TRUE(launch("printf 'R\\n' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -CAfile " + crt + " -servername localhost -state >" + log + " 2>&1", log, log + ".pid"));
		// Сторож клиента openssl
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение с пределом ожидания приёма
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём связь до конца рукопожатия
		ASSERT_TRUE(serve(server, fd)) << static_cast <int> (server.error());
		// Связь установлена изданием 1.2
		ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
		/**
		 * Выполняем приём пересогласования: ждём приветствия клиента под защитой
		 */
		for(size_t i = 0; (i < 8) && (server.state() == context::state_t::ESTABLISHED); i++){
			// Место принятых байтов
			uint8_t buffer[16384];
			// Принимаем байты клиента
			const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
			// Если байты приняты
			if(received > 0)
				// Подаём байты серверу
				server.push(view_t(buffer, static_cast <size_t> (received)));
			// Если приём оборвался
			else break;
			// Байты сервера
			const view_t data = server.output();
			// Если серверу есть что отправить
			if(data.size > 0){
				// Отправляем байты
				const ssize_t sent = ::send(fd, data.data, data.size, 0);
				// Если отправлено
				if(sent > 0)
					// Снимаем байты
					server.consume(static_cast <size_t> (sent));
			}
		}
		/**
		 * Раздел 7.2.2 RFC 5246: на приветствие клиента за установленной связью сервер
		 * ответил предупреждением no_renegotiation и связи не рвал; роковым отказ счёл сам
		 * openssl и оборвал связь извещением handshake_failure
		 */
		ASSERT_EQ(server.error(), context::error_t::ALERT);
		// Извещение handshake_failure собеседника
		ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
		// Закрываем сокеты
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Текст журнала клиента
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(settle(log, text)) << text;
		// Клиент openssl принял предупреждение no_renegotiation
		ASSERT_NE(text.find("warning:no renegotiation"), std::string::npos) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка просьбы о пересогласовании HelloRequest (раздел 7.4.1.1 RFC 5246), составленной
 * руками: по ходу рукопожатия клиент её пропускает и в переписку не кладёт - как за
 * приветствием сервера, так и до него, - с непустым телом отвергает, клиент «только 1.3»
 * отвергает как неведомый вид, а сервер не принимает её никогда - ни до согласования
 * издания, ни за ним
 */
TEST(Tls12Test, HelloRequest){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Составитель просьбы о пересогласовании
	handshake::writer_t writer;
	// Составляем просьбу с пустым телом
	ASSERT_EQ(writer.push(handshake::type_t::HELLO_REQUEST, view_t(nullptr, 0)), handshake::error_t::NONE);
	// Нарезчик записей просьбы
	record::writer_t records;
	// Составляем открытую запись просьбы
	ASSERT_EQ(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()), record::error_t::NONE);
	// Запись просьбы о пересогласовании
	const view_t request = records.data();
	// Тело порченой просьбы
	const uint8_t alien[1] = {0x00};
	// Составитель порченой просьбы
	handshake::writer_t spoiler;
	// Составляем просьбу с непустым телом
	ASSERT_EQ(spoiler.push(handshake::type_t::HELLO_REQUEST, view_t(alien, sizeof(alien))), handshake::error_t::NONE);
	// Нарезчик записей порченой просьбы
	record::writer_t spoiled;
	// Составляем открытую запись порченой просьбы
	ASSERT_EQ(spoiled.push(record::type_t::HANDSHAKE, record::version_t::TLS12, spoiler.data()), record::error_t::NONE);
	// Запись порченой просьбы
	const view_t corrupted = spoiled.data();
	/**
	 * Выполняем два круга: просьба пустая пропускается, порченая - обрывает связь
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу
		ASSERT_TRUE(deliver(client, server));
		// Залп сервера: приветствие, цепочка, обмен ключами, конец приветствия
		const view_t flight = server.output();
		// Залп составлен
		ASSERT_GT(flight.size, record::RECORD_HEADER);
		// Обвязка первой записи залпа
		record::header_t header;
		// Разбираем обвязку первой записи
		ASSERT_EQ(record::parse(flight, header), record::error_t::NONE);
		// Длина первой записи залпа вместе с обвязкой
		const size_t first = (record::RECORD_HEADER + header.size);
		// За первой записью идут остальные
		ASSERT_LT(first, flight.size);
		// Залп с просьбой, вклиненной за приветствием сервера
		vector <uint8_t> spliced(flight.data, flight.data + first);
		// Вклиниваем просьбу о пересогласовании: пустую либо порченую
		spliced.insert(spliced.end(), ((item == 0) ? request.data : corrupted.data), ((item == 0) ? request.data : corrupted.data) + ((item == 0) ? request.size : corrupted.size));
		// Добавляем остаток залпа
		spliced.insert(spliced.end(), flight.data + first, flight.data + flight.size);
		// Снимаем залп с накопителя сервера
		server.consume(flight.size);
		// Если просьба пустая
		if(item == 0){
			// Клиент пропускает просьбу и разбирает залп до конца
			ASSERT_EQ(client.push(view_t(spliced.data(), spliced.size())), context::error_t::NONE);
			// Клиент разобрал приветствие сервера изданием 1.2
			ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
			// Проводим рукопожатие до конца
			converse(client, server);
			// Связь установлена: просьба не легла ни в переписку, ни в подпись владения
			ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Обмен прикладными данными сходится
			ASSERT_TRUE(barter(client, server));
		// Если просьба порченая
		} else {
			// Клиент обрывает связь отказом разбора
			ASSERT_EQ(client.push(view_t(spliced.data(), spliced.size())), context::error_t::MESSAGE);
			// Извещение decode_error
			ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
		}
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Передаём приветствие клиента серверу: издание 1.2 согласовано
		ASSERT_TRUE(deliver(client, server));
		// Сервер согласовал издание 1.2
		ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303));
		// Сервер просьбу не принимает: у него она не в свой черёд
		ASSERT_EQ(server.push(request), context::error_t::ORDER);
		// Извещение unexpected_message
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	}
	{
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Просьба прежде приветствия клиента: издание ещё не согласовано, сообщение не в свой черёд
		ASSERT_EQ(server.push(request), context::error_t::ORDER);
		// Извещение unexpected_message
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	}
	/**
	 * Выполняем три круга у клиента до приветствия сервера: клиент 1.2…1.3 просьбу пропускает и
	 * связь доводит, клиент «только 1.3» отвергает её unexpected_message, порченая - decode_error
	 */
	for(size_t item = 0; item < 3; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// На втором круге клиент ведёт лишь издание 1.3
		if(item == 1){
			// Ограничиваем клиента
			ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
			// Изданию 1.3 нужен его набор: без набора издания предложение не составится
			client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		}
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Подаём просьбу клиенту прежде приветствия сервера: издание ещё не согласовано
		const context::error_t outcome = client.push((item == 2) ? corrupted : request);
		/**
		 * Выполняем разбор исхода круга
		 */
		switch(item){
			// Раздел 7.4.1.1 RFC 5246: клиент, дозволяющий издание 1.2, просьбу по ходу рукопожатия пропускает
			case 0: {
				// Просьба пропущена без отказа
				ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
				// Связь не оборвана
				ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
				// Проводим рукопожатие до конца
				converse(client, server);
				// Связь установлена изданием 1.2: просьба не легла в переписку
				ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Обмен прикладными данными сходится
				ASSERT_TRUE(barter(client, server));
			} break;
			// Раздел 4 RFC 8446: изданию 1.3 вид ноль неведом, и клиент «только 1.3» обрывается
			case 1: {
				// Отказ сообщения не в свой черёд
				ASSERT_EQ(outcome, context::error_t::ORDER);
				// Извещение unexpected_message
				ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
			} break;
			// Раздел 7.4.1.1 RFC 5246: тело просьбы пусто, непустое - decode_error
			case 2: {
				// Отказ разбора
				ASSERT_EQ(outcome, context::error_t::MESSAGE);
				// Извещение decode_error
				ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
			} break;
		}
	}
}

/**
 * Проверка ответа на HelloRequest за установленной связью изданием 1.2: сервер openssl по
 * команде r шлёт просьбу о пересогласовании, наш клиент отвечает извещением no_renegotiation
 * уровня предупреждения (раздел 4.2 RFC 5746) и связь продолжает; openssl отказ
 * пересогласования считает роковым и обрывает связь извещением handshake_failure
 */
TEST(Tls12Test, Renegotiation){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.2 с ECDHE
	if(!toolkit.tls12){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.2";
	}
	// Если openssl без расширенного главного секрета
	if(!toolkit.master){
		// Пропускаем проверку вслух: связь без RFC 7627 не ведётся намеренно (отказ MASTER)
		GTEST_SKIP() << "s_client не предлагает extended_master_secret (RFC 7627; нет у OpenSSL 1.0.2 и у LibreSSL): связь без него не ведётся намеренно";
	}
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Свободный порт
	const uint16_t number = vacant(false);
	// Проверяем наличие порта
	ASSERT_NE(number, 0);
	// Журнал сервера openssl
	const std::string log = "/tmp/ants-tls12-hello-" + std::to_string(number) + ".log";
	// Именованный канал, по которому серверу openssl подаётся команда
	const std::string channel = "/tmp/ants-tls12-hello-" + std::to_string(number) + ".fifo";
	// Удаляем прежний канал
	::remove(channel.c_str());
	// Заводим именованный канал
	ASSERT_EQ(::mkfifo(channel.c_str(), 0600), 0);
	/**
	 * Сервер openssl читает команды со входа: команда r за рукопожатием шлёт клиенту
	 * HelloRequest; -state пишет в журнал принятые извещения
	 */
	ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -no_ticket -cert " + crt + " -key " + key + " -state" + once(toolkit) + " <" + channel + " >" + log + " 2>&1", log, log + ".pid"));
	// Сторож сервера openssl
	sentinel_t sentinel(log + ".pid");
	// Открываем канал на запись: открытие ждёт, пока сервер openssl откроет его на чтение
	const int channelled = ::open(channel.c_str(), O_WRONLY);
	// Проверяем канал
	ASSERT_GE(channelled, 0);
	// Подключаемся к серверу openssl
	const int fd = dial(number);
	// Проверяем подключение
	ASSERT_GE(fd, 0) << "порт " << number;
	// Связь стороны клиента
	client::context_t client;
	// Набор клиента
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Группы клиента: обмен и кривая сертификата
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Имя узла
	client.name("localhost");
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Выполняем передачу байтов до установления связи
	 */
	for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
		// Передаём байты
		relay(client, fd);
	// Связь установлена
	ASSERT_TRUE(client.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
	// Издание 1.2
	ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
	// Подаём серверу openssl команду пересогласования
	ASSERT_EQ(::write(channelled, "r\n", 2), static_cast <ssize_t> (2));
	// Место принятых байтов
	uint8_t buffer[16384];
	// Принимаем просьбу о пересогласовании под защитой
	const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
	// Просьба принята
	ASSERT_GT(received, 0);
	// Вид записи в обвязке открыт: это запись рукопожатия
	ASSERT_EQ(buffer[0], 0x16);
	// Клиент просьбу отвергает без обрыва связи
	ASSERT_EQ(client.push(view_t(buffer, static_cast <size_t> (received))), context::error_t::NONE);
	// Связь остаётся установленной
	ASSERT_TRUE(client.established());
	// Ответ клиента
	const view_t answer = client.output();
	// Ответ составлен
	ASSERT_GT(answer.size, record::RECORD_HEADER);
	// Вид записи ответа открыт: это извещение
	ASSERT_EQ(answer.data[0], 0x15);
	// Отправляем ответ серверу openssl
	ASSERT_EQ(::send(fd, answer.data, answer.size, 0), static_cast <ssize_t> (answer.size));
	// Снимаем ответ с накопителя
	client.consume(answer.size);
	// Принимаем ответ сервера openssl: отказ пересогласования он считает роковым
	const ssize_t closing = ::recv(fd, buffer, sizeof(buffer), 0);
	// Если ответ пришёл
	if(closing > 0)
		// Подаём ответ клиенту
		client.push(view_t(buffer, static_cast <size_t> (closing)));
	// Закрываем канал команд: сервер openssl на конце входа завершается
	::close(channelled);
	// Закрываем сокет
	::close(fd);
	// Текст журнала сервера
	std::string text;
	// Сервер обязан завершиться
	ASSERT_TRUE(settle(log, text)) << text;
	// Сервер openssl принял извещение no_renegotiation
	ASSERT_NE(text.find("no renegotiation"), std::string::npos) << text;
	// Связь у клиента оборвана роковым извещением сервера openssl
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	// Обрыв пришёл извещением собеседника
	ASSERT_EQ(client.error(), context::error_t::ALERT);
	// Извещение handshake_failure
	ASSERT_EQ(client.alert().description, alert::description_t::HANDSHAKE);
	// Удаляем журнал
	::remove(log.c_str());
	// Удаляем канал
	::remove(channel.c_str());
}

/**
 * Проверка пределов издания по способам переноса: под уровнями QUIC пределы, издание 1.3
 * исключающие, заведению связи отказывают SETTINGS, а поверх дейтаграмм издание 1.2 ведётся
 * (DTLS 1.2 по RFC 6347) - пределы «только 1.2» заведению не мешают, как и пределы 1.2…1.3
 */
TEST(Tls12Test, Datagrams){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Перенос по уровням: издание 1.2 ему чуждо
	{
		// Связь стороны клиента
		client::context_t client;
		// Устанавливаем способ переноса
		client.transport(context::transport_t::LEVELS);
		// Пределы «только 1.2» ставятся: пределы не знают переноса
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заведение связи отказывает: вестись ей нечем
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
		// Связь не заведена
		ASSERT_EQ(client.state(), context::state_t::NONE);
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем способ переноса
		server.transport(context::transport_t::LEVELS);
		// Подлинность сервера
		server.credential(credential);
		// Пределы «только 1.2»
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заведение связи отказывает
		ASSERT_EQ(server.start(), context::error_t::SETTINGS);
		// Связь не заведена
		ASSERT_EQ(server.state(), context::state_t::NONE);
		// Пределы 1.2…1.3 законны: издание 1.2 под уровнями просто не предлагается
		ASSERT_EQ(client.versions(0x0303, 0x0304), context::error_t::NONE);
	}
	// Перенос дейтаграммами: издание 1.2 ведётся по RFC 6347
	{
		// Связь стороны клиента
		client::context_t client;
		// Устанавливаем способ переноса
		client.transport(context::transport_t::DATAGRAMS);
		// Набор издания 1.2
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Пределы «только 1.2»
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим клиента: DTLS 1.2 ведётся
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Связь заведена
		ASSERT_NE(client.state(), context::state_t::NONE);
		// Приветствие клиента составлено
		ASSERT_GT(client.output().size, static_cast <size_t> (0));
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем способ переноса
		server.transport(context::transport_t::DATAGRAMS);
		// Подлинность сервера
		server.credential(credential);
		// Набор издания 1.2
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Адрес собеседника для метки возврата состояния
		static const uint8_t ADDRESS[] = {10, 0, 0, 1};
		// Устанавливаем адрес
		ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
		// Пределы «только 1.2»
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер: DTLS 1.2 ведётся
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Связь заведена
		ASSERT_NE(server.state(), context::state_t::NONE);
	}
}

/**
 * Проверка поведения рукопожатия TLS 1.2 при нехватке памяти: перебор запасов
 * выделений, всякий отказ либо NONE, либо MEMORY, либо обрыв внутренним извещением
 */
TEST(Tls12Test, Starved){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Наборы шифрования перебора: AES-GCM и ChaCha20-Poly1305 идут разными примитивами
	static const protect::suite_t STARVING[] = {protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256};
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(STARVING) / sizeof(STARVING[0])); s++){
		// Признак того, что нехватка памяти встретилась
		bool starved = false;
		// Признак того, что связь на щедром запасе установилась
		bool complete = false;
		/**
		 * Выполняем перебор запасов выделений
		 */
		for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны с подлинностью клиента
			arrange(client, server, STARVING[s], extension::group_t::SECP256R1, credential, true);
			// Клиент ведёт лишь издание 1.2
			client.versions(0x0303, 0x0303);
			// Ошибки сторон
			context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
			{
				// Ограничиваем запас выделений
				starve::ration_t ration(budget);
				// Заводим сервер
				first = server.start();
				// Заводим клиента
				second = client.start();
				// Если стороны заведены
				if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
					// Проводим рукопожатие
					converse(client, server);
					// Ошибки сторон после рукопожатия
					first = server.error();
					// Ошибка клиента
					second = client.error();
				}
			}
			// Запоминаем нехватку памяти
			starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
			/**
			 * Дозволенные исходы: успех, нехватка памяти либо обрыв собеседником с внутренним
			 * извещением о его нехватке памяти
			 */
			const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
				((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
			// Проверяем законность исхода
			ASSERT_TRUE(lawful) << "набор " << s << " запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
			// Запоминаем установление связи
			complete = (client.established() && server.established() && (client.version() == 0x0303));
		}
		// Проверяем, что нехватка памяти встретилась
		ASSERT_TRUE(starved) << "набор " << s;
		// Проверяем, что на щедром запасе связь установилась
		ASSERT_TRUE(complete) << "набор " << s;
	}
}

/**
 * Проверка издания в заголовке записи: за согласованием издания 1.2 запись с иным изданием
 * заголовка отвергается protocol_version - защищённая у сервера и открытая у клиента
 * (приложение E.1 RFC 5246); а издание заголовка входит в связанные данные защищённой
 * записи по проводу (раздел 6.2.3.3), и подмена заголовка рвёт метку целостности у самой
 * защиты записей, не доходя до движка
 */
TEST(Tls12Test, Versioned){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов AES-GCM и ChaCha20-Poly1305
	 */
	for(size_t item = 0; item < 2; item++){
		// Набор шифрования круга
		const protect::suite_t suite = ((item == 0) ? protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256 : protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256);
		{
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны
			arrange(client, server, suite, extension::group_t::SECP256R1, credential, false);
			// Клиент ведёт лишь издание 1.2
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Проводим рукопожатие
			converse(client, server);
			// Связь установлена
			ASSERT_TRUE(client.established() && server.established());
			// Прикладные данные
			const string request = "Запись с подменённым изданием заголовка";
			// Отправляем данные
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Запись клиента
			const view_t data = client.output();
			// Переносим запись
			vector <uint8_t> forged(data.data, data.data + data.size);
			// Снимаем запись
			client.consume(forged.size());
			// Подменяем издание заголовка на TLS 1.0
			forged[2] = 0x01;
			// Сервер отвергает запись несовпадением издания заголовка
			ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::VERSION) << item;
			// Извещение protocol_version
			ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
			// Связь оборвана
			ASSERT_EQ(server.state(), context::state_t::FAILED);
		}
		{
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны
			arrange(client, server, suite, extension::group_t::SECP256R1, credential, false);
			// Клиент ведёт лишь издание 1.2
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Проводим рукопожатие
			converse(client, server);
			// Связь установлена
			ASSERT_TRUE(client.established() && server.established());
			// Прикладные данные
			const string request = "Запись с изданием заголовка вне реестра";
			// Отправляем данные
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Запись клиента
			const view_t data = client.output();
			// Переносим запись
			vector <uint8_t> forged(data.data, data.data + data.size);
			// Снимаем запись
			client.consume(forged.size());
			// Подменяем издание заголовка на неведомое протоколу
			forged[1] = 0x99;
			// Младший байт издания
			forged[2] = 0x99;
			// Сборщик записей издания заголовка не судит: неведомое издание отвергает движок сличением с 0x0303
			ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::VERSION) << item;
			// Извещение protocol_version
			ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
		}
		{
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны
			arrange(client, server, suite, extension::group_t::SECP256R1, credential, false);
			// Сервер ведёт лишь издание 1.2
			ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Записи залпа сервера
			vector <vector <uint8_t>> pieces;
			// Получаем залп сервера
			ASSERT_TRUE(volley(client, server, pieces));
			// В залпе приветствие, цепочка, обмен ключами и конец приветствия
			ASSERT_EQ(pieces.size(), static_cast <size_t> (4));
			// Подменяем издание заголовка цепочки сертификатов на TLS 1.1: приветствие сервера уже прошло
			pieces[1][2] = 0x02;
			// Поток залпа
			vector <uint8_t> wire;
			// Собираем поток
			join(pieces, wire);
			// Клиент отвергает запись несовпадением издания заголовка
			ASSERT_EQ(client.push(view_t(wire.data(), wire.size())), context::error_t::VERSION) << item;
			// Извещение protocol_version
			ASSERT_EQ(client.alert().description, alert::description_t::VERSION);
			// Издание 1.2 к тому мигу согласовано приветствием сервера
			ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
		}
		{
			// Ключ защиты записей проверки
			const vector <uint8_t> key(protect::key(suite), 0x4B);
			// Вектор замены защиты записей проверки
			const vector <uint8_t> salt(protect::block(suite), 0x56);
			// Защита отправляемых записей
			protect::protection_t sealing;
			// Устанавливаем ключевой материал
			ASSERT_TRUE(sealing.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size())));
			// Защищаемое содержимое
			const string text = "Связанные данные несут издание заголовка по проводу";
			// Защищённая запись
			vector <uint8_t> sealed;
			// Накладываем защиту
			ASSERT_EQ(sealing.seal(record::type_t::APPLICATION, view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), sealed, 0), protect::error_t::NONE);
			// Заголовок защищённой записи
			record::header_t header;
			// Разбираем заголовок
			ASSERT_EQ(record::parse(view_t(sealed.data(), sealed.size()), header), record::error_t::NONE);
			// Заголовок несёт издание 1.2
			ASSERT_EQ(header.version, record::version_t::TLS12);
			// Содержимое защищённой записи
			const view_t payload(sealed.data() + record::RECORD_HEADER, header.size);
			/**
			 * Выполняем три круга снятия защиты: заголовок как есть, с подменённым изданием,
			 * с подменённым видом; всякий круг свежей защитой, ибо порядковый номер один
			 */
			for(size_t round = 0; round < 3; round++){
				// Защита принимаемых записей
				protect::protection_t opening;
				// Устанавливаем тот же ключевой материал
				ASSERT_TRUE(opening.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size())));
				// Заголовок круга
				record::header_t forged = header;
				// На втором круге подменяем издание заголовка
				if(round == 1)
					// Издание TLS 1.0
					forged.version = record::version_t::TLS10;
				// На третьем круге подменяем вид содержимого
				else if(round == 2)
					// Вид рукопожатия
					forged.type = record::type_t::HANDSHAKE;
				// Вид открытого содержимого
				record::type_t type = record::type_t::NONE;
				// Открытое содержимое
				vector <uint8_t> opened;
				// Итог снятия защиты
				const protect::error_t outcome = opening.open(forged, payload, type, opened);
				// Заголовок как есть сходится, подменённый - рвёт метку целостности
				ASSERT_EQ(outcome, ((round == 0) ? protect::error_t::NONE : protect::error_t::TAG)) << item << " " << round;
				// На первом круге содержимое то же (скобки: ASSERT_* сам раскрывается в if/else)
				if(round == 0){
					// Сличаем содержимое
					ASSERT_EQ(string(opened.begin(), opened.end()), text);
				}
			}
		}
	}
}

/**
 * Проверка привязки ключей к переписке расширенным главным секретом (раздел 4 RFC 7627):
 * приветствие сервера с подменённым по дороге опознавателем связи разводит переписки
 * сторон, главные секреты выводятся от разных хешей переписки, и завершение клиента у
 * сервера не снимается - bad_record_mac и обрыв; сверку самого завершения при верных
 * ключах закрепляет Tls12Test.Counterfeit
 */
TEST(Tls12Test, Divergent){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Сервер ведёт лишь издание 1.2
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Записи залпа сервера
	vector <vector <uint8_t>> pieces;
	// Получаем залп сервера
	ASSERT_TRUE(volley(client, server, pieces));
	// В залпе четыре записи
	ASSERT_EQ(pieces.size(), static_cast <size_t> (4));
	// Приветствие сервера: заголовок записи, обвязка, издание, случайное значение, пустой опознаватель
	ASSERT_EQ(pieces[0][5 + 4 + 2 + 32], 0x00);
	// Вклиниваем опознаватель связи из одного байта: клиент опознаватель не толкует и примет
	pieces[0].insert(pieces[0].begin() + 5 + 4 + 2 + 32 + 1, static_cast <uint8_t> (0x5A));
	// Длина опознавателя
	pieces[0][5 + 4 + 2 + 32] = 0x01;
	// Правим длины записи и сообщения
	lengthen(pieces[0], 1);
	// Поток залпа
	vector <uint8_t> wire;
	// Собираем поток
	join(pieces, wire);
	// Клиент принимает подменённый залп и отвечает обменом ключами, сменой набора и завершением
	ASSERT_EQ(client.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
	// Клиент связь не рвал
	ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
	// Передаём ответ клиента серверу
	ASSERT_TRUE(deliver(client, server));
	// Ключи клиента выведены от иного хеша переписки: завершение у сервера не снимается
	ASSERT_EQ(server.error(), context::error_t::PROTECTION);
	// Извещение bad_record_mac
	ASSERT_EQ(server.alert().description, alert::description_t::MAC);
	// Связь оборвана
	ASSERT_EQ(server.state(), context::state_t::FAILED);
	// Извещение дошло до клиента
	converse(client, server);
	// Клиент оборван извещением собеседника
	ASSERT_EQ(client.error(), context::error_t::ALERT);
	// Связь не установлена ни одной стороной
	ASSERT_FALSE(client.established() || server.established());
}

/**
 * Проверка явной части одноразового значения AES-GCM (раздел 3 RFC 5288): в своих записях
 * она равна порядковому номеру и растёт на единицу; повтор записи отвергается bad_record_mac
 * порядковым номером в связанных данных - как у AES-GCM, так и у ChaCha20-Poly1305 (RFC 7905)
 */
TEST(Tls12Test, Nonce){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов AES-GCM и ChaCha20-Poly1305
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, ((item == 0) ? protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384 : protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256), extension::group_t::X25519, credential, false);
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// Первая запись прикладных данных клиента
		vector <uint8_t> first;
		// Явная часть предыдущей записи
		uint64_t previous = 0;
		/**
		 * Выполняем отправку четырёх записей подряд
		 */
		for(size_t i = 0; i < 4; i++){
			// Порядковый номер записи до отправки
			const uint64_t expected = client.sequence();
			// Прикладные данные
			const string request = "Запись " + std::to_string(i);
			// Отправляем данные
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Запись клиента
			const view_t data = client.output();
			// Переносим запись
			const vector <uint8_t> wire(data.data, data.data + data.size);
			// Снимаем запись
			client.consume(wire.size());
			// Запись длиннее заголовка и явной части
			ASSERT_GT(wire.size(), static_cast <size_t> (record::RECORD_HEADER + 8));
			// Если набор AES-GCM: явная часть идёт первыми восемью байтами содержимого
			if(item == 0){
				// Явная часть одноразового значения
				uint64_t nonce = 0;
				/**
				 * Выполняем чтение явной части от старшего байта к младшему
				 */
				for(size_t j = 0; j < 8; j++)
					// Добавляем очередной байт
					nonce = ((nonce << 8) | wire[record::RECORD_HEADER + j]);
				// Явная часть равна порядковому номеру записи
				ASSERT_EQ(nonce, expected) << i;
				// Явная часть растёт на единицу (скобки: ASSERT_* сам раскрывается в if/else)
				if(i > 0){
					// Сличаем с предыдущей
					ASSERT_EQ(nonce, previous + 1) << i;
				}
				// Запоминаем явную часть
				previous = nonce;
			}
			// Запоминаем первую запись
			if(i == 0)
				// Переносим запись
				first = wire;
			// Сервер принимает запись
			ASSERT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::NONE) << item << " " << i;
			// Принятые данные
			vector <uint8_t> received;
			// Читаем данные
			ASSERT_EQ(server.read(received), context::error_t::NONE);
			// Данные те же
			ASSERT_EQ(string(received.begin(), received.end()), request);
		}
		// Повтор первой записи: порядковый номер в связанных данных иной, метка не сходится
		ASSERT_EQ(server.push(view_t(first.data(), first.size())), context::error_t::PROTECTION) << item;
		// Извещение bad_record_mac
		ASSERT_EQ(server.alert().description, alert::description_t::MAC);
		// Связь оборвана
		ASSERT_EQ(server.state(), context::state_t::FAILED);
	}
}

/**
 * Проверка исчерпания записей на ключе изданием 1.2: смены ключей у издания нет, и, дойдя
 * своим направлением до порога (ручка renewal в самодеятельном порядке) либо до предела
 * набора, связь шлёт close_notify и отвечает EXHAUSTED; в ручном порядке порог ручки не
 * действует и остаётся предел набора; пределы наборов AES-GCM - 2^24.5 записей
 */
TEST(Tls12Test, Exhausted){
	// Пределы наборов AES-GCM издания 1.2: раздел 5.5 RFC 8446 обосновывает 2^24.5
	static const protect::suite_t GCM[] = {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384};
	/**
	 * Выполняем перебор наборов AES-GCM
	 */
	for(size_t i = 0; i < (sizeof(GCM) / sizeof(GCM[0])); i++)
		// Предел набора равен 2^24.5 записей
		ASSERT_EQ(protect::limit(GCM[i]), static_cast <uint64_t> (23726566)) << i;
	// Предел ChaCha20-Poly1305 много шире: одноразовое значение там не повторяется до переполнения
	ASSERT_GT(protect::limit(protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256), static_cast <uint64_t> (23726566));
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем два круга: порог ручки в самодеятельном порядке и в ручном
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Порог в три записи: самодеятельный порядок на первом круге, ручной - на втором
		client.renewal(item == 0, 3);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// Счётчик записей клиента: одно завершение рукопожатия
		ASSERT_EQ(client.sequence(), static_cast <uint64_t> (1));
		// Прикладные данные
		const string request = "Запись до порога";
		/**
		 * Выполняем отправку записей до порога: вторая и третья проходят
		 */
		for(size_t i = 0; i < 2; i++)
			// Отправляем данные
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE) << item << " " << i;
		// Счётчик дошёл до порога
		ASSERT_EQ(client.sequence(), static_cast <uint64_t> (3));
		// Передаём записи серверу
		converse(client, server);
		// Сервер принял записи без отказа
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// Если порядок самодеятельный: четвёртая запись за порогом
		if(item == 0){
			// Отправка отвергается исчерпанием записей на ключе
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::EXHAUSTED);
			// Связь закрыта своей стороной
			ASSERT_EQ(client.state(), context::state_t::CLOSED);
			// Ушедшие байты
			const view_t closing = client.output();
			// Ушло извещение: вид записи в заголовке открыт
			ASSERT_GT(closing.size, record::RECORD_HEADER);
			// Запись извещения
			ASSERT_EQ(closing.data[0], 0x15);
			// Передаём закрытие серверу
			converse(client, server);
			// Сервер принял close_notify и ответил своим
			ASSERT_EQ(server.state(), context::state_t::CLOSED);
			// Отказа у сервера нет
			ASSERT_EQ(server.error(), context::error_t::NONE);
			// Дальнейшая отправка отвергается состоянием
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::STATE);
		// Если порядок ручной: порог ручки не действует, остаётся предел набора
		} else {
			/**
			 * Выполняем отправку записей за порогом ручки
			 */
			for(size_t i = 0; i < 3; i++)
				// Отправка проходит
				ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE) << i;
			// Связь по-прежнему установлена
			ASSERT_TRUE(client.established());
			// Передаём записи серверу
			converse(client, server);
			// Принятые сервером данные
			vector <uint8_t> received;
			// Снимаем принятое, чтобы обмен ниже сличал лишь своё
			ASSERT_EQ(server.read(received), context::error_t::NONE);
			// Пять записей по одному запросу
			ASSERT_EQ(received.size(), request.size() * 5);
			// Обмен данными сходится
			ASSERT_TRUE(barter(client, server));
		}
	}
}

/**
 * Проверка предела длины защищённой записи издания 1.2 (раздел 6.2.3 RFC 5246): запись в
 * 2^14 + 2048 байтов проходит сборщик записей и отвергается уже защитой как негодная
 * (bad_record_mac), запись в 2^14 + 2049 байтов - record_overflow
 */
TEST(Tls12Test, Oversize){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем два круга: на пределе и за пределом
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// Длина содержимого записи: предел либо предел плюс один
		const size_t length = (record::RECORD_PROTECTED + item);
		// Предел равен 2^14 + 2048
		ASSERT_EQ(record::RECORD_PROTECTED, static_cast <size_t> (16384 + 2048));
		// Запись прикладных данных с заголовком
		vector <uint8_t> wire(record::RECORD_HEADER + length, 0x00);
		// Вид содержимого
		wire[0] = 0x17;
		// Издание заголовка
		wire[1] = 0x03;
		// Младший байт издания
		wire[2] = 0x03;
		// Старший байт длины
		wire[3] = static_cast <uint8_t> ((length >> 8) & 0xFF);
		// Младший байт длины
		wire[4] = static_cast <uint8_t> (length & 0xFF);
		// Подаём запись серверу
		const context::error_t outcome = server.push(view_t(wire.data(), wire.size()));
		// На пределе запись доходит до защиты и отвергается ею, за пределом - сборщиком записей
		ASSERT_EQ(outcome, ((item == 0) ? context::error_t::PROTECTION : context::error_t::RECORD)) << item;
		// Извещение: bad_record_mac на пределе, record_overflow за ним
		ASSERT_EQ(server.alert().description, ((item == 0) ? alert::description_t::MAC : alert::description_t::OVERSIZE)) << item;
	}
}

/**
 * Проверка заслонов на подделанных руками сообщениях рукопожатия: сжатая точка и схема вне
 * перечня клиента в ServerKeyExchange - illegal_parameter; CertificateStatus без запроса -
 * unexpected_message; session_id длиннее 32 байтов - decode_error; непустое
 * renegotiation_info на первом рукопожатии в приветствии сервера и клиента -
 * handshake_failure; смена набора шифрования не в свой черёд - unexpected_message;
 * CertificateVerify за пустой цепочкой клиента - unexpected_message; сжатая точка в
 * ClientKeyExchange - illegal_parameter
 */
TEST(Tls12Test, Forged){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор подделок залпа сервера у клиента
	 */
	for(size_t item = 0; item < 5; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, false);
		// Схема подписи клиента одна: сервер подпишет ею
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256});
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Записи залпа сервера
		vector <vector <uint8_t>> pieces;
		// Получаем залп сервера
		ASSERT_TRUE(volley(client, server, pieces));
		// В залпе приветствие, цепочка, обмен ключами и конец приветствия
		ASSERT_EQ(pieces.size(), static_cast <size_t> (4));
		// Ожидаемый отказ
		context::error_t error = context::error_t::NONE;
		// Ожидаемое извещение
		alert::description_t description = alert::description_t::INTERNAL;
		/**
		 * Выполняем подделку залпа
		 */
		switch(item){
			// Сжатая точка в ServerKeyExchange: раздел 5.4 RFC 8422
			case 0: {
				// Обмен ключами: заголовок записи, обвязка, вид параметров, кривая, длина точки, точка
				ASSERT_EQ(pieces[2][5 + 4], 0x03);
				// Точка несжатая
				ASSERT_EQ(pieces[2][5 + 4 + 3 + 1], 0x04);
				// Подменяем запись точки на сжатую
				pieces[2][5 + 4 + 3 + 1] = 0x02;
				// Отказ обмена ключами
				error = context::error_t::EXCHANGE;
				// Извещение illegal_parameter
				description = alert::description_t::PARAMETER;
			} break;
			// Схема вне перечня клиента в ServerKeyExchange: раздел 7.4.1.4.1 RFC 5246
			case 1: {
				// Длина точки
				const size_t width = pieces[2][5 + 4 + 3];
				// Схема подписи идёт за точкой: ecdsa_secp256r1_sha256
				ASSERT_EQ(pieces[2][5 + 4 + 3 + 1 + width], 0x04);
				// Младший байт схемы
				ASSERT_EQ(pieces[2][5 + 4 + 3 + 1 + width + 1], 0x03);
				// Подменяем схему на ecdsa_secp384r1_sha384, клиентом не предложенную
				pieces[2][5 + 4 + 3 + 1 + width] = 0x05;
				// Отказ схемы подписи
				error = context::error_t::SCHEME;
				// Извещение illegal_parameter
				description = alert::description_t::PARAMETER;
			} break;
			// CertificateStatus без запроса: раздел 8 RFC 6066
			case 2: {
				// Тело состояния сертификата: вид ocsp и ответ из одного байта
				static const uint8_t status[5] = {0x01, 0x00, 0x00, 0x01, 0x00};
				// Запись состояния
				vector <uint8_t> record;
				// Составляем запись
				ASSERT_TRUE(framed(handshake::type_t::STATUS, view_t(status, sizeof(status)), record));
				// Вклиниваем состояние за цепочкой
				pieces.insert(pieces.begin() + 2, record);
				// Отказ сообщения не в свой черёд
				error = context::error_t::ORDER;
				// Извещение unexpected_message
				description = alert::description_t::UNEXPECTED;
			} break;
			// Опознаватель связи длиннее 32 байтов: раздел 7.4.1.3 RFC 5246
			case 3: {
				// Опознаватель пуст
				ASSERT_EQ(pieces[0][5 + 4 + 2 + 32], 0x00);
				// Вклиниваем опознаватель из 33 байтов
				pieces[0].insert(pieces[0].begin() + 5 + 4 + 2 + 32 + 1, static_cast <size_t> (33), static_cast <uint8_t> (0x5A));
				// Длина опознавателя
				pieces[0][5 + 4 + 2 + 32] = 33;
				// Правим длины
				lengthen(pieces[0], 33);
				// Отказ разбора
				error = context::error_t::MESSAGE;
				// Извещение decode_error
				description = alert::description_t::DECODE;
			} break;
			// Непустое renegotiation_info в приветствии сервера: раздел 3.4 RFC 5746
			case 4: {
				// Расширение renegotiation_info с пустым перечнем
				static const uint8_t empty[5] = {0xFF, 0x01, 0x00, 0x01, 0x00};
				// Ищем расширение в приветствии сервера
				const auto found = std::search(pieces[0].begin(), pieces[0].end(), empty, empty + sizeof(empty));
				// Расширение найдено
				ASSERT_NE(found, pieces[0].end());
				// Подменяем длину перечня: перечень стал непустым при той же длине тела
				*(found + 4) = 0x01;
				// Отказ разбора
				error = context::error_t::MESSAGE;
				// Извещение handshake_failure
				description = alert::description_t::HANDSHAKE;
			} break;
		}
		// Поток залпа
		vector <uint8_t> wire;
		// Собираем поток
		join(pieces, wire);
		// Клиент отвергает подделанный залп
		ASSERT_EQ(client.push(view_t(wire.data(), wire.size())), error) << item;
		// Извещение
		ASSERT_EQ(client.alert().description, description) << item;
		// Связь оборвана
		ASSERT_EQ(client.state(), context::state_t::FAILED) << item;
	}
	/**
	 * Выполняем перебор подделок у сервера
	 */
	for(size_t item = 0; item < 4; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны без подлинности клиента
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, false);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// На круге подписи владения сервер запрашивает подлинность, а у клиента её нет
		server.request(item == 1);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Ожидаемый отказ
		context::error_t error = context::error_t::NONE;
		// Ожидаемое извещение
		alert::description_t description = alert::description_t::INTERNAL;
		// Подаваемый серверу поток
		vector <uint8_t> wire;
		/**
		 * Выполняем подделку
		 */
		switch(item){
			// Смена набора шифрования сразу за приветствием клиента: раздел 7.1 RFC 5246
			case 0: {
				// Передаём приветствие клиента
				ASSERT_TRUE(deliver(client, server));
				// Запись смены набора шифрования
				wire = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
				// Отказ записи
				error = context::error_t::RECORD;
				// Извещение unexpected_message
				description = alert::description_t::UNEXPECTED;
			} break;
			// CertificateVerify за пустой цепочкой клиента: раздел 7.4.8 RFC 5246
			case 1: {
				// Передаём приветствия и залп сервера
				ASSERT_TRUE(pump(client, server));
				// Записи ответа клиента
				vector <vector <uint8_t>> pieces;
				// Нарезаем ответ клиента: пустая цепочка, обмен ключами, смена набора, завершение
				ASSERT_TRUE(slice(client.output(), pieces));
				// Четыре записи
				ASSERT_EQ(pieces.size(), static_cast <size_t> (4));
				// Тело подписи владения: схема и подпись из одного байта
				static const uint8_t verify[5] = {0x04, 0x03, 0x00, 0x01, 0x00};
				// Запись подписи владения
				vector <uint8_t> record;
				// Составляем запись
				ASSERT_TRUE(framed(handshake::type_t::VERIFY, view_t(verify, sizeof(verify)), record));
				// Вклиниваем подпись владения за обменом ключами
				pieces.insert(pieces.begin() + 2, record);
				// Собираем поток
				join(pieces, wire);
				// Отказ сообщения не в свой черёд
				error = context::error_t::ORDER;
				// Извещение unexpected_message
				description = alert::description_t::UNEXPECTED;
			} break;
			// Сжатая точка в ClientKeyExchange: раздел 5.7 RFC 8422
			case 2: {
				// Передаём приветствия и залп сервера
				ASSERT_TRUE(pump(client, server));
				// Записи ответа клиента
				vector <vector <uint8_t>> pieces;
				// Нарезаем ответ клиента: обмен ключами, смена набора, завершение
				ASSERT_TRUE(slice(client.output(), pieces));
				// Три записи
				ASSERT_EQ(pieces.size(), static_cast <size_t> (3));
				// Обмен ключами: заголовок записи, обвязка, длина точки, точка несжатая
				ASSERT_EQ(pieces[0][5 + 4 + 1], 0x04);
				// Подменяем запись точки на сжатую
				pieces[0][5 + 4 + 1] = 0x02;
				// Собираем поток
				join(pieces, wire);
				// Отказ обмена ключами
				error = context::error_t::EXCHANGE;
				// Извещение illegal_parameter
				description = alert::description_t::PARAMETER;
			} break;
			// Непустое renegotiation_info в приветствии клиента: раздел 3.6 RFC 5746
			case 3: {
				// Составляем приветствие чужого клиента с непустым расширением
				ASSERT_TRUE(greeting(true, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, wire, true, extension::group_t::SECP256R1));
				// Отказ разбора
				error = context::error_t::MESSAGE;
				// Извещение handshake_failure
				description = alert::description_t::HANDSHAKE;
			} break;
		}
		// Сервер отвергает подделку
		ASSERT_EQ(server.push(view_t(wire.data(), wire.size())), error) << item;
		// Извещение
		ASSERT_EQ(server.alert().description, description) << item;
		// Связь оборвана
		ASSERT_EQ(server.state(), context::state_t::FAILED) << item;
	}
}

/**
 * Проверка сверки завершения рукопожатия (раздел 7.4.9 RFC 5246) поддельным клиентом,
 * собранным из открытых примитивов: приветствие руками, обмен X25519, расширенный главный
 * секрет по хешу переписки (RFC 7627), ключевой материал по разделу 6.3 и защита записей
 * своими ключами. Верное завершение сервер принимает - так доказана сама выработка, - а
 * завершение с испорченным байтом отвергает decrypt_error; заслон этот ловит снятую сверку
 */
TEST(Tls12Test, Counterfeit){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Набор шифрования круга
	const protect::suite_t suite = protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256;
	/**
	 * Выполняем два круга: завершение верное и завершение порченое
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны сервера
		server::context_t server;
		// Набор сервера
		server.suites(vector <protect::suite_t> {suite});
		// Группа сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность сервера
		server.credential(credential);
		// Сервер ведёт лишь издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Запись приветствия поддельного клиента: случайное значение в нём - байты 0…31
		vector <uint8_t> hello;
		// Составляем приветствие с расширенным главным секретом по группе X25519
		ASSERT_TRUE(greeting(true, suite, hello, false, extension::group_t::X25519));
		// Переписка рукопожатия: сообщения без заголовков записей
		vector <uint8_t> transcript(hello.begin() + record::RECORD_HEADER, hello.end());
		// Случайное значение клиента: переносится, ибо переписка растёт и переезжает в памяти
		const vector <uint8_t> clientRandom(transcript.begin() + 4 + 2, transcript.begin() + 4 + 2 + 32);
		// Подаём приветствие серверу
		ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE) << static_cast <int> (server.alert().description);
		// Залп сервера
		const view_t flight = server.output();
		// Записи залпа
		vector <vector <uint8_t>> pieces;
		// Нарезаем залп
		ASSERT_TRUE(slice(flight, pieces));
		// Снимаем залп
		server.consume(flight.size);
		// В залпе приветствие, цепочка, обмен ключами и конец приветствия
		ASSERT_EQ(pieces.size(), static_cast <size_t> (4));
		/**
		 * Выполняем перенос сообщений залпа в переписку
		 */
		for(size_t i = 0; i < pieces.size(); i++)
			// Добавляем сообщение без заголовка записи
			transcript.insert(transcript.end(), pieces[i].begin() + record::RECORD_HEADER, pieces[i].end());
		// Случайное значение сервера: обвязка, издание, случайное значение
		const vector <uint8_t> serverRandom(pieces[0].begin() + 5 + 4 + 2, pieces[0].begin() + 5 + 4 + 2 + 32);
		// Обмен ключами сервера: именованная кривая X25519
		ASSERT_EQ(pieces[2][5 + 4], 0x03);
		// Старший байт кривой
		ASSERT_EQ(pieces[2][5 + 4 + 1], 0x00);
		// Младший байт кривой: X25519
		ASSERT_EQ(pieces[2][5 + 4 + 2], 0x1D);
		// Длина точки сервера
		ASSERT_EQ(pieces[2][5 + 4 + 3], 32);
		// Точка сервера
		const view_t serverPoint(pieces[2].data() + 5 + 4 + 3 + 1, 32);
		// Секретный ключ поддельного клиента
		vector <uint8_t> secret(agreement::X25519_SIZE, 0x11);
		// Открытая часть ключа поддельного клиента
		uint8_t opened[agreement::X25519_SIZE];
		// Вырабатываем открытую часть
		ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), opened));
		// Общее значение обмена
		uint8_t premaster[agreement::X25519_SIZE];
		// Вырабатываем общее значение
		ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), serverPoint, premaster));
		// Тело обмена ключами клиента: длина точки и точка
		vector <uint8_t> body = {static_cast <uint8_t> (agreement::X25519_SIZE)};
		// Добавляем точку
		body.insert(body.end(), opened, opened + sizeof(opened));
		// Запись обмена ключами клиента
		vector <uint8_t> exchange;
		// Составляем запись
		ASSERT_TRUE(framed(handshake::type_t::PREMASTER, view_t(body.data(), body.size()), exchange));
		// Добавляем обмен ключами в переписку
		transcript.insert(transcript.end(), exchange.begin() + record::RECORD_HEADER, exchange.end());
		// Хеш переписки по обмен ключами клиента включительно
		uint8_t session[32];
		// Вычисляем хеш переписки
		ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(transcript.data(), transcript.size()), session, sizeof(session)));
		// Метка расширенного главного секрета
		const char * extended = "extended master secret";
		// Главный секрет
		uint8_t master[48];
		// Раздел 4 RFC 7627: главный секрет от общего значения меткой и хешем переписки
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(premaster, sizeof(premaster)), view_t(reinterpret_cast <const uint8_t *> (extended), ::strlen(extended)), view_t(session, sizeof(session)), master, sizeof(master)));
		// Затравка ключевого материала: случайные значения сервера и клиента
		vector <uint8_t> seed(serverRandom);
		// Добавляем случайное значение клиента
		seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
		// Метка ключевого материала
		const char * expansion = "key expansion";
		// Ключевой материал: ключи по 16 байтов и соли по 4 байта обеих сторон
		uint8_t material[(16 + 4) * 2];
		// Раздел 6.3 RFC 5246: ключевой материал от главного секрета меткой и затравкой
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (expansion), ::strlen(expansion)), view_t(seed.data(), seed.size()), material, sizeof(material)));
		// Метка завершения клиента
		const char * label = "client finished";
		// Хеш переписки для завершения
		uint8_t digested[32];
		// Вычисляем хеш переписки
		ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(transcript.data(), transcript.size()), digested, sizeof(digested)));
		// Завершение рукопожатия
		uint8_t completion[12];
		// Раздел 7.4.9 RFC 5246: двенадцать байтов от главного секрета меткой стороны
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(digested, sizeof(digested)), completion, sizeof(completion)));
		// На втором круге портим завершение
		if(item == 1)
			// Меняем один разряд
			completion[0] = static_cast <uint8_t> (completion[0] ^ 0x01);
		// Составитель сообщения завершения
		handshake::writer_t writer;
		// Составляем сообщение завершения
		ASSERT_EQ(writer.push(handshake::type_t::FINISHED, view_t(completion, sizeof(completion))), handshake::error_t::NONE);
		// Защита записей поддельного клиента: ключ клиента идёт первым, соль клиента - третьей
		protect::protection_t sealing;
		// Устанавливаем ключевой материал клиента
		ASSERT_TRUE(sealing.start(suite, view_t(material, 16), view_t(material + 32, 4)));
		// Поток к серверу: обмен ключами открытой записью
		vector <uint8_t> wire(exchange);
		// Смена набора шифрования
		static const uint8_t change[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
		// Добавляем смену набора
		wire.insert(wire.end(), change, change + sizeof(change));
		// Защищённая запись завершения
		vector <uint8_t> sealed;
		// Накладываем защиту своими ключами
		ASSERT_EQ(sealing.seal(record::type_t::HANDSHAKE, writer.data(), sealed, 0), protect::error_t::NONE);
		// Добавляем завершение
		wire.insert(wire.end(), sealed.begin(), sealed.end());
		// Итог подачи потока серверу
		const context::error_t outcome = server.push(view_t(wire.data(), wire.size()));
		// Если завершение верное
		if(item == 0){
			// Сервер принял завершение: выработка сошлась с движком
			ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (server.alert().description);
			// Связь установлена
			ASSERT_TRUE(server.established());
			// Сервер ответил сменой набора и своим завершением
			ASSERT_GT(server.output().size, static_cast <size_t> (6 + record::RECORD_HEADER + 12));
		// Если завершение порченое
		} else {
			// Сервер отверг завершение несхождением
			ASSERT_EQ(outcome, context::error_t::COMPLETION);
			// Извещение decrypt_error
			ASSERT_EQ(server.alert().description, alert::description_t::DECRYPT);
			// Связь оборвана
			ASSERT_EQ(server.state(), context::state_t::FAILED);
		}
	}
}

/**
 * Проверка векторов рукопожатий TLS 1.2, снятых с настоящего openssl: наш сервер против
 * записанного ClientHello каждого издания и сценария выбирает тот же набор и ту же группу,
 * что и s_server, отвечает handshake_failure без расширенного главного секрета и без
 * общего набора (CBC)
 */
TEST(Tls12Test, VectorServer){
	// Число проверенных векторов
	size_t verified = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к каталогу вектора
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если каталога вектора нет
			if(!exists(path)){
				// Отсутствие вектора допустимо лишь там, где openssl ключа не имел
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Сообщаем о пропуске явно
				std::cout << "OpenSSL " << EDITIONS[e] << " без -no_ems: вектор " << SCENARIOS[s].name << " не снят, пропуск" << std::endl;
				// Переходим к следующему сценарию
				continue;
			}
			// Сведения о векторе из описания
			brief_t brief;
			// Описание обязано разобраться
			ASSERT_TRUE(describe(path, brief)) << path;
			// Набор описания обязан совпасть с ожидаемым сценарием
			ASSERT_EQ(brief.suite, SCENARIOS[s].suite) << path;
			// Признак расширенного главного секрета описания обязан совпасть со сценарием
			ASSERT_EQ(brief.master, SCENARIOS[s].master) << path;
			// Поток клиента по проводу
			stream_t stream;
			// Поток обязан разобраться: непустой файл ещё не рукопожатие
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), stream, true)) << path;
			// Первое сообщение клиента обязано быть ClientHello
			ASSERT_EQ(kind(stream.messages[0]), handshake::type_t::CLIENT) << path;
			// Нарезанный ClientHello обязан совпасть с сообщением на проводе
			ASSERT_EQ(slurp(path + "/client-clienthello.bin"), stream.messages[0]) << path;
			// Поток по проводу целиком
			const vector <uint8_t> wire = slurp(path + "/handshake-c2s.bin");
			// Заголовок первой записи по проводу
			record::header_t header;
			// Первая запись обязана разобраться
			ASSERT_EQ(record::parse(view_t(wire.data(), wire.size()), header), record::error_t::NONE) << path;
			// Первая запись по проводу с ClientHello
			const vector <uint8_t> first(wire.begin(), wire.begin() + record::RECORD_HEADER + header.size);
			// Ожидаемый ServerHello настоящего openssl
			const vector <uint8_t> expected = slurp(path + "/serverhello.bin");
			// Приветствие настоящего сервера
			hello::server_t theirs;
			// Приветствие настоящего сервера обязано разобраться
			ASSERT_EQ(hello::parse(inner(expected), theirs), hello::error_t::NONE) << path;
			// Настоящий сервер обязан был выбрать набор описания
			ASSERT_EQ(theirs.suite, SCENARIOS[s].suite) << path;
			// Подлинность нашего сервера тем же сертификатом
			context::credential_t credential;
			// Подлинность обязана составиться
			ASSERT_TRUE(identity(brief.key.c_str(), credential)) << path;
			/**
			 * Выполняем перебор пределов изданий: только 1.2 и 1.2…1.3
			 */
			for(size_t v = 0; v < 2; v++){
				// Наш сервер
				server::context_t server;
				// Устанавливаем пределы изданий
				ASSERT_EQ(server.versions(0x0303, ((v == 0) ? 0x0303 : 0x0304)), context::error_t::NONE);
				// Устанавливаем подлинность
				server.credential(credential);
				// Устанавливаем все три группы: выбор обязан пасть на группу описания
				server.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
				// Если сценарий про порядок наборов
				if(::strncmp(SCENARIOS[s].name, "preference-", 11) == 0)
					// Устанавливаем наборы порядком s_server из описания
					server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
				// Если сценарий про набор CBC: наборы связи остаются умолчанием, второй круг его несёт
				else if(SCENARIOS[s].suite == 0xC023)
					// Выбор порядком сервера
					server.preference(true);
				// Иначе набор один
				else
					// Устанавливаем набор сценария
					server.suites(vector <protect::suite_t> {static_cast <protect::suite_t> (SCENARIOS[s].suite)});
				// Устанавливаем порядок выбора набора
				server.preference(SCENARIOS[s].preference);
				// Если подлинность взаимная
				if(SCENARIOS[s].mutual)
					// Требуем сертификат клиента
					server.request(true);
				// Заводим связь
				ASSERT_EQ(server.start(), context::error_t::NONE) << path;
				// Подаём записанный ClientHello как запись по проводу
				(void) server.push(view_t(first.data(), first.size()));
				// Если сценарий без расширенного главного секрета
				if(!SCENARIOS[s].master){
					// Наш сервер обязан отказать: MASTER и handshake_failure
					ASSERT_EQ(server.error(), context::error_t::MASTER) << path << " предел " << v;
					// Извещение обязано быть handshake_failure
					ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE) << path;
					// Извещение обязано уйти на провод
					ASSERT_GT(server.output().size, static_cast <size_t> (0)) << path;
					// Запись на проводе обязана быть извещением
					ASSERT_EQ(server.output().data[0], 0x15) << path;
					// Переходим к следующему пределу
					continue;
				}
				// Отказа быть не должно: набор CBC 0xC023 вторым кругом ведом связи
				ASSERT_EQ(server.error(), context::error_t::NONE) << path << " предел " << v << " извещение " << static_cast <int> (server.alert().description);
				// Издание обязано быть 1.2
				ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0303)) << path;
				// Набор обязан совпасть с выбором настоящего openssl
				ASSERT_EQ(static_cast <uint16_t> (server.suite()), theirs.suite) << path;
				// Записи ответа нашего сервера
				vector <vector <uint8_t>> records;
				// Ответ обязан нарезаться на записи
				ASSERT_TRUE(slice(server.output(), records)) << path;
				// Ответ нашего сервера как поток
				vector <uint8_t> flight;
				// Собираем ответ
				join(records, flight);
				// Сборщик сообщений ответа
				handshake::reader_t reader;
				// Сообщения ответа
				vector <vector <uint8_t>> messages;
				/**
				 * Выполняем перебор записей ответа
				 */
				for(size_t r = 0; r < records.size(); r++){
					// Всякая запись ответа обязана быть рукопожатием издания 1.2
					ASSERT_EQ(records[r][0], 0x16) << path;
					// Издание заголовка обязано быть 0x0303
					ASSERT_TRUE((records[r][1] == 0x03) && (records[r][2] == 0x03)) << path;
					// Складываем содержимое записи в сборщик сообщений
					ASSERT_EQ(reader.push(view_t(records[r].data() + record::RECORD_HEADER, records[r].size() - record::RECORD_HEADER)), handshake::error_t::NONE) << path;
				}
				// Заголовок сообщения
				handshake::header_t head;
				// Тело сообщения
				view_t body;
				/**
				 * Выполняем перебор сообщений ответа
				 */
				while(reader.next(head, body) == handshake::error_t::NONE){
					// Сообщение целиком
					vector <uint8_t> message(handshake::HANDSHAKE_HEADER + body.size, 0);
					// Складываем заголовок
					ASSERT_EQ(handshake::build(head, message.data()), handshake::error_t::NONE);
					// Переносим тело
					::memcpy(message.data() + handshake::HANDSHAKE_HEADER, body.data, body.size);
					// Запоминаем сообщение
					messages.push_back(message);
				}
				// Ответ обязан начинаться с ServerHello
				ASSERT_FALSE(messages.empty()) << path;
				// Первое сообщение обязано быть ServerHello
				ASSERT_EQ(kind(messages[0]), handshake::type_t::SERVER) << path;
				// Наше приветствие сервера
				hello::server_t ours;
				// Наше приветствие обязано разобраться
				ASSERT_EQ(hello::parse(inner(messages[0]), ours), hello::error_t::NONE) << path;
				// Издание приветствия обязано быть 1.2
				ASSERT_EQ(ours.version, static_cast <uint16_t> (0x0303)) << path;
				// Набор обязан совпасть с выбором настоящего openssl
				ASSERT_EQ(ours.suite, theirs.suite) << path;
				// Сжатие обязано быть нулевым
				ASSERT_EQ(ours.method, 0) << path;
				// Расширенный главный секрет обязан быть подтверждён, как и у openssl
				ASSERT_NE(hello::extension(ours.extensions, static_cast <uint16_t> (extension::type_t::MASTER)), nullptr) << path;
				// Расширенный главный секрет обязан быть и у openssl
				ASSERT_NE(hello::extension(theirs.extensions, static_cast <uint16_t> (extension::type_t::MASTER)), nullptr) << path;
				// Признак безопасного пересогласования обязан быть, как и у openssl
				ASSERT_NE(hello::extension(ours.extensions, static_cast <uint16_t> (extension::type_t::RENEGOTIATION)), nullptr) << path;
				// Цепочка сертификатов обязана быть
				ASSERT_NE(seek(messages, handshake::type_t::CERTIFICATE), nullptr) << path;
				// Обмен ключами сервера
				const vector <uint8_t> * agreement = seek(messages, handshake::type_t::AGREEMENT);
				// Обмен ключами обязан быть
				ASSERT_NE(agreement, nullptr) << path;
				// Разобранный обмен ключами
				exchange_t exchanged;
				// Обмен ключами обязан разобраться
				ASSERT_TRUE(dissect(inner(*agreement), exchanged)) << path;
				// Группа обязана совпасть с выбором настоящего openssl по описанию
				ASSERT_EQ(exchanged.group, brief.group) << path << " группа " << naming(exchanged.group);
				// Запрос сертификата обязан быть ровно при взаимной подлинности
				ASSERT_EQ(seek(messages, handshake::type_t::REQUEST) != nullptr, SCENARIOS[s].mutual) << path;
				// Конец приветствия обязан быть
				ASSERT_EQ(kind(messages.back()), handshake::type_t::DONE) << path;
				// Учитываем проверенный вектор
				verified++;
			}
		}
	}
	// Векторы обязаны были проверяться: 70 каталогов по два предела за вычетом четырёх сценариев без EMS; шесть CBC вторым кругом проверяются
	ASSERT_EQ(verified, static_cast <size_t> ((70 - 4) * 2));
}

/**
 * Проверка векторов рукопожатий TLS 1.2 на стороне клиента: сообщения настоящего s_server
 * разбираются нашими открытыми примитивами - издание, набор, расширенный главный секрет и
 * renegotiation_info по описанию, сертификат из набора, подпись ServerKeyExchange ключом
 * сертификата над случайными значениями и параметрами, а во взаимной подлинности - подпись
 * CertificateVerify клиента над переписью
 */
TEST(Tls12Test, VectorClient){
	// Число проверенных подписей обмена ключами
	size_t signatures = 0;
	// Число проверенных подписей владения ключом клиента
	size_t attestations = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к каталогу вектора
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если каталога вектора нет
			if(!exists(path)){
				// Отсутствие вектора допустимо лишь там, где openssl ключа не имел
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Сообщаем о пропуске явно
				std::cout << "OpenSSL " << EDITIONS[e] << " без -no_ems: вектор " << SCENARIOS[s].name << " не снят, пропуск" << std::endl;
				// Переходим к следующему сценарию
				continue;
			}
			// Сведения о векторе из описания
			brief_t brief;
			// Описание обязано разобраться
			ASSERT_TRUE(describe(path, brief)) << path;
			// Набор описания обязан совпасть с ожидаемым сценарием
			ASSERT_EQ(brief.suite, SCENARIOS[s].suite) << path;
			// Потоки сторон по проводу
			stream_t c2s, s2c;
			// Поток клиента обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), c2s, true)) << path;
			// Поток сервера обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-s2c.bin"), s2c, true)) << path;
			// Нарезанные сообщения обязаны совпасть с сообщениями на проводе
			ASSERT_EQ(slurp(path + "/client-clienthello.bin"), c2s.messages[0]) << path;
			// Приветствие сервера обязано быть первым в потоке сервера
			ASSERT_EQ(slurp(path + "/serverhello.bin"), s2c.messages[0]) << path;
			// Цепочка сертификатов обязана совпасть
			ASSERT_EQ(slurp(path + "/certificate.bin"), *seek(s2c.messages, handshake::type_t::CERTIFICATE)) << path;
			// Обмен ключами обязан совпасть
			ASSERT_EQ(slurp(path + "/serverkeyexchange.bin"), *seek(s2c.messages, handshake::type_t::AGREEMENT)) << path;
			// Конец приветствия обязан совпасть
			ASSERT_EQ(slurp(path + "/serverhellodone.bin"), *seek(s2c.messages, handshake::type_t::DONE)) << path;
			// Обмен ключами клиента обязан совпасть
			ASSERT_EQ(slurp(path + "/client-clientkeyexchange.bin"), *seek(c2s.messages, handshake::type_t::PREMASTER)) << path;
			// Приветствие клиента
			hello::client_t client;
			// Приветствие клиента обязано разобраться
			ASSERT_EQ(hello::parse(inner(c2s.messages[0]), client), hello::error_t::NONE) << path;
			// Клиент обязан был предложить набор сценария
			ASSERT_NE(std::find(client.suites.begin(), client.suites.end(), SCENARIOS[s].suite), client.suites.end()) << path;
			// Клиент обязан был предложить расширенный главный секрет ровно по сценарию
			ASSERT_EQ(hello::extension(client.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr, SCENARIOS[s].master) << path;
			// Приветствие сервера
			hello::server_t server;
			// Приветствие сервера обязано разобраться
			ASSERT_EQ(hello::parse(inner(s2c.messages[0]), server), hello::error_t::NONE) << path;
			// Издание обязано быть 0x0303
			ASSERT_EQ(server.version, static_cast <uint16_t> (0x0303)) << path;
			// Набор обязан быть набором описания
			ASSERT_EQ(server.suite, brief.suite) << path;
			// Сжатие обязано быть нулевым
			ASSERT_EQ(server.method, 0) << path;
			// Расширенный главный секрет обязан быть ровно по описанию
			ASSERT_EQ(hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr, brief.master) << path;
			// Признак безопасного пересогласования
			const hello::extension_t * renegotiation = hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::RENEGOTIATION));
			// Признак обязан быть во всяком сценарии
			ASSERT_NE(renegotiation, nullptr) << path;
			// На первом рукопожатии признак пуст: один байт нулевой длины
			ASSERT_TRUE((renegotiation->data.size == 1) && (renegotiation->data.data[0] == 0)) << path;
			// Сертификат сервера из сообщения
			const view_t der = leaf(inner(*seek(s2c.messages, handshake::type_t::CERTIFICATE)));
			// Сертификат обязан быть
			ASSERT_NE(der.data, nullptr) << path;
			// Подлинность из набора
			context::credential_t credential;
			// Подлинность обязана составиться
			ASSERT_TRUE(identity(brief.key.c_str(), credential)) << path;
			// Сертификат обязан совпасть с сертификатом набора байт в байт
			ASSERT_EQ(vector <uint8_t> (der.data, der.data + der.size), credential.chain[0]) << path;
			// Разобранный сертификат
			x509::certificate_t certificate;
			// Сертификат обязан разобраться
			ASSERT_EQ(certificate.parse(der), x509::error_t::NONE) << path;
			// Разобранный обмен ключами
			exchange_t exchanged;
			// Обмен ключами обязан разобраться
			ASSERT_TRUE(dissect(inner(*seek(s2c.messages, handshake::type_t::AGREEMENT)), exchanged)) << path;
			// Группа обязана совпасть с описанием
			ASSERT_EQ(exchanged.group, brief.group) << path;
			// Схема подписи обязана отвечать ключу сертификата
			if(brief.key == "ec256"){
				// У ECDSA на P-256 схема одна
				ASSERT_EQ(exchanged.scheme, 0x0403) << path;
			// Иначе ключ RSA
			} else {
				// У RSA схема RSASSA-PSS либо PKCS #1 v1.5 с SHA-256
				ASSERT_TRUE((exchanged.scheme == 0x0804) || (exchanged.scheme == 0x0401)) << path << " схема " << std::hex << exchanged.scheme;
			}
			// Подписанное содержимое: client_random ‖ server_random ‖ ECParameters
			vector <uint8_t> content(client.random, client.random + hello::HELLO_RANDOM);
			// Добавляем случайное значение сервера
			content.insert(content.end(), server.random, server.random + hello::HELLO_RANDOM);
			// Добавляем параметры обмена
			content.insert(content.end(), exchanged.parameters.data, exchanged.parameters.data + exchanged.parameters.size);
			// Подпись обязана сойтись ключом сертификата
			ASSERT_TRUE(attested(certificate.key(), exchanged.scheme, view_t(content.data(), content.size()), exchanged.signature)) << path << " схема " << std::hex << exchanged.scheme;
			// Испорченная подпись обязана отвергаться
			vector <uint8_t> spoiled(exchanged.signature.data, exchanged.signature.data + exchanged.signature.size);
			// Портим последний байт подписи
			spoiled.back() ^= 0x01;
			// Подпись с испорченным байтом обязана не сойтись
			ASSERT_FALSE(attested(certificate.key(), exchanged.scheme, view_t(content.data(), content.size()), view_t(spoiled.data(), spoiled.size()))) << path;
			// Подмена случайного значения обязана отвергаться
			content[0] ^= 0x01;
			// Подпись над подменённым содержимым обязана не сойтись
			ASSERT_FALSE(attested(certificate.key(), exchanged.scheme, view_t(content.data(), content.size()), exchanged.signature)) << path;
			// Учитываем проверенную подпись
			signatures++;
			// Если подлинность взаимная
			if(SCENARIOS[s].mutual){
				// Запрос сертификата
				const vector <uint8_t> * request = seek(s2c.messages, handshake::type_t::REQUEST);
				// Запрос обязан быть
				ASSERT_NE(request, nullptr) << path;
				// Нарезанный запрос обязан совпасть
				ASSERT_EQ(slurp(path + "/certificaterequest.bin"), *request) << path;
				// Тело запроса
				const view_t asked = inner(*request);
				// Тело обязано вместить перечень видов
				ASSERT_GT(asked.size, static_cast <size_t> (1 + asked.data[0] + 2)) << path;
				// Признак вида ecdsa_sign (64) среди видов
				bool ecdsa = false;
				/**
				 * Выполняем перебор видов сертификатов
				 */
				for(size_t i = 0; i < asked.data[0]; i++)
					// Ищем вид ecdsa_sign
					ecdsa = (ecdsa || (asked.data[1 + i] == 0x40));
				// Вид ecdsa_sign обязан быть запрошен
				ASSERT_TRUE(ecdsa) << path;
				// Смещение перечня схем
				const size_t offset = (1 + asked.data[0]);
				// Длина перечня схем
				const size_t length = ((static_cast <size_t> (asked.data[offset]) << 8) | asked.data[offset + 1]);
				// Схемы обязаны вместиться в тело
				ASSERT_LE(offset + 2 + length + 2, asked.size) << path;
				// Схемы запроса
				vector <extension::scheme_t> schemes;
				// Перечень схем обязан разобраться тем же кодом, что и расширение
				ASSERT_EQ(extension::schemes(view_t(asked.data + offset, 2 + length), schemes), extension::error_t::NONE) << path;
				// Схема ECDSA на P-256 обязана быть среди запрошенных
				ASSERT_NE(std::find(schemes.begin(), schemes.end(), extension::scheme_t::ECDSA_SECP256R1_SHA256), schemes.end()) << path;
				// Сертификат клиента
				const vector <uint8_t> * presented = seek(c2s.messages, handshake::type_t::CERTIFICATE);
				// Сертификат клиента обязан быть
				ASSERT_NE(presented, nullptr) << path;
				// Нарезанный сертификат клиента обязан совпасть
				ASSERT_EQ(slurp(path + "/client-certificate.bin"), *presented) << path;
				// Сертификат клиента DER
				const view_t own = leaf(inner(*presented));
				// Сертификат клиента обязан быть тем же ec256
				ASSERT_EQ(vector <uint8_t> (own.data, own.data + own.size), credential.chain[0]) << path;
				// Подпись владения ключом
				const vector <uint8_t> * verify = seek(c2s.messages, handshake::type_t::VERIFY);
				// Подпись владения обязана быть
				ASSERT_NE(verify, nullptr) << path;
				// Нарезанная подпись владения обязана совпасть
				ASSERT_EQ(slurp(path + "/client-certificateverify.bin"), *verify) << path;
				// Тело подписи владения: схема, длина, подпись
				const view_t attest = inner(*verify);
				// Тело обязано вместить схему и длину
				ASSERT_GT(attest.size, static_cast <size_t> (4)) << path;
				// Схема подписи владения
				const uint16_t scheme = ((static_cast <uint16_t> (attest.data[0]) << 8) | attest.data[1]);
				// Схема обязана быть ECDSA на P-256
				ASSERT_EQ(scheme, 0x0403) << path;
				// Длина подписи
				const size_t size = ((static_cast <size_t> (attest.data[2]) << 8) | attest.data[3]);
				// Подпись обязана заполнять тело ровно
				ASSERT_EQ(4 + size, attest.size) << path;
				// Подписанная перепись: все сообщения до CertificateVerify по порядку провода
				vector <uint8_t> transcript;
				/**
				 * Выполняем перебор сообщений переписи: ClientHello, ответ сервера, сообщения клиента до подписи
				 */
				for(size_t i = 0; i < (1 + s2c.messages.size() + c2s.messages.size()); i++){
					// Сообщение по порядку провода
					const vector <uint8_t> * message = nullptr;
					// Первым идёт ClientHello
					if(i == 0)
						// Берём ClientHello
						message = &c2s.messages[0];
					// Затем ответ сервера без билета (билет идёт за завершением клиента)
					else if(i <= s2c.messages.size())
						// Берём сообщение сервера
						message = &s2c.messages[i - 1];
					// Затем сообщения клиента
					else
						// Берём сообщение клиента
						message = &c2s.messages[i - s2c.messages.size()];
					// Билет сервера в перепись до подписи не входит
					if(kind(*message) == handshake::type_t::TICKET)
						// Пропускаем билет
						continue;
					// Подпись владения саму себя не покрывает
					if(kind(*message) == handshake::type_t::VERIFY)
						// Перепись окончена
						break;
					// Добавляем сообщение в перепись
					transcript.insert(transcript.end(), message->begin(), message->end());
				}
				// Подпись владения обязана сойтись ключом сертификата клиента над переписью
				ASSERT_TRUE(attested(certificate.key(), scheme, view_t(transcript.data(), transcript.size()), view_t(attest.data + 4, size))) << path;
				// Подмена байта переписи обязана отвергаться
				transcript[transcript.size() / 2] ^= 0x01;
				// Подпись над подменённой переписью обязана не сойтись
				ASSERT_FALSE(attested(certificate.key(), scheme, view_t(transcript.data(), transcript.size()), view_t(attest.data + 4, size))) << path;
				// Учитываем проверенную подпись владения
				attestations++;
			}
		}
	}
	// Подписей обмена ключами: все 70 векторов
	ASSERT_EQ(signatures, static_cast <size_t> (70));
	// Подписей владения ключом клиента: шесть взаимных сценариев
	ASSERT_EQ(attestations, static_cast <size_t> (6));
}

/**
 * Проверка полного прогона потоков векторов TLS 1.2: по ключевому файлу и случайным
 * значениям сторон ключевой материал выводится нашей порождающей функцией, защищённые
 * завершения обеих сторон расшифровываются нашей защитой записей, verify_data сверяется
 * с переписью - совместимость PRF, расписания ключей и раскладки AEAD с шестью изданиями
 * openssl байт в байт
 */
TEST(Tls12Test, VectorFinished){
	// Число расшифрованных завершений
	size_t decrypted = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к каталогу вектора
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если каталога вектора нет
			if(!exists(path)){
				// Отсутствие вектора допустимо лишь там, где openssl ключа не имел
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Сообщаем о пропуске явно
				std::cout << "OpenSSL " << EDITIONS[e] << " без -no_ems: вектор " << SCENARIOS[s].name << " не снят, пропуск" << std::endl;
				// Переходим к следующему сценарию
				continue;
			}
			// Сведения о векторе из описания
			brief_t brief;
			// Описание обязано разобраться
			ASSERT_TRUE(describe(path, brief)) << path;
			// Набор описания обязан совпасть с ожидаемым сценарием
			ASSERT_EQ(brief.suite, SCENARIOS[s].suite) << path;
			// Потоки сторон по проводу
			stream_t c2s, s2c;
			// Поток клиента обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), c2s, true)) << path;
			// Поток сервера обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-s2c.bin"), s2c, true)) << path;
			// Защищённые завершения обязаны идти записями рукопожатия издания 1.2
			ASSERT_EQ(c2s.header.type, record::type_t::HANDSHAKE) << path;
			// Издание заголовка защищённой записи клиента обязано быть 1.2
			ASSERT_EQ(c2s.header.version, record::version_t::TLS12) << path;
			// Издание заголовка защищённой записи сервера обязано быть 1.2
			ASSERT_EQ(s2c.header.version, record::version_t::TLS12) << path;
			// Приветствия сторон
			hello::client_t client;
			// Приветствие клиента обязано разобраться
			ASSERT_EQ(hello::parse(inner(c2s.messages[0]), client), hello::error_t::NONE) << path;
			// Приветствие сервера
			hello::server_t server;
			// Приветствие сервера обязано разобраться
			ASSERT_EQ(hello::parse(inner(s2c.messages[0]), server), hello::error_t::NONE) << path;
			// Набор обязан быть набором описания
			ASSERT_EQ(server.suite, brief.suite) << path;
			// Случайное значение клиента и главный секрет из ключевого файла
			vector <uint8_t> random, master;
			// Ключевой файл обязан разобраться
			ASSERT_TRUE(keylog(path, random, master)) << path;
			// Случайное значение ключевого файла обязано быть от этого обмена
			ASSERT_EQ(random, vector <uint8_t> (client.random, client.random + hello::HELLO_RANDOM)) << path;
			// Случайное значение сервера
			const vector <uint8_t> theirs(server.random, server.random + hello::HELLO_RANDOM);
			// Набор шифрования
			const protect::suite_t suite = static_cast <protect::suite_t> (SCENARIOS[s].suite);
			// Раздел 3 RFC 7366: порядок encrypt-then-MAC действует, когда сервер подтвердил расширение при наборе CBC
			const bool etm = ((protect::mac(suite) != digest::hash_t::NONE) && (hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::ETM)) != nullptr));
			// Набор обязан быть классическим для связи
			ASSERT_TRUE(protect::legacy(suite)) << path;
			// Перепись: ClientHello, ответ сервера без билета, сообщения клиента
			vector <vector <uint8_t>> transcript;
			// Первым идёт ClientHello
			transcript.push_back(c2s.messages[0]);
			// Билеты сервера идут за завершением клиента
			vector <vector <uint8_t>> tickets;
			/**
			 * Выполняем перебор сообщений сервера
			 */
			for(size_t i = 0; i < s2c.messages.size(); i++){
				// Если это билет
				if(kind(s2c.messages[i]) == handshake::type_t::TICKET)
					// Откладываем билет
					tickets.push_back(s2c.messages[i]);
				// Иначе сообщение первого круга сервера
				else
					// Добавляем сообщение в перепись
					transcript.push_back(s2c.messages[i]);
			}
			/**
			 * Выполняем перебор сообщений клиента за приветствием
			 */
			for(size_t i = 1; i < c2s.messages.size(); i++)
				// Добавляем сообщение в перепись
				transcript.push_back(c2s.messages[i]);
			// Защита записей клиента
			protect::protection_t incoming;
			// Ключ клиента обязан вывестись
			ASSERT_TRUE(keyed(suite, master, random, theirs, incoming, true, etm)) << path;
			// Вид содержимого расшифрованной записи
			record::type_t type = record::type_t::NONE;
			// Открытое содержимое записи
			vector <uint8_t> plain;
			// Завершение клиента обязано расшифроваться нашим ключевым материалом
			ASSERT_EQ(incoming.open(c2s.header, view_t(c2s.sealed.data(), c2s.sealed.size()), type, plain), protect::error_t::NONE) << path;
			// Содержимое обязано быть рукопожатием
			ASSERT_EQ(type, record::type_t::HANDSHAKE) << path;
			// Завершение: заголовок и 12 байтов verify_data
			ASSERT_EQ(plain.size(), static_cast <size_t> (handshake::HANDSHAKE_HEADER + 12)) << path;
			// Вид сообщения обязан быть Finished
			ASSERT_EQ(kind(plain), handshake::type_t::FINISHED) << path;
			// Ожидаемый verify_data клиента
			uint8_t expected[12];
			// verify_data обязан вычислиться
			ASSERT_TRUE(completion(suite, master, "client finished", transcript, expected)) << path;
			// verify_data клиента обязан сойтись с переписью
			ASSERT_EQ(vector <uint8_t> (plain.begin() + handshake::HANDSHAKE_HEADER, plain.end()), vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Завершение клиента входит в перепись сервера
			transcript.push_back(plain);
			/**
			 * Выполняем перебор отложенных билетов: они идут за завершением клиента
			 */
			for(size_t i = 0; i < tickets.size(); i++)
				// Добавляем билет в перепись
				transcript.push_back(tickets[i]);
			// Защита записей сервера
			protect::protection_t outgoing;
			// Ключ сервера обязан вывестись
			ASSERT_TRUE(keyed(suite, master, random, theirs, outgoing, false, etm)) << path;
			// Защита доливает открытый текст в накопитель: перед новой записью он очищается
			plain.clear();
			// Завершение сервера обязано расшифроваться нашим ключевым материалом
			ASSERT_EQ(outgoing.open(s2c.header, view_t(s2c.sealed.data(), s2c.sealed.size()), type, plain), protect::error_t::NONE) << path;
			// Содержимое обязано быть рукопожатием
			ASSERT_EQ(type, record::type_t::HANDSHAKE) << path;
			// Вид сообщения обязан быть Finished
			ASSERT_EQ(kind(plain), handshake::type_t::FINISHED) << path;
			// verify_data сервера обязан вычислиться
			ASSERT_TRUE(completion(suite, master, "server finished", transcript, expected)) << path;
			// verify_data сервера обязан сойтись с переписью
			ASSERT_EQ(vector <uint8_t> (plain.begin() + handshake::HANDSHAKE_HEADER, plain.end()), vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Порча байта защищённой записи обязана отвергаться меткой
			vector <uint8_t> spoiled = s2c.sealed;
			// Портим байт шифротекста
			spoiled[spoiled.size() / 2] ^= 0x01;
			// Защита сервера заново: порядковый номер обязан быть нулевым
			protect::protection_t again;
			// Ключ сервера обязан вывестись
			ASSERT_TRUE(keyed(suite, master, random, theirs, again, false, etm)) << path;
			// Очищаем накопитель перед испорченной записью
			plain.clear();
			// Испорченная запись обязана отвергаться меткой целостности
			ASSERT_EQ(again.open(s2c.header, view_t(spoiled.data(), spoiled.size()), type, plain), protect::error_t::TAG) << path;
			// Учитываем расшифрованный вектор
			decrypted++;
		}
	}
	// Расшифрованы обязаны быть все векторы, вместе с шестью CBC второго круга
	ASSERT_EQ(decrypted, static_cast <size_t> (70));
}

/**
 * @brief Внутренние служебные объекты второго круга: наборы CBC, обмен RSA, PSK и билеты
 *
 */
namespace {
	/**
	 * @brief Связка заранее разделённого ключа для проверок
	 *
	 */
	typedef struct Keyring {
		// Опознаватель и ключ стороны
		vector <uint8_t> identity, key;
		// Запасные опознаватель и ключ: выбираются клиентом по подсказке
		vector <uint8_t> alternative, spare;
		// Опознаватель, увиденный сервером, и подсказка, увиденная клиентом
		vector <uint8_t> seen, hint;
		// Признак того, что клиент выбирает запасные по подсказке
		bool replace;
		/**
		 * Конструктор
		 */
		Keyring() noexcept : replace(false) {}
	} keyring_t;
	/**
	 * @brief Вызов сервера: ключ по опознавателю
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителях перехватывает связь
	 *
	 * @param identity опознаватель клиента
	 * @param key      накопитель ключа
	 * @param context  связка
	 *
	 * @return         признак известности опознавателя
	 *
	 */
	bool responding(const view_t & identity, vector <uint8_t> & key, void * context) {
		// Связка
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем увиденный опознаватель
		ring->seen.assign(identity.data, identity.data + identity.size);
		// Если опознаватель основной
		if(ring->seen == ring->identity){
			// Выдаём ключ
			key = ring->key;
			// Опознаватель известен
			return true;
		}
		// Если опознаватель запасной
		if(!ring->alternative.empty() && (ring->seen == ring->alternative)){
			// Выдаём запасной ключ
			key = ring->spare;
			// Опознаватель известен
			return true;
		}
		// Опознаватель неизвестен
		return false;
	}
	/**
	 * @brief Вызов клиента: опознаватель и ключ по подсказке
	 *
	 * @param hint     подсказка сервера
	 * @param identity накопитель опознавателя
	 * @param key      накопитель ключа
	 * @param context  связка
	 *
	 * @return         признак выбора заново
	 *
	 */
	bool advising(const view_t & hint, vector <uint8_t> & identity, vector <uint8_t> & key, void * context) {
		// Связка
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем подсказку
		ring->hint.assign(hint.data, hint.data + hint.size);
		// Если выбор заново не нужен
		if(!ring->replace)
			// Остаются настроенные
			return false;
		// Выбираем запасной опознаватель
		identity = ring->alternative;
		// Выбираем запасной ключ
		key = ring->spare;
		// Выбрано заново
		return true;
	}
	/**
	 * @brief Описание набора второго круга
	 *
	 */
	typedef struct Second {
		// Набор шифрования
		protect::suite_t suite;
		// Имя набора у openssl
		const char * title;
		// Имя ключа набора
		const char * key;
	} second_t;
	/**
	 * Наборы CBC второго круга: ECDHE и обмен RSA
	 */
	static const second_t CHAINED[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256"},
		{protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA256,   "ECDHE-RSA-AES128-SHA256",   "rsa2048"},
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA,    "ECDHE-ECDSA-AES128-SHA",    "ec256"},
		{protect::suite_t::ECDHE_ECDSA_AES_256_CBC_SHA,    "ECDHE-ECDSA-AES256-SHA",    "ec384"},
		{protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA,      "ECDHE-RSA-AES128-SHA",      "rsa2048"},
		{protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA,      "ECDHE-RSA-AES256-SHA",      "rsa2048"},
		{protect::suite_t::RSA_AES_128_CBC_SHA,            "AES128-SHA",                "rsa2048"},
		{protect::suite_t::RSA_AES_256_CBC_SHA,            "AES256-SHA",                "rsa2048"},
		{protect::suite_t::RSA_AES_128_CBC_SHA256,         "AES128-SHA256",             "rsa2048"},
		{protect::suite_t::RSA_AES_256_CBC_SHA256,         "AES256-SHA256",             "rsa2048"}
	};
	/**
	 * Наборы обмена RSA второго круга
	 */
	static const second_t PLAIN[] = {
		{protect::suite_t::RSA_AES_128_CBC_SHA,    "AES128-SHA",         "rsa2048"},
		{protect::suite_t::RSA_AES_256_CBC_SHA,    "AES256-SHA",         "rsa2048"},
		{protect::suite_t::RSA_AES_128_CBC_SHA256, "AES128-SHA256",      "rsa2048"},
		{protect::suite_t::RSA_AES_256_CBC_SHA256, "AES256-SHA256",      "rsa2048"},
		{protect::suite_t::RSA_AES_128_GCM_SHA256, "AES128-GCM-SHA256",  "rsa2048"},
		{protect::suite_t::RSA_AES_256_GCM_SHA384, "AES256-GCM-SHA384",  "rsa2048"}
	};
	/**
	 * Наборы PSK второго круга
	 */
	static const second_t PRESHARED[] = {
		{protect::suite_t::PSK_AES_128_CBC_SHA,                "PSK-AES128-CBC-SHA",           ""},
		{protect::suite_t::PSK_AES_256_CBC_SHA,                "PSK-AES256-CBC-SHA",           ""},
		{protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA,          "ECDHE-PSK-AES128-CBC-SHA",     ""},
		{protect::suite_t::ECDHE_PSK_AES_256_CBC_SHA,          "ECDHE-PSK-AES256-CBC-SHA",     ""},
		{protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, "ECDHE-PSK-CHACHA20-POLY1305",  ""}
	};
	/**
	 * @brief Метод разбора потока записей на виды записей и виды сообщений рукопожатия
	 *
	 * @param wire     поток записей
	 * @param records  перечень видов записей
	 * @param messages перечень видов сообщений рукопожатия открытых записей
	 *
	 * @return         признак успешности разбора
	 *
	 */
	bool anatomy(const view_t & wire, vector <record::type_t> & records, vector <handshake::type_t> & messages) noexcept {
		// Нарезанные записи
		vector <vector <uint8_t>> pieces;
		// Если поток на записи не нарезался
		if(!slice(wire, pieces))
			// Выводим отказ
			return false;
		// Сборщик сообщений
		handshake::reader_t reader;
		// Признак того, что смена набора встречена: дальше записи защищены
		bool changed = false;
		/**
		 * Выполняем перебор записей
		 */
		for(size_t i = 0; i < pieces.size(); i++){
			// Вид записи
			const record::type_t type = static_cast <record::type_t> (pieces[i][0]);
			// Запоминаем вид записи
			records.push_back(type);
			// Если это смена набора
			if(type == record::type_t::CHANGE)
				// Дальше защищённые записи
				changed = true;
			// Если это открытая запись рукопожатия
			else if((type == record::type_t::HANDSHAKE) && !changed){
				// Если содержимое в сборщик не легло
				if(reader.push(view_t(pieces[i].data() + record::RECORD_HEADER, pieces[i].size() - record::RECORD_HEADER)) != handshake::error_t::NONE)
					// Выводим отказ
					return false;
				// Заголовок сообщения
				handshake::header_t head;
				// Тело сообщения
				view_t body;
				/**
				 * Выполняем перебор собранных сообщений
				 */
				while(reader.next(head, body) == handshake::error_t::NONE)
					// Запоминаем вид сообщения
					messages.push_back(head.type);
			}
		}
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод розыска вида сообщения в перечне
	 *
	 * @param messages перечень видов
	 * @param type     искомый вид
	 *
	 * @return         признак наличия
	 *
	 */
	bool among(const vector <handshake::type_t> & messages, const handshake::type_t type) noexcept {
		// Выводим итог розыска
		return (std::find(messages.begin(), messages.end(), type) != messages.end());
	}
	/**
	 * @brief Метод настройки сторон под набор PSK
	 *
	 * @param client связь клиента
	 * @param server связь сервера
	 * @param suite  набор
	 * @param theirs связка сервера
	 * @param ours   связка клиента
	 * @param hint   подсказка сервера
	 *
	 */
	void presharing(client::context_t & client, server::context_t & server, const protect::suite_t suite, keyring_t & theirs, keyring_t & ours, const char * hint) noexcept {
		// Наборы сторон
		client.suites(vector <protect::suite_t> {suite});
		// Набор сервера
		server.suites(vector <protect::suite_t> {suite});
		// Группа
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группа сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Настройки сервера
		context::psk_t mine;
		// Вызов ключа по опознавателю
		mine.respond = responding;
		// Связка
		mine.context = &theirs;
		// Подсказка
		mine.identity.assign(hint, hint + ::strlen(hint));
		// Устанавливаем
		server.psk(mine);
		// Настройки клиента
		context::psk_t yours;
		// Опознаватель
		yours.identity = ours.identity;
		// Ключ
		yours.key = ours.key;
		// Вызов по подсказке
		yours.advise = advising;
		// Связка
		yours.context = &ours;
		// Устанавливаем
		client.psk(yours);
		// Клиент ведёт лишь издание 1.2
		client.versions(0x0303, 0x0303);
	}
	/**
	 * @brief Метод получения залпа сервера и залпа клиента в ответ на него
	 *
	 * @param client связь клиента
	 * @param server связь сервера
	 * @param answer записи залпа клиента: обмен ключами, смена набора, завершение
	 *
	 * @return       признак успешности
	 *
	 */
	bool preparing(client::context_t & client, server::context_t & server, vector <vector <uint8_t>> & answer) noexcept {
		// Записи залпа сервера
		vector <vector <uint8_t>> flight;
		// Если залп сервера не получен
		if(!volley(client, server, flight))
			// Выводим отказ
			return false;
		// Залп потоком
		vector <uint8_t> stream;
		// Собираем поток
		join(flight, stream);
		// Подаём залп клиенту
		if(client.push(view_t(stream.data(), stream.size())) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Залп клиента
		const view_t data = client.output();
		// Нарезаем на записи
		const bool sliced = slice(data, answer);
		// Снимаем
		client.consume(data.size);
		// Выводим итог
		return sliced;
	}
	/**
	 * @brief Метод вывода ключей стороны для разбора записей CBC своими руками
	 *
	 * @param suite  набор
	 * @param master главный секрет
	 * @param client случайное значение клиента
	 * @param server случайное значение сервера
	 * @param own    ключ клиента (иначе сервера)
	 * @param key    место ключа шифрования
	 * @param mac    место ключа имитовставки
	 *
	 * @return       признак успешности
	 *
	 */
	bool deriving(const protect::suite_t suite, const vector <uint8_t> & master, const vector <uint8_t> & client, const vector <uint8_t> & server, const bool own, vector <uint8_t> & key, vector <uint8_t> & mac) noexcept {
		// Длины
		const size_t width = protect::key(suite), stamp = digest::length(protect::mac(suite));
		// Затравка
		uint8_t seed[64];
		// Случайное значение сервера
		::memcpy(seed, server.data(), 32);
		// Случайное значение клиента
		::memcpy(seed + 32, client.data(), 32);
		// Метка
		const char * label = "key expansion";
		// Материал
		uint8_t material[(protect::PROTECT_MAC + protect::PROTECT_KEY + protect::PROTECT_VECTOR) * 2];
		// Если материал не выведен
		if(!digest::prf(protect::hash(suite), view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed, sizeof(seed)), material, (stamp + width) * 2))
			// Выводим отказ
			return false;
		// Ключ имитовставки стороны
		mac.assign(material + (own ? 0 : stamp), material + (own ? 0 : stamp) + stamp);
		// Ключ шифрования стороны
		key.assign(material + (stamp * 2) + (own ? 0 : width), material + (stamp * 2) + (own ? 0 : width) + width);
		// Выводим успешность
		return true;
	}
	/**
	 * Сценарии векторов второго круга
	 */
	static const struct Scenario2 {
		// Имя каталога
		const char * name;
		// Ожидаемый набор
		uint16_t suite;
		// Имя ключа сервера, пусто у PSK
		const char * key;
		// Ожидается ли encrypt_then_mac в ServerHello
		bool etm;
		// Подсказка сервера у PSK
		const char * hint;
	} SCENARIOS2[] = {
		{"cbc-ecdsa-sha256-etm",   0xC023, "ec256",   true,  ""},
		{"cbc-ecdsa-sha256-noetm", 0xC023, "ec256",   false, ""},
		{"cbc-rsa-sha-etm",        0xC013, "rsa2048", true,  ""},
		{"cbc-rsa-sha256-etm",     0xC027, "rsa2048", true,  ""},
		{"cbc-rsa-sha256-noetm",   0xC027, "rsa2048", false, ""},
		{"psk-aes128-cbc",         0x008C, "",        true,  "anyks-hint"},
		{"psk-ecdhe-chacha",       0xCCAC, "",        false, ""},
		{"psk-wrong-key",          0x008C, "",        true,  ""},
		{"rsa-plain-aes128-gcm",   0x009C, "rsa2048", false, ""},
		{"rsa-plain-aes256-sha",   0x0035, "rsa2048", true,  ""}
	};
	/**
	 * @brief Метод составления пути к каталогу вектора второго круга
	 *
	 * @param edition  издание openssl
	 * @param scenario имя сценария
	 *
	 * @return         путь
	 *
	 */
	std::string place2(const char * edition, const char * scenario) noexcept {
		// Выводим путь
		return (std::string(CORPUS) + "/tls12x/tls12x-OpenSSL-" + edition + "/" + scenario);
	}
};

/**
 * Проверка наборов CBC (раздел 6.2.3.2 RFC 5246, RFC 7366): петля по десяти наборам ECDHE и
 * обмена RSA с согласованным encrypt_then_mac, обмен данными, признак etm() наружу, порча
 * имитовставки и шифртекста записи - bad_record_mac и обрыв; у наборов AEAD признак ложен;
 * требование ETM: приветствие клиента без расширения при наборе CBC - handshake_failure и
 * отказ ETM, без требования - рукопожатие идёт в порядке MAC-then-encrypt без расширения в
 * ответе сервера
 */
TEST(Tls12Test, Chained){
	/**
	 * Выполняем перебор наборов CBC
	 */
	for(size_t s = 0; s < (sizeof(CHAINED) / sizeof(CHAINED[0])); s++){
		// Подлинность
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(CHAINED[s].key, credential));
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем стороны со взаимной подлинностью у ECDHE
		arrange(client, server, CHAINED[s].suite, extension::group_t::SECP256R1, credential, (s < 6));
		// Клиент ведёт лишь издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// До согласования признак ложен
		ASSERT_FALSE(client.etm());
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << CHAINED[s].title << " отказы " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Набор
		ASSERT_EQ(client.suite(), CHAINED[s].suite);
		// Порядок RFC 7366 согласован обеими сторонами
		ASSERT_TRUE(client.etm() && server.etm()) << CHAINED[s].title;
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << CHAINED[s].title;
		// Данные клиента
		const string request = "запись CBC второго круга";
		// Отправляем
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Запись клиента
		const view_t sealed = client.output();
		// Порченая запись: последний байт - имитовставка (encrypt-then-MAC)
		vector <uint8_t> spoiled(sealed.data, sealed.data + sealed.size);
		// Снимаем
		client.consume(sealed.size);
		// Портим байт имитовставки
		spoiled.back() ^= 0x01;
		// Подаём серверу: раздел 6.2.3.2 RFC 5246 велит отвечать bad_record_mac
		ASSERT_EQ(server.push(view_t(spoiled.data(), spoiled.size())), context::error_t::PROTECTION) << CHAINED[s].title;
		// Извещение bad_record_mac
		ASSERT_EQ(server.alert().description, alert::description_t::MAC) << CHAINED[s].title;
		// Связь оборвана
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Новая пара для порчи шифртекста
		client::context_t again;
		// Сервер
		server::context_t peer;
		// Настраиваем
		arrange(again, peer, CHAINED[s].suite, extension::group_t::SECP256R1, credential, false);
		// Издание 1.2
		ASSERT_EQ(again.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(peer.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(again.start(), context::error_t::NONE);
		// Рукопожатие
		converse(again, peer);
		// Установлена
		ASSERT_TRUE(again.established() && peer.established()) << CHAINED[s].title;
		// Отправляем
		ASSERT_EQ(again.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Запись
		const view_t other = again.output();
		// Порченая запись: байт шифртекста за вектором замены
		vector <uint8_t> broken(other.data, other.data + other.size);
		// Снимаем
		again.consume(other.size);
		// Портим байт шифртекста: заголовок, вектор и первый байт
		broken[record::RECORD_HEADER + 16] ^= 0x80;
		// Подаём: имитовставка над шифртекстом не сходится
		ASSERT_EQ(peer.push(view_t(broken.data(), broken.size())), context::error_t::PROTECTION) << CHAINED[s].title;
		// Извещение bad_record_mac
		ASSERT_EQ(peer.alert().description, alert::description_t::MAC) << CHAINED[s].title;
	}
	{
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Набор AEAD у сервера
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент предлагает набор CBC рядом с AEAD: расширение encrypt_then_mac в приветствии будет
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Требование ETM наборов AEAD не касается
		client.etm(true);
		// И у сервера
		server.etm(true);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Записи приветствия клиента
		vector <vector <uint8_t>> offers;
		// Нарезаем
		ASSERT_TRUE(slice(client.output(), offers));
		// Приветствие клиента
		hello::client_t greeting;
		// Разбираем
		ASSERT_EQ(hello::parse(view_t(offers[0].data() + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, offers[0].size() - record::RECORD_HEADER - handshake::HANDSHAKE_HEADER), greeting), hello::error_t::NONE);
		// Раздел 2 RFC 7366: клиент предложил encrypt_then_mac ради набора CBC
		ASSERT_NE(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::ETM)), nullptr);
		// Приветствие серверу
		ASSERT_TRUE(deliver(client, server));
		// Записи залпа сервера
		vector <vector <uint8_t>> records;
		// Нарезаем
		ASSERT_TRUE(slice(server.output(), records));
		// Приветствие сервера
		hello::server_t answer;
		// Разбираем
		ASSERT_EQ(hello::parse(view_t(records[0].data() + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, records[0].size() - record::RECORD_HEADER - handshake::HANDSHAKE_HEADER), answer), hello::error_t::NONE);
		// Сервер выбрал набор AEAD
		ASSERT_EQ(answer.suite, static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256));
		// Раздел 3 RFC 7366: при наборе AEAD сервер подтверждать encrypt_then_mac не вправе
		ASSERT_EQ(hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::ETM)), nullptr);
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established());
		// Порядок RFC 7366 у AEAD не значится
		ASSERT_FALSE(client.etm() || server.etm());
	}
	/**
	 * Выполняем перебор требования ETM у сервера: приветствие клиента без расширения
	 */
	for(size_t strict = 0; strict < 2; strict++){
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Связь сервера
		server::context_t server;
		// Подлинность
		server.credential(credential);
		// Требование
		server.etm(strict == 1);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Приветствие руками: набор CBC, без encrypt_then_mac
		vector <uint8_t> hello;
		// Составляем
		ASSERT_TRUE(greeting(true, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, hello, false, extension::group_t::SECP256R1));
		// Подаём
		const context::error_t outcome = server.push(view_t(hello.data(), hello.size()));
		// Если ETM требуется
		if(strict == 1){
			// Отказ ETM
			ASSERT_EQ(outcome, context::error_t::ETM);
			// Извещение handshake_failure
			ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
			// Извещение на проводе
			ASSERT_EQ(server.output().data[0], 0x15);
		// Если ETM не требуется: рукопожатие идёт в порядке MAC-then-encrypt
		} else {
			// Отказа нет
			ASSERT_EQ(outcome, context::error_t::NONE);
			// Набор CBC выбран
			ASSERT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256);
			// Порядок RFC 7366 не согласован
			ASSERT_FALSE(server.etm());
			// Записи ответа
			vector <vector <uint8_t>> records;
			// Нарезаем
			ASSERT_TRUE(slice(server.output(), records));
			// Приветствие сервера
			hello::server_t answer;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(records[0].data() + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, records[0].size() - record::RECORD_HEADER - handshake::HANDSHAKE_HEADER), answer), hello::error_t::NONE);
			// Расширения encrypt_then_mac в ответе нет
			ASSERT_EQ(hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::ETM)), nullptr);
		}
	}
}

/**
 * Проверка голого обмена RSA (раздел 7.4.7.1 RFC 5246): петля по шести наборам, залп сервера
 * без ServerKeyExchange, сертификат ECDSA набору не годен; защита от Бляйхенбахера: порченый
 * шифртекст, чужое издание и чужая длина общего значения не отличимы от годного по виду -
 * ответ сервера на ClientKeyExchange во всех случаях пуст, состояние и отказ те же, а
 * рукопожатие проваливается лишь на завершении клиента извещением bad_record_mac
 */
TEST(Tls12Test, Plain){
	// Подлинность RSA
	context::credential_t rsa;
	// Составляем
	ASSERT_TRUE(identity("rsa2048", rsa));
	/**
	 * Выполняем перебор наборов обмена RSA
	 */
	for(size_t s = 0; s < (sizeof(PLAIN) / sizeof(PLAIN[0])); s++){
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем с подлинностью клиента на чётных
		arrange(client, server, PLAIN[s].suite, extension::group_t::X25519, rsa, ((s % 2) == 0));
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Получаем
		ASSERT_TRUE(volley(client, server, flight));
		// Залп потоком
		vector <uint8_t> stream;
		// Собираем
		join(flight, stream);
		// Виды записей и сообщений
		vector <record::type_t> records;
		// Виды сообщений
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(view_t(stream.data(), stream.size()), records, messages));
		// Обмена ключами сервера у голого RSA нет
		ASSERT_FALSE(among(messages, handshake::type_t::AGREEMENT)) << PLAIN[s].title;
		// Цепочка есть
		ASSERT_TRUE(among(messages, handshake::type_t::CERTIFICATE)) << PLAIN[s].title;
		// Запрос подлинности ровно по настройке
		ASSERT_EQ(among(messages, handshake::type_t::REQUEST), ((s % 2) == 0)) << PLAIN[s].title;
		// Конец приветствия последний
		ASSERT_EQ(messages.back(), handshake::type_t::DONE) << PLAIN[s].title;
		// Подаём залп клиенту и доводим
		ASSERT_EQ(client.push(view_t(stream.data(), stream.size())), context::error_t::NONE);
		// Доводим
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << PLAIN[s].title << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Набор
		ASSERT_EQ(server.suite(), PLAIN[s].suite);
		// Порядок RFC 7366 у CBC согласован, у GCM нет
		ASSERT_EQ(client.etm(), (protect::mac(PLAIN[s].suite) != digest::hash_t::NONE)) << PLAIN[s].title;
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << PLAIN[s].title;
		// Закрываем
		ASSERT_EQ(client.close(), context::error_t::NONE);
		// Передаём
		converse(client, server);
		// Закрыта
		ASSERT_EQ(server.state(), context::state_t::CLOSED);
	}
	{
		// Подлинность ECDSA
		context::credential_t ec;
		// Составляем
		ASSERT_TRUE(identity("ec256", ec));
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Набор обмена RSA при ключе ECDSA
		arrange(client, server, protect::suite_t::RSA_AES_128_CBC_SHA, extension::group_t::X25519, ec, false);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Общего набора нет: ключ сертификата набору не отвечает
		ASSERT_EQ(server.error(), context::error_t::SUITE);
		// Извещение handshake_failure
		ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	}
	/**
	 * Выполняем перебор путей обмена ключами клиента: годный, порченый шифртекст, чужое издание
	 * общего значения, чужая длина общего значения, шифртекст чужой длины
	 */
	for(size_t path = 0; path < 5; path++){
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, protect::suite_t::RSA_AES_128_GCM_SHA256, extension::group_t::X25519, rsa, false);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп клиента: обмен ключами, смена набора, завершение
		vector <vector <uint8_t>> answer;
		// Получаем
		ASSERT_TRUE(preparing(client, server, answer)) << path;
		// Три записи
		ASSERT_EQ(answer.size(), static_cast <size_t> (3)) << path;
		// Первая - обмен ключами
		ASSERT_EQ(answer[0][0], 0x16) << path;
		// Вторая - смена набора
		ASSERT_EQ(answer[1][0], 0x14) << path;
		// Обмен ключами клиента, подаваемый серверу
		vector <uint8_t> exchange = answer[0];
		// Если путь - порченый шифртекст
		if(path == 1)
			// Портим байт шифртекста
			exchange[record::RECORD_HEADER + handshake::HANDSHAKE_HEADER + 2 + 17] ^= 0x01;
		// Если путь - чужое издание либо чужая длина общего значения
		else if((path == 2) || (path == 3)){
			// Сертификат сервера
			x509::certificate_t leaf;
			// Разбираем
			ASSERT_EQ(leaf.parse(view_t(client.peer()[0].data(), client.peer()[0].size())), x509::error_t::NONE);
			// Открытый ключ RSA
			sign::rsa_t key;
			// Загружаем
			ASSERT_TRUE(key.decode(leaf.key().key));
			// Общее значение: издание 0x0302 при пути два, длина 47 при пути три
			vector <uint8_t> premaster(((path == 2) ? 48 : 47), 0x5A);
			// Старший байт издания
			premaster[0] = 0x03;
			// Младший байт издания: чужое у пути два
			premaster[1] = static_cast <uint8_t> ((path == 2) ? 0x02 : 0x03);
			// Шифртекст
			vector <uint8_t> encrypted(key.size(), 0);
			// Шифруем
			ASSERT_TRUE(key.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(premaster.data(), premaster.size()), encrypted.data()));
			// Тело обмена: длина и шифртекст
			vector <uint8_t> body;
			// Старший байт длины
			body.push_back(static_cast <uint8_t> ((encrypted.size() >> 8) & 0xFF));
			// Младший байт длины
			body.push_back(static_cast <uint8_t> (encrypted.size() & 0xFF));
			// Шифртекст
			body.insert(body.end(), encrypted.begin(), encrypted.end());
			// Запись
			ASSERT_TRUE(framed(handshake::type_t::PREMASTER, view_t(body.data(), body.size()), exchange));
		// Если путь - шифртекст чужой длины
		} else if(path == 4){
			// Тело: длина 100 и сто байтов
			vector <uint8_t> body(102, 0x33);
			// Старший байт длины
			body[0] = 0x00;
			// Младший байт длины
			body[1] = 100;
			// Запись
			ASSERT_TRUE(framed(handshake::type_t::PREMASTER, view_t(body.data(), body.size()), exchange));
		}
		// Подаём обмен ключами: ответ сервера во всех путях один - молчание без отказа
		ASSERT_EQ(server.push(view_t(exchange.data(), exchange.size())), context::error_t::NONE) << path;
		// Ничего не отправлено
		ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << path;
		// Состояние - рукопожатие
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE) << path;
		// Отказа нет
		ASSERT_EQ(server.error(), context::error_t::NONE) << path;
		// Подаём смену набора и завершение клиента
		const context::error_t outcome = server.push(view_t(answer[1].data(), answer[1].size()));
		// Смена набора принята
		ASSERT_EQ(outcome, context::error_t::NONE) << path;
		// Завершение
		const context::error_t verdict = server.push(view_t(answer[2].data(), answer[2].size()));
		// Если путь годный
		if(path == 0){
			// Установлена
			ASSERT_EQ(verdict, context::error_t::NONE);
			// Сервер установил связь
			ASSERT_TRUE(server.established());
			// Ответ: билет сеанса, смена набора и завершение
			vector <record::type_t> records;
			// Сообщения
			vector <handshake::type_t> messages;
			// Разбираем
			ASSERT_TRUE(anatomy(server.output(), records, messages));
			// Три записи
			ASSERT_EQ(records.size(), static_cast <size_t> (3));
			// Билет перед сменой набора
			ASSERT_EQ(records[1], record::type_t::CHANGE);
		// Если общее значение подменено случайным: ключи разошлись, завершение клиента не расшифровывается
		} else {
			// Отказ снятия защиты
			ASSERT_EQ(verdict, context::error_t::PROTECTION) << path;
			// Извещение bad_record_mac
			ASSERT_EQ(server.alert().description, alert::description_t::MAC) << path;
			// На проводе одно извещение
			ASSERT_EQ(server.output().size, static_cast <size_t> (record::RECORD_HEADER + alert::ALERT_LENGTH)) << path;
			// Запись - извещение
			ASSERT_EQ(server.output().data[0], 0x15) << path;
		}
	}
}

/**
 * Проверка заранее разделённых ключей (RFC 4279, RFC 5489): петля по пяти наборам без
 * сертификатов у обеих сторон, опознаватель доставлен серверу вызовом, подсказка доставлена
 * клиенту вызовом и по ней выбирается иной опознаватель, чистый PSK без подсказки идёт без
 * ServerKeyExchange, неверный ключ - bad_record_mac на завершении, неизвестный опознаватель -
 * unknown_psk_identity (115) при disclose либо bad_record_mac на завершении без него, наборы
 * PSK не предлагаются без ключа и не признаются без вызова, пределы длин - SETTINGS
 */
TEST(Tls12Test, Preshared){
	// Ключ проверок
	const vector <uint8_t> secret = decode("0123456789abcdef");
	/**
	 * Выполняем перебор наборов PSK
	 */
	for(size_t s = 0; s < (sizeof(PRESHARED) / sizeof(PRESHARED[0])); s++){
		// Связки сторон
		keyring_t theirs, ours;
		// Опознаватель сервера
		theirs.identity = decode("616e796b73");
		// Ключ сервера
		theirs.key = secret;
		// Опознаватель клиента
		ours.identity = theirs.identity;
		// Ключ клиента
		ours.key = secret;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем: сервер без сертификата вовсе
		presharing(client, server, PRESHARED[s].suite, theirs, ours, "anyks-hint");
		// Заводим сервер без подлинности
		ASSERT_EQ(server.start(), context::error_t::NONE) << PRESHARED[s].title;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Получаем
		ASSERT_TRUE(volley(client, server, flight));
		// Поток
		vector <uint8_t> stream;
		// Собираем
		join(flight, stream);
		// Виды
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(view_t(stream.data(), stream.size()), records, messages));
		// Сертификата нет
		ASSERT_FALSE(among(messages, handshake::type_t::CERTIFICATE)) << PRESHARED[s].title;
		// Обмен ключами сервера есть: подсказка, у ECDHE_PSK и параметры кривой
		ASSERT_TRUE(among(messages, handshake::type_t::AGREEMENT)) << PRESHARED[s].title;
		// Запроса подлинности нет
		ASSERT_FALSE(among(messages, handshake::type_t::REQUEST)) << PRESHARED[s].title;
		// Подаём и доводим
		ASSERT_EQ(client.push(view_t(stream.data(), stream.size())), context::error_t::NONE);
		// Доводим
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << PRESHARED[s].title << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Набор
		ASSERT_EQ(client.suite(), PRESHARED[s].suite);
		// Сертификатов у сторон нет
		ASSERT_TRUE(client.peer().empty() && server.peer().empty());
		// Опознаватель доставлен серверу
		ASSERT_EQ(theirs.seen, theirs.identity) << PRESHARED[s].title;
		// Подсказка доставлена клиенту
		ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("anyks-hint")) << PRESHARED[s].title;
		// Порядок RFC 7366 у CBC
		ASSERT_EQ(client.etm(), (protect::mac(PRESHARED[s].suite) != digest::hash_t::NONE));
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << PRESHARED[s].title;
	}
	{
		// Связки: клиент выбирает запасной опознаватель по подсказке
		keyring_t theirs, ours;
		// Основной опознаватель сервера
		theirs.identity = decode("616e796b73");
		// Ключ
		theirs.key = secret;
		// Запасной опознаватель сервера
		theirs.alternative = decode("6f74686572");
		// Запасной ключ
		theirs.spare = decode("ffeeddccbbaa99887766554433221100");
		// Клиент настроен основным
		ours.identity = theirs.identity;
		// Ключ основной
		ours.key = secret;
		// Запасные клиента
		ours.alternative = theirs.alternative;
		// Запасной ключ
		ours.spare = theirs.spare;
		// Выбор заново по подсказке
		ours.replace = true;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "pick-other");
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Сервер увидел запасной опознаватель
		ASSERT_EQ(theirs.seen, theirs.alternative);
		// Подсказка дошла
		ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("pick-other"));
	}
	{
		// Связки без подсказки
		keyring_t theirs, ours;
		// Опознаватель
		theirs.identity = decode("616e796b73");
		// Ключ
		theirs.key = secret;
		// Клиент
		ours.identity = theirs.identity;
		// Ключ
		ours.key = secret;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Без подсказки
		presharing(client, server, protect::suite_t::PSK_AES_256_CBC_SHA, theirs, ours, "");
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Получаем
		ASSERT_TRUE(volley(client, server, flight));
		// Поток
		vector <uint8_t> stream;
		// Собираем
		join(flight, stream);
		// Виды
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(view_t(stream.data(), stream.size()), records, messages));
		// Раздел 2 RFC 4279: без подсказки обмена ключами сервера нет
		ASSERT_FALSE(among(messages, handshake::type_t::AGREEMENT));
		// Приветствие и конец
		ASSERT_EQ(messages.size(), static_cast <size_t> (2));
		// Доводим
		ASSERT_EQ(client.push(view_t(stream.data(), stream.size())), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Подсказки не было
		ASSERT_TRUE(ours.hint.empty());
	}
	{
		// Связки с неверным ключом клиента
		keyring_t theirs, ours;
		// Опознаватель
		theirs.identity = decode("616e796b73");
		// Ключ сервера
		theirs.key = secret;
		// Клиент
		ours.identity = theirs.identity;
		// Ключ клиента иной
		ours.key = decode("0123456789abcdee");
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		presharing(client, server, protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA, theirs, ours, "anyks-hint");
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп клиента
		vector <vector <uint8_t>> answer;
		// Получаем
		ASSERT_TRUE(preparing(client, server, answer));
		// Обмен ключами принят молча: ключ не сверяется до завершения
		ASSERT_EQ(server.push(view_t(answer[0].data(), answer[0].size())), context::error_t::NONE);
		// Ничего не отправлено
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Смена набора
		ASSERT_EQ(server.push(view_t(answer[1].data(), answer[1].size())), context::error_t::NONE);
		// Завершение клиента под чужими ключами не расшифровывается
		ASSERT_EQ(server.push(view_t(answer[2].data(), answer[2].size())), context::error_t::PROTECTION);
		// Извещение bad_record_mac
		ASSERT_EQ(server.alert().description, alert::description_t::MAC);
		// Извещение доходит клиенту
		converse(client, server);
		// Клиент оборван извещением
		ASSERT_EQ(client.error(), context::error_t::ALERT);
		// Тем же извещением
		ASSERT_EQ(client.alert().description, alert::description_t::MAC);
	}
	/**
	 * Выполняем перебор ручки disclose при неизвестном опознавателе
	 */
	for(size_t disclose = 0; disclose < 2; disclose++){
		// Связки
		keyring_t theirs, ours;
		// Опознаватель сервера
		theirs.identity = decode("616e796b73");
		// Ключ
		theirs.key = secret;
		// Клиент с неизвестным опознавателем
		ours.identity = decode("756e6b6e6f776e");
		// Ключ
		ours.key = secret;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "");
		// Настройки сервера заново с ручкой
		context::psk_t mine;
		// Вызов
		mine.respond = responding;
		// Связка
		mine.context = &theirs;
		// Ручка
		mine.disclose = (disclose == 1);
		// Устанавливаем
		server.psk(mine);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп клиента
		vector <vector <uint8_t>> answer;
		// Получаем
		ASSERT_TRUE(preparing(client, server, answer));
		// Подаём обмен ключами
		const context::error_t outcome = server.push(view_t(answer[0].data(), answer[0].size()));
		// Сервер увидел опознаватель
		ASSERT_EQ(theirs.seen, ours.identity);
		// Если неизвестный опознаватель раскрывается
		if(disclose == 1){
			// Отказ неизвестного опознавателя
			ASSERT_EQ(outcome, context::error_t::IDENTITY);
			// Извещение unknown_psk_identity (115)
			ASSERT_EQ(server.alert().description, alert::description_t::PSK);
			// Извещение доходит клиенту
			converse(client, server);
			// Клиент оборван
			ASSERT_EQ(client.error(), context::error_t::ALERT);
			// Тем же извещением
			ASSERT_EQ(client.alert().description, alert::description_t::PSK);
		// Если не раскрывается: случайный ключ и обрыв на завершении
		} else {
			// Обмен принят молча
			ASSERT_EQ(outcome, context::error_t::NONE);
			// Ничего не отправлено
			ASSERT_EQ(server.output().size, static_cast <size_t> (0));
			// Смена набора
			ASSERT_EQ(server.push(view_t(answer[1].data(), answer[1].size())), context::error_t::NONE);
			// Завершение не расшифровывается
			ASSERT_EQ(server.push(view_t(answer[2].data(), answer[2].size())), context::error_t::PROTECTION);
			// Извещение bad_record_mac
			ASSERT_EQ(server.alert().description, alert::description_t::MAC);
		}
	}
	{
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Связка сервера
		keyring_t theirs;
		// Опознаватель
		theirs.identity = decode("616e796b73");
		// Ключ
		theirs.key = secret;
		// Клиент без ключа с наборами PSK и ECDHE
		client::context_t client;
		// Сервер с вызовом и сертификатом
		server::context_t server;
		// Наборы клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Подлинность
		server.credential(credential);
		// Настройки сервера
		context::psk_t mine;
		// Вызов
		mine.respond = responding;
		// Связка
		mine.context = &theirs;
		// Устанавливаем
		server.psk(mine);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established());
		// Набор PSK без ключа не предлагался: выбран ECDHE
		ASSERT_EQ(server.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
		// Сервер без вызова набор PSK не признаёт
		client::context_t again;
		// Сервер без вызова
		server::context_t peer;
		// Клиент с ключом
		context::psk_t yours;
		// Опознаватель
		yours.identity = theirs.identity;
		// Ключ
		yours.key = secret;
		// Устанавливаем
		again.psk(yours);
		// Наборы: PSK впереди
		again.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Наборы сервера
		peer.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Подлинность
		peer.credential(credential);
		// Издание 1.2
		ASSERT_EQ(again.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(peer.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(again.start(), context::error_t::NONE);
		// Рукопожатие
		converse(again, peer);
		// Установлена
		ASSERT_TRUE(again.established() && peer.established());
		// Выбран ECDHE
		ASSERT_EQ(peer.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
		// Клиент с одними наборами PSK без ключа предложить нечего
		client::context_t bare;
		// Наборы
		bare.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA});
		// Издание 1.2
		ASSERT_EQ(bare.versions(0x0303, 0x0303), context::error_t::NONE);
		// Отказ настроек
		ASSERT_EQ(bare.start(), context::error_t::SETTINGS);
		// Опознаватель длиннее 128 байтов
		client::context_t wide;
		// Настройки
		context::psk_t broad;
		// Опознаватель в 129 байтов
		broad.identity.assign(129, 0x41);
		// Ключ
		broad.key = secret;
		// Устанавливаем
		wide.psk(broad);
		// Отказ настроек
		ASSERT_EQ(wide.start(), context::error_t::SETTINGS);
		// Ключ длиннее 64 байтов
		client::context_t heavy;
		// Настройки
		context::psk_t thick;
		// Опознаватель
		thick.identity = theirs.identity;
		// Ключ в 65 байтов
		thick.key.assign(65, 0x42);
		// Устанавливаем
		heavy.psk(thick);
		// Отказ настроек
		ASSERT_EQ(heavy.start(), context::error_t::SETTINGS);
		// Сервер без сертификата и без вызова связь завести не вправе
		server::context_t naked;
		// Отказ настроек
		ASSERT_EQ(naked.start(), context::error_t::SETTINGS);
	}
}

/**
 * Круг 11 (разрез по свойству, noexcept): вызовы потребителя по заранее разделённому ключу -
 * respond у сервера (exchanged()) и advise у клиента (agreed()) - были обёрнуты лишь
 * catch(bad_alloc); чужое (не bad_alloc) исключение из коллбэка пробило бы noexcept связи ->
 * std::terminate. Тот же класс, что распаковка цепочки, где catch(...) закалён явно
 * (CompressTest.Selection). Правка: catch(...) -> EXCHANGE в agreed() и exchanged(). Дойти до
 * ASSERT под бросающим коллбэком уже значит, что terminate не случился; мутация (снять catch(...))
 * роняет процесс проверки.
 */
TEST(Tls12Test, PresharedCallbackThrows){
	const vector <uint8_t> secret = decode("0123456789abcdef");
	// Сценарий A: respond сервера бросает чужое исключение (путь exchanged())
	{
		keyring_t theirs, ours;
		theirs.identity = decode("616e796b73"); theirs.key = secret;
		ours.identity = theirs.identity; ours.key = secret;
		client::context_t client;
		server::context_t server;
		presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "anyks-hint");
		// Переустанавливаем respond сервера на бросающий
		context::psk_t mine;
		mine.respond = [](const view_t &, vector <uint8_t> &, void *) -> bool { throw 42; };
		const string hint("anyks-hint");
		mine.identity.assign(hint.begin(), hint.end());
		server.psk(mine);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		vector <vector <uint8_t>> flight;
		ASSERT_TRUE(volley(client, server, flight));
		vector <uint8_t> stream;
		join(flight, stream);
		// Клиент разбирает залп сервера штатно (advise настоящий) и шлёт свой обмен ключами
		client.push(view_t(stream.data(), stream.size()));
		converse(client, server);
		// Сервер обязан завершиться отказом обмена ключами, а не обрушить процесс
		EXPECT_EQ(server.state(), context::state_t::FAILED);
		EXPECT_EQ(server.error(), context::error_t::EXCHANGE);
	}
	// Сценарий B: advise клиента бросает чужое исключение (путь agreed())
	{
		keyring_t theirs, ours;
		theirs.identity = decode("616e796b73"); theirs.key = secret;
		ours.identity = theirs.identity; ours.key = secret;
		client::context_t client;
		server::context_t server;
		presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "anyks-hint");
		// Переустанавливаем advise клиента на бросающий
		context::psk_t yours;
		yours.identity = ours.identity;
		yours.key = ours.key;
		yours.advise = [](const view_t &, vector <uint8_t> &, vector <uint8_t> &, void *) -> bool { throw 42; };
		client.psk(yours);
		client.versions(0x0303, 0x0303);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		vector <vector <uint8_t>> flight;
		ASSERT_TRUE(volley(client, server, flight));
		vector <uint8_t> stream;
		join(flight, stream);
		// Клиент разбирает обмен ключами сервера с подсказкой -> advise бросает
		client.push(view_t(stream.data(), stream.size()));
		converse(client, server);
		// Клиент обязан завершиться отказом обмена ключами, а не обрушить процесс
		EXPECT_EQ(client.state(), context::state_t::FAILED);
		EXPECT_EQ(client.error(), context::error_t::EXCHANGE);
	}
}

/**
 * Проверка билетов сеансов RFC 5077 и сокращённого рукопожатия (раздел 7.3 RFC 5246): полное
 * рукопожатие выдаёт билет перед сменой набора сервера, билет уходит октетами и возвращается
 * чтением, сокращённое рукопожатие идёт без сертификата и обмена ключами с завершением
 * сервера первым и новым билетом; порченый билет, чужой ключ, вышедший срок у клиента и у
 * сервера, набор вне предложения - полное рукопожатие без отказа; смена ключа билетов с двумя
 * живыми поколениями; билет 1.3 в записи потребителя изданию 1.2 не предъявляется
 */
TEST(Tls12Test, Tickets){
	// Подлинность
	context::credential_t credential;
	// Составляем
	ASSERT_TRUE(identity("ec256", credential));
	// Секреты ключей билетов
	const vector <uint8_t> first = decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"), second = decode("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"), third = decode("0f0e0d0c0b0a09080706050403020100");
	// Октеты билета, ушедшие «в другой процесс»
	vector <uint8_t> octets;
	{
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Ключ билетов
		server.vault(first);
		// Миг
		client.moment(1000000);
		// Миг сервера
		server.moment(1000000);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Залп клиента
		vector <vector <uint8_t>> answer;
		// Получаем
		ASSERT_TRUE(preparing(client, server, answer));
		// Поток залпа клиента
		vector <uint8_t> stream;
		// Собираем
		join(answer, stream);
		// Подаём серверу
		ASSERT_EQ(server.push(view_t(stream.data(), stream.size())), context::error_t::NONE);
		// Ответ сервера: билет, смена набора, завершение
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(server.output(), records, messages));
		// Три записи
		ASSERT_EQ(records.size(), static_cast <size_t> (3));
		// Раздел 3.3 RFC 5077: билет перед сменой набора
		ASSERT_EQ(records[0], record::type_t::HANDSHAKE);
		// Смена набора
		ASSERT_EQ(records[1], record::type_t::CHANGE);
		// Завершение под защитой
		ASSERT_EQ(records[2], record::type_t::HANDSHAKE);
		// Открытое сообщение одно - билет
		ASSERT_EQ(messages.size(), static_cast <size_t> (1));
		// Билет
		ASSERT_EQ(messages[0], handshake::type_t::TICKET);
		// Доводим
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Полное рукопожатие
		ASSERT_FALSE(client.shared() || server.shared());
		// Сертификат сервера предъявлен
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
		// Билет принят клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Билет выдан сервером
		ASSERT_EQ(server.tickets().size(), static_cast <size_t> (1));
		// Билет клиента
		const context::ticket_t & ticket = client.tickets()[0];
		// Набор
		ASSERT_EQ(ticket.suite, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
		// Главный секрет
		ASSERT_EQ(ticket.secret.size(), static_cast <size_t> (48));
		// Тело билета
		ASSERT_FALSE(ticket.identity.empty());
		// Срок два часа по умолчанию
		ASSERT_EQ(ticket.lifetime, static_cast <uint32_t> (7200));
		// Миг
		ASSERT_EQ(ticket.moment, static_cast <int64_t> (1000000));
		// Тело билета совпало у сторон
		ASSERT_EQ(ticket.identity, server.tickets()[0].identity);
		// Билет уходит октетами
		ASSERT_EQ(context::encode(ticket, octets), context::error_t::NONE);
		// Билет за рукопожатием изданию 1.2 не выдаётся
		ASSERT_EQ(server.issue(), context::error_t::STATE);
		// Обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	// Билет из октетов
	context::ticket_t ticket;
	// Читаем
	ASSERT_EQ(context::decode(view_t(octets.data(), octets.size()), ticket), context::error_t::NONE);
	/**
	 * @brief Описание пути возобновления
	 */
	struct Path {
		// Имя пути
		const char * name;
		// Секреты сервера по порядку: первый заводит, второй сменяет
		const vector <uint8_t> * keys[2];
		// Порча билета: ноль - нет, один - байт состояния, два - байт имитовставки
		int spoil;
		// Миг клиента
		int64_t client;
		// Миг сервера
		int64_t server;
		// Набор клиента: NONE - тот же
		protect::suite_t suite;
		// Ожидается ли возобновление
		bool resumed;
	} paths[] = {
		{"тот же ключ",                     {&first, nullptr},  0, 1000100, 1000100, protect::suite_t::NONE, true},
		{"порченое состояние билета",       {&first, nullptr},  1, 1000100, 1000100, protect::suite_t::NONE, false},
		{"порченая имитовставка билета",    {&first, nullptr},  2, 1000100, 1000100, protect::suite_t::NONE, false},
		{"чужой ключ",                      {&second, nullptr}, 0, 1000100, 1000100, protect::suite_t::NONE, false},
		{"срок вышел у клиента",            {&first, nullptr},  0, 1007300, 1000100, protect::suite_t::NONE, false},
		{"срок вышел у сервера",            {&first, nullptr},  0, 0,       1007300, protect::suite_t::NONE, false},
		{"набор вне предложения",           {&first, nullptr},  0, 1000100, 1000100, protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, false},
		{"предыдущее поколение ключа",      {&first, &second},  0, 1000100, 1000100, protect::suite_t::NONE, true},
		{"поколение ушло",                  {&second, &third},  0, 1000100, 1000100, protect::suite_t::NONE, false}
	};
	/**
	 * Выполняем перебор путей возобновления
	 */
	for(size_t p = 0; p < (sizeof(paths) / sizeof(paths[0])); p++){
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Набор клиента
		const protect::suite_t suite = ((paths[p].suite == protect::suite_t::NONE) ? ticket.suite : paths[p].suite);
		// Наборы клиента
		client.suites(vector <protect::suite_t> {suite});
		// Наборы сервера: оба
		server.suites(vector <protect::suite_t> {ticket.suite, protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384});
		// Группы
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность
		server.credential(credential);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Ключи билетов по порядку
		server.vault(*paths[p].keys[0]);
		// Если второй ключ задан
		if(paths[p].keys[1] != nullptr)
			// Сменяем поколение
			server.vault(*paths[p].keys[1]);
		// Миги
		client.moment(paths[p].client);
		// Миг сервера
		server.moment(paths[p].server);
		// Предъявляемый билет
		context::ticket_t presented = ticket;
		// Если портится состояние билета
		if(paths[p].spoil == 1)
			// Портим байт шифртекста состояния
			presented.identity[presented.identity.size() / 2] ^= 0x01;
		// Если портится имитовставка билета
		else if(paths[p].spoil == 2)
			// Портим последний байт: имитовставка HMAC-SHA256
			presented.identity.back() ^= 0x01;
		// Предъявляем
		client.resume(presented);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE) << paths[p].name;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << paths[p].name;
		// Приветствие серверу
		ASSERT_TRUE(deliver(client, server)) << paths[p].name;
		// Залп сервера
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(server.output(), records, messages)) << paths[p].name;
		// Если ожидается возобновление
		if(paths[p].resumed){
			// Раздел 3.3 RFC 5077: приветствие, билет, смена набора, завершение - без сертификата и обмена
			ASSERT_TRUE(among(messages, handshake::type_t::SERVER)) << paths[p].name;
			// Билет заново
			ASSERT_TRUE(among(messages, handshake::type_t::TICKET)) << paths[p].name;
			// Сертификата нет
			ASSERT_FALSE(among(messages, handshake::type_t::CERTIFICATE)) << paths[p].name;
			// Обмена нет
			ASSERT_FALSE(among(messages, handshake::type_t::AGREEMENT)) << paths[p].name;
			// Конца приветствия нет
			ASSERT_FALSE(among(messages, handshake::type_t::DONE)) << paths[p].name;
			// Смена набора сервера идёт первой: завершение сервера впереди клиентского
			ASSERT_NE(std::find(records.begin(), records.end(), record::type_t::CHANGE), records.end()) << paths[p].name;
		// Если ожидается полное рукопожатие
		} else {
			// Сертификат есть
			ASSERT_TRUE(among(messages, handshake::type_t::CERTIFICATE)) << paths[p].name;
			// Конец приветствия есть
			ASSERT_TRUE(among(messages, handshake::type_t::DONE)) << paths[p].name;
			// Смены набора нет
			ASSERT_EQ(std::find(records.begin(), records.end(), record::type_t::CHANGE), records.end()) << paths[p].name;
		}
		// Доводим
		converse(client, server);
		// Установлена без отказа
		ASSERT_TRUE(client.established() && server.established()) << paths[p].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " " << static_cast <int> (client.alert().description);
		// Признак возобновления у обеих сторон
		ASSERT_EQ(client.shared(), paths[p].resumed) << paths[p].name;
		// У сервера тот же
		ASSERT_EQ(server.shared(), paths[p].resumed) << paths[p].name;
		// Сертификат сервера у клиента лишь в полном
		ASSERT_EQ(client.peer().empty(), paths[p].resumed) << paths[p].name;
		// Набор
		ASSERT_EQ(client.suite(), suite) << paths[p].name;
		// Новый билет выдан во всяком рукопожатии
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << paths[p].name;
		// Новый билет иной телом
		ASSERT_NE(client.tickets()[0].identity, ticket.identity) << paths[p].name;
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << paths[p].name;
		// Возобновлённая связь закрывается как обычная
		ASSERT_EQ(client.close(), context::error_t::NONE);
		// Передаём
		converse(client, server);
		// Закрыта
		ASSERT_EQ(server.state(), context::state_t::CLOSED) << paths[p].name;
	}
	{
		// Билет издания 1.3 в записи потребителя изданию 1.2 не предъявляется: полное рукопожатие
		context::ticket_t modern;
		// Набор 1.3
		modern.suite = protect::suite_t::AES_128_GCM_SHA256;
		// Тело
		modern.identity.assign(32, 0x77);
		// Ключ
		modern.secret.assign(32, 0x88);
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Предъявляем
		client.resume(modern);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Установлена полным
		ASSERT_TRUE(client.established() && server.established());
		// Не возобновлена
		ASSERT_FALSE(client.shared());
	}
}

/**
 * Проверка обмена с настоящим openssl 3.6 вторым кругом: наборы CBC с encrypt_then_mac и с
 * -no_etm в обе стороны, требование ETM клиента против s_server -no_etm - отказ ETM, голый RSA
 * (@SECLEVEL=0 - свойство сборки openssl), PSK в обе стороны с подсказкой и с неверным ключом,
 * билеты: s_client -sess_out/-sess_in против нашего сервера («Reused, TLSv1.2»), наш клиент
 * против s_server дважды с билетом (второе возобновлено). Завершённость обмена судится по
 * «Verify return code: 0 (ok)» у клиента и отсутствию отказа у сервера - строка «Cipher :»
 * печатается до проверки завершения
 */
TEST(Tls12Test, Interop){
	// Способности openssl
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl без TLS 1.2 либо без расширенного главного секрета
	if(!toolkit.tls12 || !toolkit.master){
		// Пропускаем вслух
		GTEST_SKIP() << "openssl без TLS 1.2 с RFC 7627";
	}
	// Если ключ -no_etm openssl неведом
	if(!listed("s_server", "no_etm") || !listed("s_client", "no_etm")){
		// Пропускаем вслух
		GTEST_SKIP() << "openssl без ключа -no_etm";
	}
	// Ключ PSK
	const vector <uint8_t> secret = decode("0123456789abcdef");
	/**
	 * @brief Описание круга обмена
	 */
	struct Round {
		// Набор связи
		protect::suite_t suite;
		// Набор openssl вместе с уровнем безопасности
		const char * cipher;
		// Имя ключа
		const char * key;
		// Ключ -no_etm у openssl
		bool noetm;
		// Набор PSK
		bool psk;
	} rounds[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256", false, false},
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256", true,  false},
		{protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA,      "ECDHE-RSA-AES256-SHA",      "rsa2048", false, false},
		{protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA,      "ECDHE-RSA-AES128-SHA",      "rsa2048", true,  false},
		{protect::suite_t::RSA_AES_128_CBC_SHA,            "AES128-SHA@SECLEVEL=0",     "rsa2048", false, false},
		{protect::suite_t::RSA_AES_256_CBC_SHA256,         "AES256-SHA256@SECLEVEL=0",  "rsa2048", true,  false},
		{protect::suite_t::RSA_AES_128_GCM_SHA256,         "AES128-GCM-SHA256@SECLEVEL=0", "rsa2048", false, false},
		{protect::suite_t::PSK_AES_128_CBC_SHA,            "PSK-AES128-CBC-SHA@SECLEVEL=0", "", false, true},
		{protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, "ECDHE-PSK-CHACHA20-POLY1305@SECLEVEL=0", "", false, true}
	};
	/**
	 * Выполняем перебор кругов: наш клиент против s_server
	 */
	for(size_t r = 0; r < (sizeof(rounds) / sizeof(rounds[0])); r++){
		// Свободный порт
		const uint16_t number = vacant(false);
		// Порт есть
		ASSERT_NE(number, 0);
		// Журнал
		const std::string log = "/tmp/ants-tls12b-server-" + std::to_string(number) + ".log";
		// Подлинность и ключи сервера openssl
		std::string arming;
		// Если набор PSK
		if(rounds[r].psk)
			// Сервер без сертификата с подсказкой
			arming = " -nocert -psk_identity anyks -psk 0123456789ABCDEF -psk_hint anyks-hint";
		// Иначе сертификат
		else
			// Сертификат и ключ
			arming = " -cert " + std::string(CORPUS) + "/" + rounds[r].key + ".crt -key " + std::string(CORPUS) + "/" + rounds[r].key + ".pem";
		// Запускаем сервер openssl: билеты включены, чтобы проверить их у клиента
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2" + arming + " -cipher " + rounds[r].cipher + (rounds[r].noetm ? " -no_etm" : "") + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Подключаемся
		const int fd = dial(number);
		// Подключение
		ASSERT_GE(fd, 0) << rounds[r].cipher;
		// Связь клиента
		client::context_t client;
		// Набор
		client.suites(vector <protect::suite_t> {rounds[r].suite});
		// Группы
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
		// Связка клиента
		keyring_t ours;
		// Если набор PSK
		if(rounds[r].psk){
			// Настройки
			context::psk_t yours;
			// Опознаватель
			yours.identity = decode("616e796b73");
			// Ключ
			yours.key = secret;
			// Вызов по подсказке
			yours.advise = advising;
			// Связка
			yours.context = &ours;
			// Устанавливаем
			client.psk(yours);
		}
		// Имя узла
		client.name("localhost");
		// Заводим
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу до установления
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём
			relay(client, fd);
		// Установлена
		ASSERT_TRUE(client.established()) << rounds[r].cipher << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Набор
		ASSERT_EQ(client.suite(), rounds[r].suite);
		// Порядок RFC 7366 ровно по ключу openssl
		ASSERT_EQ(client.etm(), ((protect::mac(rounds[r].suite) != digest::hash_t::NONE) && !rounds[r].noetm)) << rounds[r].cipher;
		// Если набор PSK: подсказка дошла, сертификата нет
		if(rounds[r].psk){
			// Подсказка
			ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("anyks-hint")) << rounds[r].cipher;
			// Сертификата нет
			ASSERT_TRUE(client.peer().empty());
		}
		// Запрос
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Ответ
		vector <uint8_t> answer;
		/**
		 * Выполняем передачу до ответа
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём
			relay(client, fd);
			// Читаем
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Текст ответа
		const string text(answer.begin(), answer.end());
		// Ответ HTTP получен под защитой
		ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << rounds[r].cipher;
		// Издание 1.2
		ASSERT_NE(text.find("TLSv1.2"), string::npos) << text;
		// Билет от s_server получен
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << rounds[r].cipher;
		// Закрываем сокет
		::close(fd);
		// Снимаем сервер
		sentinel.halt();
		// Журнал
		std::string journal;
		// Дожидаемся
		(void) settle(log, journal);
		// Удаляем
		::remove(log.c_str());
	}
	/**
	 * Выполняем перебор кругов: s_client против нашего сервера
	 */
	for(size_t r = 0; r < (sizeof(rounds) / sizeof(rounds[0])); r++){
		// Порт
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Сокет
		ASSERT_GE(listener, 0);
		// Журнал
		const std::string log = "/tmp/ants-tls12b-client-" + std::to_string(number) + ".log";
		// Доводы клиента openssl
		std::string arming;
		// Если набор PSK
		if(rounds[r].psk)
			// Опознаватель и ключ
			arming = " -psk_identity anyks -psk 0123456789ABCDEF";
		// Иначе доверие
		else
			// Сертификат
			arming = " -CAfile " + std::string(CORPUS) + "/" + rounds[r].key + ".crt -servername localhost -verify_return_error";
		// Запускаем клиента openssl
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2" + arming + " -cipher " + rounds[r].cipher + (rounds[r].noetm ? " -no_etm" : "") + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение с пределом ожидания приёма
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь сервера
		server::context_t server;
		// Набор
		server.suites(vector <protect::suite_t> {rounds[r].suite});
		// Группы
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Связка сервера
		keyring_t theirs;
		// Если набор PSK
		if(rounds[r].psk){
			// Опознаватель
			theirs.identity = decode("616e796b73");
			// Ключ
			theirs.key = secret;
			// Настройки
			context::psk_t mine;
			// Вызов
			mine.respond = responding;
			// Связка
			mine.context = &theirs;
			// Подсказка
			mine.identity = decode("616e796b732d68696e74");
			// Устанавливаем
			server.psk(mine);
		// Иначе подлинность
		} else {
			// Подлинность
			context::credential_t credential;
			// Составляем
			ASSERT_TRUE(identity(rounds[r].key, credential));
			// Устанавливаем
			server.credential(credential);
		}
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём до конца рукопожатия
		ASSERT_TRUE(serve(server, fd)) << rounds[r].cipher << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
		// Отказа нет
		ASSERT_EQ(server.error(), context::error_t::NONE) << rounds[r].cipher;
		// Набор
		ASSERT_EQ(server.suite(), rounds[r].suite);
		// Порядок RFC 7366 ровно по ключу openssl
		ASSERT_EQ(server.etm(), ((protect::mac(rounds[r].suite) != digest::hash_t::NONE) && !rounds[r].noetm)) << rounds[r].cipher;
		// Если набор PSK: опознаватель дошёл
		if(rounds[r].psk){
			// Опознаватель
			ASSERT_EQ(theirs.seen, theirs.identity) << rounds[r].cipher;
		}
		// Билет выдан
		ASSERT_EQ(server.tickets().size(), static_cast <size_t> (1)) << rounds[r].cipher;
		// Закрываем связь, коли она ещё открыта
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем
		::close(fd);
		// Закрываем слушающий
		::close(listener);
		// Текст
		std::string text;
		// Клиент завершился
		ASSERT_TRUE(settle(log, text)) << text;
		// Завершённость: подлинность сошлась
		ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		// Издание
		ASSERT_NE(text.find("Protocol  : TLSv1.2"), std::string::npos) << text;
		// Билет в журнале клиента
		ASSERT_NE(text.find("TLS session ticket:"), std::string::npos) << text;
		// Удаляем
		::remove(log.c_str());
	}
	{
		// Требование ETM у нашего клиента против s_server -no_etm: отказ ETM
		const uint16_t number = vacant(false);
		// Порт
		ASSERT_NE(number, 0);
		// Журнал
		const std::string log = "/tmp/ants-tls12b-strict-" + std::to_string(number) + ".log";
		// Запускаем сервер без ETM
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -cert " + std::string(CORPUS) + "/ec256.crt -key " + std::string(CORPUS) + "/ec256.pem -cipher ECDHE-ECDSA-AES128-SHA256 -no_etm -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Подключаемся
		const int fd = dial(number);
		// Подключение
		ASSERT_GE(fd, 0);
		// Связь клиента
		client::context_t client;
		// Набор
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256});
		// Требование ETM
		client.etm(true);
		// Имя узла
		client.name("localhost");
		// Заводим
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу до обрыва
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём
			relay(client, fd);
		// Не установлена
		ASSERT_FALSE(client.established());
		// Отказ ETM
		ASSERT_EQ(client.error(), context::error_t::ETM);
		// Извещение handshake_failure
		ASSERT_EQ(client.alert().description, alert::description_t::HANDSHAKE);
		// Закрываем
		::close(fd);
		// Снимаем
		sentinel.halt();
		// Журнал
		std::string journal;
		// Дожидаемся
		(void) settle(log, journal);
		// Удаляем
		::remove(log.c_str());
	}
	{
		// Неверный ключ PSK у s_client против нашего сервера: обрыв на завершении bad_record_mac
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Сокет
		ASSERT_GE(listener, 0);
		// Журнал
		const std::string log = "/tmp/ants-tls12b-wrongpsk-" + std::to_string(number) + ".log";
		// Запускаем клиента с иным ключом
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -psk_identity anyks -psk 0123456789ABCDEE -cipher PSK-AES128-CBC-SHA@SECLEVEL=0 </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение с пределом ожидания приёма
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь сервера
		server::context_t server;
		// Набор
		server.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA});
		// Связка
		keyring_t theirs;
		// Опознаватель
		theirs.identity = decode("616e796b73");
		// Ключ
		theirs.key = secret;
		// Настройки
		context::psk_t mine;
		// Вызов
		mine.respond = responding;
		// Связка
		mine.context = &theirs;
		// Устанавливаем
		server.psk(mine);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём: рукопожатие обязано провалиться
		(void) serve(server, fd);
		// Отказ снятия защиты завершения
		ASSERT_EQ(server.error(), context::error_t::PROTECTION);
		// Извещение bad_record_mac
		ASSERT_EQ(server.alert().description, alert::description_t::MAC);
		// Опознаватель дошёл
		ASSERT_EQ(theirs.seen, theirs.identity);
		// Закрываем
		::close(fd);
		// Закрываем слушающий
		::close(listener);
		// Текст
		std::string text;
		// Клиент завершился
		ASSERT_TRUE(settle(log, text)) << text;
		// Клиент openssl принял извещение bad record mac
		ASSERT_NE(text.find("bad record mac"), std::string::npos) << text;
		// Удаляем
		::remove(log.c_str());
	}
	{
		// Билеты: s_client -sess_out, затем -sess_in против двух наших серверов с одним ключом билетов
		const vector <uint8_t> vault = decode("00112233445566778899aabbccddeeff");
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Файл сеанса
		const std::string session = "/tmp/ants-tls12b-session-" + std::to_string(static_cast <long> (::getpid())) + ".pem";
		// Удаляем прежний
		::remove(session.c_str());
		/**
		 * Выполняем два рукопожатия: полное с записью сеанса и возобновлённое с чтением
		 */
		for(size_t pass = 0; pass < 2; pass++){
			// Порт
			uint16_t number = 0;
			// Слушающий сокет
			const int listener = harbour(number);
			// Сокет
			ASSERT_GE(listener, 0);
			// Журнал
			const std::string log = "/tmp/ants-tls12b-ticket-" + std::to_string(number) + ".log";
			// Запускаем клиента openssl
			ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -CAfile " + std::string(CORPUS) + "/ec256.crt -servername localhost -verify_return_error -cipher ECDHE-ECDSA-AES128-GCM-SHA256 " + ((pass == 0) ? ("-sess_out " + session) : ("-sess_in " + session)) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
			// Сторож
			sentinel_t sentinel(log + ".pid");
			// Принимаем подключение с пределом ожидания приёма
			const int fd = greeted(listener);
			// Проверяем подключение
			ASSERT_GE(fd, 0);
			// Связь сервера
			server::context_t server;
			// Подлинность
			server.credential(credential);
			// Ключ билетов: у обоих серверов один
			server.vault(vault);
			// Заводим
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Ведём
			ASSERT_TRUE(serve(server, fd)) << "проход " << pass << " отказ " << static_cast <int> (server.error());
			// Отказа нет
			ASSERT_EQ(server.error(), context::error_t::NONE);
			// Возобновление на втором проходе
			ASSERT_EQ(server.shared(), (pass == 1)) << pass;
			// Билет выдан на обоих
			ASSERT_EQ(server.tickets().size(), static_cast <size_t> (1));
			// Закрываем связь, коли она ещё открыта
			ASSERT_TRUE(farewell(server, fd));
			// Закрываем
			::close(fd);
			// Закрываем слушающий
			::close(listener);
			// Текст
			std::string text;
			// Клиент завершился
			ASSERT_TRUE(settle(log, text)) << text;
			// Подлинность сошлась
			ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
			// Полное либо возобновлённое по отчёту openssl
			ASSERT_NE(text.find((pass == 0) ? "New, TLSv1.2" : "Reused, TLSv1.2"), std::string::npos) << text;
			// Удаляем
			::remove(log.c_str());
		}
		// Удаляем файл сеанса
		::remove(session.c_str());
	}
	{
		// Билеты: наш клиент против s_server дважды, второе рукопожатие возобновлено билетом
		const uint16_t number = vacant(false);
		// Порт
		ASSERT_NE(number, 0);
		// Журнал
		const std::string log = "/tmp/ants-tls12b-reuse-" + std::to_string(number) + ".log";
		// Запускаем сервер на два приёма с билетами
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -cert " + std::string(CORPUS) + "/ec256.crt -key " + std::string(CORPUS) + "/ec256.pem -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -www" + (toolkit.naccept ? " -naccept 2" : "") + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Билет первого рукопожатия
		context::ticket_t ticket;
		/**
		 * Выполняем два рукопожатия
		 */
		for(size_t pass = 0; pass < 2; pass++){
			// Подключаемся
			const int fd = dial(number);
			// Подключение
			ASSERT_GE(fd, 0) << pass;
			// Связь клиента
			client::context_t client;
			// Набор
			client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
			// Имя узла
			client.name("localhost");
			// На втором проходе предъявляем билет
			if(pass == 1)
				// Предъявляем
				client.resume(ticket);
			// Заводим
			ASSERT_EQ(client.start(), context::error_t::NONE);
			/**
			 * Выполняем передачу до установления
			 */
			for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
				// Передаём
				relay(client, fd);
			// Установлена
			ASSERT_TRUE(client.established()) << pass << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			// Возобновление на втором проходе
			ASSERT_EQ(client.shared(), (pass == 1)) << pass;
			// Сертификат лишь на первом
			ASSERT_EQ(client.peer().empty(), (pass == 1)) << pass;
			// Запрос
			const string request = "GET / HTTP/1.0\r\n\r\n";
			// Отправляем
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Ответ
			vector <uint8_t> answer;
			/**
			 * Выполняем передачу до ответа
			 */
			for(size_t i = 0; (i < 16) && answer.empty(); i++){
				// Передаём
				relay(client, fd);
				// Читаем
				ASSERT_EQ(client.read(answer), context::error_t::NONE);
			}
			// Текст
			const string text(answer.begin(), answer.end());
			// Ответ получен
			ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << pass;
			// Отчёт s_server о возобновлении: -www печатает «Reused» либо «New»
			ASSERT_NE(text.find((pass == 1) ? "Reused" : "New"), string::npos) << pass << " " << text;
			// На полном рукопожатии билет получен; на возобновлённом openssl билета не обновляет
			if(pass == 0){
				// Билет получен
				ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << pass;
				// Запоминаем билет
				ticket = client.tickets()[0];
			}
			// Закрываем
			::close(fd);
		}
		// Снимаем
		sentinel.halt();
		// Журнал
		std::string journal;
		// Дожидаемся
		(void) settle(log, journal);
		// Удаляем
		::remove(log.c_str());
	}
}

/**
 * Проверка векторов второго круга, снятых с шести изданий openssl (tests/corpus/tls12x):
 * выбор набора нашим сервером по записанному ClientHello с тем же составом залпа (обмен
 * ключами с подсказкой у PSK байт в байт, без обмена у голого RSA, без сертификата у PSK,
 * encrypt_then_mac ровно как у openssl), разбор записанного залпа сервера и обмена клиента,
 * расшифровка завершений по ключевому файлу у CBC (с ETM и без, раскладка имитовставки и
 * дополнения байт в байт) и AEAD, у неверного ключа PSK завершение сервера не вскрывается
 * ключами клиента, у билета - полное рукопожатие с NewSessionTicket и возобновлённое без
 * сертификата и обмена, с тем же билетом в приветствии
 */
TEST(Tls12Test, VectorSecond){
	// Число проверенных векторов сервером и число расшифрованных завершений
	size_t served = 0, decrypted = 0;
	// Ключ PSK векторов
	const vector <uint8_t> secret = decode("0123456789abcdef");
	/**
	 * Выполняем перебор изданий
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS2) / sizeof(SCENARIOS2[0])); s++){
			// Путь
			const std::string path = place2(EDITIONS[e], SCENARIOS2[s].name);
			// Каталог обязан быть
			ASSERT_TRUE(exists(path)) << path;
			// Признак вектора отказа: сервер на неверном ключе шлёт извещение вместо завершения
			const bool wrong = (::strcmp(SCENARIOS2[s].name, "psk-wrong-key") == 0);
			// Потоки сторон
			stream_t c2s, s2c;
			// Поток клиента
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), c2s, true)) << path;
			// Поток сервера: у вектора отказа без смены набора и завершения
			ASSERT_TRUE(unwind(slurp(path + "/handshake-s2c.bin"), s2c, !wrong)) << path;
			// Если вектор отказа: поток сервера кончается извещением bad_record_mac
			if(wrong){
				// Поток
				const vector <uint8_t> tail = slurp(path + "/handshake-s2c.bin");
				// Извещение в хвосте: вид 21, роковое, bad_record_mac (20)
				ASSERT_GE(tail.size(), static_cast <size_t> (7)) << path;
				// Вид записи
				ASSERT_EQ(tail[tail.size() - 7], 0x15) << path;
				// Уровень
				ASSERT_EQ(tail[tail.size() - 2], 0x02) << path;
				// Описание
				ASSERT_EQ(tail[tail.size() - 1], 0x14) << path;
			}
			// Приветствие клиента совпало
			ASSERT_EQ(slurp(path + "/client-clienthello.bin"), c2s.messages[0]) << path;
			// Приветствие сервера совпало
			ASSERT_EQ(slurp(path + "/serverhello.bin"), s2c.messages[0]) << path;
			// Обмен клиента совпал
			ASSERT_EQ(slurp(path + "/client-clientkeyexchange.bin"), *seek(c2s.messages, handshake::type_t::PREMASTER)) << path;
			// Приветствия
			hello::client_t client;
			// Разбираем
			ASSERT_EQ(hello::parse(inner(c2s.messages[0]), client), hello::error_t::NONE) << path;
			// Сервер
			hello::server_t server;
			// Разбираем
			ASSERT_EQ(hello::parse(inner(s2c.messages[0]), server), hello::error_t::NONE) << path;
			// Набор
			ASSERT_EQ(server.suite, SCENARIOS2[s].suite) << path;
			// EMS
			ASSERT_NE(hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::MASTER)), nullptr) << path;
			// encrypt_then_mac ровно по сценарию
			ASSERT_EQ(hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::ETM)) != nullptr, SCENARIOS2[s].etm) << path;
			// Набор связи
			const protect::suite_t suite = static_cast <protect::suite_t> (SCENARIOS2[s].suite);
			// Способ обмена
			const protect::exchange_t exchange = protect::exchange(suite);
			// Признак PSK
			const bool psk = ((exchange == protect::exchange_t::PSK) || (exchange == protect::exchange_t::ECDHE_PSK));
			// Сертификат ровно у наборов с сертификатом
			ASSERT_EQ(seek(s2c.messages, handshake::type_t::CERTIFICATE) != nullptr, !psk) << path;
			// Обмен ключами сервера
			const vector <uint8_t> * agreement = seek(s2c.messages, handshake::type_t::AGREEMENT);
			// У голого RSA обмена нет, у PSK с подсказкой и у ECDHE есть
			ASSERT_EQ(agreement != nullptr, (exchange != protect::exchange_t::RSA) && !((exchange == protect::exchange_t::PSK) && (::strlen(SCENARIOS2[s].hint) == 0))) << path;
			// Если обмен PSK
			if(psk && (agreement != nullptr)){
				// Разборщик
				field::scanner_t scanner;
				// Тело
				scanner.start(inner(*agreement));
				// Подсказка
				view_t hint;
				// Читаем
				ASSERT_EQ(scanner.vector(hint, 2), field::error_t::NONE) << path;
				// Подсказка ровно по сценарию
				ASSERT_EQ(string(reinterpret_cast <const char *> (hint.data), hint.size), string(SCENARIOS2[s].hint)) << path;
				// Если ECDHE_PSK: за подсказкой параметры кривой
				if(exchange == protect::exchange_t::ECDHE_PSK){
					// Вид параметров
					uint32_t kind = 0;
					// Читаем
					ASSERT_EQ(scanner.number(kind, 1), field::error_t::NONE) << path;
					// Именованная кривая
					ASSERT_EQ(kind, static_cast <uint32_t> (3)) << path;
					// Кривая
					uint32_t named = 0;
					// Читаем
					ASSERT_EQ(scanner.number(named, 2), field::error_t::NONE) << path;
					// X25519
					ASSERT_EQ(named, static_cast <uint32_t> (extension::group_t::X25519)) << path;
					// Точка
					view_t point;
					// Читаем
					ASSERT_EQ(scanner.vector(point, 1), field::error_t::NONE) << path;
					// Длина точки X25519
					ASSERT_EQ(point.size, static_cast <size_t> (32)) << path;
					// Раздел 3.2 RFC 5489: подписи нет
					ASSERT_EQ(scanner.left(), static_cast <size_t> (0)) << path;
				// У чистого PSK одна подсказка
				} else
					// Лишнего нет
					ASSERT_EQ(scanner.left(), static_cast <size_t> (0)) << path;
			}
			// Обмен клиента
			const view_t premaster = inner(*seek(c2s.messages, handshake::type_t::PREMASTER));
			// Если набор PSK: опознаватель anyks впереди
			if(psk){
				// Ожидаемое начало: длина 5 и anyks
				const vector <uint8_t> expected = decode("0005616e796b73");
				// Опознаватель совпал
				ASSERT_EQ(vector <uint8_t> (premaster.data, premaster.data + 7), expected) << path;
				// У чистого PSK на этом всё
				if(exchange == protect::exchange_t::PSK){
					// Ровно опознаватель
					ASSERT_EQ(premaster.size, static_cast <size_t> (7)) << path;
				// У ECDHE_PSK точка X25519 следом
				} else {
					// Длина точки и точка
					ASSERT_EQ(premaster.size, static_cast <size_t> (7 + 1 + 32)) << path;
				}
			// Если голый RSA: длина и шифртекст в модуль 2048 разрядов
			} else if(exchange == protect::exchange_t::RSA){
				// Длина 256
				ASSERT_EQ(premaster.size, static_cast <size_t> (2 + 256)) << path;
				// Старший байт длины
				ASSERT_EQ(premaster.data[0], 0x01) << path;
				// Младший байт длины
				ASSERT_EQ(premaster.data[1], 0x00) << path;
			}
			// Первая запись клиента по проводу с приветствием
			const vector <uint8_t> wire = slurp(path + "/handshake-c2s.bin");
			// Заголовок
			record::header_t header;
			// Разбираем
			ASSERT_EQ(record::parse(view_t(wire.data(), wire.size()), header), record::error_t::NONE) << path;
			// Запись приветствия
			const vector <uint8_t> first(wire.begin(), wire.begin() + record::RECORD_HEADER + header.size);
			// Наш сервер
			server::context_t ours;
			// Связка сервера
			keyring_t theirs;
			// Если набор PSK
			if(psk){
				// Опознаватель
				theirs.identity = decode("616e796b73");
				// Ключ
				theirs.key = secret;
				// Настройки
				context::psk_t mine;
				// Вызов
				mine.respond = responding;
				// Связка
				mine.context = &theirs;
				// Подсказка по сценарию
				mine.identity.assign(SCENARIOS2[s].hint, SCENARIOS2[s].hint + ::strlen(SCENARIOS2[s].hint));
				// Устанавливаем
				ours.psk(mine);
			// Иначе подлинность
			} else {
				// Подлинность
				context::credential_t credential;
				// Составляем
				ASSERT_TRUE(identity(SCENARIOS2[s].key, credential)) << path;
				// Устанавливаем
				ours.credential(credential);
			}
			// Группы
			ours.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
			// Заводим
			ASSERT_EQ(ours.start(), context::error_t::NONE) << path;
			// Подаём записанное приветствие
			(void) ours.push(view_t(first.data(), first.size()));
			// Отказа нет
			ASSERT_EQ(ours.error(), context::error_t::NONE) << path << " извещение " << static_cast <int> (ours.alert().description);
			// Набор тот же, что выбрал openssl
			ASSERT_EQ(static_cast <uint16_t> (ours.suite()), server.suite) << path;
			// Порядок RFC 7366 тот же
			ASSERT_EQ(ours.etm(), SCENARIOS2[s].etm) << path;
			// Залп нашего сервера
			vector <record::type_t> records;
			// Сообщения
			vector <handshake::type_t> messages;
			// Разбираем
			ASSERT_TRUE(anatomy(ours.output(), records, messages)) << path;
			// Приветствие первое
			ASSERT_EQ(messages[0], handshake::type_t::SERVER) << path;
			// Сертификат ровно как у openssl
			ASSERT_EQ(among(messages, handshake::type_t::CERTIFICATE), !psk) << path;
			// Обмен ключами ровно как у openssl
			ASSERT_EQ(among(messages, handshake::type_t::AGREEMENT), (agreement != nullptr)) << path;
			// Конец приветствия последний
			ASSERT_EQ(messages.back(), handshake::type_t::DONE) << path;
			// Если обмен чистого PSK с подсказкой: наш обмен ключами совпадает с openssl байт в байт
			if((exchange == protect::exchange_t::PSK) && (agreement != nullptr)){
				// Записи залпа
				vector <vector <uint8_t>> pieces;
				// Нарезаем
				ASSERT_TRUE(slice(ours.output(), pieces)) << path;
				// Поток
				vector <uint8_t> flight;
				// Собираем
				join(pieces, flight);
				// Поток как записи
				stream_t mine;
				// Разбор потока залпа без смены набора не сходится, потому ищем сообщение сборщиком
				handshake::reader_t reader;
				/**
				 * Выполняем перебор записей
				 */
				for(size_t i = 0; i < pieces.size(); i++)
					// Складываем содержимое
					ASSERT_EQ(reader.push(view_t(pieces[i].data() + record::RECORD_HEADER, pieces[i].size() - record::RECORD_HEADER)), handshake::error_t::NONE) << path;
				// Заголовок
				handshake::header_t head;
				// Тело
				view_t body;
				/**
				 * Выполняем перебор сообщений
				 */
				while(reader.next(head, body) == handshake::error_t::NONE){
					// Если это обмен ключами
					if(head.type == handshake::type_t::AGREEMENT){
						// Тело совпадает с openssl байт в байт
						ASSERT_EQ(vector <uint8_t> (body.data, body.data + body.size), vector <uint8_t> (inner(*agreement).data, inner(*agreement).data + inner(*agreement).size)) << path;
					}
				}
			}
			// Учитываем
			served++;
			// Ключевой файл
			vector <uint8_t> random, master;
			// Разбираем
			ASSERT_TRUE(keylog(path, random, master)) << path;
			// Случайное значение клиента
			ASSERT_EQ(random, vector <uint8_t> (client.random, client.random + hello::HELLO_RANDOM)) << path;
			// Случайное значение сервера
			const vector <uint8_t> theirsRandom(server.random, server.random + hello::HELLO_RANDOM);
			// Порядок RFC 7366 по приветствию сервера
			const bool etm = SCENARIOS2[s].etm && (protect::mac(suite) != digest::hash_t::NONE);
			// Переписка
			vector <vector <uint8_t>> transcript;
			// Приветствие клиента
			transcript.push_back(c2s.messages[0]);
			// Билеты сервера
			vector <vector <uint8_t>> tickets;
			/**
			 * Выполняем перебор сообщений сервера
			 */
			for(size_t i = 0; i < s2c.messages.size(); i++){
				// Если билет
				if(kind(s2c.messages[i]) == handshake::type_t::TICKET)
					// Откладываем
					tickets.push_back(s2c.messages[i]);
				// Иначе в переписку
				else
					// Добавляем
					transcript.push_back(s2c.messages[i]);
			}
			/**
			 * Выполняем перебор сообщений клиента
			 */
			for(size_t i = 1; i < c2s.messages.size(); i++)
				// Добавляем
				transcript.push_back(c2s.messages[i]);
			// Защита записей клиента
			protect::protection_t incoming;
			// Ключ клиента
			ASSERT_TRUE(keyed(suite, master, random, theirsRandom, incoming, true, etm)) << path;
			// Вид
			record::type_t type = record::type_t::NONE;
			// Открытое
			vector <uint8_t> plain;
			// Завершение клиента расшифровывается
			ASSERT_EQ(incoming.open(c2s.header, view_t(c2s.sealed.data(), c2s.sealed.size()), type, plain), protect::error_t::NONE) << path;
			// Рукопожатие
			ASSERT_EQ(type, record::type_t::HANDSHAKE) << path;
			// Завершение
			ASSERT_EQ(kind(plain), handshake::type_t::FINISHED) << path;
			// Ожидаемый verify_data
			uint8_t expected[12];
			// Вычисляем
			ASSERT_TRUE(completion(suite, master, "client finished", transcript, expected)) << path;
			// Сошёлся
			ASSERT_EQ(vector <uint8_t> (plain.begin() + handshake::HANDSHAKE_HEADER, plain.end()), vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Если набор CBC: раскладка записи клиента байт в байт своими руками
			if(protect::mac(suite) != digest::hash_t::NONE){
				// Ключи клиента
				vector <uint8_t> key, mac;
				// Выводим
				ASSERT_TRUE(deriving(suite, master, random, theirsRandom, true, key, mac)) << path;
				// Длина имитовставки
				const size_t width = digest::length(protect::mac(suite));
				// Длина шифртекста без вектора и открытой имитовставки
				const size_t length = (c2s.sealed.size() - 16 - (etm ? width : 0));
				// Кратна блоку
				ASSERT_EQ(length % 16, static_cast <size_t> (0)) << path;
				// AES
				cipher::aes_t aes;
				// Ключ
				ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
				// Режим
				cipher::chaining_t chaining;
				// Вектор из записи
				ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(c2s.sealed.data(), 16)));
				// Открытый текст
				vector <uint8_t> opened(length, 0);
				// Расшифровываем
				ASSERT_TRUE(chaining.decrypt(view_t(c2s.sealed.data() + 16, length), opened.data()));
				// Длина дополнения
				const size_t padding = opened.back();
				// Дополнение умещается
				ASSERT_LT(padding + 1 + (etm ? 0 : width), length + 1) << path;
				/**
				 * Выполняем сверку байтов дополнения
				 */
				for(size_t i = 0; i <= padding; i++)
					// Байт равен длине
					ASSERT_EQ(opened[length - 1 - i], static_cast <uint8_t> (padding)) << path << " байт " << i;
				// Открытое содержимое: заголовок и verify_data завершения
				const size_t total = (length - padding - 1 - (etm ? 0 : width));
				// Содержимое совпало с вскрытым защитой
				ASSERT_EQ(vector <uint8_t> (opened.begin(), opened.begin() + total), plain) << path;
				// Связанные данные: номер 0, вид 22, издание 0x0303, длина
				uint8_t associated[13] = {0, 0, 0, 0, 0, 0, 0, 0, 0x16, 0x03, 0x03, 0, 0};
				// Сообщение имитовставки
				vector <uint8_t> message;
				// Ожидаемая имитовставка
				uint8_t stamp[32];
				// Если MAC-then-encrypt: имитовставка над содержимым лежит за ним внутри
				if(!etm){
					// Длина содержимого
					associated[11] = static_cast <uint8_t> ((total >> 8) & 0xFF);
					// Младший
					associated[12] = static_cast <uint8_t> (total & 0xFF);
					// Связанные данные
					message.assign(associated, associated + sizeof(associated));
					// Содержимое
					message.insert(message.end(), opened.begin(), opened.begin() + total);
					// Имитовставка
					ASSERT_TRUE(digest::hmac(protect::mac(suite), view_t(mac.data(), mac.size()), view_t(message.data(), message.size()), stamp, width));
					// Лежит за содержимым
					ASSERT_EQ(vector <uint8_t> (opened.begin() + total, opened.begin() + total + width), vector <uint8_t> (stamp, stamp + width)) << path;
				// Если encrypt-then-MAC: имитовставка над вектором и шифртекстом лежит открытой в хвосте
				} else {
					// Длина вектора и шифртекста
					associated[11] = static_cast <uint8_t> (((16 + length) >> 8) & 0xFF);
					// Младший
					associated[12] = static_cast <uint8_t> ((16 + length) & 0xFF);
					// Связанные данные
					message.assign(associated, associated + sizeof(associated));
					// Вектор и шифртекст
					message.insert(message.end(), c2s.sealed.begin(), c2s.sealed.begin() + 16 + length);
					// Имитовставка
					ASSERT_TRUE(digest::hmac(protect::mac(suite), view_t(mac.data(), mac.size()), view_t(message.data(), message.size()), stamp, width));
					// Лежит в хвосте
					ASSERT_EQ(vector <uint8_t> (c2s.sealed.end() - width, c2s.sealed.end()), vector <uint8_t> (stamp, stamp + width)) << path;
				}
			}
			// Завершение клиента в перепись
			transcript.push_back(plain);
			/**
			 * Выполняем перебор билетов
			 */
			for(size_t i = 0; i < tickets.size(); i++)
				// В перепись
				transcript.push_back(tickets[i]);
			// Если сценарий неверного ключа: завершения сервера нет, есть извещение; завершение клиента вскрылось его же ключами
			if(wrong){
				// Учитываем
				decrypted++;
				// Переходим
				continue;
			}
			// Защита сервера
			protect::protection_t outgoing;
			// Ключ сервера
			ASSERT_TRUE(keyed(suite, master, random, theirsRandom, outgoing, false, etm)) << path;
			// Очищаем
			plain.clear();
			// Итог вскрытия завершения сервера
			const protect::error_t verdict = outgoing.open(s2c.header, view_t(s2c.sealed.data(), s2c.sealed.size()), type, plain);
			// Вскрылось
			ASSERT_EQ(verdict, protect::error_t::NONE) << path;
			// Завершение
			ASSERT_EQ(kind(plain), handshake::type_t::FINISHED) << path;
			// Ожидаемое
			ASSERT_TRUE(completion(suite, master, "server finished", transcript, expected)) << path;
			// Сошлось
			ASSERT_EQ(vector <uint8_t> (plain.begin() + handshake::HANDSHAKE_HEADER, plain.end()), vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Учитываем
			decrypted++;
		}
		// Сценарий билета
		const std::string path = place2(EDITIONS[e], "ticket");
		// Каталог обязан быть
		ASSERT_TRUE(exists(path)) << path;
		// Потоки полного рукопожатия
		stream_t full, again;
		// Полное
		ASSERT_TRUE(unwind(slurp(path + "/full/handshake-s2c.bin"), full, true)) << path;
		// Возобновлённое: приветствие, билет, смена, завершение
		ASSERT_TRUE(unwind(slurp(path + "/resumed/handshake-s2c.bin"), again, true)) << path;
		// В полном есть билет
		const vector <uint8_t> * issued = seek(full.messages, handshake::type_t::TICKET);
		// Билет есть
		ASSERT_NE(issued, nullptr) << path;
		// В полном есть сертификат и обмен
		ASSERT_NE(seek(full.messages, handshake::type_t::CERTIFICATE), nullptr) << path;
		// Обмен
		ASSERT_NE(seek(full.messages, handshake::type_t::AGREEMENT), nullptr) << path;
		// В возобновлённом нет сертификата
		ASSERT_EQ(seek(again.messages, handshake::type_t::CERTIFICATE), nullptr) << path;
		// Нет обмена
		ASSERT_EQ(seek(again.messages, handshake::type_t::AGREEMENT), nullptr) << path;
		// Нет конца приветствия
		ASSERT_EQ(seek(again.messages, handshake::type_t::DONE), nullptr) << path;
		// Приветствие клиента возобновлённого
		stream_t offer;
		// Разбираем
		ASSERT_TRUE(unwind(slurp(path + "/resumed/handshake-c2s.bin"), offer, true)) << path;
		// Одно приветствие до смены набора
		ASSERT_EQ(offer.messages.size(), static_cast <size_t> (1)) << path;
		// Приветствие
		hello::client_t client;
		// Разбираем
		ASSERT_EQ(hello::parse(inner(offer.messages[0]), client), hello::error_t::NONE) << path;
		// Расширение билета
		const hello::extension_t * presented = hello::extension(client.extensions, static_cast <uint16_t> (extension::type_t::TICKET));
		// Есть
		ASSERT_NE(presented, nullptr) << path;
		// Билет из полного: срок и билет с длиной
		const view_t body = inner(*issued);
		// Длина билета
		const size_t length = ((static_cast <size_t> (body.data[4]) << 8) | body.data[5]);
		// Билет в приветствии тот самый, что выдан полным рукопожатием
		ASSERT_EQ(vector <uint8_t> (presented->data.data, presented->data.data + presented->data.size), vector <uint8_t> (body.data + 6, body.data + 6 + length)) << path;
		// Полное приветствие клиента несёт пустое расширение билета
		stream_t initial;
		// Разбираем
		ASSERT_TRUE(unwind(slurp(path + "/full/handshake-c2s.bin"), initial, true)) << path;
		// Приветствие
		hello::client_t opener;
		// Разбираем
		ASSERT_EQ(hello::parse(inner(initial.messages[0]), opener), hello::error_t::NONE) << path;
		// Расширение
		const hello::extension_t * empty = hello::extension(opener.extensions, static_cast <uint16_t> (extension::type_t::TICKET));
		// Есть и пусто
		ASSERT_TRUE((empty != nullptr) && (empty->data.size == 0)) << path;
		// Наш сервер на записанное приветствие возобновления с чужим билетом отвечает полным рукопожатием
		server::context_t ours;
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Устанавливаем
		ours.credential(credential);
		// Заводим
		ASSERT_EQ(ours.start(), context::error_t::NONE);
		// Поток
		const vector <uint8_t> wire = slurp(path + "/resumed/handshake-c2s.bin");
		// Заголовок
		record::header_t header;
		// Разбираем
		ASSERT_EQ(record::parse(view_t(wire.data(), wire.size()), header), record::error_t::NONE) << path;
		// Подаём приветствие
		(void) ours.push(view_t(wire.data(), record::RECORD_HEADER + header.size));
		// Отказа нет
		ASSERT_EQ(ours.error(), context::error_t::NONE) << path;
		// Полное рукопожатие: чужой билет не признан
		ASSERT_FALSE(ours.shared()) << path;
		// Залп
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(ours.output(), records, messages)) << path;
		// Сертификат есть
		ASSERT_TRUE(among(messages, handshake::type_t::CERTIFICATE)) << path;
		// Конец приветствия есть
		ASSERT_TRUE(among(messages, handshake::type_t::DONE)) << path;
	}
	// Векторов сервером: шесть изданий по десять сценариев
	ASSERT_EQ(served, static_cast <size_t> (60));
	// Расшифрованных завершений столько же
	ASSERT_EQ(decrypted, static_cast <size_t> (60));
}

/**
 * Проверка нехватки памяти на путях второго круга: набор CBC, голый RSA, PSK и сокращённое
 * рукопожатие билетом - перебор запасов выделений, всякий исход NONE, MEMORY либо обрыв
 * внутренним извещением
 */
TEST(Tls12Test, StarvedSecond){
	// Подлинности
	context::credential_t ec, rsa;
	// Составляем
	ASSERT_TRUE(identity("ec256", ec));
	// RSA
	ASSERT_TRUE(identity("rsa2048", rsa));
	// Ключ PSK
	const vector <uint8_t> secret = decode("0123456789abcdef");
	// Ключ билетов
	const vector <uint8_t> vault = decode("00112233445566778899aabbccddeeff");
	// Билет на возобновление
	context::ticket_t ticket;
	{
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, extension::group_t::SECP256R1, ec, false);
		// Издание 1.2
		client.versions(0x0303, 0x0303);
		// Ключ билетов
		server.vault(vault);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established());
		// Билет
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем
		ticket = client.tickets()[0];
	}
	/**
	 * Выполняем перебор путей: CBC, RSA, PSK, билет
	 */
	for(size_t path = 0; path < 4; path++){
		// Нехватка встретилась
		bool starved = false;
		// Установилась на щедром запасе
		bool complete = false;
		/**
		 * Выполняем перебор запасов
		 */
		for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
			// Связь клиента
			client::context_t client;
			// Связь сервера
			server::context_t server;
			// Связки
			keyring_t theirs, ours;
			// Если путь CBC
			if(path == 0)
				// Настраиваем
				arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, extension::group_t::SECP256R1, ec, true);
			// Если путь RSA
			else if(path == 1)
				// Настраиваем
				arrange(client, server, protect::suite_t::RSA_AES_128_CBC_SHA, extension::group_t::SECP256R1, rsa, false);
			// Если путь PSK
			else if(path == 2){
				// Опознаватель
				theirs.identity = decode("616e796b73");
				// Ключ
				theirs.key = secret;
				// Клиент
				ours.identity = theirs.identity;
				// Ключ
				ours.key = secret;
				// Настраиваем
				presharing(client, server, protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA, theirs, ours, "anyks-hint");
			// Если путь билета
			} else {
				// Настраиваем
				arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, extension::group_t::SECP256R1, ec, false);
				// Ключ билетов
				server.vault(vault);
				// Предъявляем
				client.resume(ticket);
			}
			// Издание 1.2
			client.versions(0x0303, 0x0303);
			// Ошибки
			context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
			{
				// Запас
				starve::ration_t ration(budget);
				// Заводим
				first = server.start();
				// Заводим клиента
				second = client.start();
				// Если заведены
				if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
					// Рукопожатие
					converse(client, server);
					// Ошибки
					first = server.error();
					// Клиента
					second = client.error();
				}
			}
			// Нехватка
			starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
			// Законность
			const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
				((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
			// Проверяем
			ASSERT_TRUE(lawful) << "путь " << path << " запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
			// Установилась
			complete = (client.established() && server.established() && ((path != 3) || client.shared()));
		}
		// Нехватка встретилась
		ASSERT_TRUE(starved) << "путь " << path;
		// Установилась
		ASSERT_TRUE(complete) << "путь " << path;
	}
}

/**
 * @brief Внутренние служебные объекты правок по аудиту второго круга
 *
 */
namespace {
	/**
	 * @brief Метод составления приветствия клиента с предъявленным билетом сеанса руками
	 *
	 * @param suite   предлагаемый набор шифрования
	 * @param ticket  предъявляемые октеты билета
	 * @param chained предлагается ли порядок encrypt_then_mac
	 * @param result  накопитель, в который складывается запись приветствия
	 *
	 * @return        признак успешности составления приветствия
	 *
	 */
	bool resuming(const protect::suite_t suite, const vector <uint8_t> & ticket, const bool chained, vector <uint8_t> & result) noexcept {
		// Составляемое приветствие клиента
		hello::client_t hello;
		// Издание TLS 1.2 заголовком
		hello.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения
		 */
		for(size_t i = 0; i < sizeof(hello.random); i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (0x40 + i);
		// Набор шифрования
		hello.suites = {static_cast <uint16_t> (suite)};
		// Способ сжатия
		hello.methods = {0x00};
		// Тела расширений
		vector <uint8_t> groups, schemes;
		// Если группы либо схемы составить не удалось
		if((extension::groups(vector <extension::group_t> {extension::group_t::X25519}, groups) != extension::error_t::NONE) || (extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA256}, schemes) != extension::error_t::NONE))
			// Выводим отказ
			return false;
		// Добавляем группы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		// Добавляем схемы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Добавляем пустое расширение расширенного главного секрета
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Если порядок encrypt_then_mac предлагается
		if(chained)
			// Добавляем пустое расширение encrypt_then_mac
			hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::ETM), view_t(nullptr, 0)));
		// Раздел 3.2 RFC 5077: билет предъявляется расширением session_ticket
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TICKET), view_t(ticket.data(), ticket.size())));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело приветствия составить не удалось
		if(hello::build(hello, body) != hello::error_t::NONE)
			// Выводим отказ
			return false;
		// Выводим итог составления записи
		return framed(handshake::type_t::CLIENT, view_t(body.data(), body.size()), result);
	}
	/**
	 * @brief Метод составления приветствия сервера сокращённого рукопожатия руками
	 *
	 * @param suite   выбранный набор шифрования
	 * @param chained подтверждается ли порядок encrypt_then_mac
	 * @param result  накопитель, в который складывается запись приветствия
	 *
	 * @return        признак успешности составления приветствия
	 *
	 */
	bool replying(const protect::suite_t suite, const bool chained, vector <uint8_t> & result) noexcept {
		// Составляемое приветствие сервера
		hello::server_t answer;
		// Издание TLS 1.2
		answer.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения: заслонов понижения в хвосте нет
		 */
		for(size_t i = 0; i < sizeof(answer.random); i++)
			// Записываем очередной байт
			answer.random[i] = 0x11;
		// Выбранный набор
		answer.suite = static_cast <uint16_t> (suite);
		// Способ сжатия
		answer.method = 0x00;
		// Раздел 5.3 RFC 7627: подтверждение расширенного главного секрета
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Раздел 3.3 RFC 5077: обещание билета
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TICKET), view_t(nullptr, 0)));
		// Если порядок encrypt_then_mac подтверждается
		if(chained)
			// Добавляем пустое расширение encrypt_then_mac
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::ETM), view_t(nullptr, 0)));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело приветствия составить не удалось
		if(hello::build(answer, body) != hello::error_t::NONE)
			// Выводим отказ
			return false;
		// Выводим итог составления записи
		return framed(handshake::type_t::SERVER, view_t(body.data(), body.size()), result);
	}
	/**
	 * @brief Метод составления подлинности из ключа и сертификата разных имён
	 *
	 * @param key    имя файла ключа без расширения
	 * @param leaf   имя файла сертификата без расширения
	 * @param result подлинность
	 *
	 * @return       признак успешности составления
	 *
	 */
	bool credentialed(const char * key, const char * leaf, context::credential_t & result) noexcept {
		// Секретный ключ
		result.secret = corpus((std::string(key) + ".pem").c_str());
		// Сертификат
		const vector <uint8_t> text = corpus((std::string(leaf) + ".crt").c_str());
		// Если не прочитано
		if(result.secret.empty() || text.empty())
			// Выводим отказ
			return false;
		// Сброс цепочки
		result.chain.clear();
		// Выводим итог разбора
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод проведения полного рукопожатия ради билета сеанса
	 *
	 * @param suite      набор шифрования
	 * @param credential подлинность сервера
	 * @param vault      секрет ключа билетов
	 * @param mutual     запрашивается ли подлинность клиента и предъявляется ли она
	 * @param name       имя узла, запрашиваемое клиентом; пусто - без имени
	 * @param result     выданный билет
	 *
	 * @return           признак успешности рукопожатия и выдачи билета
	 *
	 */
	bool ticketed(const protect::suite_t suite, const context::credential_t & credential, const vector <uint8_t> & vault, const bool mutual, const char * name, context::ticket_t & result) noexcept {
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, suite, extension::group_t::X25519, credential, mutual);
		// Издание 1.2
		if(client.versions(0x0303, 0x0303) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Ключ билетов
		server.vault(vault);
		// Миги
		client.moment(1000000);
		// Миг сервера
		server.moment(1000000);
		// Если имя узла запрашивается
		if(::strlen(name) > 0)
			// Устанавливаем имя
			client.name(name);
		// Заводим
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ
			return false;
		// Рукопожатие
		converse(client, server);
		// Если связь не установлена либо билет не выдан
		if(!client.established() || !server.established() || (client.tickets().size() != 1))
			// Выводим отказ
			return false;
		// Запоминаем билет
		result = client.tickets()[0];
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Вызов сервера: ключ длиннее дозволенного по всякому опознавателю
	 *
	 * @param identity опознаватель клиента
	 * @param key      накопитель ключа
	 * @param context  не используется
	 *
	 * @return         признак известности опознавателя
	 *
	 */
	bool bloating(const view_t & identity, vector <uint8_t> & key, void * context) {
		// Опознаватель и контекст не нужны
		(void) identity;
		// Контекст
		(void) context;
		// Раздел 5.3 RFC 4279: ключ до 64 байтов - выдаём 65
		key.assign(65, 0x77);
		// Опознаватель известен
		return true;
	}
};

/**
 * Проверка подмены общего значения обмена RSA при неверном издании и неверной длине
 * (раздел 7.4.7.1 RFC 5246): поддельный клиент выводит главный секрет из СВОЕГО общего
 * значения с изданием 0x0302 либо длиною 47 и шлёт согласованное с ним завершение - сервер,
 * подменивший общее значение случайным, ответит bad_record_mac, а сервер без подмены принял
 * бы завершение; годный путь с изданием 0x0303 и длиною 48 устанавливает связь и тем
 * доказывает, что выработка поддельного клиента сходится с движком
 */
TEST(Tls12Test, Counterfeited){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем
	ASSERT_TRUE(identity("rsa2048", credential));
	// Набор обмена RSA
	const protect::suite_t suite = protect::suite_t::RSA_AES_128_GCM_SHA256;
	// Сертификат сервера
	x509::certificate_t leaf;
	// Разбираем
	ASSERT_EQ(leaf.parse(view_t(credential.chain[0].data(), credential.chain[0].size())), x509::error_t::NONE);
	// Открытый ключ RSA
	sign::rsa_t key;
	// Загружаем
	ASSERT_TRUE(key.decode(leaf.key().key));
	/**
	 * Выполняем перебор путей: годный, чужое издание, чужая длина
	 */
	for(size_t path = 0; path < 3; path++){
		// Связь сервера
		server::context_t server;
		// Набор
		server.suites(vector <protect::suite_t> {suite});
		// Подлинность
		server.credential(credential);
		// Издание 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Приветствие поддельного клиента изданием 0x0303 в заголовке
		vector <uint8_t> hello;
		// Составляем
		ASSERT_TRUE(greeting(true, suite, hello, false, extension::group_t::X25519));
		// Переписка: сообщения без заголовков записей
		vector <uint8_t> transcript(hello.begin() + record::RECORD_HEADER, hello.end());
		// Случайное значение клиента
		const vector <uint8_t> clientRandom(transcript.begin() + 4 + 2, transcript.begin() + 4 + 2 + 32);
		// Подаём приветствие
		ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE) << path;
		// Залп сервера
		const view_t flight = server.output();
		// Записи
		vector <vector <uint8_t>> pieces;
		// Нарезаем
		ASSERT_TRUE(slice(flight, pieces));
		// Снимаем
		server.consume(flight.size);
		// Приветствие, цепочка, конец приветствия: обмена ключами сервера у голого RSA нет
		ASSERT_EQ(pieces.size(), static_cast <size_t> (3)) << path;
		/**
		 * Выполняем перенос залпа в переписку
		 */
		for(size_t i = 0; i < pieces.size(); i++)
			// Добавляем сообщение без заголовка записи
			transcript.insert(transcript.end(), pieces[i].begin() + record::RECORD_HEADER, pieces[i].end());
		// Случайное значение сервера
		const vector <uint8_t> serverRandom(pieces[0].begin() + 5 + 4 + 2, pieces[0].begin() + 5 + 4 + 2 + 32);
		// Общее значение поддельного клиента: 48 байтов, у пути два - 47
		vector <uint8_t> premaster(((path == 2) ? 47 : 48), 0x5A);
		// Старший байт издания
		premaster[0] = 0x03;
		// Младший байт издания: чужой у пути один
		premaster[1] = static_cast <uint8_t> ((path == 1) ? 0x02 : 0x03);
		// Шифртекст
		vector <uint8_t> encrypted(key.size(), 0);
		// Раздел 7.4.7.1 RFC 5246: RSAES-PKCS1-v1_5
		ASSERT_TRUE(key.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(premaster.data(), premaster.size()), encrypted.data()));
		// Тело обмена ключами: длина и шифртекст
		vector <uint8_t> body;
		// Старший байт длины
		body.push_back(static_cast <uint8_t> ((encrypted.size() >> 8) & 0xFF));
		// Младший байт длины
		body.push_back(static_cast <uint8_t> (encrypted.size() & 0xFF));
		// Шифртекст
		body.insert(body.end(), encrypted.begin(), encrypted.end());
		// Запись обмена ключами
		vector <uint8_t> exchange;
		// Составляем
		ASSERT_TRUE(framed(handshake::type_t::PREMASTER, view_t(body.data(), body.size()), exchange));
		// Добавляем обмен в переписку
		transcript.insert(transcript.end(), exchange.begin() + record::RECORD_HEADER, exchange.end());
		// Хеш переписки по обмен ключами включительно
		uint8_t session[32];
		// Вычисляем
		ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(transcript.data(), transcript.size()), session, sizeof(session)));
		// Метка расширенного главного секрета
		const char * extended = "extended master secret";
		// Главный секрет поддельного клиента: из его собственного общего значения
		uint8_t master[48];
		// Раздел 4 RFC 7627
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(premaster.data(), premaster.size()), view_t(reinterpret_cast <const uint8_t *> (extended), ::strlen(extended)), view_t(session, sizeof(session)), master, sizeof(master)));
		// Затравка ключевого материала
		vector <uint8_t> seed(serverRandom);
		// Случайное значение клиента
		seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
		// Метка
		const char * expansion = "key expansion";
		// Материал: ключи по 16 и соли по 4 байта обеих сторон
		uint8_t material[(16 + 4) * 2];
		// Раздел 6.3 RFC 5246
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (expansion), ::strlen(expansion)), view_t(seed.data(), seed.size()), material, sizeof(material)));
		// Хеш переписки для завершения
		uint8_t digested[32];
		// Вычисляем
		ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(transcript.data(), transcript.size()), digested, sizeof(digested)));
		// Метка завершения клиента
		const char * label = "client finished";
		// Завершение, согласованное с общим значением поддельного клиента
		uint8_t completion[12];
		// Раздел 7.4.9 RFC 5246
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(digested, sizeof(digested)), completion, sizeof(completion)));
		// Составитель сообщения завершения
		handshake::writer_t writer;
		// Составляем
		ASSERT_EQ(writer.push(handshake::type_t::FINISHED, view_t(completion, sizeof(completion))), handshake::error_t::NONE);
		// Защита записей поддельного клиента
		protect::protection_t sealing;
		// Ключ клиента первый, соль клиента третья
		ASSERT_TRUE(sealing.start(suite, view_t(material, 16), view_t(material + 32, 4)));
		// Поток к серверу: обмен ключами открытой записью
		vector <uint8_t> wire(exchange);
		// Смена набора
		static const uint8_t change[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
		// Добавляем
		wire.insert(wire.end(), change, change + sizeof(change));
		// Защищённое завершение
		vector <uint8_t> sealed;
		// Накладываем защиту ключами поддельного клиента
		ASSERT_EQ(sealing.seal(record::type_t::HANDSHAKE, writer.data(), sealed, 0), protect::error_t::NONE);
		// Добавляем завершение
		wire.insert(wire.end(), sealed.begin(), sealed.end());
		// Подаём поток серверу
		const context::error_t outcome = server.push(view_t(wire.data(), wire.size()));
		// Если путь годный
		if(path == 0){
			// Сервер принял завершение: выработка поддельного клиента сходится с движком
			ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (server.alert().description);
			// Установлена
			ASSERT_TRUE(server.established());
		// Если общее значение чужого издания либо чужой длины
		} else {
			// Раздел 7.4.7.1 RFC 5246: общее значение подменено случайным - ключи разошлись, завершение не вскрывается
			ASSERT_EQ(outcome, context::error_t::PROTECTION) << path;
			// Извещение bad_record_mac
			ASSERT_EQ(server.alert().description, alert::description_t::MAC) << path;
			// Связь оборвана
			ASSERT_EQ(server.state(), context::state_t::FAILED) << path;
		}
	}
}

/**
 * Проверка наследования порядка encrypt_then_mac при возобновлении (раздел 3.1 RFC 7366):
 * билет помнит порядок выдавшей связи; сервер с билетом связи ETM и приветствием без
 * encrypt_then_mac ведёт полное рукопожатие, а с предложением - сокращённое с подтверждением;
 * клиент, получив на предъявленный билет связи ETM приветствие возобновления без
 * подтверждения, обрывается illegal_parameter; так же при билете без ETM и подтверждении
 */
TEST(Tls12Test, Retained){
	// Подлинность
	context::credential_t credential;
	// Составляем
	ASSERT_TRUE(identity("ec256", credential));
	// Секрет ключа билетов
	const vector <uint8_t> vault = decode("00112233445566778899aabbccddeeff");
	// Набор CBC
	const protect::suite_t suite = protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256;
	// Билет связи с ETM
	context::ticket_t ticket;
	// Проводим полное рукопожатие
	ASSERT_TRUE(ticketed(suite, credential, vault, false, "", ticket));
	// Билет помнит порядок ETM
	ASSERT_TRUE(ticket.etm);
	/**
	 * Выполняем перебор приветствий клиента серверу: без encrypt_then_mac и с ним
	 */
	for(size_t chained = 0; chained < 2; chained++){
		// Связь сервера
		server::context_t server;
		// Набор
		server.suites(vector <protect::suite_t> {suite});
		// Группа
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность
		server.credential(credential);
		// Ключ билетов
		server.vault(vault);
		// Миг
		server.moment(1000100);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Приветствие с билетом
		vector <uint8_t> hello;
		// Составляем
		ASSERT_TRUE(resuming(suite, ticket.identity, (chained == 1), hello));
		// Подаём
		ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE) << chained;
		// Записи и сообщения залпа
		vector <record::type_t> records;
		// Сообщения
		vector <handshake::type_t> messages;
		// Разбираем
		ASSERT_TRUE(anatomy(server.output(), records, messages));
		// Записи залпа
		vector <vector <uint8_t>> pieces;
		// Нарезаем
		ASSERT_TRUE(slice(server.output(), pieces));
		// Приветствие сервера
		hello::server_t answer;
		// Разбираем
		ASSERT_EQ(hello::parse(view_t(pieces[0].data() + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, pieces[0].size() - record::RECORD_HEADER - handshake::HANDSHAKE_HEADER), answer), hello::error_t::NONE);
		// Если encrypt_then_mac не предложен: билет связи ETM не возобновляется - понижения нет
		if(chained == 0){
			// Полное рукопожатие: цепочка и конец приветствия
			ASSERT_TRUE(among(messages, handshake::type_t::CERTIFICATE));
			// Конец приветствия
			ASSERT_TRUE(among(messages, handshake::type_t::DONE));
			// Смены набора нет
			ASSERT_EQ(std::find(records.begin(), records.end(), record::type_t::CHANGE), records.end());
			// Сервер не возобновил
			ASSERT_FALSE(server.shared());
			// Порядок ETM не согласован: клиент его не предлагал
			ASSERT_FALSE(server.etm());
			// Подтверждения в приветствии нет
			ASSERT_EQ(hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::ETM)), nullptr);
		// Если encrypt_then_mac предложен: сокращённое рукопожатие тем же порядком
		} else {
			// Сертификата нет
			ASSERT_FALSE(among(messages, handshake::type_t::CERTIFICATE));
			// Смена набора есть
			ASSERT_NE(std::find(records.begin(), records.end(), record::type_t::CHANGE), records.end());
			// Сервер возобновил
			ASSERT_TRUE(server.shared());
			// Порядок унаследован
			ASSERT_TRUE(server.etm());
			// Подтверждение в приветствии есть
			ASSERT_NE(hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::ETM)), nullptr);
		}
	}
	/**
	 * Выполняем перебор путей клиента: билет ETM и приветствие без подтверждения, билет ETM
	 * с подтверждением (годно), билет без ETM и приветствие с подтверждением
	 */
	for(size_t path = 0; path < 3; path++){
		// Связь клиента
		client::context_t client;
		// Набор
		client.suites(vector <protect::suite_t> {suite});
		// Группа
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Миг
		client.moment(1000100);
		// Предъявляемый билет
		context::ticket_t presented = ticket;
		// У пути два билет помнит порядок MAC-then-encrypt
		presented.etm = (path != 2);
		// Предъявляем
		client.resume(presented);
		// Заводим
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Снимаем приветствие клиента
		client.consume(client.output().size);
		// Приветствие сервера сокращённого рукопожатия: подтверждение лишь у пути один
		vector <uint8_t> answer;
		// Составляем
		ASSERT_TRUE(replying(suite, (path != 0), answer));
		// Подаём: приветствие принято, вид рукопожатия решит следующее сообщение
		ASSERT_EQ(client.push(view_t(answer.data(), answer.size())), context::error_t::NONE) << path << " " << static_cast <int> (client.alert().description);
		// Тело билета сеанса: срок и билет в 32 байта
		vector <uint8_t> body = {0x00, 0x00, 0x1C, 0x20, 0x00, 0x20};
		// Октеты билета
		body.insert(body.end(), 32, 0x99);
		// Запись билета
		vector <uint8_t> granted;
		// Составляем
		ASSERT_TRUE(framed(handshake::type_t::TICKET, view_t(body.data(), body.size()), granted));
		// Подаём: билет первым сообщением означает сокращённое рукопожатие
		const context::error_t outcome = client.push(view_t(granted.data(), granted.size()));
		// Если порядок сошёлся с билетом
		if(path == 1){
			// Отказа нет
			ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (client.alert().description);
			// Клиент признал возобновление
			ASSERT_TRUE(client.shared());
			// Порядок ETM
			ASSERT_TRUE(client.etm());
		// Если порядок разошёлся с билетом: раздел 3.1 RFC 7366
		} else {
			// Отказ порядка «шифрование, затем имитовставка»
			ASSERT_EQ(outcome, context::error_t::ETM) << path;
			// Извещение illegal_parameter
			ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER) << path;
			// Связь оборвана
			ASSERT_EQ(client.state(), context::state_t::FAILED) << path;
		}
	}
}

/**
 * Проверка наследования подлинности клиента и имени узла билетом: сервер с запросом
 * подлинности возобновляет лишь билет связи с проверенной подлинностью и предъявляет
 * потребителю сертификат клиента вновь; билет связи без подлинности при запросе ведёт к
 * полному рукопожатию; имя узла возобновлённой связи обязано сойтись с именем выдавшей
 */
TEST(Tls12Test, Inherited){
	// Подлинность
	context::credential_t credential;
	// Составляем
	ASSERT_TRUE(identity("ec256", credential));
	// Секрет ключа билетов
	const vector <uint8_t> vault = decode("ffeeddccbbaa99887766554433221100");
	// Набор
	const protect::suite_t suite = protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256;
	/**
	 * @brief Описание пути возобновления
	 */
	struct Path {
		// Имя пути
		const char * name;
		// Подлинность клиента у выдавшей связи
		bool issued;
		// Запрос подлинности у возобновляющей связи
		bool request;
		// Предъявляет ли клиент подлинность возобновляющей связи
		bool present;
		// Имя узла у выдавшей связи
		const char * first;
		// Имя узла у возобновляющей связи
		const char * second;
		// Ожидается ли возобновление
		bool resumed;
	} paths[] = {
		{"подлинность проверена и запрошена вновь", true,  true,  true,  "", "", true},
		{"подлинность не предъявлялась, запрошена", false, true,  true,  "", "", false},
		{"подлинность проверена, не запрошена",     true,  false, false, "", "", true},
		{"имя узла то же",                          false, false, false, "anyks.com", "anyks.com", true},
		{"имя узла иное",                           false, false, false, "anyks.com", "other.com", false},
		{"имя узла пропало",                        false, false, false, "anyks.com", "", false}
	};
	/**
	 * Выполняем перебор путей
	 */
	for(size_t p = 0; p < (sizeof(paths) / sizeof(paths[0])); p++){
		// Билет
		context::ticket_t ticket;
		// Полное рукопожатие
		ASSERT_TRUE(ticketed(suite, credential, vault, paths[p].issued, paths[p].first, ticket)) << paths[p].name;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем: запрос подлинности по пути
		arrange(client, server, suite, extension::group_t::X25519, credential, paths[p].request);
		// Если клиент подлинность предъявляет без запроса
		if(paths[p].present && !paths[p].request)
			// Устанавливаем подлинность клиента
			client.credential(credential);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Ключ билетов
		server.vault(vault);
		// Миги
		client.moment(1000100);
		// Миг сервера
		server.moment(1000100);
		// Если имя узла запрашивается
		if(::strlen(paths[p].second) > 0)
			// Устанавливаем имя
			client.name(paths[p].second);
		// Предъявляем билет
		client.resume(ticket);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE) << paths[p].name;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << paths[p].name;
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << paths[p].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Возобновление ровно по ожиданию
		ASSERT_EQ(server.shared(), paths[p].resumed) << paths[p].name;
		// У клиента то же
		ASSERT_EQ(client.shared(), paths[p].resumed) << paths[p].name;
		// Если подлинность клиента унаследована билетом
		if(paths[p].issued && paths[p].resumed){
			// Сертификат клиента предъявлен потребителю вновь
			ASSERT_EQ(server.peer().size(), static_cast <size_t> (1)) << paths[p].name;
			// Тот самый сертификат
			ASSERT_EQ(server.peer()[0], credential.chain[0]) << paths[p].name;
		// Если полное рукопожатие с запросом подлинности: сертификат предъявлен заново
		} else if(paths[p].request)
			// Сертификат клиента у сервера
			ASSERT_EQ(server.peer().size(), static_cast <size_t> (1)) << paths[p].name;
		// Иначе сертификата клиента нет
		else
			// Пусто
			ASSERT_TRUE(server.peer().empty()) << paths[p].name;
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << paths[p].name;
	}
}

/**
 * Проверка пригодности сертификата сервера обмену (раздел 7.4.2 и 7.4.7.1 RFC 5246):
 * ключ RSA короче 2048 разрядов при обмене шифрованием RSA - bad_certificate; назначение
 * ключа digitalSignature без keyEncipherment годно ECDHE_RSA и негодно обмену RSA;
 * назначение keyEncipherment без digitalSignature - наоборот
 */
TEST(Tls12Test, Feeble){
	/**
	 * @brief Описание пути
	 */
	struct Path {
		// Имя пути
		const char * name;
		// Ключ
		const char * key;
		// Сертификат
		const char * leaf;
		// Набор
		protect::suite_t suite;
		// Ожидается ли установка связи
		bool established;
	} paths[] = {
		{"RSA-1024 при обмене RSA",             "rsa1024", "rsa1024",          protect::suite_t::RSA_AES_128_GCM_SHA256,       false},
		{"RSA-1024 при обмене RSA и CBC",       "rsa1024", "rsa1024",          protect::suite_t::RSA_AES_128_CBC_SHA,          false},
		{"RSA-2048 при обмене RSA",             "rsa2048", "rsa2048",          protect::suite_t::RSA_AES_128_GCM_SHA256,       true},
		{"digitalSignature при обмене RSA",     "rsa2048", "rsa2048-sign",     protect::suite_t::RSA_AES_128_GCM_SHA256,       false},
		{"digitalSignature при ECDHE_RSA",      "rsa2048", "rsa2048-sign",     protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, true},
		{"keyEncipherment при обмене RSA",      "rsa2048", "rsa2048-encipher", protect::suite_t::RSA_AES_128_GCM_SHA256,       true},
		{"keyEncipherment при ECDHE_RSA",       "rsa2048", "rsa2048-encipher", protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, false}
	};
	/**
	 * Выполняем перебор путей
	 */
	for(size_t p = 0; p < (sizeof(paths) / sizeof(paths[0])); p++){
		// Подлинность сервера
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(credentialed(paths[p].key, paths[p].leaf, credential)) << paths[p].name;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем
		arrange(client, server, paths[p].suite, extension::group_t::X25519, credential, false);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE) << paths[p].name;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << paths[p].name;
		// Рукопожатие
		converse(client, server);
		// Если связь ожидается
		if(paths[p].established){
			// Установлена
			ASSERT_TRUE(client.established() && server.established()) << paths[p].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Обмен данными
			ASSERT_TRUE(barter(client, server)) << paths[p].name;
		// Если сертификат набору непригоден
		} else {
			// Клиент отверг сертификат
			ASSERT_EQ(client.error(), context::error_t::CERTIFICATE) << paths[p].name;
			// Извещение bad_certificate
			ASSERT_EQ(client.alert().description, alert::description_t::BADCERT) << paths[p].name;
			// Клиент оборван
			ASSERT_EQ(client.state(), context::state_t::FAILED) << paths[p].name;
			// Сервер не установил связь
			ASSERT_FALSE(server.established()) << paths[p].name;
		}
	}
}

/**
 * Проверка пустого опознавателя PSK (раздел 2 RFC 4279: psk_identity<0..2^16-1>): клиент с
 * ключом без опознавателя предъявляет пустой, сервер его принимает и выдаёт ключ; вызов
 * advise вправе выбрать пустой опознаватель; ключ длиннее 64 байтов от вызова respond -
 * отказ настроек SETTINGS, а не неизвестный опознаватель
 */
TEST(Tls12Test, Nameless){
	// Ключ проверок
	const vector <uint8_t> secret = decode("0123456789abcdef0123456789abcdef");
	/**
	 * Выполняем перебор путей: пустой опознаватель настройкой, пустой по подсказке
	 */
	for(size_t path = 0; path < 2; path++){
		// Связка сервера
		keyring_t theirs;
		// Связка клиента
		keyring_t ours;
		// Ключ сервера по пустому опознавателю
		theirs.key = secret;
		// Если пустой опознаватель выбирается по подсказке
		if(path == 1){
			// Опознаватель клиента настройкой непуст
			ours.identity = decode("616e796b73");
			// Ключ настройкой иной
			ours.key = decode("00000000000000000000000000000000");
			// Запасной ключ - настоящий
			ours.spare = secret;
			// Выбор по подсказке
			ours.replace = true;
		// Если пустой опознаватель задан настройкой
		} else
			// Ключ клиента
			ours.key = secret;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Настраиваем стороны с подсказкой
		presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "anyks-hint");
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE) << path;
		// Заводим клиента: ключ без опознавателя законен
		ASSERT_EQ(client.start(), context::error_t::NONE) << path;
		// Рукопожатие
		converse(client, server);
		// Установлена
		ASSERT_TRUE(client.established() && server.established()) << path << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Сервер увидел пустой опознаватель
		ASSERT_TRUE(theirs.seen.empty()) << path;
		// Подсказка дошла до клиента
		ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("anyks-hint")) << path;
		// Обмен данными
		ASSERT_TRUE(barter(client, server)) << path;
	}
	{
		// Связка клиента
		keyring_t ours;
		// Опознаватель
		ours.identity = decode("616e796b73");
		// Ключ
		ours.key = secret;
		// Связь клиента
		client::context_t client;
		// Связь сервера
		server::context_t server;
		// Наборы
		client.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA});
		// Набор сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::PSK_AES_128_CBC_SHA});
		// Настройки сервера: вызов выдаёт ключ в 65 байтов
		context::psk_t mine;
		// Вызов
		mine.respond = bloating;
		// Устанавливаем
		server.psk(mine);
		// Настройки клиента
		context::psk_t yours;
		// Опознаватель
		yours.identity = ours.identity;
		// Ключ
		yours.key = ours.key;
		// Устанавливаем
		client.psk(yours);
		// Издание 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Рукопожатие
		converse(client, server);
		// Раздел 5.3 RFC 4279: ключ длиннее 64 байтов - отказ настроек, а не неизвестный опознаватель
		ASSERT_EQ(server.error(), context::error_t::SETTINGS);
		// Извещение internal_error
		ASSERT_EQ(server.alert().description, alert::description_t::INTERNAL);
		// Сервер оборван
		ASSERT_EQ(server.state(), context::state_t::FAILED);
	}
}

/**
 * Решение 15 движка (раздел 4.2.1 RFC 8446): расширение перечня изданий supported_versions
 * клиент кладёт лишь когда предлагает 1.3; при versions(0x0303, 0x0303) приветствие идёт без
 * него, как у openssl, - издание 1.2 сервер берёт из заголовка; умолчанием расширение есть
 */
TEST(Tls12Test, VersionsOmitted){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Два клиента: закреплённый на 1.2 и умолчательный
	 */
	for(size_t pinned = 0; pinned < 2; pinned++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Если клиент закреплён на 1.2
		if(pinned == 1)
			// Клиент ведёт лишь издание 1.2
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Иначе клиент предлагает и издание 1.3: без набора 1.3 оно не предлагается, и расширения не было бы по тому же правилу
		else client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Первое приветствие: запись с сообщением рукопожатия
		const view_t data = client.output();
		// Запись есть и несёт обвязку записи и сообщения
		ASSERT_GT(data.size, static_cast <size_t> (5 + handshake::HANDSHAKE_HEADER)) << pinned;
		// Запись рукопожатия
		ASSERT_EQ(data.data[0], static_cast <uint8_t> (record::type_t::HANDSHAKE)) << pinned;
		// Обвязка сообщения
		handshake::header_t header;
		// Разбираем обвязку
		ASSERT_EQ(handshake::parse(view_t(data.data + 5, data.size - 5), header), handshake::error_t::NONE) << pinned;
		// Приветствие клиента
		ASSERT_EQ(header.type, handshake::type_t::CLIENT) << pinned;
		// Разобранное приветствие
		hello::client_t greeting;
		// Разбираем приветствие
		ASSERT_EQ(hello::parse(view_t(data.data + 5 + handshake::HANDSHAKE_HEADER, header.size), greeting), hello::error_t::NONE) << pinned;
		// Расширение изданий
		const hello::extension_t * versions = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Закреплённый на 1.2 клиент расширения не кладёт, умолчательный кладёт
		if(pinned == 1)
			ASSERT_EQ(versions, nullptr);
		else
			ASSERT_NE(versions, nullptr);
		// Заголовок приветствия несёт издание 1.2 в обоих случаях
		ASSERT_EQ(greeting.version, static_cast <uint16_t> (0x0303)) << pinned;
		// Связь всё равно встаёт
		ASSERT_EQ(server.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << pinned << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303)) << pinned;
	}
}
