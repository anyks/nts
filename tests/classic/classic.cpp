/**
 * @file classic.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок классических наборов TLS 1.3: векторы RFC 8448, петлевое
 *        рукопожатие по всем сочетаниям набора, группы и ключа, отказы, GREASE, обмен с
 *        настоящим openssl и нехватка памяти
 *
 * @note Эталоном служат RFC 8448 «Example Handshake Traces for TLS 1.3» (разделы 3, 4 и 5)
 *       и системный openssl: ключи и сертификаты берутся из набора tests/corpus
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
#include <sstream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include "rfc8448.hpp"
#include <pem/pem.hpp>
#include <keys/keys.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <handshake/handshake.hpp>
#include <protect/protect.hpp>
#include <session/session.hpp>
#include <schedule/schedule.hpp>
#include <extension/extension.hpp>
#include <agreement/x25519.hpp>
#include <entropy/entropy.hpp>
#include <agreement/ecdhe.hpp>
#include <curve/parameters.hpp>
#include <digest/hash.hpp>
#include <sign/rsa.hpp>
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
		const string request = "Запрос прикладного протокола классическим набором";
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
		const string answer = "Ответ прикладного протокола классическим набором";
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
	 * @brief Виды искажений враждебного сервера классической ветви
	 *
	 */
	enum class hostility_t : uint8_t {
		NONE     = 0x00, // Искажения нет: честное рукопожатие
		PKCS1    = 0x01, // Подпись владения ключом схемой PKCS #1 v1.5 (0x0401)
		OFFCURVE = 0x02, // Доля ключа сервера вне кривой P-256
		ODDSCHEME = 0x03 // Подпись схемой, клиентом не предложенной (0x0805 при предложении 0x0804)
	};
	/**
	 * @brief Метод ответа враждебного сервера классической ветви на приветствие клиента
	 *
	 * @details Сервер разбирает приветствие, вырабатывает свою долю, выводит ключи
	 *          рукопожатия по-настоящему набором TLS_AES_128_GCM_SHA256 и складывает ими
	 *          сообщения вплоть до завершения, искажая одно из них по заказу проверки
	 *
	 * @param client     связь стороны клиента, приветствие которой разбирается
	 * @param hostility  вид искажения
	 * @param credential подлинность сервера с ключом RSA
	 *
	 * @return           признак успешности ответа враждебного сервера
	 *
	 */
	bool hostile(client::context_t & client, const hostility_t hostility, const context::credential_t & credential) noexcept {
		// Получаем байты, отправляемые клиентом серверу
		const view_t sending = client.output();
		// Если клиент серверу ничего не отправил
		if(sending.size == 0)
			// Выводим отказ ответа
			return false;
		// Переносим отправленные байты
		const vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(wire.size());
		// Сборщик записей
		record::reader_t records;
		// Если записи собрать не удалось
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Заголовок записи
		record::header_t header;
		// Содержимое записи
		view_t payload;
		// Если запись извлечь не удалось
		if(records.next(header, payload) != record::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Сборщик сообщений рукопожатия
		handshake::reader_t messages;
		// Если сообщения собрать не удалось
		if(messages.push(payload) != handshake::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Обвязка сообщения
		handshake::header_t message;
		// Тело сообщения
		view_t body;
		// Если сообщение извлечь не удалось либо это не приветствие клиента
		if((messages.next(message, body) != handshake::error_t::NONE) || (message.type != handshake::type_t::CLIENT))
			// Выводим отказ ответа
			return false;
		// Разобранное приветствие клиента
		hello::client_t greeting;
		// Если приветствие клиента разобрать не удалось
		if(hello::parse(body, greeting) != hello::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Разыскиваем расширение долей ключа
		const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если долей ключа нет
		if(extension == nullptr)
			// Выводим отказ ответа
			return false;
		// Доли ключа клиента
		vector <extension::share_t> shares;
		// Если доли ключа разобрать не удалось
		if((extension::shares(extension->data, shares) != extension::error_t::NONE) || shares.empty())
			// Выводим отказ ответа
			return false;
		// Группа обмена: первая доля клиента
		const extension::group_t group = shares[0].group;
		// Общее значение обмена ключами
		uint8_t shared[64];
		// Длина общего значения
		size_t length = 0;
		// Открытая часть ключа сервера в записи протокола
		vector <uint8_t> opened;
		// Если группа обмена - X25519
		if(group == extension::group_t::X25519){
			// Секретный ключ сервера
			uint8_t secret[32];
			// Если секретный ключ выработать не удалось
			if(!entropy::bytes(secret, sizeof(secret)))
				// Выводим отказ ответа
				return false;
			// Занимаем место под открытый ключ
			opened.assign(32, 0);
			// Если открытый ключ либо общее значение выработать не удалось
			if(!agreement::x25519(view_t(secret, sizeof(secret)), opened.data()) || !agreement::x25519(view_t(secret, sizeof(secret)), shares[0].key, shared))
				// Выводим отказ ответа
				return false;
			// Запоминаем длину общего значения
			length = 32;
		// Если группа обмена - P-256
		} else if(group == extension::group_t::SECP256R1){
			// Кривая P-256
			curve::curve_t curve;
			// Если кривую завести не удалось
			if(!curve::parameters(extension::curve(group), curve))
				// Выводим отказ ответа
				return false;
			// Секретный ключ сервера обратной записью
			uint8_t secret[32];
			// Координаты открытого ключа обратной записью
			uint8_t point[64];
			// Если пару ключей выработать не удалось
			if(!agreement::generate(curve, secret, point))
				// Выводим отказ ответа
				return false;
			// Занимаем место под несжатую точку
			opened.assign(65, 0);
			// Записываем признак несжатой точки
			opened[0] = 0x04;
			/**
			 * Выполняем перенос координат прямой записью
			 */
			for(size_t i = 0; i < 32; i++){
				// Переносим байт первой координаты
				opened[1 + i] = point[31 - i];
				// Переносим байт второй координаты
				opened[33 + i] = point[63 - i];
			}
			// Если доля клиента негодной длины
			if(shares[0].key.size != 65)
				// Выводим отказ ответа
				return false;
			// Координаты доли клиента обратной записью
			uint8_t peer[64];
			/**
			 * Выполняем перенос координат доли клиента обратной записью
			 */
			for(size_t i = 0; i < 32; i++){
				// Переносим байт первой координаты
				peer[i] = shares[0].key.data[32 - i];
				// Переносим байт второй координаты
				peer[32 + i] = shares[0].key.data[64 - i];
			}
			// Общее значение обратной записью
			uint8_t reversed[32];
			// Если общее значение выработать не удалось
			if(!agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(peer, sizeof(peer)), reversed))
				// Выводим отказ ответа
				return false;
			/**
			 * Выполняем перенос общего значения прямой записью
			 */
			for(size_t i = 0; i < 32; i++)
				// Переносим очередной байт
				shared[i] = reversed[31 - i];
			// Запоминаем длину общего значения
			length = 32;
			// Если заказана доля вне кривой
			if(hostility == hostility_t::OFFCURVE)
				// Портим первую координату: длина и запись остаются годными
				opened[1] = static_cast <uint8_t> (opened[1] ^ 0x01);
		// Иные группы враждебный сервер не ведёт
		} else return false;
		// Набор шифрования враждебного сервера
		const protect::suite_t suite = protect::suite_t::AES_128_GCM_SHA256;
		// Переписка рукопожатия хешем набора
		session::transcript_t transcript;
		// Если переписку начать не удалось
		if(transcript.start(digest::hash_t::SHA256) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Если приветствие клиента в переписку добавить не удалось
		if(transcript.update(messages.message()) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Приветствие сервера
		hello::server_t answer;
		// Устанавливаем издание протокола
		answer.version = 0x0303;
		// Повторяем опознаватель связи
		answer.session = greeting.session;
		// Устанавливаем набор шифрования
		answer.suite = static_cast <uint16_t> (suite);
		// Устанавливаем способ сжатия
		answer.method = 0x00;
		/**
		 * Выполняем набивку случайного значения приветствия
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт
			answer.random[i] = static_cast <uint8_t> (0x80 + i);
		// Тела расширений приветствия сервера
		vector <uint8_t> version, share;
		// Если издание протокола составить не удалось
		if(extension::version(0x0304, version) != extension::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Если долю ключа составить не удалось
		if(extension::share(extension::share_t(group, view_t(opened.data(), opened.size())), share) != extension::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Добавляем расширение издания протокола
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
		// Добавляем расширение доли ключа
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(share.data(), share.size())));
		// Тело приветствия сервера
		vector <uint8_t> hello;
		// Если приветствие сервера составить не удалось
		if(hello::build(answer, hello) != hello::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Составитель сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие сервера обвязать не удалось
		if(writer.push(handshake::type_t::SERVER, view_t(hello.data(), hello.size())) != handshake::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Если приветствие сервера в переписку добавить не удалось
		if(transcript.update(writer.data()) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Составитель открытых записей
		record::writer_t plain;
		// Если приветствие сервера в запись сложить не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Накопитель байтов ответа враждебного сервера
		vector <uint8_t> answered(plain.data().data, plain.data().data + plain.data().size);
		// Хеш переписки
		uint8_t digest[64];
		// Если хеш переписки получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Расписание ключей
		session::secrets_t secrets;
		// Если начальную ступень завести не удалось
		if(secrets.start(digest::hash_t::SHA256, view_t(nullptr, 0)) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Если ступень рукопожатия вывести не удалось
		if(secrets.handshake(view_t(shared, length), view_t(digest, 32)) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Ключ и вектор замены направления сервера
		uint8_t material[protect::PROTECT_KEY], element[protect::PROTECT_VECTOR];
		// Если ключевой материал вывести не удалось
		if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Защита записей сервера
		protect::protection_t protection;
		// Если защиту записей завести не удалось
		if(!protection.start(suite, view_t(material, protect::key(suite)), view_t(element, protect::block(suite))))
			// Выводим отказ ответа
			return false;
		/**
		 * @brief Метод доставки сообщения под защитой рукопожатия
		 *
		 */
		auto deliver = [&](const handshake::type_t type, const view_t & content) noexcept -> bool {
			// Составитель сообщения
			handshake::writer_t item;
			// Если сообщение обвязать не удалось
			if(item.push(type, content) != handshake::error_t::NONE)
				// Выводим отказ доставки
				return false;
			// Если сообщение в переписку добавить не удалось
			if(transcript.update(item.data()) != session::error_t::NONE)
				// Выводим отказ доставки
				return false;
			// Защищённая запись
			vector <uint8_t> sealed;
			// Если защиту наложить не удалось
			if(protection.seal(record::type_t::HANDSHAKE, item.data(), sealed, 0) != protect::error_t::NONE)
				// Выводим отказ доставки
				return false;
			// Складываем запись в накопитель
			answered.insert(answered.end(), sealed.begin(), sealed.end());
			// Выводим успешность доставки
			return true;
		};
		// Пустые защищённые расширения
		const uint8_t extensions[2] = {0x00, 0x00};
		// Если защищённые расширения доставить не удалось
		if(!deliver(handshake::type_t::EXTENSIONS, view_t(extensions, sizeof(extensions))))
			// Выводим отказ ответа
			return false;
		// Сообщение цепочки сертификатов
		message::certificate_t certificate;
		/**
		 * Выполняем перебор сертификатов цепочки
		 */
		for(size_t i = 0; i < credential.chain.size(); i++){
			// Запись цепочки
			message::entry_t entry;
			// Устанавливаем тело сертификата
			entry.data = view_t(credential.chain[i].data(), credential.chain[i].size());
			// Добавляем запись в цепочку
			certificate.entries.push_back(entry);
		}
		// Тело сообщения цепочки
		vector <uint8_t> chain;
		// Если цепочку составить либо доставить не удалось
		if((message::build(certificate, chain) != message::error_t::NONE) || !deliver(handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size())))
			// Выводим отказ ответа
			return false;
		// Если хеш переписки получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Подписываемое содержимое
		vector <uint8_t> content;
		// Если подписываемое содержимое составить не удалось
		if(message::content(view_t(digest, 32), true, content) != message::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Секретный ключ сервера
		keys::key_t key;
		// Если секретный ключ разобрать не удалось
		if(keys::decode(std::string(credential.secret.begin(), credential.secret.end()), view_t(), key) != keys::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Объект подписи RSA
		sign::rsa_t rsa;
		// Если ключ RSA загрузить не удалось
		if(!key.load(rsa))
			// Выводим отказ ответа
			return false;
		// Хеш подписываемого содержимого
		const digest::hash_t algorithm = ((hostility == hostility_t::ODDSCHEME) ? digest::hash_t::SHA384 : digest::hash_t::SHA256);
		// Хеш подписываемого содержимого
		uint8_t hashed[64];
		// Если хеш вычислить не удалось
		if(!digest::hash(algorithm, view_t(content.data(), content.size()), hashed, sizeof(hashed)))
			// Выводим отказ ответа
			return false;
		// Подпись владения ключом
		vector <uint8_t> signature(rsa.size(), 0);
		// Схема подписи: PKCS #1 v1.5 по заказу, иначе RSASSA-PSS
		const bool legacy = (hostility == hostility_t::PKCS1);
		// Если подпись выработать не удалось
		if(!rsa.make((legacy ? sign::scheme_t::PKCS1 : sign::scheme_t::PSS), algorithm, view_t(hashed, digest::length(algorithm)), signature.data(), digest::length(algorithm)))
			// Выводим отказ ответа
			return false;
		// Сообщение подписи владения ключом
		message::verify_t verify;
		// Устанавливаем схему подписи: 0x0401 у PKCS #1 v1.5
		verify.scheme = (legacy ? static_cast <extension::scheme_t> (0x0401) : ((hostility == hostility_t::ODDSCHEME) ? extension::scheme_t::RSA_PSS_RSAE_SHA384 : extension::scheme_t::RSA_PSS_RSAE_SHA256));
		// Устанавливаем подпись
		verify.signature = view_t(signature.data(), signature.size());
		// Тело сообщения подписи
		vector <uint8_t> witnessed;
		// Если подпись составить либо доставить не удалось
		if((message::build(verify, witnessed) != message::error_t::NONE) || !deliver(handshake::type_t::VERIFY, view_t(witnessed.data(), witnessed.size())))
			// Выводим отказ ответа
			return false;
		// Ключ завершения сервера
		uint8_t completion[64];
		// Если ключ завершения вывести не удалось
		if(secrets.finished(session::side_t::SERVER, completion) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Если хеш переписки получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ ответа
			return false;
		// Тело завершения
		uint8_t finished[64];
		// Если завершение выработать либо доставить не удалось
		if((message::finished(digest::hash_t::SHA256, view_t(completion, 32), view_t(digest, 32), finished) != message::error_t::NONE) || !deliver(handshake::type_t::FINISHED, view_t(finished, 32)))
			// Выводим отказ ответа
			return false;
		// Подаём ответ враждебного сервера клиенту
		client.push(view_t(answered.data(), answered.size()));
		// Выводим успешность ответа
		return true;
	}
	/**
	 * @brief Метод настройки пары связей на классический набор, группу и ключ
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования
	 * @param group      группа обмена ключами
	 * @param credential подлинность сервера
	 * @param mutual     признак запроса подлинности клиента тою же подлинностью
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual) noexcept {
		// Устанавливаем набор шифрования обеим сторонам
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
	 * Наборы шифрования классической ветви
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};

	/**
	 * Группы обмена классической ветви
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1};

	/**
	 * Ключи набора и схемы их подписи
	 */
	static const struct Entry {
		// Имя ключа набора
		const char * name;
		// Схема подписи ключа
		extension::scheme_t scheme;
	} ENTRIES[] = {
		{"rsa2048", extension::scheme_t::RSA_PSS_RSAE_SHA256},
		{"ec256", extension::scheme_t::ECDSA_SECP256R1_SHA256},
		{"ec384", extension::scheme_t::ECDSA_SECP384R1_SHA384},
		{"ed25519", extension::scheme_t::ED25519}
	};
};

/**
 * Проверка простого рукопожатия 1-RTT по разделу 3 RFC 8448: обмен X25519, расписание
 * ключей, ключи записей, завершения, защищённые записи и ключ билета байт в байт
 */
TEST(ClassicTest, Rfc8448Simple){
	// Набор шифрования следа
	const protect::suite_t suite = protect::suite_t::AES_128_GCM_SHA256;
	// Секретный ключ клиента
	const vector <uint8_t> secret = decode(rfc8448::S3_CLIENT_PRIVATE);
	// Открытый ключ клиента
	uint8_t opened[32];
	// Проверяем выработку открытого ключа клиента
	ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), opened));
	// Проверяем схождение открытого ключа клиента с RFC
	ASSERT_EQ(vector <uint8_t> (opened, opened + 32), decode(rfc8448::S3_CLIENT_PUBLIC));
	// Открытый ключ сервера
	const vector <uint8_t> peer = decode(rfc8448::S3_SERVER_PUBLIC);
	// Общее значение обмена
	uint8_t shared[32];
	// Проверяем выработку общего значения клиентом
	ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), view_t(peer.data(), peer.size()), shared));
	// Проверяем схождение общего значения с IKM ступени рукопожатия
	ASSERT_EQ(vector <uint8_t> (shared, shared + 32), decode(rfc8448::S3_HANDSHAKE_IKM));
	// Секретный ключ сервера
	const vector <uint8_t> serving = decode(rfc8448::S3_SERVER_PRIVATE);
	// Общее значение обмена стороной сервера
	uint8_t reply[32];
	// Проверяем выработку общего значения сервером по ключу клиента
	ASSERT_TRUE(agreement::x25519(view_t(serving.data(), serving.size()), view_t(opened, sizeof(opened)), reply));
	// Проверяем схождение общих значений сторон
	ASSERT_EQ(::memcmp(shared, reply, 32), 0);
	// Переписка рукопожатия: до выбора набора ведётся всеми хешами
	session::transcript_t transcript;
	// Начинаем переписку
	transcript.start();
	// Приветствие клиента
	const vector <uint8_t> hello = decode(rfc8448::S3_CLIENT_HELLO);
	// Добавляем приветствие клиента в переписку
	ASSERT_EQ(transcript.update(view_t(hello.data(), hello.size())), session::error_t::NONE);
	// Выбираем хеш набора
	ASSERT_EQ(transcript.select(protect::hash(suite)), session::error_t::NONE);
	// Проверяем хеш и длину переписки
	ASSERT_EQ(transcript.algorithm(), digest::hash_t::SHA256);
	// Проверяем длину хеша переписки
	ASSERT_EQ(transcript.size(), static_cast <size_t> (32));
	// Приветствие сервера
	const vector <uint8_t> answer = decode(rfc8448::S3_SERVER_HELLO);
	// Добавляем приветствие сервера в переписку
	ASSERT_EQ(transcript.update(view_t(answer.data(), answer.size())), session::error_t::NONE);
	// Хеш переписки
	uint8_t digest[64];
	// Получаем хеш переписки по приветствиям
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Расписание ключей
	session::secrets_t secrets;
	// Заводим начальную ступень без заранее разделённого ключа
	ASSERT_EQ(secrets.start(protect::hash(suite), view_t(nullptr, 0)), session::error_t::NONE);
	// Проверяем хеш расписания
	ASSERT_EQ(secrets.algorithm(), digest::hash_t::SHA256);
	// Проверяем длину значения расписания
	ASSERT_EQ(secrets.size(), static_cast <size_t> (32));
	// Выводим ступень рукопожатия
	ASSERT_EQ(secrets.handshake(view_t(shared, sizeof(shared)), view_t(digest, 32)), session::error_t::NONE);
	// Значение направления
	uint8_t traffic[64];
	// Получаем значение направления клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S3_C_HS));
	// Получаем значение направления сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 s hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S3_S_HS));
	// Ключ и вектор замены
	uint8_t key[protect::PROTECT_KEY], vector_[protect::PROTECT_VECTOR];
	// Выводим ключевой материал сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, suite, key, vector_), session::error_t::NONE);
	// Проверяем длину ключа набора
	ASSERT_EQ(protect::key(suite), static_cast <size_t> (16));
	// Проверяем длину вектора набора
	ASSERT_EQ(protect::block(suite), static_cast <size_t> (12));
	// Проверяем длину метки набора
	ASSERT_EQ(protect::tag(suite), static_cast <size_t> (16));
	// Проверяем схождение ключа записей сервера
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_S_HS_KEY));
	// Проверяем схождение вектора замены сервера
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S3_S_HS_IV));
	// Защита записей сервера
	protect::protection_t outgoing;
	// Заводим защиту записей сервера
	ASSERT_TRUE(outgoing.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Ключ завершения сервера
	uint8_t completion[64];
	// Выводим ключ завершения сервера
	ASSERT_EQ(secrets.finished(session::side_t::SERVER, completion), session::error_t::NONE);
	// Проверяем схождение ключа завершения сервера
	ASSERT_EQ(vector <uint8_t> (completion, completion + 32), decode(rfc8448::S3_SERVER_FINISHED_KEY));
	// Защищённые расширения, цепочка и подпись сервера
	const vector <uint8_t> extensions = decode(rfc8448::S3_ENCRYPTED_EXTENSIONS);
	// Цепочка сертификатов
	const vector <uint8_t> certificate = decode(rfc8448::S3_CERTIFICATE);
	// Подпись владения ключом
	const vector <uint8_t> verify = decode(rfc8448::S3_CERTIFICATE_VERIFY);
	// Добавляем защищённые расширения в переписку
	ASSERT_EQ(transcript.update(view_t(extensions.data(), extensions.size())), session::error_t::NONE);
	// Добавляем цепочку в переписку
	ASSERT_EQ(transcript.update(view_t(certificate.data(), certificate.size())), session::error_t::NONE);
	// Добавляем подпись в переписку
	ASSERT_EQ(transcript.update(view_t(verify.data(), verify.size())), session::error_t::NONE);
	// Получаем хеш переписки до завершения сервера
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Завершение сервера
	uint8_t finished[64];
	// Вырабатываем завершение сервера
	ASSERT_EQ(message::finished(digest::hash_t::SHA256, view_t(completion, 32), view_t(digest, 32), finished), message::error_t::NONE);
	// Проверяем схождение завершения сервера
	ASSERT_EQ(vector <uint8_t> (finished, finished + 32), decode(rfc8448::S3_SERVER_FINISHED));
	// Весь защищённый выход сервера: расширения, цепочка, подпись и завершение одним сообщением
	const vector <uint8_t> flight = decode(rfc8448::S3_SERVER_FLIGHT_PAYLOAD);
	// Накопитель защищённой записи
	vector <uint8_t> sealed;
	// Накладываем защиту на выход сервера
	ASSERT_EQ(outgoing.seal(record::type_t::HANDSHAKE, view_t(flight.data(), flight.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение защищённой записи сервера байт в байт
	ASSERT_EQ(sealed, decode(rfc8448::S3_SERVER_FLIGHT_RECORD));
	// Сообщение завершения сервера с обвязкой
	const vector <uint8_t> finishing(flight.end() - 36, flight.end());
	// Добавляем завершение сервера в переписку
	ASSERT_EQ(transcript.update(view_t(finishing.data(), finishing.size())), session::error_t::NONE);
	// Получаем хеш переписки по завершение сервера
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Ключ завершения клиента снимается до перехода к прикладным данным
	uint8_t completing[64];
	// Выводим ключ завершения клиента
	ASSERT_EQ(secrets.finished(session::side_t::CLIENT, completing), session::error_t::NONE);
	// Проверяем схождение ключа завершения клиента
	ASSERT_EQ(vector <uint8_t> (completing, completing + 32), decode(rfc8448::S3_CLIENT_FINISHED_KEY));
	// Ключевой материал клиента на ступени рукопожатия
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа записей клиента
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_C_HS_KEY));
	// Проверяем схождение вектора замены клиента
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S3_C_HS_IV));
	// Защита записей клиента
	protect::protection_t incoming;
	// Заводим защиту записей клиента
	ASSERT_TRUE(incoming.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Выводим ступень прикладных данных
	ASSERT_EQ(secrets.application(view_t(digest, 32)), session::error_t::NONE);
	// Получаем значение направления клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c ap traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S3_C_AP));
	// Получаем значение направления сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 s ap traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S3_S_AP));
	// Завершение клиента
	ASSERT_EQ(message::finished(digest::hash_t::SHA256, view_t(completing, 32), view_t(digest, 32), finished), message::error_t::NONE);
	// Проверяем схождение завершения клиента
	ASSERT_EQ(vector <uint8_t> (finished, finished + 32), decode(rfc8448::S3_CLIENT_FINISHED));
	// Составитель сообщения завершения клиента
	handshake::writer_t writer;
	// Обвязываем завершение клиента
	ASSERT_EQ(writer.push(handshake::type_t::FINISHED, view_t(finished, 32)), handshake::error_t::NONE);
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на завершение клиента
	ASSERT_EQ(incoming.seal(record::type_t::HANDSHAKE, writer.data(), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение защищённой записи клиента байт в байт
	ASSERT_EQ(sealed, decode(rfc8448::S3_CLIENT_FINISHED_RECORD));
	// Добавляем завершение клиента в переписку
	ASSERT_EQ(transcript.update(writer.data()), session::error_t::NONE);
	// Получаем хеш переписки по завершение клиента
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Выводим значение возобновления
	ASSERT_EQ(secrets.resumption(view_t(digest, 32)), session::error_t::NONE);
	// Одноразовое значение билета
	const uint8_t nonce[2] = {0x00, 0x00};
	// Ключ билета
	uint8_t ticket[64];
	// Выводим ключ билета
	ASSERT_EQ(secrets.ticket(view_t(nonce, sizeof(nonce)), ticket), session::error_t::NONE);
	// Проверяем схождение ключа билета с «tls13 resumption»
	ASSERT_EQ(vector <uint8_t> (ticket, ticket + 32), decode(rfc8448::S3_RESUMPTION));
	// Ключевой материал прикладных данных сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа записей сервера
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_S_AP_KEY));
	// Проверяем схождение вектора замены сервера
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S3_S_AP_IV));
	// Заводим защиту прикладных записей сервера
	ASSERT_TRUE(outgoing.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Билет возобновления сервера
	const vector <uint8_t> issued = decode(rfc8448::S3_TICKET);
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на билет
	ASSERT_EQ(outgoing.seal(record::type_t::HANDSHAKE, view_t(issued.data(), issued.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи билета байт в байт
	ASSERT_EQ(sealed, decode(rfc8448::S3_TICKET_RECORD));
	// Прикладные данные сторон
	const vector <uint8_t> data = decode(rfc8448::S3_APP_PAYLOAD);
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на прикладные данные сервера
	ASSERT_EQ(outgoing.seal(record::type_t::APPLICATION, view_t(data.data(), data.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение прикладной записи сервера
	ASSERT_EQ(sealed, decode(rfc8448::S3_SERVER_APP_RECORD));
	// Извещение о закрытии
	const uint8_t notice[2] = {0x01, 0x00};
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на извещение сервера
	ASSERT_EQ(outgoing.seal(record::type_t::ALERT, view_t(notice, sizeof(notice)), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи извещения сервера
	ASSERT_EQ(sealed, decode(rfc8448::S3_SERVER_ALERT_RECORD));
	// Ключевой материал прикладных данных клиента
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа записей клиента
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_C_AP_KEY));
	// Проверяем схождение вектора замены клиента
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S3_C_AP_IV));
	// Заводим защиту прикладных записей клиента
	ASSERT_TRUE(incoming.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на прикладные данные клиента
	ASSERT_EQ(incoming.seal(record::type_t::APPLICATION, view_t(data.data(), data.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение прикладной записи клиента
	ASSERT_EQ(sealed, decode(rfc8448::S3_CLIENT_APP_RECORD));
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на извещение клиента
	ASSERT_EQ(incoming.seal(record::type_t::ALERT, view_t(notice, sizeof(notice)), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи извещения клиента
	ASSERT_EQ(sealed, decode(rfc8448::S3_CLIENT_ALERT_RECORD));
	// Снятие защиты с записи сервера: заголовок и содержимое
	const vector <uint8_t> record = decode(rfc8448::S3_SERVER_FLIGHT_RECORD);
	// Заголовок записи
	record::header_t header;
	// Разбираем заголовок записи
	ASSERT_EQ(record::parse(view_t(record.data(), record.size()), header), record::error_t::NONE);
	// Ключевой материал сервера на ступени рукопожатия заново
	const vector <uint8_t> hkey = decode(rfc8448::S3_S_HS_KEY), hiv = decode(rfc8448::S3_S_HS_IV);
	// Защита записей принимающей стороны
	protect::protection_t receiver;
	// Заводим защиту записей принимающей стороны
	ASSERT_TRUE(receiver.start(suite, view_t(hkey.data(), hkey.size()), view_t(hiv.data(), hiv.size())));
	// Истинный вид содержимого
	record::type_t type = record::type_t::NONE;
	// Накопитель открытого содержимого
	vector <uint8_t> opened_;
	// Снимаем защиту с записи сервера
	ASSERT_EQ(receiver.open(header, view_t(record.data() + record::RECORD_HEADER, record.size() - record::RECORD_HEADER), type, opened_), protect::error_t::NONE);
	// Проверяем вид содержимого
	ASSERT_EQ(type, record::type_t::HANDSHAKE);
	// Проверяем схождение открытого содержимого с выходом сервера
	ASSERT_EQ(opened_, flight);
}

/**
 * Проверка возобновления с упреждающими данными по разделу 4 RFC 8448: привязка билета,
 * ключи упреждения, расписание и записи байт в байт
 */
TEST(ClassicTest, Rfc8448Resumed){
	// Набор шифрования следа
	const protect::suite_t suite = protect::suite_t::AES_128_GCM_SHA256;
	// Ключ билета из раздела 3
	const vector <uint8_t> psk = decode(rfc8448::S3_RESUMPTION);
	// Расписание ключей на ключе билета
	session::secrets_t secrets;
	// Заводим начальную ступень на ключе билета
	ASSERT_EQ(secrets.start(digest::hash_t::SHA256, view_t(psk.data(), psk.size())), session::error_t::NONE);
	// Переписка рукопожатия
	session::transcript_t transcript;
	// Начинаем переписку
	transcript.start();
	// Усечённое приветствие клиента
	const vector <uint8_t> prefix = decode(rfc8448::S4_BINDER_PREFIX);
	// Хеш переписки
	uint8_t digest[64];
	// Получаем хеш усечённого приветствия хешем набора билета: набор связи ещё не выбран
	ASSERT_EQ(transcript.digest(digest::hash_t::SHA256, view_t(prefix.data(), prefix.size()), digest), session::error_t::NONE);
	// Привязка билета
	uint8_t binder[64];
	// Вырабатываем привязку билета
	ASSERT_EQ(secrets.binder(view_t(digest, 32), binder), session::error_t::NONE);
	// Проверяем схождение привязки с RFC
	ASSERT_EQ(vector <uint8_t> (binder, binder + 32), decode(rfc8448::S4_BINDER));
	// Запись приветствия клиента: листинг самого сообщения в RFC усечён, полное - в записи
	const vector <uint8_t> record = decode(rfc8448::S4_CLIENT_HELLO_RECORD);
	// Полное приветствие клиента без заголовка записи
	const vector <uint8_t> hello(record.begin() + record::RECORD_HEADER, record.end());
	// Проверяем, что усечённое приветствие есть начало полного без привязки
	ASSERT_EQ(vector <uint8_t> (hello.begin(), hello.begin() + prefix.size()), prefix);
	// Проверяем, что привязка стоит в хвосте приветствия
	ASSERT_EQ(::memcmp(hello.data() + hello.size() - 32, binder, 32), 0);
	// Добавляем приветствие клиента в переписку
	ASSERT_EQ(transcript.update(view_t(hello.data(), hello.size())), session::error_t::NONE);
	// Получаем хеш приветствия хешем билета
	ASSERT_EQ(transcript.digest(digest::hash_t::SHA256, view_t(nullptr, 0), digest), session::error_t::NONE);
	// Выводим значение упреждающих данных
	ASSERT_EQ(secrets.early(view_t(digest, 32)), session::error_t::NONE);
	// Значение упреждающих данных
	uint8_t traffic[64];
	// Получаем значение упреждающих данных
	ASSERT_EQ(secrets.early(traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c e traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S4_C_E_TRAFFIC));
	// Ключ и вектор замены
	uint8_t key[protect::PROTECT_KEY], vector_[protect::PROTECT_VECTOR];
	// Выводим ключевой материал упреждающих данных
	ASSERT_EQ(session::material(view_t(traffic, 32), suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа упреждения
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S4_E_KEY));
	// Проверяем схождение вектора упреждения
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S4_E_IV));
	// Защита записей упреждения
	protect::protection_t early;
	// Заводим защиту записей упреждения
	ASSERT_TRUE(early.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Упреждающие данные
	const vector <uint8_t> data = decode(rfc8448::S4_EARLY_APP_PAYLOAD);
	// Накопитель записи
	vector <uint8_t> sealed;
	// Накладываем защиту на упреждающие данные
	ASSERT_EQ(early.seal(record::type_t::APPLICATION, view_t(data.data(), data.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи упреждающих данных
	ASSERT_EQ(sealed, decode(rfc8448::S4_EARLY_APP_RECORD));
	// Выбираем хеш набора связи
	ASSERT_EQ(transcript.select(protect::hash(suite)), session::error_t::NONE);
	// Приветствие сервера
	const vector <uint8_t> answer = decode(rfc8448::S4_SERVER_HELLO);
	// Добавляем приветствие сервера в переписку
	ASSERT_EQ(transcript.update(view_t(answer.data(), answer.size())), session::error_t::NONE);
	// Общее значение обмена
	uint8_t shared[32];
	// Секретный ключ клиента
	const vector <uint8_t> secret = decode(rfc8448::S4_CLIENT_PRIVATE);
	// Открытый ключ сервера
	const vector <uint8_t> peer = decode(rfc8448::S4_SERVER_PUBLIC);
	// Вырабатываем общее значение
	ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), view_t(peer.data(), peer.size()), shared));
	// Проверяем схождение общего значения
	ASSERT_EQ(vector <uint8_t> (shared, shared + 32), decode(rfc8448::S4_HANDSHAKE_IKM));
	// Получаем хеш переписки
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Выводим ступень рукопожатия
	ASSERT_EQ(secrets.handshake(view_t(shared, sizeof(shared)), view_t(digest, 32)), session::error_t::NONE);
	// Получаем значение направления сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 s hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S4_S_HS));
	// Получаем значение направления клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S4_C_HS));
	// Выводим ключевой материал сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, suite, key, vector_), session::error_t::NONE);
	// Защита записей сервера
	protect::protection_t outgoing;
	// Заводим защиту записей сервера
	ASSERT_TRUE(outgoing.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Выход сервера: расширения и завершение
	const vector <uint8_t> flight = decode(rfc8448::S4_SERVER_FLIGHT_PAYLOAD);
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на выход сервера
	ASSERT_EQ(outgoing.seal(record::type_t::HANDSHAKE, view_t(flight.data(), flight.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи выхода сервера
	ASSERT_EQ(sealed, decode(rfc8448::S4_SERVER_FLIGHT_RECORD));
	// Добавляем выход сервера в переписку
	ASSERT_EQ(transcript.update(view_t(flight.data(), flight.size())), session::error_t::NONE);
	// Ключевой материал клиента на ступени рукопожатия
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа записей клиента
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S4_C_HS_KEY));
	// Защита записей клиента
	protect::protection_t incoming;
	// Заводим защиту записей клиента
	ASSERT_TRUE(incoming.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Конец упреждающих данных
	const vector <uint8_t> ending = decode(rfc8448::S4_EOED);
	// Сбрасываем накопитель записи
	sealed.clear();
	/**
	 * Раздел 4.5 RFC 8446: конец упреждающих данных идёт под ключами упреждения, второй
	 * записью того же направления
	 */
	ASSERT_EQ(early.seal(record::type_t::HANDSHAKE, view_t(ending.data(), ending.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи конца упреждающих данных
	ASSERT_EQ(sealed, decode(rfc8448::S4_EOED_RECORD));
	// Ключ завершения клиента
	uint8_t completion[64];
	// Выводим ключ завершения клиента
	ASSERT_EQ(secrets.finished(session::side_t::CLIENT, completion), session::error_t::NONE);
	// Получаем хеш переписки по выход сервера
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Выводим ступень прикладных данных
	ASSERT_EQ(secrets.application(view_t(digest, 32)), session::error_t::NONE);
	// Получаем значение направления сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 s ap traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S4_S_AP));
	// Добавляем конец упреждающих данных в переписку
	ASSERT_EQ(transcript.update(view_t(ending.data(), ending.size())), session::error_t::NONE);
	// Получаем хеш переписки по конец упреждающих данных
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Завершение клиента
	uint8_t finished[64];
	// Вырабатываем завершение клиента
	ASSERT_EQ(message::finished(digest::hash_t::SHA256, view_t(completion, 32), view_t(digest, 32), finished), message::error_t::NONE);
	// Проверяем схождение завершения клиента
	ASSERT_EQ(vector <uint8_t> (finished, finished + 32), decode(rfc8448::S4_CLIENT_FINISHED));
	// Составитель сообщения завершения
	handshake::writer_t writer;
	// Обвязываем завершение клиента
	ASSERT_EQ(writer.push(handshake::type_t::FINISHED, view_t(finished, 32)), handshake::error_t::NONE);
	// Сбрасываем накопитель записи
	sealed.clear();
	// Накладываем защиту на завершение клиента: первая запись под ключами рукопожатия
	ASSERT_EQ(incoming.seal(record::type_t::HANDSHAKE, writer.data(), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи завершения клиента
	ASSERT_EQ(sealed, decode(rfc8448::S4_CLIENT_FINISHED_RECORD));
	// Добавляем завершение клиента в переписку
	ASSERT_EQ(transcript.update(writer.data()), session::error_t::NONE);
	// Получаем хеш переписки по завершение клиента
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Выводим значение возобновления
	ASSERT_EQ(secrets.resumption(view_t(digest, 32)), session::error_t::NONE);
	// Ключ билета с одноразовым значением 0000
	const uint8_t nonce[2] = {0x00, 0x00};
	// Ключ билета
	uint8_t ticket[64];
	// Выводим ключ билета: сличается с RFC лишь значение возобновления через ключ билета
	ASSERT_EQ(secrets.ticket(view_t(nonce, sizeof(nonce)), ticket), session::error_t::NONE);
	// Значение возобновления по RFC
	const vector <uint8_t> master = decode(rfc8448::S4_RES_MASTER);
	// Ожидаемый ключ билета из значения возобновления RFC
	uint8_t expected[64];
	// Выводим ожидаемый ключ билета
	ASSERT_TRUE(schedule::derive(digest::hash_t::SHA256, view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> ("resumption"), 10), view_t(nonce, sizeof(nonce)), expected, 32));
	// Проверяем схождение ключа билета
	ASSERT_EQ(::memcmp(ticket, expected, 32), 0);
}

/**
 * Проверка просьбы о повторе приветствия по разделу 5 RFC 8448: замена переписки хешем,
 * обмен по P-256 несжатой точкой и расписание байт в байт
 */
TEST(ClassicTest, Rfc8448Retry){
	// Набор шифрования следа
	const protect::suite_t suite = protect::suite_t::AES_128_GCM_SHA256;
	// Кривая P-256
	curve::curve_t curve;
	// Заводим кривую P-256
	ASSERT_TRUE(curve::parameters(extension::curve(extension::group_t::SECP256R1), curve));
	// Секретный ключ клиента прямой записью
	const vector <uint8_t> secret = decode(rfc8448::S5_CLIENT_P256_PRIVATE);
	// Открытый ключ сервера несжатой точкой
	const vector <uint8_t> peer = decode(rfc8448::S5_SERVER_P256_PUBLIC);
	// Проверяем длину доли ключа P-256
	ASSERT_EQ(extension::length(extension::group_t::SECP256R1), static_cast <size_t> (65));
	// Проверяем признак несжатой точки
	ASSERT_EQ(peer[0], 0x04);
	// Секретный ключ и координаты обратной записью для выработки
	uint8_t reversed[32], point[64];
	/**
	 * Выполняем перенос секретного ключа и координат обратной записью
	 */
	for(size_t i = 0; i < 32; i++){
		// Переносим байт секретного ключа
		reversed[i] = secret[31 - i];
		// Переносим байт первой координаты
		point[i] = peer[32 - i];
		// Переносим байт второй координаты
		point[32 + i] = peer[64 - i];
	}
	// Общее значение обратной записью
	uint8_t backward[32];
	// Вырабатываем общее значение
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(reversed, sizeof(reversed)), view_t(point, sizeof(point)), backward));
	// Общее значение прямой записью
	uint8_t shared[32];
	/**
	 * Выполняем перенос общего значения прямой записью
	 */
	for(size_t i = 0; i < 32; i++)
		// Переносим очередной байт
		shared[i] = backward[31 - i];
	// Проверяем схождение общего значения с IKM
	ASSERT_EQ(vector <uint8_t> (shared, shared + 32), decode(rfc8448::S5_HANDSHAKE_IKM));
	// Переписка рукопожатия
	session::transcript_t transcript;
	// Начинаем переписку
	transcript.start();
	// Первое приветствие клиента
	const vector <uint8_t> first = decode(rfc8448::S5_CLIENT_HELLO1);
	// Добавляем первое приветствие в переписку
	ASSERT_EQ(transcript.update(view_t(first.data(), first.size())), session::error_t::NONE);
	// Выбираем хеш набора
	ASSERT_EQ(transcript.select(protect::hash(suite)), session::error_t::NONE);
	// Заменяем переписку хешем первого приветствия
	ASSERT_EQ(transcript.replace(), session::error_t::NONE);
	// Просьба о повторе, второе приветствие и приветствие сервера
	const vector <uint8_t> retry = decode(rfc8448::S5_HRR), second = decode(rfc8448::S5_CLIENT_HELLO2), answer = decode(rfc8448::S5_SERVER_HELLO);
	// Добавляем просьбу о повторе в переписку
	ASSERT_EQ(transcript.update(view_t(retry.data(), retry.size())), session::error_t::NONE);
	// Добавляем второе приветствие в переписку
	ASSERT_EQ(transcript.update(view_t(second.data(), second.size())), session::error_t::NONE);
	// Добавляем приветствие сервера в переписку
	ASSERT_EQ(transcript.update(view_t(answer.data(), answer.size())), session::error_t::NONE);
	// Хеш переписки
	uint8_t digest[64];
	// Получаем хеш переписки
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Расписание ключей
	session::secrets_t secrets;
	// Заводим начальную ступень
	ASSERT_EQ(secrets.start(digest::hash_t::SHA256, view_t(nullptr, 0)), session::error_t::NONE);
	// Выводим ступень рукопожатия
	ASSERT_EQ(secrets.handshake(view_t(shared, sizeof(shared)), view_t(digest, 32)), session::error_t::NONE);
	// Значение направления
	uint8_t traffic[64];
	// Получаем значение направления клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S5_C_HS));
	// Получаем значение направления сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 s hs traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S5_S_HS));
	// Ключ и вектор замены
	uint8_t key[protect::PROTECT_KEY], vector_[protect::PROTECT_VECTOR];
	// Выводим ключевой материал сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа записей сервера
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S5_S_HS_KEY));
	// Проверяем схождение вектора замены сервера
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S5_S_HS_IV));
	// Защита записей сервера
	protect::protection_t outgoing;
	// Заводим защиту записей сервера
	ASSERT_TRUE(outgoing.start(suite, view_t(key, 16), view_t(vector_, 12)));
	// Выход сервера
	const vector <uint8_t> flight = decode(rfc8448::S5_SERVER_FLIGHT_PAYLOAD);
	// Накопитель записи
	vector <uint8_t> sealed;
	// Накладываем защиту на выход сервера
	ASSERT_EQ(outgoing.seal(record::type_t::HANDSHAKE, view_t(flight.data(), flight.size()), sealed, 0), protect::error_t::NONE);
	// Проверяем схождение записи выхода сервера
	ASSERT_EQ(sealed, decode(rfc8448::S5_SERVER_FLIGHT_RECORD));
	// Ключ завершения сервера
	uint8_t completion[64];
	// Выводим ключ завершения сервера
	ASSERT_EQ(secrets.finished(session::side_t::SERVER, completion), session::error_t::NONE);
	// Добавляем выход сервера без завершения в переписку
	ASSERT_EQ(transcript.update(view_t(flight.data(), flight.size() - 36)), session::error_t::NONE);
	// Получаем хеш переписки до завершения сервера
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Завершение сервера
	uint8_t finished[64];
	// Вырабатываем завершение сервера
	ASSERT_EQ(message::finished(digest::hash_t::SHA256, view_t(completion, 32), view_t(digest, 32), finished), message::error_t::NONE);
	// Проверяем схождение завершения сервера
	ASSERT_EQ(vector <uint8_t> (finished, finished + 32), decode(rfc8448::S5_SERVER_FINISHED));
	// Добавляем завершение сервера в переписку
	ASSERT_EQ(transcript.update(view_t(flight.data() + flight.size() - 36, 36)), session::error_t::NONE);
	// Получаем хеш переписки по завершение сервера
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Ключ завершения клиента
	uint8_t completing[64];
	// Выводим ключ завершения клиента
	ASSERT_EQ(secrets.finished(session::side_t::CLIENT, completing), session::error_t::NONE);
	// Выводим ступень прикладных данных
	ASSERT_EQ(secrets.application(view_t(digest, 32)), session::error_t::NONE);
	// Получаем значение направления клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Проверяем схождение с «tls13 c ap traffic»
	ASSERT_EQ(vector <uint8_t> (traffic, traffic + 32), decode(rfc8448::S5_C_AP));
	// Вырабатываем завершение клиента
	ASSERT_EQ(message::finished(digest::hash_t::SHA256, view_t(completing, 32), view_t(digest, 32), finished), message::error_t::NONE);
	// Проверяем схождение завершения клиента
	ASSERT_EQ(vector <uint8_t> (finished, finished + 32), decode(rfc8448::S5_CLIENT_FINISHED));
}

/**
 * Проверка петлевого рукопожатия по всем сочетаниям набора, группы и ключа сервера со
 * встречной подлинностью клиента, билетом, возобновлением и сменой ключей
 */
TEST(ClassicTest, Loopback){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность из ключей набора
		ASSERT_TRUE(identity(ENTRIES[k].name, credential)) << "ключ " << ENTRIES[k].name;
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			/**
			 * Выполняем перебор групп обмена
			 */
			for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
				// Связь стороны клиента
				client::context_t client;
				// Связь стороны сервера
				server::context_t server;
				// Настраиваем стороны с подлинностью клиента
				arrange(client, server, SUITES[s], GROUPS[g], credential, true);
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE) << ENTRIES[k].name << " " << s << " " << g;
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE) << ENTRIES[k].name << " " << s << " " << g;
				// Проводим рукопожатие
				converse(client, server);
				// Проверяем установленность связи клиентом
				ASSERT_TRUE(client.established()) << ENTRIES[k].name << " " << s << " " << g << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Проверяем установленность связи сервером
				ASSERT_TRUE(server.established()) << ENTRIES[k].name << " " << s << " " << g;
				// Проверяем набор шифрования
				ASSERT_EQ(client.suite(), SUITES[s]);
				// Проверяем схождение наборов сторон
				ASSERT_EQ(server.suite(), SUITES[s]);
				// Проверяем цепочку сервера у клиента
				ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
				// Проверяем цепочку клиента у сервера
				ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
				// Проверяем обмен данными
				ASSERT_TRUE(barter(client, server)) << ENTRIES[k].name << " " << s << " " << g;
				// Смена ключей с просьбой об ответной
				ASSERT_EQ(client.update(true), context::error_t::NONE);
				// Проводим смену ключей
				converse(client, server);
				// Проверяем обмен данными после смены ключей
				ASSERT_TRUE(barter(client, server)) << ENTRIES[k].name << " " << s << " " << g;
				// Выдаём билет
				ASSERT_EQ(server.issue(), context::error_t::NONE);
				// Доставляем билет
				converse(client, server);
				// Проверяем получение билета клиентом
				ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
				// Проверяем набор билета
				ASSERT_EQ(client.tickets()[0].suite, SUITES[s]);
				// Проверяем длину ключа билета по хешу набора
				ASSERT_EQ(client.tickets()[0].secret.size(), digest::length(protect::hash(SUITES[s])));
				// Связь возобновляющего клиента
				client::context_t resuming;
				// Связь возобновляющего сервера
				server::context_t resumed;
				// Настраиваем стороны без подлинности клиента
				arrange(resuming, resumed, SUITES[s], GROUPS[g], credential, false);
				// Предъявляем билет
				resuming.resume(client.tickets()[0]);
				// Признаём билеты
				resumed.resume(server.tickets());
				// Заводим сервер
				ASSERT_EQ(resumed.start(), context::error_t::NONE);
				// Заводим клиента
				ASSERT_EQ(resuming.start(), context::error_t::NONE);
				// Проводим рукопожатие
				converse(resuming, resumed);
				// Проверяем установленность связи
				ASSERT_TRUE(resuming.established() && resumed.established()) << ENTRIES[k].name << " " << s << " " << g;
				// Проверяем возобновление билетом
				ASSERT_TRUE(resuming.shared() && resumed.shared()) << ENTRIES[k].name << " " << s << " " << g;
				// Проверяем обмен данными по возобновлённой связи
				ASSERT_TRUE(barter(resuming, resumed));
			}
		}
	}
}

/**
 * Проверка просьбы о повторе приветствия по группе: клиент шлёт долю по одной группе, а
 * сервер ведёт другую из объявленных клиентом
 */
TEST(ClassicTest, Retry){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, SUITES[s], extension::group_t::X25519, credential, false);
		// Клиент объявляет две группы
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::SECP384R1});
		// Клиент шлёт долю лишь по первой
		client.shares(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Сервер ведёт лишь вторую
		server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие с просьбой о повторе
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established()) << s << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	// Доли по двум группам разом: сервер выбирает по своему предпочтению без повтора
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Клиент объявляет три группы
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
	// Клиент шлёт доли по двум
	client.shares(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Сервер предпочитает P-256
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::X25519});
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
	// Доля вне объявленных групп - ошибка настройки
	client::context_t wrong;
	// Клиент объявляет X25519
	wrong.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Доля по P-256 вне объявленных
	wrong.shares(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Проверяем отказ заведения
	ASSERT_EQ(wrong.start(), context::error_t::SETTINGS);
}

/**
 * Проверка отказов: набор без общей группы, подпись не той схемы, PKCS #1 v1.5 в
 * CertificateVerify, доля вне кривой у сервера и у клиента, схема вне предложения
 */
TEST(ClassicTest, Refusals){
	// Подлинность RSA
	context::credential_t rsa;
	// Составляем подлинность RSA
	ASSERT_TRUE(identity("rsa2048", rsa));
	// Подлинность EC
	context::credential_t ec;
	// Составляем подлинность EC
	ASSERT_TRUE(identity("ec256", ec));
	{
		// Связь стороны клиента без общей группы
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::SECP384R1, ec, false);
		// Сервер ведёт лишь X25519
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем отказ сервера по группе
		ASSERT_EQ(server.error(), context::error_t::GROUP);
		// Проверяем извещение
		ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Клиент признаёт лишь ECDSA, а ключ сервера - RSA
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, rsa, false);
		// Клиент признаёт лишь ECDSA
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256});
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем отказ сервера по схеме
		ASSERT_EQ(server.error(), context::error_t::SCHEME);
		// Проверяем извещение
		ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Сервер признаёт лишь RSA-PSS, а ключ клиента - EC
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, rsa, false);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Подлинность клиента - EC
		client.credential(ec);
		// Сервер признаёт лишь RSA-PSS
		server.schemes(vector <extension::scheme_t> {extension::scheme_t::RSA_PSS_RSAE_SHA256});
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем отказ клиента по схеме
		ASSERT_EQ(client.error(), context::error_t::SCHEME);
		// Проверяем неустановленность связи
		ASSERT_FALSE(server.established());
	}
	{
		// Враждебный сервер подписывает схемой PKCS #1 v1.5
		client::context_t client;
		// Настраиваем клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группа X25519
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Отвечаем враждебным сервером
		ASSERT_TRUE(hostile(client, hostility_t::PKCS1, rsa));
		/**
		 * Раздел 4.4.3 RFC 8446: схема PKCS #1 v1.5 в подписи владения ключом запрещена,
		 * и объявлена она быть не вправе - схема вне предложения клиента
		 */
		ASSERT_EQ(client.error(), context::error_t::SCHEME);
		// Проверяем извещение
		ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Честный ответ того же враждебного сервера проходит: заслон стоит на схеме, а не рядом
		client::context_t client;
		// Настраиваем клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группа X25519
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Отвечаем честным сервером
		ASSERT_TRUE(hostile(client, hostility_t::NONE, rsa));
		// Проверяем установленность связи
		ASSERT_TRUE(client.established()) << static_cast <int> (client.error());
	}
	{
		// Враждебный сервер подписывает схемой, клиентом не предложенной
		client::context_t client;
		// Настраиваем клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группа X25519
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Клиент предлагает лишь RSA-PSS-SHA256
		client.schemes(vector <extension::scheme_t> {extension::scheme_t::RSA_PSS_RSAE_SHA256});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Отвечаем подписью RSA-PSS-SHA384
		ASSERT_TRUE(hostile(client, hostility_t::ODDSCHEME, rsa));
		// Проверяем отказ по схеме
		ASSERT_EQ(client.error(), context::error_t::SCHEME);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Враждебный сервер шлёт долю вне кривой P-256
		client::context_t client;
		// Настраиваем клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группа P-256
		client.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Отвечаем долей вне кривой
		ASSERT_TRUE(hostile(client, hostility_t::OFFCURVE, rsa));
		// Проверяем отказ по обмену
		ASSERT_EQ(client.error(), context::error_t::EXCHANGE);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Клиент шлёт серверу долю вне кривой P-256: приветствие подделывается в потоке
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::SECP256R1, ec, false);
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Байты приветствия клиента
		const view_t sending = client.output();
		// Переносим приветствие
		vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем приветствие с накопителя
		client.consume(wire.size());
		// Несжатая точка доли ищется по признаку 0x04 за длиной доли 0x0041 и группой 0x0017
		const uint8_t marker[5] = {0x00, 0x17, 0x00, 0x41, 0x04};
		// Место доли в приветствии
		size_t offset = 0;
		/**
		 * Выполняем розыск доли ключа в приветствии
		 */
		for(size_t i = 0; (offset == 0) && (i + sizeof(marker) < wire.size()); i++){
			// Если признак доли найден
			if(::memcmp(wire.data() + i, marker, sizeof(marker)) == 0)
				// Запоминаем место первой координаты
				offset = (i + sizeof(marker));
		}
		// Проверяем, что доля найдена
		ASSERT_NE(offset, static_cast <size_t> (0));
		// Портим первую координату точки
		wire[offset] = static_cast <uint8_t> (wire[offset] ^ 0x01);
		// Подаём подделанное приветствие серверу
		server.push(view_t(wire.data(), wire.size()));
		// Проверяем отказ сервера по обмену
		ASSERT_EQ(server.error(), context::error_t::EXCHANGE);
		// Проверяем неустановленность связи
		ASSERT_FALSE(server.established());
	}
	{
		// Набор с иным хешем при возобновлении: билет SHA-256 предъявлен связи SHA-384
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны на AES-128
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, ec, false);
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Выдаём билет
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Доставляем билет
		converse(client, server);
		// Проверяем получение билета
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Возобновляющий клиент на AES-256
		client::context_t resuming;
		// Сервер на AES-256
		server::context_t resumed;
		// Настраиваем стороны на AES-256
		arrange(resuming, resumed, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::X25519, ec, false);
		// Предъявляем билет с хешем SHA-256
		resuming.resume(client.tickets()[0]);
		// Признаём билеты
		resumed.resume(server.tickets());
		// Заводим стороны
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(resuming, resumed);
		/**
		 * Раздел 4.2.11 RFC 8446: билет с иным хешем не признаётся, а связь идёт полным
		 * рукопожатием
		 */
		ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		// Проверяем, что возобновления не было
		ASSERT_FALSE(resuming.shared() || resumed.shared());
	}
}

/**
 * @brief Метод проведения связи с выдачей билета и возобновления её иным набором
 *
 * @param first      набор шифрования связи, выдающей билет
 * @param second     набор шифрования связи, предъявляющей билет
 * @param credential подлинность сервера
 * @param shared     место, в которое помещается признак возобновления билетом
 *
 * @return           признак установленности обеих связей
 *
 */
static bool crossing(const protect::suite_t first, const protect::suite_t second, const context::credential_t & credential, bool & shared) noexcept {
	// Снимаем признак возобновления
	shared = false;
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны на первый набор
	arrange(client, server, first, extension::group_t::X25519, credential, false);
	// Если стороны завести не удалось
	if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
		// Выводим отказ
		return false;
	// Проводим рукопожатие
	converse(client, server);
	// Если связь не установилась
	if(!client.established() || !server.established())
		// Выводим отказ
		return false;
	// Если билет выдать не удалось
	if(server.issue() != context::error_t::NONE)
		// Выводим отказ
		return false;
	// Доставляем билет
	converse(client, server);
	// Если билет не получен либо набор билета не тот
	if((client.tickets().size() != 1) || (client.tickets()[0].suite != first))
		// Выводим отказ
		return false;
	// Возобновляющий клиент
	client::context_t resuming;
	// Возобновляемый сервер
	server::context_t resumed;
	// Настраиваем стороны на второй набор
	arrange(resuming, resumed, second, extension::group_t::X25519, credential, false);
	// Предъявляем билет первого набора
	resuming.resume(client.tickets()[0]);
	// Признаём билеты
	resumed.resume(server.tickets());
	// Если стороны завести не удалось
	if((resumed.start() != context::error_t::NONE) || (resuming.start() != context::error_t::NONE))
		// Выводим отказ
		return false;
	// Проводим рукопожатие
	converse(resuming, resumed);
	// Если связь не установилась
	if(!resuming.established() || !resumed.established())
		// Выводим отказ
		return false;
	// Если набор второй связи не тот
	if((resuming.suite() != second) || (resumed.suite() != second))
		// Выводим отказ
		return false;
	// Запоминаем признак возобновления билетом
	shared = (resuming.shared() && resumed.shared());
	// Выводим признак обмена данными по второй связи
	return barter(resuming, resumed);
}

/**
 * Проверка возобновления между наборами: раздел 4.6.1 RFC 8446 дозволяет билет лишь
 * набору с тем же хешем, оттого 0x1301 и 0x1303 возобновляют друг друга в обе стороны,
 * а 0x1302 с 0x1303 - нет, и связь идёт полным рукопожатием
 */
TEST(ClassicTest, Crossing){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Признак возобновления билетом
	bool shared = false;
	// Билет ChaCha20-Poly1305 предъявлен связи AES-128-GCM: хеш общий, возобновление есть
	ASSERT_TRUE(crossing(protect::suite_t::CHACHA20_POLY1305_SHA256, protect::suite_t::AES_128_GCM_SHA256, credential, shared));
	// Проверяем возобновление
	ASSERT_TRUE(shared);
	// Билет AES-128-GCM предъявлен связи ChaCha20-Poly1305: хеш общий, возобновление есть
	ASSERT_TRUE(crossing(protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::CHACHA20_POLY1305_SHA256, credential, shared));
	// Проверяем возобновление
	ASSERT_TRUE(shared);
	// Билет ChaCha20-Poly1305 предъявлен связи AES-256-GCM: хеш иной, полное рукопожатие
	ASSERT_TRUE(crossing(protect::suite_t::CHACHA20_POLY1305_SHA256, protect::suite_t::AES_256_GCM_SHA384, credential, shared));
	// Проверяем отсутствие возобновления
	ASSERT_FALSE(shared);
	// Билет AES-256-GCM предъявлен связи ChaCha20-Poly1305: хеш иной, полное рукопожатие
	ASSERT_TRUE(crossing(protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256, credential, shared));
	// Проверяем отсутствие возобновления
	ASSERT_FALSE(shared);
	// Билет ChaCha20-Poly1305 предъявлен связи ChaCha20-Poly1305: возобновление есть
	ASSERT_TRUE(crossing(protect::suite_t::CHACHA20_POLY1305_SHA256, protect::suite_t::CHACHA20_POLY1305_SHA256, credential, shared));
	// Проверяем возобновление
	ASSERT_TRUE(shared);
}

/**
 * Проверка выбора набора по хешу билета: сервер предпочитает AES-256-GCM, но билет выдан
 * набором ChaCha20-Poly1305, и по разделу 4.2.11 RFC 8446 сервер выбирает заново среди
 * предложенных клиентом набор с хешем билета; на нём же принимаются упреждающие данные
 */
TEST(ClassicTest, Reselect){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec384", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны на ChaCha20-Poly1305
	arrange(client, server, protect::suite_t::CHACHA20_POLY1305_SHA256, extension::group_t::SECP384R1, credential, false);
	// Дозволяем упреждающие данные сервером
	server.advance(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established());
	// Выдаём билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Доставляем билет
	converse(client, server);
	// Проверяем получение билета
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Проверяем набор билета
	ASSERT_EQ(client.tickets()[0].suite, protect::suite_t::CHACHA20_POLY1305_SHA256);
	// Проверяем, что билет упреждающие данные дозволяет
	ASSERT_GT(client.tickets()[0].advance, static_cast <uint32_t> (0));
	// Возобновляющий клиент
	client::context_t resuming;
	// Возобновляемый сервер
	server::context_t resumed;
	// Клиент предлагает все три классических набора, ChaCha20-Poly1305 последним
	resuming.suites(vector <protect::suite_t> {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::CHACHA20_POLY1305_SHA256});
	// Сервер предпочитает AES-256-GCM, а ChaCha20-Poly1305 держит запасным
	resumed.suites(vector <protect::suite_t> {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256});
	// Группа клиента
	resuming.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Группа сервера
	resumed.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Подлинность сервера
	resumed.credential(credential);
	// Дозволяем упреждающие данные сервером
	resumed.advance(true);
	// Предлагаем упреждающие данные клиентом
	resuming.advance(true);
	// Предъявляем билет
	resuming.resume(client.tickets()[0]);
	// Признаём билеты
	resumed.resume(server.tickets());
	// Заводим сервер
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Упреждающие данные
	const string request = "Упреждающие данные под ключами набора ChaCha20-Poly1305 из билета";
	// Отправляем упреждающие данные до ответа сервера
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Проводим рукопожатие
	converse(resuming, resumed);
	// Проверяем установленность связи
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	// Проверяем возобновление билетом
	ASSERT_TRUE(resuming.shared() && resumed.shared());
	// Проверяем, что набор выбран заново под хеш билета, а не по предпочтению сервера
	ASSERT_EQ(resumed.suite(), protect::suite_t::CHACHA20_POLY1305_SHA256);
	// Проверяем схождение наборов сторон
	ASSERT_EQ(resuming.suite(), protect::suite_t::CHACHA20_POLY1305_SHA256);
	// Проверяем приём упреждающих данных
	ASSERT_TRUE(resuming.accepted() && resumed.accepted());
	// Накопитель принятых данных
	vector <uint8_t> received;
	// Читаем принятые сервером упреждающие данные
	ASSERT_EQ(resumed.read(received), context::error_t::NONE);
	// Проверяем схождение упреждающих данных
	ASSERT_EQ(string(received.begin(), received.end()), request);
	// Проверяем обмен данными по возобновлённой связи
	ASSERT_TRUE(barter(resuming, resumed));
	// Смена ключей с просьбой об ответной по возобновлённой связи
	ASSERT_EQ(resumed.update(true), context::error_t::NONE);
	// Проводим смену ключей
	converse(resuming, resumed);
	// Проверяем обмен данными после смены ключей
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка GREASE (RFC 8701): чужие неведомые значения в перечнях клиента сервер
 * пропускает молча, свои значения клиент вставляет снаружи во все перечни и долю ключа
 */
TEST(ClassicTest, Grease){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Значение GREASE
	static constexpr uint16_t GREASE = 0x0A0A;
	// Наборы клиента с GREASE впереди
	client.suites(vector <protect::suite_t> {static_cast <protect::suite_t> (GREASE), protect::suite_t::AES_128_GCM_SHA256});
	// Группы клиента с GREASE впереди
	client.groups(vector <extension::group_t> {static_cast <extension::group_t> (GREASE), extension::group_t::X25519});
	// Доли клиента: GREASE и X25519
	client.shares(vector <extension::group_t> {static_cast <extension::group_t> (GREASE), extension::group_t::X25519});
	// Схемы клиента с GREASE впереди
	client.schemes(vector <extension::scheme_t> {static_cast <extension::scheme_t> (GREASE), extension::scheme_t::ECDSA_SECP256R1_SHA256});
	// Наборы сервера
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Группы сервера с GREASE впереди: своё значение сервер выбирать не вправе
	server.groups(vector <extension::group_t> {static_cast <extension::group_t> (GREASE), extension::group_t::X25519});
	// Подлинность сервера
	server.credential(credential);
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем выбранный набор
	ASSERT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка поведения классического рукопожатия при нехватке памяти: перебор запасов
 * выделений, всякий отказ либо NONE, либо MEMORY, либо обрыв внутренним извещением
 */
TEST(ClassicTest, Starved){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Наборы шифрования перебора: AES-GCM и ChaCha20-Poly1305 идут разными примитивами
	static const protect::suite_t STARVING[] = {protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
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
			complete = (client.established() && server.established());
		}
		// Проверяем, что нехватка памяти встретилась
		ASSERT_TRUE(starved) << "набор " << s;
		// Проверяем, что на щедром запасе связь установилась
		ASSERT_TRUE(complete) << "набор " << s;
	}
}
