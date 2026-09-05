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
 *        пересогласование, пределы изданий, порча записи, обмен с настоящим openssl и
 *        нехватка памяти
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <protect/protect.hpp>
#include <extension/extension.hpp>
#include <digest/hmac.hpp>
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
	 * @brief Метод запуска команды оболочки без консоли на входе
	 *
	 * @param command запускаемая команда
	 *
	 * @return        код возврата команды
	 *
	 */
	int shell(const std::string & command) noexcept {
		// Запускаем команду с пустым входом
		return ::system((command + " </dev/null").c_str());
	}
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
	bool exchange(client::context_t & client, server::context_t & server) noexcept {
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
	 * @brief Метод получения свободного порта на петлевом устройстве
	 *
	 * @return свободный порт либо ноль
	 *
	 */
	uint16_t port() noexcept {
		// Заводим сокет для розыска свободного порта
		const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
		// Если сокет завести не удалось
		if(fd < 0)
			// Выводим отсутствие порта
			return 0;
		// Адрес привязки на петлевом устройстве
		struct sockaddr_in address;
		// Обнуляем адрес привязки
		::memset(&address, 0, sizeof(address));
		// Устанавливаем семейство адреса
		address.sin_family = AF_INET;
		// Устанавливаем петлевое устройство
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		// Порт назначается системой
		address.sin_port = 0;
		// Найденный свободный порт
		uint16_t result = 0;
		// Длина адреса привязки
		socklen_t length = sizeof(address);
		// Если привязка и чтение адреса удались
		if((::bind(fd, reinterpret_cast <struct sockaddr *> (&address), sizeof(address)) == 0) && (::getsockname(fd, reinterpret_cast <struct sockaddr *> (&address), &length) == 0))
			// Запоминаем назначенный системой порт
			result = ntohs(address.sin_port);
		// Закрываем сокет розыска порта
		::close(fd);
		// Выводим найденный свободный порт
		return result;
	}
	/**
	 * @brief Метод подключения к порту петлевого устройства с ожиданием
	 *
	 * @param number порт подключения
	 *
	 * @return       описатель подключённого сокета либо отрицательное число
	 *
	 */
	int connect(const uint16_t number) noexcept {
		/**
		 * Выполняем попытки подключения, пока сервер поднимается
		 */
		for(size_t attempt = 0; attempt < 600; attempt++){
			// Заводим сокет подключения
			const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
			// Если сокет завести не удалось
			if(fd < 0)
				// Выводим отказ подключения
				return -1;
			// Адрес подключения на петлевом устройстве
			struct sockaddr_in address;
			// Обнуляем адрес подключения
			::memset(&address, 0, sizeof(address));
			// Устанавливаем семейство адреса
			address.sin_family = AF_INET;
			// Устанавливаем петлевое устройство
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			// Устанавливаем порт подключения
			address.sin_port = htons(number);
			// Если подключение удалось
			if(::connect(fd, reinterpret_cast <struct sockaddr *> (&address), sizeof(address)) == 0){
				// Предел ожидания приёма: зависание собеседника не должно вешать проверку
				struct timeval limit = {60, 0};
				// Устанавливаем предел ожидания приёма
				(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
				// Выводим описатель подключённого сокета
				return fd;
			}
			// Закрываем сокет неудавшегося подключения
			::close(fd);
			// Ждём подъёма сервера
			::usleep(100000);
		}
		// Выводим отказ подключения
		return -1;
	}
	/**
	 * @brief Метод передачи байтов между связью клиента и сокетом
	 *
	 * @param client связь стороны клиента
	 * @param fd     описатель сокета
	 *
	 * @return       признак того, что байты передавались
	 *
	 */
	bool relay(client::context_t & client, const int fd) noexcept {
		// Признак того, что байты передавались
		bool moved = false;
		// Получаем байты, отправляемые клиентом
		const view_t data = client.output();
		// Если клиенту есть что отправить
		if(data.size > 0){
			// Отправляем байты в сокет
			const ssize_t sent = ::send(fd, data.data, data.size, 0);
			// Если отправка не удалась
			if(sent <= 0)
				// Выводим отсутствие передачи
				return false;
			// Снимаем отправленные байты с накопителя клиента
			client.consume(static_cast <size_t> (sent));
			// Запоминаем передачу
			moved = true;
		}
		// Место, в которое помещаются принятые байты
		uint8_t buffer[16384];
		// Принимаем байты из сокета с ожиданием
		const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
		// Если байты приняты
		if(received > 0){
			// Подаём принятые байты связи клиента
			client.push(view_t(buffer, static_cast <size_t> (received)));
			// Запоминаем передачу
			moved = true;
		}
		// Выводим признак передачи
		return moved;
	}
	/**
	 * @brief Метод заведения слушающего сокета на свободном порту петлевого устройства
	 *
	 * @param number место, в которое помещается назначенный порт
	 *
	 * @return       описатель слушающего сокета либо отрицательное число
	 *
	 */
	int listen(uint16_t & number) noexcept {
		// Слушающий сокет
		const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
		// Если сокет завести не удалось
		if(listener < 0)
			// Выводим отказ
			return -1;
		// Адрес привязки
		struct sockaddr_in address;
		// Обнуляем адрес
		::memset(&address, 0, sizeof(address));
		// Семейство адреса
		address.sin_family = AF_INET;
		// Петлевое устройство
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		// Порт назначается системой
		address.sin_port = 0;
		// Длина адреса
		socklen_t length = sizeof(address);
		// Если привязка, чтение адреса либо прослушивание не удались
		if((::bind(listener, reinterpret_cast <struct sockaddr *> (&address), sizeof(address)) != 0) || (::getsockname(listener, reinterpret_cast <struct sockaddr *> (&address), &length) != 0) || (::listen(listener, 1) != 0)){
			// Закрываем сокет
			::close(listener);
			// Выводим отказ
			return -1;
		}
		// Запоминаем назначенный порт
		number = ntohs(address.sin_port);
		// Выводим слушающий сокет
		return listener;
	}
	/**
	 * @brief Метод ведения связи сервера с сокетом до конца рукопожатия
	 *
	 * @param server связь стороны сервера
	 * @param fd     описатель сокета
	 *
	 * @return       признак того, что рукопожатие дошло до конца
	 *
	 */
	bool serve(server::context_t & server, const int fd) noexcept {
		// Признак того, что рукопожатие дошло до конца
		bool complete = false;
		/**
		 * Выполняем передачу байтов до установления, закрытия либо обрыва связи
		 */
		for(size_t i = 0; (i < 8) && !complete && (server.state() != context::state_t::FAILED); i++){
			// Место принятых байтов
			uint8_t buffer[16384];
			// Принимаем байты клиента
			const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
			// Если байты приняты
			if(received > 0)
				// Подаём байты серверу
				server.push(view_t(buffer, static_cast <size_t> (received)));
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
			// Запоминаем установление либо закрытие связи
			complete = (server.established() || (server.state() == context::state_t::CLOSED));
		}
		// Выводим признак завершения рукопожатия
		return complete;
	}
	/**
	 * @brief Метод ожидания отметки завершения в журнале openssl
	 *
	 * @param log  путь к журналу
	 * @param text место, в которое помещается текст журнала
	 *
	 * @return     признак того, что отметка дождалась
	 *
	 */
	bool await(const std::string & log, std::string & text) noexcept {
		// Признак того, что отметка найдена
		bool finished = false;
		/**
		 * Ожидание идёт по состоянию: до отметки завершения в журнале; срок в шестьдесят
		 * секунд лишь защита от зависания, под нагрузкой он не наступает
		 */
		for(size_t i = 0; !finished && (i < 600); i++){
			// Читаем журнал
			std::ifstream file(log);
			// Переносим текст журнала
			text.assign((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
			// Проверяем отметку завершения
			finished = (text.find("ANTS-DONE") != std::string::npos);
			// Если отметки ещё нет, ждём
			if(!finished)
				// Выдерживаем паузу
				::usleep(100000);
		}
		// Выводим признак того, что отметка дождалась
		return finished;
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
	 * @brief Метод получения имени группы у openssl
	 *
	 * @param group группа обмена
	 *
	 * @return      имя группы у openssl
	 *
	 */
	const char * naming(const extension::group_t group) noexcept {
		// Выводим имя группы у openssl
		return ((group == extension::group_t::X25519) ? "X25519" : ((group == extension::group_t::SECP256R1) ? "P-256" : "P-384"));
	}
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
	 * @param master объявляется ли расширенный главный секрет
	 * @param suite  предлагаемый набор шифрования
	 * @param result накопитель, в который складывается запись приветствия
	 *
	 * @return       признак успешности составления приветствия
	 *
	 */
	bool greeting(const bool master, const protect::suite_t suite, vector <uint8_t> & result) noexcept {
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
		if((extension::groups(vector <extension::group_t> {extension::group_t::SECP256R1}, groups) != extension::error_t::NONE) || (extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA256}, schemes) != extension::error_t::NONE))
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
			ASSERT_TRUE(exchange(client, server)) << SUITES[s].title << " " << naming(GROUPS[g]);
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
		ASSERT_TRUE(exchange(client, server));
	}
}

/**
 * Проверка пределов изданий: сервер «только 1.3» против клиента «только 1.2» -
 * protocol_version; клиент «только 1.2» против сервера 1.2…1.3 - издание 1.2 с заслоном
 * понижения в случайном значении сервера; негодные пределы отвергаются
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
		// Заслон понижения RFC 8446 §4.1.3: сервер знает 1.3, а выбрал 1.2
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
		// Проверяем длину ответа
		ASSERT_GT(answer.size, static_cast <size_t> (5 + 4 + 2 + 32));
		// Заслон лежит в хвосте случайного значения
		ASSERT_EQ(::memcmp(answer.data + 5 + 4 + 2 + 32 - 8, downgrade, 8), 0);
		// Проводим рукопожатие дальше
		converse(client, server);
		/**
		 * Раздел 4.1.3 RFC 8446: клиент, предлагавший 1.3, обязан оборваться на заслоне -
		 * так стороны узнают о вмешательстве в согласование издания
		 */
		ASSERT_EQ(client.error(), context::error_t::VERSION);
		// Извещение illegal_parameter
		ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
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
		ASSERT_TRUE(exchange(client, server));
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Умолчание: от 1.2 до 1.3
		ASSERT_EQ(client.lowest(), static_cast <uint16_t> (0x0303));
		// Верхний предел
		ASSERT_EQ(client.highest(), static_cast <uint16_t> (0x0304));
		// Ниже 1.2 - никогда
		ASSERT_EQ(client.versions(0x0302, 0x0304), context::error_t::SETTINGS);
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
		if(item == 1)
			// Ограничиваем клиента
			ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// На первом круге клиент несёт и набор издания 1.3: без него издание 1.3 не предлагается
		else client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::AES_128_GCM_SHA256});
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
		ASSERT_TRUE(greeting(item == 1, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, wire));
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
		// Подаём запись клиенту
		ASSERT_EQ(client.push(records.data()), context::error_t::ORDER) << item;
		// Извещение unexpected_message
		ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
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
 * -tls1_2 против нашего клиента «только 1.3» и пересогласование с обеих сторон
 */
TEST(Tls12Test, Openssl){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.2 с ECDHE (проба возможности, не по номеру издания)
	if(shell("openssl ciphers -s -tls1_2 ECDHE-ECDSA-AES128-GCM-SHA256 >/dev/null 2>&1") != 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.2";
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
			// Свободный порт
			const uint16_t number = port();
			// Проверяем наличие порта
			ASSERT_NE(number, 0);
			// Журнал сервера openssl
			const std::string log = "/tmp/ants-tls12-server-" + std::to_string(number) + ".log";
			/**
			 * Раздел 5.1.1 RFC 8422: у openssl изданием 1.2 кривая ключа сертификата клиента
			 * обязана входить в группы сервера, иначе отвечает «wrong curve»; группа обмена
			 * идёт первой, кривые сертификатов следом
			 */
			ASSERT_EQ(::system(("openssl s_server -accept " + std::to_string(number) + " -tls1_2 -no_ticket -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -cipher " + SUITES[s].title + " -groups " + naming(GROUPS[g]) + ":P-256:P-384 -www -naccept 1 </dev/null >" + log + " 2>&1 &").c_str()), 0);
			// Подключаемся к серверу openssl
			const int fd = connect(number);
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
			// Порт сервера
			uint16_t number = 0;
			// Слушающий сокет
			const int listener = listen(number);
			// Проверяем сокет
			ASSERT_GE(listener, 0);
			// Журнал клиента openssl
			const std::string log = "/tmp/ants-tls12-client-" + std::to_string(number) + ".log";
			// Запускаем клиента openssl изданием 1.2 со своей подлинностью
			/**
			 * Раздел 5.1.1 RFC 8422: кривая ключа сертификата обязана входить в поддерживаемые
			 * группы клиента openssl - группа обмена идёт первой, кривые сертификатов следом
			 */
			ASSERT_EQ(::system(("(openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -CAfile " + crt + " -cert " + crt + " -key " + key + " -cipher " + SUITES[s].title + " -groups " + naming(GROUPS[g]) + ":P-256:P-384 -servername localhost -verify_return_error </dev/null >" + log + " 2>&1; echo ANTS-DONE >>" + log + ") &").c_str()), 0);
			// Принимаем подключение
			const int fd = ::accept(listener, nullptr, nullptr);
			// Проверяем подключение
			ASSERT_GE(fd, 0);
			// Предел ожидания приёма
			struct timeval limit = {60, 0};
			// Устанавливаем предел ожидания приёма
			(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
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
			// Если связь ещё открыта
			if(server.established()){
				// Закрываем связь
				ASSERT_EQ(server.close(), context::error_t::NONE);
				// Байты закрытия
				const view_t closing = server.output();
				// Отправляем закрытие
				(void) ::send(fd, closing.data, closing.size, 0);
			}
			// Закрываем сокеты
			::close(fd);
			// Закрываем слушающий сокет
			::close(listener);
			// Текст журнала клиента
			std::string text;
			// Клиент обязан завершиться
			ASSERT_TRUE(await(log, text)) << text;
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
		const int listener = listen(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-tls12-any-" + std::to_string(number) + ".log";
		// Запускаем клиента openssl без предела издания против нашего сервера «только 1.2»
		ASSERT_EQ(::system(("(openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -CAfile " + crt + " -servername localhost -verify_return_error </dev/null >" + log + " 2>&1; echo ANTS-DONE >>" + log + ") &").c_str()), 0);
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
		// Если связь ещё открыта
		if(server.established()){
			// Закрываем связь
			ASSERT_EQ(server.close(), context::error_t::NONE);
			// Байты закрытия
			const view_t closing = server.output();
			// Отправляем закрытие
			(void) ::send(fd, closing.data, closing.size, 0);
		}
		// Закрываем сокеты
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Текст журнала клиента
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(await(log, text)) << text;
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
		const uint16_t number = port();
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-tls12-only13-" + std::to_string(number) + ".log";
		// Запускаем сервер openssl изданием 1.2
		ASSERT_EQ(::system(("openssl s_server -accept " + std::to_string(number) + " -tls1_2 -cert " + crt + " -key " + key + " -www -naccept 1 </dev/null >" + log + " 2>&1 &").c_str()), 0);
		// Подключаемся к серверу openssl
		const int fd = connect(number);
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
		const int listener = listen(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-tls12-reneg-" + std::to_string(number) + ".log";
		/**
		 * Клиент openssl получает на вход команду R: за рукопожатием он затевает
		 * пересогласование новым приветствием, а наш сервер отвечает no_renegotiation
		 */
		ASSERT_EQ(::system(("(printf 'R\\n' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 -CAfile " + crt + " -servername localhost >" + log + " 2>&1; echo ANTS-DONE >>" + log + ") &").c_str()), 0);
		// Принимаем подключение
		const int fd = ::accept(listener, nullptr, nullptr);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Предел ожидания приёма
		struct timeval limit = {60, 0};
		// Устанавливаем предел ожидания приёма
		(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
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
		// Сервер оборвал связь отказом пересогласования
		ASSERT_EQ(server.error(), context::error_t::RENEGOTIATION);
		// Извещение no_renegotiation
		ASSERT_EQ(server.alert().description, alert::description_t::RENEGOTIATION);
		// Закрываем сокеты
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Текст журнала клиента
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(await(log, text)) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка просьбы о пересогласовании HelloRequest (раздел 7.4.1.1 RFC 5246), составленной
 * руками: по ходу рукопожатия клиент её пропускает и в переписку не кладёт, с непустым
 * телом - отвергает, а сервер не принимает её никогда - ни до согласования издания, ни за ним
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
			ASSERT_TRUE(exchange(client, server));
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
}

/**
 * Проверка ответа на HelloRequest за установленной связью изданием 1.2: сервер openssl по
 * команде r шлёт просьбу о пересогласовании, наш клиент отвечает извещением no_renegotiation
 * уровня предупреждения (раздел 4.2 RFC 5746) и связь продолжает; openssl отказ
 * пересогласования считает роковым и обрывает связь извещением handshake_failure
 */
TEST(Tls12Test, Renegotiation){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.2 с ECDHE
	if(shell("openssl ciphers -s -tls1_2 ECDHE-ECDSA-AES128-GCM-SHA256 >/dev/null 2>&1") != 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.2";
	}
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Свободный порт
	const uint16_t number = port();
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
	ASSERT_EQ(::system(("(openssl s_server -accept " + std::to_string(number) + " -tls1_2 -no_ticket -cert " + crt + " -key " + key + " -state -naccept 1 <" + channel + " >" + log + " 2>&1; echo ANTS-DONE >>" + log + ") &").c_str()), 0);
	// Открываем канал на запись: открытие ждёт, пока сервер openssl откроет его на чтение
	const int channelled = ::open(channel.c_str(), O_WRONLY);
	// Проверяем канал
	ASSERT_GE(channelled, 0);
	// Подключаемся к серверу openssl
	const int fd = connect(number);
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
	ASSERT_TRUE(await(log, text)) << text;
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
 * Проверка того, что издание 1.2 ведётся лишь переносом записями: под дейтаграммами DTLS 1.3
 * и уровнями QUIC пределы, издание 1.3 исключающие, заведению связи отказывают SETTINGS, а
 * пределы 1.2…1.3 законны - издание 1.2 там просто не предлагается
 */
TEST(Tls12Test, Datagrams){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Способы переноса, изданию 1.2 чуждые
	static const context::transport_t FOREIGN[] = {context::transport_t::DATAGRAMS, context::transport_t::LEVELS};
	/**
	 * Выполняем перебор чуждых способов переноса
	 */
	for(size_t item = 0; item < (sizeof(FOREIGN) / sizeof(FOREIGN[0])); item++){
		// Связь стороны клиента
		client::context_t client;
		// Устанавливаем способ переноса
		client.transport(FOREIGN[item]);
		// Пределы «только 1.2» ставятся: пределы не знают переноса
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заведение связи отказывает: вестись ей нечем
		ASSERT_EQ(client.start(), context::error_t::SETTINGS) << item;
		// Связь не заведена
		ASSERT_EQ(client.state(), context::state_t::NONE);
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем способ переноса
		server.transport(FOREIGN[item]);
		// Подлинность сервера
		server.credential(credential);
		// Пределы «только 1.2»
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заведение связи отказывает
		ASSERT_EQ(server.start(), context::error_t::SETTINGS) << item;
		// Связь не заведена
		ASSERT_EQ(server.state(), context::state_t::NONE);
		// Пределы 1.2…1.3 законны и заведению не мешают: издание 1.2 там не предлагается
		ASSERT_EQ(client.versions(0x0303, 0x0304), context::error_t::NONE);
		// Если перенос дейтаграммами: переносу по уровням нужны ещё протоколы и параметры
		if(FOREIGN[item] == context::transport_t::DATAGRAMS){
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Связь заведена
			ASSERT_NE(client.state(), context::state_t::NONE);
			// Приветствие клиента составлено
			ASSERT_GT(client.output().size, static_cast <size_t> (0));
		}
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
