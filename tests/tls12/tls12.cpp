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
	 * @brief Сторож фонового процесса openssl
	 *
	 * @details Номер процесса пишется оболочкой в файл при запуске; по выходу из проверки -
	 *          и при отказе посреди неё - процесс снимается по номеру, а не по шаблону имени
	 *
	 */
	typedef class Sentinel {
		private:
			// Путь к файлу с номером процесса
			std::string _path;
		public:
			/**
			 * @brief Метод снятия процесса по номеру из файла
			 *
			 */
			void halt() noexcept {
				// Если файл номера процесса не назначен
				if(this->_path.empty())
					// Выходим
					return;
				// Читаем файл номера процесса
				std::ifstream file(this->_path);
				// Номер процесса
				long number = 0;
				// Если номер прочитан и процесс жив
				if((file >> number) && (number > 0) && (::kill(static_cast <pid_t> (number), 0) == 0))
					// Снимаем процесс по номеру
					(void) ::kill(static_cast <pid_t> (number), SIGTERM);
				// Удаляем файл номера процесса
				::remove(this->_path.c_str());
				// Забываем путь
				this->_path.clear();
			}
			/**
			 * @brief Конструктор
			 *
			 * @param path путь к файлу с номером процесса
			 *
			 */
			explicit Sentinel(const std::string & path) noexcept : _path(path) {}
			/**
			 * @brief Деструктор
			 *
			 */
			~Sentinel() noexcept {
				// Снимаем процесс, коли он ещё жив
				this->halt();
			}
	} sentinel_t;
	/**
	 * @brief Метод запуска команды openssl фоном с записью номера процесса и отметкой завершения
	 *
	 * @param command запускаемая команда вместе с перенаправлениями входа и вывода
	 * @param log     путь к журналу, в который по завершении дописывается отметка ANTS-DONE
	 * @param path    путь к файлу, в который пишется номер процесса
	 *
	 * @return        признак успешности запуска
	 *
	 */
	bool launch(const std::string & command, const std::string & log, const std::string & path) noexcept {
		// Запускаем команду фоном: номер её процесса кладётся в файл, по завершении пишется отметка
		return (::system(("(" + command + " & echo $! >" + path + "; wait; echo ANTS-DONE >>" + log + ") &").c_str()) == 0);
	}
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
	 * @brief Метод получения свободного порта на петлевом устройстве
	 *
	 * @return свободный порт либо ноль
	 *
	 */
	uint16_t vacant() noexcept {
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
	int dial(const uint16_t number) noexcept {
		/**
		 * Выполняем попытки подключения, пока сервер поднимается
		 */
		for(size_t attempt = 0; attempt < 600; attempt++){
			/**
			 * Выполняем перебор семейств адресов: сперва IPv4, затем IPv6 - s_server без
			 * явного адреса на DragonFly BSD слушает лишь tcp6
			 */
			for(size_t family = 0; family < 2; family++){
				// Заводим сокет подключения
				const int fd = ::socket(((family == 0) ? AF_INET : AF_INET6), SOCK_STREAM, 0);
				// Если сокет завести не удалось
				if(fd < 0)
					// Переходим к следующему семейству
					continue;
				// Адрес подключения на петлевом устройстве IPv4
				struct sockaddr_in address4;
				// Адрес подключения на петлевом устройстве IPv6
				struct sockaddr_in6 address6;
				// Обнуляем адрес подключения IPv4
				::memset(&address4, 0, sizeof(address4));
				// Обнуляем адрес подключения IPv6
				::memset(&address6, 0, sizeof(address6));
				// Устанавливаем семейство адреса IPv4
				address4.sin_family = AF_INET;
				// Устанавливаем петлевое устройство IPv4
				address4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				// Устанавливаем порт подключения IPv4
				address4.sin_port = htons(number);
				// Устанавливаем семейство адреса IPv6
				address6.sin6_family = AF_INET6;
				// Устанавливаем петлевое устройство IPv6
				address6.sin6_addr = in6addr_loopback;
				// Устанавливаем порт подключения IPv6
				address6.sin6_port = htons(number);
				// Адрес подключения выбранного семейства
				const struct sockaddr * address = ((family == 0) ? reinterpret_cast <const struct sockaddr *> (&address4) : reinterpret_cast <const struct sockaddr *> (&address6));
				// Длина адреса подключения выбранного семейства
				const socklen_t length = ((family == 0) ? static_cast <socklen_t> (sizeof(address4)) : static_cast <socklen_t> (sizeof(address6)));
				// Если подключение удалось
				if(::connect(fd, address, length) == 0){
					// Предел ожидания приёма: зависание собеседника не должно вешать проверку
					struct timeval limit = {60, 0};
					// Устанавливаем предел ожидания приёма
					(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
					// Выводим описатель подключённого сокета
					return fd;
				}
				// Закрываем сокет неудавшегося подключения
				::close(fd);
			}
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
	int harbour(uint16_t & number) noexcept {
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
	bool settle(const std::string & log, std::string & text) noexcept {
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
	 * @param master       объявляется ли расширенный главный секрет
	 * @param suite        предлагаемый набор шифрования
	 * @param result       накопитель, в который складывается запись приветствия
	 * @param renegotiated объявляется ли непустое расширение renegotiation_info
	 * @param group        предлагаемая группа обмена
	 *
	 * @return             признак успешности составления приветствия
	 *
	 */
	bool greeting(const bool master, const protect::suite_t suite, vector <uint8_t> & result, const bool renegotiated = false, const extension::group_t group = extension::group_t::SECP256R1) noexcept {
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
	 * @brief Способности системного openssl, снятые щупами
	 *
	 * @details Ключи командной строки разнятся по изданиям (1.0.2, 1.1.x, 3.x) и по ветвям
	 *          (OpenSSL, LibreSSL); что нельзя спросить у справки, выводится из издания
	 *
	 */
	typedef struct Toolkit {
		// Признак наличия openssl
		bool present;
		// Признак ветви LibreSSL
		bool libre;
		// Признак поддержки издания TLS 1.2 набором ECDHE
		bool tls12;
		// Признак поддержки расширенного главного секрета RFC 7627
		bool master;
		// Признак ключа -groups у s_server
		bool serverGroups;
		// Признак ключа -named_curve у s_server
		bool namedCurve;
		// Признак ключа -groups у s_client
		bool clientGroups;
		// Признак ключа -curves у s_client
		bool clientCurves;
		// Признак ключа -naccept у s_server
		bool naccept;
		// Признак приёма -accept в виде host:port
		bool addressed;
		// Признак поддержки кривой X25519
		bool x25519;
		// Число издания: старший, средний и младший разряды
		uint32_t edition;
		/**
		 * Конструктор
		 */
		Toolkit() noexcept : present(false), libre(false), tls12(false), master(false), serverGroups(false), namedCurve(false), clientGroups(false), clientCurves(false), naccept(false), addressed(false), x25519(false), edition(0) {}
	} toolkit_t;
	/**
	 * @brief Метод щупа ключа справки openssl
	 *
	 * @param program подкоманда openssl: s_server либо s_client
	 * @param key     имя ключа без ведущей чёрточки
	 *
	 * @return        признак наличия ключа в справке
	 *
	 */
	bool listed(const char * program, const char * key) noexcept {
		/**
		 * Чёрточка ключа спрятана в скобки, чтобы grep всякой системы не принял её за свой
		 * ключ; конвейер обёрнут в скобки, иначе перенаправление входа помощника shell()
		 * достаётся grep и подменяет ему трубу пустым входом
		 */
		return (shell(std::string("(openssl ") + program + " -help 2>&1 | grep -q '[-]" + key + "') >/dev/null 2>&1") == 0);
	}
	/**
	 * @brief Метод щупа расширенного главного секрета у s_client
	 *
	 * @details Справкой RFC 7627 не снять: ключ -no_ems есть лишь у OpenSSL 3.3+, а связь без
	 *          расширения не ведётся намеренно (отказ MASTER). Щуп принимает приветствие
	 *          s_client на своём слушающем сокете и ищет в нём расширение 0x0017
	 *
	 * @return признак того, что s_client предлагает extended_master_secret
	 *
	 */
	bool offered() noexcept {
		// Порт слушающего сокета
		uint16_t number = 0;
		// Заводим слушающий сокет
		const int listener = harbour(number);
		// Если сокет не завёлся
		if(listener < 0)
			// Выводим отсутствие расширения
			return false;
		// Журнал s_client
		const std::string log = "/tmp/ants-tls12-probe-" + std::to_string(number) + ".log";
		// Если s_client не запустился
		if(!launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 </dev/null >" + log + " 2>&1", log, log + ".pid")){
			// Закрываем слушающий сокет
			::close(listener);
			// Выводим отсутствие расширения
			return false;
		}
		// Сторож процесса s_client
		sentinel_t sentinel(log + ".pid");
		// Набор ожидаемых описателей
		fd_set waiting;
		// Обнуляем набор описателей
		FD_ZERO(&waiting);
		// Ждём слушающий сокет
		FD_SET(listener, &waiting);
		// Предел ожидания подключения
		struct timeval limit = {30, 0};
		// Признак предложенного расширения
		bool result = false;
		// Если подключение пришло в срок
		if(::select(listener + 1, &waiting, nullptr, nullptr, &limit) > 0){
			// Принимаем подключение
			const int fd = ::accept(listener, nullptr, nullptr);
			// Если подключение принято
			if(fd >= 0){
				// Предел ожидания приёма
				struct timeval pause = {30, 0};
				// Устанавливаем предел ожидания приёма
				(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &pause, sizeof(pause));
				// Накопитель приветствия
				uint8_t buffer[16384];
				// Принимаем приветствие клиента
				const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
				// Заголовок записи
				record::header_t header;
				// Заголовок сообщения
				handshake::header_t head;
				// Приветствие клиента
				hello::client_t hello;
				// Если запись и сообщение приветствия разобрались
				if((received > static_cast <ssize_t> (record::RECORD_HEADER + handshake::HANDSHAKE_HEADER)) && (record::parse(view_t(buffer, static_cast <size_t> (received)), header) == record::error_t::NONE) && (header.type == record::type_t::HANDSHAKE) && (handshake::parse(view_t(buffer + record::RECORD_HEADER, static_cast <size_t> (received) - record::RECORD_HEADER), head) == handshake::error_t::NONE) && (head.type == handshake::type_t::CLIENT) && ((record::RECORD_HEADER + handshake::HANDSHAKE_HEADER + head.size) <= static_cast <size_t> (received)) && (hello::parse(view_t(buffer + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, head.size), hello) == hello::error_t::NONE))
					// Ищем расширение extended_master_secret
					result = (hello::extension(hello.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr);
				// Закрываем подключение: s_client завершится сам
				::close(fd);
			}
		}
		// Закрываем слушающий сокет
		::close(listener);
		// Журнал s_client
		std::string text;
		// Дожидаемся завершения s_client
		(void) settle(log, text);
		// Удаляем журнал
		::remove(log.c_str());
		// Выводим признак предложенного расширения
		return result;
	}
	/**
	 * @brief Метод снятия способностей системного openssl
	 *
	 * @return способности системного openssl
	 *
	 */
	toolkit_t inspect() noexcept {
		// Способности системного openssl
		toolkit_t result;
		// Если openssl недоступен
		if(shell("openssl version >/dev/null 2>&1") != 0)
			// Выводим пустые способности
			return result;
		// Запоминаем наличие openssl
		result.present = true;
		// Путь к файлу с изданием openssl
		const std::string path = "/tmp/ants-tls12-edition-" + std::to_string(static_cast <long> (::getpid())) + ".txt";
		// Снимаем издание openssl в файл
		(void) shell("openssl version >" + path + " 2>&1");
		// Открываем файл с изданием
		std::ifstream file(path);
		// Ветвь и издание openssl
		std::string branch, release;
		// Читаем ветвь и издание
		file >> branch >> release;
		// Закрываем файл с изданием
		file.close();
		// Удаляем файл с изданием
		::remove(path.c_str());
		// Признак ветви LibreSSL
		result.libre = (branch == "LibreSSL");
		// Разряды издания
		unsigned major = 0, minor = 0, patch = 0;
		// Если издание разобрано
		if(::sscanf(release.c_str(), "%u.%u.%u", &major, &minor, &patch) >= 2)
			// Складываем число издания
			result.edition = ((major << 16) | (minor << 8) | patch);
		// Признак поддержки TLS 1.2 набором ECDHE
		result.tls12 = (shell("openssl ciphers -s -tls1_2 ECDHE-ECDSA-AES128-GCM-SHA256 >/dev/null 2>&1") == 0);
		// Расширенный главный секрет снимается с живого приветствия s_client (OpenSSL 1.0.2 и LibreSSL его не несут)
		result.master = (result.tls12 && offered());
		// Снимаем ключи s_server
		result.serverGroups = listed("s_server", "groups");
		// Снимаем ключ одиночной кривой s_server
		result.namedCurve = listed("s_server", "named_curve");
		// Снимаем ключи s_client
		result.clientGroups = listed("s_client", "groups");
		// Снимаем ключ старого вида s_client
		result.clientCurves = listed("s_client", "curves");
		// Снимаем предел числа приёмов s_server
		result.naccept = listed("s_server", "naccept");
		// Приём в виде host:port есть у OpenSSL с 1.1.0: справка так и говорит «host and port»
		result.addressed = (shell("(openssl s_server -help 2>&1 | grep -q 'host and port') >/dev/null 2>&1") == 0);
		// Кривая X25519 появилась в 1.1.0: щупом служит порождение ключа
		result.x25519 = (shell("openssl genpkey -algorithm X25519 -out /dev/null >/dev/null 2>&1") == 0);
		// Выводим способности
		return result;
	}
	/**
	 * @brief Метод составления ключа приёма s_server
	 *
	 * @param toolkit способности openssl
	 * @param number  порт приёма
	 *
	 * @return        ключ приёма с портом
	 *
	 */
	std::string accepting(const toolkit_t & toolkit, const uint16_t number) noexcept {
		/**
		 * Без явного адреса s_server слушает «*», а на DragonFly BSD это лишь tcp6 - потому
		 * адрес петлевого устройства задаётся всюду, где ключ принимает вид host:port
		 */
		return (toolkit.addressed ? (" -accept 127.0.0.1:" + std::to_string(number)) : (" -accept " + std::to_string(number)));
	}
	/**
	 * @brief Метод составления ключа предела приёмов s_server
	 *
	 * @param toolkit способности openssl
	 *
	 * @return        ключ предела приёмов либо пустая строка
	 *
	 */
	std::string once(const toolkit_t & toolkit) noexcept {
		// Без ключа сервер живёт до снятия сторожем
		return (toolkit.naccept ? " -naccept 1" : "");
	}
	/**
	 * @brief Метод получения имени кривой в записи ecparam
	 *
	 * @param group группа обмена ключами
	 *
	 * @return      имя кривой для ключа -named_curve
	 *
	 */
	const char * formal(const extension::group_t group) noexcept {
		// Выводим имя кривой
		return ((group == extension::group_t::X25519) ? "X25519" : ((group == extension::group_t::SECP256R1) ? "prime256v1" : "secp384r1"));
	}
	/**
	 * @brief Метод составления перечня групп без повторов
	 *
	 * @param group предпочитаемая группа, идущая первой
	 *
	 * @return      перечень групп через двоеточие
	 *
	 */
	std::string roster(const extension::group_t group) noexcept {
		/**
		 * OpenSSL 3.0 отвергает перечень с повтором («Call to SSL_CONF_cmd(-groups,
		 * P-256:P-256:P-384) failed»), потому запасные группы дописываются лишь отличные
		 */
		std::string result = naming(group);
		// Если предпочитаемая группа не P-256
		if(group != extension::group_t::SECP256R1)
			// Дописываем запасную группу P-256
			result += ":P-256";
		// Если предпочитаемая группа не P-384
		if(group != extension::group_t::SECP384R1)
			// Дописываем запасную группу P-384
			result += ":P-384";
		// Выводим перечень групп
		return result;
	}
	/**
	 * @brief Метод составления ключа групп для s_server либо s_client
	 *
	 * @param toolkit способности openssl
	 * @param server  признак составления для s_server
	 * @param group   предпочитаемая группа
	 *
	 * @return        ключ групп либо пустая строка, коли ключа у openssl нет
	 *
	 */
	std::string grouping(const toolkit_t & toolkit, const bool server, const extension::group_t group) noexcept {
		// Если составляется ключ сервера
		if(server){
			// Если есть ключ -groups
			if(toolkit.serverGroups)
				// Выводим перечень групп
				return (" -groups " + roster(group));
			// Если есть лишь одиночная кривая старого вида
			if(toolkit.namedCurve)
				// Выводим одиночную кривую
				return (std::string(" -named_curve ") + formal(group));
		// Если составляется ключ клиента
		} else {
			// Если есть ключ -groups
			if(toolkit.clientGroups)
				// Выводим перечень групп
				return (" -groups " + roster(group));
			// Если есть ключ старого вида -curves (тот же перечень)
			if(toolkit.clientCurves)
				// Выводим перечень групп старым ключом
				return (" -curves " + roster(group));
		}
		// Ключа групп у openssl нет
		return "";
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
	bool unwind(const vector <uint8_t> & wire, stream_t & result) noexcept {
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
				// За защищённым завершением идёт лишь извещение закрытия
				if(result.changed)
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
		// Поток обязан нести открытые сообщения, смену набора и защищённое завершение
		return (result.changed && !result.sealed.empty() && !result.messages.empty());
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
	bool exchange(const view_t & data, exchange_t & result) noexcept {
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
	bool keyed(const protect::suite_t suite, const vector <uint8_t> & master, const vector <uint8_t> & client, const vector <uint8_t> & server, protect::protection_t & protection, const bool own) noexcept {
		// Длина ключа набора
		const size_t width = protect::key(suite);
		// Длина неявной части вектора набора
		const size_t size = protect::block(suite);
		// Если набор связи неизвестен
		if((width == 0) || (size == 0))
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
		// Ключевой материал: ключ клиента, ключ сервера, вектор клиента, вектор сервера
		uint8_t material[(protect::PROTECT_KEY + protect::PROTECT_VECTOR) * 2];
		// Если материал не выведен
		if(!digest::prf(protect::hash(suite), view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed, sizeof(seed)), material, (width + size) * 2))
			// Выводим отказ
			return false;
		// Ключ стороны
		const view_t key(material + (own ? 0 : width), width);
		// Вектор стороны
		const view_t vector(material + (width * 2) + (own ? 0 : size), size);
		// Выводим итог заведения защиты
		return protection.start(suite, key, vector);
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
			const uint16_t number = vacant();
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
		const uint16_t number = vacant();
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
	const uint16_t number = vacant();
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
				ASSERT_TRUE(greeting(true, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, wire, true));
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
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), stream)) << path;
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
				// Если сценарий про набор CBC
				else if(SCENARIOS[s].suite == 0xC023)
					// Наборы связи остаются умолчанием: CBC среди них нет
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
				// Если сценарий про набор CBC
				if(SCENARIOS[s].suite == 0xC023){
					// Общего набора у сторон нет: SUITE и handshake_failure
					ASSERT_EQ(server.error(), context::error_t::SUITE) << path << " предел " << v;
					// Извещение обязано быть handshake_failure
					ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE) << path;
					// Запись на проводе обязана быть извещением
					ASSERT_EQ(server.output().data[0], 0x15) << path;
					// Переходим к следующему пределу
					continue;
				}
				// Отказа быть не должно
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
				ASSERT_TRUE(exchange(inner(*agreement), exchanged)) << path;
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
	// Векторы обязаны были проверяться: 70 каталогов по два предела за вычетом отказных сценариев
	ASSERT_EQ(verified, static_cast <size_t> ((70 - 6 - 4) * 2));
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
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), c2s)) << path;
			// Поток сервера обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-s2c.bin"), s2c)) << path;
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
			ASSERT_TRUE(exchange(inner(*seek(s2c.messages, handshake::type_t::AGREEMENT)), exchanged)) << path;
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
			ASSERT_TRUE(unwind(slurp(path + "/handshake-c2s.bin"), c2s)) << path;
			// Поток сервера обязан разобраться
			ASSERT_TRUE(unwind(slurp(path + "/handshake-s2c.bin"), s2c)) << path;
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
			// Если это набор CBC
			if(SCENARIOS[s].suite == 0xC023){
				// Расшифровка пропускается явно: CBC связью не реализован
				std::cout << "OpenSSL " << EDITIONS[e] << " " << SCENARIOS[s].name << ": набор 0xC023 связью не реализован, расшифровка завершений пропущена" << std::endl;
				// Переходим к следующему сценарию
				continue;
			}
			// Набор шифрования
			const protect::suite_t suite = static_cast <protect::suite_t> (SCENARIOS[s].suite);
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
			ASSERT_TRUE(keyed(suite, master, random, theirs, incoming, true)) << path;
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
			ASSERT_TRUE(keyed(suite, master, random, theirs, outgoing, false)) << path;
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
			ASSERT_TRUE(keyed(suite, master, random, theirs, again, false)) << path;
			// Очищаем накопитель перед испорченной записью
			plain.clear();
			// Испорченная запись обязана отвергаться меткой целостности
			ASSERT_EQ(again.open(s2c.header, view_t(spoiled.data(), spoiled.size()), type, plain), protect::error_t::TAG) << path;
			// Учитываем расшифрованный вектор
			decrypted++;
		}
	}
	// Расшифрованы обязаны быть все векторы, кроме шести CBC
	ASSERT_EQ(decrypted, static_cast <size_t> (70 - 6));
}
