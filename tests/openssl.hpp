/**
 * @file openssl.hpp
 * @date 2026-09-06
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
 * @brief Общий для проверок заголовочный файл обмена с системным openssl: запуск команд
 *        оболочки без консоли на входе, сторож фонового процесса по номеру, ожидание по
 *        состоянию журнала, свободные порты и сокеты петлевого устройства, ведение связи
 *        клиента и сервера с сокетом, щупы способностей openssl и составление его ключей
 *
 * @details Помощники собраны из наборов tls12, dtls12, classic, ocsp и compress, где всякий
 *          носил свои копии; стендовые особенности сохранены: адрес приёма host:port лишь
 *          там, где ключ его принимает (DragonFly BSD без адреса слушает лишь tcp6), ключ
 *          -naccept по наличию, «( (» с пробелом ради ksh93 у Solaris, расширенный главный
 *          секрет снимается с живого приветствия s_client (нет у OpenSSL 1.0.2 и LibreSSL)
 *
 * @note Всё содержимое лежит в безымянном пространстве имён: у всякой проверки своя
 *       программа, но правило это блюдётся и здесь - так заголовочный файл годится и
 *       для набора, собранного единой программой
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию заголовочного файла
 */
#ifndef __ANTS_TESTS_OPENSSL__
#define __ANTS_TESTS_OPENSSL__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>
#include <chrono>
#include <posix.hpp>
#include <signal.h>

/**
 * Сокеты оснастки: одни имена под POSIX и Windows
 */
#include <sockets.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Служебные объекты обмена с системным openssl
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
	inline int shell(const std::string & command) noexcept {
		// Запускаем команду с пустым входом
		return ::system((command + " </dev/null").c_str());
	}
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
				#if !defined(_WIN32)
					if((file >> number) && (number > 0) && (::kill(static_cast <pid_t> (number), 0) == 0))
						// Снимаем процесс по номеру
						(void) ::kill(static_cast <pid_t> (number), SIGTERM);
				#else
					// Под Windows порождённых процессов openssl оснастка не ведёт: интероп там пропускается
					(void) number;
				#endif
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
	 * @param holder  путь к именованному каналу входа команды, пустой без держателя
	 *
	 * @return        признак успешности запуска
	 *
	 */
	inline bool launch(const std::string & command, const std::string & log, const std::string & path, const std::string & holder) noexcept {
		/**
		 * Держатель входа: подоболочка открывает именованный канал на запись и держит его до
		 * конца команды - вход команды не кончается, пока она жива, и никаких пауз по времени
		 */
		const std::string opening = (holder.empty() ? std::string() : ("exec 3>" + holder + "; "));
		/**
		 * Команда уходит фоном: номер её процесса кладётся в файл, по завершении пишется
		 * отметка; вести оболочки о судьбе фонового задания глушатся, чтобы не сорить в вывод.
		 * Скобки разделены пробелом: сдвоенная «((» у ksh93 (/bin/sh Solaris) - арифметика,
		 * и оболочка валила запуск синтаксической ошибкой
		 */
		return (::system(("( (" + command + " & echo $! >" + path + "; " + opening + "wait) 2>/dev/null; echo ANTS-DONE >>" + log + ") &").c_str()) == 0);
	}
	/**
	 * @brief Метод запуска команды openssl фоном без держателя входа
	 *
	 * @param command запускаемая команда вместе с перенаправлениями входа и вывода
	 * @param log     путь к журналу, в который по завершении дописывается отметка ANTS-DONE
	 * @param path    путь к файлу, в который пишется номер процесса
	 *
	 * @return        признак успешности запуска
	 *
	 */
	inline bool launch(const std::string & command, const std::string & log, const std::string & path) noexcept {
		// Запускаем команду без держателя входа
		return launch(command, log, path, std::string());
	}
	/**
	 * @brief Метод ожидания строки в журнале openssl
	 *
	 * @param log   путь к журналу
	 * @param mark  искомая строка
	 * @param text  место, в которое помещается текст журнала
	 * @param limit предел ожидания в десятых долях секунды
	 *
	 * @return      признак того, что строка дождалась
	 *
	 */
	inline bool awaited(const std::string & log, const std::string & mark, std::string & text, const size_t limit) noexcept {
		// Признак того, что строка найдена
		bool found = false;
		/**
		 * Ожидание идёт по состоянию: до строки в журнале; предел лишь защита от зависания,
		 * под нагрузкой он не наступает
		 */
		for(size_t i = 0; !found && (i < limit); i++){
			// Читаем журнал
			std::ifstream file(log);
			// Переносим текст журнала
			text.assign((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
			// Проверяем строку
			found = (text.find(mark) != std::string::npos);
			// Если строки ещё нет, ждём
			if(!found)
				// Выдерживаем паузу
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		// Выводим признак того, что строка дождалась
		return found;
	}
	/**
	 * @brief Метод ожидания строки в журнале openssl сроком в тридцать секунд
	 *
	 * @param log  путь к журналу
	 * @param mark искомая строка
	 * @param text место, в которое помещается текст журнала
	 *
	 * @return     признак того, что строка дождалась
	 *
	 */
	inline bool awaited(const std::string & log, const std::string & mark, std::string & text) noexcept {
		// Ждём строку сроком в тридцать секунд
		return awaited(log, mark, text, 300);
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
	inline bool settle(const std::string & log, std::string & text) noexcept {
		// Ждём отметку завершения сроком в шестьдесят секунд
		return awaited(log, "ANTS-DONE", text, 600);
	}
	/**
	 * @brief Метод получения свободного порта на петлевом устройстве
	 *
	 * @details Порт назначает система привязкой к нулевому порту; выданные за жизнь процесса
	 *          порты помнятся, и порт, выданный системой повторно, отвергается - соседние
	 *          проверки одного процесса не делят один порт, даже если система отдаёт
	 *          освобождённый порт тут же
	 *
	 * @param datagram признак порта UDP, иначе TCP
	 *
	 * @return         свободный порт либо ноль
	 *
	 */
	inline uint16_t vacant(const bool datagram) noexcept {
		// Порты, выданные за жизнь процесса
		static std::vector <uint16_t> issued;
		/**
		 * Выполняем попытки получения порта, не выданного прежде
		 */
		for(size_t attempt = 0; attempt < 16; attempt++){
			// Заводим сокет для розыска свободного порта
			const int fd = ::socket(AF_INET, (datagram ? SOCK_DGRAM : SOCK_STREAM), 0);
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
			closing(fd);
			// Если порта нет
			if(result == 0)
				// Выводим отсутствие порта
				return 0;
			// Признак того, что порт выдавался прежде
			bool repeated = false;
			/**
			 * Выполняем перебор выданных прежде портов
			 */
			for(size_t i = 0; !repeated && (i < issued.size()); i++)
				// Сличаем порт с выданным прежде
				repeated = (issued[i] == result);
			// Если порт свежий
			if(!repeated){
				// Запоминаем выданный порт
				issued.push_back(result);
				// Выводим найденный свободный порт
				return result;
			}
		}
		// Выводим отсутствие порта
		return 0;
	}
	/**
	 * @brief Метод подключения к порту петлевого устройства с ожиданием
	 *
	 * @param number порт подключения
	 *
	 * @return       описатель подключённого сокета либо отрицательное число
	 *
	 */
	inline int dial(const uint16_t number) noexcept {
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
					patience(fd, 60, 0);
					// Выводим описатель подключённого сокета
					return fd;
				}
				// Закрываем сокет неудавшегося подключения
				closing(fd);
			}
			// Ждём подъёма сервера
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
	inline bool relay(client::context_t & client, const int fd) noexcept {
		// Признак того, что байты передавались
		bool moved = false;
		// Получаем байты, отправляемые клиентом
		const view_t data = client.output();
		// Если клиенту есть что отправить
		if(data.size > 0){
			// Отправляем байты в сокет
			const ssize_t sent = sending(fd, data.data, data.size);
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
		const ssize_t received = receiving(fd, buffer, sizeof(buffer));
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
	inline int harbour(uint16_t & number) noexcept {
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
			closing(listener);
			// Выводим отказ
			return -1;
		}
		// Запоминаем назначенный порт
		number = ntohs(address.sin_port);
		// Выводим слушающий сокет
		return listener;
	}
	/**
	 * @brief Метод приёма подключения на слушающем сокете с пределом ожидания приёма
	 *
	 * @param listener описатель слушающего сокета
	 *
	 * @return         описатель принятого подключения либо отрицательное число
	 *
	 */
	inline int greeted(const int listener) noexcept {
		/**
		 * Ожидание подключения с пределом: клиент openssl, умерший на разборе доводов
		 * (LibreSSL не знает иных имён групп), иначе оставил бы accept() навсегда
		 */
		struct pollfd waiting;
		waiting.fd = listener;
		waiting.events = POLLIN;
		waiting.revents = 0;
		// Если за тридцать секунд никто не подключился
		if(ANTS_POLL(&waiting, 1, 30000) <= 0)
			// Выводим отказ
			return -1;
		// Принимаем подключение
		const int fd = ::accept(listener, nullptr, nullptr);
		// Если подключение принято
		if(fd >= 0){
			// Предел ожидания приёма
			patience(fd, 60, 0);
		}
		// Выводим описатель
		return fd;
	}
	/**
	 * @brief Метод ведения связи сервера с сокетом до конца рукопожатия
	 *
	 * @details Клиент openssl с пустым входом шлёт извещение о закрытии сразу за своим
	 *          завершением, и оба сообщения могут прийти одним приёмом - тогда связь уже
	 *          закрыта, а не установлена, и это тоже конец рукопожатия
	 *
	 * @param server связь стороны сервера
	 * @param fd     описатель сокета
	 *
	 * @return       признак того, что рукопожатие дошло до конца
	 *
	 */
	inline bool serve(server::context_t & server, const int fd) noexcept {
		// Признак того, что рукопожатие дошло до конца
		bool complete = false;
		/**
		 * Выполняем передачу байтов до установления, закрытия либо обрыва связи
		 */
		for(size_t i = 0; (i < 8) && !complete && (server.state() != context::state_t::FAILED); i++){
			// Место принятых байтов
			uint8_t buffer[16384];
			// Принимаем байты клиента
			const ssize_t received = receiving(fd, buffer, sizeof(buffer));
			// Если байты приняты
			if(received > 0)
				// Подаём байты серверу
				server.push(view_t(buffer, static_cast <size_t> (received)));
			// Байты сервера
			const view_t data = server.output();
			// Если серверу есть что отправить
			if(data.size > 0){
				// Отправляем байты
				const ssize_t sent = sending(fd, data.data, data.size);
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
	 * @brief Метод закрытия связи сервера с отправкой извещения о закрытии
	 *
	 * @param server связь стороны сервера
	 * @param fd     описатель сокета
	 *
	 * @return       признак того, что закрытие прошло без отказа
	 *
	 */
	inline bool farewell(server::context_t & server, const int fd) noexcept {
		// Если связь уже не открыта
		if(!server.established())
			// Закрывать нечего
			return true;
		// Если закрыть связь не удалось
		if(server.close() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Байты закрытия
		const view_t closing = server.output();
		// Отправляем закрытие
		(void) sending(fd, closing.data, closing.size);
		// Снимаем байты закрытия
		server.consume(closing.size);
		// Выводим успешность закрытия
		return true;
	}
	/**
	 * @brief Метод заведения сокета UDP на петлевом устройстве
	 *
	 * @param number порт привязки, ноль назначается системой
	 * @param bound  место, в которое помещается назначенный порт
	 *
	 * @return       описатель сокета либо отрицательное число
	 *
	 */
	inline int socketing(const uint16_t number, uint16_t & bound) noexcept {
		// Заводим сокет
		const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
		// Если сокет завести не удалось
		if(fd < 0)
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
		// Порт привязки
		address.sin_port = htons(number);
		// Длина адреса
		socklen_t length = sizeof(address);
		// Если привязка либо чтение адреса не удались
		if((::bind(fd, reinterpret_cast <struct sockaddr *> (&address), sizeof(address)) != 0) || (::getsockname(fd, reinterpret_cast <struct sockaddr *> (&address), &length) != 0)){
			// Закрываем сокет
			closing(fd);
			// Выводим отказ
			return -1;
		}
		// Запоминаем назначенный порт
		bound = ntohs(address.sin_port);
		// Предел ожидания приёма: доля секунды, ибо часы связи ведёт проверка
		patience(fd, 0, 200000);
		// Выводим сокет
		return fd;
	}
	/**
	 * @brief Метод ведения связи клиента с сокетом UDP до конца рукопожатия либо приёма данных
	 *
	 * @param client связь стороны клиента
	 * @param fd     описатель сокета, подключённого к серверу
	 * @param peer   адрес сервера
	 * @param rounds предел кругов переноса
	 *
	 * @return       признак того, что связь установлена
	 *
	 */
	inline bool relay(client::context_t & client, const int fd, const struct sockaddr_in & peer, const size_t rounds) noexcept {
		/**
		 * Выполняем перенос дейтаграмм до установления, обрыва либо исчерпания кругов
		 */
		for(size_t i = 0; (i < rounds) && (client.state() != context::state_t::FAILED); i++){
			/**
			 * Выполняем отправку готовых дейтаграмм по одной
			 */
			while(client.output().size > 0){
				// Очередная дейтаграмма
				const view_t data = client.output();
				// Отправляем дейтаграмму серверу
				(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), sizeof(peer));
				// Снимаем дейтаграмму
				client.consume(data.size);
			}
			// Если связь установлена и ждать нечего
			if(client.established() && (client.timeout() == 0))
				// Выводим успешность
				return true;
			// Место принятой дейтаграммы
			uint8_t buffer[65536];
			// Принимаем дейтаграмму с ожиданием
			const ssize_t received = receiving(fd, buffer, sizeof(buffer));
			// Если дейтаграмма принята
			if(received > 0)
				// Подаём дейтаграмму связи
				client.push(view_t(buffer, static_cast <size_t> (received)));
			// Если ожидание истекло, а часы идут
			else if(client.timeout() > 0)
				// Извещаем связь об истечении срока
				client.elapsed();
		}
		// Выводим итог
		return (client.established() && (client.timeout() == 0));
	}
	/**
	 * @brief Метод получения имени группы у openssl
	 *
	 * @param group группа обмена
	 *
	 * @return      имя группы у openssl
	 *
	 */
	inline const char * naming(const extension::group_t group) noexcept {
		// Выводим имя группы у openssl
		return ((group == extension::group_t::X25519) ? "X25519" : ((group == extension::group_t::SECP256R1) ? "P-256" : "P-384"));
	}
	/**
	 * @brief Метод получения имени кривой в записи ecparam
	 *
	 * @param group группа обмена ключами
	 *
	 * @return      имя кривой для ключа -named_curve
	 *
	 */
	inline const char * formal(const extension::group_t group) noexcept {
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
	inline std::string roster(const extension::group_t group) noexcept {
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
	 * @brief Способности системного openssl, снятые щупами
	 *
	 * @details Ключи командной строки разнятся по изданиям (1.0.2, 1.1.x, 3.x) и по ветвям
	 *          (OpenSSL, LibreSSL); что нельзя спросить у справки, выводится пробой
	 *          возможности, а не по номеру издания
	 *
	 */
	typedef struct Toolkit {
		// Признак наличия openssl
		bool present;
		// Признак ветви LibreSSL
		bool libre;
		// Признак поддержки издания TLS 1.2 набором ECDHE
		bool tls12;
		// Признак поддержки издания TLS 1.3
		bool tls13;
		// Признак поддержки расширенного главного секрета RFC 7627
		bool master;
		// Признак поддержки DTLS 1.2 у s_server и s_client
		bool dtls12;
		// Признак ключа -listen у s_server: приём приветствия с меткой
		bool listening;
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
		// Признак поддержки ключа Ed25519
		bool edwards;
		// Число издания: старший, средний и младший разряды
		uint32_t edition;
		/**
		 * Конструктор
		 */
		Toolkit() noexcept : present(false), libre(false), tls12(false), tls13(false), master(false), dtls12(false), listening(false), serverGroups(false), namedCurve(false), clientGroups(false), clientCurves(false), naccept(false), addressed(false), x25519(false), edwards(false), edition(0) {}
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
	inline bool listed(const char * program, const char * key) noexcept {
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
	inline bool offered() noexcept {
		// Порт слушающего сокета
		uint16_t number = 0;
		// Заводим слушающий сокет
		const int listener = harbour(number);
		// Если сокет не завёлся
		if(listener < 0)
			// Выводим отсутствие расширения
			return false;
		// Журнал s_client
		const std::string log = "/tmp/ants-openssl-probe-" + std::to_string(number) + ".log";
		// Если s_client не запустился
		if(!launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_2 </dev/null >" + log + " 2>&1", log, log + ".pid")){
			// Закрываем слушающий сокет
			closing(listener);
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
				patience(fd, 30, 0);
				// Накопитель приветствия
				uint8_t buffer[16384];
				// Принимаем приветствие клиента
				const ssize_t received = receiving(fd, buffer, sizeof(buffer));
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
				closing(fd);
			}
		}
		// Закрываем слушающий сокет
		closing(listener);
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
	inline toolkit_t inspect() noexcept {
		// Способности системного openssl
		toolkit_t result;
		// Если openssl недоступен
		if(shell("openssl version >/dev/null 2>&1") != 0)
			// Выводим пустые способности
			return result;
		// Запоминаем наличие openssl
		result.present = true;
		// Путь к файлу с изданием openssl
		const std::string path = "/tmp/ants-openssl-edition-" + std::to_string(static_cast <long> (::getpid())) + ".txt";
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
		// Признак поддержки TLS 1.3 (проба возможности, не по номеру издания)
		result.tls13 = (shell("openssl ciphers -s -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 >/dev/null 2>&1") == 0);
		// Расширенный главный секрет снимается с живого приветствия s_client (OpenSSL 1.0.2 и LibreSSL его не несут)
		result.master = (result.tls12 && offered());
		// Снимаем поддержку DTLS 1.2 у обеих подкоманд
		result.dtls12 = (listed("s_server", "dtls1_2") && listed("s_client", "dtls1_2"));
		// Снимаем ключ приёма приветствия с меткой
		result.listening = listed("s_server", "listen");
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
		// Ключ Ed25519: щупом служит порождение ключа
		result.edwards = (shell("openssl genpkey -algorithm ed25519 -out /dev/null >/dev/null 2>&1") == 0);
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
	inline std::string accepting(const toolkit_t & toolkit, const uint16_t number) noexcept {
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
	 * @param count   число приёмов
	 *
	 * @return        ключ предела приёмов либо пустая строка
	 *
	 */
	inline std::string once(const toolkit_t & toolkit, const size_t count) noexcept {
		// Без ключа сервер живёт до снятия сторожем
		return (toolkit.naccept ? (" -naccept " + std::to_string(count)) : "");
	}
	/**
	 * @brief Метод составления ключа единственного приёма s_server
	 *
	 * @param toolkit способности openssl
	 *
	 * @return        ключ единственного приёма либо пустая строка
	 *
	 */
	inline std::string once(const toolkit_t & toolkit) noexcept {
		// Выводим ключ единственного приёма
		return once(toolkit, 1);
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
	inline std::string grouping(const toolkit_t & toolkit, const bool server, const extension::group_t group) noexcept {
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
};

#endif // __ANTS_TESTS_OPENSSL__
