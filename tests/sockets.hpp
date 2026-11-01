/**
 * @file sockets.hpp
 * @date 2026-09-17
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
 * @brief Сокеты оснастки проверок: одни имена под POSIX и Windows (Winsock)
 *
 * @details Проверки интеропа гоняют байты через настоящие сокеты к openssl. У Windows
 *          сокет не закрывается close(), срок ожидания приёма - число миллисекунд, а
 *          не timeval, опрос - WSAPoll, и Winsock требует подъёма. Всё это спрятано
 *          здесь: проверки зовут closing(), patience() и ANTS_POLL()
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_TESTS_SOCKETS__
/**
 * Страж включения: файл подключается однократно
 */
#define __ANTS_TESTS_SOCKETS__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>

/**
 * Системные заголовочные файлы сокетов: у Windows - Winsock, у прочих - POSIX
 */
#if defined(_WIN32)
	/**
	 * Урезанный windows.h: без него winsock2.h тянет rpcndr/objidl, где ::byte
	 * спорит со std::byte при using namespace std; min/max макросами тоже не нужны
	 */
	#if !defined(WIN32_LEAN_AND_MEAN)
		/**
		 * Включаем урезанный windows.h без rpcndr/objidl и без min/max
		 */
		#define WIN32_LEAN_AND_MEAN
	#endif
	/**
	 * Макросы min/max Windows оснастке не нужны
	 */
	#if !defined(NOMINMAX)
		/**
		 * Отключаем макросы min/max Windows
		 */
		#define NOMINMAX
	#endif
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>
/**
 * Прочие системы: POSIX-заголовки сокетов
 */
#else
	#include <sys/stat.h>
	#include <posix.hpp>
	#include <poll.h>
	#include <sys/socket.h>
	#include <sys/select.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

/**
 * Для операционной системы MS Windows
 */
#if defined(_WIN32)
	/**
	 * @brief Подъём Winsock один раз на процесс: сокеты оснастки без него не заводятся
	 *
	 */
	struct AntsWinsock {
		// Подъём Winsock версии 2.2 при создании объекта
		AntsWinsock() noexcept { WSADATA data; (void) ::WSAStartup(MAKEWORD(2, 2), &data); }
		// Опускание Winsock при уничтожении объекта
		~AntsWinsock() noexcept { ::WSACleanup(); }
	};
	// Единственный экземпляр поднимает Winsock при загрузке оснастки
	static const AntsWinsock __ants_winsock__;
	/**
	 * @brief Закрытие сокета: у Windows close() сокет не закрывает
	 *
	 * @param fd описатель сокета
	 *
	 */
	static inline void closing(const int fd) noexcept { ::closesocket(static_cast <SOCKET> (fd)); }
	/**
	 * @brief Срок ожидания приёма: у Windows это число миллисекунд, а не timeval
	 *
	 * @param fd      описатель сокета
	 * @param seconds секунды
	 * @param micros  микросекунды
	 *
	 */
	static inline void patience(const int fd, const long seconds, const long micros) noexcept {
		// Срок ожидания приёма в миллисекундах
		const DWORD limit = static_cast <DWORD> ((seconds * 1000) + (micros / 1000));
		// Устанавливаем срок ожидания приёма на сокете
		(void) ::setsockopt(static_cast <SOCKET> (fd), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast <const char *> (&limit), sizeof(limit));
	}
	/**
	 * Опрос готовности сокетов через WSAPoll
	 */
	#define ANTS_POLL(fds, count, timeout) ::WSAPoll((fds), (count), (timeout))
/**
 * Для операционных систем POSIX
 */
#else
	/**
	 * @brief Закрытие сокета
	 *
	 * @param fd описатель сокета
	 *
	 */
	static inline void closing(const int fd) noexcept { ::close(fd); }
	/**
	 * @brief Срок ожидания приёма
	 *
	 * @param fd      описатель сокета
	 * @param seconds секунды
	 * @param micros  микросекунды
	 *
	 */
	static inline void patience(const int fd, const long seconds, const long micros) noexcept {
		// Срок ожидания приёма в виде timeval
		struct timeval limit;
		// Секунды срока ожидания
		limit.tv_sec = seconds;
		// Микросекунды срока ожидания
		limit.tv_usec = static_cast <suseconds_t> (micros);
		// Устанавливаем срок ожидания приёма на сокете
		(void) ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
	}
	/**
	 * Опрос готовности сокетов через poll
	 */
	#define ANTS_POLL(fds, count, timeout) ::poll((fds), (count), (timeout))
#endif

/**
 * @brief Отправка и приём: у Winsock буферы char *, у POSIX void *; длины - int у Winsock
 *
 */
#if defined(_WIN32)
	// Отправка байт собеседнику через Winsock
	static inline long sending(const int fd, const void * data, const size_t size) noexcept { return ::send(static_cast <SOCKET> (fd), static_cast <const char *> (data), static_cast <int> (size), 0); }
	// Приём байт от собеседника через Winsock
	static inline long receiving(const int fd, void * data, const size_t size) noexcept { return ::recv(static_cast <SOCKET> (fd), static_cast <char *> (data), static_cast <int> (size), 0); }
	// Отправка дейтаграммы адресату через Winsock
	static inline long sendingto(const int fd, const void * data, const size_t size, const struct sockaddr * peer, const socklen_t length) noexcept { return ::sendto(static_cast <SOCKET> (fd), static_cast <const char *> (data), static_cast <int> (size), 0, peer, static_cast <int> (length)); }
	// Приём дейтаграммы с адресом отправителя через Winsock
	static inline long receivingfrom(const int fd, void * data, const size_t size, struct sockaddr * peer, socklen_t * length) noexcept { int width = static_cast <int> (*length); const int result = ::recvfrom(static_cast <SOCKET> (fd), static_cast <char *> (data), static_cast <int> (size), 0, peer, &width); *length = static_cast <socklen_t> (width); return result; }
/**
 * Прочие системы: POSIX-варианты отправки и приёма
 */
#else
	// Отправка байт собеседнику
	static inline long sending(const int fd, const void * data, const size_t size) noexcept { return static_cast <long> (::send(fd, data, size, 0)); }
	// Приём байт от собеседника
	static inline long receiving(const int fd, void * data, const size_t size) noexcept { return static_cast <long> (::recv(fd, data, size, 0)); }
	// Отправка дейтаграммы адресату
	static inline long sendingto(const int fd, const void * data, const size_t size, const struct sockaddr * peer, const socklen_t length) noexcept { return static_cast <long> (::sendto(fd, data, size, 0, peer, length)); }
	// Приём дейтаграммы с адресом отправителя
	static inline long receivingfrom(const int fd, void * data, const size_t size, struct sockaddr * peer, socklen_t * length) noexcept { return static_cast <long> (::recvfrom(fd, data, size, 0, peer, length)); }
#endif

/**
 * @brief Именованный канал для команд серверу openssl: у Windows его нет, и оснастка
 *        честно отвечает отказом - интероп там пропускается
 *
 * @param path путь канала
 * @return     нуль при успехе
 *
 */
static inline int fifo(const char * path) noexcept {
	/**
	 * У Windows именованных каналов нет
	 */
	#if defined(_WIN32)
		// Путь канала не используется
		(void) path;
		// Честный отказ вместо создания канала
		return -1;
	/**
	 * Создание именованного канала в POSIX
	 */
	#else
		// Канал с правами доступа только владельца
		return ::mkfifo(path, 0600);
	#endif
}

#endif
