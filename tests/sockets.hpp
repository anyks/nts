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
 *          здесь: проверки зовут closing(), patience() и NTS_POLL()
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

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
	static const AntsWinsock __nts_winsock__;
	/**
	 * @brief Функция закрытия сокета: у Windows close() сокет не закрывает
	 *
	 * @param peer описатель сокета
	 *
	 */
	static inline void closing(const int peer) noexcept {
		// Закрываем сокет собеседника
		::closesocket(static_cast <SOCKET> (peer));
	}
	/**
	 * @brief Функция срока ожидания приёма: у Windows это число миллисекунд, а не timeval
	 *
	 * @param peer    описатель сокета
	 * @param seconds секунды
	 * @param micros  микросекунды
	 *
	 */
	static inline void patience(const int peer, const long seconds, const long micros) noexcept {
		// Срок ожидания приёма в миллисекундах
		const DWORD limit = static_cast <DWORD> ((seconds * 1000) + (micros / 1000));
		// Устанавливаем срок ожидания приёма на сокете
		(void) ::setsockopt(static_cast <SOCKET> (peer), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast <const char *> (&limit), sizeof(limit));
	}
	/**
	 * Опрос готовности сокетов через WSAPoll
	 */
	#define NTS_POLL(fds, count, timeout) ::WSAPoll((fds), (count), (timeout))
/**
 * Для операционных систем POSIX
 */
#else
	/**
	 * @brief Функция закрытия сокета
	 *
	 * @param peer описатель сокета
	 *
	 */
	static inline void closing(const int peer) noexcept {
		// Закрываем сокет собеседника
		::close(peer);
	}
	/**
	 * @brief Функция срока ожидания приёма
	 *
	 * @param peer    описатель сокета
	 * @param seconds секунды
	 * @param micros  микросекунды
	 *
	 */
	static inline void patience(const int peer, const long seconds, const long micros) noexcept {
		// Срок ожидания приёма в виде timeval
		struct timeval limit;
		// Секунды срока ожидания
		limit.tv_sec = seconds;
		// Микросекунды срока ожидания
		limit.tv_usec = static_cast <suseconds_t> (micros);
		// Устанавливаем срок ожидания приёма на сокете
		(void) ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
	}
	/**
	 * Опрос готовности сокетов через poll
	 */
	#define NTS_POLL(fds, count, timeout) ::poll((fds), (count), (timeout))
#endif

/**
 * @brief Функции отправки и приёма: у Winsock буферы char *, у POSIX void *; длины - int у Winsock
 *
 */
#if defined(_WIN32)
	// Отправка байт собеседнику через Winsock
	static inline long sending(const int peer, const void * data, const size_t size) noexcept {
		// Отправляем байты собеседнику и возвращаем их число
		return ::send(static_cast <SOCKET> (peer), static_cast <const char *> (data), static_cast <int> (size), 0);
	}
	// Приём байт от собеседника через Winsock
	static inline long receiving(const int peer, void * data, const size_t size) noexcept {
		// Принимаем байты от собеседника и возвращаем их число
		return ::recv(static_cast <SOCKET> (peer), static_cast <char *> (data), static_cast <int> (size), 0);
	}
	// Отправка дейтаграммы адресату через Winsock
	static inline long sendingto(const int peer, const void * data, const size_t size, const struct sockaddr * address, const socklen_t length) noexcept {
		// Отправляем дейтаграмму адресату и возвращаем её размер
		return ::sendto(static_cast <SOCKET> (peer), static_cast <const char *> (data), static_cast <int> (size), 0, address, static_cast <int> (length));
	}
	// Приём дейтаграммы с адресом отправителя через Winsock
	static inline long receivingfrom(const int peer, void * data, const size_t size, struct sockaddr * address, socklen_t * length) noexcept {
		// Ширина адреса отправителя в терминах Winsock
		int width = static_cast <int> (*length);
		// Принимаем дейтаграмму с адресом отправителя и возвращаем её размер
		const int result = ::recvfrom(static_cast <SOCKET> (peer), static_cast <char *> (data), static_cast <int> (size), 0, address, &width);
		// Возвращаем ширину адреса отправителя
		*length = static_cast <socklen_t> (width);
		// Возвращаем размер принятой дейтаграммы
		return result;
	}
/**
 * Прочие системы: POSIX-варианты отправки и приёма
 */
#else
	// Отправка байт собеседнику
	static inline long sending(const int peer, const void * data, const size_t size) noexcept {
		// Отправляем байты собеседнику и возвращаем их число
		return static_cast <long> (::send(peer, data, size, 0));
	}
	// Приём байт от собеседника
	static inline long receiving(const int peer, void * data, const size_t size) noexcept {
		// Принимаем байты от собеседника и возвращаем их число
		return static_cast <long> (::recv(peer, data, size, 0));
	}
	// Отправка дейтаграммы адресату
	static inline long sendingto(const int peer, const void * data, const size_t size, const struct sockaddr * address, const socklen_t length) noexcept {
		// Отправляем дейтаграмму адресату и возвращаем её размер
		return static_cast <long> (::sendto(peer, data, size, 0, address, length));
	}
	// Приём дейтаграммы с адресом отправителя
	static inline long receivingfrom(const int peer, void * data, const size_t size, struct sockaddr * address, socklen_t * length) noexcept {
		// Принимаем дейтаграмму с адресом отправителя и возвращаем её размер
		return static_cast <long> (::recvfrom(peer, data, size, 0, address, length));
	}
#endif

/**
 * @brief Функция именованного канала для команд серверу openssl: у Windows его нет, и оснастка
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

