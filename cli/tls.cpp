/**
 * @file tls.cpp
 * @date 2026-11-19
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
 * @brief Команды связи консольной утилиты a-nts — клиент s_client и сервер s_server
 *
 * @details Команды повторяют устройство openssl: s_client подключается к узлу по имени
 *          и порту, ведёт рукопожатие и ретранслирует данные между стандартным вводом
 *          и связью; s_server принимает соединение на порту, предъявляет подлинность
 *          сертификатом и ретранслирует данные между связью и стандартным вводом.
 *          Сеть утилита ведёт сама сокетами системы, а рукопожатие и защиту записей
 *          отдаёт фасадам связи библиотеки
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>

/**
 * Системные заголовочные файлы сокетов: у Windows — Winsock, у прочих — POSIX
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
	 * Макросы min/max Windows утилите не нужны
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
	#include <io.h>
	#include <fcntl.h>
/**
 * Прочие системы: POSIX-заголовки сокетов
 */
#else
	#include <unistd.h>
	#include <poll.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include "common.hpp"
#include "tls.hpp"
#include "pem/pem.hpp"
#include "trust/trust.hpp"
#include "x509/x509.hpp"
#include "client/client.hpp"
#include "server/server.hpp"

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Вид описателя сокета: у Windows — SOCKET, у прочих — int
	 */
	#if defined(_WIN32)
		// Описатель сокета Winsock
		typedef SOCKET __nts_socket_t__;
		/**
		 * @brief Функция получения негодного описателя сокета
		 *
		 * @return негодный описатель сокета
		 *
		 */
		static inline __nts_socket_t__ __nts_socket_invalid__() noexcept {
			// Выводим негодный описатель сокета Winsock
			return INVALID_SOCKET;
		}
		/**
		 * @brief Подъём Winsock один раз на процесс: сокеты без него не заводятся
		 *
		 */
		struct __nts_winsock__ {
			// Подъём Winsock версии 2.2 при создании объекта
			__nts_winsock__() noexcept { WSADATA data; (void) ::WSAStartup(MAKEWORD(2, 2), &data); }
			// Опускание Winsock при уничтожении объекта
			~__nts_winsock__() noexcept { ::WSACleanup(); }
		};
		// Единственный экземпляр поднимает Winsock при загрузке утилиты
		static const __nts_winsock__ __nts_socket_lift__;
	/**
	 * Описатель сокета POSIX
	 */
	#else
		// Описатель сокета системы
		typedef int __nts_socket_t__;
		/**
		 * @brief Функция получения негодного описателя сокета
		 *
		 * @return негодный описатель сокета
		 *
		 */
		static inline __nts_socket_t__ __nts_socket_invalid__() noexcept {
			// Выводим негодный описатель сокета системы
			return -1;
		}
	#endif

	/**
	 * @brief Функция закрытия сокета: у Windows close() сокет не закрывает
	 *
	 * @param peer описатель сокета
	 *
	 */
	static void __nts_close__(const __nts_socket_t__ peer) noexcept {
		/**
		 * У Windows сокет закрывается своим вызовом
		 */
		#if defined(_WIN32)
			// Закрываем сокет собеседника
			::closesocket(peer);
		/**
		 * У POSIX сокет закрывается обычным close
		 */
		#else
			// Закрываем сокет собеседника
			::close(peer);
		#endif
	}
	/**
	 * @brief Функция отправки байтов собеседнику
	 *
	 * @param peer описатель сокета
	 * @param data отправляемые байты
	 * @param size размер отправляемых байтов
	 * @return     число отправленных байтов, отрицательное при отказе
	 *
	 */
	static long __nts_send__(const __nts_socket_t__ peer, const void * data, const size_t size) noexcept {
		/**
		 * У Windows буфер send() — const char *, длина — int
		 */
		#if defined(_WIN32)
			// Отправляем байты собеседнику
			return ::send(peer, static_cast <const char *> (data), static_cast <int> (size), 0);
		/**
		 * У POSIX отправка без сигнала о разорванном канале
		 */
		#else
			// Отправляем байты собеседнику
			return static_cast <long> (::send(peer, data, size, MSG_NOSIGNAL));
		#endif
	}
	/**
	 * @brief Функция приёма байтов от собеседника
	 *
	 * @param peer описатель сокета
	 * @param data место, в которое помещаются принятые байты
	 * @param size размер места приёма
	 * @return     число принятых байтов, ноль при закрытии, отрицательное при отказе
	 *
	 */
	static long __nts_recv__(const __nts_socket_t__ peer, void * data, const size_t size) noexcept {
		/**
		 * У Windows буфер recv() — char *, длина — int
		 */
		#if defined(_WIN32)
			// Принимаем байты от собеседника
			return ::recv(peer, static_cast <char *> (data), static_cast <int> (size), 0);
		/**
		 * У POSIX приём обычным recv
		 */
		#else
			// Принимаем байты от собеседника
			return static_cast <long> (::recv(peer, data, size, 0));
		#endif
	}
	/**
	 * @brief Функция чтения стандартного ввода
	 *
	 * @param data место, в которое помещаются прочитанные байты
	 * @param size размер места чтения
	 * @return     число прочитанных байтов, ноль в конце ввода, отрицательное при отказе
	 *
	 */
	static long __nts_input__(void * data, const size_t size) noexcept {
		/**
		 * У Windows ввод читается вызовом _read по описателю ноль
		 */
		#if defined(_WIN32)
			// Читаем стандартный ввод
			return ::_read(0, data, static_cast <unsigned int> (size));
		/**
		 * У POSIX ввод читается обычным read
		 */
		#else
			// Читаем стандартный ввод
			return static_cast <long> (::read(STDIN_FILENO, data, size));
		#endif
	}
	/**
	 * @brief Функция записи на стандартный вывод
	 *
	 * @param data записываемые байты
	 * @param size размер записываемых байтов
	 *
	 */
	static void __nts_output__(const void * data, const size_t size) noexcept {
		/**
		 * У Windows вывод пишется вызовом _write по описателю один
		 */
		#if defined(_WIN32)
			// Пишем на стандартный вывод
			(void) ::_write(1, data, static_cast <unsigned int> (size));
		/**
		 * У POSIX вывод пишется обычным write
		 */
		#else
			// Пишем на стандартный вывод
			(void) ::write(STDOUT_FILENO, data, size);
		#endif
	}
	/**
	 * @brief Функция перевода ввода и вывода в двоичный вид: на Windows без неё перевод
	 *        строки искажает передаваемые байты
	 *
	 */
	static void __nts_binary__() noexcept {
		/**
		 * Перевод в двоичный вид нужен лишь Windows
		 */
		#if defined(_WIN32)
			// Переводим стандартный ввод в двоичный вид
			(void) ::_setmode(::_fileno(stdin), _O_BINARY);
			// Переводим стандартный вывод в двоичный вид
			(void) ::_setmode(::_fileno(stdout), _O_BINARY);
		/**
		 * Прочим системам перевод не нужен
		 */
		#else
			// Перевода не требуется
			return;
		#endif
	}
	/**
	 * @brief Функция ожидания готовности сокета либо стандартного ввода
	 *
	 * @param peer        описатель сокета
	 * @param stdinOpen   ведётся ли приём со стандартного ввода
	 * @param socketReady место, в которое помещается признак готовности сокета
	 * @param stdinReady  место, в которое помещается признак готовности ввода
	 * @return            признак успешности ожидания
	 *
	 */
	bool __nts_wait__(const __nts_socket_t__ peer, const bool stdinOpen, bool & socketReady, bool & stdinReady) noexcept {
		// Сбрасываем признак готовности сокета
		socketReady = false;
		// Сбрасываем признак готовности ввода
		stdinReady = false;
		/**
		 * Ожидание у Windows: сокет через WSAPoll, ввод — ожиданием описателя
		 */
		#if defined(_WIN32)
			/**
			 * Ожидаем готовности сокета либо ввода короткими промежутками
			 */
			for(;;){
				// Опрос готовности сокета
				WSAPOLLFD pfd;
				// Описатель опрашиваемого сокета
				pfd.fd = peer;
				// Интересует готовность приёма
				pfd.events = POLLRDNORM;
				// Сбрасываем итог опроса
				pfd.revents = 0;
				// Ожидаем готовность сокета пятьюдесятью миллисекундами
				const int ready = ::WSAPoll(&pfd, 1, 50);
				// Если сокет готов к приёму либо оборван
				if((ready > 0) && ((pfd.revents & (POLLRDNORM | POLLERR | POLLHUP)) != 0)){
					// Отмечаем готовность сокета
					socketReady = true;
					// Выходим из ожидания
					break;
				}
				// Если опрос отказал
				if(ready < 0)
					// Сообщаем об отказе ожидания
					return false;
				// Если ввод ведётся
				if(stdinOpen){
					// Описатель стандартного ввода
					const HANDLE input = ::GetStdHandle(STD_INPUT_HANDLE);
					// Если ввод готов
					if((input != nullptr) && (input != INVALID_HANDLE_VALUE) && (::WaitForSingleObject(input, 0) == WAIT_OBJECT_0)){
						// Отмечаем готовность ввода
						stdinReady = true;
						// Выходим из ожидания
						break;
					}
				}
			}
		/**
		 * Ожидание у POSIX: обычный poll по сокету и вводу
		 */
		#else
			// Набор опрашиваемых описателей
			struct pollfd fds[2];
			// Описатель сокета
			fds[0].fd = peer;
			// Интересует готовность приёма
			fds[0].events = POLLIN;
			// Число опрашиваемых описателей
			nfds_t count = 1;
			// Если ввод ведётся
			if(stdinOpen){
				// Описатель стандартного ввода
				fds[1].fd = STDIN_FILENO;
				// Интересует готовность приёма
				fds[1].events = POLLIN;
				// Опрашиваем оба описателя
				count = 2;
			}
			// Ожидаем готовности описателей
			const int ready = ::poll(fds, count, -1);
			// Если ожидание отказало
			if(ready < 0)
				// Сообщаем об отказе ожидания
				return false;
			// Если сокет готов либо оборван
			socketReady = ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0);
			// Если ввод ведётся и готов
			if(stdinOpen)
				// Отмечаем готовность ввода
				stdinReady = ((fds[1].revents & (POLLIN | POLLHUP)) != 0);
		#endif
		// Сообщаем об успешности ожидания
		return true;
	}
	/**
	 * @brief Функция составления подлинности стороны из ключа и цепочки сертификатов
	 *
	 * @param cert   путь к файлу цепочки сертификатов в записи PEM либо DER
	 * @param key    путь к файлу секретного ключа в записи PEM
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool __nts_identity__(const char * cert, const char * key, context::credential_t & result) noexcept {
		// Если путей не задано
		if((cert == nullptr) || (key == nullptr))
			// Сообщаем об отказе составления подлинности
			return false;
		// Область прочитанного секретного ключа
		vector <uint8_t> secret;
		// Если ключ прочитать не удалось
		if(!cli::readBytes(key, secret))
			// Сообщаем об отказе составления подлинности
			return false;
		// Область прочитанной цепочки сертификатов
		vector <uint8_t> text;
		// Если цепочку прочитать не удалось
		if(!cli::readBytes(cert, text))
			// Сообщаем об отказе составления подлинности
			return false;
		// Запоминаем секретный ключ как есть
		result.secret = secret;
		// Сбрасываем цепочку сертификатов
		result.chain.clear();
		// Текст записи цепочки
		const string pemText(reinterpret_cast <const char *> (text.data()), text.size());
		// Если цепочку из записи PEM разобрать не удалось либо её нет
		if((pem::certificates(pemText, result.chain) != pem::error_t::NONE) || result.chain.empty()){
			// Сбрасываем цепочку сертификатов
			result.chain.clear();
			// Принимаем запись DER одним сертификатом
			result.chain.push_back(text);
		}
		// Готовим подлинность к работе и выводим итог
		return (result.prepare() == context::error_t::NONE);
	}
	/**
	 * @brief Функция наполнения запаса доверенных сертификатов из файла
	 *
	 * @param path  путь к файлу доверенных сертификатов в записи PEM либо DER
	 * @param store запас, в который помещаются доверенные сертификаты
	 * @return      признак успешности наполнения запаса
	 *
	 */
	bool __nts_store__(const char * path, trust::store_t & store) noexcept {
		// Область прочитанного файла
		vector <uint8_t> text;
		// Если файл прочитать не удалось
		if(!cli::readBytes(path, text))
			// Сообщаем об отказе наполнения запаса
			return false;
		// Текст записи файла
		const string pemText(reinterpret_cast <const char *> (text.data()), text.size());
		// Цепочка доверенных сертификатов
		vector <vector <uint8_t>> chain;
		// Если цепочку из записи PEM разобрать удалось
		if(pem::certificates(pemText, chain) == pem::error_t::NONE){
			/**
			 * Добавляем доверенные сертификаты в запас
			 */
			for(size_t i = 0; i < chain.size(); i++)
				// Если сертификат добавить не удалось
				if(!store.add(view_t(chain[i].data(), chain[i].size())))
					// Сообщаем об отказе наполнения запаса
					return false;
			// Сообщаем об успешности наполнения запаса
			return true;
		}
		// Принимаем запись DER одним доверенным сертификатом
		return store.add(view_t(text.data(), text.size()));
	}
	/**
	 * @brief Функция проведения рукопожатия через сокет
	 *
	 * @param context связь стороны
	 * @param peer    описатель сокета собеседника
	 * @return        признак того, что рукопожатие пройдено
	 *
	 */
	template <typename Context>
	bool __nts_handshake__(Context & context, const __nts_socket_t__ peer) noexcept {
		// Если связь завести не удалось
		if(context.start() != context::error_t::NONE)
			// Сообщаем об отказе рукопожатия
			return false;
		// Область принятых байтов
		uint8_t buffer[16384];
		/**
		 * Ведём рукопожатие кругами обмена байтами
		 */
		for(size_t rounds = 0; rounds < 64; rounds++){
			/**
			 * Выводим всё, что связь накопила к отправке
			 */
			for(;;){
				// Накопленные байты связи
				view_t data = context.output();
				// Если выводить нечего
				if(data.size == 0)
					// Прерываем вывод
					break;
				// Если байты отправить не удалось
				if(__nts_send__(peer, data.data, data.size) <= 0)
					// Сообщаем об отказе рукопожатия
					return false;
				// Снимаем отправленные байты с накопителя связи
				context.consume(data.size);
			}
			// Если рукопожатие пройдено
			if(context.established())
				// Сообщаем об успешности рукопожатия
				return true;
			// Если связь оборвана отказом
			if(context.error() != context::error_t::NONE)
				// Сообщаем об отказе рукопожатия
				return false;
			// Принятые байты
			const long received = __nts_recv__(peer, buffer, sizeof(buffer));
			// Если байты принять не удалось
			if(received <= 0)
				// Сообщаем об отказе рукопожатия
				return false;
			// Подаём принятые байты связи
			if(context.push(view_t(buffer, static_cast <size_t> (received))) != context::error_t::NONE)
				// Сообщаем об отказе рукопожатия
				return false;
		}
		// Сообщаем об отказе рукопожатия
		return false;
	}
	/**
	 * @brief Функция ретрансляции данных между стандартным вводом и связью
	 *
	 * @param context связь стороны
	 * @param peer    описатель сокета собеседника
	 * @param ignEof  не закрывать ли связь по концу стандартного ввода
	 * @return        код выхода из команды
	 *
	 */
	template <typename Context>
	int __nts_relay__(Context & context, const __nts_socket_t__ peer, const bool ignEof) noexcept {
		// Область передаваемых байтов
		uint8_t buffer[16384];
		// Признак того, что ввод ещё ведётся
		bool stdinOpen = true;
		/**
		 * Ретранслируем данные, пока связь и ввод живы
		 */
		for(;;){
			/**
			 * Выводим всё, что связь накопила к отправке
			 */
			for(;;){
				// Накопленные байты связи
				view_t data = context.output();
				// Если выводить нечего
				if(data.size == 0)
					// Прерываем вывод
					break;
				// Если байты отправить не удалось
				if(__nts_send__(peer, data.data, data.size) <= 0)
					// Сообщаем об отказе ретрансляции
					return EXIT_FAILURE;
				// Снимаем отправленные байты с накопителя связи
				context.consume(data.size);
			}
			// Если связь оборвана отказом
			if(context.error() != context::error_t::NONE)
				// Сообщаем об отказе ретрансляции
				return EXIT_FAILURE;
			// Если собеседник завершил передачу извещением close_notify: приём окончен,
			// своё извещение (прямое либо ответное) уже выведено выше, связь завершена
			if(context.alert().description == alert::description_t::CLOSE)
				// Завершаем ретрансляцию
				return EXIT_SUCCESS;
			// Признак готовности сокета
			bool socketReady = false;
			// Признак готовности ввода
			bool stdinReady = false;
			// Если готовности дождаться не удалось
			if(!__nts_wait__(peer, stdinOpen, socketReady, stdinReady))
				// Сообщаем об отказе ретрансляции
				return EXIT_FAILURE;
			// Если сокет готов к приёму
			if(socketReady){
				// Принятые байты
				const long received = __nts_recv__(peer, buffer, sizeof(buffer));
				// Если байты принять не удалось либо собеседник закрыл связь
				if(received <= 0)
					// Завершаем ретрансляцию
					return EXIT_SUCCESS;
				// Подаём принятые байты связи
				if(context.push(view_t(buffer, static_cast <size_t> (received))) != context::error_t::NONE)
					// Сообщаем об отказе ретрансляции
					return EXIT_FAILURE;
				// Принятые прикладные данные
				vector <uint8_t> plain;
				// Если прикладные данные получены
				if((context.read(plain) == context::error_t::NONE) && !plain.empty())
					// Выводим прикладные данные на стандартный вывод
					__nts_output__(plain.data(), plain.size());
			}
			// Если ввод ведётся и готов
			if(stdinOpen && stdinReady){
				// Число прочитанных байтов ввода
				const long got = __nts_input__(buffer, sizeof(buffer));
				// Если ввод прочитать не удалось
				if(got < 0)
					// Сообщаем об отказе ретрансляции
					return EXIT_FAILURE;
				// Если ввод окончен
				if(got == 0){
					// Ввод более не ведётся
					stdinOpen = false;
					// Если связь по концу ввода не удерживается
					if(!ignEof)
						// Завершаем свою передачу извещением close_notify
						(void) context.close();
				// Иначе передаём прочитанные байты собеседнику
				} else if(context.write(view_t(buffer, static_cast <size_t> (got))) != context::error_t::NONE)
					// Сообщаем об отказе ретрансляции
					return EXIT_FAILURE;
			}
		}
	}
	/**
	 * @brief Функция получения названия набора шифрования
	 *
	 * @param suite набор шифрования
	 * @return      название набора шифрования
	 *
	 */
	const char * __nts_suite_name__(const protect::suite_t suite) noexcept {
		/**
		 * Подбираем название по значению набора
		 */
		switch(static_cast <uint16_t> (suite)){
			// Набор не установлен
			case static_cast <uint16_t> (protect::suite_t::NONE): return "-";
			// «Кузнечик» в MGM с редкой сменой ключа
			case static_cast <uint16_t> (protect::suite_t::KUZNYECHIK_MGM_L): return "GOST-KUZNYECHIK-MGM-L";
			// «Магма» в MGM с редкой сменой ключа
			case static_cast <uint16_t> (protect::suite_t::MAGMA_MGM_L): return "GOST-MAGMA-MGM-L";
			// «Кузнечик» в MGM с частой сменой ключа
			case static_cast <uint16_t> (protect::suite_t::KUZNYECHIK_MGM_S): return "GOST-KUZNYECHIK-MGM-S";
			// «Магма» в MGM с частой сменой ключа
			case static_cast <uint16_t> (protect::suite_t::MAGMA_MGM_S): return "GOST-MAGMA-MGM-S";
			// SM4-GCM со SM3
			case static_cast <uint16_t> (protect::suite_t::SM4_GCM_SM3): return "SM4-GCM-SM3";
			// SM4-CCM со SM3
			case static_cast <uint16_t> (protect::suite_t::SM4_CCM_SM3): return "SM4-CCM-SM3";
			// TLS 1.3: AES-128-GCM
			case static_cast <uint16_t> (protect::suite_t::AES_128_GCM_SHA256): return "TLS_AES_128_GCM_SHA256";
			// TLS 1.3: AES-256-GCM
			case static_cast <uint16_t> (protect::suite_t::AES_256_GCM_SHA384): return "TLS_AES_256_GCM_SHA384";
			// TLS 1.3: ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::CHACHA20_POLY1305_SHA256): return "TLS_CHACHA20_POLY1305_SHA256";
			// ECDHE-ECDSA-AES128-GCM
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256): return "ECDHE-ECDSA-AES128-GCM-SHA256";
			// ECDHE-ECDSA-AES256-GCM
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384): return "ECDHE-ECDSA-AES256-GCM-SHA384";
			// ECDHE-RSA-AES128-GCM
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256): return "ECDHE-RSA-AES128-GCM-SHA256";
			// ECDHE-RSA-AES256-GCM
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384): return "ECDHE-RSA-AES256-GCM-SHA384";
			// ECDHE-RSA-ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256): return "ECDHE-RSA-CHACHA20-POLY1305";
			// ECDHE-ECDSA-ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256): return "ECDHE-ECDSA-CHACHA20-POLY1305";
			// ECDHE-ECDSA-AES128-SHA256
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256): return "ECDHE-ECDSA-AES128-SHA256";
			// ECDHE-RSA-AES128-SHA256
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA256): return "ECDHE-RSA-AES128-SHA256";
			// ECDHE-ECDSA-AES128-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA): return "ECDHE-ECDSA-AES128-SHA";
			// ECDHE-ECDSA-AES256-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_256_CBC_SHA): return "ECDHE-ECDSA-AES256-SHA";
			// ECDHE-RSA-AES128-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA): return "ECDHE-RSA-AES128-SHA";
			// ECDHE-RSA-AES256-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA): return "ECDHE-RSA-AES256-SHA";
			// DHE-RSA-AES128-GCM
			case static_cast <uint16_t> (protect::suite_t::DHE_RSA_AES_128_GCM_SHA256): return "DHE-RSA-AES128-GCM-SHA256";
			// DHE-RSA-AES256-GCM
			case static_cast <uint16_t> (protect::suite_t::DHE_RSA_AES_256_GCM_SHA384): return "DHE-RSA-AES256-GCM-SHA384";
			// DHE-RSA-ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::DHE_RSA_CHACHA20_POLY1305_SHA256): return "DHE-RSA-CHACHA20-POLY1305";
			// DHE-RSA-AES128-SHA
			case static_cast <uint16_t> (protect::suite_t::DHE_RSA_AES_128_CBC_SHA): return "DHE-RSA-AES128-SHA";
			// DHE-RSA-AES256-SHA
			case static_cast <uint16_t> (protect::suite_t::DHE_RSA_AES_256_CBC_SHA): return "DHE-RSA-AES256-SHA";
			// AES128-SHA
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_128_CBC_SHA): return "AES128-SHA";
			// AES256-SHA
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_256_CBC_SHA): return "AES256-SHA";
			// AES128-SHA256
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_128_CBC_SHA256): return "AES128-SHA256";
			// AES256-SHA256
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_256_CBC_SHA256): return "AES256-SHA256";
			// AES128-GCM-SHA256
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_128_GCM_SHA256): return "AES128-GCM-SHA256";
			// AES256-GCM-SHA384
			case static_cast <uint16_t> (protect::suite_t::RSA_AES_256_GCM_SHA384): return "AES256-GCM-SHA384";
			// PSK-AES128-CBC-SHA
			case static_cast <uint16_t> (protect::suite_t::PSK_AES_128_CBC_SHA): return "PSK-AES128-CBC-SHA";
			// PSK-AES256-CBC-SHA
			case static_cast <uint16_t> (protect::suite_t::PSK_AES_256_CBC_SHA): return "PSK-AES256-CBC-SHA";
			// ECDHE-PSK-AES128-CBC-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA): return "ECDHE-PSK-AES128-CBC-SHA";
			// ECDHE-PSK-AES256-CBC-SHA
			case static_cast <uint16_t> (protect::suite_t::ECDHE_PSK_AES_256_CBC_SHA): return "ECDHE-PSK-AES256-CBC-SHA";
			// ECDHE-PSK-ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256): return "ECDHE-PSK-CHACHA20-POLY1305";
		}
		// Место под шестнадцатеричную запись набора
		static char buffer[8];
		// Складываем шестнадцатеричную запись набора
		::snprintf(buffer, sizeof(buffer), "0x%04X", static_cast <unsigned int> (suite));
		// Выводим шестнадцатеричную запись набора
		return buffer;
	}
	/**
	 * @brief Функция получения названия издания протокола
	 *
	 * @param version код издания протокола
	 * @return        название издания протокола
	 *
	 */
	const char * __nts_version_name__(const uint16_t version) noexcept {
		// Если издание 1.3
		if(version == 0x0304)
			// Выводим название издания 1.3
			return "TLSv1.3";
		// Если издание 1.2
		if(version == 0x0303)
			// Выводим название издания 1.2
			return "TLSv1.2";
		// Выводим неизвестное издание
		return "TLS";
	}
	/**
	 * @brief Функция получения имени владельца сертификата строкой
	 *
	 * @param der    запись сертификата в кодировке DER
	 * @param result строка, в которую помещается имя владельца
	 * @return       признак успешности получения имени
	 *
	 */
	bool __nts_subject__(const vector <uint8_t> & der, string & result) noexcept {
		// Разобранный сертификат
		x509::certificate_t certificate;
		// Если сертификат разобрать не удалось
		if(certificate.parse(view_t(der.data(), der.size())) != x509::error_t::NONE)
			// Сообщаем об отказе получения имени
			return false;
		// Выводим итог получения имени владельца
		return (x509::text(certificate.subjects(), result) == x509::error_t::NONE);
	}
	/**
	 * @brief Функция получения названия отказа доверия
	 *
	 * @param error отказ доверия
	 * @return      название отказа доверия
	 *
	 */
	const char * __nts_verify_name__(const trust::error_t error) noexcept {
		/**
		 * Подбираем название по значению отказа
		 */
		switch(static_cast <uint8_t> (error)){
			// Отказа нет
			case static_cast <uint8_t> (trust::error_t::NONE): return "ok";
			// Цепочка пуста
			case static_cast <uint8_t> (trust::error_t::EMPTY): return "empty chain";
			// Цепочка длиннее дозволенной
			case static_cast <uint8_t> (trust::error_t::DEPTH): return "chain too long";
			// Сертификат не разобран
			case static_cast <uint8_t> (trust::error_t::PARSE): return "bad certificate";
			// Срок не идёт
			case static_cast <uint8_t> (trust::error_t::EXPIRED): return "certificate expired";
			// Издатель разошёлся
			case static_cast <uint8_t> (trust::error_t::ISSUER): return "issuer mismatch";
			// Издавать не вправе
			case static_cast <uint8_t> (trust::error_t::CONSTRAINT): return "not a CA";
			// Подпись не сошлась
			case static_cast <uint8_t> (trust::error_t::SIGNATURE): return "signature mismatch";
			// Издателя в запасе нет
			case static_cast <uint8_t> (trust::error_t::AUTHORITY): return "unable to get issuer certificate";
			// Имя узла не сошлось
			case static_cast <uint8_t> (trust::error_t::NAME): return "hostname mismatch";
			// Памяти не хватило
			case static_cast <uint8_t> (trust::error_t::MEMORY): return "out of memory";
			// Неизвестное критичное расширение
			case static_cast <uint8_t> (trust::error_t::CRITICAL): return "unknown critical extension";
			// Назначение ключа не подходит
			case static_cast <uint8_t> (trust::error_t::PURPOSE): return "unsuitable key purpose";
			// Ограничения имён нарушены
			case static_cast <uint8_t> (trust::error_t::CONSTRAINED): return "name constraints violated";
			// Звено подписано слабым хешем либо ключом
			case static_cast <uint8_t> (trust::error_t::WEAK): return "weak signature";
			// Сертификат отозван
			case static_cast <uint8_t> (trust::error_t::REVOKED): return "certificate revoked";
			// Списка отзыва нет
			case static_cast <uint8_t> (trust::error_t::MISSING): return "revocation list missing";
			// Список отзыва просрочен
			case static_cast <uint8_t> (trust::error_t::OUTDATED): return "revocation list outdated";
			// Список отзыва подделан
			case static_cast <uint8_t> (trust::error_t::FORGED): return "revocation list forged";
		}
		// Выводим неизвестный отказ
		return "unknown";
	}
	/**
	 * @brief Функция установки пределов издания протокола по флагам командной строки
	 *
	 * @param argc    длина списка параметров
	 * @param argv    список параметров
	 * @param context связь, которой устанавливаются пределы
	 *
	 */
	template <typename Context>
	void __nts_versions__(const int argc, const char * const argv[], Context & context) noexcept {
		// Наименьшее издание: по умолчанию 1.2
		uint16_t lowest = 0x0303;
		// Наибольшее издание: по умолчанию 1.3
		uint16_t highest = 0x0304;
		// Если запрошено лишь издание 1.2
		if(cli::flag(argc, argv, "-tls1_2")){
			// Наибольшее издание — 1.2
			highest = 0x0303;
		}
		// Если запрошено лишь издание 1.3
		if(cli::flag(argc, argv, "-tls1_3")){
			// Наименьшее издание — 1.3
			lowest = 0x0304;
		}
		// Устанавливаем пределы издания связи
		(void) context.versions(lowest, highest);
	}
	/**
	 * @brief Функция вывода сведений о связи по завершении рукопожатия
	 *
	 * @param context связь стороны
	 * @param role    роль стороны: «клиент» либо «сервер»
	 * @param verify  проверялась ли цепочка собеседника
	 * @param code    итог проверки цепочки собеседника
	 *
	 */
	template <typename Context>
	void __nts_report__(Context & context, const char * role, const bool verify, const trust::error_t code) noexcept {
		// Выводим роль и издание связи
		cout << role << ": " << __nts_version_name__(context.version()) << ", набор " << __nts_suite_name__(context.suite()) << endl;
		// Цепочка сертификатов собеседника
		const vector <vector <uint8_t>> & chain = context.peer();
		// Имя владельца сертификата собеседника
		string subject;
		// Если цепочка непуста и имя владельца получено
		if(!chain.empty() && __nts_subject__(chain[0], subject))
			// Выводим имя владельца сертификата собеседника
			cout << "Сертификат          : " << subject << endl;
		// Если проверка доверия велась
		if(verify)
			// Выводим итог проверки доверия
			cout << "Verify return code  : " << static_cast <uint32_t> (code) << " (" << __nts_verify_name__(code) << ")" << endl;
	}
	/**
	 * @brief Функция установления пределов издания по флагам и проверки цепочки клиентом
	 *
	 * @param argc   длина списка параметров
	 * @param argv   список параметров
	 * @param client связь клиента
	 * @param name   имя узла, к которому идёт подключение
	 * @param verify велась ли проверка доверия
	 * @param store  запас доверенных сертификатов
	 * @return       код выхода: ноль при успехе, иначе отказ
	 *
	 */
	int __nts_verify__(client::context_t & client, const string & name, const bool verify, const trust::store_t & store) noexcept {
		// Если проверка не велась
		if(!verify)
			// Проверки нет, успех
			return EXIT_SUCCESS;
		// Цепочка сертификатов собеседника
		const vector <vector <uint8_t>> & chain = client.peer();
		// Миг проверки в секундах
		const int64_t moment = static_cast <int64_t> (::time(nullptr));
		// Проверяем цепочку запасом доверенных
		const trust::error_t chainCode = trust::verify(chain, store, moment, trust::role_t::SERVER);
		// Если цепочка не сошлась
		if(chainCode != trust::error_t::NONE)
			// Сообщаем об отказе проверки
			return static_cast <int> (chainCode);
		// Если имя узла ни одному имени сертификата не отвечает
		if(trust::belongs(view_t(chain[0].data(), chain[0].size()), name) != trust::error_t::NONE)
			// Сообщаем об отказе проверки имени
			return static_cast <int> (trust::error_t::NAME);
		// Сообщаем об успешности проверки
		return EXIT_SUCCESS;
	}
	/**
	 * @brief Функция разбора строки «узел:порт» подключения
	 *
	 * @param text разбираемая строка
	 * @param host место, в которое помещается имя узла
	 * @param port место, в которое помещается порт
	 * @return     признак успешности разбора
	 *
	 */
	bool __nts_split__(const string & text, string & host, string & port) noexcept {
		// Если строка пуста
		if(text.empty())
			// Сообщаем об отказе разбора
			return false;
		// Если узел записан в скобках как адрес IPv6
		if(text[0] == '['){
			// Конец адреса в скобках
			const size_t close = text.find(']');
			// Если закрывающей скобки нет
			if(close == string::npos)
				// Сообщаем об отказе разбора
				return false;
			// Запоминаем адрес узла
			host = text.substr(1, close - 1);
			// Если за скобкой нет двоеточия и порта
			if((close + 1 >= text.size()) || (text[close + 1] != ':'))
				// Сообщаем об отказе разбора
				return false;
			// Запоминаем порт
			port = text.substr(close + 2);
		// Иначе узел записан без скобок
		} else {
			// Место последнего двоеточия
			const size_t colon = text.rfind(':');
			// Если двоеточия нет либо порт пуст
			if((colon == string::npos) || (colon + 1 >= text.size()))
				// Сообщаем об отказе разбора
				return false;
			// Запоминаем имя узла
			host = text.substr(0, colon);
			// Запоминаем порт
			port = text.substr(colon + 1);
		}
		// Выводим итог разбора
		return (!host.empty() && !port.empty());
	}
	/**
	 * @brief Функция подключения сокета к узлу
	 *
	 * @param host   имя узла
	 * @param port   порт либо имя службы
	 * @param result место, в которое помещается описатель сокета
	 * @return       признак успешности подключения
	 *
	 */
	bool __nts_connect__(const string & host, const string & port, __nts_socket_t__ & result) noexcept {
		// Настройки разыскания адреса
		struct addrinfo hints;
		// Сбрасываем настройки разыскания
		::memset(&hints, 0, sizeof(hints));
		// Семейство адресов любое
		hints.ai_family = AF_UNSPEC;
		// Потоковый сокет
		hints.ai_socktype = SOCK_STREAM;
		// Список разысканных адресов
		struct addrinfo * list = nullptr;
		// Если адреса разыскать не удалось
		if(::getaddrinfo(host.c_str(), port.c_str(), &hints, &list) != 0)
			// Сообщаем об отказе подключения
			return false;
		// Признак успешности подключения
		bool ok = false;
		/**
		 * Перебираем разысканные адреса
		 */
		for(struct addrinfo * cur = list; cur != nullptr; cur = cur->ai_next){
			// Открываем сокет по адресу
			result = ::socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
			// Если сокет открыть не удалось
			if(result == __nts_socket_invalid__())
				// Переходим к следующему адресу
				continue;
			// Если подключение состоялось
			if(::connect(result, cur->ai_addr, static_cast <socklen_t> (cur->ai_addrlen)) == 0){
				// Отмечаем успешность подключения
				ok = true;
				// Прерываем перебор
				break;
			}
			// Закрываем сокет
			__nts_close__(result);
			// Помечаем сокет негодным
			result = __nts_socket_invalid__();
		}
		// Освобождаем список адресов
		::freeaddrinfo(list);
		// Выводим итог подключения
		return ok;
	}
	/**
	 * @brief Функция заведения слушающего сокета на порту
	 *
	 * @param port   порт либо имя службы
	 * @param result место, в которое помещается описатель сокета
	 * @return       признак успешности заведения слушателя
	 *
	 */
	bool __nts_listen__(const string & port, __nts_socket_t__ & result) noexcept {
		// Настройки разыскания адреса
		struct addrinfo hints;
		// Сбрасываем настройки разыскания
		::memset(&hints, 0, sizeof(hints));
		// Семейство адресов любое
		hints.ai_family = AF_UNSPEC;
		// Потоковый сокет
		hints.ai_socktype = SOCK_STREAM;
		// Адрес слушателя без узла
		hints.ai_flags = AI_PASSIVE;
		// Список разысканных адресов
		struct addrinfo * list = nullptr;
		// Если адреса разыскать не удалось
		if(::getaddrinfo(nullptr, port.c_str(), &hints, &list) != 0)
			// Сообщаем об отказе заведения слушателя
			return false;
		// Признак успешности заведения слушателя
		bool ok = false;
		/**
		 * Перебираем разысканные адреса
		 */
		for(struct addrinfo * cur = list; cur != nullptr; cur = cur->ai_next){
			// Открываем сокет по адресу
			result = ::socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
			// Если сокет открыть не удалось
			if(result == __nts_socket_invalid__())
				// Переходим к следующему адресу
				continue;
			// Признак повторного занятия адреса
			int reuse = 1;
			// Дозволяем повторное занятие адреса
			(void) ::setsockopt(result, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast <const char *> (&reuse), sizeof(reuse));
			// Если сокет привязать и перевести в слушание не удалось
			if((::bind(result, cur->ai_addr, static_cast <socklen_t> (cur->ai_addrlen)) != 0) || (::listen(result, SOMAXCONN) != 0)){
				// Закрываем сокет
				__nts_close__(result);
				// Помечаем сокет негодным
				result = __nts_socket_invalid__();
				// Переходим к следующему адресу
				continue;
			}
			// Отмечаем успешность заведения слушателя
			ok = true;
			// Прерываем перебор
			break;
		}
		// Освобождаем список адресов
		::freeaddrinfo(list);
		// Выводим итог заведения слушателя
		return ok;
	}
};

/**
 * @brief Функция ведения связи со стороны клиента
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::sClient(const int argc, const char * const argv[]) noexcept {
	// Строка подключения «узел:порт»
	const char * connect = cli::value(argc, argv, "-connect");
	// Если строки подключения нет
	if((connect == nullptr) || (connect[0] == '\0')){
		// Печатаем подсказку команды
		cout << "применение: a-nts s_client -connect узел:порт [-servername имя] [-cert файл -key файл] [-CAfile файл -verify] [-tls1_2|-tls1_3] [-quiet] [-ign_eof]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Имя узла подключения
	string host;
	// Порт подключения
	string port;
	// Если строку подключения разобрать не удалось
	if(!__nts_split__(connect, host, port)){
		// Печатаем сообщение об отказе разбора подключения
		cout << "Разобрать подключение «" << connect << "» не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Имя узла, запрашиваемое у сервера
	const char * servername = cli::value(argc, argv, "-servername");
	// Если имя узла не задано
	if((servername == nullptr) || (servername[0] == '\0'))
		// Имя узла берём из подключения
		servername = host.c_str();
	// Описатель сокета собеседника
	__nts_socket_t__ peer = __nts_socket_invalid__();
	// Если подключиться не удалось
	if(!__nts_connect__(host, port, peer)){
		// Печатаем сообщение об отказе подключения
		cout << "Подключиться к " << host << ":" << port << " не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Переводим ввод и вывод в двоичный вид
	__nts_binary__();
	// Связь стороны клиента
	client::context_t client;
	// Имя узла, запрашиваемое у сервера
	client.name(servername);
	// Устанавливаем пределы издания протокола
	__nts_versions__(argc, argv, client);
	// Подлинность стороны клиента
	context::credential_t credential;
	// Если заданы сертификат и ключ клиента
	if((cli::value(argc, argv, "-cert") != nullptr) && (cli::value(argc, argv, "-key") != nullptr)){
		// Если подлинность составить не удалось
		if(!__nts_identity__(cli::value(argc, argv, "-cert"), cli::value(argc, argv, "-key"), credential)){
			// Печатаем сообщение об отказе составления подлинности
			cout << "Составить подлинность клиента не удалось" << endl;
			// Закрываем сокет
			__nts_close__(peer);
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Устанавливаем подлинность клиента
		client.credential(credential);
	}
	// Запас доверенных сертификатов
	trust::store_t store;
	// Признак проверки доверия
	bool verify = false;
	// Файл доверенных сертификатов
	const char * caFile = cli::value(argc, argv, "-CAfile");
	// Если файл доверенных сертификатов задан
	if((caFile != nullptr) && (caFile[0] != '\0')){
		// Если запас наполнить не удалось
		if(!__nts_store__(caFile, store)){
			// Печатаем сообщение об отказе наполнения запаса
			cout << "Прочитать доверенные сертификаты не удалось" << endl;
			// Закрываем сокет
			__nts_close__(peer);
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Отмечаем, что доверие проверяется
		verify = true;
	}
	// Если рукопожатие пройти не удалось
	if(!__nts_handshake__(client, peer)){
		// Печатаем сообщение об отказе рукопожатия
		cout << "Рукопожатие не прошло: отказ " << static_cast <int> (client.error()) << ", извещение " << alert::name(client.alert().description) << endl;
		// Закрываем сокет
		__nts_close__(peer);
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Итог проверки доверия
	const trust::error_t code = static_cast <trust::error_t> (__nts_verify__(client, servername, verify, store));
	// Если итог не запрошен тишиной
	if(!cli::flag(argc, argv, "-quiet"))
		// Выводим сведения о связи
		__nts_report__(client, "CONNECTED", verify, code);
	// Если проверка доверия не прошла
	if(code != trust::error_t::NONE){
		// Закрываем связь
		(void) client.close();
		// Закрываем сокет
		__nts_close__(peer);
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Ретранслируем данные
	const int relay = __nts_relay__(client, peer, cli::flag(argc, argv, "-ign_eof"));
	// Закрываем сокет
	__nts_close__(peer);
	// Выводим код выхода ретрансляции
	return relay;
}

/**
 * @brief Функция ведения связи со стороны сервера
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::sServer(const int argc, const char * const argv[]) noexcept {
	// Порт приёма соединений
	const char * accept = cli::value(argc, argv, "-accept");
	// Если порта приёма нет
	if((accept == nullptr) || (accept[0] == '\0')){
		// Печатаем подсказку команды
		cout << "применение: a-nts s_server -accept порт -cert файл -key файл [-verify] [-tls1_2|-tls1_3] [-quiet]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Файлы сертификата и ключа сервера
	const char * cert = cli::value(argc, argv, "-cert");
	// Файл ключа сервера
	const char * key = cli::value(argc, argv, "-key");
	// Подлинность стороны сервера
	context::credential_t credential;
	// Если подлинность составить не удалось
	if(!__nts_identity__(cert, key, credential)){
		// Печатаем сообщение об отказе составления подлинности
		cout << "Составить подлинность сервера не удалось: задайте -cert и -key" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Описатель слушающего сокета
	__nts_socket_t__ listener = __nts_socket_invalid__();
	// Если слушателя завести не удалось
	if(!__nts_listen__(accept, listener)){
		// Печатаем сообщение об отказе заведения слушателя
		cout << "Завести слушателя на порту " << accept << " не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Переводим ввод и вывод в двоичный вид
	__nts_binary__();
	// Признак запроса подлинности клиента
	const bool request = cli::flag(argc, argv, "-verify");
	// Признак тишины вывода
	const bool quiet = cli::flag(argc, argv, "-quiet");
	/**
	 * Принимаем соединения одно за другим
	 */
	for(;;){
		// Описатель сокета собеседника
		const __nts_socket_t__ peer = ::accept(listener, nullptr, nullptr);
		// Если соединение принять не удалось
		if(peer == __nts_socket_invalid__()){
			// Печатаем сообщение об отказе приёма соединения
			cout << "Принять соединение не удалось" << endl;
			// Закрываем слушателя
			__nts_close__(listener);
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Устанавливаем пределы издания протокола
		__nts_versions__(argc, argv, server);
		// Если подлинность клиента запрашивается
		if(request)
			// Запрашиваем подлинность клиента
			server.request(true);
		// Если рукопожатие пройти не удалось
		if(!__nts_handshake__(server, peer)){
			// Печатаем сообщение об отказе рукопожатия
			cout << "Рукопожатие не прошло: отказ " << static_cast <int> (server.error()) << ", извещение " << alert::name(server.alert().description) << endl;
			// Закрываем сокет
			__nts_close__(peer);
			// Переходим к следующему соединению
			continue;
		}
		// Если итог не запрошен тишиной
		if(!quiet)
			// Выводим сведения о связи
			__nts_report__(server, "ACCEPT", false, trust::error_t::NONE);
		// Ретранслируем данные и запоминаем код выхода: сервер вводом не ведётся,
		// конец стандартного ввода его передачу не завершает (как у openssl s_server)
		const int code = __nts_relay__(server, peer, true);
		// Закрываем сокет
		__nts_close__(peer);
		// Если ретрансляция оборвана отказом
		if(code != EXIT_SUCCESS){
			// Закрываем слушателя
			__nts_close__(listener);
			// Сообщаем об отказе команды
			return code;
		}
	}
}
