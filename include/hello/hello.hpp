/**
 * @file hello.hpp
 * @date 2026-08-29
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
 * \~russian
 * @brief Заголовочный файл модуля приветствий рукопожатия протокола TLS — разбор и
 *        составление тел сообщений приветствия клиента и приветствия сервера
 *
 * \~english
 * @brief Header file of the module of the greetings of the handshake of the TLS protocol — the
 *        parsing and the composition of the bodies of the messages of the greeting of the client
 *        and of the greeting of the server
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_HELLO__
#define __ANTS_HELLO__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace anyks {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён приветствий рукопожатия протокола TLS
	 *
	 * @details Разделы 4.1.2 и 4.1.3 RFC 8446: приветствиями стороны объявляют друг другу
	 *          свои возможности, а всё, чем издание TLS 1.3 отличается от предыдущих, вынесено
	 *          в расширения. Поля приветствий, доставшиеся от предыдущих изданий, здесь
	 *          разбираются, но истолковываются лишь настолько, насколько того требует протокол.
	 *
	 * @note Расширения разбираются лишь до вида и тела: тела расширений разбираются
	 *       разборщиками своего вида, каждым по своему разделу
	 *
	 * \~english
	 * @brief Namespace of the greetings of the handshake of the TLS protocol
	 * @details The sections 4.1.2 and 4.1.3 of RFC 8446: by the greetings the parties announce their
	 *          capabilities to each other, while everything by which the TLS 1.3 edition differs from
	 *          the previous ones is moved into the extensions. The fields of the greetings inherited
	 *          from the previous editions are parsed here, but are interpreted only as much as the
	 *          protocol requires it.
	 * @note The extensions are parsed only down to the type and the body: the bodies of the extensions
	 *       are parsed by the parsers of their type, each by its own section
	 *
	 * \~
	 */
	namespace hello {
		/**
		 * \~russian
		 * @brief Длина случайного значения приветствия в байтах
		 *
		 * \~english
		 * @brief Length of the random value of a greeting in bytes
		 *
		 * \~
		 */
		static constexpr size_t HELLO_RANDOM = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина опознавателя связи приветствия в байтах
		 *
		 * @details Раздел 4.1.2 RFC 8446: опознаватель достался от предыдущих изданий и в
		 *          издании TLS 1.3 своего назначения не имеет, но длину его протокол ограничивает
		 *
		 * \~english
		 * @brief Greatest length of the identifier of a connection of a greeting in bytes
		 * @details The section 4.1.2 of RFC 8446: the identifier is inherited from the previous editions
		 *          and has no purpose of its own in the TLS 1.3 edition, but the protocol limits its length
		 *
		 * \~
		 */
		static constexpr size_t HELLO_SESSION = 32;

		/**
		 * \~russian
		 * @brief Отказы разбора и составления приветствий
		 *
		 * \~english
		 * @brief Failures of the parsing and of the composition of the greetings
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY    = 0x01, /*!< \~russian Тело приветствия оборвано посреди поля \~english The body of the greeting is cut off in the middle of a field \~ */
			SESSION   = 0x02, /*!< \~russian Опознаватель связи длиннее дозволенного \~english The identifier of the connection is longer than allowed \~ */
			SUITE     = 0x03, /*!< \~russian Перечень наборов шифрования пуст либо оборван \~english The list of the cipher suites is empty or is cut off \~ */
			METHOD    = 0x04, /*!< \~russian Перечень способов сжатия пуст \~english The list of the methods of the compression is empty \~ */
			EXTENSION = 0x05, /*!< \~russian Расширение оборвано либо объявлено дважды \~english An extension is cut off or is declared twice \~ */
			TRAILING  = 0x06, /*!< \~russian За телом приветствия идут лишние байты \~english There are extra bytes behind the body of the greeting \~ */
			LENGTH    = 0x07, /*!< \~russian Составляемое поле в свою длину не входит \~english A field being composed does not fit into its length \~ */
			MEMORY    = 0x08  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Расширение приветствия рукопожатия
		 *
		 * @note Тело расширения смотрит внутрь разобранного приветствия и живёт ровно
		 *       столько, сколько живёт разобранная область байтов
		 *
		 * \~english
		 * @brief Extension of a greeting of the handshake
		 * @note The body of an extension looks inside the parsed greeting and lives exactly as long as
		 *       the parsed byte area lives
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Extension {
			// Вид расширения приветствия
			uint16_t type;
			// Тело расширения приветствия
			view_t data;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Extension() noexcept : type(0) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param type вид расширения приветствия
			 * @param data тело расширения приветствия
			 *
			 * \~english
			 * @brief Constructor
			 * @param type the type of the extension of the greeting
			 * @param data the body of the extension of the greeting
			 *
			 * \~
			 */
			Extension(const uint16_t type, const view_t & data) noexcept : type(type), data(data) {}
		} extension_t;

		/**
		 * \~russian
		 * @brief Приветствие клиента
		 *
		 * @details Раздел 4.1.2 RFC 8446
		 *
		 * \~english
		 * @brief Greeting of the client
		 * @details The section 4.1.2 of RFC 8446
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Client {
			// Версия протокола, доставшаяся от предыдущих изданий
			uint16_t version;
			// Случайное значение приветствия
			uint8_t random[HELLO_RANDOM];
			// Опознаватель связи, доставшийся от предыдущих изданий
			vector <uint8_t> session;
			// Перечень предлагаемых наборов шифрования
			vector <uint16_t> suites;
			// Перечень способов сжатия, доставшийся от предыдущих изданий
			vector <uint8_t> methods;
			// Перечень расширений приветствия
			vector <extension_t> extensions;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Client() noexcept;
		} client_t;

		/**
		 * \~russian
		 * @brief Приветствие сервера
		 *
		 * @details Раздел 4.1.3 RFC 8446
		 *
		 * \~english
		 * @brief Greeting of the server
		 * @details The section 4.1.3 of RFC 8446
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Server {
			// Версия протокола, доставшаяся от предыдущих изданий
			uint16_t version;
			// Случайное значение приветствия
			uint8_t random[HELLO_RANDOM];
			// Опознаватель связи, повторённый за приветствием клиента
			vector <uint8_t> session;
			// Выбранный сервером набор шифрования
			uint16_t suite;
			// Выбранный способ сжатия, доставшийся от предыдущих изданий
			uint8_t method;
			// Перечень расширений приветствия
			vector <extension_t> extensions;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Server() noexcept;
		} server_t;

		/**
		 * \~russian
		 * @brief Метод поиска расширения приветствия по его виду
		 *
		 * @param extensions перечень расширений приветствия
		 * @param type       разыскиваемый вид расширения
		 *
		 * @return           найденное расширение либо nullptr
		 *
		 * \~english
		 * @brief Method of the search of an extension of a greeting by its type
		 * @param extensions the list of the extensions of the greeting
		 * @param type       the type of the extension being searched for
		 * @return           the found extension or nullptr
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const extension_t * extension(const vector <extension_t> & extensions, const uint16_t type) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки того, что приветствие сервера есть просьба о повторе
		 *
		 * @param hello проверяемое приветствие сервера
		 *
		 * @return      признак того, что сервер просит повторить приветствие клиента
		 *
		 * @details Раздел 4.1.3 RFC 8446: просьба о повторе приветствия передаётся тем же
		 *          сообщением, что и само приветствие сервера, и отличается лишь заранее
		 *          назначенным случайным значением
		 *
		 * \~english
		 * @brief Method of checking that a greeting of the server is a request of a repetition
		 * @param hello the greeting of the server being checked
		 * @return      the flag of the server asking to repeat the greeting of the client
		 * @details The section 4.1.3 of RFC 8446: the request of a repetition of the greeting is
		 *          transmitted by the same message as the greeting of the server itself and differs only
		 *          by the beforehand appointed random value
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool retry(const server_t & hello) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела приветствия клиента
		 *
		 * @param data   разбираемое тело приветствия клиента
		 * @param result приветствие, в которое помещается итог разбора
		 *
		 * @return       отказ разбора приветствия клиента
		 *
		 * @note Тела расширений смотрят внутрь разбираемой области байтов
		 *
		 * \~english
		 * @brief Method of the parsing of the body of a greeting of the client
		 * @param data   the body of the greeting of the client being parsed
		 * @param result the greeting the outcome of the parsing is put into
		 * @return       the failure of the parsing of the greeting of the client
		 * @note The bodies of the extensions look inside the byte area being parsed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, client_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела приветствия сервера
		 *
		 * @param data   разбираемое тело приветствия сервера
		 * @param result приветствие, в которое помещается итог разбора
		 *
		 * @return       отказ разбора приветствия сервера
		 *
		 * @note Тела расширений смотрят внутрь разбираемой области байтов
		 *
		 * \~english
		 * @brief Method of the parsing of the body of a greeting of the server
		 * @param data   the body of the greeting of the server being parsed
		 * @param result the greeting the outcome of the parsing is put into
		 * @return       the failure of the parsing of the greeting of the server
		 * @note The bodies of the extensions look inside the byte area being parsed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, server_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела приветствия клиента
		 *
		 * @param hello  составляемое приветствие клиента
		 * @param result накопитель, в конец которого дописывается тело приветствия
		 *
		 * @return       отказ составления приветствия клиента
		 *
		 * \~english
		 * @brief Method of the composition of the body of a greeting of the client
		 * @param hello  the greeting of the client being composed
		 * @param result the accumulator the body of the greeting is appended to the end of
		 * @return       the failure of the composition of the greeting of the client
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const client_t & hello, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела приветствия сервера
		 *
		 * @param hello  составляемое приветствие сервера
		 * @param result накопитель, в конец которого дописывается тело приветствия
		 *
		 * @return       отказ составления приветствия сервера
		 *
		 * \~english
		 * @brief Method of the composition of the body of a greeting of the server
		 * @param hello  the greeting of the server being composed
		 * @param result the accumulator the body of the greeting is appended to the end of
		 * @return       the failure of the composition of the greeting of the server
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const server_t & hello, vector <uint8_t> & result) noexcept;
	};
};

#endif // __ANTS_HELLO__
