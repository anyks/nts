/**
 * @file extension.hpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANTS-1.0}
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
 * @brief Заголовочный файл модуля расширений приветствий протокола TLS — разбор и
 *        составление тел расширений, которыми стороны договариваются об условиях связи
 *
 * \~english
 * @brief Header file of the module of the extensions of the greetings of the TLS protocol —
 *        the parsing and the composition of the bodies of the extensions, by which the parties
 *        agree upon the conditions of the connection
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_EXTENSION__
#define __ANTS_EXTENSION__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
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
	 * @brief Пространство имён расширений приветствий протокола TLS
	 *
	 * @details Раздел 4.2 RFC 8446: издание TLS 1.3 вынесло в расширения всё, чем оно
	 *          отличается от предыдущих изданий, - и выбор издания, и обмен ключами, и
	 *          схемы подписи. Тело всякого расширения разбирается по своему разделу и от
	 *          тел остальных не зависит.
	 *
	 * @note Одно и то же расширение у клиента и у сервера сложено по-разному: клиент
	 *       предлагает перечень, сервер выбирает из него одно. Оттого у таких расширений
	 *       здесь по два разборщика, а не один
	 *
	 * \~english
	 * @brief Namespace of the extensions of the greetings of the TLS protocol
	 * @details The section 4.2 of RFC 8446: the TLS 1.3 edition has moved into the extensions
	 *          everything by which it differs from the previous editions — the choice of the edition,
	 *          the exchange of the keys and the signature schemes. The body of every extension is
	 *          parsed by its own section and does not depend on the bodies of the rest.
	 * @note One and the same extension is composed differently at the client and at the server: the
	 *       client offers a list, the server chooses one from it. Hence such extensions have two
	 *       parsers here and not one
	 *
	 * \~
	 */
	namespace extension {
		/**
		 * \~russian
		 * @brief Виды расширений приветствий
		 *
		 * @details Раздел 4.2 RFC 8446: перечисление ExtensionType
		 *
		 * \~english
		 * @brief Types of the extensions of the greetings
		 * @details The section 4.2 of RFC 8446: the ExtensionType enumeration
		 *
		 * \~
		 */
		enum class type_t : uint16_t {
			NAME      = 0x0000, /*!< \~russian Имя запрашиваемого узла \~english The name of the requested host \~ */
			GROUPS    = 0x000A, /*!< \~russian Поддерживаемые группы обмена ключами \~english The supported groups of the exchange of the keys \~ */
			SCHEMES   = 0x000D, /*!< \~russian Поддерживаемые схемы подписи \~english The supported signature schemes \~ */
			PROTOCOLS = 0x0010, /*!< \~russian Перечень прикладных протоколов связи \~english The list of the application protocols of a connection \~ */
			SECRET    = 0x0029, /*!< \~russian Заранее разделённый ключ \~english The pre-shared key \~ */
			EARLY     = 0x002A, /*!< \~russian Упреждающие данные связи \~english The early data of a connection \~ */
			COOKIE    = 0x002C, /*!< \~russian Метка возврата состояния сервера \~english The label of the return of the state of the server \~ */
			VERSIONS  = 0x002B, /*!< \~russian Поддерживаемые издания протокола \~english The supported editions of the protocol \~ */
			MODES     = 0x002D, /*!< \~russian Способы обмена с заранее разделённым ключом \~english The modes of the exchange with a pre-shared key \~ */
			SHARE     = 0x0033  /*!< \~russian Открытая часть ключа обмена \~english The public part of the key of the exchange \~ */
		};

		/**
		 * \~russian
		 * @brief Группы обмена ключами
		 *
		 * @details Раздел 6.1 описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ:
		 *          перечисление NamedGroup
		 *
		 * \~english
		 * @brief Groups of the exchange of the keys
		 * @details The section 6.1 of the description of the cipher suites of TLS 1.3 on the GOST
		 *          algorithms: the NamedGroup enumeration
		 *
		 * \~
		 */
		enum class group_t : uint16_t {
			NONE   = 0x0000, /*!< \~russian Группа обмена ключами не установлена \~english The group of the exchange of the keys is not set \~ */
			GC256A = 0x0022, /*!< \~russian Кривая набора параметров A длиной 256 разрядов \~english The curve of the parameter set A of a length of 256 bits \~ */
			GC256B = 0x0023, /*!< \~russian Кривая набора параметров A издания 2001 года \~english The curve of the parameter set A of the 2001 edition \~ */
			GC256C = 0x0024, /*!< \~russian Кривая набора параметров B издания 2001 года \~english The curve of the parameter set B of the 2001 edition \~ */
			GC256D = 0x0025, /*!< \~russian Кривая набора параметров C издания 2001 года \~english The curve of the parameter set C of the 2001 edition \~ */
			GC512A = 0x0026, /*!< \~russian Кривая набора параметров A длиной 512 разрядов \~english The curve of the parameter set A of a length of 512 bits \~ */
			GC512B = 0x0027, /*!< \~russian Кривая набора параметров B длиной 512 разрядов \~english The curve of the parameter set B of a length of 512 bits \~ */
			GC512C = 0x0028  /*!< \~russian Кривая набора параметров C длиной 512 разрядов \~english The curve of the parameter set C of a length of 512 bits \~ */
		};

		/**
		 * \~russian
		 * @brief Схемы подписи
		 *
		 * @details Раздел 5 описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ:
		 *          перечисление SignatureScheme
		 *
		 * \~english
		 * @brief Signature schemes
		 * @details The section 5 of the description of the cipher suites of TLS 1.3 on the GOST
		 *          algorithms: the SignatureScheme enumeration
		 *
		 * \~
		 */
		enum class scheme_t : uint16_t {
			NONE = 0x0000, /*!< \~russian Схема подписи не установлена \~english The signature scheme is not set \~ */
			S256A = 0x0709, /*!< \~russian Подпись на кривой GC256A \~english The signature on the GC256A curve \~ */
			S256B = 0x070A, /*!< \~russian Подпись на кривой GC256B \~english The signature on the GC256B curve \~ */
			S256C = 0x070B, /*!< \~russian Подпись на кривой GC256C \~english The signature on the GC256C curve \~ */
			S256D = 0x070C, /*!< \~russian Подпись на кривой GC256D \~english The signature on the GC256D curve \~ */
			S512A = 0x070D, /*!< \~russian Подпись на кривой GC512A \~english The signature on the GC512A curve \~ */
			S512B = 0x070E, /*!< \~russian Подпись на кривой GC512B \~english The signature on the GC512B curve \~ */
			S512C = 0x070F  /*!< \~russian Подпись на кривой GC512C \~english The signature on the GC512C curve \~ */
		};

		/**
		 * \~russian
		 * @brief Способы обмена с заранее разделённым ключом
		 *
		 * @details Раздел 4.2.9 RFC 8446: перечисление PskKeyExchangeMode
		 *
		 * \~english
		 * @brief Modes of the exchange with a pre-shared key
		 * @details The section 4.2.9 of RFC 8446: the PskKeyExchangeMode enumeration
		 *
		 * \~
		 */
		enum class mode_t : uint8_t {
			SECRET = 0x00, /*!< \~russian Обмен одним заранее разделённым ключом \~english The exchange by a pre-shared key alone \~ */
			SHARED = 0x01  /*!< \~russian Обмен заранее разделённым ключом вместе с ключом кривой \~english The exchange by a pre-shared key together with a key of a curve \~ */
		};

		/**
		 * \~russian
		 * @brief Отказы разбора и составления тел расширений
		 *
		 * \~english
		 * @brief Failures of the parsing and of the composition of the bodies of the extensions
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY   = 0x01, /*!< \~russian Тело расширения оборвано посреди поля \~english The body of the extension is cut off in the middle of a field \~ */
			EMPTY    = 0x02, /*!< \~russian Перечень тела расширения пуст \~english The list of the body of the extension is empty \~ */
			TRAILING = 0x03, /*!< \~russian За телом расширения идут лишние байты \~english There are extra bytes behind the body of the extension \~ */
			LENGTH   = 0x04, /*!< \~russian Составляемое поле в свою длину не входит \~english A field being composed does not fit into its length \~ */
			MEMORY   = 0x05  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Открытая часть ключа обмена одной группы
		 *
		 * @details Раздел 4.2.8 RFC 8446: запись KeyShareEntry
		 *
		 * @note Открытая часть ключа смотрит внутрь разобранного тела расширения
		 *
		 * \~english
		 * @brief Public part of the key of the exchange of a single group
		 * @details The section 4.2.8 of RFC 8446: the KeyShareEntry record
		 * @note The public part of the key looks inside the parsed body of the extension
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Share {
			// Группа обмена ключами, которой принадлежит открытая часть ключа
			group_t group;
			// Открытая часть ключа обмена
			view_t key;
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
			Share() noexcept : group(group_t::NONE) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param group группа обмена ключами
			 * @param key   открытая часть ключа обмена
			 *
			 * \~english
			 * @brief Constructor
			 * @param group the group of the exchange of the keys
			 * @param key   the public part of the key of the exchange
			 *
			 * \~
			 */
			Share(const group_t group, const view_t & key) noexcept : group(group), key(key) {}
		} share_t;

		/**
		 * \~russian
		 * @brief Опознаватель заранее разделённого ключа
		 *
		 * @details Раздел 4.2.11 RFC 8446: опознавателем ключа клиент предъявляет билет,
		 *          выданный сервером прошлой связи, а добавка к возрасту скрывает от
		 *          посторонних, давно ли билет выдан
		 *
		 * @note Опознаватель смотрит внутрь разобранного тела расширения
		 *
		 * \~english
		 * @brief Identifier of a pre-shared key
		 * @details The section 4.2.11 of RFC 8446: by the identifier of a key the client presents the
		 *          ticket issued by the server of a past connection, and the addition to the age hides
		 *          from the outsiders how long ago the ticket was issued
		 * @note The identifier looks inside the parsed body of the extension
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Identity {
			// Опознаватель заранее разделённого ключа
			view_t identity;
			// Скрытый возраст билета, выдавшего ключ
			uint32_t age;
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
			Identity() noexcept : age(0) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param identity опознаватель заранее разделённого ключа
			 * @param age      скрытый возраст билета, выдавшего ключ
			 *
			 * \~english
			 * @brief Constructor
			 * @param identity the identifier of the pre-shared key
			 * @param age      the hidden age of the ticket which issued the key
			 *
			 * \~
			 */
			Identity(const view_t & identity, const uint32_t age) noexcept : identity(identity), age(age) {}
		} identity_t;

		/**
		 * \~russian
		 * @brief Метод получения опознавателя кривой группы обмена ключами
		 *
		 * @param group группа обмена ключами
		 *
		 * @return      опознаватель кривой набора параметров либо nullptr
		 *
		 * @details Раздел 6.1 описания наборов: всякая группа обмена ключами есть кривая, и
		 *          опознаватель её набора параметров тот же, что и в сертификатах
		 *
		 * \~english
		 * @brief Method of getting the identifier of the curve of a group of the exchange of the keys
		 * @param group the group of the exchange of the keys
		 * @return      the identifier of the curve of the parameter set or nullptr
		 * @details The section 6.1 of the description of the suites: every group of the exchange of the
		 *          keys is a curve, and the identifier of its parameter set is the same as in the
		 *          certificates
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * curve(const group_t group) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения опознавателя кривой схемы подписи
		 *
		 * @param scheme схема подписи
		 *
		 * @return       опознаватель кривой набора параметров либо nullptr
		 *
		 * @details Раздел 5.2 описания наборов: схема подписи задаёт кривую наравне с
		 *          алгоритмом подписи
		 *
		 * \~english
		 * @brief Method of getting the identifier of the curve of a signature scheme
		 * @param scheme the signature scheme
		 * @return       the identifier of the curve of the parameter set or nullptr
		 * @details The section 5.2 of the description of the suites: a signature scheme sets the curve
		 *          on a par with the algorithm of the signature
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * curve(const scheme_t scheme) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины ключа схемы подписи
		 *
		 * @param scheme схема подписи
		 *
		 * @return       длина ключа подписи в байтах, ноль у неизвестной схемы
		 *
		 * \~english
		 * @brief Method of getting the length of the key of a signature scheme
		 * @param scheme the signature scheme
		 * @return       the length of the key of the signature in bytes, a zero at an unknown scheme
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const scheme_t scheme) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых изданий протокола
		 *
		 * @param data   разбираемое тело расширения приветствия клиента
		 * @param result перечень, в который помещаются поддерживаемые издания протокола
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.1 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported editions of the protocol
		 * @param data   the body of the extension of the greeting of the client being parsed
		 * @param result the list the supported editions of the protocol are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.1 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t versions(const view_t & data, vector <uint16_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых изданий протокола
		 *
		 * @param versions составляемый перечень поддерживаемых изданий протокола
		 * @param result   накопитель, в конец которого дописывается тело расширения
		 *
		 * @return         отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported editions of the protocol
		 * @param versions the list of the supported editions of the protocol being composed
		 * @param result   the accumulator the body of the extension is appended to the end of
		 * @return         the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t versions(const vector <uint16_t> & versions, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного издания протокола
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result число, в которое помещается выбранное издание протокола
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.1 RFC 8446: сервер отвечает единственным изданием без перечня
		 *
		 * \~english
		 * @brief Method of the parsing of the chosen edition of the protocol
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the number the chosen edition of the protocol is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.1 of RFC 8446: the server answers with a single edition without a list
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t version(const view_t & data, uint16_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного издания протокола
		 *
		 * @param version составляемое выбранное издание протокола
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the chosen edition of the protocol
		 * @param version the chosen edition of the protocol being composed
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t version(const uint16_t version, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых групп обмена ключами
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются поддерживаемые группы
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.7 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported groups of the exchange of the keys
		 * @param data   the body of the extension being parsed
		 * @param result the list the supported groups are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.7 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t groups(const view_t & data, vector <group_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых групп обмена ключами
		 *
		 * @param groups составляемый перечень поддерживаемых групп
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported groups of the exchange of the keys
		 * @param groups the list of the supported groups being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t groups(const vector <group_t> & groups, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых схем подписи
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются поддерживаемые схемы подписи
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.3 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported signature schemes
		 * @param data   the body of the extension being parsed
		 * @param result the list the supported signature schemes are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.3 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t schemes(const view_t & data, vector <scheme_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых схем подписи
		 *
		 * @param schemes составляемый перечень поддерживаемых схем подписи
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported signature schemes
		 * @param schemes the list of the supported signature schemes being composed
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t schemes(const vector <scheme_t> & schemes, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня открытых частей ключей обмена
		 *
		 * @param data   разбираемое тело расширения приветствия клиента
		 * @param result перечень, в который помещаются открытые части ключей обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: клиент вправе предложить открытые части ключей
		 *          сразу нескольких групп, а вправе не предложить ни одной
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the public parts of the keys of the exchange
		 * @param data   the body of the extension of the greeting of the client being parsed
		 * @param result the list the public parts of the keys of the exchange are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: the client may offer the public parts of the keys of
		 *          several groups at once, and may offer none at all
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t shares(const view_t & data, vector <share_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня открытых частей ключей обмена
		 *
		 * @param shares составляемый перечень открытых частей ключей обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the public parts of the keys of the exchange
		 * @param shares the list of the public parts of the keys of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t shares(const vector <share_t> & shares, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора открытой части ключа обмена сервера
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result запись, в которую помещается открытая часть ключа обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: сервер отвечает единственной открытой частью ключа
		 *          без перечня
		 *
		 * \~english
		 * @brief Method of the parsing of the public part of the key of the exchange of the server
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the record the public part of the key of the exchange is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: the server answers with a single public part of a key
		 *          without a list
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t share(const view_t & data, share_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления открытой части ключа обмена сервера
		 *
		 * @param share  составляемая открытая часть ключа обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the public part of the key of the exchange of the server
		 * @param share  the public part of the key of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t share(const share_t & share, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранной сервером группы обмена ключами
		 *
		 * @param data   разбираемое тело расширения просьбы о повторе приветствия
		 * @param result группа, в которую помещается выбранная сервером группа обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: просьбой о повторе приветствия сервер называет ту
		 *          группу, открытой части ключа которой он от клиента не дождался
		 *
		 * \~english
		 * @brief Method of the parsing of the group of the exchange of the keys chosen by the server
		 * @param data   the body of the extension of the request of a repetition of the greeting being parsed
		 * @param result the group the group of the exchange chosen by the server is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: by a request of a repetition of the greeting the server
		 *          names the group the public part of the key of which it did not receive from the client
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t selected(const view_t & data, group_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранной сервером группы обмена ключами
		 *
		 * @param group  составляемая выбранная группа обмена ключами
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the group of the exchange of the keys chosen by the server
		 * @param group  the chosen group of the exchange of the keys being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t selected(const group_t group, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня способов обмена с заранее разделённым ключом
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются способы обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.9 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the modes of the exchange with a pre-shared key
		 * @param data   the body of the extension being parsed
		 * @param result the list the modes of the exchange are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.9 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t modes(const view_t & data, vector <mode_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня способов обмена с заранее разделённым ключом
		 *
		 * @param modes  составляемый перечень способов обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the modes of the exchange with a pre-shared key
		 * @param modes  the list of the modes of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t modes(const vector <mode_t> & modes, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора метки возврата состояния сервера
		 *
		 * @param data   разбираемое тело расширения
		 * @param result просмотр, в который помещается метка возврата состояния
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.2 RFC 8446: меткой сервер возвращает себе своё состояние, не
		 *          храня его у себя между приветствиями
		 *
		 * \~english
		 * @brief Method of the parsing of the label of the return of the state of the server
		 * @param data   the body of the extension being parsed
		 * @param result the view the label of the return of the state is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.2 of RFC 8446: by the label the server returns its state to itself
		 *          without storing it at itself between the greetings
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t cookie(const view_t & data, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления метки возврата состояния сервера
		 *
		 * @param cookie составляемая метка возврата состояния
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the label of the return of the state of the server
		 * @param cookie the label of the return of the state being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t cookie(const view_t & cookie, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора имени запрашиваемого узла
		 *
		 * @param data   разбираемое тело расширения
		 * @param result просмотр, в который помещается имя запрашиваемого узла
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3 RFC 6066: перечень имён узлов, из которого протокол дозволяет
		 *          лишь имя вида «host_name», и лишь одно
		 *
		 * \~english
		 * @brief Method of the parsing of the name of the requested host
		 * @param data   the body of the extension being parsed
		 * @param result the view the name of the requested host is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3 of RFC 6066: a list of the names of the hosts, of which the protocol
		 *          allows only a name of the «host_name» kind, and only one
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t name(const view_t & data, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления имени запрашиваемого узла
		 *
		 * @param name   составляемое имя запрашиваемого узла
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the name of the requested host
		 * @param name   the name of the requested host being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t name(const view_t & name, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня прикладных протоколов
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются названия прикладных протоколов
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3.1 RFC 7301: перечень названий прикладных протоколов, идущий от
		 *          более желаемого протокола к менее желаемому
		 *
		 * @note Пустое название протокола разделом 3.1 RFC 7301 запрещено и даёт отказ
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the application protocols
		 * @param data   the body of the extension being parsed
		 * @param result the list the names of the application protocols are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3.1 of RFC 7301: a list of the names of the application protocols going
		 *          from a more desired protocol to a less desired one
		 * @note An empty name of a protocol is forbidden by the section 3.1 of RFC 7301 and gives a failure
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocols(const view_t & data, vector <string> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня прикладных протоколов
		 *
		 * @param protocols составляемый перечень названий прикладных протоколов
		 * @param result    накопитель, в конец которого дописывается тело расширения
		 *
		 * @return          отказ составления тела расширения
		 *
		 * @note Порядок перечня значим: он объявляет предпочтение стороны связи
		 *
		 * \~english
		 * @brief Method of the composition of the list of the application protocols
		 * @param protocols the list of the names of the application protocols being composed
		 * @param result    the accumulator the body of the extension is appended to the end of
		 * @return          the failure of the composition of the body of the extension
		 * @note The order of the list is significant: it declares the preference of the side of the connection
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocols(const vector <string> & protocols, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного прикладного протокола
		 *
		 * @param data   разбираемое тело расширения
		 * @param result название, в которое помещается выбранный прикладной протокол
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3.1 RFC 7301: сервер отвечает тем же перечнем, но кладёт в него
		 *          ровно один протокол — тот, которым связь и пойдёт
		 *
		 * \~english
		 * @brief Method of the parsing of the chosen application protocol
		 * @param data   the body of the extension being parsed
		 * @param result the name the chosen application protocol is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3.1 of RFC 7301: the server answers by the same list but puts exactly
		 *          one protocol into it — the one the connection will go by
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocol(const view_t & data, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного прикладного протокола
		 *
		 * @param protocol составляемое название выбранного прикладного протокола
		 * @param result   накопитель, в конец которого дописывается тело расширения
		 *
		 * @return         отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the chosen application protocol
		 * @param protocol the name of the chosen application protocol being composed
		 * @param result   the accumulator the body of the extension is appended to the end of
		 * @return         the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocol(const string & protocol, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора предложения заранее разделённых ключей
		 *
		 * @param data       разбираемое тело расширения приветствия клиента
		 * @param result     перечень, в который помещаются опознаватели ключей
		 * @param binders    перечень, в который помещаются привязки ключей
		 * @param truncation место, в которое помещается длина приветствия без привязок
		 *
		 * @return           отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.11.2 RFC 8446: привязка всякого ключа берётся от приветствия,
		 *          усечённого перед перечнем привязок, и длина этого усечения выводится здесь
		 *          же - иначе её пришлось бы искать разбором приветствия заново
		 *
		 * @note Длина усечения выводится от начала разбираемого тела расширения: чтобы
		 *       получить её от начала сообщения, к ней прибавляется место тела в сообщении
		 *
		 * \~english
		 * @brief Method of the parsing of an offer of the pre-shared keys
		 * @param data       the body of the extension of the greeting of the client being parsed
		 * @param result     the list the identifiers of the keys are put into
		 * @param binders    the list the binders of the keys are put into
		 * @param truncation the place the length of the greeting without the binders is put into
		 * @return           the failure of the parsing of the body of the extension
		 * @details The section 4.2.11.2 of RFC 8446: the binder of every key is taken from the greeting
		 *          truncated before the list of the binders, and the length of this truncation is output
		 *          here as well — otherwise it would have to be searched for by parsing the greeting anew
		 * @note The length of the truncation is output from the beginning of the parsed body of the
		 *       extension: to get it from the beginning of the message the place of the body in the
		 *       message is added to it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t identities(const view_t & data, vector <identity_t> & result, vector <view_t> & binders, size_t & truncation) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления предложения заранее разделённых ключей
		 *
		 * @param identities составляемый перечень опознавателей ключей
		 * @param binders    составляемый перечень привязок ключей
		 * @param result     накопитель, в конец которого дописывается тело расширения
		 *
		 * @return           отказ составления тела расширения
		 *
		 * @note Число привязок обязано совпадать с числом опознавателей: всякому ключу
		 *       отвечает своя привязка, и разошедшиеся перечни сервер отвергнет
		 *
		 * \~english
		 * @brief Method of the composition of an offer of the pre-shared keys
		 * @param identities the list of the identifiers of the keys being composed
		 * @param binders    the list of the binders of the keys being composed
		 * @param result     the accumulator the body of the extension is appended to the end of
		 * @return           the failure of the composition of the body of the extension
		 * @note The number of the binders is obliged to coincide with the number of the identifiers: every
		 *       key corresponds to its own binder, and the server will reject the diverged lists
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t identities(const vector <identity_t> & identities, const vector <view_t> & binders, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного сервером заранее разделённого ключа
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result место, в которое помещается место выбранного ключа в предложении
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * \~english
		 * @brief Method of the parsing of the pre-shared key chosen by the server
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the place the position of the chosen key in the offer is put into
		 * @return       the failure of the parsing of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t chosen(const view_t & data, uint16_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного сервером заранее разделённого ключа
		 *
		 * @param chosen место выбранного ключа в предложении клиента
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the pre-shared key chosen by the server
		 * @param chosen the position of the chosen key in the offer of the client
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t chosen(const uint16_t chosen, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора предела упреждающих данных билета
		 *
		 * @param data   разбираемое тело расширения билета возобновления связи
		 * @param result место, в которое помещается предел упреждающих данных в байтах
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.10 RFC 8446: пределом сервер объявляет, сколько упреждающих
		 *          данных он примет по этому билету. В приветствии же и в защищённых
		 *          расширениях тело этого расширения пусто.
		 *
		 * \~english
		 * @brief Method of the parsing of the limit of the early data of a ticket
		 * @param data   the body of the extension of the ticket of the resumption being parsed
		 * @param result the place the limit of the early data in bytes is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.10 of RFC 8446: by the limit the server declares how much early data it
		 *          will accept by this ticket. In a greeting and in the encrypted extensions the body of this
		 *          extension is empty.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t early(const view_t & data, uint32_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления предела упреждающих данных билета
		 *
		 * @param limit  объявляемый предел упреждающих данных в байтах
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the limit of the early data of a ticket
		 * @param limit  the limit of the early data in bytes being declared
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t early(const uint32_t limit, vector <uint8_t> & result) noexcept;
	};
};

#endif // __ANTS_EXTENSION__
