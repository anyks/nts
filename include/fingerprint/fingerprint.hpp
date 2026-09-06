/**
 * @file fingerprint.hpp
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
 * \~russian
 * @brief Заголовочный файл модуля отпечатков клиента протокола TLS — разбор приветствия
 *        клиента в профиль, вычисление отпечатков JA3, JA4, PeetPrint и Akamai HTTP/2,
 *        печать, переносимый снимок профиля и хранилище профилей
 *
 * \~english
 * @brief Header file of the module of the fingerprints of a client of the TLS protocol — the
 *        parsing of a greeting of the client into a profile, the computation of the JA3, JA4,
 *        PeetPrint and Akamai HTTP/2 fingerprints, the printing, the portable snapshot of a
 *        profile and the store of the profiles
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_FINGERPRINT__
#define __ANTS_FINGERPRINT__

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
#include <protect/protect.hpp>
#include <extension/extension.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён отпечатков клиента протокола TLS
	 *
	 * @details Приветствие клиента разбирается в профиль: издания, наборы, способы сжатия
	 *          и расширения в порядке провода, с сырыми телами и разобранными перечнями.
	 *          Профиль служит двум делам: по нему считаются отпечатки принятого
	 *          приветствия (JA3, JA4, PeetPrint), и по нему же связь клиента складывает
	 *          своё приветствие «как есть» - тем же составом и порядком
	 *
	 * @note Ядро не ведёт ввода-вывода и не знает потоков: охрана хранилища от
	 *       одновременного доступа принадлежит тому, кто им пользуется
	 *
	 * @note Значения GREASE (RFC 8701) хранятся числами по проводу и отмечаются признаком:
	 *       для них нет отдельного кода, а место их в перечне - часть отпечатка
	 *
	 * \~english
	 * @brief Namespace of the fingerprints of a client of the TLS protocol
	 * @details A greeting of the client is parsed into a profile: the editions, the suites, the
	 *          compression methods and the extensions in the wire order, with raw bodies and parsed
	 *          lists. The profile serves two purposes: by it the fingerprints of an accepted greeting
	 *          are computed (JA3, JA4, PeetPrint), and by it a connection of the client composes its
	 *          own greeting «as is» - by the same composition and order
	 * @note The core leads no input-output and knows no threads: the guarding of the store against
	 *       a concurrent access belongs to the one who uses it
	 * @note The GREASE values (RFC 8701) are stored as wire numbers and are marked by a flag: there is
	 *       no separate code for them, and their place in a list is a part of the fingerprint
	 *
	 * \~
	 */
	namespace fingerprint {
		/**
		 * \~russian
		 * @brief Длина случайного значения приветствия в байтах
		 *
		 * \~english
		 * @brief Length of the random value of a greeting in bytes
		 *
		 * \~
		 */
		static constexpr size_t FINGERPRINT_RANDOM = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина опознавателя связи приветствия в байтах
		 *
		 * \~english
		 * @brief Greatest length of the identifier of a connection of a greeting in bytes
		 *
		 * \~
		 */
		static constexpr size_t FINGERPRINT_SESSION = 32;

		/**
		 * \~russian
		 * @brief Издание записи снимка профиля
		 *
		 * @details Снимок несёт поле издания: снимок иного издания разбором отвергается
		 *
		 * \~english
		 * @brief Edition of the record of a snapshot of a profile
		 * @details A snapshot carries an edition field: a snapshot of another edition is rejected by the parsing
		 *
		 * \~
		 */
		static constexpr uint8_t FINGERPRINT_EDITION = 0x01;

		/**
		 * \~russian
		 * @brief Отказы разбора, вычисления и снимков отпечатков
		 *
		 * \~english
		 * @brief Failures of the parsing, of the computation and of the snapshots of the fingerprints
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY    = 0x01, /*!< \~russian Вход оборван посреди поля \~english The input is cut off in the middle of a field \~ */
			RECORD    = 0x02, /*!< \~russian Запись не есть запись рукопожатия либо издание её неведомо \~english The record is not a handshake record or its edition is unknown \~ */
			MESSAGE   = 0x03, /*!< \~russian Сообщение рукопожатия не есть приветствие клиента \~english The handshake message is not a greeting of the client \~ */
			SESSION   = 0x04, /*!< \~russian Опознаватель связи длиннее дозволенного \~english The identifier of the connection is longer than allowed \~ */
			SUITE     = 0x05, /*!< \~russian Перечень наборов шифрования пуст либо сложен не по правилам \~english The list of the cipher suites is empty or is composed not by the rules \~ */
			METHOD    = 0x06, /*!< \~russian Перечень способов сжатия пуст \~english The list of the compression methods is empty \~ */
			EXTENSION = 0x07, /*!< \~russian Расширение оборвано либо тело его сложено не по правилам \~english An extension is cut off or its body is composed not by the rules \~ */
			TRAILING  = 0x08, /*!< \~russian За разобранным идут лишние байты \~english There are extra bytes behind the parsed \~ */
			MEMORY    = 0x09, /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
			VERSION   = 0x0A, /*!< \~russian Издание снимка разбору неведомо \~english The edition of the snapshot is unknown to the parsing \~ */
			FORMAT    = 0x0B, /*!< \~russian Снимок сложен не по правилам \~english The snapshot is composed not by the rules \~ */
			EMPTY     = 0x0C, /*!< \~russian Профиль пуст: отпечаток снимать не с чего \~english The profile is empty: there is nothing to take the fingerprint from \~ */
			FULL      = 0x0D, /*!< \~russian Хранилище профилей полно \~english The store of the profiles is full \~ */
			ABSENT    = 0x0E  /*!< \~russian Профиля с таким опознавателем в хранилище нет \~english There is no profile with such an identifier in the store \~ */
		};

		/**
		 * \~russian
		 * @brief Доля ключа обмена приветствия
		 *
		 * @details Раздел 4.2.8 RFC 8446: группа и открытая часть ключа в записи протокола.
		 *          У доли GREASE и у группы, связи неведомой, ключ хранится как записан
		 *
		 * \~english
		 * @brief Key share of a greeting
		 * @details The section 4.2.8 of RFC 8446: the group and the public part of the key in the
		 *          protocol record. At a GREASE share and at a group unknown to the connection the
		 *          key is stored as recorded
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Share {
			// Группа обмена ключами доли: неведомые значения хранятся числом по проводу
			extension::group_t group;
			// Открытая часть ключа обмена как записана
			vector <uint8_t> key;
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
			Share() noexcept : group(extension::group_t::NONE) {}
		} share_t;

		/**
		 * \~russian
		 * @brief Опознаватель заранее разделённого ключа приветствия
		 *
		 * @details Раздел 4.2.11 RFC 8446: опознаватель билета и скрытый возраст билета
		 *
		 * \~english
		 * @brief Identity of a pre-shared key of a greeting
		 * @details The section 4.2.11 of RFC 8446: the identity of the ticket and the obfuscated age of the ticket
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Identity {
			// Опознаватель заранее разделённого ключа
			vector <uint8_t> identity;
			// Скрытый возраст билета
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
		} identity_t;

		/**
		 * \~russian
		 * @brief Расширение приветствия клиента в профиле
		 *
		 * @details Запись плоская: вид по проводу, признак GREASE, сырое тело и разобранные
		 *          перечни. Какие перечни заполнены - зависит от вида: имена узлов у
		 *          server_name, протоколы у ALPN, NPN и ALPS, группы у supported_groups,
		 *          схемы у signature_algorithms, signature_algorithms_cert и
		 *          delegated_credential, издания у supported_versions, записи точек у
		 *          ec_point_formats, способы обмена у psk_key_exchange_modes, алгоритмы у
		 *          compress_certificate, доли у key_share, опознаватели у pre_shared_key,
		 *          значения у use_srtp (профили) и ech_outer_extensions (виды расширений),
		 *          число у padding (длина заполнения), record_size_limit (предел),
		 *          max_fragment_length (код), early_data (предел), heartbeat (режим) и
		 *          status_request (вид состояния)
		 *
		 * @note Сырое тело хранится всегда: по нему приветствие складывается обратно
		 *       байт в байт, а снимок профиля несёт одни лишь сырые тела
		 *
		 * \~english
		 * @brief Extension of a greeting of the client in a profile
		 * @details The record is flat: the wire type, the GREASE flag, the raw body and the parsed lists.
		 *          Which lists are filled depends on the type: host names at server_name, protocols at
		 *          ALPN, NPN and ALPS, groups at supported_groups, schemes at signature_algorithms,
		 *          signature_algorithms_cert and delegated_credential, editions at supported_versions,
		 *          point formats at ec_point_formats, exchange modes at psk_key_exchange_modes,
		 *          algorithms at compress_certificate, shares at key_share, identities at
		 *          pre_shared_key, values at use_srtp (profiles) and ech_outer_extensions (extension
		 *          types), a number at padding (length of the padding), record_size_limit (limit),
		 *          max_fragment_length (code), early_data (limit), heartbeat (mode) and
		 *          status_request (kind of the status)
		 * @note The raw body is always stored: by it the greeting is composed back byte by byte,
		 *       and the snapshot of a profile carries the raw bodies alone
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Extension {
			// Вид расширения по проводу
			uint16_t type;
			// Признак того, что вид расширения есть значение GREASE
			bool grease;
			// Сырое тело расширения как записано
			vector <uint8_t> data;
			// Имена узлов server_name
			vector <string> names;
			// Прикладные протоколы ALPN, NPN либо ALPS
			vector <string> protocols;
			// Группы обмена ключами supported_groups
			vector <extension::group_t> groups;
			// Схемы подписи signature_algorithms, signature_algorithms_cert либо delegated_credential
			vector <extension::scheme_t> schemes;
			// Издания протокола supported_versions
			vector <uint16_t> versions;
			// Записи точек кривой ec_point_formats
			vector <uint8_t> formats;
			// Способы обмена заранее разделённым ключом psk_key_exchange_modes
			vector <extension::regime_t> modes;
			// Алгоритмы сжатия цепочки сертификатов compress_certificate
			vector <extension::compression_t> algorithms;
			// Доли ключа обмена key_share
			vector <share_t> shares;
			// Опознаватели заранее разделённых ключей pre_shared_key
			vector <identity_t> identities;
			// Значения перечня: профили use_srtp либо виды ech_outer_extensions
			vector <uint16_t> values;
			// Число расширения: длина заполнения, предел записи, код длины куска, предел упреждения, режим либо вид состояния
			uint32_t value;
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
			Extension() noexcept : type(0), grease(false), value(0) {}
		} extension_t;

		/**
		 * \~russian
		 * @brief Профиль приветствия клиента
		 *
		 * @details Всё, что клиент объявил приветствием, в порядке провода: издание записи
		 *          и приветствия, случайное значение, опознаватель связи, метка возврата
		 *          состояния поверх дейтаграмм, наборы шифрования, способы сжатия и
		 *          расширения. Наборы, связи неведомые, хранятся числом по проводу
		 *
		 * @note Признак GREASE один на профиль: места вставки значений GREASE берутся из
		 *       самих перечней профиля, а признак лишь говорит, что они там есть
		 *
		 * \~english
		 * @brief Profile of a greeting of the client
		 * @details Everything the client announced by the greeting, in the wire order: the edition of
		 *          the record and of the greeting, the random value, the identifier of the connection,
		 *          the cookie over datagrams, the cipher suites, the compression methods and the
		 *          extensions. The suites unknown to the connection are stored as wire numbers
		 * @note The GREASE flag is single per profile: the places of the insertion of the GREASE values
		 *       are taken from the lists of the profile themselves, and the flag only says they are there
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Profile {
			// Признак того, что приветствие несёт значения GREASE
			bool grease;
			// Признак того, что приветствие снято поверх дейтаграмм
			bool datagram;
			// Издание слоя записей: ноль, когда разбиралось голое сообщение рукопожатия
			uint16_t record;
			// Издание приветствия клиента, доставшееся от предыдущих изданий
			uint16_t version;
			// Пора записи поверх дейтаграмм
			uint16_t epoch;
			// Порядковый номер записи поверх дейтаграмм
			uint64_t sequence;
			// Порядковый номер сообщения рукопожатия поверх дейтаграмм
			uint16_t message;
			// Длина тела приветствия как записана: по ней связь заполняет своё приветствие до той же длины
			uint32_t length;
			// Случайное значение приветствия
			uint8_t random[FINGERPRINT_RANDOM];
			// Опознаватель связи приветствия
			vector <uint8_t> session;
			// Метка возврата состояния поверх дейтаграмм
			vector <uint8_t> cookie;
			// Наборы шифрования в порядке провода: неведомые и GREASE хранятся числом по проводу
			vector <protect::suite_t> suites;
			// Способы сжатия в порядке провода
			vector <uint8_t> methods;
			// Расширения приветствия в порядке провода
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
			Profile() noexcept;
		} profile_t;

		/**
		 * \~russian
		 * @brief Отпечатки приветствия клиента
		 *
		 * @details JA3 - строка «издание,наборы,расширения,группы,записи точек» и её MD5;
		 *          JA4, JA4_r и JA4_o - по описанию FoxIO (SHA-256, усечённый до 12 знаков);
		 *          PeetPrint - восемь разделов через «|» с отметками GREASE и его MD5
		 *
		 * \~english
		 * @brief Fingerprints of a greeting of the client
		 * @details JA3 - the string «edition,suites,extensions,groups,point formats» and its MD5;
		 *          JA4, JA4_r and JA4_o - by the description of FoxIO (SHA-256 truncated to 12 characters);
		 *          PeetPrint - eight sections through «|» with GREASE marks and its MD5
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Imprint {
			// Строка JA3
			string ja3;
			// Хеш MD5 строки JA3 шестнадцатеричной записью
			string ja3hash;
			// Отпечаток JA4
			string ja4;
			// Отпечаток JA4_r: раскрытые перечни в порядке сортировки
			string ja4r;
			// Отпечаток JA4_o: раскрытые перечни в порядке провода
			string ja4o;
			// Строка PeetPrint
			string peetprint;
			// Хеш MD5 строки PeetPrint шестнадцатеричной записью
			string peethash;
			// Случайное значение приветствия шестнадцатеричной записью
			string random;
			// Опознаватель связи шестнадцатеричной записью
			string session;
			// Издание слоя записей
			uint16_t record;
			// Согласуемое издание: старшее из supported_versions без GREASE, иначе издание приветствия
			uint16_t negotiated;
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
			Imprint() noexcept : record(0), negotiated(0) {}
		} imprint_t;

		/**
		 * \~russian
		 * @brief Настройка кадра SETTINGS протокола HTTP/2
		 *
		 * \~english
		 * @brief Setting of the SETTINGS frame of the HTTP/2 protocol
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Setting {
			// Опознаватель настройки
			uint16_t id;
			// Значение настройки
			uint32_t value;
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
			Setting() noexcept : id(0), value(0) {}
		} setting_t;

		/**
		 * \~russian
		 * @brief Кадр PRIORITY протокола HTTP/2
		 *
		 * \~english
		 * @brief PRIORITY frame of the HTTP/2 protocol
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Priority {
			// Признак исключительной зависимости
			bool exclusive;
			// Вес потока как записан: настоящий вес на единицу больше
			uint8_t weight;
			// Опознаватель потока
			uint32_t stream;
			// Опознаватель потока, от которого зависит поток
			uint32_t dependency;
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
			Priority() noexcept : exclusive(false), weight(0), stream(0), dependency(0) {}
		} priority_t;

		/**
		 * \~russian
		 * @brief Начало связи протокола HTTP/2 для отпечатка Akamai
		 *
		 * @details Раздел 3.5 RFC 7540: преамбула клиента, кадр SETTINGS, кадр WINDOW_UPDATE
		 *          связи, кадры PRIORITY и порядок псевдозаголовков первого кадра HEADERS
		 *
		 * \~english
		 * @brief Beginning of a connection of the HTTP/2 protocol for the Akamai fingerprint
		 * @details The section 3.5 of RFC 7540: the client preface, the SETTINGS frame, the WINDOW_UPDATE
		 *          frame of the connection, the PRIORITY frames and the order of the pseudo-headers of the
		 *          first HEADERS frame
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Stream {
			// Прибавка окна связи кадром WINDOW_UPDATE: ноль, когда кадра не было
			uint32_t window;
			// Порядок псевдозаголовков первого запроса буквами: m - :method, p - :path, s - :scheme, a - :authority
			string pseudo;
			// Настройки кадра SETTINGS в порядке провода
			vector <setting_t> settings;
			// Кадры PRIORITY в порядке провода
			vector <priority_t> priorities;
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
			Stream() noexcept : window(0) {}
		} stream_t;

		/**
		 * \~russian
		 * @brief Опознаватель профиля в хранилище
		 *
		 * @details Ноль профилю не выдаётся: им хранилище отвечает на отказ добавления
		 *
		 * \~english
		 * @brief Identifier of a profile in the store
		 * @details Zero is not issued to a profile: by it the store answers to a failure of the addition
		 *
		 * \~
		 */
		typedef uint8_t id_t;

		/**
		 * \~russian
		 * @brief Метод проверки того, что значение есть значение GREASE
		 *
		 * @param value проверяемое значение по проводу
		 *
		 * @return      признак значения GREASE
		 *
		 * @details Раздел 2 RFC 8701: значения вида 0x?A?A с равными старшим и младшим байтами
		 *
		 * \~english
		 * @brief Method of checking that a value is a GREASE value
		 * @param value the wire value being checked
		 * @return      the flag of a GREASE value
		 * @details The section 2 of RFC 8701: the values of the form 0x?A?A with equal high and low bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool grease(const uint16_t value) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи с приветствием клиента в профиль
		 *
		 * @param data   разбираемая запись: заголовок слоя записей TLS либо DTLS, обвязка сообщения рукопожатия и тело приветствия
		 * @param result профиль, в который помещается итог разбора
		 *
		 * @return       отказ разбора приветствия
		 *
		 * @details Перенос узнаётся по изданию заголовка записи: 0xFEFF и 0xFEFD - дейтаграммы
		 *          с заголовком записи в 13 байтов и обвязкой сообщения в 12 байтов, иное -
		 *          поток с заголовком в 5 байтов и обвязкой в 4 байта. Запись обязана нести
		 *          приветствие целиком; лишние байты за записью отвергаются
		 *
		 * @note На любом обрезанном либо порченом входе разбор отвечает отказом
		 *
		 * \~english
		 * @brief Method of the parsing of a record with a greeting of the client into a profile
		 * @param data   the record being parsed: the header of the record layer of TLS or DTLS, the handshake message framing and the body of the greeting
		 * @param result the profile the outcome of the parsing is put into
		 * @return       the failure of the parsing of the greeting
		 * @details The transport is recognized by the edition of the record header: 0xFEFF and 0xFEFD are
		 *          datagrams with a record header of 13 bytes and a message framing of 12 bytes, anything
		 *          else is a stream with a header of 5 bytes and a framing of 4 bytes. The record must carry
		 *          the greeting whole; extra bytes behind the record are rejected
		 * @note At any cut off or corrupted input the parsing answers by a failure
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, profile_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора сообщения рукопожатия с приветствием клиента в профиль
		 *
		 * @param data     разбираемое сообщение: обвязка в 4 байта по разделу 4 RFC 8446 и тело приветствия
		 * @param result   профиль, в который помещается итог разбора
		 * @param datagram признак приветствия поверх дейтаграмм: за опознавателем связи идёт метка возврата состояния
		 *
		 * @return         отказ разбора приветствия
		 *
		 * @details Таким сообщение держит связь сервера: и поверх потока, и после сборки поверх
		 *          дейтаграмм обвязка у него в 4 байта, а тело - по переносу. Издание записи у
		 *          профиля остаётся нулём
		 *
		 * \~english
		 * @brief Method of the parsing of a handshake message with a greeting of the client into a profile
		 * @param data     the message being parsed: the framing of 4 bytes by the section 4 of RFC 8446 and the body of the greeting
		 * @param result   the profile the outcome of the parsing is put into
		 * @param datagram the flag of a greeting over datagrams: the cookie follows the session identifier
		 * @return         the failure of the parsing of the greeting
		 * @details Such a message is held by a connection of the server: both over a stream and after the
		 *          reassembly over datagrams its framing is of 4 bytes, and the body is by the transport.
		 *          The record edition of the profile stays zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, profile_t & result, const bool datagram) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления отпечатков профиля
		 *
		 * @param profile профиль приветствия клиента
		 * @param result  отпечатки, в которые помещается итог вычисления
		 *
		 * @return        отказ вычисления отпечатков: EMPTY у профиля без наборов и расширений
		 *
		 * @details JA3: издание приветствия и перечни без GREASE через «-», хеш MD5.
		 *          JA4 по описанию FoxIO: буква переноса (t, d, q), издание по supported_versions
		 *          без GREASE либо по изданию приветствия, d при server_name и i без него,
		 *          числа наборов и расширений без GREASE не более 99, первый и последний знаки
		 *          первого протокола ALPN (00 без ALPN, шестнадцатеричные знаки у неалфавитных),
		 *          SHA-256 отсортированных наборов и SHA-256 отсортированных расширений без
		 *          server_name и ALPN с «_» и схемами подписи в порядке провода; пустой
		 *          перечень - 000000000000. PeetPrint: издания, способы сжатия, группы, схемы,
		 *          число записей точек, число способов обмена, наборы и расширения с
		 *          отметками GREASE, хеш MD5
		 *
		 * \~english
		 * @brief Method of the computation of the fingerprints of a profile
		 * @param profile the profile of a greeting of the client
		 * @param result  the fingerprints the outcome of the computation is put into
		 * @return        the failure of the computation: EMPTY at a profile without suites and extensions
		 * @details JA3: the edition of the greeting and the lists without GREASE through «-», an MD5 hash.
		 *          JA4 by the description of FoxIO: the transport letter (t, d, q), the edition by
		 *          supported_versions without GREASE or by the edition of the greeting, d at server_name and
		 *          i without it, the counts of the suites and of the extensions without GREASE at most 99, the
		 *          first and the last characters of the first ALPN protocol (00 without ALPN, hex characters
		 *          at non-alphanumeric ones), the SHA-256 of the sorted suites and the SHA-256 of the sorted
		 *          extensions without server_name and ALPN with «_» and the signature schemes in the wire
		 *          order; an empty list is 000000000000. PeetPrint: the editions, the compression methods,
		 *          the groups, the schemes, the count of the point formats, the count of the exchange modes,
		 *          the suites and the extensions with GREASE marks, an MD5 hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t imprint(const profile_t & profile, imprint_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки того, что отпечатки похожи на отпечатки браузера
		 *
		 * @param imprint проверяемые отпечатки
		 *
		 * @return        признак похожести на браузер: издание TLS 1.3, имя узла и непустой JA3
		 *
		 * \~english
		 * @brief Method of checking that the fingerprints look like those of a browser
		 * @param imprint the fingerprints being checked
		 * @return        the flag of the likeness to a browser: the TLS 1.3 edition, a host name and a non-empty JA3
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool browser(const imprint_t & imprint) noexcept;
		/**
		 * \~russian
		 * @brief Метод печати профиля человеку
		 *
		 * @param profile печатаемый профиль
		 * @param result  строка, в которую помещается печать
		 *
		 * @return        отказ печати
		 *
		 * @details Печатаются слой записей, обвязка сообщения, приветствие, наборы, способы
		 *          сжатия, расширения с разобранными перечнями и вычисленные отпечатки
		 *
		 * \~english
		 * @brief Method of the printing of a profile for a human
		 * @param profile the profile being printed
		 * @param result  the string the print is put into
		 * @return        the failure of the printing
		 * @details The record layer, the message framing, the greeting, the suites, the compression methods,
		 *          the extensions with the parsed lists and the computed fingerprints are printed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t print(const profile_t & profile, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора начала связи протокола HTTP/2
		 *
		 * @param data   разбираемые байты: преамбула клиента и первые кадры
		 * @param result начало связи, в которое помещается итог разбора
		 *
		 * @return       отказ разбора: EMPTY без кадра SETTINGS
		 *
		 * @details Разбор идёт до первого кадра HEADERS включительно; псевдозаголовки берутся
		 *          из его блока HPACK по статической таблице и открытым именам
		 *
		 * \~english
		 * @brief Method of the parsing of the beginning of a connection of the HTTP/2 protocol
		 * @param data   the bytes being parsed: the client preface and the first frames
		 * @param result the beginning of the connection the outcome of the parsing is put into
		 * @return       the failure of the parsing: EMPTY without a SETTINGS frame
		 * @details The parsing goes up to the first HEADERS frame inclusively; the pseudo-headers are taken
		 *          from its HPACK block by the static table and by the literal names
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, stream_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления отпечатка Akamai HTTP/2
		 *
		 * @param stream начало связи протокола HTTP/2
		 * @param result строка, в которую помещается отпечаток
		 *
		 * @return       отказ вычисления: EMPTY без настроек
		 *
		 * @details Вид «настройки|окно|приоритеты|псевдозаголовки»: настройки парами «опознаватель:значение»
		 *          через «;», приоритеты «поток:исключительность:зависимость:вес» через «,», псевдозаголовки через «,»
		 *
		 * \~english
		 * @brief Method of the computation of the Akamai HTTP/2 fingerprint
		 * @param stream the beginning of a connection of the HTTP/2 protocol
		 * @param result the string the fingerprint is put into
		 * @return       the failure of the computation: EMPTY without settings
		 * @details The form «settings|window|priorities|pseudo-headers»: the settings by pairs «id:value» through «;»,
		 *          the priorities «stream:exclusive:dependency:weight» through «,», the pseudo-headers through «,»
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t akamai(const stream_t & stream, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод снятия переносимого снимка профиля
		 *
		 * @param profile снимаемый профиль
		 * @param result  накопитель, в конец которого дописывается снимок
		 *
		 * @return        отказ снятия снимка
		 *
		 * @details Снимок переносим между машинами: старший байт вперёд, поле издания и поля
		 *          постоянной ширины. Расширения идут одними сырыми телами: разобранные
		 *          перечни при подъёме снимка выводятся из тел заново
		 *
		 * \~english
		 * @brief Method of taking a portable snapshot of a profile
		 * @param profile the profile being snapshotted
		 * @param result  the accumulator the snapshot is appended to the end of
		 * @return        the failure of taking the snapshot
		 * @details The snapshot is portable between machines: the high byte first, an edition field and
		 *          fields of a fixed width. The extensions go by the raw bodies alone: the parsed lists
		 *          are derived from the bodies anew at the loading of the snapshot
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t dump(const profile_t & profile, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод подъёма профиля из переносимого снимка
		 *
		 * @param data   разбираемый снимок
		 * @param result профиль, в который помещается итог подъёма
		 *
		 * @return       отказ подъёма: VERSION у чужого издания, FORMAT у снимка не по правилам, TRAILING у лишних байтов
		 *
		 * \~english
		 * @brief Method of loading a profile from a portable snapshot
		 * @param data   the snapshot being parsed
		 * @param result the profile the outcome of the loading is put into
		 * @return       the failure of the loading: VERSION at a foreign edition, FORMAT at a snapshot not by the rules, TRAILING at extra bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t load(const view_t & data, profile_t & result) noexcept;

		/**
		 * \~russian
		 * @brief Хранилище профилей с опознавателями
		 *
		 * @details Простая связка профилей под однобайтовыми опознавателями: добавление,
		 *          изъятие, розыск, перечень и снимок связки целиком. Потоков хранилище
		 *          не знает: охрана от одновременного доступа принадлежит потребителю
		 *
		 * \~english
		 * @brief Store of the profiles with identifiers
		 * @details A simple bundle of the profiles under one-byte identifiers: addition, removal, search,
		 *          listing and a snapshot of the bundle whole. The store knows no threads: the guarding
		 *          against a concurrent access belongs to the consumer
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Store {
			private:
				/**
				 * \~russian
				 * @brief Запись хранилища
				 *
				 * \~english
				 * @brief Entry of the store
				 *
				 * \~
				 */
				typedef struct Entry {
					// Опознаватель профиля
					id_t id;
					// Хранимый профиль
					profile_t profile;
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
					Entry() noexcept : id(0) {}
				} entry_t;
			private:
				// Записи хранилища в порядке добавления
				vector <entry_t> _entries;
			public:
				/**
				 * \~russian
				 * @brief Метод добавления профиля в хранилище
				 *
				 * @param profile добавляемый профиль
				 *
				 * @return        опознаватель профиля, ноль при полном хранилище либо нехватке памяти
				 *
				 * @details Выдаётся наименьший свободный опознаватель от единицы
				 *
				 * \~english
				 * @brief Method of the addition of a profile into the store
				 * @param profile the profile being added
				 * @return        the identifier of the profile, zero at a full store or at a lack of memory
				 * @details The least free identifier from one is issued
				 *
				 * \~
				 */
				id_t add(const profile_t & profile) noexcept;
				/**
				 * \~russian
				 * @brief Метод изъятия профиля из хранилища
				 *
				 * @param id опознаватель изымаемого профиля
				 *
				 * @return   признак того, что профиль был и изъят
				 *
				 * \~english
				 * @brief Method of the removal of a profile from the store
				 * @param id the identifier of the profile being removed
				 * @return   the flag that the profile was there and is removed
				 *
				 * \~
				 */
				bool remove(const id_t id) noexcept;
				/**
				 * \~russian
				 * @brief Метод розыска профиля по опознавателю
				 *
				 * @param id опознаватель разыскиваемого профиля
				 *
				 * @return   найденный профиль либо nullptr
				 *
				 * @note Указатель живёт до ближайшего изменения хранилища
				 *
				 * \~english
				 * @brief Method of the search of a profile by the identifier
				 * @param id the identifier of the profile being searched for
				 * @return   the found profile or nullptr
				 * @note The pointer lives until the nearest change of the store
				 *
				 * \~
				 */
				const profile_t * get(const id_t id) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения перечня опознавателей хранилища
				 *
				 * @param result накопитель, в конец которого дописываются опознаватели в порядке добавления
				 *
				 * @return       отказ получения перечня
				 *
				 * \~english
				 * @brief Method of getting the list of the identifiers of the store
				 * @param result the accumulator the identifiers are appended to the end of in the order of the addition
				 * @return       the failure of getting the list
				 *
				 * \~
				 */
				error_t list(vector <id_t> & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки хранилища
				 *
				 *
				 * \~english
				 * @brief Method of clearing the store
				 *
				 * \~
				 */
				void clear() noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки пустоты хранилища
				 *
				 * @return признак того, что профилей в хранилище нет
				 *
				 * \~english
				 * @brief Method of checking the emptiness of the store
				 * @return the flag that there are no profiles in the store
				 *
				 * \~
				 */
				bool empty() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа профилей хранилища
				 *
				 * @return число профилей хранилища
				 *
				 * \~english
				 * @brief Method of getting the count of the profiles of the store
				 * @return the count of the profiles of the store
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия переносимого снимка связки профилей
				 *
				 * @param result накопитель, в конец которого дописывается снимок связки
				 *
				 * @return       отказ снятия снимка
				 *
				 * \~english
				 * @brief Method of taking a portable snapshot of the bundle of the profiles
				 * @param result the accumulator the snapshot of the bundle is appended to the end of
				 * @return       the failure of taking the snapshot
				 *
				 * \~
				 */
				error_t dump(vector <uint8_t> & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод подъёма связки профилей из переносимого снимка
				 *
				 * @param data разбираемый снимок связки
				 *
				 * @return     отказ подъёма
				 *
				 * @details Прежнее содержимое хранилища замещается лишь при годном снимке целиком
				 *
				 * \~english
				 * @brief Method of loading the bundle of the profiles from a portable snapshot
				 * @param data the snapshot of the bundle being parsed
				 * @return     the failure of the loading
				 * @details The previous content of the store is replaced only at a snapshot fit whole
				 *
				 * \~
				 */
				error_t load(const view_t & data) noexcept;
			public:
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
				Store() noexcept;
		} store_t;
	};
};

#endif // __ANTS_FINGERPRINT__
