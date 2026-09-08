/**
 * @file datagram.hpp
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
 * \~russian
 * @brief Заголовочный файл слоя записей протокола DTLS 1.3 (RFC 9147) — заголовки
 *        записей поверх дейтаграмм, обвязка кусков сообщений рукопожатия, сообщение
 *        подтверждения, шифрование номера записи и окно защиты от повторов
 *
 * \~english
 * @brief Header file of the record layer of the DTLS 1.3 protocol (RFC 9147) — the headers
 *        of the records over datagrams, the framing of the fragments of the messages of the
 *        handshake, the acknowledgement message, the record number encryption and the
 *        anti-replay window
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_DATAGRAM__
#define __ANTS_DATAGRAM__

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
#include <record/record.hpp>
#include <protect/protect.hpp>
#include <handshake/handshake.hpp>

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
	 * @brief Пространство имён слоя записей протокола DTLS 1.3
	 *
	 * @details Раздел 4 RFC 9147: запись поверх дейтаграммы несёт пору ключей и
	 *          порядковый номер в самом заголовке, ибо дейтаграммы теряются, двоятся и
	 *          приходят не по порядку. Открытые записи идут заголовком DTLSPlaintext, а
	 *          защищённые - объединённым заголовком DTLSCiphertext с зашифрованным номером
	 *
	 * @note Ввода-вывода здесь нет: модуль разбирает и составляет байты, а перенос
	 *       дейтаграмм по UDP либо SCTP остаётся за тем, кто связь ведёт
	 *
	 * \~english
	 * @brief Namespace of the record layer of the DTLS 1.3 protocol
	 * @details The section 4 of RFC 9147: a record over a datagram carries the epoch of the keys
	 *          and the sequence number in the header itself, because the datagrams get lost, get
	 *          doubled and arrive out of order. The plain records go by the DTLSPlaintext header,
	 *          while the protected ones go by the unified DTLSCiphertext header with an encrypted
	 *          number
	 * @note There is no input-output here: the module parses and composes bytes, while the transport
	 *       of the datagrams over UDP or SCTP remains with the one who leads the connection
	 *
	 * \~
	 */
	namespace datagram {
		/**
		 * \~russian
		 * @brief Издание протокола DTLS 1.3 в перечне изданий приветствия
		 *
		 * @details Раздел 5.3 RFC 9147: DTLS 1.3 объявляется значением 0xFEFC
		 *
		 * \~english
		 * @brief Edition of the DTLS 1.3 protocol in the list of the editions of a greeting
		 * @details The section 5.3 of RFC 9147: DTLS 1.3 is announced by the value 0xFEFC
		 *
		 * \~
		 */
		static constexpr uint16_t DATAGRAM_VERSION = 0xFEFC;

		/**
		 * \~russian
		 * @brief Издание протокола, доставшееся заголовкам от DTLS 1.2
		 *
		 * @details Раздел 5.3 RFC 9147: legacy_version приветствия и legacy_record_version
		 *          открытой записи несут 0xFEFD
		 *
		 * \~english
		 * @brief Edition of the protocol inherited by the headers from DTLS 1.2
		 * @details The section 5.3 of RFC 9147: the legacy_version of a greeting and the
		 *          legacy_record_version of a plain record carry 0xFEFD
		 *
		 * \~
		 */
		static constexpr uint16_t DATAGRAM_LEGACY = 0xFEFD;

		/**
		 * \~russian
		 * @brief Размер дейтаграммы, принятый по умолчанию, в байтах
		 *
		 * @details Раздел 4.4 RFC 9147: 1200 байтов проходят по всякому пути IPv6 без
		 *          дробления, и тем же размером ограничивает себя QUIC
		 *
		 * \~english
		 * @brief Size of a datagram taken by default, in bytes
		 * @details The section 4.4 of RFC 9147: 1200 bytes pass along any IPv6 path without a
		 *          fragmentation, and QUIC limits itself by the same size
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_MTU = 1200;

		/**
		 * \~russian
		 * @brief Наименьший размер дейтаграммы, который связи дозволено назначить, в байтах
		 *
		 * @note Меньший размер не вмещает и заголовка защищённой записи с куском сообщения
		 *       рукопожатия, и рукопожатие им не прошло бы вовсе
		 *
		 * \~english
		 * @brief Least size of a datagram a connection is allowed to appoint, in bytes
		 * @note A smaller size does not hold even the header of a protected record with a fragment
		 *       of a message of the handshake, and the handshake would not pass by it at all
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_MTU_LEAST = 256;

		/**
		 * \~russian
		 * @brief Размер заголовка открытой записи в байтах
		 *
		 * @details Раздел 4 RFC 9147: вид содержимого, издание, пора ключей двумя байтами,
		 *          порядковый номер шестью байтами и длина двумя
		 *
		 * \~english
		 * @brief Size of the header of a plain record in bytes
		 * @details The section 4 of RFC 9147: the type of the content, the edition, the epoch by two
		 *          bytes, the sequence number by six bytes and the length by two
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_PLAIN_HEADER = 13;

		/**
		 * \~russian
		 * @brief Размер объединённого заголовка защищённой записи, составляемого связью, в байтах
		 *
		 * @details Раздел 4 RFC 9147: байт разрядов 0b001CSLEE, порядковый номер двумя
		 *          байтами и длина двумя; опознаватель связи не составляется
		 *
		 * \~english
		 * @brief Size of the unified header of a protected record composed by a connection, in bytes
		 * @details The section 4 of RFC 9147: the byte of the bits 0b001CSLEE, the sequence number by
		 *          two bytes and the length by two; a connection identifier is not composed
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_UNIFIED_HEADER = 5;

		/**
		 * \~russian
		 * @brief Размер обвязки куска сообщения рукопожатия в байтах
		 *
		 * @details Раздел 5.2 RFC 9147: вид, длина тремя байтами, порядковый номер сообщения
		 *          двумя, смещение куска тремя и длина куска тремя
		 *
		 * \~english
		 * @brief Size of the framing of a fragment of a message of the handshake in bytes
		 * @details The section 5.2 of RFC 9147: the type, the length by three bytes, the sequence
		 *          number of the message by two, the offset of the fragment by three and the length
		 *          of the fragment by three
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_FRAGMENT_HEADER = 12;

		/**
		 * \~russian
		 * @brief Ширина окна защиты от повторов в записях
		 *
		 * @details Раздел 4.5.1 RFC 9147: окно шириной 64 записи, как у RFC 4303
		 *
		 * \~english
		 * @brief Width of the anti-replay window in records
		 * @details The section 4.5.1 of RFC 9147: a window of 64 records wide, as at RFC 4303
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_WINDOW = 64;

		/**
		 * \~russian
		 * @brief Длина образца шифртекста, из которого выводится маска номера записи, в байтах
		 *
		 * @details Раздел 4.2.3 RFC 9147: маска берётся от первых шестнадцати байтов
		 *          шифртекста, и запись короче того защитить нельзя
		 *
		 * \~english
		 * @brief Length of the sample of the ciphertext the mask of the record number is derived from,
		 *        in bytes
		 * @details The section 4.2.3 of RFC 9147: the mask is taken from the first sixteen bytes of the
		 *          ciphertext, and a record shorter than that cannot be protected
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_SAMPLE = 16;

		/**
		 * \~russian
		 * @brief Длина маски номера записи в байтах
		 *
		 * \~english
		 * @brief Length of the mask of the record number in bytes
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_MASK = 2;

		/**
		 * \~russian
		 * @brief Наибольший порядковый номер записи в поре ключей
		 *
		 * @details Раздел 4 RFC 9147: номер занимает сорок восемь разрядов
		 *
		 * \~english
		 * @brief Greatest sequence number of a record within an epoch
		 * @details The section 4 of RFC 9147: the number occupies forty eight bits
		 *
		 * \~
		 */
		static constexpr uint64_t DATAGRAM_SEQUENCE = 0xFFFFFFFFFFFFULL;

		/**
		 * \~russian
		 * @brief Начальный срок ожидания повторной передачи в миллисекундах
		 *
		 * @details Раздел 5.8.2 RFC 9147: секунда, удваиваемая всякой попыткой
		 *
		 * \~english
		 * @brief Initial term of the waiting for a retransmission in milliseconds
		 * @details The section 5.8.2 of RFC 9147: a second doubled by every attempt
		 *
		 * \~
		 */
		static constexpr uint32_t DATAGRAM_TIMEOUT = 1000;

		/**
		 * \~russian
		 * @brief Предел срока ожидания повторной передачи в миллисекундах
		 *
		 * @details Раздел 5.8.2 RFC 9147: шестьдесят секунд
		 *
		 * \~english
		 * @brief Limit of the term of the waiting for a retransmission in milliseconds
		 * @details The section 5.8.2 of RFC 9147: sixty seconds
		 *
		 * \~
		 */
		static constexpr uint32_t DATAGRAM_TIMEOUT_LIMIT = 60000;

		/**
		 * \~russian
		 * @brief Число попыток повторной передачи, по исчерпании которых связь обрывается
		 *
		 * \~english
		 * @brief Number of the attempts of a retransmission, on the exhaustion of which the connection
		 *        is torn
		 *
		 * \~
		 */
		static constexpr uint32_t DATAGRAM_ATTEMPTS = 8;

		/**
		 * \~russian
		 * @brief Наибольшая длина принимаемой дейтаграммы в байтах
		 *
		 * @details Раздел 4.5.2 RFC 9147: защищённая запись не длиннее 2^14 + 256 байтов, и
		 *          дейтаграмма вмещает такую запись вместе с заголовком; более длинная
		 *          означает чужой перенос и отбрасывается. Размер своих дейтаграмм с этим
		 *          пределом не связан: стороны с разным размером обязаны сходиться
		 *
		 * \~english
		 * @brief Greatest length of a received datagram in bytes
		 * @details The section 4.5.2 of RFC 9147: a protected record is not longer than 2^14 + 256 bytes,
		 *          and a datagram holds such a record together with its header; a longer one means a
		 *          foreign transport and is discarded. The size of the own datagrams is not bound to this
		 *          limit: the sides with different sizes are obliged to converge
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_LONGEST = (DATAGRAM_PLAIN_HEADER + record::RECORD_CIPHERTEXT);

		/**
		 * \~russian
		 * @brief Наибольшая длина адреса собеседника, привязываемого к метке возврата состояния, в байтах
		 *
		 * @note Адрес непрозрачен и сличается побайтно; более длинный отвергается установкой
		 *
		 * \~english
		 * @brief Greatest length of the address of the interlocutor bound to the label of the return of
		 *        the state, in bytes
		 * @note The address is opaque and compared byte by byte; a longer one is rejected by the setting
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_ADDRESS = 256;

		/**
		 * \~russian
		 * @brief Число записей, дозволенное одной передаче залпа
		 *
		 * @details Раздел 5.8.3 RFC 9147: за одну передачу не следует слать более десяти
		 *          записей. Связь залп дозирует не по этому пределу, а целиком: управления
		 *          перегрузкой у неё нет, и предел лишь именует норму стандарта
		 *
		 * \~english
		 * @brief Number of the records allowed to a single transmission of a flight
		 * @details The section 5.8.3 of RFC 9147: no more than ten records should be sent in a single
		 *          transmission. The connection does not dose a flight by this limit but sends it whole:
		 *          it has no congestion control, and the limit merely names the norm of the standard
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_RECORDS = 10;

		/**
		 * \~russian
		 * @brief Число сообщений рукопожатия, принимаемых наперёд ожидаемого
		 *
		 * @details Залп редко длиннее, а большее означало бы накопление чужого мусора:
		 *          сборок принимаемых сообщений держится не более этого числа
		 *
		 * \~english
		 * @brief Number of the messages of the handshake received ahead of the expected one
		 * @details A flight is rarely longer, and more would mean an accumulation of foreign garbage: no
		 *          more assemblies of the received messages than this number are kept
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_AHEAD = 8;

		/**
		 * \~russian
		 * @brief Наибольшая длина собираемого сообщения рукопожатия в байтах
		 *
		 * @details Память под сборку занимается по чужому слову - по длине из обвязки куска;
		 *          шестнадцать мегабайтов предела сообщения рукопожатия поверх дейтаграмм не
		 *          собираются, и сообщение длиннее отбрасывается
		 *
		 * \~english
		 * @brief Greatest length of an assembled message of the handshake in bytes
		 * @details The memory for an assembly is taken by a foreign word — by the length from the framing
		 *          of a fragment; the sixteen megabytes of the limit of a message of the handshake are not
		 *          assembled over datagrams, and a longer message is discarded
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_ASSEMBLY = 65536;

		/**
		 * \~russian
		 * @brief Число записей следующей поры, откладываемых до прихода её ключей
		 *
		 * @details Раздел 4.2.1 RFC 9147: приветствие сервера теряется, а его защищённый
		 *          выход доходит - и ждёт повтора приветствия; сверх этого числа записи
		 *          отбрасываются
		 *
		 * \~english
		 * @brief Number of the records of the next epoch deferred until the arrival of its keys
		 * @details The section 4.2.1 of RFC 9147: the greeting of the server gets lost while its protected
		 *          output arrives — and waits for the repetition of the greeting; beyond this number the
		 *          records are discarded
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_DEFERRED = 8;

		/**
		 * \~russian
		 * @brief Причины молчаливого отброса записей и дейтаграмм
		 *
		 * @details Раздел 4.5.2 RFC 9147: негодное отбрасывается без извещений, и лишь
		 *          счётчики по причинам дают о том знать тому, кто связь ведёт
		 *
		 * \~english
		 * @brief Reasons of the silent discarding of records and datagrams
		 * @details The section 4.5.2 of RFC 9147: the unfit is discarded without alerts, and only the
		 *          counters by reasons let the one who leads the connection know about it
		 *
		 * \~
		 */
		enum class reason_t : uint8_t {
			LENGTH     = 0x00, /*!< \~russian Дейтаграмма пуста либо длиннее принимаемой, запись усечена, пуста либо длиннее дозволенного \~english The datagram is empty or longer than accepted, the record is truncated, empty or longer than allowed \~ */
			TYPE       = 0x01, /*!< \~russian Вид содержимого записи протоколом не определён \~english The type of the content of the record is not defined by the protocol \~ */
			EPOCH      = 0x02, /*!< \~russian Пора ключей записи связью не держится либо отложить запись некуда \~english The epoch of the record is not kept by the connection or there is no room to defer the record \~ */
			IDENTIFIER = 0x03, /*!< \~russian Запись несёт опознаватель связи \~english The record carries a connection identifier \~ */
			REPLAY     = 0x04, /*!< \~russian Запись повторная либо позади окна повторов \~english The record is repeated or behind the anti-replay window \~ */
			DAMAGE     = 0x05, /*!< \~russian Защита с записи не снимается: запись порчена либо чужая \~english The protection is not removed from the record: it is damaged or foreign \~ */
			PLAIN      = 0x06, /*!< \~russian Открытая запись пришла, когда ей уже не место: извещение либо кусок за появлением ключей чтения, подтверждение с номерами \~english A plain record came when there is no place for it: an alert or a fragment after the read keys appeared, an acknowledgement with numbers \~ */
			AHEAD      = 0x07, /*!< \~russian Кусок сообщения слишком далеко впереди ожидаемого \~english The fragment of a message is too far ahead of the expected one \~ */
			FRAMING    = 0x08, /*!< \~russian Обвязка куска открытой записи негодна либо кусок расходится со сборкой \~english The framing of a fragment of a plain record is unfit or the fragment diverges from the assembly \~ */
			PREMATURE  = 0x09, /*!< \~russian Прикладные данные пришли до установления связи \~english The application data came before the establishment of the connection \~ */
			COOKIE     = 0x0A, /*!< \~russian Повторное приветствие клиента без метки возврата состояния либо с чужою \~english A repeated greeting of the client without a label of the return of the state or with a foreign one \~ */
			VERSION    = 0x0B, /*!< \~russian Заголовок записи DTLS 1.2 несёт чужое издание протокола: не 0xFEFD, а 0xFEFF - не у открытой записи рукопожатия (раздел 4.1 RFC 6347) \~english The header of a DTLS 1.2 record carries a foreign edition of the protocol: not 0xFEFD, and 0xFEFF - not at a plain handshake record (the section 4.1 of RFC 6347) \~ */
			GREETING   = 0x0C  /*!< \~russian Приветствие клиента до подтверждения адреса негодно: порчено, дроблёно либо кусок чужого сообщения - сервер без состояния отбрасывает его молча (разделы 4.1.2.7 и 4.2.1 RFC 6347) \~english The greeting of the client before the confirmation of the address is unfit: damaged, fragmented or a fragment of a foreign message - the stateless server discards it silently (the sections 4.1.2.7 and 4.2.1 of RFC 6347) \~ */
		};

		/**
		 * \~russian
		 * @brief Число причин молчаливого отброса
		 *
		 * \~english
		 * @brief Number of the reasons of the silent discarding
		 *
		 * \~
		 */
		static constexpr size_t DATAGRAM_REASONS = 13;

		/**
		 * \~russian
		 * @brief Отказы слоя записей поверх дейтаграмм
		 *
		 * \~english
		 * @brief Failures of the record layer over datagrams
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE       = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY     = 0x01, /*!< \~russian Байтов для целого заголовка либо записи не хватает \~english There are not enough bytes for a whole header or record \~ */
			TYPE       = 0x02, /*!< \~russian Вид содержимого записи протоколом не определён \~english The type of the content of the record is not defined by the protocol \~ */
			EPOCH      = 0x03, /*!< \~russian Открытая запись несёт ненулевую пору ключей \~english The plain record carries a non-zero epoch \~ */
			LENGTH     = 0x04, /*!< \~russian Длина поля вышла за дозволенный предел \~english The length of a field has gone beyond the allowed limit \~ */
			IDENTIFIER = 0x05, /*!< \~russian Запись несёт опознаватель связи, связью не поддержанный \~english The record carries a connection identifier not supported by the connection \~ */
			MEMORY     = 0x06, /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
			VERSION    = 0x07  /*!< \~russian Заголовок записи издания DTLS 1.2 несёт чужое издание протокола: не 0xFEFD, а 0xFEFF - не у открытой записи рукопожатия (раздел 4.1 RFC 6347) \~english The header of a DTLS 1.2 record carries a foreign edition of the protocol: not 0xFEFD, and 0xFEFF - not at a plain handshake record (the section 4.1 of RFC 6347) \~ */
		};


		/**
		 * \~russian
		 * @brief Заголовок записи поверх дейтаграммы
		 *
		 * @details У открытой записи поля заполнены целиком; у защищённой порядковый
		 *          номер несёт лишь свои младшие разряды, а пора ключей - два младших
		 *          разряда: полные значения восстанавливает связь по своему состоянию
		 *
		 * \~english
		 * @brief Header of a record over a datagram
		 * @details At a plain record the fields are filled wholly; at a protected one the sequence
		 *          number carries only its junior bits, and the epoch — two junior bits: the full
		 *          values are restored by the connection by its state
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Header {
			// Признак объединённого заголовка защищённой записи
			bool unified;
			// Признак того, что запись несёт опознаватель связи
			bool identifier;
			// Признак того, что заголовок несёт длину записи
			bool sized;
			// Число разрядов порядкового номера в заголовке
			uint8_t bits;
			// Вид содержимого записи
			record::type_t type;
			// Пора ключей записи
			uint16_t epoch;
			// Порядковый номер записи
			uint64_t sequence;
			// Длина содержимого записи в байтах
			size_t size;
			// Длина самого заголовка в байтах
			size_t length;
			// Издание протокола из заголовка по проводу: заполняется лишь разбором заголовка издания DTLS 1.2
			uint16_t version;
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
			Header() noexcept : unified(false), identifier(false), sized(true), bits(16), type(record::type_t::NONE), epoch(0), sequence(0), size(0), length(0), version(0) {}
		} header_t;

		/**
		 * \~russian
		 * @brief Обвязка куска сообщения рукопожатия
		 *
		 * @details Раздел 5.2 RFC 9147: сообщение рукопожатия дробится на куски по
		 *          размеру дейтаграммы, и всякий кусок несёт номер сообщения, своё смещение
		 *          и длину
		 *
		 * \~english
		 * @brief Framing of a fragment of a message of the handshake
		 * @details The section 5.2 of RFC 9147: a message of the handshake is split into fragments by
		 *          the size of a datagram, and every fragment carries the number of the message, its
		 *          offset and length
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Fragment {
			// Вид сообщения рукопожатия
			handshake::type_t type;
			// Порядковый номер сообщения рукопожатия
			uint16_t sequence;
			// Длина тела целого сообщения в байтах
			size_t size;
			// Смещение куска в теле сообщения
			size_t offset;
			// Длина куска в байтах
			size_t length;
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
			Fragment() noexcept : type(handshake::type_t::NONE), sequence(0), size(0), offset(0), length(0) {}
		} fragment_t;

		/**
		 * \~russian
		 * @brief Номер записи: пора ключей и порядковый номер
		 *
		 * @details Раздел 7 RFC 9147: сообщение подтверждения перечисляет принятые записи
		 *          именно такими парами по восемь байтов каждое поле
		 *
		 * \~english
		 * @brief Number of a record: the epoch and the sequence number
		 * @details The section 7 of RFC 9147: the acknowledgement message lists the received records
		 *          exactly by such pairs of eight bytes per field
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Number {
			// Пора ключей записи
			uint64_t epoch;
			// Порядковый номер записи
			uint64_t sequence;
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
			Number() noexcept : epoch(0), sequence(0) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param epoch    пора ключей записи
			 * @param sequence порядковый номер записи
			 *
			 * \~english
			 * @brief Constructor
			 * @param epoch    the epoch of the record
			 * @param sequence the sequence number of the record
			 *
			 * \~
			 */
			Number(const uint64_t epoch, const uint64_t sequence) noexcept : epoch(epoch), sequence(sequence) {}
		} number_t;

		/**
		 * \~russian
		 * @brief Метод разбора заголовка записи поверх дейтаграммы
		 *
		 * @param data   разбираемая область байтов от начала записи до конца дейтаграммы
		 * @param result заголовок, в который помещается итог разбора
		 *
		 * @return       отказ разбора заголовка записи
		 *
		 * @details Первый байт решает вид заголовка: три старших разряда 001 означают
		 *          объединённый заголовок защищённой записи, иное - открытую запись. У
		 *          объединённого заголовка без поля длины содержимым считается весь остаток
		 *          дейтаграммы; заголовок с опознавателем связи отвергается, ибо длина
		 *          опознавателя связи не согласована
		 *
		 * \~english
		 * @brief Method of the parsing of the header of a record over a datagram
		 * @param data   the byte area being parsed from the beginning of the record to the end of the datagram
		 * @param result the header the outcome of the parsing is put into
		 * @return       the failure of the parsing of the header of the record
		 * @details The first byte decides the kind of the header: the three senior bits 001 mean the
		 *          unified header of a protected record, anything else — a plain record. At a unified
		 *          header without the length field the whole rest of the datagram is taken as the
		 *          content; a header with a connection identifier is rejected, because the length of
		 *          the identifier is not negotiated by the connection
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, header_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи заголовка записи поверх дейтаграммы
		 *
		 * @param header записываемый заголовок записи
		 * @param result место, в которое помещается заголовок записи
		 * @param length место, в которое помещается длина записанного заголовка
		 *
		 * @return       отказ записи заголовка записи
		 *
		 * @note Место итога обязано вмещать DATAGRAM_PLAIN_HEADER байтов; объединённый
		 *       заголовок составляется всегда с шестнадцатиразрядным номером и полем длины
		 *
		 * \~english
		 * @brief Method of the writing of the header of a record over a datagram
		 * @param header the header of the record being written
		 * @param result the place the header of the record is put into
		 * @param length the place the length of the written header is put into
		 * @return       the failure of the writing of the header of the record
		 * @note The place of the outcome is obliged to hold DATAGRAM_PLAIN_HEADER bytes; a unified header
		 *       is always composed with a sixteen-bit number and the length field
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const header_t & header, uint8_t * result, size_t & length) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора заголовка записи поверх дейтаграммы по изданию переноса
		 *
		 * @param data   разбираемая область байтов от начала записи до конца дейтаграммы
		 * @param result заголовок, в который помещается итог разбора
		 * @param legacy ведётся ли перенос изданием DTLS 1.2
		 *
		 * @return       отказ разбора заголовка записи
		 *
		 * @details Раздел 4.1 RFC 6347: у издания DTLS 1.2 всякая запись, и защищённая тоже,
		 *          идёт открытым заголовком с видом, изданием, порой, 48-разрядным номером и
		 *          длиной; защищённую выдаёт ненулевая пора. Изданием признаётся 0xFEFD, а
		 *          0xFEFF - лишь у открытой записи рукопожатия: им чужие узлы шлют первое
		 *          приветствие и просьбу о подтверждении адреса; иное - отказ VERSION. Издание
		 *          из заголовка кладётся в поле version как есть. Без признака издания 1.2
		 *          разбор идёт заголовком DTLS 1.3
		 *
		 * \~english
		 * @brief Method of the parsing of the header of a record over a datagram by the edition of the transport
		 * @param data   the byte area being parsed from the beginning of the record to the end of the datagram
		 * @param result the header the outcome of the parsing is put into
		 * @param legacy whether the transport is conducted by the DTLS 1.2 edition
		 * @return       the failure of the parsing of the header of the record
		 * @details The section 4.1 of RFC 6347: at the DTLS 1.2 edition every record, a protected one too,
		 *          goes with a plain header carrying the type, the edition, the epoch, the 48-bit number and
		 *          the length; a protected one is told by a non-zero epoch. 0xFEFD is recognized as the
		 *          edition, and 0xFEFF - only at a plain handshake record: foreign nodes send by it the first
		 *          greeting and the HelloVerifyRequest; anything else is the VERSION failure. The edition from
		 *          the header is put into the version field as is. Without the sign of the 1.2 edition the
		 *          parsing goes by the DTLS 1.3 header
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, header_t & result, const bool legacy) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора заголовка записи с учётом издания DTLS 1.0
		 *
		 * @param data    разбираемая область байтов
		 * @param result  заголовок, в который помещается итог разбора
		 * @param legacy  ведётся ли перенос открытым заголовком (DTLS 1.2 либо 1.0)
		 * @param ancient ведётся ли перенос изданием DTLS 1.0: издание 0xFEFF у всякой записи
		 *
		 * @return        отказ разбора заголовка
		 *
		 * @details RFC 4347: записи издания DTLS 1.0 несут 0xFEFF в заголовке; без признака
		 *          0xFEFF признаётся лишь у открытой записи приветствия (раздел 4.1 RFC 6347)
		 *
		 * \~english
		 * @brief Method of the parsing of the header of a record with regard to the DTLS 1.0 edition
		 * @param data    the area of bytes being parsed
		 * @param result  the header the result of the parsing is put into
		 * @param legacy  whether the transport goes by a plain header (DTLS 1.2 or 1.0)
		 * @param ancient whether the transport goes by the DTLS 1.0 edition: 0xFEFF at every record
		 * @return        the failure of the parsing of the header
		 * @details RFC 4347: the records of the DTLS 1.0 edition carry 0xFEFF in the header; without
		 *          the flag 0xFEFF is recognized only at a plain record of a greeting (the section 4.1 of RFC 6347)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, header_t & result, const bool legacy, const bool ancient) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи заголовка записи поверх дейтаграммы по изданию переноса
		 *
		 * @param header записываемый заголовок записи
		 * @param result место, в которое помещается заголовок записи
		 * @param length место, в которое помещается длина записанного заголовка
		 * @param legacy ведётся ли перенос изданием DTLS 1.2
		 *
		 * @return       отказ записи заголовка записи
		 *
		 * @details Раздел 4.1 RFC 6347: заголовок издания DTLS 1.2 всегда открытый и всегда с
		 *          изданием 0xFEFD; пора берётся из заголовка как есть, а предел длины
		 *          содержимого зависит от неё - 2^14 у нулевой поры, 2^14 + 2048 у защищённой
		 *          (раздел 6.2.3 RFC 5246). Без признака издания 1.2 запись идёт заголовком DTLS 1.3
		 *
		 * @note Место итога обязано вмещать DATAGRAM_PLAIN_HEADER байтов
		 *
		 * \~english
		 * @brief Method of the writing of the header of a record over a datagram by the edition of the transport
		 * @param header the header of the record being written
		 * @param result the place the header of the record is put into
		 * @param length the place the length of the written header is put into
		 * @param legacy whether the transport is conducted by the DTLS 1.2 edition
		 * @return       the failure of the writing of the header of the record
		 * @details The section 4.1 of RFC 6347: the header of the DTLS 1.2 edition is always plain and always
		 *          with the 0xFEFD edition; the epoch is taken from the header as is, and the limit of the
		 *          length of the content depends on it - 2^14 at the zero epoch, 2^14 + 2048 at a protected
		 *          one (the section 6.2.3 of RFC 5246). Without the sign of the 1.2 edition the record goes
		 *          by the DTLS 1.3 header
		 * @note The place of the outcome is obliged to hold DATAGRAM_PLAIN_HEADER bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const header_t & header, uint8_t * result, size_t & length, const bool legacy) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи заголовка записи с учётом издания DTLS 1.0
		 *
		 * @param header  записываемый заголовок
		 * @param result  место, в которое помещается запись заголовка
		 * @param length  место, в которое помещается длина записи заголовка
		 * @param legacy  ведётся ли перенос открытым заголовком
		 * @param ancient ведётся ли перенос изданием DTLS 1.0: в заголовок кладётся 0xFEFF
		 *
		 * @return        отказ записи заголовка
		 *
		 * \~english
		 * @brief Method of the writing of the header of a record with regard to the DTLS 1.0 edition
		 * @param header  the header being written
		 * @param result  the place the record of the header is put into
		 * @param length  the place the length of the record of the header is put into
		 * @param legacy  whether the transport goes by a plain header
		 * @param ancient whether the transport goes by the DTLS 1.0 edition: 0xFEFF is put into the header
		 * @return        the failure of the writing of the header
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const header_t & header, uint8_t * result, size_t & length, const bool legacy, const bool ancient) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора обвязки куска сообщения рукопожатия
		 *
		 * @param data   разбираемая область байтов
		 * @param result обвязка, в которую помещается итог разбора
		 *
		 * @return       отказ разбора обвязки куска
		 *
		 * @details Кусок обязан лежать в пределах сообщения: смещение вместе с длиной не
		 *          превосходят длины сообщения, а сама длина сообщения - предела протокола
		 *
		 * \~english
		 * @brief Method of the parsing of the framing of a fragment of a message of the handshake
		 * @param data   the byte area being parsed
		 * @param result the framing the outcome of the parsing is put into
		 * @return       the failure of the parsing of the framing of the fragment
		 * @details The fragment is obliged to lie within the message: the offset together with the length
		 *          do not exceed the length of the message, and the length of the message itself — the
		 *          limit of the protocol
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, fragment_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи обвязки куска сообщения рукопожатия
		 *
		 * @param fragment записываемая обвязка куска
		 * @param result   место, в которое помещается обвязка куска
		 *
		 * @return         отказ записи обвязки куска
		 *
		 * @note Место итога обязано вмещать DATAGRAM_FRAGMENT_HEADER байтов
		 *
		 * \~english
		 * @brief Method of the writing of the framing of a fragment of a message of the handshake
		 * @param fragment the framing of the fragment being written
		 * @param result   the place the framing of the fragment is put into
		 * @return         the failure of the writing of the framing of the fragment
		 * @note The place of the outcome is obliged to hold DATAGRAM_FRAGMENT_HEADER bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const fragment_t & fragment, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела сообщения подтверждения
		 *
		 * @param data   разбираемое тело сообщения подтверждения
		 * @param result перечень, в который помещаются подтверждённые номера записей
		 *
		 * @return       отказ разбора сообщения подтверждения
		 *
		 * @details Раздел 7 RFC 9147: перечень номеров записей с двухбайтовой длиной
		 *          впереди; пустой перечень законен и означает, что ничего не принято
		 *
		 * \~english
		 * @brief Method of the parsing of the body of an acknowledgement message
		 * @param data   the body of the acknowledgement message being parsed
		 * @param result the list the acknowledged numbers of the records are put into
		 * @return       the failure of the parsing of the acknowledgement message
		 * @details The section 7 of RFC 9147: a list of the numbers of the records with a two-byte length
		 *          ahead; an empty list is lawful and means that nothing has been received
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, vector <number_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела сообщения подтверждения
		 *
		 * @param numbers подтверждаемые номера записей
		 * @param result  накопитель, в который складывается тело сообщения
		 *
		 * @return        отказ составления сообщения подтверждения
		 *
		 * \~english
		 * @brief Method of the composition of the body of an acknowledgement message
		 * @param numbers the numbers of the records being acknowledged
		 * @param result  the accumulator the body of the message is put into
		 * @return        the failure of the composition of the acknowledgement message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const vector <number_t> & numbers, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки маски номера записи
		 *
		 * @param suite  набор шифрования связи
		 * @param key    ключ шифрования номера записи, выведенный меткой «sn»
		 * @param sample образец шифртекста длиной DATAGRAM_SAMPLE байтов
		 * @param result место, в которое помещаются DATAGRAM_MASK байтов маски
		 *
		 * @return       признак успешности выработки маски
		 *
		 * @details Раздел 4.2.3 RFC 9147: у наборов AES маска - первые байты блока AES-ECB
		 *          от образца; у ChaCha20-Poly1305 - первые байты гаммы ChaCha20 со
		 *          счётчиком из первых четырёх байтов образца и одноразовым значением из
		 *          остальных двенадцати. Наборы ГОСТ маски не имеют: DTLS 1.3 их не знает
		 *
		 * \~english
		 * @brief Method of the derivation of the mask of a record number
		 * @param suite  the cipher suite of the connection
		 * @param key    the key of the record number encryption derived by the «sn» label
		 * @param sample the sample of the ciphertext of DATAGRAM_SAMPLE bytes long
		 * @param result the place the DATAGRAM_MASK bytes of the mask are put into
		 * @return       the flag of the success of the derivation of the mask
		 * @details The section 4.2.3 of RFC 9147: at the AES suites the mask is the first bytes of the
		 *          AES-ECB block of the sample; at ChaCha20-Poly1305 — the first bytes of the ChaCha20
		 *          gamma with the counter from the first four bytes of the sample and the nonce from the
		 *          remaining twelve. The GOST suites have no mask: DTLS 1.3 does not know them
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool mask(const protect::suite_t suite, const view_t & key, const uint8_t * sample, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод восстановления полного порядкового номера записи по младшим разрядам
		 *
		 * @param expected ожидаемый порядковый номер: следующий за наибольшим принятым
		 * @param junior   младшие разряды номера, принесённые заголовком
		 * @param bits     число принесённых разрядов: восемь либо шестнадцать
		 *
		 * @return         полный порядковый номер, ближайший к ожидаемому
		 *
		 * @details Раздел 4.2.2 RFC 9147: из всех номеров с такими младшими разрядами
		 *          берётся ближайший к ожидаемому, и лишь на нём пробуется снятие защиты
		 *
		 * \~english
		 * @brief Method of the restoration of the full sequence number of a record by the junior bits
		 * @param expected the expected sequence number: the one following the greatest received
		 * @param junior   the junior bits of the number brought by the header
		 * @param bits     the number of the brought bits: eight or sixteen
		 * @return         the full sequence number closest to the expected one
		 * @details The section 4.2.2 of RFC 9147: of all the numbers with such junior bits the one closest
		 *          to the expected is taken, and the removal of the protection is tried only at it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint64_t restore(const uint64_t expected, const uint64_t junior, const size_t bits) noexcept;
		/**
		 * \~russian
		 * @brief Окно защиты от повторов записей одной поры ключей
		 *
		 * @details Раздел 4.5.1 RFC 9147: окно хранит наибольший принятый номер и разряды
		 *          принятых записей на DATAGRAM_WINDOW номеров позади него. Запись позади
		 *          окна либо уже отмеченная отбрасывается до снятия защиты, а отметка
		 *          ставится лишь после того, как защита снята
		 *
		 * \~english
		 * @brief Anti-replay window of the records of a single epoch
		 * @details The section 4.5.1 of RFC 9147: the window keeps the greatest received number and the
		 *          bits of the received records over DATAGRAM_WINDOW numbers behind it. A record behind
		 *          the window or one already marked is discarded before the removal of the protection,
		 *          while the mark is set only after the protection has been removed
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Window {
			private:
				// Признак того, что хоть одна запись принята
				bool _filled;
			private:
				// Наибольший принятый порядковый номер записи
				uint64_t _top;
				// Разряды принятых записей позади наибольшего номера
				uint64_t _bits;
			public:
				/**
				 * \~russian
				 * @brief Метод получения ожидаемого порядкового номера записи
				 *
				 * @return номер, следующий за наибольшим принятым, ноль до первой записи
				 *
				 * \~english
				 * @brief Method of getting the expected sequence number of a record
				 * @return the number following the greatest received, a zero before the first record
				 *
				 * \~
				 */
				uint64_t expected() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки того, что запись повторная либо позади окна
				 *
				 * @param sequence порядковый номер проверяемой записи
				 *
				 * @return         признак того, что запись отбрасывается
				 *
				 * \~english
				 * @brief Method of checking that a record is a repeated one or behind the window
				 * @param sequence the sequence number of the record being checked
				 * @return         the flag of the record being discarded
				 *
				 * \~
				 */
				bool stale(const uint64_t sequence) const noexcept;
				/**
				 * \~russian
				 * @brief Метод отметки принятой записи
				 *
				 * @param sequence порядковый номер принятой записи
				 *
				 * \~english
				 * @brief Method of the marking of a received record
				 * @param sequence the sequence number of the received record
				 *
				 * \~
				 */
				void mark(const uint64_t sequence) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса окна
				 *
				 * \~english
				 * @brief Method of the reset of the window
				 *
				 * \~
				 */
				void clear() noexcept;
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
				Window() noexcept;
		} window_t;
	};
};

#endif // __ANTS_DATAGRAM__
