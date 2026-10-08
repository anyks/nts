/**
 * @file handshake.hpp
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
 * @brief Заголовочный файл модуля обвязки сообщений рукопожатия протокола TLS — сборка
 *        сообщений из содержимого записей и составление исходящих сообщений
 *
 * \~english
 * @brief Header file of the module of the framing of the messages of the handshake of the TLS
 *        protocol — the assembly of the messages from the content of the records and the
 *        composition of the outgoing messages
 *
 * \~
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
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён обвязки сообщений рукопожатия протокола TLS
	 *
	 * @details Раздел 4 RFC 8446: сообщение рукопожатия несёт свои вид и длину и границам
	 *          записей не подчиняется - оно вправе занимать несколько записей подряд либо
	 *          делить одну запись с соседними сообщениями.
	 *
	 * @note Здесь разбирается только обвязка сообщения: тела сообщений разбираются
	 *       разборщиками своего вида, каждым по своему разделу RFC 8446
	 *
	 * \~english
	 * @brief Namespace of the framing of the messages of the handshake of the TLS protocol
	 * @details The section 4 of RFC 8446: a message of the handshake carries its type and its length
	 *          and does not obey the boundaries of the records — it may occupy several records in a
	 *          row or share a single record with the neighbouring messages.
	 * @note Only the framing of a message is parsed here: the bodies of the messages are parsed by
	 *       the parsers of their type, each by its own section of RFC 8446
	 *
	 * \~
	 */
	namespace handshake {
		/**
		 * \~russian
		 * @brief Размер обвязки сообщения рукопожатия в байтах
		 *
		 * @details Раздел 4 RFC 8446: вид сообщения и его длина тремя байтами
		 *
		 * \~english
		 * @brief Size of the framing of a message of the handshake in bytes
		 * @details The section 4 of RFC 8446: the type of the message and its length by three bytes
		 *
		 * \~
		 */
		static constexpr size_t HANDSHAKE_HEADER = 4;

		/**
		 * \~russian
		 * @brief Наибольшая длина тела сообщения рукопожатия в байтах
		 *
		 * @details Длина сообщения записывается тремя байтами, чем предел и задан
		 *
		 * \~english
		 * @brief Greatest length of the body of a message of the handshake in bytes
		 * @details The length of a message is written by three bytes, which is what the limit is set by
		 *
		 * \~
		 */
		static constexpr size_t HANDSHAKE_LIMIT = 0xFFFFFF;

		/**
		 * \~russian
		 * @brief Отказы обвязки сообщений рукопожатия
		 *
		 * \~english
		 * @brief Failures of the framing of the messages of the handshake
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY = 0x01, /*!< \~russian Данных для целого сообщения ещё не набралось \~english The data for a whole message has not accumulated yet \~ */
			TYPE   = 0x02, /*!< \~russian Вид сообщения рукопожатия протоколом не определён \~english The type of the message of the handshake is not defined by the protocol \~ */
			LENGTH = 0x03, /*!< \~russian Длина тела сообщения превышает дозволенную \~english The length of the body of the message exceeds the allowed one \~ */
			MEMORY = 0x04  /*!< \~russian Памяти под накопитель не хватило \~english There was not enough memory for the accumulator \~ */
		};

		/**
		 * \~russian
		 * @brief Виды сообщений рукопожатия
		 *
		 * @details Раздел 4 RFC 8446: перечисление HandshakeType; сжатая цепочка
		 *          сертификатов добавлена разделом 4 RFC 8879; виды издания TLS 1.2, в
		 *          том числе просьба о пересогласовании HelloRequest, - разделом 7.4 RFC 5246
		 *
		 * \~english
		 * @brief Types of the messages of the handshake
		 * @details The section 4 of RFC 8446: the HandshakeType enumeration; the compressed chain of
		 *          the certificates is added by the section 4 of RFC 8879; the types of the TLS 1.2
		 *          edition, the HelloRequest of the renegotiation among them, - by the section 7.4 of RFC 5246
		 *
		 * \~
		 */
		enum class type_t : uint8_t {
			HELLO_REQUEST = 0x00, /*!< \~russian Просьба о пересогласовании HelloRequest (раздел 7.4.1.1 RFC 5246, TLS 1.2): на проводе несёт ноль \~english The HelloRequest of the renegotiation (the section 7.4.1.1 of RFC 5246, TLS 1.2): carries zero on the wire \~ */
			VERIFY_REQUEST = 0x03, /*!< \~russian Просьба о подтверждении адреса HelloVerifyRequest (раздел 4.2.1 RFC 6347, DTLS 1.2): издание и метка возврата состояния \~english The HelloVerifyRequest of the address confirmation (the section 4.2.1 of RFC 6347, DTLS 1.2): the edition and the cookie \~ */
			CLIENT        = 0x01, /*!< \~russian Приветствие клиента \~english The greeting of the client \~ */
			SERVER        = 0x02, /*!< \~russian Приветствие сервера \~english The greeting of the server \~ */
			TICKET        = 0x04, /*!< \~russian Билет на возобновление связи \~english The ticket for the resumption of the connection \~ */
			EARLY         = 0x05, /*!< \~russian Конец упреждающих данных \~english The end of the early data \~ */
			EXTENSIONS    = 0x08, /*!< \~russian Защищённые расширения \~english The encrypted extensions \~ */
			CERTIFICATE   = 0x0B, /*!< \~russian Цепочка сертификатов \~english The chain of the certificates \~ */
			AGREEMENT     = 0x0C, /*!< \~russian Обмен ключами сервера ServerKeyExchange (раздел 7.4.3 RFC 5246, TLS 1.2) \~english The ServerKeyExchange of the server (the section 7.4.3 of RFC 5246, TLS 1.2) \~ */
			REQUEST       = 0x0D, /*!< \~russian Запрос сертификата собеседника \~english The request of the certificate of the peer \~ */
			DONE          = 0x0E, /*!< \~russian Конец приветствия сервера ServerHelloDone (раздел 7.4.5 RFC 5246, TLS 1.2) \~english The ServerHelloDone of the server (the section 7.4.5 of RFC 5246, TLS 1.2) \~ */
			VERIFY        = 0x0F, /*!< \~russian Подпись владения ключом сертификата \~english The signature of the possession of the key of the certificate \~ */
			PREMASTER     = 0x10, /*!< \~russian Обмен ключами клиента ClientKeyExchange (раздел 7.4.7 RFC 5246, TLS 1.2) \~english The ClientKeyExchange of the client (the section 7.4.7 of RFC 5246, TLS 1.2) \~ */
			FINISHED      = 0x14, /*!< \~russian Завершение рукопожатия \~english The completion of the handshake \~ */
			STATUS        = 0x16, /*!< \~russian Состояние сертификата CertificateStatus (раздел 8 RFC 6066, TLS 1.2) \~english The CertificateStatus (the section 8 of RFC 6066, TLS 1.2) \~ */
			UPDATE        = 0x18, /*!< \~russian Смена ключевого материала связи \~english The change of the key material of the connection \~ */
			COMPRESSED    = 0x19, /*!< \~russian Сжатая цепочка сертификатов по RFC 8879 \~english The compressed chain of the certificates by RFC 8879 \~ */
			NEXT_PROTOCOL = 0x43, /*!< \~russian Выбранный протокол NextProtocol выработки NPN (draft-agl-tls-nextprotoneg, TLS 1.2) \~english The NextProtocol of the NPN negotiation (draft-agl-tls-nextprotoneg, TLS 1.2) \~ */
			DIGEST        = 0xFE, /*!< \~russian Хеш приветствия клиента вместо него самого \~english The hash of the greeting of the client instead of it itself \~ */
			NONE          = 0xFF  /*!< \~russian Вид сообщения не установлен: значение вне реестра видов и с проводным видом не совпадает \~english The type of the message is not set: a value outside the registry of the types, coinciding with no type on the wire \~ */
		};

		/**
		 * \~russian
		 * @brief Обвязка сообщения рукопожатия
		 *
		 * \~english
		 * @brief Framing of a message of the handshake
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Header {
			// Вид сообщения рукопожатия
			type_t type;
			// Длина тела сообщения рукопожатия в байтах
			size_t size;
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
			Header() noexcept : type(type_t::NONE), size(0) {}
		} header_t;

		/**
		 * \~russian
		 * @brief Метод разбора обвязки сообщения рукопожатия
		 *
		 * @param data   разбираемая область байтов
		 * @param result обвязка, в которую помещается итог разбора
		 *
		 * @return       отказ разбора обвязки сообщения
		 *
		 * \~english
		 * @brief Method of the parsing of the framing of a message of the handshake
		 * @param data   the byte area being parsed
		 * @param result the framing the outcome of the parsing is put into
		 * @return       the failure of the parsing of the framing of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, header_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи обвязки сообщения рукопожатия
		 *
		 * @param header записываемая обвязка сообщения
		 * @param result место, в которое помещается обвязка сообщения
		 *
		 * @return       отказ записи обвязки сообщения
		 *
		 * @note Место итога обязано вмещать HANDSHAKE_HEADER байтов
		 *
		 * \~english
		 * @brief Method of the writing of the framing of a message of the handshake
		 * @param header the framing of the message being written
		 * @param result the place the framing of the message is put into
		 * @return       the failure of the writing of the framing of the message
		 * @note The place of the outcome is obliged to hold HANDSHAKE_HEADER bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const header_t & header, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки известности вида сообщения рукопожатия
		 *
		 * @param type проверяемый вид сообщения рукопожатия
		 *
		 * @return     признак того, что вид сообщения определён протоколом
		 *
		 * \~english
		 * @brief Method of the checking of the knownness of the type of a message of the handshake
		 * @param type the type of the message of the handshake being checked
		 * @return     the flag of the type of the message being defined by the protocol
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool known(const type_t type) noexcept;
		/**
		 * \~russian
		 * @brief Сборщик входящих сообщений рукопожатия
		 *
		 * @details Содержимое записей рукопожатия подаётся вызовом push в том порядке, в
		 *          каком его выдал слой записей, а собранные сообщения забираются вызовом
		 *          next до тех пор, пока тот не ответит отказом HUNGRY
		 *
		 * \~english
		 * @brief Assembler of the incoming messages of the handshake
		 * @details The content of the records of the handshake is supplied by a call of push in the
		 *          order in which the record layer has produced it, while the assembled messages are
		 *          taken by a call of next until it answers with the HUNGRY failure
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Reader {
			private:
				// Смещение начала неразобранных данных в накопителе
				size_t _offset;
			private:
				// Длина сообщения, выданного последним вызовом получения
				size_t _length;
			private:
				// Предел длины тела принимаемого сообщения
				size_t _limit;
			private:
				// Накопитель принятых, но ещё не разобранных данных
				vector <uint8_t> _buffer;
			public:
				/**
				 * \~russian
				 * @brief Метод получения предела длины тела принимаемого сообщения
				 *
				 * @return предел длины тела сообщения в байтах
				 *
				 * \~english
				 * @brief Method of getting the limit of the length of the body of a message being received
				 * @return the limit of the length of the body of a message in bytes
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предела длины тела принимаемого сообщения
				 *
				 * @param limit устанавливаемый предел длины тела сообщения в байтах
				 *
				 * @return      признак успешности установки предела
				 *
				 * @details Умолчанием берётся предел самого протокола. Опускают его затем, что
				 *          сообщение рукопожатия накапливается целиком до первого своего разбора:
				 *          собеседник, объявивший цепочку сертификатов в шестнадцать мегабайтов,
				 *          иначе занял бы эти шестнадцать мегабайтов
				 *
				 * \~english
				 * @brief Method of setting the limit of the length of the body of a message being received
				 * @param limit the limit of the length of the body of a message in bytes being set
				 * @return      the flag of the success of the setting of the limit
				 * @details The limit of the protocol itself is taken as the default. It is lowered because a
				 *          message of the handshake is accumulated as a whole before its first parsing: a peer
				 *          which has announced a chain of the certificates of sixteen megabytes would otherwise
				 *          occupy these sixteen megabytes
				 *
				 * \~
				 */
				bool limit(const size_t limit) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения объёма ещё не разобранных данных
				 *
				 * @return объём ещё не разобранных данных в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the data not parsed yet
				 * @return the volume of the data not parsed yet in bytes
				 *
				 * \~
				 */
				size_t pending() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения последнего собранного сообщения целиком
				 *
				 * @return просмотр собранного сообщения вместе с его обвязкой
				 *
				 * @details Хеш переписки рукопожатия по разделу 4.4.1 RFC 8446 берётся от сообщений
				 *          вместе с их обвязкой, оттого выдаётся и она
				 *
				 * @note Просмотр действителен до следующего вызова push, next или clear
				 *
				 * \~english
				 * @brief Method of getting the last assembled message as a whole
				 * @return the view of the assembled message together with its framing
				 * @details The hash of the transcript of the handshake by the section 4.4.1 of RFC 8446 is
				 *          taken from the messages together with their framing, hence it is produced as well
				 * @note The view is valid until the next call of push, next or clear
				 *
				 * \~
				 */
				view_t message() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния сборщика
				 *
				 * \~english
				 * @brief Method of the reset of the state of the assembler
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи содержимого принятой записи рукопожатия
				 *
				 * @param data подаваемое содержимое записи рукопожатия
				 *
				 * @return     отказ подачи содержимого записи
				 *
				 * \~english
				 * @brief Method of the supply of the content of a received record of the handshake
				 * @param data the content of the record of the handshake being supplied
				 * @return     the failure of the supply of the content of the record
				 *
				 * \~
				 */
				error_t push(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения очередного собранного сообщения
				 *
				 * @param header  обвязка, в которую помещается обвязка собранного сообщения
				 * @param payload просмотр, в который помещается тело собранного сообщения
				 *
				 * @return        отказ получения собранного сообщения
				 *
				 * @note Просмотр тела действителен до следующего вызова push, next или clear
				 *
				 * \~english
				 * @brief Method of getting the next assembled message
				 * @param header  the framing the framing of the assembled message is put into
				 * @param payload the view the body of the assembled message is put into
				 * @return        the failure of the getting of the assembled message
				 * @note The view of the body is valid until the next call of push, next or clear
				 *
				 * \~
				 */
				error_t next(header_t & header, view_t & payload) noexcept;
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
				Reader() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Reader() noexcept;
		} reader_t;
		/**
		 * \~russian
		 * @brief Составитель исходящих сообщений рукопожатия
		 *
		 * @details Составленные сообщения складываются в накопитель подряд и оттуда
		 *          передаются слою записей, который сам решает, как разложить их по записям
		 *
		 * \~english
		 * @brief Composer of the outgoing messages of the handshake
		 * @details The composed messages are put into the accumulator in a row and from there are
		 *          passed to the record layer, which itself decides how to lay them out over the records
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Writer {
			private:
				// Накопитель составленных сообщений
				vector <uint8_t> _buffer;
			public:
				/**
				 * \~russian
				 * @brief Метод получения объёма составленных сообщений
				 *
				 * @return объём составленных сообщений в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the composed messages
				 * @return the volume of the composed messages in bytes
				 *
				 * \~
				 */
				size_t pending() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения составленных сообщений
				 *
				 * @return просмотр составленных сообщений
				 *
				 * @note Просмотр действителен до следующего вызова push либо clear
				 *
				 * \~english
				 * @brief Method of getting the composed messages
				 * @return the view of the composed messages
				 * @note The view is valid until the next call of push or clear
				 *
				 * \~
				 */
				view_t data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса накопителя составленных сообщений
				 *
				 * \~english
				 * @brief Method of the reset of the accumulator of the composed messages
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод составления сообщения рукопожатия
				 *
				 * @param type вид составляемого сообщения рукопожатия
				 * @param data тело составляемого сообщения рукопожатия
				 *
				 * @return     отказ составления сообщения рукопожатия
				 *
				 * \~english
				 * @brief Method of the composition of a message of the handshake
				 * @param type the type of the message of the handshake being composed
				 * @param data the body of the message of the handshake being composed
				 * @return     the failure of the composition of the message of the handshake
				 *
				 * \~
				 */
				error_t push(const type_t type, const view_t & data) noexcept;
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
				Writer() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Writer() noexcept;
		} writer_t;
	};
};

