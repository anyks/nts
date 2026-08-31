/**
 * @file message.hpp
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
 * @brief Заголовочный файл модуля сообщений подтверждения подлинности протокола TLS —
 *        цепочки сертификатов, подписи владения ключом и завершения рукопожатия
 *
 * \~english
 * @brief Header file of the module of the messages of the authentication of the TLS protocol —
 *        the chains of the certificates, the signature of the possession of the key and the
 *        completion of the handshake
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_MESSAGE__
#define __ANTS_MESSAGE__

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
#include <hello/hello.hpp>
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
namespace anyks {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён сообщений подтверждения подлинности протокола TLS
	 *
	 * @details Разделы 4.4.2, 4.4.3 и 4.4.4 RFC 8446: тремя этими сообщениями сторона
	 *          доказывает, что она та, за кого себя выдаёт. Сертификатом она называет свой
	 *          открытый ключ, подписью владения - доказывает владение закрытым, а
	 *          завершением рукопожатия - что обе стороны видели одну и ту же переписку.
	 *
	 * \~english
	 * @brief Namespace of the messages of the authentication of the TLS protocol
	 * @details The sections 4.4.2, 4.4.3 and 4.4.4 of RFC 8446: by these three messages a party proves
	 *          that it is the one it claims to be. By the certificate it names its public key, by the
	 *          signature of the possession it proves the possession of the private one, and by the
	 *          completion of the handshake — that both parties have seen one and the same transcript.
	 *
	 * \~
	 */
	namespace message {
		/**
		 * \~russian
		 * @brief Отказы разбора и составления сообщений подтверждения подлинности
		 *
		 * \~english
		 * @brief Failures of the parsing and of the composition of the messages of the authentication
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY    = 0x01, /*!< \~russian Тело сообщения оборвано посреди поля \~english The body of the message is cut off in the middle of a field \~ */
			TRAILING  = 0x02, /*!< \~russian За телом сообщения идут лишние байты \~english There are extra bytes behind the body of the message \~ */
			EMPTY     = 0x03, /*!< \~russian Обязательное поле сообщения пусто \~english A mandatory field of the message is empty \~ */
			EXTENSION = 0x04, /*!< \~russian Расширение записи оборвано либо объявлено дважды \~english An extension of the record is cut off or is declared twice \~ */
			LENGTH    = 0x05, /*!< \~russian Составляемое поле в свою длину не входит \~english A field being composed does not fit into its length \~ */
			DIGEST    = 0x06, /*!< \~russian Выработать имитовставку завершения не удалось \~english It was not possible to produce the authentication code of the completion \~ */
			MEMORY    = 0x07  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Запись цепочки сертификатов
		 *
		 * @details Раздел 4.4.2 RFC 8446: всякая запись цепочки несёт сертификат и свои
		 *          расширения, относящиеся именно к нему
		 *
		 * @note Тело сертификата смотрит внутрь разобранного сообщения
		 *
		 * \~english
		 * @brief Record of a chain of the certificates
		 * @details The section 4.4.2 of RFC 8446: every record of the chain carries a certificate and its
		 *          own extensions relating exactly to it
		 * @note The body of the certificate looks inside the parsed message
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Entry {
			// Тело сертификата записи цепочки
			view_t data;
			// Перечень расширений записи цепочки
			vector <hello::extension_t> extensions;
		} entry_t;

		/**
		 * \~russian
		 * @brief Сообщение цепочки сертификатов
		 *
		 * @details Раздел 4.4.2 RFC 8446
		 *
		 * \~english
		 * @brief Message of a chain of the certificates
		 * @details The section 4.4.2 of RFC 8446
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Certificate {
			// Привязка цепочки к запросу сертификата собеседником
			view_t context;
			// Записи цепочки сертификатов
			vector <entry_t> entries;
		} certificate_t;

		/**
		 * \~russian
		 * @brief Сообщение подписи владения ключом сертификата
		 *
		 * @details Раздел 4.4.3 RFC 8446
		 *
		 * @note Подпись здесь записана так, как её велит записывать раздел 5.3 описания
		 *       наборов шифрования на алгоритмах ГОСТ: обе половины идут младшим разрядом
		 *       вперёд, тогда как модуль подписи работает с обратной записью
		 *
		 * \~english
		 * @brief Message of the signature of the possession of the key of the certificate
		 * @details The section 4.4.3 of RFC 8446
		 * @note The signature here is written the way the section 5.3 of the description of the cipher
		 *       suites on the GOST algorithms orders to write it: both halves go with the least
		 *       significant bit ahead, whereas the module of the signature works with the reverse notation
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Verify {
			// Схема подписи владения ключом сертификата
			extension::scheme_t scheme;
			// Значение подписи владения ключом сертификата
			view_t signature;
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
			Verify() noexcept : scheme(extension::scheme_t::NONE) {}
		} verify_t;

		/**
		 * \~russian
		 * @brief Билет возобновления связи
		 *
		 * @details Раздел 4.6.1 RFC 8446: сервер выдаёт билет за рукопожатием, а клиент
		 *          предъявляет его будущей связи вместо полного обмена ключами
		 *
		 * @note Значения билета смотрят внутрь разобранного сообщения
		 *
		 * \~english
		 * @brief Ticket of the resumption of a connection
		 * @details The section 4.6.1 of RFC 8446: the server issues a ticket after the handshake, and the
		 *          client presents it to a future connection instead of a full key exchange
		 * @note The values of the ticket look inside the parsed message
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Ticket {
			// Срок жизни билета в секундах
			uint32_t lifetime;
			// Добавка к возрасту билета, скрывающая его от посторонних
			uint32_t age;
			// Неповторимое значение билета, разводящее ключи билетов одной связи
			view_t nonce;
			// Тело билета, опознающее связь для выдавшего его сервера
			view_t data;
			// Перечень расширений билета
			vector <hello::extension_t> extensions;
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
			Ticket() noexcept : lifetime(0), age(0) {}
		} ticket_t;

		/**
		 * \~russian
		 * @brief Виды смены ключевого материала связи
		 *
		 * @details Раздел 4.6.3 RFC 8446: перечисление KeyUpdateRequest
		 *
		 * \~english
		 * @brief Types of the change of the key material of a connection
		 * @details The section 4.6.3 of RFC 8446: the KeyUpdateRequest enumeration
		 *
		 * \~
		 */
		enum class update_t : uint8_t {
			NOTIFY  = 0x00, /*!< \~russian Сторона сменила ключи своего направления связи \~english The side has changed the keys of its direction of the connection \~ */
			REQUEST = 0x01  /*!< \~russian Сторона просит собеседника сменить свои ключи в ответ \~english The side asks the interlocutor to change their keys in return \~ */
		};

		/**
		 * \~russian
		 * @brief Метод разбора тела сообщения цепочки сертификатов
		 *
		 * @param data   разбираемое тело сообщения
		 * @param result сообщение, в которое помещается итог разбора
		 *
		 * @return       отказ разбора тела сообщения
		 *
		 * \~english
		 * @brief Method of the parsing of the body of the message of a chain of the certificates
		 * @param data   the body of the message being parsed
		 * @param result the message the outcome of the parsing is put into
		 * @return       the failure of the parsing of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, certificate_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела сообщения цепочки сертификатов
		 *
		 * @param message составляемое сообщение цепочки сертификатов
		 * @param result  накопитель, в конец которого дописывается тело сообщения
		 *
		 * @return        отказ составления тела сообщения
		 *
		 * \~english
		 * @brief Method of the composition of the body of the message of a chain of the certificates
		 * @param message the message of the chain of the certificates being composed
		 * @param result  the accumulator the body of the message is appended to the end of
		 * @return        the failure of the composition of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const certificate_t & message, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела сообщения подписи владения ключом
		 *
		 * @param data   разбираемое тело сообщения
		 * @param result сообщение, в которое помещается итог разбора
		 *
		 * @return       отказ разбора тела сообщения
		 *
		 * \~english
		 * @brief Method of the parsing of the body of the message of the signature of the possession of the key
		 * @param data   the body of the message being parsed
		 * @param result the message the outcome of the parsing is put into
		 * @return       the failure of the parsing of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, verify_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела сообщения подписи владения ключом
		 *
		 * @param message составляемое сообщение подписи владения ключом
		 * @param result  накопитель, в конец которого дописывается тело сообщения
		 *
		 * @return        отказ составления тела сообщения
		 *
		 * \~english
		 * @brief Method of the composition of the body of the message of the signature of the possession of the key
		 * @param message the message of the signature of the possession of the key being composed
		 * @param result  the accumulator the body of the message is appended to the end of
		 * @return        the failure of the composition of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const verify_t & message, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод обращения записи подписи владения ключом
		 *
		 * @param signature обращаемая подпись владения ключом
		 * @param result    место, в которое помещается обращённая подпись
		 *
		 * @return          отказ обращения записи подписи
		 *
		 * @details Раздел 5.3 описания наборов шифрования на алгоритмах ГОСТ записывает обе
		 *          половины подписи младшим разрядом вперёд, а модуль подписи работает с
		 *          обратной записью. Обращение это само себе обратно: тем же вызовом подпись
		 *          переводится и в ту, и в другую сторону
		 *
		 * @note Место итога обязано вмещать подпись целиком, а длина её обязана быть чётной
		 *
		 * \~english
		 * @brief Method of the reversal of the notation of the signature of the possession of the key
		 * @param signature the signature of the possession of the key being reversed
		 * @param result    the place the reversed signature is put into
		 * @return          the failure of the reversal of the notation of the signature
		 * @details The section 5.3 of the description of the cipher suites on the GOST algorithms writes
		 *          both halves of the signature with the least significant bit ahead, whereas the module
		 *          of the signature works with the reverse notation. This reversal is its own inverse: by
		 *          the same call the signature is translated in both directions
		 * @note The place of the outcome is obliged to hold the whole signature, and its length is obliged
		 *       to be even
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t reverse(const view_t & signature, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления подписываемого содержимого владения ключом
		 *
		 * @param transcript хеш переписки рукопожатия на миг подписания
		 * @param server     признак того, что подпись составляется сервером
		 * @param result     накопитель, в конец которого дописывается подписываемое содержимое
		 *
		 * @return           отказ составления подписываемого содержимого
		 *
		 * @details Раздел 4.4.3 RFC 8446: подписывается не хеш переписки сам по себе, а
		 *          запись из шестидесяти четырёх пробелов, названия назначения подписи, нуля
		 *          и хеша переписки. Пробелами отделяется подпись рукопожатия от подписей
		 *          предыдущих изданий протокола, а названием - подпись клиента от подписи
		 *          сервера: одну нельзя выдать за другую
		 *
		 * \~english
		 * @brief Method of the composition of the content being signed of the possession of the key
		 * @param transcript the hash of the transcript of the handshake at the moment of the signing
		 * @param server     the flag of the signature being composed by the server
		 * @param result     the accumulator the content being signed is appended to the end of
		 * @return           the failure of the composition of the content being signed
		 * @details The section 4.4.3 of RFC 8446: not the hash of the transcript by itself is signed, but a
		 *          record of sixty four spaces, of the name of the purpose of the signature, of a zero and
		 *          of the hash of the transcript. By the spaces the signature of the handshake is separated
		 *          from the signatures of the previous editions of the protocol, and by the name — the
		 *          signature of the client from the signature of the server: one may not be passed for the other
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t content(const view_t & transcript, const bool server, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки тела сообщения завершения рукопожатия
		 *
		 * @param secret     ключ выработки завершения рукопожатия
		 * @param transcript хеш переписки рукопожатия на миг завершения
		 * @param result     место, в которое помещается тело сообщения
		 *
		 * @return           отказ выработки тела сообщения
		 *
		 * @details Раздел 4.4.4 RFC 8446: телом сообщения служит имитовставка от хеша
		 *          переписки, выработанная на ключе завершения. Ключ этот выводится
		 *          расписанием ключей меткою «finished» из значения направления связи
		 *
		 * @note Место итога обязано вмещать длину хеша
		 *
		 * \~english
		 * @brief Method of the production of the body of the message of the completion of the handshake
		 * @param secret     the key of the production of the completion of the handshake
		 * @param transcript the hash of the transcript of the handshake at the moment of the completion
		 * @param result     the place the body of the message is put into
		 * @return           the failure of the production of the body of the message
		 * @details The section 4.4.4 of RFC 8446: an authentication code from the hash of the transcript
		 *          produced under the key of the completion serves as the body of the message. This key is
		 *          derived by the key schedule by the «finished» label from the value of the direction of
		 *          the connection
		 * @note The place of the outcome is obliged to hold the length of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t finished(const view_t & secret, const view_t & transcript, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сличения тел сообщений завершения рукопожатия
		 *
		 * @param first  первое сличаемое тело сообщения
		 * @param second второе сличаемое тело сообщения
		 *
		 * @return       признак схождения сличаемых тел сообщений
		 *
		 * @details Сличение ведётся за постоянное время: время сличения не выдаёт, сколько
		 *          байтов у принятого завершения сошлось, и подобрать завершение по одному
		 *          байту за раз оттого нельзя
		 *
		 * \~english
		 * @brief Method of the comparison of the bodies of the messages of the completion of the handshake
		 * @param first  the first body of the message being compared
		 * @param second the second body of the message being compared
		 * @return       the flag of the coincidence of the bodies of the messages being compared
		 * @details The comparison is conducted in a constant time: the time of the comparison does not
		 *          reveal how many bytes of a received completion have matched, and hence it is not
		 *          possible to guess the completion one byte at a time
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool compare(const view_t & first, const view_t & second) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела сообщения смены ключевого материала
		 *
		 * @param data   разбираемое тело сообщения
		 * @param result вид смены, в который помещается итог разбора
		 *
		 * @return       отказ разбора тела сообщения
		 *
		 * @note Вид смены, протоколом не определённый, отвергается: раздел 4.6.3 RFC 8446
		 *       велит рвать по нему связь, а не толковать его наугад
		 *
		 * \~english
		 * @brief Method of the parsing of the body of the message of the change of the key material
		 * @param data   the body of the message being parsed
		 * @param result the type of the change the outcome of the parsing is put into
		 * @return       the failure of the parsing of the body of the message
		 * @note A type of the change not defined by the protocol is rejected: the section 4.6.3 of
		 *       RFC 8446 orders to tear the connection by it and not to interpret it by a guess
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, update_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела сообщения смены ключевого материала
		 *
		 * @param update составляемый вид смены ключевого материала
		 * @param result накопитель, в который складывается тело сообщения
		 *
		 * @return       отказ составления тела сообщения
		 *
		 * \~english
		 * @brief Method of the composition of the body of the message of the change of the key material
		 * @param update the type of the change of the key material being composed
		 * @param result the accumulator the body of the message is put into
		 * @return       the failure of the composition of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const update_t update, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела сообщения билета возобновления связи
		 *
		 * @param data   разбираемое тело сообщения
		 * @param result билет, в который помещается итог разбора
		 *
		 * @return       отказ разбора тела сообщения
		 *
		 * \~english
		 * @brief Method of the parsing of the body of the message of a ticket of the resumption
		 * @param data   the body of the message being parsed
		 * @param result the ticket the outcome of the parsing is put into
		 * @return       the failure of the parsing of the body of the message
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, ticket_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела сообщения билета возобновления связи
		 *
		 * @param ticket составляемый билет возобновления связи
		 * @param result накопитель, в который складывается тело сообщения
		 *
		 * @return       отказ составления тела сообщения
		 *
		 * @note Пустое тело билета отвергается: раздел 4.6.1 RFC 8446 велит билету занимать
		 *       хотя бы один байт, а опознать связь по пустому билету всё равно нечем
		 *
		 * \~english
		 * @brief Method of the composition of the body of the message of a ticket of the resumption
		 * @param ticket the ticket of the resumption being composed
		 * @param result the accumulator the body of the message is put into
		 * @return       the failure of the composition of the body of the message
		 * @note An empty body of a ticket is rejected: the section 4.6.1 of RFC 8446 orders a ticket to
		 *       occupy at least one byte, and there is nothing to identify a connection by an empty
		 *       ticket anyway
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const ticket_t & ticket, vector <uint8_t> & result) noexcept;
	};
};

#endif // __ANTS_MESSAGE__
