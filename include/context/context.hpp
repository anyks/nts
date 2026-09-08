/**
 * @file context.hpp
 * @date 2026-08-30
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
 * @brief Заголовочный файл общих объявлений фасадов связи — состояние связи, отказы
 *        и подлинность стороны, предъявляемая собеседнику
 *
 * \~english
 * @brief Header file of the common declarations of the facades of a connection — the state of
 *        the connection, the failures and the authenticity of a side presented to the interlocutor
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_CONTEXT__
#define __ANTS_CONTEXT__

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
#include <alert/alert.hpp>
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
	 * @brief Пространство имён общих объявлений фасадов связи
	 *
	 * @details Фасады клиента и сервера ведут одну и ту же связь с разных её концов, и
	 *          состояние, отказы и подлинность у них общие: расходятся лишь порядок
	 *          сообщений да настройки, которые всякой роли доступны
	 *
	 * @note Связь не занимается вводом и выводом вовсе: принятые байты подаются ей
	 *       вызовом, а отправляемые она складывает в накопитель. Откуда байты пришли
	 *       и куда уйдут - дело того, кто связь ведёт
	 *
	 * \~english
	 * @brief Namespace of the common declarations of the facades of a connection
	 * @details The facades of the client and of the server lead one and the same connection from
	 *          the different ends of it, and the state, the failures and the authenticity are common
	 *          to them: only the order of the messages and the settings available to every role differ
	 * @note The connection does not deal with the input and the output at all: the received bytes are
	 *       given to it by a call, and it puts the sent ones into an accumulator. Where the bytes came
	 *       from and where they will go is the business of the one who leads the connection
	 *
	 * \~
	 */
	namespace context {
		/**
		 * \~russian
		 * @brief Отказы связи
		 *
		 * \~english
		 * @brief Failures of a connection
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE       = 0x01, /*!< \~russian Вызов сделан не в том состоянии связи \~english The call is made in a wrong state of the connection \~ */
			SETTINGS    = 0x02, /*!< \~russian Настроек для заведения связи не хватает \~english There are not enough settings for the establishment of the connection \~ */
			MEMORY      = 0x03, /*!< \~russian Памяти под накопитель не хватило \~english There was not enough memory for the accumulator \~ */
			RECORD      = 0x04, /*!< \~russian Запись протокола сложена не по правилам \~english A record of the protocol is composed not by the rules \~ */
			PROTECTION  = 0x05, /*!< \~russian Защиту записи наложить либо снять не удалось \~english It was not possible to impose or to remove the protection of a record \~ */
			MESSAGE     = 0x06, /*!< \~russian Сообщение рукопожатия разобрать не удалось \~english It was not possible to parse a message of the handshake \~ */
			ORDER       = 0x07, /*!< \~russian Сообщение рукопожатия пришло не в свой черёд \~english A message of the handshake came out of its turn \~ */
			VERSION     = 0x08, /*!< \~russian Издание протокола собеседником не поддержано \~english The edition of the protocol is not supported by the interlocutor \~ */
			SUITE       = 0x09, /*!< \~russian Общего набора шифрования у сторон не нашлось \~english The sides have not found a common cipher suite \~ */
			GROUP       = 0x0A, /*!< \~russian Общей кривой обмена ключами у сторон не нашлось \~english The sides have not found a common curve of the key exchange \~ */
			EXCHANGE    = 0x0B, /*!< \~russian Общее значение обмена ключами выработать не удалось \~english It was not possible to produce the shared value of the key exchange \~ */
			SCHEDULE    = 0x0C, /*!< \~russian Ключевой материал связи вывести не удалось \~english It was not possible to derive the key material of the connection \~ */
			CERTIFICATE = 0x0D, /*!< \~russian Цепочка сертификатов собеседника непригодна \~english The chain of the certificates of the interlocutor is unsuitable \~ */
			SIGNATURE   = 0x0E, /*!< \~russian Подпись владения ключом не сошлась \~english The signature of the possession of the key has not matched \~ */
			COMPLETION  = 0x0F, /*!< \~russian Завершение рукопожатия собеседника не сошлось \~english The completion of the handshake of the interlocutor has not matched \~ */
			ALERT       = 0x10, /*!< \~russian Собеседник оборвал связь извещением \~english The interlocutor has torn the connection by an alert \~ */
			CLOSED      = 0x11, /*!< \~russian Связь уже закрыта \~english The connection is already closed \~ */
			PROTOCOL    = 0x12, /*!< \~russian Общего прикладного протокола у сторон не нашлось \~english The sides have not found a common application protocol \~ */
			LIMIT       = 0x13, /*!< \~russian Упреждающие данные вышли за объявленный билетом предел \~english The early data has gone beyond the limit declared by the ticket \~ */
			SCHEME      = 0x14, /*!< \~russian Схема подписи собеседника связью не предлагалась \~english The signature scheme of the interlocutor was not offered by the connection \~ */
			EXTENSION   = 0x15, /*!< \~russian Собеседник объявил расширение, связью не предлагавшееся \~english The interlocutor announced an extension that was not offered by the connection \~ */
			LEVEL       = 0x16, /*!< \~russian Сообщение подано не на своём уровне защиты либо не тем способом переноса \~english A message is given not at its protection level or not by its transport \~ */
			PARAMETERS  = 0x17, /*!< \~russian Параметры переноса QUIC отсутствуют там, где обязательны, либо пришли туда, где запрещены \~english The QUIC transport parameters are absent where mandatory or came where forbidden \~ */
			TICKET      = 0x18, /*!< \~russian Запись билета возобновления сложена не по правилам \~english A record of a ticket of the resumption is composed not by the rules \~ */
			COMPRESSION = 0x19, /*!< \~russian Цепочка сертификатов сжата алгоритмом, связью не объявлявшимся \~english The chain of the certificates is compressed by an algorithm not announced by the connection \~ */
			STATUS      = 0x1A, /*!< \~russian Ответ о состоянии сертификата собеседника негоден либо сертификат отозван \~english The certificate status response of the interlocutor is unsuitable or the certificate is revoked \~ */
			TIMEOUT     = 0x1B, /*!< \~russian Попытки повторной передачи поверх дейтаграмм исчерпаны \~english The attempts of the retransmission over datagrams are exhausted \~ */
			MASTER      = 0x1C, /*!< \~russian Собеседник по TLS 1.2 не поддерживает расширенный главный секрет RFC 7627 \~english The TLS 1.2 interlocutor does not support the extended master secret of RFC 7627 \~ */
			RENEGOTIATION = 0x1D, /*!< \~russian Собеседник по TLS 1.2 затеял пересогласование, связью не дозволенное \~english The TLS 1.2 interlocutor has started a renegotiation not allowed by the connection \~ */
			EXHAUSTED   = 0x1E, /*!< \~russian Записи своего направления по TLS 1.2 исчерпали предел ключа: смены ключей у издания нет, связь закрыта извещением close_notify \~english The records of the own direction by TLS 1.2 have exhausted the limit of the key: the edition has no change of the keys, the connection is closed by the close_notify alert \~ */
			IDENTITY    = 0x1F, /*!< \~russian Опознаватель заранее разделённого ключа клиента серверу неизвестен (RFC 4279, TLS 1.2) \~english The identity of the pre-shared key of the client is unknown to the server (RFC 4279, TLS 1.2) \~ */
			ETM         = 0x20, /*!< \~russian Собеседник по TLS 1.2 не поддержал порядок encrypt_then_mac RFC 7366 при наборе CBC, а связь его требует \~english The TLS 1.2 interlocutor has not supported the encrypt_then_mac order of RFC 7366 at a CBC suite, while the connection requires it \~ */
			PROFILE     = 0x21, /*!< \~russian Профиль отпечатка исполнить нельзя: сервер выбрал набор, схему либо группу профиля, связи неведомые, либо профиль задан не в свой черёд \~english The fingerprint profile cannot be fulfilled: the server has selected a suite, a scheme or a group of the profile unknown to the connection, or the profile is set out of turn \~ */
			ECH         = 0x22, /*!< \~russian Зашифрованное приветствие ECH отвергнуто сервером: рукопожатие сложилось по публичному имени и оборвано извещением ech_required, запасные конфигурации сервера - в retry(); либо конфигурации ECH негодны \~english The encrypted client hello ECH has been rejected by the server: the handshake has completed by the public name and has been aborted by the ech_required alert, the retry configurations of the server are in retry(); or the ECH configurations are invalid \~ */
			TIMESTAMPS  = 0x23  /*!< \~russian Перечень меток времени сертификата собеседника сложен не по правилам (RFC 6962) \~english The list of the certificate timestamps of the peer is composed not by the rules (RFC 6962) \~ */
		};

		/**
		 * \~russian
		 * @brief Состояния связи
		 *
		 * \~english
		 * @brief States of a connection
		 *
		 * \~
		 */
		enum class state_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Связь ещё не заведена \~english The connection is not established yet \~ */
			HANDSHAKE   = 0x01, /*!< \~russian Рукопожатие связи идёт \~english The handshake of the connection is going on \~ */
			ESTABLISHED = 0x02, /*!< \~russian Связь установлена, идут прикладные данные \~english The connection is established, the application data is going \~ */
			CLOSED      = 0x03, /*!< \~russian Связь закрыта одной из сторон \~english The connection is closed by one of the sides \~ */
			FAILED      = 0x04  /*!< \~russian Связь оборвана отказом \~english The connection is torn by a failure \~ */
		};

		/**
		 * \~russian
		 * @brief Способы переноса рукопожатия
		 *
		 * @details Записями протокола рукопожатие идёт по TLS поверх потока: связь сама
		 *          защищает записи и разбирает их заголовки. Сообщениями по уровням оно
		 *          идёт под QUIC (RFC 9001): связь принимает и выдаёт голые сообщения
		 *          рукопожатия с пометкой уровня защиты, а шифрование и перенос остаются
		 *          за тем, кто связь ведёт. Дейтаграммами оно идёт по DTLS 1.3 (RFC 9147)
		 *          либо DTLS 1.2 (RFC 6347) по пределам издания: связь принимает и выдаёт
		 *          целые дейтаграммы с записями, а перенос их по UDP либо SCTP и часы
		 *          повторной передачи остаются за тем, кто связь ведёт
		 *
		 * \~english
		 * @brief Ways of the transport of the handshake
		 * @details By the records of the protocol the handshake goes by TLS over a stream: the
		 *          connection protects the records and parses their headers itself. By the messages
		 *          by levels it goes under QUIC (RFC 9001): the connection accepts and gives out bare
		 *          messages of the handshake marked with a protection level, while the encryption and
		 *          the transport remain with the one who leads the connection. By datagrams it goes by
		 *          DTLS 1.3 (RFC 9147) or DTLS 1.2 (RFC 6347) by the limits of the edition: the connection
		 *          accepts and gives out whole datagrams with the records, while their transport over UDP
		 *          or SCTP and the clock of the retransmission remain with the one who leads the connection
		 *
		 * \~
		 */
		enum class transport_t : uint8_t {
			RECORDS   = 0x00, /*!< \~russian Записи протокола TLS поверх потока \~english The records of the TLS protocol over a stream \~ */
			LEVELS    = 0x01, /*!< \~russian Сообщения рукопожатия по уровням защиты QUIC \~english The messages of the handshake by the protection levels of QUIC \~ */
			DATAGRAMS = 0x02  /*!< \~russian Дейтаграммы протокола DTLS 1.3 либо DTLS 1.2 поверх UDP либо SCTP \~english The datagrams of the DTLS 1.3 or DTLS 1.2 protocol over UDP or SCTP \~ */
		};

		/**
		 * \~russian
		 * @brief Уровни защиты QUIC
		 *
		 * @details Раздел 2.1 RFC 9001: всякое сообщение рукопожатия и всякий ключ помечены
		 *          уровнем, на котором они идут. Уровни не строго по порядку: упреждающие
		 *          данные идут рядом с рукопожатием
		 *
		 * \~english
		 * @brief Protection levels of QUIC
		 * @details The section 2.1 of RFC 9001: every message of the handshake and every key are marked
		 *          with the level at which they go. The levels are not strictly in order: the early data
		 *          goes side by side with the handshake
		 *
		 * \~
		 */
		enum class level_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Уровень не установлен \~english The level is not set \~ */
			INITIAL     = 0x01, /*!< \~russian Начальный уровень: приветствия сторон \~english The initial level: the greetings of the sides \~ */
			EARLY       = 0x02, /*!< \~russian Уровень упреждающих данных \~english The level of the early data \~ */
			HANDSHAKE   = 0x03, /*!< \~russian Уровень рукопожатия \~english The level of the handshake \~ */
			APPLICATION = 0x04  /*!< \~russian Уровень прикладных данных \~english The level of the application data \~ */
		};

		/**
		 * \~russian
		 * @brief Направления связи относительно своей стороны
		 *
		 * \~english
		 * @brief Directions of the connection relative to one's own side
		 *
		 * \~
		 */
		enum class direction_t : uint8_t {
			READ  = 0x01, /*!< \~russian Чтение: ключи собеседника \~english The reading: the keys of the interlocutor \~ */
			WRITE = 0x02  /*!< \~russian Запись: свои ключи \~english The writing: one's own keys \~ */
		};

		/**
		 * \~russian
		 * @brief Подлинность стороны связи
		 *
		 * @details Раздел 4.4.2 RFC 8446: цепочка сертификатов идёт от своего сертификата к
		 *          сертификату издателя, и секретный ключ отвечает именно первому из них
		 *
		 * @note Секретный ключ записывается тем же порядком, каким открытый ключ лежит в
		 *       сертификате, — от старшего байта к младшему
		 *
		 * \~english
		 * @brief Authenticity of a side of a connection
		 * @details The section 4.4.2 of RFC 8446: the chain of the certificates goes from one's own
		 *          certificate to the certificate of the issuer, and the secret key corresponds exactly
		 *          to the first of them
		 * @note The secret key is written by the same order the public key lies in the certificate by —
		 *       from the senior byte to the junior one
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Credential {
			// Секретный ключ своего сертификата
			vector <uint8_t> secret;
			// Цепочка сертификатов своей стороны
			vector <vector <uint8_t>> chain;
		} credential_t;
		/**
		 * \~russian
		 * @brief Алгоритм сжатия цепочки сертификатов, предоставляемый потребителем
		 *
		 * @details RFC 8879: цепочка сертификатов идёт сообщением CompressedCertificate, когда
		 *          у сторон нашёлся общий алгоритм. Библиотека ни zlib, ни Brotli, ни Zstandard
		 *          не несёт и не тащит: сжатие и распаковку предоставляет потребитель двумя
		 *          вызовами без состояния, а связь лишь зовёт их по опознавателю алгоритма
		 *
		 * @note Сжатие вправе отказать: тогда цепочка уходит несжатой, как велит раздел 4
		 *       RFC 8879. Распаковка обязана выдать ровно ожидаемую длину, иначе цепочка
		 *       отвергается извещением «bad_certificate»
		 *
		 * @note Указатель контекста передаётся вызовам как есть и связью не толкуется
		 *
		 * \~english
		 * @brief Algorithm of the compression of the chain of the certificates provided by the consumer
		 * @details RFC 8879: the chain of the certificates goes by the CompressedCertificate message when
		 *          the sides have found a common algorithm. The library carries neither zlib, nor Brotli,
		 *          nor Zstandard and does not drag them along: the compression and the decompression are
		 *          provided by the consumer by two stateless calls, and the connection only invokes them by
		 *          the identifier of the algorithm
		 * @note The compression may refuse: then the chain goes uncompressed, as the section 4 of RFC 8879
		 *       orders. The decompression is obliged to give out exactly the expected length, otherwise
		 *       the chain is rejected by the «bad_certificate» alert
		 * @note The pointer of the context is passed to the calls as it is and is not interpreted by the connection
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Codec {
			/**
			 * \~russian
			 * @brief Вызов сжатия цепочки сертификатов
			 *
			 * @param source  сжимаемое тело сообщения цепочки сертификатов
			 * @param result  накопитель, в который складывается сжатое тело
			 * @param context указатель контекста потребителя
			 *
			 * @return        признак успешности сжатия; отказ шлёт цепочку несжатой
			 *
			 * \~english
			 * @brief Call of the compression of the chain of the certificates
			 * @param source  the body of the message of the chain of the certificates being compressed
			 * @param result  the accumulator the compressed body is put into
			 * @param context the pointer of the context of the consumer
			 * @return        the flag of the success of the compression; a refusal sends the chain uncompressed
			 *
			 * \~
			 */
			typedef bool (* compress_t)(const view_t & source, vector <uint8_t> & result, void * context);
			/**
			 * \~russian
			 * @brief Вызов распаковки цепочки сертификатов
			 *
			 * @param source   распаковываемое сжатое тело
			 * @param expected ожидаемая длина тела после распаковки
			 * @param result   накопитель, в который складывается распакованное тело
			 * @param context  указатель контекста потребителя
			 *
			 * @return         признак успешности распаковки; отказ отвергает цепочку
			 *
			 * \~english
			 * @brief Call of the decompression of the chain of the certificates
			 * @param source   the compressed body being decompressed
			 * @param expected the expected length of the body after the decompression
			 * @param result   the accumulator the decompressed body is put into
			 * @param context  the pointer of the context of the consumer
			 * @return         the flag of the success of the decompression; a refusal rejects the chain
			 *
			 * \~
			 */
			typedef bool (* decompress_t)(const view_t & source, const size_t expected, vector <uint8_t> & result, void * context);
			// Опознаватель алгоритма по реестру RFC 8879: zlib 1, Brotli 2, Zstandard 3, частные 16384…65535
			uint16_t algorithm;
			// Указатель контекста потребителя, передаваемый вызовам как есть
			void * context;
			// Вызов сжатия цепочки сертификатов
			compress_t compress;
			// Вызов распаковки цепочки сертификатов
			decompress_t decompress;
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
			Codec() noexcept : algorithm(0), context(nullptr), compress(nullptr), decompress(nullptr) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param algorithm  опознаватель алгоритма по реестру RFC 8879
			 * @param compress   вызов сжатия цепочки сертификатов
			 * @param decompress вызов распаковки цепочки сертификатов
			 * @param context    указатель контекста потребителя
			 *
			 * \~english
			 * @brief Constructor
			 * @param algorithm  the identifier of the algorithm by the registry of RFC 8879
			 * @param compress   the call of the compression of the chain of the certificates
			 * @param decompress the call of the decompression of the chain of the certificates
			 * @param context    the pointer of the context of the consumer
			 *
			 * \~
			 */
			Codec(const uint16_t algorithm, compress_t compress, decompress_t decompress, void * context = nullptr) noexcept : algorithm(algorithm), context(context), compress(compress), decompress(decompress) {}
		} codec_t;
		/**
		 * \~russian
		 * @brief Заранее разделённый ключ издания TLS 1.2
		 *
		 * @details RFC 4279 и RFC 5489: наборы PSK ведут рукопожатие без сертификатов - общее
		 *          значение обмена выводится из ключа, известного обеим сторонам заранее.
		 *          Сервер держит много ключей одним контекстом, и потому не хранит ключ, а
		 *          отвечает на опознаватель клиента вызовом «дано identity - ключ либо отказ»;
		 *          клиент хранит свой опознаватель с ключом и вправе выбрать их заново по
		 *          подсказке сервера psk_identity_hint вызовом advise
		 *
		 * @note Раздел 5.3 RFC 4279: опознаватель не длиннее 128 байтов, ключ - не длиннее
		 *       64; иное заведение связи отвергает отказом SETTINGS. Наборы PSK
		 *       предлагаются и признаются лишь тогда, когда ключ либо вызов заданы
		 *
		 * @note Раздел 2 RFC 4279: неизвестный опознаватель сервер вправе отвергнуть
		 *       извещением unknown_psk_identity (115) либо продолжить случайным ключом и
		 *       оборваться на завершении decrypt_error (51), не выдавая, что опознаватель
		 *       неизвестен; выбор за признаком disclose
		 *
		 * \~english
		 * @brief Pre-shared key of the TLS 1.2 edition
		 * @details RFC 4279 and RFC 5489: the PSK suites conduct the handshake without certificates - the
		 *          shared value of the exchange is derived from a key known to both sides beforehand. The
		 *          server holds many keys by one context, hence it does not store the key but answers the
		 *          identity of the client by the call «given the identity - the key or a refusal»; the client
		 *          stores its identity with the key and may choose them anew by the psk_identity_hint of the
		 *          server by the advise call
		 * @note The section 5.3 of RFC 4279: the identity is not longer than 128 bytes, the key - not longer
		 *       than 64; otherwise the establishment of the connection refuses by SETTINGS. The PSK suites are
		 *       offered and recognized only when the key or the call is set
		 * @note The section 2 of RFC 4279: an unknown identity the server may reject by the unknown_psk_identity
		 *       alert (115) or continue with a random key and fail at the completion by decrypt_error (51),
		 *       not disclosing that the identity is unknown; the choice is by the disclose flag
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Psk {
			/**
			 * \~russian
			 * @brief Вызов сервера: ключ по опознавателю клиента
			 *
			 * @param identity опознаватель, предъявленный клиентом
			 * @param key      накопитель, в который помещается ключ не длиннее 64 байтов
			 * @param context  указатель контекста потребителя
			 *
			 * @return         признак того, что опознаватель известен и ключ выдан
			 *
			 * \~english
			 * @brief Call of the server: the key by the identity of the client
			 * @param identity the identity presented by the client
			 * @param key      the accumulator the key not longer than 64 bytes is put into
			 * @param context  the pointer of the context of the consumer
			 * @return         the flag of the identity being known and the key given
			 *
			 * \~
			 */
			typedef bool (* respond_t)(const view_t & identity, vector <uint8_t> & key, void * context);
			/**
			 * \~russian
			 * @brief Вызов клиента: опознаватель и ключ по подсказке сервера
			 *
			 * @param hint     подсказка psk_identity_hint сервера
			 * @param identity накопитель, в который помещается опознаватель не длиннее 128 байтов
			 * @param key      накопитель, в который помещается ключ не длиннее 64 байтов
			 * @param context  указатель контекста потребителя
			 *
			 * @return         признак того, что опознаватель и ключ выбраны заново; отказ оставляет настроенные
			 *
			 * \~english
			 * @brief Call of the client: the identity and the key by the hint of the server
			 * @param hint     the psk_identity_hint of the server
			 * @param identity the accumulator the identity not longer than 128 bytes is put into
			 * @param key      the accumulator the key not longer than 64 bytes is put into
			 * @param context  the pointer of the context of the consumer
			 * @return         the flag of the identity and the key being chosen anew; a refusal leaves the configured ones
			 *
			 * \~
			 */
			typedef bool (* advise_t)(const view_t & hint, vector <uint8_t> & identity, vector <uint8_t> & key, void * context);
			// Опознаватель клиента; у сервера - подсказка psk_identity_hint, пустая не шлётся
			vector <uint8_t> identity;
			// Ключ клиента; сервером не используется
			vector <uint8_t> key;
			// Вызов сервера: ключ по опознавателю
			respond_t respond;
			// Вызов клиента: опознаватель и ключ по подсказке
			advise_t advise;
			// Указатель контекста потребителя, передаваемый вызовам как есть
			void * context;
			// Признак того, что неизвестный опознаватель отвечается извещением unknown_psk_identity, а не decrypt_error на завершении
			bool disclose;
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
			Psk() noexcept : respond(nullptr), advise(nullptr), context(nullptr), disclose(false) {}
			/**
			 * \~russian
			 * @brief Деструктор
			 *
			 * @note Ключ затирается изменчивым циклом прежде освобождения; копии настроек
			 *       (у связи своя) затирают каждая свой ключ, и копирование оставлено обычным
			 *
			 * \~english
			 * @brief Destructor
			 * @note The key is wiped by the volatile loop before the release; the copies of the settings (the
			 *       connection has its own) wipe each its own key, and the copying is left ordinary
			 *
			 * \~
			 */
			~Psk() noexcept;
		} psk_t;
		/**
		 * \~russian
		 * @brief Билет возобновления связи
		 *
		 * @details Раздел 4.6.1 RFC 8446: сервер выдаёт билет за рукопожатием, а клиент
		 *          предъявляет его будущей связи. Тело билета серверу назначать самому: по
		 *          нему он и опознаёт, какой связи билет принадлежит.
		 *
		 * @note Прикладной протокол связи хранится в билете затем, что раздел 4.2.10 RFC 8446
		 *       велит отвергать упреждающие данные, когда протокол новой связи разошёлся с
		 *       протоколом той, что билет выдала
		 *
		 * @note Ключ билета связь выводит сама, а вот хранение пары «тело и ключ» ей не
		 *       принадлежит: где её держать и как её беречь - решает тот, кто связь ведёт
		 *
		 * @note Раздел 8.2 RFC 9001: клиенту, шлющему упреждающие данные под QUIC, нужны
		 *       параметры переноса сервера той связи, что билет выдала, - связь по уровням
		 *       складывает их в билет сама, а в записи билета они идут своим полем
		 *
		 * @note Раздел 3.1 RFC 7366: порядок «шифрование, затем имитовставка» у издания 1.2
		 *       понижать нельзя, и билет помнит порядок выдавшей его связи: сокращённое
		 *       рукопожатие иным порядком клиент отвергает illegal_parameter
		 *
		 * @note Раздел 8 RFC 8446 велит беречь упреждающие данные от повторной подачи, и
		 *       беречь их приходится тому же, кому принадлежат билеты: связь одна о
		 *       повторе не судит, ибо второй раз билет предъявляется уже другой связи.
		 *       Простейший заслон - выдавать всякий билет к одному употреблению, снимая
		 *       его из запаса тотчас по возобновлении
		 *
		 * \~english
		 * @brief Ticket of the resumption of a connection
		 * @details The section 4.6.1 of RFC 8446: the server issues a ticket after the handshake, and the
		 *          client presents it to a future connection. The body of the ticket is for the server to
		 *          appoint itself: by it it identifies which connection the ticket belongs to.
		 * @note The application protocol of the connection is kept in the ticket because the section 4.2.10
		 *       of RFC 8446 orders to reject the early data when the protocol of the new connection has
		 *       diverged from the protocol of the one which issued the ticket
		 * @note The connection derives the key of the ticket itself, while the storage of the pair of «the
		 *       body and the key» does not belong to it: where to keep it and how to guard it is decided by
		 *       the one who leads the connection
		 * @note The section 3.1 of RFC 7366: the encrypt-then-MAC order of the 1.2 edition must not be
		 *       downgraded, and the ticket remembers the order of the connection which issued it: an
		 *       abbreviated handshake by another order the client rejects by illegal_parameter
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Ticket {
			// Набор шифрования связи, выдавшей билет
			protect::suite_t suite;
			// Миг выдачи билета в секундах, ноль означает неизвестный миг
			int64_t moment;
			// Срок жизни билета в секундах
			uint32_t lifetime;
			// Предел упреждающих данных билета в байтах, ноль запрещает их вовсе
			uint32_t advance;
			// Добавка к возрасту билета, скрывающая его от посторонних
			uint32_t age;
			// Признак порядка «шифрование, затем имитовставка» RFC 7366 у связи издания 1.2, выдавшей билет: возобновление ведётся тем же порядком
			bool etm;
			// Прикладной протокол связи, выдавшей билет
			string protocol;
			// Признак согласования прикладных настроек ALPS у связи, выдавшей билет (draft-vvv-tls-alps)
			bool settled;
			// Свои прикладные настройки ALPS связи, выдавшей билет
			vector <uint8_t> settings;
			// Прикладные настройки ALPS собеседника связи, выдавшей билет
			vector <uint8_t> obtained;
			// Тело билета, опознающее связь для выдавшего его сервера
			vector <uint8_t> identity;
			// Ключ билета, выведенный из значения возобновления связи
			vector <uint8_t> secret;
			// Параметры переноса QUIC собеседника связи, выдавшей билет
			vector <uint8_t> parameters;
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
			Ticket() noexcept;
			/**
			 * \~russian
			 * @brief Деструктор: ключ билета затирается, копии у потребителя не оставляют его в освобождённой памяти
			 * \~english
			 * @brief Destructor: the key of the ticket is wiped, the copies at the consumer do not leave it in the freed memory
			 * \~
			 */
			~Ticket() noexcept;
			/**
			 * \~russian
			 * @brief Конструктор копирования
			 * @param other копируемый билет
			 * \~english
			 * @brief Copy constructor
			 * @param other the ticket being copied
			 * \~
			 */
			Ticket(const Ticket & other);
			/**
			 * \~russian
			 * @brief Конструктор перемещения: ключ переезжает, у источника затирается
			 * @param other перемещаемый билет
			 * \~english
			 * @brief Move constructor: the key moves over, at the source it is wiped
			 * @param other the ticket being moved
			 * \~
			 */
			Ticket(Ticket && other) noexcept;
			/**
			 * \~russian
			 * @brief Оператор присваивания копированием: прежний ключ затирается до замены
			 * @param other копируемый билет
			 * @return      сам билет
			 * \~english
			 * @brief Copy assignment operator: the former key is wiped before the replacement
			 * @param other the ticket being copied
			 * @return      the ticket itself
			 * \~
			 */
			Ticket & operator = (const Ticket & other);
			/**
			 * \~russian
			 * @brief Оператор присваивания перемещением: прежний ключ затирается, ключ источника переезжает и затирается у него
			 * @param other перемещаемый билет
			 * @return      сам билет
			 * \~english
			 * @brief Move assignment operator: the former key is wiped, the key of the source moves over and is wiped there
			 * @param other the ticket being moved
			 * @return      the ticket itself
			 * \~
			 */
			Ticket & operator = (Ticket && other) noexcept;
		} ticket_t;
		/**
		 * \~russian
		 * @brief Метод записи билета возобновления связи в октеты
		 *
		 * @param ticket записываемый билет возобновления связи
		 * @param result накопитель, в который складывается запись билета
		 *
		 * @return       отказ записи билета: MEMORY у нехватки памяти, TICKET у билета, в запись не входящего
		 *
		 * @details Запись самодостаточна и от процесса не зависит: байт издания записи, за ним
		 *          поля билета постоянной ширины в порядке от старшего байта к младшему и поля
		 *          переменной длины с двухбайтовой длиной впереди. Ею билет уходит в другой
		 *          процесс и возвращается обратно чтением
		 *
		 * \~english
		 * @brief Method of the writing of a ticket of the resumption of a connection into octets
		 * @param ticket the ticket of the resumption of the connection being written
		 * @param result the accumulator the record of the ticket is put into
		 * @return       the failure of the writing of the ticket: MEMORY at the lack of memory, TICKET at a ticket not fitting the record
		 * @details The record is self-sufficient and does not depend on the process: a byte of the edition of
		 *          the record, then the fields of the ticket of a constant width in the order from the senior
		 *          byte to the junior one and the fields of a variable length with a two-byte length in front.
		 *          By it the ticket goes to another process and comes back by the reading
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const ticket_t & ticket, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод чтения билета возобновления связи из октетов
		 *
		 * @param data   читаемая запись билета возобновления связи
		 * @param result билет, в который помещается прочитанное
		 *
		 * @return       отказ чтения билета: TICKET у записи не по правилам, MEMORY у нехватки памяти
		 *
		 * @note Запись чужого издания, обрезанная, с порченой длиной поля либо с лишними
		 *       байтами за хвостом отвергается целиком: половина билета не билет
		 *
		 * \~english
		 * @brief Method of the reading of a ticket of the resumption of a connection from octets
		 * @param data   the record of the ticket of the resumption of the connection being read
		 * @param result the ticket the read one is put into
		 * @return       the failure of the reading of the ticket: TICKET at a record not by the rules, MEMORY at the lack of memory
		 * @note A record of a foreign edition, a truncated one, one with a corrupted length of a field or with
		 *       extra bytes behind the tail is rejected wholly: a half of a ticket is not a ticket
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const view_t & data, ticket_t & result) noexcept;
	};
};

#endif // __ANTS_CONTEXT__
