/**
 * @file session.hpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
 * @brief Заголовочный файл модуля состояния связи протокола TLS 1.3 — переписка
 *        рукопожатия и выведенные из неё значения расписания ключей
 *
 * \~english
 * @brief Header file of the module of the state of a connection of the TLS 1.3 protocol — the
 *        transcript of the handshake and the values of the key schedule derived from it
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_SESSION__
#define __ANYKS_TLS_SESSION__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <digest/streebog.hpp>
#include <protect/protect.hpp>
#include <schedule/schedule.hpp>

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
	 * @brief Пространство имён состояния связи протокола TLS
	 *
	 * @details Всё, чем связь отличается от голого обмена байтами, держится на двух
	 *          величинах: на хеше переписки рукопожатия и на цепочке значений расписания
	 *          ключей. Первая связывает ключи со всем, что стороны друг другу сказали, а
	 *          вторая уводит их вперёд так, что раскрытие позднего ключа раннего не выдаёт.
	 *
	 * \~english
	 * @brief Namespace of the state of a connection of the TLS protocol
	 * @details Everything by which a connection differs from a bare exchange of the bytes rests on two
	 *          values: on the hash of the transcript of the handshake and on the chain of the values of
	 *          the key schedule. The first binds the keys to everything the parties have said to each
	 *          other, while the second takes them forward so that a disclosure of a later key does not
	 *          reveal an earlier one.
	 *
	 * \~
	 */
	namespace session {
		/**
		 * \~russian
		 * @brief Отказы работы с состоянием связи
		 *
		 * \~english
		 * @brief Failures of the work with the state of a connection
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE    = 0x01, /*!< \~russian Порядок вывода значений расписания нарушен \~english The order of the derivation of the values of the schedule is violated \~ */
			DIGEST   = 0x02, /*!< \~russian Захешировать переписку рукопожатия не удалось \~english It was not possible to hash the transcript of the handshake \~ */
			SCHEDULE = 0x03, /*!< \~russian Вывести значение расписания ключей не удалось \~english It was not possible to derive a value of the key schedule \~ */
			SUITE    = 0x04, /*!< \~russian Набор шифрования протоколом не определён \~english The cipher suite is not defined by the protocol \~ */
			EMPTY    = 0x05  /*!< \~russian Обязательный довод вывода не передан \~english A mandatory argument of the derivation is not passed \~ */
		};

		/**
		 * \~russian
		 * @brief Стороны связи
		 *
		 * \~english
		 * @brief Sides of a connection
		 *
		 * \~
		 */
		enum class side_t : uint8_t {
			CLIENT = 0x01, /*!< \~russian Направление связи от клиента \~english The direction of the connection from the client \~ */
			SERVER = 0x02  /*!< \~russian Направление связи от сервера \~english The direction of the connection from the server \~ */
		};

		/**
		 * \~russian
		 * @brief Ступени расписания ключей
		 *
		 * @details Раздел 7.1 RFC 8446: расписание проходится ступенями, и всякая следующая
		 *          выводится из предыдущей. Перепрыгнуть ступень нельзя, вернуться назад тоже
		 *
		 * \~english
		 * @brief Stages of the key schedule
		 * @details The section 7.1 of RFC 8446: the schedule is passed by the stages, and every next one
		 *          is derived from the previous one. It is not possible to skip a stage, nor to return back
		 *
		 * \~
		 */
		enum class stage_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Расписание ключей ещё не начато \~english The key schedule is not started yet \~ */
			EARLY       = 0x01, /*!< \~russian Начальная ступень расписания ключей \~english The initial stage of the key schedule \~ */
			HANDSHAKE   = 0x02, /*!< \~russian Ступень рукопожатия расписания ключей \~english The handshake stage of the key schedule \~ */
			APPLICATION = 0x03  /*!< \~russian Ступень прикладных данных расписания ключей \~english The application data stage of the key schedule \~ */
		};

		/**
		 * \~russian
		 * @brief Метод вывода ключевого материала из значения направления связи
		 *
		 * @param traffic значение направления связи, из которого выводится материал
		 * @param suite   набор шифрования, которым защищаются записи
		 * @param key     место, в которое помещается корневой ключ направления
		 * @param vector  место, в которое помещается вектор замены направления
		 *
		 * @return        отказ вывода ключевого материала направления связи
		 *
		 * @details Раздел 7.3 RFC 8446: ключ и вектор замены выводятся из значения направления
		 *          метками «key» и «iv», и порядок этот один на все ступени расписания
		 *
		 * \~english
		 * @brief Method of the derivation of the key material from a value of a direction of a connection
		 * @param traffic the value of the direction of the connection the material is derived from
		 * @param suite   the cipher suite the records are protected by
		 * @param key     the place the root key of the direction is put into
		 * @param vector  the place the vector of the replacement of the direction is put into
		 * @return        the failure of the derivation of the key material of the direction
		 * @details The section 7.3 of RFC 8446: the key and the vector of the replacement are derived from
		 *          the value of the direction by the «key» and «iv» labels, and this order is one for all
		 *          the stages of the schedule
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t material(const view_t & traffic, const protect::suite_t suite, uint8_t * key, uint8_t * vector) noexcept;

		/**
		 * \~russian
		 * @brief Переписка рукопожатия
		 *
		 * @details Раздел 4.4.1 RFC 8446: хеш переписки берётся от всех сообщений рукопожатия
		 *          подряд, вместе с их обвязкой и в том порядке, в каком они прошли по связи.
		 *          Хеш этот входит в вывод всякого ключа и в подпись владения ключом, чем обе
		 *          стороны и убеждаются, что видели одну и ту же переписку.
		 *
		 * @note Сообщения не хранятся: переписка хешируется потоком, а промежуточный хеш
		 *       берётся со снимка состояния хеширования. Иначе связь держала бы у себя всю
		 *       цепочку сертификатов собеседника до самого конца рукопожатия
		 *
		 * \~english
		 * @brief Transcript of the handshake
		 * @details The section 4.4.1 of RFC 8446: the hash of the transcript is taken from all the
		 *          messages of the handshake in a row, together with their framing and in the order in
		 *          which they have passed over the connection. This hash enters the derivation of every
		 *          key and the signature of the possession of the key, by which both parties make sure
		 *          that they have seen one and the same transcript.
		 * @note The messages are not stored: the transcript is hashed by a stream, while an interim hash
		 *       is taken from a snapshot of the state of the hashing. Otherwise a connection would keep
		 *       the whole chain of the certificates of the peer at itself until the very end of the handshake
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Transcript {
			private:
				// Объект хеширования переписки рукопожатия
				digest::streebog_t _hash;
			public:
				/**
				 * \~russian
				 * @brief Метод начала переписки рукопожатия
				 *
				 * \~english
				 * @brief Method of the beginning of the transcript of the handshake
				 *
				 * \~
				 */
				void start() noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса переписки рукопожатия
				 *
				 * \~english
				 * @brief Method of the reset of the transcript of the handshake
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод добавления сообщения в переписку рукопожатия
				 *
				 * @param message добавляемое сообщение вместе с его обвязкой
				 *
				 * @return        отказ добавления сообщения в переписку
				 *
				 * @note Сообщение добавляется вместе с обвязкой: хеш переписки берётся именно
				 *       от такой записи, а не от одних только тел сообщений
				 *
				 * \~english
				 * @brief Method of the addition of a message into the transcript of the handshake
				 * @param message the message being added together with its framing
				 * @return        the failure of the addition of the message into the transcript
				 * @note A message is added together with its framing: the hash of the transcript is taken
				 *       exactly from such a record and not from the bodies of the messages alone
				 *
				 * \~
				 */
				error_t update(const view_t & message) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения хеша переписки рукопожатия
				 *
				 * @param result место, в которое помещается хеш переписки
				 *
				 * @return       отказ получения хеша переписки
				 *
				 * @details Хеш берётся со снимка состояния хеширования: переписка при этом не
				 *          закрывается, и добавлять в неё сообщения можно и дальше
				 *
				 * @note Место итога обязано вмещать длину хеша
				 *
				 * \~english
				 * @brief Method of getting the hash of the transcript of the handshake
				 * @param result the place the hash of the transcript is put into
				 * @return       the failure of the getting of the hash of the transcript
				 * @details The hash is taken from a snapshot of the state of the hashing: the transcript is
				 *          not closed at that, and the messages may be added into it further on
				 * @note The place of the outcome is obliged to hold the length of the hash
				 *
				 * \~
				 */
				error_t digest(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения хеша переписки рукопожатия с довеском
				 *
				 * @param suffix довесок, дописываемый к переписке лишь на этот хеш
				 * @param result место, в которое помещается хеш переписки с довеском
				 *
				 * @return       отказ получения хеша переписки с довеском
				 *
				 * @details Раздел 4.2.11.2 RFC 8446: привязка заранее разделённого ключа берётся
				 *          от переписки с усечённым приветствием, которое сообщением ещё не стало,
				 *          - вот на этот случай довесок и нужен
				 *
				 * @note Довесок в переписку не добавляется: она остаётся такой, какой была до
				 *       этого вызова
				 *
				 * \~english
				 * @brief Method of getting the hash of the transcript of the handshake with an appendage
				 * @param suffix the appendage appended to the transcript only for this hash
				 * @param result the place the hash of the transcript with the appendage is put into
				 * @return       the failure of getting the hash of the transcript with the appendage
				 * @details The section 4.2.11.2 of RFC 8446: the binder of a pre-shared key is taken from the
				 *          transcript with a truncated greeting which has not become a message yet — it is for
				 *          this case that the appendage is needed
				 * @note The appendage is not added to the transcript: it stays such as it was before this call
				 *
				 * \~
				 */
				error_t digest(const view_t & suffix, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод замены накопленной переписки её хешем
				 *
				 * @return отказ замены накопленной переписки
				 *
				 * @details Раздел 4.4.1 RFC 8446: получив просьбу о повторе приветствия, обе
				 *          стороны заменяют первое приветствие клиента особым сообщением, несущим
				 *          хеш этого приветствия. Тем переписка укорачивается до одного сообщения,
				 *          а связь с первым приветствием не теряется
				 *
				 * \~english
				 * @brief Method of the replacement of the accumulated transcript by its hash
				 * @return the failure of the replacement of the accumulated transcript
				 * @details The section 4.4.1 of RFC 8446: having received a request of a repetition of the
				 *          greeting, both parties replace the first greeting of the client by a special
				 *          message carrying the hash of this greeting. By that the transcript is shortened to
				 *          a single message, while the bond with the first greeting is not lost
				 *
				 * \~
				 */
				error_t replace() noexcept;
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
				Transcript() noexcept;
		} transcript_t;
		/**
		 * \~russian
		 * @brief Значения расписания ключей связи
		 *
		 * @details Раздел 7.1 RFC 8446: расписание проходится тремя ступенями. Начальная
		 *          заводится либо на заранее разделённом ключе, либо на нулях, ступень
		 *          рукопожатия - на общем значении обмена ключами, а ступень прикладных данных
		 *          из неё выводится вовсе без нового ключевого материала.
		 *
		 * @note Объект хранит значения обоих направлений связи: направления различаются лишь
		 *       меткою вывода, и держать под них два одинаковых объекта было бы незачем
		 *
		 * \~english
		 * @brief Values of the key schedule of a connection
		 * @details The section 7.1 of RFC 8446: the schedule is passed by three stages. The initial one is
		 *          set up either on a pre-shared key or on the zeroes, the handshake stage — on the shared
		 *          value of the exchange of the keys, while the application data stage is derived from it
		 *          without any new key material at all.
		 * @note The object stores the values of both directions of the connection: the directions differ
		 *       only by the label of the derivation, and it would be pointless to keep two identical
		 *       objects for them
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Secrets {
			private:
				// Пройденная ступень расписания ключей
				stage_t _stage;
			private:
				// Значение расписания ключей текущей ступени
				uint8_t _secret[schedule::SCHEDULE_SECRET];
			private:
				// Значение направления связи от клиента
				uint8_t _client[schedule::SCHEDULE_SECRET];
			private:
				// Значение направления связи от сервера
				uint8_t _server[schedule::SCHEDULE_SECRET];
			private:
				// Значение возобновления связи
				uint8_t _resumption[schedule::SCHEDULE_SECRET];
			private:
				// Значение упреждающих данных связи
				uint8_t _early[schedule::SCHEDULE_SECRET];
			public:
				/**
				 * \~russian
				 * @brief Метод получения пройденной ступени расписания ключей
				 *
				 * @return пройденная ступень расписания ключей
				 *
				 * \~english
				 * @brief Method of getting the passed stage of the key schedule
				 * @return the passed stage of the key schedule
				 *
				 * \~
				 */
				stage_t stage() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса значений расписания ключей
				 *
				 * \~english
				 * @brief Method of the reset of the values of the key schedule
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения начальной ступени расписания ключей
				 *
				 * @param secret заранее разделённый ключ связи
				 *
				 * @return       отказ заведения начальной ступени
				 *
				 * @details Раздел 7.1 RFC 8446: заранее разделённого ключа у связи может и не
				 *          быть, и тогда на его место идут нули длиною в хеш
				 *
				 * \~english
				 * @brief Method of the setting up of the initial stage of the key schedule
				 * @param secret the pre-shared key of the connection
				 * @return       the failure of the setting up of the initial stage
				 * @details The section 7.1 of RFC 8446: a connection may have no pre-shared key, and then
				 *          the zeroes of a length of the hash go in its place
				 *
				 * \~
				 */
				error_t start(const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода ступени рукопожатия расписания ключей
				 *
				 * @param shared     общее значение обмена ключами
				 * @param transcript хеш переписки рукопожатия на миг вывода
				 *
				 * @return           отказ вывода ступени рукопожатия
				 *
				 * @details Раздел 7.1 RFC 8446: хешем переписки берётся хеш приветствий обеих
				 *          сторон, и им ключи рукопожатия связываются со всем, о чём стороны
				 *          успели договориться
				 *
				 * \~english
				 * @brief Method of the derivation of the handshake stage of the key schedule
				 * @param shared     the shared value of the exchange of the keys
				 * @param transcript the hash of the transcript of the handshake at the moment of the derivation
				 * @return           the failure of the derivation of the handshake stage
				 * @details The section 7.1 of RFC 8446: the hash of the greetings of both parties is taken as
				 *          the hash of the transcript, and by it the keys of the handshake are bound to
				 *          everything the parties have managed to agree upon
				 *
				 * \~
				 */
				error_t handshake(const view_t & shared, const view_t & transcript) noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода ступени прикладных данных расписания ключей
				 *
				 * @param transcript хеш переписки рукопожатия на миг вывода
				 *
				 * @return           отказ вывода ступени прикладных данных
				 *
				 * @details Раздел 7.1 RFC 8446: нового ключевого материала эта ступень не берёт
				 *          вовсе, а хешем переписки ей служит хеш всего рукопожатия вплоть до
				 *          завершения его сервером
				 *
				 * \~english
				 * @brief Method of the derivation of the application data stage of the key schedule
				 * @param transcript the hash of the transcript of the handshake at the moment of the derivation
				 * @return           the failure of the derivation of the application data stage
				 * @details The section 7.1 of RFC 8446: this stage takes no new key material at all, while the
				 *          hash of the whole handshake up to its completion by the server serves as its hash
				 *          of the transcript
				 *
				 * \~
				 */
				error_t application(const view_t & transcript) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения значения направления связи
				 *
				 * @param side   сторона, чьё направление связи запрашивается
				 * @param result место, в которое помещается значение направления связи
				 *
				 * @return       отказ получения значения направления связи
				 *
				 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
				 *
				 * \~english
				 * @brief Method of getting the value of a direction of the connection
				 * @param side   the side whose direction of the connection is being requested
				 * @param result the place the value of the direction of the connection is put into
				 * @return       the failure of the getting of the value of the direction of the connection
				 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
				 *
				 * \~
				 */
				error_t traffic(const side_t side, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода ключевого материала направления связи
				 *
				 * @param side   сторона, чьё направление связи запрашивается
				 * @param suite  набор шифрования, которым защищаются записи
				 * @param key    место, в которое помещается корневой ключ направления
				 * @param vector место, в которое помещается вектор замены направления
				 *
				 * @return       отказ вывода ключевого материала направления связи
				 *
				 * @details Раздел 7.3 RFC 8446: ключ и вектор замены выводятся из значения
				 *          направления связи метками «key» и «iv». Длина вектора замены задана
				 *          набором шифрования и равна длине блока его базового шифра
				 *
				 * \~english
				 * @brief Method of the derivation of the key material of a direction of the connection
				 * @param side   the side whose direction of the connection is being requested
				 * @param suite  the cipher suite the records are protected by
				 * @param key    the place the root key of the direction is put into
				 * @param vector the place the initialization vector of the direction is put into
				 * @return       the failure of the derivation of the key material of the direction
				 * @details The section 7.3 of RFC 8446: the key and the initialization vector are derived from
				 *          the value of the direction of the connection by the «key» and «iv» labels. The
				 *          length of the initialization vector is set by the cipher suite and equals the length
				 *          of a block of its base cipher
				 *
				 * \~
				 */
				error_t material(const side_t side, const protect::suite_t suite, uint8_t * key, uint8_t * vector) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода ключа завершения рукопожатия
				 *
				 * @param side   сторона, чей ключ завершения запрашивается
				 * @param result место, в которое помещается ключ завершения рукопожатия
				 *
				 * @return       отказ вывода ключа завершения рукопожатия
				 *
				 * @details Раздел 4.4.4 RFC 8446: ключ выводится из значения направления связи
				 *          меткою «finished», и на нём вырабатывается имитовставка завершения
				 *
				 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
				 *
				 * \~english
				 * @brief Method of the derivation of the key of the completion of the handshake
				 * @param side   the side whose key of the completion is being requested
				 * @param result the place the key of the completion of the handshake is put into
				 * @return       the failure of the derivation of the key of the completion of the handshake
				 * @details The section 4.4.4 of RFC 8446: the key is derived from the value of the direction of
				 *          the connection by the «finished» label, and the authentication code of the completion
				 *          is produced under it
				 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
				 *
				 * \~
				 */
				error_t finished(const side_t side, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод смены значения направления связи
				 *
				 * @param side сторона, чьё направление связи сменяется
				 *
				 * @return     отказ смены значения направления связи
				 *
				 * @details Раздел 7.2 RFC 8446: новое значение направления выводится из прежнего
				 *          меткою «traffic upd», и прежнее значение по нему не восстанавливается
				 *
				 * @note Смена дозволена лишь на ступени прикладных данных: ключи рукопожатия
				 *       живут ровно до её вывода и сменяться не вправе
				 *
				 * \~english
				 * @brief Method of the change of the value of the direction of the connection
				 * @param side the side whose direction of the connection is being changed
				 * @return     the failure of the change of the value of the direction of the connection
				 * @details The section 7.2 of RFC 8446: the new value of the direction is derived from the
				 *          previous one by the «traffic upd» label, and the previous value is not restored by it
				 * @note The change is allowed only at the stage of the application data: the keys of the
				 *       handshake live exactly until its derivation and are not entitled to be changed
				 *
				 * \~
				 */
				error_t renew(const side_t side) noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода значения возобновления связи
				 *
				 * @param transcript хеш переписки рукопожатия на миг вывода
				 *
				 * @return           отказ вывода значения возобновления связи
				 *
				 * @details Раздел 7.1 RFC 8446: значение выводится меткою «res master» от переписки,
				 *          дошедшей до завершения рукопожатия клиентом, и из него выводятся ключи
				 *          билетов, выдаваемых сервером на будущую связь
				 *
				 * \~english
				 * @brief Method of the derivation of the value of the resumption of the connection
				 * @param transcript the hash of the transcript of the handshake at the moment of the derivation
				 * @return           the failure of the derivation of the value of the resumption of the connection
				 * @details The section 7.1 of RFC 8446: the value is derived by the «res master» label from the
				 *          transcript which has reached the completion of the handshake by the client, and the
				 *          keys of the tickets issued by the server for a future connection are derived from it
				 *
				 * \~
				 */
				error_t resumption(const view_t & transcript) noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода ключа билета возобновления связи
				 *
				 * @param nonce  неповторимое значение билета, назначенное сервером
				 * @param result место, в которое помещается ключ билета
				 *
				 * @return       отказ вывода ключа билета возобновления связи
				 *
				 * @details Раздел 4.6.1 RFC 8446: всякому билету отвечает свой ключ, и неповторимое
				 *          значение билета их и разводит - иначе все билеты одной связи вышли бы
				 *          одинаковыми
				 *
				 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
				 *
				 * \~english
				 * @brief Method of the derivation of the key of a ticket of the resumption of the connection
				 * @param nonce  the unique value of the ticket appointed by the server
				 * @param result the place the key of the ticket is put into
				 * @return       the failure of the derivation of the key of the ticket of the resumption
				 * @details The section 4.6.1 of RFC 8446: every ticket corresponds to its own key, and the unique
				 *          value of the ticket is what separates them — otherwise all the tickets of one connection
				 *          would come out identical
				 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
				 *
				 * \~
				 */
				error_t ticket(const view_t & nonce, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки привязки заранее разделённого ключа
				 *
				 * @param transcript хеш усечённого приветствия клиента
				 * @param result     место, в которое помещается привязка ключа
				 *
				 * @return           отказ выработки привязки заранее разделённого ключа
				 *
				 * @details Раздел 4.2.11.2 RFC 8446: привязка есть имитовставка усечённого
				 *          приветствия на ключе, выведенном из начальной ступени расписания
				 *          меткою «res binder». Ею клиент и доказывает владение ключом билета.
				 *
				 * @note Привязка вырабатывается на начальной ступени расписания ключей: на ней
				 *       заранее разделённый ключ уже вложен, а ключей обмена ещё нет
				 *
				 * \~english
				 * @brief Method of the production of the binder of a pre-shared key
				 * @param transcript the hash of the truncated greeting of the client
				 * @param result     the place the binder of the key is put into
				 * @return           the failure of the production of the binder of the pre-shared key
				 * @details The section 4.2.11.2 of RFC 8446: the binder is the authentication code of the
				 *          truncated greeting under the key derived from the initial stage of the schedule by
				 *          the «res binder» label. By it the client proves the possession of the key of the ticket.
				 * @note The binder is produced at the initial stage of the schedule of the keys: at it the
				 *       pre-shared key is already put in, and the keys of the exchange are not there yet
				 *
				 * \~
				 */
				error_t binder(const view_t & transcript, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода значения упреждающих данных связи
				 *
				 * @param transcript хеш переписки рукопожатия на миг вывода
				 *
				 * @return           отказ вывода значения упреждающих данных
				 *
				 * @details Раздел 7.1 RFC 8446: значение выводится из начальной ступени расписания
				 *          меткою «c e traffic» от одного лишь приветствия клиента - ответа сервера
				 *          на этот миг ещё нет вовсе
				 *
				 * @note Упреждающие данные идут одним лишь направлением от клиента: ответить на
				 *       них сервер вправе не раньше, чем ключами рукопожатия
				 *
				 * \~english
				 * @brief Method of the derivation of the value of the early data of the connection
				 * @param transcript the hash of the transcript of the handshake at the moment of the derivation
				 * @return           the failure of the derivation of the value of the early data
				 * @details The section 7.1 of RFC 8446: the value is derived from the initial stage of the
				 *          schedule by the «c e traffic» label from the greeting of the client alone — there is
				 *          no answer of the server at this moment at all
				 * @note The early data goes by one direction only, from the client: the server is not entitled
				 *       to answer it earlier than by the keys of the handshake
				 *
				 * \~
				 */
				error_t early(const view_t & transcript) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения значения упреждающих данных связи
				 *
				 * @param result место, в которое помещается значение упреждающих данных
				 *
				 * @return       отказ получения значения упреждающих данных
				 *
				 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
				 *
				 * \~english
				 * @brief Method of getting the value of the early data of the connection
				 * @param result the place the value of the early data is put into
				 * @return       the failure of getting the value of the early data
				 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
				 *
				 * \~
				 */
				error_t early(uint8_t * result) const noexcept;
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
				Secrets() noexcept;
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
				~Secrets() noexcept;
		} secrets_t;
	};
};

#endif // __ANYKS_TLS_SESSION__
