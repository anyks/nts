/**
 * @file server.hpp
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
 * @brief Заголовочный файл фасада связи сервера протокола TLS 1.3
 *
 * \~english
 * @brief Header file of the facade of a connection of the server of the TLS 1.3 protocol
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_SERVER__
#define __ANTS_SERVER__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <ocsp/ocsp.hpp>
#include <trust/trust.hpp>
#include <context/context.hpp>
#include <datagram/datagram.hpp>

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
	 * @brief Пространство имён внутренних модулей библиотеки
	 *
	 * \~english
	 * @brief Namespace of the internal modules of the library
	 *
	 * \~
	 */
	namespace internal {
		/**
		 * \~russian
		 * @brief Ведение связи протокола TLS 1.3
		 *
		 * @note Устройство ведения связи наружному договору библиотеки не принадлежит:
		 *       здесь оно лишь объявлено, а лежит во внутренних модулях
		 *
		 * \~english
		 * @brief Leading of a connection of the TLS 1.3 protocol
		 * @note The structure of the leading of a connection does not belong to the outward contract
		 *       of the library: here it is only declared, and it lies in the internal modules
		 *
		 * \~
		 */
		class Engine;
	};

	/**
	 * \~russian
	 * @brief Пространство имён фасада связи сервера
	 *
	 * \~english
	 * @brief Namespace of the facade of a connection of the server
	 *
	 * \~
	 */
	namespace server {
		/**
		 * \~russian
		 * @brief Связь протокола TLS 1.3 со стороны сервера
		 *
		 * @details Ввода и вывода связь не ведёт вовсе: принятые байты подаются ей вызовом
		 *          push, а отправляемые она складывает в накопитель, откуда их забирают
		 *          вызовами output и consume. Сеть, файл или память - дело того, кто связь ведёт.
		 *
		 * @note Настройки устанавливаются до заведения связи вызовом start: за ним они уже
		 *       не действуют
		 *
		 * \~english
		 * @brief Connection of the TLS 1.3 protocol from the side of the server
		 * @details The connection does not lead the input and the output at all: the received bytes are
		 *          given to it by a call of push, and it puts the sent ones into an accumulator they are
		 *          taken from by the calls of output and consume. A network, a file or a memory is the
		 *          business of the one who leads the connection.
		 * @note The settings are set before the establishment of the connection by a call of start: after
		 *       it they do not take effect any more
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Context {
			private:
				// Объект ведения связи протокола
				unique_ptr <internal::Engine> _engine;
			public:
				/**
				 * \~russian
				 * @brief Метод получения состояния связи
				 *
				 * @return состояние связи
				 *
				 * \~english
				 * @brief Method of getting the state of the connection
				 * @return the state of the connection
				 *
				 * \~
				 */
				context::state_t state() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения отказа, которым связь оборвана
				 *
				 * @return отказ, которым связь оборвана
				 *
				 * \~english
				 * @brief Method of getting the failure the connection is torn by
				 * @return the failure the connection is torn by
				 *
				 * \~
				 */
				context::error_t error() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки установленности связи
				 *
				 * @return признак того, что рукопожатие пройдено обеими сторонами
				 *
				 * \~english
				 * @brief Method of checking the establishment of the connection
				 * @return the flag of the handshake being passed by both sides
				 *
				 * \~
				 */
				bool established() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения извещения, которым связь оборвана
				 *
				 * @return извещение, которым связь оборвана
				 *
				 * @note Извещение выводится и своё, и принятое от собеседника: связь рвёт та
				 *       сторона, которая отказ заметила первой
				 *
				 * \~english
				 * @brief Method of getting the alert the connection is torn by
				 * @return the alert the connection is torn by
				 * @note Both one's own alert and the one received from the interlocutor are output: the
				 *       connection is torn by the side which noticed the failure first
				 *
				 * \~
				 */
				const alert::alert_t & alert() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения набора шифрования связи
				 *
				 * @return согласованный сторонами набор шифрования
				 *
				 * \~english
				 * @brief Method of getting the cipher suite of the connection
				 * @return the cipher suite agreed upon by the sides
				 *
				 * \~
				 */
				protect::suite_t suite() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения цепочки сертификатов собеседника
				 *
				 * @return цепочка сертификатов, предъявленная собеседником
				 *
				 * @details Связь сличает подпись владения ключом с ключом первого сертификата
				 *          цепочки: этим рукопожатие и привязано к предъявившей его стороне
				 *
				 * @note Доверие к издателю цепочки связь не проверяет: запас доверенных
				 *       сертификатов принадлежит тому, кто связь ведёт, и решение это его
				 *
				 * \~english
				 * @brief Method of getting the chain of the certificates of the interlocutor
				 * @return the chain of the certificates presented by the interlocutor
				 * @details The connection compares the signature of the possession of the key against the
				 *          key of the first certificate of the chain: by this the handshake is tied to the
				 *          side which presented it
				 * @note The connection does not check the trust to the issuer of the chain: the store of the
				 *       trusted certificates belongs to the one who leads the connection, and this decision
				 *       is theirs
				 *
				 * \~
				 */
				const vector <vector <uint8_t>> & peer() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          опознаватель алгоритма по реестру RFC 8879, ноль у несжатой цепочки
				 *
				 * @details Чтение отвечает цепочке собеседника: ноль означает, что она пришла обычным
				 *          сообщением Certificate. Запись отвечает своей цепочке: ноль означает, что
				 *          общего алгоритма не нашлось либо сжатие у потребителя отказало
				 *
				 * \~english
				 * @brief Method of getting the algorithm of the compression of the chain of the certificates of a direction
				 * @param direction the direction of the connection relative to one's own side
				 * @return          the identifier of the algorithm by the registry of RFC 8879, zero at an uncompressed chain
				 * @details The reading answers to the chain of the interlocutor: zero means that it came by the
				 *          ordinary Certificate message. The writing answers to one's own chain: zero means that
				 *          no common algorithm was found or the compression at the consumer has refused
				 *
				 * \~
				 */
				uint16_t compression(const context::direction_t direction) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения прикладного протокола связи
				 *
				 * @return прикладной протокол, выбранный сторонами связи
				 *
				 * @details Раздел 3.2 RFC 7301: протокол выбирается сервером из предложенного
				 *          клиентом, и объявляется он под защитой рукопожатия
				 *
				 * @note Пустое название значит, что протокол сторонами не выбирался вовсе:
				 *       предлагать его связи никто не поручал
				 *
				 * \~english
				 * @brief Method of getting the application protocol of the connection
				 * @return the application protocol chosen by the sides of the connection
				 * @details The section 3.2 of RFC 7301: the protocol is chosen by the server out of the one
				 *          offered by the client, and it is declared under the protection of the handshake
				 * @note An empty name means that the protocol was not chosen by the sides at all: nobody
				 *       instructed the connection to offer it
				 *
				 * \~
				 */
				const string & protocol() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения имени узла, запрошенного клиентом
				 *
				 * @return имя узла, за которым клиент пришёл
				 *
				 * @details Раздел 3 RFC 6066: по этому имени сервер и выбирает, какой
				 *          подлинностью отвечать клиенту
				 *
				 * @note Связь имя лишь принимает: выбор подлинности по нему принадлежит тому,
				 *       кто связь ведёт, - подлинность устанавливает он
				 *
				 * \~english
				 * @brief Method of getting the name of the host requested by the client
				 * @return the name of the host the client came for
				 * @details The section 3 of RFC 6066: by this name the server chooses which authenticity to
				 *          answer the client by
				 * @note The connection only accepts the name: the choice of the authenticity by it belongs
				 *       to the one who leads the connection — they set the authenticity
				 *
				 * \~
				 */
				const string & name() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения билетов возобновления связи
				 *
				 * @return билеты возобновления связи, выданные клиенту
				 *
				 * @note Билет и ключ к нему хранит тот, кто связь ведёт: связь их лишь выдаёт,
				 *       а держать их между связями ей негде
				 *
				 * \~english
				 * @brief Method of getting the tickets of the resumption of the connection
				 * @return the tickets of the resumption of the connection issued to the client
				 * @note The ticket and the key to it are kept by the one who leads the connection: the connection
				 *       only outputs them, and it has nowhere to keep them between the connections
				 *
				 * \~
				 */
				const vector <context::ticket_t> & tickets() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки возобновления связи билетом
				 *
				 * @return признак того, что связь возобновлена заранее разделённым ключом
				 *
				 * @note При возобновлении цепочки сертификатов не бывает вовсе: подлинность
				 *       сторон подтверждена билетом, а не сертификатом
				 *
				 * \~english
				 * @brief Method of checking the resumption of the connection by a ticket
				 * @return the flag of the connection being resumed by a pre-shared key
				 * @note At a resumption there is no chain of the certificates at all: the authenticity of the
				 *       sides is confirmed by the ticket and not by a certificate
				 *
				 * \~
				 */
				bool shared() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых наборов шифрования
				 *
				 * @param suites устанавливаемые наборы шифрования
				 *
				 * @note Наборы перечисляются от предпочтительного к запасному
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 *
				 * \~english
				 * @brief Method of setting the offered cipher suites
				 * @param suites the cipher suites being set
				 * @note The suites are listed from the preferable one to the spare one
				 * @note An empty list skips the setting, keeping the set having been set before
				 *
				 * \~
				 */
				void suites(const vector <protect::suite_t> & suites) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки пределов издания протокола
				 *
				 * @param lowest  наименьшее дозволенное издание: 0x0303 (издание 1.2) либо 0x0304 (издание 1.3)
				 * @param highest наибольшее дозволенное издание: 0x0303 либо 0x0304
				 *
				 * @return        отказ установки: SETTINGS у издания ниже TLS 1.2 либо перевёрнутых
				 *                пределов, STATE у уже заведённой связи
				 *
				 * @details Раздел 4.2.1 RFC 8446 и приложение D RFC 8446: клиент объявляет издания
				 *          расширением supported_versions, сервер выбирает высшее общее; чужая
				 *          сторона без расширения ведёт связь изданием заголовка приветствия -
				 *          TLS 1.2. Умолчание - от 1.2 до 1.3; режим «только 1.3» - оба предела
				 *          0x0304; ниже 1.2 связь не опускается никогда
				 *
				 * @note Издания задаются и отдаются кодами TLS 0x0303/0x0304 на любом переносе; на
				 *       проводе DTLS они ложатся как 0xFEFD/0xFEFC. Поверх дейтаграмм 0x0303 отвечает
				 *       DTLS 1.2 (RFC 6347), 0x0304 - DTLS 1.3 (RFC 9147); под QUIC связь знает одно
				 *       издание 1.3
				 *
				 * \~english
				 * @brief Method of setting the limits of the edition of the protocol
				 * @param lowest  the lowest allowed edition: 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3)
				 * @param highest the highest allowed edition: 0x0303 or 0x0304
				 * @return        the failure of the setting: SETTINGS at an edition below TLS 1.2 or at inverted
				 *                limits, STATE at an already established connection
				 * @details The section 4.2.1 of RFC 8446 and the appendix D of RFC 8446: the client announces the
				 *          editions by the supported_versions extension, the server chooses the highest common one;
				 *          a foreign side without the extension conducts the connection by the edition of the header
				 *          of the greeting - TLS 1.2. The default is from 1.2 to 1.3; the «1.3 only» mode - both
				 *          limits 0x0304; the connection never goes below 1.2
				 * @note The editions are set and returned by the TLS codes 0x0303/0x0304 on any transport; on the
				 *       DTLS wire they are laid as 0xFEFD/0xFEFC. Over datagrams 0x0303 stands for DTLS 1.2
				 *       (RFC 6347), 0x0304 - for DTLS 1.3 (RFC 9147); under QUIC the connection knows the 1.3
				 *       edition alone
				 *
				 * \~
				 */
				context::error_t versions(const uint16_t lowest, const uint16_t highest) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения наименьшего дозволенного издания протокола
				 *
				 * @return наименьшее дозволенное издание протокола
				 *
				 * \~english
				 * @brief Method of getting the lowest allowed edition of the protocol
				 * @return the lowest allowed edition of the protocol
				 *
				 * \~
				 */
				uint16_t lowest() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения наибольшего дозволенного издания протокола
				 *
				 * @return наибольшее дозволенное издание протокола
				 *
				 * \~english
				 * @brief Method of getting the highest allowed edition of the protocol
				 * @return the highest allowed edition of the protocol
				 *
				 * \~
				 */
				uint16_t highest() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения издания протокола, согласованного сторонами
				 *
				 * @return 0x0304 у издания 1.3, 0x0303 у издания 1.2, ноль до согласования
				 *
				 * @note Издания задаются и отдаются кодами TLS 0x0303/0x0304 на любом переносе; на
				 *       проводе DTLS они ложатся как 0xFEFD/0xFEFC. Проводное издание наружу не
				 *       показывается: 0x0303 поверх дейтаграмм означает DTLS 1.2, 0x0304 - DTLS 1.3
				 *
				 * \~english
				 * @brief Method of getting the edition of the protocol agreed by the sides
				 * @return 0x0304 at the 1.3 edition, 0x0303 at the 1.2 edition, a zero before the agreement
				 * @note The editions are set and returned by the TLS codes 0x0303/0x0304 on any transport; on the
				 *       DTLS wire they are laid as 0xFEFD/0xFEFC. The wire edition is not shown outside: 0x0303
				 *       over datagrams means DTLS 1.2, 0x0304 - DTLS 1.3
				 *
				 * \~
				 */
				uint16_t version() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки порядка выбора набора шифрования изданием TLS 1.2
				 *
				 * @param own выбирается ли набор порядком сервера (умолчание), а не клиента
				 *
				 * @details Раздел 7.4.1.2 RFC 5246 велит выбирать набор серверу; порядком клиента
				 *          сервер выбирает, когда потребитель так велел. Издания TLS 1.3 настройка
				 *          не касается: там выбор идёт порядком сервера как прежде
				 *
				 * \~english
				 * @brief Method of setting the order of the choice of the cipher suite by the TLS 1.2 edition
				 * @param own whether the suite is chosen by the order of the server (the default) and not of the client
				 * @details The section 7.4.1.2 of RFC 5246 orders the server to choose the suite; the server chooses
				 *          by the order of the client when the consumer has told so. The setting does not touch the
				 *          TLS 1.3 edition: there the choice goes by the order of the server as before
				 *
				 * \~
				 */
				void preference(const bool own) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых кривых обмена ключами
				 *
				 * @param groups устанавливаемые кривые обмена ключами
				 *
				 * @note Кривые перечисляются от предпочтительной к запасной
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 *
				 * \~english
				 * @brief Method of setting the offered curves of the key exchange
				 * @param groups the curves of the key exchange being set
				 * @note The curves are listed from the preferable one to the spare one
				 * @note An empty list skips the setting, keeping the set having been set before
				 *
				 * \~
				 */
				void groups(const vector <extension::group_t> & groups) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки признаваемых схем подписи
				 *
				 * @param schemes устанавливаемые схемы подписи
				 *
				 * @note Схемы перечисляются от предпочтительной к запасной; перечень объявляется
				 *       собеседнику и им же выбирается схема своей подписи по своему ключу
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 *
				 * \~english
				 * @brief Method of setting the recognized signature schemes
				 * @param schemes the signature schemes being set
				 * @note The schemes are listed from the preferable one to the spare one; the list is declared
				 *       to the peer and by it the scheme of the own signature is chosen by the own key
				 * @note An empty list skips the setting, keeping the set having been set before
				 *
				 * \~
				 */
				void schemes(const vector <extension::scheme_t> & schemes) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
				 *
				 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
				 * @param inflation предел длины цепочки после распаковки в байтах, ноль оставляет умолчание 65536
				 *
				 * @details RFC 8879: алгоритмы предоставляет потребитель, библиотека ни одного не
				 *          несёт. Сервер выбирает алгоритм из объявленных клиентом и объявляет свой
				 *          перечень запросом подлинности клиента.
				 *          Цепочка сжимается первым общим алгоритмом по порядку объявившей стороны;
				 *          неведомые значения собеседника пропускаются молча
				 *
				 * @note Пустой перечень выключает сжатие: расширение не объявляется, и рукопожатие
				 *       идёт байт в байт как без него
				 * @note Алгоритм без обоих вызовов либо с нулевым опознавателем заводить связь не
				 *       даёт: отказ настроек
				 *
				 * \~english
				 * @brief Method of setting the algorithms of the compression of the chain of the certificates
				 * @param codecs    the algorithms being set in the order of the preference
				 * @param inflation the limit of the length of the chain after the decompression in bytes, zero keeps the default of 65536
				 * @details RFC 8879: the algorithms are provided by the consumer, the library carries none.
				 *          The server chooses the algorithm from the ones announced by the client and
				 *          announces its own list by the request of the authenticity of the client.
				 *          The chain is compressed by the first common algorithm in the order of the announcing
				 *          side; the values of the peer unknown to the connection are skipped silently
				 * @note An empty list switches the compression off: the extension is not announced, and the
				 *       handshake goes byte for byte as without it
				 * @note An algorithm without both calls or with a zero identifier does not let the connection
				 *       be established: the failure of the settings
				 *
				 * \~
				 */
				void codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки запроса состояния сертификата собеседника
				 *
				 * @param request запрашивается ли состояние сертификата собеседника
				 *
				 * @details Раздел 4.4.2.1 RFC 8446 и раздел 8 RFC 6066: запрос идёт расширением
				 *          status_request (0x0005) запроса подлинности клиента; ответ приходит расширением записи
				 *          цепочки сертификатов собеседника и доступен вызовом status()
				 *
				 * @note Отсутствие ответа при запросе отказом не считается: собеседник вправе
				 *       не отвечать, а потребитель узнаёт об этом пустым ответом
				 *
				 * @note Запрос самодостаточен: расширение уходит и без иных настроек связи,
				 *       а полученный ответ сам по себе связь не судит - проверка включается
				 *       только явно вызовом verification(), иначе ответ лишь отдаётся наружу
				 *
				 * \~english
				 * @brief Method of setting the request of the certificate status of the peer
				 * @param request whether the certificate status of the peer is requested
				 * @details The section 4.4.2.1 of RFC 8446 and the section 8 of RFC 6066: the request goes as the
				 *          extension status_request (0x0005) of the certificate request; the response comes as an extension of the
				 *          entry of the certificate chain of the peer and is available by the call of status()
				 * @note The absence of a response upon the request is not considered a failure: the peer is entitled
				 *       not to respond, and the consumer learns about it by an empty response
				 * @note The request is self-sufficient: the extension goes without any other settings of the connection,
				 *       and a received response does not judge the connection by itself - the check is enabled only
				 *       explicitly by the call of verification(), otherwise the response is merely given outside
				 *
				 * \~
				 */
				void status(const bool request) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ответа о состоянии своего сертификата для сшивки
				 *
				 * @param response запись ответа OCSP по RFC 6960, пустая снимает ответ
				 * @param index    место сертификата в своей цепочке, ноль - лист
				 *
				 * @details Ответ ответчика получает потребитель сам (адрес - ocsp::responder,
				 *          запрос - ocsp::request) и подаёт октетами; связь его не разбирает,
				 *          а сшивает в расширение status_request записи цепочки по запросу
				 *          собеседника (раздел 4.4.2.1 RFC 8446, раздел 8 RFC 6066)
				 *
				 * \~english
				 * @brief Method of setting the status response of the own certificate for the stapling
				 * @param response the record of the OCSP response according to RFC 6960, an empty one removes the response
				 * @param index    the place of the certificate in the own chain, zero is the leaf
				 * @details The response of the responder is obtained by the consumer itself (the address is
				 *          ocsp::responder, the request is ocsp::request) and is given as octets; the connection
				 *          does not parse it but staples it into the extension status_request of the entry of the
				 *          chain upon the request of the peer (the section 4.4.2.1 of RFC 8446, the section 8 of RFC 6066)
				 *
				 * \~
				 */
				void status(const vector <uint8_t> & response, const size_t index = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ответа о состоянии сертификата собеседника
				 *
				 * @return запись ответа OCSP по RFC 6960 либо пустой накопитель
				 *
				 * @note Ответ отдаётся как принят - и без проверки, и с ней; разобрать его
				 *       потребитель вправе модулем ocsp
				 *
				 * \~english
				 * @brief Method of getting the certificate status response of the peer
				 * @return the record of the OCSP response according to RFC 6960 or an empty accumulator
				 * @note The response is given out as received - both without the check and with it; the consumer
				 *       is entitled to parse it by the ocsp module
				 *
				 * \~
				 */
				const vector <uint8_t> & status() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки проверки принятого ответа о состоянии сертификата
				 *
				 * @param verify проверяется ли принятый ответ связью
				 * @param leeway дозволенный люфт сроков ответа в секундах в обе стороны
				 * @param store  запас доверенных сертификатов для розыска издателя собеседника
				 *
				 * @details Ответ проверяется модулем ocsp против первого сертификата цепочки
				 *          собеседника и его издателя: издатель берётся вторым звеном цепочки,
				 *          у самоподписанного сертификата - им самим, а у цепочки из одного
				 *          сертификата - из запаса по имени издателя. Сроки судятся мигом,
				 *          установленным вызовом moment(); нулевой миг сроки не судит,
				 *          а миг, отстоящий от срока ответа, законно даёт отказ EXPIRED - это
				 *          не порок ответчика, а часы потребителя.
				 *          Негодный ответ и отозванный сертификат обрывают связь извещением
				 *          «bad_certificate_status_response» (113); неведомый ответчику
				 *          сертификат связь не обрывает - состояние доступно вызовом certified()
				 *
				 * \~english
				 * @brief Method of setting the check of the received certificate status response
				 * @param verify whether the received response is checked by the connection
				 * @param leeway the allowed slack of the validity of the response in seconds in both directions
				 * @param store  the store of the trusted certificates for the search of the issuer of the peer
				 * @details The response is checked by the ocsp module against the first certificate of the chain of
				 *          the peer and its issuer: the issuer is taken as the second link of the chain, for a
				 *          self-signed certificate - as itself, and for a chain of a single certificate - from the
				 *          store by the name of the issuer. The validity is judged by the moment set by the call of
				 *          moment(); a zero moment does not judge the validity, while a moment away from the
				 *          validity of the response lawfully yields the failure EXPIRED - that is not a fault of the
				 *          responder but the clock of the consumer. An unsuitable response and a revoked
				 *          certificate tear the connection by the alert «bad_certificate_status_response» (113); a
				 *          certificate unknown to the responder does not tear the connection - the status is
				 *          available by the call of certified()
				 *
				 * \~
				 */
				void verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения состояния сертификата собеседника
				 *
				 * @return состояние по проверенному ответу либо ocsp::status_t::NONE
				 *
				 * \~english
				 * @brief Method of getting the certificate status of the peer
				 * @return the status by the checked response or ocsp::status_t::NONE
				 *
				 * \~
				 */
				ocsp::status_t certified() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки подлинности своей стороны связи
				 *
				 * @param credential устанавливаемая подлинность своей стороны
				 *
				 * @note Подлинность сервера обязательна: без своего сертификата и ключа связь не
				 *       заводится вовсе
				 *
				 * \~english
				 * @brief Method of setting the authenticity of one's own side of the connection
				 * @param credential the authenticity of one's own side being set
				 * @note The authenticity of the server is obligatory: without one’s own certificate and key the
				 *       connection is not established at all
				 *
				 * \~
				 */
				void credential(const context::credential_t & credential) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых прикладных протоколов
				 *
				 * @param protocols устанавливаемые прикладные протоколы
				 *
				 * @details Раздел 3.1 RFC 7301: порядок перечня объявляет предпочтение стороны,
				 *          а выбор из него делает сервер
				 *
				 * @note Пустой перечень отключает выбор прикладного протокола вовсе
				 *
				 * \~english
				 * @brief Method of setting the offered application protocols
				 * @param protocols the application protocols being set
				 * @details The section 3.1 of RFC 7301: the order of the list declares the preference of the
				 *          side, and the choice out of it is made by the server
				 * @note An empty list disables the choice of the application protocol at all
				 *
				 * \~
				 */
				void protocols(const vector <string> & protocols) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки метки возврата состояния сервера
				 *
				 * @param cookie устанавливаемая метка возврата состояния
				 *
				 * @details Раздел 4.2.2 RFC 8446: меткой сервер возвращает себе своё состояние,
				 *          не храня его у себя между приветствиями клиента
				 *
				 * @note Содержимое метки складывает потребитель: связь несёт её дословно и
				 *       ничего в ней не разбирает. Метка уходит лишь просьбой о повторе
				 *       приветствия, а пустая метка отключает её выдачу вовсе
				 *
				 * \~english
				 * @brief Method of setting the label of the return of the state of the server
				 * @param cookie the label of the return of the state being set
				 * @details The section 4.2.2 of RFC 8446: by the label the server returns its state
				 *          to itself without storing it at itself between the greetings of the client
				 * @note The content of the label is composed by the consumer: the connection carries
				 *       it verbatim and parses nothing in it. The label goes only with the request of
				 *       the repetition of the greeting, and an empty label disables its issuing at all
				 *
				 * \~
				 */
				void cookie(const vector <uint8_t> & cookie) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения метки возврата состояния сервера
				 *
				 * @return метка возврата состояния, повторённая клиентом
				 *
				 * @note Пустая метка означает, что клиент её не повторил: судит о том, годна
				 *       ли метка и та ли она вовсе, сам потребитель
				 *
				 * \~english
				 * @brief Method of getting the label of the return of the state of the server
				 * @return the label of the return of the state repeated by the client
				 * @note An empty label means that the client has not repeated it: the consumer
				 *       itself judges whether the label is suitable and whether it is the same one
				 *
				 * \~
				 */
				const vector <uint8_t> & cookie() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки мига, которым судятся сроки билетов
				 *
				 * @param moment устанавливаемый миг в секундах
				 *
				 * @details Раздел 4.6.1 RFC 8446: билет годен не дольше объявленного срока,
				 *          а раздел 4.2.10 велит сличать объявленный возраст билета с
				 *          наблюдаемым, прежде чем принимать упреждающие данные
				 *
				 * @note Часов связь не читает: миг подаётся ей доводом, оттого ход её
				 *       повторим и проверяем. Нулевой миг сроки судить запрещает вовсе -
				 *       билет тогда идёт в дело как есть
				 *
				 * @note Повторную подачу упреждающих данных этот миг не ловит: второй раз
				 *       билет предъявляется уже другой связи, и заслон от повтора ставит
				 *       тот, кому принадлежат билеты
				 *
				 * \~english
				 * @brief Method of setting the moment the terms of the tickets are judged by
				 * @param moment the moment being set in the seconds
				 * @details The section 4.6.1 of RFC 8446: a ticket is valid no longer than the declared term,
				 *          and the section 4.2.10 orders to compare the declared age of a ticket against the
				 *          observed one before accepting the early data
				 * @note The connection does not read the clock: the moment is given to it by an argument, so
				 *       its course is repeatable and checkable. A zero moment forbids judging the terms at
				 *       all — a ticket then goes into the work as it is
				 * @note This moment does not catch the repeated submission of the early data: the second time
				 *       a ticket is presented to a different connection already, and the guard against the
				 *       repetition is set by the one the tickets belong to
				 *
				 * \~
				 */
				void moment(const int64_t moment) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки срока жизни выдаваемых билетов
				 *
				 * @param lifetime устанавливаемый срок в секундах
				 *
				 * @details Раздел 4.6.1 RFC 8446 кладёт сроку билета семь суток: больший срок
				 *          усекается до семи суток, а нулевой возвращает срок по умолчанию -
				 *          два часа
				 *
				 * @note Срок действует на билеты, выдаваемые после его установки; уже
				 *       выданные билеты своего срока не меняют
				 *
				 * \~english
				 * @brief Method of setting the lifetime of the tickets being issued
				 * @param lifetime the term being set in the seconds
				 * @details The section 4.6.1 of RFC 8446 lays seven days to the term of a ticket: a bigger
				 *          term is cut to seven days, and a zero one returns the default term — two hours
				 * @note The term acts on the tickets issued after its setting; the tickets already issued
				 *       do not change their term
				 *
				 * \~
				 */
				void lifetime(const uint32_t lifetime) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки требования подлинности клиента
				 *
				 * @param request устанавливаемое требование подлинности клиента
				 *
				 * @details Раздел 4.3.2 RFC 8446: сервер вправе запросить у клиента подлинность,
				 *          а клиент вправе ответить пустой цепочкой, годного сертификата не найдя
				 *
				 * @note Пустой ответ клиента связь отказом не считает: решение о допуске такого
				 *       клиента принадлежит тому, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of setting the requirement of the authenticity of the client
				 * @param request the requirement of the authenticity of the client being set
				 * @details The section 4.3.2 of RFC 8446: the server is entitled to request the authenticity
				 *          from the client, and the client is entitled to answer by an empty chain, having not
				 *          found a suitable certificate
				 * @note The connection does not consider an empty answer of the client a failure: the decision
				 *       about the admission of such a client belongs to the one who leads the connection
				 *
				 * \~
				 */
				void request(const bool request) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки признаваемых билетов возобновления связи
				 *
				 * @param tickets признаваемые билеты возобновления связи
				 *
				 * @details Раздел 4.6.1 RFC 8446: билеты сервер выдал сам прошлыми связями, а
				 *          хранил их между связями тот, кто связь ведёт: связи их и подавать
				 *
				 * @note Предъявленный билет признаётся лишь тогда, когда сошлась его привязка:
				 *       ею клиент и доказывает владение ключом билета, а не одним его телом
				 *
				 * \~english
				 * @brief Method of setting the recognized tickets of the resumption of a connection
				 * @param tickets the recognized tickets of the resumption of the connection
				 * @details The section 4.6.1 of RFC 8446: the tickets were issued by the server itself by the
				 *          past connections, and they were kept between the connections by the one who leads
				 *          the connection: it is for them to give them to the connection
				 * @note A presented ticket is recognized only when its binder has converged: by it the client
				 *       proves the possession of the key of the ticket and not of its body alone
				 *
				 * \~
				 */
				void resume(const vector <context::ticket_t> & tickets) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки приёма упреждающих данных клиента
				 *
				 * @param advance принимаются ли упреждающие данные
				 * @param limit   предел упреждающих данных в байтах, объявляемый билетом
				 *
				 * @details Раздел 2.3 RFC 8446: упреждающие данные уходят вместе с приветствием
				 *          клиента, не дожидаясь ответа сервера, и защищены ключами, выведенными
				 *          из одного лишь билета возобновления связи.
				 *
				 * @note Повтор упреждающих данных протоколом не отсекается: та же запись, посланная
				 *       злоумышленником заново, будет принята повторно, и заслон этому ставит тот,
				 *       кто связь ведёт, - повторяемые запросы упреждающими данными не принимать
				 *
				 * \~english
				 * @brief Method of setting the acceptance of the early data of the client
				 * @param advance whether the early data is accepted
				 * @param limit   the limit of the early data in the bytes declared by a ticket
				 * @details The section 2.3 of RFC 8446: the early data goes together with the greeting of the
				 *          client without waiting for the answer of the server, and it is protected by the keys
				 *          derived from the ticket of the resumption of the connection alone.
				 * @note A repetition of the early data is not cut off by the protocol: the same record sent
				 *       anew by an attacker will be accepted repeatedly, and the barrier to it is set by the
				 *       one who leads the connection — not to accept repeatable requests by the early data
				 *
				 * \~
				 */
				void advance(const bool advance, const uint32_t limit = 16384) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки приёма упреждающих данных связью
				 *
				 * @return признак того, что упреждающие данные связью приняты
				 *
				 * @note Упреждающие данные связь вправе и отвергнуть: расхождение объявленного
				 *       возраста билета с наблюдаемым, иной набор шифрования либо иной прикладной
				 *       протокол приёму их препятствуют. Отвергнутые записи связь пропускает молча,
				 *       как и велит раздел 4.2.10 RFC 8446, и по пустоте прочитанного отказ приёма
				 *       от их отсутствия неотличим - оттого о приёме и объявляется отдельно
				 *
				 * @note Принятые упреждающие данные могли быть поданы повторно: протокол повтора не
				 *       отсекает, и знать о приёме нужно затем, чтобы решить, как с таким повтором
				 *       обходиться
				 *
				 * \~english
				 * @brief Method of checking the acceptance of the early data by the connection
				 * @return the flag of the early data being accepted by the connection
				 * @note The connection has the right to reject the early data as well: a divergence of the
				 *       declared age of a ticket from the observed one, another cipher suite or another
				 *       application protocol prevent its acceptance. The rejected records are skipped by the
				 *       connection silently as the section 4.2.10 of RFC 8446 prescribes, and by the emptiness
				 *       of what has been read a rejection is indistinguishable from an absence — that is why
				 *       the acceptance is announced separately
				 * @note The accepted early data could have been submitted repeatedly: the protocol does not cut
				 *       off a repetition, and the acceptance needs to be known in order to decide how to deal
				 *       with such a repetition
				 *
				 * \~
				 */
				bool accepted() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки порядка смены ключей по счётчику записей
				 *
				 * @param automatic сменяет ли движок ключи сам по счётчику записей
				 * @param records   число записей направления, по которому идёт смена
				 *
				 * @details Раздел 5.5 RFC 8446: смена ключевого материала обязана идти впереди
				 *          предела порядковых номеров записей. В самодеятельном порядке движок
				 *          сменяет ключи своего направления сам, дойдя счётчиком до порога, а у
				 *          собеседника испрашивает смену просьбою в KeyUpdate; в ручном порядке
				 *          за счётчиком следит тот, кто связь ведёт, методами sequence() и update()
				 *
				 * @note Нулевое число записей означает половину предела набора шифрования: столько
				 *       же места остаётся собеседнику ответить на просьбу, сколько берёт своё
				 *       направление. По умолчанию порядок самодеятельный
				 *
				 * \~english
				 * @brief Method of setting the order of the change of the keys by the counter of the records
				 * @param automatic whether the engine changes the keys itself by the counter of the records
				 * @param records   the number of the records of a direction at which the change goes
				 * @details The section 5.5 of RFC 8446: the change of the key material must go ahead of the
				 *          limit of the sequence numbers of the records. In the automatic order the engine
				 *          changes the keys of its own direction itself having reached the threshold by the
				 *          counter, and asks the interlocutor for the change by the request in KeyUpdate; in
				 *          the manual order the one who leads the connection watches the counter by the
				 *          methods sequence() and update()
				 * @note The zero number of the records means a half of the limit of the cipher suite: as much
				 *       room is left to the interlocutor to answer the request as one's own direction takes.
				 *       The automatic order is the default
				 *
				 * \~
				 */
				void renewal(const bool automatic, const uint64_t records = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения счётчика записей направления связи
				 *
				 * @param incoming запрашивается ли направление собеседника
				 *
				 * @return         число записей направления на текущих ключах
				 *
				 * @details Раздел 5.3 RFC 8446: счётчик начинается заново с каждой сменой ключей
				 *          направления, оттого он равен числу записей, прошедших на текущих ключах
				 *
				 * \~english
				 * @brief Method of getting the counter of the records of a direction of the connection
				 * @param incoming whether the direction of the interlocutor is requested
				 * @return         the number of the records of the direction under the current keys
				 * @details The section 5.3 of RFC 8446: the counter starts anew with each change of the keys of
				 *          the direction, hence it equals the number of the records passed under the current keys
				 *
				 * \~
				 */
				uint64_t sequence(const bool incoming = false) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки способа переноса рукопожатия
				 *
				 * @param transport устанавливаемый способ переноса
				 *
				 * @details Записями протокола (умолчание) связь ведёт TLS поверх потока: сама
				 *          защищает записи и разбирает их заголовки. Сообщениями по уровням она
				 *          ведёт рукопожатие под QUIC (RFC 9001): принимает и выдаёт голые
				 *          сообщения рукопожатия с пометкой уровня защиты, а записи, извещения,
				 *          смена ключей KeyUpdate и конец упреждающих данных в этом переносе не
				 *          идут вовсе - их берёт на себя перенос QUIC
				 *
				 * @note Способ переноса устанавливается до заведения связи
				 *
				 * @note Перенос по уровням без прикладных протоколов protocols() и без
				 *       параметров переноса parameters() связь не заводит (отказ SETTINGS):
				 *       под QUIC и то, и другое обязательно, и молчание тут было бы дефектом
				 *
				 * \~english
				 * @brief Method of setting the way of the transport of the handshake
				 * @param transport the way of the transport being set
				 * @details By the records of the protocol (the default) the connection leads TLS over a stream:
				 *          it protects the records and parses their headers itself. By the messages by levels it
				 *          leads the handshake under QUIC (RFC 9001): it accepts and gives out bare messages of
				 *          the handshake marked with a protection level, while the records, the alerts, the change
				 *          of the keys by KeyUpdate and the end of the early data do not go in this transport at
				 *          all — the QUIC transport takes them upon itself
				 * @note The way of the transport is set before the establishment of the connection
				 * @note The transport by levels without the application protocols protocols() and without the
				 *       transport parameters parameters() does not establish the connection (the failure SETTINGS):
				 *       under QUIC both are mandatory, and silence here would be a defect
				 *
				 * \~
				 */
				void transport(const context::transport_t transport) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения способа переноса рукопожатия
				 *
				 * @return способ переноса рукопожатия связи
				 *
				 * \~english
				 * @brief Method of getting the way of the transport of the handshake
				 * @return the way of the transport of the handshake of the connection
				 *
				 * \~
				 */
				context::transport_t transport() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки своих параметров переноса QUIC
				 *
				 * @param parameters устанавливаемые параметры переноса в записи QUIC
				 *
				 * @details Раздел 8.2 RFC 9001: параметры уходят расширением
				 *          quic_transport_parameters как есть - связь их не толкует. Клиент кладёт
				 *          их в приветствие, сервер - в защищённые расширения
				 *
				 * @note Расширение идёт лишь при переносе по уровням; переносу записями оно не
				 *       положено, и принятое там отвергается
				 *
				 * \~english
				 * @brief Method of setting one's own QUIC transport parameters
				 * @param parameters the transport parameters being set in the QUIC encoding
				 * @details The section 8.2 of RFC 9001: the parameters go by the quic_transport_parameters
				 *          extension as they are — the connection does not interpret them. The client puts them
				 *          into the greeting, the server — into the encrypted extensions
				 * @note The extension goes only at the transport by levels; the transport by records is not
				 *       entitled to it, and one received there is rejected
				 *
				 * \~
				 */
				void parameters(const vector <uint8_t> & parameters) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения параметров переноса QUIC собеседника
				 *
				 * @return параметры переноса, принятые от собеседника как есть
				 *
				 * @note Приняты ли параметры вовсе, говорит acquired(): пустые параметры от
				 *       отсутствующих пустотой не отличить
				 *
				 * \~english
				 * @brief Method of getting the QUIC transport parameters of the interlocutor
				 * @return the transport parameters received from the interlocutor as they are
				 * @note Whether the parameters are received at all is told by acquired(): empty parameters
				 *       cannot be distinguished from absent ones by the emptiness
				 *
				 * \~
				 */
				const vector <uint8_t> & parameters() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки приёма параметров переноса собеседника
				 *
				 * @return признак того, что параметры переноса собеседника приняты
				 *
				 * \~english
				 * @brief Method of checking the receipt of the transport parameters of the interlocutor
				 * @return the flag of the transport parameters of the interlocutor being received
				 *
				 * \~
				 */
				bool acquired() const noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
				 *
				 * @param level уровень защиты, на котором сообщения приняты
				 * @param data  принятые сообщения рукопожатия без обвязки записей (данные CRYPTO)
				 *
				 * @return      отказ разбора принятых сообщений
				 *
				 * @details Раздел 4.1.3 RFC 9001: сообщения подаются как пришли по потоку CRYPTO
				 *          уровня, границы сообщений связь восстанавливает сама. Раздел 4.1.4:
				 *          сообщение не на своём уровне обрывает связь отказом LEVEL с извещением
				 *          unexpected_message; уровень упреждающих данных сообщений не несёт
				 *
				 * @note Подача переносу записями отвечает отказом LEVEL без обрыва связи
				 *
				 * \~english
				 * @brief Method of the giving of the messages of the handshake of a protection level to the connection
				 * @param level the protection level the messages are received at
				 * @param data  the received messages of the handshake without the records framing (the CRYPTO data)
				 * @return      the failure of the parsing of the received messages
				 * @details The section 4.1.3 of RFC 9001: the messages are given as they came by the CRYPTO stream
				 *          of the level, the connection restores the boundaries of the messages itself. The section
				 *          4.1.4: a message not at its level tears the connection by the LEVEL failure with the
				 *          unexpected_message alert; the level of the early data carries no messages
				 * @note The giving to the transport by records answers by the LEVEL failure without tearing the connection
				 *
				 * \~
				 */
				context::error_t push(const context::level_t level, const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения сообщений рукопожатия, отправляемых на уровне защиты
				 *
				 * @param level уровень защиты, сообщения которого запрашиваются
				 *
				 * @return      накопленные сообщения рукопожатия уровня без обвязки записей
				 *
				 * \~english
				 * @brief Method of getting the messages of the handshake sent at a protection level
				 * @param level the protection level whose messages are requested
				 * @return      the accumulated messages of the handshake of the level without the records framing
				 *
				 * \~
				 */
				view_t output(const context::level_t level) const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия отправленных сообщений с накопителя уровня защиты
				 *
				 * @param level уровень защиты, с накопителя которого снимаются сообщения
				 * @param size  размер снимаемых байтов
				 *
				 * \~english
				 * @brief Method of the removal of the sent messages from the accumulator of a protection level
				 * @param level the protection level whose accumulator the messages are removed from
				 * @param size  the size of the bytes being removed
				 *
				 * \~
				 */
				void consume(const context::level_t level, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения значения направления связи уровня защиты
				 *
				 * @param level     уровень защиты: EARLY, HANDSHAKE либо APPLICATION
				 * @param direction направление связи относительно своей стороны
				 * @param result    место, в которое помещается значение; nullptr - лишь опрос длины
				 * @param size      место, в которое помещается длина значения по хешу набора
				 *
				 * @return          признак того, что значение уровня уже выведено
				 *
				 * @details Раздел 7.1 RFC 8446: выдаются client_early_traffic_secret,
				 *          {client,server}_handshake_traffic_secret и
				 *          {client,server}_application_traffic_secret; ключ, вектор и защиту
				 *          заголовка (метки «quic key», «quic iv», «quic hp» по разделу 5.1 RFC
				 *          9001) выводит из них тот, кто связь ведёт. Значения прикладных данных
				 *          доступны и после рукопожатия: следующее поколение по разделу 6 RFC 9001
				 *          («quic ku») выводится из текущего
				 *
				 * @note Место под значение обязано вмещать schedule::SCHEDULE_WIDEST байтов
				 *
				 * \~english
				 * @brief Method of getting the traffic secret of a direction of the connection of a protection level
				 * @param level     the protection level: EARLY, HANDSHAKE or APPLICATION
				 * @param direction the direction of the connection relative to one's own side
				 * @param result    the place the secret is put into; nullptr — only the query of the length
				 * @param size      the place the length of the secret by the hash of the suite is put into
				 * @return          the flag of the secret of the level being already derived
				 * @details The section 7.1 of RFC 8446: client_early_traffic_secret,
				 *          {client,server}_handshake_traffic_secret and {client,server}_application_traffic_secret
				 *          are given out; the key, the vector and the header protection (the labels «quic key»,
				 *          «quic iv», «quic hp» by the section 5.1 of RFC 9001) are derived from them by the one who
				 *          leads the connection. The secrets of the application data are available after the
				 *          handshake too: the next generation by the section 6 of RFC 9001 («quic ku») is derived
				 *          from the current one
				 * @note The place for the secret must hold schedule::SCHEDULE_WIDEST bytes
				 *
				 * \~
				 */
				bool secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения уровня защиты, ключи которого готовы направлению
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          наивысший уровень защиты, ключи которого у направления есть
				 *
				 * @note Упреждающие данные клиента объявляются уровнем EARLY, пока стороны не
				 *       перешли к ключам рукопожатия
				 *
				 * \~english
				 * @brief Method of getting the protection level whose keys are ready for a direction
				 * @param direction the direction of the connection relative to one's own side
				 * @return          the highest protection level whose keys the direction has
				 * @note The early data of the client is announced by the EARLY level until the sides have moved
				 *       to the keys of the handshake
				 *
				 * \~
				 */
				context::level_t level(const context::direction_t direction) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки хода упреждающих данных прямо сейчас
				 *
				 * @return признак того, что упреждающие данные идут прямо сейчас
				 *
				 * \~english
				 * @brief Method of checking the early data going right now
				 * @return the flag of the early data going right now
				 *
				 * \~
				 */
				bool earlying() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки размера дейтаграммы связи
				 *
				 * @param mtu устанавливаемый размер дейтаграммы в байтах
				 *
				 * @details Раздел 4.4 RFC 9147: поверх дейтаграмм всякая выдаваемая дейтаграмма не
				 *          длиннее этого размера, а сообщения рукопожатия дробятся под него на
				 *          куски. Умолчание - 1200 байтов; размер ниже наименьшего дозволенного
				 *          (DATAGRAM_MTU_LEAST) поднимается до него, верхнего предела нет: по SCTP
				 *          сообщения бывают длиннее 1500 байтов, а запись протокола и так не
				 *          шире 2^14 байтов. Принимаемые дейтаграммы этим размером не
				 *          ограничены: стороны с разным размером сходятся
				 *
				 * @note Размер устанавливается до заведения связи и значим лишь переносу дейтаграммами
				 *
				 * \~english
				 * @brief Method of setting the size of a datagram of the connection
				 * @param mtu the size of a datagram in bytes being set
				 * @details The section 4.4 of RFC 9147: over datagrams every datagram given out is not longer
				 *          than this size, and the messages of the handshake are split into fragments under it.
				 *          The default is 1200 bytes; a size below the least allowed one (DATAGRAM_MTU_LEAST) is
				 *          raised up to it, there is no upper limit: over SCTP the messages happen to be longer
				 *          than 1500 bytes, and a record of the protocol is not wider than 2^14 bytes anyway. The
				 *          received datagrams are not bound by this size: the sides with different sizes converge
				 * @note The size is set before the establishment of the connection and matters only to the
				 *       transport by datagrams
				 *
				 * \~
				 */
				void mtu(const size_t mtu) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера дейтаграммы связи
				 *
				 * @return размер дейтаграммы в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of a datagram of the connection
				 * @return the size of a datagram in bytes
				 *
				 * \~
				 */
				size_t mtu() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения срока ожидания повторной передачи
				 *
				 * @return срок ожидания в миллисекундах, ноль, когда ждать нечего
				 *
				 * @details Раздел 5.8.2 RFC 9147: часов у связи нет - срок отдаётся тому, кто связь
				 *          ведёт, а по его истечении зовётся elapsed. Начальный срок - секунда,
				 *          всякая попытка его удваивает до шестидесяти секунд, продвижение залпа
				 *          возвращает его к начальному
				 *
				 * \~english
				 * @brief Method of getting the term of the waiting for a retransmission
				 * @return the term of the waiting in milliseconds, a zero when there is nothing to wait for
				 * @details The section 5.8.2 of RFC 9147: the connection has no clock — the term is given to the
				 *          one who leads the connection, and on its expiry elapsed is called. The initial term is
				 *          a second, every attempt doubles it up to sixty seconds, a progress of the flight
				 *          returns it to the initial one
				 *
				 * \~
				 */
				uint32_t timeout() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извещения связи об истечении срока ожидания
				 *
				 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
				 *
				 * @details Неподтверждённые куски последнего залпа нарезаются заново и раскладываются по
				 *          дейтаграммам новыми номерами записей; по исчерпании попыток связь обрывается
				 *
				 * \~english
				 * @brief Method of notifying the connection about the expiry of the term of the waiting
				 * @return the failure of the retransmission: TIMEOUT on the exhaustion of the attempts
				 * @details The unacknowledged fragments of the last flight are split anew and laid out over the
				 *          datagrams by new numbers of the records; on the exhaustion of the attempts the
				 *          connection is torn
				 *
				 * \~
				 */
				context::error_t elapsed() noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
				 *
				 * @return число отброшенных записей и дейтаграмм
				 *
				 * @details Раздел 4.5.2 RFC 9147: порча записи, повтор, неведомая пора ключей,
				 *          чужая метка возврата состояния и опознаватель связи отбрасываются молча,
				 *          без извещений; счётчик даёт о них знать тому, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of getting the number of the records and datagrams discarded silently
				 * @return the number of the discarded records and datagrams
				 * @details The section 4.5.2 of RFC 9147: a corruption of a record, a repetition, an unknown epoch,
				 *          a foreign label of the return of the state and a connection identifier are discarded
				 *          silently, without alerts; the counter lets the one who leads the connection know about them
				 *
				 * \~
				 */
				uint64_t discarded() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа отброшенного по причине
				 *
				 * @param reason причина отброса
				 *
				 * @return       число записей и дейтаграмм, отброшенных по этой причине
				 *
				 * @note Сумма по всем причинам равна общему счётчику discarded
				 *
				 * \~english
				 * @brief Method of getting the number of the discarded by a reason
				 * @param reason the reason of the discarding
				 * @return       the number of the records and datagrams discarded by this reason
				 * @note The sum over all the reasons equals the total counter discarded
				 *
				 * \~
				 */
				uint64_t discarded(const datagram::reason_t reason) const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки адреса собеседника для метки возврата состояния
				 *
				 * @param address адрес либо иной опознаватель собеседника
				 *
				 * @return        признак того, что адрес принят
				 *
				 * @details Раздел 5.1 RFC 9147: метка возврата состояния привязывается к адресу, с
				 *          которого пришло приветствие, и повторное приветствие с иного адреса
				 *          отвергается. Содержимое адреса непрозрачно: связь его не разбирает, а
				 *          сличает побайтно - ведущий подаёт, к примеру, два октета порта с четырьмя
				 *          либо шестнадцатью октетами адреса, а по SCTP опознаватель связи
				 *          sinfo_assoc_id. Адрес не длиннее DATAGRAM_ADDRESS байтов, иначе
				 *          отвергается; пустой снимает адрес
				 *
				 * @note Адрес подаётся до заведения связи: без него start отвечает SETTINGS;
				 *       сброс связи вызовом clear снимает и адрес. Молча отбрасывается лишь
				 *       повторное приветствие чужого клиента с негодной меткой
				 *
				 * \~english
				 * @brief Method of setting the address of the interlocutor for the label of the return of the state
				 * @param address the address or another identifier of the interlocutor
				 * @return        the flag of the address being accepted
				 * @details The section 5.1 of RFC 9147: the label of the return of the state is bound to the address
				 *          the greeting came from, and a repeated greeting from another address is rejected. The
				 *          content of the address is opaque: the connection does not parse it but compares byte by
				 *          byte — the leader gives, for instance, two octets of the port with four or sixteen
				 *          octets of the address, or over SCTP the association identifier sinfo_assoc_id. The
				 *          address is not longer than DATAGRAM_ADDRESS bytes, otherwise it is rejected; an empty
				 *          one removes the address
				 * @note The address is given before the establishment of the connection: without it start answers
				 *       SETTINGS; the reset of the connection by clear removes the address too. Only a repeated
				 *       greeting of a foreign client with an unfit label is discarded silently
				 *
				 * \~
				 */
				bool address(const view_t & address) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки секрета метки возврата состояния
				 *
				 * @param secret устанавливаемый секрет любой длины
				 *
				 * @details Секрет сворачивается хешем и служит ключом имитовставки метки; не заданный
				 *          секрет порождается энтропией при заведении связи
				 *
				 * \~english
				 * @brief Method of setting the secret of the label of the return of the state
				 * @param secret the secret of any length being set
				 * @details The secret is folded by a hash and serves as the key of the authentication code of the
				 *          label; a secret not set is generated from the entropy at the establishment of the connection
				 *
				 * \~
				 */
				void stamp(const vector <uint8_t> & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод смены поколения секрета метки возврата состояния
				 *
				 * @details Часов у связи нет, и срок жизни метки судится поколениями: живы два -
				 *          нынешнее и предыдущее, а смену поколения зовёт тот, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of the change of the generation of the secret of the label of the return of the state
				 * @details The connection has no clock, and the lifetime of the label is judged by generations: two
				 *          are alive — the current and the previous one, and the change of the generation is called
				 *          by the one who leads the connection
				 *
				 * \~
				 */
				void restamp() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения связи
				 *
				 * @return отказ заведения связи
				 *
				 * @details Сервер говорит вторым: заведение связи лишь готовит её к приветствию клиента,
				 *          а в накопитель до него ничего не складывается
				 *
				 * \~english
				 * @brief Method of the establishment of the connection
				 * @return the failure of the establishment of the connection
				 * @details The server speaks second: the establishment of the connection only prepares it for the
				 *          greeting of the client, and nothing is put into the accumulator before it
				 *
				 * \~
				 */
				context::error_t start() noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния связи
				 *
				 * @note Настройки связи сбросом не затрагиваются: связь заводится заново теми же
				 *
				 * \~english
				 * @brief Method of the reset of the state of the connection
				 * @note The settings of the connection are not affected by the reset: the connection is
				 *       established anew by the same ones
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи связи принятых байтов
				 *
				 * @param data принятые от собеседника байты
				 *
				 * @return     отказ разбора принятых байтов
				 *
				 * @note Байты подаются как пришли: границы записей протокола связь
				 *       восстанавливает сама
				 *
				 * \~english
				 * @brief Method of the giving of the received bytes to the connection
				 * @param data the bytes received from the interlocutor
				 * @return     the failure of the parsing of the received bytes
				 * @note The bytes are given as they came: the connection restores the boundaries of the
				 *       records of the protocol itself
				 *
				 * \~
				 */
				context::error_t push(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения байтов, отправляемых собеседнику
				 *
				 * @return накопленные байты, отправляемые собеседнику
				 *
				 * @details Поверх дейтаграмм вызов отдаёт ровно одну готовую дейтаграмму - первую
				 *          из очереди; за одну подачу либо отправку готовых дейтаграмм может быть
				 *          несколько, и звать output и consume надлежит, пока просмотр не
				 *          опустеет, иначе остальные дейтаграммы ждут в очереди. Всякая готовая
				 *          запись прикладных данных либо извещения уходит своей дейтаграммой,
				 *          ни одна не теряется и с соседней не сливается
				 *
				 * @note Просмотр смотрит внутрь накопителя связи: снятие байтов вызовом consume
				 *       его обесценивает
				 *
				 * \~english
				 * @brief Method of getting the bytes sent to the interlocutor
				 * @return the accumulated bytes sent to the interlocutor
				 * @details Over datagrams the call gives out exactly one ready datagram — the first of the queue;
				 *          per a single feeding or sending there may be several ready datagrams, and output and
				 *          consume are to be called until the view gets empty, otherwise the rest of the datagrams
				 *          wait in the queue. Every ready record of the application data or of an alert goes by
				 *          its own datagram, none is lost and none merges with the neighbouring one
				 * @note The view looks inside the accumulator of the connection: the removal of the bytes
				 *       by a call of consume invalidates it
				 *
				 * \~
				 */
				view_t output() const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия отправленных байтов с накопителя
				 *
				 * @param size размер снимаемых байтов
				 *
				 * @note Снимается ровно столько, сколько ушло собеседнику: связь не знает, дошло
				 *       ли отправленное, и судит об этом лишь по этому вызову
				 *
				 * \~english
				 * @brief Method of the removal of the sent bytes from the accumulator
				 * @param size the size of the bytes being removed
				 * @note Exactly as much is removed as went to the interlocutor: the connection does not know
				 *       whether the sent has arrived and judges of it only by this call
				 *
				 * \~
				 */
				void consume(const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод отправки прикладных данных собеседнику
				 *
				 * @param data отправляемые прикладные данные
				 *
				 * @return     отказ отправки прикладных данных
				 *
				 * @note Данные нарезаются на записи протокола сами: длина записи протоколом
				 *       ограничена, а длина отправляемого - нет
				 *
				 * \~english
				 * @brief Method of the sending of the application data to the interlocutor
				 * @param data the application data being sent
				 * @return     the failure of the sending of the application data
				 * @note The data is cut into the records of the protocol by itself: the length of a record is
				 *       limited by the protocol, and the length of the sent is not
				 *
				 * \~
				 */
				context::error_t write(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения принятых прикладных данных
				 *
				 * @param result накопитель, в который переносятся принятые данные
				 *
				 * @return       отказ получения принятых прикладных данных
				 *
				 * @note Принятые данные с накопителя связи снимаются: повторный вызов выдаст
				 *       лишь то, что пришло после
				 *
				 * \~english
				 * @brief Method of getting the received application data
				 * @param result the accumulator the received data is transferred into
				 * @return       the failure of getting the received application data
				 * @note The received data is removed from the accumulator of the connection: a repeated call
				 *       will output only what came after
				 *
				 * \~
				 */
				context::error_t read(vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод выдачи билета возобновления связи клиенту
				 *
				 * @return отказ выдачи билета возобновления связи
				 *
				 * @details Раздел 4.6.1 RFC 8446: билет выдаётся за рукопожатием и годится клиенту
				 *          на будущую связь. Число выдаваемых билетов сервер выбирает сам, и всякому
				 *          из них отвечает свой ключ.
				 *
				 * @note Тело выданного билета назначается связью случайно: опознавать по нему связь
				 *       - дело того, кто связь ведёт, и запись эта принадлежит ему
				 *
				 * \~english
				 * @brief Method of the issue of a ticket of the resumption of the connection to the client
				 * @return the failure of the issue of the ticket of the resumption of the connection
				 * @details The section 4.6.1 of RFC 8446: a ticket is issued after the handshake and is suitable
				 *          for the client for a future connection. The number of the issued tickets is chosen by
				 *          the server itself, and every one of them corresponds to its own key.
				 * @note The body of an issued ticket is appointed by the connection at random: to identify the
				 *       connection by it is the business of the one who leads the connection, and this record
				 *       belongs to them
				 *
				 * \~
				 */
				context::error_t issue() noexcept;
				/**
				 * \~russian
				 * @brief Метод смены ключевого материала своего направления связи
				 *
				 * @param request просьба к собеседнику сменить свои ключи в ответ
				 *
				 * @return        отказ смены ключевого материала своего направления
				 *
				 * @details Раздел 4.6.3 RFC 8446: сторона вправе сменить ключи своего направления
				 *          связи в любой миг после рукопожатия, и счётчик записей направления при
				 *          этом начинается заново
				 *
				 * @note Сообщение о смене уходит прежними ключами, а новые ставятся уже за ним:
				 *       иначе собеседник не смог бы прочесть само извещение о смене
				 *
				 * \~english
				 * @brief Method of the change of the key material of one’s own direction of the connection
				 * @param request the request to the interlocutor to change their keys in return
				 * @return        the failure of the change of the key material of one’s own direction
				 * @details The section 4.6.3 of RFC 8446: a side is entitled to change the keys of its direction
				 *          of the connection at any moment after the handshake, and the counter of the records of
				 *          the direction starts anew at that
				 * @note The message about the change goes by the previous keys, and the new ones are set already
				 *       behind it: otherwise the interlocutor would not be able to read the very notification
				 *       about the change
				 *
				 * \~
				 */
				context::error_t update(const bool request = false) noexcept;
				/**
				 * \~russian
				 * @brief Метод закрытия связи
				 *
				 * @return отказ закрытия связи
				 *
				 * @details Раздел 6.1 RFC 8446: закрытие завершает лишь свою передачу. Отправка
				 *          после него отвергается, а приём идёт дальше, пока собеседник не
				 *          завершит свою передачу таким же извещением; принятое извещение
				 *          о закрытии связь отвечает своим сама и после него принятое
				 *          пропускает
				 *
				 * @note Извещение о завершении передачи складывается в накопитель: отправить его
				 *       собеседнику - дело того, кто связь ведёт
				 *
				 * @note Состояние закрытия наступает по любой из сторон; кончился ли приём,
				 *       говорит не оно, а отсутствие принятых данных после подачи
				 *
				 * \~english
				 * @brief Method of the closing of the connection
				 * @return the failure of the closing of the connection
				 * @details The section 6.1 of RFC 8446: the closing finishes only the own transfer. The sending
				 *          after it is refused, and the receiving goes on until the interlocutor finishes its
				 *          transfer by the same alert; the connection answers a received alert about the closing
				 *          by its own one itself and skips what is received after it
				 * @note The alert about the finishing of the transfer is put into the accumulator: to send it
				 *       to the interlocutor is the business of the one who leads the connection
				 * @note The state of the closing comes by any of the sides; whether the receiving is over is
				 *       told not by it but by the absence of the received data after a submission
				 *
				 * \~
				 */
				context::error_t close() noexcept;
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
				Context() noexcept;
				/**
				 * \~russian
				 * @brief Конструктор копирования
				 *
				 * @note Связь копированию не подлежит: два её списка вели бы одно и то же
				 *       состояние защиты записей, а счётчик записей у него один
				 *
				 * \~english
				 * @brief Copy constructor
				 * @note The connection is not subject to the copying: two copies of it would lead one and the
				 *       same state of the protection of the records, while the counter of the records of it
				 *       is a single one
				 *
				 * \~
				 */
				Context(const Context &) = delete;
				/**
				 * \~russian
				 * @brief Оператор присваивания
				 *
				 * @return связь, которой присваивается значение
				 *
				 * \~english
				 * @brief Assignment operator
				 * @return the connection the value is assigned to
				 *
				 * \~
				 */
				Context & operator = (const Context &) = delete;
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
				~Context() noexcept;
		} context_t;
	};
};

#endif // __ANTS_SERVER__
