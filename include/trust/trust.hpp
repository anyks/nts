/**
 * @file trust.hpp
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
 * @brief Заголовочный файл модуля доверия цепочке сертификатов — запас доверенных
 *        сертификатов, проверка цепочки и сличение имени узла
 *
 * \~english
 * @brief Header file of the module of the trust to a chain of the certificates — the store of
 *        the trusted certificates, the check of a chain and the comparison of the name of a host
 *
 * \~
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
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <x509/x509.hpp>

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
	 * @brief Пространство имён модуля доверия цепочке сертификатов
	 *
	 * @details Связь цепочку собеседника лишь принимает и сличает подпись владения ключом
	 *          с первым её сертификатом. Доверие же к издателю решается запасом доверенных
	 *          сертификатов, который принадлежит не связи, а тому, кто её ведёт: этим модулем
	 *          он это решение и принимает.
	 *
	 * @note Часов модуль не читает: миг проверки подаётся ему доводом. Иначе проверку нельзя
	 *       было бы ни повторить, ни проверить, а связи с истёкшим сроком вели бы себя по-разному
	 *       в зависимости от того, когда их проверяют
	 *
	 * \~english
	 * @brief Namespace of the module of the trust to a chain of the certificates
	 *
	 * @details A connection only accepts the chain of the interlocutor and compares the signature of the
	 *          possession of the key against the first certificate of it. The trust to the issuer is decided
	 *          by the store of the trusted certificates which belongs not to the connection but to the one
	 *          who leads it: by this module they make this decision.
	 *
	 * @note The module does not read the clock: the moment of the check is given to it by an argument.
	 *       Otherwise the check could be neither repeated nor checked, and the connections with an expired
	 *       validity would behave differently depending on when they are checked
	 *
	 * \~
	 */
	namespace trust {
		/**
		 * \~russian
		 * @brief Предел длины проверяемой цепочки сертификатов
		 *
		 * @details Раздел 6.1 RFC 5280 длины цепочки не ограничивает, но всякая проверка
		 *          стоит проверки подписи: без предела цепочка обращается в трату времени,
		 *          назначаемую встречной стороной
		 *
		 * \~english
		 * @brief Limit of the length of a chain of the certificates being checked
		 *
		 * @details The section 6.1 of RFC 5280 does not limit the length of a chain, but every check costs
		 *          a check of a signature: without a limit a chain turns into a waste of the time appointed
		 *          by the opposite side
		 *
		 * \~
		 */
		static constexpr size_t TRUST_DEPTH = 8;

		/**
		 * \~russian
		 * @brief Отказы доверия цепочке сертификатов
		 *
		 * \~english
		 * @brief Failures of the trust to a chain of the certificates
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			// Отказа нет, цепочка доверия сложилась
			NONE       = 0x00, /*!< \~russian Отказа нет, цепочка доверия сложилась \~english There is no failure, the chain of the trust has formed \~ */
			// Проверяемая цепочка пуста
			EMPTY      = 0x01, /*!< \~russian Проверяемая цепочка пуста \~english The chain being checked is empty \~ */
			// Длина цепочки превышает дозволенную
			DEPTH      = 0x02, /*!< \~russian Длина цепочки превышает дозволенную \~english The length of the chain exceeds the allowed one \~ */
			// Сертификат цепочки разобрать не удалось
			PARSE      = 0x03, /*!< \~russian Сертификат цепочки разобрать не удалось \~english It was not possible to parse a certificate of the chain \~ */
			// Срок действия сертификата на этот миг не идёт
			EXPIRED    = 0x04, /*!< \~russian Срок действия сертификата на этот миг не идёт \~english The validity of a certificate does not go at this moment \~ */
			// Издатель сертификата с владельцем следующего разошёлся
			ISSUER     = 0x05, /*!< \~russian Издатель сертификата с владельцем следующего разошёлся \~english The issuer of a certificate has diverged with the subject of the next one \~ */
			// Сертификат издавать другие сертификаты не вправе
			CONSTRAINT = 0x06, /*!< \~russian Сертификат издавать другие сертификаты не вправе \~english A certificate is not entitled to issue other certificates \~ */
			// Подпись сертификата издателем не сошлась
			SIGNATURE  = 0x07, /*!< \~russian Подпись сертификата издателем не сошлась \~english The signature of a certificate by its issuer has not converged \~ */
			// Издателя цепочки в запасе доверенных нет
			AUTHORITY  = 0x08, /*!< \~russian Издателя цепочки в запасе доверенных нет \~english There is no issuer of the chain in the store of the trusted ones \~ */
			// Имя узла ни одному имени сертификата не отвечает
			NAME       = 0x09, /*!< \~russian Имя узла ни одному имени сертификата не отвечает \~english The name of the host corresponds to no name of the certificate \~ */
			// Памяти под разбор цепочки не хватило
			MEMORY     = 0x0A, /*!< \~russian Памяти под разбор цепочки не хватило \~english There was not enough memory for the parsing of the chain \~ */
			// Сертификат несёт неизвестное расширение, объявленное критичным
			CRITICAL   = 0x0B, /*!< \~russian Сертификат несёт неизвестное расширение, объявленное критичным \~english A certificate carries an unknown extension declared critical \~ */
			// Назначение ключа сертификата подписи владения не дозволяет
			PURPOSE    = 0x0C, /*!< \~russian Назначение ключа сертификата подписи владения не дозволяет \~english The purpose of the key of the certificate does not allow the signature of the possession \~ */
			// Имя сертификата нарушает ограничения имён издателя (раздел 4.2.1.10 RFC 5280) либо ограничения не разобрать
			CONSTRAINED = 0x0D, /*!< \~russian Имя сертификата нарушает ограничения имён издателя (раздел 4.2.1.10 RFC 5280) либо ограничения не разобрать \~english A name of a certificate violates the name constraints of an issuer (the section 4.2.1.10 of RFC 5280) or the constraints cannot be parsed \~ */
			// Звено цепочки подписано хешем MD5/SHA-1 либо несёт ключ RSA короче 2048 разрядов: стойкости на цепочку доверия недостаёт (RFC 9155, SP 800-131A)
			WEAK        = 0x0E, /*!< \~russian Звено цепочки подписано хешем MD5/SHA-1 либо несёт ключ RSA короче 2048 разрядов: стойкости на цепочку доверия недостаёт (RFC 9155, SP 800-131A) \~english A link of the chain is signed with an MD5/SHA-1 hash or carries an RSA key shorter than 2048 bits: the strength does not suffice for a chain of the trust (RFC 9155, SP 800-131A) \~ */
			// Сертификат отозван списком отзыва своего издателя (раздел 5 RFC 5280)
			REVOKED     = 0x0F, /*!< \~russian Сертификат отозван списком отзыва своего издателя (раздел 5 RFC 5280) \~english The certificate is revoked by the revocation list of its issuer (the section 5 of RFC 5280) \~ */
			// Списка отзыва для издателя звена в запасе нет: запас списками владеет, а этому издателю списка не подали
			MISSING     = 0x10, /*!< \~russian Списка отзыва для издателя звена в запасе нет: запас списками владеет, а этому издателю списка не подали \~english There is no revocation list for the issuer of a link in the store: the store owns the lists, but none has been given for this issuer \~ */
			// Список отзыва издателя просрочен: миг проверки ушёл за nextUpdate
			OUTDATED    = 0x11, /*!< \~russian Список отзыва издателя просрочен: миг проверки ушёл за nextUpdate \~english The revocation list of the issuer is outdated: the moment of the check has gone beyond the nextUpdate \~ */
			// Список отзыва издателю не отвечает: подпись списка не сошлась с ключом издателя
			FORGED      = 0x12  /*!< \~russian Список отзыва издателю не отвечает: подпись списка не сошлась с ключом издателя \~english The revocation list does not correspond to the issuer: the signature of the list has not converged with the key of the issuer \~ */
		};

		/**
		 * \~russian
		 * @brief Запас доверенных сертификатов
		 *
		 * @details Запас владеет записями сертификатов: цепочка, поданная на проверку, живёт
		 *          ровно столько, сколько длится связь, а запас переживает всякую из них
		 *
		 * \~english
		 * @brief Store of the trusted certificates
		 *
		 * @details The store owns the records of the certificates: a chain given for a check lives exactly
		 *          as long as a connection lasts, while the store outlives every one of them
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Store {
			private:
				// Записи доверенных сертификатов запаса
				vector <vector <uint8_t>> _chain;
				// Записи списков отзыва запаса в DER
				vector <vector <uint8_t>> _lists;
			public:
				/**
				 * \~russian
				 * @brief Метод получения числа доверенных сертификатов запаса
				 *
				 * @return число доверенных сертификатов запаса
				 *
				 * \~english
				 * @brief Method of getting the number of the trusted certificates of the store
				 *
				 * @return the number of the trusted certificates of the store
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения доверенного сертификата запаса
				 *
				 * @param index место запрашиваемого сертификата в запасе
				 * @return      запись запрашиваемого сертификата
				 *
				 * \~english
				 * @brief Method of getting a trusted certificate of the store
				 *
				 * @param index the place of the requested certificate in the store
				 * @return      the record of the requested certificate
				 *
				 * \~
				 */
				view_t get(const size_t index) const noexcept;
				/**
				 * \~russian
				 * @brief Метод добавления доверенного сертификата в запас
				 *
				 * @param certificate запись добавляемого сертификата
				 * @return            признак успешности добавления сертификата
				 *
				 * @note Сертификат разбирается при добавлении: непригодной записью запас
				 *       доверия пополнять нечего
				 *
				 * \~english
				 * @brief Method of the addition of a trusted certificate to the store
				 *
				 * @param certificate the record of the certificate being added
				 * @return            the flag of the success of the addition of the certificate
				 *
				 * @note The certificate is parsed at the addition: there is no point in replenishing the store
				 *       of the trust by an unsuitable record
				 *
				 * \~
				 */
				bool add(const view_t & certificate) noexcept;
				/**
				 * \~russian
				 * @brief Метод добавления списка отзыва в запас
				 *
				 * @param list запись добавляемого списка отзыва в DER
				 * @return     признак успешности добавления списка
				 *
				 * @note Список разбирается при добавлении: непригодной записью запас доверия
				 *       пополнять нечего
				 *
				 * @note Поданный список включает проверку отзыва всей цепочки: запас без
				 *       списков отзыва не проверяет вовсе, а запас со списками требует список
				 *       каждому издателю звеньев цепочки и отвечает отказом MISSING, если
				 *       издателю списка не подали (раздел 6.1 RFC 5280)
				 *
				 * \~english
				 * @brief Method of the addition of a revocation list to the store
				 *
				 * @param list the record of the revocation list being added in DER
				 * @return     the flag of the success of the addition of the list
				 *
				 * @note The list is parsed at the addition: there is no point in replenishing the store
				 *       of the trust by an unsuitable record
				 *
				 * @note A given list turns on the check of the revocation of the whole chain: a store
				 *       without revocation lists does not check it at all, while a store with the
				 *       lists requires a list to every issuer of the links of the chain and answers
				 *       by the MISSING failure when no list has been given to an issuer
				 *       (the section 6.1 of RFC 5280)
				 *
				 * \~
				 */
				bool addList(const view_t & list) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа списков отзыва запаса
				 *
				 * @return число списков отзыва запаса
				 *
				 * \~english
				 * @brief Method of getting the number of the revocation lists of the store
				 *
				 * @return the number of the revocation lists of the store
				 *
				 * \~
				 */
				size_t lists() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения списка отзыва запаса
				 *
				 * @param index место запрашиваемого списка в запасе
				 * @return      запись запрашиваемого списка отзыва
				 *
				 * \~english
				 * @brief Method of getting a revocation list of the store
				 *
				 * @param index the place of the requested list in the store
				 * @return      the record of the requested revocation list
				 *
				 * \~
				 */
				view_t list(const size_t index) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса запаса доверенных сертификатов
				 *
				 * \~english
				 * @brief Method of the reset of the store of the trusted certificates
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Store() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Store() noexcept;
		} store_t;

		/**
		 * \~russian
		 * @brief Роль собеседника, чья цепочка проверяется
		 *
		 * @details Раздел 4.2.1.12 RFC 5280: назначение extendedKeyUsage листа обязано отвечать роли -
		 *          serverAuth у сервера, clientAuth у клиента; anyExtendedKeyUsage годится обеим
		 *
		 * \~english
		 * @brief Role of the peer whose chain is being checked
		 *
		 * @details The section 4.2.1.12 of RFC 5280: the extendedKeyUsage purpose of the leaf must match the
		 *          role - serverAuth at a server, clientAuth at a client; anyExtendedKeyUsage suits both
		 *
		 * \~
		 */
		enum class role_t : uint8_t {
			// Роль не судится: годится любое из назначений
			ANY    = 0x00, /*!< \~russian Роль не судится: годится любое из назначений \~english The role is not judged: any of the purposes suits \~ */
			// Проверяется сервер: нужен serverAuth
			SERVER = 0x01, /*!< \~russian Проверяется сервер: нужен serverAuth \~english A server is being checked: serverAuth is needed \~ */
			// Проверяется клиент: нужен clientAuth
			CLIENT = 0x02  /*!< \~russian Проверяется клиент: нужен clientAuth \~english A client is being checked: clientAuth is needed \~ */
		};
		/**
		 * \~russian
		 * @brief Функция проверки цепочки сертификатов запасом доверенных
		 *
		 * @param chain  проверяемая цепочка сертификатов от своего к издателю
		 * @param store  запас доверенных сертификатов
		 * @param moment миг проверки в секундах от начала эпохи
		 * @return       отказ доверия цепочке сертификатов
		 *
		 * @details Раздел 6.1 RFC 5280: цепочка проверяется звено за звеном - срок действия,
		 *          совпадение издателя с владельцем следующего, право издавать сертификаты и
		 *          подпись, - а замыкается она сертификатом из запаса доверенных
		 *
		 * @note Списки отзыва проверяются лишь поданными в запас вызовом addList: запас без
		 *       списков отзыва не проверяет вовсе, а запас со списками требует список каждому
		 *       издателю звеньев цепочки. Ядро ввода и вывода модуль по-прежнему не ведёт:
		 *       список добывает и подаёт потребитель
		 *
		 * \~english
		 * @brief Function of the check of a chain of the certificates by a store of the trusted ones
		 *
		 * @param chain  the chain of the certificates being checked from one's own to the issuer
		 * @param store  the store of the trusted certificates
		 * @param moment the moment of the check in seconds from the beginning of the epoch
		 * @return       the failure of the trust to the chain of the certificates
		 *
		 * @details The section 6.1 of RFC 5280: a chain is checked link by link — the validity, the
		 *          coincidence of the issuer with the subject of the next one, the right to issue the
		 *          certificates and the signature — and it is closed by a certificate from the store
		 *
		 * @note The revocation lists are checked only by the ones given into the store by the addList
		 *       call: a store without the revocation lists does not check them at all, while a store
		 *       with the lists requires a list to every issuer of the links of the chain. The module
		 *       still does not lead the input and the output: the consumer obtains and gives a list
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки цепочки сертификатов по запасу доверенных с учётом роли собеседника
		 *
		 * @param chain  проверяемая цепочка сертификатов от своего к издателю
		 * @param store  запас доверенных сертификатов
		 * @param moment миг проверки в секундах от начала эпохи
		 * @param role   роль собеседника: назначение листа обязано ей отвечать
		 * @return       отказ доверия цепочке сертификатов: PURPOSE при назначении не по роли
		 *
		 * \~english
		 * @brief Function of the check of a chain of the certificates by a store of the trusted ones with the role of the peer
		 *
		 * @param chain  the chain of the certificates being checked from one's own to the issuer
		 * @param store  the store of the trusted certificates
		 * @param moment the moment of the check in seconds from the beginning of the epoch
		 * @param role   the role of the peer: the purpose of the leaf must match it
		 * @return       the failure of the trust to the chain of the certificates: PURPOSE at a purpose not by the role
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment, const role_t role) noexcept;
		/**
		 * \~russian
		 * @brief Функция сличения имени узла с именами сертификата
		 *
		 * @param certificate запись сличаемого сертификата
		 * @param name        имя узла, за которым пришли
		 * @return            отказ сличения имени узла
		 *
		 * @details Раздел 6.4 RFC 6125: имя разыскивается среди дополнительных имён владельца,
		 *          а общее имя владельца берётся лишь тогда, когда дополнительных имён нет вовсе
		 *
		 * @note Звёздочка дозволена лишь в самой левой части имени и лишь целой частью: имя
		 *       вида «*.anyks.com» отвечает «www.anyks.com», но не «www.dev.anyks.com»
		 *
		 * \~english
		 * @brief Function of the comparison of the name of a host with the names of a certificate
		 *
		 * @param certificate the record of the certificate being compared
		 * @param name        the name of the host one came for
		 * @return            the failure of the comparison of the name of the host
		 *
		 * @details The section 6.4 of RFC 6125: the name is searched for among the alternative names of the
		 *          subject, and the common name of the subject is taken only when there are no alternative
		 *          names at all
		 *
		 * @note An asterisk is allowed only in the leftmost part of a name and only as a whole part: a name
		 *       of the kind «*.anyks.com» corresponds to «www.anyks.com» but not to «www.dev.anyks.com»
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t belongs(const view_t & certificate, const string & name) noexcept;
	};
};

