/**
 * @file x509.hpp
 * @date 2026-08-27
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
 * @brief Заголовочный файл модуля сертификатов X.509 — разбор записи сертификата,
 *        имён, срока действия, сведений об открытом ключе и расширений
 *
 * \~english
 * @brief Header file of the X.509 certificate module — parsing of the certificate
 *        encoding, of the names, of the validity, of the public key info and of the extensions
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_X509__
#define __ANTS_X509__

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
#include <asn1/asn1.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 *
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модуля сертификатов X.509
	 *
	 * @details Разбор ведётся по RFC 5280 поверх модуля ASN.1 и, как и он, ничего не
	 *          копирует сверх необходимого: двоичные поля отдаются просмотром внутрь
	 *          разбираемой записи, и время жизни записи обязан обеспечить вызывающий.
	 *
	 *          Проверка подписи и построение цепочки доверия в этот модуль не входят:
	 *          здесь только разбор записи и извлечение её полей.
	 *
	 * \~english
	 * @brief Namespace of the X.509 certificate module
	 * @details The parsing follows RFC 5280 on top of the ASN.1 module and, like it,
	 *          copies nothing beyond the necessary: the binary fields are given out as
	 *          views inside the encoding being parsed, and the lifetime of the encoding
	 *          is up to the caller.
	 *          The verification of the signature and the building of the chain of trust
	 *          are not part of this module: it only parses the encoding and extracts its fields.
	 *
	 * \~
	 *
	 */
	namespace x509 {
		/**
		 * \~russian
		 * @brief Причина отказа разбора сертификата
		 *
		 * \~english
		 * @brief Reason of a certificate parsing failure
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа не произошло \~english No failure has occurred \~ */
			ENCODING  = 0x01, /*!< \~russian Запись не отвечает правилам кодировки DER \~english The record does not meet the rules of the DER encoding \~ */
			STRUCTURE = 0x02, /*!< \~russian Состав записи не отвечает устройству сертификата \~english The composition of the record does not meet the structure of a certificate \~ */
			VERSION   = 0x03, /*!< \~russian Издание сертификата не поддерживается либо записано неверно \~english The version of the certificate is not supported or is written incorrectly \~ */
			SERIAL    = 0x04, /*!< \~russian Порядковый номер сертификата записан неверно \~english The serial number of the certificate is written incorrectly \~ */
			NAME      = 0x05, /*!< \~russian Имя записано неверно \~english The name is written incorrectly \~ */
			VALIDITY  = 0x06, /*!< \~russian Срок действия записан неверно \~english The validity period is written incorrectly \~ */
			KEY       = 0x07, /*!< \~russian Сведения об открытом ключе записаны неверно \~english The information about the public key is written incorrectly \~ */
			EXTENSION = 0x08, /*!< \~russian Расширение записано неверно \~english The extension is written incorrectly \~ */
			DUPLICATE = 0x09, /*!< \~russian Расширение либо признак имени встретились дважды \~english An extension or an attribute of a name was met twice \~ */
			MEMORY    = 0x0A, /*!< \~russian Не удалось выделить память под разобранные сведения \~english It was not possible to allocate memory for the parsed information \~ */
			SIGNATURE = 0x0B  /*!< \~russian Подпись не сошлась либо непригодна для проверки \~english The signature has not converged or is unsuitable for the check \~ */
		};

		/**
		 * \~russian
		 * @brief Издание сертификата
		 *
		 * \~english
		 * @brief Version of a certificate
		 *
		 * \~
		 *
		 */
		enum class version_t : uint8_t {
			V1 = 0x00, /*!< \~russian Первое издание, расширений не имеет \~english First version, has no extensions \~ */
			V2 = 0x01, /*!< \~russian Второе издание, добавлены опознаватели издателя и владельца \~english Second version, the identifiers of the issuer and of the subject are added \~ */
			V3 = 0x02 /*!< \~russian Третье издание, добавлены расширения \~english Third version, the extensions are added \~ */
		};

		/**
		 * \~russian
		 * @brief Вид имени в дополнительных именах владельца
		 *
		 * \~english
		 * @brief Kind of a name in the subject alternative names
		 *
		 * \~
		 *
		 */
		enum class kind_t : uint8_t {
			OTHER     = 0x00, /*!< \~russian Имя иного вида, отдаётся записью как есть \~english A name of another kind, given as the record as is \~ */
			EMAIL     = 0x01, /*!< \~russian Адрес электронной почты \~english E-mail address \~ */
			DNS       = 0x02, /*!< \~russian Доменное имя \~english Domain name \~ */
			DIRECTORY = 0x03, /*!< \~russian Отличительное имя \~english Distinguished name \~ */
			URI       = 0x04, /*!< \~russian Единый указатель ресурса \~english Uniform resource identifier \~ */
			ADDRESS   = 0x05 /*!< \~russian Адрес сети \~english Network address \~ */
		};

		/**
		 * \~russian
		 * @brief Назначение открытого ключа
		 *
		 * @details Значения отвечают разрядам строки битов расширения назначения ключа
		 *          в порядке, заданном RFC 5280.
		 *
		 * \~english
		 * @brief Purpose of the public key
		 * @details The values correspond to the bits of the bit string of the key usage
		 *          extension in the order given by RFC 5280.
		 *
		 * \~
		 *
		 */
		enum class usage_t : uint16_t {
			SIGNATURE  = 0x0080, /*!< \~russian Проверка подписи \~english Signature verification \~ */
			CONTENT    = 0x0040, /*!< \~russian Неотрекаемость от содержимого \~english Non-repudiation of the content \~ */
			ENCIPHER   = 0x0020, /*!< \~russian Шифрование ключа \~english Key encipherment \~ */
			DATA       = 0x0010, /*!< \~russian Шифрование данных \~english Data encipherment \~ */
			AGREEMENT  = 0x0008, /*!< \~russian Согласование ключа \~english Key agreement \~ */
			CERTIFICATE= 0x0004, /*!< \~russian Подписывание сертификатов \~english Signing of certificates \~ */
			REVOCATION = 0x0002, /*!< \~russian Подписывание списков отзыва \~english Signing of revocation lists \~ */
			ENCIPHER_ONLY = 0x0001, /*!< \~russian Только шифрование при согласовании ключа \~english Encipherment only during the key agreement \~ */
			DECIPHER_ONLY = 0x8000 /*!< \~russian Только расшифровывание при согласовании ключа \~english Decipherment only during the key agreement \~ */
		};

		/**
		 * \~russian
		 * @brief Признак имени
		 *
		 * \~english
		 * @brief Attribute of a name
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Attribute {
			// Вид записи значения признака
			asn1::tag_t type;
			// Опознаватель признака
			string oid;
			// Значение признака в кодировке UTF-8
			string value;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Attribute() noexcept : type(asn1::tag_t::UTF8_STRING) {}
		} attribute_t;

		/**
		 * \~russian
		 * @brief Отличительное имя
		 *
		 * @details Имя состоит из набора составляющих, каждая из которых несёт один и
		 *          более признаков. Составляющая из нескольких признаков применяется
		 *          редко, но встречается, и сводить её к одному признаку нельзя:
		 *          порядок признаков внутри составляющей значения не имеет, а порядок
		 *          самих составляющих значим.
		 *
		 * \~english
		 * @brief Distinguished name
		 * @details A name consists of a set of parts, each of which carries one or more
		 *          attributes. A part of several attributes is used rarely but does occur,
		 *          and it cannot be reduced to a single attribute: the order of the
		 *          attributes inside a part is insignificant, while the order of the
		 *          parts themselves is significant.
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Name {
			// Просмотр записи имени целиком
			view_t element;
			// Набор составляющих имени
			vector <vector <attribute_t>> parts;
		} name_t;

		/**
		 * \~russian
		 * @brief Дополнительное имя владельца
		 *
		 * \~english
		 * @brief Alternative name of the subject
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Alternative {
			// Вид имени
			kind_t kind;
			// Значение имени
			string value;
			// Просмотр записи имени целиком
			view_t element;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Alternative() noexcept : kind(kind_t::OTHER) {}
		} alternative_t;

		/**
		 * \~russian
		 * @brief Расширение сертификата
		 *
		 * \~english
		 * @brief Extension of a certificate
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Extension {
			// Признак обязательности расширения
			bool critical;
			// Опознаватель расширения
			string oid;
			// Просмотр содержимого расширения
			view_t value;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Extension() noexcept : critical(false) {}
		} extension_t;

		/**
		 * \~russian
		 * @brief Сведения об открытом ключе
		 *
		 * \~english
		 * @brief Public key info
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Key {
			// Число неиспользуемых разрядов последнего байта ключа
			uint8_t unused;
			// Опознаватель алгоритма ключа
			string algorithm;
			// Просмотр записи настроек алгоритма ключа
			view_t parameters;
			// Просмотр записи открытого ключа
			view_t key;
			// Просмотр записи сведений об открытом ключе целиком
			view_t element;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Key() noexcept : unused(0) {}
		} key_t;

		/**
		 * \~russian
		 * @brief Сертификат X.509
		 *
		 * @details Объект хранит разобранные сведения сертификата и просмотры внутрь
		 *          разбираемой записи. Запись обязана пережить объект.
		 *
		 * \~english
		 * @brief X.509 certificate
		 * @details The object keeps the parsed info of the certificate and the views
		 *          inside the encoding being parsed. The encoding must outlive the object.
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Certificate {
			private:
				// Издание сертификата
				version_t _version;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Просмотр записи сертификата целиком
				view_t _element;
				// Просмотр подписываемой части сертификата
				view_t _body;
			private:
				// Просмотр порядкового номера сертификата
				view_t _serial;
				// Просмотр записи подписи
				view_t _signature;
				// Число неиспользуемых разрядов последнего байта подписи
				uint8_t _unused;
			private:
				// Просмотр опознавателя издателя
				view_t _issuerUID;
				// Просмотр опознавателя владельца
				view_t _subjectUID;
			private:
				// Опознаватель алгоритма подписи внутри подписываемой части
				string _algorithm;
				// Опознаватель алгоритма подписи снаружи
				string _outer;
				// Просмотр записи настроек алгоритма подписи
				view_t _parameters;
			private:
				// Имя издателя сертификата
				name_t _issuer;
				// Имя владельца сертификата
				name_t _subject;
			private:
				// Начало срока действия сертификата
				int64_t _before;
				// Окончание срока действия сертификата
				int64_t _after;
			private:
				// Сведения об открытом ключе
				key_t _key;
			private:
				// Набор расширений сертификата
				vector <extension_t> _extensions;
			private:
				/**
				 * @brief Метод разбора отличительного имени
				 *
				 * @param element элемент записи имени
				 * @param result  объект имени, в который производится разбор
				 * @return        причина отказа либо error_t::NONE
				 *
				 */
				error_t name(const asn1::element_t & element, name_t & result) noexcept;
				/**
				 * @brief Метод разбора опознавателя алгоритма
				 *
				 * @param element элемент записи опознавателя алгоритма
				 * @param oid     строка, в которую помещается опознаватель алгоритма
				 * @param params  просмотр, в который помещается запись настроек алгоритма
				 * @return        причина отказа либо error_t::NONE
				 *
				 */
				error_t identifier(const asn1::element_t & element, string & oid, view_t & params) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи сертификата
				 *
				 * @param data просмотр разбираемой записи сертификата
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект сертификата
				 *
				 * \~english
				 * @brief Method of parsing a certificate encoding
				 * @param data the view of the certificate encoding being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
				 *
				 */
				error_t parse(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки разобранных сведений
				 *
				 * \~english
				 * @brief Method of clearing the parsed info
				 *
				 * \~
				 *
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод извлечения причины последнего отказа
				 *
				 * @return причина последнего отказа
				 *
				 * \~english
				 * @brief Method of getting the reason of the last failure
				 * @return the reason of the last failure
				 *
				 * \~
				 *
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения издания сертификата
				 *
				 * @return издание сертификата
				 *
				 * \~english
				 * @brief Method of getting the version of the certificate
				 * @return the version of the certificate
				 *
				 * \~
				 *
				 */
				version_t release() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписываемой части сертификата
				 *
				 * @return просмотр подписываемой части сертификата
				 *
				 * @note Подпись ставится под записью этой части, а не под её смыслом,
				 *       поэтому проверять её надлежит по этому просмотру, а не по заново
				 *       собранной записи разобранных полей
				 *
				 * \~english
				 * @brief Method of getting the signed part of the certificate
				 * @return the view of the signed part of the certificate
				 *
				 * \~
				 *
				 */
				const view_t & body() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения порядкового номера сертификата
				 *
				 * @return просмотр порядкового номера сертификата
				 *
				 * \~english
				 * @brief Method of getting the serial number of the certificate
				 * @return the view of the serial number of the certificate
				 *
				 * \~
				 *
				 */
				const view_t & number() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписи сертификата
				 *
				 * @param unused число неиспользуемых разрядов последнего байта подписи
				 * @return       просмотр записи подписи
				 *
				 * \~english
				 * @brief Method of getting the signature of the certificate
				 * @param unused the number of unused bits in the last byte of the signature
				 * @return       the view of the signature encoding
				 *
				 * \~
				 *
				 */
				const view_t & sign(uint8_t & unused) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма подписи
				 *
				 * @return опознаватель алгоритма подписи
				 *
				 * \~english
				 * @brief Method of getting the identifier of the signature algorithm
				 * @return the identifier of the signature algorithm
				 *
				 * \~
				 *
				 */
				const string & algorithms() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения записи настроек алгоритма подписи
				 *
				 * @return просмотр записи настроек (RSASSA-PSS-params у id-RSASSA-PSS) либо пустой просмотр
				 *
				 * \~english
				 * @brief Method of getting the encoding of the parameters of the signature algorithm
				 * @return the view of the encoding of the parameters (RSASSA-PSS-params at id-RSASSA-PSS) or an empty view
				 *
				 * \~
				 */
				const view_t & settings() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения имени издателя сертификата
				 *
				 * @return имя издателя сертификата
				 *
				 * \~english
				 * @brief Method of getting the name of the issuer of the certificate
				 * @return the name of the issuer of the certificate
				 *
				 * \~
				 *
				 */
				const name_t & issuers() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения имени владельца сертификата
				 *
				 * @return имя владельца сертификата
				 *
				 * \~english
				 * @brief Method of getting the name of the subject of the certificate
				 * @return the name of the subject of the certificate
				 *
				 * \~
				 *
				 */
				const name_t & subjects() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения срока действия сертификата
				 *
				 * @param before начало срока действия в секундах от начала эпохи
				 * @param after  окончание срока действия в секундах от начала эпохи
				 *
				 * \~english
				 * @brief Method of getting the validity of the certificate
				 * @param before the beginning of the validity in seconds since the epoch
				 * @param after  the end of the validity in seconds since the epoch
				 *
				 * \~
				 *
				 */
				void validity(int64_t & before, int64_t & after) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения сведений об открытом ключе
				 *
				 * @return сведения об открытом ключе
				 *
				 * \~english
				 * @brief Method of getting the public key info
				 * @return the public key info
				 *
				 * \~
				 *
				 */
				const key_t & key() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора расширений сертификата
				 *
				 * @return набор расширений сертификата
				 *
				 * \~english
				 * @brief Method of getting the set of the extensions of the certificate
				 * @return the set of the extensions of the certificate
				 *
				 * \~
				 *
				 */
				const vector <extension_t> & extension() const noexcept;
				/**
				 * \~russian
				 * @brief Метод поиска расширения сертификата по опознавателю
				 *
				 * @param oid опознаватель разыскиваемого расширения
				 * @return    расширение сертификата либо nullptr
				 *
				 * \~english
				 * @brief Method of finding an extension of the certificate by its identifier
				 * @param oid the identifier of the extension being sought
				 * @return    the extension of the certificate or nullptr
				 *
				 * \~
				 *
				 */
				const extension_t * extension(const string & oid) const noexcept;
				/**
				 * \~russian
				 * @brief Метод поиска расширения сертификата по опознавателю-литералу
				 *
				 * Не строит временную строку: на libstdc++ с прежним устройством строк
				 * любая строка выделяет память, и под noexcept это оборачивалось броском
				 *
				 * @param oid опознаватель разыскиваемого расширения
				 * @return    расширение сертификата либо nullptr
				 *
				 * \~english
				 * @brief Method of finding an extension of the certificate by a literal identifier
				 *
				 * Does not build a temporary string: on libstdc++ with the former string layout
				 * every string allocates, and under noexcept that turned into a throw
				 *
				 * @param oid the identifier of the extension being sought
				 * @return    the extension of the certificate or nullptr
				 *
				 * \~
				 *
				 */
				const extension_t * extension(const char * oid) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор сертификата
				 *
				 * \~english
				 * @brief Constructor of a certificate
				 *
				 * \~
				 *
				 */
				Certificate() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 *
				 */
				~Certificate() noexcept {}
		} certificate_t;

		/**
		 * \~russian
		 * @brief Метод поиска признака имени по опознавателю
		 *
		 * @param name имя, в котором ведётся поиск
		 * @param oid  опознаватель разыскиваемого признака
		 * @return     признак имени либо nullptr
		 *
		 * @note Отдаётся первый признак: опознаватель вправе встретиться в имени не
		 *       единожды, и выбор одного из нескольких — дело вызывающего
		 *
		 * \~english
		 * @brief Method of finding an attribute of a name by its identifier
		 * @param name the name the search is performed in
		 * @param oid  the identifier of the attribute being sought
		 * @return     the attribute of the name or nullptr
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ const attribute_t * attribute(const name_t & name, const string & oid) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки записи имени в виде строки
		 *
		 * @param name   имя, запись которого собирается
		 * @param result строка, в которую помещается результат
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @note Запись собирается по RFC 4514 от последней составляющей к первой.
		 *       Она предназначена для чтения человеком и для сличения имён негодна:
		 *       сличение ведётся по разобранным признакам
		 *
		 * \~english
		 * @brief Method of building the notation of a name as a string
		 * @param name   the name whose notation is being built
		 * @param result the string the result is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t text(const name_t & name, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения основных ограничений сертификата
		 *
		 * @param extension расширение основных ограничений
		 * @param authority признак принадлежности сертификата удостоверяющему центру
		 * @param depth     предельная глубина цепочки либо минус единица
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting the basic constraints of a certificate
		 * @param extension the extension of the basic constraints
		 * @param authority the flag of the certificate belonging to a certification authority
		 * @param depth     the maximum depth of the chain or minus one
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t constraints(const extension_t & extension, bool & authority, int64_t & depth) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения назначения открытого ключа
		 *
		 * @param extension расширение назначения ключа
		 * @param result    набор разрядов назначения ключа
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting the usage of the public key
		 * @param extension the extension of the key usage
		 * @param result    the set of the bits of the key usage
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t usage(const extension_t & extension, uint16_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки критичных расширений сертификата на известность
		 *
		 * @param certificate проверяемый сертификат
		 * @return            признак того, что все критичные расширения известны библиотеке
		 * @details Раздел 4.2 RFC 5280: сертификат с критичным расширением, которого проверяющий не
		 *          понимает, отвергается. Известны: subjectKeyIdentifier, keyUsage, subjectAltName,
		 *          basicConstraints, authorityKeyIdentifier, extendedKeyUsage
		 *
		 * \~english
		 * @brief Method of checking the critical extensions of a certificate for being known
		 * @param certificate the certificate being checked
		 * @return            the flag of all the critical extensions being known to the library
		 * @details The section 4.2 of RFC 5280: a certificate with a critical extension the verifier does not
		 *          understand is rejected. Known: subjectKeyIdentifier, keyUsage, subjectAltName,
		 *          basicConstraints, authorityKeyIdentifier, extendedKeyUsage
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool recognized(const certificate_t & certificate) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки стойкости алгоритма подписи
		 *
		 * @param algorithm  опознаватель алгоритма подписи
		 * @param parameters запись настроек алгоритма подписи либо пустой просмотр
		 * @return           признак слабой подписи: хеш MD2/MD4/MD5/SHA-1, у RSASSA-PSS - по настройкам (без них SHA-1)
		 * @details RFC 9155 выводит SHA-1 из подписей; политика единая для цепочки доверия и
		 *          ответов OCSP: примитив проверки подписи SHA-1 сам по себе принимает,
		 *          политика доверия строже примитива
		 *
		 * \~english
		 * @brief Method of checking the strength of a signature algorithm
		 * @param algorithm  the identifier of the signature algorithm
		 * @param parameters the encoding of the parameters of the algorithm or an empty view
		 * @return           the flag of a weak signature: an MD2/MD4/MD5/SHA-1 hash, for RSASSA-PSS by the parameters (SHA-1 without them)
		 * @details RFC 9155 deprecates SHA-1 in signatures; the policy is common for the chain of
		 *          the trust and for the OCSP responses: the primitive itself accepts SHA-1,
		 *          the trust policy is stricter than the primitive
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool weak(const string & algorithm, const view_t & parameters) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки стойкости открытого ключа
		 *
		 * @param key сведения об открытом ключе
		 * @return    признак слабого ключа: RSA короче 2048 разрядов (SP 800-131A) либо не разбираемый
		 *
		 * \~english
		 * @brief Method of checking the strength of a public key
		 * @param key the info of the public key
		 * @return    the flag of a weak key: RSA shorter than 2048 bits (SP 800-131A) or unparsable
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool weak(const key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки стойкости сертификата как звена доверия
		 *
		 * @param certificate проверяемый сертификат
		 * @param anchor      признак якоря: самоподпись якоря не судится, ключ судится всегда
		 * @return            признак слабого звена: подпись хешем MD5/SHA-1 либо ключ RSA короче 2048 разрядов
		 *
		 * \~english
		 * @brief Method of checking the strength of a certificate as a link of the trust
		 * @param certificate the certificate being checked
		 * @param anchor      the flag of an anchor: the self-signature of an anchor is not judged, the key always is
		 * @return            the flag of a weak link: a signature with an MD5/SHA-1 hash or an RSA key shorter than 2048 bits
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool weak(const certificate_t & certificate, const bool anchor) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения расширенного назначения открытого ключа
		 *
		 * @param extension расширение расширенного назначения ключа
		 * @param result    набор опознавателей назначения ключа
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting the extended usage of the public key
		 * @param extension the extension of the extended key usage
		 * @param result    the set of the identifiers of the key usage
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t purpose(const extension_t & extension, vector <string> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения дополнительных имён владельца
		 *
		 * @param extension расширение дополнительных имён
		 * @param result    набор дополнительных имён
		 * @return          причина отказа либо error_t::NONE
		 *
		 * @note Адрес сети отдаётся записью как есть, без приведения к строке: приведение
		 *       это дело модуля работы с сетью, а не разборщика сертификата
		 *
		 * \~english
		 * @brief Method of getting the alternative names of the subject
		 * @param extension the extension of the alternative names
		 * @param result    the set of the alternative names
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t alternatives(const extension_t & extension, vector <alternative_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения ограничений имён издателя
		 *
		 * @param extension расширение nameConstraints (2.5.29.30)
		 * @param permitted дозволенные поддеревья имён
		 * @param excluded  запрещённые поддеревья имён
		 * @return          причина отказа либо error_t::NONE
		 * @details Раздел 4.2.1.10 RFC 5280: поддеревья с minimum либо maximum отвергаются как
		 *          неразбираемые (EXTENSION) - их стандарт велит не выпускать
		 *
		 * \~english
		 * @brief Method of getting the name constraints of an issuer
		 * @param extension the nameConstraints extension (2.5.29.30)
		 * @param permitted the permitted subtrees of the names
		 * @param excluded  the excluded subtrees of the names
		 * @return          the reason of the failure or error_t::NONE
		 * @details The section 4.2.1.10 of RFC 5280: the subtrees with minimum or maximum are rejected as
		 *          unparseable (EXTENSION) - the standard orders not to issue them
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t constraints(const extension_t & extension, vector <alternative_t> & permitted, vector <alternative_t> & excluded) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения опознавателя ключа владельца
		 *
		 * @param extension расширение опознавателя ключа владельца
		 * @param result    просмотр, в который помещается опознаватель ключа
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting the subject key identifier
		 * @param extension the extension of the subject key identifier
		 * @param result    the view the key identifier is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t subjectKey(const extension_t & extension, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения опознавателя ключа издателя
		 *
		 * @param extension расширение опознавателя ключа издателя
		 * @param result    просмотр, в который помещается опознаватель ключа
		 * @return          причина отказа либо error_t::NONE
		 *
		 * @note Расширение несёт три необязательных поля, и опознаватель ключа среди них
		 *       может отсутствовать вовсе. Его отсутствие отказом не считается: просмотр
		 *       остаётся пустым
		 *
		 * \~english
		 * @brief Method of getting the authority key identifier
		 * @param extension the extension of the authority key identifier
		 * @param result    the view the key identifier is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t authorityKey(const extension_t & extension, view_t & result) noexcept;
	};
};

#endif // __ANTS_X509__
