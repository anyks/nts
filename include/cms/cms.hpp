/**
 * @file cms.hpp
 * @date 2026-10-06
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
 * @brief Заголовочный файл модуля синтаксиса криптографических сообщений —
 *        подписанные и зашифрованные сообщения по RFC 5652,
 *        сведения о получателе KEM по RFC 9629
 *
 * \~english
 * @brief Header file of the cryptographic message syntax module —
 *        the signed and enveloped messages according to RFC 5652,
 *        the KEM recipient info according to RFC 9629
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
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <x509/x509.hpp>
#include <keys/keys.hpp>
#include <sys/global.hpp>
#include <digest/hash.hpp>
#include <agreement/mlkem.hpp>

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
	 * @brief Пространство имён модуля синтаксиса криптографических сообщений
	 *
	 * @details Модуль разбирает и собирает записи ContentInfo по RFC 5652:
	 *          SignedData (подписанное сообщение, в том числе вырожденная запись
	 *          цепочки сертификатов «.p7b») и EnvelopedData (зашифрованное сообщение
	 *          с передачей ключа по RSA и по KEM). Транспортом (S/MIME, файлы)
	 *          модуль не занимается: запись приходит просмотром и уходит набором
	 *          байтов.
	 *
	 * \~english
	 * @brief Namespace of the cryptographic message syntax module
	 *
	 * @details The module parses and builds ContentInfo records according to RFC 5652:
	 *          SignedData (a signed message, including the degenerate record of a
	 *          certificate chain ".p7b") and EnvelopedData (an enveloped message with
	 *          the key transport by RSA and by KEM). The module does not deal with the
	 *          transport (S/MIME, files): the record comes as a view and leaves as a
	 *          byte array.
	 *
	 * \~
	 */
	namespace cms {
		/**
		 * \~russian
		 * @brief Вид содержимого записи ContentInfo
		 *
		 * \~english
		 * @brief Kind of the content of a ContentInfo record
		 *
		 * \~
		 */
		enum class content_t : uint8_t {
			/*!< \~russian Запись не разобрана \~english The record is not parsed \~ */
			NONE = 0x00,
			/*!< \~russian Данные id-data по разделу 4 RFC 5652 \~english The id-data content according to the section 4 of RFC 5652 \~ */
			DATA = 0x01,
			/*!< \~russian Подписанные данные id-signedData по разделу 5 RFC 5652 \~english The id-signedData content according to the section 5 of RFC 5652 \~ */
			SIGNED = 0x02,
			/*!< \~russian Зашифрованные данные id-envelopedData по разделу 6 RFC 5652 \~english The id-envelopedData content according to the section 6 of RFC 5652 \~ */
			ENVELOPED = 0x03,
			/*!< \~russian Хешированные данные id-digestedData по разделу 7 RFC 5652 \~english The id-digestedData content according to the section 7 of RFC 5652 \~ */
			DIGESTED = 0x04,
			/*!< \~russian Зашифрованные данные id-encryptedData по разделу 8 RFC 5652 \~english The id-encryptedData content according to the section 8 of RFC 5652 \~ */
			ENCRYPTED = 0x05,
			/*!< \~russian Данные с имитовставкой id-authenticatedData по разделу 9 RFC 5652 \~english The id-authenticatedData content according to the section 9 of RFC 5652 \~ */
			AUTHENTICATED = 0x06
		};
		/**
		 * \~russian
		 * @brief Причина отказа работы модуля
		 *
		 * \~english
		 * @brief Reason of a failure of the module work
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			/*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			NONE = 0x00,
			/*!< \~russian Ключ чужого алгоритма либо не несёт нужной части \~english The key is of a foreign algorithm or does not carry the needed part \~ */
			KEY = 0x01,
			/*!< \~russian Запись либо ключ не установлены \~english The record or the key is not set \~ */
			EMPTY = 0x02,
			/*!< \~russian Случайные байты выработать не удалось \~english Failed to produce the random bytes \~ */
			RANDOM = 0x03,
			/*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
			MEMORY = 0x04,
			/*!< \~russian Запись не отвечает устройству своего вида \~english The record does not meet the structure of its kind \~ */
			STRUCTURE = 0x05,
			/*!< \~russian Алгоритм подписи, хеша либо шифрования неизвестен \~english The algorithm of the signature, the hash or the encryption is unknown \~ */
			ALGORITHM = 0x06,
			/*!< \~russian Подпись не сошлась либо непригодна для проверки \~english The signature has not converged or is unsuitable for the check \~ */
			SIGNATURE = 0x07
		};

		/**
		 * \~russian
		 * @brief Структура сведения о подписанте в записи SignedData
		 *
		 * @details Просмотры полей указывают внутрь разбираемой записи: запись обязана
		 *          пережить объект. Подпись проверяется отдельным вызовом verify
		 *          сведениями об открытом ключе из сертификата подписывающего.
		 *
		 * \~english
		 * @brief Structure of information about a signer within a SignedData record
		 *
		 * @details The views of the fields point inside the record being parsed: the
		 *          record must outlive the object. The signature is checked by a separate
		 *          call of verify with the public key info from the certificate of the signer.
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Signer {
			// Просмотр записи имени издателя сертификата подписывающего
			view_t issuer;
			// Просмотр порядкового номера сертификата подписывающего
			view_t serial;
			// Просмотр подписи
			view_t signature;
			// Просмотр записи настроек алгоритма подписи
			view_t parameters;
			// Просмотр записи подписанных атрибутов целиком (с меткой [0]), пуст при их отсутствии
			view_t attributes;
			// Опознаватель алгоритма хеша содержимого
			string digest;
			// Опознаватель алгоритма подписи
			string algorithm;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			explicit Signer() noexcept;
		} signer_info_t;
		/**
		 * \~russian
		 * @brief Структура сведения о получателе записи EnvelopedData
		 *
		 * @details Вид сведений определяется полем kind: у передачи ключа RSA
		 *          (KeyTransRecipientInfo по разделу 6.2.1 RFC 5652) заполнены issuer,
		 *          serial и encryptedKey; у сведений KEM (KEMRecipientInfo по разделу 3
		 *          RFC 9629) дополнительно заполнены kem, kemct, kdf, kekLength и wrap.
		 *
		 * \~english
		 * @brief Structure of the recipient information for an EnvelopedData record
		 *
		 * @details The kind of the info is determined by the kind field: at the RSA key
		 *          transport (KeyTransRecipientInfo according to the section 6.2.1 of
		 *          RFC 5652) the issuer, the serial and the encryptedKey are filled; at
		 *          the KEM info (KEMRecipientInfo according to the section 3 of RFC 9629)
		 *          the kem, the kemct, the kdf, the kekLength and the wrap are filled
		 *          additionally.
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Recipient {
			/**
			 * \~russian
			 * @brief Вид сведений о получателе: RSA либо KEM
			 *
			 * \~english
			 * @brief The kind of the recipient information: RSA or KEM
			 *
			 * \~
			 */
			enum class kind_t : uint8_t {
				/*!< \~russian Передача ключа по RSA \~english Key transport by RSA \~ */
				RSA = 0x00,
				/*!< \~russian Инкапсуляция ключа по KEM \~english Key encapsulation by KEM \~ */
				KEM = 0x01
			} kind;
			// Просмотр текста инкапсуляции kemct у сведений вида KEM
			view_t kemct;
			// Просмотр записи имени издателя сертификата получателя
			view_t issuer;
			// Просмотр порядкового номера сертификата получателя
			view_t serial;
			// Длина ключа KEK в байтах у сведений вида KEM
			uint16_t kekLength;
			// Просмотр защищённого ключа шифрования содержимого
			view_t encryptedKey;
			// Опознаватель алгоритма выработки ключа KEK у сведений вида KEM
			string kdf;
			// Опознаватель алгоритма KEM у сведений вида KEM
			string kem;
			// Опознаватель алгоритма защиты ключа CEK у сведений вида KEM
			string wrap;
			// Опознаватель алгоритма защиты ключа (rsaEncryption либо KEM)
			string algorithm;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			explicit Recipient() noexcept;
		} recipient_t;

		/**
		 * \~russian
		 * @brief Класс подписанного сообщения SignedData
		 *
		 * @details Разобранная запись хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Вырожденная запись цепочки
		 *          сертификатов («.p7b») разбирается тем же методом: у неё нет ни
		 *          содержимого, ни подписывающих, есть только сертификаты.
		 *
		 * \~english
		 * @brief Class of the signed message SignedData
		 *
		 * @details The parsed record keeps views inside the record being parsed: the
		 *          record must outlive the object. The degenerate record of a certificate
		 *          chain (".p7b") is parsed by the same method: it carries neither the
		 *          content nor the signers, only the certificates.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Signed {
			private:
				// Просмотр содержимого, пуст при отделённом содержимом
				view_t _content;
			private:
				// Опознаватель вида содержимого
				string _kind;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Набор просмотров записей сертификатов
				vector <view_t> _certificates;
				// Набор сведений о подписывающих
				vector <signer_info_t> _signers;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ContentInfo вида id-signedData
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-signedData kind
				 *
				 * @note The views of the parsed fields point inside the passed encoding,
				 *       therefore the encoding must outlive the object
				 *
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя вида содержимого
				 *
				 * @return опознаватель вида содержимого
				 *
				 * \~english
				 * @brief Method of getting the identifier of the kind of the content
				 *
				 * @return the identifier of the kind of the content
				 *
				 * \~
				 */
				const string & kind() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения содержимого
				 *
				 * @return просмотр содержимого либо пустой просмотр при отделённом содержимом
				 *
				 * \~english
				 * @brief Method of getting the content
				 *
				 * @return the view of the content or an empty view at a detached content
				 *
				 * \~
				 */
				const view_t & content() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора записей сертификатов
				 *
				 * @return набор просмотров записей сертификатов
				 *
				 * \~english
				 * @brief Method of getting the set of the certificate records
				 *
				 * @return the set of the views of the certificate records
				 *
				 * \~
				 */
				const vector <view_t> & certificates() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора сведений о подписывающих
				 *
				 * @return набор сведений о подписывающих
				 *
				 * \~english
				 * @brief Method of getting the set of the infos of the signers
				 *
				 * @return the set of the infos of the signers
				 *
				 * \~
				 */
				const vector <signer_info_t> & signers() const noexcept;
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
				explicit Signed() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Signed() noexcept;
		} signed_t;
		/**
		 * \~russian
		 * @brief Класс зашифрованного сообщения EnvelopedData
		 *
		 * @details Разобранная запись хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Содержимое расшифровывается
		 *          отдельным вызовом unenvelop секретным ключом получателя.
		 *
		 * \~english
		 * @brief EnvelopedData encrypted message class
		 *
		 * @details The parsed record keeps views inside the record being parsed: the
		 *          record must outlive the object. The content is decrypted by a separate
		 *          call of unenvelop with the secret key of the recipient.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Enveloped {
			private:
				// Просмотр зашифрованного содержимого
				view_t _content;
				// Просмотр записи настроек шифра содержимого (синхропосылка)
				view_t _parameters;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель вида содержимого
				string _kind;
				// Опознаватель шифра содержимого
				string _algorithm;
			private:
				// Набор сведений о получателях
				vector <recipient_t> _recipients;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ContentInfo вида id-envelopedData
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-envelopedData kind
				 *
				 * @note The views of the parsed fields point inside the passed encoding,
				 *       therefore the encoding must outlive the object
				 *
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя вида содержимого
				 *
				 * @return опознаватель вида содержимого
				 *
				 * \~english
				 * @brief Method of getting the identifier of the kind of the content
				 *
				 * @return the identifier of the kind of the content
				 *
				 * \~
				 */
				const string & kind() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя шифра содержимого
				 *
				 * @return опознаватель шифра содержимого
				 *
				 * \~english
				 * @brief Method of getting the identifier of the content cipher
				 *
				 * @return the identifier of the content cipher
				 *
				 * \~
				 */
				const string & algorithm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения записи настроек шифра содержимого
				 *
				 * @return просмотр записи настроек шифра содержимого
				 *
				 * \~english
				 * @brief Method of getting the encoding of the settings of the content cipher
				 *
				 * @return the view of the encoding of the settings of the content cipher
				 *
				 * \~
				 */
				const view_t & parameters() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения зашифрованного содержимого
				 *
				 * @return просмотр зашифрованного содержимого
				 *
				 * \~english
				 * @brief Method of getting the encrypted content
				 *
				 * @return the view of the encrypted content
				 *
				 * \~
				 */
				const view_t & content() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора сведений о получателях
				 *
				 * @return набор сведений о получателях
				 *
				 * \~english
				 * @brief Method of getting the set of the infos of the recipients
				 *
				 * @return the set of the infos of the recipients
				 *
				 * \~
				 */
				const vector <recipient_t> & recipients() const noexcept;
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
				explicit Enveloped() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Enveloped() noexcept;
		} enveloped_t;
		/**
		 * \~russian
		 * @brief Класс хешированного сообщения DigestedData
		 *
		 * @details Объект хранит разобранные сведения записи и просмотры внутрь
		 *          разбираемой записи. Запись обязана пережить объект.
		 *
		 * \~english
		 * @brief DigestedData hashed message class
		 *
		 * @details The object keeps the parsed info of the record and the views inside
		 *          the record being parsed. The record must outlive the object.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Digested {
			private:
				// Просмотр содержимого хеша
				view_t _digest;
				// Просмотр содержимого
				view_t _content;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель алгоритма хеша
				string _algorithm;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ContentInfo вида id-digestedData
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-digestedData kind
				 *
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма хеша
				 *
				 * @return опознаватель алгоритма хеша
				 *
				 * \~english
				 * @brief Method of getting the hash algorithm identifier
				 *
				 * @return the hash algorithm identifier
				 *
				 * \~
				 */
				const string & algorithm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения содержимого
				 *
				 * @return просмотр содержимого
				 *
				 * \~english
				 * @brief Method of getting the content
				 *
				 * @return the view of the content
				 *
				 * \~
				 */
				const view_t & content() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения хеша содержимого
				 *
				 * @return просмотр содержимого хеша
				 *
				 * \~english
				 * @brief Method of getting the content digest
				 *
				 * @return the view of the digest content
				 *
				 * \~
				 */
				const view_t & digest() const noexcept;
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
				explicit Digested() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Digested() noexcept;
		} digested_t;
		/**
		 * \~russian
		 * @brief Класс зашифрованного сообщения EncryptedData
		 *
		 * \~english
		 * @brief EncryptedData class for an encrypted message
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Encrypted {
			private:
				// Просмотр зашифрованного содержимого
				view_t _content;
				// Просмотр записи настроек алгоритма шифрования (вектор инициализации)
				view_t _parameters;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель алгоритма шифрования содержимого
				string _algorithm;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ContentInfo вида id-encryptedData
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-encryptedData kind
				 *
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма шифрования
				 *
				 * @return опознаватель алгоритма шифрования содержимого
				 *
				 * \~english
				 * @brief Method of getting the encryption algorithm identifier
				 *
				 * @return the content encryption algorithm identifier
				 *
				 * \~
				 */
				const string & algorithm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения настроек алгоритма шифрования
				 *
				 * @return просмотр записи настроек алгоритма (вектор инициализации)
				 *
				 * \~english
				 * @brief Method of getting the encryption algorithm parameters
				 *
				 * @return the view of the algorithm parameters record (the initialization vector)
				 *
				 * \~
				 */
				const view_t & parameters() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения зашифрованного содержимого
				 *
				 * @return просмотр зашифрованного содержимого
				 *
				 * \~english
				 * @brief Method of getting the encrypted content
				 *
				 * @return the view of the encrypted content
				 *
				 * \~
				 */
				const view_t & content() const noexcept;
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
				explicit Encrypted() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Encrypted() noexcept;
		} encrypted_t;
		/**
		 * \~russian
		 * @brief Класс сообщения с имитовставкой AuthenticatedData
		 *
		 * \~english
		 * @brief AuthenticatedData message class with an authentication tag (imitation tag)
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Authenticated {
			private:
				// Просмотр содержимого имитовставки
				view_t _mac;
				// Просмотр содержимого
				view_t _content;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель алгоритма имитовставки
				string _algorithm;
			public:
				/**
				 * \~russian
				 * @brief  Метод разбора записи ContentInfo вида id-authenticatedData
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-authenticatedData kind
				 *
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма имитовставки
				 *
				 * @return опознаватель алгоритма имитовставки
				 *
				 * \~english
				 * @brief Method of getting the MAC algorithm identifier
				 *
				 * @return the MAC algorithm identifier
				 *
				 * \~
				 */
				const string & algorithm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения содержимого
				 *
				 * @return просмотр содержимого
				 *
				 * \~english
				 * @brief Method of getting the content
				 *
				 * @return the view of the content
				 *
				 * \~
				 */
				const view_t & content() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения имитовставки
				 *
				 * @return просмотр содержимого имитовставки
				 *
				 * \~english
				 * @brief Method of getting the MAC
				 *
				 * @return the view of the MAC content
				 *
				 * \~
				 */
				const view_t & mac() const noexcept;
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
				explicit Authenticated() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Authenticated() noexcept;
		} authenticated_t;

		/**
		 * \~russian
		 * @brief Функция сборки записи DigestedData
		 *
		 * @param content хешируемое содержимое
		 * @param hash    алгоритм хеша
		 * @param result  место, в которое помещается запись ContentInfo
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a DigestedData record
		 *
		 * @param content the content being digested
		 * @param hash    the hashing algorithm
		 * @param result  the place the ContentInfo record is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t digest(const view_t & content, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки записи DigestedData
		 *
		 * @param digested разобранная запись
		 * @return         причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of checking a DigestedData record
		 *
		 * @param digested the parsed record
		 * @return         the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t digestVerify(const digested_t & digested) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки записи EncryptedData
		 *
		 * @param content шифруемое содержимое
		 * @param key     ключ шифрования содержимого (16/24/32 байта AES)
		 * @param result  место, в которое помещается запись ContentInfo
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an EncryptedData record
		 *
		 * @param content the content being encrypted
		 * @param key     the content encryption key (16/24/32 bytes of AES)
		 * @param result  the place the ContentInfo record is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encrypt(const view_t & content, const view_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция расшифрования записи EncryptedData
		 *
		 * @param encrypted разобранная запись
		 * @param key       ключ шифрования содержимого
		 * @param result    место, в которое помещается расшифрованное содержимое
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of decrypting an EncryptedData record
		 *
		 * @param encrypted the parsed record
		 * @param key       the content encryption key
		 * @param result    the place the decrypted content is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decrypt(const encrypted_t & encrypted, const view_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки записи AuthenticatedData
		 *
		 * @param content содержимое под имитовставку
		 * @param key     ключ имитовставки
		 * @param hash    алгоритм хеша имитовставки HMAC
		 * @param result  место, в которое помещается запись ContentInfo
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an AuthenticatedData record
		 *
		 * @param content the content being authenticated
		 * @param key     the MAC key
		 * @param hash    the hashing algorithm of the HMAC MAC
		 * @param result  the place the ContentInfo record is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t authenticate(const view_t & content, const view_t & key, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки записи AuthenticatedData
		 *
		 * @param authenticated разобранная запись
		 * @param key           ключ имитовставки
		 * @return              причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of checking an AuthenticatedData record
		 *
		 * @param authenticated the parsed record
		 * @param key           the MAC key
		 * @return              the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t authenticateVerify(const authenticated_t & authenticated, const view_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Функция определения вида записи ContentInfo
		 *
		 * @param data просмотр разбираемой записи
		 * @return     вид содержимого записи, content_t::NONE у записи иного вида
		 *
		 * \~english
		 * @brief Function of determining the kind of a ContentInfo record
		 *
		 * @param data the view of the record being parsed
		 * @return     the kind of the content of the record, content_t::NONE at a record of a foreign kind
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ content_t content(const view_t & data) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки подписанного сообщения
		 *
		 * @param certificates набор записей сертификатов (первый — сертификат подписывающего)
		 * @param issuer       просмотр записи имени издателя сертификата подписывающего
		 * @param serial       просмотр порядкового номера сертификата подписывающего
		 * @param content      подписываемое содержимое
		 * @param signer       подготовленный секретный ключ подписи
		 * @param hash         алгоритм хеша содержимого (для RSA и ECDSA; не рассматривается у Ed25519 и ML-DSA)
		 * @param result       место, в которое помещается запись ContentInfo
		 * @return             отказ сборки
		 *
		 * @details Собирается SignedData с подписанными атрибутами contentType и
		 *          messageDigest по разделу 11 RFC 5652: подпись ставится под записью
		 *          атрибутов. Содержимое вкладывается в запись.
		 *
		 * \~english
		 * @brief Function of building a signed message
		 *
		 * @param certificates the set of the certificate records (the first one is of the signer)
		 * @param issuer       the view of the issuer name encoding of the certificate of the signer
		 * @param serial       the view of the serial number of the certificate of the signer
		 * @param content      the content being signed
		 * @param signer       the prepared secret key of the signature
		 * @param hash         the hash algorithm of the content (for RSA and ECDSA; not considered at Ed25519 and ML-DSA)
		 * @param result       the place the ContentInfo record is put into
		 * @return             the failure of the building
		 *
		 * @details A SignedData with the signed attributes contentType and
		 *          messageDigest according to the section 11 of RFC 5652 is built: the signature is put over the encoding
		 *          of the attributes. The content is embedded into the record.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t sign(const vector <view_t> & certificates, const view_t & issuer, const view_t & serial, const view_t & content, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки подписи подписанного сообщения
		 *
		 * @param signed_ разобранное подписанное сообщение
		 * @param signer  сведения о проверяемом подписывающем
		 * @param content отделённое содержимое либо пустой просмотр, если содержимое вложено в запись
		 * @param key     сведения об открытом ключе из сертификата подписывающего
		 * @return        отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *                непригодна, ALGORITHM - алгоритм неизвестен, KEY - ключ чужого алгоритма
		 *
		 * @details При наличии подписанных атрибутов сперва сверяется хеш содержимого из
		 *          атрибута messageDigest, затем проверяется подпись под записью атрибутов
		 *          по разделу 5.4 RFC 5652. При отсутствии атрибутов подпись проверяется
		 *          под самим содержимым.
		 *
		 * \~english
		 * @brief Function of the check of the signature of a signed message
		 *
		 * @param signed_ the parsed signed message
		 * @param signer  the info of the signer being checked
		 * @param content the detached content or an empty view if the content is embedded into the record
		 * @param key     the info of the public key from the certificate of the signer
		 * @return        the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *                unsuitable, ALGORITHM - the algorithm is unknown, KEY - a key of a foreign algorithm
		 *
		 * @details When the signed attributes are present, the hash of the content from
		 *          the messageDigest attribute is compared first, then the signature over the encoding of the attributes
		 *          is checked according to the section 5.4 of RFC 5652. When the attributes are absent, the signature is checked
		 *          over the content itself.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const signed_t & signed_, const signer_info_t & signer, const view_t & content, const x509::key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки вырожденной записи цепочки сертификатов («.p7b»)
		 *
		 * @param certificates набор записей сертификатов
		 * @param result       место, в которое помещается запись ContentInfo
		 * @return             отказ сборки
		 *
		 * @details Собирается SignedData без содержимого и без подписывающих: только
		 *          набор сертификатов, как принято у записей «.p7b» (degenerate SignedData
		 *          по разделу 5.2.1 RFC 5652).
		 *
		 * \~english
		 * @brief Function of building a degenerate record of a certificate chain (".p7b")
		 *
		 * @param certificates the set of the certificate records
		 * @param result       the place the ContentInfo record is put into
		 * @return             the failure of the building
		 *
		 * @details A SignedData without the content and without the signers is built: only
		 *          the set of the certificates, as accepted at the ".p7b" encodings (degenerate SignedData
		 *          according to the section 5.2.1 of RFC 5652).
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certificates(const vector <view_t> & certificates, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки зашифрованного сообщения с передачей ключа по RSA
		 *
		 * @param content зашифровываемое содержимое
		 * @param issuer  просмотр записи имени издателя сертификата получателя
		 * @param serial  просмотр порядкового номера сертификата получателя
		 * @param key     сведения об открытом ключе RSA из сертификата получателя
		 * @param result  место, в которое помещается запись ContentInfo
		 * @return        отказ сборки
		 *
		 * @details Содержимое зашифровывается AES-256-CBC со случайным ключом и
		 *          синхропосылкой, ключ передаётся получателю в KeyTransRecipientInfo
		 *          по схеме RSA PKCS #1 v1.5 (раздел 6.2.1 RFC 5652).
		 *
		 * \~english
		 * @brief Function of building an enveloped message with the key transport by RSA
		 *
		 * @param content the content being encrypted
		 * @param issuer  the view of the issuer name encoding of the certificate of the recipient
		 * @param serial  the view of the serial number of the certificate of the recipient
		 * @param key     the info of the public RSA key from the certificate of the recipient
		 * @param result  the place the ContentInfo record is put into
		 * @return        the failure of the building
		 *
		 * @details The content is encrypted by AES-256-CBC with a random key and
		 *          an IV, the key is transported to the recipient in a KeyTransRecipientInfo
		 *          by the RSA PKCS #1 v1.5 scheme (the section 6.2.1 of RFC 5652).
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t envelop(const view_t & content, const view_t & issuer, const view_t & serial, const x509::key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки зашифрованного сообщения с инкапсуляцией ключа по KEM
		 *
		 * @param content зашифровываемое содержимое
		 * @param issuer  просмотр записи имени издателя сертификата получателя
		 * @param serial  просмотр порядкового номера сертификата получателя
		 * @param kem     набор параметров ML-KEM
		 * @param key     открытый ключ инкапсуляции ML-KEM получателя
		 * @param result  место, в которое помещается запись ContentInfo
		 * @return        отказ сборки
		 *
		 * @details Содержимое зашифровывается AES-256-CBC со случайным ключом и
		 *          синхропосылкой. Ключ содержимого защищается по RFC 9629: общий секрет
		 *          инкапсуляции ML-KEM пропускается через HKDF-SHA-256 со сведениями
		 *          CMSORIforKEMOtherInfo, итоговый KEK защищает ключ содержимого по
		 *          AES-KW (RFC 3394).
		 *
		 * \~english
		 * @brief Function of building an enveloped message with the key encapsulation by KEM
		 *
		 * @param content the content being encrypted
		 * @param issuer  the view of the issuer name encoding of the certificate of the recipient
		 * @param serial  the view of the serial number of the certificate of the recipient
		 * @param kem     the ML-KEM parameter set
		 * @param key     the ML-KEM encapsulation key of the recipient
		 * @param result  the place the ContentInfo record is put into
		 * @return        the failure of the building
		 *
		 * @details The content is encrypted by AES-256-CBC with a random key and
		 *          an IV. The content key is protected according to RFC 9629: the shared secret
		 *          of the ML-KEM encapsulation is passed through HKDF-SHA-256 with the info
		 *          CMSORIforKEMOtherInfo, and the resulting KEK protects the content key by
		 *          AES-KW (RFC 3394).
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t envelop(const view_t & content, const view_t & issuer, const view_t & serial, const agreement::kem_t kem, const view_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция расшифрования зашифрованного сообщения ключом RSA
		 *
		 * @param enveloped разобранное зашифрованное сообщение
		 * @param key       секретный ключ RSA получателя
		 * @param result    место, в которое помещается расшифрованное содержимое
		 * @return          отказ расшифрования
		 *
		 * \~english
		 * @brief Function of the decryption of an enveloped message by an RSA key
		 *
		 * @param enveloped the parsed enveloped message
		 * @param key       the secret RSA key of the recipient
		 * @param result    the place the decrypted content is put into
		 * @return          the failure of the decryption
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t unenvelop(const enveloped_t & enveloped, const keys::key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция расшифрования зашифрованного сообщения ключом ML-KEM
		 *
		 * @param enveloped разобранное зашифрованное сообщение
		 * @param kem       набор параметров ML-KEM
		 * @param secret    секретный ключ декапсуляции ML-KEM получателя
		 * @param result    место, в которое помещается расшифрованное содержимое
		 * @return          отказ расшифрования
		 *
		 * \~english
		 * @brief Function of the decryption of an enveloped message by an ML-KEM key
		 *
		 * @param enveloped the parsed enveloped message
		 * @param kem       the ML-KEM parameter set
		 * @param secret    the ML-KEM decapsulation key of the recipient
		 * @param result    the place the decrypted content is put into
		 * @return          the failure of the decryption
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t unenvelop(const enveloped_t & enveloped, const agreement::kem_t kem, const view_t & secret, vector <uint8_t> & result) noexcept;
	};
};
