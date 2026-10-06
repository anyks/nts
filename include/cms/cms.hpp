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
#ifndef __ANTS_CMS__
#define __ANTS_CMS__

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
#include <digest/hash.hpp>
#include <agreement/mlkem.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>

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
	 * @details The module parses and builds ContentInfo records according to RFC 5652:
	 *          SignedData (a signed message, including the degenerate record of a
	 *          certificate chain ".p7b") and EnvelopedData (an enveloped message with
	 *          the key transport by RSA and by KEM). The module does not deal with the
	 *          transport (S/MIME, files): the record comes as a view and leaves as a
	 *          byte array.
	 *
	 * \~
	 *
	 */
	namespace cms {
		/**
		 * \~russian
		 * @brief Причина отказа работы модуля
		 *
		 * \~english
		 * @brief Reason of a failure of the module work
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY     = 0x01, /*!< \~russian Запись либо ключ не установлены \~english The record or the key is not set \~ */
			STRUCTURE = 0x02, /*!< \~russian Запись не отвечает устройству своего вида \~english The record does not meet the structure of its kind \~ */
			ALGORITHM = 0x03, /*!< \~russian Алгоритм подписи, хеша либо шифрования неизвестен \~english The algorithm of the signature, the hash or the encryption is unknown \~ */
			SIGNATURE = 0x04, /*!< \~russian Подпись не сошлась либо непригодна для проверки \~english The signature has not converged or is unsuitable for the check \~ */
			KEY       = 0x05, /*!< \~russian Ключ чужого алгоритма либо не несёт нужной части \~english The key is of a foreign algorithm or does not carry the needed part \~ */
			RANDOM    = 0x06, /*!< \~russian Случайные байты выработать не удалось \~english Failed to produce the random bytes \~ */
			MEMORY    = 0x07  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Вид содержимого записи ContentInfo
		 *
		 * \~english
		 * @brief Kind of the content of a ContentInfo record
		 *
		 * \~
		 *
		 */
		enum class content_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Запись не разобрана \~english The record is not parsed \~ */
			DATA     = 0x01, /*!< \~russian Данные id-data по разделу 4 RFC 5652 \~english The id-data content according to the section 4 of RFC 5652 \~ */
			SIGNED   = 0x02, /*!< \~russian Подписанные данные id-signedData по разделу 5 RFC 5652 \~english The id-signedData content according to the section 5 of RFC 5652 \~ */
			ENVELOPED = 0x03 /*!< \~russian Зашифрованные данные id-envelopedData по разделу 6 RFC 5652 \~english The id-envelopedData content according to the section 6 of RFC 5652 \~ */
		};

		/**
		 * \~russian
		 * @brief Сведения о подписывающем в записи SignedData
		 *
		 * @details Просмотры полей указывают внутрь разбираемой записи: запись обязана
		 *          пережить объект. Подпись проверяется отдельным вызовом verify
		 *          сведениями об открытом ключе из сертификата подписывающего.
		 *
		 * \~english
		 * @brief Info of a signer of a SignedData record
		 * @details The views of the fields point inside the record being parsed: the
		 *          record must outlive the object. The signature is checked by a separate
		 *          call of verify with the public key info from the certificate of the signer.
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Signer {
			// Просмотр записи имени издателя сертификата подписывающего
			view_t issuer;
			// Просмотр порядкового номера сертификата подписывающего
			view_t serial;
			// Опознаватель алгоритма хеша содержимого
			string digest;
			// Опознаватель алгоритма подписи
			string algorithm;
			// Просмотр записи настроек алгоритма подписи
			view_t parameters;
			// Просмотр записи подписанных атрибутов целиком (с меткой [0]), пуст при их отсутствии
			view_t attributes;
			// Просмотр подписи
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
			 *
			 */
			Signer() noexcept {}
		} signer_info_t;

		/**
		 * \~russian
		 * @brief Подписанное сообщение SignedData
		 *
		 * @details Разобранная запись хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Вырожденная запись цепочки
		 *          сертификатов («.p7b») разбирается тем же методом: у неё нет ни
		 *          содержимого, ни подписывающих, есть только сертификаты.
		 *
		 * \~english
		 * @brief A signed message SignedData
		 * @details The parsed record keeps views inside the record being parsed: the
		 *          record must outlive the object. The degenerate record of a certificate
		 *          chain (".p7b") is parsed by the same method: it carries neither the
		 *          content nor the signers, only the certificates.
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Signed {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель вида содержимого
				string _kind;
				// Просмотр содержимого, пуст при отделённом содержимом
				view_t _content;
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
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-signedData kind
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
				Signed() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Signed() noexcept {}
		} signed_t;

		/**
		 * \~russian
		 * @brief Сведения о получателе записи EnvelopedData
		 *
		 * @details Вид сведений определяется полем kind: у передачи ключа RSA
		 *          (KeyTransRecipientInfo по разделу 6.2.1 RFC 5652) заполнены issuer,
		 *          serial и encryptedKey; у сведений KEM (KEMRecipientInfo по разделу 3
		 *          RFC 9629) дополнительно заполнены kem, kemct, kdf, kekLength и wrap.
		 *
		 * \~english
		 * @brief Info of a recipient of an EnvelopedData record
		 * @details The kind of the info is determined by the kind field: at the RSA key
		 *          transport (KeyTransRecipientInfo according to the section 6.2.1 of
		 *          RFC 5652) the issuer, the serial and the encryptedKey are filled; at
		 *          the KEM info (KEMRecipientInfo according to the section 3 of RFC 9629)
		 *          the kem, the kemct, the kdf, the kekLength and the wrap are filled
		 *          additionally.
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Recipient {
			// Вид сведений о получателе: RSA либо KEM
			enum class kind_t : uint8_t {
				RSA = 0x00, /*!< \~russian Передача ключа по RSA \~english Key transport by RSA \~ */
				KEM = 0x01  /*!< \~russian Инкапсуляция ключа по KEM \~english Key encapsulation by KEM \~ */
			} kind;
			// Просмотр записи имени издателя сертификата получателя
			view_t issuer;
			// Просмотр порядкового номера сертификата получателя
			view_t serial;
			// Опознаватель алгоритма защиты ключа (rsaEncryption либо KEM)
			string algorithm;
			// Просмотр защищённого ключа шифрования содержимого
			view_t encryptedKey;
			// Опознаватель алгоритма KEM у сведений вида KEM
			string kem;
			// Просмотр текста инкапсуляции kemct у сведений вида KEM
			view_t kemct;
			// Опознаватель алгоритма выработки ключа KEK у сведений вида KEM
			string kdf;
			// Длина ключа KEK в байтах у сведений вида KEM
			uint16_t kekLength;
			// Опознаватель алгоритма защиты ключа CEK у сведений вида KEM
			string wrap;
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
			Recipient() noexcept : kind(kind_t::RSA), kekLength(0) {}
		} recipient_t;

		/**
		 * \~russian
		 * @brief Зашифрованное сообщение EnvelopedData
		 *
		 * @details Разобранная запись хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Содержимое расшифровывается
		 *          отдельным вызовом unenvelop секретным ключом получателя.
		 *
		 * \~english
		 * @brief An enveloped message EnvelopedData
		 * @details The parsed record keeps views inside the record being parsed: the
		 *          record must outlive the object. The content is decrypted by a separate
		 *          call of unenvelop with the secret key of the recipient.
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Enveloped {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Опознаватель вида содержимого
				string _kind;
				// Опознаватель шифра содержимого
				string _algorithm;
				// Просмотр записи настроек шифра содержимого (синхропосылка)
				view_t _parameters;
				// Просмотр зашифрованного содержимого
				view_t _content;
			private:
				// Набор сведений о получателях
				vector <recipient_t> _recipients;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ContentInfo вида id-envelopedData
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект
				 *
				 * \~english
				 * @brief Method of parsing a ContentInfo record of the id-envelopedData kind
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
				Enveloped() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Enveloped() noexcept {}
		} enveloped_t;

		/**
		 * \~russian
		 * @brief Метод определения вида записи ContentInfo
		 *
		 * @param data просмотр разбираемой записи
		 * @return     вид содержимого записи, content_t::NONE у записи иного вида
		 *
		 * \~english
		 * @brief Method of determining the kind of a ContentInfo record
		 * @param data the view of the record being parsed
		 * @return     the kind of the content of the record, content_t::NONE at a record of a foreign kind
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ content_t content(const view_t & data) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки подписанного сообщения
		 *
		 * @param certificates набор записей сертификатов (первый — сертификат подписывающего)
		 * @param issuer       просмотр записи имени издателя сертификата подписывающего
		 * @param serial       просмотр порядкового номера сертификата подписывающего
		 * @param content      подписываемое содержимое
		 * @param signer       подготовленный секретный ключ подписи
		 * @param hash         алгоритм хеша содержимого (для RSA и ECDSA; не рассматривается у Ed25519 и ML-DSA)
		 * @param result       место, в которое помещается запись ContentInfo
		 *
		 * @return             отказ сборки
		 *
		 * @details Собирается SignedData с подписанными атрибутами contentType и
		 *          messageDigest по разделу 11 RFC 5652: подпись ставится под записью
		 *          атрибутов. Содержимое вкладывается в запись.
		 *
		 * \~english
		 * @brief Method of building a signed message
		 * @param certificates the set of the certificate records (the first one is of the signer)
		 * @param issuer       the view of the issuer name encoding of the certificate of the signer
		 * @param serial       the view of the serial number of the certificate of the signer
		 * @param content      the content being signed
		 * @param signer       the prepared secret key of the signature
		 * @param hash         the hash algorithm of the content (for RSA and ECDSA; not considered at Ed25519 and ML-DSA)
		 * @param result       the place the ContentInfo record is put into
		 * @return             the failure of the building
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t sign(const vector <view_t> & certificates, const view_t & issuer, const view_t & serial, const view_t & content, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки подписи подписанного сообщения
		 *
		 * @param signed_ разобранное подписанное сообщение
		 * @param signer  сведения о проверяемом подписывающем
		 * @param content отделённое содержимое либо пустой просмотр, если содержимое вложено в запись
		 * @param key     сведения об открытом ключе из сертификата подписывающего
		 *
		 * @return        отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *                непригодна, ALGORITHM - алгоритм неизвестен, KEY - ключ чужого алгоритма
		 *
		 * @details При наличии подписанных атрибутов сперва сверяется хеш содержимого из
		 *          атрибута messageDigest, затем проверяется подпись под записью атрибутов
		 *          по разделу 5.4 RFC 5652. При отсутствии атрибутов подпись проверяется
		 *          под самим содержимым.
		 *
		 * \~english
		 * @brief Method of the check of the signature of a signed message
		 * @param signed_ the parsed signed message
		 * @param signer  the info of the signer being checked
		 * @param content the detached content or an empty view if the content is embedded into the record
		 * @param key     the info of the public key from the certificate of the signer
		 * @return        the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *                unsuitable, ALGORITHM - the algorithm is unknown, KEY - a key of a foreign algorithm
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const signed_t & signed_, const signer_info_t & signer, const view_t & content, const x509::key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки вырожденной записи цепочки сертификатов («.p7b»)
		 *
		 * @param certificates набор записей сертификатов
		 * @param result       место, в которое помещается запись ContentInfo
		 *
		 * @return             отказ сборки
		 *
		 * @details Собирается SignedData без содержимого и без подписывающих: только
		 *          набор сертификатов, как принято у записей «.p7b» (degenerate SignedData
		 *          по разделу 5.2.1 RFC 5652).
		 *
		 * \~english
		 * @brief Method of building a degenerate record of a certificate chain (".p7b")
		 * @param certificates the set of the certificate records
		 * @param result       the place the ContentInfo record is put into
		 * @return             the failure of the building
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certificates(const vector <view_t> & certificates, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки зашифрованного сообщения с передачей ключа по RSA
		 *
		 * @param content    зашифровываемое содержимое
		 * @param issuer     просмотр записи имени издателя сертификата получателя
		 * @param serial     просмотр порядкового номера сертификата получателя
		 * @param key        сведения об открытом ключе RSA из сертификата получателя
		 * @param result     место, в которое помещается запись ContentInfo
		 *
		 * @return           отказ сборки
		 *
		 * @details Содержимое зашифровывается AES-256-CBC со случайным ключом и
		 *          синхропосылкой, ключ передаётся получателю в KeyTransRecipientInfo
		 *          по схеме RSA PKCS #1 v1.5 (раздел 6.2.1 RFC 5652).
		 *
		 * \~english
		 * @brief Method of building an enveloped message with the key transport by RSA
		 * @param content    the content being encrypted
		 * @param issuer     the view of the issuer name encoding of the certificate of the recipient
		 * @param serial     the view of the serial number of the certificate of the recipient
		 * @param key        the info of the public RSA key from the certificate of the recipient
		 * @param result     the place the ContentInfo record is put into
		 * @return           the failure of the building
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t envelop(const view_t & content, const view_t & issuer, const view_t & serial, const x509::key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки зашифрованного сообщения с инкапсуляцией ключа по KEM
		 *
		 * @param content    зашифровываемое содержимое
		 * @param issuer     просмотр записи имени издателя сертификата получателя
		 * @param serial     просмотр порядкового номера сертификата получателя
		 * @param kem        набор параметров ML-KEM
		 * @param key        открытый ключ инкапсуляции ML-KEM получателя
		 * @param result     место, в которое помещается запись ContentInfo
		 *
		 * @return           отказ сборки
		 *
		 * @details Содержимое зашифровывается AES-256-CBC со случайным ключом и
		 *          синхропосылкой. Ключ содержимого защищается по RFC 9629: общий секрет
		 *          инкапсуляции ML-KEM пропускается через HKDF-SHA-256 со сведениями
		 *          CMSORIforKEMOtherInfo, итоговый KEK защищает ключ содержимого по
		 *          AES-KW (RFC 3394).
		 *
		 * \~english
		 * @brief Method of building an enveloped message with the key encapsulation by KEM
		 * @param content    the content being encrypted
		 * @param issuer     the view of the issuer name encoding of the certificate of the recipient
		 * @param serial     the view of the serial number of the certificate of the recipient
		 * @param kem        the ML-KEM parameter set
		 * @param key        the ML-KEM encapsulation key of the recipient
		 * @param result     the place the ContentInfo record is put into
		 * @return           the failure of the building
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t envelop(const view_t & content, const view_t & issuer, const view_t & serial, const agreement::kem_t kem, const view_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод расшифрования зашифрованного сообщения ключом RSA
		 *
		 * @param enveloped разобранное зашифрованное сообщение
		 * @param key       секретный ключ RSA получателя
		 * @param result    место, в которое помещается расшифрованное содержимое
		 *
		 * @return          отказ расшифрования
		 *
		 * \~english
		 * @brief Method of the decryption of an enveloped message by an RSA key
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
		 * @brief Метод расшифрования зашифрованного сообщения ключом ML-KEM
		 *
		 * @param enveloped разобранное зашифрованное сообщение
		 * @param kem       набор параметров ML-KEM
		 * @param secret    секретный ключ декапсуляции ML-KEM получателя
		 * @param result    место, в которое помещается расшифрованное содержимое
		 *
		 * @return          отказ расшифрования
		 *
		 * \~english
		 * @brief Method of the decryption of an enveloped message by an ML-KEM key
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

#endif // __ANTS_CMS__
