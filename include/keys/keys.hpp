/**
 * @file keys.hpp
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
 * @brief Заголовочный файл модуля кодеков ключей — разбор и запись ключей в
 *        кодировке DER и обёртке PEM: SubjectPublicKeyInfo по RFC 5480 и RFC 8410,
 *        PrivateKeyInfo по RFC 5958, ECPrivateKey по RFC 5915, RSAPrivateKey по
 *        RFC 8017, EncryptedPrivateKeyInfo по схеме PBES2 из RFC 8018
 *
 * \~english
 * @brief Header file of the module of the codecs of the keys — the parsing and the writing
 *        of the keys in the DER encoding and in the PEM envelope: SubjectPublicKeyInfo according
 *        to RFC 5480 and RFC 8410, PrivateKeyInfo according to RFC 5958, ECPrivateKey according
 *        to RFC 5915, RSAPrivateKey according to RFC 8017, EncryptedPrivateKeyInfo according
 *        to the PBES2 scheme of RFC 8018
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_KEYS__
#define __ANTS_KEYS__

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
#include <sign/rsa.hpp>
#include <sign/gost.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <curve/curve.hpp>

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
	 * @brief Пространство имён модуля кодеков ключей
	 *
	 * @details Модуль переводит ключи между их записью в кодировке DER (либо в обёртке
	 *          PEM по RFC 7468) и разобранным видом: набором составляющих ключа числами
	 *          порядком от старшего байта к младшему. Разобранный ключ устанавливается
	 *          в примитивы подписи и согласования ключей методами-помощниками.
	 *
	 * @note Ввода и вывода модуль не делает: он принимает и выдаёт готовую запись целиком,
	 *       а чтение файла принадлежит тому, кому принадлежит и файловая система
	 *
	 * @note Пароль зашифрованного ключа идёт в выработку ключа шифрования последовательностью
	 *       октетов без какого-либо преобразования, как того велит раздел 3 RFC 8018
	 *
	 * \~english
	 * @brief Namespace of the module of the codecs of the keys
	 * @details The module translates the keys between their writing in the DER encoding (or in
	 *          the PEM envelope according to RFC 7468) and the parsed form: a set of the components
	 *          of the key as the numbers in the order from the senior byte to the junior one. The
	 *          parsed key is installed into the primitives of the signature and of the key agreement
	 *          by the helper methods.
	 * @note The module does no input and output: it accepts and produces a ready record as a whole,
	 *       while the reading of a file belongs to the one the file system belongs to
	 * @note The password of an encrypted key goes into the derivation of the encryption key as a
	 *       sequence of the octets without any transformation, as the section 3 of RFC 8018 orders
	 *
	 * \~
	 */
	namespace keys {
		/**
		 * \~russian
		 * @brief Отказы работы с ключами
		 *
		 * \~english
		 * @brief Failures of the work with the keys
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY     = 0x01, /*!< \~russian Ключ не установлен либо не несёт нужной части \~english The key is not set or does not carry the needed part \~ */
			STRUCTURE = 0x02, /*!< \~russian Запись не отвечает устройству своего вида \~english The record does not meet the structure of its kind \~ */
			ALGORITHM = 0x03, /*!< \~russian Алгоритм ключа либо его настройки неизвестны \~english The algorithm of the key or its settings are unknown \~ */
			CURVE     = 0x04, /*!< \~russian Кривая неизвестна либо точка ей не принадлежит \~english The curve is unknown or the point does not belong to it \~ */
			VALUE     = 0x05, /*!< \~russian Составляющие ключа негодны либо не согласованы \~english The components of the key are unfit or not consistent \~ */
			CIPHER    = 0x06, /*!< \~russian Схема защиты ключа паролем неизвестна \~english The scheme of the protection of the key by a password is unknown \~ */
			PASSWORD  = 0x07, /*!< \~russian Пароль не подошёл к зашифрованному ключу \~english The password did not fit the encrypted key \~ */
			LABEL     = 0x08, /*!< \~russian Записи ключа известного вида в тексте нет \~english There is no record of a key of a known kind in the text \~ */
			RANDOM    = 0x09, /*!< \~russian Случайные байты выработать не удалось \~english Failed to produce the random bytes \~ */
			MEMORY    = 0x0A  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Виды ключей
		 *
		 * \~english
		 * @brief Kinds of the keys
		 *
		 * \~
		 */
		enum class kind_t : uint8_t {
			NONE    = 0x00, /*!< \~russian Ключ не установлен \~english The key is not set \~ */
			RSA     = 0x01, /*!< \~russian Ключ RSA по RFC 8017 \~english RSA key according to RFC 8017 \~ */
			EC      = 0x02, /*!< \~russian Ключ на кривой Вейерштрасса по RFC 5480 \~english Key on a Weierstrass curve according to RFC 5480 \~ */
			ED25519 = 0x03, /*!< \~russian Ключ подписи Ed25519 по RFC 8410 \~english Ed25519 signature key according to RFC 8410 \~ */
			X25519  = 0x04, /*!< \~russian Ключ согласования X25519 по RFC 8410 \~english X25519 agreement key according to RFC 8410 \~ */
			GOST    = 0x05  /*!< \~russian Ключ по ГОСТ Р 34.10-2012 по RFC 9215 \~english GOST R 34.10-2012 key according to RFC 9215 \~ */
		};

		/**
		 * \~russian
		 * @brief Виды записи ключа в обёртке PEM
		 *
		 * \~english
		 * @brief Kinds of the writing of a key in the PEM envelope
		 *
		 * \~
		 */
		enum class container_t : uint8_t {
			PRIVATE   = 0x00, /*!< \~russian PrivateKeyInfo под меткой «PRIVATE KEY» \~english PrivateKeyInfo under the label «PRIVATE KEY» \~ */
			ENCRYPTED = 0x01, /*!< \~russian EncryptedPrivateKeyInfo под меткой «ENCRYPTED PRIVATE KEY» \~english EncryptedPrivateKeyInfo under the label «ENCRYPTED PRIVATE KEY» \~ */
			PUBLIC    = 0x02  /*!< \~russian SubjectPublicKeyInfo под меткой «PUBLIC KEY» \~english SubjectPublicKeyInfo under the label «PUBLIC KEY» \~ */
		};

		/**
		 * \~russian
		 * @brief Разобранный ключ
		 *
		 * @details Все числа записаны порядком от старшего байта к младшему: составляющие
		 *          RSA без ведущих нулей, координаты точки и ключи Ed25519 и X25519 длиной
		 *          в размер ключа. Секретные составляющие у открытого ключа пусты; у секретного
		 *          ключа открытые составляющие заполнены всегда: при разборе они выводятся
		 *          из секретных, если запись их не несёт.
		 *
		 * @note Секретные составляющие затираются при сбросе и при уничтожении ключа
		 *
		 * \~english
		 * @brief A parsed key
		 * @details All the numbers are written in the order from the senior byte to the junior one:
		 *          the RSA components without the leading zeros, the coordinates of the point and the
		 *          Ed25519 and X25519 keys with the length of the size of the key. The secret components
		 *          of a public key are empty; the
		 *          public components of a secret key are always filled: at the parsing they are
		 *          derived from the secret ones if the record does not carry them.
		 * @note The secret components are wiped at the reset and at the destruction of the key
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Key {
			// Вид ключа
			kind_t kind;
			// Опознаватель кривой у EC и ГОСТ
			string oid;
			// Опознаватель алгоритма ключа у ГОСТ
			string algorithm;
			// Опознаватель хеша из настроек ключа у ГОСТ, вправе быть пустым
			string digest;
			// Модуль n у RSA
			vector <uint8_t> n;
			// Открытый показатель e у RSA
			vector <uint8_t> e;
			// Секретный показатель у RSA, секретный скаляр у EC и ГОСТ, зерно у Ed25519 и X25519
			vector <uint8_t> d;
			// Первый простой сомножитель p у RSA
			vector <uint8_t> p;
			// Второй простой сомножитель q у RSA
			vector <uint8_t> q;
			// Показатель dP у RSA
			vector <uint8_t> dP;
			// Показатель dQ у RSA
			vector <uint8_t> dQ;
			// Коэффициент qInv у RSA
			vector <uint8_t> qInv;
			// Первая координата открытого ключа у EC и ГОСТ
			vector <uint8_t> x;
			// Вторая координата открытого ключа у EC и ГОСТ
			vector <uint8_t> y;
			// Открытый ключ у Ed25519 и X25519
			vector <uint8_t> key;
			/**
			 * \~russian
			 * @brief Метод проверки наличия секретной части ключа
			 *
			 * @return признак наличия секретной части ключа
			 *
			 * \~english
			 * @brief Method of checking the presence of the secret part of the key
			 * @return the flag of the presence of the secret part of the key
			 *
			 * \~
			 */
			bool secret() const noexcept;
			/**
			 * \~russian
			 * @brief Метод получения размера ключа в байтах
			 *
			 * @return размер модуля у RSA, координаты у EC и ГОСТ, ключа у Ed25519 и X25519
			 *
			 * \~english
			 * @brief Method of the obtaining of the size of the key in the bytes
			 * @return the size of the modulus at RSA, of a coordinate at EC and GOST, of the key at
			 *         Ed25519 and X25519
			 *
			 * \~
			 */
			size_t size() const noexcept;
			/**
			 * \~russian
			 * @brief Метод сброса ключа с затиранием секретных составляющих
			 *
			 * \~english
			 * @brief Method of the reset of the key with the wiping of the secret components
			 *
			 * \~
			 */
			void clear() noexcept;
			/**
			 * \~russian
			 * @brief Метод установки ключа RSA из разобранного ключа
			 *
			 * @param rsa примитив, в который устанавливается ключ
			 *
			 * @return    признак успешности установки ключа
			 *
			 * \~english
			 * @brief Method of the installation of an RSA key from the parsed key
			 * @param rsa the primitive the key is installed into
			 * @return    the flag of the success of the installation of the key
			 *
			 * \~
			 */
			bool load(sign::rsa_t & rsa) const noexcept;
			/**
			 * \~russian
			 * @brief Метод установки ключа ECDSA из разобранного ключа
			 *
			 * @param ecdsa примитив, в который устанавливается ключ
			 * @param curve кривая, которая устанавливается по опознавателю ключа
			 *
			 * @return      признак успешности установки ключа
			 *
			 * @note Кривая обязана жить не меньше примитива: он хранит на неё ссылку
			 *
			 * \~english
			 * @brief Method of the installation of an ECDSA key from the parsed key
			 * @param ecdsa the primitive the key is installed into
			 * @param curve the curve which is set up by the identifier of the key
			 * @return      the flag of the success of the installation of the key
			 * @note The curve must live no less than the primitive: it keeps a reference to it
			 *
			 * \~
			 */
			bool load(sign::ecdsa_t & ecdsa, curve::curve_t & curve) const noexcept;
			/**
			 * \~russian
			 * @brief Метод установки ключа Ed25519 из разобранного ключа
			 *
			 * @param ed25519 примитив, в который устанавливается ключ
			 *
			 * @return        признак успешности установки ключа
			 *
			 * \~english
			 * @brief Method of the installation of an Ed25519 key from the parsed key
			 * @param ed25519 the primitive the key is installed into
			 * @return        the flag of the success of the installation of the key
			 *
			 * \~
			 */
			bool load(sign::ed25519_t & ed25519) const noexcept;
			/**
			 * \~russian
			 * @brief Метод установки ключа ГОСТ Р 34.10-2012 из разобранного ключа
			 *
			 * @param gost  примитив, в который устанавливается ключ
			 * @param curve кривая, которая устанавливается по опознавателю ключа
			 *
			 * @return      признак успешности установки ключа
			 *
			 * @note Кривая обязана жить не меньше примитива: он хранит на неё ссылку
			 *
			 * \~english
			 * @brief Method of the installation of a GOST R 34.10-2012 key from the parsed key
			 * @param gost  the primitive the key is installed into
			 * @param curve the curve which is set up by the identifier of the key
			 * @return      the flag of the success of the installation of the key
			 * @note The curve must live no less than the primitive: it keeps a reference to it
			 *
			 * \~
			 */
			bool load(sign::gost_t & gost, curve::curve_t & curve) const noexcept;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Key() noexcept : kind(kind_t::NONE) {}
			/**
			 * \~russian
			 * @brief Деструктор
			 *
			 * \~english
			 * @brief Destructor
			 *
			 * \~
			 */
			~Key() noexcept;
		} key_t;

		/**
		 * \~russian
		 * @brief Метод разбора записи SubjectPublicKeyInfo
		 *
		 * @param der    разбираемая запись в кодировке DER
		 * @param result ключ, в который помещается итог разбора
		 *
		 * @return       отказ разбора записи
		 *
		 * @details Принимаются ключи RSA с пустыми настройками (RFC 8017), ключи EC с
		 *          именованной кривой и несжатой точкой (RFC 5480), ключи Ed25519 и X25519
		 *          (RFC 8410) и ключи ГОСТ Р 34.10-2012 (RFC 9215)
		 *
		 * \~english
		 * @brief Method of the parsing of a SubjectPublicKeyInfo record
		 * @param der    the record being parsed in the DER encoding
		 * @param result the key the result of the parsing is put into
		 * @return       the failure of the parsing of the record
		 * @details The RSA keys with the empty settings (RFC 8017), the EC keys with a named curve and
		 *          an uncompressed point (RFC 5480), the Ed25519 and X25519 keys (RFC 8410) and the
		 *          GOST R 34.10-2012 keys (RFC 9215) are accepted
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodeSubjectPublicKeyInfo(const view_t & der, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи SubjectPublicKeyInfo
		 *
		 * @param key    записываемый ключ
		 * @param result место, в которое помещается запись в кодировке DER
		 *
		 * @return       отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of a SubjectPublicKeyInfo record
		 * @param key    the key being written
		 * @param result the place the record in the DER encoding is put into
		 * @return       the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodeSubjectPublicKeyInfo(const key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи PrivateKeyInfo по RFC 5958
		 *
		 * @param der    разбираемая запись в кодировке DER
		 * @param result ключ, в который помещается итог разбора
		 *
		 * @return       отказ разбора записи
		 *
		 * @details Внутри обёртки у RSA лежит RSAPrivateKey, у EC — ECPrivateKey по RFC 5915,
		 *          у Ed25519 и X25519 — строка байтов зерна по RFC 8410, у ГОСТ — ключ одним
		 *          из трёх видов записи по RFC 9215. Открытая часть ключа выводится из секретной
		 *          и сличается с записанной, если запись её несёт
		 *
		 * \~english
		 * @brief Method of the parsing of a PrivateKeyInfo record according to RFC 5958
		 * @param der    the record being parsed in the DER encoding
		 * @param result the key the result of the parsing is put into
		 * @return       the failure of the parsing of the record
		 * @details Inside of the envelope an RSAPrivateKey lies at RSA, an ECPrivateKey according to
		 *          RFC 5915 lies at EC, an octet string of the seed according to RFC 8410 lies at Ed25519
		 *          and X25519, a key in one of the three kinds of the writing according to RFC 9215 lies
		 *          at GOST. The public part of the key is derived from the secret one and is compared to
		 *          the written one if the record carries it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodePrivateKeyInfo(const view_t & der, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи PrivateKeyInfo по RFC 5958
		 *
		 * @param key    записываемый ключ
		 * @param result место, в которое помещается запись в кодировке DER
		 *
		 * @return       отказ записи
		 *
		 * @note Запись выходит той же, какую даёт openssl издания 3: издание записи нулевое,
		 *       у EC внутри лежит открытый ключ, а именованная кривая — только в настройках
		 *       алгоритма
		 *
		 * \~english
		 * @brief Method of the writing of a PrivateKeyInfo record according to RFC 5958
		 * @param key    the key being written
		 * @param result the place the record in the DER encoding is put into
		 * @return       the failure of the writing
		 * @note The record comes out the same one openssl of the edition 3 gives: the version of the
		 *       record is zero, the public key lies inside at EC, while the named curve lies only in
		 *       the settings of the algorithm
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodePrivateKeyInfo(const key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи ECPrivateKey по RFC 5915 вне обёртки
		 *
		 * @param der    разбираемая запись в кодировке DER
		 * @param result ключ, в который помещается итог разбора
		 *
		 * @return       отказ разбора записи
		 *
		 * @note Вне обёртки кривую объявить больше нечему: запись без именованной кривой
		 *       отвергается
		 *
		 * \~english
		 * @brief Method of the parsing of an ECPrivateKey record according to RFC 5915 outside of the envelope
		 * @param der    the record being parsed in the DER encoding
		 * @param result the key the result of the parsing is put into
		 * @return       the failure of the parsing of the record
		 * @note Outside of the envelope there is nothing else to declare the curve: a record without a
		 *       named curve is refused
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodeECPrivateKey(const view_t & der, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи ECPrivateKey по RFC 5915 вне обёртки
		 *
		 * @param key    записываемый ключ
		 * @param result место, в которое помещается запись в кодировке DER
		 *
		 * @return       отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of an ECPrivateKey record according to RFC 5915 outside of the envelope
		 * @param key    the key being written
		 * @param result the place the record in the DER encoding is put into
		 * @return       the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodeECPrivateKey(const key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи RSAPrivateKey по RFC 8017
		 *
		 * @param der    разбираемая запись в кодировке DER
		 * @param result ключ, в который помещается итог разбора
		 *
		 * @return       отказ разбора записи
		 *
		 * \~english
		 * @brief Method of the parsing of an RSAPrivateKey record according to RFC 8017
		 * @param der    the record being parsed in the DER encoding
		 * @param result the key the result of the parsing is put into
		 * @return       the failure of the parsing of the record
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodeRSAPrivateKey(const view_t & der, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи RSAPrivateKey по RFC 8017
		 *
		 * @param key    записываемый ключ
		 * @param result место, в которое помещается запись в кодировке DER
		 *
		 * @return       отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of an RSAPrivateKey record according to RFC 8017
		 * @param key    the key being written
		 * @param result the place the record in the DER encoding is put into
		 * @return       the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodeRSAPrivateKey(const key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи RSAPublicKey по RFC 8017
		 *
		 * @param der    разбираемая запись в кодировке DER
		 * @param result ключ, в который помещается итог разбора
		 *
		 * @return       отказ разбора записи
		 *
		 * \~english
		 * @brief Method of the parsing of an RSAPublicKey record according to RFC 8017
		 * @param der    the record being parsed in the DER encoding
		 * @param result the key the result of the parsing is put into
		 * @return       the failure of the parsing of the record
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodeRSAPublicKey(const view_t & der, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи RSAPublicKey по RFC 8017
		 *
		 * @param key    записываемый ключ
		 * @param result место, в которое помещается запись в кодировке DER
		 *
		 * @return       отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of an RSAPublicKey record according to RFC 8017
		 * @param key    the key being written
		 * @param result the place the record in the DER encoding is put into
		 * @return       the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodeRSAPublicKey(const key_t & key, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи EncryptedPrivateKeyInfo по схеме PBES2 из RFC 8018
		 *
		 * @param der      разбираемая запись в кодировке DER
		 * @param password пароль последовательностью октетов
		 * @param result   ключ, в который помещается итог разбора
		 *
		 * @return         отказ разбора записи
		 *
		 * @details Ключ выводится PBKDF2 с числом оборотов и солью из записи; имитовставка
		 *          hmacWithSHA1 подразумевается при отсутствии настройки, принимаются также
		 *          hmacWithSHA224, hmacWithSHA256, hmacWithSHA384 и hmacWithSHA512. Шифр —
		 *          AES-CBC с ключом 128, 192 либо 256 разрядов и дополнением PKCS #7
		 *
		 * @note Негодный пароль опознаётся по дополнению и по устройству расшифрованной
		 *       записи: отдельного признака подлинности схема не несёт
		 *
		 * \~english
		 * @brief Method of the parsing of an EncryptedPrivateKeyInfo record according to the PBES2 scheme of RFC 8018
		 * @param der      the record being parsed in the DER encoding
		 * @param password the password as a sequence of the octets
		 * @param result   the key the result of the parsing is put into
		 * @return         the failure of the parsing of the record
		 * @details The key is derived by PBKDF2 with the number of the iterations and the salt from the
		 *          record; the hmacWithSHA1 is implied at the absence of the setting, the hmacWithSHA224,
		 *          hmacWithSHA256, hmacWithSHA384 and hmacWithSHA512 are accepted as well. The cipher is
		 *          AES-CBC with a key of 128, 192 or 256 bits and the PKCS #7 padding
		 * @note An unfit password is recognized by the padding and by the structure of the decrypted
		 *       record: the scheme carries no separate authenticity tag
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decodeEncryptedPrivateKeyInfo(const view_t & der, const view_t & password, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи EncryptedPrivateKeyInfo по схеме PBES2 из RFC 8018
		 *
		 * @param key        записываемый ключ
		 * @param password   пароль последовательностью октетов
		 * @param result     место, в которое помещается запись в кодировке DER
		 * @param bits       длина ключа AES в разрядах: 128, 192 либо 256
		 * @param iterations число оборотов PBKDF2, не меньше одного
		 *
		 * @return           отказ записи
		 *
		 * @details Соль из шестнадцати случайных байтов, имитовставка hmacWithSHA256, шифр
		 *          AES-CBC со случайной синхропосылкой. Число оборотов по умолчанию то же,
		 *          что у openssl издания 3
		 *
		 * \~english
		 * @brief Method of the writing of an EncryptedPrivateKeyInfo record according to the PBES2 scheme of RFC 8018
		 * @param key        the key being written
		 * @param password   the password as a sequence of the octets
		 * @param result     the place the record in the DER encoding is put into
		 * @param bits       the length of the AES key in the bits: 128, 192 or 256
		 * @param iterations the number of the PBKDF2 iterations, not less than one
		 * @return           the failure of the writing
		 * @details A salt of sixteen random bytes, the hmacWithSHA256, the AES-CBC cipher with a random
		 *          initialization vector. The default number of the iterations is the same one openssl
		 *          of the edition 3 has
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encodeEncryptedPrivateKeyInfo(const key_t & key, const view_t & password, vector <uint8_t> & result, const size_t bits = 256, const uint32_t iterations = 2048) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора ключа из текста в обёртке PEM
		 *
		 * @param text     разбираемый текст
		 * @param password пароль последовательностью октетов, нужен лишь зашифрованному ключу
		 * @param result   ключ, в который помещается итог разбора
		 *
		 * @return         отказ разбора текста
		 *
		 * @details Принимаются метки «PRIVATE KEY», «ENCRYPTED PRIVATE KEY», «PUBLIC KEY»,
		 *          «EC PRIVATE KEY», «RSA PRIVATE KEY» и «RSA PUBLIC KEY»; разбирается
		 *          первая запись известного вида, записи чужих видов пропускаются
		 *
		 * \~english
		 * @brief Method of the parsing of a key from a text in the PEM envelope
		 * @param text     the text being parsed
		 * @param password the password as a sequence of the octets, needed only by an encrypted key
		 * @param result   the key the result of the parsing is put into
		 * @return         the failure of the parsing of the text
		 * @details The labels «PRIVATE KEY», «ENCRYPTED PRIVATE KEY», «PUBLIC KEY», «EC PRIVATE KEY»,
		 *          «RSA PRIVATE KEY» and «RSA PUBLIC KEY» are accepted; the first record of a known kind
		 *          is parsed, the records of the foreign kinds are skipped
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const string & text, const view_t & password, key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи ключа в текст в обёртке PEM
		 *
		 * @param key        записываемый ключ
		 * @param container  вид записи ключа
		 * @param result     текст, в который помещается итог записи
		 * @param password   пароль последовательностью октетов, нужен лишь зашифрованной записи
		 * @param bits       длина ключа AES в разрядах у зашифрованной записи
		 * @param iterations число оборотов PBKDF2 у зашифрованной записи
		 *
		 * @return           отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of a key into a text in the PEM envelope
		 * @param key        the key being written
		 * @param container  the kind of the writing of the key
		 * @param result     the text the result of the writing is put into
		 * @param password   the password as a sequence of the octets, needed only by an encrypted record
		 * @param bits       the length of the AES key in the bits at an encrypted record
		 * @param iterations the number of the PBKDF2 iterations at an encrypted record
		 * @return           the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const key_t & key, const container_t container, string & result, const view_t & password = view_t(), const size_t bits = 256, const uint32_t iterations = 2048) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения названия отказа
		 *
		 * @param error отказ, название которого извлекается
		 *
		 * @return      название отказа
		 *
		 * \~english
		 * @brief Method of the obtaining of the name of a failure
		 * @param error the failure the name of which is extracted
		 * @return      the name of the failure
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * name(const error_t error) noexcept;
	};
};

#endif // __ANTS_KEYS__
