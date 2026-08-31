/**
 * @file pem.hpp
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
 * @brief Заголовочный файл модуля хранения записей в виде PEM — разбор и запись
 *        обёртки по RFC 7468, извлечение цепочки сертификатов и секретного ключа
 *
 * \~english
 * @brief Header file of the module of the storage of the records in the PEM form — the parsing and
 *        the writing of the envelope according to RFC 7468, the extraction of a chain of the
 *        certificates and of a secret key
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_PEM__
#define __ANTS_PEM__

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
	 * @brief Пространство имён модуля хранения записей в виде PEM
	 *
	 * @details Библиотека работает с записями в кодировке DER, а хранятся и передаются они
	 *          чаще всего обёрнутыми по RFC 7468: рамка с меткой вида записи и её тело,
	 *          переложенное в основание 64. Модуль эту обёртку снимает и накладывает, а
	 *          смысла разобранного тела не касается вовсе.
	 *
	 * @note Ввода и вывода модуль не делает: он принимает и выдаёт готовую запись целиком,
	 *       а чтение файла принадлежит тому, кому принадлежит и файловая система
	 *
	 * \~english
	 * @brief Namespace of the module of the storage of the records in the PEM form
	 * @details The library works with the records in the DER encoding, while they are stored and
	 *          transferred most often wrapped according to RFC 7468: a frame with a label of the kind
	 *          of the record and its body laid out into the base 64. The module removes and puts on
	 *          this envelope and does not touch the meaning of the parsed body at all.
	 * @note The module does no input and output: it accepts and produces a ready record as a whole,
	 *       while the reading of a file belongs to the one the file system belongs to
	 *
	 * \~
	 */
	namespace pem {
		/**
		 * \~russian
		 * @brief Длина строки тела записи в знаках
		 *
		 * @details Раздел 2 RFC 7468 велит выдавать тело записи строками ровно этой длины,
		 *          а последняя строка вправе быть короче
		 *
		 * \~english
		 * @brief Length of a line of the body of a record in the characters
		 * @details The section 2 of RFC 7468 orders to produce the body of a record by the lines of
		 *          exactly this length, while the last line may be shorter
		 *
		 * \~
		 */
		static constexpr size_t PEM_WIDTH = 64;

		/**
		 * \~russian
		 * @brief Метка записи сертификата
		 *
		 * \~english
		 * @brief Label of a record of a certificate
		 *
		 * \~
		 */
		static constexpr const char * PEM_CERTIFICATE = "CERTIFICATE";

		/**
		 * \~russian
		 * @brief Метка записи секретного ключа
		 *
		 * \~english
		 * @brief Label of a record of a secret key
		 *
		 * \~
		 */
		static constexpr const char * PEM_SECRET = "PRIVATE KEY";

		/**
		 * \~russian
		 * @brief Метка записи зашифрованного секретного ключа
		 *
		 * \~english
		 * @brief Label of a record of an encrypted secret key
		 *
		 * \~
		 */
		static constexpr const char * PEM_ENCRYPTED = "ENCRYPTED PRIVATE KEY";

		/**
		 * \~russian
		 * @brief Отказы работы с записями в виде PEM
		 *
		 * \~english
		 * @brief Failures of the work with the records in the PEM form
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY     = 0x01, /*!< \~russian Записей заданного вида в тексте нет \~english There are no records of the given kind in the text \~ */
			BOUNDARY  = 0x02, /*!< \~russian Рамка записи оборвана или закрыта не своей меткой \~english The frame of a record is torn or is closed by a foreign label \~ */
			LABEL     = 0x03, /*!< \~russian Метка записи пуста или содержит недозволенные знаки \~english The label of a record is empty or holds the forbidden characters \~ */
			ALPHABET  = 0x04, /*!< \~russian В теле записи встретился знак вне основания 64 \~english A character outside of the base 64 has met in the body of a record \~ */
			PADDING   = 0x05, /*!< \~russian Добивка тела записи записана неверно \~english The padding of the body of a record is written wrongly \~ */
			LENGTH    = 0x06, /*!< \~russian Длина тела записи не отвечает основанию 64 \~english The length of the body of a record does not correspond to the base 64 \~ */
			CONTENT   = 0x07, /*!< \~russian Тело записи разбору не поддалось \~english The body of a record did not yield to the parsing \~ */
			ENCRYPTED = 0x08, /*!< \~russian Ключ зашифрован, и расшифровать его нечем \~english The key is encrypted, and there is nothing to decrypt it with \~ */
			MEMORY    = 0x09  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Запись, обёрнутая по RFC 7468
		 *
		 * @details Метка объявляет вид записи, а тело лежит в кодировке DER уже снятым с
		 *          основания 64
		 *
		 * \~english
		 * @brief A record wrapped according to RFC 7468
		 * @details The label declares the kind of the record, and the body lies in the DER encoding
		 *          already taken off of the base 64
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Block {
			// Метка вида записи
			string label;
			// Тело записи в кодировке DER
			vector <uint8_t> data;
		} block_t;

		/**
		 * \~russian
		 * @brief Метод разбора всех записей текста
		 *
		 * @param text   разбираемый текст
		 * @param result набор записей, в который помещается итог разбора
		 *
		 * @return       отказ разбора текста
		 *
		 * @details Разбор идёт по всему тексту подряд: всё, что лежит вне рамок записей,
		 *          пропускается, как того велит раздел 5.2 RFC 7468
		 *
		 * \~english
		 * @brief Method of the parsing of all the records of a text
		 * @param text   the text being parsed
		 * @param result the set of the records the result of the parsing is put into
		 * @return       the failure of the parsing of the text
		 * @details The parsing goes over the whole text in a row: everything lying outside of the
		 *          frames of the records is skipped as the section 5.2 of RFC 7468 orders
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const string & text, vector <block_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записей заданного вида
		 *
		 * @param text   разбираемый текст
		 * @param label  метка вида отбираемых записей
		 * @param result набор тел записей, в который помещается итог разбора
		 *
		 * @return       отказ разбора текста
		 *
		 * @note Порядок тел записей в итоге отвечает порядку их появления в тексте
		 *
		 * \~english
		 * @brief Method of the parsing of the records of a given kind
		 * @param text   the text being parsed
		 * @param label  the label of the kind of the records being selected
		 * @param result the set of the bodies of the records the result of the parsing is put into
		 * @return       the failure of the parsing of the text
		 * @note The order of the bodies of the records in the result corresponds to the order of their
		 *       appearance in the text
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const string & text, const string & label, vector <vector <uint8_t>> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи одной записи
		 *
		 * @param block записываемая запись
		 * @param result текст, в который помещается итог записи
		 *
		 * @return       отказ записи
		 *
		 * \~english
		 * @brief Method of the writing of a single record
		 * @param block  the record being written
		 * @param result the text the result of the writing is put into
		 * @return       the failure of the writing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const block_t & block, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи набора записей
		 *
		 * @param blocks записываемый набор записей
		 * @param result текст, в который помещается итог записи
		 *
		 * @return       отказ записи
		 *
		 * @note Записи ложатся в текст одна за другой в поданном порядке
		 *
		 * \~english
		 * @brief Method of the writing of a set of the records
		 * @param blocks the set of the records being written
		 * @param result the text the result of the writing is put into
		 * @return       the failure of the writing
		 * @note The records lie into the text one after another in the given order
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const vector <block_t> & blocks, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения цепочки сертификатов
		 *
		 * @param text   разбираемый текст
		 * @param result цепочка сертификатов, в которую помещается итог извлечения
		 *
		 * @return       отказ извлечения цепочки сертификатов
		 *
		 * @details Раздел 4.4.2 RFC 8446 велит вести цепочку от своего сертификата к
		 *          сертификату издателя, и этот же порядок в текст обычно и записан:
		 *          извлечение его сохраняет, ничего не переставляя
		 *
		 * \~english
		 * @brief Method of the extraction of a chain of the certificates
		 * @param text   the text being parsed
		 * @param result the chain of the certificates the result of the extraction is put into
		 * @return       the failure of the extraction of the chain of the certificates
		 * @details The section 4.4.2 of RFC 8446 orders to lead a chain from one's own certificate to
		 *          the certificate of the issuer, and this same order is usually written into the text:
		 *          the extraction preserves it and rearranges nothing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certificates(const string & text, vector <vector <uint8_t>> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения секретного ключа
		 *
		 * @param text   разбираемый текст
		 * @param result место, в которое помещается извлечённый секретный ключ
		 *
		 * @return       отказ извлечения секретного ключа
		 *
		 * @details Ключ ожидается обёрнутым по разделу 4 RFC 5958. Внутри обёртки правилами
		 *          записи ключа дозволены три вида, и вид опознаётся по метке ASN.1: строка
		 *          байтов даёт число порядком от младшего байта к старшему, целое число —
		 *          порядком от старшего, а набор значений разбирается по RFC 5915.
		 *
		 * @note Итог записывается порядком от старшего байта к младшему — тем же, каким его
		 *       ждёт подлинность стороны связи
		 *
		 * @note Разрядность ключа определяется по длине его значащей части: до 32 байт - ключ
		 *       256 разрядов, свыше - ключ 512 разрядов. Число, значащая часть которого длиннее
		 *       64 байт, отвергается отказом
		 *
		 * @note Зашифрованный ключ отвергается отказом: расшифровать его нечем, пароля
		 *       библиотека не спрашивает
		 *
		 * \~english
		 * @brief Method of the extraction of a secret key
		 * @param text   the text being parsed
		 * @param result the place the extracted secret key is put into
		 * @return       the failure of the extraction of the secret key
		 * @details The key is expected wrapped according to the section 4 of RFC 5958. Inside of the
		 *          envelope three kinds are allowed by the rules of the writing of a key, and the kind is
		 *          recognized by the ASN.1 tag: an octet string gives the number by the order from the
		 *          junior byte to the senior one, an integer gives it by the order from the senior one,
		 *          and a set of the values is parsed according to RFC 5915.
		 * @note The result is written by the order from the senior byte to the junior one — the same one
		 *       the authenticity of a side of a connection awaits it by
		 * @note The width of the key is determined by the length of its significant part: up to 32 bytes
		 *       gives a key of 256 bits, above that gives a key of 512 bits. A number the significant part
		 *       of which is longer than 64 bytes is refused by a failure
		 * @note An encrypted key is refused by a failure: there is nothing to decrypt it with, the library
		 *       does not ask for a password
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t secret(const string & text, vector <uint8_t> & result) noexcept;
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

#endif // __ANTS_PEM__
