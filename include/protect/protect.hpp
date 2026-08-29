/**
 * @file protect.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл модуля защиты записей протокола TLS 1.3 наборами шифрования
 *        на алгоритмах ГОСТ
 *
 * \~english
 * @brief Header file of the module of the protection of the records of the TLS 1.3 protocol
 *        by the cipher suites on the GOST algorithms
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_PROTECT__
#define __ANYKS_TLS_PROTECT__

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
#include <cipher/mgm.hpp>
#include <cipher/mode.hpp>
#include <cipher/magma.hpp>
#include <cipher/kuznyechik.hpp>
#include <record/record.hpp>

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
	 * @brief Пространство имён защиты записей протокола TLS
	 *
	 * @details Раздел 5.2 RFC 8446: открытая запись обращается в защищённую наложением
	 *          шифрования с проверкой целостности, где связанными данными служит сам
	 *          заголовок записи, а истинный вид её содержимого прячется внутрь шифртекста.
	 *
	 * @note Ключ записи вырабатывается заново для всякого порядкового номера построением
	 *       TLSTREE: тем ограничивается объём данных, зашифрованных на одном ключе
	 *
	 * \~english
	 * @brief Namespace of the protection of the records of the TLS protocol
	 * @details The section 5.2 of RFC 8446: a plain record is turned into a protected one by the
	 *          application of an encryption with an integrity check, where the header of the record
	 *          itself serves as the associated data, while the true type of its content is hidden
	 *          inside the ciphertext.
	 * @note The key of a record is derived anew for every sequence number by the TLSTREE
	 *       construction: this limits the volume of the data encrypted under a single key
	 *
	 * \~
	 */
	namespace protect {
		/**
		 * \~russian
		 * @brief Длина ключа набора шифрования в байтах
		 *
		 * \~english
		 * @brief Length of the key of a cipher suite in bytes
		 *
		 * \~
		 */
		static constexpr size_t PROTECT_KEY = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина вектора замены набора шифрования в байтах
		 *
		 * @details Длина вектора замены равна длине блока базового шифра: у «Кузнечика»
		 *          это шестнадцать байтов, у «Магмы» - восемь
		 *
		 * \~english
		 * @brief Greatest length of the initialization vector of a cipher suite in bytes
		 * @details The length of the initialization vector equals the length of a block of the base
		 *          cipher: at «Kuznyechik» it is sixteen bytes, at «Magma» it is eight
		 *
		 * \~
		 */
		static constexpr size_t PROTECT_VECTOR = 16;

		/**
		 * \~russian
		 * @brief Отказы защиты записей
		 *
		 * \~english
		 * @brief Failures of the protection of the records
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE    = 0x01, /*!< \~russian Набор шифрования ещё не установлен \~english The cipher suite is not set yet \~ */
			LENGTH   = 0x02, /*!< \~russian Длина содержимого записи выходит за дозволенные пределы \~english The length of the content of the record goes beyond the allowed limits \~ */
			SEQUENCE = 0x03, /*!< \~russian Порядковые номера записей на этом ключе исчерпаны \~english The sequence numbers of the records under this key are exhausted \~ */
			TAG      = 0x04, /*!< \~russian Метка целостности записи не сошлась \~english The authentication tag of the record did not match \~ */
			TYPE     = 0x05, /*!< \~russian Вид содержимого записи протоколом не определён \~english The type of the content of the record is not defined by the protocol \~ */
			CIPHER   = 0x06, /*!< \~russian Базовый шифр набора отработать не смог \~english The base cipher of the suite was unable to work \~ */
			MEMORY   = 0x07  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Наборы шифрования протокола TLS 1.3 на алгоритмах ГОСТ
		 *
		 * @details Наборы различаются базовым шифром и тем, как часто сменяется ключ записи:
		 *          у наборов с буквой L смена редкая, у наборов с буквой S - частая
		 *
		 * \~english
		 * @brief Cipher suites of the TLS 1.3 protocol on the GOST algorithms
		 * @details The suites differ by the base cipher and by how often the key of a record is
		 *          changed: at the suites with the letter L the change is rare, at the suites with
		 *          the letter S it is frequent
		 *
		 * \~
		 */
		enum class suite_t : uint16_t {
			NONE             = 0x0000, /*!< \~russian Набор шифрования не установлен \~english The cipher suite is not set \~ */
			KUZNYECHIK_MGM_L = 0xC103, /*!< \~russian «Кузнечик» в режиме MGM с редкой сменой ключа записи \~english «Kuznyechik» in the MGM mode with a rare change of the key of a record \~ */
			MAGMA_MGM_L      = 0xC104, /*!< \~russian «Магма» в режиме MGM с редкой сменой ключа записи \~english «Magma» in the MGM mode with a rare change of the key of a record \~ */
			KUZNYECHIK_MGM_S = 0xC105, /*!< \~russian «Кузнечик» в режиме MGM с частой сменой ключа записи \~english «Kuznyechik» in the MGM mode with a frequent change of the key of a record \~ */
			MAGMA_MGM_S      = 0xC106  /*!< \~russian «Магма» в режиме MGM с частой сменой ключа записи \~english «Magma» in the MGM mode with a frequent change of the key of a record \~ */
		};

		/**
		 * \~russian
		 * @brief Метод получения длины блока базового шифра набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      длина блока базового шифра в байтах, ноль у неизвестного набора
		 *
		 * @note Ей же равны длина вектора замены и длина метки целостности записи
		 *
		 * \~english
		 * @brief Method of getting the length of a block of the base cipher of a cipher suite
		 * @param suite the cipher suite
		 * @return      the length of a block of the base cipher in bytes, a zero at an unknown suite
		 * @note The length of the initialization vector and the length of the authentication tag of a
		 *       record are equal to it as well
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ size_t block(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения наибольшего порядкового номера записи набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      наибольший порядковый номер записи, ноль у неизвестного набора
		 *
		 * @details Достигнув этого номера, связь обязана сменить ключевой материал: дальше
		 *          записи на нём защищать нельзя
		 *
		 * \~english
		 * @brief Method of getting the greatest sequence number of a record of a cipher suite
		 * @param suite the cipher suite
		 * @return      the greatest sequence number of a record, a zero at an unknown suite
		 * @details Having reached this number, a connection is obliged to change the key material:
		 *          further records may not be protected under it
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ uint64_t limit(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки ключа записи построением TLSTREE
		 *
		 * @param suite    набор шифрования, которым заданы постоянные построения
		 * @param key      корневой ключ выработки ключа записи
		 * @param sequence порядковый номер записи
		 * @param result   место, в которое помещается ключ записи
		 *
		 * @return         признак успешности выработки ключа записи
		 *
		 * @details Ключ вырабатывается тремя ярусами выработки производного ключа, и затравкой
		 *          всякого яруса служит порядковый номер записи, обрезанный своей постоянной.
		 *          Оттого соседние записи делят ключ до тех пор, пока обрезанный номер не
		 *          изменится, а изменившись - уводят ключ безвозвратно
		 *
		 * @note Место итога обязано вмещать PROTECT_KEY байтов
		 *
		 * \~english
		 * @brief Method of the derivation of the key of a record by the TLSTREE construction
		 * @param suite    the cipher suite the constants of the construction are set by
		 * @param key      the root key of the derivation of the key of the record
		 * @param sequence the sequence number of the record
		 * @param result   the place the key of the record is put into
		 * @return         the flag of the success of the derivation of the key of the record
		 * @details The key is derived by three levels of the derivation of a key, and the sequence
		 *          number of the record truncated by the constant of the level serves as the seed of
		 *          every level. Hence the neighbouring records share a key until the truncated number
		 *          changes, and having changed, it takes the key away irreversibly
		 * @note The place of the outcome is obliged to hold PROTECT_KEY bytes
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ bool tree(const suite_t suite, const view_t & key, const uint64_t sequence, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Защита записей одного направления связи
		 *
		 * @details Объект хранит ключевой материал одного направления и порядковый номер
		 *          записи, который сам растёт с каждой защищённой либо снятой записью. Для
		 *          встречного направления заводится второй такой же объект.
		 *
		 * @note Ввода-вывода объект не ведёт: наложение защиты составляет целую запись, а
		 *       снятие принимает то, что выдал сборщик слоя записей
		 *
		 * \~english
		 * @brief Protection of the records of a single direction of a connection
		 * @details The object stores the key material of a single direction and the sequence number
		 *          of a record, which grows on its own with every protected or unprotected record. A
		 *          second object of the same kind is created for the opposite direction.
		 * @note The object does not perform an input-output: the application of the protection composes
		 *       a whole record, while the removal accepts what the assembler of the record layer has
		 *       produced
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Protection {
			private:
				// Признак того, что ключевой материал установлен
				bool _ready;
			private:
				// Набор шифрования, которым защищаются записи
				suite_t _suite;
			private:
				// Длина блока базового шифра набора шифрования
				size_t _size;
			private:
				// Порядковый номер очередной записи
				uint64_t _sequence;
			private:
				// Наибольший порядковый номер записи набора шифрования
				uint64_t _limit;
			private:
				// Порядковый номер записи, на котором выработан ключ записи
				uint64_t _derived;
			private:
				// Корневой ключ направления связи
				uint8_t _key[PROTECT_KEY];
			private:
				// Вектор замены направления связи
				uint8_t _vector[PROTECT_VECTOR];
			private:
				// Объект базового шифра «Магма»
				cipher::magma_t _magma;
			private:
				// Объект базового шифра «Кузнечик»
				cipher::kuznyechik_t _kuznyechik;
			private:
				/**
				 * \~russian
				 * @brief Метод подготовки базового шифра к защите записи
				 *
				 * @param sequence порядковый номер защищаемой записи
				 * @param block    описание базового шифра, в которое помещается итог
				 *
				 * @return         отказ подготовки базового шифра
				 *
				 * \~english
				 * @brief Method of the preparation of the base cipher for the protection of a record
				 * @param sequence the sequence number of the record being protected
				 * @param block    the description of the base cipher the outcome is put into
				 * @return         the failure of the preparation of the base cipher
				 *
				 * \~
				 */
				error_t prepare(const uint64_t sequence, cipher::block_t & block) noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки одноразового значения записи
				 *
				 * @param sequence порядковый номер защищаемой записи
				 * @param result   место, в которое помещается одноразовое значение
				 *
				 * \~english
				 * @brief Method of the derivation of the nonce of a record
				 * @param sequence the sequence number of the record being protected
				 * @param result   the place the nonce is put into
				 *
				 * \~
				 */
				void nonce(const uint64_t sequence, uint8_t * result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности защиты записей к работе
				 *
				 * @return признак того, что ключевой материал установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness of the protection of the records for the work
				 * @return the flag of the key material being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения набора шифрования, которым защищаются записи
				 *
				 * @return набор шифрования направления связи
				 *
				 * \~english
				 * @brief Method of getting the cipher suite the records are protected by
				 * @return the cipher suite of the direction of the connection
				 *
				 * \~
				 */
				suite_t suite() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения порядкового номера очередной записи
				 *
				 * @return порядковый номер очередной записи направления связи
				 *
				 * \~english
				 * @brief Method of getting the sequence number of the next record
				 * @return the sequence number of the next record of the direction of the connection
				 *
				 * \~
				 */
				uint64_t sequence() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки ключевого материала направления связи
				 *
				 * @param suite  устанавливаемый набор шифрования
				 * @param key    корневой ключ направления связи
				 * @param vector вектор замены направления связи
				 *
				 * @return       признак успешности установки ключевого материала
				 *
				 * @details Раздел 7.3 RFC 8446: ключ и вектор замены вырабатываются расписанием
				 *          ключей рукопожатия. Порядковый номер записи сбрасывается в ноль всякой
				 *          сменой ключевого материала
				 *
				 * \~english
				 * @brief Method of setting the key material of a direction of a connection
				 * @param suite  the cipher suite being set
				 * @param key    the root key of the direction of the connection
				 * @param vector the initialization vector of the direction of the connection
				 * @return       the flag of the success of the setting of the key material
				 * @details The section 7.3 of RFC 8446: the key and the initialization vector are derived
				 *          by the key schedule of the handshake. The sequence number of a record is reset
				 *          to a zero by every change of the key material
				 *
				 * \~
				 */
				bool start(const suite_t suite, const view_t & key, const view_t & vector) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса ключевого материала направления связи
				 *
				 * \~english
				 * @brief Method of the reset of the key material of a direction of a connection
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод наложения защиты на запись
				 *
				 * @param type    истинный вид содержимого защищаемой записи
				 * @param data    защищаемое содержимое записи
				 * @param result  накопитель, в конец которого дописывается защищённая запись
				 * @param padding длина дополнения, скрывающего истинную длину содержимого
				 *
				 * @return        отказ наложения защиты на запись
				 *
				 * @details Раздел 5.2 RFC 8446: заголовок защищённой записи всегда выдаёт себя за
				 *          прикладные данные издания TLS 1.2, а истинный вид содержимого идёт
				 *          последним значащим байтом внутри шифртекста
				 *
				 * @note Дописывается целая запись вместе с заголовком: заголовок служит связанными
				 *       данными, и составляется он здесь же
				 *
				 * \~english
				 * @brief Method of the application of the protection to a record
				 * @param type    the true type of the content of the record being protected
				 * @param data    the content of the record being protected
				 * @param result  the accumulator the protected record is appended to the end of
				 * @param padding the length of the padding hiding the true length of the content
				 * @return        the failure of the application of the protection to the record
				 * @details The section 5.2 of RFC 8446: the header of a protected record always pretends
				 *          to be the application data of the TLS 1.2 edition, while the true type of the
				 *          content goes as the last significant byte inside the ciphertext
				 * @note A whole record together with the header is appended: the header serves as the
				 *       associated data, and it is composed right here
				 *
				 * \~
				 */
				error_t seal(const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты с записи
				 *
				 * @param header заголовок принятой защищённой записи
				 * @param data   защищённое содержимое принятой записи
				 * @param type   вид содержимого, в который помещается истинный вид содержимого записи
				 * @param result накопитель, в конец которого дописывается открытое содержимое записи
				 *
				 * @return       отказ снятия защиты с записи
				 *
				 * @details Раздел 5.2 RFC 8446: истинным видом содержимого объявляется последний
				 *          значащий байт открытого текста, а нули за ним отбрасываются дополнением.
				 *          Открытый текст из одних нулей истинного вида содержимого не несёт и
				 *          принимается за отказ
				 *
				 * @note Открытое содержимое дописывается лишь после того, как метка целостности
				 *       сошлась
				 *
				 * \~english
				 * @brief Method of the removal of the protection from a record
				 * @param header the header of the received protected record
				 * @param data   the protected content of the received record
				 * @param type   the type of the content the true type of the content of the record is put into
				 * @param result the accumulator the plain content of the record is appended to the end of
				 * @return       the failure of the removal of the protection from the record
				 * @details The section 5.2 of RFC 8446: the last significant byte of the plain text is
				 *          declared to be the true type of the content, while the zeroes behind it are
				 *          discarded as the padding. A plain text of the zeroes alone does not carry a
				 *          true type of the content and is taken for a failure
				 * @note The plain content is appended only after the authentication tag has matched
				 *
				 * \~
				 */
				error_t open(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept;
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
				Protection() noexcept;
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
				~Protection() noexcept;
		} protection_t;
	};
};

#endif // __ANYKS_TLS_PROTECT__
