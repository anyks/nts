/**
 * @file ech.hpp
 * @date 2026-09-07
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
 * @brief Заголовочный файл модуля зашифрованного приветствия клиента ECH по RFC 9849 —
 *        конфигурации ECHConfig и их перечень, расширение encrypted_client_hello, кодирование
 *        внутреннего приветствия со сжатием ech_outer_extensions и заполнением, добавочные
 *        данные внешнего приветствия, привязка HPKE и подтверждение принятия
 *
 * \~english
 * @brief Header file of the module of the encrypted client hello ECH according to RFC 9849 —
 *        the ECHConfig configurations and their list, the encrypted_client_hello extension, the
 *        encoding of the inner greeting with the ech_outer_extensions compression and the padding,
 *        the associated data of the outer greeting, the HPKE binding and the acceptance confirmation
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_ECH__
#define __ANTS_ECH__

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
#include <hpke/hpke.hpp>
#include <hello/hello.hpp>
#include <digest/hash.hpp>

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
	 * @brief Пространство имён зашифрованного приветствия клиента
	 *
	 * \~english
	 * @brief Namespace of the encrypted client hello
	 *
	 * \~
	 *
	 */
	namespace ech {
		/**
		 * \~russian
		 * @brief Издание конфигурации ECHConfig, признаваемое модулем (раздел 4 RFC 9849)
		 *
		 * \~english
		 * @brief The edition of the ECHConfig configuration recognized by the module (the section 4 of RFC 9849)
		 *
		 * \~
		 */
		static constexpr uint16_t ECH_VERSION = 0xFE0D;
		/**
		 * \~russian
		 * @brief Вид расширения encrypted_client_hello (раздел 5 RFC 9849)
		 *
		 * \~english
		 * @brief The type of the encrypted_client_hello extension (the section 5 of RFC 9849)
		 *
		 * \~
		 */
		static constexpr uint16_t ECH_EXTENSION = 0xFE0D;
		/**
		 * \~russian
		 * @brief Вид расширения ech_outer_extensions внутреннего приветствия (раздел 5.1 RFC 9849)
		 *
		 * \~english
		 * @brief The type of the ech_outer_extensions extension of the inner greeting (the section 5.1 of RFC 9849)
		 *
		 * \~
		 */
		static constexpr uint16_t ECH_OUTER = 0xFD00;
		/**
		 * \~russian
		 * @brief Длина подтверждения принятия ECH в байтах (раздел 7.2 RFC 9849)
		 *
		 * \~english
		 * @brief The length of the ECH acceptance confirmation in bytes (the section 7.2 of RFC 9849)
		 *
		 * \~
		 */
		static constexpr size_t ECH_CONFIRMATION = 8;
		/**
		 * \~russian
		 * @brief Наибольшая длина публичного имени конфигурации
		 *
		 * \~english
		 * @brief The greatest length of the public name of a configuration
		 *
		 * \~
		 */
		static constexpr size_t ECH_NAME = 255;

		/**
		 * \~russian
		 * @brief Отказы модуля
		 *
		 * \~english
		 * @brief Failures of the module
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY    = 0x01, /*!< \~russian Запись оборвана посреди поля \~english The record is cut off in the middle of a field \~ */
			FORMAT    = 0x02, /*!< \~russian Запись сложена не по правилам \~english The record is composed not by the rules \~ */
			VERSION   = 0x03, /*!< \~russian Ни одной конфигурации признаваемого издания \~english Not a single configuration of a recognized edition \~ */
			SUITE     = 0x04, /*!< \~russian Ни одного признаваемого набора HPKE у конфигурации \~english Not a single recognized HPKE suite at the configuration \~ */
			LENGTH    = 0x05, /*!< \~russian Поле в свою длину не входит \~english A field does not fit into its length \~ */
			EMPTY     = 0x06, /*!< \~russian Обязательное поле пусто \~english A mandatory field is empty \~ */
			OUTER     = 0x07, /*!< \~russian Ссылки ech_outer_extensions негодны: расширение отсутствует, повторено, идёт не в том порядке либо ссылается на само ECH \~english The ech_outer_extensions references are invalid: an extension is absent, repeated, out of order or references ECH itself \~ */
			MEMORY    = 0x08  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Набор симметричных алгоритмов HPKE конфигурации (HpkeSymmetricCipherSuite)
		 *
		 * \~english
		 * @brief The HPKE symmetric cipher suite of a configuration (HpkeSymmetricCipherSuite)
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Suite {
			// Функция вывода ключей
			hpke::kdf_t kdf;
			// Шифр с проверкой целостности
			hpke::aead_t aead;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Suite() noexcept : kdf(hpke::kdf_t::NONE), aead(hpke::aead_t::NONE) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param kdf  функция вывода ключей
			 * @param aead шифр с проверкой целостности
			 *
			 * \~english
			 * @brief Constructor
			 * @param kdf  the key derivation function
			 * @param aead the authenticated cipher
			 *
			 * \~
			 */
			Suite(const hpke::kdf_t kdf, const hpke::aead_t aead) noexcept : kdf(kdf), aead(aead) {}
		} suite_t;

		/**
		 * \~russian
		 * @brief Конфигурация ECHConfig издания 0xFE0D (раздел 4 RFC 9849)
		 *
		 * @details Поле `raw` хранит конфигурацию как записана на проводе: она идёт привязкой
		 *          HPKE (`info = "tls ech" || 0 || ECHConfig`) и обязана совпадать байт в байт
		 *          у клиента и сервера; при разборе перечня оно заполняется из перечня, при
		 *          составлении - складывается заново
		 *
		 * \~english
		 * @brief The ECHConfig configuration of the edition 0xFE0D (the section 4 of RFC 9849)
		 * @details The `raw` field holds the configuration as recorded on the wire: it goes as the HPKE
		 *          binding (`info = "tls ech" || 0 || ECHConfig`) and is obliged to coincide byte by byte at
		 *          the client and the server; at the parsing of a list it is filled from the list, at the
		 *          composition it is composed anew
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Config {
			// Опознаватель конфигурации
			uint8_t id;
			// Наибольшая длина имени узла, на которую рассчитано заполнение
			uint8_t length;
			// Способ инкапсуляции ключа
			hpke::kem_t kem;
			// Открытая часть ключа HPKE сервера
			vector <uint8_t> key;
			// Наборы симметричных алгоритмов в порядке предпочтения сервера
			vector <suite_t> suites;
			// Публичное имя, которым идёт внешнее приветствие
			string name;
			// Расширения конфигурации как записаны
			vector <uint8_t> extensions;
			// Конфигурация как записана на проводе
			vector <uint8_t> raw;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Config() noexcept : id(0), length(0), kem(hpke::kem_t::NONE) {}
		} config_t;

		/**
		 * \~russian
		 * @brief Расширение encrypted_client_hello приветствия клиента (раздел 5 RFC 9849)
		 *
		 * \~english
		 * @brief The encrypted_client_hello extension of the client greeting (the section 5 of RFC 9849)
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Hello {
			// Признак внутреннего вида: тело пусто
			bool inner;
			// Опознаватель конфигурации
			uint8_t id;
			// Набор симметричных алгоритмов
			suite_t suite;
			// Инкапсулированный ключ HPKE (пуст у повторного приветствия)
			vector <uint8_t> enc;
			// Шифротекст закодированного внутреннего приветствия
			vector <uint8_t> payload;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Hello() noexcept : inner(false), id(0) {}
		} hello_t;

		/**
		 * \~russian
		 * @brief Метод разбора перечня конфигураций ECHConfigList
		 *
		 * @param data   разбираемый перечень
		 * @param result перечень конфигураций признаваемого издания в порядке провода
		 *
		 * @return       отказ разбора: VERSION, если ни одной конфигурации издания 0xFE0D
		 *
		 * @details Раздел 4 RFC 9849: конфигурации иных изданий пропускаются по их длине;
		 *          конфигурация без единого признаваемого набора HPKE пропускается тоже
		 *
		 * \~english
		 * @brief Method of parsing the ECHConfigList list of configurations
		 * @param data   the list being parsed
		 * @param result the configurations of the recognized edition in the order of the wire
		 * @return       the failure of the parsing: VERSION if not a single configuration of the edition 0xFE0D
		 * @details The section 4 of RFC 9849: the configurations of other editions are skipped by their
		 *          length; a configuration without a single recognized HPKE suite is skipped too
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, vector <config_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора одной конфигурации ECHConfig
		 *
		 * @param data   разбираемая конфигурация вместе с изданием и длиной
		 * @param result конфигурация
		 *
		 * @return       отказ разбора
		 *
		 * \~english
		 * @brief Method of parsing a single ECHConfig configuration
		 * @param data   the configuration being parsed together with the edition and the length
		 * @param result the configuration
		 * @return       the failure of the parsing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, config_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления одной конфигурации ECHConfig
		 *
		 * @param config составляемая конфигурация (поле `raw` не читается)
		 * @param result накопитель, в конец которого дописывается конфигурация
		 *
		 * @return       отказ составления
		 *
		 * \~english
		 * @brief Method of composing a single ECHConfig configuration
		 * @param config the configuration being composed (the `raw` field is not read)
		 * @param result the accumulator the configuration is appended to
		 * @return       the failure of the composition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const config_t & config, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня конфигураций ECHConfigList
		 *
		 * @param configs составляемые конфигурации
		 * @param result  накопитель, в конец которого дописывается перечень
		 *
		 * @return        отказ составления
		 *
		 * \~english
		 * @brief Method of composing the ECHConfigList list of configurations
		 * @param configs the configurations being composed
		 * @param result  the accumulator the list is appended to
		 * @return        the failure of the composition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const vector <config_t> & configs, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора тела расширения encrypted_client_hello
		 *
		 * @param data   тело расширения
		 * @param result расширение
		 *
		 * @return       отказ разбора
		 *
		 * \~english
		 * @brief Method of parsing the body of the encrypted_client_hello extension
		 * @param data   the body of the extension
		 * @param result the extension
		 * @return       the failure of the parsing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, hello_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления тела расширения encrypted_client_hello
		 *
		 * @param hello  составляемое расширение
		 * @param result накопитель, в конец которого дописывается тело
		 *
		 * @return       отказ составления
		 *
		 * \~english
		 * @brief Method of composing the body of the encrypted_client_hello extension
		 * @param hello  the extension being composed
		 * @param result the accumulator the body is appended to
		 * @return       the failure of the composition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const hello_t & hello, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления привязки HPKE конфигурации
		 *
		 * @param config конфигурация как записана на проводе
		 * @param result накопитель, в который помещается привязка `"tls ech" || 0 || ECHConfig`
		 *
		 * @return       отказ составления
		 *
		 * \~english
		 * @brief Method of composing the HPKE binding of a configuration
		 * @param config the configuration as recorded on the wire
		 * @param result the accumulator the binding `"tls ech" || 0 || ECHConfig` is put into
		 * @return       the failure of the composition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t binding(const view_t & config, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод подсчёта заполнения закодированного внутреннего приветствия
		 *
		 * @param named   длина имени узла внутреннего приветствия, ноль без имени
		 * @param maximum наибольшая длина имени по конфигурации
		 * @param encoded длина закодированного приветствия без заполнения
		 *
		 * @return        число нулевых байтов заполнения
		 *
		 * @details Раздел 6.1.3 RFC 9849: с именем длины D добавляется max(0, M - D), без имени -
		 *          M + 9; затем длина доводится до кратной 32
		 *
		 * \~english
		 * @brief Method of computing the padding of the encoded inner greeting
		 * @param named   the length of the host name of the inner greeting, zero without a name
		 * @param maximum the greatest length of a name by the configuration
		 * @param encoded the length of the encoded greeting without the padding
		 * @return        the number of the zero bytes of the padding
		 * @details The section 6.1.3 of RFC 9849: with a name of the length D max(0, M - D) is added, without
		 *          a name - M + 9; then the length is rounded up to a multiple of 32
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t padding(const size_t named, const size_t maximum, const size_t encoded) noexcept;
		/**
		 * \~russian
		 * @brief Метод кодирования внутреннего приветствия EncodedClientHelloInner
		 *
		 * @param inner      внутреннее приветствие; его опознаватель связи опускается
		 * @param outsourced виды расширений, вынесенных во внешнее приветствие подряд (пусто - без сжатия)
		 * @param padding    число нулевых байтов заполнения
		 * @param result     накопитель, в который помещается закодированное приветствие
		 *
		 * @return           отказ кодирования: OUTER, если вынесенные расширения не идут подряд
		 *
		 * @details Раздел 5.1 RFC 9849: вынесенные расширения обязаны идти во внутреннем приветствии
		 *          подряд и заменяются расширением ech_outer_extensions на их месте
		 *
		 * \~english
		 * @brief Method of encoding the inner greeting EncodedClientHelloInner
		 * @param inner      the inner greeting; its session identifier is omitted
		 * @param outsourced the types of the extensions carried out to the outer greeting contiguously (empty - without compression)
		 * @param padding    the number of the zero bytes of the padding
		 * @param result     the accumulator the encoded greeting is put into
		 * @return           the failure of the encoding: OUTER if the carried-out extensions are not contiguous
		 * @details The section 5.1 of RFC 9849: the carried-out extensions are obliged to go in the inner
		 *          greeting contiguously and are replaced by the ech_outer_extensions extension at their place
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const hello::client_t & inner, const vector <uint16_t> & outsourced, const size_t padding, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод кодирования внутреннего приветствия с выбором записи
		 *
		 * @param inner      внутреннее приветствие
		 * @param outsourced виды расширений, выносимых во внешнее приветствие ссылкой
		 * @param padding    число нулевых байтов заполнения
		 * @param datagram   признак записи поверх дейтаграмм: тело несёт поле метки возврата состояния (RFC 9147)
		 * @param result     накопитель закодированного приветствия
		 *
		 * @return           отказ кодирования
		 *
		 * \~english
		 * @brief Method of the encoding of the inner greeting with the choice of the record
		 *
		 * @param inner      inner greeting
		 * @param outsourced kinds of the extensions carried to the outer greeting by a reference
		 * @param padding    number of the zero bytes of the padding
		 * @param datagram   sign of the record over datagrams: the body carries the cookie field (RFC 9147)
		 * @param result     accumulator of the encoded greeting
		 *
		 * @return           failure of the encoding
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const hello::client_t & inner, const vector <uint16_t> & outsourced, const size_t padding, const bool datagram, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод восстановления внутреннего приветствия из закодированного
		 *
		 * @param encoded закодированное внутреннее приветствие (раскрытый шифротекст)
		 * @param outer   внешнее приветствие, из которого берутся опознаватель связи и вынесенные расширения
		 * @param result  накопитель, в который помещается тело внутреннего приветствия
		 *
		 * @return        отказ восстановления: OUTER по правилам раздела 7.1 RFC 9849
		 *
		 * @details Раздел 7.1 RFC 9849: опознаватель связи копируется из внешнего приветствия;
		 *          ech_outer_extensions заменяется расширениями внешнего приветствия в их
		 *          порядке; ссылка на отсутствующее, повторённое, идущее не в том порядке
		 *          либо на само encrypted_client_hello - отказ; хвост заполнения обязан
		 *          быть нулевым
		 *
		 * \~english
		 * @brief Method of restoring the inner greeting from the encoded one
		 * @param encoded the encoded inner greeting (the opened ciphertext)
		 * @param outer   the outer greeting the session identifier and the carried-out extensions are taken from
		 * @param result  the accumulator the body of the inner greeting is put into
		 * @return        the failure of the restoration: OUTER by the rules of the section 7.1 of RFC 9849
		 * @details The section 7.1 of RFC 9849: the session identifier is copied from the outer greeting;
		 *          ech_outer_extensions is replaced by the extensions of the outer greeting in their order; a
		 *          reference to an absent, repeated, out-of-order extension or to encrypted_client_hello itself
		 *          is a failure; the tail of the padding is obliged to be zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const view_t & encoded, const hello::client_t & outer, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод восстановления внутреннего приветствия с выбором записи
		 *
		 * @param encoded  закодированное внутреннее приветствие
		 * @param outer    внешнее приветствие, из которого берутся вынесенные расширения
		 * @param datagram признак записи поверх дейтаграмм
		 * @param result   накопитель восстановленного приветствия
		 *
		 * @return         отказ восстановления
		 *
		 * \~english
		 * @brief Method of the restoring of the inner greeting with the choice of the record
		 *
		 * @param encoded  encoded inner greeting
		 * @param outer    outer greeting the carried extensions are taken from
		 * @param datagram sign of the record over datagrams
		 * @param result   accumulator of the restored greeting
		 *
		 * @return         failure of the restoring
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t decode(const view_t & encoded, const hello::client_t & outer, const bool datagram, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления добавочных данных внешнего приветствия ClientHelloOuterAAD
		 *
		 * @param body   тело внешнего приветствия с расширением encrypted_client_hello
		 * @param result накопитель, в который помещается тело с обнулённым шифротекстом
		 *
		 * @return       отказ составления
		 *
		 * @details Раздел 5.2 RFC 9849: добавочные данные есть внешнее приветствие, в котором
		 *          поле payload расширения заменено нулями той же длины
		 *
		 * \~english
		 * @brief Method of composing the associated data of the outer greeting ClientHelloOuterAAD
		 * @param body   the body of the outer greeting with the encrypted_client_hello extension
		 * @param result the accumulator the body with the zeroed ciphertext is put into
		 * @return       the failure of the composition
		 * @details The section 5.2 of RFC 9849: the associated data is the outer greeting where the payload
		 *          field of the extension is replaced by zeros of the same length
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t redact(const view_t & body, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления связанных данных из внешнего приветствия с выбором записи
		 *
		 * @param body     тело внешнего приветствия
		 * @param datagram признак записи поверх дейтаграмм
		 * @param result   накопитель связанных данных: тело с обнулённым шифротекстом
		 *
		 * @return         отказ составления
		 *
		 * \~english
		 * @brief Method of the composition of the associated data from the outer greeting with the choice of the record
		 *
		 * @param body     body of the outer greeting
		 * @param datagram sign of the record over datagrams
		 * @param result   accumulator of the associated data: the body with the zeroed ciphertext
		 *
		 * @return         failure of the composition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t redact(const view_t & body, const bool datagram, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления подтверждения принятия ECH
		 *
		 * @param algorithm  хеш набора шифрования связи
		 * @param random     случайное значение внутреннего приветствия
		 * @param transcript хеш переписки внутреннего приветствия с сообщением сервера, подтверждение в котором обнулено
		 * @param retry      признак просьбы о повторе (метка «hrr ech accept confirmation»)
		 * @param result     место, в которое помещаются восемь байтов подтверждения
		 *
		 * @return           результат вычисления
		 *
		 * @details Разделы 7.2 и 7.2.1 RFC 9849: HKDF-Expand-Label(HKDF-Extract(0, random), метка,
		 *          transcript, 8)
		 *
		 * \~english
		 * @brief Method of computing the ECH acceptance confirmation
		 * @param algorithm  the hash of the cipher suite of the connection
		 * @param random     the random value of the inner greeting
		 * @param transcript the hash of the transcript of the inner greeting with the message of the server the confirmation in which is zeroed
		 * @param retry      the flag of the retry request (the «hrr ech accept confirmation» label)
		 * @param result     the place the eight bytes of the confirmation are put into
		 * @return           the result of the computation
		 * @details The sections 7.2 and 7.2.1 of RFC 9849: HKDF-Expand-Label(HKDF-Extract(0, random), label,
		 *          transcript, 8)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool confirmation(const digest::hash_t algorithm, const view_t & random, const view_t & transcript, const bool retry, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки, признаётся ли набор HPKE конфигурации
		 *
		 * @param kem   способ инкапсуляции ключа
		 * @param suite набор симметричных алгоритмов
		 *
		 * @return      признак того, что набор исполним модулем hpke
		 *
		 * \~english
		 * @brief Method of checking whether the HPKE suite of a configuration is recognized
		 * @param kem   the key encapsulation method
		 * @param suite the symmetric cipher suite
		 * @return      the flag of the suite being executable by the hpke module
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool supported(const hpke::kem_t kem, const suite_t & suite) noexcept;
	};
};

#endif // __ANTS_ECH__
