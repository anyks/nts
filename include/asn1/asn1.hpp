/**
 * @file asn1.hpp
 * @date 2026-08-26
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
 * @brief Заголовочный файл модуля ASN.1 — разбор данных в кодировке DER (X.690)
 *        без владения содержимым и без применения исключений
 *
 * \~english
 * @brief Header file of the ASN.1 module — parsing of data in the DER encoding (X.690)
 *        without owning the content and without the use of exceptions
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
	 * @brief Пространство имён модуля ASN.1
	 *
	 * @details Разбор ведётся по строгим правилам кодировки DER, а не BER: длина
	 *          неопределённого вида отвергается, длина и номер метки обязаны быть
	 *          записаны кратчайшим образом, целое число обязано быть без лишних
	 *          старших байтов. Послабления здесь недопустимы: разночтение в том,
	 *          какая запись считается верной, — это и есть путь к подделке подписи,
	 *          потому что подпись ставится под одной записью, а смысл извлекается
	 *          из другой.
	 *
	 *          Содержимым модуль не владеет: разбор идёт по просмотру чужого буфера
	 *          и ничего не копирует. Время жизни буфера обязан обеспечить вызывающий.
	 *
	 * \~english
	 * @brief Namespace of the ASN.1 module
	 *
	 * @details The parsing follows the strict rules of the DER encoding rather than BER:
	 *          the indefinite form of the length is rejected, the length and the tag number
	 *          must be written in the shortest way, an integer must carry no redundant
	 *          leading bytes. Relaxations are inadmissible here: a disagreement about which
	 *          encoding is considered valid is the very road to a signature forgery, because
	 *          the signature is put under one encoding while the meaning is taken from another.
	 *          The module does not own the content: the parsing goes over a view of a foreign
	 *          buffer and copies nothing. The lifetime of the buffer is up to the caller.
	 *
	 * \~
	 */
	namespace asn1 {
		/**
		 * \~russian
		 * @brief Класс метки
		 *
		 * \~english
		 * @brief Class of a tag
		 *
		 * \~
		 */
		enum class cls_t : uint8_t {
			// Универсальный класс, метки определены стандартом
			UNIVERSAL   = 0x00, /*!< \~russian Универсальный класс, метки определены стандартом \~english Universal class, the tags are defined by the standard \~ */
			// Класс приложения
			APPLICATION = 0x01, /*!< \~russian Класс приложения \~english Application class \~ */
			// Класс, зависящий от места употребления
			CONTEXT     = 0x02, /*!< \~russian Класс, зависящий от места употребления \~english Class depending on the place of use \~ */
			// Частный класс
			PRIVATE     = 0x03 /*!< \~russian Частный класс \~english Private class \~ */
		};

		/**
		 * \~russian
		 * @brief Номер метки универсального класса
		 *
		 * \~english
		 * @brief Number of a tag of the universal class
		 *
		 * \~
		 */
		enum class tag_t : uint32_t {
			// Логическое значение
			BOOLEAN          = 0x01, /*!< \~russian Логическое значение \~english Boolean value \~ */
			// Целое число произвольной разрядности
			INTEGER          = 0x02, /*!< \~russian Целое число произвольной разрядности \~english Integer of an arbitrary width \~ */
			// Строка битов
			BIT_STRING       = 0x03, /*!< \~russian Строка битов \~english String of bits \~ */
			// Строка байтов
			OCTET_STRING     = 0x04, /*!< \~russian Строка байтов \~english String of bytes \~ */
			// Отсутствие значения (NULL)
			NOTHING          = 0x05, /*!< \~russian Отсутствие значения (NULL) \~english Absence of a value (NULL) \~ */
			// Опознаватель объекта (OID)
			OBJECT           = 0x06, /*!< \~russian Опознаватель объекта (OID) \~english Object identifier (OID) \~ */
			// Строка в кодировке UTF-8
			UTF8_STRING      = 0x0C, /*!< \~russian Строка в кодировке UTF-8 \~english String in the UTF-8 encoding \~ */
			// Упорядоченный набор значений
			SEQUENCE         = 0x10, /*!< \~russian Упорядоченный набор значений \~english Ordered set of values \~ */
			// Неупорядоченный набор значений
			SET              = 0x11, /*!< \~russian Неупорядоченный набор значений \~english Unordered set of values \~ */
			// Строка печатных знаков
			PRINTABLE_STRING = 0x13, /*!< \~russian Строка печатных знаков \~english String of printable characters \~ */
			// Строка в кодировке T.61
			T61_STRING       = 0x14, /*!< \~russian Строка в кодировке T.61 \~english String in the T.61 encoding \~ */
			// Строка в кодировке IA5
			IA5_STRING       = 0x16, /*!< \~russian Строка в кодировке IA5 \~english String in the IA5 encoding \~ */
			// Время в двузначной записи года
			UTC_TIME         = 0x17, /*!< \~russian Время в двузначной записи года \~english Time with a two-digit writing of the year \~ */
			// Время в четырёхзначной записи года
			GENERALIZED_TIME = 0x18, /*!< \~russian Время в четырёхзначной записи года \~english Time with a four-digit writing of the year \~ */
			// Строка видимых знаков
			VISIBLE_STRING   = 0x1A, /*!< \~russian Строка видимых знаков \~english String of visible characters \~ */
			// Строка в кодировке UCS-4
			UNIVERSAL_STRING = 0x1C, /*!< \~russian Строка в кодировке UCS-4 \~english String in the UCS-4 encoding \~ */
			// Строка в кодировке UCS-2
			BMP_STRING       = 0x1E /*!< \~russian Строка в кодировке UCS-2 \~english String in the UCS-2 encoding \~ */
		};

		/**
		 * \~russian
		 * @brief Причина отказа разбора
		 *
		 * @details Отказ возвращается значением, а не исключением: разбор идёт по
		 *          недоверенным данным, где отказ — обычное течение работы, а не
		 *          исключительное обстоятельство.
		 *
		 * \~english
		 * @brief Reason of a parsing failure
		 *
		 * @details A failure is returned by value rather than by an exception: the parsing
		 *          goes over untrusted data, where a failure is the ordinary course of work
		 *          rather than an exceptional circumstance.
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			// Отказа не произошло
			NONE       = 0x00, /*!< \~russian Отказа не произошло \~english No failure has occurred \~ */
			// Данные оборваны, объявленная длина за пределами буфера
			TRUNCATED  = 0x01, /*!< \~russian Данные оборваны, объявленная длина за пределами буфера \~english The data is truncated, the declared length is beyond the buffer \~ */
			// Длина неопределённого вида, кодировкой DER запрещена
			INDEFINITE = 0x02, /*!< \~russian Длина неопределённого вида, кодировкой DER запрещена \~english The length is of an indefinite form, forbidden by the DER encoding \~ */
			// Длина или номер метки записаны не кратчайшим образом
			EXCESSIVE  = 0x03, /*!< \~russian Длина или номер метки записаны не кратчайшим образом \~english The length or the number of the tag is written not in the shortest way \~ */
			// Длина или номер метки не умещаются в разрядную сетку
			HUGE_SIZE  = 0x04, /*!< \~russian Длина или номер метки не умещаются в разрядную сетку \~english The length or the number of the tag does not fit into the bit width \~ */
			// Метка не та, которая ожидалась в этом месте
			TAG        = 0x05, /*!< \~russian Метка не та, которая ожидалась в этом месте \~english The tag is not the one expected in this place \~ */
			// Составной вид метки там, где требуется простой, или наоборот
			FORM       = 0x06, /*!< \~russian Составной вид метки там, где требуется простой, или наоборот \~english A constructed form of the tag where a primitive one is required, or vice versa \~ */
			// Содержимое не отвечает правилам записи своей метки
			VALUE      = 0x07, /*!< \~russian Содержимое не отвечает правилам записи своей метки \~english The content does not meet the rules of writing of its tag \~ */
			// После разобранного значения остались лишние байты
			TRAILING   = 0x08, /*!< \~russian После разобранного значения остались лишние байты \~english Extra bytes remained after the parsed value \~ */
			// Превышена предельная глубина вложенности
			DEPTH      = 0x09, /*!< \~russian Превышена предельная глубина вложенности \~english The limit depth of nesting is exceeded \~ */
			// Не удалось выделить память под собираемую запись
			MEMORY     = 0x0A, /*!< \~russian Не удалось выделить память под собираемую запись \~english It was not possible to allocate memory for the record being composed \~ */
			// Составные элементы записи открыты и закрыты не парно
			BALANCE    = 0x0B /*!< \~russian Составные элементы записи открыты и закрыты не парно \~english The constructed elements of the record are opened and closed not in pairs \~ */
		};

		/**
		 * \~russian
		 * @brief Разобранный элемент ASN.1
		 *
		 * @details Элемент указывает внутрь разбираемого буфера и ничего не копирует.
		 *          Поле content содержит только содержимое элемента, поле element —
		 *          элемент целиком, вместе с меткой и длиной. Второе нужно там, где
		 *          подпись ставится под записью, а не под смыслом.
		 *
		 * \~english
		 * @brief A parsed ASN.1 element
		 *
		 * @details The element points inside the buffer being parsed and copies nothing.
		 *          The content field holds only the content of the element, the element
		 *          field holds the whole element together with its tag and length. The
		 *          latter is needed where a signature is put under the encoding rather
		 *          than under the meaning.
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Element {
			// Признак составного вида метки
			bool constructed;
			// Класс метки
			cls_t cls;
			// Номер метки внутри своего класса
			uint32_t tag;
			// Просмотр содержимого элемента
			view_t content;
			// Просмотр элемента целиком, вместе с меткой и длиной
			view_t element;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Element() noexcept;
		} element_t;

		/**
		 * \~russian
		 * @brief Разборщик данных в кодировке DER
		 *
		 * @details Разборщик хранит просмотр области данных и место, до которого разбор
		 *          дошёл. Он не владеет данными, не выделяет памяти и не возбуждает
		 *          исключений.
		 *
		 * \~english
		 * @brief Parser of data in the DER encoding
		 *
		 * @details The parser keeps a view of the data area and the position the parsing
		 *          has reached. It does not own the data, does not allocate memory and
		 *          does not raise exceptions.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Reader {
			private:
				// Просмотр разбираемой области данных
				view_t _view;
			private:
				// Смещение, до которого дошёл разбор
				size_t _offset;
			private:
				// Причина последнего отказа
				error_t _error;
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
				 * @brief Метод проверки наличия неразобранных данных
				 *
				 * @return признак наличия неразобранных данных
				 *
				 * \~english
				 * @brief Method of checking the presence of unparsed data
				 *
				 * @return the flag of the presence of unparsed data
				 *
				 * \~
				 */
				bool empty() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения размера ещё не разобранных данных
				 *
				 * @return размер ещё не разобранных данных в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of the data not parsed yet
				 *
				 * @return the size of the data not parsed yet in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора очередного элемента
				 *
				 * @param element объект элемента, в который производится разбор
				 * @return        признак успешности разбора
				 *
				 * \~english
				 * @brief Method of parsing the next element
				 *
				 * @param element the object of the element the parsing is performed into
				 * @return        the flag of the success of the parsing
				 *
				 * \~
				 */
				bool next(element_t & element) noexcept;
				/**
				 * \~russian
				 * @brief Метод разбора очередного элемента с проверкой ожидаемой метки
				 *
				 * @param tag     ожидаемая метка универсального класса
				 * @param element объект элемента, в который производится разбор
				 * @return        признак успешности разбора
				 *
				 * @note Проверка метки выполняется здесь, а не у вызывающего: забытая
				 *       проверка метки — это разбор чужой записи как своей, и заметить
				 *       её пропуск по коду вызывающего невозможно
				 *
				 * \~english
				 * @brief Method of parsing the next element with a check of the expected tag
				 *
				 * @param tag     the expected tag of the universal class
				 * @param element the object of the element the parsing is performed into
				 * @return        the flag of the success of the parsing
				 *
				 * @note The check of the tag is performed here, and not at the caller: a forgotten
				 *       check of the tag is a parsing of a foreign encoding as one's own, and to notice
				 *       its omission by the code of the caller is impossible
				 *
				 * \~
				 */
				bool next(const tag_t tag, element_t & element) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения разборщика содержимого составного элемента
				 *
				 * @param element составной элемент, содержимое которого разбирается
				 * @return        разборщик содержимого составного элемента
				 *
				 * \~english
				 * @brief Method of getting a parser of the content of a constructed element
				 *
				 * @param element the constructed element whose content is parsed
				 * @return        the parser of the content of the constructed element
				 *
				 * \~
				 */
				Reader enter(const element_t & element) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор пустого разборщика
				 *
				 * \~english
				 * @brief Constructor of an empty parser
				 *
				 * \~
				 */
				Reader() noexcept;
				/**
				 * \~russian
				 * @brief Конструктор разборщика области данных
				 *
				 * @param view просмотр разбираемой области данных
				 *
				 * \~english
				 * @brief Constructor of a parser of a data area
				 *
				 * @param view the view of the data area being parsed
				 *
				 * \~
				 */
				Reader(const view_t & view) noexcept;
				/**
				 * \~russian
				 * @brief Конструктор разборщика области данных
				 *
				 * @param data указатель на начало разбираемой области данных
				 * @param size размер разбираемой области данных
				 *
				 * \~english
				 * @brief Constructor of a parser of a data area
				 *
				 * @param data the pointer to the beginning of the data area being parsed
				 * @param size the size of the data area being parsed
				 *
				 * \~
				 */
				Reader(const uint8_t * data, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Reader() noexcept;
		} reader_t;

		/**
		 * \~russian
		 * @brief Функция извлечения логического значения
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  переменная, в которую помещается результат
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @note Кодировка DER допускает лишь два байта содержимого: 0x00 и 0xFF.
		 *       Всякое иное значение отвергается, потому что «любое ненулевое —
		 *       истина» это правило BER, а под DER оно даёт две разные записи
		 *       одного значения
		 *
		 * \~english
		 * @brief Function of getting a boolean value
		 *
		 * @param element the element the value is taken from
		 * @param result  the variable the result is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * @note The DER encoding allows only two bytes of the content: 0x00 and 0xFF.
		 *       Any other value is refused, because «any non-zero is true» is the rule
		 *       of BER, and under DER it gives two different encodings of
		 *       one value
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t boolean(const element_t & element, bool & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения целого числа
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  переменная, в которую помещается результат
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @note Числа, не умещающиеся в 64 разряда, отвергаются с причиной
		 *       error_t::HUGE_SIZE. Для длинных чисел — модулей ключей и точек
		 *       кривых — предназначен метод integer, отдающий просмотр содержимого
		 *
		 * \~english
		 * @brief Function of getting an integer number
		 *
		 * @param element the element the value is taken from
		 * @param result  the variable the result is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * @note The numbers not fitting into 64 bits are refused with the reason
		 *       error_t::HUGE_SIZE. For the long numbers - the moduli of the keys and the points
		 *       of the curves - the method integer is intended, giving the view of the content
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t integer(const element_t & element, int64_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения целого числа произвольной разрядности
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  просмотр, в который помещается содержимое числа
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @note Отдаётся содержимое в том виде, в каком оно записано: в порядке от
		 *       старшего байта к младшему, в дополнительном коде, с проверенной
		 *       кратчайшей записью
		 *
		 * \~english
		 * @brief Function of getting an integer number of an arbitrary bit width
		 *
		 * @param element the element the value is taken from
		 * @param result  the view the content of the number is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * @note The content is given in the form it is written in: in the order from
		 *       the senior byte to the junior one, in the two's complement notation, with the shortest
		 *       form checked
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t integer(const element_t & element, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения строки битов
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  просмотр, в который помещается содержимое строки битов
		 * @param unused  число неиспользуемых битов в последнем байте
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of getting a bit string
		 *
		 * @param element the element the value is taken from
		 * @param result  the view the content of the bit string is put into
		 * @param unused  the number of unused bits in the last byte
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t bits(const element_t & element, view_t & result, uint8_t & unused) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения опознавателя объекта
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  строка, в которую помещается запись опознавателя через точку
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of getting an object identifier
		 *
		 * @param element the element the value is taken from
		 * @param result  the string the dotted notation of the identifier is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t oid(const element_t & element, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения времени
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param type    вид записи времени
		 * @param result  переменная, в которую помещается число секунд от начала эпохи
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @note Результат отдаётся в int64_t, а не в time_t: у части систем time_t
		 *       разрядностью в тридцать два разряда, и время после 2038 года там
		 *       переполняется молча. Сертификаты с такими сроками уже выписываются
		 *
		 * @note Кодировка DER оставляет от записи времени единственный вид: часовой
		 *       пояс только Z, доли секунды запрещены, у записи с двузначным годом
		 *       обязательны секунды. Послабления X.690 здесь не принимаются
		 *
		 * \~english
		 * @brief Function of getting a time
		 *
		 * @param element the element the value is taken from
		 * @param type    the kind of the time notation
		 * @param result  the variable the number of seconds since the epoch is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * @note The result is given in int64_t, and not in time_t: at some systems time_t is
		 *       thirty two bits wide, and the time after the year 2038 overflows there
		 *       silently. Certificates with such terms are already being issued
		 *
		 * @note The DER encoding leaves a single form of the time notation: the time zone
		 *       of Z only, the fractions of a second are forbidden, at the notation with a two-digit
		 *       year the seconds are obligatory. The relaxations of X.690 are not accepted here
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t time(const element_t & element, const tag_t type, int64_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения строки
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param type    вид строки, определяющий правила записи содержимого
		 * @param result  строка, в которую помещается результат в кодировке UTF-8
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @note Строки UCS-2 и UCS-4 перекодируются в UTF-8, остальные виды строк
		 *       проверяются на соответствие своему набору знаков и отдаются как есть.
		 *       Проверка эта обязательна: имя, записанное знаками не своего набора,
		 *       у разных разборщиков читается по-разному, а на сличении имён держится
		 *       вся проверка принадлежности сертификата
		 *
		 * \~english
		 * @brief Function of getting a string
		 *
		 * @param element the element the value is taken from
		 * @param type    the kind of the string which determines the rules of the content
		 * @param result  the string the result in the UTF-8 encoding is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * @note The UCS-2 and UCS-4 strings are re-encoded into UTF-8, the other kinds of strings
		 *       are checked against their own character set and are given as they are.
		 *       This check is obligatory: a name written in characters of a foreign set
		 *       is read differently by different parsers, and the whole check of the belonging
		 *       of a certificate rests on the comparison of the names
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t text(const element_t & element, const tag_t type, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Записчик данных в кодировке DER
		 *
		 * @details Записчик собирает запись в собственном буфере. Составные элементы
		 *          открываются и закрываются парой вызовов, длина проставляется при
		 *          закрытии: заранее она неизвестна, а кодировка DER требует длины
		 *          определённого вида.
		 *
		 * @note Записчик выделяет память, и нехватка её — это отказ, который обязан дойти
		 *       до вызывающего причиной error_t::MEMORY, а не завершить процесс. Перехват
		 *       ведётся внутри самих методов, оттого noexcept с них не снимается:
		 *       разборщик памяти не выделяет вовсе и в перехвате не нуждается
		 *
		 * \~english
		 * @brief Writer of data in the DER encoding
		 *
		 * @details The writer builds the encoding in its own buffer. Constructed elements
		 *          are opened and closed by a pair of calls, the length is put in place at
		 *          the closing: it is unknown beforehand, while the DER encoding requires
		 *          the definite form of the length.
		 *
		 * @note The writer allocates memory, and its shortage is a failure which must reach
		 *       the caller with the reason error_t::MEMORY, and not terminate the process. The catching
		 *       is conducted inside the methods themselves, therefore the noexcept is not lifted from them:
		 *       the parser does not allocate memory at all and needs no catching
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Writer {
			private:
				// Буфер собираемой записи
				vector <uint8_t> _buffer;
			private:
				// Места начала содержимого открытых элементов
				vector <size_t> _opened;
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				/**
				 * \~russian
				 * @brief Метод записи метки элемента
				 *
				 * @param cls         класс метки
				 * @param constructed признак составного вида метки
				 * @param tag         номер метки внутри своего класса
				 *
				 * \~english
				 * @brief Method of writing the tag of an element
				 *
				 * @param cls         the class of the tag
				 * @param constructed the flag of the constructed form of the tag
				 * @param tag         the number of the tag inside its class
				 *
				 * \~
				 */
				bool identifier(const cls_t cls, const bool constructed, const uint32_t tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи длины содержимого
				 *
				 * @param offset место, в которое вставляется запись длины
				 * @param length длина содержимого
				 *
				 * \~english
				 * @brief Method of writing the length of the content
				 *
				 * @param offset the place the record of the length is inserted into
				 * @param length the length of the content
				 *
				 * \~
				 */
				bool length(const size_t offset, const size_t length) noexcept;
				/**
				 * \~russian
				 * @brief Метод обеспечения места под запись с затиранием прежнего буфера
				 *
				 * @param extra число байтов, которое предстоит записать
				 *
				 * @note Буфер растёт только здесь: прежняя память затирается до
				 *       освобождения, и секретное содержимое (записи ключей) в
				 *       освобождённой памяти не остаётся
				 *
				 * \~english
				 * @brief Method of providing a place for a record with wiping of the former buffer
				 *
				 * @param extra the number of bytes which is to be written
				 *
				 * @note The buffer grows only here: the former memory is wiped before
				 *       the release, and the secret content (the records of keys) does
				 *       not remain in the released memory
				 *
				 * \~
				 */
				bool grow(const size_t extra) noexcept;
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
				 * @brief Метод извлечения собранной записи
				 *
				 * @return просмотр собранной записи
				 *
				 * @note Запись отдаётся просмотром внутреннего буфера: всякая последующая
				 *       запись в записчик просмотр этот обесценивает
				 *
				 * \~english
				 * @brief Method of getting the built encoding
				 *
				 * @return the view of the built encoding
				 *
				 * @note The encoding is given by the view of the internal buffer: any subsequent
				 *       writing into the writer devalues this view
				 *
				 * \~
				 */
				view_t data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения накопителя записи целиком
				 *
				 * @return просмотр накопителя, каким бы ни было состояние записи
				 *
				 * @note В отличие от data() накопитель отдаётся и при отказе записи, и при
				 *       незакрытом элементе: он нужен тому, кто обязан затереть секретное
				 *       содержимое на пути отказа, а записью служить не вправе
				 *
				 * \~english
				 * @brief Method of getting the whole accumulator of the encoding
				 *
				 * @return the view of the accumulator whatever the state of the encoding is
				 *
				 * @note Unlike data() the accumulator is given both after a failure and with an
				 *       unclosed element: it serves the one who must wipe a secret content on the
				 *       failure path, and it must not serve as the encoding
				 *
				 * \~
				 */
				view_t buffer() const noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки собранной записи
				 *
				 * \~english
				 * @brief Method of clearing the built encoding
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод открытия составного элемента
				 *
				 * @param tag метка универсального класса
				 * @return    признак успешности записи
				 *
				 * \~english
				 * @brief Method of opening a constructed element
				 *
				 * @param tag the tag of the universal class
				 * @return    the flag of the success of the writing
				 *
				 * \~
				 */
				bool open(const tag_t tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод открытия составного элемента
				 *
				 * @param cls класс метки
				 * @param tag номер метки внутри своего класса
				 * @return    признак успешности записи
				 *
				 * \~english
				 * @brief Method of opening a constructed element
				 *
				 * @param cls the class of the tag
				 * @param tag the number of the tag inside its class
				 * @return    the flag of the success of the writing
				 *
				 * \~
				 */
				bool open(const cls_t cls, const uint32_t tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод закрытия последнего открытого составного элемента
				 *
				 * @return признак успешности записи
				 *
				 * \~english
				 * @brief Method of closing the last opened constructed element
				 *
				 * @return the flag of the success of the writing
				 *
				 * \~
				 */
				bool close() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод записи произвольного элемента
				 *
				 * @param cls         класс метки
				 * @param constructed признак составного вида метки
				 * @param tag         номер метки внутри своего класса
				 * @param content     содержимое элемента
				 * @return            признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing an arbitrary element
				 *
				 * @param cls         the class of the tag
				 * @param constructed the flag of the constructed form of the tag
				 * @param tag         the number of the tag inside its class
				 * @param content     the content of the element
				 * @return            the flag of the success of the writing
				 *
				 * \~
				 */
				bool element(const cls_t cls, const bool constructed, const uint32_t tag, const view_t & content) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи логического значения
				 *
				 * @param value записываемое значение
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing a boolean value
				 *
				 * @param value the value being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool boolean(const bool value) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи отсутствия значения
				 *
				 * @return признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing an absence of a value
				 *
				 * @return the flag of the success of the writing
				 *
				 * \~
				 */
				bool nothing() noexcept;
				/**
				 * \~russian
				 * @brief Метод записи целого числа
				 *
				 * @param value записываемое значение
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing an integer number
				 *
				 * @param value the value being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool integer(const int64_t value) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи строки байтов
				 *
				 * @param value записываемое содержимое
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing an octet string
				 *
				 * @param value the content being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool octets(const view_t & value) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи строки битов
				 *
				 * @param value  записываемое содержимое
				 * @param unused число неиспользуемых разрядов последнего байта
				 * @return       признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing a bit string
				 *
				 * @param value  the content being written
				 * @param unused the number of unused bits in the last byte
				 * @return       the flag of the success of the writing
				 *
				 * \~
				 */
				bool bits(const view_t & value, const uint8_t unused = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи опознавателя объекта
				 *
				 * @param value запись опознавателя через точку
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing an object identifier
				 *
				 * @param value the dotted notation of the identifier
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool oid(const string & value) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи времени
				 *
				 * @param type  вид записи времени
				 * @param value число секунд от начала эпохи
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing a time
				 *
				 * @param type  the kind of the time notation
				 * @param value the number of seconds since the epoch
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool time(const tag_t type, const int64_t value) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи строки
				 *
				 * @param type  вид строки, определяющий правила записи содержимого
				 * @param value записываемая строка в кодировке UTF-8
				 * @return      признак успешности записи
				 *
				 * \~english
				 * @brief Method of writing a string
				 *
				 * @param type  the kind of the string which determines the rules of the content
				 * @param value the string being written in the UTF-8 encoding
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 */
				bool text(const tag_t type, const string & value) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор записчика
				 *
				 * \~english
				 * @brief Constructor of a writer
				 *
				 * \~
				 */
				Writer() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Writer() noexcept;
		} writer_t;

	};
};

