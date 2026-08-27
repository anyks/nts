/**
 * @file asn1.hpp
 * @date 2026-08-26
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
 * @brief Заголовочный файл модуля ASN.1 — разбор данных в кодировке DER (X.690)
 *        без владения содержимым и без применения исключений
 *
 * \~english
 * @brief Header file of the ASN.1 module — parsing of data in the DER encoding (X.690)
 *        without owning the content and without the use of exceptions
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_ASN1__
#define __ANYKS_TLS_ASN1__

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
 *
 */
namespace anyks {
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
	 *
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
		 *
		 */
		enum class cls_t : uint8_t {
			UNIVERSAL   = 0x00, // Универсальный класс, метки определены стандартом
			APPLICATION = 0x01, // Класс приложения
			CONTEXT     = 0x02, // Класс, зависящий от места употребления
			PRIVATE     = 0x03  // Частный класс
		};

		/**
		 * \~russian
		 * @brief Номер метки универсального класса
		 *
		 * \~english
		 * @brief Number of a tag of the universal class
		 *
		 * \~
		 *
		 */
		enum class tag_t : uint32_t {
			BOOLEAN          = 0x01, // Логическое значение
			INTEGER          = 0x02, // Целое число произвольной разрядности
			BIT_STRING       = 0x03, // Строка битов
			OCTET_STRING     = 0x04, // Строка байтов
			NOTHING          = 0x05, // Отсутствие значения (NULL)
			OBJECT           = 0x06, // Опознаватель объекта (OID)
			UTF8_STRING      = 0x0C, // Строка в кодировке UTF-8
			SEQUENCE         = 0x10, // Упорядоченный набор значений
			SET              = 0x11, // Неупорядоченный набор значений
			PRINTABLE_STRING = 0x13, // Строка печатных знаков
			T61_STRING       = 0x14, // Строка в кодировке T.61
			IA5_STRING       = 0x16, // Строка в кодировке IA5
			UTC_TIME         = 0x17, // Время в двузначной записи года
			GENERALIZED_TIME = 0x18, // Время в четырёхзначной записи года
			VISIBLE_STRING   = 0x1A, // Строка видимых знаков
			UNIVERSAL_STRING = 0x1C, // Строка в кодировке UCS-4
			BMP_STRING       = 0x1E  // Строка в кодировке UCS-2
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
		 * @details A failure is returned by value rather than by an exception: the parsing
		 *          goes over untrusted data, where a failure is the ordinary course of work
		 *          rather than an exceptional circumstance.
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE       = 0x00, // Отказа не произошло
			TRUNCATED  = 0x01, // Данные оборваны, объявленная длина за пределами буфера
			INDEFINITE = 0x02, // Длина неопределённого вида, кодировкой DER запрещена
			EXCESSIVE  = 0x03, // Длина или номер метки записаны не кратчайшим образом
			HUGE_SIZE  = 0x04, // Длина или номер метки не умещаются в разрядную сетку
			TAG        = 0x05, // Метка не та, которая ожидалась в этом месте
			FORM       = 0x06, // Составной вид метки там, где требуется простой, или наоборот
			VALUE      = 0x07, // Содержимое не отвечает правилам записи своей метки
			TRAILING   = 0x08, // После разобранного значения остались лишние байты
			DEPTH      = 0x09, // Превышена предельная глубина вложенности
			MEMORY     = 0x0A, // Не удалось выделить память под собираемую запись
			BALANCE    = 0x0B  // Составные элементы записи открыты и закрыты не парно
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
		 * @details The element points inside the buffer being parsed and copies nothing.
		 *          The content field holds only the content of the element, the element
		 *          field holds the whole element together with its tag and length. The
		 *          latter is needed where a signature is put under the encoding rather
		 *          than under the meaning.
		 *
		 * \~
		 *
		 */
		typedef struct __ANYKS_TLS_SHARED_EXPORT__ Element {
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
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Element() noexcept : constructed(false), cls(cls_t::UNIVERSAL), tag(0) {}
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
		 * @details The parser keeps a view of the data area and the position the parsing
		 *          has reached. It does not own the data, does not allocate memory and
		 *          does not raise exceptions.
		 *
		 * \~
		 *
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Reader {
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
				 * @return the reason of the last failure
				 *
				 * \~
				 *
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
				 * @return the flag of the presence of unparsed data
				 *
				 * \~
				 *
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
				 * @return the size of the data not parsed yet in bytes
				 *
				 * \~
				 *
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
				 * @param element the object of the element the parsing is performed into
				 * @return        the flag of the success of the parsing
				 *
				 * \~
				 *
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
				 * @param tag     the expected tag of the universal class
				 * @param element the object of the element the parsing is performed into
				 * @return        the flag of the success of the parsing
				 *
				 * \~
				 *
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
				 * @param element the constructed element whose content is parsed
				 * @return        the parser of the content of the constructed element
				 *
				 * \~
				 *
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
				 *
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
				 * @param view the view of the data area being parsed
				 *
				 * \~
				 *
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
				 * @param data the pointer to the beginning of the data area being parsed
				 * @param size the size of the data area being parsed
				 *
				 * \~
				 *
				 */
				Reader(const uint8_t * data, const size_t size) noexcept;
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
				~Reader() noexcept {}
		} reader_t;

		/**
		 * \~russian
		 * @brief Метод извлечения логического значения
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
		 * @brief Method of getting a boolean value
		 * @param element the element the value is taken from
		 * @param result  the variable the result is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t boolean(const element_t & element, bool & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения целого числа
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
		 * @brief Method of getting an integer number
		 * @param element the element the value is taken from
		 * @param result  the variable the result is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t integer(const element_t & element, int64_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения целого числа произвольной разрядности
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
		 * @brief Method of getting an integer number of an arbitrary bit width
		 * @param element the element the value is taken from
		 * @param result  the view the content of the number is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t integer(const element_t & element, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения строки битов
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  просмотр, в который помещается содержимое строки битов
		 * @param unused  число неиспользуемых битов в последнем байте
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting a bit string
		 * @param element the element the value is taken from
		 * @param result  the view the content of the bit string is put into
		 * @param unused  the number of unused bits in the last byte
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t bits(const element_t & element, view_t & result, uint8_t & unused) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения опознавателя объекта
		 *
		 * @param element элемент, из которого извлекается значение
		 * @param result  строка, в которую помещается запись опознавателя через точку
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Method of getting an object identifier
		 * @param element the element the value is taken from
		 * @param result  the string the dotted notation of the identifier is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t oid(const element_t & element, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения времени
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
		 * @brief Method of getting a time
		 * @param element the element the value is taken from
		 * @param type    the kind of the time notation
		 * @param result  the variable the number of seconds since the epoch is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t time(const element_t & element, const tag_t type, int64_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения строки
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
		 * @brief Method of getting a string
		 * @param element the element the value is taken from
		 * @param type    the kind of the string which determines the rules of the content
		 * @param result  the string the result in the UTF-8 encoding is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 *
		 */
		__ANYKS_TLS_SHARED_EXPORT__ error_t text(const element_t & element, const tag_t type, string & result) noexcept;
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
		 * @details The writer builds the encoding in its own buffer. Constructed elements
		 *          are opened and closed by a pair of calls, the length is put in place at
		 *          the closing: it is unknown beforehand, while the DER encoding requires
		 *          the definite form of the length.
		 *
		 * \~
		 *
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Writer {
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
				 * @brief Метод записи метки элемента
				 *
				 * @param cls         класс метки
				 * @param constructed признак составного вида метки
				 * @param tag         номер метки внутри своего класса
				 *
				 */
				void identifier(const cls_t cls, const bool constructed, const uint32_t tag) noexcept;
				/**
				 * @brief Метод записи длины содержимого
				 *
				 * @param offset место, в которое вставляется запись длины
				 * @param length длина содержимого
				 *
				 */
				void length(const size_t offset, const size_t length) noexcept;
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
				 * @brief Метод извлечения собранной записи
				 *
				 * @return просмотр собранной записи
				 *
				 * @note Запись отдаётся просмотром внутреннего буфера: всякая последующая
				 *       запись в записчик просмотр этот обесценивает
				 *
				 * \~english
				 * @brief Method of getting the built encoding
				 * @return the view of the built encoding
				 *
				 * \~
				 *
				 */
				view_t data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки собранной записи
				 *
				 * \~english
				 * @brief Method of clearing the built encoding
				 *
				 * \~
				 *
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
				 * @param tag the tag of the universal class
				 * @return    the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param cls the class of the tag
				 * @param tag the number of the tag inside its class
				 * @return    the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @return the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param cls         the class of the tag
				 * @param constructed the flag of the constructed form of the tag
				 * @param tag         the number of the tag inside its class
				 * @param content     the content of the element
				 * @return            the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param value the value being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @return the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param value the value being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param value the content being written
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param value  the content being written
				 * @param unused the number of unused bits in the last byte
				 * @return       the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param value the dotted notation of the identifier
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param type  the kind of the time notation
				 * @param value the number of seconds since the epoch
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 * @param type  the kind of the string which determines the rules of the content
				 * @param value the string being written in the UTF-8 encoding
				 * @return      the flag of the success of the writing
				 *
				 * \~
				 *
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
				 *
				 */
				Writer() noexcept;
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
				~Writer() noexcept {}
		} writer_t;

	};
};

#endif // __ANYKS_TLS_ASN1__
