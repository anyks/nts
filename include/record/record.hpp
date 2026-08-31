/**
 * @file record.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл модуля слоя записей протокола TLS — нарезка исходящих данных
 *        на записи и сборка входящих записей из кусков произвольной длины
 *
 * \~english
 * @brief Header file of the module of the record layer of the TLS protocol — the splitting of
 *        the outgoing data into records and the assembly of the incoming records from chunks
 *        of an arbitrary length
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_RECORD__
#define __ANTS_RECORD__

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
	 * @brief Пространство имён слоя записей протокола TLS
	 *
	 * @details Слой записей ни с кем не обменивается данными: сборщик принимает куски
	 *          байтов такими, какими их выдал вызов чтения, а нарезчик складывает готовые
	 *          записи в свой накопитель, откуда их забирает потребитель. Ни сокета, ни
	 *          обратного вызова, ни ожидания здесь нет.
	 *
	 * @note Разбор входящих записей ведёт себя одинаково при любой нарезке потока на
	 *       куски: место события не зависит от того, пришла запись целиком, по одному
	 *       байту или вперемешку с соседними
	 *
	 * \~english
	 * @brief Namespace of the record layer of the TLS protocol
	 * @details The record layer does not exchange data with anybody: the assembler accepts the
	 *          chunks of bytes exactly as a call of a reading produced them, while the splitter
	 *          puts the ready records into its accumulator, from which the consumer takes them.
	 *          There is neither a socket, nor a callback, nor a waiting here.
	 * @note The parsing of the incoming records behaves identically at any splitting of the
	 *       stream into chunks: the place of an event does not depend on whether a record has
	 *       arrived as a whole, by a single byte or intermixed with the neighbouring ones
	 *
	 * \~
	 */
	namespace record {
		/**
		 * \~russian
		 * @brief Размер заголовка записи в байтах
		 *
		 * @details Раздел 6.2.1 RFC 5246: вид содержимого, версия протокола и длина
		 *
		 * \~english
		 * @brief Size of the header of a record in bytes
		 * @details The section 6.2.1 of RFC 5246: the type of the content, the version of the
		 *          protocol and the length
		 *
		 * \~
		 */
		static constexpr size_t RECORD_HEADER = 5;

		/**
		 * \~russian
		 * @brief Наибольшая длина открытого содержимого записи в байтах
		 *
		 * @details Раздел 6.2.1 RFC 5246 и раздел 5.1 RFC 8446: две в четырнадцатой степени
		 *
		 * \~english
		 * @brief Greatest length of the plain content of a record in bytes
		 * @details The section 6.2.1 of RFC 5246 and the section 5.1 of RFC 8446: two to the
		 *          power of fourteen
		 *
		 * \~
		 */
		static constexpr size_t RECORD_PLAINTEXT = 16384;

		/**
		 * \~russian
		 * @brief Наибольшее приращение длины, вносимое защитой записи, в байтах
		 *
		 * @details Раздел 5.2 RFC 8446: байт истинного вида содержимого, дополнение и
		 *          имитовставка вместе прибавляют к длине не более двухсот пятидесяти шести байтов
		 *
		 * \~english
		 * @brief Greatest increment of the length introduced by the protection of a record, in bytes
		 * @details The section 5.2 of RFC 8446: the byte of the true type of the content, the padding
		 *          and the authentication code together add no more than two hundred fifty six bytes
		 *          to the length
		 *
		 * \~
		 */
		static constexpr size_t RECORD_EXPANSION = 256;

		/**
		 * \~russian
		 * @brief Наибольшее приращение длины, вносимое сжатием записи, в байтах
		 *
		 * @details Раздел 6.2.2 RFC 5246: сжатие вправе удлинить содержимое не более чем
		 *          на тысячу двадцать четыре байта
		 *
		 * @note Сжатие записей в библиотеке не поддерживается, но входящую запись такой длины
		 *       собеседник по правилам TLS 1.2 вправе прислать
		 *
		 * \~english
		 * @brief Greatest increment of the length introduced by the compression of a record, in bytes
		 * @details The section 6.2.2 of RFC 5246: a compression may lengthen the content by no more
		 *          than one thousand twenty four bytes
		 * @note The compression of the records is not supported in the library, but a peer is entitled
		 *       to send an incoming record of such a length by the rules of TLS 1.2
		 *
		 * \~
		 */
		static constexpr size_t RECORD_COMPRESSION = 1024;

		/**
		 * \~russian
		 * @brief Наибольшая длина защищённого содержимого записи в байтах
		 *
		 * @details Раздел 5.2 RFC 8446: две в четырнадцатой степени и двести пятьдесят шесть байтов
		 *
		 * \~english
		 * @brief Greatest length of the protected content of a record in bytes
		 * @details The section 5.2 of RFC 8446: two to the power of fourteen and two hundred fifty
		 *          six bytes
		 *
		 * \~
		 */
		static constexpr size_t RECORD_CIPHERTEXT = (RECORD_PLAINTEXT + RECORD_EXPANSION);

		/**
		 * \~russian
		 * @brief Наибольшая длина содержимого записи предыдущих изданий протокола в байтах
		 *
		 * @details Раздел 6.2.2 RFC 5246: две в четырнадцатой степени и тысяча двадцать четыре байта
		 *
		 * \~english
		 * @brief Greatest length of the content of a record of the previous editions of the protocol
		 *        in bytes
		 * @details The section 6.2.2 of RFC 5246: two to the power of fourteen and one thousand
		 *          twenty four bytes
		 *
		 * \~
		 */
		static constexpr size_t RECORD_LEGACY = (RECORD_PLAINTEXT + RECORD_COMPRESSION);

		/**
		 * \~russian
		 * @brief Наибольшее приращение длины, вносимое защитой записи предыдущих изданий, в байтах
		 *
		 * @details Раздел 6.2.3 RFC 5246: там имитовставка идёт отдельно от дополнения, а
		 *          вектор замены передаётся в самой записи, оттого запас и вчетверо шире нынешнего
		 *
		 * \~english
		 * @brief Greatest increment of the length introduced by the protection of a record of the
		 *        previous editions, in bytes
		 * @details The section 6.2.3 of RFC 5246: an authentication code goes there separately from the
		 *          padding, while the initialization vector is transmitted in the record itself, hence the
		 *          reserve is four times wider than the present one
		 *
		 * \~
		 */
		static constexpr size_t RECORD_ENCRYPTION = 2048;

		/**
		 * \~russian
		 * @brief Наибольшая длина содержимого записи, дозволенная протоколом, в байтах
		 *
		 * @details Раздел 6.2.3 RFC 5246: две в четырнадцатой степени и две тысячи сорок восемь
		 *          байтов - самый широкий предел из всех изданий протокола
		 *
		 * @note Разбор одного заголовка сличается именно с этим пределом: предел, принятый связью,
		 *       строже, но знает его сборщик, а не разборщик
		 *
		 * \~english
		 * @brief Greatest length of the content of a record allowed by the protocol, in bytes
		 * @details The section 6.2.3 of RFC 5246: two to the power of fourteen and two thousand forty
		 *          eight bytes — the widest limit of all the editions of the protocol
		 * @note The parsing of a single header is compared exactly against this limit: the limit accepted
		 *       by a connection is stricter, but it is known by the assembler and not by the parser
		 *
		 * \~
		 */
		static constexpr size_t RECORD_PROTECTED = (RECORD_PLAINTEXT + RECORD_ENCRYPTION);

		/**
		 * \~russian
		 * @brief Отказы слоя записей
		 *
		 * \~english
		 * @brief Failures of the record layer
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE    = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY  = 0x01, /*!< \~russian Данных для целой записи ещё не набралось \~english The data for a whole record has not accumulated yet \~ */
			TYPE    = 0x02, /*!< \~russian Вид содержимого записи протоколом не определён \~english The type of the content of the record is not defined by the protocol \~ */
			VERSION = 0x03, /*!< \~russian Версия протокола в заголовке записи неизвестна \~english The version of the protocol in the header of the record is unknown \~ */
			LENGTH  = 0x04, /*!< \~russian Длина содержимого записи превышает дозволенную \~english The length of the content of the record exceeds the allowed one \~ */
			EMPTY   = 0x05, /*!< \~russian Запись этого вида содержимого пустой быть не вправе \~english A record of this type of the content is not entitled to be empty \~ */
			MEMORY  = 0x06  /*!< \~russian Памяти под накопитель не хватило \~english There was not enough memory for the accumulator \~ */
		};

		/**
		 * \~russian
		 * @brief Виды содержимого записи
		 *
		 * @details Раздел 5 RFC 8446: перечисление ContentType
		 *
		 * \~english
		 * @brief Types of the content of a record
		 * @details The section 5 of RFC 8446: the ContentType enumeration
		 *
		 * \~
		 */
		enum class type_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Вид содержимого не установлен \~english The type of the content is not set \~ */
			CHANGE      = 0x14, /*!< \~russian Извещение о смене набора шифрования \~english The notification of the change of the cipher suite \~ */
			ALERT       = 0x15, /*!< \~russian Извещение о событии или об отказе \~english The notification of an event or of a failure \~ */
			HANDSHAKE   = 0x16, /*!< \~russian Сообщение рукопожатия \~english A message of the handshake \~ */
			APPLICATION = 0x17  /*!< \~russian Данные прикладного протокола \~english The data of the application protocol \~ */
		};

		/**
		 * \~russian
		 * @brief Версии протокола
		 *
		 * @details Приложение A.1 RFC 5246 и раздел 5.1 RFC 8446: версия записывается двумя
		 *          байтами, старший из которых идёт первым
		 *
		 * \~english
		 * @brief Versions of the protocol
		 * @details The appendix A.1 of RFC 5246 and the section 5.1 of RFC 8446: a version is written
		 *          by two bytes, the most significant of which goes first
		 *
		 * \~
		 */
		enum class version_t : uint16_t {
			NONE  = 0x0000, /*!< \~russian Версия протокола не установлена \~english The version of the protocol is not set \~ */
			SSL30 = 0x0300, /*!< \~russian Издание SSL 3.0 \~english The SSL 3.0 edition \~ */
			TLS10 = 0x0301, /*!< \~russian Издание TLS 1.0 \~english The TLS 1.0 edition \~ */
			TLS11 = 0x0302, /*!< \~russian Издание TLS 1.1 \~english The TLS 1.1 edition \~ */
			TLS12 = 0x0303, /*!< \~russian Издание TLS 1.2 \~english The TLS 1.2 edition \~ */
			TLS13 = 0x0304  /*!< \~russian Издание TLS 1.3 \~english The TLS 1.3 edition \~ */
		};

		/**
		 * \~russian
		 * @brief Заголовок записи протокола TLS
		 *
		 * \~english
		 * @brief Header of a record of the TLS protocol
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Header {
			// Вид содержимого записи
			type_t type;
			// Версия протокола, указанная в записи
			version_t version;
			// Длина содержимого записи в байтах
			size_t size;
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
			Header() noexcept : type(type_t::NONE), version(version_t::NONE), size(0) {}
		} header_t;

		/**
		 * \~russian
		 * @brief Метод разбора заголовка записи
		 *
		 * @param data   разбираемая область байтов
		 * @param result заголовок записи, в который помещается итог разбора
		 *
		 * @return       отказ разбора заголовка записи
		 *
		 * @details Длина содержимого проверяется только на предел протокола: предел, принятый
		 *          связью, знает сборщик, а не разборщик одного заголовка
		 *
		 * \~english
		 * @brief Method of the parsing of the header of a record
		 * @param data   the byte area being parsed
		 * @param result the header of the record the outcome of the parsing is put into
		 * @return       the failure of the parsing of the header of the record
		 * @details The length of the content is checked only against the limit of the protocol: the
		 *          limit accepted by the connection is known by the assembler and not by the parser
		 *          of a single header
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, header_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи заголовка записи
		 *
		 * @param header записываемый заголовок записи
		 * @param result место, в которое помещается заголовок записи
		 *
		 * @return       отказ записи заголовка записи
		 *
		 * @note Место итога обязано вмещать RECORD_HEADER байтов
		 *
		 * \~english
		 * @brief Method of the writing of the header of a record
		 * @param header the header of the record being written
		 * @param result the place the header of the record is put into
		 * @return       the failure of the writing of the header of the record
		 * @note The place of the outcome is obliged to hold RECORD_HEADER bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const header_t & header, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки известности вида содержимого записи
		 *
		 * @param type проверяемый вид содержимого записи
		 *
		 * @return     признак того, что вид содержимого определён протоколом
		 *
		 * \~english
		 * @brief Method of the checking of the knownness of the type of the content of a record
		 * @param type the type of the content of the record being checked
		 * @return     the flag of the type of the content being defined by the protocol
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool known(const type_t type) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки допустимости пустого содержимого записи
		 *
		 * @param type проверяемый вид содержимого записи
		 *
		 * @return     признак того, что запись этого вида вправе быть пустой
		 *
		 * @details Раздел 6.2.1 RFC 5246 и раздел 5.1 RFC 8446: пустыми вправе быть только
		 *          записи прикладных данных, и посылаются они противодействием разбору обмена
		 *          по его виду
		 *
		 * \~english
		 * @brief Method of the checking of the admissibility of an empty content of a record
		 * @param type the type of the content of the record being checked
		 * @return     the flag of a record of this type being entitled to be empty
		 * @details The section 6.2.1 of RFC 5246 and the section 5.1 of RFC 8446: only the records of
		 *          the application data are entitled to be empty, and they are sent as a countermeasure
		 *          against the analysis of the traffic by its shape
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool empty(const type_t type) noexcept;
		/**
		 * \~russian
		 * @brief Сборщик входящих записей протокола TLS
		 *
		 * @details Куски байтов подаются вызовом push в том виде, в каком их выдало чтение, а
		 *          собранные записи забираются вызовом next до тех пор, пока тот не ответит
		 *          отказом HUNGRY
		 *
		 * \~english
		 * @brief Assembler of the incoming records of the TLS protocol
		 * @details The chunks of bytes are supplied by a call of push in the shape in which a reading
		 *          has produced them, while the assembled records are taken by a call of next until
		 *          it answers with the HUNGRY failure
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Reader {
			private:
				// Смещение начала неразобранных данных в накопителе
				size_t _offset;
			private:
				// Предел длины содержимого принимаемой записи
				size_t _limit;
			private:
				// Накопитель принятых, но ещё не разобранных данных
				vector <uint8_t> _buffer;
			public:
				/**
				 * \~russian
				 * @brief Метод получения предела длины содержимого принимаемой записи
				 *
				 * @return предел длины содержимого записи в байтах
				 *
				 * \~english
				 * @brief Method of getting the limit of the length of the content of a record being received
				 * @return the limit of the length of the content of a record in bytes
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предела длины содержимого принимаемой записи
				 *
				 * @param limit устанавливаемый предел длины содержимого записи в байтах
				 *
				 * @return      признак успешности установки предела
				 *
				 * @details Умолчанием берётся предел защищённой записи TLS 1.3, самый строгий из
				 *          дозволенных протоколом. Связи по TLS 1.2 предел поднимают до RECORD_LEGACY,
				 *          а согласовавшие наибольшую длину куска - опускают
				 *
				 * \~english
				 * @brief Method of setting the limit of the length of the content of a record being received
				 * @param limit the limit of the length of the content of a record in bytes being set
				 * @return      the flag of the success of the setting of the limit
				 * @details The limit of a protected record of TLS 1.3 is taken as the default, the strictest
				 *          of the ones allowed by the protocol. The connections over TLS 1.2 raise the limit
				 *          up to RECORD_LEGACY, while the ones which have negotiated a greatest length of a
				 *          fragment lower it
				 *
				 * \~
				 */
				bool limit(const size_t limit) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения объёма ещё не разобранных данных
				 *
				 * @return объём ещё не разобранных данных в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the data not parsed yet
				 * @return the volume of the data not parsed yet in bytes
				 *
				 * \~
				 */
				size_t pending() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния сборщика
				 *
				 * \~english
				 * @brief Method of the reset of the state of the assembler
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи принятого куска данных
				 *
				 * @param data подаваемый кусок данных
				 *
				 * @return     отказ подачи куска данных
				 *
				 * @note Длина куска ничем не связана с длиной записи: кусок вправе нести часть
				 *       записи, несколько записей подряд либо и то и другое
				 *
				 * \~english
				 * @brief Method of the supply of a received chunk of data
				 * @param data the chunk of data being supplied
				 * @return     the failure of the supply of the chunk of data
				 * @note The length of a chunk is not tied by anything to the length of a record: a chunk
				 *       is entitled to carry a part of a record, several records in a row or both
				 *
				 * \~
				 */
				error_t push(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения очередной собранной записи
				 *
				 * @param header  заголовок, в который помещается заголовок собранной записи
				 * @param payload просмотр, в который помещается содержимое собранной записи
				 *
				 * @return        отказ получения собранной записи
				 *
				 * @note Просмотр содержимого действителен до следующего вызова push, next или clear:
				 *       содержимое лежит в накопителе сборщика, а не в отдельной памяти
				 *
				 * \~english
				 * @brief Method of getting the next assembled record
				 * @param header  the header the header of the assembled record is put into
				 * @param payload the view the content of the assembled record is put into
				 * @return        the failure of the getting of the assembled record
				 * @note The view of the content is valid until the next call of push, next or clear: the
				 *       content lies in the accumulator of the assembler and not in a separate memory
				 *
				 * \~
				 */
				error_t next(header_t & header, view_t & payload) noexcept;
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
				Reader() noexcept;
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
				~Reader() noexcept;
		} reader_t;
		/**
		 * \~russian
		 * @brief Нарезчик исходящих записей протокола TLS
		 *
		 * @details Данные подаются вызовом push и нарезаются на записи дозволенной длины, а
		 *          готовые записи забираются вызовом data и снимаются вызовом consume по мере
		 *          того, как их принимает у потребителя передача
		 *
		 * \~english
		 * @brief Splitter of the outgoing records of the TLS protocol
		 * @details The data are supplied by a call of push and are split into the records of an allowed
		 *          length, while the ready records are taken by a call of data and are removed by a call
		 *          of consume as the transmission accepts them from the consumer
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Writer {
			private:
				// Смещение начала ещё не снятых записей в накопителе
				size_t _offset;
			private:
				// Предел длины содержимого нарезаемой записи
				size_t _limit;
			private:
				// Накопитель готовых, но ещё не снятых записей
				vector <uint8_t> _buffer;
			public:
				/**
				 * \~russian
				 * @brief Метод получения предела длины содержимого нарезаемой записи
				 *
				 * @return предел длины содержимого записи в байтах
				 *
				 * \~english
				 * @brief Method of getting the limit of the length of the content of a record being split
				 * @return the limit of the length of the content of a record in bytes
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предела длины содержимого нарезаемой записи
				 *
				 * @param limit устанавливаемый предел длины содержимого записи в байтах
				 *
				 * @return      признак успешности установки предела
				 *
				 * @details Умолчанием берётся RECORD_PLAINTEXT - наибольшая длина, дозволенная
				 *          протоколом. Предел опускается, когда собеседник согласовал наибольшую
				 *          длину куска, и поднят быть не вправе
				 *
				 * \~english
				 * @brief Method of setting the limit of the length of the content of a record being split
				 * @param limit the limit of the length of the content of a record in bytes being set
				 * @return      the flag of the success of the setting of the limit
				 * @details RECORD_PLAINTEXT is taken as the default — the greatest length allowed by the
				 *          protocol. The limit is lowered when a peer has negotiated a greatest length of a
				 *          fragment, and it is not entitled to be raised
				 *
				 * \~
				 */
				bool limit(const size_t limit) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения объёма ещё не снятых записей
				 *
				 * @return объём ещё не снятых записей в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the records not removed yet
				 * @return the volume of the records not removed yet in bytes
				 *
				 * \~
				 */
				size_t pending() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения готовых записей
				 *
				 * @return просмотр готовых, но ещё не снятых записей
				 *
				 * @note Просмотр действителен до следующего вызова push, consume или clear
				 *
				 * \~english
				 * @brief Method of getting the ready records
				 * @return the view of the records ready but not removed yet
				 * @note The view is valid until the next call of push, consume or clear
				 *
				 * \~
				 */
				view_t data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия переданных байтов записей
				 *
				 * @param size объём снимаемых байтов
				 *
				 * @return     признак успешности снятия байтов
				 *
				 * @note Снимается ровно тот объём, который принят передачей: границы записей
				 *       передаче не видны, и остановиться она вправе где угодно
				 *
				 * \~english
				 * @brief Method of the removal of the transmitted bytes of the records
				 * @param size the volume of the bytes being removed
				 * @return     the flag of the success of the removal of the bytes
				 * @note Exactly the volume which has been accepted by the transmission is removed: the
				 *       boundaries of the records are not visible to the transmission, and it is entitled
				 *       to stop anywhere
				 *
				 * \~
				 */
				bool consume(const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния нарезчика
				 *
				 * \~english
				 * @brief Method of the reset of the state of the splitter
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод нарезки данных на записи
				 *
				 * @param type    вид содержимого нарезаемых данных
				 * @param version версия протокола, указываемая в записях
				 * @param data    нарезаемые на записи данные
				 *
				 * @return        отказ нарезки данных на записи
				 *
				 * @details Раздел 6.2.1 RFC 5246: данные длиннее предела нарезаются на несколько
				 *          записей подряд, границы поданных вызовов слоем записей не хранятся
				 *
				 * \~english
				 * @brief Method of the splitting of the data into the records
				 * @param type    the type of the content of the data being split
				 * @param version the version of the protocol being indicated in the records
				 * @param data    the data being split into the records
				 * @return        the failure of the splitting of the data into the records
				 * @details The section 6.2.1 of RFC 5246: the data longer than the limit are split into
				 *          several records in a row, the boundaries of the supplied calls are not stored by
				 *          the record layer
				 *
				 * \~
				 */
				error_t push(const type_t type, const version_t version, const view_t & data) noexcept;
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
				 */
				~Writer() noexcept;
		} writer_t;
	};
};

#endif // __ANTS_RECORD__
