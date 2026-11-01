/**
 * @file field.hpp
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
 * @brief Заголовочный файл модуля полей протокола TLS — чтение и запись чисел и полей
 *        переменной длины, из которых сложены тела сообщений рукопожатия
 *
 * \~english
 * @brief Header file of the module of the fields of the TLS protocol — the reading and the
 *        writing of the numbers and of the fields of a variable length, of which the bodies of
 *        the messages of the handshake are composed
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
#include <vector>
#include <utility>
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
	 * @brief Пространство имён полей протокола TLS
	 *
	 * @details Приложение B RFC 8446: тела сообщений сложены из чисел заданной ширины и из
	 *          полей переменной длины, у которых длина идёт впереди содержимого и сама
	 *          занимает от одного до трёх байтов. Поля вкладываются друг в друга без
	 *          ограничения глубины.
	 *
	 * @note Всякое чтение сличается с оставшейся длиной, а не с объявленной: длину объявляет
	 *       собеседник, и доверять ей нельзя
	 *
	 * \~english
	 * @brief Namespace of the fields of the TLS protocol
	 *
	 * @details The appendix B of RFC 8446: the bodies of the messages are composed of the numbers of a
	 *          given width and of the fields of a variable length, at which the length goes ahead of
	 *          the content and itself occupies from one to three bytes. The fields are nested into each
	 *          other without a limitation of the depth.
	 *
	 * @note Every reading is compared against the remaining length and not against the declared one: the
	 *       length is declared by a peer, and it may not be trusted
	 *
	 * \~
	 */
	namespace field {
		/**
		 * \~russian
		 * @brief Отказы работы с полями протокола
		 *
		 * \~english
		 * @brief Failures of the work with the fields of the protocol
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			// Отказа нет
			NONE   = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			// Читаемое поле за разбираемой областью не помещается
			HUNGRY = 0x01, /*!< \~russian Читаемое поле за разбираемой областью не помещается \~english The field being read does not fit into the area being parsed \~ */
			// Ширина числа либо длины поля протоколом не задана
			WIDTH  = 0x02, /*!< \~russian Ширина числа либо длины поля протоколом не задана \~english The width of a number or of a length of a field is not set by the protocol \~ */
			// Записываемое значение в поле заданной ширины не входит
			LENGTH = 0x03, /*!< \~russian Записываемое значение в поле заданной ширины не входит \~english The value being written does not fit into a field of the given width \~ */
			// Закрываемого поля переменной длины нет
			NESTING = 0x04, /*!< \~russian Закрываемого поля переменной длины нет \~english There is no field of a variable length being closed \~ */
			// Памяти под накопитель не хватило
			MEMORY = 0x05  /*!< \~russian Памяти под накопитель не хватило \~english There was not enough memory for the accumulator \~ */
		};

		/**
		 * \~russian
		 * @brief Разборщик полей протокола
		 *
		 * @details Читает разбираемую область слева направо, подвигая своё место чтения.
		 *          Всякое чтение либо помещается в оставшуюся часть области, либо отвечает
		 *          отказом и места чтения не подвигает.
		 *
		 * @note Просмотры, выдаваемые чтениями, смотрят внутрь разбираемой области и живут
		 *       ровно столько, сколько живёт она сама
		 *
		 * \~english
		 * @brief Parser of the fields of the protocol
		 *
		 * @details It reads the area being parsed from the left to the right, moving its place of the
		 *          reading. Every reading either fits into the remaining part of the area or answers
		 *          with a failure and does not move the place of the reading.
		 *
		 * @note The views produced by the readings look inside the area being parsed and live exactly
		 *       as long as it itself lives
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Scanner {
			private:
				// Разбираемая область байтов
				view_t _data;
			private:
				// Место чтения в разбираемой области байтов
				size_t _offset;
			public:
				/**
				 * \~russian
				 * @brief Метод установки разбираемой области байтов
				 *
				 * @param data устанавливаемая разбираемая область байтов
				 *
				 * \~english
				 * @brief Method of setting the byte area being parsed
				 *
				 * @param data the byte area being parsed being set
				 *
				 * \~
				 */
				void start(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния разборщика
				 *
				 * \~english
				 * @brief Method of the reset of the state of the parser
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения места чтения в разбираемой области
				 *
				 * @return место чтения в разбираемой области в байтах
				 *
				 * \~english
				 * @brief Method of getting the place of the reading in the area being parsed
				 *
				 * @return the place of the reading in the area being parsed in bytes
				 *
				 * \~
				 */
				size_t offset() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения объёма ещё не прочитанной части области
				 *
				 * @return объём ещё не прочитанной части области в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the part of the area not read yet
				 *
				 * @return the volume of the part of the area not read yet in bytes
				 *
				 * \~
				 */
				size_t left() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод чтения числа заданной ширины
				 *
				 * @param result число, в которое помещается прочитанное значение
				 * @param size   ширина читаемого числа в байтах
				 * @return       отказ чтения числа
				 *
				 * @details Числа протокола записываются старшим разрядом вперёд
				 *
				 * \~english
				 * @brief Method of the reading of a number of a given width
				 *
				 * @param result the number the read value is put into
				 * @param size   the width of the number being read in bytes
				 * @return       the failure of the reading of the number
				 *
				 * @details The numbers of the protocol are written with the most significant bit ahead
				 *
				 * \~
				 */
				error_t number(uint32_t & result, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод чтения области байтов заданной длины
				 *
				 * @param result просмотр, в который помещается прочитанная область
				 * @param size   длина читаемой области в байтах
				 * @return       отказ чтения области байтов
				 *
				 * \~english
				 * @brief Method of the reading of a byte area of a given length
				 *
				 * @param result the view the read area is put into
				 * @param size   the length of the area being read in bytes
				 * @return       the failure of the reading of the byte area
				 *
				 * \~
				 */
				error_t bytes(view_t & result, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод чтения поля переменной длины
				 *
				 * @param result просмотр, в который помещается содержимое поля
				 * @param width  ширина записи длины поля в байтах
				 * @return       отказ чтения поля переменной длины
				 *
				 * @details Читается длина поля шириной от одного до трёх байтов, а за нею -
				 *          содержимое поля объявленной длины
				 *
				 * \~english
				 * @brief Method of the reading of a field of a variable length
				 *
				 * @param result the view the content of the field is put into
				 * @param width  the width of the record of the length of the field in bytes
				 * @return       the failure of the reading of the field of a variable length
				 *
				 * @details The length of the field of a width from one to three bytes is read, and behind
				 *          it the content of the field of the declared length
				 *
				 * \~
				 */
				error_t vector(view_t & result, const size_t width) noexcept;
				/**
				 * \~russian
				 * @brief Метод чтения всей оставшейся части области
				 *
				 * @param result просмотр, в который помещается оставшаяся часть области
				 * @return       отказ чтения оставшейся части области
				 *
				 * \~english
				 * @brief Method of the reading of the whole remaining part of the area
				 *
				 * @param result the view the remaining part of the area is put into
				 * @return       the failure of the reading of the remaining part of the area
				 *
				 * \~
				 */
				error_t rest(view_t & result) noexcept;
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
				Scanner() noexcept;
		} scanner_t;
		/**
		 * \~russian
		 * @brief Составитель полей протокола
		 *
		 * @details Числа и области байтов дописываются в накопитель подряд, а поля переменной
		 *          длины открываются вызовом open и закрываются вызовом close, который сам
		 *          проставляет длину на отложенное под неё место. Поля вкладываются друг в
		 *          друга: открытых полей вправе быть сколько угодно.
		 *
		 * @note Накопитель считается хранилищем секретов: сброс и разрушение затирают его
		 *       содержимое по длине записи, и потребителю затирать составленное самому не нужно
		 *
		 * \~english
		 * @brief Composer of the fields of the protocol
		 *
		 * @details The numbers and the byte areas are appended to the accumulator in a row, while the
		 *          fields of a variable length are opened by a call of open and are closed by a call of
		 *          close, which itself writes the length into the place reserved for it. The fields are
		 *          nested into each other: there may be any number of the opened fields.
		 *
		 * @note The accumulator is considered a storage of secrets: the reset and the destruction wipe its
		 *       content by the length of the record, and the consumer does not need to wipe the composed one itself
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Builder {
			private:
				// Накопитель составляемой записи
				vector <uint8_t> _buffer;
			private:
				// Места отложенных длин ещё не закрытых полей переменной длины
				vector <pair <size_t, size_t>> _marks;
			private:
				/**
				 * \~russian
				 * @brief Метод выделения места под запись с затиранием прежнего накопителя
				 *
				 * @param extra требуемое число свободных байтов
				 * @return      признак успешности выделения места
				 *
				 * \~english
				 * @brief Method of allocating room for the record with wiping of the previous accumulator
				 *
				 * @param extra the required number of free bytes
				 * @return      the sign of the success of the allocation
				 *
				 * \~
				 */
				bool grow(const size_t extra) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения объёма составленной записи
				 *
				 * @return объём составленной записи в байтах
				 *
				 * \~english
				 * @brief Method of getting the volume of the composed record
				 *
				 * @return the volume of the composed record in bytes
				 *
				 * \~
				 */
				size_t pending() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа ещё не закрытых полей переменной длины
				 *
				 * @return число ещё не закрытых полей переменной длины
				 *
				 * \~english
				 * @brief Method of getting the number of the fields of a variable length not closed yet
				 *
				 * @return the number of the fields of a variable length not closed yet
				 *
				 * \~
				 */
				size_t nesting() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения составленной записи
				 *
				 * @return просмотр составленной записи
				 *
				 * @note Просмотр действителен до следующего дописывания в накопитель
				 *
				 * \~english
				 * @brief Method of getting the composed record
				 *
				 * @return the view of the composed record
				 *
				 * @note The view is valid until the next appending to the accumulator
				 *
				 * \~
				 */
				view_t data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса накопителя составляемой записи
				 *
				 * @details Накопитель затирается прежде сброса: составитель складывает и
				 *          секреты (общее значение обмена, состояние билета сеанса), и
				 *          оставлять их в освобождённой памяти нельзя. Затирание идёт по
				 *          длине записи изменчивым циклом sys::wipe; то же делает деструктор
				 *
				 * \~english
				 * @brief Method of the reset of the accumulator of the record being composed
				 *
				 * @details The accumulator is wiped before the reset: the composer holds secrets too (the
				 *          shared value of the exchange, the state of a session ticket), and leaving them in
				 *          the freed memory is not allowed. The wiping goes by the length of the record by the
				 *          volatile loop sys::wipe; the destructor does the same
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод записи числа заданной ширины
				 *
				 * @param value записываемое число
				 * @param size  ширина записи числа в байтах
				 * @return      отказ записи числа
				 *
				 * \~english
				 * @brief Method of the writing of a number of a given width
				 *
				 * @param value the number being written
				 * @param size  the width of the record of the number in bytes
				 * @return      the failure of the writing of the number
				 *
				 * \~
				 */
				error_t number(const uint32_t value, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи области байтов
				 *
				 * @param data записываемая область байтов
				 * @return     отказ записи области байтов
				 *
				 * \~english
				 * @brief Method of the writing of a byte area
				 *
				 * @param data the byte area being written
				 * @return     the failure of the writing of the byte area
				 *
				 * \~
				 */
				error_t bytes(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод открытия поля переменной длины
				 *
				 * @param width ширина записи длины поля в байтах
				 * @return      отказ открытия поля переменной длины
				 *
				 * \~english
				 * @brief Method of the opening of a field of a variable length
				 *
				 * @param width the width of the record of the length of the field in bytes
				 * @return      the failure of the opening of the field of a variable length
				 *
				 * \~
				 */
				error_t open(const size_t width) noexcept;
				/**
				 * \~russian
				 * @brief Метод закрытия поля переменной длины
				 *
				 * @return отказ закрытия поля переменной длины
				 *
				 * @details Длина поля определяется тем, сколько записано с его открытия, и
				 *          проставляется на отложенное под неё место
				 *
				 * \~english
				 * @brief Method of the closing of a field of a variable length
				 *
				 * @return the failure of the closing of the field of a variable length
				 *
				 * @details The length of the field is determined by how much has been written since its
				 *          opening and is written into the place reserved for it
				 *
				 * \~
				 */
				error_t close() noexcept;
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
				Builder() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * @note Накопитель затирается по длине записи прежде освобождения
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * @note The accumulator is wiped by the length of the record before the release
				 *
				 * \~
				 */
				~Builder() noexcept;
		} builder_t;
	};
};

