/**
 * @file field25519.hpp
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
 * @brief Заголовочный файл модуля арифметики поля по модулю 2^255 - 19 —
 *        основание кривых Curve25519 и Ed25519 по RFC 7748 и RFC 8032
 *
 * \~english
 * @brief Header file of the module of the arithmetic of the field by the modulus 2^255 - 19 —
 *        the foundation of the curves Curve25519 and Ed25519 according to RFC 7748 and RFC 8032
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
	 * @brief Пространство имён модулей арифметики
	 *
	 * \~english
	 * @brief Namespace of the arithmetic modules
	 *
	 * \~
	 */
	namespace math {
		/**
		 * \~russian
		 * @brief Пространство имён арифметики поля по модулю 2^255 - 19
		 *
		 * @details Элемент поля хранится пятью конечностями по пятьдесят одному разряду
		 *          в машинных словах: младшая конечность идёт первой. Между действиями
		 *          конечности вправе выходить за пятьдесят один разряд - приведение до
		 *          единственной записи выполняется лишь при записи в байты. Всякое действие
		 *          идёт за постоянное время: ни ветвлений по значению, ни обращений к памяти
		 *          по индексу, зависящему от значения, здесь нет
		 *
		 * @note Модуль памяти не выделяет и исключений не возбуждает
		 *
		 * \~english
		 * @brief Namespace of the arithmetic of the field by the modulus 2^255 - 19
		 * @details An element of the field is kept by five limbs of fifty one bits in the machine
		 *          words: the junior limb goes first. Between the operations the limbs may exceed
		 *          fifty one bits - the reduction to the only record is performed only at the writing
		 *          into the bytes. Every operation goes in a constant time: there are neither the branches
		 *          by a value nor the memory accesses by an index depending on a value here
		 * @note The module does not allocate memory and raises no exceptions
		 *
		 * \~
		 */
		namespace field25519 {
			/**
			 * \~russian
			 * @brief Размер записи элемента поля в байтах
			 *
			 * \~english
			 * @brief Size of the record of an element of the field in bytes
			 *
			 * \~
			 */
			static constexpr size_t SIZE = 32;

			/**
			 * \~russian
			 * @brief Число конечностей элемента поля
			 *
			 * \~english
			 * @brief Number of the limbs of an element of the field
			 *
			 * \~
			 */
			static constexpr size_t LIMBS = 5;

			/**
			 * \~russian
			 * @brief Элемент поля по модулю 2^255 - 19
			 *
			 * @details Конечности записаны от младшей к старшей, по пятьдесят один разряд
			 *          в каждой
			 *
			 * \~english
			 * @brief Element of the field by the modulus 2^255 - 19
			 * @details The limbs are written from the junior one to the senior one, fifty one
			 *          bits in each
			 *
			 * \~
			 */
			typedef struct __ANTS_SHARED_EXPORT__ Element {
				// Конечности элемента поля
				uint64_t limbs[LIMBS];
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
				Element() noexcept : limbs{0, 0, 0, 0, 0} {}
			} element_t;

			/**
			 * \~russian
			 * @brief Метод получения нуля поля
			 *
			 * @param result место, в которое помещается ноль поля
			 *
			 * \~english
			 * @brief Method of getting the zero of the field
			 * @param result the place the zero of the field is put into
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void zero(element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод получения единицы поля
			 *
			 * @param result место, в которое помещается единица поля
			 *
			 * \~english
			 * @brief Method of getting the unit of the field
			 * @param result the place the unit of the field is put into
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void one(element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод разбора элемента поля из тридцати двух байтов
			 *
			 * @param data   разбираемые байты, записанные младшим байтом вперёд
			 * @param result место, в которое помещается разобранный элемент
			 *
			 * @details Старший разряд последнего байта отбрасывается, как велит раздел 5
			 *          RFC 7748, а значение, не меньшее модуля, приводится по модулю
			 *
			 * \~english
			 * @brief Method of the parsing of an element of the field from thirty two bytes
			 * @param data   the bytes being parsed, written with the junior byte ahead
			 * @param result the place the parsed element is put into
			 * @details The senior bit of the last byte is dropped, as the section 5 of RFC 7748
			 *          orders, and a value not less than the modulus is reduced by the modulus
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void load(const uint8_t * data, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод записи элемента поля в тридцать два байта
			 *
			 * @param value записываемый элемент
			 * @param data  место, в которое помещается запись младшим байтом вперёд
			 *
			 * @details Элемент приводится до единственной записи, меньшей модуля: старший
			 *          разряд последнего байта всегда обращается в ноль
			 *
			 * \~english
			 * @brief Method of the writing of an element of the field into thirty two bytes
			 * @param value the element being written
			 * @param data  the place the record is put into with the junior byte ahead
			 * @details The element is reduced to the only record less than the modulus: the senior
			 *          bit of the last byte always turns into a zero
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void store(const element_t & value, uint8_t * data) noexcept;
			/**
			 * \~russian
			 * @brief Метод сложения элементов поля
			 *
			 * @param first  первое слагаемое
			 * @param second второе слагаемое
			 * @param result место, в которое помещается сумма
			 *
			 * @note Место итога вправе совпадать с местом всякого слагаемого
			 *
			 * \~english
			 * @brief Method of the addition of the elements of the field
			 * @param first  the first addend
			 * @param second the second addend
			 * @param result the place the sum is put into
			 * @note The place of the result may coincide with the place of every addend
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void add(const element_t & first, const element_t & second, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод вычитания элементов поля
			 *
			 * @param first  уменьшаемое
			 * @param second вычитаемое
			 * @param result место, в которое помещается разность
			 *
			 * @note Место итога вправе совпадать с местом уменьшаемого либо вычитаемого
			 *
			 * \~english
			 * @brief Method of the subtraction of the elements of the field
			 * @param first  the minuend
			 * @param second the subtrahend
			 * @param result the place the difference is put into
			 * @note The place of the result may coincide with the place of the minuend or of the subtrahend
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void sub(const element_t & first, const element_t & second, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод умножения элементов поля
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @param result место, в которое помещается произведение
			 *
			 * @note Место итога вправе совпадать с местом всякого сомножителя
			 *
			 * \~english
			 * @brief Method of the multiplication of the elements of the field
			 * @param first  the first factor
			 * @param second the second factor
			 * @param result the place the product is put into
			 * @note The place of the result may coincide with the place of every factor
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void mul(const element_t & first, const element_t & second, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод умножения элемента поля на малое число
			 *
			 * @param value  умножаемый элемент
			 * @param factor множитель, не больше 2^32
			 * @param result место, в которое помещается произведение
			 *
			 * @note Место итога вправе совпадать с местом умножаемого элемента; множитель
			 *       сверх 2^32 переполняет перенос между конечностями, и итог выходит неверным
			 *
			 * \~english
			 * @brief Method of the multiplication of an element of the field by a small number
			 * @param value  the element being multiplied
			 * @param factor the factor, not greater than 2^32
			 * @param result the place the product is put into
			 * @note The place of the result may coincide with the place of the element being multiplied;
			 *       a factor greater than 2^32 overflows the carry between the limbs and the result comes out wrong
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void mul(const element_t & value, const uint64_t factor, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод возведения элемента поля в квадрат
			 *
			 * @param value  возводимый элемент
			 * @param result место, в которое помещается квадрат
			 *
			 * @note Место итога вправе совпадать с местом возводимого элемента
			 *
			 * \~english
			 * @brief Method of the squaring of an element of the field
			 * @param value  the element being squared
			 * @param result the place the square is put into
			 * @note The place of the result may coincide with the place of the element being squared
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void square(const element_t & value, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод обращения элемента поля
			 *
			 * @param value  обращаемый элемент
			 * @param result место, в которое помещается обратный элемент
			 *
			 * @details Обращение выполняется возведением в степень 2^255 - 21 по малой
			 *          теореме Ферма, оттого обратный к нулю - тоже ноль
			 *
			 * @note Место итога вправе совпадать с местом обращаемого элемента
			 *
			 * \~english
			 * @brief Method of the inversion of an element of the field
			 * @param value  the element being inverted
			 * @param result the place the inverse element is put into
			 * @details The inversion is performed by the raise into the power 2^255 - 21 by the
			 *          little theorem of Fermat, therefore the inverse of a zero is a zero too
			 * @note The place of the result may coincide with the place of the element being inverted
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void invert(const element_t & value, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод возведения элемента поля в степень (2^255 - 24) / 8
			 *
			 * @param value  возводимый элемент
			 * @param result место, в которое помещается степень
			 *
			 * @details Степень 2^252 - 3 нужна извлечению квадратного корня при разборе
			 *          точки кривой Эдвардса по разделу 5.1.3 RFC 8032
			 *
			 * @note Место итога вправе совпадать с местом возводимого элемента
			 *
			 * \~english
			 * @brief Method of the raise of an element of the field into the power (2^255 - 24) / 8
			 * @param value  the element being raised
			 * @param result the place the power is put into
			 * @details The power 2^252 - 3 is needed by the extraction of a square root at the parsing
			 *          of a point of the Edwards curve according to the section 5.1.3 of RFC 8032
			 * @note The place of the result may coincide with the place of the element being raised
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void root(const element_t & value, element_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод сличения элементов поля
			 *
			 * @param first  первый сличаемый элемент
			 * @param second второй сличаемый элемент
			 *
			 * @return       признак равенства элементов
			 *
			 * @note Сличение идёт за постоянное время по приведённым записям элементов
			 *
			 * \~english
			 * @brief Method of the comparison of the elements of the field
			 * @param first  the first element being compared
			 * @param second the second element being compared
			 * @return       the flag of the equality of the elements
			 * @note The comparison goes in a constant time by the reduced records of the elements
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool equal(const element_t & first, const element_t & second) noexcept;
			/**
			 * \~russian
			 * @brief Метод проверки обращения элемента поля в ноль
			 *
			 * @param value проверяемый элемент
			 *
			 * @return      признак обращения элемента в ноль
			 *
			 * @note Проверка идёт за постоянное время по приведённой записи элемента
			 *
			 * \~english
			 * @brief Method of the check of the turning of an element of the field into a zero
			 * @param value the element being checked
			 * @return      the flag of the turning of the element into a zero
			 * @note The check goes in a constant time by the reduced record of the element
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool nil(const element_t & value) noexcept;
			/**
			 * \~russian
			 * @brief Метод условного обмена элементов поля
			 *
			 * @param first  первый обмениваемый элемент
			 * @param second второй обмениваемый элемент
			 * @param flag   признак обмена: единица меняет элементы местами, ноль оставляет как есть
			 *
			 * @details Обмен выполняется наложением маски, выведенной из признака, оттого идёт
			 *          за постоянное время независимо от значения признака
			 *
			 * \~english
			 * @brief Method of the conditional swap of the elements of the field
			 * @param first  the first element being swapped
			 * @param second the second element being swapped
			 * @param flag   the flag of the swap: a unit swaps the elements, a zero leaves them as they are
			 * @details The swap is performed by the imposition of a mask derived from the flag, therefore
			 *          it goes in a constant time regardless of the value of the flag
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void swap(element_t & first, element_t & second, const uint64_t flag) noexcept;
		};
	};
};

