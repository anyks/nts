/**
 * @file edwards448.hpp
 * @date 2026-11-05
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
 * @brief Заголовочный файл внутреннего модуля арифметики точек незакрученной кривой Эдвардса Ed448
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Точки в расширенных координатах нужны и подписи Ed448
 *       (sign/ed448.cpp), и программе вычисления кратных точки основания
 *       (tools/sign-tables.cpp), оттого формулы живут здесь и встраиваются в обоих
 *       потребителях
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_INTERNAL_SIGN_EDWARDS448__
/**
 * Экранируем повторную инициализацию модуля
 */
#define __ANTS_INTERNAL_SIGN_EDWARDS448__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <sys/wipe.hpp>
#include <math/field448.hpp>
#include <internal/math/field448.hpp>

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
	/**
	 * @brief Пространство имён подписей
	 *
	 */
	namespace sign {
		/**
		 * @brief Пространство имён встраиваемых ядер кривой Эдвардса Ed448
		 *
		 */
		namespace kernel448 {
			/**
			 * Элемент поля и его арифметика берутся из открытого модуля поля
			 */
			using namespace nts::math::field448;
			/**
			 * @brief Точка кривой в расширенных координатах
			 *
			 * @details Точка (x, y) представлена как (X, Y, Z, T) с x = X / Z, y = Y / Z
			 *          и x * y = T / Z
			 *
			 */
			typedef struct Point {
				// Координаты точки
				element_t x, y, z, t;
			} point_t;
			/**
			 * @brief Коэффициент кривой, записанный младшим байтом вперёд
			 *
			 * @details Равен -39081 по модулю поля
			 *
			 */
			static const uint8_t COEFFICIENT[SIZE] = {
				// Младшие разряды записаны первыми
				0x56, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
			};
			/**
			 * @brief Первая координата точки основания, записанная младшим байтом вперёд
			 *
			 */
			static const uint8_t BASE_X[SIZE] = {
				// Младшие разряды записаны первыми
				0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26,
				0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B, 0x43,
				0x11, 0x65, 0xB6, 0x2A, 0xF7, 0x1A, 0xAE, 0x12,
				0x64, 0xA4, 0xD3, 0xA3, 0x24, 0xE3, 0x6D, 0xEA,
				0x67, 0x17, 0x0F, 0x47, 0x70, 0x65, 0x14, 0x9E,
				0xDA, 0x36, 0xBF, 0x22, 0xA6, 0x15, 0x1D, 0x22,
				0xED, 0x0D, 0xED, 0x6B, 0xC6, 0x70, 0x19, 0x4F
			};
			/**
			 * @brief Вторая координата точки основания, записанная младшим байтом вперёд
			 *
			 */
			static const uint8_t BASE_Y[SIZE] = {
				// Младшие разряды записаны первыми
				0x14, 0xFA, 0x30, 0xF2, 0x5B, 0x79, 0x08, 0x98,
				0xAD, 0xC8, 0xD7, 0x4E, 0x2C, 0x13, 0xBD, 0xFD,
				0xC4, 0x39, 0x7C, 0xE6, 0x1C, 0xFF, 0xD3, 0x3A,
				0xD7, 0xC2, 0xA0, 0x05, 0x1E, 0x9C, 0x78, 0x87,
				0x40, 0x98, 0xA3, 0x6C, 0x73, 0x73, 0xEA, 0x4B,
				0x62, 0xC7, 0xC9, 0x56, 0x37, 0x20, 0x76, 0x88,
				0x24, 0xBC, 0xB6, 0x6E, 0x71, 0x46, 0x3F, 0x69
			};
			/**
			 * @brief Функция заведения коэффициента кривой элементом поля
			 *
			 * @details Сложение зовёт коэффициент на всяком шаге умножения, оттого он
			 *          заводится один раз, а не разбирается из записи при всяком
			 *          сложении
			 *
			 * @return коэффициент кривой элементом поля
			 *
			 */
			static __ANTS_INLINE__ const element_t & coefficient() noexcept {
				// Коэффициент кривой, заведённый один раз
				static const element_t item = []() noexcept {
					// Разбираемый коэффициент
					element_t value;
					// Разбор коэффициента из записи
					load(COEFFICIENT, value);
					// Выводим разобранный коэффициент
					return value;
				}();
				// Выводим коэффициент кривой
				return item;
			}
			/**
			 * @brief Функция получения нейтральной точки
			 *
			 * @param result место, в которое помещается нейтральная точка
			 *
			 */
			static __ANTS_INLINE__ void neutral(point_t & result) noexcept {
				// Первая координата нейтральной точки - ноль
				zero(result.x);
				// Вторая координата нейтральной точки - единица
				one(result.y);
				// Знаменатель нейтральной точки - единица
				one(result.z);
				// Произведение координат нейтральной точки - ноль
				zero(result.t);
			}
			/**
			 * @brief Функция получения точки основания
			 *
			 * @param result место, в которое помещается точка основания
			 *
			 */
			static __ANTS_INLINE__ void base(point_t & result) noexcept {
				// Разбор первой координаты точки основания
				load(BASE_X, result.x);
				// Разбор второй координаты точки основания
				load(BASE_Y, result.y);
				// Знаменатель точки основания - единица
				one(result.z);
				// Произведение координат точки основания
				math::field448::kernel::multiply(result.x, result.y, result.t);
			}
			/**
			 * @brief Функция сложения точек кривой
			 *
			 * @details Раздел 5.2.4 RFC 8032 при коэффициенте a = 1: сложение полное, оттого
			 *          верно и при равных слагаемых, и при нейтральном слагаемом
			 *
			 * @param first  первое слагаемое
			 * @param second второе слагаемое
			 * @param result место, в которое помещается сумма
			 *
			 */
			static __ANTS_INLINE__ void add(const point_t & first, const point_t & second, point_t & result) noexcept {
				// Промежуточные значения сложения
				element_t a, b, c, d, e, f, g, h, item;
				// Вырабатываем произведение первых координат
				math::field448::kernel::multiply(first.x, second.x, a);
				// Вырабатываем произведение вторых координат
				math::field448::kernel::multiply(first.y, second.y, b);
				// Вырабатываем произведение четвёртых координат
				math::field448::kernel::multiply(first.t, second.t, c);
				// Вырабатываем произведение четвёртых координат на коэффициент
				math::field448::kernel::multiply(c, coefficient(), c);
				// Вырабатываем произведение знаменателей
				math::field448::kernel::multiply(first.z, second.z, d);
				// Вырабатываем сумму координат первого слагаемого
				math::field448::kernel::plus(first.x, first.y, e);
				// Вырабатываем сумму координат второго слагаемого
				math::field448::kernel::plus(second.x, second.y, item);
				// Вырабатываем произведение сумм координат
				math::field448::kernel::multiply(e, item, e);
				// Вычитаем из произведения сумм произведение первых координат
				math::field448::kernel::minus(e, a, e);
				// Вычитаем из произведения сумм произведение вторых координат
				math::field448::kernel::minus(e, b, e);
				// Вырабатываем разность произведений знаменателей и четвёртых координат
				math::field448::kernel::minus(d, c, f);
				// Вырабатываем сумму произведений знаменателей и четвёртых координат
				math::field448::kernel::plus(d, c, g);
				// Вычитаем из произведения вторых координат произведение первых: коэффициент a равен единице
				math::field448::kernel::minus(b, a, h);
				// Первая координата суммы точек
				math::field448::kernel::multiply(e, f, result.x);
				// Вторая координата суммы точек
				math::field448::kernel::multiply(g, h, result.y);
				// Четвёртая координата суммы точек
				math::field448::kernel::multiply(e, h, result.t);
				// Знаменатель суммы точек
				math::field448::kernel::multiply(f, g, result.z);
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&item, sizeof(item));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&h, sizeof(h));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&g, sizeof(g));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&f, sizeof(f));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&e, sizeof(e));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&d, sizeof(d));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&c, sizeof(c));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&b, sizeof(b));
				// Затирание промежуточных значений сложения
				nts::sys::wipe(&a, sizeof(a));
			}
			/**
			 * @brief Функция удвоения точки кривой
			 *
			 * @details Раздел 5.2.4 RFC 8032 при коэффициенте a = 1
			 *
			 * @param value  удваиваемая точка
			 * @param result место, в которое помещается удвоенная точка
			 *
			 */
			static __ANTS_INLINE__ void twice(const point_t & value, point_t & result) noexcept {
				// Промежуточные значения удвоения
				element_t a, b, c, e, f, g, h;
				// Вырабатываем квадрат первой координаты
				math::field448::kernel::square(value.x, a);
				// Вырабатываем квадрат второй координаты
				math::field448::kernel::square(value.y, b);
				// Вырабатываем квадрат знаменателя
				math::field448::kernel::square(value.z, c);
				// Вырабатываем удвоенный квадрат знаменателя
				math::field448::kernel::plus(c, c, c);
				// Вырабатываем сумму координат
				math::field448::kernel::plus(value.x, value.y, e);
				// Вырабатываем квадрат суммы координат
				math::field448::kernel::square(e, e);
				// Вычитаем из квадрата суммы квадрат первой координаты
				math::field448::kernel::minus(e, a, e);
				// Вычитаем из квадрата суммы квадрат второй координаты
				math::field448::kernel::minus(e, b, e);
				// Вырабатываем сумму квадрата первой координаты и квадрата второй: коэффициент a равен единице
				math::field448::kernel::plus(a, b, g);
				// Вырабатываем разность этой суммы и удвоенного квадрата знаменателя
				math::field448::kernel::minus(g, c, f);
				// Вырабатываем разность квадрата первой координаты и квадрата второй
				math::field448::kernel::minus(a, b, h);
				// Первая координата удвоенной точки
				math::field448::kernel::multiply(e, f, result.x);
				// Вторая координата удвоенной точки
				math::field448::kernel::multiply(g, h, result.y);
				// Четвёртая координата удвоенной точки
				math::field448::kernel::multiply(e, h, result.t);
				// Знаменатель удвоенной точки
				math::field448::kernel::multiply(f, g, result.z);
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&h, sizeof(h));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&g, sizeof(g));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&f, sizeof(f));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&e, sizeof(e));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&c, sizeof(c));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&b, sizeof(b));
				// Затирание промежуточных значений удвоения
				nts::sys::wipe(&a, sizeof(a));
			}
		};
	};
};

#endif
