/**
 * @file curve.hpp
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
 * @brief Заголовочный файл модуля арифметики точек эллиптической кривой над
 *        полем простого порядка
 *
 * \~english
 * @brief Header file of the module of the arithmetic of the points of an elliptic
 *        curve over a field of a prime order
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_CURVE__
#define __ANYKS_TLS_CURVE__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>

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
	 * @brief Пространство имён модулей эллиптических кривых
	 *
	 * @details Кривая задана уравнением Вейерштрасса y^2 = x^3 + a*x + b над полем
	 *          вычетов по простому модулю: именно этот вид задан разделом 5.1
	 *          ГОСТ Р 34.10-2012
	 *
	 * \~english
	 * @brief Namespace of the elliptic curve modules
	 * @details The curve is given by the Weierstrass equation y^2 = x^3 + a*x + b over
	 *          the field of the residues by a prime modulus: it is exactly this form that
	 *          is given by the section 5.1 of GOST R 34.10-2012
	 *
	 * \~
	 */
	namespace curve {
		/**
		 * \~russian
		 * @brief Точка эллиптической кривой
		 *
		 * @details Точка хранится в координатах Якоби: аффинные координаты выходят
		 *          делением на квадрат и куб третьей координаты, оттого сложение точек
		 *          обходится без обращения по модулю, самого дорогого из действий.
		 *          Нулевая третья координата означает бесконечно удалённую точку.
		 *
		 * @note Координаты хранятся в области Монтгомери поля кривой
		 *
		 * \~english
		 * @brief Point of an elliptic curve
		 * @details The point is stored in the Jacobi coordinates: the affine coordinates
		 *          come out by a division by the square and the cube of the third coordinate,
		 *          therefore the addition of the points goes without an inversion by the
		 *          modulus, the most expensive of the operations. A zero third coordinate
		 *          means the point at infinity.
		 * @note The coordinates are stored in the Montgomery domain of the field of the curve
		 *
		 * \~
		 */
		typedef struct __ANYKS_TLS_SHARED_EXPORT__ Point {
			// Первая координата точки
			math::number_t x;
			// Вторая координата точки
			math::number_t y;
			// Третья координата точки
			math::number_t z;
		} point_t;

		/**
		 * \~russian
		 * @brief Эллиптическая кривая над полем простого порядка
		 *
		 * @details Умножение точки на число выполняется удвоением со сложением на всяком
		 *          разряде числа независимо от его значения: нужная из двух точек
		 *          выбирается наложением маски, оттого время работы от значения множителя
		 *          не зависит
		 *
		 * @note Кривые с ненулевым порядком кручения не поддерживаются намеренно: наборы
		 *       параметров ГОСТ Р 34.10-2012 задают кофактор, равный единице
		 *
		 * \~english
		 * @brief Elliptic curve over a field of a prime order
		 * @details The multiplication of a point by a number is performed by a doubling with
		 *          an addition at every bit of the number regardless of its value: the needed
		 *          one of the two points is chosen by an overlay of a mask, therefore the time
		 *          of the work does not depend on the value of the factor
		 * @note The curves with a non-unit cofactor are not supported deliberately: the sets of
		 *       the parameters of GOST R 34.10-2012 give a cofactor equal to a unit
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Curve {
			private:
				// Признак того, что кривая установлена
				bool _ready;
			private:
				// Арифметика поля кривой
				math::modulus_t _field;
				// Арифметика порядка подгруппы точек кривой
				math::modulus_t _order;
			private:
				// Первый коэффициент уравнения кривой
				math::number_t _first;
				// Второй коэффициент уравнения кривой
				math::number_t _second;
			private:
				// Отношение порядка группы точек кривой к порядку подгруппы
				uint64_t _cofactor;
			private:
				// Образующая точка подгруппы точек кривой
				point_t _base;
			private:
				/**
				 * \~russian
				 * @brief Метод сложения точек кривой без ветвления
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое
				 * @param result место, в которое помещается сумма точек
				 *
				 * @note Бесконечная удалённость слагаемых разбирается наложением маски, а не
				 *       ветвлением: метод применяется к точкам, зависящим от секретного числа
				 *
				 * @note Совпадение слагаемых методу не подлежит: в порядке действий умножения
				 *       точки на число накопленная точка равняется умножаемой лишь тогда,
				 *       когда обе бесконечно удалены
				 *
				 * \~english
				 * @brief Method of the addition of the points of the curve without a branch
				 * @param first  the first addend
				 * @param second the second addend
				 * @param result the place the sum of the points is put into
				 * @note The infinite remoteness of the addends is handled by an overlay of a mask
				 *       and not by a branch: the method is applied to the points depending on a secret number
				 * @note The coincidence of the addends is not subject to the method: in the order of
				 *       the operations of the multiplication of a point by a number the accumulated
				 *       point equals the multiplied one only when both are infinitely remote
				 *
				 * \~
				 */
				void attach(const point_t & first, const point_t & second, point_t & result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности кривой к работе
				 *
				 * @return признак того, что кривая установлена
				 *
				 * \~english
				 * @brief Method of checking the readiness of the curve for the work
				 * @return the flag of the curve being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера координаты точки
				 *
				 * @return размер координаты точки в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of a coordinate of a point
				 * @return the size of a coordinate of a point in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения кофактора кривой
				 *
				 * @return отношение порядка группы точек кривой к порядку подгруппы
				 *
				 * @details Кофактор участвует в выработке общего ключа: раздел 4.3 RFC 7836
				 *          множит секретное значение на отношение порядка группы к порядку
				 *          подгруппы. У кривых, заданных в скрученной форме Эдвардса, он
				 *          равен четырём, у прочих наборов - единице
				 *
				 * \~english
				 * @brief Method of getting the cofactor of the curve
				 * @return the ratio of the order of the group of the points of the curve to the order of the subgroup
				 * @details The cofactor takes part in the production of a shared key: the section 4.3
				 *          of RFC 7836 multiplies the secret value by the ratio of the order of the
				 *          group to the order of the subgroup. At the curves given in the twisted
				 *          Edwards form it equals four, at the rest of the sets it equals one
				 *
				 * \~
				 */
				uint64_t cofactor() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения арифметики порядка подгруппы точек кривой
				 *
				 * @return арифметика порядка подгруппы точек кривой
				 *
				 * \~english
				 * @brief Method of getting the arithmetic of the order of the subgroup of the points of the curve
				 * @return the arithmetic of the order of the subgroup of the points of the curve
				 *
				 * \~
				 */
				const math::modulus_t & order() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки параметров кривой
				 *
				 * @param modulus модуль поля кривой
				 * @param first   первый коэффициент уравнения кривой
				 * @param second  второй коэффициент уравнения кривой
				 * @param order   порядок подгруппы точек кривой
				 * @param x        первая координата образующей точки
				 * @param y        вторая координата образующей точки
				 * @param cofactor отношение порядка группы точек кривой к порядку подгруппы
				 *
				 * @return признак успешности установки параметров кривой
				 *
				 * @note Образующая точка проверяется на принадлежность кривой
				 *
				 * \~english
				 * @brief Method of setting the parameters of the curve
				 * @param modulus the modulus of the field of the curve
				 * @param first   the first coefficient of the equation of the curve
				 * @param second  the second coefficient of the equation of the curve
				 * @param order   the order of the subgroup of the points of the curve
				 * @param x        the first coordinate of the generating point
				 * @param y        the second coordinate of the generating point
				 * @param cofactor the ratio of the order of the group of the points of the curve to the order of the subgroup
				 * @return the flag of the success of the setting of the parameters of the curve
				 * @note The generating point is checked for the belonging to the curve
				 *
				 * \~
				 */
				bool start(const view_t & modulus, const view_t & first, const view_t & second, const view_t & order, const view_t & x, const view_t & y, const uint64_t cofactor = 1) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса установленных параметров кривой
				 *
				 * \~english
				 * @brief Method of the reset of the set parameters of the curve
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения образующей точки подгруппы точек кривой
				 *
				 * @param result место, в которое помещается образующая точка
				 *
				 * \~english
				 * @brief Method of getting the generating point of the subgroup of the points of the curve
				 * @param result the place the generating point is put into
				 *
				 * \~
				 */
				void base(point_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод разбора точки из координат
				 *
				 * @param x      первая координата разбираемой точки
				 * @param y      вторая координата разбираемой точки
				 * @param result место, в которое помещается разобранная точка
				 *
				 * @return признак успешности разбора точки
				 *
				 * @note Точка, не принадлежащая кривой, разбору не подлежит
				 *
				 * \~english
				 * @brief Method of the parsing of a point from the coordinates
				 * @param x      the first coordinate of the point being parsed
				 * @param y      the second coordinate of the point being parsed
				 * @param result the place the parsed point is put into
				 * @return the flag of the success of the parsing of the point
				 * @note A point not belonging to the curve is not subject to the parsing
				 *
				 * \~
				 */
				bool point(const view_t & x, const view_t & y, point_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод записи координат точки
				 *
				 * @param value записываемая точка
				 * @param x     место, в которое записывается первая координата точки
				 * @param y     место, в которое записывается вторая координата точки
				 * @param size  размер места, в которое записывается всякая координата
				 *
				 * @return признак успешности записи координат точки
				 *
				 * @note Бесконечно удалённая точка аффинных координат не имеет и записи не подлежит
				 *
				 * \~english
				 * @brief Method of the writing of the coordinates of a point
				 * @param value the point being written
				 * @param x     the place the first coordinate of the point is written into
				 * @param y     the place the second coordinate of the point is written into
				 * @param size  the size of the place every coordinate is written into
				 * @return the flag of the success of the writing of the coordinates of the point
				 * @note The point at infinity has no affine coordinates and is not subject to the writing
				 *
				 * \~
				 */
				bool coordinates(const point_t & value, uint8_t * x, uint8_t * y, const size_t size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки точки на бесконечную удалённость
				 *
				 * @param value проверяемая точка
				 *
				 * @return признак бесконечной удалённости точки
				 *
				 * \~english
				 * @brief Method of checking a point for the infinite remoteness
				 * @param value the point being checked
				 * @return the flag of the infinite remoteness of the point
				 *
				 * \~
				 */
				bool infinity(const point_t & value) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод удвоения точки кривой
				 *
				 * @param value  удваиваемая точка
				 * @param result место, в которое помещается удвоенная точка
				 *
				 * @note Место итога вправе совпадать с местом удваиваемой точки
				 *
				 * \~english
				 * @brief Method of the doubling of a point of the curve
				 * @param value  the point being doubled
				 * @param result the place the doubled point is put into
				 * @note The place of the result may coincide with the place of the point being doubled
				 *
				 * \~
				 */
				void twice(const point_t & value, point_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сложения точек кривой
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое
				 * @param result место, в которое помещается сумма точек
				 *
				 * @note Место итога вправе совпадать с местом всякого слагаемого
				 *
				 * @note Совпадение слагаемых и их противоположность разбираются ветвлением:
				 *       здесь оно допустимо, поскольку метод применяется к общедоступным
				 *       точкам при проверке подписи, тогда как умножение точки на секретное
				 *       число ведётся телом, ветвления лишённым
				 *
				 * \~english
				 * @brief Method of the addition of the points of the curve
				 * @param first  the first addend
				 * @param second the second addend
				 * @param result the place the sum of the points is put into
				 * @note The place of the result may coincide with the place of every addend
				 * @note The coincidence of the addends and their oppositeness are handled by a
				 *       branch: it is admissible here, since the method is applied to the publicly
				 *       available points at the check of a signature, whereas the multiplication of
				 *       a point by a secret number is carried by a body devoid of a branch
				 *
				 * \~
				 */
				void add(const point_t & first, const point_t & second, point_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод умножения точки кривой на число
				 *
				 * @param value  умножаемая точка
				 * @param factor число, на которое умножается точка
				 * @param result место, в которое помещается произведение
				 *
				 * @note Место итога вправе совпадать с местом умножаемой точки
				 *
				 * \~english
				 * @brief Method of the multiplication of a point of the curve by a number
				 * @param value  the point being multiplied
				 * @param factor the number the point is multiplied by
				 * @param result the place the product is put into
				 * @note The place of the result may coincide with the place of the point being multiplied
				 *
				 * \~
				 */
				void multiply(const point_t & value, const math::number_t & factor, point_t & result) const noexcept;
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
				Curve() noexcept;
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
				~Curve() noexcept;
		} curve_t;
	};
};

#endif // __ANYKS_TLS_CURVE__
