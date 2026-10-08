/**
 * @file curve.hpp
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
namespace nts {
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
		 * @note Координаты хранятся в области поля кривой: у общего пути и P-256 это область
		 *       Монтгомери, у простых вида 2^k ± c числа лежат как есть (см. math::Modulus)
		 *
		 * \~english
		 * @brief Point of an elliptic curve
		 * @details The point is stored in the Jacobi coordinates: the affine coordinates
		 *          come out by a division by the square and the cube of the third coordinate,
		 *          therefore the addition of the points goes without an inversion by the
		 *          modulus, the most expensive of the operations. A zero third coordinate
		 *          means the point at infinity.
		 * @note The coordinates are stored in the domain of the field of the curve: at the general
		 *       path and P-256 it is the Montgomery domain, at the primes of the form 2^k ± c the
		 *       numbers lie as they are (see math::Modulus)
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Point {
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
		 * @note Кривые с кофактором больше единицы (наборы ГОСТ Р 34.10-2012 с кофактором 4)
		 *       ведутся: точка вне подгруппы порядка q отсекается при загрузке умножением на
		 *       порядок (раздел 5.2 ГОСТ Р 34.10-2012), у кривых с кофактором единица
		 *       принадлежность подгруппе следует из уравнения кривой
		 *
		 * @note Формулы точек на полях в четыре и восемь слов встраивают ядра арифметики
		 *       поля прямо в своё тело (внутренний заголовок ядер, устройство модуля из
		 *       layout), а прочие ширины идут через объект арифметики: вызов через границу
		 *       модуля стоил до трети умножения и половины сложения, при восьми умножениях и
		 *       девяти сложениях на удвоение. Перебор заготовленных кратных при этом ведётся в
		 *       накопителях по числу слов, а не в памяти. Замер 21.09.2026 (M4): удвоение
		 *       148 → 114 нс, подпись ГОСТ 32 240 → 67 510 в секунду вместе с прочими
		 *       правками того же дня
		 * @note Формулы точек собираются из ядер на значениях поля в регистрах, а не на
		 *       числах в памяти, как ассемблерные формулы OpenSSL (ecp_nistz256): стык двух
		 *       ядер не стоит записи с чтением. Умножение на секретное число идёт знаковыми
		 *       окнами по пять разрядов (кодирование Бута), точка основания - заготовленными
		 *       знаковыми окнами по шесть, сумма двух произведений сличения подписи - порознь
		 *       с одним сложением, выборка кратных - векторно. Замер 22.09.2026 (M4): удвоение
		 *       80 → 57 нс при 53 у nistz256, подпись ГОСТ 79 700 → 134 000 в секунду при
		 *       83 000 у ECDSA P-256 OpenSSL, обмен ключами 26 800 → 41 600 при 38 400
		 *
		 * \~english
		 * @brief Elliptic curve over a field of a prime order
		 * @details The multiplication of a point by a number is performed by a doubling with
		 *          an addition at every bit of the number regardless of its value: the needed
		 *          one of the two points is chosen by an overlay of a mask, therefore the time
		 *          of the work does not depend on the value of the factor
		 * @note The curves with a cofactor above a unit (the sets of GOST R 34.10-2012 with a
		 *       cofactor of 4) are carried: a point outside the subgroup of the order q is rejected
		 *       at the load by a multiplication by the order (section 5.2 of GOST R 34.10-2012),
		 *       at the curves with a unit cofactor the membership follows from the equation of the curve
		 * @note The formulas of the points on the fields of four and eight words inline the kernels
		 *       of the field arithmetic right into their body (the internal header of the kernels,
		 *       the layout of the modulus from layout), while the rest of the widths go through the
		 *       arithmetic object: a call across the module boundary cost up to a third of a
		 *       multiplication and a half of an addition, at eight multiplications and nine additions
		 *       per doubling. The scanning of the precomputed multiples goes in the accumulators by the
		 *       number of words rather than in memory. Measurement of 21.09.2026 (M4): a doubling
		 *       148 → 114 ns, a GOST signature 32 240 → 67 510 per second together with the other
		 *       changes of the same day
		 * @note The formulas of the points are assembled from the kernels on the values of the field
		 *       in the registers rather than on the numbers in memory, like the assembly formulas of
		 *       OpenSSL (ecp_nistz256): a junction of two kernels does not cost a store with a load.
		 *       The multiplication by a secret number goes by the signed windows of five bits (the
		 *       Booth recoding), the base point by the precomputed signed windows of six bits, the sum
		 *       of two products of the signature verification separately with one addition, the
		 *       selection of the multiples by vectors. Measurement of 22.09.2026 (M4): a doubling
		 *       80 → 57 ns at 53 of nistz256, a GOST signature 79 700 → 134 000 per second at 83 000
		 *       of ECDSA P-256 of OpenSSL, a key exchange 26 800 → 41 600 at 38 400
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Curve {
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
				// Признак того, что первый коэффициент равен модулю без трёх
				bool _shortened;
				// Второй коэффициент уравнения кривой
				math::number_t _second;
			private:
				// Отношение порядка группы точек кривой к порядку подгруппы
				uint64_t _cofactor;
			private:
				// Образующая точка подгруппы точек кривой
				point_t _base;
			private:
				// Единица поля кривой в области Монтгомери
				math::number_t _unit;
			private:
				// Заготовленные кратные точки основания либо nullptr у их отсутствия
				const void * _multiples;
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
			private:
				/**
				 * \~russian
				 * @brief Метод сложения точек кривой с аффинным вторым слагаемым
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое, третья координата которого равна единице поля
				 * @param result место, в которое помещается сумма точек
				 *
				 * @note Единичная третья координата второго слагаемого снимает со сложения пять
				 *       умножений поля из двенадцати: приведение обеих координат первого
				 *       слагаемого и умножение третьих координат обращаются в переписывание
				 *
				 * @note Бесконечная удалённость слагаемых разбирается наложением маски, а не
				 *       ветвлением, ровно как у сложения общего вида
				 *
				 * \~english
				 * @brief Method of the addition of the points of the curve with an affine second addend
				 * @param first  the first addend
				 * @param second the second addend the third coordinate of which equals the unit of the field
				 * @param result the place the sum of the points is put into
				 * @note The unit third coordinate of the second addend removes five multiplications
				 *       of the field out of twelve from the addition: the reduction of both coordinates
				 *       of the first addend and the multiplication of the third coordinates turn into a copy
				 * @note The infinite remoteness of the addends is handled by an overlay of a mask
				 *       and not by a branch exactly as in the addition of the general kind
				 *
				 * \~
				 */
				void join(const point_t & first, const point_t & second, point_t & result) const noexcept;
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
				 * @param x        первая координата разбираемой точки
				 * @param y        вторая координата разбираемой точки
				 * @param result   место, в которое помещается разобранная точка
				 * @param subgroup признак проверки принадлежности точки подгруппе порядка q
				 *
				 * @return признак успешности разбора точки
				 *
				 * @note Точка, не принадлежащая кривой, разбору не подлежит при любом значении
				 *       признака подгруппы: принадлежность кривой проверяется всегда
				 *
				 * @note Принадлежность подгруппе порядка q у кривых с кофактором больше единицы
				 *       стоит умножения точки на порядок (полное умножение точки: 30 мкс на 256
				 *       разрядах и 245 на 512 у M4) и нужна ключу проверки подписи по разделу 5.2
				 *       ГОСТ Р 34.10-2012. Потребитель, снимающий кручение сам, вправе её не
				 *       просить: обмен ключами по разделу 6.1.1 RFC 9367 и выработка ключа VKO по
				 *       разделу 4.3 RFC 7836 множат кофактором, и от точки требуют лишь
				 *       принадлежности кривой. У кривых с кофактором единица признак ничего не
				 *       меняет: там всякая точка кривой лежит в подгруппе
				 *
				 * \~english
				 * @brief Method of the parsing of a point from the coordinates
				 * @param x        the first coordinate of the point being parsed
				 * @param y        the second coordinate of the point being parsed
				 * @param result   the place the parsed point is put into
				 * @param subgroup the flag of checking that the point belongs to the subgroup of the order q
				 * @return the flag of the success of the parsing of the point
				 * @note A point not belonging to the curve is not subject to the parsing whatever the value of
				 *       the subgroup flag: the belonging to the curve is always checked
				 * @note On the curves with a cofactor above one the belonging to the subgroup of the order q
				 *       costs a multiplication of the point by the order (a full point multiplication: 30 us on
				 *       256 bits and 245 on 512 on M4) and is needed for a signature verification key by the
				 *       section 5.2 of GOST R 34.10-2012. A consumer clearing the torsion itself is free not to
				 *       ask for it: the key exchange of the section 6.1.1 of RFC 9367 and the VKO key derivation
				 *       of the section 4.3 of RFC 7836 multiply by the cofactor and require of the point only
				 *       the belonging to the curve. On the curves with the cofactor one the flag changes nothing:
				 *       there every point of the curve lies in the subgroup
				 *
				 * \~
				 */
				bool point(const view_t & x, const view_t & y, point_t & result, const bool subgroup = true) const noexcept;
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
				/**
				 * \~russian
				 * @brief Метод умножения точки основания кривой на число
				 *
				 * @param factor число, на которое умножается точка основания
				 * @param result место, в которое помещается произведение
				 *
				 * @note Точка основания у кривой одна и известна заранее, оттого кратные её
				 *       заготавливаются при сборке библиотеки: умножение обращается в перебор
				 *       заготовленного, и удвоений не остаётся вовсе
				 *
				 * @note Окно множителя - пять разрядов: у 256 разрядов выходит 52 окна и 52
				 *       смешанных сложения вместо 64 при четырёх, строка окна - 31 кратное, и
				 *       перебирается она целиком наложением маски в накопителях по числу слов;
				 *       окно вправе лежать через границу слова, а старшее окно неполно
				 *
				 * @note У кривой, кратные которой не заготовлены, метод отступает к общему
				 *       умножению точки на число, и итог от этого не меняется
				 *
				 * \~english
				 * @brief Method of the multiplication of the base point of the curve by a number
				 * @param factor the number the base point is multiplied by
				 * @param result the place the product is put into
				 * @note The base point of a curve is the only one and is known beforehand, therefore
				 *       its multiples are precomputed at the build of the library: the multiplication
				 *       turns into the scanning of the precomputed ones, and no doublings are left at all
				 * @note The window of the factor is five bits: at 256 bits it makes 52 windows and 52
				 *       mixed additions instead of 64 at four, the row of a window holds 31 multiples, and
				 *       it is scanned whole by an overlay of a mask in the accumulators by the number of
				 *       words; a window may lie across the boundary of a word, and the top window is partial
				 * @note At a curve the multiples of which are not precomputed the method falls back to
				 *       the general multiplication of a point by a number, and the result does not
				 *       change because of that
				 *
				 * \~
				 */
				void product(const math::number_t & factor, point_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод счёта суммы двух произведений точек кривой на числа
				 *
				 * @param first  первая умножаемая точка
				 * @param single число, на которое умножается первая точка
				 * @param second вторая умножаемая точка
				 * @param pair   число, на которое умножается вторая точка
				 * @param result место, в которое помещается сумма произведений
				 *
				 * @details Оба произведения считаются разом единым перебором разрядов: удвоения
				 *          у них общие, и обходится сумма вдвое дешевле двух умножений порознь.
				 *
				 * @warning Время работы здесь зависит от чисел, и для секретных чисел метод
				 *          негоден вовсе: он положен лишь сличению подписи, где и числа, и
				 *          точки открыты обеим сторонам и подслушивающему
				 *
				 * \~english
				 * @brief Method of the computation of the sum of two products of points of the curve by numbers
				 * @param first  the first point being multiplied
				 * @param single the number the first point is multiplied by
				 * @param second the second point being multiplied
				 * @param pair the number the second point is multiplied by
				 * @param result the place the sum of the products is put into
				 * @details Both products are computed at once by a single traversal of the bits: their
				 *          doublings are common, and the sum costs twice as little as two separate
				 *          multiplications.
				 * @warning The time of the work here depends on the numbers, and the method is not
				 *          suitable for secret numbers at all: it is intended only for the check of a
				 *          signature, where both the numbers and the points are open to both sides and
				 *          to an eavesdropper
				 *
				 * \~
				 */
				void combine(const point_t & first, const math::number_t & single, const point_t & second, const math::number_t & pair, point_t & result) const noexcept;
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

