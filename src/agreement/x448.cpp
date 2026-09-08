/**
 * @file x448.cpp
 * @date 2026-09-09
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
 * @brief Модуль выработки общего ключа на кривой Curve448 — функция X448 по RFC 7748
 *
 * @details Лестница Монтгомери идёт в общей арифметике по простому модулю: поле
 *          2^448 - 2^224 - 1 занимает семь слов, и отдельной раскладки на конечности,
 *          как у Curve25519, ему не заведено. Умножение по Монтгомери идёт за постоянное
 *          время, выбор точек лестницы - маской без ветвлений
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/x448.hpp>
#include <math/number.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён проекта
	 */
	using namespace nts;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Модуль поля кривой Curve448 от старшего байта к младшему: 2^448 - 2^224 - 1
	 *
	 */
	static const uint8_t MODULUS[agreement::X448_SIZE] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	/**
	 * @brief Множитель удвоения лестницы Монтгомери
	 *
	 * @details Раздел 5 RFC 7748: a24 = (156326 - 2) / 4 = 39081
	 *
	 */
	static constexpr uint64_t A24 = 39081;

	/**
	 * @brief Метод условного обмена двух чисел за постоянное время
	 *
	 * @param first  первое число
	 * @param second второе число
	 * @param swap   признак обмена: единица меняет числа местами, ноль оставляет как есть
	 *
	 */
	static void exchange(math::number_t & first, math::number_t & second, const uint64_t swap) noexcept {
		// Маска обмена: все разряды по признаку
		const uint64_t mask = (0 - swap);
		/**
		 * Выполняем перебор слов чисел
		 */
		for(size_t i = 0; i < math::NUMBER_WORDS; i++){
			// Разность слов под маской
			const uint64_t item = (mask & (first.words[i] ^ second.words[i]));
			// Меняем слово первого числа
			first.words[i] ^= item;
			// Меняем слово второго числа
			second.words[i] ^= item;
		}
	}
	/**
	 * @brief Метод разбора записи младшим байтом вперёд числом поля
	 *
	 * @param field  арифметика поля кривой
	 * @param data   запись младшим байтом вперёд
	 * @param result место, в которое помещается число в области Монтгомери
	 *
	 * @return       признак успешности разбора
	 *
	 */
	static bool decode(const math::modulus_t & field, const uint8_t * data, math::number_t & result) noexcept {
		// Запись старшим байтом вперёд
		uint8_t buffer[agreement::X448_SIZE];
		/**
		 * Выполняем обращение порядка байтов
		 */
		for(size_t i = 0; i < agreement::X448_SIZE; i++)
			// Переносим байт с конца
			buffer[i] = data[agreement::X448_SIZE - 1 - i];
		// Число до приведения в область Монтгомери
		math::number_t plain;
		// Раздел 5 RFC 7748: значения, не меньшие модуля, приводятся по модулю
		const bool ok = field.reduce(view_t(buffer, sizeof(buffer)), plain);
		// Если разбор удался
		if(ok)
			// Приводим число в область Монтгомери
			field.enter(plain, result);
		// Затираем запись
		wipe(buffer, sizeof(buffer));
		// Выводим итог разбора
		return ok;
	}
	/**
	 * @brief Метод умножения точки на скаляр лестницей Монтгомери
	 *
	 * @param field  арифметика поля кривой
	 * @param scalar зажатый скаляр, записанный младшим байтом вперёд
	 * @param point  первая координата множимой точки в области Монтгомери
	 * @param result место, в которое помещается первая координата кратной точки младшим байтом вперёд
	 *
	 * @return       признак того, что кратная точка не обратилась в ноль
	 *
	 */
	static bool ladder(const math::modulus_t & field, const uint8_t * scalar, const math::number_t & point, uint8_t * result) noexcept {
		// Координаты двух точек лестницы
		math::number_t x2, z2, x3, z3;
		// Служебные значения шага
		math::number_t a, aa, b, bb, e, c, d, da, cb, a24;
		// Первая точка лестницы начинается с нейтральной точки: (1, 0)
		field.word(1, x2);
		// Приводим единицу в область Монтгомери
		field.enter(x2, x2);
		// Вторая координата нейтральной точки
		field.word(0, z2);
		// Вторая точка лестницы начинается с множимой точки
		x3 = point;
		// Вторая координата множимой точки
		z3 = x2;
		// Множитель удвоения в области Монтгомери
		field.word(A24, a24);
		// Приводим множитель в область Монтгомери
		field.enter(a24, a24);
		// Накопленный признак обмена точек лестницы
		uint64_t swapped = 0;
		/**
		 * Выполняем обход разрядов скаляра от 447-го к нулевому
		 */
		for(size_t i = 448; i > 0; i--){
			// Номер очередного разряда скаляра
			const size_t index = (i - 1);
			// Значение очередного разряда скаляра
			const uint64_t bit = ((scalar[index / 8] >> (index % 8)) & 1);
			// Складываем признак обмена с очередным разрядом
			swapped ^= bit;
			// Выполняем условный обмен первых координат точек
			exchange(x2, x3, swapped);
			// Выполняем условный обмен вторых координат точек
			exchange(z2, z3, swapped);
			// Запоминаем признак обмена
			swapped = bit;
			// A = x2 + z2
			field.add(x2, z2, a);
			// AA = A^2
			field.multiply(a, a, aa);
			// B = x2 - z2
			field.subtract(x2, z2, b);
			// BB = B^2
			field.multiply(b, b, bb);
			// E = AA - BB
			field.subtract(aa, bb, e);
			// C = x3 + z3
			field.add(x3, z3, c);
			// D = x3 - z3
			field.subtract(x3, z3, d);
			// DA = D * A
			field.multiply(d, a, da);
			// CB = C * B
			field.multiply(c, b, cb);
			// x3 = (DA + CB)^2
			field.add(da, cb, x3);
			// Возводим в квадрат
			field.multiply(x3, x3, x3);
			// z3 = x1 * (DA - CB)^2
			field.subtract(da, cb, z3);
			// Возводим в квадрат
			field.multiply(z3, z3, z3);
			// Умножаем на первую координату множимой точки
			field.multiply(z3, point, z3);
			// x2 = AA * BB
			field.multiply(aa, bb, x2);
			// z2 = E * (AA + a24 * E)
			field.multiply(a24, e, z2);
			// Складываем с AA
			field.add(aa, z2, z2);
			// Умножаем на E
			field.multiply(e, z2, z2);
		}
		// Заключительный условный обмен
		exchange(x2, x3, swapped);
		// Заключительный условный обмен вторых координат
		exchange(z2, z3, swapped);
		// Обращаем вторую координату
		field.invert(z2, z2);
		// Делим первую координату на вторую
		field.multiply(x2, z2, x2);
		// Выводим число из области Монтгомери
		field.leave(x2, x2);
		// Признак ненулевого итога
		const bool nonzero = !field.zero(x2);
		// Запись старшим байтом вперёд
		uint8_t buffer[agreement::X448_SIZE];
		// Записываем число
		const bool stored = field.store(x2, buffer, sizeof(buffer));
		/**
		 * Выполняем обращение порядка байтов
		 */
		for(size_t i = 0; i < agreement::X448_SIZE; i++)
			// Переносим байт с конца
			result[i] = buffer[agreement::X448_SIZE - 1 - i];
		// Затираем служебные значения
		wipe(&x2, sizeof(x2));
		wipe(&z2, sizeof(z2));
		wipe(&x3, sizeof(x3));
		wipe(&z3, sizeof(z3));
		wipe(&a, sizeof(a));
		wipe(&aa, sizeof(aa));
		wipe(&b, sizeof(b));
		wipe(&bb, sizeof(bb));
		wipe(&e, sizeof(e));
		wipe(&c, sizeof(c));
		wipe(&d, sizeof(d));
		wipe(&da, sizeof(da));
		wipe(&cb, sizeof(cb));
		wipe(buffer, sizeof(buffer));
		// Выводим итог
		return (stored && nonzero);
	}
	/**
	 * @brief Метод умножения первой координаты точки на секретный ключ
	 *
	 * @param secret секретный ключ младшим байтом вперёд
	 * @param point  первая координата точки младшим байтом вперёд
	 * @param result место, в которое помещается первая координата кратной точки
	 *
	 * @return       признак того, что итог не обратился в ноль
	 *
	 */
	static bool multiply(const uint8_t * secret, const uint8_t * point, uint8_t * result) noexcept {
		// Арифметика поля кривой
		math::modulus_t field;
		// Если модуль поля установить не удалось
		if(!field.start(view_t(MODULUS, sizeof(MODULUS))))
			// Выводим отказ
			return false;
		// Зажатый скаляр
		uint8_t scalar[agreement::X448_SIZE];
		// Переносим секретный ключ
		::memcpy(scalar, secret, sizeof(scalar));
		// Раздел 5 RFC 7748: сбрасываем два младших разряда
		scalar[0] &= 252;
		// Ставим разряд 447
		scalar[55] |= 128;
		// Первая координата точки
		math::number_t u;
		// Признак итога
		bool ok = decode(field, point, u);
		// Если координата разобрана
		if(ok)
			// Выполняем умножение лестницей
			ok = ladder(field, scalar, u, result);
		// Затираем скаляр
		wipe(scalar, sizeof(scalar));
		// Затираем координату
		wipe(&u, sizeof(u));
		// Выводим итог
		return ok;
	}
};

/**
 * @brief Метод выработки общего значения на кривой Curve448
 *
 * @param secret секретный ключ своей стороны длиной в пятьдесят шесть байтов
 * @param point  открытый ключ встречной стороны длиной в пятьдесят шесть байтов
 * @param result место, в которое помещается общее значение длиной в пятьдесят шесть байтов
 *
 * @return       признак успешности выработки общего значения
 *
 */
bool nts::agreement::x448(const view_t & secret, const view_t & point, uint8_t * result) noexcept {
	// Если место общего значения не передано
	if(result == nullptr)
		// Выводим отказ выработки общего значения
		return false;
	// Если секретный ключ передан длиной не в пятьдесят шесть байтов
	if((secret.data == nullptr) || (secret.size != X448_SIZE))
		// Выводим отказ выработки общего значения
		return false;
	// Если открытый ключ передан длиной не в пятьдесят шесть байтов
	if((point.data == nullptr) || (point.size != X448_SIZE))
		// Выводим отказ выработки общего значения
		return false;
	// Выполняем умножение открытого ключа на секретный
	const bool ok = multiply(secret.data, point.data, result);
	// Если общее значение обратилось в ноль
	if(!ok)
		// Выполняем затирание места общего значения
		wipe(result, X448_SIZE);
	// Выводим признак успешности выработки общего значения
	return ok;
}
/**
 * @brief Метод выработки открытого ключа на кривой Curve448
 *
 * @param secret секретный ключ длиной в пятьдесят шесть байтов
 * @param result место, в которое помещается открытый ключ длиной в пятьдесят шесть байтов
 *
 * @return       признак успешности выработки открытого ключа
 *
 */
bool nts::agreement::x448(const view_t & secret, uint8_t * result) noexcept {
	// Если место открытого ключа не передано
	if(result == nullptr)
		// Выводим отказ выработки открытого ключа
		return false;
	// Если секретный ключ передан длиной не в пятьдесят шесть байтов
	if((secret.data == nullptr) || (secret.size != X448_SIZE))
		// Выводим отказ выработки открытого ключа
		return false;
	// Точка основания кривой: первая координата пять
	uint8_t base[X448_SIZE] = {5};
	// Выполняем умножение точки основания на секретный ключ
	const bool ok = multiply(secret.data, base, result);
	// Если открытый ключ обратился в ноль
	if(!ok)
		// Выполняем затирание места открытого ключа
		wipe(result, X448_SIZE);
	// Выводим признак успешности выработки открытого ключа
	return ok;
}
/**
 * @brief Метод порождения пары ключей на кривой Curve448
 *
 * @param secret место, в которое помещается секретный ключ длиной в пятьдесят шесть байтов
 * @param key    место, в которое помещается открытый ключ длиной в пятьдесят шесть байтов
 *
 * @return       признак успешности порождения пары ключей
 *
 */
bool nts::agreement::pair448(uint8_t * secret, uint8_t * key) noexcept {
	// Если места ключей не переданы
	if((secret == nullptr) || (key == nullptr))
		// Выводим отказ порождения пары ключей
		return false;
	// Если случайные байты секретного ключа получить не удалось
	if(!entropy::bytes(secret, X448_SIZE)){
		// Выполняем затирание места секретного ключа
		wipe(secret, X448_SIZE);
		// Выполняем затирание места открытого ключа
		wipe(key, X448_SIZE);
		// Выводим отказ порождения пары ключей
		return false;
	}
	// Раздел 5 RFC 7748: сбрасываем два младших разряда
	secret[0] &= 252;
	// Ставим разряд 447
	secret[55] |= 128;
	// Если открытый ключ выработать не удалось
	if(!x448(view_t(secret, X448_SIZE), key)){
		// Выполняем затирание места секретного ключа
		wipe(secret, X448_SIZE);
		// Выводим отказ порождения пары ключей
		return false;
	}
	// Выводим успешность порождения пары ключей
	return true;
}
