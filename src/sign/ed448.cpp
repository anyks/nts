/**
 * @file ed448.cpp
 * @date 2026-10-07
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
 * @brief Исходный файл модуля выработки и проверки электронной подписи Ed448
 *
 * @section Намеренные решения
 *
 * 1. Поле кривой 2^448 - 2^224 - 1 и порядок подгруппы взяты у общего модуля чисел
 *    библиотеки: он выполняет сложение, вычитание, умножение и обращение Монтгомери
 *    за постоянное время, а своё поле с особыми переносами обошлось бы сотнями строк
 *    ради того же итога. Записи там идут от старшего байта, оттого на границе разворот.
 *
 * 2. Точки кривой держатся в расширенных координатах (X, Y, Z, T) со сложением и
 *    удвоением по разделу 5.2.4 RFC 8032 при коэффициенте a = 1. Сложение на
 *    скрученной кривой Эдвардса полное: оно верно и при равных точках, и при
 *    нейтральной точке, оттого лестница умножения не ветвится по значению.
 *
 * 3. Умножение на секретный скаляр идёт лестницей за постоянное время: на всяком из
 *    448 разрядов выполняются одно сложение и одно удвоение, а выбор пары делается
 *    условным обменом координат по маске. Раздел 5.2.5 RFC 8032 ставит разряд 447
 *    скаляра, но скаляр r выработки подписи приведён по порядку подгруппы и такого
 *    разряда не имеет, оттого обход идёт по всем 448 разрядам без исключений.
 *
 * 4. Проверка подписи идёт без умножения на кофактор: сличается [S]B с R + [k]A, как
 *    разрешает раздел 5.2.7 RFC 8032. Скаляр S не меньше L отвергается, чем и
 *    закрывается ковкость подписи. Проверка секретов не касается, оттого её умножения
 *    вправе идти тою же лестницей без вреда, а сличение точек выполняется по их сжатым
 *    записям: сжатие каноническое, и равные точки дают равные записи.
 *
 * 5. Разбор сжатой точки отвергает вторую координату, записанную не меньшей модуля,
 *    и первую координату, обратившуюся в ноль при поставленном разряде знака: обе
 *    записи не каноничны, и раздел 5.2.3 RFC 8032 велит их отвергать. Корень первой
 *    координаты берётся возведением в степень (p + 1) / 4, ибо поле сравнимо с тремя
 *    по модулю четырёх.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/ed448.hpp>
#include <digest/sha3.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * @brief Размер записи скаляра и точки в байтах
	 *
	 */
	static constexpr size_t RECORD = sign::ed448_t::KEY_SIZE;

	/**
	 * @brief Размер выхода функции SHAKE256 в байтах
	 *
	 */
	static constexpr size_t DIGEST = 114;

	/**
	 * @brief Модуль поля кривой 2^448 - 2^224 - 1, записанный от старшего байта
	 *
	 * @details Поле занимает четыреста сорок восемь разрядов - пятьдесят шесть байтов
	 *
	 */
	static const uint8_t FIELD[] = {
		// Записываем модуль поля от старшего байта
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	/**
	 * @brief Порядок подгруппы точек кривой L, записанный от старшего байта
	 *
	 * @details L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885;
	 *          порядок занимает пятьдесят шесть байтов, младший байт нечётный
	 *
	 */
	static const uint8_t ORDER[] = {
		// Записываем порядок подгруппы от старшего байта
		0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
		0xC4, 0x4E, 0xDB, 0x49, 0xAE, 0xD6, 0x36, 0x90,
		0x21, 0x6C, 0xC2, 0x72, 0x8D, 0xC5, 0x8F, 0x55,
		0x23, 0x78, 0xC2, 0x92, 0xAB, 0x58, 0x44, 0xF3
	};

	/**
	 * @brief Коэффициент кривой d, записанный младшим байтом вперёд
	 *
	 * @details d = -39081 по модулю поля
	 *
	 */
	static const uint8_t COEFFICIENT[RECORD] = {
		// Записываем коэффициент младшим байтом вперёд
		0x56, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
	};

	/**
	 * @brief Первая координата точки основания, записанная младшим байтом вперёд
	 *
	 */
	static const uint8_t BASE_X[RECORD] = {
		// Записываем первую координату точки основания младшим байтом вперёд
		0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26,
		0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B, 0x43,
		0x11, 0x65, 0xB6, 0x2A, 0xF7, 0x1A, 0xAE, 0x12,
		0x64, 0xA4, 0xD3, 0xA3, 0x24, 0xE3, 0x6D, 0xEA,
		0x67, 0x17, 0x0F, 0x47, 0x70, 0x65, 0x14, 0x9E,
		0xDA, 0x36, 0xBF, 0x22, 0xA6, 0x15, 0x1D, 0x22,
		0xED, 0x0D, 0xED, 0x6B, 0xC6, 0x70, 0x19, 0x4F, 0x00
	};

	/**
	 * @brief Вторая координата точки основания, записанная младшим байтом вперёд
	 *
	 */
	static const uint8_t BASE_Y[RECORD] = {
		// Записываем вторую координату точки основания младшим байтом вперёд
		0x14, 0xFA, 0x30, 0xF2, 0x5B, 0x79, 0x08, 0x98,
		0xAD, 0xC8, 0xD7, 0x4E, 0x2C, 0x13, 0xBD, 0xFD,
		0xC4, 0x39, 0x7C, 0xE6, 0x1C, 0xFF, 0xD3, 0x3A,
		0xD7, 0xC2, 0xA0, 0x05, 0x1E, 0x9C, 0x78, 0x87,
		0x40, 0x98, 0xA3, 0x6C, 0x73, 0x73, 0xEA, 0x4B,
		0x62, 0xC7, 0xC9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xBC, 0xB6, 0x6E, 0x71, 0x46, 0x3F, 0x69, 0x00
	};

	/**
	 * @brief Строка разграничения области dom4 для чистой подписи без контекста
	 *
	 * @details Раздел 5.2.6 RFC 8032: "SigEd448" ‖ флаг предхеширования 0 ‖ длина контекста 0
	 *
	 */
	static const uint8_t DOM4[] = {'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00};

	/**
	 * @brief Точка кривой в расширенных координатах
	 *
	 * @details Точка (x, y) представлена как (X, Y, Z, T) с x = X / Z, y = Y / Z
	 *          и x * y = T / Z
	 *
	 */
	typedef struct Point {
		// Координаты точки
		math::number_t x, y, z, t;
	} point_t;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Арифметика поля кривой, заведённая один раз
	 *
	 * @return арифметика поля кривой
	 *
	 */
	static const math::modulus_t & field() noexcept {
		// Арифметика поля кривой
		static math::modulus_t arithmetic;
		// Признак заведения арифметики
		static bool ready = arithmetic.start(view_t(FIELD, sizeof(FIELD)));
		// Подавляем предупреждение о неиспользуемом значении
		(void) ready;
		// Выводим арифметику поля кривой
		return arithmetic;
	}
	/**
	 * @brief Функция разворота записи числа
	 *
	 * @param source разворачиваемая запись числа
	 * @param result место, в которое помещается развёрнутая запись числа
	 * @param size   длина записи числа в байтах
	 *
	 */
	static void reverse(const uint8_t * source, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов записи числа
		 */
		for(size_t i = 0; i < size; i++)
			// Переносим очередной байт записи числа
			result[i] = source[size - i - 1];
	}
	/**
	 * @brief Функция разбора константы поля, записанной младшим байтом вперёд
	 *
	 * @param source запись константы младшим байтом вперёд
	 * @param result место, в которое помещается число в области Монтгомери
	 *
	 * @details Константа записана пятьюдесятью семью байтами со старшим нулевым байтом:
	 *          значение координаты меньше поля и укладывается в пятьдесят шесть байтов,
	 *          оттого разбираются лишь младшие пятьдесят шесть
	 *
	 */
	static void load(const uint8_t * source, math::number_t & result) noexcept {
		// Развёрнутая запись константы
		uint8_t buffer[RECORD];
		// Выполняем разворот записи константы от старшего байта
		reverse(source, buffer, RECORD);
		// Выполняем разбор константы: значение укладывается в пятьдесят шесть байтов
		field().load(view_t(buffer + 1, RECORD - 1), result);
		// Выполняем приведение константы в область Монтгомери
		field().enter(result, result);
		// Выполняем затирание развёрнутой записи
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Функция получения машинного слова поля в области Монтгомери
	 *
	 * @param value  машинное слово
	 * @param result место, в которое помещается число в области Монтгомери
	 *
	 */
	static void word(const uint64_t value, math::number_t & result) noexcept {
		// Записываем машинное слово
		field().word(value, result);
		// Выполняем приведение числа в область Монтгомери
		field().enter(result, result);
	}
	/**
	 * @brief Функция получения нейтральной точки
	 *
	 * @param result место, в которое помещается нейтральная точка
	 *
	 */
	static void neutral(point_t & result) noexcept {
		// Первая координата нейтральной точки - ноль
		word(0, result.x);
		// Вторая координата нейтральной точки - единица
		word(1, result.y);
		// Знаменатель нейтральной точки - единица
		word(1, result.z);
		// Произведение координат нейтральной точки - ноль
		word(0, result.t);
	}
	/**
	 * @brief Функция получения точки основания
	 *
	 * @param result место, в которое помещается точка основания
	 *
	 */
	static void base(point_t & result) noexcept {
		// Арифметика поля кривой
		const math::modulus_t & arithmetic = field();
		// Выполняем разбор первой координаты точки основания
		load(BASE_X, result.x);
		// Выполняем разбор второй координаты точки основания
		load(BASE_Y, result.y);
		// Знаменатель точки основания - единица
		word(1, result.z);
		// Произведение координат точки основания
		arithmetic.multiply(result.x, result.y, result.t);
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
	static void add(const point_t & first, const point_t & second, point_t & result) noexcept {
		// Арифметика поля кривой
		const math::modulus_t & arithmetic = field();
		// Промежуточные значения сложения
		math::number_t a, b, c, d, e, f, g, h, item;
		// Вырабатываем произведение первых координат
		arithmetic.multiply(first.x, second.x, a);
		// Вырабатываем произведение вторых координат
		arithmetic.multiply(first.y, second.y, b);
		// Вырабатываем произведение четвёртых координат
		arithmetic.multiply(first.t, second.t, c);
		// Загружаем коэффициент кривой
		load(COEFFICIENT, item);
		// Вырабатываем произведение четвёртых координат на коэффициент
		arithmetic.multiply(c, item, c);
		// Вырабатываем произведение знаменателей
		arithmetic.multiply(first.z, second.z, d);
		// Вырабатываем сумму координат первого слагаемого
		arithmetic.add(first.x, first.y, e);
		// Вырабатываем сумму координат второго слагаемого
		arithmetic.add(second.x, second.y, item);
		// Вырабатываем произведение сумм координат
		arithmetic.multiply(e, item, e);
		// Вычитаем из произведения сумм произведение первых координат
		arithmetic.subtract(e, a, e);
		// Вычитаем из произведения сумм произведение вторых координат
		arithmetic.subtract(e, b, e);
		// Вырабатываем разность произведений знаменателей и четвёртых координат
		arithmetic.subtract(d, c, f);
		// Вырабатываем сумму произведений знаменателей и четвёртых координат
		arithmetic.add(d, c, g);
		// Вычитаем из произведения вторых координат произведение первых: коэффициент a равен единице
		arithmetic.subtract(b, a, h);
		// Первая координата суммы точек
		arithmetic.multiply(e, f, result.x);
		// Вторая координата суммы точек
		arithmetic.multiply(g, h, result.y);
		// Четвёртая координата суммы точек
		arithmetic.multiply(e, h, result.t);
		// Знаменатель суммы точек
		arithmetic.multiply(f, g, result.z);
		// Выполняем затирание промежуточных значений сложения
		wipe(item.words, sizeof(item.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(h.words, sizeof(h.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(g.words, sizeof(g.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(f.words, sizeof(f.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(e.words, sizeof(e.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(d.words, sizeof(d.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(c.words, sizeof(c.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(b.words, sizeof(b.words));
		// Выполняем затирание промежуточных значений сложения
		wipe(a.words, sizeof(a.words));
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
	static void twice(const point_t & value, point_t & result) noexcept {
		// Арифметика поля кривой
		const math::modulus_t & arithmetic = field();
		// Промежуточные значения удвоения
		math::number_t a, b, c, e, f, g, h;
		// Вырабатываем квадрат первой координаты
		arithmetic.square(value.x, a);
		// Вырабатываем квадрат второй координаты
		arithmetic.square(value.y, b);
		// Вырабатываем квадрат знаменателя
		arithmetic.square(value.z, c);
		// Вырабатываем удвоенный квадрат знаменателя
		arithmetic.add(c, c, c);
		// Вырабатываем сумму координат
		arithmetic.add(value.x, value.y, e);
		// Вырабатываем квадрат суммы координат
		arithmetic.square(e, e);
		// Вычитаем из квадрата суммы квадрат первой координаты
		arithmetic.subtract(e, a, e);
		// Вычитаем из квадрата суммы квадрат второй координаты
		arithmetic.subtract(e, b, e);
		// Вырабатываем сумму квадрата первой координаты и квадрата второй: коэффициент a равен единице
		arithmetic.add(a, b, g);
		// Вырабатываем разность этой суммы и удвоенного квадрата знаменателя
		arithmetic.subtract(g, c, f);
		// Вырабатываем разность квадрата первой координаты и квадрата второй
		arithmetic.subtract(a, b, h);
		// Первая координата удвоенной точки
		arithmetic.multiply(e, f, result.x);
		// Вторая координата удвоенной точки
		arithmetic.multiply(g, h, result.y);
		// Четвёртая координата удвоенной точки
		arithmetic.multiply(e, h, result.t);
		// Знаменатель удвоенной точки
		arithmetic.multiply(f, g, result.z);
		// Выполняем затирание промежуточных значений удвоения
		wipe(h.words, sizeof(h.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(g.words, sizeof(g.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(f.words, sizeof(f.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(e.words, sizeof(e.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(c.words, sizeof(c.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(b.words, sizeof(b.words));
		// Выполняем затирание промежуточных значений удвоения
		wipe(a.words, sizeof(a.words));
	}
	/**
	 * @brief Функция условного обмена чисел по маске
	 *
	 * @param first  первое обмениваемое число
	 * @param second второе обмениваемое число
	 * @param flag   признак обмена: ноль либо единица
	 *
	 */
	static void swap(math::number_t & first, math::number_t & second, const uint64_t flag) noexcept {
		// Маска обмена: все разряды по признаку
		const uint64_t mask = (0 - flag);
		/**
		 * Выполняем перебор слов чисел
		 */
		for(size_t i = 0; i < math::NUMBER_WORDS; i++){
			// Разность слов обмениваемых чисел
			const uint64_t item = (mask & (first.words[i] ^ second.words[i]));
			// Обмениваем очередное слово первого числа
			first.words[i] ^= item;
			// Обмениваем очередное слово второго числа
			second.words[i] ^= item;
		}
	}
	/**
	 * @brief Функция условного обмена точек
	 *
	 * @param first  первая обмениваемая точка
	 * @param second вторая обмениваемая точка
	 * @param flag   признак обмена
	 *
	 */
	static void exchange(point_t & first, point_t & second, const uint64_t flag) noexcept {
		// Выполняем условный обмен первых координат
		swap(first.x, second.x, flag);
		// Выполняем условный обмен вторых координат
		swap(first.y, second.y, flag);
		// Выполняем условный обмен знаменателей
		swap(first.z, second.z, flag);
		// Выполняем условный обмен четвёртых координат
		swap(first.t, second.t, flag);
	}
	/**
	 * @brief Функция умножения точки на скаляр за постоянное время
	 *
	 * @details Лестница по всем 448 разрядам скаляра: на всяком разряде одно сложение
	 *          и одно удвоение, выбор пары - условным обменом по маске
	 *
	 * @param scalar скаляр, записанный младшим байтом вперёд
	 * @param point  множимая точка
	 * @param result место, в которое помещается кратная точка
	 *
	 */
	static void multiply(const uint8_t * scalar, const point_t & point, point_t & result) noexcept {
		// Пара точек лестницы
		point_t first, second;
		// Первая точка лестницы начинается с нейтральной
		neutral(first);
		// Вторая точка лестницы начинается с множимой
		second = point;
		// Накопленный признак обмена точек лестницы
		uint64_t swapped = 0;
		/**
		 * Выполняем обход разрядов скаляра от старшего к младшему
		 */
		for(size_t i = (RECORD * 8); i > 0; i--){
			// Номер очередного разряда скаляра
			const size_t index = (i - 1);
			// Значение очередного разряда скаляра
			const uint64_t bit = ((scalar[index / 8] >> (index % 8)) & 1);
			// Складываем признак обмена с очередным разрядом
			swapped ^= bit;
			// Выполняем условный обмен точек лестницы
			exchange(first, second, swapped);
			// Запоминаем очередной разряд признаком обмена
			swapped = bit;
			// Вторая точка становится суммой точек лестницы
			add(first, second, second);
			// Первая точка удваивается
			twice(first, first);
		}
		// Выполняем заключительный условный обмен точек лестницы
		exchange(first, second, swapped);
		// Переносим кратную точку в место итога
		result = first;
		// Выполняем затирание точек лестницы
		wipe(&second, sizeof(second));
		// Выполняем затирание точек лестницы
		wipe(&first, sizeof(first));
	}
	/**
	 * @brief Функция сжатия точки в запись
	 *
	 * @details Раздел 5.2.2 RFC 8032: вторая координата младшим байтом вперёд, старший
	 *          разряд последнего байта - младший разряд первой координаты
	 *
	 * @param point  сжимаемая точка
	 * @param result место, в которое помещается запись длиной в пятьдесят семь байтов
	 *
	 */
	static void encode(const point_t & point, uint8_t * result) noexcept {
		// Арифметика поля кривой
		const math::modulus_t & arithmetic = field();
		// Обратный знаменатель и приведённые координаты
		math::number_t inverse, x, y;
		// Выполняем обращение знаменателя
		arithmetic.invert(point.z, inverse);
		// Выполняем приведение первой координаты
		arithmetic.multiply(point.x, inverse, x);
		// Выполняем приведение второй координаты
		arithmetic.multiply(point.y, inverse, y);
		// Выполняем вывод приведённых координат из области Монтгомери
		arithmetic.leave(x, x);
		// Выполняем вывод приведённых координат из области Монтгомери
		arithmetic.leave(y, y);
		// Запись первой координаты
		uint8_t buffer[RECORD];
		// Развёрнутая запись координаты
		uint8_t stored[RECORD];
		// Выполняем запись первой координаты от старшего байта
		arithmetic.store(x, stored, RECORD);
		// Выполняем разворот записи первой координаты младшим байтом вперёд
		reverse(stored, buffer, RECORD);
		// Выполняем запись второй координаты от старшего байта
		arithmetic.store(y, stored, RECORD);
		// Выполняем разворот записи второй координаты младшим байтом вперёд
		reverse(stored, result, RECORD);
		// Дописываем младший разряд первой координаты знаком в старший разряд записи
		result[RECORD - 1] |= static_cast <uint8_t> ((buffer[0] & 1) << 7);
		// Выполняем затирание развёрнутой записи
		wipe(stored, sizeof(stored));
		// Выполняем затирание записи первой координаты
		wipe(buffer, sizeof(buffer));
		// Выполняем затирание приведённых координат
		wipe(y.words, sizeof(y.words));
		// Выполняем затирание приведённых координат
		wipe(x.words, sizeof(x.words));
		// Выполняем затирание обратного знаменателя
		wipe(inverse.words, sizeof(inverse.words));
	}
	/**
	 * @brief Функция разбора точки из сжатой записи
	 *
	 * @details Раздел 5.2.3 RFC 8032: первая координата восстанавливается корнем из
	 *          (y^2 - 1) / (d * y^2 - 1) со знаком из старшего разряда записи
	 *
	 * @param data   разбираемая запись длиной в пятьдесят семь байтов
	 * @param result место, в которое помещается разобранная точка
	 * @return       признак того, что запись канонична и точка лежит на кривой
	 *
	 */
	static bool decode(const uint8_t * data, point_t & result) noexcept {
		// Арифметика поля кривой
		const math::modulus_t & arithmetic = field();
		// Разряд знака первой координаты
		const uint8_t flag = (data[RECORD - 1] >> 7);
		// Развёрнутая запись второй координаты
		uint8_t buffer[RECORD];
		// Выполняем разворот записи второй координаты от старшего байта
		reverse(data, buffer, RECORD);
		// Сбрасываем разряд знака в развёрнутой записи
		buffer[0] &= 0x7F;
		// Выполняем разбор второй координаты: значение укладывается в пятьдесят шесть байтов
		if(!arithmetic.load(view_t(buffer + 1, RECORD - 1), result.y))
			// Выводим отказ разбора точки: вторая координата не меньше модуля
			return false;
		// Выполняем приведение второй координаты в область Монтгомери
		arithmetic.enter(result.y, result.y);
		// Промежуточные значения восстановления первой координаты
		math::number_t u, v, x, check, one;
		// Единица поля
		word(1, one);
		// Вырабатываем квадрат второй координаты
		arithmetic.square(result.y, u);
		// Загружаем коэффициент кривой
		load(COEFFICIENT, v);
		// Вырабатываем произведение коэффициента на квадрат второй координаты
		arithmetic.multiply(v, u, v);
		// Вырабатываем числитель: квадрат второй координаты без единицы
		arithmetic.subtract(u, one, u);
		// Вырабатываем знаменатель: произведение без единицы
		arithmetic.subtract(v, one, v);
		// Вырабатываем обратный знаменатель
		arithmetic.invert(v, check);
		// Вырабатываем отношение числителя к знаменателю
		arithmetic.multiply(u, check, x);
		// Показатель корня (p + 1) / 4 = 2^446 - 2^222, записанный от старшего байта
		static const uint8_t EXPONENT[] = {
			// Записываем показатель корня от старшего байта
			0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		// Возводим отношение в степень (p + 1) / 4
		math::number_t power;
		// Выполняем разбор показателя
		if(!arithmetic.load(view_t(EXPONENT, sizeof(EXPONENT)), power))
			// Выводим отказ разбора точки
			return false;
		// Выполняем возведение в степень
		arithmetic.power(x, power, x);
		// Вырабатываем квадрат возможной первой координаты
		arithmetic.square(x, check);
		// Вырабатываем произведение квадрата на знаменатель
		arithmetic.multiply(check, v, check);
		// Если квадрат не сошёлся с числителем
		if(!arithmetic.equal(check, u)){
			// Противоположный числитель
			math::number_t negative;
			// Вырабатываем противоположный числитель
			word(0, negative);
			// Вычитаем числитель из нуля
			arithmetic.subtract(negative, u, negative);
			// Если квадрат не сошёлся и с противоположным числителем
			if(!arithmetic.equal(check, negative))
				// Выводим отказ разбора точки: корня нет, точка не на кривой
				return false;
		}
		// Запись первой координаты от старшего байта
		uint8_t stored[RECORD];
		// Выполняем вывод первой координаты из области Монтгомери
		arithmetic.leave(x, check);
		// Выполняем запись первой координаты
		arithmetic.store(check, stored, RECORD);
		// Выполняем разворот записи первой координаты младшим байтом вперёд
		reverse(stored, buffer, RECORD);
		// Если первая координата обратилась в ноль при поставленном разряде знака
		if(arithmetic.zero(x) && (flag == 1))
			// Выводим отказ разбора точки: запись не канонична
			return false;
		// Если младший разряд первой координаты не сошёлся со знаком
		if((buffer[0] & 1) != flag){
			// Вырабатываем противоположную первую координату
			word(0, check);
			// Вычитаем первую координату из нуля
			arithmetic.subtract(check, x, x);
		}
		// Записываем первую координату точки
		result.x = x;
		// Знаменатель разобранной точки - единица
		word(1, result.z);
		// Произведение координат разобранной точки
		arithmetic.multiply(result.x, result.y, result.t);
		// Выполняем затирание промежуточных значений
		wipe(stored, sizeof(stored));
		// Выполняем затирание промежуточных значений
		wipe(buffer, sizeof(buffer));
		// Выполняем затирание промежуточных значений
		wipe(power.words, sizeof(power.words));
		// Выполняем затирание промежуточных значений
		wipe(one.words, sizeof(one.words));
		// Выполняем затирание промежуточных значений
		wipe(check.words, sizeof(check.words));
		// Выполняем затирание промежуточных значений
		wipe(x.words, sizeof(x.words));
		// Выполняем затирание промежуточных значений
		wipe(v.words, sizeof(v.words));
		// Выполняем затирание промежуточных значений
		wipe(u.words, sizeof(u.words));
		// Выводим успешность разбора точки
		return true;
	}
	/**
	 * @brief Функция приведения записи по порядку подгруппы
	 *
	 * @param order  арифметика порядка подгруппы
	 * @param data   приводимая запись, записанная младшим байтом вперёд
	 * @param size   длина приводимой записи в байтах
	 * @param result место, в которое помещается приведённый скаляр младшим байтом вперёд
	 * @return       признак успешности приведения
	 *
	 */
	static bool reduce(const math::modulus_t & order, const uint8_t * data, const size_t size, uint8_t * result) noexcept {
		// Развёрнутая запись и запись приведённого скаляра
		uint8_t buffer[DIGEST], stored[RECORD];
		// Выполняем разворот приводимой записи от старшего байта
		reverse(data, buffer, size);
		// Приведённый скаляр
		math::number_t value;
		// Признак успешности приведения
		bool ok = order.reduce(view_t(buffer, size), value);
		// Если приведение удалось
		if(ok){
			// Выполняем запись приведённого скаляра от старшего байта
			ok = order.store(value, stored, RECORD);
			// Если запись удалась
			if(ok)
				// Выполняем разворот записи скаляра младшим байтом вперёд
				reverse(stored, result, RECORD);
		}
		// Выполняем затирание приведённого скаляра
		wipe(value.words, sizeof(value.words));
		// Выполняем затирание записи скаляра
		wipe(stored, sizeof(stored));
		// Выполняем затирание развёрнутой записи
		wipe(buffer, sizeof(buffer));
		// Выводим признак успешности приведения
		return ok;
	}
	/**
	 * @brief Функция выработки скаляра подписи S = (r + k * a) по порядку подгруппы
	 *
	 * @param order  арифметика порядка подгруппы
	 * @param r      скаляр r, приведённый по порядку и записанный младшим байтом вперёд
	 * @param k      скаляр k, приведённый по порядку и записанный младшим байтом вперёд
	 * @param a      скаляр ключа подписи, записанный младшим байтом вперёд
	 * @param result место, в которое помещается скаляр подписи младшим байтом вперёд
	 * @return       признак успешности выработки
	 *
	 */
	static bool combine(const math::modulus_t & order, const uint8_t * r, const uint8_t * k, const uint8_t * a, uint8_t * result) noexcept {
		// Развёрнутая запись
		uint8_t buffer[RECORD];
		// Числа выработки скаляра подписи
		math::number_t first, second, third;
		// Выполняем разворот записи скаляра r
		reverse(r, buffer, RECORD);
		// Признак успешности выработки: значение скаляра укладывается в пятьдесят шесть байтов
		bool ok = order.load(view_t(buffer + 1, RECORD - 1), first);
		// Если скаляр r разобрать удалось
		if(ok){
			// Выполняем разворот записи скаляра k
			reverse(k, buffer, RECORD);
			// Выполняем разбор скаляра k
			ok = order.load(view_t(buffer + 1, RECORD - 1), second);
		}
		// Если скаляр k разобрать удалось
		if(ok){
			// Выполняем разворот записи скаляра ключа
			reverse(a, buffer, RECORD);
			// Выполняем приведение скаляра ключа: зажатый скаляр порядка не меньше
			ok = order.reduce(view_t(buffer, RECORD), third);
		}
		// Если все скаляры разобрать удалось
		if(ok){
			// Выполняем приведение скаляра k в область Монтгомери
			order.enter(second, second);
			// Выполняем приведение скаляра ключа в область Монтгомери
			order.enter(third, third);
			// Выполняем умножение скаляров
			order.multiply(second, third, second);
			// Выполняем вывод произведения из области Монтгомери
			order.leave(second, second);
			// Складываем произведение со скаляром r
			order.add(first, second, first);
			// Выполняем запись скаляра подписи от старшего байта
			ok = order.store(first, buffer, RECORD);
			// Если запись удалась
			if(ok)
				// Выполняем разворот записи скаляра подписи младшим байтом вперёд
				reverse(buffer, result, RECORD);
		}
		// Выполняем затирание чисел выработки
		wipe(third.words, sizeof(third.words));
		// Выполняем затирание чисел выработки
		wipe(second.words, sizeof(second.words));
		// Выполняем затирание чисел выработки
		wipe(first.words, sizeof(first.words));
		// Выполняем затирание развёрнутой записи
		wipe(buffer, sizeof(buffer));
		// Выводим признак успешности выработки
		return ok;
	}
	/**
	 * @brief Функция проверки скаляра на строгую меньшесть порядка подгруппы
	 *
	 * @details Раздел 5.2.7 RFC 8032: скаляр S подписи обязан быть меньше L, иначе
	 *          подпись ковка. Скаляр не секретен, оттого сличение идёт обычным перебором
	 *
	 * @param data запись скаляра младшим байтом вперёд
	 * @return     признак того, что скаляр меньше порядка подгруппы
	 *
	 */
	static bool canonical(const uint8_t * data) noexcept {
		// Старший байт скаляра обязан быть нулевым: порядок короче пятидесяти семи байтов
		if(data[RECORD - 1] != 0)
			// Выводим признак того, что скаляр не меньше порядка
			return false;
		/**
		 * Выполняем перебор значимых байтов скаляра от старшего к младшему
		 */
		for(size_t i = (RECORD - 1); i > 0; i--){
			// Очередной байт скаляра
			const uint8_t item = data[i - 1];
			// Очередной байт порядка подгруппы, записанного от старшего байта
			const uint8_t bound = ORDER[(RECORD - 1) - i];
			// Если байт скаляра меньше байта порядка
			if(item < bound)
				// Выводим признак того, что скаляр меньше порядка
				return true;
			// Если байт скаляра больше байта порядка
			if(item > bound)
				// Выводим признак того, что скаляр не меньше порядка
				return false;
		}
		// Скаляр равен порядку: он не меньше порядка
		return false;
	}
	/**
	 * @brief Функция выработки хеша SHAKE256 со строкой dom4 из частей
	 *
	 * @param first  первая часть хешируемых данных
	 * @param second вторая часть хешируемых данных
	 * @param third  третья часть хешируемых данных
	 * @param result место, в которое помещается хеш длиной в сто четырнадцать байтов
	 * @return       признак успешности выработки хеша
	 *
	 */
	static bool digestion(const view_t & first, const view_t & second, const view_t & third, uint8_t * result) noexcept {
		// Объект хеширования SHAKE256
		digest::keccak_t hasher(digest::sha3_t::SHAKE256);
		// Выполняем подачу строки dom4
		if(!hasher.update(view_t(DOM4, sizeof(DOM4))))
			// Выводим отказ выработки хеша
			return false;
		// Выполняем подачу первой части
		if(!hasher.update(first))
			// Выводим отказ выработки хеша
			return false;
		// Выполняем подачу второй части
		if(!hasher.update(second))
			// Выводим отказ выработки хеша
			return false;
		// Выполняем подачу третьей части
		if(!hasher.update(third))
			// Выводим отказ выработки хеша
			return false;
		// Выводим признак успешности выжимания хеша
		return hasher.squeeze(result, DIGEST);
	}
};

/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах
 *
 */
size_t nts::sign::Ed448::size() const noexcept {
	// Выводим размер подписи в байтах
	return SIGNATURE_SIZE;
}
/**
 * @brief Метод получения верхнего предела длины подписи в записанном виде
 *
 * @return верхний предел длины подписи в байтах, ноль без ключа
 *
 */
size_t nts::sign::Ed448::limit() const noexcept {
	// Если ни ключ подписи, ни ключ проверки не установлены
	if(!this->_secret && !this->_public)
		// Выводим нулевой предел
		return 0;
	// Подпись уходит наружу как есть: предел равен длине сырой подписи
	return SIGNATURE_SIZE;
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void nts::sign::Ed448::clear() noexcept {
	// Выполняем затирание ключа проверки подписи
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание приставки
	wipe(this->_prefix, sizeof(this->_prefix));
	// Выполняем затирание скаляра ключа подписи
	wipe(this->_scalar, sizeof(this->_scalar));
	// Снимаем признак того, что ключ проверки подписи установлен
	this->_public = false;
	// Снимаем признак того, что ключ подписи установлен
	this->_secret = false;
}
/**
 * @brief Метод установки ключа подписи
 *
 * @param secret зерно ключа подписи длиной в пятьдесят семь байтов
 * @return       признак успешности установки ключа подписи
 *
 */
bool nts::sign::Ed448::secret(const view_t & secret) noexcept {
	// Выполняем сброс прежнего состояния модуля
	this->clear();
	// Если зерно передано длиной не в пятьдесят семь байтов либо арифметика порядка не готова
	if((secret.data == nullptr) || (secret.size != KEY_SIZE) || !this->_order.ready())
		// Выводим отказ установки ключа подписи
		return false;
	// Хеш зерна
	uint8_t buffer[DIGEST];
	// Объект хеширования SHAKE256
	digest::keccak_t hasher(digest::sha3_t::SHAKE256);
	// Выполняем подачу зерна и выжимание хеша
	if(!hasher.update(secret) || !hasher.squeeze(buffer, sizeof(buffer))){
		// Выполняем затирание хеша зерна
		wipe(buffer, sizeof(buffer));
		// Выводим отказ установки ключа подписи
		return false;
	}
	/**
	 * Выполняем разделение хеша: раздел 5.2.5 RFC 8032 берёт скаляр из младшей
	 * половины, а приставку - из старшей
	 */
	for(size_t i = 0; i < KEY_SIZE; i++){
		// Переносим очередной байт скаляра
		this->_scalar[i] = buffer[i];
		// Переносим очередной байт приставки
		this->_prefix[i] = buffer[KEY_SIZE + i];
	}
	// Сбрасываем два младших разряда скаляра
	this->_scalar[0] &= 0xFC;
	// Сбрасываем старший байт скаляра
	this->_scalar[KEY_SIZE - 1] = 0;
	// Ставим разряд 447 скаляра: старший разряд предпоследнего байта
	this->_scalar[KEY_SIZE - 2] |= 0x80;
	// Точка основания и точка ключа проверки
	point_t generator, point;
	// Получаем точку основания
	base(generator);
	// Выполняем умножение точки основания на скаляр
	multiply(this->_scalar, generator, point);
	// Выполняем сжатие точки ключа проверки
	encode(point, this->_key);
	// Выполняем затирание точки ключа проверки
	wipe(&point, sizeof(point));
	// Выполняем затирание хеша зерна
	wipe(buffer, sizeof(buffer));
	// Устанавливаем признак того, что ключ проверки подписи установлен
	this->_public = true;
	// Устанавливаем признак того, что ключ подписи установлен
	this->_secret = true;
	// Выводим успешность установки ключа подписи
	return true;
}
/**
 * @brief Метод порождения долговременного ключа подписи
 *
 * @param secret место, в которое записывается зерно ключа подписи длиной в пятьдесят семь байтов
 * @param size   размер места ключа подписи
 * @return       признак успешности порождения ключа подписи
 *
 */
bool nts::sign::Ed448::generate(uint8_t * secret, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния модуля
	this->clear();
	// Если место зерна не передано либо размер его не равен длине зерна
	if((secret == nullptr) || (size != KEY_SIZE))
		// Выводим отказ порождения ключа подписи
		return false;
	/**
	 * Зерно по разделу 5.2.5 RFC 8032 есть пятьдесят семь случайных байтов как есть:
	 * зажим скаляра выполняет вывод из хеша зерна, оттого отбора здесь нет
	 */
	if(!entropy::bytes(secret, size)){
		// Выполняем затирание переданного места
		wipe(secret, size);
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Если зерно установить не удалось
	if(!this->secret(view_t(secret, size))){
		// Выполняем затирание переданного места
		wipe(secret, size);
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Выводим успешность порождения ключа подписи
	return true;
}
/**
 * @brief Метод установки ключа проверки подписи
 *
 * @param key сжатая точка ключа проверки подписи длиной в пятьдесят семь байтов
 * @return    признак успешности установки ключа проверки подписи
 *
 */
bool nts::sign::Ed448::key(const view_t & key) noexcept {
	// Если ключ подписи уже установлен
	if(this->_secret){
		/**
		 * Открытый ключ выведен из зерна при его установке: поданный обязан с ним
		 * сойтись, и тогда состояние не меняется; чужой отвергается. Затирать
		 * закрытый ключ молча нельзя
		 */
		if((key.data == nullptr) || (key.size != KEY_SIZE))
			// Выводим отказ установки ключа
			return false;
		// Накопленное различие ключей
		uint8_t difference = 0;
		/**
		 * Выполняем сличение ключей за постоянное время
		 */
		for(size_t i = 0; i < KEY_SIZE; i++)
			// Накапливаем различие
			difference = static_cast <uint8_t> (difference | (this->_key[i] ^ key.data[i]));
		// Выводим схождение поданного ключа с выведенным
		return (difference == 0);
	}
	// Выполняем сброс прежнего состояния
	this->clear();
	// Если ключ передан длиной не в пятьдесят семь байтов либо арифметика порядка не готова
	if((key.data == nullptr) || (key.size != KEY_SIZE) || !this->_order.ready())
		// Выводим отказ установки ключа проверки подписи
		return false;
	// Точка ключа проверки
	point_t point;
	// Если точку ключа проверки разобрать не удалось
	if(!decode(key.data, point))
		// Выводим отказ установки ключа проверки подписи
		return false;
	/**
	 * Выполняем перенос записи ключа проверки
	 */
	for(size_t i = 0; i < KEY_SIZE; i++)
		// Переносим очередной байт записи
		this->_key[i] = key.data[i];
	// Устанавливаем признак того, что ключ проверки подписи установлен
	this->_public = true;
	// Выводим успешность установки ключа проверки подписи
	return true;
}
/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param result место, в которое записывается сжатая точка ключа проверки подписи
 * @param size   размер места, не меньше пятидесяти семи байтов
 * @return       признак успешности получения ключа проверки подписи
 *
 */
bool nts::sign::Ed448::key(uint8_t * result, const size_t size) const noexcept {
	// Если ключ проверки не установлен либо место мало
	if(!this->_public || (result == nullptr) || (size < KEY_SIZE))
		// Выводим отказ получения ключа проверки подписи
		return false;
	/**
	 * Выполняем перенос записи ключа проверки
	 */
	for(size_t i = 0; i < KEY_SIZE; i++)
		// Переносим очередной байт записи
		result[i] = this->_key[i];
	// Выводим успешность получения ключа проверки подписи
	return true;
}
/**
 * @brief Метод выработки подписи
 *
 * @param message подписываемое сообщение целиком
 * @param result  место, в которое помещается подпись длиной в сто четырнадцать байтов
 * @return        признак успешности выработки подписи
 *
 */
bool nts::sign::Ed448::make(const view_t & message, uint8_t * result) const noexcept {
	// Если ключ подписи не установлен либо место подписи не передано
	if(!this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Если сообщение передано без данных при ненулевой длине
	if((message.data == nullptr) && (message.size != 0))
		// Выводим отказ выработки подписи
		return false;
	// Хеш и скаляры выработки подписи
	uint8_t buffer[DIGEST], r[RECORD], k[RECORD];
	// Признак успешности выработки подписи
	bool ok = digestion(view_t(this->_prefix, KEY_SIZE), message, view_t(), buffer);
	// Если хеш приставки с сообщением выработать удалось
	if(ok)
		// Выполняем приведение хеша по порядку подгруппы в скаляр r
		ok = reduce(this->_order, buffer, DIGEST, r);
	// Если скаляр r выработать удалось
	if(ok){
		// Точка основания и точка R
		point_t generator, point;
		// Получаем точку основания
		base(generator);
		// Выполняем умножение точки основания на скаляр r
		multiply(r, generator, point);
		// Выполняем сжатие точки R в начало подписи
		encode(point, result);
		// Выполняем затирание точки R
		wipe(&point, sizeof(point));
		// Выполняем выработку хеша точки R, ключа проверки и сообщения
		ok = digestion(view_t(result, RECORD), view_t(this->_key, KEY_SIZE), message, buffer);
	}
	// Если хеш точки R с ключом и сообщением выработать удалось
	if(ok)
		// Выполняем приведение хеша по порядку подгруппы в скаляр k
		ok = reduce(this->_order, buffer, DIGEST, k);
	// Если скаляр k выработать удалось
	if(ok)
		// Выполняем выработку скаляра подписи в конец подписи
		ok = combine(this->_order, r, k, this->_scalar, result + RECORD);
	// Выполняем затирание скаляра k
	wipe(k, sizeof(k));
	// Выполняем затирание скаляра r
	wipe(r, sizeof(r));
	// Выполняем затирание хеша
	wipe(buffer, sizeof(buffer));
	// Если подпись выработать не удалось
	if(!ok)
		// Выполняем затирание места подписи
		wipe(result, SIGNATURE_SIZE);
	// Выводим признак успешности выработки подписи
	return ok;
}
/**
 * @brief Метод проверки подписи
 *
 * @param message   подписанное сообщение целиком
 * @param signature проверяемая подпись длиной в сто четырнадцать байтов
 * @return          признак того, что подпись сошлась
 *
 */
bool nts::sign::Ed448::check(const view_t & message, const view_t & signature) const noexcept {
	// Если ключ проверки не установлен
	if(!this->_public)
		// Выводим отказ проверки подписи
		return false;
	// Если подпись передана длиной не в сто четырнадцать байтов
	if((signature.data == nullptr) || (signature.size != SIGNATURE_SIZE))
		// Выводим отказ проверки подписи
		return false;
	// Если сообщение передано без данных при ненулевой длине
	if((message.data == nullptr) && (message.size != 0))
		// Выводим отказ проверки подписи
		return false;
	// Если скаляр S подписи не меньше порядка подгруппы
	if(!canonical(signature.data + RECORD))
		// Выводим отказ проверки подписи
		return false;
	// Точки проверки подписи
	point_t point, r, a;
	// Если точку R подписи разобрать не удалось
	if(!decode(signature.data, r))
		// Выводим отказ проверки подписи
		return false;
	// Если точку ключа проверки разобрать не удалось
	if(!decode(this->_key, a))
		// Выводим отказ проверки подписи
		return false;
	// Хеш и скаляр проверки подписи
	uint8_t buffer[DIGEST], k[RECORD];
	// Если хеш точки R, ключа проверки и сообщения выработать не удалось
	if(!digestion(view_t(signature.data, RECORD), view_t(this->_key, KEY_SIZE), message, buffer))
		// Выводим отказ проверки подписи
		return false;
	// Если хеш привести по порядку подгруппы не удалось
	if(!reduce(this->_order, buffer, DIGEST, k))
		// Выводим отказ проверки подписи
		return false;
	// Получаем точку основания
	base(point);
	// Выполняем умножение точки основания на скаляр S
	multiply(signature.data + RECORD, point, point);
	// Выполняем умножение точки ключа проверки на скаляр k
	multiply(k, a, a);
	// Складываем точку R с кратной точкой ключа проверки
	add(r, a, a);
	// Записи сличаемых точек
	uint8_t first[RECORD], second[RECORD];
	// Выполняем сжатие кратной точки основания
	encode(point, first);
	// Выполняем сжатие суммы точек
	encode(a, second);
	// Накопленная разность записей
	uint8_t item = 0;
	/**
	 * Выполняем сличение записей точек
	 */
	for(size_t i = 0; i < RECORD; i++)
		// Накапливаем разность очередных байтов
		item |= (first[i] ^ second[i]);
	// Выводим признак того, что подпись сошлась
	return (item == 0);
}
/**
 * @brief Конструктор
 *
 */
nts::sign::Ed448::Ed448() noexcept : _secret(false), _public(false), _scalar{}, _prefix{}, _key{} {
	// Выполняем установку порядка подгруппы точек кривой
	this->_order.start(view_t(ORDER, sizeof(ORDER)));
}
/**
 * @brief Деструктор
 *
 */
nts::sign::Ed448::~Ed448() noexcept {
	// Выполняем сброс состояния модуля
	this->clear();
}
