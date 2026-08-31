/**
 * @file curve.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля арифметики точек эллиптической кривой
 *
 * @note Кривая и её точки взяты из раздела 7.1 RFC 7091 — контрольного примера
 *       ГОСТ Р 34.10-2012 для ключа длиной 256 разрядов
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstring>
#include <main.hpp>
#include <curve/curve.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Модуль поля кривой контрольного примера
 */
static const char * MODULUS = "8000000000000000000000000000000000000000000000000000000000000431";

/**
 * Первый коэффициент уравнения кривой контрольного примера
 */
static const char * FIRST = "07";

/**
 * Второй коэффициент уравнения кривой контрольного примера
 */
static const char * SECOND = "5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e";

/**
 * Порядок подгруппы точек кривой контрольного примера
 */
static const char * ORDER = "8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3";

/**
 * Первая координата образующей точки контрольного примера
 */
static const char * BASE_X = "02";

/**
 * Вторая координата образующей точки контрольного примера
 */
static const char * BASE_Y = "08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
 *
 * @return     число разобранных байтов
 *
 */
static size_t bytes(const char * text, uint8_t * data) {
	// Число разобранных байтов
	size_t result = 0;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		data[result++] = value;
	}
	// Выводим число разобранных байтов
	return result;
}
/**
 * @brief Метод сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
 *
 * @return     собранная запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор собираемых байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}
/**
 * @brief Метод установки кривой контрольного примера
 *
 * @param curve устанавливаемая кривая
 *
 * @return      признак успешности установки кривой
 *
 */
static bool prepare(curve::curve_t & curve) {
	// Места, в которые помещаются параметры кривой
	uint8_t modulus[32], first[32], second[32], order[32], x[32], y[32];
	// Выполняем установку параметров кривой
	return curve.start(
		view_t(modulus, bytes(MODULUS, modulus)),
		view_t(first, bytes(FIRST, first)),
		view_t(second, bytes(SECOND, second)),
		view_t(order, bytes(ORDER, order)),
		view_t(x, bytes(BASE_X, x)),
		view_t(y, bytes(BASE_Y, y))
	);
}

/**
 * @brief Проверка умножения образующей точки на число
 *
 */
TEST(CurveTest, Multiply) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Место, в которое помещается разбираемое число
	uint8_t buffer[32];
	// Множитель образующей точки
	math::number_t factor;
	// Выполняем разбор множителя образующей точки
	ASSERT_TRUE(curve.order().load(view_t(buffer, bytes("77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3", buffer)), factor));
	// Образующая точка кривой
	curve::point_t base;
	// Получаем образующую точку кривой
	curve.base(base);
	// Место, в которое помещается произведение
	curve::point_t result;
	// Выполняем умножение образующей точки на множитель
	curve.multiply(base, factor, result);
	// Места, в которые записываются координаты произведения
	uint8_t x[32], y[32];
	// Выполняем запись координат произведения
	ASSERT_TRUE(curve.coordinates(result, x, y, sizeof(x)));
	// Сличаем первую координату произведения с контрольным примером
	ASSERT_EQ(text(x, sizeof(x)), std::string("41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"));
	// Сличаем вторую координату произведения с контрольным примером
	ASSERT_EQ(text(y, sizeof(y)), std::string("489c375a9941a3049e33b34361dd204172ad98c3e5916de27695d22a61fae46e"));
	// Множитель выработки ключа проверки подписи
	math::number_t key;
	// Выполняем разбор ключа подписи контрольного примера
	ASSERT_TRUE(curve.order().load(view_t(buffer, bytes("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28", buffer)), key));
	// Выполняем умножение образующей точки на ключ подписи
	curve.multiply(base, key, result);
	// Выполняем запись координат ключа проверки подписи
	ASSERT_TRUE(curve.coordinates(result, x, y, sizeof(x)));
	// Сличаем первую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(x, sizeof(x)), std::string("7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b"));
	// Сличаем вторую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(y, sizeof(y)), std::string("26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da"));
}
/**
 * @brief Проверка свойств сложения и удвоения точек
 *
 */
TEST(CurveTest, Properties) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Образующая точка кривой
	curve::point_t base;
	// Получаем образующую точку кривой
	curve.base(base);
	// Места, в которые помещаются проверяемые точки
	curve::point_t first, second;
	// Выполняем удвоение образующей точки
	curve.twice(base, first);
	// Выполняем сложение образующей точки с самой собой
	curve.add(base, base, second);
	// Места, в которые записываются координаты точек
	uint8_t x[32], y[32], u[32], v[32];
	// Выполняем запись координат удвоенной точки
	ASSERT_TRUE(curve.coordinates(first, x, y, sizeof(x)));
	// Выполняем запись координат суммы точки с самой собой
	ASSERT_TRUE(curve.coordinates(second, u, v, sizeof(u)));
	// Проверяем совпадение удвоения точки со сложением её с самой собой
	ASSERT_EQ(text(x, sizeof(x)), text(u, sizeof(u)));
	// Проверяем совпадение вторых координат полученных точек
	ASSERT_EQ(text(y, sizeof(y)), text(v, sizeof(v)));
	// Место, в которое помещается разбираемое число
	uint8_t buffer[32];
	// Множитель, равный порядку подгруппы точек кривой
	math::number_t factor;
	// Выполняем разбор множителя, меньшего порядка подгруппы на единицу
	ASSERT_TRUE(curve.order().load(view_t(buffer, bytes("8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b2", buffer)), factor));
	// Выполняем умножение образующей точки на полученный множитель
	curve.multiply(base, factor, first);
	// Выполняем сложение полученного произведения с образующей точкой
	curve.add(first, base, second);
	/**
	 * Умножение образующей точки на порядок подгруппы обязано давать бесконечно
	 * удалённую точку: тем и задан порядок подгруппы
	 */
	ASSERT_TRUE(curve.infinity(second));
	// Проверяем отказ записи координат бесконечно удалённой точки
	ASSERT_FALSE(curve.coordinates(second, x, y, sizeof(x)));
	// Единичный множитель образующей точки
	math::number_t unit;
	// Записываем значение единичного множителя
	curve.order().word(1, unit);
	// Выполняем умножение образующей точки на единицу
	curve.multiply(base, unit, first);
	// Выполняем запись координат полученного произведения
	ASSERT_TRUE(curve.coordinates(first, x, y, sizeof(x)));
	// Сличаем первую координату произведения с координатой образующей точки
	ASSERT_EQ(text(x, sizeof(x)), std::string("0000000000000000000000000000000000000000000000000000000000000002"));
	// Нулевой множитель образующей точки
	math::number_t zero;
	// Записываем значение нулевого множителя
	curve.order().word(0, zero);
	// Выполняем умножение образующей точки на ноль
	curve.multiply(base, zero, first);
	// Проверяем, что произведение обратилось в бесконечно удалённую точку
	ASSERT_TRUE(curve.infinity(first));
	// Выполняем сложение бесконечно удалённой точки с образующей
	curve.add(first, base, second);
	// Выполняем запись координат полученной суммы
	ASSERT_TRUE(curve.coordinates(second, x, y, sizeof(x)));
	// Сличаем первую координату суммы с координатой образующей точки
	ASSERT_EQ(text(x, sizeof(x)), std::string("0000000000000000000000000000000000000000000000000000000000000002"));
}
/**
 * @brief Проверка отказов кривой
 *
 */
TEST(CurveTest, Failures) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Проверяем отказ работы кривой до установки её параметров
	ASSERT_FALSE(curve.ready());
	// Места, в которые помещаются параметры кривой
	uint8_t modulus[32], first[32], second[32], order[32], x[32], y[32];
	// Выполняем разбор параметров кривой
	const view_t items[6] = {
		view_t(modulus, bytes(MODULUS, modulus)),
		view_t(first, bytes(FIRST, first)),
		view_t(second, bytes(SECOND, second)),
		view_t(order, bytes(ORDER, order)),
		view_t(x, bytes(BASE_X, x)),
		view_t(y, bytes(BASE_Y, y))
	};
	// Проверяем отказ установки кривой с точкой, ей не принадлежащей
	ASSERT_FALSE(curve.start(items[0], items[1], items[2], items[3], items[5], items[4]));
	// Проверяем отказ установки кривой с чётным модулем поля
	ASSERT_FALSE(curve.start(items[4], items[1], items[2], items[3], items[4], items[5]));
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(curve.start(items[0], items[1], items[2], items[3], items[4], items[5]));
	// Проверяем размер координаты точки кривой
	ASSERT_EQ(curve.size(), static_cast <size_t> (32));
	// Место, в которое помещается разбираемая точка
	curve::point_t point;
	// Проверяем отказ разбора точки, кривой не принадлежащей
	ASSERT_FALSE(curve.point(items[5], items[4], point));
	// Проверяем успешность разбора точки, кривой принадлежащей
	ASSERT_TRUE(curve.point(items[4], items[5], point));
	// Проверяем, что разобранная точка бесконечно удалённой не считается
	ASSERT_FALSE(curve.infinity(point));
}

/**
 * @brief Проверка умножения точки на число сличением с перебором разрядов
 *
 * @note Умножение идёт окнами по нескольку разрядов, и остаток множителя, в окно не
 *       уложившийся, перебор оставил бы без внимания молча: сличение с перебором
 *       разряд за разрядом такую потерю и ловит
 *
 */
TEST(CurveTest, Windows) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Образующая точка кривой
	curve::point_t base;
	// Получаем образующую точку кривой
	curve.base(base);
	// Проверяемые множители образующей точки
	const char * factors[] = {
		"01",
		"02",
		"03",
		"11",
		"ff",
		"0100",
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"8000000000000000000000000000000000000000000000000000000000000000",
		"8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b2",
		"55555555555555555555555555555555aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0ff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"
	};
	/**
	 * Выполняем перебор проверяемых множителей образующей точки
	 */
	for(size_t item = 0; item < (sizeof(factors) / sizeof(factors[0])); item++){
		// Место, в которое помещается разбираемое число
		uint8_t buffer[32];
		// Разбираемый множитель образующей точки
		math::number_t factor;
		// Выполняем разбор очередного множителя образующей точки
		ASSERT_TRUE(curve.order().load(view_t(buffer, bytes(factors[item], buffer)), factor)) << factors[item];
		// Место, в которое помещается произведение окнами
		curve::point_t result;
		// Выполняем умножение образующей точки на множитель
		curve.multiply(base, factor, result);
		// Накапливаемое произведение перебором разрядов
		curve::point_t item2;
		// Место, в которое помещается промежуточное значение перебора
		curve::point_t step;
		/**
		 * Выполняем перебор разрядов множителя от старшего к младшему
		 */
		for(size_t i = (curve.order().size() * 8); i > 0; i--){
			// Выполняем удвоение накопленного произведения
			curve.twice(item2, step);
			// Запоминаем удвоенное накопленное произведение
			item2 = step;
			// Извлекаем очередной разряд множителя
			const uint64_t bit = ((factor.words[(i - 1) / 64] >> ((i - 1) % 64)) & 0x01);
			// Если очередной разряд множителя единичный
			if(bit != 0){
				// Выполняем сложение накопленного произведения с образующей точкой
				curve.add(item2, base, step);
				// Запоминаем накопленное произведение
				item2 = step;
			}
		}
		// Проверяем схождение удалённости обоих произведений
		ASSERT_EQ(curve.infinity(result), curve.infinity(item2)) << factors[item];
		// Если произведение не обратилось в бесконечно удалённую точку
		if(!curve.infinity(result)){
			// Места, в которые записываются координаты произведений
			uint8_t x[32], y[32], u[32], v[32];
			// Выполняем запись координат произведения окнами
			ASSERT_TRUE(curve.coordinates(result, x, y, sizeof(x))) << factors[item];
			// Выполняем запись координат произведения перебором разрядов
			ASSERT_TRUE(curve.coordinates(item2, u, v, sizeof(u))) << factors[item];
			// Проверяем схождение первых координат произведений
			ASSERT_EQ(text(x, sizeof(x)), text(u, sizeof(u))) << factors[item];
			// Проверяем схождение вторых координат произведений
			ASSERT_EQ(text(y, sizeof(y)), text(v, sizeof(v))) << factors[item];
		}
	}
}

/**
 * Проверка счёта суммы двух произведений точек кривой на числа
 */
TEST(CurveTest, Combine){
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Образующая точка кривой
	curve::point_t base;
	// Получаем образующую точку кривой
	curve.base(base);
	// Вторая точка, участвующая в сумме произведений
	curve::point_t other;
	// Число, которым вторая точка выводится из образующей
	math::number_t seed;
	// Устанавливаем число, которым выводится вторая точка
	seed.words[0] = 0x9E3779B97F4A7C15ULL;
	// Выполняем вывод второй точки умножением образующей
	curve.multiply(base, seed, other);
	/**
	 * Выполняем перебор пар множителей суммы произведений
	 */
	for(size_t item = 0; item < 8; item++){
		// Первый множитель суммы произведений
		math::number_t single;
		// Второй множитель суммы произведений
		math::number_t pair;
		// Устанавливаем младшее слово первого множителя
		single.words[0] = (0x0123456789ABCDEFULL + item);
		// Устанавливаем старшее слово первого множителя
		single.words[1] = (0xFEDCBA9876543210ULL - item);
		// Устанавливаем младшее слово второго множителя
		pair.words[0] = (0x00FF00FF00FF00FFULL + (item * 7));
		// Устанавливаем старшее слово второго множителя
		pair.words[2] = (0x1122334455667788ULL + item);
		// Сумма произведений, посчитанная разом
		curve::point_t together;
		// Выполняем счёт суммы произведений разом
		curve.combine(base, single, other, pair, together);
		// Произведения, посчитанные порознь
		curve::point_t left, right, apart;
		// Выполняем счёт первого произведения порознь
		curve.multiply(base, single, left);
		// Выполняем счёт второго произведения порознь
		curve.multiply(other, pair, right);
		// Выполняем сложение произведений, посчитанных порознь
		curve.add(left, right, apart);
		// Место под первую координату суммы, посчитанной разом
		vector <uint8_t> first(curve.size(), 0);
		// Место под вторую координату суммы, посчитанной разом
		vector <uint8_t> second(curve.size(), 0);
		// Место под первую координату суммы, посчитанной порознь
		vector <uint8_t> third(curve.size(), 0);
		// Место под вторую координату суммы, посчитанной порознь
		vector <uint8_t> fourth(curve.size(), 0);
		// Выполняем снятие координат суммы, посчитанной разом
		ASSERT_TRUE(curve.coordinates(together, first.data(), second.data(), curve.size())) << "пара " << item;
		// Выполняем снятие координат суммы, посчитанной порознь
		ASSERT_TRUE(curve.coordinates(apart, third.data(), fourth.data(), curve.size())) << "пара " << item;
		/**
		 * Сумма разом обязана сойтись с суммой порознь: иначе перебор окон обоих
		 * множителей теряет разряды, как терял их разбег окна у умножения
		 */
		ASSERT_EQ(first, third) << "пара " << item;
		// Проверяем схождение вторых координат посчитанных сумм
		ASSERT_EQ(second, fourth) << "пара " << item;
	}
}
