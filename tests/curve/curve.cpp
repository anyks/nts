/**
 * @file curve.cpp
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
#include <vector>
#include <curve/curve.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

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
	/**
	 * Координаты точки разбираются ОБЕ, и всякая из них отвергает точку в одиночку:
	 * непереданная вторая координата при годной первой трогает ту половину заслона,
	 * что отвечает за вторую
	 */
	ASSERT_FALSE(curve.point(items[4], view_t(nullptr, 32), point));
	// Проверяем отказ разбора точки с непереданной первой координатой
	ASSERT_FALSE(curve.point(view_t(nullptr, 32), items[5], point));
	// Места, в которые помещаются выданные координаты точки
	uint8_t left[32] = {0}, right[32] = {0};
	/**
	 * Выдача пишет координату во ВСЁ отведённое место, дополняя её ведущими нулями до
	 * его длины, тогда как запись примера ведущих нулей не несёт. Ожидаемое потому
	 * собирается дополнением записи, а не сличается с нею напрямую
	 */
	uint8_t expected[32] = {0}, awaited[32] = {0};
	// Выполняем дополнение записи первой координаты ведущими нулями
	::memcpy((expected + (sizeof(expected) - items[4].size)), items[4].data, items[4].size);
	// Выполняем дополнение записи второй координаты ведущими нулями
	::memcpy((awaited + (sizeof(awaited) - items[5].size)), items[5].data, items[5].size);
	// Выполняем разбор точки кривой заново
	ASSERT_TRUE(curve.point(items[4], items[5], point));
	// Проверяем успешность выдачи обеих координат точки
	ASSERT_TRUE(curve.coordinates(point, left, right, sizeof(left)));
	// Сличаем выданную первую координату точки с её записью
	ASSERT_EQ(::memcmp(left, expected, sizeof(left)), 0);
	// Сличаем выданную вторую координату точки с её записью
	ASSERT_EQ(::memcmp(right, awaited, sizeof(right)), 0);
	/**
	 * Непереданное место под координату означает, что она не нужна: заслон выдачи
	 * сверяет переданность места ОТДЕЛЬНО для всякой координаты, и выдача одной
	 * лишь второй отказом не является
	 */
	::memset(right, 0, sizeof(right));
	// Выполняем выдачу одной лишь второй координаты точки
	ASSERT_TRUE(curve.coordinates(point, nullptr, right, sizeof(right)));
	// Сличаем выданную вторую координату точки с её записью
	ASSERT_EQ(::memcmp(right, awaited, sizeof(right)), 0);
	// Выполняем обнуление места первой координаты точки
	::memset(left, 0, sizeof(left));
	// Выполняем выдачу одной лишь первой координаты точки
	ASSERT_TRUE(curve.coordinates(point, left, nullptr, sizeof(left)));
	// Сличаем выданную первую координату точки с её записью
	ASSERT_EQ(::memcmp(left, expected, sizeof(left)), 0);
	// Проверяем отказ выдачи координат в место короче координаты
	ASSERT_FALSE(curve.coordinates(point, left, right, 0));
	/**
	 * Запись всякой из координат отвергается своей половиной заслона. Отказ записи
	 * первой из них до второй не доходит вовсе, оттого место под первую здесь не
	 * передаётся: так отказ достаётся именно записи второй координаты
	 */
	ASSERT_FALSE(curve.coordinates(point, nullptr, right, 0));
	/**
	 * У бесконечно удалённой точки координат нет вовсе: третья её координата нулевая,
	 * и обращать её было бы делением на ноль
	 */
	curve::point_t endless;
	// Проверяем, что незаполненная точка бесконечно удалённой и считается
	ASSERT_TRUE(curve.infinity(endless));
	// Проверяем отказ выдачи координат бесконечно удалённой точки
	ASSERT_FALSE(curve.coordinates(endless, left, right, sizeof(left)));
	// Объект незаведённой эллиптической кривой
	curve::curve_t bare;
	// Проверяем отказ выдачи координат точки незаведённой кривой
	ASSERT_FALSE(bare.coordinates(point, left, right, sizeof(left)));
	// Проверяем отказ разбора точки незаведённой кривой
	ASSERT_FALSE(bare.point(items[4], items[5], point));
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

/**
 * Проверка схождения умножения точки основания с общим умножением на точку
 */
TEST(CurveTest, Product) {
	/**
	 * Опознаватели наборов параметров всех кривых библиотеки: кратные точки основания
	 * заготавливаются на всякий набор отдельно, и сличать надо всякий
	 */
	static const char * IDENTIFIERS[] = {
		"1.2.643.7.1.2.1.2.0", "1.2.643.2.2.35.0", "1.2.643.7.1.2.1.1.1",
		"1.2.643.2.2.35.1", "1.2.643.2.2.35.2", "1.2.643.2.2.35.3",
		"1.2.643.7.1.2.1.2.1", "1.2.643.7.1.2.1.2.2", "1.2.643.7.1.2.1.2.3"
	};
	/**
	 * Выполняем обход наборов параметров кривых библиотеки
	 */
	for(size_t item = 0; item < (sizeof(IDENTIFIERS) / sizeof(IDENTIFIERS[0])); item++){
		// Объект эллиптической кривой очередного набора
		curve::curve_t elliptic;
		// Выполняем заведение кривой очередного набора параметров
		ASSERT_TRUE(curve::parameters(IDENTIFIERS[item], elliptic)) << "набор " << IDENTIFIERS[item];
		// Получаем длину координаты точки кривой
		const size_t size = elliptic.size();
		// Образующая точка подгруппы точек кривой
		curve::point_t base;
		// Получаем образующую точку подгруппы точек кривой
		elliptic.base(base);
		/**
		 * Умножение точки основания идёт по заготовленным при сборке кратным, а общее
		 * умножение - удвоениями и сложениями. Пути эти разные, а итог обязан быть
		 * один, и сличение их и есть проверка заготовленного
		 */
		for(size_t i = 1; i <= 24; i++){
			// Множитель, на который умножается точка основания
			math::number_t factor;
			/**
			 * Выполняем обнуление множителя
			 */
			for(size_t w = 0; w < math::NUMBER_WORDS; w++)
				// Обнуляем очередное слово множителя
				factor.words[w] = 0;
			/**
			 * Множитель берётся не наугад: числа с единичными разрядами по всей
			 * разрядной сетке трогают всякое окно перебора по отдельности
			 */
			for(size_t w = 0; w < ((size + 7) / 8); w++)
				// Записываем очередное слово множителя
				factor.words[w] = ((static_cast <uint64_t> (i) * 0x0123456789ABCDEFULL) ^ (static_cast <uint64_t> (w) * 0xFEDCBA9876543210ULL));
			// Произведение, полученное общим умножением на точку
			curve::point_t general;
			// Выполняем общее умножение точки основания на число
			elliptic.multiply(base, factor, general);
			// Произведение, полученное умножением точки основания
			curve::point_t fixed;
			// Выполняем умножение точки основания на число
			elliptic.product(factor, fixed);
			// Места, в которые помещаются координаты произведений
			std::vector <uint8_t> first(size, 0), second(size, 0), third(size, 0), fourth(size, 0);
			// Проверяем схождение удалённости произведений
			ASSERT_EQ(elliptic.infinity(general), elliptic.infinity(fixed)) << "набор " << IDENTIFIERS[item] << ", множитель " << i;
			// Если произведение бесконечно удалённым не является
			if(!elliptic.infinity(general)){
				// Выполняем получение координат произведения общего умножения
				ASSERT_TRUE(elliptic.coordinates(general, first.data(), second.data(), size));
				// Выполняем получение координат произведения точки основания
				ASSERT_TRUE(elliptic.coordinates(fixed, third.data(), fourth.data(), size));
				// Проверяем схождение первых координат произведений
				ASSERT_EQ(::memcmp(first.data(), third.data(), size), 0) << "набор " << IDENTIFIERS[item] << ", множитель " << i;
				// Проверяем схождение вторых координат произведений
				ASSERT_EQ(::memcmp(second.data(), fourth.data(), size), 0) << "набор " << IDENTIFIERS[item] << ", множитель " << i;
			}
		}
		// Нулевой множитель точки основания
		math::number_t zero;
		/**
		 * Выполняем обнуление множителя
		 */
		for(size_t w = 0; w < math::NUMBER_WORDS; w++)
			// Обнуляем очередное слово множителя
			zero.words[w] = 0;
		// Произведение точки основания на ноль
		curve::point_t none;
		// Выполняем умножение точки основания на ноль
		elliptic.product(zero, none);
		/**
		 * Точка основания, умноженная на ноль, бесконечно удалена: у нулевого окна
		 * кратного в таблице нет вовсе, и на его месте стоит именно она
		 */
		ASSERT_TRUE(elliptic.infinity(none)) << "набор " << IDENTIFIERS[item];
		// Единичный множитель точки основания
		math::number_t one = zero;
		// Записываем единицу множителем точки основания
		one.words[0] = 1;
		// Произведение точки основания на единицу
		curve::point_t self;
		// Выполняем умножение точки основания на единицу
		elliptic.product(one, self);
		// Места, в которые помещаются координаты точки основания и произведения
		std::vector <uint8_t> first(size, 0), second(size, 0), third(size, 0), fourth(size, 0);
		// Выполняем получение координат точки основания
		ASSERT_TRUE(elliptic.coordinates(base, first.data(), second.data(), size));
		// Выполняем получение координат произведения на единицу
		ASSERT_TRUE(elliptic.coordinates(self, third.data(), fourth.data(), size));
		// Проверяем схождение произведения на единицу с самой точкой основания
		ASSERT_EQ(::memcmp(first.data(), third.data(), size), 0) << "набор " << IDENTIFIERS[item];
		// Проверяем схождение второй координаты произведения на единицу
		ASSERT_EQ(::memcmp(second.data(), fourth.data(), size), 0) << "набор " << IDENTIFIERS[item];
	}
}

/**
 * Принадлежность подгруппе порядка q у кривой с кофактором (раздел 5.2 ГОСТ Р 34.10-2012): точка
 * G + T с T порядка два лежит на кривой и не гасится кофактором, но q·(G + T) = T - отвергается
 */
TEST(CurveTest, Subgroup){
	curve::curve_t curve;
	ASSERT_TRUE(curve::parameters("1.2.643.7.1.2.1.1.1", curve));
	ASSERT_EQ(curve.cofactor(), static_cast <uint64_t> (4));
	// Точка T порядка два: y = 0, x - корень кубического уравнения (найден отдельно)
	static const char * TX = "0100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa";
	uint8_t tx[32], ty[32] = {0};
	for(size_t i = 0; i < 32; i++){ unsigned v = 0; ::sscanf(TX + i * 2, "%2x", &v); tx[i] = static_cast <uint8_t> (v); }
	curve::point_t torsion;
	EXPECT_FALSE(curve.point(view_t(tx, sizeof(tx)), view_t(ty, sizeof(ty)), torsion));
	// Та же кривая с кофактором один: точка T читается как есть, G + T складывается
	static const char * P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", * A = "c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335", * B = "295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513", * N = "400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67", * GX = "91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28", * GY = "32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c";
	uint8_t p[32], a[32], b[32], n[32], gx[32], gy[32];
	const char * texts[6] = {P, A, B, N, GX, GY};
	uint8_t * places[6] = {p, a, b, n, gx, gy};
	for(size_t k = 0; k < 6; k++)
		for(size_t i = 0; i < 32; i++){ unsigned v = 0; ::sscanf(texts[k] + i * 2, "%2x", &v); places[k][i] = static_cast <uint8_t> (v); }
	curve::curve_t loose;
	ASSERT_TRUE(loose.start(view_t(p, 32), view_t(a, 32), view_t(b, 32), view_t(n, 32), view_t(gx, 32), view_t(gy, 32), 1));
	ASSERT_TRUE(loose.point(view_t(tx, 32), view_t(ty, 32), torsion));
	curve::point_t base, sum;
	loose.base(base);
	loose.add(base, torsion, sum);
	uint8_t sx[32], sy[32];
	ASSERT_TRUE(loose.coordinates(sum, sx, sy, 32));
	// Кривая с кофактором четыре обязана отвергнуть G + T
	curve::point_t outside;
	EXPECT_FALSE(curve.point(view_t(sx, 32), view_t(sy, 32), outside));
	// А саму G принимает
	curve::point_t inside;
	EXPECT_TRUE(curve.point(view_t(gx, 32), view_t(gy, 32), inside));
}
