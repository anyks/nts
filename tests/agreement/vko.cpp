/**
 * @file vko.cpp
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
 * @brief Исходный файл проверок модуля выработки общего ключа VKO
 *
 * @note Контрольные примеры взяты из приложения А RFC 7836, случаи седьмой и восьмой:
 *       ключи длиной 512 разрядов на наборе id-tc26-gost-3410-12-512-paramSetA с
 *       общим ключом длиной 256 и 512 разрядов
 *
 * @note Ключи в контрольных примерах записаны строкой байтов от младшего к старшему,
 *       тогда как модуль ждёт обратного порядка: разворот выполняется самой проверкой
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
#include <agreement/vko.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Секретный ключ первой стороны контрольного примера
 */
static const char * SECRET_FIRST =
	"c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"
	"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667";

/**
 * Первая координата открытого ключа первой стороны контрольного примера
 */
static const char * PUBLIC_FIRST_X =
	"aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"
	"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7";

/**
 * Вторая координата открытого ключа первой стороны контрольного примера
 */
static const char * PUBLIC_FIRST_Y =
	"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"
	"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a";

/**
 * Секретный ключ второй стороны контрольного примера
 */
static const char * SECRET_SECOND =
	"48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"
	"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db";

/**
 * Первая координата открытого ключа второй стороны контрольного примера
 */
static const char * PUBLIC_SECOND_X =
	"192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"
	"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651";

/**
 * Вторая координата открытого ключа второй стороны контрольного примера
 */
static const char * PUBLIC_SECOND_Y =
	"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"
	"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79";

/**
 * Добавочное значение сторон контрольного примера
 */
static const char * MATERIAL = "1d80603c8544c727";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками с разворотом
 *
 * @details Ключи контрольных примеров записаны строкой байтов от младшего к
 *          старшему, а модуль ждёт обратного порядка
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
	/**
	 * Выполняем разворот разобранной записи
	 */
	for(size_t i = 0; i < (result / 2); i++){
		// Запоминаем очередной байт записи
		const uint8_t item = data[i];
		// Переносим байт с конца записи в её начало
		data[i] = data[result - i - 1];
		// Переносим запомненный байт в конец записи
		data[result - i - 1] = item;
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
 * @brief Проверка выработки общего ключа по контрольным примерам
 *
 */
TEST(VkoTest, Samples) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.2.1"), curve));
	// Места, в которые помещаются ключи сторон
	uint8_t first[64], second[64], x[64], y[64], u[64], v[64], material[8];
	// Выполняем разбор секретного ключа первой стороны
	ASSERT_EQ(bytes(SECRET_FIRST, first), static_cast <size_t> (64));
	// Выполняем разбор секретного ключа второй стороны
	ASSERT_EQ(bytes(SECRET_SECOND, second), static_cast <size_t> (64));
	// Выполняем разбор координат открытого ключа первой стороны
	bytes(PUBLIC_FIRST_X, x);
	// Выполняем разбор второй координаты открытого ключа первой стороны
	bytes(PUBLIC_FIRST_Y, y);
	// Выполняем разбор координат открытого ключа второй стороны
	bytes(PUBLIC_SECOND_X, u);
	// Выполняем разбор второй координаты открытого ключа второй стороны
	bytes(PUBLIC_SECOND_Y, v);
	// Выполняем разбор добавочного значения сторон
	bytes(MATERIAL, material);
	// Место, в которое помещается общий ключ
	uint8_t key[64];
	// Выполняем выработку общего ключа первой стороной
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(material, 8), key, 32));
	// Сличаем выработанный общий ключ с контрольным примером
	ASSERT_EQ(text(key, 32), std::string("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"));
	// Выполняем выработку общего ключа второй стороной
	ASSERT_TRUE(agreement::vko(curve, view_t(second, 64), view_t(x, 64), view_t(y, 64), view_t(material, 8), key, 32));
	/**
	 * Обе стороны обязаны получить одно и то же значение: тем выработка общего ключа
	 * и отличается от всякой иной
	 */
	ASSERT_EQ(text(key, 32), std::string("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"));
	// Выполняем выработку общего ключа длиной 512 разрядов первой стороной
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(material, 8), key, 64));
	// Сличаем выработанный общий ключ с контрольным примером
	ASSERT_EQ(text(key, 64), std::string(
		"79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa"
		"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf"
	));
	// Выполняем выработку общего ключа длиной 512 разрядов второй стороной
	ASSERT_TRUE(agreement::vko(curve, view_t(second, 64), view_t(x, 64), view_t(y, 64), view_t(material, 8), key, 64));
	// Сличаем выработанный общий ключ с контрольным примером
	ASSERT_EQ(text(key, 64), std::string(
		"79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa"
		"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf"
	));
}
/**
 * @brief Проверка свойств выработки общего ключа
 *
 */
TEST(VkoTest, Properties) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.2.1"), curve));
	// Места, в которые помещаются ключи сторон
	uint8_t first[64], second[64], x[64], y[64], u[64], v[64], material[8];
	// Выполняем разбор ключей сторон контрольного примера
	bytes(SECRET_FIRST, first);
	// Выполняем разбор секретного ключа второй стороны
	bytes(SECRET_SECOND, second);
	// Выполняем разбор координат открытого ключа первой стороны
	bytes(PUBLIC_FIRST_X, x);
	// Выполняем разбор второй координаты открытого ключа первой стороны
	bytes(PUBLIC_FIRST_Y, y);
	// Выполняем разбор координат открытого ключа второй стороны
	bytes(PUBLIC_SECOND_X, u);
	// Выполняем разбор второй координаты открытого ключа второй стороны
	bytes(PUBLIC_SECOND_Y, v);
	// Выполняем разбор добавочного значения сторон
	bytes(MATERIAL, material);
	// Места, в которые помещаются вырабатываемые общие ключи
	uint8_t key[64], item[64];
	// Выполняем выработку общего ключа с добавочным значением
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(material, 8), key, 32));
	// Выполняем выработку общего ключа без добавочного значения
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(), item, 32));
	// Проверяем, что добавочное значение общий ключ меняет
	ASSERT_NE(text(key, 32), text(item, 32));
	// Выполняем выработку общего ключа с единичным добавочным значением
	const uint8_t unit[1] = {0x01};
	// Выполняем выработку общего ключа с явно переданной единицей
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(unit, 1), key, 32));
	/**
	 * Пустое добавочное значение стандарт полагает равным единице: значения обязаны
	 * совпасть
	 */
	ASSERT_EQ(text(key, 32), text(item, 32));
	// Выполняем порчу добавочного значения сторон
	material[0] = static_cast <uint8_t> (material[0] ^ 0x01);
	// Выполняем выработку общего ключа с испорченным добавочным значением
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(u, 64), view_t(v, 64), view_t(material, 8), item, 32));
	// Проверяем, что порча добавочного значения общий ключ меняет
	ASSERT_NE(text(key, 32), text(item, 32));
	// Выполняем выработку общего ключа с чужим секретным ключом
	ASSERT_TRUE(agreement::vko(curve, view_t(second, 64), view_t(u, 64), view_t(v, 64), view_t(material, 8), key, 32));
	// Проверяем, что чужой секретный ключ общий ключ меняет
	ASSERT_NE(text(key, 32), text(item, 32));
}
/**
 * @brief Проверка отказов выработки общего ключа
 *
 */
TEST(VkoTest, Failures) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.2.1"), curve));
	// Места, в которые помещаются ключи сторон
	uint8_t first[64], x[64], y[64], zero[64];
	// Выполняем разбор секретного ключа первой стороны
	bytes(SECRET_FIRST, first);
	// Выполняем разбор координат открытого ключа второй стороны
	bytes(PUBLIC_SECOND_X, x);
	// Выполняем разбор второй координаты открытого ключа второй стороны
	bytes(PUBLIC_SECOND_Y, y);
	// Выполняем обнуление места нулевого ключа
	::memset(zero, 0, sizeof(zero));
	// Место, в которое помещается общий ключ
	uint8_t key[64];
	// Объект неустановленной эллиптической кривой
	curve::curve_t empty;
	// Проверяем отказ выработки общего ключа по неустановленной кривой
	ASSERT_FALSE(agreement::vko(empty, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
	// Проверяем отказ выработки общего ключа в непереданное место
	ASSERT_FALSE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), nullptr, 32));
	// Проверяем отказ выработки общего ключа неподдерживаемой длины
	ASSERT_FALSE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 48));
	// Проверяем отказ выработки общего ключа при нулевом секретном ключе
	ASSERT_FALSE(agreement::vko(curve, view_t(zero, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
	// Проверяем отказ выработки общего ключа при нулевом добавочном значении
	ASSERT_FALSE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(zero, 8), key, 32));
	// Выполняем порчу первой координаты открытого ключа встречной стороны
	x[0] = static_cast <uint8_t> (x[0] ^ 0x01);
	/**
	 * Проверяем отказ выработки общего ключа при точке, кривой не принадлежащей: без
	 * этой проверки подставная точка малого порядка выдаёт секретный ключ
	 */
	ASSERT_FALSE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
	// Выполняем восстановление первой координаты открытого ключа встречной стороны
	x[0] = static_cast <uint8_t> (x[0] ^ 0x01);
	// Проверяем успешность выработки общего ключа после восстановления значений
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
}
