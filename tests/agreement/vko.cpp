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
#include <agreement/ecdhe.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

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
 * @brief Функция разбора записи шестнадцатеричными знаками с разворотом
 *
 * @details Ключи контрольных примеров записаны строкой байтов от младшего к
 *          старшему, а модуль ждёт обратного порядка
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
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
 * @brief Функция сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
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
	/**
	 * Непереданное добавочное значение означает его отсутствие, и выработка идёт по
	 * единице на его месте. Переданность и длина сверяются РАЗНЫМИ половинами
	 * условия, и заявленная длина при непереданном месте отсутствия не отменяет
	 */
	uint8_t bare[64] = {0}, hollow[64] = {0};
	// Выполняем выработку общего ключа с непереданным добавочным значением
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(nullptr, 8), bare, 32));
	// Выполняем выработку общего ключа вовсе без добавочного значения
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), hollow, 32));
	// Проверяем схождение выработки с непереданным добавочным значением с выработкой без него
	ASSERT_EQ(::memcmp(bare, hollow, 32), 0);
	// Проверяем отказ выработки общего ключа неподдерживаемой длины
	ASSERT_FALSE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 48));
	// Проверяем отказ выработки общего ключа при нулевом секретном ключе
	ASSERT_FALSE(agreement::vko(curve, view_t(zero, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
	// Место, в которое помещается секретный ключ, порядку подгруппы не отвечающий
	uint8_t excess[64];
	// Заполняем место секретного ключа старшими значениями
	::memset(excess, 0xFF, sizeof(excess));
	/**
	 * Секретный ключ, порядок подгруппы превзошедший, отвергается разбором, а не
	 * сверкой на ноль: половины условия отвергают ключ всякая в одиночку
	 */
	ASSERT_FALSE(agreement::vko(curve, view_t(excess, 64), view_t(x, 64), view_t(y, 64), view_t(), key, 32));
	// Место, в которое помещается выработка при добавочном значении нулевой длины
	uint8_t sparse[64] = {0};
	/**
	 * Переданное место нулевой длины - вторая половина отсутствия добавочного
	 * значения, и выработка обязана сойтись с выработкой вовсе без него
	 */
	ASSERT_TRUE(agreement::vko(curve, view_t(first, 64), view_t(x, 64), view_t(y, 64), view_t(x, 0), sparse, 32));
	// Проверяем схождение выработки с добавочным значением нулевой длины с выработкой без него
	ASSERT_EQ(::memcmp(sparse, hollow, 32), 0);
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

/**
 * @brief Проверка границ длин выработки общего ключа
 *
 */
TEST(VkoTest, Bounds) {
	// Объект эллиптической кривой длиной 256 разрядов
	curve::curve_t curve;
	// Выполняем установку кривой длиной 256 разрядов
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.2.2.35.1"), curve));
	// Проверяем длину координаты заведённой кривой
	ASSERT_EQ(curve.size(), static_cast <size_t> (32));
	// Пара ключей первой стороны
	uint8_t first[32] = {0}, opened[64] = {0};
	// Пара ключей второй стороны
	uint8_t second[32] = {0}, answer[64] = {0};
	// Выполняем выработку пары ключей первой стороны
	ASSERT_TRUE(agreement::generate(curve, first, opened));
	// Выполняем выработку пары ключей второй стороны
	ASSERT_TRUE(agreement::generate(curve, second, answer));
	/**
	 * Выработка пары ключей отдаёт записи от младшего байта к старшему - той же
	 * записью, какой ключи идут по связи, - а выработка общего ключа ждёт обратного
	 * порядка: разворот выполняется самой проверкой
	 */
	uint8_t owned[32] = {0}, mated[32] = {0}, shown[64] = {0}, faced[64] = {0};
	/**
	 * Выполняем разворот записей выработанных пар ключей
	 */
	for(size_t i = 0; i < 32; i++){
		// Переносим очередной байт секретного ключа первой стороны
		owned[i] = first[32 - i - 1];
		// Переносим очередной байт секретного ключа второй стороны
		mated[i] = second[32 - i - 1];
		// Переносим очередной байт первой координаты открытого ключа первой стороны
		shown[i] = opened[32 - i - 1];
		// Переносим очередной байт второй координаты открытого ключа первой стороны
		shown[32 + i] = opened[64 - i - 1];
		// Переносим очередной байт первой координаты открытого ключа второй стороны
		faced[i] = answer[32 - i - 1];
		// Переносим очередной байт второй координаты открытого ключа второй стороны
		faced[32 + i] = answer[64 - i - 1];
	}
	// Места, в которые помещаются вырабатываемые общие ключи
	uint8_t key[64] = {0}, item[64] = {0};
	/**
	 * Общий ключ длиной 256 разрядов кривая длиной 256 разрядов вырабатывать вправе:
	 * раздел 4.3.1 RFC 7836 требует лишь n >= 512 разрядов, а тут их ровно 512
	 */
	ASSERT_TRUE(agreement::vko(curve, view_t(owned, 32), view_t(faced, 32), view_t(faced + 32, 32), view_t(), key, 32));
	// Выполняем выработку общего ключа встречной стороной
	ASSERT_TRUE(agreement::vko(curve, view_t(mated, 32), view_t(shown, 32), view_t(shown + 32, 32), view_t(), item, 32));
	// Проверяем схождение общего ключа у обеих сторон
	ASSERT_EQ(::memcmp(key, item, 32), 0);
	/**
	 * А вот общий ключ длиной 512 разрядов той же кривой недоступен: раздел 4.3.2 RFC
	 * 7836 требует n >= 1024 разрядов, тогда как кривая даёт лишь 512
	 */
	ASSERT_FALSE(agreement::vko(curve, view_t(owned, 32), view_t(faced, 32), view_t(faced + 32, 32), view_t(), key, 64));
	// Место, в которое помещается добавочное значение сторон
	uint8_t material[33] = {0};
	// Заполняем добавочное значение сторон значимыми байтами
	::memset(material, 0x5A, sizeof(material));
	/**
	 * Добавочное значение длиною в одну координату дозволено, ибо разделы 4.3.1 и
	 * 4.3.2 держат его в пределах n/2 разрядов
	 */
	ASSERT_TRUE(agreement::vko(curve, view_t(owned, 32), view_t(faced, 32), view_t(faced + 32, 32), view_t(material, 32), key, 32));
	/**
	 * Добавочное значение, границу превзошедшее, отвергается: приведение по порядку
	 * подгруппы приняло бы его молча, обратив в остаток и сойдясь с иным значением
	 */
	ASSERT_FALSE(agreement::vko(curve, view_t(owned, 32), view_t(faced, 32), view_t(faced + 32, 32), view_t(material, 33), key, 32));
	// Объект эллиптической кривой длиной 512 разрядов
	curve::curve_t wide;
	// Выполняем установку кривой длиной 512 разрядов
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.2.1"), wide));
	// Места, в которые помещаются ключи сторон контрольного примера
	uint8_t owner[64], x[64], y[64];
	// Выполняем разбор секретного ключа первой стороны
	bytes(SECRET_FIRST, owner);
	// Выполняем разбор координат открытого ключа второй стороны
	bytes(PUBLIC_SECOND_X, x);
	// Выполняем разбор второй координаты открытого ключа второй стороны
	bytes(PUBLIC_SECOND_Y, y);
	// Место, в которое помещается добавочное значение сторон границы кривой
	uint8_t lengthy[65] = {0};
	// Заполняем добавочное значение сторон значимыми байтами
	::memset(lengthy, 0x5A, sizeof(lengthy));
	/**
	 * У кривой длиной 512 разрядов граница добавочного значения вдвое шире, и то же
	 * самое значение длиной 33 байта ею уже принимается
	 */
	ASSERT_TRUE(agreement::vko(wide, view_t(owner, 64), view_t(x, 64), view_t(y, 64), view_t(lengthy, 33), key, 32));
	// Проверяем отказ выработки при добавочном значении сверх границы широкой кривой
	ASSERT_FALSE(agreement::vko(wide, view_t(owner, 64), view_t(x, 64), view_t(y, 64), view_t(lengthy, 65), key, 32));
}

/**
 * @brief Проверка отсечения точки малого порядка на кривой с кофактором четыре
 *
 */
TEST(VkoTest, Torsion) {
	// Контекст кривой набора параметров
	curve::curve_t curve;
	// Набор параметров с кофактором четыре: группа TLS GC256A
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.1.1"), curve));
	// Кофактор набора равен четырём
	ASSERT_EQ(curve.cofactor(), static_cast <uint64_t> (4));
	/**
	 * Точка порядка два: корень уравнения x^3 + a*x + b = 0 при y = 0. Уравнению
	 * кривой она отвечает, а подгруппе порядка q не принадлежит
	 */
	// Буферы координат точки и собственного секрета
	uint8_t x[32], y[32], secret[32];
	// Абсцисса точки порядка два разобрана из записи в тридцать два байта
	ASSERT_EQ(bytes("0100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa", x), static_cast <size_t> (32));
	/**
	 * Помощник bytes() разворачивает запись к младшему байту вперёд, а координаты
	 * точки подаются от старшего: без разворота обратно точка на кривой не лежала
	 * бы вовсе, и отказ ничего о кручении не говорил бы (поправлено кругом 34)
	 */
	for(size_t i = 0; i < 16; i++){ const uint8_t item = x[i]; x[i] = x[31 - i]; x[31 - i] = item; }
	::memset(y, 0, sizeof(y));
	::memset(secret, 0x01, sizeof(secret));
	// Точка порядка два лежит на кривой: без просьбы о подгруппе разбор её принимает
	curve::point_t torsion;
	// Без просьбы о подгруппе точка порядка два на кривой принимается
	ASSERT_TRUE(curve.point(view_t(x, 32), view_t(y, 32), torsion, false));
	/**
	 * Разбор точки обязан её отвергнуть: умножение на кофактор обращает её в ноль
	 */
	curve::point_t point;
	// С просьбой о подгруппе точка порядка два отвергается
	ASSERT_FALSE(curve.point(view_t(x, 32), view_t(y, 32), point));
	// Место общего ключа
	uint8_t key[32];
	/**
	 * Раздел 5.2 ГОСТ Р 34.10-2012: чужой ключ вне подгруппы отвергается при любом
	 * своём секрете. До правки выработка удавалась при нечётном множителе и выдавала
	 * разряд секретного ключа
	 */
	ASSERT_FALSE(agreement::vko(curve, view_t(secret, 32), view_t(x, 32), view_t(y, 32), view_t(), key, 32));
	// Годный ключ той же кривой по-прежнему принимается
	uint8_t opened[64], mine[32];
	// Годная пара ключей той же кривой вырабатывается
	ASSERT_TRUE(agreement::generate(curve, mine, opened));
	// Буферы координат и секрета, развёрнутых к старшему байту вперёд
	uint8_t px[32], py[32], sec[32];
	/**
	 * Разворачиваем координаты и секрет к старшему байту вперёд, как того ждёт выработка
	 */
	for(size_t i = 0; i < 32; i++){
		// Абсцисса открытого ключа с разворотом
		px[i] = opened[31 - i];
		// Ордината открытого ключа с разворотом
		py[i] = opened[63 - i];
		// Секрет с разворотом
		sec[i] = mine[31 - i];
	}
	// Годный ключ по-прежнему принимается после отсечения кручения
	ASSERT_TRUE(agreement::vko(curve, view_t(sec, 32), view_t(px, 32), view_t(py, 32), view_t(), key, 32));
}

/**
 * @brief Проверка снятия кручения умножением на кофактор без проверки подгруппы
 *
 * @details Раздел 4.3 RFC 7836 множит кофактором и от чужой точки требует лишь
 *          принадлежности кривой. Точка Q + T с T порядка два после умножения на
 *          кофактор кручения не несёт: 4·(Q + T) = 4·Q, и общий ключ тот же, что у Q
 *
 */
TEST(VkoTest, Cleared) {
	// Контекст кривой набора параметров
	curve::curve_t curve;
	// Набор параметров с кофактором четыре: группа TLS GC256A
	ASSERT_TRUE(curve::parameters(std::string("1.2.643.7.1.2.1.1.1"), curve));
	// Кофактор набора равен четырём
	ASSERT_EQ(curve.cofactor(), static_cast <uint64_t> (4));
	// Значения набора и точка T порядка два (корень x^3 + a·x + b при y = 0) от старшего байта
	const auto decode = [](const char * text, uint8_t * place) noexcept -> void {
		/**
		 * Побайтовый разбор шестнадцатеричной записи: каждые два символа — один байт
		 */
		for(size_t i = 0; i < 32; i++){ unsigned v = 0; ::sscanf(text + i * 2, "%2x", &v); place[i] = static_cast <uint8_t> (v); }
	};
	// Буферы полей набора и координат точки T
	uint8_t p[32], a[32], b[32], n[32], gx[32], gy[32], tx[32], ty[32] = {0};
	// Модуль p набора
	decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", p);
	decode("c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335", a);
	decode("295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513", b);
	decode("400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67", n);
	decode("91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28", gx);
	decode("32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c", gy);
	decode("0100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa", tx);
	// Та же кривая с кофактором один: T читается как есть, и G + T складывается её арифметикой
	curve::curve_t loose;
	// Запуск кривой с кофактором один на разобранных параметрах
	ASSERT_TRUE(loose.start(view_t(p, 32), view_t(a, 32), view_t(b, 32), view_t(n, 32), view_t(gx, 32), view_t(gy, 32), 1));
	// Точка кручения T, точка основания G и сумма G + T
	curve::point_t torsion, base, sum;
	// Точка T читается на кривой с кофактором один
	ASSERT_TRUE(loose.point(view_t(tx, 32), view_t(ty, 32), torsion));
	// Получаем точку основания G
	loose.base(base);
	// Складываем G с точкой кручения T
	loose.add(base, torsion, sum);
	// Буферы координат суммы G + T
	uint8_t sx[32], sy[32];
	// Получаем координаты суммы
	ASSERT_TRUE(loose.coordinates(sum, sx, sy, 32));
	// Свой секрет: меньше порядка подгруппы
	uint8_t secret[32];
	::memset(secret, 0x1a, sizeof(secret));
	// Приёмники общих ключей по G + T и по G
	uint8_t first[32], second[32];
	// Точка G + T вне подгруппы, но на кривой, принимается, и общий ключ по ней равен ключу по G
	ASSERT_TRUE(agreement::vko(curve, view_t(secret, 32), view_t(sx, 32), view_t(sy, 32), view_t(), first, 32));
	ASSERT_TRUE(agreement::vko(curve, view_t(secret, 32), view_t(gx, 32), view_t(gy, 32), view_t(), second, 32));
	// Общие ключи по G + T и по G обязаны совпадать
	EXPECT_EQ(::memcmp(first, second, 32), 0);
	// Одна лишь T обращается кофактором в ноль и отвергается (VkoTest.Torsion)
	EXPECT_FALSE(agreement::vko(curve, view_t(secret, 32), view_t(tx, 32), view_t(ty, 32), view_t(), first, 32));
}
