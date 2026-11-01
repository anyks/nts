/**
 * @file gost.cpp
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
 * @brief Исходный файл проверок модуля электронной подписи по ГОСТ Р 34.10-2012
 *
 * @note Контрольный пример взят из раздела 7 RFC 7091 целиком: кривая, ключ подписи,
 *       ключ проверки, хеш сообщения, случайное число выработки и обе части подписи
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <posix.hpp>
#include <main.hpp>
#include <starve.hpp>
#include <sign/gost.hpp>
#include <keys/keys.hpp>
#include <math/integer.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Хеш подписываемого сообщения контрольного примера
 */
static const char * DIGEST = "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5";

/**
 * Случайное число выработки подписи контрольного примера
 */
static const char * RANDOM = "77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3";

/**
 * Ключ подписи контрольного примера
 */
static const char * SECRET = "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28";

/**
 * Ожидаемая подпись контрольного примера
 */
static const char * SIGNATURE =
	"41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
	"01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40";

/**
 * @brief Функция разбора записи шестнадцатеричными знаками
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
 * @brief Функция установки кривой контрольного примера
 *
 * @param curve устанавливаемая кривая
 * @return      признак успешности установки кривой
 *
 */
static bool prepare(curve::curve_t & curve) {
	// Места, в которые помещаются параметры кривой
	uint8_t modulus[32], first[32], second[32], order[32], x[32], y[32];
	// Выполняем установку параметров кривой
	return curve.start(
		view_t(modulus, bytes("8000000000000000000000000000000000000000000000000000000000000431", modulus)),
		view_t(first, bytes("07", first)),
		view_t(second, bytes("5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e", second)),
		view_t(order, bytes("8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3", order)),
		view_t(x, bytes("02", x)),
		view_t(y, bytes("08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8", y))
	);
}

/**
 * @brief Проверка выработки подписи контрольного примера
 *
 */
TEST(GostTest, Make) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], digest[32], random[32];
	// Выполняем разбор ключа подписи
	ASSERT_TRUE(gost.secret(view_t(secret, bytes(SECRET, secret))));
	// Места, в которые записывается ключ проверки подписи
	uint8_t x[32], y[32];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(gost.key(x, y, sizeof(x)));
	// Сличаем первую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(x, sizeof(x)), std::string("7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b"));
	// Сличаем вторую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(y, sizeof(y)), std::string("26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da"));
	// Проверяем размер подписи
	ASSERT_EQ(gost.size(), static_cast <size_t> (64));
	// Место, в которое помещается выработанная подпись
	uint8_t signature[64];
	// Выполняем выработку подписи
	ASSERT_TRUE(gost.make(
		view_t(digest, bytes(DIGEST, digest)),
		view_t(random, bytes(RANDOM, random)),
		signature
	));
	// Сличаем выработанную подпись с контрольным примером
	ASSERT_EQ(text(signature, sizeof(signature)), std::string(SIGNATURE));
	// Выполняем проверку выработанной подписи
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
}
/**
 * @brief Проверка подписи одним лишь ключом проверки
 *
 */
TEST(GostTest, Check) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Места, в которые помещаются разбираемые записи
	uint8_t x[32], y[32], digest[32], signature[64];
	// Выполняем разбор координат ключа проверки подписи
	bytes("7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b", x);
	bytes("26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da", y);
	// Выполняем установку ключа проверки подписи
	ASSERT_TRUE(gost.key(view_t(x, sizeof(x)), view_t(y, sizeof(y))));
	// Выполняем разбор хеша подписанного сообщения
	bytes(DIGEST, digest);
	// Выполняем разбор проверяемой подписи
	bytes(SIGNATURE, signature);
	// Проверяем схождение подписи контрольного примера
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Проверяем отказ выработки подписи без ключа подписи
	uint8_t buffer[64];
	// Выполняем попытку выработки подписи
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(x, sizeof(x)), buffer));
	/**
	 * Выполняем перебор байтов подписи
	 */
	for(size_t i = 0; i < sizeof(signature); i++){
		// Выполняем порчу очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
		// Проверяем отказ проверки испорченной подписи
		ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
	}
	/**
	 * Выполняем перебор байтов хеша подписанного сообщения
	 */
	for(size_t i = 0; i < sizeof(digest); i++){
		// Выполняем порчу очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
		// Проверяем отказ проверки подписи при испорченном хеше
		ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
	}
	// Проверяем схождение подписи после восстановления всех значений
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
}
/**
 * @brief Проверка отказов модуля электронной подписи
 *
 */
TEST(GostTest, Failures) {
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Проверяем отказ работы модуля до установки кривой
	ASSERT_FALSE(gost.ready());
	// Проверяем нулевой размер подписи до установки кривой
	ASSERT_EQ(gost.size(), static_cast <size_t> (0));
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], digest[32], signature[64];
	// Выполняем разбор ключа подписи
	bytes(SECRET, secret);
	// Проверяем отказ установки ключа подписи до установки кривой
	ASSERT_FALSE(gost.secret(view_t(secret, sizeof(secret))));
	// Места, в которые помещаются координаты ключа проверки подписи
	uint8_t first[32], second[32];
	/**
	 * Заведённость кривой сверяется ОТДЕЛЬНОЙ половиной условия от наличия ключа, и
	 * всякий вызов до заведения кривой трогает именно её: ключей нет ни того, ни
	 * другого, но останавливает вызов раньше них отсутствие самой кривой
	 */
	ASSERT_FALSE(gost.key(first, second, sizeof(first)));
	// Проверяем отказ выработки подписи до установки кривой
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), signature));
	// Проверяем отказ выработки подписи со своим случайным числом до установки кривой
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(secret, sizeof(secret)), signature));
	// Проверяем отказ проверки подписи до установки кривой
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Объект неустановленной эллиптической кривой
	curve::curve_t empty;
	// Проверяем отказ установки неготовой кривой
	ASSERT_FALSE(gost.start(empty));
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Проверяем готовность модуля к работе
	ASSERT_TRUE(gost.ready());
	// Место, в которое помещается нулевой ключ подписи
	uint8_t zero[32];
	// Выполняем обнуление ключа подписи
	::memset(zero, 0, sizeof(zero));
	// Проверяем отказ установки нулевого ключа подписи
	ASSERT_FALSE(gost.secret(view_t(zero, sizeof(zero))));
	// Места, в которые помещаются координаты ключа проверки подписи
	uint8_t x[32], y[32];
	// Проверяем отказ выдачи координат ключа проверки до его установки
	ASSERT_FALSE(gost.key(x, y, sizeof(x)));
	// Проверяем отказ проверки подписи без ключа проверки
	ASSERT_FALSE(gost.check(view_t(digest, bytes(DIGEST, digest)), view_t(signature, bytes(SIGNATURE, signature))));
	// Проверяем отказ выработки подписи со своим случайным числом до ключа подписи
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), signature));
	// Выполняем установку ключа подписи
	ASSERT_TRUE(gost.secret(view_t(secret, sizeof(secret))));
	// Проверяем отказ выработки подписи при нулевом случайном числе
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(zero, sizeof(zero)), signature));
	// Проверяем отказ выработки подписи в непереданное место
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(secret, sizeof(secret)), nullptr));
	// Проверяем отказ выработки подписи со своим случайным числом в непереданное место
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), nullptr));
	// Проверяем отказ проверки подписи неверной длины
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, 32)));
	// Проверяем отказ проверки непереданной подписи
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(nullptr, sizeof(signature))));
	// Возвращаем годную подпись контрольного примера на место
	bytes(SIGNATURE, signature);
	/**
	 * Ноль отвергается у ВСЯКОЙ из двух частей подписи по отдельности. Обнуление
	 * подписи целиком обращает в ноль обе части разом и вторую половину заслона не
	 * трогает, оттого части обнуляются порознь
	 */
	::memset(signature, 0, (sizeof(signature) / 2));
	// Проверяем отказ проверки подписи с нулевой первой частью
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Возвращаем годную подпись контрольного примера на место
	bytes(SIGNATURE, signature);
	// Выполняем обнуление второй части проверяемой подписи
	::memset((signature + (sizeof(signature) / 2)), 0, (sizeof(signature) / 2));
	// Проверяем отказ проверки подписи с нулевой второй частью
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Выполняем обнуление проверяемой подписи
	::memset(signature, 0, sizeof(signature));
	// Проверяем отказ проверки нулевой подписи
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Выполняем сброс состояния модуля
	gost.clear();
	// Проверяем отказ работы модуля после сброса его состояния
	ASSERT_FALSE(gost.ready());
	/**
	 * Открытый ключ просмотрами координат до установки кривой: кривой, на которую
	 * класть точку, нет, - отказ приходит от самой перегрузки, а не от установки
	 */
	sign::gost_t bare;
	// Проверяем отказ установки ключа просмотрами до установки кривой
	ASSERT_FALSE(bare.key(view_t(x, sizeof(x)), view_t(y, sizeof(y))));
	/**
	 * Вторая половина подписи не меньше порядка подгруппы: число такое загрузить
	 * нельзя, и подпись отвергается до всякого счёта - раздел 6.2 ГОСТ Р 34.10-2012
	 */
	ASSERT_TRUE(gost.start(curve));
	// Берём годную подпись и ставим вторую её половину не меньше порядка
	bytes(SIGNATURE, signature);
	::memset((signature + (sizeof(signature) / 2)), 0xFF, (sizeof(signature) / 2));
	// Проверяем отказ на подписи со второй половиной не меньше порядка
	ASSERT_FALSE(gost.check(view_t(digest, bytes(DIGEST, digest)), view_t(signature, sizeof(signature))));
}

/**
 * @brief Функция запуска команды оболочки без консоли на входе
 *
 * @details stdin подаётся из /dev/null: у оболочки инструмента разработки он бывает
 *          сокетом, tcgetattr на нём отвечает EOPNOTSUPP, и консольный слой openssl
 *          валит разбор даже при пароле, заданном доводом
 *
 * @param command запускаемая команда
 * @return        код возврата команды
 *
 */
static int shell(const std::string & command) {
	// Запускаем команду с пустым входом
	return ::system((command + " </dev/null").c_str());
}
/**
 * @brief Функция чтения файла целиком
 *
 * @param path путь к файлу
 * @return     содержимое файла
 *
 */
static std::string slurp(const std::string & path) {
	// Открываем файл на чтение
	std::ifstream file(path, std::ios::binary);
	// Читаем содержимое файла в поток
	std::stringstream stream;
	// Переливаем содержимое файла
	stream << file.rdbuf();
	// Выводим содержимое файла
	return stream.str();
}

/**
 * Порог расстояния Колмогорова между распределением старшего байта ключа и
 * равномерным: при двух тысячах порождений случайное превышение его вероятно
 * не более чем в одном случае из ста тысяч
 */
static const double DISTANCE = 0.055;

/**
 * Порог расстояния смещённой модели от равномерной, с которого смещение обязано
 * ловиться порогом DISTANCE по выборке
 */
static const double NOTICEABLE = 0.08;

/**
 * Кривые ГОСТ Р 34.10-2012 порождения: 256 разрядов с порядком от 0x40 и от 0x9b,
 * 512 разрядов с порядком от 0x45 и от 0xff
 */
static const char * TC26_256_A = "1.2.643.7.1.2.1.1.1";
// Порождение 256 разрядов с порядком от 0x9b: кривая КриптоПро C
static const char * CRYPTOPRO_C = "1.2.643.2.2.35.3";
// Проверочное порождение 512 разрядов с порядком от 0x45: испытательная кривая ТК26
static const char * TC26_512_TEST = "1.2.643.7.1.2.1.2.0";
// Порождение 512 разрядов с порядком от 0xff: кривая ТК26 А
static const char * TC26_512_A = "1.2.643.7.1.2.1.2.1";

/**
 * @brief Функция получения наибольшего числа порядка подгруппы кривой
 *
 * @param curve  кривая
 * @param result место, в которое записывается порядок без единицы длиной в порядок
 * @return       признак успешности получения
 *
 */
static bool bound(const curve::curve_t & curve, uint8_t * result) {
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = curve.order();
	// Ноль, единица и порядок без единицы
	math::number_t zero, one, last;
	// Получаем ноль в виде числа порядка
	order.word(0, zero);
	// Получаем единицу в виде числа порядка
	order.word(1, one);
	// Вычитание единицы из нуля по порядку даёт порядок без единицы
	order.subtract(zero, one, last);
	// Записываем порядок без единицы
	return order.store(last, result, order.size());
}
/**
 * @brief Функция получения расстояния Колмогорова между выборкой старшего байта и равномерным распределением
 *
 * @param histogram число выпадений всякого значения старшего байта
 * @param count     число значений в выборке
 * @param span      порядок подгруппы в единицах старшего байта
 * @return          наибольшее расхождение накопленных долей
 *
 */
static double distance(const std::vector <size_t> & histogram, const size_t count, const double span) {
	// Наибольшее расхождение
	double result = 0.0;
	// Накопленное число выпадений
	size_t accumulated = 0;
	/**
	 * Выполняем перебор значений старшего байта
	 */
	for(size_t value = 0; value < 256; value++){
		// Накапливаем выпадения очередного значения
		accumulated += histogram[value];
		// Накопленная доля равномерного распределения на отрезке до порядка
		const double expected = (std::min(static_cast <double> (value + 1), span) / span);
		// Расхождение долей
		const double gap = std::fabs((static_cast <double> (accumulated) / static_cast <double> (count)) - expected);
		// Запоминаем наибольшее расхождение
		result = std::max(result, gap);
	}
	// Выводим наибольшее расхождение
	return result;
}
/**
 * @brief Функция получения расстояния распределения остатка по модулю от равномерного
 *
 * @details Остаток случайных байтов по модулю порядка: значения от порядка до
 *          степени двойки складываются на начало отрезка, оттого плотность на
 *          начале выше. Расстояние считается по накопленным долям точно
 *
 * @param span порядок подгруппы в единицах старшего байта
 * @return     наибольшее расхождение накопленных долей
 *
 */
static double folded(const double span) {
	// Наибольшее расхождение
	double result = 0.0;
	// Накопленная масса остатка
	double accumulated = 0.0;
	// Шаг счёта в единицах старшего байта
	const double step = (1.0 / 1024.0);
	/**
	 * Выполняем перебор значений старшего байта
	 */
	for(size_t value = 0; value < 256; value++){
		/**
		 * Выполняем накопление плотности остатка на отрезке очередного значения
		 */
		for(double x = static_cast <double> (value); x < std::min(static_cast <double> (value + 1), span); x += step)
			// Плотность остатка в точке есть число слоёв, легших на неё
			accumulated += (std::ceil((256.0 - x) / span) * step / 256.0);
		// Накопленная доля равномерного распределения на отрезке до порядка
		const double expected = (std::min(static_cast <double> (value + 1), span) / span);
		// Запоминаем наибольшее расхождение
		result = std::max(result, std::fabs(accumulated - expected));
	}
	// Выводим наибольшее расхождение
	return result;
}
/**
 * @brief Функция выработки числа остатком случайных байтов по модулю порядка
 *
 * @details Намеренно смещённый способ: служит контролем того, что проверка
 *          равномерности различает отбор и остаток
 *
 * @param modulus порядок подгруппы
 * @param size    длина порядка в байтах
 * @param result  место, в которое записывается остаток
 * @return        признак успешности выработки
 *
 */
static bool remainder(const math::integer_t & modulus, const size_t size, uint8_t * result) {
	// Случайные байты
	uint8_t buffer[math::NUMBER_SIZE];
	// Если случайные байты получить не удалось
	if(!entropy::bytes(buffer, size))
		// Выводим отрицательный результат - случайные байты не получены
		return false;
	// Число из случайных байтов и его остаток
	math::integer_t value, reduced;
	// Если число разобрать либо привести по модулю не удалось
	if(!value.load(view_t(buffer, size)) || !reduced.reduce(value, modulus))
		// Выводим отрицательный результат - число не разобрано либо не приведено
		return false;
	// Записываем остаток
	return reduced.store(result, size);
}
/**
 * @brief Проверка порождения ключей на кривой: границы, различие, сходимость и равномерность
 *
 * @param oid   опознаватель кривой
 * @param count число порождений
 *
 */
static void generation(const char * oid, const size_t count) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters(std::string(oid), curve)) << "Кривая: " << oid;
	// Размер порядка подгруппы
	const size_t size = curve.order().size();
	// Порядок без единицы
	uint8_t last[math::NUMBER_SIZE];
	// Выполняем получение порядка без единицы
	ASSERT_TRUE(bound(curve, last)) << "Кривая: " << oid;
	// Порядок в единицах старшего байта: четыре старших байта дробью
	const double span = (last[0] + (last[1] / 256.0) + (last[2] / 65536.0) + (last[3] / 16777216.0));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve)) << "Кривая: " << oid;
	// Предел длины подписи равен длине сырой подписи
	ASSERT_EQ(gost.limit(), gost.size()) << "Кривая: " << oid;
	// Предел равен двум длинам порядка
	ASSERT_EQ(gost.limit(), size * 2) << "Кривая: " << oid;
	// Число выпадений всякого значения старшего байта
	std::vector <size_t> histogram(256, 0);
	// Число ключей со взведённым старшим разрядом
	size_t senior = 0;
	// Прежний порождённый ключ
	uint8_t previous[math::NUMBER_SIZE];
	// Обнуляем прежний ключ
	::memset(previous, 0, sizeof(previous));
	// Хеш сообщения длиной в порядок
	uint8_t digest[math::NUMBER_SIZE];
	// Заполняем хеш сообщения
	::memset(digest, 0x5a, sizeof(digest));
	/**
	 * Выполняем порождения
	 */
	for(size_t i = 0; i < count; i++){
		// Порождённый ключ подписи
		uint8_t secret[math::NUMBER_SIZE];
		// Проверяем отказ порождения в место неверного размера
		ASSERT_FALSE(gost.generate(secret, size + 1)) << "Кривая: " << oid;
		// Выполняем порождение ключа подписи
		ASSERT_TRUE(gost.generate(secret, size)) << "Кривая: " << oid << ", порождение " << i;
		// Ключ не превышает порядка без единицы
		ASSERT_LE(::memcmp(secret, last, size), 0) << "Кривая: " << oid << ", порождение " << i;
		// Накопленное значение байтов ключа по ИЛИ
		uint8_t accumulated = 0;
		/**
		 * Выполняем накопление байтов ключа
		 */
		for(size_t j = 0; j < size; j++)
			// Накапливаем очередной байт
			accumulated |= secret[j];
		// Ключ не ноль
		ASSERT_NE(accumulated, 0) << "Кривая: " << oid << ", порождение " << i;
		// Ключ отличается от прежнего
		ASSERT_NE(::memcmp(secret, previous, size), 0) << "Кривая: " << oid << ", порождение " << i;
		// Запоминаем ключ
		::memcpy(previous, secret, size);
		// Если порождение из первых
		if(i < 4){
			// Координаты ключа проверки порождённого и выведенного ключей
			uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE], px[math::NUMBER_SIZE], py[math::NUMBER_SIZE];
			// Выполняем получение ключа проверки порождённого ключа
			ASSERT_TRUE(gost.key(x, y, size)) << "Кривая: " << oid;
			// Объект модуля с тем же ключом, установленным через secret
			sign::gost_t other;
			// Выполняем установку эллиптической кривой
			ASSERT_TRUE(other.start(curve)) << "Кривая: " << oid;
			// Выполняем установку порождённого ключа как переданного
			ASSERT_TRUE(other.secret(view_t(secret, size))) << "Кривая: " << oid;
			// Выполняем получение ключа проверки выведенного ключа
			ASSERT_TRUE(other.key(px, py, size)) << "Кривая: " << oid;
			// Открытая часть порождённого ключа совпадает с выведенной через secret
			ASSERT_EQ(text(x, size), text(px, size)) << "Кривая: " << oid;
			ASSERT_EQ(text(y, size), text(py, size)) << "Кривая: " << oid;
			// Место подписи
			uint8_t signature[math::NUMBER_SIZE * 2];
			// Выполняем выработку подписи порождённым ключом
			ASSERT_TRUE(gost.make(view_t(digest, size), signature)) << "Кривая: " << oid;
			// Подпись сходится у выведенного ключа
			ASSERT_TRUE(other.check(view_t(digest, size), view_t(signature, size * 2))) << "Кривая: " << oid;
		}
		// Учитываем старший байт ключа
		histogram[secret[0]]++;
		// Учитываем старший разряд ключа
		senior += (secret[0] >> 7);
	}
	// Распределение старшего байта не смещено от равномерного на отрезке до порядка
	ASSERT_LT(distance(histogram, count, span), DISTANCE) << "Кривая: " << oid;
	// Ожидаемая доля ключей со взведённым старшим разрядом
	const double expected = ((span > 128.0) ? ((span - 128.0) / span) : 0.0);
	// Доля ключей со взведённым старшим разрядом сходится с ожидаемой по порядку
	ASSERT_NEAR((static_cast <double> (senior) / static_cast <double> (count)), expected, 0.05) << "Кривая: " << oid;
	/**
	 * Контроль различения: у кривой, чей порядок заметно меньше степени двойки,
	 * остаток по модулю смещён ощутимо, и выборка остатков обязана проваливать
	 * тот же порог, который выборка отбора прошла
	 */
	if(folded(span) > NOTICEABLE){
		// Порядок как целое число
		math::integer_t modulus, one, reduced;
		// Разбираем порядок без единицы
		ASSERT_TRUE(reduced.load(view_t(last, size)));
		// Записываем единицу
		one.word(1);
		// Складываем порядок из порядка без единицы и единицы
		ASSERT_TRUE(modulus.add(reduced, one));
		// Число выпадений всякого значения старшего байта остатка
		std::vector <size_t> biased(256, 0);
		/**
		 * Выполняем выработку остатков вдвое большей выборкой
		 */
		for(size_t i = 0; i < (count * 2); i++){
			// Остаток случайных байтов по модулю
			uint8_t value[math::NUMBER_SIZE];
			// Выполняем выработку остатка
			ASSERT_TRUE(remainder(modulus, size, value));
			// Учитываем старший байт остатка
			biased[value[0]]++;
		}
		// Выборка остатков проваливает порог
		ASSERT_GE(distance(biased, count * 2, span), DISTANCE) << "Кривая: " << oid;
	}
}
/**
 * @brief Проверка порождения ключей на кривой в 256 разрядов с порядком от 0x40
 *
 */
TEST(GostTest, Generate256) {
	// Выполняем проверку порождения
	generation(TC26_256_A, 2000);
}
/**
 * @brief Проверка порождения ключей на кривой в 256 разрядов с порядком от 0x9b
 *
 * @note Здесь контроль остатком по модулю различим, и он закрепляет, что проверка
 *       равномерности ловит смещение
 *
 */
TEST(GostTest, GenerateFolded) {
	// Выполняем проверку порождения
	generation(CRYPTOPRO_C, 2000);
}
/**
 * @brief Проверка порождения ключей на кривой в 512 разрядов с порядком от 0x45
 *
 */
TEST(GostTest, Generate512Test) {
	// Выполняем проверку порождения
	generation(TC26_512_TEST, 2000);
}
/**
 * @brief Проверка порождения ключей на кривой в 512 разрядов с порядком от 0xff
 *
 */
TEST(GostTest, Generate512) {
	// Выполняем проверку порождения
	generation(TC26_512_A, 2000);
}
/**
 * @brief Проверка отказов порождения и предела до установки кривой
 *
 */
TEST(GostTest, GenerateFailures) {
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Предел до установки кривой нулевой
	ASSERT_EQ(gost.limit(), static_cast <size_t> (0));
	// Место ключа подписи
	uint8_t secret[math::NUMBER_SIZE];
	// Порождение до установки кривой отвергается
	ASSERT_FALSE(gost.generate(secret, 32));
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой
	ASSERT_TRUE(curve::parameters(std::string(TC26_256_A), curve));
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Порождение без места отвергается
	ASSERT_FALSE(gost.generate(nullptr, 32));
	// Порождение в место короче порядка отвергается
	ASSERT_FALSE(gost.generate(secret, 31));
	// Хеш и подпись
	uint8_t digest[32], signature[64];
	// Заполняем хеш
	::memset(digest, 0x01, sizeof(digest));
	// Выработка подписи без ключа отвергается
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), signature));
}
/**
 * @brief Проверка порождения при нехватке памяти: порождение памяти не выделяет
 *
 */
TEST(GostTest, GenerateStarved) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой
	ASSERT_TRUE(curve::parameters(std::string(TC26_256_A), curve));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	/**
	 * Выполняем перебор запасов выделений: порождение обязано удаваться при всяком
	 * запасе, ибо памяти не выделяет, а выделение под noexcept прервало бы исполнение
	 */
	for(size_t budget = 0; budget < 8; budget++){
		// Место ключа подписи
		uint8_t secret[32];
		// Итог порождения при отмеренном запасе
		bool outcome = false;
		{
			// Отмеряем запас выделений на время порождения
			starve::ration_t ration(budget);
			// Выполняем порождение при отмеренном запасе
			outcome = gost.generate(secret, sizeof(secret));
		}
		// Порождение удалось
		ASSERT_TRUE(outcome) << "запас " << budget;
	}
}
/**
 * @brief Функция сборки записи порождённого ключа ГОСТ
 *
 * @param oid       опознаватель кривой
 * @param algorithm опознаватель алгоритма ключа
 * @param gost      модуль подписи, в который порождается ключ
 * @param curve     кривая модуля подписи
 * @param result    место, в которое помещается ключ в виде записи
 *
 */
static void assemble(const char * oid, const char * algorithm, sign::gost_t & gost, curve::curve_t & curve, keys::key_t & result) {
	// Выполняем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters(std::string(oid), curve)) << "Кривая: " << oid;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve)) << "Кривая: " << oid;
	// Размер порядка подгруппы
	const size_t size = curve.order().size();
	// Устанавливаем вид ключа
	result.kind = keys::kind_t::GOST;
	// Устанавливаем опознаватель кривой
	result.oid = oid;
	// Устанавливаем опознаватель алгоритма
	result.algorithm = algorithm;
	// Устанавливаем опознаватель хеша по размеру кривой
	result.digest = ((size == 32) ? "1.2.643.7.1.1.2.2" : "1.2.643.7.1.1.2.3");
	// Выделяем место под ключ подписи
	result.d.assign(size, 0);
	// Выполняем порождение ключа подписи
	ASSERT_TRUE(gost.generate(result.d.data(), size)) << "Кривая: " << oid;
	// Выделяем место под абсциссу ключа проверки
	result.x.assign(size, 0);
	// Выделяем место под ординату ключа проверки
	result.y.assign(size, 0);
	// Выполняем получение ключа проверки
	ASSERT_TRUE(gost.key(result.x.data(), result.y.data(), size)) << "Кривая: " << oid;
}
/**
 * @brief Проверка круга записи порождённого ключа: PKCS #8 и SubjectPublicKeyInfo
 *
 */
TEST(GostTest, GenerateKeys) {
	// Кривые и алгоритмы ключей
	const char * sets[][2] = {
		{TC26_256_A, "1.2.643.7.1.1.1.1"},
		{TC26_512_A, "1.2.643.7.1.1.1.2"}
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(const auto & set : sets){
		// Объект эллиптической кривой
		curve::curve_t curve;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Ключ в виде записи
		keys::key_t key;
		// Выполняем порождение ключа и сборку записи
		assemble(set[0], set[1], gost, curve, key);
		// Размер порядка подгруппы
		const size_t size = curve.order().size();
		// Записи ключей
		std::string secret, pub;
		// Выполняем запись секретного ключа PKCS #8
		ASSERT_EQ(keys::encode(key, keys::container_t::PRIVATE, secret), keys::error_t::NONE) << "Кривая: " << set[0];
		// Выполняем запись открытого ключа SubjectPublicKeyInfo
		ASSERT_EQ(keys::encode(key, keys::container_t::PUBLIC, pub), keys::error_t::NONE) << "Кривая: " << set[0];
		// Разобранные ключи
		keys::key_t parsed, opened;
		// Выполняем разбор записи секретного ключа
		ASSERT_EQ(keys::decode(secret, view_t(), parsed), keys::error_t::NONE) << "Кривая: " << set[0];
		// Выполняем разбор записи открытого ключа
		ASSERT_EQ(keys::decode(pub, view_t(), opened), keys::error_t::NONE) << "Кривая: " << set[0];
		// Разобранный ключ подписи совпадает с порождённым
		ASSERT_EQ(parsed.d, key.d) << "Кривая: " << set[0];
		// Разобранный ключ проверки совпадает с порождённым
		ASSERT_TRUE((opened.x == key.x) && (opened.y == key.y)) << "Кривая: " << set[0];
		// Кривая и модуль загруженного ключа
		curve::curve_t loaded;
		// Модуль подписи загруженного ключа
		sign::gost_t verifier;
		// Выполняем загрузку открытого ключа в модуль
		ASSERT_TRUE(opened.load(verifier, loaded)) << "Кривая: " << set[0];
		// Хеш сообщения длиной в порядок
		uint8_t digest[math::NUMBER_SIZE];
		// Заполняем хеш сообщения
		::memset(digest, 0x3c, sizeof(digest));
		// Место подписи
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Выполняем выработку подписи порождённым ключом
		ASSERT_TRUE(gost.make(view_t(digest, size), signature)) << "Кривая: " << set[0];
		// Подпись сходится у ключа, прошедшего через запись
		ASSERT_TRUE(verifier.check(view_t(digest, size), view_t(signature, size * 2))) << "Кривая: " << set[0];
	}
}
/**
 * @brief Проверка чтения записей порождённого ключа системным openssl
 *
 */
TEST(GostTest, GenerateOpenssl) {
	// Если системного openssl нет, сличать не с чем
	if(shell("openssl version >/dev/null 2>&1") != 0)
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "Системный openssl не найден";
	// Если системный openssl не умеет ключей ГОСТ, читать записи некому
	if(shell("openssl list -public-key-algorithms 2>/dev/null | grep -qi gost") != 0)
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "Системный openssl без ГОСТ: движок gost не подключён";
	// Заготовка имени каталога временных файлов
	char pattern[] = "gost-gen-XXXXXX";
	// Заводим каталог временных файлов
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Каталог временных файлов
	const std::string directory = pattern;
	// Кривые и алгоритмы ключей
	const char * sets[][2] = {
		{TC26_256_A, "1.2.643.7.1.1.1.1"},
		{TC26_512_A, "1.2.643.7.1.1.1.2"}
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(const auto & set : sets){
		// Объект эллиптической кривой
		curve::curve_t curve;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Ключ в виде записи
		keys::key_t key;
		// Выполняем порождение ключа и сборку записи
		assemble(set[0], set[1], gost, curve, key);
		// Записи ключей
		std::string secret, pub;
		// Выполняем запись секретного ключа PKCS #8
		ASSERT_EQ(keys::encode(key, keys::container_t::PRIVATE, secret), keys::error_t::NONE) << "Кривая: " << set[0];
		// Выполняем запись открытого ключа SubjectPublicKeyInfo
		ASSERT_EQ(keys::encode(key, keys::container_t::PUBLIC, pub), keys::error_t::NONE) << "Кривая: " << set[0];
		// Пути к файлам
		const std::string priv = (directory + "/" + set[0] + ".pem"), opened = (directory + "/" + set[0] + ".pub.pem"), derived = (directory + "/" + set[0] + ".derived.pem");
		// Записываем ключи в файлы
		ASSERT_TRUE(std::ofstream(priv) << secret) << "Кривая: " << set[0];
		ASSERT_TRUE(std::ofstream(opened) << pub) << "Кривая: " << set[0];
		// Системный openssl читает секретный ключ
		ASSERT_EQ(shell((std::string("openssl pkey -in ") + priv + " -noout 2>/dev/null").c_str()), 0) << "Кривая: " << set[0];
		// Системный openssl читает открытый ключ
		ASSERT_EQ(shell((std::string("openssl pkey -pubin -in ") + opened + " -noout 2>/dev/null").c_str()), 0) << "Кривая: " << set[0];
		// Системный openssl выводит открытый ключ из секретного
		ASSERT_EQ(shell((std::string("openssl pkey -in ") + priv + " -pubout -out " + derived + " 2>/dev/null").c_str()), 0) << "Кривая: " << set[0];
		// Разобранный выведенный openssl открытый ключ
		keys::key_t foreign;
		// Выполняем разбор выведенного openssl открытого ключа
		ASSERT_EQ(keys::decode(slurp(derived), view_t(), foreign), keys::error_t::NONE) << "Кривая: " << set[0];
		// Открытая часть выведенного openssl ключа совпадает с порождённой
		ASSERT_TRUE((foreign.x == key.x) && (foreign.y == key.y)) << "Кривая: " << set[0];
	}
	// Убираем каталог временных файлов
	ASSERT_EQ(shell((std::string("rm -rf ") + directory).c_str()), 0);
}
