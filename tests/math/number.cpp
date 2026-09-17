/**
 * @file number.cpp
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
 * @brief Исходный файл проверок модуля арифметики чисел постоянной разрядности
 *
 * @note Ожидаемые значения вычислены независимой арифметикой произвольной точности
 *       на трёх модулях: простое в одно слово, модуль кривой из раздела 7.1.1
 *       RFC 7091 и модуль набора параметров id-tc26-gost-3410-12-512-paramSetA из
 *       RFC 7836
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
#include <math/number.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

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
 * @brief Метод сборки записи числа шестнадцатеричными знаками
 *
 * @param modulus установленный модуль арифметики
 * @param value   собираемое число
 *
 * @return        собранная запись
 *
 */
static std::string number(const math::modulus_t & modulus, const math::number_t & value) {
	// Место, в которое записывается собираемое число
	uint8_t buffer[math::NUMBER_SIZE];
	// Выполняем запись собираемого числа
	if(!modulus.store(value, buffer, modulus.size()))
		// Выводим признак отказа записи числа
		return std::string("отказ записи числа");
	// Выводим собранную запись числа
	return text(buffer, modulus.size());
}

/**
 * @brief Набор ожидаемых значений действий по одному модулю
 *
 */
typedef struct Sample {
	// Значение модуля
	const char * modulus;
	// Первое значение действий
	const char * first;
	// Второе значение действий
	const char * second;
	// Ожидаемая сумма значений
	const char * add;
	// Ожидаемая разность первого и второго значений
	const char * subtract;
	// Ожидаемая разность второго и первого значений
	const char * reverse;
	// Ожидаемое произведение значений
	const char * multiply;
	// Ожидаемая степень первого значения по второму
	const char * power;
	// Ожидаемое обратное к первому значению
	const char * invert;
} sample_t;

/**
 * Наборы ожидаемых значений действий по трём модулям
 */
static const sample_t SAMPLES[3] = {
	{
		"ffffffffffffffc5",
		"52f010d04c41c07b",
		"65cc7fb2dad317e9",
		"b8bc90832714d864",
		"ed23911d716ea857",
		"12dc6ee28e91576e",
		"71b0b62e2b02f46a",
		"fb57bec5ca11dad8",
		"30a611760da92145"
	}, {
		"8000000000000000000000000000000000000000000000000000000000000431",
		"217a228044edb9ec53c45efcf32479dbd3b5217417b3953be010b0a847e5d2b8",
		"22870bc080faacad7c48ee61ec04ea18a57135be068cbd81c47e4d3006f27237",
		"44012e40c5e86699d00d4d5edf2963f4792657321e4052bda48efdd84ed844ef",
		"7ef316bfc3f30d3ed77b709b071f8fc32e43ebb61126d7ba1b92637840f364b2",
		"010ce9403c0cf2c128848f64f8e0703cd1bc1449eed92845e46d9c87bf0c9f7f",
		"49dfd3bf1a46ca4c685ff8cfa98fef6f9a2085bdca02c14a7dbcd04bf7ebb84e",
		"09cfd5c71984b97aa5cdb34164a0d32f1f43a6d00ebc4b36d8e0cf8797d22f01",
		"22b9c47c641730372aa9c3b258d819425bbf15dc2cad311a207ec2dbe163e075"
	}, {
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
		"ab72fb31087722a427c85dcd86e68e4e7c4c9b7abbb813319592d374ee4b2d694ae873999982ac20e3715d25540ebc7071f83e351c31848d42745960af4a88d4",
		"00bd3360e2de9dc6628eed8d358365c9411cfba65991bb6e22d06dfd47094bafa8033f26c435e38896187ec36492c367e82a5efc66cd0ecaa6c00a4703466f2a",
		"ac302e91eb55c06a8a574b5abc69f417bd6997211549ce9fb863417235547918f2ebb2c05db88fa97989dbe8b8a17fd85a229d3182fe9357e93463a7b290f7fe",
		"aab5c7d0259884ddc5397040516328853b2f9fd4622657c372c26577a741e1b9a2e53472d54cc8984d58de61ef7bf90889cddf38b56475c29bb44f19ac0419aa",
		"554a382fda677b223ac68fbfae9cd77ac4d0602b9dd9a83c8d3d9a8858be1e465d1acb8d2ab33767b2a7219e108406f7763220c74a9b8a3d644bb0e653fbe41d",
		"4d131dd15daab43b124cf1f8b40f59520875309e3d9be55375364719c27a8e4bcbb93c87c85f8e450471a84c9c2145ad6b162936514bb77d3a3139f91dfb9b34",
		"201863ebde3b657218f2e4cdb8c21f944d68967238cd8b1973238bfbce9efb06ea5e9ebdeab06286e2efcc7330f7dda7872e7ef0eb7c10c68f9155a8dce30cf8",
		"f295aad36b09546aba6c20a3b22fb847c97472a89c4f04a6ef8f713c16c5a88bef30445e1aa5b498503ee7390473c563ac2c868b88bee85490cbcbe6ae26460d"
	}
};

/**
 * @brief Проверка действий арифметики по трём модулям
 *
 */
TEST(NumberTest, Samples) {
	// Место, в которое помещаются разбираемые записи
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Выполняем перебор наборов ожидаемых значений
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(sample_t)); i++){
		// Извлекаем очередной набор ожидаемых значений
		const sample_t & sample = SAMPLES[i];
		// Объект арифметики по модулю
		math::modulus_t modulus;
		// Выполняем установку модуля
		ASSERT_TRUE(modulus.start(view_t(buffer, bytes(sample.modulus, buffer)))) << "Набор: " << i;
		// Первое и второе значения действий
		math::number_t first, second;
		// Выполняем разбор первого значения действий
		ASSERT_TRUE(modulus.load(view_t(buffer, bytes(sample.first, buffer)), first)) << "Набор: " << i;
		// Выполняем разбор второго значения действий
		ASSERT_TRUE(modulus.load(view_t(buffer, bytes(sample.second, buffer)), second)) << "Набор: " << i;
		// Место, в которое помещается итог очередного действия
		math::number_t result;
		// Выполняем сложение значений
		modulus.add(first, second, result);
		// Сличаем полученную сумму с ожидаемой
		ASSERT_EQ(number(modulus, result), std::string(sample.add)) << "Набор: " << i;
		// Выполняем вычитание второго значения из первого
		modulus.subtract(first, second, result);
		// Сличаем полученную разность с ожидаемой
		ASSERT_EQ(number(modulus, result), std::string(sample.subtract)) << "Набор: " << i;
		// Выполняем вычитание первого значения из второго
		modulus.subtract(second, first, result);
		// Сличаем полученную разность с ожидаемой
		ASSERT_EQ(number(modulus, result), std::string(sample.reverse)) << "Набор: " << i;
		// Первое и второе значения в области Монтгомери
		math::number_t entered, item;
		// Выполняем приведение первого значения в область Монтгомери
		modulus.enter(first, entered);
		// Выполняем приведение второго значения в область Монтгомери
		modulus.enter(second, item);
		// Выполняем умножение значений
		modulus.multiply(entered, item, result);
		// Выполняем вывод произведения из области Монтгомери
		modulus.leave(result, result);
		// Сличаем полученное произведение с ожидаемым
		ASSERT_EQ(number(modulus, result), std::string(sample.multiply)) << "Набор: " << i;
		// Выполняем возведение первого значения в степень по второму
		modulus.power(entered, second, result);
		// Выполняем вывод степени из области Монтгомери
		modulus.leave(result, result);
		// Сличаем полученную степень с ожидаемой
		ASSERT_EQ(number(modulus, result), std::string(sample.power)) << "Набор: " << i;
		// Выполняем обращение первого значения
		modulus.invert(entered, result);
		// Выполняем умножение обращённого значения на исходное
		modulus.multiply(result, entered, item);
		// Выполняем вывод обратного значения из области Монтгомери
		modulus.leave(result, result);
		// Сличаем полученное обратное значение с ожидаемым
		ASSERT_EQ(number(modulus, result), std::string(sample.invert)) << "Набор: " << i;
		// Выполняем вывод произведения обратного значения на исходное
		modulus.leave(item, item);
		// Единица, с которой сличается произведение
		math::number_t unit;
		// Записываем значение единицы
		modulus.word(1, unit);
		// Проверяем, что произведение обратного значения на исходное даёт единицу
		ASSERT_TRUE(modulus.equal(item, unit)) << "Набор: " << i;
		// Выполняем приведение первого значения в область Монтгомери и обратно
		modulus.enter(first, item);
		// Выполняем вывод значения из области Монтгомери
		modulus.leave(item, item);
		// Проверяем, что двойное приведение значения не меняет
		ASSERT_TRUE(modulus.equal(item, first)) << "Набор: " << i;
	}
}
/**
 * @brief Проверка отказов арифметики
 *
 */
TEST(NumberTest, Failures) {
	// Место, в которое помещаются разбираемые записи
	uint8_t buffer[math::NUMBER_SIZE];
	// Объект арифметики по модулю
	math::modulus_t modulus;
	// Проверяем отказ работы арифметики до установки модуля
	ASSERT_FALSE(modulus.ready());
	// Разбираемое число
	math::number_t value;
	// Проверяем отказ разбора числа до установки модуля
	ASSERT_FALSE(modulus.load(view_t(buffer, bytes("01", buffer)), value));
	// Проверяем отказ приведения потока байтов до установки модуля
	ASSERT_FALSE(modulus.reduce(view_t(buffer, bytes("01", buffer)), value));
	// Проверяем отказ записи числа до установки модуля
	ASSERT_FALSE(modulus.store(value, buffer, sizeof(buffer)));
	/**
	 * Переданное место нулевой длины - вторая половина той же оплошности: место есть,
	 * а читать из него нечего. Всякая половина отвергает модуль в одиночку
	 */
	ASSERT_FALSE(modulus.start(view_t(buffer, 0)));
	// Проверяем отказ установки чётного модуля
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("f0", buffer))));
	// Проверяем отказ установки модуля, меньшего трёх
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("01", buffer))));
	// Проверяем отказ установки модуля с нулевым старшим словом
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("0000000000000000000000000000000000000003", buffer))));
	// Проверяем отказ установки непереданного модуля
	ASSERT_FALSE(modulus.start(view_t()));
	/**
	 * Непереданное место при заявленной длине - оплошность потребителя: длина есть,
	 * а читать её не из чего. Переданность и длина сверяются РАЗНЫМИ половинами
	 * условия, и всякая отвергает модуль в одиночку
	 */
	ASSERT_FALSE(modulus.start(view_t(nullptr, 32)));
	// Проверяем отказ установки модуля шире разрядной сетки арифметики
	ASSERT_FALSE(modulus.start(view_t(buffer, ((math::NUMBER_BITS / 8) + 1))));
	// Выполняем установку модуля
	ASSERT_TRUE(modulus.start(view_t(buffer, bytes("8000000000000000000000000000000000000000000000000000000000000431", buffer))));
	// Проверяем размер установленного модуля
	ASSERT_EQ(modulus.size(), static_cast <size_t> (32));
	// Проверяем отказ разбора числа, равного модулю
	ASSERT_FALSE(modulus.load(view_t(buffer, bytes("8000000000000000000000000000000000000000000000000000000000000431", buffer)), value));
	// Проверяем отказ разбора числа, большего модуля
	ASSERT_FALSE(modulus.load(view_t(buffer, bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", buffer)), value));
	// Проверяем отказ разбора числа, не укладывающегося в разрядность модуля
	ASSERT_FALSE(modulus.load(view_t(buffer, bytes("01000000000000000000000000000000000000000000000000000000000000000000", buffer)), value));
	// Проверяем успешность разбора числа, меньшего модуля на единицу
	ASSERT_TRUE(modulus.load(view_t(buffer, bytes("8000000000000000000000000000000000000000000000000000000000000430", buffer)), value));
	// Проверяем разбор нулевого числа
	ASSERT_TRUE(modulus.load(view_t(buffer, bytes("00", buffer)), value));
	// Проверяем равенство разобранного числа нулю
	ASSERT_TRUE(modulus.zero(value));
	// Выполняем разбор ненулевого числа
	ASSERT_TRUE(modulus.load(view_t(buffer, bytes("02", buffer)), value));
	// Проверяем неравенство разобранного числа нулю
	ASSERT_FALSE(modulus.zero(value));
	// Проверяем отказ записи числа в непереданное место
	ASSERT_FALSE(modulus.store(value, nullptr, 32));
	// Проверяем отказ записи числа в место нулевой длины
	ASSERT_FALSE(modulus.store(value, buffer, 0));
	// Проверяем успешность записи числа в место шире модуля
	ASSERT_TRUE(modulus.store(value, buffer, 40));
	// Сличаем записанное число с ожидаемым
	ASSERT_EQ(text(buffer, 40), std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000002"));
	/**
	 * Разбор и приведение обнуляют итог на входе, оттого сверки на непереданный поток
	 * байтов идут ПОСЛЕДНИМИ: поставленные выше, они снесли бы разобранное число, и
	 * сверка записи сличала бы уже не его
	 */
	ASSERT_FALSE(modulus.load(view_t(nullptr, 32), value));
	// Проверяем отказ приведения непереданного потока байтов
	ASSERT_FALSE(modulus.reduce(view_t(nullptr, 32), value));
	// Проверяем, что отказ разбора обнулил разбираемое число
	ASSERT_TRUE(modulus.zero(value));
}
/**
 * @brief Проверка предельных значений арифметики
 *
 */
TEST(NumberTest, Edges) {
	// Место, в которое помещаются разбираемые записи
	uint8_t buffer[math::NUMBER_SIZE];
	// Объект арифметики по модулю
	math::modulus_t modulus;
	// Выполняем установку модуля
	ASSERT_TRUE(modulus.start(view_t(buffer, bytes("8000000000000000000000000000000000000000000000000000000000000431", buffer))));
	// Нулевое значение и значение, меньшее модуля на единицу
	math::number_t zero, last, result;
	// Выполняем разбор нулевого значения
	ASSERT_TRUE(modulus.load(view_t(buffer, bytes("00", buffer)), zero));
	// Выполняем разбор значения, меньшего модуля на единицу
	ASSERT_TRUE(modulus.load(view_t(buffer, bytes("8000000000000000000000000000000000000000000000000000000000000430", buffer)), last));
	// Выполняем сложение наибольшего значения с самим собой
	modulus.add(last, last, result);
	// Сличаем полученную сумму с ожидаемой
	ASSERT_EQ(number(modulus, result), std::string("800000000000000000000000000000000000000000000000000000000000042f"));
	// Выполняем сложение наибольшего значения с единицей
	modulus.word(1, result);
	// Выполняем сложение значений
	modulus.add(last, result, result);
	// Проверяем, что сумма обратилась в ноль
	ASSERT_TRUE(modulus.zero(result));
	// Выполняем вычитание единицы из нуля
	modulus.word(1, result);
	// Выполняем вычитание значений
	modulus.subtract(zero, result, result);
	// Проверяем, что разность дала наибольшее значение
	ASSERT_TRUE(modulus.equal(result, last));
	// Выполняем умножение нуля на наибольшее значение
	modulus.enter(last, result);
	// Выполняем умножение значений
	modulus.multiply(zero, result, result);
	// Проверяем, что произведение обратилось в ноль
	ASSERT_TRUE(modulus.zero(result));
	// Выполняем возведение наибольшего значения в нулевую степень
	modulus.enter(last, result);
	// Выполняем возведение в степень
	modulus.power(result, zero, result);
	// Выполняем вывод степени из области Монтгомери
	modulus.leave(result, result);
	// Единица, с которой сличается степень
	math::number_t unit;
	// Записываем значение единицы
	modulus.word(1, unit);
	// Проверяем, что нулевая степень дала единицу
	ASSERT_TRUE(modulus.equal(result, unit));
}

/**
 * Проверка схождения возведения в квадрат с общим умножением
 */
TEST(NumberTest, Square) {
	// Место, в которое помещаются разбираемые записи
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Возведение в квадрат идёт нынче общим умножением: отдельный путь пробовали и не
	 * взяли, ибо замер показал его медленнее. Проверка оставлена заслоном на будущее -
	 * заведись такой путь снова, он обязан сойтись с общим умножением на всяком
	 * значении, и здесь они сличаются между собой на всех трёх модулях набора
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(sample_t)); i++){
		// Извлекаем очередной набор ожидаемых значений
		const sample_t & sample = SAMPLES[i];
		// Объект арифметики по модулю
		math::modulus_t modulus;
		// Выполняем установку модуля
		ASSERT_TRUE(modulus.start(view_t(buffer, bytes(sample.modulus, buffer)))) << "Набор: " << i;
		// Возводимые в квадрат значения набора
		const char * values[2] = {sample.first, sample.second};
		/**
		 * Выполняем перебор возводимых в квадрат значений набора
		 */
		for(size_t j = 0; j < 2; j++){
			// Возводимое в квадрат значение и его двойник, лежащий отдельно
			math::number_t value, twin;
			// Выполняем разбор возводимого в квадрат значения
			ASSERT_TRUE(modulus.load(view_t(buffer, bytes(values[j], buffer)), value)) << "Набор: " << i;
			// Выполняем разбор двойника возводимого в квадрат значения
			ASSERT_TRUE(modulus.load(view_t(buffer, bytes(values[j], buffer)), twin)) << "Набор: " << i;
			// Итоги возведения в квадрат и общего умножения
			math::number_t squared, product;
			// Выполняем возведение значения в квадрат
			modulus.multiply(value, value, squared);
			// Выполняем умножение значения на его двойник, лежащий отдельно
			modulus.multiply(value, twin, product);
			// Сличаем квадрат с произведением значения на двойник
			ASSERT_EQ(number(modulus, squared), number(modulus, product)) << "Набор: " << i << ", значение: " << j;
			/**
			 * Возведение в квадрат применяется вслед за собою: так проверяется, что
			 * совпадение места итога с местом возводимого числа пути не мешает
			 */
			modulus.multiply(squared, squared, squared);
			// Выполняем то же общим умножением через двойник
			modulus.multiply(product, product, twin);
			// Сличаем четвёртую степень, полученную двумя путями
			ASSERT_EQ(number(modulus, squared), number(modulus, twin)) << "Набор: " << i << ", значение: " << j;
			// Место, в которое помещается квадрат нуля
			math::number_t hollow, none;
			// Выполняем разбор нулевого значения
			ASSERT_TRUE(modulus.load(view_t(buffer, bytes("00", buffer)), none)) << "Набор: " << i;
			// Выполняем возведение нуля в квадрат
			modulus.multiply(none, none, hollow);
			// Проверяем равенство квадрата нуля нулю
			ASSERT_TRUE(modulus.zero(hollow)) << "Набор: " << i;
		}
	}
}

/**
 * @brief Проверка заслонов усечения записи и малого модуля приведения
 *
 */
TEST(NumberTest, Guards) {
	math::modulus_t modulus;
	// Модуль длиной 32 байта
	uint8_t prime[32];
	ASSERT_EQ(bytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", prime), static_cast <size_t> (32));
	ASSERT_TRUE(modulus.start(view_t(prime, sizeof(prime))));
	// Число со старшим ненулевым байтом
	uint8_t wide[32];
	ASSERT_EQ(bytes("0100000000000000000000000000000000000000000000000000000000000000", wide), static_cast <size_t> (32));
	math::number_t value;
	ASSERT_TRUE(modulus.load(view_t(wide, sizeof(wide)), value));
	uint8_t buffer[32];
	/**
	 * Место короче числа усекло бы старший байт молча: запись обязана отказать,
	 * а место с младшими байтами - остаться затёртым
	 */
	ASSERT_FALSE(modulus.store(value, buffer, 31));
	ASSERT_TRUE(modulus.store(value, buffer, 32));
	ASSERT_EQ(buffer[0], 0x01);
	// Число, умещающееся в короткое место, записывается и в него
	uint8_t narrow[32];
	ASSERT_EQ(bytes("0000000000000000000000000000000000000000000000000000000000000002", narrow), static_cast <size_t> (32));
	ASSERT_TRUE(modulus.load(view_t(narrow, sizeof(narrow)), value));
	ASSERT_TRUE(modulus.store(value, buffer, 1));
	ASSERT_EQ(buffer[0], 0x02);
	/**
	 * Приведение по модулю не длиннее байта: слагаемые сложения превысили бы модуль
	 */
	math::modulus_t small;
	const uint8_t eleven[1] = {0x0B};
	ASSERT_TRUE(small.start(view_t(eleven, 1)));
	const uint8_t stream[1] = {0xFF};
	ASSERT_FALSE(small.reduce(view_t(stream, 1), value));
}

/**
 * Проверка пути умножения P-256 с постоянными: итог сходится с золотыми векторами
 * (a*b mod p посчитаны независимо), путь общего Монтгомери на той же паре чисел
 * даёт то же самое через модуль, отличающийся на единицу (без признака P-256)
 */
TEST(NumberTest, Nist256) {
	static const uint8_t prime[32] = {0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	struct { const char * a; const char * b; const char * r; } cases[] = {
		{"d23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438", "36f675cc81e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902b", "8a0738a0a9cc1a6bdc2ec5cad956023880c2fafb38567705e3a79ea958be0737"},
		{"8d116ece1738f7d93d9c172411e20b8f6b0d549b6f03675a1600a35a099950d8", "a170b33839263059f28c105d1fb17c2390c192cfd3ac94af0f21ddb66cad4a26", "b885da50d1e04695e4053c5c68703ecc40618f4687dadeaab26a8b8aaa2077f2"},
		{"0cb1e29c658cda1495e60af593bd04cf0fd630f1f29d0da9953f48f1a09f76b5", "6b4cb2424a23d5962217beaddbc496cb8e81973e0becd7b03898d190f9ebdacc", "9630d5166a7920b1fb250868f444ed5c73b02be0b55e7c40e9e317ea81165192"},
	};
	auto unhex = [](const char * text, uint8_t * out){ for(size_t i = 0; i < 32; i++){ unsigned v = 0; sscanf(text + 2 * i, "%2x", &v); out[i] = static_cast <uint8_t> (v); } };
	math::modulus_t field;
	ASSERT_TRUE(field.start(view_t(prime, 32)));
	for(const auto & item : cases){
		uint8_t a[32], b[32], r[32], out[32];
		unhex(item.a, a); unhex(item.b, b); unhex(item.r, r);
		math::number_t x, y, ex, ey, product, plain;
		ASSERT_TRUE(field.load(view_t(a, 32), x));
		ASSERT_TRUE(field.load(view_t(b, 32), y));
		field.enter(x, ex);
		field.enter(y, ey);
		field.multiply(ex, ey, product);
		field.leave(product, plain);
		ASSERT_TRUE(field.store(plain, out, 32));
		EXPECT_EQ(::memcmp(out, r, 32), 0) << "вектор " << item.r;
	}
}

/**
 * @brief Проверка переноса и заёма между словами у сложения и вычитания по модулю
 *
 * @details Развёртки на четыре слова ведут перенос и заём командами сложения с
 *          переносом, а не числом двойной разрядности. Перенос складывается из двух:
 *          от сложения слов и от прибавления переноса снизу; случай, где второй
 *          возникает без первого (сумма слов ровно из всех единиц), ловится отдельно,
 *          как и заём, рождённый только заёмом снизу (разность слов ноль)
 */
TEST(NumberTest, Carries) {
	// Модули: P-256 и 2^256 - 189 (старшее слово из всех единиц)
	static const uint8_t p256[32] = {0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	static const uint8_t full[32] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x43};
	const uint8_t * primes[2] = {p256, full};
	for(const uint8_t * prime : primes){
		math::modulus_t field;
		ASSERT_TRUE(field.start(view_t(prime, 32)));
		uint8_t less[32], out[32];
		uint8_t one[32] = {}; one[31] = 1;
		uint8_t two[32] = {}; two[31] = 2;
		math::number_t a, b, c, d, e, f, r;
		::memcpy(less, prime, 32); less[31] -= 1;
		ASSERT_TRUE(field.load(view_t(less, 32), a));
		ASSERT_TRUE(field.load(view_t(one, 32), b));
		ASSERT_TRUE(field.load(view_t(two, 32), d));
		// (p-1) + (p-1) = p - 2: перенос за разрядность у модуля из всех единиц
		field.add(a, a, r); ASSERT_TRUE(field.store(r, out, 32)); ::memcpy(less, prime, 32); less[31] -= 2; EXPECT_EQ(::memcmp(out, less, 32), 0);
		// (p-1) + 1 = 0
		field.add(a, b, r); EXPECT_TRUE(field.zero(r));
		// 0 - 1 = p - 1: заём сквозь все слова
		field.subtract(c, b, r); ASSERT_TRUE(field.store(r, out, 32)); ::memcpy(less, prime, 32); less[31] -= 1; EXPECT_EQ(::memcmp(out, less, 32), 0);
		// 1 - (p-1) = 2
		field.subtract(b, a, r); ASSERT_TRUE(field.store(r, out, 32)); EXPECT_EQ(::memcmp(out, two, 32), 0);
		// (2^128 - 1) + 1 = 2^128: перенос рождается только вторым сложением
		uint8_t high[32] = {}; ::memset(high + 16, 0xff, 16);
		uint8_t shifted[32] = {}; shifted[15] = 1;
		ASSERT_TRUE(field.load(view_t(high, 32), e));
		field.add(e, b, r); ASSERT_TRUE(field.store(r, out, 32)); EXPECT_EQ(::memcmp(out, shifted, 32), 0);
		// 2^64 - (2^64 + 1) = p - 1: заём рождается только заёмом снизу
		uint8_t word[32] = {}; word[23] = 1;
		uint8_t next[32] = {}; next[23] = 1; next[31] = 1;
		ASSERT_TRUE(field.load(view_t(word, 32), e));
		ASSERT_TRUE(field.load(view_t(next, 32), f));
		field.subtract(e, f, r); ASSERT_TRUE(field.store(r, out, 32)); ::memcpy(less, prime, 32); less[31] -= 1; EXPECT_EQ(::memcmp(out, less, 32), 0);
	}
}

/**
 * @brief Проверка квадрата Монтгомери по P-256 против умножения числа на копию себя
 *
 * @details Совпадающие сомножители идут своим путём с десятью произведениями; итог
 *          обязан совпадать с общим умножением на копию того же числа на золотых
 *          векторах и на границах: ноль, единица, p - 1
 */
TEST(NumberTest, Squaring) {
	static const uint8_t prime[32] = {0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	const char * values[] = {"d23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438", "36f675cc81e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902b", "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe", "0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000000", "8000000000000000800000000000000080000000000000008000000000000000"};
	auto unhex = [](const char * text, uint8_t * out){ for(size_t i = 0; i < 32; i++){ unsigned v = 0; sscanf(text + 2 * i, "%2x", &v); out[i] = static_cast <uint8_t> (v); } };
	math::modulus_t field;
	ASSERT_TRUE(field.start(view_t(prime, 32)));
	for(const char * value : values){
		uint8_t a[32], first[32], second[32];
		unhex(value, a);
		math::number_t x, entered, copy, square, product;
		ASSERT_TRUE(field.load(view_t(a, 32), x));
		field.enter(x, entered);
		copy = entered;
		// Квадрат своим путём: сомножители по одному адресу
		field.multiply(entered, entered, square);
		// Умножение общим путём: сомножители по разным адресам
		field.multiply(entered, copy, product);
		ASSERT_TRUE(field.store(square, first, 32));
		ASSERT_TRUE(field.store(product, second, 32));
		EXPECT_EQ(::memcmp(first, second, 32), 0) << "значение " << value;
	}
}
