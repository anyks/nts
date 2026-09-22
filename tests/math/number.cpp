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

/**
 * Проверка путей прямой свёртки по простым вида 2^k - c и 2^k + c: умножение, квадрат и
 * обращение сличаются с золотыми векторами (посчитаны независимо), по одному модулю на
 * всякий из четырёх видов кривых ГОСТ: 2^256 - 617, 2^255 + 3225, 2^512 - 569, 2^511 + 111.
 * Значения взяты в том числе на краях: модуль без единицы, дополнение до модуля, и число
 * из всех единиц ниже старшего разряда - на них свёртка выходит за разрядную сетку
 */
TEST(NumberTest, Folding) {
	struct vector_t { const char * a; const char * b; const char * product; const char * square; const char * inverse; };
	struct group_t { const char * modulus; vector_t vectors[5]; };
	static const group_t GROUPS[] = {
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", {
			{"de27f4c90ba4596ad3d80ead13e95e7330c10a5c096900933de2a0c0dee98e6c", "53ba509554a703a7b87b2e103025bad0594e4876610cb1e82851d5edb7b43884", "9a70746a5c3b2929f826cbd71c99c2db14ba2bf4ed1a5421194c5c8c373aaec9", "fdd26c277fba2224d7f1f342e7f1b50e1049d17a31183b4e95aaad4374caca4e", "959af3b90b96dbb95eff1537d58c8965b3cfe68b9f8f7032801057c0bd0b12d9"},
			{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96", "0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96"},
			{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96", "0000000000000000000000000000000000000000000000000000000000000002", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd95", "0000000000000000000000000000000000000000000000000000000000000001", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96"},
			{"de27f4c90ba4596ad3d80ead13e95e7330c10a5c096900933de2a0c0dee98e6c", "21d80b36f45ba6952c27f152ec16a18ccf3ef5a3f696ff6cc21d5f3f21166f2b", "022d93d88045dddb280e0cbd180e4af1efb62e85cee7c4b16a5552bc8b353349", "fdd26c277fba2224d7f1f342e7f1b50e1049d17a31183b4e95aaad4374caca4e", "959af3b90b96dbb95eff1537d58c8965b3cfe68b9f8f7032801057c0bd0b12d9"},
			{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", "4000000000000000000000000000000000000000000000000000000000016e5b", "40000000000000000000000000000000000000000000000000000000000170c2", "cee19cee19cee19cee19cee19cee19cee19cee19cee19cee19cee19cee19ccef"}
		}},
		{"8000000000000000000000000000000000000000000000000000000000000c99", {
			{"46c7916f525c9e10884fb01ab84a8f8a1c99d4c85920b15727b453c2a3a98da0", "131968eaa25e41b64398cca28a07d75090755d52d3035b1c78ceb4a074081d1d", "780129852cc4f5f4f50aef1b1bc8590496feb1b699e36042cfce1e10dd014166", "67efaf731af6b2347d47d3c26fb079d2dd86bf40f8e7c223984891f68405b021", "736b876aea6d4d1b0e4019c86445ec6bbb9f1963b48ea878e486403c02a52348"},
			{"8000000000000000000000000000000000000000000000000000000000000c98", "8000000000000000000000000000000000000000000000000000000000000c98", "0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001", "8000000000000000000000000000000000000000000000000000000000000c98"},
			{"8000000000000000000000000000000000000000000000000000000000000c98", "0000000000000000000000000000000000000000000000000000000000000002", "8000000000000000000000000000000000000000000000000000000000000c97", "0000000000000000000000000000000000000000000000000000000000000001", "8000000000000000000000000000000000000000000000000000000000000c98"},
			{"46c7916f525c9e10884fb01ab84a8f8a1c99d4c85920b15727b453c2a3a98da0", "39386e90ada361ef77b04fe547b57075e3662b37a6df4ea8d84bac3d5c567ef9", "1810508ce5094dcb82b82c3d904f862d227940bf07183ddc67b76e097bfa5c78", "67efaf731af6b2347d47d3c26fb079d2dd86bf40f8e7c223984891f68405b021", "736b876aea6d4d1b0e4019c86445ec6bbb9f1963b48ea878e486403c02a52348"},
			{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", "00000000000000000000000000000000000000000000000000000000009ee5d8", "00000000000000000000000000000000000000000000000000000000009ecca4", "020607ef7e7e0420607ef7e7e0420607ef7e7e0420607ef7e7e0420607ef7eb1"}
		}},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", {
			{"e0dca897e610b4d803ca1481112098f40b9a2180fc76cf4d80805ac31e3612cae345407daf75968d87eb2de4827d95417d2c453688dd120488c30d1f875bec6b", "2d1d5b609b1aabf6833cea047e2c3b12bb0dc012c0f455b7dfa83b79b5d9eb5b26dec29dca6bc5874c9ec69cf8f1dea4db2a1c9d0134b7e81b13ecabaab2ab80", "3719a5baf4a1aa019fc5e637480e22b4b84b5be97c96b7865df7b1deef765478b1aa3c3213781e7569b2f7994eefc6ba8774923142077e36eac54ea551b62f0c", "4d4b150f0cab63df36d65cb2bb7c0b2a8a2ce1d3c9609ff836f48d526112bc1bcab8ad8125fba25cc69115033e52019a671b22d1f7ee70e51e85d45365f0927c", "03a1b04d629f24d165df6dee5ccd5b599bee82e133352721b975b3417ea14acab96ad76b4ce31f5693e809cbd01e30eacb2ebe76b75dfbc74c14197b7171e7d3"},
			{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc6", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc6", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc6"},
			{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc6", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc5", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc6"},
			{"e0dca897e610b4d803ca1481112098f40b9a2180fc76cf4d80805ac31e3612cae345407daf75968d87eb2de4827d95417d2c453688dd120488c30d1f875bec6b", "1f23576819ef4b27fc35eb7eeedf670bf465de7f038930b27f7fa53ce1c9ed351cbabf82508a69727814d21b7d826abe82d3bac97722edfb773cf2e078a4115c", "b2b4eaf0f3549c20c929a34d4483f4d575d31e2c369f6007c90b72ad9eed43e43547527eda045da3396eeafcc1adfe6598e4dd2e08118f1ae17a2bac9a0f6b4b", "4d4b150f0cab63df36d65cb2bb7c0b2a8a2ce1d3c9609ff836f48d526112bc1bcab8ad8125fba25cc69115033e52019a671b22d1f7ee70e51e85d45365f0927c", "03a1b04d629f24d165df6dee5ccd5b599bee82e133352721b975b3417ea14acab96ad76b4ce31f5693e809cbd01e30eacb2ebe76b75dfbc74c14197b7171e7d3"},
			{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", "4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001372f", "40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013966", "e31aa3715386ff8c6a8dc54e1bfe31aa3715386ff8c6a8dc54e1bfe31aa3715386ff8c6a8dc54e1bfe31aa3715386ff8c6a8dc54e1bfe31aa3715386ff8c6895"}
		}},
		{"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f", {
			{"32f50bc74ccd68b4c81ffd258bfcde5c8c3cbf86cc2f44d26be4f2e17b45ab4cffa500c49ad39a9bcf36a8dff920df1f4b00052353800f79ed0eb8801e9f904d", "4d364f076cccf2daa2526d3e106e820ee96a4f44705c8aef42f9db0593745e206327c09ebb59e05f8ddd79eac42e0140147eea9108e24ae0290a716d50696d82", "0960bcb1f4485a9445331ea77060c16679e9bb9e9ce2c6322c88c71e28d6a0a949b1c9208731d69db551b53211d6bb0caeea411c13e1526af655b269550c587d", "2d8da6ed1a7a6b7dbb88baac5a107ad189b48db17c5db948a18be69d6d8bbb67a5a02560178f8049cfb77f23caa1e88bbf6504da3d374264c114f524c16902e2", "2bba730bc8ca516d69f73d2f448d871ea350945d2a70ba09e5af5f2eab2f7bddec64b51aaa27d1ce2d69c5b514f360888f515a7779f10e1b1655ec6ff283cc31"},
			{"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e", "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e"},
			{"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006d", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e"},
			{"32f50bc74ccd68b4c81ffd258bfcde5c8c3cbf86cc2f44d26be4f2e17b45ab4cffa500c49ad39a9bcf36a8dff920df1f4b00052353800f79ed0eb8801e9f904d", "4d0af438b332974b37e002da740321a373c3407933d0bb2d941b0d1e84ba54b3005aff3b652c656430c9572006df20e0b4fffadcac7ff08612f1477fe1607022", "52725912e585948244774553a5ef852e764b724e83a246b75e741962927444985a5fda9fe8707fb6304880dc355e1774409afb25c2c8bd9b3eeb0adb3e96fd8d", "2d8da6ed1a7a6b7dbb88baac5a107ad189b48db17c5db948a18be69d6d8bbb67a5a02560178f8049cfb77f23caa1e88bbf6504da3d374264c114f524c16902e2", "2bba730bc8ca516d69f73d2f448d871ea350945d2a70ba09e5af5f2eab2f7bddec64b51aaa27d1ce2d69c5b514f360888f515a7779f10e1b1655ec6ff283cc31"},
			{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000031e0", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003100", "11249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249249258"}
		}}
	};
	// Место, в которое помещаются разбираемые записи
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Выполняем перебор модулей
	 */
	for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
		// Объект арифметики по модулю
		math::modulus_t modulus;
		// Выполняем установку модуля
		ASSERT_TRUE(modulus.start(view_t(buffer, bytes(GROUPS[g].modulus, buffer)))) << "модуль " << g;
		/**
		 * Выполняем перебор векторов модуля
		 */
		for(size_t v = 0; v < 5; v++){
			// Очередной вектор
			const vector_t & item = GROUPS[g].vectors[v];
			// Сомножители и итоги
			math::number_t a, b, result;
			// Выполняем разбор сомножителей
			ASSERT_TRUE(modulus.load(view_t(buffer, bytes(item.a, buffer)), a)) << "модуль " << g << ", вектор " << v;
			ASSERT_TRUE(modulus.load(view_t(buffer, bytes(item.b, buffer)), b)) << "модуль " << g << ", вектор " << v;
			// Выполняем приведение в область: у прямой свёртки это переписывание, договор тот же
			modulus.enter(a, a);
			modulus.enter(b, b);
			// Выполняем умножение и сличаем с золотым произведением
			modulus.multiply(a, b, result);
			modulus.leave(result, result);
			ASSERT_EQ(number(modulus, result), std::string(item.product)) << "модуль " << g << ", вектор " << v << ": произведение";
			// Выполняем возведение в квадрат своим входом: путь квадрата
			modulus.square(a, result);
			modulus.leave(result, result);
			ASSERT_EQ(number(modulus, result), std::string(item.square)) << "модуль " << g << ", вектор " << v << ": квадрат";
			// Умножение совпадающих сомножителей обязано давать тот же квадрат общим путём
			modulus.multiply(a, a, result);
			modulus.leave(result, result);
			ASSERT_EQ(number(modulus, result), std::string(item.square)) << "модуль " << g << ", вектор " << v << ": квадрат умножением";
			// Квадрат на место возводимого числа: место итога вправе совпадать с местом числа
			math::number_t self = a;
			modulus.square(self, self);
			modulus.leave(self, self);
			ASSERT_EQ(number(modulus, self), std::string(item.square)) << "модуль " << g << ", вектор " << v << ": квадрат на место";
			// Выполняем обращение и сличаем с золотым обратным
			modulus.invert(a, result);
			modulus.leave(result, result);
			ASSERT_EQ(number(modulus, result), std::string(item.inverse)) << "модуль " << g << ", вектор " << v << ": обратное";
			// Произведение на место сомножителя: место итога вправе совпадать с местом сомножителя
			math::number_t twin = a;
			modulus.multiply(twin, b, twin);
			modulus.leave(twin, twin);
			ASSERT_EQ(number(modulus, twin), std::string(item.product)) << "модуль " << g << ", вектор " << v << ": на место";
		}
	}
}

/**
 * Проверка приведения потока байтов по модулю умножениями: потоки длиннее модуля вдвое и
 * не кратные его разрядной сетке, ровно в модуль, в байт - по модулям всех видов: общий
 * (порядок кривой CryptoPro-A и порядок тестовой кривой 512), P-256, 2^k - c и 2^k + c.
 * Ожидаемые остатки посчитаны независимо
 */
TEST(NumberTest, Reduce) {
	struct stream_t { const char * stream; const char * remainder; };
	struct group_t { const char * modulus; stream_t streams[5]; };
	static const group_t GROUPS[] = {
		{"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", {
			{"621e1360907f6085a8f5fe2337ddb56441a81490706ca8fc02cb40cd2b05600a73465a408c5ee086182163037f058744b0a52a49c6610000de6d73444660ac57", "a61716c7f741f6ec3a0d0c1b42bb806b9037c4c443a52f593430109b813209ca"},
			{"06654eb28deb8799e7d570c5e3e7fe266be8a52c6daf53638f7d7a4f47a941ad93b422ffbf4994ea6aadb140c2268fcffa6f1bbe68b27f4d5682907826ee88d23ad5afe544", "1642786e8bc1c2c21fb780c9b439722537a8f0666fba836963b2b69b5e5d6d4c"},
			{"46288898267a6381d6a39f0089843725315bb2f39b7d2b583247f688a0dce664ef", "288898267a6381d6a39f008984372559b92874d18e56321f45d723f8b82decbd"},
			{"bebb09d89a1b929eaab8999eedc47b8862f5b39c18efb83b56d821cf1252f172", "bebb09d89a1b929eaab8999eedc47b8862f5b39c18efb83b56d821cf1252f172"},
			{"42", "0000000000000000000000000000000000000000000000000000000000000042"}
		}},
		{"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", {
			{"a3f002d10f54715854a95add1063beb34029e0fc780702df6a5492f9a7860b36fb1acc1ed308af720fa63fe0cb9bca5aad27fd9f45ae8040c81031655c63dcb2", "7132e25f8bb4c5c8c360f740c2aed8f9ed21f6d7f5f19515921a3984b9b30eff"},
			{"fbed3e5b82e8831fd5906a8c2fa8fb51a72deda79494252fd3ed08599017f15aa1cacf2c9511cac36dddfc34c89d5bc42720ab54dd0736228a846eb572df1673ceaf5fc889", "e04499654c002782777d154a6cafbfdfb41a0803f674e5a7943985b35e62b1f4"},
			{"f3407ab646fdd59ffca0a6e4b961acf8a545865349dfb32daa09406b3a375248f0", "407ab739fdd59f09a0a6e4b961acf8a545865256dfb32daa09406b3a375249e3"},
			{"116eb1ec6511ac99806d56cc678057307bbb82942962db40f9f5aa2287e83cdc", "116eb1ec6511ac99806d56cc678057307bbb82942962db40f9f5aa2287e83cdc"},
			{"f5", "00000000000000000000000000000000000000000000000000000000000000f5"}
		}},
		{"4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df", {
			{"f7ff3da778a63bf7df292ba14f69d796d75d2d1d0873dc83a39a8a40a1b80b686b6ede806b91c89372f53d6875017794043b825d007284a7f677bcd591a63f5ca9f25478615c04b316db696e33acc312ad5eef2c4e28ecadbcfb98c31adf14c4baaa90cbebecd285a458d81fbb5a202646bc8981135b345483b877ecab11e501", "44eafce56c0b4c8ad703cad6bcaf4549e58c24544b675621138ce6fa1da9a533b1ec100418a1d81b6c8f3bfc356597aee5795befe6b2ff181e23c8a8c502b760"},
			{"1a3e16e9cf4a1bab54b182c9b3dde89ec089855285d97d57dca848d165949b2dea84e2f0e970dc05e9fb0c05d80453a47245d52514307466dee46ebf69ba862b84c7d8fa57109b4892b322b579220f2f0305aa7672cfae4b5322300dba86821f8f87f53bd366132d325ffc692697ea51adb9ace3a56b1927e00ac522ed816856c60e255e1e", "3accd54aa235b4f56ee61b8d420090afffdb32e0dffe18ebec7e69808da28b6101f5ae746a74a450c8a494ca908891c37b7415d0d55b097b5e78280a9354dcef"},
			{"e8f3c2d9b98fd528f0b2d7e6985f83423c96f5dc16b519ef863eb6280a90b6e1f2c4dd2505cb447e966c95328a468fca3cec2ce1b05ff3b06c7224cdd9f7c9656e", "3bb09b76495cd387a59d7980df4e1bd0fc113e10a3b26c4622b5fb620aacb9f41e312194a8474ef5720e8747f6e2e5d801b75117e1a4277acd31df83e432e96b"},
			{"373a9e1076bf554604d0274ab3c88295bb0fc400a9bac1c14aaf017b9df67493e9f7f98298262b13065390d8b539576e5f137fe6f4adba7112fd187ccb686577", "373a9e1076bf554604d0274ab3c88295bb0fc400a9bac1c14aaf017b9df67493e9f7f98298262b13065390d8b539576e5f137fe6f4adba7112fd187ccb686577"},
			{"4e", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e"}
		}},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", {
			{"201d113aa7356d0a8266db28eda6aba193f3723ab753bbe5894d7c3676f676cef8812739ffcca13b492170e2d11c82446cac7679c121d642a417830a32b6ef77", "5e8fad96ff906f8f9307a68797d02ab2026ac5fd99f1b27a8fd7e24eeabc01f3"},
			{"14b72a11cb31ac0956de893f0bd800a2d93161563a0ba6f91b61f9147db154af9b656f518753a49f5a87c8cc952358d111ac20f2950fee43a6b5a89f942b9fe898bc685247", "0b4721b8e091c020bce14e89afb9c47b255ca6a5d6fb028491337b6dbcda4559"},
			{"a32f4310b609eed4582237a9ee693ea4193034313babcf09c0494c669978e695ff", "2f4310b609eed4582237a9ee693ea4193034313babcf09c0494c669978e81eda"},
			{"3b79be44897bd3f7c856ce12c23e82ab7416fafc204b15eb00c484b9021ba640", "3b79be44897bd3f7c856ce12c23e82ab7416fafc204b15eb00c484b9021ba640"},
			{"c3", "00000000000000000000000000000000000000000000000000000000000000c3"}
		}},
		{"8000000000000000000000000000000000000000000000000000000000000c99", {
			{"c577afba06d3fe3e3f8fe3c5be8a129f0018268bafc7204423202b5f735f7c67ec2b5c8599bae9d6b86e9d504f0aaff64bffbfbc617965610d9397b8da0a5e29", "2aa1df85907f2d794115d1159c4185e5eb8494499a6e70a40d0eccd000279920"},
			{"cf2af439be9221742f15f3dad8ace8da30b8ae440a8db722eae7d67e39f045e35dd801bb3a6db71d3f6245a52857b550e2da675bafe615fd5265741937a982bfad7f497d8e", "1ed5d2e84845bdf3d4ebf155c3b909c955e83acd2b3bc971ea5f121a9ad9f23d"},
			{"b5c91efa6cf8ea075af091463d12666dba81877b2de45addaedadabb85626c6232", "491efa6cf8ea075af091463d12666dba81877b2de45addaedadabb85625a853f"},
			{"e7a3824939adabd2cbe143a0c41616a1bf6426165757afcf7482c3119982de1a", "67a3824939adabd2cbe143a0c41616a1bf6426165757afcf7482c3119982d181"},
			{"90", "0000000000000000000000000000000000000000000000000000000000000090"}
		}},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", {
			{"83192502384eaf0b0a74f3a86fe1a98344ff7ad5c1c3001de07553fdf23ae2bb0dc0c9c6ba0c7ca5ee750d52f828d5ca4e1647dc1bb6fa42491c37494f97d78963e2a34f86c98aa70a2cf76f1eef2cf2697ad8e95fc8feed59ec367019215b7e27ef052ed06a0433b0e7d57435b19b40689352b2dcb2437ed86aaf5a8288e824", "c6c5e53eadac9a31481e88cfcb80f1b6c552de050a3441553eb3e5df7e034d3fb96f7fe2562b1102b31272ddc874c9e7f8190aec766480d35821914c6b097e70"},
			{"d005a5bde638bf56b197df15f2265a804d7b0aa0ec155bb965c2d96dc16c0ad6f748a915adff19fc377405466e7babb96e7464ca17d7788ba9d1267516e4832769f33aef5bf85a88e105c50be4376b82a17d7a350c2243644e9e3bf204aac98b0a760b0feaa69e614b2adc56bae78d15255055fa457e85ec453abe4c276e9c21a0183035e2", "19a2399b949cd31b7692aed7f819e1c79b22777cb380e4edcee156aaf5dc3fa6a75ff88c0a95e24bc83c3ba6045b2943697458b719388c095a2267d3f7673d72"},
			{"6f7977f85ca0dbc23fa3d7287b40cbc34b461bc9c3524744ef97beefe211c8693b7ac17bb88bcf1cb5609f38864b02ab761b45a8ecca39bcd58f9e9c14e98f860b", "7977f85ca0dbc23fa3d7287b40cbc34b461bc9c3524744ef97beefe211c8693b7ac17bb88bcf1cb5609f38864b02ab761b45a8ecca39bcd58f9e9c14e9907cc2"},
			{"2a70555486289093eb5b4c066f0b1b824b3fabc17c9aa4577fb9a2b7b038fe15668b4d6f7a4317c8991c3eb7fec66607f776d9d99f020848050f51972c132f52", "2a70555486289093eb5b4c066f0b1b824b3fabc17c9aa4577fb9a2b7b038fe15668b4d6f7a4317c8991c3eb7fec66607f776d9d99f020848050f51972c132f52"},
			{"27", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027"}
		}},
		{"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f", {
			{"3d003b4af25ac09387a6cb6213c99b2c9c6cd52081fe277463f658b51ad256b1cdbd9986ef1ac4db419339050baa5896a508dbfa84a9f42005d64099141bbc17706a1032926f142f3f7e5a54e44498a80136081ba77a71bb1de232d5c3cfe4e28eda8f1fa2aa9fdfc2a350b16c113096a4c288177176819a387cb74941b14245", "0a36a53467bc143f9cd9fb47bb7007f85ad535eaed143acc6e4145c88168b6b2246f6c1c4973e9bce4f7de514e585df38713c4d86614cdd528b0b289d1a453da"},
			{"143ca91b29e34e92884b37dc9762f2dbe64c2e0b386834e12467feeb73a70ee460a8011c8fbd79fa271189c2507d8695451d4721c32175d4014eb0a0925275c6e14fe4834a0fa4f6897561c117693cfb11af62d23777776ec60b8c65a57babfa70c4e9d9747b7526aff98bfd687f80d69cb38745ff894f72e796e5fb2f424f8feddf455ab3", "7181e4583af075cf9aa2495b9f75174d199c3133dc7c375a9cc1ee9f13f314ce2bae38cec4157b9ba4cb64ad4fd7fec8852199c559babc4bc03c5078b2acecf0"},
			{"cbdcada140d4f417352fb1fc56d73f6cb8ee17e0984f901346948b5511ed9385bcd159a851b9a6063ed56712fb09a7d45443f78988bfb8dd7165953ac58c9bfb2d", "5cada140d4f417352fb1fc56d73f6cb8ee17e0984f901346948b5511ed9385bcd159a851b9a6063ed56712fb09a7d45443f78988bfb8dd7165953ac58c9b4ab4"},
			{"82bbff37f89db4607a53c95336d7a8526b46947e8ee6b13868c9b01e333ec5785c0093f1c47c5bc346218e4105790ecf626ab9490ad2e821fd01697dbf648fd0", "02bbff37f89db4607a53c95336d7a8526b46947e8ee6b13868c9b01e333ec5785c0093f1c47c5bc346218e4105790ecf626ab9490ad2e821fd01697dbf648f61"},
			{"2e", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e"}
		}}
	};
	// Места, в которые помещаются разбираемые записи: поток длиннее числа
	uint8_t buffer[math::NUMBER_SIZE], stream[math::NUMBER_SIZE * 3];
	/**
	 * Выполняем перебор модулей
	 */
	for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
		// Объект арифметики по модулю
		math::modulus_t modulus;
		// Выполняем установку модуля
		ASSERT_TRUE(modulus.start(view_t(buffer, bytes(GROUPS[g].modulus, buffer)))) << "модуль " << g;
		/**
		 * Выполняем перебор потоков модуля
		 */
		for(size_t v = 0; v < 5; v++){
			// Приведённое значение
			math::number_t result;
			// Выполняем приведение потока по модулю
			ASSERT_TRUE(modulus.reduce(view_t(stream, bytes(GROUPS[g].streams[v].stream, stream)), result)) << "модуль " << g << ", поток " << v;
			// Сличаем остаток с ожидаемым
			ASSERT_EQ(number(modulus, result), std::string(GROUPS[g].streams[v].remainder)) << "модуль " << g << ", поток " << v;
		}
	}
}

/**
 * Проверка обращения окнами открытого показателя по модулям, идущим областью Монтгомери:
 * общий путь на четыре и восемь слов и путь P-256; пути прямой свёртки сличены выше
 */
TEST(NumberTest, Inverse) {
	struct item_t { const char * modulus; const char * value; const char * inverse; };
	static const item_t ITEMS[] = {
		{"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", "9069aef3a98d5a4176765b474bfe95fe9a49e13d1b0cb0edde079eaea48e8c67", "72bc0089a5cfb0d5ac12769bb5fcb40c88f2a47f70ed4cdffa91efd3492c4be8"},
		{"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "7eda1fca69a3e9a58f6aa4b93364aad344f45befbfab26db022bdd5559bb22f2", "461e4016eed14fe21b637a1ef382f2ad8c4618f181367f47e1ddc8c24e7002f0"},
		{"4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df", "15a18eb2e9066d94493f0556e9b8a466f2dd77d55565e21df8cc013f05bd729c4e70b96f9eab1ba961a5749e249a47ef27c42632314839f029f44f8cf1e92481", "05ac39a1758e6f33bedeb233cb6b32d46cb7aad39ece6df14dddb6438b325ad3c7c9edc83b450db95b46b9ff6a2b51fcd8135258c26951869be539c4f24fe9b2"},
		/**
		 * Модули прямой свёртки: 2^256 - 617 (CryptoPro-A), 2^255 + 3225 (CryptoPro-B),
		 * 2^512 - 569 и 2^511 + 111 (наборы 512 разрядов), а также p - 1, обратное самому
		 * себе: у таких модулей области Монтгомери нет, и обратное берётся как есть
		 */
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", "5c9a4b56088704ce240a488c3ab368b26df5dfb876b897efadd43e771030055f", "f036fd515a09961de7f9adda07d00f7a5419fd7b6416e5716bcab9ffcdcae8dc"},
		{"8000000000000000000000000000000000000000000000000000000000000c99", "3b77e4dd8ac585fad29b4bd454bf551f72b536eb5cc8bf534630c5c638bfdd2c", "0815f4454eba010932d523b70e9a5b0f3bb8e9882dfaf232ef884c1258a057c4"},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", "6e3c33237f2e86cac108143f29efe27864599c8f65b211282c9d709cdc53bfe8ec41e52b92e308d9298af1b854a5afc73a956b5ad50cf25b842089abd34ca117", "1179ea9f62c7c85a24b66f1357b2df110f0ecdf773cc2c9cfcf5d62ad7a4d4e4449d02df3d445908881ec3fb3cfc2871afff586f90af9ef185d4c86107498f4d"},
		{"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f", "131fac4bf1537ad24884eba32ed8ea9183d22067ec95f13be2e21c367edc51b456acbf180849a9fd3d98b9c9076e87ce673f5c00cf1851ceb3a3f73ed2ec24ac", "6b6f85264d7e77217606255a81657e7999490e0bacee2bcd1816a981f6a1ce9df378baf8b19e2b246ce2cfc33ded256241870aac25c9ca29c0a0b32d3ba090e4"},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd96"},
		/**
		 * Обращение идёт шагами деления Бернстайна и Янга проходами по 62 шага, и число
		 * проходов задано разрядностью модуля: 12 на четырёх словах, 18 на шести, 24 на
		 * восьми и 27 на девяти. Число по порядку CryptoPro-A ниже требует 562 шага, то
		 * есть десять проходов из двенадцати - больше всех из 20 000 случайных: оно ловит
		 * недобор проходов. Порядки P-384 и P-521 и поле P-521 закрепляют шесть и девять
		 * слов модуля, где порция разрядов ложится через границу слова иначе, чем на
		 * четырёх и восьми
		 */
		{"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", "521780d0690d570c1406c689310f9412d858daf5583fb71a2e46b9c02469a877", "677af82fa67181fa1137326d50a77f1dde629dbea47e8d7ca54bb9d2ceb678e2"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", "cd112a77dbdb12da98d1110ae98b680073a0068f5eeac54c6b306901653c8c66f9911a4a9d7426e383b0900ee64f1433", "9cb0e83241c5875988118dbd0772320b97d47200957a20343ebda28656bc59b23148d0c0f7ba5d7af80c59e1194cf742"},
		{"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", "01f668b5e1684861c243754dec13edcdfaad1e740b9b452c5b4ad3e3f4e26c17732ffc9e23d83cbd2b4da922397160494991be8e5e3844f97fd78fa34ba78dff9a41", "01265c447d7d5aec945f898e2e0145e2f1c6e54ea134e933ff60ae645f4def184c816299c263ca3f6fb4b8e13d12dd795736240eea22b107280bea835e8395ef5b0a"},
		{"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0110e727fad29c8fffa8bfecf8f181c7e979efb06af6b55059f173cdb013494f5fa18119831e52c29337509f929d46e0d400e046f12a51b50c4b4c271704028ae57e", "01a1672cb9a252d758493cf4d9472e9432f6c5309b582c72959682093868b3b1c9affc95d06af571b41983193cd3f584b47b59250dbf93aefd474fa466d29d32f7cb"}
	};
	uint8_t buffer[math::NUMBER_SIZE];
	for(size_t i = 0; i < (sizeof(ITEMS) / sizeof(ITEMS[0])); i++){
		math::modulus_t modulus;
		ASSERT_TRUE(modulus.start(view_t(buffer, bytes(ITEMS[i].modulus, buffer)))) << "модуль " << i;
		math::number_t value, result;
		ASSERT_TRUE(modulus.load(view_t(buffer, bytes(ITEMS[i].value, buffer)), value)) << "модуль " << i;
		modulus.enter(value, value);
		modulus.invert(value, result);
		modulus.leave(result, result);
		ASSERT_EQ(number(modulus, result), std::string(ITEMS[i].inverse)) << "модуль " << i;
	}
}
