/**
 * @file number.cpp
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
using namespace anyks;

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
	// Проверяем отказ установки чётного модуля
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("f0", buffer))));
	// Проверяем отказ установки модуля, меньшего трёх
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("01", buffer))));
	// Проверяем отказ установки модуля с нулевым старшим словом
	ASSERT_FALSE(modulus.start(view_t(buffer, bytes("0000000000000000000000000000000000000003", buffer))));
	// Проверяем отказ установки непереданного модуля
	ASSERT_FALSE(modulus.start(view_t()));
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
	// Проверяем успешность записи числа в место шире модуля
	ASSERT_TRUE(modulus.store(value, buffer, 40));
	// Сличаем записанное число с ожидаемым
	ASSERT_EQ(text(buffer, 40), std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000002"));
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
