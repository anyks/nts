/**
 * @file field25519.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля арифметики поля по модулю 2^255 - 19
 *
 * @note Контрольные значения выработаны независимой арифметикой произвольной
 *       точности: два случайных элемента, их сумма, разность, произведение,
 *       квадрат и обратный к первому
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <main.hpp>
#include <math/field25519.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Первый контрольный элемент, записанный младшим байтом вперёд
 */
static const char * FIRST = "6aad39f4c2aaed1a8a27e534ce4aa7426078fe43c27a88b4ada9dd74482b8410";

/**
 * Второй контрольный элемент, записанный младшим байтом вперёд
 */
static const char * SECOND = "232cae48c88fff9b500f0b4cca8e9f33a72971aa44125c7294d11bb5c82df818";

/**
 * Сумма контрольных элементов
 */
static const char * SUM = "8dd9e73c8b3aedb6da36f08098d9467607a26fee068de426427bf92911597c29";

/**
 * Разность контрольных элементов
 */
static const char * DIFFERENCE = "34818babfa1aee7e3918dae803bc070fb94e8d997d682c4219d8c1bf7ffd8b77";

/**
 * Произведение контрольных элементов
 */
static const char * PRODUCT = "4d9c89b13b70b95cd657e3834059cf68e24ce21919e03c3a40f70b9a3d6bf258";

/**
 * Квадрат первого контрольного элемента
 */
static const char * SQUARE = "4318b58bddddf6e546fba0f956a2e5540edf5573dcd505c51222524f1ca28c44";

/**
 * Обратный к первому контрольному элементу
 */
static const char * INVERSE = "3eb7b9b06dbd9f24df520e8f63ba87954dd94f0fa3a043496e36afc2a4d8b36e";

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
 * @brief Метод разбора элемента поля из записи
 *
 * @param source разбираемая запись
 * @param result место, в которое помещается элемент
 *
 */
static void element(const char * source, math::field25519::element_t & result) {
	// Место разобранных байтов
	uint8_t buffer[32];
	// Выполняем разбор записи
	ASSERT_EQ(bytes(source, buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента поля
	math::field25519::load(buffer, result);
}
/**
 * @brief Метод записи элемента поля строкой
 *
 * @param value записываемый элемент
 *
 * @return      запись элемента младшим байтом вперёд
 *
 */
static std::string record(const math::field25519::element_t & value) {
	// Место записи элемента
	uint8_t buffer[32];
	// Выполняем запись элемента
	math::field25519::store(value, buffer);
	// Выводим запись элемента
	return text(buffer, sizeof(buffer));
}

/**
 * @brief Проверка сложения и вычитания по контрольным значениям
 *
 */
TEST(Field25519Test, Addition) {
	// Контрольные элементы и итог
	math::field25519::element_t first, second, result;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем разбор второго элемента
	element(SECOND, second);
	// Выполняем сложение элементов
	math::field25519::add(first, second, result);
	// Сличаем сумму с контрольным значением
	ASSERT_EQ(record(result), std::string(SUM));
	// Выполняем вычитание элементов
	math::field25519::sub(first, second, result);
	// Сличаем разность с контрольным значением
	ASSERT_EQ(record(result), std::string(DIFFERENCE));
	// Выполняем вычитание в обратном порядке
	math::field25519::sub(second, first, result);
	// Прибавляем разность к первому элементу: обязан выйти второй
	math::field25519::add(result, first, result);
	// Сличаем итог со вторым элементом
	ASSERT_TRUE(math::field25519::equal(result, second));
	// Выполняем вычитание элемента из себя же в место одного из доводов
	math::field25519::sub(first, first, first);
	// Проверяем обращение разности в ноль
	ASSERT_TRUE(math::field25519::nil(first));
}
/**
 * @brief Проверка умножения и квадрата по контрольным значениям
 *
 */
TEST(Field25519Test, Multiplication) {
	// Контрольные элементы и итог
	math::field25519::element_t first, second, result;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем разбор второго элемента
	element(SECOND, second);
	// Выполняем умножение элементов
	math::field25519::mul(first, second, result);
	// Сличаем произведение с контрольным значением
	ASSERT_EQ(record(result), std::string(PRODUCT));
	// Выполняем умножение в обратном порядке в место одного из сомножителей
	math::field25519::mul(second, first, second);
	// Сличаем произведение с контрольным значением
	ASSERT_EQ(record(second), std::string(PRODUCT));
	// Выполняем возведение в квадрат
	math::field25519::square(first, result);
	// Сличаем квадрат с контрольным значением
	ASSERT_EQ(record(result), std::string(SQUARE));
	// Выполняем возведение в квадрат в место довода
	math::field25519::square(first, first);
	// Сличаем квадрат с контрольным значением
	ASSERT_EQ(record(first), std::string(SQUARE));
}
/**
 * @brief Проверка обращения элемента
 *
 */
TEST(Field25519Test, Inversion) {
	// Контрольный элемент, обратный к нему и единица
	math::field25519::element_t first, inverse, unit;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем обращение элемента
	math::field25519::invert(first, inverse);
	// Сличаем обратный элемент с контрольным значением
	ASSERT_EQ(record(inverse), std::string(INVERSE));
	// Выполняем умножение элемента на обратный
	math::field25519::mul(first, inverse, inverse);
	// Получаем единицу поля
	math::field25519::one(unit);
	// Проверяем обращение произведения в единицу
	ASSERT_TRUE(math::field25519::equal(inverse, unit));
	// Выполняем обращение элемента в место довода
	math::field25519::invert(first, first);
	// Сличаем обратный элемент с контрольным значением
	ASSERT_EQ(record(first), std::string(INVERSE));
	// Ноль поля
	math::field25519::element_t empty;
	// Выполняем обращение нуля
	math::field25519::invert(empty, inverse);
	// Проверяем, что обратный к нулю - ноль
	ASSERT_TRUE(math::field25519::nil(inverse));
}
/**
 * @brief Проверка степени (p - 5) / 8 извлечением корня
 *
 */
TEST(Field25519Test, Root) {
	// Контрольный элемент и промежуточные значения
	math::field25519::element_t first, square, power, check;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Вырабатываем квадрат элемента
	math::field25519::square(first, square);
	// Возводим квадрат в степень (p - 5) / 8
	math::field25519::root(square, power);
	// Умножаем степень на квадрат: выходит корень из квадрата либо корень с множителем
	math::field25519::mul(power, square, power);
	// Возводим возможный корень в квадрат
	math::field25519::square(power, check);
	// Противоположный квадрат
	math::field25519::element_t negative;
	// Получаем ноль поля
	math::field25519::zero(negative);
	// Вычитаем квадрат из нуля
	math::field25519::sub(negative, square, negative);
	// Проверяем, что квадрат возможного корня сошёлся с квадратом либо его противоположностью
	ASSERT_TRUE(math::field25519::equal(check, square) || math::field25519::equal(check, negative));
}
/**
 * @brief Проверка приведения записей, не меньших модуля
 *
 */
TEST(Field25519Test, Reduction) {
	// Место разбираемых байтов и элемент
	uint8_t buffer[32];
	// Разбираемый элемент
	math::field25519::element_t value;
	// Выполняем разбор записи p + 5
	ASSERT_EQ(bytes("f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента
	math::field25519::load(buffer, value);
	// Проверяем приведение к пяти
	ASSERT_EQ(record(value), std::string("0500000000000000000000000000000000000000000000000000000000000000"));
	// Выполняем разбор записи 2^255 - 1
	ASSERT_EQ(bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента
	math::field25519::load(buffer, value);
	// Проверяем приведение к восемнадцати
	ASSERT_EQ(record(value), std::string("1200000000000000000000000000000000000000000000000000000000000000"));
	// Выполняем разбор записи 2^256 - 1: старший разряд отбрасывается
	ASSERT_EQ(bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента
	math::field25519::load(buffer, value);
	// Проверяем приведение к восемнадцати
	ASSERT_EQ(record(value), std::string("1200000000000000000000000000000000000000000000000000000000000000"));
	// Выполняем разбор записи p: приводится к нулю
	ASSERT_EQ(bytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента
	math::field25519::load(buffer, value);
	// Проверяем обращение модуля в ноль
	ASSERT_TRUE(math::field25519::nil(value));
	// Выполняем разбор записи p - 1: остаётся как есть
	ASSERT_EQ(bytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", buffer), static_cast <size_t> (32));
	// Выполняем разбор элемента
	math::field25519::load(buffer, value);
	// Проверяем сохранение записи
	ASSERT_EQ(record(value), std::string("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
	// Единица поля
	math::field25519::element_t unit;
	// Получаем единицу поля
	math::field25519::one(unit);
	// Прибавляем единицу к p - 1: обязан выйти ноль
	math::field25519::add(value, unit, value);
	// Проверяем обращение суммы в ноль
	ASSERT_TRUE(math::field25519::nil(value));
	// Вычитаем единицу из нуля: обязан выйти p - 1
	math::field25519::sub(value, unit, value);
	// Проверяем запись разности
	ASSERT_EQ(record(value), std::string("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
}
/**
 * @brief Проверка условного обмена элементов
 *
 */
TEST(Field25519Test, Swap) {
	// Контрольные элементы
	math::field25519::element_t first, second;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем разбор второго элемента
	element(SECOND, second);
	// Выполняем обмен с нулевым признаком
	math::field25519::swap(first, second, 0);
	// Проверяем, что первый элемент остался на месте
	ASSERT_EQ(record(first), std::string(FIRST));
	// Проверяем, что второй элемент остался на месте
	ASSERT_EQ(record(second), std::string(SECOND));
	// Выполняем обмен с единичным признаком
	math::field25519::swap(first, second, 1);
	// Проверяем, что первый элемент стал вторым
	ASSERT_EQ(record(first), std::string(SECOND));
	// Проверяем, что второй элемент стал первым
	ASSERT_EQ(record(second), std::string(FIRST));
	// Проверяем, что элементы различны
	ASSERT_FALSE(math::field25519::equal(first, second));
}
