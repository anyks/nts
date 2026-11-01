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
#include <internal/math/field25519.hpp>

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
 * @brief Функция разбора элемента поля из записи
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
 * @brief Функция записи элемента поля строкой
 *
 * @param value записываемый элемент
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
 * @brief Проверка возведения в квадрат на неприведённых конечностях
 *
 * @details Квадрат считается своим путём, а не умножением элемента на себя: конечности
 *          между действиями доходят до 2^54, и путь квадрата обязан давать то же, что
 *          и умножение, на всех допустимых конечностях, а не только на приведённых
 *
 */
TEST(Field25519Test, Squaring) {
	// Границы конечностей: приведённая, за пределом приведения, на верхней границе умножения
	static const uint64_t limits[] = {0, 1, ((static_cast <uint64_t> (1) << 51) - 1), (static_cast <uint64_t> (1) << 51), ((static_cast <uint64_t> (1) << 53) - 1), ((static_cast <uint64_t> (1) << 54) - 1)};
	// Число проверенных сочетаний
	size_t count = 0;
	/**
	 * Выполняем перебор сочетаний конечностей по границам
	 */
	for(size_t i = 0; i < 6; i++){
		/**
		 * Средний перебор: вторая конечность по границам
		 */
		for(size_t j = 0; j < 6; j++){
			/**
			 * Внутренний перебор: третья конечность по границам
			 */
			for(size_t k = 0; k < 6; k++){
				// Элемент, составленный по границам
				math::field25519::element_t value;
				// Записываем конечности элемента
				value.limbs[0] = limits[i];
				// Вторая конечность — граница j
				value.limbs[1] = limits[j];
				// Третья конечность — граница k
				value.limbs[2] = limits[k];
				// Четвёртая конечность — граница i+j по модулю 6
				value.limbs[3] = limits[(i + j) % 6];
				// Пятая конечность — граница j+k по модулю 6
				value.limbs[4] = limits[(j + k) % 6];
				// Квадрат своим путём и умножением на себя
				math::field25519::element_t square, product;
				// Выполняем возведение в квадрат
				math::field25519::square(value, square);
				// Выполняем умножение элемента на себя
				math::field25519::mul(value, value, product);
				// Сличаем записи квадрата и произведения
				ASSERT_EQ(record(square), record(product)) << "конечности " << i << " " << j << " " << k;
				// Считаем проверенное сочетание
				count++;
			}
		}
	}
	// Сличаем число проверенных сочетаний
	ASSERT_EQ(count, static_cast <size_t> (216));
}
/**
 * @brief Проверка умножения элемента на малое число
 *
 * @details Малое число умножает пять конечностей вместо двадцати пяти произведений:
 *          итог обязан совпадать с умножением на элемент, несущий то же число, на
 *          приведённых и неприведённых конечностях и на границе множителя 2^32
 *
 */
TEST(Field25519Test, Scaling) {
	// Множители: единица, множитель удвоения X25519, граница
	static const uint64_t factors[] = {1, 19, 121665, 0xFFFFFFFFULL, (static_cast <uint64_t> (1) << 32)};
	// Контрольный элемент
	math::field25519::element_t value;
	// Выполняем разбор контрольного элемента
	element(FIRST, value);
	/**
	 * Выполняем перебор множителей
	 */
	for(const uint64_t factor : factors){
		// Множитель элементом поля
		math::field25519::element_t scalar;
		// Записываем множитель в младшую конечность
		scalar.limbs[0] = factor;
		// Произведение своим путём и умножением элементов
		math::field25519::element_t scaled, product;
		// Выполняем умножение на малое число
		math::field25519::mul(value, factor, scaled);
		// Выполняем умножение на элемент
		math::field25519::mul(value, scalar, product);
		// Сличаем записи произведений
		ASSERT_EQ(record(scaled), record(product)) << "множитель " << factor;
		// Выполняем умножение на малое число в место довода
		math::field25519::element_t inplace = value;
		// Выполняем умножение на месте
		math::field25519::mul(inplace, factor, inplace);
		// Сличаем запись произведения на месте
		ASSERT_EQ(record(inplace), record(product)) << "множитель на месте " << factor;
	}
	// Неприведённый элемент: все конечности на верхней границе умножения
	math::field25519::element_t wide, scalar, scaled, product;
	/**
	 * Записываем конечности на границе
	 */
	for(size_t i = 0; i < 5; i++){
		// Записываем конечности на верхней границе
		wide.limbs[i] = ((static_cast <uint64_t> (1) << 54) - 1 - i);
	}
	// Записываем множитель удвоения X25519
	scalar.limbs[0] = 121665;
	// Выполняем умножение на малое число
	math::field25519::mul(wide, static_cast <uint64_t> (121665), scaled);
	// Выполняем умножение на элемент
	math::field25519::mul(wide, scalar, product);
	// Сличаем записи произведений
	ASSERT_EQ(record(scaled), record(product));
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

/**
 * Под x86-64 ядра шага лестницы по столбцам на MULQ сличаются с ядрами на C++
 */
#if defined(__ANTS_FIELD25519_COLUMNS__)
/**
 * @brief Проверка ядер по столбцам на MULQ против ядер на C++
 *
 * @details Шаг лестницы X25519 под x86-64 без ADX идёт ядрами columns внутреннего заголовочного
 *          файла (решение 8 x25519.cpp): умножение, квадрат и малый множитель обязаны давать то
 *          же, что ядра kernel, на всех допустимых конечностях - по границам до 2^54 и на
 *          случайных, и когда место итога совпадает с сомножителем
 *
 */
TEST(Field25519Test, Columns) {
	// Границы конечностей: приведённая, за пределом приведения, на верхней границе умножения
	static const uint64_t limits[] = {0, 1, ((static_cast <uint64_t> (1) << 51) - 1), (static_cast <uint64_t> (1) << 51), ((static_cast <uint64_t> (1) << 53) - 1), ((static_cast <uint64_t> (1) << 54) - 1)};
	// Число проверенных сочетаний
	size_t count = 0;
	// Состояние вырабатывателя случайных конечностей
	uint64_t state = 0x9E3779B97F4A7C15ull;
	/**
	 * Выполняем перебор сочетаний: по границам и случайные до 2^54
	 */
	for(size_t n = 0; n < 4216; n++){
		// Сомножители
		math::field25519::element_t first, second;
		// Если сочетание по границам
		if(n < 216){
			// Индексы границ
			const size_t i = (n / 36), j = ((n / 6) % 6), k = (n % 6);
			// Записываем конечности первого сомножителя
			first.limbs[0] = limits[i];
			// Вторая конечность первого сомножителя — граница j
			first.limbs[1] = limits[j];
			// Третья конечность первого сомножителя — граница k
			first.limbs[2] = limits[k];
			// Четвёртая конечность первого сомножителя — граница i+j по модулю 6
			first.limbs[3] = limits[(i + j) % 6];
			// Пятая конечность первого сомножителя — граница j+k по модулю 6
			first.limbs[4] = limits[(j + k) % 6];
			// Записываем конечности второго сомножителя сдвигом границ
			second.limbs[0] = limits[(k + 1) % 6];
			// Вторая конечность второго сомножителя — граница i+2 по модулю 6
			second.limbs[1] = limits[(i + 2) % 6];
			// Третья конечность второго сомножителя — граница j+3 по модулю 6
			second.limbs[2] = limits[(j + 3) % 6];
			// Четвёртая конечность второго сомножителя — граница i+k+4 по модулю 6
			second.limbs[3] = limits[(i + k + 4) % 6];
			// Пятая конечность второго сомножителя — граница j+k+5 по модулю 6
			second.limbs[4] = limits[(j + k + 5) % 6];
		// Иначе сочетание случайное
		} else {
			// Разряды конечностей: до 2^51 либо до 2^54
			const uint64_t mask = ((static_cast <uint64_t> (1) << ((n & 1) ? 54 : 51)) - 1);
			/**
			 * Выполняем выработку конечностей
			 */
			for(size_t i = 0; i < math::field25519::LIMBS; i++){
				// Шаг вырабатывателя xorshift
				state ^= (state << 13); state ^= (state >> 7); state ^= (state << 17);
				// Записываем конечность первого сомножителя
				first.limbs[i] = (state & mask);
				// Шаг вырабатывателя xorshift
				state ^= (state << 13); state ^= (state >> 7); state ^= (state << 17);
				// Записываем конечность второго сомножителя
				second.limbs[i] = (state & mask);
			}
		}
		// Итоги ядер на C++ и по столбцам
		math::field25519::element_t expected, actual;
		// Умножение
		math::field25519::kernel::multiply(first, second, expected);
		// Умножение по столбцам
		math::field25519::columns::multiply(first, second, actual);
		// Сличаем записи произведений
		ASSERT_EQ(record(actual), record(expected)) << "умножение " << n;
		// Квадрат
		math::field25519::kernel::square(first, expected);
		// Квадрат по столбцам
		math::field25519::columns::square(first, actual);
		// Сличаем записи квадратов
		ASSERT_EQ(record(actual), record(expected)) << "квадрат " << n;
		// Малый множитель на границе 2^32 и множитель лестницы
		const uint64_t factor = ((n & 2) ? (static_cast <uint64_t> (1) << 32) : 121666);
		// Масштаб на малое число ядром
		math::field25519::kernel::scale(first, factor, expected);
		// Масштаб на малое число по столбцам
		math::field25519::columns::scale(first, factor, actual);
		// Сличаем записи произведений на малое число
		ASSERT_EQ(record(actual), record(expected)) << "малый множитель " << n;
		// Итог поверх сомножителя: умножение в место первого, квадрат в место довода, квадрат умножением на себя
		expected = first; actual = first;
		// Умножение с записью поверх первого сомножителя ядром
		math::field25519::kernel::multiply(expected, second, expected);
		// Умножение с записью поверх первого сомножителя по столбцам
		math::field25519::columns::multiply(actual, second, actual);
		// Сличаем записи произведений на месте
		ASSERT_EQ(record(actual), record(expected)) << "умножение на месте " << n;
		// Восстанавливаем сомножитель перед квадратом на месте
		expected = first; actual = first;
		// Квадрат на месте ядром
		math::field25519::kernel::square(expected, expected);
		// Квадрат на месте по столбцам
		math::field25519::columns::square(actual, actual);
		// Сличаем записи квадратов на месте
		ASSERT_EQ(record(actual), record(expected)) << "квадрат на месте " << n;
		// Восстанавливаем сомножитель перед умножением на себя
		expected = first; actual = first;
		// Умножение элемента на себя с записью поверх него ядром
		math::field25519::kernel::multiply(expected, expected, expected);
		// Умножение элемента на себя с записью поверх него по столбцам
		math::field25519::columns::multiply(actual, actual, actual);
		// Сличаем записи произведений элемента на себя на месте
		ASSERT_EQ(record(actual), record(expected)) << "умножение на себя на месте " << n;
		// Считаем проверенное сочетание
		count++;
	}
	// Сличаем число проверенных сочетаний
	ASSERT_EQ(count, static_cast <size_t> (4216));
}
/**
 * @brief Шаг лестницы одной вставкой против ядер kernel в порядке шага x25519.cpp
 *
 * @details Кадры по границам конечностей (0, 1, 2^51 - 1, 2^51, 2^51 + 2^13 - 1 - предел итогов
 *          ядер) и случайные до 2^51 + 2^13 при приведённой множимой точке, оба признака обмена;
 *          сличаются все семь элементов кадра, включая промежуточные значения
 *
 */
TEST(Field25519Test, Step) {
	// Границы конечностей координат
	static const uint64_t limits[] = {0, 1, ((static_cast <uint64_t> (1) << 51) - 1), (static_cast <uint64_t> (1) << 51), (((static_cast <uint64_t> (1) << 51) + (static_cast <uint64_t> (1) << 13)) - 1)};
	// Предел конечностей итогов ядер
	const uint64_t bound = ((static_cast <uint64_t> (1) << 51) + (static_cast <uint64_t> (1) << 13));
	// Число проверенных кадров
	size_t count = 0;
	// Состояние вырабатывателя случайных конечностей
	uint64_t state = 0xD1B54A32D192ED03ull;
	/**
	 * Выполняем перебор кадров: по границам и случайные
	 */
	for(size_t n = 0; n < 4125; n++){
		// Кадр шага одной вставкой
		math::field25519::columns::ladder_t actual;
		// Элементы кадра подряд
		math::field25519::element_t * items = &actual.x2;
		// Если кадр по границам
		if(n < 125){
			// Индексы границ
			const size_t i = (n / 25), j = ((n / 5) % 5), k = (n % 5);
			/**
			 * Выполняем перебор элементов кадра
			 */
			for(size_t e = 0; e < 7; e++){
				/**
				 * Выполняем перебор конечностей элемента
				 */
				for(size_t l = 0; l < math::field25519::LIMBS; l++)
					// Записываем конечность по границам со сдвигом
					items[e].limbs[l] = limits[(i + (j * l) + (k * e)) % 5];
			}
			// Множимая точка приведена
			items[4].limbs[0] &= ((static_cast <uint64_t> (1) << 51) - 1);
		// Иначе кадр случайный
		} else {
			/**
			 * Выполняем перебор элементов кадра
			 */
			for(size_t e = 0; e < 7; e++){
				/**
				 * Выполняем перебор конечностей элемента
				 */
				for(size_t l = 0; l < math::field25519::LIMBS; l++){
					// Шаг вырабатывателя xorshift
					state ^= (state << 13); state ^= (state >> 7); state ^= (state << 17);
					// Записываем конечность: множимая точка приведена, остальные до предела итогов ядер
					items[e].limbs[l] = ((e == 4) ? (state & ((static_cast <uint64_t> (1) << 51) - 1)) : (state % bound));
				}
			}
		}
		// Признак обмена
		const uint64_t flag = (n & 1);
		// Кадр эталона: тот же шаг ядрами kernel в порядке x25519.cpp
		math::field25519::columns::ladder_t expected = actual;
		// Выполняем условный обмен первых координат точек
		math::field25519::swap(expected.x2, expected.x3, flag);
		// Выполняем условный обмен вторых координат точек
		math::field25519::swap(expected.z2, expected.z3, flag);
		// Разность координат точки сложения: x3-z3
		math::field25519::kernel::minus(expected.x3, expected.z3, expected.first);
		// Разность координат удвоенной точки: x2-z2
		math::field25519::kernel::minus(expected.x2, expected.z2, expected.second);
		// Сумма координат удвоенной точки поверх x2
		math::field25519::kernel::plus(expected.x2, expected.z2, expected.x2);
		// Сумма координат точки сложения поверх z2
		math::field25519::kernel::plus(expected.x3, expected.z3, expected.z2);
		// Произведение суммы x2 на разность x3 поверх z3
		math::field25519::kernel::multiply(expected.x2, expected.first, expected.z3);
		// Произведение суммы x3 на разность x2 поверх z2
		math::field25519::kernel::multiply(expected.z2, expected.second, expected.z2);
		// Квадрат разности координат удвоенной точки
		math::field25519::kernel::square(expected.second, expected.first);
		// Квадрат суммы координат удвоенной точки
		math::field25519::kernel::square(expected.x2, expected.second);
		// Сумма произведений поверх x3
		math::field25519::kernel::plus(expected.z3, expected.z2, expected.x3);
		// Разность произведений поверх z2
		math::field25519::kernel::minus(expected.z3, expected.z2, expected.z2);
		// Произведение квадратов суммы и разности — итоговая x2
		math::field25519::kernel::multiply(expected.second, expected.first, expected.x2);
		// Разность квадратов суммы и разности координат
		math::field25519::kernel::minus(expected.second, expected.first, expected.second);
		// Квадрат разности произведений
		math::field25519::kernel::square(expected.z2, expected.z2);
		// Масштаб разности квадратов на множитель лестницы 121666
		math::field25519::kernel::scale(expected.second, 121666, expected.z3);
		// Квадрат суммы произведений — итоговая x3
		math::field25519::kernel::square(expected.x3, expected.x3);
		// Сумма квадрата разности и масштаба — множитель итоговой z2
		math::field25519::kernel::plus(expected.first, expected.z3, expected.first);
		// Произведение базовой координаты на квадрат разности произведений — итоговая z3
		math::field25519::kernel::multiply(expected.x1, expected.z2, expected.z3);
		// Произведение разности квадратов на множитель — итоговая z2
		math::field25519::kernel::multiply(expected.second, expected.first, expected.z2);
		// Выполняем шаг одной вставкой
		math::field25519::columns::step(actual, flag);
		// Элементы кадра эталона подряд
		const math::field25519::element_t * wanted = &expected.x2;
		// Имена элементов кадра
		static const char * const names[7] = {"x2", "z2", "x3", "z3", "x1", "first", "second"};
		/**
		 * Выполняем сличение всех элементов кадра
		 */
		for(size_t e = 0; e < 7; e++)
			// Сличаем записи элементов
			ASSERT_EQ(record(items[e]), record(wanted[e])) << "кадр " << n << ", элемент " << names[e];
		// Считаем проверенный кадр
		count++;
	}
	// Сличаем число проверенных кадров
	ASSERT_EQ(count, static_cast <size_t> (4125));
}
#endif
