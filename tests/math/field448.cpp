/**
 * @file field448.cpp
 * @date 2026-11-05
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
 * @brief Исходный файл проверок модуля арифметики поля по модулю 2^448 - 2^224 - 1
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
#include <math/field448.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Первый контрольный элемент, записанный младшим байтом вперёд
 */
static const char * FIRST = "bedc8be0e03f7696db8d652341a6685721f03913c7c3f71be7a3ac779aced49f68b4267c674547edf10d03db73cd7660393daf395a509900";

/**
 * Второй контрольный элемент, записанный младшим байтом вперёд
 */
static const char * SECOND = "896cc83920b18b5cf1d6afe5ebc3b8c50d6889106320d224fc391fc775d5fe9654b36a83787f63b9cb653b03b5e7704357b6444151004600";

/**
 * Сумма контрольных элементов
 */
static const char * SUM = "4749541a01f101f3cc6415092d6a211d2f58c3232ae4c940e3ddcb3e10a4d336bd6791ffdfc4aaa6bd733ede28b5e7a390f3f37aab50df00";

/**
 * Разность контрольных элементов
 */
static const char * DIFFERENCE = "3570c3a6c08eea39eab6b53d55e2af911388b00264a325f7ea698db024f9d5081401bcf8eec5e33326a8c7d7bee5051de2866af808505300";

/**
 * Произведение контрольных элементов
 */
static const char * PRODUCT = "32249697a9e7392730e8e14c4396f9d81f6337ccff002cc2bf446609df8f022ad0c9a6ac6280aacf220570efbb825ad8442200ac97fbef78";

/**
 * Квадрат первого контрольного элемента
 */
static const char * SQUARE = "5e10f2dd901f6cf1a49df7bb547f6351b0563eae6d851a8c8d7272f1bb1b819989d9761714b6aa9b47592419017a51a62b52c1ccadb14d46";

/**
 * Обратный к первому контрольному элементу
 */
static const char * INVERSE = "f602e3ae4858aca3e03c8afb9ee377e5d79935131d288b4306811b2a537aba01d1384d638defcabec309cca2dd692df854a2b9faaeb27e81";

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
static void element(const char * source, math::field448::element_t & result) {
	// Место разобранных байтов
	uint8_t buffer[math::field448::SIZE];
	// Выполняем разбор записи
	ASSERT_EQ(bytes(source, buffer), math::field448::SIZE);
	// Выполняем разбор элемента поля
	math::field448::load(buffer, result);
}
/**
 * @brief Функция записи элемента поля строкой
 *
 * @param value записываемый элемент
 * @return      запись элемента младшим байтом вперёд
 *
 */
static std::string record(const math::field448::element_t & value) {
	// Место записи элемента
	uint8_t buffer[math::field448::SIZE];
	// Выполняем запись элемента
	math::field448::store(value, buffer);
	// Выводим запись элемента
	return text(buffer, sizeof(buffer));
}

/**
 * @brief Проверка сложения и вычитания по контрольным значениям
 *
 */
TEST(Field448Test, Addition) {
	// Контрольные элементы и итог
	math::field448::element_t first, second, result;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем разбор второго элемента
	element(SECOND, second);
	// Выполняем сложение элементов
	math::field448::add(first, second, result);
	// Сличаем сумму с контрольным значением
	ASSERT_EQ(record(result), std::string(SUM));
	// Выполняем вычитание элементов
	math::field448::sub(first, second, result);
	// Сличаем разность с контрольным значением
	ASSERT_EQ(record(result), std::string(DIFFERENCE));
	// Выполняем вычитание в обратном порядке
	math::field448::sub(second, first, result);
	// Прибавляем разность к первому элементу: обязан выйти второй
	math::field448::add(result, first, result);
	// Сличаем итог со вторым элементом
	ASSERT_TRUE(math::field448::equal(result, second));
	// Выполняем вычитание элемента из себя же в место одного из доводов
	math::field448::sub(first, first, first);
	// Проверяем обращение разности в ноль
	ASSERT_TRUE(math::field448::nil(first));
}
/**
 * @brief Проверка умножения и квадрата по контрольным значениям
 *
 */
TEST(Field448Test, Multiplication) {
	// Контрольные элементы и итог
	math::field448::element_t first, second, result;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем разбор второго элемента
	element(SECOND, second);
	// Выполняем умножение элементов
	math::field448::mul(first, second, result);
	// Сличаем произведение с контрольным значением
	ASSERT_EQ(record(result), std::string(PRODUCT));
	// Выполняем умножение в обратном порядке в место одного из сомножителей
	math::field448::mul(second, first, second);
	// Сличаем произведение с контрольным значением
	ASSERT_EQ(record(second), std::string(PRODUCT));
	// Выполняем возведение в квадрат
	math::field448::square(first, result);
	// Сличаем квадрат с контрольным значением
	ASSERT_EQ(record(result), std::string(SQUARE));
	// Выполняем возведение в квадрат в место довода
	math::field448::square(first, first);
	// Сличаем квадрат с контрольным значением
	ASSERT_EQ(record(first), std::string(SQUARE));
}
/**
 * @brief Проверка возведения в квадрат на неприведённых конечностях
 *
 * @details Квадрат считается своим путём, а не умножением элемента на себя: конечности
 *          между действиями доходят до 2^58, и путь квадрата обязан давать то же, что
 *          и умножение, на всех допустимых конечностях, а не только на приведённых
 *
 */
TEST(Field448Test, Squaring) {
	// Границы конечностей: приведённая, за пределом приведения, на верхней границе умножения
	static const uint64_t limits[] = {0, 1, ((static_cast <uint64_t> (1) << 56) - 1), (static_cast <uint64_t> (1) << 56), ((static_cast <uint64_t> (1) << 57) - 1), ((static_cast <uint64_t> (1) << 58) - 1)};
	// Число проверенных сочетаний
	size_t count = 0;
	/**
	 * Выполняем перебор сочетаний конечностей по границам
	 */
	for(size_t i = 0; i < 6; i++){
		/**
		 * Средний перебор: вторая граница сочетания
		 */
		for(size_t j = 0; j < 6; j++){
			/**
			 * Внутренний перебор: третья граница сочетания
			 */
			for(size_t k = 0; k < 6; k++){
				// Элемент, составленный по границам
				math::field448::element_t value;
				/**
				 * Записываем конечности элемента сочетанием границ
				 */
				for(size_t w = 0; w < math::field448::LIMBS; w++)
					// Записываем очередную конечность по номерам границ
					value.limbs[w] = limits[(((i + j) * w + (k * ((w + 1) / 2)) + ((w % 2) ? k : i)) % 6)];
				// Квадрат своим путём и умножением на себя
				math::field448::element_t square, product;
				// Выполняем возведение в квадрат
				math::field448::square(value, square);
				// Выполняем умножение элемента на себя
				math::field448::mul(value, value, product);
				// Сличаем записи квадрата и произведения
				ASSERT_EQ(record(square), record(product)) << "сочетание " << i << " " << j << " " << k;
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
 * @details Малое число умножает восемь конечностей вместо шестидесяти четырёх
 *          произведений: итог обязан совпадать с умножением на элемент, несущий то же
 *          число, на приведённых и неприведённых конечностях
 *
 */
TEST(Field448Test, Scaling) {
	// Множители: единица, множитель удвоения X448, граница
	static const uint64_t factors[] = {1, 39082, 0xFFFFFFFFULL, (static_cast <uint64_t> (1) << 32)};
	// Контрольный элемент
	math::field448::element_t value;
	// Выполняем разбор контрольного элемента
	element(FIRST, value);
	/**
	 * Выполняем перебор множителей
	 */
	for(const uint64_t factor : factors){
		// Множитель элементом поля
		math::field448::element_t scalar;
		// Записываем множитель в нулевую конечность
		scalar.limbs[0] = factor;
		// Произведение своим путём и умножением элементов
		math::field448::element_t scaled, product;
		// Выполняем умножение на малое число
		math::field448::mul(value, factor, scaled);
		// Выполняем умножение на элемент
		math::field448::mul(value, scalar, product);
		// Сличаем записи произведений
		ASSERT_EQ(record(scaled), record(product)) << "множитель " << factor;
		// Выполняем умножение на малое число в место довода
		math::field448::element_t inplace = value;
		// Выполняем умножение на месте
		math::field448::mul(inplace, factor, inplace);
		// Сличаем запись произведения на месте
		ASSERT_EQ(record(inplace), record(product)) << "множитель на месте " << factor;
	}
	// Неприведённый элемент: все конечности на верхней границе умножения
	math::field448::element_t wide, scalar, scaled, product;
	/**
	 * Записываем конечности на границе
	 */
	for(size_t i = 0; i < math::field448::LIMBS; i++){
		// Записываем конечности на верхней границе
		wide.limbs[i] = ((static_cast <uint64_t> (1) << 58) - 1 - i);
	}
	// Записываем множитель удвоения X448
	scalar.limbs[0] = 39082;
	// Выполняем умножение на малое число
	math::field448::mul(wide, static_cast <uint64_t> (39082), scaled);
	// Выполняем умножение на элемент
	math::field448::mul(wide, scalar, product);
	// Сличаем записи произведений
	ASSERT_EQ(record(scaled), record(product));
}
/**
 * @brief Проверка обращения элемента
 *
 */
TEST(Field448Test, Inversion) {
	// Контрольный элемент, обратный к нему и единица
	math::field448::element_t first, inverse, unit;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Выполняем обращение элемента
	math::field448::invert(first, inverse);
	// Сличаем обратный элемент с контрольным значением
	ASSERT_EQ(record(inverse), std::string(INVERSE));
	// Выполняем умножение элемента на обратный
	math::field448::mul(first, inverse, inverse);
	// Получаем единицу поля
	math::field448::one(unit);
	// Проверяем обращение произведения в единицу
	ASSERT_TRUE(math::field448::equal(inverse, unit));
	// Выполняем обращение элемента в место довода
	math::field448::invert(first, first);
	// Сличаем обратный элемент с контрольным значением
	ASSERT_EQ(record(first), std::string(INVERSE));
	// Ноль поля
	math::field448::element_t empty;
	// Выполняем обращение нуля
	math::field448::invert(empty, inverse);
	// Проверяем, что обратный к нулю - ноль
	ASSERT_TRUE(math::field448::nil(inverse));
}
/**
 * @brief Проверка степени (p + 1) / 4 извлечением корня
 *
 * @details Поле сравнимо с тремя по модулю четырёх, отчего квадрат всякого вычета
 *          обязан возвращаться корнем точно, без противоположного варианта
 *
 */
TEST(Field448Test, Root) {
	// Контрольный элемент и промежуточные значения
	math::field448::element_t first, square, power, check;
	// Выполняем разбор первого элемента
	element(FIRST, first);
	// Вырабатываем квадрат элемента: квадрат всегда есть вычет
	math::field448::square(first, square);
	// Извлекаем корень из квадрата возведением в степень (p + 1) / 4
	math::field448::root(square, power);
	// Возводим корень в квадрат
	math::field448::square(power, check);
	// Проверяем точное возвращение квадрата корнем
	ASSERT_TRUE(math::field448::equal(check, square));
}
/**
 * @brief Проверка приведения записей, не меньших модуля
 *
 */
TEST(Field448Test, Reduction) {
	// Место разбираемых байтов и элемент
	uint8_t buffer[math::field448::SIZE];
	// Разбираемый элемент
	math::field448::element_t value;
	// Выполняем разбор записи p + 5
	ASSERT_EQ(bytes("04000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", buffer), math::field448::SIZE);
	// Выполняем разбор элемента
	math::field448::load(buffer, value);
	// Проверяем приведение к пяти
	ASSERT_EQ(record(value), std::string("0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
	// Выполняем разбор записи 2^448 - 1
	ASSERT_EQ(bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", buffer), math::field448::SIZE);
	// Выполняем разбор элемента
	math::field448::load(buffer, value);
	// Проверяем приведение к 2^224: 2^448 - 1 больше модуля ровно на 2^224
	ASSERT_EQ(record(value), std::string("0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000"));
	// Выполняем разбор записи самого модуля
	ASSERT_EQ(bytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff", buffer), math::field448::SIZE);
	// Выполняем разбор элемента
	math::field448::load(buffer, value);
	// Проверяем приведение к нулю
	ASSERT_TRUE(math::field448::nil(value));
}
