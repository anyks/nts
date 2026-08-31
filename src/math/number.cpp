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
 * @brief Исходный файл модуля арифметики чисел постоянной разрядности по простому
 *        модулю
 *
 * @note Умножение выполняется приёмом Монтгомери: приведение по модулю сводится к
 *       сдвигу, а деления, время работы которого зависит от значений, здесь нет вовсе
 *
 * @note Все действия выполняются на полном числе слов модуля независимо от значений,
 *       ветвление по значениям заменено наложением маски
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <math/number.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Проверяем наличие целых чисел двойной разрядности
 */
static_assert(sizeof(void *) >= 8, "Арифметика требует машинного слова разрядностью не менее 64");

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::math;

	/**
	 * @brief Целое число двойной разрядности
	 *
	 * @details Собиратели GCC и Clang дают такой тип на всех целевых платформах, а
	 *          иных собирателей у проекта нет
	 *
	 */
	typedef __uint128_t double_t;

	/**
	 * @brief Метод затирания области памяти
	 *
	 * @details Затирание ведётся через изменчивый указатель: обычное присваивание
	 *          собиратель вправе выбросить, увидев, что записанное значение больше
	 *          никем не читается, - и секрет остался бы в памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}
	/**
	 * @brief Метод затирания области памяти словами
	 *
	 * @note Имя у него своё, а не общее с побайтовым затиранием: перегрузка по виду
	 *       указателя молча увела бы к нему всякий вызов, где затирается число, а
	 *       размер подан в байтах
	 *
	 * @param data  затираемая область памяти
	 * @param count число затираемых слов области памяти
	 *
	 * @note Затирание словами дешевле побайтового ровно во столько раз, сколько байтов
	 *       в слове: числа лежат словами, и байтовый перебор здесь ничего не даёт
	 *
	 */
	static void clean(uint64_t * data, const size_t count) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint64_t * item = static_cast <volatile uint64_t *> (data);
		/**
		 * Выполняем перебор слов затираемой области памяти
		 */
		for(size_t i = 0; i < count; i++)
			// Обнуляем очередное слово области памяти
			item[i] = 0;
	}
	/**
	 * @brief Метод умножения Монтгомери для модуля известного числа слов
	 *
	 * @param first   первый сомножитель
	 * @param second  второй сомножитель
	 * @param modulus модуль поля
	 * @param factor  множитель приведения по модулю
	 * @param result  место, в которое помещается произведение
	 *
	 * @return        старшее слово переноса произведения
	 *
	 */
	template <size_t WORDS>
	static uint64_t montgomery(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const uint64_t factor, uint64_t * result) noexcept {
		// Слова накапливаемого произведения
		uint64_t buffer[WORDS + 1] = {};
		/**
		 * Выполняем перебор слов второго сомножителя от младшего к старшему
		 */
		for(size_t i = 0; i < WORDS; i++){
			// Получаем очередное слово второго сомножителя
			const uint64_t word = second[i];
			// Перенос из очередного слова накапливаемого произведения
			uint64_t carry = 0;
			/**
			 * Выполняем умножение первого сомножителя на очередное слово второго
			 */
			for(size_t j = 0; j < WORDS; j++){
				// Складываем накопленное слово с произведением слов и переносом
				const double_t item = (static_cast <double_t> (first[j]) * word + buffer[j] + carry);
				// Записываем младшую половину полученного значения
				buffer[j] = static_cast <uint64_t> (item);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (item >> 64);
			}
			// Складываем старшее слово произведения с переносом
			const double_t item = (static_cast <double_t> (buffer[WORDS]) + carry);
			// Записываем младшую половину полученного значения
			buffer[WORDS] = static_cast <uint64_t> (item);
			// Запоминаем перенос в дополнительное слово произведения
			const uint64_t extra = static_cast <uint64_t> (item >> 64);
			/**
			 * Выработанный множитель обращает младшее слово накопленного произведения
			 * в ноль: тем приведение по модулю и сводится к сдвигу на слово
			 */
			const uint64_t reducer = (buffer[0] * factor);
			// Складываем младшее слово произведения с произведением множителя на модуль
			const double_t value = (static_cast <double_t> (reducer) * modulus[0] + buffer[0]);
			// Запоминаем перенос из младшего слова произведения
			carry = static_cast <uint64_t> (value >> 64);
			/**
			 * Выполняем приведение произведения по модулю со сдвигом на слово
			 */
			for(size_t j = 1; j < WORDS; j++){
				// Складываем накопленное слово с произведением множителя на модуль
				const double_t step = (static_cast <double_t> (reducer) * modulus[j] + buffer[j] + carry);
				// Записываем младшую половину полученного значения со сдвигом на слово
				buffer[j - 1] = static_cast <uint64_t> (step);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (step >> 64);
			}
			// Складываем старшее слово произведения с переносом
			const double_t last = (static_cast <double_t> (buffer[WORDS]) + carry);
			// Записываем младшую половину полученного значения со сдвигом на слово
			buffer[WORDS - 1] = static_cast <uint64_t> (last);
			// Складываем дополнительное слово произведения с переносом
			buffer[WORDS] = static_cast <uint64_t> (extra + (last >> 64));
		}
		/**
		 * Выполняем перебор слов накопленного произведения
		 */
		for(size_t i = 0; i < WORDS; i++)
			// Записываем очередное слово произведения
			result[i] = buffer[i];
		// Выводим старшее слово переноса произведения
		return buffer[WORDS];
	}
	/**
	 * @brief Метод выбора одного из двух слов наложением маски
	 *
	 * @param mask   маска выбора: все разряды единичны либо все нулевые
	 * @param first  слово, выбираемое при единичной маске
	 * @param second слово, выбираемое при нулевой маске
	 *
	 * @return       выбранное слово
	 *
	 */
	static uint64_t select(const uint64_t mask, const uint64_t first, const uint64_t second) noexcept {
		// Выводим выбранное наложением маски слово
		return (second ^ (mask & (first ^ second)));
	}
	/**
	 * @brief Метод сложения наборов слов
	 *
	 * @param first  первое слагаемое
	 * @param second второе слагаемое
	 * @param result место, в которое помещается сумма
	 * @param size   число складываемых слов
	 *
	 * @return       перенос из старшего слова суммы
	 *
	 */
	static uint64_t increase(const uint64_t * first, const uint64_t * second, uint64_t * result, const size_t size) noexcept {
		// Перенос из очередного слова суммы
		uint64_t carry = 0;
		/**
		 * Выполняем перебор складываемых слов от младшего к старшему
		 */
		for(size_t i = 0; i < size; i++){
			// Складываем очередные слова с переносом
			const double_t item = (static_cast <double_t> (first[i]) + second[i] + carry);
			// Записываем младшую половину суммы
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		// Выводим перенос из старшего слова суммы
		return carry;
	}
	/**
	 * @brief Метод вычитания наборов слов
	 *
	 * @param first  уменьшаемое
	 * @param second вычитаемое
	 * @param result место, в которое помещается разность
	 * @param size   число вычитаемых слов
	 *
	 * @return       заём из старшего слова разности
	 *
	 */
	static uint64_t decrease(const uint64_t * first, const uint64_t * second, uint64_t * result, const size_t size) noexcept {
		// Заём в очередное слово разности
		uint64_t borrow = 0;
		/**
		 * Выполняем перебор вычитаемых слов от младшего к старшему
		 */
		for(size_t i = 0; i < size; i++){
			// Вычитаем очередные слова с заёмом
			const double_t item = (static_cast <double_t> (first[i]) - second[i] - borrow);
			// Записываем младшую половину разности
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем заём в следующее слово
			borrow = static_cast <uint64_t> ((item >> 64) & 0x01);
		}
		// Выводим заём из старшего слова разности
		return borrow;
	}
	/**
	 * @brief Метод условного вычитания модуля
	 *
	 * @details Вычитание выполняется всегда, а нужный из двух итогов выбирается
	 *          наложением маски: ветвление по значению выдало бы соотношение
	 *          уменьшаемого и модуля временем работы
	 *
	 * @param value   уменьшаемое, замещаемое итогом вычитания
	 * @param modulus вычитаемый модуль
	 * @param carry   перенос из старшего слова уменьшаемого
	 * @param size    число слов модуля
	 *
	 */
	static void lessen(uint64_t * value, const uint64_t * modulus, const uint64_t carry, const size_t size) noexcept {
		// Итог вычитания модуля из уменьшаемого
		uint64_t buffer[NUMBER_WORDS];
		// Выполняем вычитание модуля из уменьшаемого
		const uint64_t borrow = decrease(value, modulus, buffer, size);
		/**
		 * Модуль вычитается, когда уменьшаемое его не меньше: либо вычитание прошло
		 * без заёма, либо уменьшаемое и без того вышло за разрядность своих слов
		 */
		const uint64_t mask = (0 - (carry | (borrow ^ 0x01)));
		/**
		 * Выполняем перебор слов уменьшаемого
		 */
		for(size_t i = 0; i < size; i++)
			// Выбираем очередное слово итога наложением маски
			value[i] = select(mask, buffer[i], value[i]);
		// Выполняем затирание итога вычитания модуля
		clean(buffer, size);
	}
	/**
	 * @brief Метод сложения чисел по модулю известного числа слов
	 *
	 * @param first   первое слагаемое
	 * @param second  второе слагаемое
	 * @param modulus модуль поля
	 * @param result  место, в которое помещается сумма
	 *
	 * @note Число слов заложено в тело постоянной по той же причине, что и у
	 *       умножения: собиратель разворачивает тогда циклы и держит слова в регистрах
	 *
	 */
	template <size_t WORDS>
	static void addition(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, uint64_t * result) noexcept {
		// Перенос из очередного слова суммы
		uint64_t carry = 0;
		/**
		 * Выполняем перебор складываемых слов от младшего к старшему
		 */
		for(size_t i = 0; i < WORDS; i++){
			// Складываем очередные слова с переносом
			const double_t item = (static_cast <double_t> (first[i]) + second[i] + carry);
			// Записываем младшую половину суммы
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		// Итог вычитания модуля из полученной суммы
		uint64_t buffer[WORDS];
		// Заём из старшего слова разности
		uint64_t borrow = 0;
		/**
		 * Выполняем вычитание модуля из полученной суммы
		 */
		for(size_t i = 0; i < WORDS; i++){
			// Вычитаем очередное слово модуля с заёмом
			const double_t item = (static_cast <double_t> (result[i]) - modulus[i] - borrow);
			// Записываем младшую половину разности
			buffer[i] = static_cast <uint64_t> (item);
			// Запоминаем заём из следующего слова
			borrow = static_cast <uint64_t> ((item >> 64) & 0x01);
		}
		/**
		 * Модуль вычитается, когда сумма его не меньше: либо вычитание прошло без
		 * заёма, либо сумма и без того вышла за разрядность своих слов
		 */
		const uint64_t mask = (0 - (carry | (borrow ^ 0x01)));
		/**
		 * Выполняем перебор слов полученной суммы
		 */
		for(size_t i = 0; i < WORDS; i++)
			// Выбираем очередное слово итога наложением маски
			result[i] = select(mask, buffer[i], result[i]);
		// Выполняем затирание итога вычитания модуля
		clean(buffer, WORDS);
	}
	/**
	 * @brief Метод вычитания чисел по модулю известного числа слов
	 *
	 * @param first   уменьшаемое
	 * @param second  вычитаемое
	 * @param modulus модуль поля
	 * @param result  место, в которое помещается разность
	 *
	 */
	template <size_t WORDS>
	static void subtraction(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, uint64_t * result) noexcept {
		// Заём из очередного слова разности
		uint64_t borrow = 0;
		/**
		 * Выполняем перебор вычитаемых слов от младшего к старшему
		 */
		for(size_t i = 0; i < WORDS; i++){
			// Вычитаем очередные слова с заёмом
			const double_t item = (static_cast <double_t> (first[i]) - second[i] - borrow);
			// Записываем младшую половину разности
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем заём из следующего слова
			borrow = static_cast <uint64_t> ((item >> 64) & 0x01);
		}
		// Сумма разности с модулем, применяемая при заёме из старшего слова
		uint64_t buffer[WORDS];
		// Перенос из очередного слова суммы
		uint64_t carry = 0;
		/**
		 * Выполняем сложение полученной разности с модулем
		 */
		for(size_t i = 0; i < WORDS; i++){
			// Складываем очередные слова с переносом
			const double_t item = (static_cast <double_t> (result[i]) + modulus[i] + carry);
			// Записываем младшую половину суммы
			buffer[i] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		/**
		 * Выполняем перебор слов полученной разности
		 */
		for(size_t i = 0; i < WORDS; i++)
			// Выбираем очередное слово итога наложением маски заёма
			result[i] = select(0 - borrow, buffer[i], result[i]);
		// Выполняем затирание суммы разности с модулем
		clean(buffer, WORDS);
	}
};

/**
 * @brief Конструктор
 *
 */
nts::math::Number::Number() noexcept : words{} {}
/**
 * @brief Метод проверки готовности арифметики к работе
 *
 * @return признак того, что модуль установлен
 *
 */
bool nts::math::Modulus::ready() const noexcept {
	// Выводим признак того, что модуль установлен
	return this->_ready;
}
/**
 * @brief Метод получения размера модуля
 *
 * @return размер модуля в байтах
 *
 */
size_t nts::math::Modulus::size() const noexcept {
	// Выводим размер модуля в байтах
	return this->_size;
}
/**
 * @brief Метод установки модуля
 *
 * @param modulus устанавливаемый модуль, записанный от старшего байта к младшему
 *
 * @return        признак успешности установки модуля
 *
 */
bool nts::math::Modulus::start(const view_t & modulus) noexcept {
	// Выполняем сброс прежде установленного модуля
	this->clear();
	// Если модуль не передан либо не укладывается в разрядность числа
	if((modulus.data == nullptr) || (modulus.size == 0) || (modulus.size > (NUMBER_BITS / 8)))
		// Выводим отказ установки модуля
		return false;
	// Определяем число слов модуля
	this->_words = ((modulus.size + 7) / 8);
	// Запоминаем размер модуля в байтах
	this->_size = modulus.size;
	/**
	 * Выполняем разбор модуля от младшего байта к старшему
	 */
	for(size_t i = 0; i < modulus.size; i++){
		// Извлекаем очередной байт модуля от его конца
		const uint64_t item = modulus.data[modulus.size - i - 1];
		// Записываем очередной байт в своё место внутри слова модуля
		this->_modulus.words[i / 8] |= (item << ((i % 8) * 8));
	}
	// Если модуль оказался чётным либо меньшим трёх
	if(((this->_modulus.words[0] & 0x01) == 0) || ((this->_words == 1) && (this->_modulus.words[0] < 3))){
		// Выполняем сброс установленного модуля
		this->clear();
		// Выводим отказ установки модуля
		return false;
	}
	// Если старшее слово модуля оказалось нулевым
	if(this->_modulus.words[this->_words - 1] == 0){
		// Выполняем сброс установленного модуля
		this->clear();
		// Выводим отказ установки модуля
		return false;
	}
	/**
	 * Выполняем выработку обратного к младшему слову модуля значения приёмом Ньютона:
	 * всякий шаг удваивает число верных разрядов, оттого шести шагов довольно на все
	 * шестьдесят четыре разряда слова
	 */
	uint64_t factor = 1;
	/**
	 * Выполняем уточнение обратного значения
	 */
	for(size_t i = 0; i < 6; i++)
		// Выполняем очередной шаг уточнения обратного значения
		factor *= (2 - (this->_modulus.words[0] * factor));
	// Запоминаем обратное значение со сменой знака
	this->_factor = (0 - factor);
	/**
	 * Выполняем выработку квадрата основания области Монтгомери удвоением единицы:
	 * всякое удвоение сдвигает значение на разряд, а после двух разрядностей модуля
	 * удвоений выходит основание, возведённое в квадрат
	 */
	this->_square.words[0] = 1;
	/**
	 * Выполняем удвоение значения по модулю
	 */
	for(size_t i = 0; i < (this->_words * 128); i++)
		// Выполняем очередное удвоение значения
		this->add(this->_square, this->_square, this->_square);
	// Устанавливаем признак того, что модуль установлен
	this->_ready = true;
	// Выводим успешность установки модуля
	return true;
}
/**
 * @brief Метод сброса установленного модуля
 *
 */
void nts::math::Modulus::clear() noexcept {
	// Выполняем затирание квадрата основания области Монтгомери
	wipe(this->_square.words, sizeof(this->_square.words));
	// Выполняем затирание значения модуля
	wipe(this->_modulus.words, sizeof(this->_modulus.words));
	// Сбрасываем обратное к младшему слову модуля значение
	this->_factor = 0;
	// Сбрасываем размер модуля в байтах
	this->_size = 0;
	// Сбрасываем число слов модуля
	this->_words = 0;
	// Снимаем признак того, что модуль установлен
	this->_ready = false;
}
/**
 * @brief Метод разбора числа из потока байтов
 *
 * @param data   разбираемый поток байтов, записанный от старшего байта к младшему
 * @param result место, в которое помещается разобранное число
 *
 * @return       признак успешности разбора числа
 *
 */
bool nts::math::Modulus::load(const view_t & data, number_t & result) const noexcept {
	// Выполняем обнуление разбираемого числа
	result = number_t();
	// Если модуль не установлен либо поток байтов не передан
	if(!this->_ready || (data.data == nullptr) || (data.size > (this->_words * 8)))
		// Выводим отказ разбора числа
		return false;
	/**
	 * Выполняем разбор числа от младшего байта к старшему
	 */
	for(size_t i = 0; i < data.size; i++){
		// Извлекаем очередной байт числа от его конца
		const uint64_t item = data.data[data.size - i - 1];
		// Записываем очередной байт в своё место внутри слова числа
		result.words[i / 8] |= (item << ((i % 8) * 8));
	}
	// Итог вычитания модуля из разобранного числа
	uint64_t buffer[NUMBER_WORDS];
	// Выполняем вычитание модуля из разобранного числа
	const uint64_t borrow = decrease(result.words, this->_modulus.words, buffer, this->_words);
	// Выполняем затирание итога вычитания модуля
	clean(buffer, this->_words);
	// Если разобранное число оказалось не меньше модуля
	if(borrow == 0){
		// Выполняем обнуление разобранного числа
		result = number_t();
		// Выводим отказ разбора числа
		return false;
	}
	// Выводим успешность разбора числа
	return true;
}
/**
 * @brief Метод приведения потока байтов по модулю
 *
 * @param data   приводимый поток байтов, записанный от старшего байта к младшему
 * @param result место, в которое помещается приведённое число
 *
 * @return       признак успешности приведения потока байтов
 *
 */
bool nts::math::Modulus::reduce(const view_t & data, number_t & result) const noexcept {
	// Выполняем обнуление приводимого числа
	result = number_t();
	// Если модуль не установлен либо поток байтов не передан
	if(!this->_ready || (data.data == nullptr))
		// Выводим отказ приведения потока байтов
		return false;
	/**
	 * Выполняем перебор байтов приводимого потока от старшего к младшему
	 */
	for(size_t i = 0; i < data.size; i++){
		// Очередной байт приводимого потока
		number_t item;
		/**
		 * Выполняем сдвиг накопленного значения на восемь разрядов удвоением: умножение
		 * здесь свелось бы к приведению в область Монтгомери и обратно
		 */
		for(size_t j = 0; j < 8; j++)
			// Выполняем очередное удвоение накопленного значения
			this->add(result, result, result);
		// Записываем очередной байт приводимого потока
		this->word(data.data[i], item);
		// Складываем накопленное значение с очередным байтом потока
		this->add(result, item, result);
	}
	// Выводим успешность приведения потока байтов
	return true;
}
/**
 * @brief Метод записи числа в поток байтов
 *
 * @param value записываемое число
 * @param data  место, в которое записывается число
 * @param size  размер места, в которое записывается число
 *
 * @return      признак успешности записи числа
 *
 */
bool nts::math::Modulus::store(const number_t & value, uint8_t * data, const size_t size) const noexcept {
	// Если модуль не установлен либо место записи не передано
	if(!this->_ready || (data == nullptr) || (size == 0))
		// Выводим отказ записи числа
		return false;
	/**
	 * Выполняем перебор слов записываемого числа от старшего к младшему
	 */
	for(size_t i = size; i > 0; i--){
		// Определяем место очередного байта числа от его конца
		const size_t index = (size - i);
		// Извлекаем очередной байт числа, дополняя нулями за его разрядностью
		data[i - 1] = static_cast <uint8_t> (
			index < (this->_words * 8) ? ((value.words[index / 8] >> ((index % 8) * 8)) & 0xFF) : 0
		);
	}
	// Выводим успешность записи числа
	return true;
}
/**
 * @brief Метод получения числа из машинного слова
 *
 * @param value  значение машинного слова
 * @param result место, в которое помещается полученное число
 *
 */
void nts::math::Modulus::word(const uint64_t value, number_t & result) const noexcept {
	// Выполняем обнуление получаемого числа
	result = number_t();
	// Записываем значение машинного слова в младшее слово числа
	result.words[0] = value;
}
/**
 * @brief Метод проверки числа на равенство нулю
 *
 * @param value проверяемое число
 *
 * @return      признак равенства числа нулю
 *
 */
bool nts::math::Modulus::zero(const number_t & value) const noexcept {
	// Собираемое объединение слов проверяемого числа
	uint64_t item = 0;
	/**
	 * Выполняем перебор слов проверяемого числа
	 */
	for(size_t i = 0; i < this->_words; i++)
		// Собираем объединение слов проверяемого числа
		item |= value.words[i];
	// Выводим признак равенства числа нулю
	return (item == 0);
}
/**
 * @brief Метод сличения двух чисел
 *
 * @param first  первое сличаемое число
 * @param second второе сличаемое число
 *
 * @return       признак равенства сличаемых чисел
 *
 */
bool nts::math::Modulus::equal(const number_t & first, const number_t & second) const noexcept {
	// Собираемое расхождение сличаемых чисел
	uint64_t item = 0;
	/**
	 * Выполняем перебор слов сличаемых чисел
	 */
	for(size_t i = 0; i < this->_words; i++)
		// Собираем расхождение очередных слов сличаемых чисел
		item |= (first.words[i] ^ second.words[i]);
	// Выводим признак равенства сличаемых чисел
	return (item == 0);
}
/**
 * @brief Метод приведения числа в область Монтгомери
 *
 * @param value  приводимое число
 * @param result место, в которое помещается приведённое число
 *
 */
void nts::math::Modulus::enter(const number_t & value, number_t & result) const noexcept {
	// Выполняем умножение числа на квадрат основания области Монтгомери
	this->multiply(value, this->_square, result);
}
/**
 * @brief Метод вывода числа из области Монтгомери
 *
 * @param value  выводимое число
 * @param result место, в которое помещается выведенное число
 *
 */
void nts::math::Modulus::leave(const number_t & value, number_t & result) const noexcept {
	// Единица, на которую умножается выводимое число
	number_t unit;
	// Записываем значение единицы
	unit.words[0] = 1;
	// Выполняем умножение числа на единицу
	this->multiply(value, unit, result);
}
/**
 * @brief Метод сложения чисел по модулю
 *
 * @param first  первое слагаемое
 * @param second второе слагаемое
 * @param result место, в которое помещается сумма
 *
 */
void nts::math::Modulus::add(const number_t & first, const number_t & second, number_t & result) const noexcept {
	// Если модуль поля укладывается в четыре слова
	if(this->_words == 4){
		// Выполняем сложение слагаемых развёрнутым способом
		addition <4> (first.words, second.words, this->_modulus.words, result.words);
		// Выходим из сложения чисел
		return;
	// Если модуль поля укладывается в восемь слов
	} else if(this->_words == 8) {
		// Выполняем сложение слагаемых развёрнутым способом
		addition <8> (first.words, second.words, this->_modulus.words, result.words);
		// Выходим из сложения чисел
		return;
	}
	// Выполняем сложение слагаемых
	const uint64_t carry = increase(first.words, second.words, result.words, this->_words);
	// Выполняем приведение суммы по модулю
	lessen(result.words, this->_modulus.words, carry, this->_words);
}
/**
 * @brief Метод вычитания чисел по модулю
 *
 * @param first  уменьшаемое
 * @param second вычитаемое
 * @param result место, в которое помещается разность
 *
 */
void nts::math::Modulus::subtract(const number_t & first, const number_t & second, number_t & result) const noexcept {
	// Если модуль поля укладывается в четыре слова
	if(this->_words == 4){
		// Выполняем вычитание развёрнутым способом
		subtraction <4> (first.words, second.words, this->_modulus.words, result.words);
		// Выходим из вычитания чисел
		return;
	// Если модуль поля укладывается в восемь слов
	} else if(this->_words == 8) {
		// Выполняем вычитание развёрнутым способом
		subtraction <8> (first.words, second.words, this->_modulus.words, result.words);
		// Выходим из вычитания чисел
		return;
	}
	// Выполняем вычитание вычитаемого из уменьшаемого
	const uint64_t borrow = decrease(first.words, second.words, result.words, this->_words);
	// Сумма разности с модулем, применяемая при заёме из старшего слова
	uint64_t buffer[NUMBER_WORDS];
	// Выполняем сложение разности с модулем
	increase(result.words, this->_modulus.words, buffer, this->_words);
	/**
	 * Выполняем перебор слов разности
	 */
	for(size_t i = 0; i < this->_words; i++)
		// Выбираем очередное слово итога наложением маски заёма
		result.words[i] = select(0 - borrow, buffer[i], result.words[i]);
	// Выполняем затирание суммы разности с модулем
	clean(buffer, this->_words);
}
/**
 * @brief Метод умножения чисел по модулю
 *
 * @param first  первый сомножитель в области Монтгомери
 * @param second второй сомножитель в области Монтгомери
 * @param result место, в которое помещается произведение в области Монтгомери
 *
 */
void nts::math::Modulus::multiply(const number_t & first, const number_t & second, number_t & result) const noexcept {
	/**
	 * Кривые протокола имеют модуль в четыре либо в восемь слов, и оба этих числа
	 * заложены в тело умножения постоянными: собиратель разворачивает тогда циклы и
	 * держит накопитель в регистрах, а не в памяти. Прочие числа слов идут общим путём
	 */
	if((this->_words == 4) || (this->_words == 8)){
		// Старшее слово переноса полученного произведения
		const uint64_t carry = ((this->_words == 4) ?
			montgomery <4> (first.words, second.words, this->_modulus.words, this->_factor, result.words) :
			montgomery <8> (first.words, second.words, this->_modulus.words, this->_factor, result.words)
		);
		// Выполняем приведение произведения по модулю
		lessen(result.words, this->_modulus.words, carry, this->_words);
		// Выходим из умножения чисел
		return;
	}
	// Накапливаемое произведение с двумя дополнительными словами переноса
	uint64_t buffer[NUMBER_WORDS + 2];
	// Число слов накапливаемого произведения, идущих в дело
	const size_t total = (this->_words + 2);
	/**
	 * Обнуляется лишь та часть накопителя, которая идёт в дело: у кривой на 256
	 * разрядов это шесть слов из десяти, и обнуление всех десяти было бы работой,
	 * никому не нужной
	 */
	::memset(buffer, 0, total * sizeof(uint64_t));
	/**
	 * Выполняем перебор слов второго сомножителя от младшего к старшему
	 */
	for(size_t i = 0; i < this->_words; i++){
		// Перенос из очередного слова накапливаемого произведения
		uint64_t carry = 0;
		/**
		 * Выполняем умножение первого сомножителя на очередное слово второго
		 */
		for(size_t j = 0; j < this->_words; j++){
			// Складываем накопленное слово с произведением слов и переносом
			const double_t item = (
				static_cast <double_t> (first.words[j]) * second.words[i] + buffer[j] + carry
			);
			// Записываем младшую половину полученного значения
			buffer[j] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		// Складываем старшее слово произведения с переносом
		const double_t item = (static_cast <double_t> (buffer[this->_words]) + carry);
		// Записываем младшую половину полученного значения
		buffer[this->_words] = static_cast <uint64_t> (item);
		// Записываем перенос в дополнительное слово произведения
		buffer[this->_words + 1] = static_cast <uint64_t> (item >> 64);
		/**
		 * Выработанный множитель обращает младшее слово накопленного произведения в
		 * ноль: тем приведение по модулю и сводится к сдвигу на слово
		 */
		const uint64_t factor = (buffer[0] * this->_factor);
		// Складываем младшее слово произведения с произведением множителя на модуль
		const double_t value = (
			static_cast <double_t> (factor) * this->_modulus.words[0] + buffer[0]
		);
		// Запоминаем перенос из младшего слова произведения
		carry = static_cast <uint64_t> (value >> 64);
		/**
		 * Выполняем приведение накопленного произведения по модулю со сдвигом на слово
		 */
		for(size_t j = 1; j < this->_words; j++){
			// Складываем накопленное слово с произведением множителя на модуль
			const double_t item = (
				static_cast <double_t> (factor) * this->_modulus.words[j] + buffer[j] + carry
			);
			// Записываем младшую половину полученного значения со сдвигом на слово
			buffer[j - 1] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		// Складываем старшее слово произведения с переносом
		const double_t last = (static_cast <double_t> (buffer[this->_words]) + carry);
		// Записываем младшую половину полученного значения со сдвигом на слово
		buffer[this->_words - 1] = static_cast <uint64_t> (last);
		// Складываем дополнительное слово произведения с переносом
		buffer[this->_words] = static_cast <uint64_t> (buffer[this->_words + 1] + (last >> 64));
	}
	/**
	 * Выполняем перебор слов накопленного произведения
	 */
	for(size_t i = 0; i < this->_words; i++)
		// Записываем очередное слово произведения
		result.words[i] = buffer[i];
	// Выполняем приведение произведения по модулю
	lessen(result.words, this->_modulus.words, buffer[this->_words], this->_words);
	// Выполняем затирание накопленного произведения
	clean(buffer, total);
}
/**
 * @brief Метод возведения числа в степень по модулю
 *
 * @param base     основание степени в области Монтгомери
 * @param exponent показатель степени вне области Монтгомери
 * @param result   место, в которое помещается степень в области Монтгомери
 *
 */
void nts::math::Modulus::power(const number_t & base, const number_t & exponent, number_t & result) const noexcept {
	// Накапливаемая степень основания
	number_t value;
	// Произведение накопленной степени на основание
	number_t item;
	// Единица области Монтгомери, с которой начинается накопление степени
	number_t unit;
	// Записываем значение единицы вне области Монтгомери
	unit.words[0] = 1;
	// Выполняем приведение единицы в область Монтгомери
	this->enter(unit, value);
	/**
	 * Выполняем перебор разрядов показателя степени от старшего к младшему
	 */
	for(size_t i = (this->_words * 64); i > 0; i--){
		// Извлекаем очередной разряд показателя степени
		const uint64_t bit = ((exponent.words[(i - 1) / 64] >> ((i - 1) % 64)) & 0x01);
		// Выполняем возведение накопленной степени в квадрат
		this->multiply(value, value, value);
		// Выполняем умножение накопленной степени на основание
		this->multiply(value, base, item);
		/**
		 * Выполняем перебор слов накопленной степени
		 */
		for(size_t j = 0; j < this->_words; j++)
			// Выбираем очередное слово степени наложением маски разряда показателя
			value.words[j] = select(0 - bit, item.words[j], value.words[j]);
	}
	// Записываем накопленную степень
	result = value;
	// Выполняем затирание единицы области Монтгомери
	wipe(unit.words, sizeof(unit.words));
	// Выполняем затирание произведения накопленной степени на основание
	wipe(item.words, sizeof(item.words));
	// Выполняем затирание накопленной степени основания
	wipe(value.words, sizeof(value.words));
}
/**
 * @brief Метод обращения числа по модулю
 *
 * @param value  обращаемое число в области Монтгомери
 * @param result место, в которое помещается обратное число в области Монтгомери
 *
 */
void nts::math::Modulus::invert(const number_t & value, number_t & result) const noexcept {
	// Показатель степени обращения числа
	number_t exponent;
	// Двойка, вычитаемая из модуля
	number_t two;
	// Записываем значение двойки
	two.words[0] = 2;
	// Выполняем вычитание двойки из модуля
	decrease(this->_modulus.words, two.words, exponent.words, this->_words);
	// Выполняем возведение обращаемого числа в полученную степень
	this->power(value, exponent, result);
	// Выполняем затирание показателя степени обращения числа
	wipe(exponent.words, sizeof(exponent.words));
}
/**
 * @brief Конструктор
 *
 */
nts::math::Modulus::Modulus() noexcept : _ready(false), _words(0), _size(0), _factor(0) {}
/**
 * @brief Деструктор
 *
 */
nts::math::Modulus::~Modulus() noexcept {
	// Выполняем сброс установленного модуля
	this->clear();
}
