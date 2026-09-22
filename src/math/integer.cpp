/**
 * @file integer.cpp
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
 * @brief Модуль многоразрядных целых чисел длиной до 4096 разрядов
 *
 * @details Число хранится на 64 словах по 64 разряда от младшего к старшему.
 *          Сложение, вычитание и сравнение ведутся по всем словам за постоянное
 *          время. Умножение школьное, произведение накапливается в накопителе
 *          двойной ёмкости на стеке. Возведение в степень по модулю ведётся
 *          умножением Монтгомери на словах с окном в пять разрядов: при секретном
 *          показателе значение из таблицы окна выбирается перебором всей таблицы
 *          наложением масок. Деление - двоичное столбиком, обращение по модулю -
 *          двоичный расширенный алгоритм Евклида (алгоритм 14.61 «Handbook of
 *          Applied Cryptography»), оба за переменное время
 *
 * @section Намеренные решения
 * 1. Арифметика Монтгомери с предвычислениями вынесена в отдельный класс Montgomery:
 *    множитель приведения, единица области R mod m и квадрат R² mod m считаются один
 *    раз при установке модуля (удвоениями по модулю за постоянное время, 94 мкс на
 *    1024 разрядах и 241 мкс на 2048 на M4), а не на каждом действии. Прежде power,
 *    mulmod и residue считали их всякий раз: секретное действие RSA-2048 тратило на
 *    это половину своих 3,9 мс, а сличение подписи 308 мкс из 308 (круг 28, CONFORMANCE.md).
 *    Методы Integer::power, mulmod и residue оставлены как есть ради прежних вызовов
 *    (проверка простоты, порождение ключей): им предвычисления не мешают.
 * 2. Открытый показатель идёт двоичным методом по значимым разрядам: показателю RSA
 *    в семнадцать разрядов таблица окон в тридцать две степени стоила дороже самого
 *    возведения. Секретный показатель идёт окнами в пять разрядов по всей ширине слов
 *    модуля с выбором из таблицы наложением масок, как и прежде.
 * 3. Обращение за постоянное время - алгоритм Бернстайна и Янга на конечностях по
 *    шестьдесят два разряда, тот же, что у арифметики кривых (math/number.cpp), но с
 *    числом конечностей, задаваемым на исполнении: модули RSA бывают любой ширины, а
 *    шаблон на каждую ширину раздул бы код. Обратимость проверяется умножением на
 *    найденное: у составного модуля алгоритм выдаёт мусор молча. Обращение
 *    ослепляющего числа RSA-1024 стоит 8,8 мкс против 490 у возведения в степень p - 2.
 * 4. Ядро умножения Монтгомери затирает лишь использованные слова накопителя:
 *    затирание всей ёмкости (два килобайта) стоило десятую часть самого умножения на
 *    шестнадцати словах.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <math/integer.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>
#include <math/wide.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

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
	 * Двойное слово для произведений слов
	 */
	// Целое число двойной разрядности: __uint128_t либо своя запись у MSVC (math/wide.hpp)
	typedef nts::math::wide_t wide_t;

	/**
	 * @brief Число слов накопителя двойной ёмкости
	 *
	 */
	static constexpr size_t DOUBLE_WORDS = (INTEGER_WORDS * 2);

	/**
	 * @brief Число слов знакового числа расширенного алгоритма Евклида
	 *
	 * @details Слово запаса: сумма коэффициента с модулем полной ёмкости выходит
	 *          за неё на разряд прежде деления на два
	 *
	 */
	static constexpr size_t SIGNED_WORDS = (INTEGER_WORDS + 1);

	/**
	 * @brief Ширина окна возведения в степень в разрядах
	 *
	 */
	static constexpr size_t WINDOW = 5;

	/**
	 * @brief Число записей таблицы окна возведения в степень
	 *
	 */
	static constexpr size_t TABLE = (1 << WINDOW);

	/**
	 * @brief Верхняя граница малых простых пробного деления
	 *
	 * @details Решето строится на стеке при каждой проверке: простых до этой
	 *          границы 1028, и пробное деление на них отсеивает подавляющую часть
	 *          составных чисел прежде дорогого теста Миллера-Рабина
	 *
	 */
	static constexpr size_t SIEVE = 8192;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
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
	 * @brief Метод получения маски признака «первое слово меньше второго»
	 *
	 * @param first  первое слово
	 * @param second второе слово
	 *
	 * @return       маска: все разряды единичны, если первое слово меньше второго
	 *
	 */
	static uint64_t below(const uint64_t first, const uint64_t second) noexcept {
		// Выводим заём вычитания второго слова из первого, растянутый на всё слово
		return (0 - (((~first & second) | (~(first ^ second) & (first - second))) >> 63));
	}
	/**
	 * @brief Метод получения маски признака нулевого слова
	 *
	 * @param value проверяемое слово
	 *
	 * @return      маска: все разряды единичны, если слово равно нулю
	 *
	 */
	static uint64_t nil(const uint64_t value) noexcept {
		// Выводим признак нуля, растянутый на всё слово
		return (0 - (((value | (0 - value)) >> 63) ^ 1));
	}
	/**
	 * @brief Метод сложения чисел на словах
	 *
	 * @param first  слова первого слагаемого
	 * @param second слова второго слагаемого
	 * @param result место, в которое помещаются слова суммы
	 * @param count  число слов
	 *
	 * @return       перенос из старшего слова
	 *
	 */
	static uint64_t increase(const uint64_t * first, const uint64_t * second, uint64_t * result, const size_t count) noexcept {
		// Перенос из очередного слова
		uint64_t carry = 0;
		/**
		 * Выполняем перебор слов слагаемых от младшего к старшему
		 */
		for(size_t i = 0; i < count; i++){
			// Складываем очередные слова с переносом
			const wide_t item = (static_cast <wide_t> (first[i]) + second[i] + carry);
			// Записываем младшую половину полученного значения
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем перенос в следующее слово
			carry = static_cast <uint64_t> (item >> 64);
		}
		// Выводим перенос из старшего слова
		return carry;
	}
	/**
	 * @brief Метод вычитания чисел на словах
	 *
	 * @param first  слова уменьшаемого
	 * @param second слова вычитаемого
	 * @param result место, в которое помещаются слова разности
	 * @param count  число слов
	 *
	 * @return       заём из старшего слова
	 *
	 */
	static uint64_t decrease(const uint64_t * first, const uint64_t * second, uint64_t * result, const size_t count) noexcept {
		// Заём из очередного слова
		uint64_t borrow = 0;
		/**
		 * Выполняем перебор слов от младшего к старшему
		 */
		for(size_t i = 0; i < count; i++){
			// Вычитаем очередные слова с заёмом
			const wide_t item = (static_cast <wide_t> (first[i]) - second[i] - borrow);
			// Записываем младшую половину полученного значения
			result[i] = static_cast <uint64_t> (item);
			// Запоминаем заём из следующего слова
			borrow = (static_cast <uint64_t> (item >> 64) & 1);
		}
		// Выводим заём из старшего слова
		return borrow;
	}
	/**
	 * @brief Метод копирования слов
	 *
	 * @param source откуда копируются слова
	 * @param target куда копируются слова
	 * @param count  число слов
	 *
	 */
	static void transfer(const uint64_t * source, uint64_t * target, const size_t count) noexcept {
		/**
		 * Выполняем перебор копируемых слов
		 */
		for(size_t i = 0; i < count; i++)
			// Копируем очередное слово
			target[i] = source[i];
	}
	/**
	 * @brief Метод обнуления слов
	 *
	 * @param data  обнуляемые слова
	 * @param count число слов
	 *
	 */
	static void clean(uint64_t * data, const size_t count) noexcept {
		/**
		 * Выполняем перебор обнуляемых слов
		 */
		for(size_t i = 0; i < count; i++)
			// Обнуляем очередное слово
			data[i] = 0;
	}
	/**
	 * @brief Метод получения числа значимых слов
	 *
	 * @param data  слова числа
	 * @param count число слов
	 *
	 * @return      число слов до старшего ненулевого включительно
	 *
	 * @note Время работы переменное: метод зовётся для модулей и делителей
	 *
	 */
	static size_t top(const uint64_t * data, const size_t count) noexcept {
		// Число значимых слов
		size_t result = count;
		/**
		 * Выполняем перебор слов от старшего к младшему
		 */
		while((result > 0) && (data[result - 1] == 0))
			// Отбрасываем нулевое старшее слово
			result--;
		// Выводим число значимых слов
		return result;
	}
	/**
	 * @brief Метод получения числа значимых разрядов
	 *
	 * @param data  слова числа
	 * @param count число слов
	 *
	 * @return      число разрядов до старшего единичного включительно
	 *
	 */
	static size_t width(const uint64_t * data, const size_t count) noexcept {
		// Число значимых слов
		const size_t words = top(data, count);
		// Если число равно нулю
		if(words == 0)
			// Выводим нулевую ширину
			return 0;
		// Старшее значимое слово
		uint64_t word = data[words - 1];
		// Число разрядов старшего слова
		size_t result = 0;
		/**
		 * Выполняем подсчёт разрядов старшего слова
		 */
		while(word != 0){
			// Учитываем очередной разряд
			result++;
			// Сдвигаем слово на разряд
			word >>= 1;
		}
		// Выводим число значимых разрядов
		return (((words - 1) * 64) + result);
	}
	/**
	 * @brief Метод сдвига слов влево на один разряд
	 *
	 * @param data  сдвигаемые слова
	 * @param count число слов
	 * @param low   разряд, вдвигаемый снизу
	 *
	 * @return      разряд, вышедший сверху
	 *
	 */
	static uint64_t shift(uint64_t * data, const size_t count, const uint64_t low) noexcept {
		// Разряд, переходящий в следующее слово
		uint64_t carry = low;
		/**
		 * Выполняем перебор слов от младшего к старшему
		 */
		for(size_t i = 0; i < count; i++){
			// Запоминаем старший разряд очередного слова
			const uint64_t next = (data[i] >> 63);
			// Сдвигаем очередное слово с вдвиганием переходящего разряда
			data[i] = ((data[i] << 1) | carry);
			// Запоминаем разряд для следующего слова
			carry = next;
		}
		// Выводим разряд, вышедший сверху
		return carry;
	}
	/**
	 * @brief Метод сравнения слов за переменное время
	 *
	 * @param first  слова первого числа
	 * @param second слова второго числа
	 * @param count  число слов
	 *
	 * @return       отрицательное значение, если первое меньше, ноль при равенстве, положительное, если больше
	 *
	 */
	static int rank(const uint64_t * first, const uint64_t * second, const size_t count) noexcept {
		/**
		 * Выполняем перебор слов от старшего к младшему
		 */
		for(size_t i = count; i > 0; i--){
			// Если слова различны
			if(first[i - 1] != second[i - 1])
				// Выводим итог сравнения по первому различному слову
				return ((first[i - 1] < second[i - 1]) ? -1 : 1);
		}
		// Выводим признак равенства
		return 0;
	}
	/**
	 * @brief Метод школьного умножения слов
	 *
	 * @param first  слова первого сомножителя
	 * @param count1 число слов первого сомножителя
	 * @param second слова второго сомножителя
	 * @param count2 число слов второго сомножителя
	 * @param result место, в которое помещается произведение: count1 + count2 слов
	 *
	 */
	static void product(const uint64_t * first, const size_t count1, const uint64_t * second, const size_t count2, uint64_t * result) noexcept {
		// Обнуляем слова произведения
		clean(result, count1 + count2);
		/**
		 * Выполняем перебор слов первого сомножителя
		 */
		for(size_t i = 0; i < count1; i++){
			// Перенос из очередного слова
			uint64_t carry = 0;
			/**
			 * Выполняем умножение второго сомножителя на очередное слово первого
			 */
			for(size_t j = 0; j < count2; j++){
				// Складываем накопленное слово с произведением слов и переносом
				const wide_t item = (static_cast <wide_t> (first[i]) * second[j] + result[i + j] + carry);
				// Записываем младшую половину полученного значения
				result[i + j] = static_cast <uint64_t> (item);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (item >> 64);
			}
			// Записываем перенос в старшее слово частичного произведения
			result[i + count2] = carry;
		}
	}
	/**
	 * @brief Метод деления слов столбиком
	 *
	 * @param dividend  слова делимого
	 * @param count     число слов делимого
	 * @param divisor   слова ненулевого делителя
	 * @param words     число значимых слов делителя
	 * @param quotient  место, в которое помещается частное: count слов, либо nullptr
	 * @param remainder место, в которое помещается остаток: words + 1 слов
	 *
	 * @note Деление двоичное: разряды делимого вдвигаются в остаток по одному
	 *       от старшего к младшему; время работы переменное
	 *
	 */
	static void divide(const uint64_t * dividend, const size_t count, const uint64_t * divisor, const size_t words, uint64_t * quotient, uint64_t * remainder) noexcept {
		// Обнуляем остаток
		clean(remainder, words + 1);
		// Если частное нужно
		if(quotient != nullptr)
			// Обнуляем частное
			clean(quotient, count);
		// Слова разности остатка и делителя
		uint64_t buffer[INTEGER_WORDS + 1];
		// Число значимых разрядов делимого
		const size_t bits = width(dividend, count);
		/**
		 * Выполняем перебор разрядов делимого от старшего к младшему
		 */
		for(size_t i = bits; i > 0; i--){
			// Вдвигаем очередной разряд делимого в остаток
			shift(remainder, words + 1, (dividend[(i - 1) / 64] >> ((i - 1) % 64)) & 1);
			// Вычитаем делитель из остатка
			const uint64_t borrow = decrease(remainder, divisor, buffer, words);
			// Вычитаем заём из старшего слова остатка
			buffer[words] = (remainder[words] - borrow);
			// Если остаток не меньше делителя: старшее слово покрывает заём
			if(remainder[words] >= borrow){
				// Записываем разность в остаток
				transfer(buffer, remainder, words + 1);
				// Если частное нужно
				if(quotient != nullptr)
					// Выставляем очередной разряд частного
					quotient[(i - 1) / 64] |= (static_cast <uint64_t> (1) << ((i - 1) % 64));
			}
		}
		// Затираем разность
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Метод проверки наличия разрядов выше заданной границы за постоянное время
	 *
	 * @param data  слова числа
	 * @param count число слов
	 * @param bits  граница: номер первого разряда, который обязан быть нулевым
	 *
	 * @return      ноль, если разрядов выше границы нет, иначе ненулевое значение
	 *
	 * @note Ветвления зависят лишь от границы и номера слова, а не от самого числа:
	 *       так проверка ширины секретного показателя либо сомножителя не выдаёт
	 *       его длину временем работы
	 *
	 */
	static uint64_t beyond(const uint64_t * data, const size_t count, const size_t bits) noexcept {
		// Накопитель разрядов выше границы
		uint64_t result = 0;
		/**
		 * Выполняем перебор слов числа
		 */
		for(size_t i = 0; i < count; i++){
			// Номер младшего разряда слова
			const size_t low = (i * 64);
			// Если слово целиком выше границы
			if(low >= bits)
				// Учитываем слово целиком
				result |= data[i];
			// Если граница проходит внутри слова
			else if((low + 64) > bits)
				// Учитываем разряды слова выше границы
				result |= (data[i] >> (bits - low));
		}
		// Выводим накопитель
		return result;
	}
	/**
	 * @brief Метод одного прохода приведения Монтгомери на словах за постоянное время
	 *
	 * @param buffer  слова приводимого числа с запасом в число слов модуля и ещё одно
	 * @param length  число значимых слов приводимого числа
	 * @param modulus слова нечётного модуля
	 * @param count   число слов модуля
	 * @param inverse множитель приведения по модулю
	 *
	 * @note Число обращается в (число + m·модуль) / R, где R - основание области по
	 *       числу слов модуля: итог меньше числа / R + модуль. Ни ветвления, ни адреса
	 *       обращений от слов числа не зависят
	 *
	 */
	static void descend(uint64_t * buffer, const size_t length, const uint64_t * modulus, const size_t count, const uint64_t inverse) noexcept {
		/**
		 * Выполняем перебор слов модуля: каждый шаг обращает очередное младшее слово в ноль
		 */
		for(size_t i = 0; i < count; i++){
			// Множитель, обращающий очередное слово в ноль
			const uint64_t reducer = (buffer[i] * inverse);
			// Перенос в следующее слово
			uint64_t carry = 0;
			/**
			 * Выполняем сложение произведения множителя на модуль со сдвигом на слово
			 */
			for(size_t j = 0; j < count; j++){
				// Складываем накопленное слово с произведением множителя на слово модуля и переносом
				const wide_t item = (static_cast <wide_t> (reducer) * modulus[j] + buffer[i + j] + carry);
				// Записываем младшую половину полученного значения
				buffer[i + j] = static_cast <uint64_t> (item);
				// Запоминаем перенос
				carry = static_cast <uint64_t> (item >> 64);
			}
			/**
			 * Выполняем проведение переноса по всем старшим словам: число шагов
			 * зависит лишь от длины, а не от значения переноса
			 */
			for(size_t j = (i + count); j <= (length + count); j++){
				// Складываем слово с переносом
				const wide_t item = (static_cast <wide_t> (buffer[j]) + carry);
				// Записываем младшую половину
				buffer[j] = static_cast <uint64_t> (item);
				// Запоминаем перенос
				carry = static_cast <uint64_t> (item >> 64);
			}
		}
		/**
		 * Выполняем сдвиг числа вниз на слова модуля
		 */
		for(size_t j = 0; j <= length; j++)
			// Переносим слово
			buffer[j] = buffer[j + count];
		/**
		 * Выполняем обнуление освободившихся слов
		 */
		for(size_t j = (length + 1); j <= (length + count); j++)
			// Обнуляем слово
			buffer[j] = 0;
	}
	/**
	 * @brief Метод вычисления множителя приведения Монтгомери
	 *
	 * @param word младшее слово нечётного модуля
	 *
	 * @return     обратное к слову значение по модулю 2^64 со сменой знака
	 *
	 */
	static uint64_t factor(const uint64_t word) noexcept {
		// Начальное приближение обратного значения: верно в трёх младших разрядах
		uint64_t result = word;
		/**
		 * Выполняем уточнение обратного значения по Ньютону: каждый шаг удваивает
		 * число верных разрядов, пяти шагов довольно на 64 разряда
		 */
		for(size_t i = 0; i < 5; i++)
			// Уточняем обратное значение
			result *= (2 - (word * result));
		// Выводим обратное значение со сменой знака
		return (0 - result);
	}
	/**
	 * @brief Метод умножения Монтгомери на словах
	 *
	 * @param first   слова первого сомножителя, меньшего модуля
	 * @param second  слова второго сомножителя, меньшего модуля
	 * @param modulus слова нечётного модуля
	 * @param count   число слов модуля
	 * @param inverse множитель приведения по модулю
	 * @param result  место, в которое помещается произведение, меньшее модуля
	 *
	 * @note Умножение с чередованием шагов (CIOS): после каждого слова второго
	 *       сомножителя накопленное произведение приводится сдвигом на слово.
	 *       Итог доводится до значения, меньшего модуля, вычитанием под маской
	 *
	 */
	static void montgomery(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result) noexcept {
		// Слова накапливаемого произведения
		uint64_t buffer[INTEGER_WORDS + 2];
		// Обнуляем накопитель
		clean(buffer, count + 2);
		/**
		 * Выполняем перебор слов второго сомножителя от младшего к старшему
		 */
		for(size_t i = 0; i < count; i++){
			// Получаем очередное слово второго сомножителя
			const uint64_t word = second[i];
			// Перенос из очередного слова накапливаемого произведения
			uint64_t carry = 0;
			/**
			 * Выполняем умножение первого сомножителя на очередное слово второго
			 */
			for(size_t j = 0; j < count; j++){
				// Складываем накопленное слово с произведением слов и переносом
				const wide_t item = (static_cast <wide_t> (first[j]) * word + buffer[j] + carry);
				// Записываем младшую половину полученного значения
				buffer[j] = static_cast <uint64_t> (item);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (item >> 64);
			}
			// Складываем старшее слово произведения с переносом
			const wide_t item = (static_cast <wide_t> (buffer[count]) + carry);
			// Записываем младшую половину полученного значения
			buffer[count] = static_cast <uint64_t> (item);
			// Запоминаем перенос в дополнительное слово произведения
			buffer[count + 1] = static_cast <uint64_t> (item >> 64);
			/**
			 * Выработанный множитель обращает младшее слово накопленного произведения
			 * в ноль: тем приведение по модулю и сводится к сдвигу на слово
			 */
			const uint64_t reducer = (buffer[0] * inverse);
			// Складываем младшее слово произведения с произведением множителя на модуль
			const wide_t value = (static_cast <wide_t> (reducer) * modulus[0] + buffer[0]);
			// Запоминаем перенос из младшего слова произведения
			carry = static_cast <uint64_t> (value >> 64);
			/**
			 * Выполняем приведение произведения по модулю со сдвигом на слово
			 */
			for(size_t j = 1; j < count; j++){
				// Складываем накопленное слово с произведением множителя на модуль
				const wide_t step = (static_cast <wide_t> (reducer) * modulus[j] + buffer[j] + carry);
				// Записываем младшую половину полученного значения со сдвигом на слово
				buffer[j - 1] = static_cast <uint64_t> (step);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (step >> 64);
			}
			// Складываем старшее слово произведения с переносом
			const wide_t last = (static_cast <wide_t> (buffer[count]) + carry);
			// Записываем младшую половину полученного значения со сдвигом на слово
			buffer[count - 1] = static_cast <uint64_t> (last);
			// Складываем дополнительное слово произведения с переносом
			buffer[count] = (buffer[count + 1] + static_cast <uint64_t> (last >> 64));
		}
		// Слова разности произведения и модуля
		uint64_t lessened[INTEGER_WORDS];
		// Вычитаем модуль из накопленного произведения
		const uint64_t borrow = decrease(buffer, modulus, lessened, count);
		// Маска выбора разности: произведение не умещается в слова либо не меньше модуля
		const uint64_t mask = (0 - ((buffer[count] | (borrow ^ 1)) & 1));
		/**
		 * Выполняем перебор слов произведения
		 */
		for(size_t i = 0; i < count; i++)
			// Записываем выбранное слово итога
			result[i] = select(mask, lessened[i], buffer[i]);
		// Затираем использованные слова накопителя: затирание всей ёмкости стоило десятую часть умножения
		wipe(buffer, (count + 2) * sizeof(uint64_t));
		// Затираем использованные слова разности
		wipe(lessened, count * sizeof(uint64_t));
	}
	/**
	 * @brief Метод удвоения числа по модулю за постоянное время
	 *
	 * @param value   слова удваиваемого числа, меньшего модуля
	 * @param modulus слова модуля
	 * @param count   число слов модуля
	 *
	 */
	static void twice(uint64_t * value, const uint64_t * modulus, const size_t count) noexcept {
		// Сдвигаем число на разряд влево
		const uint64_t carry = shift(value, count, 0);
		// Слова разности удвоенного числа и модуля
		uint64_t lessened[INTEGER_WORDS];
		// Вычитаем модуль из удвоенного числа
		const uint64_t borrow = decrease(value, modulus, lessened, count);
		// Маска выбора разности: число вышло за слова либо не меньше модуля
		const uint64_t mask = (0 - ((carry | (borrow ^ 1)) & 1));
		/**
		 * Выполняем перебор слов числа
		 */
		for(size_t i = 0; i < count; i++)
			// Записываем выбранное слово итога
			value[i] = select(mask, lessened[i], value[i]);
		// Затираем разность
		wipe(lessened, sizeof(lessened));
	}
	/**
	 * @brief Метод вычисления основания области Монтгомери и его квадрата по модулю
	 *
	 * @param modulus слова модуля
	 * @param count   число слов модуля
	 * @param base    место, в которое помещается основание области по модулю
	 * @param square  место, в которое помещается квадрат основания по модулю
	 *
	 * @note Оба значения получаются последовательным удвоением единицы: основание
	 *       области - это 2 в степени числа разрядов слов модуля, квадрат - вдвое
	 *       большей; удвоение ведётся за постоянное время
	 *
	 */
	static void domain(const uint64_t * modulus, const size_t count, uint64_t * base, uint64_t * square) noexcept {
		// Обнуляем квадрат основания
		clean(square, count);
		// Записываем единицу, из которой удвоением получаются оба значения
		square[0] = 1;
		/**
		 * Выполняем удвоения: по разряду на каждый из удвоенного числа разрядов слов
		 * модуля; на половине пути значение и есть основание области
		 */
		for(size_t i = 0; i < (count * 128); i++){
			// Если пройдена половина удвоений
			if(i == (count * 64))
				// Запоминаем основание области
				transfer(square, base, count);
			// Удваиваем значение по модулю
			twice(square, modulus, count);
		}
	}
	/**
	 * @brief Метод извлечения окна показателя степени
	 *
	 * @param exponent слова показателя
	 * @param position номер младшего разряда окна
	 * @param bits     ширина окна в разрядах
	 *
	 * @return         значение окна
	 *
	 * @note Место окна открыто: оно определяется номером шага, а не значением
	 *       показателя; секретно лишь само значение окна
	 *
	 */
	static uint64_t window(const uint64_t * exponent, const size_t position, const size_t bits) noexcept {
		// Номер слова младшего разряда окна
		const size_t index = (position / 64);
		// Сдвиг младшего разряда окна внутри слова
		const size_t offset = (position % 64);
		// Извлекаем разряды окна из слова
		uint64_t result = (exponent[index] >> offset);
		// Если окно переходит в следующее слово, и слово есть
		if((offset > 0) && ((index + 1) < INTEGER_WORDS))
			// Дополняем окно разрядами следующего слова
			result |= (exponent[index + 1] << (64 - offset));
		// Выводим значение окна под маской ширины
		return (result & ((static_cast <uint64_t> (1) << bits) - 1));
	}
	/**
	 * @brief Метод получения остатка от деления слов на одно слово
	 *
	 * @param data    слова делимого
	 * @param count   число слов делимого
	 * @param divisor ненулевой делитель
	 *
	 * @return        остаток от деления
	 *
	 */
	static uint64_t modulo(const uint64_t * data, const size_t count, const uint64_t divisor) noexcept {
		// Накапливаемый остаток
		wide_t result = 0;
		/**
		 * Выполняем перебор слов от старшего к младшему
		 */
		for(size_t i = count; i > 0; i--)
			// Вдвигаем очередное слово в остаток и приводим по делителю
			result = (((result << 64) | data[i - 1]) % divisor);
		// Выводим остаток от деления
		return static_cast <uint64_t> (result);
	}
	/**
	 * @brief Знаковое число для расширенного алгоритма Евклида
	 *
	 * @details Величина держится отдельно от знака: коэффициенты алгоритма
	 *          14.61 меняют знак, а слова числа знака не имеют
	 *
	 */
	typedef struct Signed {
		// Признак отрицательного значения
		bool negative;
		// Слова величины числа
		uint64_t words[SIGNED_WORDS];
		/**
		 * @brief Конструктор
		 *
		 */
		Signed() noexcept : negative(false), words{} {}
		/**
		 * @brief Деструктор
		 *
		 */
		~Signed() noexcept {
			// Затираем слова величины числа
			wipe(this->words, sizeof(this->words));
		}
	} signed_t;

	/**
	 * @brief Метод проверки знакового числа на чётность
	 *
	 * @param value проверяемое число
	 *
	 * @return      признак чётности числа
	 *
	 */
	static bool even(const signed_t & value) noexcept {
		// Выводим признак чётности младшего слова
		return ((value.words[0] & 1) == 0);
	}
	/**
	 * @brief Метод вычитания знаковых чисел
	 *
	 * @param first  уменьшаемое
	 * @param second вычитаемое
	 * @param result место, в которое помещается разность
	 *
	 * @note Величины ограничены исходными числами, оттого переполнения нет
	 *
	 */
	static void lessen(const signed_t & first, const signed_t & second, signed_t & result) noexcept {
		// Если знаки чисел различны, величины складываются
		if(first.negative != second.negative){
			// Складываем величины чисел
			increase(first.words, second.words, result.words, SIGNED_WORDS);
			// Знак разности - знак уменьшаемого
			result.negative = first.negative;
		// Если знаки чисел одинаковы, величины вычитаются
		} else {
			// Если величина уменьшаемого не меньше величины вычитаемого
			if(rank(first.words, second.words, SIGNED_WORDS) >= 0){
				// Вычитаем величину вычитаемого из величины уменьшаемого
				decrease(first.words, second.words, result.words, SIGNED_WORDS);
				// Знак разности - знак уменьшаемого
				result.negative = first.negative;
			// Если величина вычитаемого больше
			} else {
				// Вычитаем величину уменьшаемого из величины вычитаемого
				decrease(second.words, first.words, result.words, SIGNED_WORDS);
				// Знак разности противоположен знаку уменьшаемого
				result.negative = !first.negative;
			}
		}
		// Ноль знака не имеет
		if(top(result.words, SIGNED_WORDS) == 0)
			// Снимаем знак с нуля
			result.negative = false;
	}
	/**
	 * @brief Метод деления знакового числа на два с прибавлением слагаемого
	 *
	 * @param value  делимое число
	 * @param addend слова прибавляемой величины либо nullptr
	 * @param minus  признак вычитания величины вместо прибавления
	 *
	 * @note Сумма чётна по устройству алгоритма; перенос из старшего слова
	 *       возвращается в него после сдвига
	 *
	 */
	static void halve(signed_t & value, const uint64_t * addend, const bool minus) noexcept {
		// Перенос из старшего слова суммы
		uint64_t carry = 0;
		// Если слагаемое есть
		if(addend != nullptr){
			// Знаковое слагаемое
			signed_t item;
			// Копируем величину слагаемого
			transfer(addend, item.words, SIGNED_WORDS);
			// Если знак слагаемого совпадает со знаком числа, величины складываются
			if(value.negative == minus)
				// Складываем величины с запоминанием переноса
				carry = increase(value.words, item.words, value.words, SIGNED_WORDS);
			// Если знаки различны, величины вычитаются
			else {
				// Знак слагаемого обращается: вычитание обращённого и есть сложение
				item.negative = !minus;
				// Разность величин
				signed_t result;
				// Вычитаем обращённое слагаемое из числа
				lessen(value, item, result);
				// Записываем разность в число
				transfer(result.words, value.words, SIGNED_WORDS);
				// Записываем знак разности
				value.negative = result.negative;
			}
		}
		/**
		 * Выполняем перебор слов от младшего к старшему
		 */
		for(size_t i = 0; i < SIGNED_WORDS; i++)
			// Сдвигаем очередное слово с вдвиганием младшего разряда следующего
			value.words[i] = ((value.words[i] >> 1) | (((i + 1) < SIGNED_WORDS) ? (value.words[i + 1] << 63) : (carry << 63)));
		// Ноль знака не имеет
		if(top(value.words, SIGNED_WORDS) == 0)
			// Снимаем знак с нуля
			value.negative = false;
	}
	/**
	 * @brief Метод двоичного расширенного алгоритма Евклида
	 *
	 * @param first   первое число
	 * @param second  второе число, не ноль
	 * @param divisor место, в которое помещается наибольший общий делитель, либо nullptr
	 * @param inverse место, в которое помещается коэффициент при первом числе, либо nullptr
	 *
	 * @return        признак успешности: числа не оба чётны и не оба нули
	 *
	 * @note Алгоритм 14.61 «Handbook of Applied Cryptography»: находятся a и b,
	 *       такие что a·x + b·y = gcd(x, y); коэффициент при x и есть обратное
	 *       к x по модулю y, когда делитель равен единице. Ведутся все четыре
	 *       коэффициента: при чётном y отбросить два из них нельзя
	 *
	 */
	static bool euclid(const uint64_t * first, const uint64_t * second, uint64_t * divisor, signed_t * inverse) noexcept {
		// Если оба числа чётны, общий делитель чётен, а обратного нет
		if(((first[0] | second[0]) & 1) == 0)
			// Выводим отказ
			return false;
		// Если второе число равно нулю, деление его на два не остановится
		if(top(second, INTEGER_WORDS) == 0)
			// Выводим отказ
			return false;
		// Слова чисел с запасным словом
		uint64_t x[SIGNED_WORDS] = {}, y[SIGNED_WORDS] = {};
		// Копируем первое число
		transfer(first, x, INTEGER_WORDS);
		// Копируем второе число
		transfer(second, y, INTEGER_WORDS);
		// Текущие величины алгоритма
		signed_t u, v, a, b, c, d;
		// Копируем первое число
		transfer(x, u.words, SIGNED_WORDS);
		// Копируем второе число
		transfer(y, v.words, SIGNED_WORDS);
		// Начальный коэффициент при x у первой величины
		a.words[0] = 1;
		// Начальный коэффициент при y у второй величины
		d.words[0] = 1;
		/**
		 * Выполняем шаги алгоритма, пока первая величина не обратится в ноль
		 */
		while(top(u.words, SIGNED_WORDS) > 0){
			/**
			 * Выполняем деление первой величины на два, пока она чётна
			 */
			while(even(u)){
				// Делим первую величину на два
				halve(u, nullptr, false);
				// Если оба коэффициента чётны
				if(even(a) && even(b)){
					// Делим первый коэффициент на два
					halve(a, nullptr, false);
					// Делим второй коэффициент на два
					halve(b, nullptr, false);
				// Если хотя бы один коэффициент нечётен
				} else {
					// Делим на два первый коэффициент с прибавлением y
					halve(a, y, false);
					// Делим на два второй коэффициент с вычитанием x
					halve(b, x, true);
				}
			}
			/**
			 * Выполняем деление второй величины на два, пока она чётна
			 */
			while(even(v)){
				// Делим вторую величину на два
				halve(v, nullptr, false);
				// Если оба коэффициента чётны
				if(even(c) && even(d)){
					// Делим третий коэффициент на два
					halve(c, nullptr, false);
					// Делим четвёртый коэффициент на два
					halve(d, nullptr, false);
				// Если хотя бы один коэффициент нечётен
				} else {
					// Делим на два третий коэффициент с прибавлением y
					halve(c, y, false);
					// Делим на два четвёртый коэффициент с вычитанием x
					halve(d, x, true);
				}
			}
			// Если первая величина не меньше второй
			if(rank(u.words, v.words, SIGNED_WORDS) >= 0){
				// Вычитаем вторую величину из первой
				decrease(u.words, v.words, u.words, SIGNED_WORDS);
				// Разность коэффициентов
				signed_t item;
				// Вычитаем третий коэффициент из первого
				lessen(a, c, item);
				// Записываем разность в первый коэффициент
				transfer(item.words, a.words, SIGNED_WORDS);
				// Записываем знак разности
				a.negative = item.negative;
				// Вычитаем четвёртый коэффициент из второго
				lessen(b, d, item);
				// Записываем разность во второй коэффициент
				transfer(item.words, b.words, SIGNED_WORDS);
				// Записываем знак разности
				b.negative = item.negative;
			// Если вторая величина больше
			} else {
				// Вычитаем первую величину из второй
				decrease(v.words, u.words, v.words, SIGNED_WORDS);
				// Разность коэффициентов
				signed_t item;
				// Вычитаем первый коэффициент из третьего
				lessen(c, a, item);
				// Записываем разность в третий коэффициент
				transfer(item.words, c.words, SIGNED_WORDS);
				// Записываем знак разности
				c.negative = item.negative;
				// Вычитаем второй коэффициент из четвёртого
				lessen(d, b, item);
				// Записываем разность в четвёртый коэффициент
				transfer(item.words, d.words, SIGNED_WORDS);
				// Записываем знак разности
				d.negative = item.negative;
			}
		}
		// Если делитель нужен
		if(divisor != nullptr)
			// Записываем наибольший общий делитель
			transfer(v.words, divisor, INTEGER_WORDS);
		// Если коэффициент при x нужен
		if(inverse != nullptr){
			// Записываем величину коэффициента
			transfer(c.words, inverse->words, SIGNED_WORDS);
			// Записываем знак коэффициента
			inverse->negative = c.negative;
		}
		// Выполняем затирание копии первого числа
		wipe(x, sizeof(x));
		// Выполняем затирание копии второго числа
		wipe(y, sizeof(y));
		// Выводим признак успешности
		return true;
	}
	/**
	 * @brief Метод получения числа оборотов теста Миллера-Рабина
	 *
	 * @param bits число разрядов проверяемого числа
	 *
	 * @return     число оборотов теста
	 *
	 * @note Таблица B.1 FIPS 186-5 для простых сомножителей ключа RSA: пять
	 *       оборотов на 1024 разряда, четыре на 1536 и 2048. Числа короче
	 *       1024 разрядов ключом не бывают, для них оборотов берётся больше:
	 *       вероятность ошибки одного оборота растёт с укорочением числа
	 *
	 */
	static size_t rounds(const size_t bits) noexcept {
		// Если число не короче 1536 разрядов
		if(bits >= 1536)
			// Выводим четыре оборота
			return 4;
		// Если число не короче 1024 разрядов
		if(bits >= 1024)
			// Выводим пять оборотов
			return 5;
		// Если число не короче 512 разрядов
		if(bits >= 512)
			// Выводим восемь оборотов
			return 8;
		// Выводим шестьдесят четыре оборота для коротких чисел
		return 64;
	}
	/**
	 * @brief Метод сравнения чисел по словам за постоянное время
	 *
	 * @param first  первое число
	 * @param second второе число
	 * @param count  число слов
	 * @return       признак того, что первое число меньше второго
	 *
	 */
	static bool smaller(const uint64_t * first, const uint64_t * second, const size_t count) noexcept {
		// Признаки «меньше» и «исход решён»
		uint64_t less = 0, done = 0;
		/**
		 * Выполняем обход слов от старшего к младшему без ветвлений
		 */
		for(size_t i = count; i > 0; i--){
			// Признаки «слово первого меньше» и «слово второго меньше»
			const uint64_t lower = below(first[i - 1], second[i - 1]);
			const uint64_t upper = below(second[i - 1], first[i - 1]);
			// Запоминаем исход первого расхождения
			less |= (~done & lower);
			// Отмечаем, что исход решён
			done |= (lower | upper);
		}
		// Выводим признак
		return ((less & 1) != 0);
	}
	/**
	 * Обращение по модулю за постоянное время: алгоритм Бернстайна и Янга на конечностях по
	 * шестьдесят два разряда, как у арифметики кривых (math/number.cpp), но с числом
	 * конечностей, задаваемым на исполнении: модули RSA бывают любой ширины. Собиратели
	 * без 128-разрядных чисел со знаком (MSVC) обращают алгоритмом Евклида за переменное время
	 */
	#if !defined(_MSC_VER)
		/**
		 * @brief Знаковое число двойной ёмкости для произведений конечностей
		 *
		 */
		typedef __int128_t twin_t;
		/**
		 * @brief Ширина конечности в разрядах
		 *
		 */
		static constexpr size_t SLICE = 62;
		/**
		 * @brief Маска конечности
		 *
		 */
		static constexpr uint64_t SLICE_MASK = ((static_cast <uint64_t> (1) << SLICE) - 1);
		/**
		 * @brief Наибольшее число конечностей: ширина модуля, знак и запас в конечность
		 *
		 */
		static constexpr size_t SLICES = (((INTEGER_BITS + 64) / SLICE) + 1);
		/**
		 * @brief Метод сокрытия маски от собирателя
		 *
		 * @details Пустая вставка не даёт собирателю обратить наложение маски в ветвление
		 *
		 * @param mask маска
		 * @return     та же маска
		 *
		 */
		static inline int64_t hide(int64_t mask) noexcept {
			__asm__ __volatile__("" : "+r"(mask));
			return mask;
		}
		/**
		 * @brief Матрица перехода пачки шагов деления
		 *
		 */
		typedef struct Transition {
			int64_t u; // Множитель первого числа в первой строке
			int64_t v; // Множитель второго числа в первой строке
			int64_t q; // Множитель первого числа во второй строке
			int64_t r; // Множитель второго числа во второй строке
		} transition_t;
		/**
		 * @brief Метод пачки шагов деления по младшим конечностям
		 *
		 * @param eta    показатель хода
		 * @param first  младшая конечность первого числа
		 * @param second младшая конечность второго числа
		 * @param result место, в которое помещается матрица перехода
		 * @return       показатель хода после пачки
		 *
		 */
		static int64_t divsteps(int64_t eta, const uint64_t first, const uint64_t second, transition_t & result) noexcept {
			// Множители матрицы перехода
			uint64_t u = 1, v = 0, q = 0, r = 1;
			// Младшие конечности чисел
			uint64_t f = first, g = second;
			/**
			 * Выполняем шаги деления без ветвлений
			 */
			for(size_t i = 0; i < SLICE; i++){
				// Маска обмена по знаку показателя хода
				uint64_t swap = static_cast <uint64_t> (hide(eta >> 63));
				// Маска нечётности второго числа
				const uint64_t odd = static_cast <uint64_t> (hide(0 - static_cast <int64_t> (g & 0x01)));
				// Числа со сменой знака под маской обмена
				const uint64_t x = ((f ^ swap) - swap);
				const uint64_t y = ((u ^ swap) - swap);
				const uint64_t z = ((v ^ swap) - swap);
				// Складываем под маской нечётности
				g += (x & odd);
				q += (y & odd);
				r += (z & odd);
				// Обмен идёт лишь при нечётном втором числе
				swap &= odd;
				// Обновляем показатель хода
				eta = static_cast <int64_t> ((static_cast <uint64_t> (eta) ^ swap) - (swap + 1));
				// Выполняем обмен под маской
				f += (g & swap);
				u += (q & swap);
				v += (r & swap);
				// Делим второе число пополам, удваиваем множители первой строки
				g >>= 1;
				u <<= 1;
				v <<= 1;
			}
			// Записываем матрицу перехода
			result.u = static_cast <int64_t> (u);
			result.v = static_cast <int64_t> (v);
			result.q = static_cast <int64_t> (q);
			result.r = static_cast <int64_t> (r);
			// Выводим показатель хода
			return eta;
		}
		/**
		 * @brief Метод применения матрицы перехода к делимым числам
		 *
		 * @param f     первое число на конечностях, заменяется итогом
		 * @param g     второе число на конечностях, заменяется итогом
		 * @param limbs число конечностей
		 * @param t     матрица перехода
		 *
		 */
		static void advance(int64_t * f, int64_t * g, const size_t limbs, const transition_t & t) noexcept {
			// Накопители строк с переносом
			twin_t cf = ((static_cast <twin_t> (t.u) * f[0]) + (static_cast <twin_t> (t.v) * g[0]));
			twin_t cg = ((static_cast <twin_t> (t.q) * f[0]) + (static_cast <twin_t> (t.r) * g[0]));
			// Младшая конечность выбывает: она делится нацело
			cf >>= SLICE;
			cg >>= SLICE;
			/**
			 * Выполняем обход конечностей
			 */
			for(size_t i = 1; i < limbs; i++){
				// Накапливаем очередные конечности
				cf += ((static_cast <twin_t> (t.u) * f[i]) + (static_cast <twin_t> (t.v) * g[i]));
				cg += ((static_cast <twin_t> (t.q) * f[i]) + (static_cast <twin_t> (t.r) * g[i]));
				// Записываем конечности со сдвигом на одну
				f[i - 1] = static_cast <int64_t> (static_cast <uint64_t> (cf) & SLICE_MASK);
				g[i - 1] = static_cast <int64_t> (static_cast <uint64_t> (cg) & SLICE_MASK);
				// Переносим остаток
				cf >>= SLICE;
				cg >>= SLICE;
			}
			// Записываем старшие конечности со знаком
			f[limbs - 1] = static_cast <int64_t> (cf);
			g[limbs - 1] = static_cast <int64_t> (cg);
		}
		/**
		 * @brief Метод применения матрицы перехода к множителям Безу по модулю
		 *
		 * @param d       первый множитель на конечностях, заменяется итогом
		 * @param e       второй множитель на конечностях, заменяется итогом
		 * @param limbs   число конечностей
		 * @param t       матрица перехода
		 * @param modulus модуль на конечностях
		 * @param inverse обратное к младшей конечности модуля по 2^62
		 *
		 */
		static void advance(int64_t * d, int64_t * e, const size_t limbs, const transition_t & t, const int64_t * modulus, const uint64_t inverse) noexcept {
			// Маски знаков множителей
			const int64_t sd = hide(d[limbs - 1] >> 63);
			const int64_t se = hide(e[limbs - 1] >> 63);
			// Поправки на знак
			int64_t md = ((t.u & sd) + (t.v & se));
			int64_t me = ((t.q & sd) + (t.r & se));
			// Накопители строк
			twin_t cd = ((static_cast <twin_t> (t.u) * d[0]) + (static_cast <twin_t> (t.v) * e[0]));
			twin_t ce = ((static_cast <twin_t> (t.q) * d[0]) + (static_cast <twin_t> (t.r) * e[0]));
			// Множители модуля, обращающие младшие конечности в ноль
			md -= static_cast <int64_t> (((inverse * static_cast <uint64_t> (cd)) + static_cast <uint64_t> (md)) & SLICE_MASK);
			me -= static_cast <int64_t> (((inverse * static_cast <uint64_t> (ce)) + static_cast <uint64_t> (me)) & SLICE_MASK);
			// Прибавляем кратные модуля
			cd += (static_cast <twin_t> (modulus[0]) * md);
			ce += (static_cast <twin_t> (modulus[0]) * me);
			// Младшие конечности выбывают
			cd >>= SLICE;
			ce >>= SLICE;
			/**
			 * Выполняем обход конечностей
			 */
			for(size_t i = 1; i < limbs; i++){
				// Накапливаем очередные конечности с кратными модуля
				cd += ((static_cast <twin_t> (t.u) * d[i]) + (static_cast <twin_t> (t.v) * e[i]) + (static_cast <twin_t> (modulus[i]) * md));
				ce += ((static_cast <twin_t> (t.q) * d[i]) + (static_cast <twin_t> (t.r) * e[i]) + (static_cast <twin_t> (modulus[i]) * me));
				// Записываем конечности со сдвигом на одну
				d[i - 1] = static_cast <int64_t> (static_cast <uint64_t> (cd) & SLICE_MASK);
				e[i - 1] = static_cast <int64_t> (static_cast <uint64_t> (ce) & SLICE_MASK);
				// Переносим остаток
				cd >>= SLICE;
				ce >>= SLICE;
			}
			// Записываем старшие конечности со знаком
			d[limbs - 1] = static_cast <int64_t> (cd);
			e[limbs - 1] = static_cast <int64_t> (ce);
		}
		/**
		 * @brief Метод приведения множителя Безу к остатку по модулю
		 *
		 * @param value   множитель на конечностях, заменяется остатком
		 * @param limbs   число конечностей
		 * @param sign    знак первого делимого числа: отрицательный обращает знак итога
		 * @param modulus модуль на конечностях
		 *
		 */
		static void settle(int64_t * value, const size_t limbs, const int64_t sign, const int64_t * modulus) noexcept {
			// Маска отрицательности
			int64_t negative = hide(value[limbs - 1] >> 63);
			/**
			 * Прибавляем модуль под маской отрицательности
			 */
			for(size_t i = 0; i < limbs; i++)
				value[i] += (modulus[i] & negative);
			// Маска смены знака
			const int64_t flip = hide(sign >> 63);
			/**
			 * Меняем знак под маской
			 */
			for(size_t i = 0; i < limbs; i++)
				value[i] = ((value[i] ^ flip) - flip);
			/**
			 * Проносим переносы по конечностям
			 */
			for(size_t i = 0; (i + 1) < limbs; i++){
				value[i + 1] += (value[i] >> SLICE);
				value[i] &= static_cast <int64_t> (SLICE_MASK);
			}
			// Маска отрицательности после смены знака
			negative = hide(value[limbs - 1] >> 63);
			/**
			 * Прибавляем модуль под маской отрицательности
			 */
			for(size_t i = 0; i < limbs; i++)
				value[i] += (modulus[i] & negative);
			/**
			 * Проносим переносы по конечностям
			 */
			for(size_t i = 0; (i + 1) < limbs; i++){
				value[i + 1] += (value[i] >> SLICE);
				value[i] &= static_cast <int64_t> (SLICE_MASK);
			}
		}
		/**
		 * @brief Метод разложения слов числа на конечности
		 *
		 * @param words  слова числа
		 * @param count  число слов
		 * @param result место, в которое помещаются конечности
		 * @param limbs  число конечностей
		 *
		 */
		static void slice(const uint64_t * words, const size_t count, int64_t * result, const size_t limbs) noexcept {
			/**
			 * Выполняем обход конечностей
			 */
			for(size_t i = 0; i < limbs; i++){
				// Разряд, слово и смещение начала конечности
				const size_t bit = (SLICE * i), word = (bit / 64), offset = (bit % 64);
				// Собираем конечность из одного либо двух слов
				uint64_t item = ((word < count) ? (words[word] >> offset) : 0);
				if((offset > (64 - SLICE)) && ((word + 1) < count))
					item |= (words[word + 1] << (64 - offset));
				// Записываем конечность
				result[i] = static_cast <int64_t> (item & SLICE_MASK);
			}
		}
		/**
		 * @brief Метод сборки слов числа из конечностей
		 *
		 * @param value  конечности приведённого числа
		 * @param limbs  число конечностей
		 * @param result место, в которое помещаются слова
		 * @param count  число слов
		 *
		 */
		static void gather(const int64_t * value, const size_t limbs, uint64_t * result, const size_t count) noexcept {
			/**
			 * Обнуляем слова
			 */
			for(size_t i = 0; i < count; i++)
				result[i] = 0;
			/**
			 * Выполняем обход конечностей
			 */
			for(size_t i = 0; i < limbs; i++){
				// Разряд, слово и смещение начала конечности
				const size_t bit = (SLICE * i), word = (bit / 64), offset = (bit % 64);
				// Раскладываем конечность по одному либо двум словам
				if(word < count)
					result[word] |= (static_cast <uint64_t> (value[i]) << offset);
				if((offset > (64 - SLICE)) && ((word + 1) < count))
					result[word + 1] |= (static_cast <uint64_t> (value[i]) >> (64 - offset));
			}
		}
		/**
		 * @brief Метод обращения по нечётному модулю за постоянное время
		 *
		 * @param modulus слова модуля
		 * @param words   число слов модуля
		 * @param factor  множитель приведения Монтгомери младшего слова модуля
		 * @param value   слова обращаемого числа, меньшего модуля
		 * @param result  место, в которое помещаются слова обратного числа
		 *
		 */
		static void safegcd(const uint64_t * modulus, const size_t words, const uint64_t factor, const uint64_t * value, uint64_t * result) noexcept {
			// Число конечностей: ширина модуля, знак и запас в конечность
			const size_t limbs = ((((64 * words) + 64) / SLICE) + 1);
			// Число шагов деления по оценке Бернстайна и Янга и число пачек
			const size_t steps = (((49 * 64 * words) + 57) / 17);
			const size_t batches = ((steps + (SLICE - 1)) / SLICE);
			// Модуль и делимые числа на конечностях
			int64_t m[SLICES], f[SLICES], g[SLICES];
			// Множители Безу на конечностях
			int64_t d[SLICES] = {}, e[SLICES] = {};
			// Раскладываем модуль и число
			slice(modulus, words, m, limbs);
			slice(modulus, words, f, limbs);
			slice(value, words, g, limbs);
			// Второй множитель начинается с единицы
			e[0] = 1;
			// Обратное к младшей конечности модуля по 2^62
			const uint64_t inverse = ((0 - factor) & SLICE_MASK);
			// Показатель хода
			int64_t eta = -1;
			// Матрица перехода
			transition_t t;
			/**
			 * Выполняем пачки шагов деления
			 */
			for(size_t i = 0; i < batches; i++){
				// Считаем матрицу перехода по младшим конечностям
				eta = divsteps(eta, static_cast <uint64_t> (f[0]), static_cast <uint64_t> (g[0]), t);
				// Применяем матрицу к множителям и к делимым
				advance(d, e, limbs, t, m, inverse);
				advance(f, g, limbs, t);
			}
			// Приводим первый множитель к остатку по модулю со знаком первого числа
			settle(d, limbs, f[limbs - 1], m);
			// Собираем слова обратного числа
			gather(d, limbs, result, words);
			// Затираем рабочие числа
			wipe(m, sizeof(m));
			wipe(f, sizeof(f));
			wipe(g, sizeof(g));
			wipe(d, sizeof(d));
			wipe(e, sizeof(e));
			wipe(&t, sizeof(t));
		}
	#endif
};

/**
 * @brief Метод получения слов числа
 *
 * @return слова числа от младшего к старшему
 *
 */
const uint64_t * nts::math::Integer::words() const noexcept {
	// Выводим слова числа
	return this->_words;
}
/**
 * @brief Метод получения числа значимых разрядов
 *
 * @return число разрядов до старшего единичного включительно, ноль у нуля
 *
 */
size_t nts::math::Integer::bits() const noexcept {
	// Выводим число значимых разрядов
	return width(this->_words, INTEGER_WORDS);
}
/**
 * @brief Метод получения размера числа в байтах
 *
 * @return наименьшее число байтов, вмещающее значение, ноль у нуля
 *
 */
size_t nts::math::Integer::size() const noexcept {
	// Выводим число байтов по числу разрядов
	return ((this->bits() + 7) / 8);
}
/**
 * @brief Метод проверки числа на ноль
 *
 * @return признак того, что число равно нулю
 *
 */
bool nts::math::Integer::zero() const noexcept {
	// Объединение всех слов числа
	uint64_t result = 0;
	/**
	 * Выполняем перебор слов числа
	 */
	for(size_t i = 0; i < INTEGER_WORDS; i++)
		// Учитываем очередное слово
		result |= this->_words[i];
	// Выводим признак нуля
	return (result == 0);
}
/**
 * @brief Метод проверки числа на нечётность
 *
 * @return признак того, что число нечётно
 *
 */
bool nts::math::Integer::odd() const noexcept {
	// Выводим младший разряд числа
	return ((this->_words[0] & 1) == 1);
}
/**
 * @brief Метод получения разряда числа
 *
 * @param index номер разряда от младшего
 * @return      значение разряда, ноль за пределами ёмкости
 *
 */
bool nts::math::Integer::bit(const size_t index) const noexcept {
	// Если разряд за пределами ёмкости
	if(index >= INTEGER_BITS)
		// Выводим нулевой разряд
		return false;
	// Выводим значение разряда
	return (((this->_words[index / 64] >> (index % 64)) & 1) == 1);
}
/**
 * @brief Метод сравнения с другим числом
 *
 * @param other число, с которым ведётся сравнение
 * @return      отрицательное значение, если число меньше, ноль при равенстве, положительное, если больше
 *
 */
int nts::math::Integer::compare(const Integer & other) const noexcept {
	// Маски признаков «меньше», «больше» и «различие найдено»
	uint64_t smaller = 0, greater = 0, done = 0;
	/**
	 * Выполняем перебор слов от старшего к младшему
	 */
	for(size_t i = INTEGER_WORDS; i > 0; i--){
		// Маска признака «слово меньше»
		const uint64_t lower = below(this->_words[i - 1], other._words[i - 1]);
		// Маска признака «слово больше»
		const uint64_t upper = below(other._words[i - 1], this->_words[i - 1]);
		// Учитываем признак «меньше», если различие ещё не найдено
		smaller |= (~done & lower);
		// Учитываем признак «больше», если различие ещё не найдено
		greater |= (~done & upper);
		// Учитываем найденное различие
		done |= (lower | upper);
	}
	// Выводим итог сравнения
	return (static_cast <int> (greater & 1) - static_cast <int> (smaller & 1));
}
/**
 * @brief Метод проверки равенства с другим числом
 *
 * @param other число, с которым ведётся сравнение
 * @return      признак равенства чисел
 *
 */
bool nts::math::Integer::equal(const Integer & other) const noexcept {
	// Объединение различий слов
	uint64_t result = 0;
	/**
	 * Выполняем перебор слов чисел
	 */
	for(size_t i = 0; i < INTEGER_WORDS; i++)
		// Учитываем различие очередных слов
		result |= (this->_words[i] ^ other._words[i]);
	// Выводим признак равенства
	return (result == 0);
}
/**
 * @brief Метод обнуления числа
 *
 */
void nts::math::Integer::clear() noexcept {
	// Затираем слова числа
	wipe(this->_words, sizeof(this->_words));
}
/**
 * @brief Метод установки значения из одного слова
 *
 * @param value устанавливаемое значение
 *
 */
void nts::math::Integer::word(const uint64_t value) noexcept {
	// Обнуляем число
	this->clear();
	// Записываем младшее слово
	this->_words[0] = value;
}
/**
 * @brief Метод разбора числа из байтов
 *
 * @param data байты числа от старшего к младшему
 * @return     признак успешности разбора: значение умещается в ёмкость
 *
 */
bool nts::math::Integer::load(const view_t & data) noexcept {
	// Если данных нет вовсе
	if((data.data == nullptr) && (data.size > 0))
		// Выводим отказ
		return false;
	// Число ведущих байтов, не умещающихся в ёмкость
	size_t excess = 0;
	/**
	 * Выполняем подсчёт ведущих байтов сверх ёмкости
	 */
	while(((data.size - excess) > INTEGER_SIZE) && (data.data[excess] == 0))
		// Учитываем ведущий нулевой байт
		excess++;
	// Если значимая часть не умещается в ёмкость
	if((data.size - excess) > INTEGER_SIZE)
		// Выводим отказ
		return false;
	// Обнуляем число
	this->clear();
	/**
	 * Выполняем перебор байтов от младшего к старшему
	 */
	for(size_t i = 0; i < (data.size - excess); i++)
		// Записываем очередной байт в своё слово
		this->_words[i / 8] |= (static_cast <uint64_t> (data.data[data.size - 1 - i]) << ((i % 8) * 8));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод записи числа в байты
 *
 * @param data место, в которое записывается число от старшего байта к младшему
 * @param size размер места в байтах: число дополняется ведущими нулями
 * @return     признак успешности записи: значение умещается в размер
 *
 */
bool nts::math::Integer::store(uint8_t * data, const size_t size) const noexcept {
	// Если места нет
	if((data == nullptr) && (size > 0))
		// Выводим отказ
		return false;
	// Объединение байтов, не умещающихся в размер
	uint8_t excess = 0;
	/**
	 * Выполняем перебор байтов ёмкости от младшего к старшему
	 */
	for(size_t i = 0; i < INTEGER_SIZE; i++){
		// Извлекаем очередной байт числа
		const uint8_t item = static_cast <uint8_t> (this->_words[i / 8] >> ((i % 8) * 8));
		// Если байт умещается в размер
		if(i < size)
			// Записываем очередной байт
			data[size - 1 - i] = item;
		// Если байт не умещается в размер
		else excess |= item;
	}
	/**
	 * Выполняем дополнение ведущими нулями места сверх ёмкости
	 */
	for(size_t i = INTEGER_SIZE; i < size; i++)
		// Записываем ведущий ноль
		data[size - 1 - i] = 0;
	// Выводим признак того, что число уместилось
	return (excess == 0);
}
/**
 * @brief Метод выработки случайного числа
 *
 * @param bits число разрядов вырабатываемого числа
 * @return     признак успешности выработки
 *
 */
bool nts::math::Integer::random(const size_t bits) noexcept {
	// Если число разрядов вне ёмкости
	if((bits == 0) || (bits > INTEGER_BITS))
		// Выводим отказ
		return false;
	// Обнуляем число
	this->clear();
	// Число слов, покрывающих разряды
	const size_t count = ((bits + 63) / 64);
	// Вырабатываем случайные слова
	if(!entropy::bytes(reinterpret_cast <uint8_t *> (this->_words), count * sizeof(uint64_t)))
		// Выводим отказ
		return false;
	// Если старшее слово заполнено не целиком
	if((bits % 64) > 0)
		// Обрезаем старшее слово по числу разрядов
		this->_words[count - 1] &= ((static_cast <uint64_t> (1) << (bits % 64)) - 1);
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод сложения чисел
 *
 * @param first  первое слагаемое
 * @param second второе слагаемое
 * @return       признак успешности: сумма умещается в ёмкость
 *
 */
bool nts::math::Integer::add(const Integer & first, const Integer & second) noexcept {
	// Выводим признак отсутствия переноса
	return (increase(first._words, second._words, this->_words, INTEGER_WORDS) == 0);
}
/**
 * @brief Метод вычитания чисел
 *
 * @param first  уменьшаемое
 * @param second вычитаемое
 * @return       признак успешности: уменьшаемое не меньше вычитаемого
 *
 */
bool nts::math::Integer::subtract(const Integer & first, const Integer & second) noexcept {
	// Выводим признак отсутствия заёма
	return (decrease(first._words, second._words, this->_words, INTEGER_WORDS) == 0);
}
/**
 * @brief Метод умножения чисел
 *
 * @param first  первый сомножитель
 * @param second второй сомножитель
 * @return       признак успешности: произведение умещается в ёмкость
 *
 */
bool nts::math::Integer::multiply(const Integer & first, const Integer & second) noexcept {
	// Накопитель произведения двойной ёмкости
	uint64_t buffer[DOUBLE_WORDS];
	// Вычисляем произведение целиком
	product(first._words, INTEGER_WORDS, second._words, INTEGER_WORDS, buffer);
	// Записываем младшую половину произведения
	transfer(buffer, this->_words, INTEGER_WORDS);
	// Объединение слов старшей половины
	uint64_t excess = 0;
	/**
	 * Выполняем перебор слов старшей половины произведения
	 */
	for(size_t i = INTEGER_WORDS; i < DOUBLE_WORDS; i++)
		// Учитываем очередное слово
		excess |= buffer[i];
	// Затираем накопитель
	wipe(buffer, sizeof(buffer));
	// Выводим признак того, что произведение уместилось
	return (excess == 0);
}
/**
 * @brief Метод сдвига числа влево
 *
 * @param value сдвигаемое число
 * @param count число разрядов сдвига
 *
 */
void nts::math::Integer::left(const Integer & value, const size_t count) noexcept {
	// Слова исходного значения
	uint64_t buffer[INTEGER_WORDS];
	// Копируем исходное значение
	transfer(value._words, buffer, INTEGER_WORDS);
	// Обнуляем число
	this->clear();
	// Сдвиг в словах
	const size_t words = (count / 64);
	// Сдвиг в разрядах внутри слова
	const size_t offset = (count % 64);
	/**
	 * Выполняем перебор слов от старшего к младшему
	 */
	for(size_t i = INTEGER_WORDS; i > words; i--){
		// Записываем сдвинутое слово
		this->_words[i - 1] = (buffer[i - 1 - words] << offset);
		// Если сдвиг внутри слова есть, и младшее слово есть
		if((offset > 0) && ((i - 1 - words) > 0))
			// Дополняем слово разрядами младшего слова
			this->_words[i - 1] |= (buffer[i - 2 - words] >> (64 - offset));
	}
	// Затираем исходное значение
	wipe(buffer, sizeof(buffer));
}
/**
 * @brief Метод сдвига числа вправо
 *
 * @param value сдвигаемое число
 * @param count число разрядов сдвига
 *
 */
void nts::math::Integer::right(const Integer & value, const size_t count) noexcept {
	// Слова исходного значения
	uint64_t buffer[INTEGER_WORDS];
	// Копируем исходное значение
	transfer(value._words, buffer, INTEGER_WORDS);
	// Обнуляем число
	this->clear();
	// Сдвиг в словах
	const size_t words = (count / 64);
	// Сдвиг в разрядах внутри слова
	const size_t offset = (count % 64);
	/**
	 * Выполняем перебор слов от младшего к старшему
	 */
	for(size_t i = 0; (i + words) < INTEGER_WORDS; i++){
		// Записываем сдвинутое слово
		this->_words[i] = (buffer[i + words] >> offset);
		// Если сдвиг внутри слова есть, и старшее слово есть
		if((offset > 0) && ((i + words + 1) < INTEGER_WORDS))
			// Дополняем слово разрядами старшего слова
			this->_words[i] |= (buffer[i + words + 1] << (64 - offset));
	}
	// Затираем исходное значение
	wipe(buffer, sizeof(buffer));
}
/**
 * @brief Метод деления чисел с остатком
 *
 * @param dividend  делимое
 * @param divisor   делитель
 * @param remainder место, в которое помещается остаток, либо nullptr
 * @return          признак успешности: делитель не ноль
 *
 */
bool nts::math::Integer::divide(const Integer & dividend, const Integer & divisor, Integer * remainder) noexcept {
	// Число значимых слов делителя
	const size_t words = top(divisor._words, INTEGER_WORDS);
	// Если делитель равен нулю
	if(words == 0)
		// Выводим отказ
		return false;
	// Слова частного
	uint64_t quotient[INTEGER_WORDS];
	// Слова остатка
	uint64_t buffer[INTEGER_WORDS + 1];
	// Выполняем деление столбиком
	::divide(dividend._words, INTEGER_WORDS, divisor._words, words, quotient, buffer);
	// Записываем частное
	transfer(quotient, this->_words, INTEGER_WORDS);
	// Если остаток нужен
	if(remainder != nullptr){
		// Обнуляем остаток
		remainder->clear();
		// Записываем остаток
		transfer(buffer, remainder->_words, words);
	}
	// Затираем частное
	wipe(quotient, sizeof(quotient));
	// Затираем остаток
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод приведения числа по модулю
 *
 * @param value   приводимое число
 * @param modulus модуль
 * @return        признак успешности: модуль не ноль
 *
 */
bool nts::math::Integer::reduce(const Integer & value, const Integer & modulus) noexcept {
	// Число значимых слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль равен нулю
	if(words == 0)
		// Выводим отказ
		return false;
	// Слова остатка
	uint64_t buffer[INTEGER_WORDS + 1];
	// Выполняем деление столбиком без частного
	::divide(value._words, INTEGER_WORDS, modulus._words, words, nullptr, buffer);
	// Обнуляем число
	this->clear();
	// Записываем остаток
	transfer(buffer, this->_words, words);
	// Затираем остаток
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод приведения числа по нечётному модулю за постоянное время
 *
 * @param value   приводимое число
 * @param modulus нечётный модуль
 * @return        признак успешности: модуль нечётный
 *
 */
bool nts::math::Integer::residue(const Integer & value, const Integer & modulus) noexcept {
	// Число значимых слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль чётный либо пуст
	if((words == 0) || ((modulus._words[0] & 1) == 0))
		// Выводим отказ
		return false;
	/**
	 * Число значимых слов приводимого числа открыто: оно задано ёмкостью величины
	 * (модулем ключа), а не её значением, оттого по нему допустимо считать проходы
	 */
	const size_t counted = top(value._words, INTEGER_WORDS);
	// Длина приводимого числа в словах: не меньше слов модуля, чтобы проход шёл по всем его словам
	const size_t length = ((counted > words) ? counted : words);
	// Число проходов приведения: по одному на каждые слова модуля в длине числа
	const size_t passes = ((length + words - 1) / words);
	// Слова приводимого числа с запасом под перенос и сдвиг
	uint64_t buffer[INTEGER_WORDS + INTEGER_WORDS + 1];
	// Обнуляем накопитель
	clean(buffer, sizeof(buffer) / sizeof(buffer[0]));
	// Переносим приводимое число
	transfer(value._words, buffer, INTEGER_WORDS);
	// Множитель приведения по модулю
	const uint64_t inverse = factor(modulus._words[0]);
	/**
	 * Выполняем проходы приведения: каждый делит число на основание области, после
	 * всех проходов число меньше модуля с единицей
	 */
	for(size_t i = 0; i < passes; i++)
		// Выполняем проход приведения
		descend(buffer, length, modulus._words, words, inverse);
	// Слова разности числа и модуля
	uint64_t lessened[INTEGER_WORDS];
	// Вычитаем модуль из числа
	const uint64_t borrow = decrease(buffer, modulus._words, lessened, words);
	// Маска выбора разности: число не умещается в слова модуля либо не меньше его
	const uint64_t mask = (0 - ((buffer[words] | (borrow ^ 1)) & 1));
	/**
	 * Выполняем перебор слов числа
	 */
	for(size_t i = 0; i < words; i++)
		// Записываем выбранное слово
		buffer[i] = select(mask, lessened[i], buffer[i]);
	// Основание области Монтгомери и его квадрат по модулю
	uint64_t base[INTEGER_WORDS], square[INTEGER_WORDS];
	// Вычисляем основание области и его квадрат
	domain(modulus._words, words, base, square);
	// Множитель возврата: основание области в степени числа проходов с единицей
	uint64_t restorer[INTEGER_WORDS];
	// Начинаем с квадрата основания области
	transfer(square, restorer, words);
	/**
	 * Выполняем доведение множителя до нужной степени: каждое умножение Монтгомери
	 * на квадрат основания поднимает степень на единицу
	 */
	for(size_t i = 1; i < passes; i++)
		// Поднимаем степень множителя
		montgomery(restorer, square, modulus._words, words, inverse, restorer);
	// Итог в отдельное место: модуль вправе совпадать с итогом (алиасинг)
	uint64_t outcome[INTEGER_WORDS];
	// Возвращаем число из области: делённое на основание в степени проходов и умноженное на него же
	montgomery(buffer, restorer, modulus._words, words, inverse, outcome);
	// Сбрасываем итог
	this->clear();
	// Переносим итог
	transfer(outcome, this->_words, words);
	// Затираем итог
	wipe(outcome, sizeof(outcome));
	// Затираем накопитель
	wipe(buffer, sizeof(buffer));
	// Затираем разность
	wipe(lessened, sizeof(lessened));
	// Затираем множитель возврата
	wipe(restorer, sizeof(restorer));
	// Затираем основание области
	wipe(base, sizeof(base));
	// Затираем квадрат основания
	wipe(square, sizeof(square));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод сложения чисел по модулю за постоянное время
 *
 * @param first   первое слагаемое, меньшее модуля
 * @param second  второе слагаемое, меньшее модуля
 * @param modulus модуль
 * @return        признак успешности: слагаемые меньше модуля
 *
 */
bool nts::math::Integer::addmod(const Integer & first, const Integer & second, const Integer & modulus) noexcept {
	// Если слагаемые не меньше модуля
	if((first.compare(modulus) >= 0) || (second.compare(modulus) >= 0))
		// Выводим отказ
		return false;
	// Слова суммы и её разности с модулем
	uint64_t sum[INTEGER_WORDS], lessened[INTEGER_WORDS];
	// Складываем слагаемые
	const uint64_t carry = increase(first._words, second._words, sum, INTEGER_WORDS);
	// Вычитаем модуль из суммы
	const uint64_t borrow = decrease(sum, modulus._words, lessened, INTEGER_WORDS);
	// Маска выбора разности: сумма вышла за ёмкость либо не меньше модуля
	const uint64_t mask = (0 - ((carry | (borrow ^ 1)) & 1));
	/**
	 * Выполняем перебор слов суммы
	 */
	for(size_t i = 0; i < INTEGER_WORDS; i++)
		// Записываем выбранное слово итога
		this->_words[i] = select(mask, lessened[i], sum[i]);
	// Затираем сумму
	wipe(sum, sizeof(sum));
	// Затираем разность
	wipe(lessened, sizeof(lessened));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод вычитания чисел по модулю за постоянное время
 *
 * @param first   уменьшаемое, меньшее модуля
 * @param second  вычитаемое, меньшее модуля
 * @param modulus модуль
 * @return        признак успешности: уменьшаемое и вычитаемое меньше модуля
 *
 */
bool nts::math::Integer::submod(const Integer & first, const Integer & second, const Integer & modulus) noexcept {
	// Если уменьшаемое либо вычитаемое не меньше модуля
	if((first.compare(modulus) >= 0) || (second.compare(modulus) >= 0))
		// Выводим отказ
		return false;
	// Слова разности и её суммы с модулем
	uint64_t difference[INTEGER_WORDS], restored[INTEGER_WORDS];
	// Вычитаем вычитаемое из уменьшаемого
	const uint64_t borrow = decrease(first._words, second._words, difference, INTEGER_WORDS);
	// Прибавляем модуль к разности
	increase(difference, modulus._words, restored, INTEGER_WORDS);
	// Маска выбора суммы: разность отрицательна
	const uint64_t mask = (0 - (borrow & 1));
	/**
	 * Выполняем перебор слов разности
	 */
	for(size_t i = 0; i < INTEGER_WORDS; i++)
		// Записываем выбранное слово итога
		this->_words[i] = select(mask, restored[i], difference[i]);
	// Затираем разность
	wipe(difference, sizeof(difference));
	// Затираем сумму
	wipe(restored, sizeof(restored));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод умножения чисел по модулю
 *
 * @param first   первый сомножитель
 * @param second  второй сомножитель
 * @param modulus модуль
 * @param secret  признак секретных сомножителей
 * @return        признак успешности: модуль не ноль, при секретных сомножителях нечётный и больше их
 *
 */
bool nts::math::Integer::mulmod(const Integer & first, const Integer & second, const Integer & modulus, const bool secret) noexcept {
	// Число значимых слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль равен нулю
	if(words == 0)
		// Выводим отказ
		return false;
	// Если сомножители секретны, умножение ведётся по Монтгомери
	if(secret){
		/**
		 * Умножению Монтгомери довольно, чтобы произведение сомножителей было
		 * меньше произведения модуля на основание области: сомножители, умещающиеся
		 * в слова модуля, этому отвечают и без приведения по модулю; проверка
		 * ширины сомножителей ведётся без ветвления по их словам
		 */
		if(((modulus._words[0] & 1) == 0) || (beyond(first._words, INTEGER_WORDS, words * 64) != 0) || (beyond(second._words, INTEGER_WORDS, words * 64) != 0))
			// Выводим отказ
			return false;
		// Основание области Монтгомери и его квадрат по модулю
		uint64_t base[INTEGER_WORDS], square[INTEGER_WORDS];
		// Вычисляем основание области и его квадрат
		domain(modulus._words, words, base, square);
		// Множитель приведения по модулю
		const uint64_t inverse = factor(modulus._words[0]);
		// Первый сомножитель в области Монтгомери
		uint64_t entered[INTEGER_WORDS];
		// Приводим первый сомножитель в область Монтгомери
		montgomery(first._words, square, modulus._words, words, inverse, entered);
		// Обнуляем число
		// Произведение в отдельное место: второй сомножитель вправе совпадать с итогом (алиасинг)
		uint64_t product[INTEGER_WORDS];
		// Умножаем
		montgomery(entered, second._words, modulus._words, words, inverse, product);
		// Сбрасываем итог
		this->clear();
		// Переносим произведение
		transfer(product, this->_words, words);
		// Затираем произведение
		wipe(product, sizeof(product));
		// Затираем приведённый сомножитель
		wipe(entered, sizeof(entered));
		// Затираем основание области
		wipe(base, sizeof(base));
		// Затираем квадрат основания
		wipe(square, sizeof(square));
	// Если сомножители открыты, произведение делится столбиком
	} else {
		// Накопитель произведения двойной ёмкости
		uint64_t buffer[DOUBLE_WORDS];
		// Вычисляем произведение целиком
		product(first._words, INTEGER_WORDS, second._words, INTEGER_WORDS, buffer);
		// Слова остатка
		uint64_t remainder[INTEGER_WORDS + 1];
		// Выполняем деление столбиком без частного
		::divide(buffer, DOUBLE_WORDS, modulus._words, words, nullptr, remainder);
		// Обнуляем число
		this->clear();
		// Записываем остаток
		transfer(remainder, this->_words, words);
		// Затираем накопитель
		wipe(buffer, sizeof(buffer));
		// Затираем остаток
		wipe(remainder, sizeof(remainder));
	}
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод возведения в степень по модулю
 *
 * @param base     основание, меньшее модуля
 * @param exponent показатель степени
 * @param modulus  нечётный модуль
 * @param secret   признак секретного показателя
 * @return         признак успешности: модуль нечётный, основание меньше модуля
 *
 */
bool nts::math::Integer::power(const Integer & base, const Integer & exponent, const Integer & modulus, const bool secret) noexcept {
	// Число значимых слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль пуст
	if(words == 0)
		// Выводим отказ
		return false;
	// Ширина перебора: у секретного показателя - все разряды слов модуля, у открытого - значимые
	return this->power(base, exponent, modulus, (secret ? (words * 64) : width(exponent._words, INTEGER_WORDS)));
}
/**
 * @brief Метод возведения числа в степень по модулю с заданной шириной перебора показателя
 *
 * @param base     основание
 * @param exponent показатель
 * @param modulus  нечётный модуль
 * @param bits     число разрядов показателя, по которым идёт перебор: не меньше его значимых разрядов
 *
 * @return         признак успешности
 *
 */
bool nts::math::Integer::power(const Integer & base, const Integer & exponent, const Integer & modulus, const size_t bits) noexcept {
	// Число значимых слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль чётный либо основание не меньше модуля
	if((words == 0) || ((modulus._words[0] & 1) == 0) || (base.compare(modulus) >= 0))
		// Выводим отказ
		return false;
	// Если ширина перебора шире самого числа либо не покрывает показатель: проверка без ветвления по разрядам показателя
	if((bits > INTEGER_BITS) || (beyond(exponent._words, INTEGER_WORDS, bits) != 0))
		// Выводим отказ
		return false;
	// Основание области Монтгомери и его квадрат по модулю
	uint64_t unit[INTEGER_WORDS], square[INTEGER_WORDS];
	// Вычисляем основание области и его квадрат
	domain(modulus._words, words, unit, square);
	// Множитель приведения по модулю
	const uint64_t inverse = factor(modulus._words[0]);
	// Таблица степеней основания в области Монтгомери
	uint64_t table[TABLE][INTEGER_WORDS];
	// Единица в области Монтгомери - само основание области
	transfer(unit, table[0], words);
	// Приводим основание степени в область Монтгомери
	montgomery(base._words, square, modulus._words, words, inverse, table[1]);
	/**
	 * Выполняем заполнение таблицы степеней основания
	 */
	for(size_t i = 2; i < TABLE; i++)
		// Вычисляем очередную степень основания
		montgomery(table[i - 1], table[1], modulus._words, words, inverse, table[i]);
	// Число разрядов показателя: вся разрядность слов модуля при секретном показателе
	// Накопитель степени и выбранная запись таблицы
	uint64_t result[INTEGER_WORDS], chosen[INTEGER_WORDS];
	// Начинаем с единицы в области Монтгомери
	transfer(unit, result, words);
	/**
	 * Выполняем перебор окон показателя от старшего к младшему
	 */
	for(size_t i = ((bits + WINDOW - 1) / WINDOW); i > 0; i--){
		// Номер младшего разряда окна
		const size_t position = ((i - 1) * WINDOW);
		// Ширина окна: старшее окно может быть неполным
		const size_t count = (((bits - position) < WINDOW) ? (bits - position) : WINDOW);
		/**
		 * Выполняем возведение накопителя в квадрат по ширине окна
		 */
		for(size_t j = 0; j < count; j++)
			// Возводим накопитель в квадрат
			montgomery(result, result, modulus._words, words, inverse, result);
		// Извлекаем значение окна
		const uint64_t index = window(exponent._words, position, count);
		// Обнуляем выбранную запись
		clean(chosen, words);
		/**
		 * Выполняем перебор всех записей таблицы: запись выбирается наложением
		 * маски, оттого ни ветвления, ни адрес обращения от показателя не зависят
		 */
		for(size_t j = 0; j < TABLE; j++){
			// Маска совпадения номера записи со значением окна
			const uint64_t mask = nil(static_cast <uint64_t> (j) ^ index);
			/**
			 * Выполняем перебор слов записи
			 */
			for(size_t k = 0; k < words; k++)
				// Учитываем слово записи под маской
				chosen[k] |= (table[j][k] & mask);
		}
		// Умножаем накопитель на выбранную запись
		montgomery(result, chosen, modulus._words, words, inverse, result);
	}
	// Единица для вывода из области Монтгомери
	clean(chosen, words);
	// Записываем единицу
	chosen[0] = 1;
	// Обнуляем число
	// Итог в отдельное место: модуль вправе совпадать с итогом (алиасинг)
	uint64_t outcome[INTEGER_WORDS];
	// Выводим из области Монтгомери
	montgomery(result, chosen, modulus._words, words, inverse, outcome);
	// Сбрасываем итог
	this->clear();
	// Переносим итог
	transfer(outcome, this->_words, words);
	// Затираем итог
	wipe(outcome, sizeof(outcome));
	// Затираем таблицу степеней
	wipe(table, sizeof(table));
	// Затираем накопитель
	wipe(result, sizeof(result));
	// Затираем выбранную запись
	wipe(chosen, sizeof(chosen));
	// Затираем основание области
	wipe(unit, sizeof(unit));
	// Затираем квадрат основания
	wipe(square, sizeof(square));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод обращения числа по модулю
 *
 * @param value   обращаемое число
 * @param modulus модуль
 * @return        признак успешности: число и модуль взаимно просты
 *
 */
bool nts::math::Integer::invert(const Integer & value, const Integer & modulus) noexcept {
	// Если модуль не больше единицы
	if(width(modulus._words, INTEGER_WORDS) < 2)
		// Выводим отказ
		return false;
	// Приведённое по модулю значение
	Integer item;
	// Приводим значение по модулю
	item.reduce(value, modulus);
	// Если приведённое значение равно нулю
	if(item.zero())
		// Выводим отказ
		return false;
	// Наибольший общий делитель
	uint64_t divisor[INTEGER_WORDS];
	// Коэффициент при обращаемом значении
	signed_t inverse;
	// Выполняем расширенный алгоритм Евклида
	if(!euclid(item._words, modulus._words, divisor, &inverse)){
		// Затираем делитель
		wipe(divisor, sizeof(divisor));
		// Выводим отказ
		return false;
	}
	// Признак того, что делитель равен единице
	const bool unit = ((divisor[0] == 1) && (top(divisor, INTEGER_WORDS) == 1));
	// Затираем делитель
	wipe(divisor, sizeof(divisor));
	// Если числа не взаимно просты
	if(!unit)
		// Выводим отказ
		return false;
	// Приводим величину коэффициента по модулю
	Integer amount, reduced;
	// Копируем величину коэффициента
	transfer(inverse.words, amount._words, INTEGER_WORDS);
	// Приводим величину по модулю в отдельное место: модуль вправе совпадать с итогом (алиасинг)
	reduced.reduce(amount, modulus);
	// Если коэффициент отрицателен, и величина не ноль
	if(inverse.negative && !reduced.zero())
		// Вычитаем величину из модуля: итог пишется лишь теперь
		this->subtract(modulus, reduced);
	// Иначе переносим приведённую величину
	else transfer(reduced._words, this->_words, INTEGER_WORDS);
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод вычисления наибольшего общего делителя
 *
 * @param first  первое число
 * @param second второе число
 * @return       признак успешности: хотя бы одно из чисел не ноль
 *
 */
bool nts::math::Integer::gcd(const Integer & first, const Integer & second) noexcept {
	// Число двоек, общих обоим числам
	size_t twos = 0;
	// Копии чисел без общих двоек
	Integer x, y;
	// Копируем первое число
	transfer(first._words, x._words, INTEGER_WORDS);
	// Копируем второе число
	transfer(second._words, y._words, INTEGER_WORDS);
	// Если оба числа нули
	if(x.zero() && y.zero())
		// Выводим отказ
		return false;
	/**
	 * Выполняем вынесение общих двоек: алгоритм Евклида требует хотя бы одного
	 * нечётного числа
	 */
	while(!x.odd() && !y.odd()){
		// Делим первое число на два
		x.right(x, 1);
		// Делим второе число на два
		y.right(y, 1);
		// Учитываем вынесенную двойку
		twos++;
	}
	// Слова делителя чисел без общих двоек
	uint64_t divisor[INTEGER_WORDS];
	// Если второе число равно нулю, делитель - первое число
	if(y.zero())
		// Копируем первое число
		transfer(x._words, divisor, INTEGER_WORDS);
	// Если оба числа не нули, выполняем расширенный алгоритм Евклида
	else if(!euclid(x._words, y._words, divisor, nullptr))
		// Выводим отказ
		return false;
	// Копируем делитель
	transfer(divisor, this->_words, INTEGER_WORDS);
	// Возвращаем вынесенные двойки
	this->left(*this, twos);
	// Затираем делитель
	wipe(divisor, sizeof(divisor));
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод проверки числа на простоту
 *
 * @return признак того, что число вероятно простое
 *
 */
bool nts::math::Integer::prime() const noexcept {
	// Число значимых разрядов
	const size_t bits = this->bits();
	// Если число меньше двух
	if(bits < 2)
		// Выводим отказ
		return false;
	// Если число мало, оно проверяется по решету напрямую
	const bool small = (bits <= 13);
	// Значение малого числа
	const uint64_t value = this->_words[0];
	// Решето Эратосфена: признак составного числа
	uint8_t sieve[SIEVE] = {};
	/**
	 * Выполняем построение решета
	 */
	for(size_t i = 2; (i * i) < SIEVE; i++){
		// Если число простое
		if(sieve[i] == 0){
			/**
			 * Выполняем вычёркивание кратных
			 */
			for(size_t j = (i * i); j < SIEVE; j += i)
				// Помечаем кратное составным
				sieve[j] = 1;
		}
	}
	// Если число мало
	if(small && (value < SIEVE))
		// Выводим признак простоты по решету
		return (sieve[value] == 0);
	// Накопленное произведение малых простых
	uint64_t bundle = 1;
	/**
	 * Выполняем пробное деление на малые простые: простые собираются в связки,
	 * умещающиеся в слово, и остаток по связке даёт остатки по каждому из них
	 */
	for(size_t i = 2; i <= SIEVE; i++){
		// Если очередное число простое, и связка вмещает его
		if((i < SIEVE) && (sieve[i] == 0) && ((bundle * i) < (static_cast <uint64_t> (1) << 50))){
			// Вносим простое в связку
			bundle *= i;
			// Продолжаем сбор связки
			continue;
		}
		// Если связка пуста
		if(bundle == 1)
			// Продолжаем перебор
			continue;
		// Остаток числа по связке
		const uint64_t remainder = modulo(this->_words, INTEGER_WORDS, bundle);
		/**
		 * Выполняем перебор простых связки: связка собрана из простых подряд,
		 * оттого её состав восстанавливается делением
		 */
		for(uint64_t item = bundle, j = 2; item > 1; j++){
			// Если простое входит в связку
			if((item % j) == 0){
				// Если число делится на простое
				if((remainder % j) == 0)
					// Выводим отказ: число составное
					return false;
				// Выносим простое из связки
				item /= j;
			}
		}
		// Начинаем новую связку
		bundle = 1;
		// Если очередное число простое, начинаем с него
		if((i < SIEVE) && (sieve[i] == 0))
			// Вносим простое в связку
			bundle = i;
	}
	// Число без единицы
	Integer lessened, one;
	// Записываем единицу
	one.word(1);
	// Вычисляем число без единицы
	lessened.subtract(*this, one);
	// Число двоек в числе без единицы
	size_t twos = 0;
	// Нечётная часть числа без единицы
	Integer part;
	// Копируем число без единицы
	transfer(lessened._words, part._words, INTEGER_WORDS);
	/**
	 * Выполняем вынесение двоек из числа без единицы
	 */
	while(!part.odd()){
		// Делим нечётную часть на два
		part.right(part, 1);
		// Учитываем вынесенную двойку
		twos++;
	}
	// Число без двойки: верхняя граница случайного основания
	Integer bound, two;
	// Записываем двойку
	two.word(2);
	// Вычисляем число без двойки
	bound.subtract(*this, two);
	/**
	 * Выполняем обороты теста Миллера-Рабина
	 */
	for(size_t i = 0; i < rounds(bits); i++){
		// Случайное основание
		Integer witness;
		/**
		 * Выполняем выработку основания в отрезке от двух до числа без двойки
		 */
		do {
			// Вырабатываем случайное число
			if(!witness.random(bits))
				// Выводим отказ
				return false;
		} while((witness.compare(two) < 0) || (witness.compare(bound) > 0));
		// Степень основания
		Integer item;
		// Возводим основание в нечётную часть степени: показатель открыт
		item.power(witness, part, *this, false);
		// Если степень равна единице либо числу без единицы
		if(item.equal(one) || item.equal(lessened))
			// Продолжаем следующим оборотом
			continue;
		// Признак прохождения оборота
		bool passed = false;
		/**
		 * Выполняем возведение степени в квадрат по числу вынесенных двоек
		 */
		for(size_t j = 1; (j < twos) && !passed; j++){
			// Возводим степень в квадрат
			item.mulmod(item, item, *this, false);
			// Если степень равна числу без единицы
			if(item.equal(lessened))
				// Оборот пройден
				passed = true;
			// Если степень равна единице, число составное
			else if(item.equal(one))
				// Выводим отказ
				return false;
		}
		// Если оборот не пройден
		if(!passed)
			// Выводим отказ: число составное
			return false;
	}
	// Выводим признак вероятной простоты
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::math::Integer::Integer() noexcept : _words{} {}
/**
 * @brief Деструктор
 *
 */
nts::math::Integer::~Integer() noexcept {
	// Затираем слова числа
	wipe(this->_words, sizeof(this->_words));
}
/**
 * @brief Метод проверки того, что модуль установлен
 *
 * @return признак установленного модуля
 *
 */
bool nts::math::Montgomery::ready() const noexcept {
	// Выводим признак
	return this->_ready;
}
/**
 * @brief Метод получения числа слов модуля
 *
 * @return число слов модуля до старшего ненулевого включительно
 *
 */
size_t nts::math::Montgomery::words() const noexcept {
	// Выводим число слов
	return this->_words;
}
/**
 * @brief Метод установки модуля
 *
 * @param modulus нечётный модуль
 * @return        признак успешности установки
 *
 */
bool nts::math::Montgomery::start(const Integer & modulus) noexcept {
	// Сбрасываем прежний модуль
	this->clear();
	// Число слов модуля
	const size_t words = top(modulus._words, INTEGER_WORDS);
	// Если модуль нулевой либо чётный
	if((words == 0) || ((modulus._words[0] & 1) == 0))
		// Выходим отказом
		return false;
	// Запоминаем число слов и слова модуля
	this->_words = words;
	transfer(modulus._words, this->_modulus, words);
	// Считаем множитель приведения
	this->_inverse = factor(modulus._words[0]);
	// Считаем единицу области и квадрат R² удвоениями по модулю
	domain(this->_modulus, words, this->_unit, this->_square);
	// Отмечаем модуль установленным
	this->_ready = true;
	// Выходим успехом
	return true;
}
/**
 * @brief Метод сброса модуля с затиранием предвычислений
 *
 */
void nts::math::Montgomery::clear() noexcept {
	// Сбрасываем признак, число слов и множитель
	this->_ready = false;
	this->_words = 0;
	this->_inverse = 0;
	// Затираем слова модуля и предвычисления
	wipe(this->_modulus, sizeof(this->_modulus));
	wipe(this->_unit, sizeof(this->_unit));
	wipe(this->_square, sizeof(this->_square));
}
/**
 * @brief Метод перевода числа в область Монтгомери
 *
 * @param value  число, меньшее модуля
 * @param result место, в которое помещается число в области
 * @return       признак успешности перевода
 *
 */
bool nts::math::Montgomery::enter(const Integer & value, Integer & result) const noexcept {
	// Если модуль не установлен либо число не меньше модуля
	if(!this->_ready || (beyond(value._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(value._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Слова итога
	uint64_t outcome[INTEGER_WORDS];
	// Умножаем число на квадрат R²
	montgomery(value._words, this->_square, this->_modulus, this->_words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, this->_words);
	// Затираем итог
	wipe(outcome, this->_words * sizeof(uint64_t));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод вывода числа из области Монтгомери
 *
 * @param value  число в области, меньшее модуля
 * @param result место, в которое помещается число
 * @return       признак успешности вывода
 *
 */
bool nts::math::Montgomery::leave(const Integer & value, Integer & result) const noexcept {
	// Если модуль не установлен либо число не меньше модуля
	if(!this->_ready || (beyond(value._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(value._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Единица вне области
	uint64_t one[INTEGER_WORDS];
	clean(one, this->_words);
	one[0] = 1;
	// Слова итога
	uint64_t outcome[INTEGER_WORDS];
	// Умножаем число на единицу: множитель R⁻¹ выводит из области
	montgomery(value._words, one, this->_modulus, this->_words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, this->_words);
	// Затираем итог
	wipe(outcome, this->_words * sizeof(uint64_t));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод умножения Монтгомери
 *
 * @param first  первый сомножитель в области, меньший модуля
 * @param second второй сомножитель в области, меньший модуля
 * @param result место, в которое помещается произведение
 * @return       признак успешности умножения
 *
 */
bool nts::math::Montgomery::multiply(const Integer & first, const Integer & second, Integer & result) const noexcept {
	// Если модуль не установлен либо сомножители не меньше модуля
	if(!this->_ready ||
	   (beyond(first._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(first._words, this->_modulus, this->_words) ||
	   (beyond(second._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(second._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Слова итога
	uint64_t outcome[INTEGER_WORDS];
	// Выполняем умножение Монтгомери
	montgomery(first._words, second._words, this->_modulus, this->_words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, this->_words);
	// Затираем итог
	wipe(outcome, this->_words * sizeof(uint64_t));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод умножения по модулю чисел вне области
 *
 * @param first  первый сомножитель, меньший модуля
 * @param second второй сомножитель, меньший модуля
 * @param result место, в которое помещается произведение
 * @return       признак успешности умножения
 *
 */
bool nts::math::Montgomery::mulmod(const Integer & first, const Integer & second, Integer & result) const noexcept {
	// Если модуль не установлен либо сомножители не меньше модуля
	if(!this->_ready ||
	   (beyond(first._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(first._words, this->_modulus, this->_words) ||
	   (beyond(second._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(second._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Первый сомножитель в области и слова итога
	uint64_t entered[INTEGER_WORDS], outcome[INTEGER_WORDS];
	// Переводим первый сомножитель в область
	montgomery(first._words, this->_square, this->_modulus, this->_words, this->_inverse, entered);
	// Умножаем на второй: множитель R сокращается
	montgomery(entered, second._words, this->_modulus, this->_words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, this->_words);
	// Затираем итог и сомножитель в области
	wipe(outcome, this->_words * sizeof(uint64_t));
	wipe(entered, this->_words * sizeof(uint64_t));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод возведения в степень по модулю
 *
 * @param base     основание, меньшее модуля
 * @param exponent показатель
 * @param secret   признак секретного показателя
 * @param result   место, в которое помещается степень
 * @return         признак успешности возведения
 *
 */
bool nts::math::Montgomery::power(const Integer & base, const Integer & exponent, const bool secret, Integer & result) const noexcept {
	// Если модуль не установлен либо основание не меньше модуля
	if(!this->_ready || (beyond(base._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(base._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Число слов модуля
	const size_t words = this->_words;
	// Число разрядов перебора: у секретного показателя вся разрядность слов модуля, у открытого - его значимые разряды
	const size_t bits = (secret ? (words * 64) : width(exponent._words, INTEGER_WORDS));
	// Если секретный показатель не умещается в слова модуля
	if(secret && (beyond(exponent._words, INTEGER_WORDS, bits) != 0))
		// Выходим отказом
		return false;
	// Основание в области и накопитель степени
	uint64_t entered[INTEGER_WORDS], accumulator[INTEGER_WORDS];
	// Переводим основание в область
	montgomery(base._words, this->_square, this->_modulus, words, this->_inverse, entered);
	// Накопитель начинается с единицы области
	transfer(this->_unit, accumulator, words);
	// Если показатель секретный
	if(secret){
		// Таблица степеней окна и выбранное значение
		uint64_t table[TABLE][INTEGER_WORDS], chosen[INTEGER_WORDS];
		// Нулевая степень есть единица области, первая - основание
		transfer(this->_unit, table[0], words);
		transfer(entered, table[1], words);
		/**
		 * Заполняем таблицу степеней
		 */
		for(size_t i = 2; i < TABLE; i++)
			// Считаем очередную степень
			montgomery(table[i - 1], table[1], this->_modulus, words, this->_inverse, table[i]);
		/**
		 * Выполняем перебор окон от старшего к младшему
		 */
		for(size_t i = ((bits + WINDOW - 1) / WINDOW); i > 0; i--){
			// Положение и ширина окна
			const size_t position = ((i - 1) * WINDOW);
			const size_t count = (((bits - position) < WINDOW) ? (bits - position) : WINDOW);
			/**
			 * Возводим накопитель в квадрат по ширине окна
			 */
			for(size_t j = 0; j < count; j++)
				// Выполняем возведение в квадрат
				montgomery(accumulator, accumulator, this->_modulus, words, this->_inverse, accumulator);
			// Значение окна
			const uint64_t index = window(exponent._words, position, count);
			// Обнуляем выбранное значение
			clean(chosen, words);
			/**
			 * Выбираем степень перебором всей таблицы наложением масок
			 */
			for(size_t j = 0; j < TABLE; j++){
				// Маска совпадения номера с окном
				const uint64_t mask = nil(static_cast <uint64_t> (j) ^ index);
				/**
				 * Накапливаем слова под маской
				 */
				for(size_t k = 0; k < words; k++)
					// Накапливаем очередное слово
					chosen[k] |= (table[j][k] & mask);
			}
			// Умножаем накопитель на выбранную степень
			montgomery(accumulator, chosen, this->_modulus, words, this->_inverse, accumulator);
		}
		// Затираем таблицу и выбранное значение
		wipe(table, sizeof(table));
		wipe(chosen, words * sizeof(uint64_t));
	// Если показатель открытый
	} else {
		/**
		 * Выполняем перебор разрядов от старшего к младшему двоичным методом
		 */
		for(size_t i = bits; i > 0; i--){
			// Выполняем возведение в квадрат
			montgomery(accumulator, accumulator, this->_modulus, words, this->_inverse, accumulator);
			// Если разряд показателя единичный
			if(((exponent._words[(i - 1) / 64] >> ((i - 1) % 64)) & 1) != 0)
				// Умножаем накопитель на основание
				montgomery(accumulator, entered, this->_modulus, words, this->_inverse, accumulator);
		}
	}
	// Единица вне области
	uint64_t one[INTEGER_WORDS];
	clean(one, words);
	one[0] = 1;
	// Слова итога
	uint64_t outcome[INTEGER_WORDS];
	// Выводим степень из области
	montgomery(accumulator, one, this->_modulus, words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, words);
	// Затираем рабочие слова
	wipe(outcome, words * sizeof(uint64_t));
	wipe(accumulator, words * sizeof(uint64_t));
	wipe(entered, words * sizeof(uint64_t));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод приведения числа по модулю
 *
 * @param value  приводимое число
 * @param result место, в которое помещается остаток
 * @return       признак успешности приведения
 *
 */
bool nts::math::Montgomery::reduce(const Integer & value, Integer & result) const noexcept {
	// Если модуль не установлен
	if(!this->_ready)
		// Выходим отказом
		return false;
	// Число слов модуля
	const size_t words = this->_words;
	// Число значимых слов числа, длина накопителя и число проходов приведения
	const size_t counted = top(value._words, INTEGER_WORDS);
	const size_t length = ((counted > words) ? counted : words);
	const size_t passes = ((length + words - 1) / words);
	// Накопитель приведения
	uint64_t buffer[INTEGER_WORDS + INTEGER_WORDS + 1];
	// Обнуляем накопитель и переносим число
	clean(buffer, sizeof(buffer) / sizeof(buffer[0]));
	transfer(value._words, buffer, INTEGER_WORDS);
	/**
	 * Выполняем проходы приведения по слову: каждый делит на R по модулю
	 */
	for(size_t i = 0; i < passes; i++)
		// Выполняем очередной проход
		descend(buffer, length, this->_modulus, words, this->_inverse);
	// Слова разности с модулем
	uint64_t lessened[INTEGER_WORDS];
	// Вычитаем модуль из накопителя
	const uint64_t borrow = decrease(buffer, this->_modulus, lessened, words);
	// Маска выбора разности: накопитель не умещается в слова либо не меньше модуля
	const uint64_t mask = (0 - ((buffer[words] | (borrow ^ 1)) & 1));
	/**
	 * Записываем выбранные слова
	 */
	for(size_t i = 0; i < words; i++)
		// Записываем очередное слово
		buffer[i] = select(mask, lessened[i], buffer[i]);
	// Множитель возврата: степень R по числу проходов и одна сверх на умножение
	uint64_t restorer[INTEGER_WORDS];
	transfer(this->_square, restorer, words);
	/**
	 * Возводим множитель возврата в нужную степень R
	 */
	for(size_t i = 1; i < passes; i++)
		// Умножаем на квадрат R²
		montgomery(restorer, this->_square, this->_modulus, words, this->_inverse, restorer);
	// Слова итога
	uint64_t outcome[INTEGER_WORDS];
	// Возвращаем множитель R за проходы
	montgomery(buffer, restorer, this->_modulus, words, this->_inverse, outcome);
	// Записываем итог
	result.clear();
	transfer(outcome, result._words, words);
	// Затираем рабочие слова
	wipe(outcome, words * sizeof(uint64_t));
	wipe(restorer, words * sizeof(uint64_t));
	wipe(lessened, words * sizeof(uint64_t));
	wipe(buffer, sizeof(buffer));
	// Выходим успехом
	return true;
}
/**
 * @brief Метод обращения числа по модулю за постоянное время
 *
 * @param value  обращаемое число, меньшее модуля
 * @param result место, в которое помещается обратное число вне области
 * @return       признак успешности обращения
 *
 */
bool nts::math::Montgomery::invert(const Integer & value, Integer & result) const noexcept {
	// Если модуль не установлен либо число не меньше модуля
	if(!this->_ready || (beyond(value._words, INTEGER_WORDS, this->_words * 64) != 0) || !smaller(value._words, this->_modulus, this->_words))
		// Выходим отказом
		return false;
	// Число слов модуля
	const size_t words = this->_words;
	// Слова обратного числа
	uint64_t inverse[INTEGER_WORDS];
	/**
	 * Собиратели с 128-разрядными числами со знаком обращают за постоянное время
	 */
	#if !defined(_MSC_VER)
		// Выполняем обращение алгоритмом Бернстайна и Янга
		safegcd(this->_modulus, words, this->_inverse, value._words, inverse);
	/**
	 * Иные собиратели обращают алгоритмом Евклида за переменное время
	 */
	#else
		// Модуль числом и обратное число
		Integer modulus, found;
		transfer(this->_modulus, modulus._words, words);
		// Выполняем обращение
		if(!found.invert(value, modulus))
			// Выходим отказом
			return false;
		// Переносим слова обратного числа
		transfer(found._words, inverse, words);
	#endif
	// Число в области и произведение проверки
	uint64_t entered[INTEGER_WORDS], product[INTEGER_WORDS];
	// Переводим число в область и умножаем на найденное обратное
	montgomery(value._words, this->_square, this->_modulus, words, this->_inverse, entered);
	montgomery(entered, inverse, this->_modulus, words, this->_inverse, product);
	// Накопитель расхождения произведения с единицей
	uint64_t difference = (product[0] ^ 1);
	/**
	 * Накапливаем расхождение по всем словам
	 */
	for(size_t i = 1; i < words; i++)
		// Накапливаем очередное слово
		difference |= product[i];
	// Маска обратимости: единица подтверждает обратное число
	const uint64_t mask = nil(difference);
	// Записываем итог под маской обратимости
	result.clear();
	/**
	 * Записываем слова обратного числа под маской
	 */
	for(size_t i = 0; i < words; i++)
		// Записываем очередное слово
		result._words[i] = (inverse[i] & mask);
	// Затираем рабочие слова
	wipe(inverse, words * sizeof(uint64_t));
	wipe(entered, words * sizeof(uint64_t));
	wipe(product, words * sizeof(uint64_t));
	// Выводим признак обратимости
	return ((mask & 1) != 0);
}
/**
 * @brief Конструктор
 *
 */
nts::math::Montgomery::Montgomery() noexcept : _ready(false), _words(0), _inverse(0), _modulus{}, _unit{}, _square{} {}
/**
 * @brief Деструктор
 *
 */
nts::math::Montgomery::~Montgomery() noexcept {
	// Затираем модуль и предвычисления
	this->clear();
}
