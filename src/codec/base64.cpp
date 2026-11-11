/**
 * @file base64.cpp
 * @date 2026-11-07
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
 * @brief Модуль кодирования основания 64 по RFC 4648
 *
 * @details Кодирование идёт блоками по двенадцать байтов: полные блоки забирает
 *          машинное ядро при его наличии, хвост до одиннадцати байтов и всякое
 *          малое вход - переносимый ход. Разбор строгий, таблицей обратных
 *          номеров знаков, вычисленной при компиляции из алфавита
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Автовекторизация gcc ломает цепочки переносов развёрнутых ядер арифметики (см.
 * math/number.cpp): ключ ставится на весь файл, clang и lcc сюда не входят
 */
#if defined(__GNUC__) && !defined(__clang__) && !defined(__e2k__)
	#pragma GCC optimize("no-tree-vectorize")
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include <codec/base64.hpp>
#include <sys/machine.hpp>
#include <sys/wipe.hpp>
#include <internal/codec/base64.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;

	/**
	 * Подписываемся на пространство имён проекта
	 */
	using namespace nts;

	/**
	 * @brief Знаки основания 64 по разделу 4 RFC 4648
	 *
	 */
	constexpr char ALPHABET[65] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/','\0'};
	/**
	 * @brief Знаки основания 64 URL по разделу 5 RFC 4648
	 *
	 */
	constexpr char WANTED[65] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_','\0'};

	/**
	 * @brief Таблица обратных номеров знаков основания
	 *
	 */
	struct Table {
		// Номера знаков: посторонний знак - 255
		uint8_t items[256];
	};

	/**
	 * @brief Функция построения таблицы обратных номеров знаков при компиляции
	 *
	 * @param alphabet знаки основания
	 * @return        таблица двухсот пятидесяти шести номеров: посторонний знак - 255
	 *
	 */
	constexpr Table reverse(const char (&alphabet)[65]) noexcept {
		// Заполняемая таблица
		Table table = {};
		/**
		 * Выполняем перебор знаков таблицы
		 */
		for(uint32_t i = 0; i < 256; i++)
			// Помечаем всякий знак посторонним
			table.items[i] = 255;
		/**
		 * Выполняем перебор знаков основания
		 */
		for(uint32_t i = 0; i < 64; i++)
			// Запоминаем номер знака основания
			table.items[static_cast <uint8_t> (alphabet[i])] = static_cast <uint8_t> (i);
		// Выводим построенную таблицу
		return table;
	}

	/**
	 * @brief Таблица обратных номеров знаков основания, вычисленная при компиляции
	 *
	 */
	static constexpr Table NUMBERS = reverse(ALPHABET);
	/**
	 * @brief Таблица обратных номеров знаков основания URL, вычисленная при компиляции
	 *
	 */
	static constexpr Table POINTERS = reverse(WANTED);

	/**
	 * @brief Функция проверки того, что знак является пробельным
	 *
	 * @param letter проверяемый знак
	 * @return       признак того, что знак является пробельным
	 *
	 */
	static bool space(const char letter) noexcept {
		// Выводим признак принадлежности знака к пробельным
		return ((letter == ' ') || (letter == '\t') || (letter == '\r') || (letter == '\n') || (letter == '\v') || (letter == '\f'));
	}
/**
 * @brief Функция шага полных блоков кодирования
 *
 * @details Векторное ядро AVX2 кодирует двадцать четыре байта за шаг, прочие
 *          ядра - двенадцать; шаг спрашивается до разбора входа, чтобы запись
 *          завелась точной длиной
 *
 * @return число байтов шага: двадцать четыре либо двенадцать
 *
 */
static size_t stepping() noexcept {
	/**
	 * x86-64 спрашивает команды AVX2 у машины на исполнении
	 */
	#if (defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || defined(__GNUC__)) && !defined(ANTS_NO_MACHINE)
		// Шаг двадцать четыре байта при векторном ядре машины
		return (::nts::machine::has(::nts::machine::feature_t::AVX2) ? 24 : 12);
	/**
	 * Прочие машины шагают двенадцатью байтами
	 */
	#else
		// Выводим шаг переносимого и двенадцатибайтового хода
		return 12;
	#endif
}
/**
 * @brief Функция кодирования очереди полных блоков выбранным ядром
 *
 * @details Векторное ядро AVX2 берёт всю очередь одним вызовом и ведёт блоки
 *          парами вперемежку, прочие ядра кодируют блок за блоком
 *
 * @param step     шаг блока из функции шага
 * @param data     кодируемые байты очереди
 * @param result   место, в которое помещаются знаки очереди
 * @param blocks   число полных блоков очереди
 * @param alphabet алфавит записи
 *
 */
static void dispatchBlocks(const size_t step, const uint8_t * data, uint8_t * result, const size_t blocks, const codec::alphabet_t alphabet) noexcept {
	/**
	 * Шаг двадцать четыре байта достаётся лишь векторному ядру AVX2
	 */
	#if (defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || defined(__GNUC__)) && !defined(ANTS_NO_MACHINE)
		// Векторное ядро несётся при шаге двадцать четыре
		if(step == 24){
			// Кодируем очередь блоков векторным ядром
			encodeBlocks(data, result, blocks, alphabet);
			// Выходим из кодирования очереди
			return;
		}
	#endif
	/**
	 * Выполняем перебор полных блоков: блок кодирует выбранное ядро
	 */
	for(size_t i = 0; i < blocks; i++)
		// Кодируем блок выбранным ядром
		dispatch(data + (step * i), result + (((step * 4) / 3) * i), alphabet);
}
};



/**
 * @brief Метод кодирования основания 64
 *
 * @param data     кодируемые данные
 * @param result   строка, в которую помещается запись
 * @param padding  признак заполнения записи знаками «=» до кратности четырём
 * @param alphabet алфавит записи
 * @return         признак успешности кодирования
 *
 */
bool nts::codec::encode(const view_t & data, string & result, const bool padding, const alphabet_t alphabet) noexcept {
	// Если данные переданы без данных при ненулевой длине
	if((data.data == nullptr) && (data.size != 0))
		// Выводим отказ кодирования
		return false;
	/**
	 * Выполняем перебор попыток кодирования
	 */
	try {
		// Выводим итог служебного кодирования
		return rawEncode(data, result, padding, alphabet);
	}
	/**
	 * Выполняем перехват нехватки памяти
	 */
	catch(const std::bad_alloc &){
		// Затираем недописанную запись
		wipe(result.data(), result.size());
		// Очищаем запись
		result.clear();
		// Выводим отказ кодирования
		return false;
	}
}

/**
 * @brief Служебный метод кодирования основания 64 с пробросом нехватки памяти
 *
 * @param data     кодируемые данные
 * @param result   строка, в которую помещается запись
 * @param padding  признак заполнения записи знаками «=» до кратности четырём
 * @param alphabet алфавит записи
 * @return         признак успешности кодирования
 *
 */
bool nts::codec::rawEncode(const view_t & data, string & result, const bool padding, const alphabet_t alphabet) {
	// Очистка прежней записи
	result.clear();
	// Шаг полных блоков: двадцать четыре байта при векторном ядре AVX2, иначе двенадцать
	const size_t step = stepping();
	// Число полных блоков шага
	const size_t blocks = (data.size / step);
	// Число байтов хвоста
	const size_t rest = (data.size - (step * blocks));
	// Остаётся один либо два байта
	const size_t odd = (rest % 3);
	// Полная длина записи: блоки, тройки и кусок с заполнением либо без
	const size_t total = ((blocks * ((step * 4) / 3)) + ((rest / 3) * 4) + ((odd != 0) ? ((odd + 1) + ((padding) ? (3 - odd) : 0)) : 0));
	// Запись заводится точной длиной: знаки пишутся прямо в неё
	result.resize(total);
	// Кодируем очередь полных блоков выбранным ядром
	dispatchBlocks(step, data.data, reinterpret_cast <uint8_t *> (result.data()), blocks, alphabet);
	// Счётчик знаков записи: знаки полных блоков уже записаны
	size_t written = (blocks * ((step * 4) / 3));
	// Хвост входа до двадцати трёх байтов переносимым ходом
	const uint8_t * tail = data.data + (step * blocks);
		/**
		 * Выполняем перебор полных троек хвоста
		 */
		for(size_t i = 0; i < (rest / 3); i++){
			// Слово из тройки байтов старшим вперёд
			const uint32_t word = ((static_cast <uint32_t> (tail[3 * i]) << 16) | (static_cast <uint32_t> (tail[(3 * i) + 1]) << 8) | tail[(3 * i) + 2]);
			/**
			 * Выполняем перебор знаков тройки
			 */
			for(size_t j = 0; j < 4; j++)
				// Дописываем очередной знак из шести разрядов тройки
				reinterpret_cast <uint8_t *> (result.data())[written++] = kernel::translate(static_cast <uint8_t> ((word >> (18 - (6 * j))) & kernel::SIX), alphabet);
		}
		// Остаётся байты
		if(odd != 0){
			// Слово из куска с нулевым хвостом старшим вперёд
			const uint32_t word = ((static_cast <uint32_t> (tail[rest - odd]) << 16) | ((odd > 1) ? (static_cast <uint32_t> (tail[rest - 1]) << 8) : 0));
			// Число знаков куска: два на байт без одного
			const size_t signs = (odd + 1);
			/**
			 * Выполняем перебор знаков куска
			 */
			for(size_t j = 0; j < signs; j++)
				// Дописываем очередной знак из шести разрядов куска
				reinterpret_cast <uint8_t *> (result.data())[written++] = kernel::translate(static_cast <uint8_t> ((word >> (18 - (6 * j))) & kernel::SIX), alphabet);
			// Заполнение заказано
			if(padding)
				/**
				 * Выполняем добор заполнения знаками «=» до кратности четырём
				 */
				for(size_t j = signs; j < 4; j++)
					// Дописываем знак заполнения
					result.data()[written++] = '=';
		}
		// Счётчик знаков обязан сойтись с полной длиной записи
		if(written != total)
			// Выводим отказ кодирования
			return false;
	// Выводим успешность кодирования
	return true;
}

/**
 * @brief Служебная функция отказа разбора с затиранием накопленных байтов
 *
 * @param result накопленные байты
 * @return       признак отказа разбора
 *
 */
static bool failure(vector <uint8_t> & result) noexcept {
	// Затираем недоразобранные байты
	wipe(result.data(), result.size());
	// Очищаем место
	result.clear();
	// Выводим отказ разбора
	return false;
}

/**
 * @brief Метод разбора записи основания 64
 *
 * @param text     разбираемая запись
 * @param result   место, в которое помещаются разобранные байты
 * @param alphabet алфавит записи
 * @param spaces   признак пропуска пробельных знаков записи
 * @return         признак успешности разбора
 *
 */
bool nts::codec::decode(const view_t & text, vector <uint8_t> & result, const alphabet_t alphabet, const bool spaces, const bool padding) noexcept {
	// Если запись передана без данных при ненулевой длине
	if((text.data == nullptr) && (text.size != 0))
		// Выводим отказ разбора
		return false;
	/**
	 * Выполняем перебор попыток разбора
	 */
	try {
		// Выводим итог служебного разбора
		return rawDecode(text, result, alphabet, spaces, padding);
	}
	/**
	 * Выполняем перехват нехватки памяти
	 */
	catch(const std::bad_alloc &){
		// Затираем недоразобранные байты
		wipe(result.data(), result.size());
		// Очищаем место
		result.clear();
		// Выводим отказ разбора
		return false;
	}
}

/**
 * @brief Служебный метод разбора записи основания 64 с пробросом нехватки памяти
 *
 * @param text     разбираемая запись
 * @param result   место, в которое помещаются разобранные байты
 * @param alphabet алфавит записи
 * @param spaces   признак пропуска пробельных знаков записи
 * @param padding  признак допущения знаков «=» в хвосте записи
 * @return         признак успешности разбора
 *
 */
bool nts::codec::rawDecode(const view_t & text, vector <uint8_t> & result, const alphabet_t alphabet, const bool spaces, const bool padding) {
	// Таблица обратных номеров знаков выбранного алфавита
	const Table & table = ((alphabet == alphabet_t::URL) ? POINTERS : NUMBERS);
	// Очистка прежнего места
	result.clear();
		// Байты по три на всякие четыре знака
		result.reserve(((text.size / 4) + 1) * 3);
		// Накопитель тройки байтов
		uint32_t accumulator = 0;
		// Число знаков в накопителе
		size_t gathered = 0;
		// Число знаков заполнения
		size_t filled = 0;
		/**
		 * Выполняем перебор знаков записи
		 */
		for(size_t i = 0; i < text.size; i++){
			// Очередной знак записи
			const char letter = text.data[i];
			// Знак заполнения при допущенном заполнении
			if((letter == '=') && padding){
				// Считаем знак заполнения
				filled++;
				// Продолжаем перебор
				continue;
			}
			// Пробельный знак при заказанном пропуске
			if(spaces && space(letter))
				// Продолжаем перебор
				continue;
			// Номер знака основания из таблицы
			const uint8_t number = table.items[static_cast <uint8_t> (letter)];
			// Посторонний знак либо знак после заполнения
			if((number == 255) || (filled != 0))
				// Выводим отказ разбора с затиранием накопленного
				return failure(result);
			// Накапливаем шесть разрядов знака
			accumulator = ((accumulator << 6) | number);
			// Четвёрка знаков собрана
			if(++gathered == 4){
				// Выписываем три байта четвёрки
				result.push_back(static_cast <uint8_t> (accumulator >> 16));
				// Второй байт
				result.push_back(static_cast <uint8_t> (accumulator >> 8));
				// Третий байт
				result.push_back(static_cast <uint8_t> (accumulator));
				// Накопитель пуст
				accumulator = 0;
				// Накопленная четвёрка израсходована
				gathered = 0;
			}
		}
		// Остаток знаков: один знак не собирает байта, два либо три собирают
		if(gathered == 1)
			// Выводим отказ разбора с затиранием накопленного
			return failure(result);
		// Заполнение сверх двух знаков либо не дополняющее четвёрку
		if((filled > 2) || ((filled != 0) && ((gathered + filled) != 4)))
			// Выводим отказ разбора с затиранием накопленного
			return failure(result);
		// Ненулевые отброшенные разряды остатка
		if((gathered == 2) && ((accumulator & 15) != 0))
			// Выводим отказ разбора с затиранием накопленного
			return failure(result);
		// Ненулевые отброшенные разряды остатка
		if((gathered == 3) && ((accumulator & 3) != 0))
			// Выводим отказ разбора с затиранием накопленного
			return failure(result);
		// Байты остатка
		if(gathered != 0)
			/**
			 * Число байтов остатка: по три четверти байта на знак без одного
			 */
			for(size_t i = 0; i < (gathered - 1); i++)
				// Выписываем очередной байт остатка от старших разрядов накопителя
				result.push_back(static_cast <uint8_t> ((accumulator >> ((6 * gathered) - (8 * (i + 1)))) & 0xFF));
	// Выводим успешность разбора
	return true;
}
