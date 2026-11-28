/**
 * @file ripemd.cpp
 * @date 2026-10-10
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
 * @brief Модуль хеш-функции RIPEMD-160
 *
 * @details Блок сообщения в 64 байта проходит восемьдесят шагов в двух параллельных
 *          потоках (левом и правом) над пятью рабочими словами каждый: потоки различаются
 *          функциями кругов, константами, порядком слов сообщения и величинами сдвигов.
 *          Итоги потоков сходятся в значение хеша перекрёстным сложением. Сообщение
 *          дополняется байтом 0x80 и длиной в разрядах от младшего байта
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартный заголовочный файл
 */
#include <utility>

/**
 * Подключаем заголовочный файл проекта
 */
#include "sys/wipe.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "digest/ripemd.hpp"

/**
 * @brief Служебные объекты модуля
 *
 * @note Проход ведётся развёрткой восьмидесяти шагов по номеру шага в шаблоне, а не циклом:
 *       номер шага в шаблоне превращает номер круга, порядок слова сообщения и величину
 *       сдвига в непосредственные операнды, отчего функция круга сворачивается в одну-две
 *       логические команды, чтения таблиц порядка и сдвигов исчезают, а круговой сдвиг
 *       становится одной командой поворота. Оба потока идут вперемежку в одном теле: цепи
 *       независимы, и процессор с широкой командой исполняет их внахлёст, отчего задержка
 *       цепи одного потока прячется работой другого. Так решено по замерам (11.11.2026):
 *       на M4 цикл 371 МБ/с, развёртка 621, эталон OpenSSL 460; на x86_64 цикл 171,
 *       развёртка 418, эталон 259. Раздельное исполнение потоков вдвое медленнее
 *       чередования (183 против 621 на M4), а свёртка только функции круга при живом цикле
 *       не даёт ничего (370 против 371): выигрыш приносит именно непосредственность
 *       порядка слов и величин сдвигов
 *
 */
namespace {
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;

	/**
	 * @brief Порядок слов сообщения у левого потока по кругам
	 *
	 */
	static constexpr uint8_t LEFT_ORDER[80] = {
		// Первый круг: слова блока по порядку
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
	};
	/**
	 * @brief Порядок слов сообщения у правого потока по кругам
	 *
	 */
	static constexpr uint8_t RIGHT_ORDER[80] = {
		// Первый круг: сдвинутая последовательность слов
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	};
	/**
	 * @brief Величины круговых сдвигов у левого потока по кругам
	 *
	 */
	static constexpr uint8_t LEFT_SHIFT[80] = {
		// Сдвиги первого круга левого потока
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
	};
	/**
	 * @brief Величины круговых сдвигов у правого потока по кругам
	 *
	 */
	static constexpr uint8_t RIGHT_SHIFT[80] = {
		// Сдвиги первого круга правого потока
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
	};
	/**
	 * @brief Константы кругов левого потока
	 *
	 */
	static constexpr uint32_t LEFT_K[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
	/**
	 * @brief Константы кругов правого потока
	 *
	 */
	static constexpr uint32_t RIGHT_K[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};
	/**
	 * @brief Начальные значения хеша
	 *
	 */
	static constexpr uint32_t H[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

	/**
	 * @brief Функция кругового сдвига слова влево
	 *
	 * @param value сдвигаемое слово
	 * @param count количество разрядов сдвига
	 * @return      сдвинутое слово
	 *
	 */
	static constexpr uint32_t __nts_rotl__(const uint32_t value, const unsigned count) noexcept {
		// Выводим слово, сдвинутое по кругу
		return ((value << count) | (value >> (32 - count)));
	}
	/**
	 * @brief Функция функции круга по её номеру
	 *
	 * @param round номер круга (от нуля до четырёх)
	 * @param x     первое слово
	 * @param y     второе слово
	 * @param z     третье слово
	 * @return      значение функции круга
	 *
	 */
	static constexpr uint32_t __nts_fn__(const size_t round, const uint32_t x, const uint32_t y, const uint32_t z) noexcept {
		/**
		 * Выбираем функцию по номеру круга
		 */
		switch(round){
			// Первая функция: x ^ y ^ z
			case 0: return (x ^ y ^ z);
			// Вторая функция: (x & y) | (~x & z)
			case 1: return ((x & y) | (~x & z));
			// Третья функция: (x | ~y) ^ z
			case 2: return ((x | ~y) ^ z);
			// Четвёртая функция: (x & z) | (y & ~z)
			case 3: return ((x & z) | (y & ~z));
			// Пятая функция: x ^ (y | ~z)
			default: return (x ^ (y | ~z));
		}
	}
	/**
	 * @brief Функция чтения слова от младшего байта
	 *
	 * @param data читаемые байты
	 * @return     прочитанное слово
	 *
	 */
	static __NTS_INLINE__ uint32_t __nts_load__(const uint8_t * data) noexcept {
		// Выводим слово, собранное от младшего байта
		return (
			static_cast <uint32_t> (data[0]) | (static_cast <uint32_t> (data[1]) << 8) |
			(static_cast <uint32_t> (data[2]) << 16) | (static_cast <uint32_t> (data[3]) << 24)
		);
	}
	/**
	 * @brief Функция записи слова от младшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __NTS_INLINE__ void __nts_store__(const uint32_t value, uint8_t * data) noexcept {
		// Записываем младший байт слова
		data[0] = static_cast <uint8_t> (value);
		// Записываем второй байт слова
		data[1] = static_cast <uint8_t> (value >> 8);
		// Записываем третий байт слова
		data[2] = static_cast <uint8_t> (value >> 16);
		// Записываем старший байт слова
		data[3] = static_cast <uint8_t> (value >> 24);
	}
	/**
	 * @brief Шаблон функции шага левого потока с номером шага в шаблоне
	 *
	 * @tparam STEP тип размера шага
	 *
	 */
	template <size_t STEP>
	/**
	 * @brief Функция шага левого потока с номером шага в шаблоне
	 *
	 * @param first   первое рабочее слово потока
	 * @param second  второе рабочее слово потока
	 * @param third   третье рабочее слово потока
	 * @param fourth  четвёртое рабочее слово потока
	 * @param fifth   пятое рабочее слово потока
	 * @param message слова блока сообщения
	 *
	 */
	static __NTS_INLINE__ void __nts_left_step__(uint32_t & first, uint32_t & second, uint32_t & third, uint32_t & fourth, uint32_t & fifth, const uint32_t * message) noexcept {
		// Номер круга шага
		constexpr size_t round = (STEP / 16);
		// Временное слово: сумма первого рабочего слова, функции круга, слова сообщения и константы круга
		uint32_t item = (first + __nts_fn__(round, second, third, fourth) + message[LEFT_ORDER[STEP]] + LEFT_K[round]);
		// Прибавляем к сдвинутому временному слову пятое рабочее слово
		item = (__nts_rotl__(item, LEFT_SHIFT[STEP]) + fifth);
		// Передвигаем рабочие слова потока на один шаг
		first = fifth; fifth = fourth; fourth = __nts_rotl__(third, 10); third = second; second = item;
	}
	/**
	 * @brief Шаблон функции шага правого потока с номером шага в шаблоне
	 *
	 * @tparam STEP тип размера шага
	 *
	 */
	template <size_t STEP>
	/**
	 * @brief Функция шага правого потока с номером шага в шаблоне
	 *
	 * @note Функции кругов правого потока идут в обратном порядке относительно левого
	 *
	 * @param first   первое рабочее слово потока
	 * @param second  второе рабочее слово потока
	 * @param third   третье рабочее слово потока
	 * @param fourth  четвёртое рабочее слово потока
	 * @param fifth   пятое рабочее слово потока
	 * @param message слова блока сообщения
	 *
	 */
	static __NTS_INLINE__ void __nts_right_step__(uint32_t & first, uint32_t & second, uint32_t & third, uint32_t & fourth, uint32_t & fifth, const uint32_t * message) noexcept {
		// Номер круга шага
		constexpr size_t round = (STEP / 16);
		// Временное слово: сумма первого рабочего слова, функции круга, слова сообщения и константы круга
		uint32_t item = (first + __nts_fn__(4 - round, second, third, fourth) + message[RIGHT_ORDER[STEP]] + RIGHT_K[round]);
		// Прибавляем к сдвинутому временному слову пятое рабочее слово
		item = (__nts_rotl__(item, RIGHT_SHIFT[STEP]) + fifth);
		// Передвигаем рабочие слова потока на один шаг
		first = fifth; fifth = fourth; fourth = __nts_rotl__(third, 10); third = second; second = item;
	}
	/**
	 * @brief Шаблон функции прохода восьмидесяти шагов обоих потоков развёрткой по номеру шага
	 *
	 * @tparam STEP тип размера шага
	 *
	 */
	template <size_t... STEP>
	/**
	 * @brief Функция прохода восьмидесяти шагов обоих потоков развёрткой по номеру шага
	 *
	 * @param leftA      первое рабочее слово левого потока
	 * @param leftB      второе рабочее слово левого потока
	 * @param leftC      третье рабочее слово левого потока
	 * @param leftD      четвёртое рабочее слово левого потока
	 * @param leftE      пятое рабочее слово левого потока
	 * @param rightA      первое рабочее слово правого потока
	 * @param rightB      второе рабочее слово правого потока
	 * @param rightC      третье рабочее слово правого потока
	 * @param rightD      четвёртое рабочее слово правого потока
	 * @param rightE      пятое рабочее слово правого потока
	 * @param message слова блока сообщения
	 * @param steps   перечень номеров шагов
	 *
	 */
	static __NTS_INLINE__ void passSteps(uint32_t & leftA, uint32_t & leftB, uint32_t & leftC, uint32_t & leftD, uint32_t & leftE,
	                                      uint32_t & rightA, uint32_t & rightB, uint32_t & rightC, uint32_t & rightD, uint32_t & rightE,
	                                      const uint32_t * message, const std::index_sequence <STEP...> &) noexcept {
		// Шаг обоих потоков для каждого номера шага: потоки независимы и идут вперемежку
		((__nts_left_step__ <STEP> (leftA, leftB, leftC, leftD, leftE, message), __nts_right_step__ <STEP> (rightA, rightB, rightC, rightD, rightE, message)), ...);
	}
};

/**
 * @brief Метод разбора блока сообщения
 *
 * @param block разбираемый блок: накопитель либо сам кусок сообщения
 *
 */
void nts::digest::Ripemd::compress(const uint8_t * block) noexcept {
	// Слова блока сообщения
	uint32_t m[16];
	/**
	 * Читаем шестнадцать слов блока
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем очередное слово блока от младшего байта
		m[i] = ::__nts_load__(block + (i * 4));
	// Рабочие переменные левого потока
	uint32_t leftA = this->_hash[0], leftB = this->_hash[1], leftC = this->_hash[2], leftD = this->_hash[3], leftE = this->_hash[4];
	// Рабочие переменные правого потока
	uint32_t rightA = this->_hash[0], rightB = this->_hash[1], rightC = this->_hash[2], rightD = this->_hash[3], rightE = this->_hash[4];
	/**
	 * Проходим восемьдесят шагов двух потоков
	 */
	passSteps(leftA, leftB, leftC, leftD, leftE, rightA, rightB, rightC, rightD, rightE, m, std::make_index_sequence <80> ());
	// Итоги потоков сходятся перекрёстным сложением
	const uint32_t t = (this->_hash[1] + leftC + rightD);
	// Складываем итоги потоков в значение хеша
	this->_hash[1] = (this->_hash[2] + leftD + rightE);
	// Складываем итоги потоков в третье слово хеша
	this->_hash[2] = (this->_hash[3] + leftE + rightA);
	// Складываем итоги потоков в четвёртое слово хеша
	this->_hash[3] = (this->_hash[4] + leftA + rightB);
	// Складываем итоги потоков в пятое слово хеша
	this->_hash[4] = (this->_hash[0] + leftB + rightC);
	// Складываем итоги потоков в первое слово хеша
	this->_hash[0] = t;
	// Затираем слова блока сообщения
	wipe(m, sizeof(m));
}
/**
 * @brief Метод сброса состояния хеширования
 *
 */
void nts::digest::Ripemd::reset() noexcept {
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	// Сбрасываем количество байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем количество разобранных байтов
	this->_count = 0;
	/**
	 * Переносим начальные значения хеша
	 */
	for(size_t i = 0; i < 5; i++)
		// Переносим очередное начальное значение
		this->_hash[i] = H[i];
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Ripemd::update(const view_t & data) noexcept {
	// Если кусок задан длиной без места: подача порчена, хеш сниматься не будет
	if((data.data == nullptr) && (data.size > 0)){
		// Запоминаем порчу подачи: снятие хеша отказывает
		this->_finished = true;
		// Выходим из метода
		return;
	}
	// Если хеш уже снят либо кусок сообщения пуст
	if(this->_finished || (data.data == nullptr) || (data.size == 0))
		// Выходим из метода
		return;
	// Число ещё не разобранных байтов куска
	size_t left = data.size;
	// Позиция чтения куска
	const uint8_t * cursor = data.data;
	// Считаем поданные байты
	this->_count += static_cast <uint64_t> (data.size);
	// Если в накопителе есть незавершённый блок
	if(this->_size > 0){
		// Количество байтов, которых накопителю не хватает до целого блока
		const size_t needed = (64 - this->_size);
		// Количество байтов, переносимых в накопитель из куска
		const size_t taken = ((left < needed) ? left : needed);
		/**
		 * Переносим байты куска в накопитель
		 */
		for(size_t i = 0; i < taken; i++)
			// Переносим очередной байт куска
			this->_block[this->_size + i] = cursor[i];
		// Считаем перенесённые байты
		this->_size += taken;
		// Сдвигаем позицию чтения куска
		cursor += taken;
		// Уменьшаем количество не разобранных байтов
		left -= taken;
		// Если блок набрался целиком
		if(this->_size == 64){
			// Разбор накопленного блока
			this->compress(this->_block);
			// Сбрасываем количество байтов незавершённого блока
			this->_size = 0;
		// Иначе весь кусок ушёл в накопитель, и блок ещё не полон
		} else return;
	}
	/**
	 * Разбираем целые блоки куска прямо из него
	 */
	while(left >= 64){
		// Разбор очередного блока куска
		this->compress(cursor);
		// Сдвигаем позицию чтения куска
		cursor += 64;
		// Уменьшаем количество не разобранных байтов
		left -= 64;
	}
	/**
	 * Переносим хвост куска в накопитель
	 */
	for(size_t i = 0; i < left; i++)
		// Переносим очередной байт хвоста
		this->_block[i] = cursor[i];
	// Запоминаем количество байтов незавершённого блока
	this->_size = left;
}
/**
 * @brief Метод снятия выработанного хеша
 *
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 * @return       признак успешности снятия хеша
 *
 */
bool nts::digest::Ripemd::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < RIPEMD160))
		// Выводим отказ снятия хеша
		return false;
	// Количество разобранных разрядов сообщения
	const uint64_t bits = (this->_count << 3);
	// Записываем байт-отделитель за последним байтом сообщения
	this->_block[this->_size++] = 0x80;
	// Если места под поле длины в этом блоке не осталось
	if(this->_size > 56){
		/**
		 * Дополняем блок нулями до конца
		 */
		for(size_t i = this->_size; i < 64; i++)
			// Записываем очередной нулевой байт
			this->_block[i] = 0;
		// Разбор дополненного блока
		this->compress(this->_block);
		// Сбрасываем количество байтов незавершённого блока
		this->_size = 0;
	}
	/**
	 * Дополняем блок нулями до поля длины
	 */
	for(size_t i = this->_size; i < 56; i++)
		// Записываем очередной нулевой байт
		this->_block[i] = 0;
	// Записываем младшую половину длины сообщения от младшего байта
	::__nts_store__(static_cast <uint32_t> (bits), this->_block + 56);
	// Записываем старшую половину длины сообщения от младшего байта
	::__nts_store__(static_cast <uint32_t> (bits >> 32), this->_block + 60);
	// Разбор последнего блока
	this->compress(this->_block);
	/**
	 * Записываем слова хеша от младшего байта
	 */
	for(size_t i = 0; i < 5; i++)
		// Записываем очередное слово хеша
		::__nts_store__(this->_hash[i], result + (i * 4));
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
	// Сбрасываем количество байтов незавершённого блока
	this->_size = 0;
	// Запоминаем, что хеш снят
	this->_finished = true;
	// Выводим успешность снятия хеша
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::digest::Ripemd::Ripemd() noexcept : _finished(true), _size(0), _count(0) {
	// Сброс состояния хеширования
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Ripemd::~Ripemd() noexcept {
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}

/**
 * @brief Функция выработки хеша RIPEMD-160 целого сообщения
 *
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::ripemd160(const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если место под хеш не передано либо мало
	if((result == nullptr) || (size < RIPEMD160))
		// Выводим отказ выработки хеша
		return false;
	// Хешируемое сообщение
	ripemd_t hasher;
	// Подаём сообщение
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
