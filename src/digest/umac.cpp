/**
 * @file umac.cpp
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
 * @brief Модуль имитовставки UMAC (RFC 4418)
 *
 * @details Имитовставка считается по RFC 4418: из ключа связи блочным шифром AES
 *          выводятся ключи универсального хеширования (KDF в режиме счётчика) и
 *          подложка от одноразового числа (PDF). Сообщение проходит три слоя UHASH:
 *          NH разбивает его на блоки по 1024 байта и множит пары слов, POLY сводит
 *          длинное сообщение полиномом по простому модулю, L3 сжимает итог до четырёх
 *          байтов на итерацию. Итог UHASH складывается с подложкой по модулю два
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/umac.hpp>
#include <cipher/aes.hpp>
#include <math/wide.hpp>
#include <sys/wipe.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

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
	 * Подписываемся на шифр AES
	 */
	using nts::cipher::Aes;
	/**
	 * Подписываемся на целое число двойной разрядности
	 */
	using nts::math::wide_t;
	/**
	 * Подписываемся на представление данных
	 */
	using nts::view_t;
	/**
	 * Подписываемся на константы модуля
	 */
	using nts::digest::UMAC_KEY;
	using nts::digest::UMAC_64;
	using nts::digest::UMAC_128;
	/**
	 * @brief Размер блока AES в байтах
	 *
	 */
	constexpr size_t BLOCK = 16;
	/**
	 * @brief Длина блока сообщения у слоя NH в байтах
	 *
	 */
	constexpr size_t L1_BLOCK = 1024;
	/**
	 * @brief Метод записи числа старшим байтом вперёд
	 *
	 * @param value  записываемое число
	 * @param result место, в которое помещаются байты
	 * @param size   число байтов записи
	 *
	 */
	static inline void store(const uint64_t value, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем запись байтов от старшего к младшему
		 */
		for(size_t i = 0; i < size; i++)
			// Записываем очередной байт числа
			result[i] = static_cast <uint8_t> (value >> ((size - 1 - i) * 8));
	}
	/**
	 * @brief Метод чтения числа старшим байтом вперёд
	 *
	 * @param data байты числа
	 * @param size число байтов (до восьми)
	 *
	 * @return     прочитанное число
	 *
	 */
	static inline uint64_t fetch(const uint8_t * data, const size_t size) noexcept {
		// Прочитанное число
		uint64_t result = 0;
		/**
		 * Выполняем чтение байтов от старшего к младшему
		 */
		for(size_t i = 0; i < size; i++)
			// Присоединяем очередной байт числа
			result = ((result << 8) | data[i]);
		// Выводим прочитанное число
		return result;
	}
	/**
	 * @brief Метод вывода ключевого материала из ключа связи (раздел 3.2.1 RFC 4418)
	 *
	 * @details Блок шифруется счётчиком: первые восемь байтов несут опознаватель
	 *          выводимого ключа, последние восемь - номер блока, оба старшим байтом
	 *          вперёд
	 *
	 * @param aes    шифр с установленным ключом связи
	 * @param index  опознаватель выводимого ключа
	 * @param result место, в которое помещается материал
	 * @param size   длина выводимого материала в байтах
	 *
	 */
	static void kdf(Aes & aes, const uint64_t index, uint8_t * result, const size_t size) noexcept {
		// Блок счётчика и его шифрованный образ
		uint8_t input[BLOCK], output[BLOCK];
		// Число блоков выводимого материала
		const size_t count = ((size + BLOCK - 1) / BLOCK);
		/**
		 * Выполняем перебор блоков выводимого материала
		 */
		for(size_t i = 0; i < count; i++){
			// Записываем опознаватель ключа в первые восемь байтов блока
			store(index, input, BLOCK - 8);
			// Записываем номер блока в последние восемь байтов блока
			store(i + 1, input + (BLOCK - 8), 8);
			// Шифруем блок счётчика
			aes.encrypt(input, output);
			// Длина переносимой доли блока
			const size_t part = ((size - i * BLOCK < BLOCK) ? (size - i * BLOCK) : BLOCK);
			// Переносим долю блока в выводимый материал
			::memcpy(result + i * BLOCK, output, part);
		}
		// Затираем блоки счётчика
		wipe(input, sizeof(input));
		wipe(output, sizeof(output));
	}
	/**
	 * @brief Метод слоя NH: умножение пар слов сообщения и ключа (раздел 5.2.2 RFC 4418)
	 *
	 * @details Блок сообщения разворачивается по четырём байтам (ENDIAN-SWAP), после
	 *          чего пары слов через четыре позиции множатся: к словам сообщения и ключа
	 *          прибавляются по модулю 2^32, произведения складываются по модулю 2^64
	 *
	 * @param key    ключ слоя NH (1024 байта)
	 * @param data   блок сообщения (кратно 32 байтам, не длиннее ключа)
	 * @param size   длина блока сообщения в байтах
	 *
	 * @return       накопленное значение слоя
	 *
	 */
	static uint64_t nh(const uint8_t * key, const uint8_t * data, const size_t size) noexcept {
		// Накопленное значение слоя
		uint64_t acc = 0;
		// Развёрнутый блок сообщения
		uint8_t swapped[L1_BLOCK];
		/**
		 * Выполняем разворот каждой четвёрки байтов блока (ENDIAN-SWAP)
		 */
		for(size_t i = 0; i < size; i += 4){
			// Разворачиваем очередную четвёрку байтов
			swapped[i] = data[i + 3];
			swapped[i + 1] = data[i + 2];
			swapped[i + 2] = data[i + 1];
			swapped[i + 3] = data[i];
		}
		/**
		 * Выполняем перебор групп по восемь слов (32 байта)
		 */
		for(size_t i = 0; i < size; i += 32){
			/**
			 * Выполняем перебор четырёх пар слов в группе
			 */
			for(size_t j = 0; j < 4; j++){
				// Слово сообщения и слово ключа первой пары
				const uint32_t m1 = static_cast <uint32_t> (fetch(swapped + i + j * 4, 4));
				const uint32_t k1 = static_cast <uint32_t> (fetch(key + i + j * 4, 4));
				// Слово сообщения и слово ключа второй пары (через четыре позиции)
				const uint32_t m2 = static_cast <uint32_t> (fetch(swapped + i + j * 4 + 16, 4));
				const uint32_t k2 = static_cast <uint32_t> (fetch(key + i + j * 4 + 16, 4));
				// Накапливаем произведение сумм по модулю 2^64
				acc += (static_cast <uint64_t> (m1 + k1) * static_cast <uint64_t> (m2 + k2));
			}
		}
		// Затираем развёрнутый блок
		wipe(swapped, sizeof(swapped));
		// Выводим накопленное значение
		return acc;
	}
	/**
	 * @brief Метод слоя L1-HASH (раздел 5.2.1 RFC 4418)
	 *
	 * @details Сообщение разбивается на блоки по 1024 байта; значение каждого блока
	 *          (NH с прибавленной длиной блока в битах) записывается старшим байтом
	 *          вперёд, и вывод слоя - их слитная строка по восемь байтов на блок
	 *
	 * @param key    ключ слоя (1024 байта)
	 * @param data   сообщение любой длины
	 * @param result место, в которое помещается вывод слоя (по восемь байтов на блок)
	 *
	 * @return       длина вывода слоя в байтах
	 *
	 */
	static size_t l1hash(const uint8_t * key, const view_t & data, uint8_t * result) noexcept {
		// Смещение пройденной части сообщения и длина вывода
		size_t offset = 0, length = 0;
		/**
		 * Выполняем перебор полных блоков сообщения по 1024 байта
		 */
		while(data.size - offset > L1_BLOCK){
			// Записываем значение блока с длиной полного блока в битах старшим байтом вперёд
			store(nh(key, data.data + offset, L1_BLOCK) + static_cast <uint64_t> (L1_BLOCK) * 8, result + length, 8);
			// Сдвигаем смещение и длину на пройденный блок
			offset += L1_BLOCK;
			length += 8;
		}
		// Длина оставшейся части сообщения
		const size_t rest = (data.size - offset);
		// Добитый до кратного 32 байтам остаток сообщения
		uint8_t tail[L1_BLOCK] = {};
		// Переносим остаток сообщения
		if(rest > 0)
			// Переносим остаток сообщения
			::memcpy(tail, data.data + offset, rest);
		// Длина добитого остатка (кратная 32 байтам, не меньше одного блока по 32 байта)
		const size_t padded = ((rest == 0) ? 32 : ((rest + 31) / 32) * 32);
		// Записываем значение остатка с его длиной в битах старшим байтом вперёд
		store(nh(key, tail, padded) + static_cast <uint64_t> (rest) * 8, result + length, 8);
		// Сдвигаем длину на остаток
		length += 8;
		// Затираем добитый остаток
		wipe(tail, sizeof(tail));
		// Выводим длину вывода слоя
		return length;
	}
	/**
	 * @brief Метод шага полинома по модулю 2^64 - 59: y = k·y + m (раздел 5.3.2 RFC 4418)
	 *
	 * @details Произведение k·y - в 128 разрядов; по модулю 2^64 - 59 старшее слово
	 *          заменяется умножением на 59 (2^64 сравнимо с 59), итог приводится
	 *          вычитанием модуля
	 *
	 * @param k ключ полинома
	 * @param y накопленное значение полинома
	 * @param m очередное слово
	 *
	 * @return  новое значение полинома по модулю
	 *
	 */
	static inline uint64_t poly64step(const uint64_t k, const uint64_t y, const uint64_t m) noexcept {
		// Простой модуль 2^64 - 59
		const uint64_t p = (~static_cast <uint64_t> (0)) - 58;
		// Произведение ключа на значение в 128 разрядов
		const wide_t product = (wide_t(k) * y);
		// Старшее и младшее слова произведения
		const uint64_t hi = static_cast <uint64_t> (product >> 64);
		const uint64_t lo = static_cast <uint64_t> (product);
		// Приведение: hi·2^64 + lo сравнимо с hi·59 + lo (2^64 сравнимо с 59)
		const wide_t reduced = (wide_t(hi) * 59 + lo + m);
		// Младшее слово приведённого значения
		uint64_t result = static_cast <uint64_t> (reduced);
		// Старшее слово приведённого значения (не больше единицы после первого шага)
		const uint64_t extra = static_cast <uint64_t> (reduced >> 64);
		// Складываем перенос умножением на 59
		result += (extra * 59);
		// Приводим вычитанием модуля, пока значение не меньше модуля
		if(result >= p)
			// Вычитаем модуль
			result -= p;
		// Выводим значение полинома по модулю
		return result;
	}
	/**
	 * @brief Метод слоя POLY по модулю 2^64 - 59 (раздел 5.3.2 RFC 4418)
	 *
	 * @param key  ключ слоя (восемь байтов)
	 * @param data значение слоя L1 (кратно восьми байтам)
	 *
	 * @return     значение полинома по модулю
	 *
	 */
	static uint64_t poly64(const uint64_t key, const view_t & data) noexcept {
		// Дополнение модуля до 2^64 (2^64 - p)
		const uint64_t offset = 59;
		// Метка модуля (p - 1)
		const uint64_t marker = (~static_cast <uint64_t> (0)) - 59;
		// Наибольшее слово, берущееся напрямую: 2^64 - 2^32
		const uint64_t maxword = ((~static_cast <uint64_t> (0)) - (static_cast <uint64_t> (1) << 32) + 1);
		// Ключ полинома с наложенной маской (раздел 5.3.1 RFC 4418)
		const uint64_t k = (key & 0x01FFFFFF01FFFFFFULL);
		// Накопленное значение полинома
		uint64_t y = 1;
		/**
		 * Выполняем перебор слов значения по восемь байтов
		 */
		for(size_t i = 0; i < data.size; i += 8){
			// Очередное слово значения старшим байтом вперёд
			const uint64_t m = fetch(data.data + i, 8);
			// Если слово не берётся напрямую
			if(m >= maxword){
				// Шаг полинома с меткой модуля
				y = poly64step(k, y, marker);
				// Шаг полинома со сдвинутым словом
				y = poly64step(k, y, m - offset);
			// Иначе слово берётся напрямую
			} else {
				// Шаг полинома со словом
				y = poly64step(k, y, m);
			}
		}
		// Выводим накопленное значение полинома
		return y;
	}
	/**
	 * @brief Метод слоя L3-HASH (раздел 5.4.1 RFC 4418)
	 *
	 * @details Восемь двухбайтовых слов значения множатся на восьмибайтовые слова
	 *          ключа по модулю 2^36 - 5, сумма усечением до 2^32 складывается с ключом
	 *          по модулю два
	 *
	 * @param k1    первый ключ слоя (64 байта)
	 * @param k2    второй ключ слоя (4 байта)
	 * @param value значение слоя L2 (16 байтов)
	 *
	 * @return      итог слоя (четыре байта)
	 *
	 */
	static uint32_t l3hash(const uint8_t * k1, const uint8_t * k2, const uint8_t * value) noexcept {
		// Простой модуль 2^36 - 5
		const uint64_t p = ((static_cast <uint64_t> (1) << 36) - 5);
		// Накопленная сумма произведений
		uint64_t acc = 0;
		/**
		 * Выполняем перебор восьми пар слов
		 */
		for(size_t i = 0; i < 8; i++){
			// Двухбайтовое слово значения старшим байтом вперёд
			const uint64_t m = fetch(value + i * 2, 2);
			// Восьмибайтовое слово ключа по модулю 2^36 - 5
			const uint64_t k = (fetch(k1 + i * 8, 8) % p);
			// Накапливаем произведение по модулю 2^36 - 5
			acc = ((acc + m * k) % p);
		}
		// Усекаем сумму до 2^32
		const uint32_t y = static_cast <uint32_t> (acc & 0xFFFFFFFFULL);
		// Второй ключ слоя
		const uint32_t pad = static_cast <uint32_t> (fetch(k2, 4));
		// Выводим итог слоя, сложенный с ключом по модулю два
		return (y ^ pad);
	}
	/**
	 * @brief Метод вывода подложки от одноразового числа (раздел 3.3.1 RFC 4418)
	 *
	 * @details Одноразовое число складывается по модулю два с его индексом подстроки
	 *          блока, добивается нулями до блока и шифруется ключом, выведенным из ключа
	 *          связи опознавателем ноль; подложка - подстрока образа по индексу
	 *
	 * @param aes    шифр с установленным ключом связи
	 * @param nonce  одноразовое число
	 * @param result место, в которое помещается подложка
	 * @param size   длина подложки в байтах (8 или 16)
	 *
	 */
	static void pdf(Aes & aes, const view_t & nonce, uint8_t * result, const size_t size) noexcept {
		// Ключ подложки, выводимый из ключа связи
		uint8_t subkey[UMAC_KEY];
		// Выводим ключ подложки опознавателем ноль
		kdf(aes, 0, subkey, sizeof(subkey));
		// Шифр подложки
		Aes pad;
		// Устанавливаем ключ подложки
		pad.key(view_t(subkey, sizeof(subkey)));
		// Добитый нулями блок одноразового числа
		uint8_t block[BLOCK] = {};
		// Переносим одноразовое число
		::memcpy(block, nonce.data, nonce.size);
		// Индекс подстроки блока по одноразовому числу
		const uint64_t index = (fetch(nonce.data, nonce.size) % (BLOCK / size));
		// Складываем одноразовое число с индексом по модулю два
		store(fetch(block, nonce.size) ^ index, block, nonce.size);
		// Шифрованный образ блока одноразового числа
		uint8_t output[BLOCK];
		// Шифруем блок одноразового числа
		pad.encrypt(block, output);
		// Переносим подстроку образа по индексу
		::memcpy(result, output + index * size, size);
		// Затираем ключ и блоки подложки
		wipe(subkey, sizeof(subkey));
		wipe(block, sizeof(block));
		wipe(output, sizeof(output));
		// Затираем шифр подложки
		pad.clear();
	}
};

/**
 * @brief Метод вычисления имитовставки UMAC
 *
 * @param key    ключ в шестнадцать байтов
 * @param nonce  одноразовое число (от одного до шестнадцати байтов)
 * @param data   сообщение любой длины
 * @param result место, в которое помещается итог
 * @param size   длина итога: 8 (UMAC-64) или 16 (UMAC-128)
 *
 * @return       признак того, что итог вычислен
 *
 */
bool nts::digest::umac(const view_t & key, const view_t & nonce, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если ключ, одноразовое число либо длина итога не годятся
	if((key.data == nullptr) || (key.size != UMAC_KEY) || (nonce.data == nullptr) || (nonce.size == 0) || (nonce.size > BLOCK) || ((size != UMAC_64) && (size != UMAC_128)) || (result == nullptr))
		// Выводим отказ вычисления
		return false;
	// Число итераций по длине итога
	const size_t iters = (size / 4);
	// Шифр с ключом связи
	Aes aes;
	// Если ключ связи не установлен
	if(!aes.key(key))
		// Выводим отказ вычисления
		return false;
	// Ключи слоёв универсального хеширования
	uint8_t l1key[1024 + (UMAC_128 / 4 - 1) * 16], l2key[(UMAC_128 / 4) * 24], l3key1[(UMAC_128 / 4) * 64], l3key2[(UMAC_128 / 4) * 4];
	// Выводим ключ слоя L1 опознавателем один
	kdf(aes, 1, l1key, 1024 + (iters - 1) * 16);
	// Выводим ключ слоя L2 опознавателем два
	kdf(aes, 2, l2key, iters * 24);
	// Выводим первый ключ слоя L3 опознавателем три
	kdf(aes, 3, l3key1, iters * 64);
	// Выводим второй ключ слоя L3 опознавателем четыре
	kdf(aes, 4, l3key2, iters * 4);
	// Итог универсального хеширования (по четыре байта на итерацию)
	uint8_t hashed[UMAC_128];
	// Вывод слоя L1: по восемь байтов на каждый блок сообщения в 1024 байта
	uint8_t * l1 = nullptr;
	// Если сообщение длиннее ключа слоя L1, вывод слоя L1 идёт потоком в слой L2
	if(data.size > 1024){
		// Выделяем место под вывод слоя L1
		l1 = new(std::nothrow) uint8_t[((data.size / L1_BLOCK) + 1) * 8];
		// Если место под вывод слоя L1 не выделено
		if(l1 == nullptr){
			// Затираем ключи слоёв
			wipe(l1key, sizeof(l1key));
			wipe(l2key, sizeof(l2key));
			wipe(l3key1, sizeof(l3key1));
			wipe(l3key2, sizeof(l3key2));
			// Затираем шифр с ключом связи
			aes.clear();
			// Выводим отказ вычисления
			return false;
		}
	}
	/**
	 * Выполняем перебор итераций по длине итога
	 */
	for(size_t i = 0; i < iters; i++){
		// Значение слоя L2: шестнадцать байтов
		uint8_t b[16] = {};
		// Если сообщение не длиннее ключа слоя L1, слой L2 - нули и значение L1
		if(data.size <= 1024){
			// Значение слоя L1 ключом этой итерации
			uint8_t av[8];
			// Вычисляем значение слоя L1
			l1hash(l1key + i * 16, data, av);
			// Записываем значение слоя L1 в младшие восемь байтов слоя L2
			::memcpy(b + 8, av, 8);
			// Затираем значение слоя L1
			wipe(av, sizeof(av));
		// Иначе значение слоя L1 сводится полиномом от потока его значений
		} else {
			// Вычисляем вывод слоя L1 потоком значений по блокам
			const size_t length = l1hash(l1key + i * 16, data, l1);
			// Сводим поток полиномом по модулю 2^64 - 59
			const uint64_t reduced = poly64(fetch(l2key + i * 24, 8), view_t(l1, length));
			// Записываем сведённое значение старшим байтом вперёд в младшие восемь байтов слоя L2
			store(reduced, b + 8, 8);
		}
		// Итог слоя L3 ключами этой итерации старшим байтом вперёд
		store(l3hash(l3key1 + i * 64, l3key2 + i * 4, b), hashed + i * 4, 4);
		// Затираем значение слоя L2
		wipe(b, sizeof(b));
	}
	// Освобождаем вывод слоя L1
	if(l1 != nullptr){
		// Затираем вывод слоя L1
		wipe(l1, ((data.size / L1_BLOCK) + 1) * 8);
		// Освобождаем вывод слоя L1
		delete[] l1;
	}
	// Подложка от одноразового числа длиной в итог
	uint8_t pad[UMAC_128];
	// Выводим подложку
	pdf(aes, nonce, pad, size);
	/**
	 * Выполняем сложение итога хеширования с подложкой по модулю два
	 */
	for(size_t i = 0; i < size; i++)
		// Складываем очередной байт итога с подложкой
		result[i] = (hashed[i] ^ pad[i]);
	// Затираем итог хеширования и подложку
	wipe(hashed, sizeof(hashed));
	wipe(pad, sizeof(pad));
	// Затираем ключи слоёв
	wipe(l1key, sizeof(l1key));
	wipe(l2key, sizeof(l2key));
	wipe(l3key1, sizeof(l3key1));
	wipe(l3key2, sizeof(l3key2));
	// Затираем шифр с ключом связи
	aes.clear();
	// Выводим признак вычисления итога
	return true;
}
