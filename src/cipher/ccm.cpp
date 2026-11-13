/**
 * @file ccm.cpp
 * @date 2026-10-04
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
 * @brief Модуль режима шифрования с проверкой целостности CCM по RFC 3610
 *
 * @details Метка целостности вырабатывается имитовставкой CBC-MAC над блоком B0,
 *          связанными данными и открытым текстом; зашифрование идёт гаммированием
 *          со счётчиком A_i, а метка накладывается суммой с гаммой блока A_0
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cipher/ccm.hpp>
#include <sys/wipe.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Если сборка ведётся под ARM64
 */
#if (defined(__aarch64__) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Подключаем заголовочный файл команд ARM
	 */
	#include <arm_neon.h>

	/**
	 * Если расширение уже разрешено ключами сборки
	 */
	#if defined(__ARM_FEATURE_AES)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_CCM_TARGET__
	/**
	 * Если собиратель Microsoft Visual C++: внутренние функции расширения доступны ему без ключей
	 */
	#elif defined(_MSC_VER)
		/**
		 * Атрибута цели у собирателя нет, и он не нужен
		 */
		#define __ANTS_CCM_TARGET__
	/**
	 * Если собиратель clang
	 */
	#elif defined(__clang__)
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_CCM_TARGET__ __attribute__((target("crypto")))
	/**
	 * Если собиратель GCC
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_CCM_TARGET__ __attribute__((target("+crypto")))
	#endif

	/**
	 * Объявляем наличие ветви слитного прохода командами машины
	 */
	#define __ANTS_CCM_ARM__ 1
/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#elif (defined(__x86_64__) || defined(__e2k__) || defined(__ANTS_MSVC_X64__)) && (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Подключаем заголовочный файл команд x86-64
	 */
	#include <wmmintrin.h>

	/**
	 * Если расширение уже разрешено ключами сборки
	 */
	#if defined(__AES__)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_CCM_TARGET__
	/**
	 * Если собиратель Microsoft Visual C++: внутренние функции расширения доступны ему без ключей
	 */
	#elif defined(_MSC_VER)
		/**
		 * Атрибута цели у собирателя нет, и он не нужен
		 */
		#define __ANTS_CCM_TARGET__
	/**
	 * Иначе разрешаем команды расширения одной функции атрибутом цели
	 */
	#else
		/**
		 * Разрешаем команды расширения слитного прохода одной функции
		 */
		#define __ANTS_CCM_TARGET__ __attribute__((target("aes,sse2")))
	#endif

	/**
	 * Объявляем наличие ветви слитного прохода командами машины
	 */
	#define __ANTS_CCM_X86__ 1
#endif

/**
 * Перестановка байтов слова: у собирателей семейства GCC это встроенная функция
 * собирателя, у Microsoft Visual C++ - внутренняя функция того же действия
 */
#if defined(_MSC_VER)
	/**
	 * Подключаем заголовочный файл внутренних функций перестановки байтов
	 */
	#include <cstdlib>

	/**
	 * Объявляем перестановку байтов слова в шестьдесят четыре разряда
	 */
	#define __ANTS_BSWAP64__(value) ::_byteswap_uint64(value)
/**
 * Для собирателей семейства GCC и Эльбруса
 */
#else
	/**
	 * Объявляем перестановку байтов слова в шестьдесят четыре разряда
	 */
	#define __ANTS_BSWAP64__(value) __builtin_bswap64(value)
#endif

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
	using namespace nts::cipher;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Функция сложения блоков по модулю два
	 *
	 * @param first  первое слагаемое
	 * @param second второе слагаемое
	 * @param result место, в которое помещается сумма
	 * @param size   размер складываемых блоков
	 *
	 */
	static void add(const uint8_t * first, const uint8_t * second, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов складываемых блоков
		 */
		for(size_t i = 0; i < size; i++)
			// Складываем очередные байты блоков по модулю два
			result[i] = static_cast <uint8_t> (first[i] ^ second[i]);
	}

	/**
	 * @brief Функция сборки блока счётчика A_i
	 *
	 * @details Раздел 5.3 RFC 3610: признаки (L-1), одноразовое значение и номер
	 *          блока длиной L от старшего байта
	 *
	 * @param nonce  одноразовое значение режима
	 * @param length длина одноразового значения
	 * @param width  длина поля номера блока в байтах
	 * @param number номер блока счётчика
	 * @param result место, в которое помещается блок счётчика
	 *
	 */
	static void counter(const uint8_t * nonce, const size_t length, const size_t width, const uint64_t number, uint8_t * result) noexcept {
		// Записываем признаки блока счётчика: длина поля номера без единицы
		result[0] = static_cast <uint8_t> (width - 1);
		// Переносим одноразовое значение
		::memcpy(result + 1, nonce, length);
		/**
		 * Записываем номер блока от старшего байта
		 */
		for(size_t i = 0; i < width; i++)
			// Записываем очередной байт номера блока
			result[15 - i] = static_cast <uint8_t> ((number >> (i * 8)) & 0xFF);
	}

	/**
	 * @brief Функция выработки начала имитовставки CBC-MAC: блок B0 и связанные данные
	 *
	 * @details Раздел 5.2 RFC 3610: блок B0 с признаками и длиной сообщения, затем
	 *          связанные данные с их длиной; всякий кусок дополняется нулями до блока
	 *
	 * @param block      базовый алгоритм блочного шифрования
	 * @param nonce      одноразовое значение режима
	 * @param length     длина одноразового значения
	 * @param width      длина поля длины сообщения в байтах
	 * @param size       длина метки целостности в байтах
	 * @param associated связанные данные
	 * @param message    длина сообщения в байтах
	 * @param result     место, в которое помещается значение начала имитовставки
	 * @return признак успешности выработки начала имитовставки
	 *
	 */
	static bool heading(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, const size_t size, const view_t & associated, const size_t message, uint8_t * result) noexcept {
		// Текущий блок форматированного сообщения
		uint8_t item[16];
		// Записываем признаки блока B0: связанные данные, длина метки и длина поля длины
		item[0] = static_cast <uint8_t> ((((associated.size > 0) ? 1 : 0) << 6) | (((size - 2) / 2) << 3) | (width - 1));
		// Переносим одноразовое значение
		::memcpy(item + 1, nonce, length);
		/**
		 * Записываем длину сообщения от старшего байта
		 */
		for(size_t i = 0; i < width; i++)
			// Записываем очередной байт длины сообщения
			item[15 - i] = static_cast <uint8_t> ((message >> (i * 8)) & 0xFF);
		// Первый блок идёт в накопитель напрямую
		if(!block.encrypt(block.cipher, item, result)){
			// Выполняем затирание текущего блока
			wipe(item, sizeof(item));
			// Выводим отказ выработки начала имитовставки
			return false;
		}
		// Если связанные данные заданы
		if(associated.size > 0){
			// Длина записи длины связанных данных
			size_t prefix = 0;
			// Если длина связанных данных укладывается в короткую форму
			if(associated.size < 0xFF00){
				// Записываем длину двумя байтами от старшего
				item[0] = static_cast <uint8_t> ((associated.size >> 8) & 0xFF);
				// Записываем младший байт длины
				item[1] = static_cast <uint8_t> (associated.size & 0xFF);
				// Запоминаем длину короткой записи
				prefix = 2;
			// Иначе длина связанных данных идёт длинной формой
			} else {
				// Записываем признак длинной формы
				item[0] = 0xFF;
				// Записываем второй байт признака
				item[1] = 0xFE;
				/**
				 * Записываем длину четырьмя байтами от старшего
				 */
				for(size_t i = 0; i < 4; i++)
					// Записываем очередной байт длины
					item[2 + i] = static_cast <uint8_t> ((associated.size >> ((3 - i) * 8)) & 0xFF);
				// Запоминаем длину длинной записи
				prefix = 6;
			}
			// Число байтов связанных данных в первом блоке
			const size_t taken = ((associated.size < (16 - prefix)) ? associated.size : (16 - prefix));
			// Переносим начало связанных данных в первый блок
			::memcpy(item + prefix, associated.data, taken);
			// Дополняем первый блок нулями
			if((prefix + taken) < 16)
				// Выполняем обнуление остатка первого блока
				::memset(item + prefix + taken, 0, 16 - prefix - taken);
			// Складываем первый блок с накопителем и зашифровываем
			add(result, item, item, 16);
			// Если очередной блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, result)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
			// Позиция чтения связанных данных
			size_t offset = taken;
			/**
			 * Выполняем разбор целых блоков связанных данных
			 */
			while((associated.size - offset) >= 16){
				// Складываем очередной блок с накопителем
				add(result, associated.data + offset, item, 16);
				// Если очередной блок зашифровать не удалось
				if(!block.encrypt(block.cipher, item, result)){
					// Выполняем затирание текущего блока
					wipe(item, sizeof(item));
					// Выводим отказ выработки имитовставки
					return false;
				}
				// Сдвигаем позицию чтения связанных данных
				offset += 16;
			}
			// Если остался неполный блок связанных данных
			if(offset < associated.size){
				// Число оставшихся байтов связанных данных
				const size_t rest = (associated.size - offset);
				// Переносим остаток связанных данных в блок
				::memcpy(item, associated.data + offset, rest);
				// Дополняем блок нулями
				::memset(item + rest, 0, 16 - rest);
				// Складываем блок с накопителем
				add(result, item, item, 16);
				// Если последний блок зашифровать не удалось
				if(!block.encrypt(block.cipher, item, result)){
					// Выполняем затирание текущего блока
					wipe(item, sizeof(item));
					// Выводим отказ выработки начала имитовставки
					return false;
				}
			}
		}
		// Выводим успешность выработки начала имитовставки
		return true;
	}

	/**
	 * @brief Функция выработки имитовставки CBC-MAC над форматированным сообщением
	 *
	 * @details Раздел 5.2 RFC 3610: начало из блока B0 и связанных данных, затем
	 *          открытый текст; всякий кусок дополняется нулями до блока
	 *
	 * @param block      базовый алгоритм блочного шифрования
	 * @param nonce      одноразовое значение режима
	 * @param length     длина одноразового значения
	 * @param width      длина поля длины сообщения в байтах
	 * @param size       длина метки целостности в байтах
	 * @param associated связанные данные
	 * @param source     открытый текст
	 * @param result     место, в которое помещается значение имитовставки
	 * @return признак успешности выработки имитовставки
	 *
	 */
	static bool mac(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, const size_t size, const view_t & associated, const view_t & source, uint8_t * result) noexcept {
		// Накопитель имитовставки
		uint8_t accumulator[16];
		// Если начало имитовставки выработать не удалось
		if(!heading(block, nonce, length, width, size, associated, source.size, accumulator)){
			// Выполняем затирание накопителя имитовставки
			wipe(accumulator, sizeof(accumulator));
			// Выводим отказ выработки имитовставки
			return false;
		}
		// Текущий блок форматированного сообщения
		uint8_t item[16];
		// Позиция чтения открытого текста
		size_t offset = 0;
		// Если базовый шифр несёт цепочку сцепления, целые блоки текста идут ею
		if(block.chain != nullptr){
			// Временное место шифрблоков цепочки: имитовставка читается из накопителя
			uint8_t scratch[256];
			// Число целых блоков открытого текста
			const size_t whole = (source.size & ~static_cast <size_t> (0xF));
			/**
			 * Выполняем прогон цепочки сцепления кусками по шестнадцать блоков
			 */
			while(offset < whole){
				// Длина очередного куска цепочки
				const size_t piece = (((whole - offset) < sizeof(scratch)) ? (whole - offset) : sizeof(scratch));
				// Если очередной кусок цепочки не прошёл, дальше ведёт общий путь
				if(!block.chain(block.cipher, accumulator, source.data + offset, piece, scratch))
					// Выходим из прогона цепочки
					break;
				// Сдвигаем позицию чтения открытого текста
				offset += piece;
			}
			// Выполняем затирание временного места шифрблоков
			wipe(scratch, sizeof(scratch));
		}
		/**
		 * Выполняем разбор целых блоков открытого текста
		 */
		while((source.size - offset) >= 16){
			// Складываем очередной блок с накопителем
			add(accumulator, source.data + offset, item, 16);
			// Если очередной блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, accumulator)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
			// Сдвигаем позицию чтения открытого текста
			offset += 16;
		}
		// Если остался неполный блок открытого текста
		if(offset < source.size){
			// Число оставшихся байтов открытого текста
			const size_t rest = (source.size - offset);
			// Переносим остаток открытого текста в блок
			::memcpy(item, source.data + offset, rest);
			// Дополняем блок нулями
			::memset(item + rest, 0, 16 - rest);
			// Складываем блок с накопителем
			add(accumulator, item, item, 16);
			// Если последний блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, accumulator)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
		}
		// Переносим значение имитовставки на место итога
		::memcpy(result, accumulator, 16);
		// Выполняем затирание накопителя имитовставки
		wipe(accumulator, sizeof(accumulator));
		// Выполняем затирание текущего блока
		wipe(item, sizeof(item));
		// Выводим успешность выработки имитовставки
		return true;
	}

	/**
	 * @brief Функция наложения гаммы счётчика на сообщение
	 *
	 * @details Раздел 5.3 RFC 3610: блоки A_1, A_2, … зашифровываются, и гамма
	 *          складывается с сообщением по модулю два
	 *
	 * @param block  базовый алгоритм блочного шифрования
	 * @param nonce  одноразовое значение режима
	 * @param length длина одноразового значения
	 * @param width  длина поля номера блока в байтах
	 * @param source сообщение, на которое накладывается гамма
	 * @param result место, в которое помещается итог наложения
	 * @return признак успешности наложения гаммы
	 *
	 */
	static bool gamma(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, const view_t & source, uint8_t * result) noexcept {
		// Текущий блок счётчика
		uint8_t item[16];
		// Текущий блок гаммы
		uint8_t stream[16];
		// Номер текущего блока счётчика
		uint64_t number = 1;
		// Позиция чтения сообщения
		size_t offset = 0;
		// Если поле номера блока занимает четыре байта и шифр несёт слитную гамму, целые блоки идут ею
		if((width == 4) && (block.stream != nullptr)){
			// Число целых блоков сообщения
			const size_t whole = (source.size & ~static_cast <size_t> (0xF));
			/**
			 * Выполняем наложение гаммы кусками по шестьдесят четыре блока
			 */
			while(offset < whole){
				// Число блоков в очередном куске гаммы
				const size_t blocks = (((whole - offset) >> 4) > 64) ? 64 : ((whole - offset) >> 4);
				// Собираем блок счётчика начала очередного куска
				counter(nonce, length, width, number, item);
				// Если очередной кусок гаммы не прошёл, дальше ведёт общий путь
				if(!block.stream(block.cipher, item, blocks, source.data + offset, result + offset))
					// Выходим из наложения слитной гаммы
					break;
				// Сдвигаем позицию чтения сообщения
				offset += (blocks << 4);
				// Увеличиваем номер блока счётчика
				number += blocks;
			}
		}
		/**
		 * Выполняем наложение гаммы по блокам сообщения
		 */
		while(offset < source.size){
			// Собираем очередной блок счётчика
			counter(nonce, length, width, number, item);
			// Если блок гаммы выработать не удалось
			if(!block.encrypt(block.cipher, item, stream)){
				// Выполняем затирание текущего блока счётчика
				wipe(item, sizeof(item));
				// Выводим отказ наложения гаммы
				return false;
			}
			// Число байтов сообщения в очередном блоке
			const size_t taken = (((source.size - offset) < 16) ? (source.size - offset) : 16);
			/**
			 * Выполняем наложение гаммы на очередной кусок сообщения
			 */
			for(size_t i = 0; i < taken; i++)
				// Накладываем очередной байт гаммы
				result[offset + i] = static_cast <uint8_t> (source.data[offset + i] ^ stream[i]);
			// Сдвигаем позицию чтения сообщения
			offset += taken;
			// Увеличиваем номер блока счётчика
			number++;
		}
		// Выполняем затирание текущего блока счётчика
		wipe(item, sizeof(item));
		// Выполняем затирание текущего блока гаммы
		wipe(stream, sizeof(stream));
		// Выводим успешность наложения гаммы
		return true;
	}

	/**
	 * Если есть ветвь слитного прохода командами машины
	 */
	#if defined(__ANTS_CCM_ARM__) || defined(__ANTS_CCM_X86__)
		/**
		 * Если есть ветвь команд AES расширения ARMv8
		 */
		#if defined(__ANTS_CCM_ARM__)
			/**
			 * @brief Функция слитного прохода командами AESE и AESMC: имитовставка CBC и гамма счётчика чередуются кругами
			 *
			 * @details Имитовставка CBC-MAC сериальна: круг шифрования очередного блока не начинается,
			 *          пока не кончится круг предыдущего, и конвейер команд AES в этих ожиданиях
			 *          простаивал бы при проходе гаммы отдельным ходом. Оттого круги гаммы счётчика
			 *          следующего блока считаются между кругами имитовставки текущего: за то время,
			 *          что цепочка имитовставки ждёт латентности своего круга, успевает пройти круг
			 *          гаммы, и оба прохода режима укладываются в один ход по сообщения
			 *
			 * @param keys    раундовые ключи байтами в порядке памяти
			 * @param rounds  число раундов
			 * @param record  накопитель имитовставки: на входе значение после начала, на выходе после целых блоков
			 * @param counter блок счётчика A_1
			 * @param sealing признак зашифрования: открытый текст берётся из источника, при расшифровании снимается гаммой
			 * @param source  сообщение: открытый текст при зашифровании, шифртекст при расшифровании
			 * @param result  место итога: шифртекст при зашифровании, открытый текст при расшифровании
			 * @param blocks  число целых блоков сообщения
			 *
			 */
			static __ANTS_CCM_TARGET__ void fusedArm(const uint8_t * keys, const size_t rounds, uint8_t * record, const uint8_t * counter, const bool sealing, const uint8_t * source, uint8_t * result, const size_t blocks) noexcept {
				// Состояние имитовставки держится вектором на весь проход
				uint8x16_t state = vld1q_u8(record);
				// Номер блока счётчика от старшего байта: у блока A_1 равен единице
				uint64_t tail = 0;
				/**
				 * Читаем младшие восемь байтов блока счётчика от старшего байта
				 */
				for(size_t i = 0; i < 8; i++)
					// Добавляем очередной байт номера
					tail = ((tail << 8) | static_cast <uint64_t> (counter[8 + i]));
				// Гамма первого блока: блок счётчика A_1
				uint8x16_t stream = vld1q_u8(counter);
				/**
				 * Выполняем внутренние круги шифрования гаммы первого блока
				 */
				for(size_t round = 0; (round + 1) < rounds; round++)
					// Выполняем круг командами AESE и AESMC
					stream = vaesmcq_u8(vaeseq_u8(stream, vld1q_u8(keys + (round * 16))));
				// Завершаем шифрование гаммы первого блока
				stream = veorq_u8(vaeseq_u8(stream, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
				/**
				 * Выполняем перебор блоков сообщения
				 */
				for(size_t b = 0; b < blocks; b++){
					// Открытый текст блока: при расшифровании снимается гаммой текущего блока
					const uint8x16_t plain = (sealing ? vld1q_u8(source) : veorq_u8(vld1q_u8(source), stream));
					// Записываем итог блока: шифртекст при зашифровании, открытый текст при расшифровании
					vst1q_u8(result, (sealing ? veorq_u8(plain, stream) : plain));
					// Блок счётчика гаммы следующего блока: номер растёт от старшего байта
					uint8x16_t lane = vreinterpretq_u8_u64(vsetq_lane_u64(__ANTS_BSWAP64__(tail + b + 1), vreinterpretq_u64_u8(vld1q_u8(counter)), 1));
					// Складываем открытый текст с состоянием имитовставки
					state = veorq_u8(state, plain);
					/**
					 * Выполняем круги имитовставки и гаммы чередованием: круги гаммы заполняют ожидания кругов имитовставки
					 */
					for(size_t round = 0; (round + 1) < rounds; round++){
						// Ключ круга
						const uint8x16_t key = vld1q_u8(keys + (round * 16));
						// Выполняем круг имитовставки
						state = vaesmcq_u8(vaeseq_u8(state, key));
						// Выполняем круг гаммы следующего блока
						lane = vaesmcq_u8(vaeseq_u8(lane, key));
					}
					// Завершаем круги имитовставки последним кругом без перемешивания
					state = veorq_u8(vaeseq_u8(state, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
					// Гамма следующего блока готова
					stream = veorq_u8(vaeseq_u8(lane, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
					// Сдвигаем позицию чтения
					source += 16;
					// Сдвигаем позицию записи
					result += 16;
				}
				// Записываем состояние имитовставки на место накопителя
				vst1q_u8(record, state);
			}
		/**
		 * Иначе есть ветвь команд AES-NI
		 */
		#else
			/**
			 * @brief Функция слитного прохода командами AES-NI: имитовставка CBC и гамма счётчика чередуются кругами
			 *
			 * @details Имитовставка CBC-MAC сериальна: круг шифрования очередного блока не начинается,
			 *          пока не кончится круг предыдущего, и конвейер команд AES в этих ожиданиях
			 *          простаивал бы при проходе гаммы отдельным ходом. Оттого круги гаммы счётчика
			 *          следующего блока считаются между кругами имитовставки текущего: за то время,
			 *          что цепочка имитовставки ждёт латентности своего круга, успевает пройти круг
			 *          гаммы, и оба прохода режима укладываются в один ход по сообщения
			 *
			 * @param keys    раундовые ключи байтами в порядке памяти
			 * @param rounds  число раундов
			 * @param record  накопитель имитовставки: на входе значение после начала, на выходе после целых блоков
			 * @param counter блок счётчика A_1
			 * @param sealing признак зашифрования: открытый текст берётся из источника, при расшифровании снимается гаммой
			 * @param source  сообщение: открытый текст при зашифровании, шифртекст при расшифровании
			 * @param result  место итога: шифртекст при зашифровании, открытый текст при расшифровании
			 * @param blocks  число целых блоков сообщения
			 *
			 */
			static __ANTS_CCM_TARGET__ void fusedX86(const uint8_t * keys, const size_t rounds, uint8_t * record, const uint8_t * counter, const bool sealing, const uint8_t * source, uint8_t * result, const size_t blocks) noexcept {
				// Состояние имитовставки держится вектором на весь проход
				__m128i state = _mm_loadu_si128(reinterpret_cast <const __m128i *> (record));
				// Первый раундовый ключ
				const __m128i first = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys));
				// Последний раундовый ключ
				const __m128i last = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16)));
				// Старшие восемь байтов блока счётчика числом машины: не меняются
				uint64_t head = 0;
				// Читаем старшие восемь байтов блока счётчика
				::memcpy(&head, counter, sizeof(head));
				// Номер блока счётчика от старшего байта: у блока A_1 равен единице
				uint64_t tail = 0;
				/**
				 * Читаем младшие восемь байтов блока счётчика от старшего байта
				 */
				for(size_t i = 0; i < 8; i++)
					// Добавляем очередной байт номера
					tail = ((tail << 8) | static_cast <uint64_t> (counter[8 + i]));
				// Гамма первого блока: блок счётчика A_1 под первым ключом
				__m128i stream = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (counter)), first);
				/**
				 * Выполняем внутренние круги шифрования гаммы первого блока
				 */
				for(size_t round = 1; round < rounds; round++)
					// Выполняем очередной круг
					stream = _mm_aesenc_si128(stream, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16))));
				// Завершаем шифрование гаммы первого блока
				stream = _mm_aesenclast_si128(stream, last);
				/**
				 * Выполняем перебор блоков сообщения
				 */
				for(size_t b = 0; b < blocks; b++){
					// Открытый текст блока: при расшифровании снимается гаммой текущего блока
					const __m128i plain = (sealing ? _mm_loadu_si128(reinterpret_cast <const __m128i *> (source)) : _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (source)), stream));
					// Записываем итог блока: шифртекст при зашифровании, открытый текст при расшифровании
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result), (sealing ? _mm_xor_si128(plain, stream) : plain));
					// Блок счётчика гаммы следующего блока: номер растёт от старшего байта
					__m128i lane = _mm_xor_si128(_mm_set_epi64x(static_cast <int64_t> (__ANTS_BSWAP64__(tail + b + 1)), static_cast <int64_t> (head)), first);
					// Складываем открытый текст с состоянием имитовставки и первым ключом
					state = _mm_xor_si128(_mm_xor_si128(state, plain), first);
					/**
					 * Выполняем круги имитовставки и гаммы чередованием: круги гаммы заполняют ожидания кругов имитовставки
					 */
					for(size_t round = 1; round < rounds; round++){
						// Ключ круга
						const __m128i key = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16)));
						// Выполняем круг имитовставки
						state = _mm_aesenc_si128(state, key);
						// Выполняем круг гаммы следующего блока
						lane = _mm_aesenc_si128(lane, key);
					}
					// Завершаем круги имитовставки последним кругом без перемешивания
					state = _mm_aesenclast_si128(state, last);
					// Гамма следующего блока готова
					stream = _mm_aesenclast_si128(lane, last);
					// Сдвигаем позицию чтения
					source += 16;
					// Сдвигаем позицию записи
					result += 16;
				}
				// Записываем состояние имитовставки на место накопителя
				_mm_storeu_si128(reinterpret_cast <__m128i *> (record), state);
			}
		#endif

		/**
		 * @brief Функция слитного прохода целых блоков сообщения: имитовставка и гамма одним ходом
		 *
		 * @param block   базовый алгоритм блочного шифрования с расписанием команд машины
		 * @param nonce   одноразовое значение режима
		 * @param length  длина одноразового значения
		 * @param width   длина поля номера блока в байтах
		 * @param record  накопитель имитовставки: на входе значение после начала, на выходе после целых блоков
		 * @param source  сообщение: открытый текст при зашифровании, шифртекст при расшифровании
		 * @param result  место итога: шифртекст при зашифровании, открытый текст при расшифровании
		 * @param blocks  число целых блоков сообщения
		 * @param sealing признак зашифрования
		 *
		 */
		static void coupling(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, uint8_t * record, const uint8_t * source, uint8_t * result, const size_t blocks, const bool sealing) noexcept {
			// Блок счётчика A_1
			uint8_t item[16];
			// Собираем блок счётчика A_1
			counter(nonce, length, width, 1, item);
			/**
			 * Если есть ветвь команд AES расширения ARMv8
			 */
			#if defined(__ANTS_CCM_ARM__)
				// Выполняем слитный проход командами ARMv8
				fusedArm(block.schedule, block.rounds, record, item, sealing, source, result, blocks);
			/**
			 * Иначе слитный проход выполняется командами x86-64
			 */
			#else
				// Выполняем слитный проход командами x86-64
				fusedX86(block.schedule, block.rounds, record, item, sealing, source, result, blocks);
			#endif
			// Выполняем затирание блока счётчика
			wipe(item, sizeof(item));
		}
	#endif
};

/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Ccm::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param nonce начальное заполнение режима
 * @param size  длина метки целостности в байтах: чётная, от 4 до 16
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Ccm::start(const block_t & block, const view_t & nonce, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый шифр непригоден либо блок его не в 16 байтов
	if((block.cipher == nullptr) || (block.encrypt == nullptr) || (block.size != 16))
		// Выводим отказ запуска режима работы
		return false;
	// Если одноразовое значение не задано либо длины не той: от 7 до 13 байтов по разделу 4 RFC 3610
	if((nonce.data == nullptr) || (nonce.size < 7) || (nonce.size > 13))
		// Выводим отказ запуска режима работы
		return false;
	// Если длина метки целостности нечётна либо вне отрезка [4, 16]
	if(((size % 2) != 0) || (size < 4) || (size > 16))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем длину метки целостности
	this->_size = size;
	// Запоминаем длину поля длины сообщения: L = 15 - nonce
	this->_width = (15 - nonce.size);
	// Запоминаем длину начального заполнения
	this->_length = nonce.size;
	// Переносим начальное заполнение режима
	::memcpy(this->_nonce, nonce.data, nonce.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод смены начального заполнения режима
 *
 * @param nonce новое начальное заполнение режима
 * @return      признак успешности смены начального заполнения
 *
 */
bool nts::cipher::Ccm::restart(const view_t & nonce) noexcept {
	// Если режим не запущен либо одноразовое значение не той длины
	if(!this->_ready || (nonce.data == nullptr) || (nonce.size < 7) || (nonce.size > 13))
		// Выводим отказ смены заполнения
		return false;
	// Запоминаем длину поля длины сообщения: L = 15 - nonce
	this->_width = (15 - nonce.size);
	// Запоминаем длину начального заполнения
	this->_length = nonce.size;
	// Переносим начальное заполнение режима
	::memcpy(this->_nonce, nonce.data, nonce.size);
	// Выводим успешность смены заполнения
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Ccm::clear() noexcept {
	// Сбрасываем признак готовности режима к работе
	this->_ready = false;
	// Сбрасываем длину метки целостности
	this->_size = 0;
	// Сбрасываем длину поля длины сообщения
	this->_width = 0;
	// Сбрасываем длину начального заполнения
	this->_length = 0;
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
/**
 * @brief Метод зашифрования сообщения с выработкой метки целостности
 *
 * @param associated связанные данные
 * @param source     зашифровываемое сообщение
 * @param result     место, в которое помещается зашифрованное сообщение
 * @param tag        место, в которое помещается метка целостности
 * @return           признак успешности зашифрования
 *
 */
bool nts::cipher::Ccm::encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept {
	// Если режим не готов, либо сообщение не задано, либо места итогов не заданы
	if(!this->_ready || ((source.data == nullptr) && (source.size > 0)) || (result == nullptr) || (tag == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Если сообщение не укладывается в поле длины
	if((this->_width < 8) && (source.size >= (1ULL << (this->_width * 8))))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Если есть ветвь слитного прохода командами машины
	 */
	#if defined(__ANTS_CCM_ARM__) || defined(__ANTS_CCM_X86__)
		// Если базовый шифр несёт расписание для слитных ядер (AES с командами машины)
		if(this->_block.schedule != nullptr){
			// Значение имитовставки сообщения
			uint8_t value[16];
			// Если начало имитовставки выработать не удалось
			if(!heading(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, source.size, value)){
				// Выполняем затирание значения имитовставки
				wipe(value, sizeof(value));
				// Выводим отказ зашифрования
				return false;
			}
			// Число целых блоков сообщения
			const size_t whole = (source.size & ~static_cast <size_t> (0xF));
			// Целые блоки: имитовставка и гамма одним проходом
			if(whole > 0)
				// Выполняем слитный проход целых блоков
				coupling(this->_block, this->_nonce, this->_length, this->_width, value, source.data, result, whole >> 4, true);
			// Блок счётчика
			uint8_t item[16];
			// Гамма блока счётчика
			uint8_t stream[16];
			// Если остался неполный блок сообщения
			if(whole < source.size){
				// Собираем блок счётчика хвоста
				counter(this->_nonce, this->_length, this->_width, (whole >> 4) + 1, item);
				// Если гамму блока счётчика выработать не удалось
				if(!this->_block.encrypt(this->_block.cipher, item, stream)){
					// Выполняем затирание значения имитовставки
					wipe(value, sizeof(value));
					// Выполняем затирание блока счётчика
					wipe(item, sizeof(item));
					// Выводим отказ зашифрования
					return false;
				}
				/**
				 * Выполняем наложение гаммы на неполный блок сообщения
				 */
				for(size_t i = whole; i < source.size; i++)
					// Накладываем очередной байт гаммы на сообщение
					result[i] = static_cast <uint8_t> (source.data[i] ^ stream[i - whole]);
				// Готовим блок неполного блока с дополнением нулями
				::memset(item, 0, sizeof(item));
				// Переносим открытый текст хвоста в блок
				::memcpy(item, source.data + whole, source.size - whole);
				// Складываем блок с накопителем имитовставки
				add(value, item, item, 16);
				// Если последний блок зашифровать не удалось
				if(!this->_block.encrypt(this->_block.cipher, item, value)){
					// Выполняем затирание значения имитовставки
					wipe(value, sizeof(value));
					// Выполняем затирание блока счётчика
					wipe(item, sizeof(item));
					// Выполняем затирание гаммы блока
					wipe(stream, sizeof(stream));
					// Выводим отказ зашифрования
					return false;
				}
			}
			// Собираем блок счётчика A_0
			counter(this->_nonce, this->_length, this->_width, 0, item);
			// Если гамму блока A_0 выработать не удалось
			if(!this->_block.encrypt(this->_block.cipher, item, stream)){
				// Выполняем затирание значения имитовставки
				wipe(value, sizeof(value));
				// Выполняем затирание блока счётчика
				wipe(item, sizeof(item));
				// Выполняем затирание гаммы блока
				wipe(stream, sizeof(stream));
				// Выводим отказ зашифрования
				return false;
			}
			/**
			 * Выполняем наложение гаммы блока A_0 на метку целостности
			 */
			for(size_t i = 0; i < this->_size; i++)
				// Накладываем очередной байт гаммы на метку
				tag[i] = static_cast <uint8_t> (value[i] ^ stream[i]);
			// Выполняем затирание значения имитовставки
			wipe(value, sizeof(value));
			// Выполняем затирание блока счётчика
			wipe(item, sizeof(item));
			// Выполняем затирание гаммы блока
			wipe(stream, sizeof(stream));
			// Выводим успешность зашифрования
			return true;
		}
	#endif
	// Значение имитовставки сообщения
	uint8_t value[16];
	// Если имитовставку выработать не удалось
	if(!mac(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, source, value))
		// Выводим отказ зашифрования
		return false;
	// Если гамму на сообщение наложить не удалось
	if(!gamma(this->_block, this->_nonce, this->_length, this->_width, source, result)){
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выводим отказ зашифрования
		return false;
	}
	// Блок счётчика A_0
	uint8_t item[16];
	// Гамма блока A_0
	uint8_t stream[16];
	// Собираем блок счётчика A_0
	counter(this->_nonce, this->_length, this->_width, 0, item);
	// Если гамму блока A_0 выработать не удалось
	if(!this->_block.encrypt(this->_block.cipher, item, stream)){
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выполняем затирание блока счётчика
		wipe(item, sizeof(item));
		// Выводим отказ зашифрования
		return false;
	}
	/**
	 * Выполняем наложение гаммы блока A_0 на метку целостности
	 */
	for(size_t i = 0; i < this->_size; i++)
		// Накладываем очередной байт гаммы на метку
		tag[i] = static_cast <uint8_t> (value[i] ^ stream[i]);
	// Выполняем затирание значения имитовставки
	wipe(value, sizeof(value));
	// Выполняем затирание блока счётчика
	wipe(item, sizeof(item));
	// Выполняем затирание гаммы блока
	wipe(stream, sizeof(stream));
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения с проверкой метки целостности
 *
 * @param associated связанные данные
 * @param source     расшифровываемое сообщение
 * @param tag        проверяемая метка целостности
 * @param result     место, в которое помещается расшифрованное сообщение
 * @return           признак того, что метка целостности сошлась
 *
 */
bool nts::cipher::Ccm::decrypt(const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) noexcept {
	// Если режим не готов, либо сообщение не задано, либо метка не той длины, либо место итога не задано
	if(!this->_ready || ((source.data == nullptr) && (source.size > 0)) || (tag.data == nullptr) || (tag.size != this->_size) || (result == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Если сообщение не укладывается в поле длины
	if((this->_width < 8) && (source.size >= (1ULL << (this->_width * 8))))
		// Выводим отказ расшифрования
		return false;
	/**
	 * Если есть ветвь слитного прохода командами машины
	 */
	#if defined(__ANTS_CCM_ARM__) || defined(__ANTS_CCM_X86__)
		// Если базовый шифр несёт расписание для слитных ядер (AES с командами машины)
		if(this->_block.schedule != nullptr){
			// Значение имитовставки сообщения
			uint8_t value[16];
			// Если начало имитовставки выработать не удалось
			if(!heading(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, source.size, value)){
				// Выполняем затирание значения имитовставки
				wipe(value, sizeof(value));
				// Выводим отказ расшифрования
				return false;
			}
			// Число целых блоков сообщения
			const size_t whole = (source.size & ~static_cast <size_t> (0xF));
			// Целые блоки: открытие гаммой и имитовставка одним проходом
			if(whole > 0)
				// Выполняем слитный проход целых блоков
				coupling(this->_block, this->_nonce, this->_length, this->_width, value, source.data, result, whole >> 4, false);
			// Блок счётчика
			uint8_t item[16];
			// Гамма блока счётчика
			uint8_t stream[16];
			// Если остался неполный блок сообщения
			if(whole < source.size){
				// Собираем блок счётчика хвоста
				counter(this->_nonce, this->_length, this->_width, (whole >> 4) + 1, item);
				// Если гамму блока счётчика выработать не удалось
				if(!this->_block.encrypt(this->_block.cipher, item, stream)){
					// Выполняем затирание расшифрованного сообщения
					wipe(result, source.size);
					// Выполняем затирание значения имитовставки
					wipe(value, sizeof(value));
					// Выполняем затирание блока счётчика
					wipe(item, sizeof(item));
					// Выводим отказ расшифрования
					return false;
				}
				/**
				 * Выполняем наложение гаммы на неполный блок сообщения
				 */
				for(size_t i = whole; i < source.size; i++)
					// Накладываем очередной байт гаммы на сообщение
					result[i] = static_cast <uint8_t> (source.data[i] ^ stream[i - whole]);
				// Готовим блок неполного блока с дополнением нулями
				::memset(item, 0, sizeof(item));
				// Переносим открытый текст хвоста в блок
				::memcpy(item, result + whole, source.size - whole);
				// Складываем блок с накопителем имитовставки
				add(value, item, item, 16);
				// Если последний блок зашифровать не удалось
				if(!this->_block.encrypt(this->_block.cipher, item, value)){
					// Выполняем затирание расшифрованного сообщения
					wipe(result, source.size);
					// Выполняем затирание значения имитовставки
					wipe(value, sizeof(value));
					// Выполняем затирание блока счётчика
					wipe(item, sizeof(item));
					// Выполняем затирание гаммы блока
					wipe(stream, sizeof(stream));
					// Выводим отказ расшифрования
					return false;
				}
			}
			// Собираем блок счётчика A_0
			counter(this->_nonce, this->_length, this->_width, 0, item);
			// Если гамму блока A_0 выработать не удалось
			if(!this->_block.encrypt(this->_block.cipher, item, stream)){
				// Выполняем затирание расшифрованного сообщения
				wipe(result, source.size);
				// Выполняем затирание значения имитовставки
				wipe(value, sizeof(value));
				// Выполняем затирание блока счётчика
				wipe(item, sizeof(item));
				// Выводим отказ расшифрования
				return false;
			}
			// Накопленное различие метки целостности
			uint8_t difference = 0;
			/**
			 * Выполняем сличение метки целостности за постоянное время
			 */
			for(size_t i = 0; i < this->_size; i++)
				// Накапливаем различие очередных байтов метки
				difference |= static_cast <uint8_t> (tag.data[i] ^ (value[i] ^ stream[i]));
			// Выполняем затирание значения имитовставки
			wipe(value, sizeof(value));
			// Выполняем затирание блока счётчика
			wipe(item, sizeof(item));
			// Выполняем затирание гаммы блока
			wipe(stream, sizeof(stream));
			// Если метка целостности не сошлась
			if(difference != 0){
				// Выполняем затирание расшифрованного сообщения
				wipe(result, source.size);
				// Выводим отказ расшифрования
				return false;
			}
			// Выводим успешность расшифрования
			return true;
		}
	#endif
	// Если гамму на сообщение наложить не удалось
	if(!gamma(this->_block, this->_nonce, this->_length, this->_width, source, result))
		// Выводим отказ расшифрования
		return false;
	// Значение имитовставки расшифрованного сообщения
	uint8_t value[16];
	// Если имитовставку выработать не удалось
	if(!mac(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, view_t(result, source.size), value)){
		// Выполняем затирание расшифрованного сообщения
		wipe(result, source.size);
		// Выводим отказ расшифрования
		return false;
	}
	// Блок счётчика A_0
	uint8_t item[16];
	// Гамма блока A_0
	uint8_t stream[16];
	// Собираем блок счётчика A_0
	counter(this->_nonce, this->_length, this->_width, 0, item);
	// Если гамму блока A_0 выработать не удалось
	if(!this->_block.encrypt(this->_block.cipher, item, stream)){
		// Выполняем затирание расшифрованного сообщения
		wipe(result, source.size);
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выполняем затирание блока счётчика
		wipe(item, sizeof(item));
		// Выводим отказ расшифрования
		return false;
	}
	// Накопленное различие метки целостности
	uint8_t difference = 0;
	/**
	 * Выполняем сличение метки целостности за постоянное время
	 */
	for(size_t i = 0; i < this->_size; i++)
		// Накапливаем различие очередных байтов метки
		difference |= static_cast <uint8_t> (tag.data[i] ^ (value[i] ^ stream[i]));
	// Выполняем затирание значения имитовставки
	wipe(value, sizeof(value));
	// Выполняем затирание блока счётчика
	wipe(item, sizeof(item));
	// Выполняем затирание гаммы блока
	wipe(stream, sizeof(stream));
	// Если метка целостности не сошлась
	if(difference != 0){
		// Выполняем затирание расшифрованного сообщения
		wipe(result, source.size);
		// Выводим отказ расшифрования
		return false;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Ccm::Ccm() noexcept : _ready(false), _size(0), _width(0), _length(0) {
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Ccm::~Ccm() noexcept {
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
