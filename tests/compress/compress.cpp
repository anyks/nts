/**
 * @file compress.cpp
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
 * @brief Исходный файл проверок сжатия цепочки сертификатов по RFC 8879: кодеки потребителя
 *        (zlib со «stored»-блоками по RFC 1950 и RFC 1951, частный алгоритм 16384),
 *        петлевые рукопожатия по записям и по уровням в обе стороны, выбор общего алгоритма
 *        по порядку клиента, отказы сжатия и распаковки, обмен с настоящим openssl и
 *        нехватка памяти
 *
 * @note Библиотека алгоритмов сжатия не несёт: кодеки здесь принадлежат проверке и служат
 *       образцом того, что предоставляет потребитель. Кодек zlib складывает поток без
 *       сжатия («stored»-блоки), а разбирает полный DEFLATE (и коды Хаффмана), чтобы
 *       принимать цепочки, сжатые настоящим zlib у openssl
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <field/field.hpp>
#include <message/message.hpp>
#include <handshake/handshake.hpp>
#include <protect/protect.hpp>
#include <extension/extension.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Опознаватель частного алгоритма сжатия по разделу 7.3 RFC 8879
	 */
	static constexpr uint16_t PRIVATE = 16384;
	/**
	 * Опознаватель алгоритма, неведомого ни одной стороне: пропускается молча
	 */
	static constexpr uint16_t STRANGER = 0x7777;
	/**
	 * Опознаватель zlib по реестру RFC 8879
	 */
	static constexpr uint16_t ZLIB = static_cast <uint16_t> (extension::compression_t::ZLIB);
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> slurp(const std::string & path) noexcept {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое файла
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Метод записи файла целиком
	 *
	 * @param path путь к файлу
	 * @param data записываемое содержимое
	 *
	 * @return     признак успешности записи
	 *
	 */
	bool spill(const std::string & path, const vector <uint8_t> & data) noexcept {
		// Открываем файл на запись
		std::ofstream file(path, std::ios::binary);
		// Если файл не открыт
		if(!file.is_open())
			// Выводим отказ записи
			return false;
		// Записываем содержимое
		file.write(reinterpret_cast <const char *> (data.data()), static_cast <std::streamsize> (data.size()));
		// Выводим успешность записи
		return file.good();
	}
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Выводим содержимое файла набора
		return slurp(std::string(CORPUS) + "/" + name);
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора: rsa2048, ec256, ec384 либо ed25519
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод вычисления суммы Adler-32 по RFC 1950
	 *
	 * @param data область байтов
	 *
	 * @return     сумма Adler-32
	 *
	 */
	uint32_t adler(const view_t & data) noexcept {
		// Младшая половина суммы
		uint32_t a = 1;
		// Старшая половина суммы
		uint32_t b = 0;
		/**
		 * Выполняем перебор байтов области
		 */
		for(size_t i = 0; i < data.size; i++){
			// Наращиваем младшую половину по модулю 65521
			a = ((a + data.data[i]) % 65521);
			// Наращиваем старшую половину по модулю 65521
			b = ((b + a) % 65521);
		}
		// Выводим сумму Adler-32
		return ((b << 16) | a);
	}
	/**
	 * @brief Кодек zlib со «stored»-блоками: сжатие
	 *
	 * @details RFC 1950: голова CMF/FLG без словаря, тело DEFLATE по RFC 1951 из блоков
	 *          BTYPE=00 до 65535 байтов каждый, хвост Adler-32 старшим байтом вперёд.
	 *          Поток без сжатия, но всякий настоящий zlib его разбирает
	 *
	 * @param source сжимаемая область байтов
	 * @param result накопитель сжатого потока
	 * @param context указатель контекста потребителя (не используется)
	 *
	 * @return       признак успешности сжатия
	 *
	 */
	bool stored(const view_t & source, vector <uint8_t> & result, void * context) {
		// Контекст кодеку не нужен
		(void) context;
		// Голова потока zlib: CM=8, CINFO=7, FLEVEL=0, без словаря, FCHECK=1 (0x7801 кратно 31)
		result.push_back(0x78);
		// Второй байт головы потока
		result.push_back(0x01);
		// Смещение очередного блока
		size_t offset = 0;
		/**
		 * Выполняем нарезку области на «stored»-блоки
		 */
		do {
			// Длина очередного блока: не более 65535 байтов
			const size_t length = (((source.size - offset) > 65535) ? 65535 : (source.size - offset));
			// Признак последнего блока
			const bool final = ((offset + length) >= source.size);
			// Голова блока: BFINAL в младшем разряде, BTYPE=00
			result.push_back(final ? 0x01 : 0x00);
			// Длина блока младшим байтом вперёд
			result.push_back(static_cast <uint8_t> (length & 0xFF));
			// Старший байт длины блока
			result.push_back(static_cast <uint8_t> ((length >> 8) & 0xFF));
			// Дополнение длины блока младшим байтом вперёд
			result.push_back(static_cast <uint8_t> ((~length) & 0xFF));
			// Старший байт дополнения длины блока
			result.push_back(static_cast <uint8_t> (((~length) >> 8) & 0xFF));
			// Дописываем содержимое блока как есть
			result.insert(result.end(), source.data + offset, source.data + offset + length);
			// Сдвигаем смещение на длину блока
			offset += length;
		} while(offset < source.size);
		// Сумма Adler-32 области
		const uint32_t sum = adler(source);
		// Хвост потока: сумма старшим байтом вперёд
		result.push_back(static_cast <uint8_t> ((sum >> 24) & 0xFF));
		// Второй байт суммы
		result.push_back(static_cast <uint8_t> ((sum >> 16) & 0xFF));
		// Третий байт суммы
		result.push_back(static_cast <uint8_t> ((sum >> 8) & 0xFF));
		// Младший байт суммы
		result.push_back(static_cast <uint8_t> (sum & 0xFF));
		// Выводим успешность сжатия
		return true;
	}
	/**
	 * @brief Чтение потока DEFLATE по разрядам младшим вперёд (RFC 1951, раздел 3.1.1)
	 *
	 */
	typedef struct Bits {
		// Читаемый поток
		const uint8_t * data;
		// Длина потока
		size_t size;
		// Смещение байта
		size_t offset;
		// Накопитель разрядов
		uint32_t hoard;
		// Число разрядов в накопителе
		size_t count;
		/**
		 * @brief Конструктор
		 *
		 * @param data читаемый поток
		 * @param size длина потока
		 *
		 */
		Bits(const uint8_t * data, const size_t size) noexcept : data(data), size(size), offset(0), hoard(0), count(0) {}
		/**
		 * @brief Метод чтения числа разрядов
		 *
		 * @param need   число читаемых разрядов, не более 16
		 * @param result место, куда помещается прочитанное
		 *
		 * @return       признак того, что разрядов хватило
		 *
		 */
		bool take(const size_t need, uint32_t & result) noexcept {
			/**
			 * Выполняем добор разрядов из байтов потока
			 */
			while(this->count < need){
				// Если байты потока кончились
				if(this->offset >= this->size)
					// Выводим отказ чтения
					return false;
				// Дописываем очередной байт в накопитель
				this->hoard |= (static_cast <uint32_t> (this->data[this->offset++]) << this->count);
				// Наращиваем число разрядов
				this->count += 8;
			}
			// Выдаём младшие разряды накопителя
			result = (this->hoard & ((1u << need) - 1));
			// Сдвигаем накопитель
			this->hoard >>= need;
			// Уменьшаем число разрядов
			this->count -= need;
			// Выводим успешность чтения
			return true;
		}
		/**
		 * @brief Метод сброса разрядов до границы байта
		 *
		 */
		void align() noexcept {
			// Сбрасываем накопитель
			this->hoard = 0;
			// Сбрасываем число разрядов
			this->count = 0;
		}
	} bits_t;
	/**
	 * @brief Каноническое дерево Хаффмана по счёту длин кодов (RFC 1951, раздел 3.2.2)
	 *
	 */
	typedef struct Huffman {
		// Число кодов всякой длины от 0 до 15
		uint16_t counts[16];
		// Символы в порядке кодов
		uint16_t symbols[320];
		/**
		 * @brief Метод построения дерева по длинам кодов
		 *
		 * @param lengths длины кодов символов
		 * @param size    число символов
		 *
		 * @return        признак того, что набор длин полон либо неполон, но не переполнен
		 *
		 */
		bool build(const uint16_t * lengths, const size_t size) noexcept {
			/**
			 * Выполняем обнуление счёта длин
			 */
			for(size_t i = 0; i < 16; i++)
				// Обнуляем счёт очередной длины
				this->counts[i] = 0;
			/**
			 * Выполняем счёт кодов всякой длины
			 */
			for(size_t i = 0; i < size; i++)
				// Наращиваем счёт длины очередного символа
				this->counts[lengths[i]]++;
			// Если ни одного кода нет
			if(this->counts[0] == size)
				// Дерево пусто, но не переполнено
				return true;
			// Остаток кодов на очередной длине
			int left = 1;
			/**
			 * Выполняем проверку переполнения набора кодов
			 */
			for(size_t i = 1; i < 16; i++){
				// Удваиваем остаток
				left <<= 1;
				// Вычитаем коды этой длины
				left -= this->counts[i];
				// Если кодов больше, чем помещается
				if(left < 0)
					// Выводим отказ построения
					return false;
			}
			// Смещения символов по длинам
			uint16_t offsets[16];
			// Смещение первой длины
			offsets[1] = 0;
			/**
			 * Выполняем счёт смещений
			 */
			for(size_t i = 1; i < 15; i++)
				// Смещение следующей длины
				offsets[i + 1] = static_cast <uint16_t> (offsets[i] + this->counts[i]);
			/**
			 * Выполняем раскладку символов по кодам
			 */
			for(size_t i = 0; i < size; i++){
				// Если у символа есть код
				if(lengths[i] != 0)
					// Кладём символ на своё место
					this->symbols[offsets[lengths[i]]++] = static_cast <uint16_t> (i);
			}
			// Выводим успешность построения
			return true;
		}
		/**
		 * @brief Метод разбора одного символа из потока
		 *
		 * @param bits   читаемый поток
		 * @param result место, куда помещается символ
		 *
		 * @return       признак успешности разбора
		 *
		 */
		bool decode(bits_t & bits, uint16_t & result) const noexcept {
			// Код, собираемый разряд за разрядом
			int code = 0;
			// Первый код текущей длины
			int first = 0;
			// Смещение символов текущей длины
			int index = 0;
			/**
			 * Выполняем перебор длин кодов
			 */
			for(size_t length = 1; length < 16; length++){
				// Очередной разряд
				uint32_t bit = 0;
				// Если разряд прочитать не удалось
				if(!bits.take(1, bit))
					// Выводим отказ разбора
					return false;
				// Дописываем разряд к коду
				code |= static_cast <int> (bit);
				// Число кодов этой длины
				const int count = this->counts[length];
				// Если код попал в коды этой длины
				if((code - count) < first){
					// Выводим символ
					result = this->symbols[index + (code - first)];
					// Выводим успешность разбора
					return true;
				}
				// Сдвигаем смещение символов
				index += count;
				// Сдвигаем первый код
				first += count;
				// Удваиваем первый код
				first <<= 1;
				// Удваиваем код
				code <<= 1;
			}
			// Выводим отказ разбора
			return false;
		}
	} huffman_t;
	/**
	 * Основания длин совпадений по разделу 3.2.5 RFC 1951
	 */
	static const uint16_t LENGTH_BASE[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
	/**
	 * Дополнительные разряды длин совпадений
	 */
	static const uint16_t LENGTH_EXTRA[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
	/**
	 * Основания расстояний совпадений
	 */
	static const uint16_t DISTANCE_BASE[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
	/**
	 * Дополнительные разряды расстояний совпадений
	 */
	static const uint16_t DISTANCE_EXTRA[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
	/**
	 * Порядок длин кодов длин кодов по разделу 3.2.7 RFC 1951
	 */
	static const uint8_t ORDER[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
	/**
	 * @brief Метод разбора сжатого блока деревьями литералов и расстояний
	 *
	 * @param bits      читаемый поток
	 * @param literals  дерево литералов и длин
	 * @param distances дерево расстояний
	 * @param expected  предел длины распакованного
	 * @param result    накопитель распакованной области
	 *
	 * @return          признак успешности разбора
	 *
	 */
	bool codes(bits_t & bits, const huffman_t & literals, const huffman_t & distances, const size_t expected, vector <uint8_t> & result) {
		/**
		 * Выполняем разбор символов до конца блока
		 */
		while(true){
			// Очередной символ
			uint16_t symbol = 0;
			// Если символ разобрать не удалось
			if(!literals.decode(bits, symbol))
				// Выводим отказ разбора
				return false;
			// Если это литерал
			if(symbol < 256){
				// Если распакованное превысило ожидаемое
				if(result.size() >= expected)
					// Выводим отказ разбора
					return false;
				// Дописываем литерал
				result.push_back(static_cast <uint8_t> (symbol));
				// Переходим к следующему символу
				continue;
			}
			// Если это конец блока
			if(symbol == 256)
				// Выводим успешность разбора
				return true;
			// Место длины в таблице
			symbol = static_cast <uint16_t> (symbol - 257);
			// Если длина вне таблицы
			if(symbol >= 29)
				// Выводим отказ разбора
				return false;
			// Дополнительные разряды длины
			uint32_t extra = 0;
			// Если дополнительные разряды прочитать не удалось
			if(!bits.take(LENGTH_EXTRA[symbol], extra))
				// Выводим отказ разбора
				return false;
			// Длина совпадения
			const size_t length = (LENGTH_BASE[symbol] + extra);
			// Символ расстояния
			uint16_t code = 0;
			// Если символ расстояния разобрать не удалось
			if(!distances.decode(bits, code) || (code >= 30))
				// Выводим отказ разбора
				return false;
			// Если дополнительные разряды расстояния прочитать не удалось
			if(!bits.take(DISTANCE_EXTRA[code], extra))
				// Выводим отказ разбора
				return false;
			// Расстояние совпадения
			const size_t distance = (DISTANCE_BASE[code] + extra);
			// Если расстояние уходит раньше начала либо длина превышает ожидаемое
			if((distance > result.size()) || ((result.size() + length) > expected))
				// Выводим отказ разбора
				return false;
			/**
			 * Выполняем копирование совпадения байт за байтом: оно вправе перекрываться
			 */
			for(size_t i = 0; i < length; i++)
				// Дописываем байт из прошлого
				result.push_back(result[result.size() - distance]);
		}
	}
	/**
	 * @brief Метод распаковки потока DEFLATE по RFC 1951: блоки «stored», с постоянными и с
	 *        порождаемыми кодами Хаффмана
	 *
	 * @param source   распаковываемый поток
	 * @param expected ожидаемая длина после распаковки
	 * @param result   накопитель распакованной области
	 * @param consumed место, куда помещается число прочитанных байтов
	 *
	 * @return         признак успешности распаковки
	 *
	 */
	bool inflate(const view_t & source, const size_t expected, vector <uint8_t> & result, size_t & consumed) {
		// Читаемый поток
		bits_t bits(source.data, source.size);
		// Признак последнего блока
		bool final = false;
		/**
		 * Выполняем перебор блоков потока
		 */
		while(!final){
			// Голова блока
			uint32_t head = 0;
			// Если голову блока прочитать не удалось
			if(!bits.take(3, head))
				// Выводим отказ распаковки
				return false;
			// Запоминаем признак последнего блока
			final = ((head & 0x01) != 0);
			// Вид блока
			const uint32_t kind = ((head >> 1) & 0x03);
			// Если блок «stored»
			if(kind == 0){
				// Сбрасываем разряды до границы байта
				bits.align();
				// Если голова блока не вмещается
				if((bits.offset + 4) > bits.size)
					// Выводим отказ распаковки
					return false;
				// Длина блока
				const size_t length = (static_cast <size_t> (bits.data[bits.offset]) | (static_cast <size_t> (bits.data[bits.offset + 1]) << 8));
				// Дополнение длины блока
				const size_t complement = (static_cast <size_t> (bits.data[bits.offset + 2]) | (static_cast <size_t> (bits.data[bits.offset + 3]) << 8));
				// Если дополнение длины не сошлось
				if((length ^ complement) != 0xFFFF)
					// Выводим отказ распаковки
					return false;
				// Сдвигаем смещение за голову блока
				bits.offset += 4;
				// Если содержимое блока не вмещается либо превышает ожидаемое
				if(((bits.offset + length) > bits.size) || ((result.size() + length) > expected))
					// Выводим отказ распаковки
					return false;
				// Дописываем содержимое блока
				result.insert(result.end(), bits.data + bits.offset, bits.data + bits.offset + length);
				// Сдвигаем смещение за содержимое блока
				bits.offset += length;
				// Переходим к следующему блоку
				continue;
			}
			// Если вид блока запрещён
			if(kind == 3)
				// Выводим отказ распаковки
				return false;
			// Длины кодов литералов и расстояний
			uint16_t lengths[320];
			// Дерево литералов
			huffman_t literals;
			// Дерево расстояний
			huffman_t distances;
			// Если блок с постоянными кодами
			if(kind == 1){
				/**
				 * Раздел 3.2.6 RFC 1951: длины постоянных кодов литералов
				 */
				for(size_t i = 0; i < 288; i++)
					// Длина очередного кода: 8 до 143, 9 до 255, 7 до 279, 8 до 287
					lengths[i] = static_cast <uint16_t> ((i < 144) ? 8 : ((i < 256) ? 9 : ((i < 280) ? 7 : 8)));
				// Строим дерево литералов
				(void) literals.build(lengths, 288);
				/**
				 * Длины постоянных кодов расстояний: пять разрядов у всех
				 */
				for(size_t i = 0; i < 30; i++)
					// Длина очередного кода расстояния
					lengths[i] = 5;
				// Строим дерево расстояний
				(void) distances.build(lengths, 30);
			// Если блок с порождаемыми кодами
			} else {
				// Число кодов литералов, расстояний и длин кодов
				uint32_t nlen = 0, ndist = 0, ncode = 0;
				// Если счёт кодов прочитать не удалось
				if(!bits.take(5, nlen) || !bits.take(5, ndist) || !bits.take(4, ncode))
					// Выводим отказ распаковки
					return false;
				// Число кодов литералов
				nlen += 257;
				// Число кодов расстояний
				ndist += 1;
				// Число кодов длин кодов
				ncode += 4;
				// Если счёт кодов вне пределов
				if((nlen > 286) || (ndist > 30))
					// Выводим отказ распаковки
					return false;
				/**
				 * Выполняем обнуление длин кодов длин кодов
				 */
				for(size_t i = 0; i < 19; i++)
					// Обнуляем очередную длину
					lengths[i] = 0;
				/**
				 * Выполняем чтение длин кодов длин кодов в установленном порядке
				 */
				for(size_t i = 0; i < ncode; i++){
					// Очередная длина
					uint32_t value = 0;
					// Если длину прочитать не удалось
					if(!bits.take(3, value))
						// Выводим отказ распаковки
						return false;
					// Запоминаем длину на своём месте
					lengths[ORDER[i]] = static_cast <uint16_t> (value);
				}
				// Дерево длин кодов
				huffman_t codelens;
				// Если дерево длин кодов построить не удалось
				if(!codelens.build(lengths, 19))
					// Выводим отказ распаковки
					return false;
				// Число прочитанных длин
				size_t index = 0;
				/**
				 * Выполняем чтение длин кодов литералов и расстояний
				 */
				while(index < (nlen + ndist)){
					// Очередной символ длины
					uint16_t symbol = 0;
					// Если символ разобрать не удалось
					if(!codelens.decode(bits, symbol))
						// Выводим отказ распаковки
						return false;
					// Если это сама длина
					if(symbol < 16){
						// Запоминаем длину
						lengths[index++] = symbol;
						// Переходим к следующему символу
						continue;
					}
					// Повторяемая длина
					uint16_t repeated = 0;
					// Число повторов
					uint32_t repeats = 0;
					// Если повторяется предыдущая длина
					if(symbol == 16){
						// Если предыдущей длины нет
						if(index == 0)
							// Выводим отказ распаковки
							return false;
						// Берём предыдущую длину
						repeated = lengths[index - 1];
						// Если число повторов прочитать не удалось
						if(!bits.take(2, repeats))
							// Выводим отказ распаковки
							return false;
						// Число повторов от трёх
						repeats += 3;
					// Если повторяется нулевая длина
					} else if(symbol == 17){
						// Если число повторов прочитать не удалось
						if(!bits.take(3, repeats))
							// Выводим отказ распаковки
							return false;
						// Число повторов от трёх
						repeats += 3;
					// Если повторяется нулевая длина много раз
					} else {
						// Если число повторов прочитать не удалось
						if(!bits.take(7, repeats))
							// Выводим отказ распаковки
							return false;
						// Число повторов от одиннадцати
						repeats += 11;
					}
					// Если повторы выходят за счёт кодов
					if((index + repeats) > (nlen + ndist))
						// Выводим отказ распаковки
						return false;
					/**
					 * Выполняем запись повторов
					 */
					while(repeats-- > 0)
						// Запоминаем повторяемую длину
						lengths[index++] = repeated;
				}
				// Если у конца блока нет кода
				if(lengths[256] == 0)
					// Выводим отказ распаковки
					return false;
				// Если дерево литералов построить не удалось
				if(!literals.build(lengths, nlen))
					// Выводим отказ распаковки
					return false;
				// Если дерево расстояний построить не удалось
				if(!distances.build(lengths + nlen, ndist))
					// Выводим отказ распаковки
					return false;
			}
			// Если сжатый блок разобрать не удалось
			if(!codes(bits, literals, distances, expected, result))
				// Выводим отказ распаковки
				return false;
		}
		// Прочитанные байты: недобранные разряды накопителя возвращаются потоку
		consumed = (bits.offset - (bits.count / 8));
		// Выводим успешность распаковки
		return true;
	}
	/**
	 * @brief Кодек zlib: распаковка потока RFC 1950 с телом DEFLATE по RFC 1951
	 *
	 * @details Голова с чужим способом либо словарём и несошедшаяся сумма отвергаются;
	 *          тело разбирается полным разборщиком DEFLATE, чтобы принимать и потоки
	 *          настоящего zlib с кодами Хаффмана, а не одни «stored»-блоки
	 *
	 * @param source   распаковываемый поток
	 * @param expected ожидаемая длина после распаковки
	 * @param result   накопитель распакованной области
	 * @param context  указатель контекста потребителя (не используется)
	 *
	 * @return         признак успешности распаковки
	 *
	 */
	bool unstored(const view_t & source, const size_t expected, vector <uint8_t> & result, void * context) {
		// Контекст кодеку не нужен
		(void) context;
		// Если поток короче головы и хвоста
		if(source.size < 6)
			// Выводим отказ распаковки
			return false;
		// Если способ сжатия не DEFLATE либо объявлен словарь либо проверка головы не сошлась
		if(((source.data[0] & 0x0F) != 8) || ((source.data[1] & 0x20) != 0) || ((((source.data[0] << 8) | source.data[1]) % 31) != 0))
			// Выводим отказ распаковки
			return false;
		// Число прочитанных байтов тела
		size_t consumed = 0;
		// Если тело DEFLATE разобрать не удалось
		if(!inflate(view_t(source.data + 2, source.size - 6), expected, result, consumed))
			// Выводим отказ распаковки
			return false;
		// Если за телом идёт не только хвост
		if((consumed + 6) != source.size)
			// Выводим отказ распаковки
			return false;
		// Смещение хвоста
		const size_t offset = (source.size - 4);
		// Объявленная сумма Adler-32
		const uint32_t declared = ((static_cast <uint32_t> (source.data[offset]) << 24) | (static_cast <uint32_t> (source.data[offset + 1]) << 16) | (static_cast <uint32_t> (source.data[offset + 2]) << 8) | static_cast <uint32_t> (source.data[offset + 3]));
		// Выводим схождение суммы распакованной области с объявленной
		return (adler(view_t(result.data(), result.size())) == declared);
	}
	/**
	 * @brief Частный кодек 16384: сжатие обратимым преобразованием
	 *
	 * @param source  сжимаемая область байтов
	 * @param result  накопитель сжатого потока
	 * @param context указатель контекста потребителя: счётчик вызовов
	 *
	 * @return        признак успешности сжатия
	 *
	 */
	bool scramble(const view_t & source, vector <uint8_t> & result, void * context) {
		// Если счётчик вызовов передан
		if(context != nullptr)
			// Наращиваем счётчик вызовов
			(*static_cast <size_t *> (context))++;
		// Метка потока частного кодека
		result.push_back(0xA5);
		/**
		 * Выполняем перебор байтов области
		 */
		for(size_t i = 0; i < source.size; i++)
			// Дописываем байт, обращённый исключающим ИЛИ
			result.push_back(static_cast <uint8_t> (source.data[i] ^ 0x5A));
		// Выводим успешность сжатия
		return true;
	}
	/**
	 * @brief Частный кодек 16384: распаковка обратимым преобразованием
	 *
	 * @param source   распаковываемый поток
	 * @param expected ожидаемая длина после распаковки
	 * @param result   накопитель распакованной области
	 * @param context  указатель контекста потребителя: счётчик вызовов
	 *
	 * @return         признак успешности распаковки
	 *
	 */
	bool unscramble(const view_t & source, const size_t expected, vector <uint8_t> & result, void * context) {
		// Если счётчик вызовов передан
		if(context != nullptr)
			// Наращиваем счётчик вызовов
			(*static_cast <size_t *> (context))++;
		// Если метка потока не сошлась либо длина не отвечает ожидаемой
		if((source.size < 1) || (source.data[0] != 0xA5) || ((source.size - 1) != expected))
			// Выводим отказ распаковки
			return false;
		/**
		 * Выполняем перебор байтов потока за меткой
		 */
		for(size_t i = 1; i < source.size; i++)
			// Дописываем байт, обращённый исключающим ИЛИ
			result.push_back(static_cast <uint8_t> (source.data[i] ^ 0x5A));
		// Выводим успешность распаковки
		return true;
	}
	/**
	 * @brief Кодек, отказывающий сжимать: раздел 4 RFC 8879 дозволяет слать несжатое
	 *
	 * @param source  сжимаемая область байтов
	 * @param result  накопитель сжатого потока
	 * @param context указатель контекста потребителя
	 *
	 * @return        всегда отказ
	 *
	 */
	bool refusing(const view_t & source, vector <uint8_t> & result, void * context) {
		// Доводы кодеку не нужны
		(void) source; (void) result; (void) context;
		// Выводим отказ сжатия
		return false;
	}
	/**
	 * @brief Кодек, бросающий чужое исключение: связь обязана его удержать
	 *
	 * @param source  сжимаемая область байтов
	 * @param result  накопитель сжатого потока
	 * @param context указатель контекста потребителя
	 *
	 * @return        не выводит ничего: бросает
	 *
	 */
	bool throwing(const view_t & source, vector <uint8_t> & result, void * context) {
		// Доводы кодеку не нужны
		(void) source; (void) result; (void) context;
		// Бросаем чужое исключение
		throw std::runtime_error("codec");
	}
	/**
	 * @brief Метод получения описания кодека zlib
	 *
	 * @return описание кодека zlib
	 *
	 */
	context::codec_t zlib() noexcept {
		// Выводим описание кодека zlib
		return context::codec_t(ZLIB, stored, unstored);
	}
	/**
	 * @brief Метод получения описания частного кодека
	 *
	 * @param counter счётчик вызовов либо nullptr
	 *
	 * @return        описание частного кодека
	 *
	 */
	context::codec_t custom(size_t * counter) noexcept {
		// Выводим описание частного кодека
		return context::codec_t(PRIVATE, scramble, unscramble, counter);
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи по записям
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Получаем байты, отправляемые клиентом
			view_t data = client.output();
			// Если клиенту есть что отправить серверу
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
			// Получаем байты, отправляемые сервером
			data = server.output();
			// Если серверу есть что отправить клиенту
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя сервера
				server.consume(buffer.size());
				// Выполняем подачу отправленных байтов клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что байты между сторонами не передавались
			return false;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи по записям
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	}
	/**
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по связи со сжатой цепочкой сертификатов";
		// Если отправить прикладные данные клиентом не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если получить принятые сервером прикладные данные не удалось
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ по связи со сжатой цепочкой сертификатов";
		// Если отправить прикладные данные сервером не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Выполняем сброс накопителя принятых данных
		received.clear();
		// Если получить принятые клиентом прикладные данные не удалось
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Выводим отказ обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Метод настройки сторон связи
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param group      группа обмена обеих сторон
	 * @param credential подлинность сервера и клиента
	 * @param mutual     запрашивается ли подлинность клиента
	 * @param levels     ведётся ли перенос по уровням QUIC
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual, const bool levels) noexcept {
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {suite});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {suite});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {group});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {group});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Если запрашивается подлинность клиента
		if(mutual){
			// Запрашиваем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
		// Если ведётся перенос по уровням
		if(levels){
			// Устанавливаем перенос по уровням клиенту
			client.transport(context::transport_t::LEVELS);
			// Устанавливаем перенос по уровням серверу
			server.transport(context::transport_t::LEVELS);
			// Устанавливаем прикладной протокол клиенту
			client.protocols(vector <string> {"h3"});
			// Устанавливаем прикладной протокол серверу
			server.protocols(vector <string> {"h3"});
			// Устанавливаем параметры переноса клиенту
			client.parameters(vector <uint8_t> {0x01, 0x04, 0x80, 0x00, 0xFF, 0xFF});
			// Устанавливаем параметры переноса серверу
			server.parameters(vector <uint8_t> {0x03, 0x02, 0x45, 0xAC});
		}
	}
	/**
	 * @brief Искажение сообщения рукопожатия на пути между сторонами по уровням
	 *
	 */
	typedef struct Mutation {
		// Искажается ли сообщение, идущее от сервера к клиенту
		bool downstream;
		// Вид искажаемого сообщения рукопожатия
		handshake::type_t type;
		// Преобразование тела сообщения; выводимый вид заменяет прежний
		std::function <handshake::type_t (vector <uint8_t> &)> apply;
		/**
		 * @brief Конструктор
		 *
		 */
		Mutation() noexcept : downstream(true), type(handshake::type_t::NONE) {}
	} mutation_t;
	/**
	 * @brief Метод искажения сообщения нужного вида в потоке сообщений уровня
	 *
	 * @param buffer   поток сообщений уровня с обвязкой
	 * @param mutation описание искажения
	 *
	 * @return         признак того, что сообщение найдено и искажено
	 *
	 */
	bool mutate(vector <uint8_t> & buffer, const mutation_t & mutation) {
		// Пересобираемый поток сообщений
		vector <uint8_t> rebuilt;
		// Признак того, что сообщение искажено
		bool applied = false;
		// Смещение разбора
		size_t offset = 0;
		/**
		 * Выполняем перебор сообщений потока
		 */
		while(offset < buffer.size()){
			// Обвязка очередного сообщения
			handshake::header_t header;
			// Если обвязку разобрать не удалось
			if(handshake::parse(view_t(buffer.data() + offset, buffer.size() - offset), header) != handshake::error_t::NONE)
				// Выводим отказ искажения
				return false;
			// Если тело сообщения не вмещается
			if((offset + handshake::HANDSHAKE_HEADER + header.size) > buffer.size())
				// Выводим отказ искажения
				return false;
			// Тело очередного сообщения
			vector <uint8_t> body(buffer.begin() + static_cast <std::ptrdiff_t> (offset + handshake::HANDSHAKE_HEADER), buffer.begin() + static_cast <std::ptrdiff_t> (offset + handshake::HANDSHAKE_HEADER + header.size));
			// Вид сообщения после искажения
			handshake::type_t type = header.type;
			// Если это искажаемое сообщение
			if(!applied && (header.type == mutation.type)){
				// Применяем искажение к телу
				type = mutation.apply(body);
				// Запоминаем, что сообщение искажено
				applied = true;
			}
			// Составитель сообщения с обвязкой
			handshake::writer_t writer;
			// Если сообщение составить не удалось
			if(writer.push(type, view_t(body.data(), body.size())) != handshake::error_t::NONE)
				// Выводим отказ искажения
				return false;
			// Получаем составленное сообщение
			const view_t data = writer.data();
			// Дописываем сообщение в пересобираемый поток
			rebuilt.insert(rebuilt.end(), data.data, data.data + data.size);
			// Сдвигаем смещение за сообщение
			offset += (handshake::HANDSHAKE_HEADER + header.size);
		}
		// Заменяем поток пересобранным
		buffer = rebuilt;
		// Выводим признак искажения
		return applied;
	}
	/**
	 * Уровни защиты, несущие сообщения рукопожатия, в порядке подачи
	 */
	static const context::level_t LEVELS[] = {context::level_t::INITIAL, context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * @brief Метод переноса сообщений одного уровня от одной стороны к другой с искажением
	 *
	 * @param from       связь стороны, отдающей сообщения
	 * @param to         связь стороны, принимающей сообщения
	 * @param level      уровень защиты переносимых сообщений
	 * @param mutation   описание искажения либо nullptr
	 * @param applied    место, куда помещается признак применённого искажения
	 *
	 * @return           признак того, что сообщения переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const context::level_t level, const mutation_t * mutation, bool & applied) {
		// Получаем сообщения, отправляемые на уровне
		const view_t data = from.output(level);
		// Если отправлять на уровне нечего
		if(data.size == 0)
			// Выводим признак того, что сообщения не переносились
			return false;
		// Выполняем перенос отправляемых сообщений
		vector <uint8_t> buffer(data.data, data.data + data.size);
		// Снимаем отправленные сообщения с накопителя уровня
		from.consume(level, buffer.size());
		// Если искажение задано и ещё не применено
		if((mutation != nullptr) && !applied)
			// Применяем искажение к потоку сообщений уровня
			applied = mutate(buffer, *mutation);
		// Выполняем подачу сообщений принимающей стороне на том же уровне
		to.push(level, view_t(buffer.data(), buffer.size()));
		// Выводим признак того, что сообщения переносились
		return true;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи по уровням с искажением
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param mutation описание искажения либо nullptr
	 *
	 * @return         признак того, что искажение применено
	 *
	 */
	bool converse(client::context_t & client, server::context_t & server, const mutation_t * mutation) {
		// Признак применённого искажения
		bool applied = false;
		/**
		 * Выполняем передачу сообщений между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; i < 16; i++){
			// Признак того, что сообщения передавались
			bool moved = false;
			/**
			 * Выполняем перебор уровней защиты от клиента к серверу
			 */
			for(size_t j = 0; j < (sizeof(LEVELS) / sizeof(LEVELS[0])); j++)
				// Переносим сообщения уровня от клиента к серверу
				moved = (carry(client, server, LEVELS[j], (((mutation != nullptr) && !mutation->downstream) ? mutation : nullptr), applied) || moved);
			/**
			 * Выполняем перебор уровней защиты от сервера к клиенту
			 */
			for(size_t j = 0; j < (sizeof(LEVELS) / sizeof(LEVELS[0])); j++)
				// Переносим сообщения уровня от сервера к клиенту
				moved = (carry(server, client, LEVELS[j], (((mutation != nullptr) && mutation->downstream) ? mutation : nullptr), applied) || moved);
			// Если сторонам сказать больше нечего
			if(!moved)
				// Прекращаем передачу
				break;
		}
		// Выводим признак применённого искажения
		return applied;
	}
	/**
	 * Наборы шифрования перебора
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
	/**
	 * Ключи набора
	 */
	static const char * ENTRIES[] = {"rsa2048", "ec256", "ec384", "ed25519"};
};

/**
 * Проверка кодека zlib со «stored»-блоками: круг, устройство потока, отказы разбора и
 * сличение с настоящим zlib через python3, если он есть
 */
TEST(CompressTest, Codec){
	// Область для сжатия длиннее одного блока: три блока по 65535 и хвост
	vector <uint8_t> sample(65535 * 2 + 777);
	/**
	 * Выполняем заполнение области
	 */
	for(size_t i = 0; i < sample.size(); i++)
		// Устанавливаем очередной байт
		sample[i] = static_cast <uint8_t> ((i * 7 + 3) & 0xFF);
	// Накопитель сжатого потока
	vector <uint8_t> packed;
	// Выполняем сжатие
	ASSERT_TRUE(stored(view_t(sample.data(), sample.size()), packed, nullptr));
	// Проверяем голову потока zlib
	ASSERT_EQ(packed[0], 0x78);
	// Проверяем второй байт головы
	ASSERT_EQ(packed[1], 0x01);
	// Проверяем длину потока: голова 2, три блока по 5, хвост 4
	ASSERT_EQ(packed.size(), sample.size() + 2 + 3 * 5 + 4);
	// Накопитель распакованной области
	vector <uint8_t> unpacked;
	// Выполняем распаковку
	ASSERT_TRUE(unstored(view_t(packed.data(), packed.size()), sample.size(), unpacked, nullptr));
	// Проверяем схождение с исходной областью
	ASSERT_EQ(unpacked, sample);
	// Выполняем сброс накопителя
	unpacked.clear();
	// Проверяем отказ распаковки при ожидаемой длине меньше настоящей
	ASSERT_FALSE(unstored(view_t(packed.data(), packed.size()), sample.size() - 1, unpacked, nullptr));
	// Портим байт содержимого
	packed[10] ^= 0x01;
	// Выполняем сброс накопителя
	unpacked.clear();
	// Проверяем отказ распаковки по сумме Adler-32
	ASSERT_FALSE(unstored(view_t(packed.data(), packed.size()), sample.size(), unpacked, nullptr));
	// Восстанавливаем байт содержимого
	packed[10] ^= 0x01;
	// Портим вид блока: BTYPE=01
	packed[2] |= 0x02;
	// Выполняем сброс накопителя
	unpacked.clear();
	// Проверяем отказ распаковки блока не «stored»
	ASSERT_FALSE(unstored(view_t(packed.data(), packed.size()), sample.size(), unpacked, nullptr));
	// Восстанавливаем вид блока
	packed[2] &= static_cast <uint8_t> (~0x02);
	// Выполняем сброс накопителя
	unpacked.clear();
	// Проверяем отказ распаковки обрезанного потока
	ASSERT_FALSE(unstored(view_t(packed.data(), packed.size() - 1), sample.size(), unpacked, nullptr));
	// Пустая область
	vector <uint8_t> nothing;
	// Выполняем сброс накопителя
	packed.clear();
	// Выполняем сжатие пустой области
	ASSERT_TRUE(stored(view_t(nothing.data(), 0), packed, nullptr));
	// Проверяем длину потока пустой области: голова, один пустой блок, хвост
	ASSERT_EQ(packed.size(), static_cast <size_t> (2 + 5 + 4));
	// Выполняем сброс накопителя
	unpacked.clear();
	// Выполняем распаковку пустой области
	ASSERT_TRUE(unstored(view_t(packed.data(), packed.size()), 0, unpacked, nullptr));
	// Проверяем пустоту распакованного
	ASSERT_TRUE(unpacked.empty());
	// Если python3 с zlib недоступен
	if(shell("python3 -c 'import zlib' >/dev/null 2>&1") != 0){
		// Сообщаем о пропуске части вслух
		std::cout << "python3 с zlib недоступен: сличение потока с настоящим zlib пропущено" << std::endl;
		// Выходим из проверки
		return;
	}
	// Образец имени временного каталога
	char pattern[] = "/tmp/ants-compress-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь к временному каталогу
	const std::string sandbox = pattern;
	// Выполняем сброс накопителя
	packed.clear();
	// Выполняем сжатие образца
	ASSERT_TRUE(stored(view_t(sample.data(), sample.size()), packed, nullptr));
	// Записываем сжатый поток
	ASSERT_TRUE(spill(sandbox + "/ours.z", packed));
	// Распаковываем поток настоящим zlib
	ASSERT_EQ(shell("python3 -c 'import zlib,sys; open(sys.argv[2],\"wb\").write(zlib.decompress(open(sys.argv[1],\"rb\").read()))' " + sandbox + "/ours.z " + sandbox + "/ours.bin"), 0);
	// Проверяем схождение распакованного настоящим zlib с образцом
	ASSERT_EQ(slurp(sandbox + "/ours.bin"), sample);
	// Записываем образец
	ASSERT_TRUE(spill(sandbox + "/sample.bin", sample));
	// Сжимаем образец настоящим zlib без сжатия: уровень 0 даёт «stored»-блоки
	ASSERT_EQ(shell("python3 -c 'import zlib,sys; open(sys.argv[2],\"wb\").write(zlib.compress(open(sys.argv[1],\"rb\").read(), 0))' " + sandbox + "/sample.bin " + sandbox + "/theirs.z"), 0);
	// Читаем поток настоящего zlib
	const vector <uint8_t> theirs = slurp(sandbox + "/theirs.z");
	// Проверяем, что поток прочитан
	ASSERT_FALSE(theirs.empty());
	// Выполняем сброс накопителя
	unpacked.clear();
	// Выполняем распаковку потока настоящего zlib нашим кодеком
	ASSERT_TRUE(unstored(view_t(theirs.data(), theirs.size()), sample.size(), unpacked, nullptr));
	// Проверяем схождение с образцом
	ASSERT_EQ(unpacked, sample);
	// Сертификат набора: настоящее содержимое для кодов Хаффмана
	const vector <uint8_t> certificate = corpus("rsa2048.crt");
	// Проверяем, что сертификат прочитан
	ASSERT_FALSE(certificate.empty());
	// Записываем сертификат
	ASSERT_TRUE(spill(sandbox + "/cert.bin", certificate));
	/**
	 * Выполняем перебор уровней сжатия настоящего zlib: постоянные и порождаемые коды Хаффмана
	 */
	for(size_t level = 1; level <= 9; level += 4){
		// Сжимаем сертификат настоящим zlib
		ASSERT_EQ(shell("python3 -c 'import zlib,sys; open(sys.argv[2],\"wb\").write(zlib.compress(open(sys.argv[1],\"rb\").read(), int(sys.argv[3])))' " + sandbox + "/cert.bin " + sandbox + "/cert.z " + std::to_string(level)), 0) << "уровень " << level;
		// Читаем поток настоящего zlib
		const vector <uint8_t> squeezed = slurp(sandbox + "/cert.z");
		// Проверяем, что поток прочитан и короче сертификата
		ASSERT_LT(squeezed.size(), certificate.size()) << "уровень " << level;
		// Выполняем сброс накопителя
		unpacked.clear();
		// Выполняем распаковку кодами Хаффмана нашим кодеком
		ASSERT_TRUE(unstored(view_t(squeezed.data(), squeezed.size()), certificate.size(), unpacked, nullptr)) << "уровень " << level;
		// Проверяем схождение с сертификатом
		ASSERT_EQ(unpacked, certificate) << "уровень " << level;
		// Выполняем сброс накопителя
		unpacked.clear();
		// Проверяем отказ при ожидаемой длине меньше настоящей
		ASSERT_FALSE(unstored(view_t(squeezed.data(), squeezed.size()), certificate.size() - 1, unpacked, nullptr)) << "уровень " << level;
	}
	// Удаляем временный каталог
	(void) shell("rm -rf " + sandbox);
}

/**
 * Проверка петлевого рукопожатия по записям со сжатием в обе стороны: все ключи и наборы,
 * сервер сжимает по объявлению клиента, клиент сжимает по запросу подлинности, переписка
 * сходится, данные идут, билет выдаётся и возобновление идёт без цепочек
 */
TEST(CompressTest, Loopback){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность из ключей набора
		ASSERT_TRUE(identity(ENTRIES[k], credential)) << "ключ " << ENTRIES[k];
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			/**
			 * Выполняем перебор способов переноса: записи и уровни
			 */
			for(size_t t = 0; t < 2; t++){
				// Связь стороны клиента
				client::context_t client;
				// Связь стороны сервера
				server::context_t server;
				// Настраиваем стороны с подлинностью клиента
				arrange(client, server, SUITES[s], extension::group_t::X25519, credential, true, (t == 1));
				// Кодеки клиента: zlib
				client.codecs(vector <context::codec_t> {zlib()}, 0);
				// Кодеки сервера: zlib
				server.codecs(vector <context::codec_t> {zlib()}, 0);
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE);
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE);
				// Если перенос идёт записями
				if(t == 0){
					// Проводим рукопожатие по записям
					converse(client, server);
				// Если перенос идёт по уровням
				} else {
					// Проводим рукопожатие по уровням без искажений
					(void) converse(client, server, nullptr);
				}
				// Проверяем установленность связи клиентом
				ASSERT_TRUE(client.established()) << ENTRIES[k] << " " << s << " " << t << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Проверяем установленность связи сервером
				ASSERT_TRUE(server.established()) << ENTRIES[k] << " " << s << " " << t;
				// Проверяем, что цепочка сервера пришла клиенту сжатой zlib
				ASSERT_EQ(client.compression(context::direction_t::READ), ZLIB);
				// Проверяем, что сервер отправил цепочку сжатой zlib
				ASSERT_EQ(server.compression(context::direction_t::WRITE), ZLIB);
				// Проверяем, что цепочка клиента пришла серверу сжатой zlib
				ASSERT_EQ(server.compression(context::direction_t::READ), ZLIB);
				// Проверяем, что клиент отправил цепочку сжатой zlib
				ASSERT_EQ(client.compression(context::direction_t::WRITE), ZLIB);
				// Проверяем цепочку сервера у клиента
				ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
				// Проверяем цепочку клиента у сервера
				ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
				// Проверяем схождение цепочки сервера у клиента с подлинностью байт в байт
				ASSERT_EQ(client.peer()[0], credential.chain[0]);
				// Проверяем схождение цепочки клиента у сервера с подлинностью байт в байт
				ASSERT_EQ(server.peer()[0], credential.chain[0]);
				// Если перенос идёт записями
				if(t == 0){
					// Проверяем обмен данными
					ASSERT_TRUE(barter(client, server)) << ENTRIES[k] << " " << s;
					// Выдаём билет
					ASSERT_EQ(server.issue(), context::error_t::NONE);
					// Доставляем билет
					converse(client, server);
					// Проверяем получение билета клиентом
					ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
					// Связь возобновляющего клиента
					client::context_t resuming;
					// Связь возобновляющего сервера
					server::context_t resumed;
					// Настраиваем стороны без подлинности клиента
					arrange(resuming, resumed, SUITES[s], extension::group_t::X25519, credential, false, false);
					// Кодеки клиента при возобновлении
					resuming.codecs(vector <context::codec_t> {zlib()}, 0);
					// Кодеки сервера при возобновлении
					resumed.codecs(vector <context::codec_t> {zlib()}, 0);
					// Предъявляем билет
					resuming.resume(client.tickets()[0]);
					// Признаём билеты
					resumed.resume(server.tickets());
					// Заводим сервер
					ASSERT_EQ(resumed.start(), context::error_t::NONE);
					// Заводим клиента
					ASSERT_EQ(resuming.start(), context::error_t::NONE);
					// Проводим рукопожатие
					converse(resuming, resumed);
					// Проверяем установленность связи
					ASSERT_TRUE(resuming.established() && resumed.established()) << ENTRIES[k] << " " << s;
					// Проверяем возобновление билетом
					ASSERT_TRUE(resuming.shared() && resumed.shared());
					// Цепочек при возобновлении нет: сжатия нет ни в одну сторону
					ASSERT_EQ(resuming.compression(context::direction_t::READ), 0);
					// Клиент цепочку не слал
					ASSERT_EQ(resuming.compression(context::direction_t::WRITE), 0);
					// Сервер цепочку не слал
					ASSERT_EQ(resumed.compression(context::direction_t::WRITE), 0);
					// Проверяем обмен данными по возобновлённой связи
					ASSERT_TRUE(barter(resuming, resumed));
				}
			}
		}
	}
}

/**
 * Проверка выбора алгоритма: только одна сторона поддерживает, нет общего алгоритма, порядок
 * клиента соблюдён сервером, неведомый опознаватель пропускается молча, отказ сжатия у
 * потребителя шлёт несжатое, чужое исключение кодека удерживается, клиент сжимает по запросу
 * подлинности частным алгоритмом, счётчик вызовов доходит до контекста потребителя
 */
TEST(CompressTest, Selection){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * @brief Сценарий выбора алгоритма
	 *
	 */
	struct Scenario {
		// Название сценария
		const char * name;
		// Кодеки клиента
		vector <context::codec_t> client;
		// Кодеки сервера
		vector <context::codec_t> server;
		// Запрашивается ли подлинность клиента
		bool mutual;
		// Ожидаемый алгоритм цепочки сервера у клиента
		uint16_t downstream;
		// Ожидаемый алгоритм цепочки клиента у сервера
		uint16_t upstream;
	};
	// Кодек zlib, отказывающий сжимать
	const context::codec_t declining(ZLIB, refusing, unstored);
	// Кодек zlib, бросающий чужое исключение
	const context::codec_t hurling(ZLIB, throwing, unstored);
	// Кодек с чужим опознавателем: сервер его не знает
	const context::codec_t stranger(STRANGER, scramble, unscramble);
	// Сценарии выбора алгоритма
	const Scenario scenarios[] = {
		{"только клиент",           {zlib()},            {},                  true,  0,       0},
		{"только сервер",           {},                  {zlib()},            true,  0,       0},
		{"нет общего",              {custom(nullptr)},          {zlib()},            true,  0,       0},
		{"порядок клиента: частный", {custom(nullptr), zlib()}, {zlib(), custom(nullptr)},  false, PRIVATE, 0},
		{"порядок клиента: zlib",   {zlib(), custom(nullptr)},  {custom(nullptr), zlib()},  false, ZLIB,    0},
		{"неведомый пропущен",      {stranger, zlib()},  {zlib()},            false, ZLIB,    0},
		{"отказ сжатия",            {zlib()},            {declining},         true,  0,       ZLIB},
		{"чужое исключение",        {zlib()},            {hurling},           true,  0,       ZLIB},
		{"по запросу подлинности",  {custom(nullptr)},          {custom(nullptr)},          true,  PRIVATE, PRIVATE},
		{"порядок сервера у клиента", {zlib(), custom(nullptr)}, {custom(nullptr), zlib()}, true,  ZLIB,    PRIVATE}
	};
	/**
	 * Выполняем перебор сценариев
	 */
	for(size_t i = 0; i < (sizeof(scenarios) / sizeof(scenarios[0])); i++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, scenarios[i].mutual, false);
		// Кодеки клиента
		client.codecs(scenarios[i].client, 0);
		// Кодеки сервера
		server.codecs(scenarios[i].server, 0);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE) << scenarios[i].name;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << scenarios[i].name;
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established()) << scenarios[i].name << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем алгоритм цепочки сервера у клиента
		ASSERT_EQ(client.compression(context::direction_t::READ), scenarios[i].downstream) << scenarios[i].name;
		// Проверяем алгоритм отправленной цепочки у сервера
		ASSERT_EQ(server.compression(context::direction_t::WRITE), scenarios[i].downstream) << scenarios[i].name;
		// Проверяем алгоритм цепочки клиента у сервера
		ASSERT_EQ(server.compression(context::direction_t::READ), scenarios[i].upstream) << scenarios[i].name;
		// Проверяем алгоритм отправленной цепочки у клиента
		ASSERT_EQ(client.compression(context::direction_t::WRITE), scenarios[i].upstream) << scenarios[i].name;
		// Проверяем цепочку сервера у клиента
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (1)) << scenarios[i].name;
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server)) << scenarios[i].name;
	}
	{
		// Счётчик вызовов кодека клиента
		size_t first = 0;
		// Счётчик вызовов кодека сервера
		size_t second = 0;
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true, false);
		// Кодек клиента со счётчиком
		client.codecs(vector <context::codec_t> {custom(&first)}, 0);
		// Кодек сервера со счётчиком
		server.codecs(vector <context::codec_t> {custom(&second)}, 0);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Контекст дошёл до кодека клиента: одна распаковка и одно сжатие
		ASSERT_EQ(first, static_cast <size_t> (2));
		// Контекст дошёл до кодека сервера: одно сжатие и одна распаковка
		ASSERT_EQ(second, static_cast <size_t> (2));
	}
	{
		// Связь стороны клиента с негодным кодеком
		client::context_t client;
		// Кодек без вызовов
		client.codecs(vector <context::codec_t> {context::codec_t(ZLIB, nullptr, nullptr)}, 0);
		// Проверяем отказ настроек при заведении
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
		// Связь стороны сервера с негодным кодеком
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Кодек с нулевым опознавателем
		server.codecs(vector <context::codec_t> {context::codec_t(0, stored, unstored)}, 0);
		// Проверяем отказ настроек при заведении
		ASSERT_EQ(server.start(), context::error_t::SETTINGS);
		// Пустой перечень выключает сжатие и заведение дозволяет
		server.codecs(vector <context::codec_t> (), 0);
		// Проверяем заведение сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
	}
}

/**
 * Проверка отказов по разделу 4 RFC 8879 искажением сообщений на пути по уровням: длина после
 * распаковки не сошлась, порча сжатого, длина за пределом протокола и за пределом потребителя,
 * сжатая цепочка без объявления, неведомый алгоритм, лишние байты, расширение не в своём
 * сообщении, искажение цепочки клиента у сервера
 */
TEST(CompressTest, Refusals){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	/**
	 * @brief Сценарий отказа
	 *
	 */
	struct Scenario {
		// Название сценария
		const char * name;
		// Кодеки клиента
		vector <context::codec_t> client;
		// Кодеки сервера
		vector <context::codec_t> server;
		// Предел длины после распаковки у принимающей стороны
		size_t inflation;
		// Искажение
		mutation_t mutation;
		// Ожидаемый отказ принимающей стороны
		context::error_t error;
		// Ожидаемое извещение принимающей стороны
		alert::description_t description;
	};
	// Сценарии отказов
	vector <Scenario> scenarios;
	{
		// Длина после распаковки не сошлась: поле uncompressed_length на единицу больше
		Scenario item = {"длина не сошлась", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::CERTIFICATE, alert::description_t::BADCERT};
		// Искажается сжатая цепочка сервера
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Наращиваем младший байт длины после распаковки
		item.mutation.apply = [](vector <uint8_t> & body) { body[4] = static_cast <uint8_t> (body[4] + 1); return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Порча сжатого: сумма Adler-32 не сойдётся
		Scenario item = {"порча сжатого", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::CERTIFICATE, alert::description_t::BADCERT};
		// Искажается сжатая цепочка сервера
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Портим байт содержимого за головами
		item.mutation.apply = [](vector <uint8_t> & body) { body[20] ^= 0x01; return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Длина после распаковки за пределом умолчания 65536
		Scenario item = {"длина за пределом", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::CERTIFICATE, alert::description_t::BADCERT};
		// Искажается сжатая цепочка сервера
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Ставим длину 2^24-1
		item.mutation.apply = [](vector <uint8_t> & body) { body[2] = 0xFF; body[3] = 0xFF; body[4] = 0xFF; return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Предел потребителя ниже длины цепочки: честное сообщение отвергается
		Scenario item = {"предел потребителя", {zlib()}, {zlib()}, 100, mutation_t(), context::error_t::CERTIFICATE, alert::description_t::BADCERT};
		// Искажения нет: вид сообщения не в потоке
		item.mutation.type = handshake::type_t::NONE;
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Сжатая цепочка без объявления: клиент кодеков не имеет, цепочка обёрнута частным кодеком
		Scenario item = {"без объявления", {}, {custom(nullptr)}, 0, mutation_t(), context::error_t::ORDER, alert::description_t::UNEXPECTED};
		// Искажается обычная цепочка сервера
		item.mutation.type = handshake::type_t::CERTIFICATE;
		// Оборачиваем цепочку в сжатую частным кодеком
		item.mutation.apply = [](vector <uint8_t> & body) {
			// Сжатое тело
			vector <uint8_t> packed;
			// Сжимаем частным кодеком
			(void) scramble(view_t(body.data(), body.size()), packed, nullptr);
			// Составитель тела сжатой цепочки
			field::builder_t builder;
			// Опознаватель алгоритма
			(void) builder.number(PRIVATE, 2);
			// Длина до сжатия
			(void) builder.number(static_cast <uint32_t> (body.size()), 3);
			// Открываем поле сжатого тела
			(void) builder.open(3);
			// Сжатое тело
			(void) builder.bytes(view_t(packed.data(), packed.size()));
			// Закрываем поле
			(void) builder.close();
			// Составленное тело
			const view_t data = builder.data();
			// Заменяем тело
			body.assign(data.data, data.data + data.size);
			// Выводим вид сжатой цепочки
			return handshake::type_t::COMPRESSED;
		};
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Неведомый алгоритм: опознаватель 1 подменён на 3
		Scenario item = {"неведомый алгоритм", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::COMPRESSION, alert::description_t::PARAMETER};
		// Искажается сжатая цепочка сервера
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Подменяем опознаватель
		item.mutation.apply = [](vector <uint8_t> & body) { body[1] = 0x03; return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Лишние байты за телом
		Scenario item = {"лишние байты", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::MESSAGE, alert::description_t::DECODE};
		// Искажается сжатая цепочка сервера
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Дописываем байт
		item.mutation.apply = [](vector <uint8_t> & body) { body.push_back(0x00); return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Расширение не в своём сообщении: перечень алгоритмов в защищённых расширениях
		Scenario item = {"не в своём сообщении", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::MESSAGE, alert::description_t::PARAMETER};
		// Искажаются защищённые расширения сервера
		item.mutation.type = handshake::type_t::EXTENSIONS;
		// Дописываем расширение 0x001B с перечнем из одного zlib
		item.mutation.apply = [](vector <uint8_t> & body) {
			// Расширение перечня алгоритмов: вид, длина 3, перечень длиной 2 из 0x0001
			const uint8_t extension[7] = {0x00, 0x1B, 0x00, 0x03, 0x02, 0x00, 0x01};
			// Дописываем расширение
			body.insert(body.end(), extension, extension + sizeof(extension));
			// Длина перечня расширений
			const size_t length = (body.size() - 2);
			// Старший байт длины
			body[0] = static_cast <uint8_t> ((length >> 8) & 0xFF);
			// Младший байт длины
			body[1] = static_cast <uint8_t> (length & 0xFF);
			// Вид не меняется
			return handshake::type_t::EXTENSIONS;
		};
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	{
		// Цепочка клиента у сервера: длина не сошлась
		Scenario item = {"цепочка клиента", {zlib()}, {zlib()}, 0, mutation_t(), context::error_t::CERTIFICATE, alert::description_t::BADCERT};
		// Искажается сжатая цепочка клиента
		item.mutation.downstream = false;
		// Вид искажаемого сообщения
		item.mutation.type = handshake::type_t::COMPRESSED;
		// Наращиваем младший байт длины после распаковки
		item.mutation.apply = [](vector <uint8_t> & body) { body[4] = static_cast <uint8_t> (body[4] + 1); return handshake::type_t::COMPRESSED; };
		// Добавляем сценарий
		scenarios.push_back(item);
	}
	/**
	 * Выполняем перебор сценариев
	 */
	for(size_t i = 0; i < scenarios.size(); i++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны по уровням с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true, true);
		// Кодеки клиента с пределом
		client.codecs(scenarios[i].client, scenarios[i].inflation);
		// Кодеки сервера
		server.codecs(scenarios[i].server, 0);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE) << scenarios[i].name;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << scenarios[i].name;
		// Проводим рукопожатие с искажением
		const bool applied = converse(client, server, ((scenarios[i].mutation.type != handshake::type_t::NONE) ? &scenarios[i].mutation : nullptr));
		// Если искажение задано, оно обязано было примениться
		if(scenarios[i].mutation.type != handshake::type_t::NONE){
			// Проверяем применение искажения
			ASSERT_TRUE(applied) << scenarios[i].name;
		}
		// Пострадавшая сторона: клиент у нисходящих искажений, сервер у восходящих
		const context::error_t error = (scenarios[i].mutation.downstream ? client.error() : server.error());
		// Извещение пострадавшей стороны
		const alert::description_t description = (scenarios[i].mutation.downstream ? client.alert().description : server.alert().description);
		// Проверяем отказ
		ASSERT_EQ(error, scenarios[i].error) << scenarios[i].name << " " << static_cast <int> (error);
		// Проверяем извещение
		ASSERT_EQ(description, scenarios[i].description) << scenarios[i].name;
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established() && server.established()) << scenarios[i].name;
	}
}

/**
 * Проверка обмена с настоящим openssl: наш клиент с zlib против s_server -cert_comp и s_client
 * против нашего сервера; s_server 3.2+ шлёт сжатую цепочку лишь пред-сжатой ключом -cert_comp,
 * s_client сжимает свою по запросу подлинности сам, принимают сжатую оба по умолчанию;
 * собранный без zlib - пропуск вслух
 */
TEST(CompressTest, Openssl){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3
	if(!toolkit.tls13){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	/**
	 * Помощник запуска подаёт пустой вход последней команде строки, и в цепочке команд он
	 * перебил бы канал у grep: оттого цепочка берётся в скобки, и вход достаётся ей целиком
	 */
	if(shell("(openssl list -disabled 2>/dev/null | grep -qi '^ZLIB$')") == 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl собран без zlib: сжатие сертификатов у него выключено";
	}
	// Если s_server не умеет пред-сжимать сертификаты: ключ -cert_comp пришёл с 3.2 и скрыт без zlib
	if(!listed("s_server", "cert_comp")){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без ключа s_server -cert_comp: сжатия сертификатов у него нет";
	}
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	{
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-compress-server-" + std::to_string(number) + ".log";
		// Запускаем сервер openssl с пред-сжатием сертификатов и запросом подлинности клиента
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -cert_comp -Verify 1 -CAfile " + crt + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера openssl: снимается по номеру и при отказе посреди проверки
		sentinel_t sentinel(log + ".pid");
		// Подключаемся к серверу openssl
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0) << "порт " << number;
		// Связь стороны клиента
		client::context_t client;
		// Наборы клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность клиента
		client.credential(credential);
		// Кодек клиента: zlib
		client.codecs(vector <context::codec_t> {zlib()}, 0);
		// Имя узла
		client.name("localhost");
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до установления связи
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты
			relay(client, fd);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Проверяем, что цепочка сервера пришла сжатой zlib
		ASSERT_EQ(client.compression(context::direction_t::READ), ZLIB);
		// Проверяем, что своя цепочка ушла сжатой zlib по запросу подлинности сервера
		ASSERT_EQ(client.compression(context::direction_t::WRITE), ZLIB);
		// Запрос HTTP серверу openssl
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем запрос
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Накопитель ответа
		vector <uint8_t> answer;
		/**
		 * Выполняем передачу байтов до получения ответа
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём байты
			relay(client, fd);
			// Читаем принятые данные
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Проверяем, что ответ HTTP получен: подлинность клиента сервером принята
		ASSERT_NE(string(answer.begin(), answer.end()).find("HTTP/1.0 200"), string::npos);
		// Закрываем сокет
		::close(fd);
		// Снимаем сервер до удаления журнала: иначе отметка завершения воссоздаст файл
		sentinel.halt();
		// Журнал сервера
		std::string journal;
		// Дожидаемся отметки завершения снятого сервера
		(void) settle(log, journal);
		// Удаляем журнал
		::remove(log.c_str());
	}
	{
		// Порт сервера
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-compress-client-" + std::to_string(number) + ".log";
		// Запускаем клиента openssl с подлинностью
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -cert " + crt + " -key " + key + " -servername localhost -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож клиента openssl
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны сервера
		server::context_t server;
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность сервера
		server.credential(credential);
		// Запрашиваем подлинность клиента
		server.request(true);
		// Кодек сервера: zlib
		server.codecs(vector <context::codec_t> {zlib()}, 0);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём связь до конца рукопожатия
		const bool complete = serve(server, fd);
		// Проверяем, что рукопожатие дошло до конца
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
		// Проверяем, что отказа не было
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// Проверяем, что своя цепочка ушла сжатой zlib по объявлению клиента openssl
		ASSERT_EQ(server.compression(context::direction_t::WRITE), ZLIB);
		// Проверяем, что цепочка клиента openssl пришла сжатой zlib по нашему запросу подлинности
		ASSERT_EQ(server.compression(context::direction_t::READ), ZLIB);
		// Проверяем подлинность клиента
		ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
		// Закрываем связь, коли она ещё открыта
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем сокет
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Содержимое журнала
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(settle(log, text)) << text;
		// Проверяем проверку сертификата сервера клиентом openssl: сжатая цепочка распакована им
		ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка поведения при нехватке памяти: перебор запасов выделений со сжатием в обе стороны,
 * всякий отказ либо NONE, либо MEMORY, либо обрыв внутренним извещением
 */
TEST(CompressTest, Starved){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Признак того, что нехватка памяти встретилась
	bool starved = false;
	// Признак того, что связь на щедром запасе установилась
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, true, false);
		// Кодеки клиента: два алгоритма
		client.codecs(vector <context::codec_t> {custom(nullptr), zlib()}, 0);
		// Кодеки сервера: два алгоритма
		server.codecs(vector <context::codec_t> {zlib(), custom(nullptr)}, 0);
		// Ошибки сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Заводим сервер
			first = server.start();
			// Заводим клиента
			second = client.start();
			// Если стороны заведены
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие
				converse(client, server);
				// Ошибка сервера после рукопожатия
				first = server.error();
				// Ошибка клиента
				second = client.error();
			}
		}
		// Запоминаем нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		/**
		 * Дозволенные исходы: успех, нехватка памяти либо обрыв собеседником с внутренним
		 * извещением о его нехватке памяти
		 */
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем законность исхода
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Запоминаем установление связи
		complete = (client.established() && server.established());
		// Если связь установилась
		if(complete){
			// Сервер сжал первым по порядку клиента: частным
			ASSERT_EQ(client.compression(context::direction_t::READ), PRIVATE);
			// Клиент сжал первым по порядку сервера: zlib
			ASSERT_EQ(server.compression(context::direction_t::READ), ZLIB);
		}
	}
	// Проверяем, что нехватка памяти встретилась
	ASSERT_TRUE(starved);
	// Проверяем, что на щедром запасе связь установилась
	ASSERT_TRUE(complete);
}
