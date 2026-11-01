/**
 * @file lz77.hpp
 * @date 2026-09-06
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
 * @brief Общий для образца сжатия и набора замеров заголовочный файл частного кодека
 *        цепочки сертификатов - честное сжатие повторами по образу LZ77
 *
 * @details Библиотека ни одного алгоритма сжатия не несёт (RFC 8879 отдаёт их
 *          потребителю), а образцу и замерам нужен настоящий кодек, который цепочку
 *          и вправду укорачивает: повторы имён издателя, опознавателей алгоритмов и
 *          расширений в соседних сертификатах цепочки ловятся окном назад. Запись
 *          потока проста: байт со старшим разрядом ноль открывает ряд буквальных
 *          байтов (длина в младших семи разрядах плюс один), байт со старшим
 *          разрядом единица - повтор (длина в младших семи разрядах плюс три) с
 *          двухбайтовым смещением назад следом
 *
 * @note Всё содержимое лежит в безымянном пространстве имён: у образца и у набора
 *       замеров своя программа, и заголовочный файл годится обоим. Кодек частный:
 *       опознаватель ему назначается из области 16384…65535 раздела 7.3 RFC 8879
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию заголовочного файла
 */
#ifndef __ANTS_SAMPLE_LZ77__
/**
 * Определяем макрос стража заголовочного файла
 */
#define __ANTS_SAMPLE_LZ77__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Служебные объекты частного кодека сжатия
 *
 */
namespace {
	/**
	 * Опознаватель частного алгоритма сжатия по разделу 7.3 RFC 8879
	 */
	static constexpr uint16_t LZ77_ALGORITHM = 16384;
	/**
	 * Наименьшая длина повтора, которую стоит записывать: короче ряд буквальных байтов
	 */
	static constexpr size_t LZ77_LEAST = 3;
	/**
	 * Наибольшая длина повтора: семь разрядов длины плюс наименьшая
	 */
	static constexpr size_t LZ77_LONGEST = (127 + LZ77_LEAST);
	/**
	 * Наибольшее смещение повтора назад: два байта смещения
	 */
	static constexpr size_t LZ77_WINDOW = 65535;
	/**
	 * Число ячеек таблицы розыска повторов по трём байтам
	 */
	static constexpr size_t LZ77_CELLS = 4096;
	/**
	 * @brief Счётчик работы кодека, передаваемый вызовам указателем контекста
	 *
	 */
	typedef struct Tally {
		// Число вызовов сжатия
		size_t compressions;
		// Число вызовов распаковки
		size_t decompressions;
		// Длина последнего сжимаемого тела
		size_t source;
		// Длина последнего сжатого тела
		size_t packed;
		/**
		 * @brief Конструктор
		 *
		 */
		Tally() noexcept : compressions(0), decompressions(0), source(0), packed(0) {}
	} tally_t;
	/**
	 * @brief Функция свёртки трёх байтов в номер ячейки таблицы розыска
	 *
	 * @param data байты, начиная с которых ищется повтор
	 * @return     номер ячейки таблицы розыска
	 *
	 */
	size_t cell(const uint8_t * data) noexcept {
		// Выводим свёртку трёх байтов в номер ячейки
		return ((((static_cast <size_t> (data[0]) << 16) | (static_cast <size_t> (data[1]) << 8) | data[2]) * 2654435761u) % LZ77_CELLS);
	}
	/**
	 * @brief Функция записи ряда буквальных байтов в сжатый поток
	 *
	 * @param source сжимаемое тело
	 * @param begin  начало ряда буквальных байтов
	 * @param end    конец ряда буквальных байтов
	 * @param result накопитель сжатого потока
	 *
	 */
	void literal(const uint8_t * source, size_t begin, const size_t end, vector <uint8_t> & result) {
		/**
		 * Выполняем запись ряда кусками не длиннее ста двадцати восьми байтов
		 */
		while(begin < end){
			// Длина очередного куска ряда
			const size_t length = (((end - begin) > 128) ? 128 : (end - begin));
			// Записываем заголовок куска: старший разряд ноль, длина без единицы
			result.push_back(static_cast <uint8_t> (length - 1));
			// Дописываем буквальные байты куска
			result.insert(result.end(), source + begin, source + begin + length);
			// Сдвигаем начало ряда на длину куска
			begin += length;
		}
	}
	/**
	 * @brief Вызов сжатия цепочки сертификатов повторами
	 *
	 * @param source  сжимаемое тело сообщения цепочки
	 * @param result  накопитель, в который складывается сжатый поток
	 * @param context указатель счётчика работы кодека либо nullptr
	 * @return        признак успешности сжатия
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителе перехватывает связь
	 *
	 */
	bool lz77Compress(const view_t & source, vector <uint8_t> & result, void * context) {
		// Таблица розыска повторов: место последнего появления трёх байтов
		vector <size_t> heads(LZ77_CELLS, SIZE_MAX);
		// Начало ещё не записанного ряда буквальных байтов
		size_t pending = 0;
		// Смещение разбираемого байта
		size_t offset = 0;
		/**
		 * Выполняем перебор байтов сжимаемого тела
		 */
		while(offset < source.size){
			// Длина найденного повтора
			size_t length = 0;
			// Смещение найденного повтора назад
			size_t distance = 0;
			// Если впереди хватает байтов на повтор
			if((source.size - offset) >= LZ77_LEAST){
				// Ячейка таблицы розыска для текущих трёх байтов
				const size_t index = cell(source.data + offset);
				// Место прежнего появления тех же трёх байтов
				const size_t previous = heads[index];
				// Если прежнее появление есть и лежит в окне
				if((previous != SIZE_MAX) && ((offset - previous) <= LZ77_WINDOW)){
					// Наибольшая возможная длина повтора
					const size_t room = (((source.size - offset) > LZ77_LONGEST) ? LZ77_LONGEST : (source.size - offset));
					/**
					 * Выполняем сличение байтов повтора с текущими
					 */
					while((length < room) && (source.data[previous + length] == source.data[offset + length]))
						// Наращиваем длину повтора
						length++;
					// Запоминаем смещение повтора назад
					distance = (offset - previous);
				}
				// Запоминаем текущее появление трёх байтов
				heads[index] = offset;
			}
			// Если повтор достаточно длинен
			if(length >= LZ77_LEAST){
				// Записываем накопленный ряд буквальных байтов
				literal(source.data, pending, offset, result);
				// Записываем заголовок повтора: старший разряд единица, длина без наименьшей
				result.push_back(static_cast <uint8_t> (0x80 | (length - LZ77_LEAST)));
				// Записываем старший байт смещения
				result.push_back(static_cast <uint8_t> ((distance >> 8) & 0xFF));
				// Записываем младший байт смещения
				result.push_back(static_cast <uint8_t> (distance & 0xFF));
				/**
				 * Выполняем запоминание троек байтов внутри повтора: без него повторы
				 * внутри повторов не находятся
				 */
				for(size_t i = 1; (i < length) && ((offset + i + LZ77_LEAST) <= source.size); i++)
					// Запоминаем появление тройки байтов
					heads[cell(source.data + offset + i)] = (offset + i);
				// Сдвигаем разбор за повтор
				offset += length;
				// Новый ряд буквальных байтов начинается за повтором
				pending = offset;
			// Если повтора нет
			} else
				// Переходим к следующему байту
				offset++;
		}
		// Записываем хвостовой ряд буквальных байтов
		literal(source.data, pending, source.size, result);
		// Если счётчик работы кодека передан
		if(context != nullptr){
			// Счётчик работы кодека
			tally_t * tally = reinterpret_cast <tally_t *> (context);
			// Считаем вызов сжатия
			tally->compressions++;
			// Запоминаем длину сжимаемого тела
			tally->source = source.size;
			// Запоминаем длину сжатого тела
			tally->packed = result.size();
		}
		// Выводим успешность сжатия
		return true;
	}
	/**
	 * @brief Вызов распаковки цепочки сертификатов
	 *
	 * @param source   распаковываемый сжатый поток
	 * @param expected ожидаемая длина тела после распаковки
	 * @param result   накопитель, в который складывается распакованное тело
	 * @param context  указатель счётчика работы кодека либо nullptr
	 * @return         признак успешности распаковки: ровно ожидаемая длина, иначе отказ
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителе перехватывает связь
	 *
	 */
	bool lz77Decompress(const view_t & source, const size_t expected, vector <uint8_t> & result, void * context) {
		// Смещение разбираемого байта потока
		size_t offset = 0;
		// Заранее занимаем место под ожидаемую длину
		result.reserve(result.size() + expected);
		/**
		 * Выполняем перебор записей сжатого потока
		 */
		while(offset < source.size){
			// Заголовок записи
			const uint8_t head = source.data[offset++];
			// Если запись несёт ряд буквальных байтов
			if((head & 0x80) == 0){
				// Длина ряда буквальных байтов
				const size_t length = (static_cast <size_t> (head & 0x7F) + 1);
				// Если ряд выходит за поток либо за ожидаемую длину
				if(((offset + length) > source.size) || ((result.size() + length) > expected))
					// Выводим отказ распаковки
					return false;
				// Дописываем буквальные байты
				result.insert(result.end(), source.data + offset, source.data + offset + length);
				// Сдвигаем разбор за ряд
				offset += length;
			// Если запись несёт повтор
			} else {
				// Длина повтора
				const size_t length = (static_cast <size_t> (head & 0x7F) + LZ77_LEAST);
				// Если смещения в потоке нет
				if((offset + 2) > source.size)
					// Выводим отказ распаковки
					return false;
				// Смещение повтора назад
				const size_t distance = ((static_cast <size_t> (source.data[offset]) << 8) | source.data[offset + 1]);
				// Сдвигаем разбор за смещение
				offset += 2;
				// Если смещение негодно либо повтор выходит за ожидаемую длину
				if((distance == 0) || (distance > result.size()) || ((result.size() + length) > expected))
					// Выводим отказ распаковки
					return false;
				// Начало повтора в распакованном теле
				const size_t start = (result.size() - distance);
				/**
				 * Выполняем побайтовый перенос повтора: повтор вправе перекрывать сам себя
				 */
				for(size_t i = 0; i < length; i++)
					// Дописываем очередной байт повтора
					result.push_back(result[start + i]);
			}
		}
		// Если счётчик работы кодека передан
		if(context != nullptr)
			// Считаем вызов распаковки
			reinterpret_cast <tally_t *> (context)->decompressions++;
		// Выводим итог сличения длины: половина цепочки не цепочка
		return (result.size() == expected);
	}
};

#endif
