/**
 * @file pem.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл модуля хранения записей в виде PEM
 *
 * @section Намеренные решения
 *
 * 1. Модуль не читает файлов. Ввода и вывода в библиотеке нет вовсе, и заводить его ради
 *    одного удобства значило бы привязать разбор ключа к устройству файловой системы: тогда
 *    ключ, пришедший из настроек, из хранилища паролей или по сети, разобрать стало бы нечем.
 *
 * 2. Всё, что лежит вне рамок записей, пропускается молча. Раздел 5.2 RFC 7468 прямо это
 *    дозволяет, а хранят ключи и цепочки обыкновенно вперемешку с пояснениями к ним: отказ
 *    на пояснении отверг бы записи, записанные ровно по стандарту.
 *
 * 3. Оборванная рамка отказ даёт. Пропуск постороннего текста тем и отличается от пропуска
 *    испорченной записи, что во втором случае запись есть и она не прочтена: смолчав, модуль
 *    выдал бы неполную цепочку за целую.
 *
 * 4. Вид записи секретного ключа опознаётся меткой ASN.1, а не догадкой о том, кто его
 *    записал. Правила записи ключа дозволяют три вида, и все три различаются меткой; выбор
 *    же вида по имени изготовителя ключа привязал бы разбор к чужой оснастке.
 *
 * 5. Порядок байтов числа берётся тот, который объявлен видом записи: строка байтов - это
 *    ключ порядком от младшего байта к старшему, как и записаны все числа ключевого
 *    вещества у ГОСТ, а целое число ASN.1 - порядком от старшего, как велит сама кодировка
 *    DER. Наружу же итог выдаётся одним порядком - тем, каким его ждёт подлинность стороны
 *    связи.
 *
 * 6. Зашифрованный ключ отвергается отказом, а не разбирается. Расшифрование его требует
 *    пароля, а спрашивать пароль - дело того, кто говорит с человеком, а не библиотеки.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён вспомогательных значений модуля
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace anyks;

	/**
	 * Пространство имён модуля
	 */
	using namespace anyks::pem;

	/**
	 * Знаки основания 64 по разделу 4 RFC 4648
	 */
	static const char ALPHABET[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/**
	 * Рамка начала записи по разделу 2 RFC 7468
	 */
	static const char OPENING[] = "-----BEGIN ";

	/**
	 * Рамка конца записи по разделу 2 RFC 7468
	 */
	static const char CLOSING[] = "-----END ";

	/**
	 * Ограда рамки записи
	 */
	static const char FENCE[] = "-----";

	/**
	 * @brief Метод получения номера знака в основании 64
	 *
	 * @param letter знак, номер которого извлекается
	 *
	 * @return       номер знака в основании 64 либо -1, если знак основанию не принадлежит
	 *
	 */
	static int16_t number(const char letter) noexcept {
		// Выполняем перебор всех знаков основания
		for(int16_t i = 0; i < 64; i++){
			// Если знак основания найден
			if(ALPHABET[i] == letter)
				// Выводим номер найденного знака
				return i;
		}
		// Выводим признак того, что знак основанию не принадлежит
		return -1;
	}
	/**
	 * @brief Метод проверки того, что знак является пробельным
	 *
	 * @param letter проверяемый знак
	 *
	 * @return       признак того, что знак является пробельным
	 *
	 */
	static bool space(const char letter) noexcept {
		// Выводим признак принадлежности знака к пробельным
		return ((letter == ' ') || (letter == '\t') || (letter == '\r') || (letter == '\n') || (letter == '\v') || (letter == '\f'));
	}
	/**
	 * @brief Метод проверки допустимости метки записи
	 *
	 * @param label проверяемая метка записи
	 *
	 * @return      признак допустимости метки записи
	 *
	 */
	static bool suitable(const string & label) noexcept {
		// Если метка записи пуста
		if(label.empty())
			// Выводим признак недопустимости метки записи
			return false;
		// Если метка записи начинается или заканчивается пробелом
		if(space(label.front()) || space(label.back()))
			// Выводим признак недопустимости метки записи
			return false;
		/**
		 * Выполняем перебор всех знаков метки записи
		 */
		for(size_t i = 0; i < label.length(); i++){
			// Получаем очередной знак метки записи
			const char letter = label[i];
			// Если знак метки записи не отвечает разделу 3 RFC 7468
			if((letter == '-') || (static_cast <uint8_t> (letter) < 0x20) || (static_cast <uint8_t> (letter) > 0x7E))
				// Выводим признак недопустимости метки записи
				return false;
		}
		// Выводим признак допустимости метки записи
		return true;
	}
	/**
	 * @brief Метод снятия тела записи с основания 64
	 *
	 * @param text   снимаемое с основания тело записи
	 * @param result место, в которое помещается снятое тело записи
	 *
	 * @return       отказ снятия тела записи с основания
	 *
	 */
	static error_t revert(const string & text, vector <uint8_t> & result) noexcept {
		// Набранные знаки основания
		int16_t letters[4] = {0, 0, 0, 0};
		// Количество набранных знаков основания
		size_t count = 0;
		// Количество знаков добивки
		size_t padding = 0;
		/**
		 * Выполняем перебор всего тела записи
		 */
		for(size_t i = 0; i < text.length(); i++){
			// Получаем очередной знак тела записи
			const char letter = text[i];
			// Если знак является пробельным
			if(space(letter))
				// Пропускаем знак, разделы 2 и 3 RFC 7468 дозволяют перевод строки в любом месте тела
				continue;
			// Если знак является знаком добивки
			if(letter == '='){
				// Если добивка встретилась не в конце четвёрки знаков
				if((count != 2) && (count != 3))
					// Выводим отказ о неверной записи добивки
					return error_t::PADDING;
				// Увеличиваем количество знаков добивки
				padding++;
				// Если знаков добивки набралось больше положенного
				if(padding > 2)
					// Выводим отказ о неверной записи добивки
					return error_t::PADDING;
				// Добавляем знак добивки в набор
				letters[count++] = 0;
			// Если знак является знаком основания
			} else {
				// Если знаки добивки уже встречались
				if(padding > 0)
					// Выводим отказ о неверной записи добивки
					return error_t::PADDING;
				// Получаем номер знака в основании
				const int16_t value = number(letter);
				// Если знак основанию не принадлежит
				if(value < 0)
					// Выводим отказ о знаке вне основания
					return error_t::ALPHABET;
				// Добавляем номер знака в набор
				letters[count++] = value;
			}
			// Если четвёрка знаков ещё не набрана
			if(count < 4)
				// Продолжаем набор знаков
				continue;
			// Собираем три байта из четвёрки знаков основания
			const uint32_t block = ((static_cast <uint32_t> (letters[0]) << 18) | (static_cast <uint32_t> (letters[1]) << 12) |
			                        (static_cast <uint32_t> (letters[2]) << 6) | static_cast <uint32_t> (letters[3]));
			/**
			 * Выполняем помещение собранных байтов в итог
			 */
			try {
				// Добавляем первый байт четвёрки
				result.push_back(static_cast <uint8_t> ((block >> 16) & 0xFF));
				// Если второй байт четвёрки добивкой не съеден
				if(padding < 2)
					// Добавляем второй байт четвёрки
					result.push_back(static_cast <uint8_t> ((block >> 8) & 0xFF));
				// Если третий байт четвёрки добивкой не съеден
				if(padding < 1)
					// Добавляем третий байт четвёрки
					result.push_back(static_cast <uint8_t> (block & 0xFF));
			/**
			 * Если память под итог выделить не удалось
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ о нехватке памяти
				return error_t::MEMORY;
			}
			// Обнуляем количество набранных знаков основания
			count = 0;
		}
		// Если знаки основания набраны не полной четвёркой
		if(count != 0)
			// Выводим отказ о длине тела записи
			return error_t::LENGTH;
		// Выводим признак успешного снятия тела записи с основания
		return error_t::NONE;
	}
	/**
	 * @brief Метод переноса числа в порядок от старшего байта к младшему
	 *
	 * @param data    переносимое число
	 * @param size    размер переносимого числа
	 * @param reverse признак того, что число записано порядком от младшего байта к старшему
	 * @param result  место, в которое помещается перенесённое число
	 *
	 * @return        отказ переноса числа
	 *
	 */
	static error_t transfer(const uint8_t * data, const size_t size, const bool reverse, vector <uint8_t> & result) noexcept {
		// Начало значащей части числа
		size_t offset = 0;
		// Длина значащей части числа
		size_t length = size;
		/**
		 * Выполняем пропуск незначащих старших байтов числа
		 */
		while((length > 0) && (data[reverse ? (length - 1) : offset] == 0x00)){
			// Если число записано порядком от старшего байта к младшему
			if(!reverse)
				// Сдвигаем начало значащей части числа
				offset++;
			// Уменьшаем длину значащей части числа
			length--;
		}
		// Если значащей части у числа не осталось вовсе
		if(length == 0)
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Определяем разрядность ключа по длине его значащей части
		const size_t width = ((length <= 32) ? 32 : 64);
		// Если число длиннее наибольшей разрядности ключа
		if(length > width)
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		/**
		 * Выполняем выделение памяти под итог переноса числа
		 */
		try {
			// Выделяем память под итог переноса числа
			result.assign(width, 0);
		/**
		 * Если память под итог выделить не удалось
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ о нехватке памяти
			return error_t::MEMORY;
		}
		/**
		 * Выполняем перенос значащей части числа
		 */
		for(size_t i = 0; i < length; i++)
			// Записываем очередной байт числа порядком от старшего байта к младшему
			result[width - length + i] = (reverse ? data[length - 1 - i] : data[offset + i]);
		// Выводим признак успешного переноса числа
		return error_t::NONE;
	}
	/**
	 * @brief Метод извлечения секретного ключа из обёртки по RFC 5958
	 *
	 * @param data   разбираемая обёртка секретного ключа
	 * @param result место, в которое помещается извлечённый секретный ключ
	 *
	 * @return       отказ извлечения секретного ключа
	 *
	 */
	static error_t unwrap(const vector <uint8_t> & data, vector <uint8_t> & result) noexcept {
		// Разобранный элемент обёртки секретного ключа
		asn1::element_t element;
		// Заводим разборщик обёртки секретного ключа
		asn1::Reader reader(data.data(), data.size());
		// Если набор значений обёртки прочитать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Заводим разборщик содержимого обёртки секретного ключа
		asn1::Reader wrapper = reader.enter(element);
		// Если номер вида записи ключа прочитать не удалось
		if(!wrapper.next(asn1::tag_t::INTEGER, element))
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Если настройки алгоритма ключа прочитать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Если само тело секретного ключа прочитать не удалось
		if(!wrapper.next(asn1::tag_t::OCTET_STRING, element))
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Заводим разборщик тела секретного ключа
		asn1::Reader body(element.content);
		// Если вид записи самого ключа прочитать не удалось
		if(!body.next(element))
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		// Если после записи ключа остались лишние байты
		if(!body.empty())
			// Выводим отказ о теле записи, разобрать которое не удалось
			return error_t::CONTENT;
		/**
		 * Выполняем определение вида записи самого ключа
		 */
		switch(element.tag){
			// Если ключ записан строкой байтов порядком от младшего байта к старшему
			case static_cast <uint32_t> (asn1::tag_t::OCTET_STRING): {
				// Если запись ключа составная либо класс метки не универсальный
				if(element.constructed || (element.cls != asn1::cls_t::UNIVERSAL))
					// Выводим отказ о теле записи, разобрать которое не удалось
					return error_t::CONTENT;
				// Выводим итог переноса ключа порядком от старшего байта к младшему
				return transfer(element.content.data, element.content.size, true, result);
			}
			// Если ключ записан целым числом порядком от старшего байта к младшему
			case static_cast <uint32_t> (asn1::tag_t::INTEGER): {
				// Просмотр значащей части целого числа
				view_t value;
				// Если значащую часть целого числа извлечь не удалось
				if(asn1::integer(element, value) != asn1::error_t::NONE)
					// Выводим отказ о теле записи, разобрать которое не удалось
					return error_t::CONTENT;
				// Выводим итог переноса ключа порядком от старшего байта к младшему
				return transfer(value.data, value.size, false, result);
			}
			// Если ключ записан набором значений по RFC 5915
			case static_cast <uint32_t> (asn1::tag_t::SEQUENCE): {
				// Заводим разборщик набора значений записи ключа
				asn1::Reader inner = body.enter(element);
				// Если номер вида записи ключа прочитать не удалось
				if(!inner.next(asn1::tag_t::INTEGER, element))
					// Выводим отказ о теле записи, разобрать которое не удалось
					return error_t::CONTENT;
				// Если само число ключа прочитать не удалось
				if(!inner.next(asn1::tag_t::OCTET_STRING, element))
					// Выводим отказ о теле записи, разобрать которое не удалось
					return error_t::CONTENT;
				// Выводим итог переноса ключа порядком от старшего байта к младшему
				return transfer(element.content.data, element.content.size, false, result);
			}
		}
		// Выводим отказ о теле записи, разобрать которое не удалось
		return error_t::CONTENT;
	}
};

/**
 * @brief Метод разбора всех записей текста
 *
 * @param text   разбираемый текст
 * @param result набор записей, в который помещается итог разбора
 *
 * @return       отказ разбора текста
 *
 */
pem::error_t anyks::pem::decode(const string & text, vector <block_t> & result) noexcept {
	// Место, до которого разбор текста дошёл
	size_t offset = 0;
	/**
	 * Выполняем разбор текста, пока в нём остаются записи
	 */
	while(offset < text.length()){
		// Выполняем поиск рамки начала записи
		const size_t begin = text.find(OPENING, offset);
		// Если рамки начала записи в тексте больше нет
		if(begin == string::npos)
			// Прекращаем разбор текста
			break;
		// Получаем место, с которого начинается метка записи
		const size_t opening = (begin + (sizeof(OPENING) - 1));
		// Выполняем поиск ограды рамки начала записи
		const size_t fence = text.find(FENCE, opening);
		// Если ограда рамки начала записи не найдена
		if(fence == string::npos)
			// Выводим отказ об оборванной рамке записи
			return error_t::BOUNDARY;
		// Получаем метку записи
		const string & label = text.substr(opening, fence - opening);
		// Если метка записи недопустима
		if(!suitable(label))
			// Выводим отказ о недопустимой метке записи
			return error_t::LABEL;
		// Собираем рамку конца записи
		const string & closing = (string(CLOSING) + label + FENCE);
		// Получаем место, с которого начинается тело записи
		const size_t body = (fence + (sizeof(FENCE) - 1));
		// Выполняем поиск рамки конца записи
		const size_t end = text.find(closing, body);
		// Если рамка конца записи не найдена
		if(end == string::npos)
			// Выводим отказ об оборванной рамке записи
			return error_t::BOUNDARY;
		// Выполняем поиск ближайшей рамки начала записи
		const size_t next = text.find(OPENING, body);
		// Если внутри записи открылась ещё одна запись
		if((next != string::npos) && (next < end))
			// Выводим отказ об оборванной рамке записи
			return error_t::BOUNDARY;
		// Заводим разбираемую запись
		block_t block;
		// Выполняем снятие тела записи с основания 64
		const error_t error = revert(text.substr(body, end - body), block.data);
		// Если снять тело записи с основания не удалось
		if(error != error_t::NONE)
			// Выводим отказ снятия тела записи с основания
			return error;
		/**
		 * Выполняем помещение разобранной записи в итог
		 */
		try {
			// Устанавливаем метку разобранной записи
			block.label = label;
			// Добавляем разобранную запись в итог
			result.push_back(::move(block));
		/**
		 * Если память под итог выделить не удалось
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ о нехватке памяти
			return error_t::MEMORY;
		}
		// Сдвигаем место, до которого разбор текста дошёл
		offset = (end + closing.length());
	}
	// Выводим признак успешного разбора текста
	return error_t::NONE;
}
/**
 * @brief Метод разбора записей заданного вида
 *
 * @param text   разбираемый текст
 * @param label  метка вида отбираемых записей
 * @param result набор тел записей, в который помещается итог разбора
 *
 * @return       отказ разбора текста
 *
 */
pem::error_t anyks::pem::decode(const string & text, const string & label, vector <vector <uint8_t>> & result) noexcept {
	// Набор всех разобранных записей
	vector <block_t> blocks;
	// Выполняем разбор всех записей текста
	const error_t error = pem::decode(text, blocks);
	// Если разобрать записи текста не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора текста
		return error;
	/**
	 * Выполняем перебор всех разобранных записей
	 */
	for(auto & block : blocks){
		// Если метка записи запрошенной не отвечает
		if(block.label.compare(label) != 0)
			// Пропускаем запись другого вида
			continue;
		/**
		 * Выполняем помещение тела записи в итог
		 */
		try {
			// Добавляем тело записи в итог
			result.push_back(::move(block.data));
		/**
		 * Если память под итог выделить не удалось
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ о нехватке памяти
			return error_t::MEMORY;
		}
	}
	// Если записей запрошенного вида в тексте не нашлось
	if(result.empty())
		// Выводим отказ об отсутствии записей запрошенного вида
		return error_t::EMPTY;
	// Выводим признак успешного разбора текста
	return error_t::NONE;
}
/**
 * @brief Метод записи одной записи
 *
 * @param block  записываемая запись
 * @param result текст, в который помещается итог записи
 *
 * @return       отказ записи
 *
 */
pem::error_t anyks::pem::encode(const block_t & block, string & result) noexcept {
	// Если метка записи недопустима
	if(!suitable(block.label))
		// Выводим отказ о недопустимой метке записи
		return error_t::LABEL;
	/**
	 * Выполняем запись обёрнутой записи
	 */
	try {
		// Количество знаков основания, записанных в текущую строку
		size_t width = 0;
		// Записываем рамку начала записи
		result.append(OPENING).append(block.label).append(FENCE).append(1, '\n');
		/**
		 * Выполняем перебор тела записи тройками байтов
		 */
		for(size_t i = 0; i < block.data.size(); i += 3){
			// Получаем количество байтов в текущей тройке
			const size_t count = ((block.data.size() - i) < 3 ? (block.data.size() - i) : 3);
			// Собираем тройку байтов в единое число
			const uint32_t value = ((static_cast <uint32_t> (block.data[i]) << 16) |
			                        (count > 1 ? (static_cast <uint32_t> (block.data[i + 1]) << 8) : 0) |
			                        (count > 2 ? static_cast <uint32_t> (block.data[i + 2]) : 0));
			/**
			 * Выполняем перебор всех знаков основания четвёрки
			 */
			for(size_t j = 0; j < 4; j++){
				// Записываем очередной знак основания либо знак добивки
				result.append(1, (j <= count ? ALPHABET[(value >> (18 - (j * 6))) & 0x3F] : '='));
				// Если строка тела записи набрана целиком
				if(++width == PEM_WIDTH){
					// Записываем перевод строки
					result.append(1, '\n');
					// Обнуляем количество знаков основания текущей строки
					width = 0;
				}
			}
		}
		// Если последняя строка тела записи переводом строки не закрыта
		if(width > 0)
			// Записываем перевод строки
			result.append(1, '\n');
		// Записываем рамку конца записи
		result.append(CLOSING).append(block.label).append(FENCE).append(1, '\n');
	/**
	 * Если память под итог выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ о нехватке памяти
		return error_t::MEMORY;
	}
	// Выводим признак успешной записи
	return error_t::NONE;
}
/**
 * @brief Метод записи набора записей
 *
 * @param blocks записываемый набор записей
 * @param result текст, в который помещается итог записи
 *
 * @return       отказ записи
 *
 */
pem::error_t anyks::pem::encode(const vector <block_t> & blocks, string & result) noexcept {
	// Если набор записей пуст
	if(blocks.empty())
		// Выводим отказ об отсутствии записей
		return error_t::EMPTY;
	/**
	 * Выполняем перебор всего набора записей
	 */
	for(auto & block : blocks){
		// Выполняем запись очередной записи набора
		const error_t error = pem::encode(block, result);
		// Если записать запись набора не удалось
		if(error != error_t::NONE)
			// Выводим отказ записи
			return error;
	}
	// Выводим признак успешной записи
	return error_t::NONE;
}
/**
 * @brief Метод извлечения цепочки сертификатов
 *
 * @param text   разбираемый текст
 * @param result цепочка сертификатов, в которую помещается итог извлечения
 *
 * @return       отказ извлечения цепочки сертификатов
 *
 */
pem::error_t anyks::pem::certificates(const string & text, vector <vector <uint8_t>> & result) noexcept {
	// Выводим итог разбора записей сертификатов
	return pem::decode(text, PEM_CERTIFICATE, result);
}
/**
 * @brief Метод извлечения секретного ключа
 *
 * @param text   разбираемый текст
 * @param result место, в которое помещается извлечённый секретный ключ
 *
 * @return       отказ извлечения секретного ключа
 *
 */
pem::error_t anyks::pem::secret(const string & text, vector <uint8_t> & result) noexcept {
	// Набор всех разобранных записей
	vector <block_t> blocks;
	// Выполняем разбор всех записей текста
	const error_t error = pem::decode(text, blocks);
	// Если разобрать записи текста не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора текста
		return error;
	/**
	 * Выполняем перебор всех разобранных записей
	 */
	for(auto & block : blocks){
		// Если запись хранит секретный ключ
		if(block.label.compare(PEM_SECRET) == 0)
			// Выводим итог извлечения секретного ключа из его обёртки
			return unwrap(block.data, result);
	}
	/**
	 * Выполняем повторный перебор всех разобранных записей
	 */
	for(auto & block : blocks){
		// Если запись хранит зашифрованный секретный ключ
		if(block.label.compare(PEM_ENCRYPTED) == 0)
			// Выводим отказ о зашифрованном ключе
			return error_t::ENCRYPTED;
	}
	// Выводим отказ об отсутствии записей запрошенного вида
	return error_t::EMPTY;
}
/**
 * @brief Метод получения названия отказа
 *
 * @param error отказ, название которого извлекается
 *
 * @return      название отказа
 *
 */
const char * anyks::pem::name(const error_t error) noexcept {
	/**
	 * Выполняем определение отказа
	 */
	switch(static_cast <uint8_t> (error)){
		// Если отказа не произошло
		case static_cast <uint8_t> (error_t::NONE):
			// Выводим название отказа
			return "NONE";
		// Если записей заданного вида в тексте нет
		case static_cast <uint8_t> (error_t::EMPTY):
			// Выводим название отказа
			return "EMPTY";
		// Если рамка записи оборвана
		case static_cast <uint8_t> (error_t::BOUNDARY):
			// Выводим название отказа
			return "BOUNDARY";
		// Если метка записи недопустима
		case static_cast <uint8_t> (error_t::LABEL):
			// Выводим название отказа
			return "LABEL";
		// Если в теле записи встретился знак вне основания 64
		case static_cast <uint8_t> (error_t::ALPHABET):
			// Выводим название отказа
			return "ALPHABET";
		// Если добивка тела записи записана неверно
		case static_cast <uint8_t> (error_t::PADDING):
			// Выводим название отказа
			return "PADDING";
		// Если длина тела записи основанию не отвечает
		case static_cast <uint8_t> (error_t::LENGTH):
			// Выводим название отказа
			return "LENGTH";
		// Если тело записи разбору не поддалось
		case static_cast <uint8_t> (error_t::CONTENT):
			// Выводим название отказа
			return "CONTENT";
		// Если ключ зашифрован
		case static_cast <uint8_t> (error_t::ENCRYPTED):
			// Выводим название отказа
			return "ENCRYPTED";
		// Если память под итог выделить не удалось
		case static_cast <uint8_t> (error_t::MEMORY):
			// Выводим название отказа
			return "MEMORY";
	}
	// Выводим название неизвестного отказа
	return "UNKNOWN";
}
