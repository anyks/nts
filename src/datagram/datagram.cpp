/**
 * @file datagram.cpp
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
 * @brief Исходный файл слоя записей протокола DTLS 1.3 (RFC 9147)
 *
 * @section Намеренные решения
 *
 * 1. Опознаватель связи (RFC 9146) не поддерживается: заголовок с разрядом C разбирается
 *    ровно настолько, чтобы отвергнуть его отказом IDENTIFIER, а длина опознавателя не
 *    угадывается. Разбор остатка дейтаграммы за такой записью невозможен, и связь его
 *    отбрасывает целиком.
 *
 * 2. Объединённый заголовок составляется всегда с шестнадцатиразрядным номером и полем
 *    длины: короткий номер экономит байт, но сужает окно восстановления, а длина позволяет
 *    складывать несколько записей в одну дейтаграмму. Разбор принимает все четыре вида.
 *
 * 3. Маска номера записи у наборов ГОСТ не определена: RFC 9147 знает лишь AES и ChaCha20,
 *    и связь поверх дейтаграмм наборы ГОСТ не предлагает вовсе.
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
#include <datagram/datagram.hpp>
#include <cipher/aes.hpp>
#include <cipher/chacha.hpp>
#include <sys/wipe.hpp>

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
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	// Маска трёх старших разрядов объединённого заголовка
	static constexpr uint8_t UNIFIED_SHAPE = 0xE0;
	// Постоянная часть объединённого заголовка: 001
	static constexpr uint8_t UNIFIED_MARK = 0x20;
	// Разряд опознавателя связи
	static constexpr uint8_t UNIFIED_IDENTIFIER = 0x10;
	// Разряд ширины номера записи: шестнадцать разрядов
	static constexpr uint8_t UNIFIED_WIDE = 0x08;
	// Разряд наличия поля длины
	static constexpr uint8_t UNIFIED_SIZED = 0x04;
	// Два младших разряда поры ключей
	static constexpr uint8_t UNIFIED_EPOCH = 0x03;

	/**
	 * Длина записи номера записи в сообщении подтверждения: два поля по восемь байтов
	 */
	static constexpr size_t NUMBER_WIDTH = 16;

	/**
	 * @brief Метод чтения числа из сетевого порядка байтов
	 *
	 * @param data  читаемая область байтов
	 * @param width число читаемых байтов
	 *
	 * @return      прочитанное число
	 *
	 */
	static uint64_t fetch(const uint8_t * data, const size_t width) noexcept {
		// Прочитанное число
		uint64_t result = 0;
		/**
		 * Выполняем перебор байтов числа от старшего к младшему
		 */
		for(size_t i = 0; i < width; i++)
			// Присоединяем очередной байт числа
			result = ((result << 8) | data[i]);
		// Выводим прочитанное число
		return result;
	}
	/**
	 * @brief Метод записи числа в сетевом порядке байтов
	 *
	 * @param value  записываемое число
	 * @param result место, в которое помещается запись числа
	 * @param width  число записываемых байтов
	 *
	 */
	static void stow(const uint64_t value, uint8_t * result, const size_t width) noexcept {
		/**
		 * Выполняем перебор байтов записываемого числа
		 */
		for(size_t i = 0; i < width; i++)
			// Записываем очередной байт числа от старшего к младшему
			result[i] = static_cast <uint8_t> ((value >> ((width - 1 - i) * 8)) & 0xFF);
	}
	/**
	 * @brief Метод проверки известности вида содержимого записи поверх дейтаграммы
	 *
	 * @param type проверяемый вид содержимого
	 *
	 * @return     признак того, что вид определён RFC 9147
	 *
	 * @note Раздел 4 RFC 9147: смены набора шифрования у DTLS 1.3 нет вовсе, а
	 *       подтверждение добавлено разделом 7
	 *
	 */
	static bool carried(const record::type_t type) noexcept {
		// Выводим признак известности вида содержимого записи
		return ((type == record::type_t::ALERT) || (type == record::type_t::HANDSHAKE) || (type == record::type_t::APPLICATION) || (type == record::type_t::ACK));
	}
};

/**
 * @brief Метод разбора заголовка записи поверх дейтаграммы
 *
 * @param data   разбираемая область байтов от начала записи до конца дейтаграммы
 * @param result заголовок, в который помещается итог разбора
 *
 * @return       отказ разбора заголовка записи
 *
 */
nts::datagram::error_t nts::datagram::parse(const view_t & data, header_t & result) noexcept {
	// Если разбираемая область байтов не передана
	if((data.data == nullptr) || (data.size == 0))
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Если первый байт несёт постоянную часть объединённого заголовка
	if((data.data[0] & UNIFIED_SHAPE) == UNIFIED_MARK){
		// Отмечаем объединённый заголовок защищённой записи
		result.unified = true;
		// Запоминаем наличие опознавателя связи
		result.identifier = ((data.data[0] & UNIFIED_IDENTIFIER) != 0);
		// Запоминаем ширину порядкового номера
		result.bits = (((data.data[0] & UNIFIED_WIDE) != 0) ? 16 : 8);
		// Запоминаем наличие поля длины
		result.sized = ((data.data[0] & UNIFIED_SIZED) != 0);
		// Запоминаем два младших разряда поры ключей
		result.epoch = static_cast <uint16_t> (data.data[0] & UNIFIED_EPOCH);
		// Защищённая запись выдаёт себя за прикладные данные
		result.type = record::type_t::APPLICATION;
		/**
		 * Раздел 4 RFC 9147: длина опознавателя связи известна лишь сторонам, его
		 * согласовавшим; связь его не согласовывает, и разобрать такую запись нечем
		 */
		if(result.identifier)
			// Выводим отказ опознавателя связи
			return error_t::IDENTIFIER;
		// Длина заголовка: байт разрядов, номер и, если есть, длина
		result.length = (1 + static_cast <size_t> (result.bits / 8) + (result.sized ? 2 : 0));
		// Если область байтов заголовок не вмещает
		if(data.size < result.length)
			// Выводим отказ нехватки байтов
			return error_t::HUNGRY;
		// Читаем младшие разряды порядкового номера записи
		result.sequence = fetch(data.data + 1, static_cast <size_t> (result.bits / 8));
		// Если заголовок несёт длину записи
		if(result.sized)
			// Читаем длину содержимого записи
			result.size = static_cast <size_t> (fetch(data.data + 1 + (result.bits / 8), 2));
		// Если длина не указана: содержимым служит остаток дейтаграммы
		else result.size = (data.size - result.length);
		// Если содержимое длиннее дозволенного защищённой записи
		if(result.size > record::RECORD_CIPHERTEXT)
			// Выводим отказ длины записи
			return error_t::LENGTH;
		// Если область байтов содержимое записи не вмещает
		if(data.size < (result.length + result.size))
			// Выводим отказ нехватки байтов
			return error_t::HUNGRY;
		// Выводим успешность разбора объединённого заголовка
		return error_t::NONE;
	}
	// Отмечаем заголовок открытой записи
	result.unified = false;
	// Опознавателя связи у открытой записи нет
	result.identifier = false;
	// Длина у открытой записи есть всегда
	result.sized = true;
	// Порядковый номер открытой записи занимает сорок восемь разрядов
	result.bits = 48;
	// Длина заголовка открытой записи
	result.length = DATAGRAM_PLAIN_HEADER;
	// Если область байтов заголовок не вмещает
	if(data.size < DATAGRAM_PLAIN_HEADER)
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Читаем вид содержимого открытой записи
	result.type = static_cast <record::type_t> (data.data[0]);
	// Если вид содержимого протоколом не определён
	if(!carried(result.type))
		// Выводим отказ вида содержимого
		return error_t::TYPE;
	// Читаем издание протокола заголовка
	const uint16_t version = static_cast <uint16_t> (fetch(data.data + 1, 2));
	/**
	 * Раздел 4 RFC 9147 велит писать в открытую запись издание DTLS 1.2; издание DTLS 1.3
	 * принимается ради снисходительности к собеседнику, пишущему туда своё издание
	 */
	if((version != DATAGRAM_LEGACY) && (version != DATAGRAM_VERSION))
		// Выводим отказ издания протокола
		return error_t::VERSION;
	// Читаем пору ключей открытой записи
	result.epoch = static_cast <uint16_t> (fetch(data.data + 3, 2));
	// Раздел 4.2.1 RFC 9147: открытая запись идёт лишь нулевой порой ключей
	if(result.epoch != 0)
		// Выводим отказ поры ключей
		return error_t::EPOCH;
	// Читаем порядковый номер открытой записи
	result.sequence = fetch(data.data + 5, 6);
	// Читаем длину содержимого открытой записи
	result.size = static_cast <size_t> (fetch(data.data + 11, 2));
	// Если содержимое длиннее дозволенного открытой записи
	if(result.size > record::RECORD_PLAINTEXT)
		// Выводим отказ длины записи
		return error_t::LENGTH;
	// Если содержимое пусто: открытые записи пустыми не бывают
	if(result.size == 0)
		// Выводим отказ длины записи
		return error_t::LENGTH;
	// Если область байтов содержимое записи не вмещает
	if(data.size < (result.length + result.size))
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Выводим успешность разбора заголовка открытой записи
	return error_t::NONE;
}
/**
 * @brief Метод записи заголовка записи поверх дейтаграммы
 *
 * @param header записываемый заголовок записи
 * @param result место, в которое помещается заголовок записи
 * @param length место, в которое помещается длина записанного заголовка
 *
 * @return       отказ записи заголовка записи
 *
 */
nts::datagram::error_t nts::datagram::build(const header_t & header, uint8_t * result, size_t & length) noexcept {
	// Если место для записи заголовка не передано
	if(result == nullptr)
		// Выводим отказ длины записи
		return error_t::LENGTH;
	// Если записывается объединённый заголовок защищённой записи
	if(header.unified){
		// Если содержимое длиннее дозволенного защищённой записи
		if(header.size > record::RECORD_CIPHERTEXT)
			// Выводим отказ длины записи
			return error_t::LENGTH;
		// Записываем байт разрядов: постоянная часть, широкий номер, длина и пора ключей
		result[0] = static_cast <uint8_t> (UNIFIED_MARK | UNIFIED_WIDE | UNIFIED_SIZED | (header.epoch & UNIFIED_EPOCH));
		// Записываем младшие шестнадцать разрядов порядкового номера
		stow(header.sequence, result + 1, 2);
		// Записываем длину содержимого записи
		stow(header.size, result + 3, 2);
		// Выводим длину объединённого заголовка
		length = DATAGRAM_UNIFIED_HEADER;
		// Выводим успешность записи объединённого заголовка
		return error_t::NONE;
	}
	// Если вид содержимого протоколом не определён
	if(!carried(header.type))
		// Выводим отказ вида содержимого
		return error_t::TYPE;
	// Открытая запись идёт лишь нулевой порой ключей
	if(header.epoch != 0)
		// Выводим отказ поры ключей
		return error_t::EPOCH;
	// Если содержимое пусто либо длиннее дозволенного открытой записи
	if((header.size == 0) || (header.size > record::RECORD_PLAINTEXT))
		// Выводим отказ длины записи
		return error_t::LENGTH;
	// Если порядковый номер вышел за сорок восемь разрядов
	if(header.sequence > DATAGRAM_SEQUENCE)
		// Выводим отказ длины записи
		return error_t::LENGTH;
	// Записываем вид содержимого открытой записи
	result[0] = static_cast <uint8_t> (header.type);
	// Записываем издание протокола, доставшееся от DTLS 1.2
	stow(DATAGRAM_LEGACY, result + 1, 2);
	// Записываем нулевую пору ключей
	stow(0, result + 3, 2);
	// Записываем порядковый номер записи
	stow(header.sequence, result + 5, 6);
	// Записываем длину содержимого записи
	stow(header.size, result + 11, 2);
	// Выводим длину заголовка открытой записи
	length = DATAGRAM_PLAIN_HEADER;
	// Выводим успешность записи заголовка открытой записи
	return error_t::NONE;
}
/**
 * @brief Метод разбора обвязки куска сообщения рукопожатия
 *
 * @param data   разбираемая область байтов
 * @param result обвязка, в которую помещается итог разбора
 *
 * @return       отказ разбора обвязки куска
 *
 */
nts::datagram::error_t nts::datagram::parse(const view_t & data, fragment_t & result) noexcept {
	// Если область байтов обвязку куска не вмещает
	if((data.data == nullptr) || (data.size < DATAGRAM_FRAGMENT_HEADER))
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Читаем вид сообщения рукопожатия
	result.type = static_cast <handshake::type_t> (data.data[0]);
	// Если вид сообщения протоколом не определён
	if(!handshake::known(result.type))
		// Выводим отказ вида сообщения
		return error_t::TYPE;
	// Читаем длину тела целого сообщения
	result.size = static_cast <size_t> (fetch(data.data + 1, 3));
	// Читаем порядковый номер сообщения рукопожатия
	result.sequence = static_cast <uint16_t> (fetch(data.data + 4, 2));
	// Читаем смещение куска в теле сообщения
	result.offset = static_cast <size_t> (fetch(data.data + 6, 3));
	// Читаем длину куска
	result.length = static_cast <size_t> (fetch(data.data + 9, 3));
	// Раздел 5.2 RFC 9147: кусок обязан лежать в пределах сообщения
	if((result.offset > result.size) || (result.length > (result.size - result.offset)))
		// Выводим отказ длины куска
		return error_t::LENGTH;
	// Если тело куска область байтов не вмещает
	if((data.size - DATAGRAM_FRAGMENT_HEADER) < result.length)
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Выводим успешность разбора обвязки куска
	return error_t::NONE;
}
/**
 * @brief Метод записи обвязки куска сообщения рукопожатия
 *
 * @param fragment записываемая обвязка куска
 * @param result   место, в которое помещается обвязка куска
 *
 * @return         отказ записи обвязки куска
 *
 */
nts::datagram::error_t nts::datagram::build(const fragment_t & fragment, uint8_t * result) noexcept {
	// Если место для записи обвязки не передано
	if(result == nullptr)
		// Выводим отказ длины куска
		return error_t::LENGTH;
	// Если вид сообщения протоколом не определён
	if(!handshake::known(fragment.type))
		// Выводим отказ вида сообщения
		return error_t::TYPE;
	// Если длина сообщения вышла за предел протокола
	if(fragment.size > handshake::HANDSHAKE_LIMIT)
		// Выводим отказ длины куска
		return error_t::LENGTH;
	// Если кусок не лежит в пределах сообщения
	if((fragment.offset > fragment.size) || (fragment.length > (fragment.size - fragment.offset)))
		// Выводим отказ длины куска
		return error_t::LENGTH;
	// Записываем вид сообщения рукопожатия
	result[0] = static_cast <uint8_t> (fragment.type);
	// Записываем длину тела целого сообщения
	stow(fragment.size, result + 1, 3);
	// Записываем порядковый номер сообщения
	stow(fragment.sequence, result + 4, 2);
	// Записываем смещение куска
	stow(fragment.offset, result + 6, 3);
	// Записываем длину куска
	stow(fragment.length, result + 9, 3);
	// Выводим успешность записи обвязки куска
	return error_t::NONE;
}
/**
 * @brief Метод разбора тела сообщения подтверждения
 *
 * @param data   разбираемое тело сообщения подтверждения
 * @param result перечень, в который помещаются подтверждённые номера записей
 *
 * @return       отказ разбора сообщения подтверждения
 *
 */
nts::datagram::error_t nts::datagram::parse(const view_t & data, vector <number_t> & result) noexcept {
	// Если область байтов длину перечня не вмещает
	if((data.data == nullptr) || (data.size < 2))
		// Выводим отказ нехватки байтов
		return error_t::HUNGRY;
	// Читаем длину перечня номеров записей
	const size_t length = static_cast <size_t> (fetch(data.data, 2));
	// Раздел 7 RFC 9147: перечень состоит из целых номеров записей и кончается с телом
	if(((length % NUMBER_WIDTH) != 0) || ((data.size - 2) != length))
		// Выводим отказ длины перечня
		return error_t::LENGTH;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор номеров записей перечня
		 */
		for(size_t offset = 2; offset < data.size; offset += NUMBER_WIDTH)
			// Добавляем очередной номер записи в перечень
			result.push_back(number_t(fetch(data.data + offset, 8), fetch(data.data + offset + 8, 8)));
	/**
	 * Если памяти под перечень номеров не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора сообщения подтверждения
	return error_t::NONE;
}
/**
 * @brief Метод составления тела сообщения подтверждения
 *
 * @param numbers подтверждаемые номера записей
 * @param result  накопитель, в который складывается тело сообщения
 *
 * @return        отказ составления сообщения подтверждения
 *
 */
nts::datagram::error_t nts::datagram::build(const vector <number_t> & numbers, vector <uint8_t> & result) noexcept {
	// Длина перечня номеров записей
	const size_t length = (numbers.size() * NUMBER_WIDTH);
	// Если перечень в два байта длины не входит
	if(length > 0xFFFF)
		// Выводим отказ длины перечня
		return error_t::LENGTH;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Смещение тела сообщения в накопителе
		const size_t offset = result.size();
		// Занимаем место под длину и перечень номеров записей
		result.resize(offset + 2 + length, 0);
		// Записываем длину перечня номеров записей
		stow(length, result.data() + offset, 2);
		/**
		 * Выполняем перебор подтверждаемых номеров записей
		 */
		for(size_t i = 0; i < numbers.size(); i++){
			// Записываем пору ключей очередной записи
			stow(numbers[i].epoch, result.data() + offset + 2 + (i * NUMBER_WIDTH), 8);
			// Записываем порядковый номер очередной записи
			stow(numbers[i].sequence, result.data() + offset + 2 + (i * NUMBER_WIDTH) + 8, 8);
		}
	/**
	 * Если памяти под тело сообщения не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления сообщения подтверждения
	return error_t::NONE;
}
/**
 * @brief Метод выработки маски номера записи
 *
 * @param suite  набор шифрования связи
 * @param key    ключ шифрования номера записи, выведенный меткой «sn»
 * @param sample образец шифртекста длиной DATAGRAM_SAMPLE байтов
 * @param result место, в которое помещаются DATAGRAM_MASK байтов маски
 *
 * @return       признак успешности выработки маски
 *
 */
bool nts::datagram::mask(const protect::suite_t suite, const view_t & key, const uint8_t * sample, uint8_t * result) noexcept {
	// Если образец либо место итога не переданы
	if((sample == nullptr) || (result == nullptr) || (key.data == nullptr))
		// Выводим отказ выработки маски
		return false;
	// Если ключ не сходится длиной с ключом набора
	if(key.size != protect::key(suite))
		// Выводим отказ выработки маски
		return false;
	/**
	 * Выполняем определение набора шифрования
	 */
	switch(static_cast <uint16_t> (suite)){
		// Если набор шифрования на AES
		case static_cast <uint16_t> (protect::suite_t::AES_128_GCM_SHA256):
		case static_cast <uint16_t> (protect::suite_t::AES_256_GCM_SHA384): {
			// Объект базового шифра AES
			cipher::aes_t aes;
			// Если ключ базового шифра установить не удалось
			if(!aes.key(key))
				// Выводим отказ выработки маски
				return false;
			// Место, в которое помещается блок AES-ECB от образца
			uint8_t block[cipher::AES_BLOCK];
			// Если блок зашифровать не удалось
			if(!aes.encrypt(sample, block)){
				// Выполняем затирание блока
				wipe(block, sizeof(block));
				// Выводим отказ выработки маски
				return false;
			}
			// Переносим первые байты блока на место маски
			::memcpy(result, block, DATAGRAM_MASK);
			// Выполняем затирание блока
			wipe(block, sizeof(block));
			// Выводим успешность выработки маски
			return true;
		}
		// Если набор шифрования ChaCha20-Poly1305
		case static_cast <uint16_t> (protect::suite_t::CHACHA20_POLY1305_SHA256): {
			// Объект поточного шифра ChaCha20
			cipher::chacha_t chacha;
			/**
			 * Раздел 4.2.3 RFC 9147: счётчик блока берётся первыми четырьмя байтами образца
			 * в порядке от младшего байта к старшему, одноразовое значение - остальными
			 */
			const uint32_t counter = (static_cast <uint32_t> (sample[0]) | (static_cast <uint32_t> (sample[1]) << 8) | (static_cast <uint32_t> (sample[2]) << 16) | (static_cast <uint32_t> (sample[3]) << 24));
			// Если шифр запустить не удалось
			if(!chacha.start(key, view_t(sample + 4, cipher::CHACHA_NONCE), counter))
				// Выводим отказ выработки маски
				return false;
			// Место, в которое помещается блок гаммы
			uint8_t gamma[cipher::CHACHA_BLOCK];
			// Если блок гаммы выработать не удалось
			if(!chacha.block(gamma)){
				// Выполняем затирание блока гаммы
				wipe(gamma, sizeof(gamma));
				// Выводим отказ выработки маски
				return false;
			}
			// Переносим первые байты гаммы на место маски
			::memcpy(result, gamma, DATAGRAM_MASK);
			// Выполняем затирание блока гаммы
			wipe(gamma, sizeof(gamma));
			// Выводим успешность выработки маски
			return true;
		}
	}
	// Выводим отказ выработки маски: набор маски не имеет
	return false;
}
/**
 * @brief Метод восстановления полного порядкового номера записи по младшим разрядам
 *
 * @param expected ожидаемый порядковый номер: следующий за наибольшим принятым
 * @param junior   младшие разряды номера, принесённые заголовком
 * @param bits     число принесённых разрядов: восемь либо шестнадцать
 *
 * @return         полный порядковый номер, ближайший к ожидаемому
 *
 */
uint64_t nts::datagram::restore(const uint64_t expected, const uint64_t junior, const size_t bits) noexcept {
	// Если число разрядов вышло за ширину номера
	if((bits == 0) || (bits >= 48))
		// Выводим младшие разряды как есть
		return junior;
	// Размах младших разрядов
	const uint64_t span = (1ULL << bits);
	// Половина размаха: граница выбора ближайшего номера
	const uint64_t half = (span >> 1);
	// Маска старших разрядов ожидаемого номера
	const uint64_t senior = ~(span - 1);
	// Соискатель: старшие разряды ожидаемого номера с младшими из заголовка
	uint64_t candidate = ((expected & senior) | (junior & (span - 1)));
	// Если соискатель отстал от ожидаемого больше чем на половину размаха
	if((candidate + half) < expected)
		// Переходим к следующему размаху
		candidate += span;
	// Если соискатель обогнал ожидаемый больше чем на половину размаха
	else if((candidate > (expected + half)) && (candidate >= span))
		// Возвращаемся к предыдущему размаху
		candidate -= span;
	// Выводим восстановленный порядковый номер
	return (candidate & DATAGRAM_SEQUENCE);
}
/**
 * @brief Метод получения ожидаемого порядкового номера записи
 *
 * @return номер, следующий за наибольшим принятым, ноль до первой записи
 *
 */
uint64_t nts::datagram::Window::expected() const noexcept {
	// Выводим номер, следующий за наибольшим принятым
	return (this->_filled ? (this->_top + 1) : 0);
}
/**
 * @brief Метод проверки того, что запись повторная либо позади окна
 *
 * @param sequence порядковый номер проверяемой записи
 *
 * @return         признак того, что запись отбрасывается
 *
 */
bool nts::datagram::Window::stale(const uint64_t sequence) const noexcept {
	// Если ни одна запись ещё не принята
	if(!this->_filled)
		// Выводим признак того, что запись годна
		return false;
	// Если запись впереди наибольшей принятой
	if(sequence > this->_top)
		// Выводим признак того, что запись годна
		return false;
	// Отставание записи от наибольшей принятой
	const uint64_t lag = (this->_top - sequence);
	// Если запись позади окна
	if(lag >= DATAGRAM_WINDOW)
		// Выводим признак того, что запись отбрасывается
		return true;
	// Выводим признак того, что запись уже отмечена
	return ((this->_bits & (1ULL << lag)) != 0);
}
/**
 * @brief Метод отметки принятой записи
 *
 * @param sequence порядковый номер принятой записи
 *
 */
void nts::datagram::Window::mark(const uint64_t sequence) noexcept {
	// Если ни одна запись ещё не принята либо запись впереди наибольшей
	if(!this->_filled || (sequence > this->_top)){
		// Сдвиг окна вперёд
		const uint64_t shift = (this->_filled ? (sequence - this->_top) : 0);
		// Если окно сдвигается дальше своей ширины
		if(shift >= DATAGRAM_WINDOW)
			// Отмечаем одну лишь новую запись
			this->_bits = 1;
		// Сдвигаем разряды принятых записей и отмечаем новую
		else this->_bits = ((this->_bits << shift) | 1ULL);
		// Запоминаем наибольший принятый номер
		this->_top = sequence;
		// Отмечаем, что запись принята
		this->_filled = true;
		// Выходим из метода
		return;
	}
	// Отставание записи от наибольшей принятой
	const uint64_t lag = (this->_top - sequence);
	// Если запись лежит в окне
	if(lag < DATAGRAM_WINDOW)
		// Отмечаем запись в окне
		this->_bits |= (1ULL << lag);
}
/**
 * @brief Метод сброса окна
 *
 */
void nts::datagram::Window::clear() noexcept {
	// Сбрасываем признак принятой записи
	this->_filled = false;
	// Сбрасываем наибольший принятый номер
	this->_top = 0;
	// Сбрасываем разряды принятых записей
	this->_bits = 0;
}
/**
 * @brief Конструктор
 *
 */
nts::datagram::Window::Window() noexcept : _filled(false), _top(0), _bits(0) {}
