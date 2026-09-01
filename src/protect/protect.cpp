/**
 * @file protect.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля защиты записей протокола TLS 1.3 наборами шифрования
 *        на алгоритмах ГОСТ
 *
 * @section Намеренные решения
 *
 * 1. Ключ записи вырабатывается заново лишь тогда, когда обрезанный постоянными
 *    порядковый номер изменился. Постоянные построения TLSTREE обрезают номер старшими
 *    разрядами, оттого у соседних записей обрезанный номер чаще всего один и тот же, а
 *    выработка ключа стоит шести хеширований. Итог от этого не меняется ни на байт.
 *
 * 2. Старший разряд одноразового значения гасится, а не отвергается вместе со всем
 *    вектором замены. Так велит раздел 4.1.1 описания наборов: разряд занят самим
 *    режимом MGM, а гашение единственного разряда вектора замены различия соседних
 *    записей не отменяет - номер записи занимает младшие восемь байтов.
 *
 * 3. Порядковый номер растёт лишь после успеха. Отказ снятия защиты смертелен для связи
 *    по разделу 5.2 RFC 8446, и продолжать приём после него всё равно не с чем.
 *
 * 4. Наложение защиты составляет целую запись вместе с заголовком. Заголовок служит
 *    связанными данными шифрования, и составить его обязан тот, кто накладывает защиту:
 *    иначе связанные данные и сама запись разъехались бы.
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
#include <digest/kdf.hpp>
#include <protect/protect.hpp>

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
	using namespace nts::protect;

	/**
	 * @brief Отказы работы модуля
	 *
	 * @note Имя заведено своё намеренно: у glibc есть собственный error_t в глобальном
	 *       пространстве имён (расширение GNU в <errno.h>), а помощники лежат в
	 *       безымянном пространстве, откуда поиск имени уходит сразу в глобальное - и
	 *       всякое обращение к error_t выходит там двусмысленным. Своё имя поиск
	 *       находит прежде глобального, и двусмысленности не возникает
	 *
	 */
	typedef protect::error_t error_t;

	/**
	 * @brief Метки ярусов выработки ключа записи
	 *
	 */
	static const char * LEVELS[3] = {"level1", "level2", "level3"};

	/**
	 * @brief Постоянные обрезки порядкового номера записи
	 *
	 * @details Таблица 1 описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ
	 *
	 */
	static const struct Sample {
		// Набор шифрования, которому принадлежат постоянные
		suite_t suite;
		// Постоянные обрезки порядкового номера записи по ярусам выработки ключа
		uint64_t masks[3];
		// Наибольший порядковый номер записи набора шифрования
		uint64_t limit;
		// Длина блока базового шифра набора шифрования
		size_t size;
	} SAMPLES[4] = {
		{suite_t::KUZNYECHIK_MGM_L, {0xF800000000000000ULL, 0xFFFFFFF000000000ULL, 0xFFFFFFFFFFFFE000ULL}, 0xFFFFFFFFFFFFFFFFULL, 16},
		{suite_t::MAGMA_MGM_L,      {0xFFE0000000000000ULL, 0xFFFFFFFFC0000000ULL, 0xFFFFFFFFFFFFFF80ULL}, 0xFFFFFFFFFFFFFFFFULL, 8},
		{suite_t::KUZNYECHIK_MGM_S, {0xFFFFFFFFE0000000ULL, 0xFFFFFFFFFFFF0000ULL, 0xFFFFFFFFFFFFFFF8ULL}, 0x000003FFFFFFFFFFULL, 16},
		{suite_t::MAGMA_MGM_S,      {0xFFFFFFFFFC000000ULL, 0xFFFFFFFFFFFFE000ULL, 0xFFFFFFFFFFFFFFFFULL}, 0x0000007FFFFFFFFFULL, 8}
	};

	/**
	 * @brief Метод поиска описания набора шифрования
	 *
	 * @param suite разыскиваемый набор шифрования
	 *
	 * @return      описание набора шифрования либо nullptr
	 *
	 */
	static const Sample * search(const suite_t suite) noexcept {
		/**
		 * Выполняем перебор описаний известных наборов шифрования
		 */
		for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
			// Если описание разыскиваемого набора шифрования найдено
			if(SAMPLES[i].suite == suite)
				// Выводим описание разыскиваемого набора шифрования
				return &SAMPLES[i];
		}
		// Выводим признак того, что набор шифрования неизвестен
		return nullptr;
	}
	/**
	 * @brief Метод затирания области памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Если затираемая область памяти передана
		if((data != nullptr) && (size > 0)){
			// Получаем изменчивый указатель на затираемую область памяти
			volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
			/**
			 * Выполняем перебор байтов затираемой области памяти
			 */
			for(size_t i = 0; i < size; i++)
				// Обнуляем очередной байт области памяти
				item[i] = 0;
		}
	}
	/**
	 * @brief Метод записи числа восемью байтами старшим разрядом вперёд
	 *
	 * @param value записываемое число
	 * @param result место, в которое помещается запись числа
	 *
	 */
	static void number(const uint64_t value, uint8_t * result) noexcept {
		/**
		 * Выполняем перебор байтов записи числа
		 */
		for(size_t i = 0; i < 8; i++)
			// Записываем очередной байт числа старшим разрядом вперёд
			result[i] = static_cast <uint8_t> ((value >> ((7 - i) * 8)) & 0xFF);
	}
};

/**
 * @brief Метод получения длины блока базового шифра набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      длина блока базового шифра в байтах, ноль у неизвестного набора
 *
 */
size_t nts::protect::block(const suite_t suite) noexcept {
	// Выполняем поиск описания набора шифрования
	const Sample * sample = search(suite);
	// Выводим длину блока базового шифра набора шифрования
	return ((sample != nullptr) ? sample->size : 0);
}
/**
 * @brief Метод получения наибольшего порядкового номера записи набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      наибольший порядковый номер записи, ноль у неизвестного набора
 *
 */
uint64_t nts::protect::limit(const suite_t suite) noexcept {
	// Выполняем поиск описания набора шифрования
	const Sample * sample = search(suite);
	// Выводим наибольший порядковый номер записи набора шифрования
	return ((sample != nullptr) ? sample->limit : 0);
}
/**
 * @brief Метод выработки ключа записи построением TLSTREE
 *
 * @param suite    набор шифрования, которым заданы постоянные построения
 * @param key      корневой ключ выработки ключа записи
 * @param sequence порядковый номер записи
 * @param result   место, в которое помещается ключ записи
 *
 * @return         признак успешности выработки ключа записи
 *
 */
bool nts::protect::tree(const suite_t suite, const view_t & key, const uint64_t sequence, uint8_t * result) noexcept {
	// Если место для ключа записи не передано
	if(result == nullptr)
		// Выводим отказ выработки ключа записи
		return false;
	// Если корневой ключ выработки не занимает всей своей длины
	if((key.data == nullptr) || (key.size != PROTECT_KEY))
		// Выводим отказ выработки ключа записи
		return false;
	// Выполняем поиск описания набора шифрования
	const Sample * sample = search(suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ выработки ключа записи
		return false;
	// Ключ, выработанный предыдущим ярусом построения
	uint8_t buffer[PROTECT_KEY];
	// Затравка выработки ключа очередного яруса построения
	uint8_t seed[8];
	// Признак успешности выработки ключа записи
	bool ok = true;
	// Записываем корневой ключ выработки ключа записи
	::memcpy(buffer, key.data, key.size);
	/**
	 * Выполняем перебор ярусов построения ключа записи
	 */
	for(size_t i = 0; ok && (i < 3); i++){
		// Записываем затравку яруса: порядковый номер, обрезанный постоянной яруса
		number((sequence & sample->masks[i]), seed);
		// Выполняем выработку ключа очередного яруса построения
		ok = digest::kdf(view_t(buffer, PROTECT_KEY), view_t(reinterpret_cast <const uint8_t *> (LEVELS[i]), ::strlen(LEVELS[i])), view_t(seed, sizeof(seed)), buffer);
	}
	// Если ключ записи выработать удалось
	if(ok)
		// Записываем выработанный ключ записи
		::memcpy(result, buffer, PROTECT_KEY);
	// Выполняем затирание ключа яруса построения
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки ключа записи
	return ok;
}
/**
 * @brief Метод подготовки базового шифра к защите записи
 *
 * @param sequence порядковый номер защищаемой записи
 * @param block    описание базового шифра, в которое помещается итог
 *
 * @return         отказ подготовки базового шифра
 *
 */
nts::protect::error_t nts::protect::Protection::prepare(const uint64_t sequence, cipher::block_t & block) noexcept {
	// Выполняем поиск описания набора шифрования
	const Sample * sample = search(this->_suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ подготовки базового шифра
		return error_t::STATE;
	// Признак того, что ключ записи требуется выработать заново
	bool fresh = !this->_ready;
	/**
	 * Выполняем перебор ярусов построения ключа записи
	 */
	for(size_t i = 0; !fresh && (i < 3); i++)
		// Ключ записи стареет, как только обрезанный номер записи изменился
		fresh = ((sequence & sample->masks[i]) != (this->_derived & sample->masks[i]));
	// Если ключ записи требуется выработать заново
	if(fresh){
		// Ключ защищаемой записи
		uint8_t key[PROTECT_KEY];
		// Если ключ записи выработать не удалось
		if(!nts::protect::tree(this->_suite, view_t(this->_key, PROTECT_KEY), sequence, key)){
			// Выполняем затирание ключа записи
			wipe(key, sizeof(key));
			// Выводим отказ подготовки базового шифра
			return error_t::CIPHER;
		}
		// Признак успешности установки ключа базового шифра
		bool ok = false;
		// Если базовым шифром набора служит «Магма»
		if(sample->size == 8)
			// Выполняем установку ключа базового шифра «Магма»
			ok = this->_magma.key(view_t(key, sizeof(key)));
		// Если базовым шифром набора служит «Кузнечик»
		else ok = this->_kuznyechik.key(view_t(key, sizeof(key)));
		// Выполняем затирание ключа записи
		wipe(key, sizeof(key));
		// Если ключ базового шифра установить не удалось
		if(!ok)
			// Выводим отказ подготовки базового шифра
			return error_t::CIPHER;
		// Запоминаем порядковый номер, на котором выработан ключ записи
		this->_derived = sequence;
	}
	// Если базовым шифром набора служит «Магма»
	if(sample->size == 8)
		// Устанавливаем описание базового шифра «Магма»
		block = cipher::block_t(this->_magma);
	// Если базовым шифром набора служит «Кузнечик»
	else block = cipher::block_t(this->_kuznyechik);
	// Выводим успешность подготовки базового шифра
	return error_t::NONE;
}
/**
 * @brief Метод выработки одноразового значения записи
 *
 * @param sequence порядковый номер защищаемой записи
 * @param result   место, в которое помещается одноразовое значение
 *
 */
void nts::protect::Protection::nonce(const uint64_t sequence, uint8_t * result) const noexcept {
	// Записываем вектор замены направления связи
	::memcpy(result, this->_vector, this->_size);
	/**
	 * Раздел 5.3 RFC 8446: порядковый номер выравнивается по правому краю вектора замены
	 */
	for(size_t i = 0; i < 8; i++)
		// Складываем очередной байт номера с байтом вектора замены
		result[this->_size - 1 - i] ^= static_cast <uint8_t> ((sequence >> (i * 8)) & 0xFF);
	/**
	 * Старший разряд одноразового значения занят самим режимом MGM и потому гасится
	 */
	result[0] = static_cast <uint8_t> (result[0] & 0x7F);
}
/**
 * @brief Метод проверки готовности защиты записей к работе
 *
 * @return признак того, что ключевой материал установлен
 *
 */
bool nts::protect::Protection::ready() const noexcept {
	// Выводим признак того, что ключевой материал установлен
	return this->_ready;
}
/**
 * @brief Метод получения набора шифрования, которым защищаются записи
 *
 * @return набор шифрования направления связи
 *
 */
suite_t nts::protect::Protection::suite() const noexcept {
	// Выводим набор шифрования направления связи
	return this->_suite;
}
/**
 * @brief Метод получения порядкового номера очередной записи
 *
 * @return порядковый номер очередной записи направления связи
 *
 */
uint64_t nts::protect::Protection::sequence() const noexcept {
	// Выводим порядковый номер очередной записи направления связи
	return this->_sequence;
}
/**
 * @brief Метод установки ключевого материала направления связи
 *
 * @param suite  устанавливаемый набор шифрования
 * @param key    корневой ключ направления связи
 * @param vector вектор замены направления связи
 *
 * @return       признак успешности установки ключевого материала
 *
 */
bool nts::protect::Protection::start(const suite_t suite, const view_t & key, const view_t & vector) noexcept {
	// Выполняем сброс прежнего ключевого материала
	this->clear();
	// Выполняем поиск описания набора шифрования
	const Sample * sample = search(suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ установки ключевого материала
		return false;
	// Если корневой ключ направления связи не занимает всей своей длины
	if((key.data == nullptr) || (key.size != PROTECT_KEY))
		// Выводим отказ установки ключевого материала
		return false;
	// Если вектор замены не занимает длины блока базового шифра
	if((vector.data == nullptr) || (vector.size != sample->size))
		// Выводим отказ установки ключевого материала
		return false;
	// Запоминаем набор шифрования направления связи
	this->_suite = suite;
	// Запоминаем длину блока базового шифра набора шифрования
	this->_size = sample->size;
	// Запоминаем наибольший порядковый номер записи набора шифрования
	this->_limit = sample->limit;
	// Запоминаем корневой ключ направления связи
	::memcpy(this->_key, key.data, key.size);
	// Запоминаем вектор замены направления связи
	::memcpy(this->_vector, vector.data, vector.size);
	// Описание базового шифра защищаемой записи
	cipher::block_t block;
	// Если базовый шифр на первой записи подготовить не удалось
	if(this->prepare(0, block) != error_t::NONE){
		// Выполняем сброс ключевого материала направления связи
		this->clear();
		// Выводим отказ установки ключевого материала
		return false;
	}
	// Устанавливаем признак готовности защиты записей к работе
	this->_ready = true;
	// Выводим успешность установки ключевого материала
	return true;
}
/**
 * @brief Метод сброса ключевого материала направления связи
 *
 */
void nts::protect::Protection::clear() noexcept {
	// Выполняем затирание корневого ключа направления связи
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание вектора замены направления связи
	wipe(this->_vector, sizeof(this->_vector));
	// Выполняем затирание раундовых ключей базового шифра «Магма»
	this->_magma.clear();
	// Выполняем затирание раундовых ключей базового шифра «Кузнечик»
	this->_kuznyechik.clear();
	// Выполняем сброс набора шифрования направления связи
	this->_suite = suite_t::NONE;
	// Выполняем сброс длины блока базового шифра
	this->_size = 0;
	// Выполняем сброс порядкового номера очередной записи
	this->_sequence = 0;
	// Выполняем сброс наибольшего порядкового номера записи
	this->_limit = 0;
	// Выполняем сброс порядкового номера выработки ключа записи
	this->_derived = 0;
	// Снимаем признак готовности защиты записей к работе
	this->_ready = false;
}
/**
 * @brief Метод наложения защиты на запись
 *
 * @param type    истинный вид содержимого защищаемой записи
 * @param data    защищаемое содержимое записи
 * @param result  накопитель, в конец которого дописывается защищённая запись
 * @param padding длина дополнения, скрывающего истинную длину содержимого
 *
 * @return        отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::seal(const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding) noexcept {
	// Если ключевой материал направления связи ещё не установлен
	if(!this->_ready)
		// Выводим отказ наложения защиты на запись
		return error_t::STATE;
	// Если истинный вид содержимого записи протоколом не определён
	if(!record::known(type))
		// Выводим отказ наложения защиты на запись
		return error_t::TYPE;
	// Если порядковые номера записей на этом ключевом материале исчерпаны
	if(this->_sequence > this->_limit)
		// Выводим отказ наложения защиты на запись
		return error_t::SEQUENCE;
	// Получаем объём защищаемого содержимого записи
	const size_t total = ((data.data != nullptr) ? data.size : 0);
	/**
	 * Слагаемые сверяются ПРЕЖДЕ, чем сложены. Длина открытого текста набирается из
	 * трёх слагаемых, и дополнение среди них - довод, приходящий от потребителя
	 * фреймворка любой величины. При большом дополнении сумма заворачивается за ноль
	 * и выходит малой, а малую сверка с пределом пропускает: накопитель открытого
	 * текста оказался бы пуст, тогда как перенос содержимого шёл бы на весь его объём,
	 * и оплошность потребителя обратилась бы выходом за память
	 */
	if((total > record::RECORD_PLAINTEXT) || (padding > record::RECORD_CIPHERTEXT))
		// Выводим отказ наложения защиты на запись
		return error_t::LENGTH;
	// Определяем длину открытого текста защищаемой записи
	const size_t length = (total + 1 + padding);
	// Если защищённая запись выходит за дозволенные пределы
	if((length + this->_size) > record::RECORD_CIPHERTEXT)
		// Выводим отказ наложения защиты на запись
		return error_t::LENGTH;
	// Описание базового шифра защищаемой записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к защите записи
	const error_t error = this->prepare(this->_sequence, block);
	// Если базовый шифр к защите записи подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ наложения защиты на запись
		return error;
	// Одноразовое значение защищаемой записи
	uint8_t nonce[PROTECT_VECTOR];
	// Выполняем выработку одноразового значения защищаемой записи
	this->nonce(this->_sequence, nonce);
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Если режим шифрования запустить не удалось
	if(!galois.start(block, view_t(nonce, this->_size), this->_size))
		// Выводим отказ наложения защиты на запись
		return error_t::CIPHER;
	// Заголовок защищаемой записи
	record::header_t header;
	// Устанавливаем вид содержимого защищённой записи
	header.type = record::type_t::APPLICATION;
	// Устанавливаем версию протокола защищённой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого защищённой записи
	header.size = (length + this->_size);
	// Место, в которое записывается заголовок защищаемой записи
	uint8_t associated[record::RECORD_HEADER];
	// Если заголовок защищаемой записи составить не удалось
	if(record::build(header, associated) != record::error_t::NONE)
		// Выводим отказ наложения защиты на запись
		return error_t::LENGTH;
	// Отказ, которым завершилось наложение защиты на запись
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открытый текст защищаемой записи
		vector <uint8_t> plain(length, 0);
		// Если защищаемое содержимое записи передано
		if(total > 0)
			// Записываем защищаемое содержимое записи
			::memcpy(plain.data(), data.data, total);
		// Записываем истинный вид содержимого защищаемой записи
		plain[total] = static_cast <uint8_t> (type);
		// Запоминаем длину накопителя до дописывания защищённой записи
		const size_t offset = result.size();
		// Выполняем дописывание заголовка защищённой записи
		result.insert(result.end(), associated, associated + record::RECORD_HEADER);
		// Выполняем расширение накопителя под шифртекст и метку целостности
		result.resize(offset + record::RECORD_HEADER + length + this->_size, 0);
		// Получаем указатель на место шифртекста защищаемой записи
		uint8_t * cipher = (result.data() + offset + record::RECORD_HEADER);
		// Если наложить шифрование с проверкой целостности не удалось
		if(!galois.encrypt(view_t(associated, record::RECORD_HEADER), view_t(plain.data(), plain.size()), cipher, (cipher + length))){
			// Выполняем откат накопителя к состоянию до наложения защиты
			result.resize(offset);
			// Запоминаем отказ работы базового шифра
			outcome = error_t::CIPHER;
		}
		// Выполняем затирание открытого текста защищаемой записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под защищённую запись не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения защищаемой записи
	wipe(nonce, sizeof(nonce));
	// Если защита на запись наложена
	if(outcome == error_t::NONE)
		// Увеличиваем порядковый номер очередной записи
		this->_sequence++;
	// Выводим отказ, которым завершилось наложение защиты на запись
	return outcome;
}
/**
 * @brief Метод снятия защиты с записи
 *
 * @param header заголовок принятой защищённой записи
 * @param data   защищённое содержимое принятой записи
 * @param type   вид содержимого, в который помещается истинный вид содержимого записи
 * @param result накопитель, в конец которого дописывается открытое содержимое записи
 *
 * @return       отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::open(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept {
	// Если ключевой материал направления связи ещё не установлен
	if(!this->_ready)
		// Выводим отказ снятия защиты с записи
		return error_t::STATE;
	/**
	 * Раздел 5.2 RFC 8446: защищённая запись всегда выдаёт себя за прикладные данные
	 */
	if(header.type != record::type_t::APPLICATION)
		// Выводим отказ снятия защиты с записи
		return error_t::TYPE;
	// Если порядковые номера записей на этом ключевом материале исчерпаны
	if(this->_sequence > this->_limit)
		// Выводим отказ снятия защиты с записи
		return error_t::SEQUENCE;
	// Если содержимое записи не вмещает ни метки целостности, ни вида содержимого
	if((data.data == nullptr) || (data.size <= this->_size) || (data.size != header.size))
		// Выводим отказ снятия защиты с записи
		return error_t::LENGTH;
	// Определяем длину открытого текста принятой записи
	const size_t length = (data.size - this->_size);
	// Описание базового шифра принятой записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к снятию защиты с записи
	const error_t error = this->prepare(this->_sequence, block);
	// Если базовый шифр к снятию защиты подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ снятия защиты с записи
		return error;
	// Одноразовое значение принятой записи
	uint8_t nonce[PROTECT_VECTOR];
	// Выполняем выработку одноразового значения принятой записи
	this->nonce(this->_sequence, nonce);
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Если режим шифрования запустить не удалось
	if(!galois.start(block, view_t(nonce, this->_size), this->_size))
		// Выводим отказ снятия защиты с записи
		return error_t::CIPHER;
	// Место, в которое записывается заголовок принятой записи
	uint8_t associated[record::RECORD_HEADER];
	// Если заголовок принятой записи составить не удалось
	if(record::build(header, associated) != record::error_t::NONE)
		// Выводим отказ снятия защиты с записи
		return error_t::LENGTH;
	// Отказ, которым завершилось снятие защиты с записи
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открытый текст принятой записи
		vector <uint8_t> plain(length, 0);
		// Если метка целостности принятой записи не сошлась
		if(!galois.decrypt(view_t(associated, record::RECORD_HEADER), view_t(data.data, length), plain.data(), view_t((data.data + length), this->_size)))
			// Запоминаем отказ несхождения метки целостности
			outcome = error_t::TAG;
		// Если метка целостности принятой записи сошлась
		else {
			// Место истинного вида содержимого принятой записи
			size_t offset = length;
			/**
			 * Раздел 5.2 RFC 8446: за истинным видом содержимого идут одни нули дополнения
			 */
			while((offset > 0) && (plain[offset - 1] == 0x00))
				// Отступаем от конца открытого текста к виду содержимого
				offset--;
			// Если открытый текст записи истинного вида содержимого не несёт
			if(offset == 0)
				// Запоминаем отказ отсутствия вида содержимого записи
				outcome = error_t::TYPE;
			// Если истинный вид содержимого записи найден
			else {
				// Получаем истинный вид содержимого принятой записи
				const record::type_t inner = static_cast <record::type_t> (plain[offset - 1]);
				// Если истинный вид содержимого записи протоколом не определён
				if(!record::known(inner))
					// Запоминаем отказ неизвестности вида содержимого записи
					outcome = error_t::TYPE;
				// Если истинный вид содержимого записи известен
				else {
					// Устанавливаем истинный вид содержимого принятой записи
					type = inner;
					// Выполняем дописывание открытого содержимого принятой записи
					result.insert(result.end(), plain.data(), (plain.data() + offset - 1));
				}
			}
		}
		// Выполняем затирание открытого текста принятой записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под открытое содержимое не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения принятой записи
	wipe(nonce, sizeof(nonce));
	// Если защита с записи снята
	if(outcome == error_t::NONE)
		// Увеличиваем порядковый номер очередной записи
		this->_sequence++;
	// Выводим отказ, которым завершилось снятие защиты с записи
	return outcome;
}
/**
 * @brief Конструктор
 *
 */
nts::protect::Protection::Protection() noexcept : _ready(false), _suite(suite_t::NONE), _size(0), _sequence(0), _limit(0), _derived(0) {
	// Выполняем обнуление корневого ключа направления связи
	::memset(this->_key, 0, sizeof(this->_key));
	// Выполняем обнуление вектора замены направления связи
	::memset(this->_vector, 0, sizeof(this->_vector));
}
/**
 * @brief Деструктор
 *
 */
nts::protect::Protection::~Protection() noexcept {
	// Выполняем сброс ключевого материала направления связи
	this->clear();
}
