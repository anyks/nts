/**
 * @file pbkdf2.cpp
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
 * @brief Модуль вывода ключа из пароля PBKDF2 по RFC 8018 над любым хешем библиотеки
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/pbkdf2.hpp>
#include <digest/hmac.hpp>
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
	 * Пространство имён модуля
	 */
	using namespace nts::digest;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
};

/**
 * @brief Функция вывода ключа из пароля PBKDF2-HMAC
 *
 * @param algorithm  алгоритм хеширования имитовставки
 * @param password   пароль, вправе быть пустым
 * @param salt       соль, вправе быть пустой
 * @param iterations число оборотов, не меньше одного
 * @param result     место, в которое помещается выведенный ключ
 * @param size       требуемая длина ключа, не меньше одного байта
 * @return           признак успешности вывода
 *
 */
bool nts::digest::pbkdf2(const hash_t algorithm, const view_t & password, const view_t & salt, const uint32_t iterations, uint8_t * result, const size_t size) noexcept {
	// Длина хеша выбранного алгоритма
	const size_t length = digest::length(algorithm);
	// Если алгоритм не установлен, либо оборотов нет, либо места под ключ нет
	if((length == 0) || (iterations == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ вывода
		return false;
	// Если соль объявлена непустой, но не передана
	if((salt.size > 0) && (salt.data == nullptr))
		// Выводим отказ вывода
		return false;
	// Раздел 5.2 RFC 8018: ключ не длиннее (2^32 - 1) блоков хеша, иначе счётчик блоков замыкается и блоки повторяются
	if(static_cast <uint64_t> (size) > (static_cast <uint64_t> (UINT32_MAX) * length))
		// Выводим отказ вывода
		return false;
	// Объект поточной выработки имитовставки: пароль заводится ключом один раз
	mac_t mac;
	// Если пароль установить ключом не удалось
	if(!mac.start(algorithm, password))
		// Выводим отказ вывода
		return false;
	// Очередной оборот
	uint8_t round[64];
	// Накопленный блок ключа
	uint8_t block[64];
	// Число уже выведенных байтов ключа
	size_t produced = 0;
	// Признак успешности вывода
	bool ok = true;
	/**
	 * Выполняем вывод блоков ключа, пока его не хватает
	 */
	for(uint32_t index = 1; ok && (produced < size); index++){
		// Номер блока от старшего байта
		const uint8_t number[4] = {static_cast <uint8_t> (index >> 24), static_cast <uint8_t> (index >> 16), static_cast <uint8_t> (index >> 8), static_cast <uint8_t> (index)};
		// Выполняем начало первого оборота
		mac.restart();
		// Выполняем подачу соли
		mac.update(salt);
		// Выполняем подачу номера блока
		mac.update(view_t(number, sizeof(number)));
		// Если первый оборот снять не удалось
		if(!(ok = mac.finish(round, length)))
			// Прерываем вывод
			break;
		// Первый оборот кладётся в блок как есть
		::memcpy(block, round, length);
		/**
		 * Выполняем остальные обороты: каждый - имитовставка предыдущего
		 */
		for(uint32_t i = 1; ok && (i < iterations); i++){
			// Выполняем начало очередного оборота
			mac.restart();
			// Выполняем подачу предыдущего оборота
			mac.update(view_t(round, length));
			// Если оборот снять не удалось
			if(!(ok = mac.finish(round, length)))
				// Прерываем вывод
				break;
			/**
			 * Выполняем сложение оборота с блоком по модулю два
			 */
			for(size_t j = 0; j < length; j++)
				// Складываем очередной байт
				block[j] ^= round[j];
		}
		// Если обороты не удались
		if(!ok)
			// Прерываем вывод
			break;
		// Число байтов блока, идущих в ключ
		const size_t taken = (((size - produced) < length) ? (size - produced) : length);
		// Переносим блок в ключ
		::memcpy(result + produced, block, taken);
		// Считаем выведенные байты
		produced += taken;
	}
	// Выполняем затирание оборота
	wipe(round, sizeof(round));
	// Выполняем затирание блока
	wipe(block, sizeof(block));
	// Если вывод не удался
	if(!ok)
		// Выполняем затирание недовыведенного ключа
		wipe(result, size);
	// Выводим признак успешности вывода
	return ok;
}
