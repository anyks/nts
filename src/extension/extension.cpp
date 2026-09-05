/**
 * @file extension.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля расширений приветствий протокола TLS
 *
 * @section Намеренные решения
 *
 * 1. Неизвестные значения перечней не отбрасываются, а выдаются наверх как есть. Раздел
 *    4.1.2 RFC 8446 велит клиенту предлагать и то, чего сервер знать не обязан, а решать,
 *    что из предложенного годится, - дело согласования, а не разбора. Отброшенное здесь
 *    значение согласование не увидело бы вовсе.
 *
 * 2. У расширений, сложенных у клиента и у сервера по-разному, здесь по два разборщика.
 *    Клиент предлагает перечень, сервер выбирает одно, и общего разборщика на оба случая
 *    нет: он был бы вынужден угадывать, чьё приветствие разбирает.
 *
 * 3. Лишние байты за телом расширения - отказ. Длина тела объявлена обвязкой расширения,
 *    и остаток за разобранными полями означает, что либо длина, либо содержимое лгут.
 *
 * 4. У составления отказать способно лишь проставление длины поля. Число заданной ширины
 *    входит в неё по самому своему виду, занятие места под поле не судит ничего, а запись
 *    содержимого длину его не объявляет. Заслоны на этих действиях стоят ради связности
 *    составления - молчаливая запись поля, в свою длину не вошедшего, была бы хуже, - и
 *    охват их не задевает. Проверками задеты все проставления длины: ExtensionTest.Bounded.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <field/field.hpp>
#include <extension/extension.hpp>

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
	using namespace nts::extension;

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
	typedef extension::error_t error_t;

	/**
	 * @brief Метод перевода отказа составителя полей в отказ модуля
	 *
	 * @param failure отказ, которым ответил составитель полей
	 *
	 * @return        отказ модуля, отвечающий отказу составителя
	 *
	 * @note Нехватка памяти обязана дойти до вызывающего своим именем: составитель
	 *       перехватывает её сам и отвечает отказом, а не исключением, и молчаливый
	 *       перевод этого отказа в невхождение поля прятал бы истинную причину
	 *
	 */
	static error_t translate(const field::error_t failure) noexcept {
		// Если составитель полей отказом не ответил
		if(failure == field::error_t::NONE)
			// Выводим успешность составления
			return error_t::NONE;
		// Если памяти под накопитель составителя не хватило
		if(failure == field::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	}

	/**
	 * @brief Описание группы обмена ключами
	 *
	 */
	static const struct Sample {
		// Группа обмена ключами
		group_t group;
		// Схема подписи на кривой этой же группы
		scheme_t scheme;
		// Опознаватель набора параметров кривой группы
		const char * oid;
		// Длина ключа подписи на кривой группы в байтах
		size_t size;
	} SAMPLES[10] = {
		{group_t::GC256A, scheme_t::S256A, "1.2.643.7.1.2.1.1.1", 32},
		{group_t::GC256B, scheme_t::S256B, "1.2.643.2.2.35.1",    32},
		{group_t::GC256C, scheme_t::S256C, "1.2.643.2.2.35.2",    32},
		{group_t::GC256D, scheme_t::S256D, "1.2.643.2.2.35.3",    32},
		{group_t::GC512A, scheme_t::S512A, "1.2.643.7.1.2.1.2.1", 64},
		{group_t::GC512B, scheme_t::S512B, "1.2.643.7.1.2.1.2.2", 64},
		{group_t::GC512C, scheme_t::S512C, "1.2.643.7.1.2.1.2.3", 64},
		{group_t::SECP256R1, scheme_t::ECDSA_SECP256R1_SHA256, "1.2.840.10045.3.1.7", 32},
		{group_t::SECP384R1, scheme_t::ECDSA_SECP384R1_SHA384, "1.3.132.0.34",        48},
		{group_t::X25519,    scheme_t::NONE,                   "1.3.101.110",         32}
	};

	/**
	 * @brief Описание хеша схемы подписи
	 *
	 */
	static const struct Hashing {
		// Схема подписи
		scheme_t scheme;
		// Хеш схемы подписи
		digest::hash_t hash;
	} HASHES[16] = {
		{scheme_t::RSA_PKCS1_SHA256, digest::hash_t::SHA256},
		{scheme_t::RSA_PKCS1_SHA384, digest::hash_t::SHA384},
		{scheme_t::RSA_PKCS1_SHA512, digest::hash_t::SHA512},
		{scheme_t::S256A, digest::hash_t::STREEBOG256},
		{scheme_t::S256B, digest::hash_t::STREEBOG256},
		{scheme_t::S256C, digest::hash_t::STREEBOG256},
		{scheme_t::S256D, digest::hash_t::STREEBOG256},
		{scheme_t::S512A, digest::hash_t::STREEBOG512},
		{scheme_t::S512B, digest::hash_t::STREEBOG512},
		{scheme_t::S512C, digest::hash_t::STREEBOG512},
		{scheme_t::ECDSA_SECP256R1_SHA256, digest::hash_t::SHA256},
		{scheme_t::ECDSA_SECP384R1_SHA384, digest::hash_t::SHA384},
		{scheme_t::RSA_PSS_RSAE_SHA256, digest::hash_t::SHA256},
		{scheme_t::RSA_PSS_RSAE_SHA384, digest::hash_t::SHA384},
		{scheme_t::RSA_PSS_RSAE_SHA512, digest::hash_t::SHA512},
		{scheme_t::ED25519, digest::hash_t::NONE}
	};

	/**
	 * @brief Метод разбора перечня чисел заданной ширины
	 *
	 * @param data   разбираемое тело расширения
	 * @param width  ширина записи длины перечня в байтах
	 * @param size   ширина записи одного числа перечня в байтах
	 * @param result перечень, в который помещаются прочитанные числа
	 *
	 * @return       отказ разбора перечня чисел
	 *
	 */
	static error_t numbers(const view_t & data, const size_t width, const size_t size, vector <uint32_t> & result) noexcept {
		// Объект разборщика полей тела расширения
		field::scanner_t scanner;
		// Устанавливаем разбираемое тело расширения
		scanner.start(data);
		// Содержимое перечня чисел тела расширения
		view_t body;
		// Если перечень чисел прочитать не удалось
		if(scanner.vector(body, width) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Если за телом расширения идут лишние байты
		if(scanner.left() > 0)
			// Выводим отказ лишних байтов за телом расширения
			return error_t::TRAILING;
		// Если перечень чисел пуст
		if(body.size == 0)
			// Выводим отказ пустого перечня тела расширения
			return error_t::EMPTY;
		// Если перечень чисел оборван посреди числа
		if((body.size % size) != 0)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Объект разборщика чисел перечня
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня чисел
		reader.start(body);
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			/**
			 * Выполняем перебор чисел перечня тела расширения
			 */
			while(reader.left() > 0){
				// Очередное прочитанное число перечня
				uint32_t value = 0;
				// Выполняем чтение очередного числа перечня
				reader.number(value, size);
				// Добавляем очередное число в перечень
				result.push_back(value);
			}
		/**
		 * Если памяти под перечень чисел не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выводим успешность разбора перечня чисел
		return error_t::NONE;
	}
	/**
	 * @brief Метод составления перечня чисел заданной ширины
	 *
	 * @param values составляемый перечень чисел
	 * @param width  ширина записи длины перечня в байтах
	 * @param size   ширина записи одного числа перечня в байтах
	 * @param result накопитель, в конец которого дописывается тело расширения
	 *
	 * @return       отказ составления перечня чисел
	 *
	 */
	static error_t compose(const vector <uint32_t> & values, const size_t width, const size_t size, vector <uint8_t> & result) noexcept {
		// Если составляемый перечень чисел пуст
		if(values.empty())
			// Выводим отказ пустого перечня тела расширения
			return error_t::EMPTY;
		// Объект составителя полей тела расширения
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t failure = field::error_t::NONE;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Открываем перечень чисел тела расширения
			if((failure = builder.open(width)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			/**
			 * Выполняем перебор чисел составляемого перечня
			 */
			for(auto & item : values){
				/**
				 * Невхождением в ширину заслон этот недостижим: числа перечней приходят
				 * из перечислений, шириной своей и заданных - издания, кривые и схемы
				 * объявлены двумя байтами, способы обмена ключом единственным, - и
				 * всякое из них в свою ширину входит по самому своему виду. Нехваткой
				 * же памяти запись отказать способна, и отказ этот обязан дойти до
				 * вызывающего своим именем, а не молчаливым усечением перечня
				 */
				if((failure = builder.number(item, size)) != field::error_t::NONE)
					// Выводим отказ, которым ответил составитель полей
					return translate(failure);
			}
			// Если перечень чисел закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Получаем составленное тело расширения
			const view_t data = builder.data();
			// Выполняем дописывание тела расширения в накопитель
			result.insert(result.end(), data.data, data.data + data.size);
		/**
		 * Если памяти под тело расширения не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выводим успешность составления перечня чисел
		return error_t::NONE;
	}
	/**
	 * @brief Метод составления одиночного поля переменной длины
	 *
	 * @param data   составляемое содержимое поля
	 * @param width  ширина записи длины поля в байтах
	 * @param result накопитель, в конец которого дописывается тело расширения
	 *
	 * @return       отказ составления поля переменной длины
	 *
	 * @note Имя «single» здесь не годится: у Solaris оно занято под вид числа с
	 *       плавающей запятой в глобальном пространстве имён, и обращение к помощнику
	 *       из безымянного пространства выходит там двусмысленным
	 *
	 */
	static error_t alone(const view_t & data, const size_t width, vector <uint8_t> & result) noexcept {
		// Объект составителя полей тела расширения
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t failure = field::error_t::NONE;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Открываем поле переменной длины
			if((failure = builder.open(width)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Записываем содержимое поля переменной длины
			if((failure = builder.bytes(data)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Если поле переменной длины закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Получаем составленное тело расширения
			const view_t body = builder.data();
			// Выполняем дописывание тела расширения в накопитель
			result.insert(result.end(), body.data, body.data + body.size);
		/**
		 * Если памяти под тело расширения не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выводим успешность составления поля переменной длины
		return error_t::NONE;
	}
};

/**
 * @brief Метод получения опознавателя кривой группы обмена ключами
 *
 * @param group группа обмена ключами
 *
 * @return      опознаватель кривой набора параметров либо nullptr
 *
 */
const char * nts::extension::curve(const group_t group) noexcept {
	/**
	 * Выполняем перебор описаний групп обмена ключами
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Если описание разыскиваемой группы обмена найдено
		if(SAMPLES[i].group == group)
			// Выводим опознаватель кривой группы обмена ключами
			return SAMPLES[i].oid;
	}
	// Выводим признак того, что группа обмена ключами неизвестна
	return nullptr;
}
/**
 * @brief Метод получения опознавателя кривой схемы подписи
 *
 * @param scheme схема подписи
 *
 * @return       опознаватель кривой набора параметров либо nullptr
 *
 */
const char * nts::extension::curve(const scheme_t scheme) noexcept {
	/**
	 * Выполняем перебор описаний схем подписи
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Если описание разыскиваемой схемы подписи найдено: у группы без схемы подписи нет
		if((SAMPLES[i].scheme != scheme_t::NONE) && (SAMPLES[i].scheme == scheme))
			// Выводим опознаватель кривой схемы подписи
			return SAMPLES[i].oid;
	}
	// Выводим признак того, что схема подписи неизвестна
	return nullptr;
}
/**
 * @brief Метод получения длины ключа схемы подписи
 *
 * @param scheme схема подписи
 *
 * @return       длина ключа подписи в байтах, ноль у неизвестной схемы
 *
 */
size_t nts::extension::length(const scheme_t scheme) noexcept {
	/**
	 * Выполняем перебор описаний схем подписи
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Если описание разыскиваемой схемы подписи найдено: у группы без схемы подписи нет
		if((SAMPLES[i].scheme != scheme_t::NONE) && (SAMPLES[i].scheme == scheme))
			// Выводим длину ключа подписи схемы
			return SAMPLES[i].size;
	}
	// Выводим признак того, что схема подписи неизвестна
	return 0;
}
/**
 * @brief Метод получения длины доли ключа группы обмена ключами
 *
 * @param group группа обмена ключами
 *
 * @return      длина доли ключа в байтах, ноль у неизвестной группы
 *
 */
size_t nts::extension::length(const group_t group) noexcept {
	// Если группа обмена - X25519
	if(group == group_t::X25519)
		// Выводим длину доли ключа X25519
		return 32;
	// Если группа обмена - кривая NIST
	if((group == group_t::SECP256R1) || (group == group_t::SECP384R1)){
		/**
		 * Выполняем перебор описаний групп обмена ключами
		 */
		for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
			// Если группа обмена найдена
			if(SAMPLES[i].group == group)
				// Выводим длину несжатой точки 0x04||X||Y
				return (1 + (SAMPLES[i].size * 2));
		}
		// Выводим отсутствие длины доли ключа
		return 0;
	}
	/**
	 * Выполняем перебор описаний групп обмена ключами
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Если группа обмена найдена
		if(SAMPLES[i].group == group)
			// Выводим длину двух координат точки
			return (SAMPLES[i].size * 2);
	}
	// Выводим отсутствие длины доли ключа
	return 0;
}
/**
 * @brief Метод получения хеша схемы подписи
 *
 * @param scheme схема подписи
 *
 * @return       хеш, которым берётся подписываемое содержимое, NONE у Ed25519 и у неизвестной схемы
 *
 */
nts::digest::hash_t nts::extension::hash(const scheme_t scheme) noexcept {
	/**
	 * Выполняем перебор описаний хешей схем подписи
	 */
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Если схема подписи найдена
		if(HASHES[i].scheme == scheme)
			// Выводим хеш схемы подписи
			return HASHES[i].hash;
	}
	// Выводим отсутствие хеша схемы подписи
	return digest::hash_t::NONE;
}
/**
 * @brief Метод разбора перечня поддерживаемых изданий протокола
 *
 * @param data   разбираемое тело расширения приветствия клиента
 * @param result перечень, в который помещаются поддерживаемые издания протокола
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::versions(const view_t & data, vector <uint16_t> & result) noexcept {
	// Прочитанный перечень изданий протокола
	vector <uint32_t> values;
	// Выполняем разбор перечня изданий протокола
	const error_t error = numbers(data, 1, 2, values);
	// Если перечень изданий протокола разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор прочитанных изданий протокола
		 */
		for(auto & item : values)
			// Добавляем очередное издание протокола в перечень
			result.push_back(static_cast <uint16_t> (item));
	/**
	 * Если памяти под перечень изданий не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня поддерживаемых изданий протокола
 *
 * @param versions составляемый перечень поддерживаемых изданий протокола
 * @param result   накопитель, в конец которого дописывается тело расширения
 *
 * @return         отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::versions(const vector <uint16_t> & versions, vector <uint8_t> & result) noexcept {
	// Составляемый перечень изданий протокола
	vector <uint32_t> values;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор составляемых изданий протокола
		 */
		for(auto & item : versions)
			// Добавляем очередное издание протокола в перечень
			values.push_back(static_cast <uint32_t> (item));
	/**
	 * Если памяти под перечень изданий не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим итог составления перечня изданий протокола
	return compose(values, 1, 2, result);
}
/**
 * @brief Метод разбора выбранного издания протокола
 *
 * @param data   разбираемое тело расширения приветствия сервера
 * @param result число, в которое помещается выбранное издание протокола
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::version(const view_t & data, uint16_t & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Прочитанное издание протокола
	uint32_t value = 0;
	// Если издание протокола прочитать не удалось
	if(scanner.number(value, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Устанавливаем выбранное издание протокола
	result = static_cast <uint16_t> (value);
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления выбранного издания протокола
 *
 * @param version составляемое выбранное издание протокола
 * @param result  накопитель, в конец которого дописывается тело расширения
 *
 * @return        отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::version(const uint16_t version, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Записываем старший байт выбранного издания протокола
		result.push_back(static_cast <uint8_t> ((version >> 8) & 0xFF));
		// Записываем младший байт выбранного издания протокола
		result.push_back(static_cast <uint8_t> (version & 0xFF));
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора перечня поддерживаемых групп обмена ключами
 *
 * @param data   разбираемое тело расширения
 * @param result перечень, в который помещаются поддерживаемые группы
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::groups(const view_t & data, vector <group_t> & result) noexcept {
	// Прочитанный перечень групп обмена ключами
	vector <uint32_t> values;
	// Выполняем разбор перечня групп обмена ключами
	const error_t error = numbers(data, 2, 2, values);
	// Если перечень групп обмена разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор прочитанных групп обмена ключами
		 */
		for(auto & item : values)
			// Добавляем очередную группу обмена в перечень
			result.push_back(static_cast <group_t> (item));
	/**
	 * Если памяти под перечень групп не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня поддерживаемых групп обмена ключами
 *
 * @param groups составляемый перечень поддерживаемых групп
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::groups(const vector <group_t> & groups, vector <uint8_t> & result) noexcept {
	// Составляемый перечень групп обмена ключами
	vector <uint32_t> values;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор составляемых групп обмена ключами
		 */
		for(auto & item : groups)
			// Добавляем очередную группу обмена в перечень
			values.push_back(static_cast <uint32_t> (item));
	/**
	 * Если памяти под перечень групп не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим итог составления перечня групп обмена ключами
	return compose(values, 2, 2, result);
}
/**
 * @brief Метод разбора перечня поддерживаемых схем подписи
 *
 * @param data   разбираемое тело расширения
 * @param result перечень, в который помещаются поддерживаемые схемы подписи
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::schemes(const view_t & data, vector <scheme_t> & result) noexcept {
	// Прочитанный перечень схем подписи
	vector <uint32_t> values;
	// Выполняем разбор перечня схем подписи
	const error_t error = numbers(data, 2, 2, values);
	// Если перечень схем подписи разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор прочитанных схем подписи
		 */
		for(auto & item : values)
			// Добавляем очередную схему подписи в перечень
			result.push_back(static_cast <scheme_t> (item));
	/**
	 * Если памяти под перечень схем не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня поддерживаемых схем подписи
 *
 * @param schemes составляемый перечень поддерживаемых схем подписи
 * @param result  накопитель, в конец которого дописывается тело расширения
 *
 * @return        отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::schemes(const vector <scheme_t> & schemes, vector <uint8_t> & result) noexcept {
	// Составляемый перечень схем подписи
	vector <uint32_t> values;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор составляемых схем подписи
		 */
		for(auto & item : schemes)
			// Добавляем очередную схему подписи в перечень
			values.push_back(static_cast <uint32_t> (item));
	/**
	 * Если памяти под перечень схем не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим итог составления перечня схем подписи
	return compose(values, 2, 2, result);
}
/**
 * @brief Метод разбора перечня открытых частей ключей обмена
 *
 * @param data   разбираемое тело расширения приветствия клиента
 * @param result перечень, в который помещаются открытые части ключей обмена
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::shares(const view_t & data, vector <share_t> & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Содержимое перечня открытых частей ключей обмена
	view_t body;
	// Если перечень открытых частей ключей прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Объект разборщика записей перечня
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое перечня
	reader.start(body);
	/**
	 * Выполняем перебор открытых частей ключей обмена
	 */
	while(reader.left() > 0){
		// Группа обмена ключами очередной открытой части ключа
		uint32_t group = 0;
		// Если группу обмена ключами прочитать не удалось
		if(reader.number(group, 2) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Открытая часть ключа обмена очередной группы
		view_t key;
		// Если открытую часть ключа обмена прочитать не удалось
		if(reader.vector(key, 2) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Раздел 4.2.8 RFC 8446: открытая часть ключа непуста
		if(key.size == 0)
			// Выводим отказ пустой открытой части ключа
			return error_t::EMPTY;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Добавляем очередную открытую часть ключа в перечень
			result.push_back(share_t(static_cast <group_t> (group), key));
		/**
		 * Если памяти под перечень открытых частей ключей не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня открытых частей ключей обмена
 *
 * @param shares составляемый перечень открытых частей ключей обмена
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::shares(const vector <share_t> & shares, vector <uint8_t> & result) noexcept {
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открываем перечень открытых частей ключей обмена
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		/**
		 * Выполняем перебор составляемых открытых частей ключей обмена
		 */
		for(auto & item : shares){
			// Записываем группу обмена очередной открытой части ключа
			if((failure = builder.number(static_cast <uint32_t> (item.group), 2)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Открываем поле открытой части ключа обмена
			if((failure = builder.open(2)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Записываем открытую часть ключа обмена
			if((failure = builder.bytes(item.key)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Если поле открытой части ключа закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
		}
		// Если перечень открытых частей ключей закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело расширения
		const view_t data = builder.data();
		// Выполняем дописывание тела расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора открытой части ключа обмена сервера
 *
 * @param data   разбираемое тело расширения приветствия сервера
 * @param result запись, в которую помещается открытая часть ключа обмена
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::share(const view_t & data, share_t & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Группа обмена ключами открытой части ключа
	uint32_t group = 0;
	// Если группу обмена ключами прочитать не удалось
	if(scanner.number(group, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Открытая часть ключа обмена сервера
	view_t key;
	// Если открытую часть ключа обмена прочитать не удалось
	if(scanner.vector(key, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Устанавливаем группу обмена открытой части ключа
	result.group = static_cast <group_t> (group);
	// Устанавливаем открытую часть ключа обмена сервера
	result.key = key;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления открытой части ключа обмена сервера
 *
 * @param share  составляемая открытая часть ключа обмена
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::share(const share_t & share, vector <uint8_t> & result) noexcept {
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Записываем группу обмена открытой части ключа
		if((failure = builder.number(static_cast <uint32_t> (share.group), 2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Открываем поле открытой части ключа обмена
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Записываем открытую часть ключа обмена
		if((failure = builder.bytes(share.key)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если поле открытой части ключа закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело расширения
		const view_t data = builder.data();
		// Выполняем дописывание тела расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора предела упреждающих данных билета
 *
 * @param data   разбираемое тело расширения билета возобновления связи
 * @param result место, в которое помещается предел упреждающих данных в байтах
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::early(const view_t & data, uint32_t & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Предел упреждающих данных, объявленный билетом
	uint32_t limit = 0;
	// Если предел упреждающих данных прочитать не удалось
	if(scanner.number(limit, 4) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Устанавливаем разобранный предел упреждающих данных
	result = limit;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления предела упреждающих данных билета
 *
 * @param limit  объявляемый предел упреждающих данных в байтах
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::early(const uint32_t limit, vector <uint8_t> & result) noexcept {
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	// Если предел упреждающих данных записать не удалось
	if((failure = builder.number(limit, 4)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Получаем составленное тело расширения приветствия
	const view_t data = builder.data();
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Дописываем составленное тело расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора перечня алгоритмов сжатия цепочки сертификатов
 *
 * @param data   разбираемое тело расширения
 * @param result перечень, в который помещаются опознаватели алгоритмов
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::algorithms(const view_t & data, vector <uint16_t> & result) noexcept {
	// Прочитанный перечень опознавателей алгоритмов
	vector <uint32_t> values;
	/**
	 * Раздел 3 RFC 8879: перечень идёт с однобайтовой длиной впереди, а всякий
	 * опознаватель алгоритма занимает два байта
	 */
	const error_t error = numbers(data, 1, 2, values);
	// Если перечень алгоритмов разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор прочитанных опознавателей алгоритмов
		 */
		for(auto & item : values)
			// Добавляем очередной опознаватель алгоритма в перечень
			result.push_back(static_cast <uint16_t> (item));
	/**
	 * Если памяти под перечень алгоритмов не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня алгоритмов сжатия цепочки сертификатов
 *
 * @param algorithms составляемый перечень опознавателей алгоритмов
 * @param result     накопитель, в конец которого дописывается тело расширения
 *
 * @return           отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::algorithms(const vector <uint16_t> & algorithms, vector <uint8_t> & result) noexcept {
	// Составляемый перечень опознавателей алгоритмов
	vector <uint32_t> values;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор составляемых опознавателей алгоритмов
		 */
		for(auto & item : algorithms)
			// Добавляем очередной опознаватель алгоритма в перечень
			values.push_back(static_cast <uint32_t> (item));
	/**
	 * Если памяти под перечень алгоритмов не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим итог составления перечня опознавателей алгоритмов
	return compose(values, 1, 2, result);
}
/**
 * @brief Метод разбора перечня прикладных протоколов
 *
 * @param data   разбираемое тело расширения
 * @param result перечень, в который помещаются названия прикладных протоколов
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::protocols(const view_t & data, vector <string> & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Содержимое перечня прикладных протоколов
	view_t body;
	// Если перечень прикладных протоколов прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Объект разборщика записей перечня прикладных протоколов
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое перечня прикладных протоколов
	reader.start(body);
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор записей перечня прикладных протоколов
		 */
		while(reader.left() > 0){
			// Название очередного прикладного протокола
			view_t item;
			// Если название очередного протокола прочитать не удалось
			if(reader.vector(item, 1) != field::error_t::NONE)
				// Выводим отказ обрыва тела расширения
				return error_t::HUNGRY;
			/**
			 * Раздел 3.1 RFC 7301: пустое название протокола запрещено
			 */
			if(item.size == 0)
				// Выводим отказ пустой записи перечня
				return error_t::EMPTY;
			// Добавляем название протокола в перечень
			result.push_back(string(reinterpret_cast <const char *> (item.data), item.size));
		}
	/**
	 * Если памяти под перечень протоколов не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Если перечень прикладных протоколов пуст
	if(result.empty())
		// Выводим отказ пустого перечня тела расширения
		return error_t::EMPTY;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня прикладных протоколов
 *
 * @param protocols составляемый перечень названий прикладных протоколов
 * @param result    накопитель, в конец которого дописывается тело расширения
 *
 * @return          отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::protocols(const vector <string> & protocols, vector <uint8_t> & result) noexcept {
	// Если составляемый перечень прикладных протоколов пуст
	if(protocols.empty())
		// Выводим отказ пустого перечня прикладных протоколов
		return error_t::EMPTY;
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открываем перечень прикладных протоколов
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		/**
		 * Выполняем перебор составляемого перечня прикладных протоколов
		 */
		for(size_t i = 0; i < protocols.size(); i++){
			/**
			 * Раздел 3.1 RFC 7301: пустое название протокола запрещено
			 */
			if(protocols[i].empty())
				// Выводим отказ пустой записи перечня
				return error_t::EMPTY;
			// Открываем поле названия прикладного протокола
			if((failure = builder.open(1)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Записываем название прикладного протокола
			if((failure = builder.bytes(view_t(reinterpret_cast <const uint8_t *> (protocols[i].data()), protocols[i].size()))) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Если поле названия прикладного протокола закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
		}
		// Если перечень прикладных протоколов закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело расширения
		const view_t data = builder.data();
		// Выполняем дописывание тела расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора выбранного прикладного протокола
 *
 * @param data   разбираемое тело расширения
 * @param result название, в которое помещается выбранный прикладной протокол
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::protocol(const view_t & data, string & result) noexcept {
	// Перечень названий прикладных протоколов
	vector <string> protocols;
	// Выполняем разбор перечня прикладных протоколов
	const error_t error = extension::protocols(data, protocols);
	// Если разобрать перечень прикладных протоколов не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Раздел 3.1 RFC 7301: в ответе сервера лежит ровно один протокол
	 */
	if(protocols.size() != 1)
		// Выводим отказ длины перечня тела расширения
		return error_t::LENGTH;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Устанавливаем выбранный прикладной протокол
		result = ::move(protocols.front());
	/**
	 * Если памяти под название протокола не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления выбранного прикладного протокола
 *
 * @param protocol составляемое название выбранного прикладного протокола
 * @param result   накопитель, в конец которого дописывается тело расширения
 *
 * @return         отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::protocol(const string & protocol, vector <uint8_t> & result) noexcept {
	// Если составляемое название прикладного протокола пусто
	if(protocol.empty())
		// Выводим отказ пустого названия прикладного протокола
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выводим итог составления перечня из одного прикладного протокола
		return extension::protocols(vector <string> (1, protocol), result);
	/**
	 * Если памяти под перечень протоколов не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора предложения заранее разделённых ключей
 *
 * @param data       разбираемое тело расширения приветствия клиента
 * @param result     перечень, в который помещаются опознаватели ключей
 * @param binders    перечень, в который помещаются привязки ключей
 * @param truncation место, в которое помещается длина приветствия без привязок
 *
 * @return           отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::identities(const view_t & data, vector <identity_t> & result, vector <view_t> & binders, size_t & truncation) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Содержимое перечня опознавателей ключей
	view_t body;
	// Если перечень опознавателей ключей прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	/**
	 * Длина усечения приветствия берётся местом, где кончился перечень опознавателей:
	 * привязки, идущие за ним, себя самих не покрывают
	 */
	truncation = scanner.offset();
	// Содержимое перечня привязок ключей
	view_t items;
	// Если перечень привязок ключей прочитать не удалось
	if(scanner.vector(items, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Объект разборщика записей перечня опознавателей
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое перечня опознавателей
	reader.start(body);
	/**
	 * Выполняем перебор опознавателей заранее разделённых ключей
	 */
	while(reader.left() > 0){
		// Опознаватель очередного заранее разделённого ключа
		view_t identity;
		// Если опознаватель ключа прочитать не удалось
		if(reader.vector(identity, 2) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Скрытый возраст билета, выдавшего ключ
		uint32_t age = 0;
		// Если скрытый возраст билета прочитать не удалось
		if(reader.number(age, 4) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Добавляем очередной опознаватель ключа в перечень
			result.push_back(identity_t(identity, age));
		/**
		 * Если памяти под перечень опознавателей не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	// Объект разборщика записей перечня привязок
	field::scanner_t items_reader;
	// Устанавливаем разбираемое содержимое перечня привязок
	items_reader.start(items);
	/**
	 * Выполняем перебор привязок заранее разделённых ключей
	 */
	while(items_reader.left() > 0){
		// Привязка очередного заранее разделённого ключа
		view_t binder;
		// Если привязку ключа прочитать не удалось
		if(items_reader.vector(binder, 1) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Раздел 4.2.11 RFC 8446: привязка не короче 32 байтов
		if(binder.size < 32)
			// Выводим отказ пустой привязки
			return error_t::EMPTY;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Добавляем очередную привязку ключа в перечень
			binders.push_back(binder);
		/**
		 * Если памяти под перечень привязок не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * Раздел 4.2.11 RFC 8446: перечни опознавателей и привязок непусты
	 */
	if(result.empty() || binders.empty())
		// Выводим отказ пустого перечня
		return error_t::EMPTY;
	/**
	 * Число привязок обязано совпадать с числом опознавателей: всякому ключу отвечает
	 * своя привязка, и без неё ключ предъявлен не по правилам
	 */
	if(result.size() != binders.size())
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления предложения заранее разделённых ключей
 *
 * @param identities составляемый перечень опознавателей ключей
 * @param binders    составляемый перечень привязок ключей
 * @param result     накопитель, в конец которого дописывается тело расширения
 *
 * @return           отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::identities(const vector <identity_t> & identities, const vector <view_t> & binders, vector <uint8_t> & result) noexcept {
	// Если перечень опознавателей ключей пуст
	if(identities.empty())
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Если число привязок с числом опознавателей не совпало
	if(identities.size() != binders.size())
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	// Если место под перечень опознавателей ключей занять не удалось
	if((failure = builder.open(2)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	/**
	 * Выполняем перебор составляемых опознавателей ключей
	 */
	for(size_t i = 0; i < identities.size(); i++){
		// Если место под опознаватель ключа занять не удалось
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если опознаватель ключа записать не удалось
		if((failure = builder.bytes(identities[i].identity)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если длину опознавателя ключа проставить не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если скрытый возраст билета записать не удалось
		if((failure = builder.number(identities[i].age, 4)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
	}
	// Если длину перечня опознавателей ключей проставить не удалось
	if((failure = builder.close()) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если место под перечень привязок ключей занять не удалось
	if((failure = builder.open(2)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	/**
	 * Выполняем перебор составляемых привязок ключей
	 */
	for(size_t i = 0; i < binders.size(); i++){
		// Если место под привязку ключа занять не удалось
		if((failure = builder.open(1)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если привязку ключа записать не удалось
		if((failure = builder.bytes(binders[i])) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если длину привязки ключа проставить не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
	}
	// Если длину перечня привязок ключей проставить не удалось
	if((failure = builder.close()) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Получаем составленное тело расширения приветствия
	const view_t data = builder.data();
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Дописываем составленное тело расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод разбора выбранного сервером заранее разделённого ключа
 *
 * @param data   разбираемое тело расширения приветствия сервера
 * @param result место, в которое помещается место выбранного ключа в предложении
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::chosen(const view_t & data, uint16_t & result) noexcept {
	// Выводим итог разбора выбранного заранее разделённого ключа
	return nts::extension::version(data, result);
}
/**
 * @brief Метод составления выбранного сервером заранее разделённого ключа
 *
 * @param chosen место выбранного ключа в предложении клиента
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::chosen(const uint16_t chosen, vector <uint8_t> & result) noexcept {
	// Выводим итог составления выбранного заранее разделённого ключа
	return nts::extension::version(chosen, result);
}
/**
 * @brief Метод разбора выбранной сервером группы обмена ключами
 *
 * @param data   разбираемое тело расширения просьбы о повторе приветствия
 * @param result группа, в которую помещается выбранная сервером группа обмена
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::selected(const view_t & data, group_t & result) noexcept {
	// Выбранная сервером группа обмена ключами
	uint16_t group = 0;
	// Выполняем разбор выбранной группы обмена ключами
	const error_t error = nts::extension::version(data, group);
	// Если выбранную группу обмена разобрать удалось
	if(error == error_t::NONE)
		// Устанавливаем выбранную сервером группу обмена ключами
		result = static_cast <group_t> (group);
	// Выводим отказ разбора тела расширения
	return error;
}
/**
 * @brief Метод составления выбранной сервером группы обмена ключами
 *
 * @param group  составляемая выбранная группа обмена ключами
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::selected(const group_t group, vector <uint8_t> & result) noexcept {
	// Выводим итог составления выбранной группы обмена ключами
	return nts::extension::version(static_cast <uint16_t> (group), result);
}
/**
 * @brief Метод разбора перечня способов обмена с заранее разделённым ключом
 *
 * @param data   разбираемое тело расширения
 * @param result перечень, в который помещаются способы обмена
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::modes(const view_t & data, vector <regime_t> & result) noexcept {
	// Прочитанный перечень способов обмена
	vector <uint32_t> values;
	// Выполняем разбор перечня способов обмена
	const error_t error = numbers(data, 1, 1, values);
	// Если перечень способов обмена разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора тела расширения
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор прочитанных способов обмена
		 */
		for(auto & item : values)
			// Добавляем очередной способ обмена в перечень
			result.push_back(static_cast <regime_t> (item));
	/**
	 * Если памяти под перечень способов обмена не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления перечня способов обмена с заранее разделённым ключом
 *
 * @param modes  составляемый перечень способов обмена
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::modes(const vector <regime_t> & modes, vector <uint8_t> & result) noexcept {
	// Составляемый перечень способов обмена
	vector <uint32_t> values;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем перебор составляемых способов обмена
		 */
		for(auto & item : modes)
			// Добавляем очередной способ обмена в перечень
			values.push_back(static_cast <uint32_t> (item));
	/**
	 * Если памяти под перечень способов обмена не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим итог составления перечня способов обмена
	return compose(values, 1, 1, result);
}
/**
 * @brief Метод разбора метки возврата состояния сервера
 *
 * @param data   разбираемое тело расширения
 * @param result просмотр, в который помещается метка возврата состояния
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::cookie(const view_t & data, view_t & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Прочитанная метка возврата состояния сервера
	view_t body;
	// Если метку возврата состояния прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Если метка возврата состояния пуста
	if(body.size == 0)
		// Выводим отказ пустого перечня тела расширения
		return error_t::EMPTY;
	// Устанавливаем прочитанную метку возврата состояния
	result = body;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления метки возврата состояния сервера
 *
 * @param cookie составляемая метка возврата состояния
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::cookie(const view_t & cookie, vector <uint8_t> & result) noexcept {
	// Если составляемая метка возврата состояния пуста
	if((cookie.data == nullptr) || (cookie.size == 0))
		// Выводим отказ пустой метки возврата состояния
		return error_t::EMPTY;
	// Выводим итог составления метки возврата состояния
	return alone(cookie, 2, result);
}
/**
 * @brief Метод разбора имени запрашиваемого узла
 *
 * @param data   разбираемое тело расширения
 * @param result просмотр, в который помещается имя запрашиваемого узла
 *
 * @return       отказ разбора тела расширения
 *
 */
nts::extension::error_t nts::extension::name(const view_t & data, view_t & result) noexcept {
	// Объект разборщика полей тела расширения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения
	scanner.start(data);
	// Содержимое перечня имён узлов
	view_t body;
	// Если перечень имён узлов прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела расширения
		return error_t::HUNGRY;
	// Если за телом расширения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом расширения
		return error_t::TRAILING;
	// Объект разборщика записей перечня имён узлов
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое перечня имён узлов
	reader.start(body);
	// Признак того, что имя запрашиваемого узла найдено
	bool found = false;
	/**
	 * Выполняем перебор записей перечня имён узлов
	 */
	while(reader.left() > 0){
		// Вид очередного имени узла
		uint32_t type = 0;
		/**
		 * Заслон этот недостижим: перебор идёт, пока в перечне остаётся хоть байт, а
		 * вид имени занимает ровно один - чтение его отказать не может. Стоит он ради
		 * связности разбора: вид имени, молча принятый нулём, отвечал бы имени узла
		 */
		// Если вид очередного имени узла прочитать не удалось
		if(reader.number(type, 1) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		// Очередное имя узла перечня
		view_t item;
		// Если очередное имя узла прочитать не удалось
		if(reader.vector(item, 2) != field::error_t::NONE)
			// Выводим отказ обрыва тела расширения
			return error_t::HUNGRY;
		/**
		 * Раздел 3 RFC 6066: имя узла непусто
		 */
		if((type == 0) && (item.size == 0))
			// Выводим отказ пустого имени узла
			return error_t::EMPTY;
		/**
		 * Раздел 3 RFC 6066: имени вида «host_name» отведено значение нуль
		 */
		if((type == 0) && !found){
			// Устанавливаем имя запрашиваемого узла
			result = item;
			// Запоминаем, что имя запрашиваемого узла найдено
			found = true;
		}
	}
	// Если имени запрашиваемого узла в перечне не нашлось
	if(!found)
		// Выводим отказ пустого перечня тела расширения
		return error_t::EMPTY;
	// Выводим успешность разбора тела расширения
	return error_t::NONE;
}
/**
 * @brief Метод составления имени запрашиваемого узла
 *
 * @param name   составляемое имя запрашиваемого узла
 * @param result накопитель, в конец которого дописывается тело расширения
 *
 * @return       отказ составления тела расширения
 *
 */
nts::extension::error_t nts::extension::name(const view_t & name, vector <uint8_t> & result) noexcept {
	// Если составляемое имя запрашиваемого узла пусто
	if((name.data == nullptr) || (name.size == 0))
		// Выводим отказ пустого имени запрашиваемого узла
		return error_t::EMPTY;
	// Объект составителя полей тела расширения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открываем перечень имён узлов
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Записываем вид имени узла «host_name»
		if((failure = builder.number(0, 1)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Открываем поле имени запрашиваемого узла
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Записываем имя запрашиваемого узла
		if((failure = builder.bytes(name)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если поле имени запрашиваемого узла закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если перечень имён узлов закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело расширения
		const view_t data = builder.data();
		// Выполняем дописывание тела расширения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело расширения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела расширения
	return error_t::NONE;
}
