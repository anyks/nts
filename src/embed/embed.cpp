/**
 * @file embed.cpp
 * @date 2026-09-16
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
 * \~russian
 * @brief Исходный файл модуля вывода ключа для зашивания в образ приложения
 *
 * \~english
 * @brief Source file of the key derivation module for embedding into the application image
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <embed/embed.hpp>
#include <sys/wipe.hpp>
#include <digest/hkdf.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * \~russian
 * @brief Метка области вывода ключа из материала: разводит контуры вывода материала и пароля
 *
 * \~english
 * @brief Label of the area of the key derivation from the material: separates the material and the password derivation domains
 */
static constexpr uint8_t EMBED_LABEL_KEY[] = {'A', '-', 'N', 'T', 'S', ' ', 'e', 'm', 'b', 'e', 'd', ' ', 'k', 'e', 'y'};

/**
 * \~russian
 * @brief Метка области вывода ключа из пароля
 *
 * \~english
 * @brief Label of the area of the key derivation from a password
 */
static constexpr uint8_t EMBED_LABEL_PWD[] = {'A', '-', 'N', 'T', 'S', ' ', 'e', 'm', 'b', 'e', 'd', ' ', 'p', 'w', 'd'};

/**
 * \~russian
 * @brief Функция вплетения метки, версии и связки в связной буфер
 *
 * @details Версия кладётся восемью октетами старшим байтом вперёд — вид не зависит от порядка
 *          октетов машины, потому закладка на сборочной машине и запуск дают одинаковый буфер
 *
 * @param buffer  собираемый буфер
 * @param label   метка области
 * @param length  длина метки
 * @param version версия ключа
 * @param context связка привязки к образу
 *
 * \~english
 * @brief Function of the weaving of the label, the version and the context into a binding buffer
 *
 * @param buffer  the buffer being assembled
 * @param label   the area label
 * @param length  the length of the label
 * @param version the key version
 * @param context the binding context
 */
static void weave(std::vector <uint8_t> & buffer, const uint8_t * label, const size_t length, const uint64_t version, const view_t & context){
	// Кладём метку области
	buffer.insert(buffer.end(), label, label + length);
	/**
	 * Кладём версию восемью октетами старшим байтом вперёд
	 */
	for(size_t i = 8; i > 0; i--)
		buffer.push_back(static_cast <uint8_t> ((version >> ((i - 1) * 8)) & 0xFF));
	// Кладём связку привязки к образу, если она задана
	if((context.data != nullptr) && (context.size > 0))
		buffer.insert(buffer.end(), context.data, context.data + context.size);
}

/**
 * key Метод вывода зашитого ключа из собранного по образу материала
 */
bool nts::embed::key(const digest::hash_t algorithm, const view_t & material, const view_t & salt, const view_t & context, const uint64_t version, uint8_t * result, const size_t size) noexcept {
	// Длина хеша выбранного алгоритма
	const size_t hashLength = digest::length(algorithm);
	/**
	 * Отсекаем негодные входы: неизвестный хеш, пустой материал, отсутствующий приёмник
	 */
	if((hashLength == 0) || (material.data == nullptr) || (material.size == 0) || (result == nullptr) || (size == 0))
		// Сообщаем об отказе вывода
		return false;
	/**
	 * Псевдослучайный ключ на стеке: длина любого хеша библиотеки не превосходит 64 октетов
	 */
	uint8_t prk[64];
	// Проверяем, что длина хеша умещается в отведённое место
	if(hashLength > sizeof(prk))
		// Сообщаем об отказе вывода
		return false;
	// Признак успеха вывода
	bool done = false;
	/**
	 * Ловим нехватку памяти при сборке буфера связки: путь noexcept обращает её в отказ
	 */
	try {
		/**
		 * Извлекаем псевдослучайный ключ из материала под солью (раздел 2.2 RFC 5869)
		 */
		if(digest::extract(algorithm, salt, material, prk, hashLength)){
			// Буфер связки: метка области, версия, привязка к образу
			std::vector <uint8_t> info;
			// Резервируем ёмкость под метку, восемь октетов версии и связку
			info.reserve(sizeof(EMBED_LABEL_KEY) + 8 + context.size);
			// Вплетаем метку, версию и связку
			weave(info, EMBED_LABEL_KEY, sizeof(EMBED_LABEL_KEY), version, context);
			/**
			 * Расширяем псевдослучайный ключ в ключ нужной длины (раздел 2.3 RFC 5869)
			 */
			done = digest::expand(algorithm, view_t(prk, hashLength), view_t(info.data(), info.size()), result, size);
		}
	// Перехватываем нехватку памяти
	} catch(const std::bad_alloc &){
		// Сообщаем об отказе вывода
		done = false;
	}
	/**
	 * Затираем псевдослучайный ключ на любом выходе: он восстанавливает выведенный ключ
	 */
	sys::wipe(prk, sizeof(prk));
	// Выводим признак успеха вывода
	return done;
}

/**
 * secret Метод вывода зашитого ключа из пароля растяжением Argon2
 */
bool nts::embed::secret(const digest::argon_params_t & params, const view_t & password, const view_t & salt, const view_t & context, const uint64_t version, uint8_t * result, const size_t size) noexcept {
	/**
	 * Отсекаем негодные входы: отсутствующий приёмник либо слишком короткая метка
	 */
	if((result == nullptr) || (size < 4))
		// Сообщаем об отказе вывода
		return false;
	// Признак успеха вывода
	bool done = false;
	/**
	 * Ловим нехватку памяти при сборке буфера связанных данных: путь noexcept обращает её в отказ
	 */
	try {
		// Буфер связанных данных Argon2: метка области, версия, привязка к образу
		std::vector <uint8_t> associated;
		// Резервируем ёмкость под метку, восемь октетов версии и связку
		associated.reserve(sizeof(EMBED_LABEL_PWD) + 8 + context.size);
		// Вплетаем метку, версию и связку
		weave(associated, EMBED_LABEL_PWD, sizeof(EMBED_LABEL_PWD), version, context);
		/**
		 * Растягиваем пароль в ключ Argon2 с версией и привязкой в связанных данных (раздел 3 RFC 9106)
		 */
		done = digest::argon2(params, password, salt, view_t(), view_t(associated.data(), associated.size()), result, size);
	// Перехватываем нехватку памяти
	} catch(const std::bad_alloc &){
		// Сообщаем об отказе вывода
		done = false;
	}
	// Выводим признак успеха вывода
	return done;
}
