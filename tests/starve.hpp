/**
 * @file: starve.hpp
 * @date: 2026-09-03
 * @license: GPL-3.0
 *
 * @telegram: @forman
 * @author: Yuriy Lobarev
 * @phone: +7 (910) 983-95-90
 * @email: forman@anyks.com
 * @site: https://anyks.com
 *
 * @copyright: Copyright © 2026
 */

#ifndef __ANTS_TESTS_STARVE__
#define __ANTS_TESTS_STARVE__

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstdlib>
#include <cstddef>

/**
 * Помощник нехватки памяти: подменяет глобальные операторы выделения так, что по
 * исчерпании отмеренного запаса выделение отвечает исключением bad_alloc. Запас
 * отмеряется на время одного вызова, оттого выделения самой оснастки проверок под
 * подмену не попадают. Подключается единожды на двоичный файл проверок
 */
namespace starve {
	/**
	 * @brief Признак того, что запас выделений отмерен
	 */
	static bool armed = false;
	/**
	 * @brief Оставшийся запас выделений
	 */
	static size_t budget = 0;
	/**
	 * @brief Класс отмеренного запаса выделений на время своей жизни
	 */
	typedef class Ration {
		public:
			/**
			 * @brief Конструктор
			 *
			 * @param count число выделений, дозволенных до отказа
			 *
			 */
			Ration(const size_t count) noexcept {
				// Устанавливаем запас выделений
				budget = count;
				// Устанавливаем признак отмеренного запаса
				armed = true;
			}
			/**
			 * @brief Метод досрочного снятия запаса
			 *
			 * @note Снимает подмену до конца области видимости: дальнейшие выделения,
			 *       например под сообщение проверки, идут без ограничения
			 *
			 */
			void stop() noexcept {
				// Снимаем признак отмеренного запаса
				armed = false;
			}
			/**
			 * @brief Деструктор
			 *
			 */
			~Ration() noexcept {
				// Снимаем признак отмеренного запаса
				armed = false;
			}
	} ration_t;
	/**
	 * @brief Метод выделения памяти с учётом запаса
	 *
	 * @param size размер выделяемой памяти
	 *
	 * @return     указатель на выделенную память
	 *
	 */
	static void * take(const size_t size) {
		// Если запас выделений отмерен
		if(armed){
			// Если запас выделений исчерпан
			if(budget == 0)
				// Выбрасываем исключение нехватки памяти
				throw std::bad_alloc();
			// Уменьшаем запас выделений
			budget--;
		}
		// Выполняем выделение памяти
		void * result = ::malloc((size == 0) ? 1 : size);
		// Если память выделить не удалось
		if(result == nullptr)
			// Выбрасываем исключение нехватки памяти
			throw std::bad_alloc();
		// Выводим выделенную память
		return result;
	}
}

/**
 * @brief Оператор выделения памяти
 *
 * @param size размер выделяемой памяти
 *
 * @return     указатель на выделенную память
 *
 */
void * operator new(const std::size_t size){
	// Выводим выделенную память
	return starve::take(size);
}
/**
 * @brief Оператор выделения памяти под массив
 *
 * @param size размер выделяемой памяти
 *
 * @return     указатель на выделенную память
 *
 */
void * operator new[](const std::size_t size){
	// Выводим выделенную память
	return starve::take(size);
}
/**
 * @brief Оператор освобождения памяти
 *
 * @param data указатель на освобождаемую память
 *
 */
void operator delete(void * data) noexcept {
	// Выполняем освобождение памяти
	::free(data);
}
/**
 * @brief Оператор освобождения памяти под массивом
 *
 * @param data указатель на освобождаемую память
 *
 */
void operator delete[](void * data) noexcept {
	// Выполняем освобождение памяти
	::free(data);
}
/**
 * Освобождение известного размера подменяется лишь у GCC: он предупреждает о его
 * отсутствии, а clang с libc++ такую подмену отвергает как необычную; стандартное
 * освобождение известного размера само зовёт подменённое освобождение без размера
 */
#if defined(__GNUC__) && !defined(__clang__)
/**
 * @brief Оператор освобождения памяти известного размера
 *
 * @param data указатель на освобождаемую память
 * @param size размер освобождаемой памяти
 *
 */
void operator delete(void * data, const std::size_t size) noexcept {
	// Размер освобождаемой памяти не нужен
	(void) size;
	// Выполняем освобождение памяти
	::free(data);
}
/**
 * @brief Оператор освобождения памяти известного размера под массивом
 *
 * @param data указатель на освобождаемую память
 * @param size размер освобождаемой памяти
 *
 */
void operator delete[](void * data, const std::size_t size) noexcept {
	// Размер освобождаемой памяти не нужен
	(void) size;
	// Выполняем освобождение памяти
	::free(data);
}
#endif

#endif // __ANTS_TESTS_STARVE__
