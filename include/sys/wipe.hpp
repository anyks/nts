/**
 * @file wipe.hpp
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
 * \~russian
 * @brief Заголовочный файл затирания областей памяти с тайнами
 *
 * \~english
 * @brief Header file of the wiping of the memory areas holding secrets
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_WIPE__
#define __ANTS_WIPE__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён служебных средств
	 *
	 * \~english
	 * @brief Namespace of the utility means
	 *
	 * \~
	 */
	namespace sys {
		/**
		 * \~russian
		 * @brief Метод затирания области памяти
		 *
		 * @details Запись идёт через изменчивый указатель, оттого собиратель не вправе
		 *          выбросить её как бесполезную, даже если после затирания область не
		 *          читается. Обычный memset такой гарантии не даёт: правило «как если бы»
		 *          дозволяет убрать запись, итог которой никто не наблюдает
		 *
		 * @param data затираемая область памяти
		 * @param size размер затираемой области памяти в байтах
		 *
		 * @note Намеренное решение: поразрядная запись через изменчивый указатель не
		 *       заменяется ни на memset, ни на memset_s, ни на что-либо «быстрее». Разбор
		 *       порождённого кода показал: с memset собиратель убирает и затирание, и сам
		 *       ключ со стека; с изменчивой записью вызов сохраняется. Под сквозной
		 *       оптимизацией (-flto, у AWH включена под Windows) проверкой это не поймать,
		 *       гарантию даёт только исходник
		 *
		 * \~english
		 * @brief Method of the wiping of a memory area
		 * @details The write goes through a volatile pointer, hence the compiler may not drop it as
		 *          useless even if the area is not read after the wiping. A plain memset gives no
		 *          such guarantee: the as-if rule allows to remove a write whose result nobody observes
		 * @param data the memory area being wiped
		 * @param size the size of the memory area being wiped in bytes
		 * @note Deliberate decision: the byte-wise write through a volatile pointer is not to be replaced
		 *       by memset, memset_s or anything "faster". The inspection of the generated code showed:
		 *       with memset the compiler removes both the wiping and the key itself from the stack; with
		 *       the volatile write the call is kept. Under the link-time optimization (-flto, enabled at
		 *       AWH on Windows) a test cannot catch this, only the source gives the guarantee
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(void * data, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод затирания набора байтов с его опустошением
		 *
		 * @param data затираемый набор байтов; после затирания пуст
		 *
		 * \~english
		 * @brief Method of the wiping of a byte vector with its emptying
		 * @param data the byte vector being wiped; empty after the wiping
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(vector <uint8_t> & data) noexcept;
		/**
		 * \~russian
		 * @brief Метод затирания строки с её опустошением
		 *
		 * @param data затираемая строка; после затирания пуста
		 *
		 * \~english
		 * @brief Method of the wiping of a string with its emptying
		 * @param data the string being wiped; empty after the wiping
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(string & data) noexcept;
	};
};

#endif // __ANTS_WIPE__
