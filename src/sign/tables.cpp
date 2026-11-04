/**
 * @file tables.cpp
 * @date 2026-11-05
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
 * @brief Исходный файл пустых кратных точки основания Эдвардсовой кривой
 *
 * @note Этот файл входит в библиотеку, когда заготовка кратных выключена
 *       настройкой сборки: отсутствие заготовки отказом не считается, и умножение
 *       точки основания отступает к общей лестнице
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <internal/sign/tables.hpp>

/**
 * @brief Метод поиска заготовленной гребёнки кратных точки основания
 *
 * @return nullptr: кратные не заготовлены сборкой
 *
 */
const nts::sign::comb_t * nts::sign::prepared() noexcept {
	// Выводим отсутствие заготовленной гребёнки
	return nullptr;
}
