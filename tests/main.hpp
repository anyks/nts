/**
 * @file main.hpp
 * @date 2026-08-26
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
 * @brief Общий заголовочный файл набора автоматических проверок —
 *        подключение Google Test и настройка общих параметров окружения проверок
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_TESTS__
/**
 * Заводим макрос стража: повторное подключение главного заголовка проверок отсекается
 */
#define __ANTS_TESTS__

/**
 * Отключаем поддержку POSIX регулярных выражений в Google Test
 */
#define GTEST_HAS_POSIX_RE 0

/**
 * Подключаем переносимую оснастку вызовов POSIX
 */
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы Google Test
 */
#include <gtest/gtest.h>

#endif
