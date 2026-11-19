/**
 * @file enc.hpp
 * @date 2026-11-19
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
 * @brief Заголовочный файл команды enc консольной утилиты a-nts
 *
 * @details Команда повторяет устройство openssl enc: имя шифра, флаги зашифрования
 *          либо расшифрования, ключ и синхропосылка шестнадцатерично либо вывод ключа
 *          из пароля
 *
 * @copyright Copyright © 2026
 *
 */

#pragma once

/**
 * Стандартные модули
 */
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "sys/global.hpp"

/**
 * Основное пространство имён
 */
namespace nts {
	/**
	 * Пространство имён помощников консольной утилиты
	 */
	namespace cli {
		/**
		 * @brief Функция зашифрования и расшифрования данных блочным шифром
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int enc(const int argc, const char * const argv[]) noexcept;
	}
}
