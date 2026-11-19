/**
 * @file tls.hpp
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
 * @brief Заголовочный файл команд связи консольной утилиты a-nts — клиент s_client
 *        и сервер s_server протокола TLS
 *
 * @details Команды повторяют устройство openssl: s_client подключается к узлу по имени
 *          и порту, ведёт рукопожатие и ретранслирует данные между стандартным вводом
 *          и связью; s_server принимает соединение на порту, предъявляет подлинность
 *          сертификатом и ретранслирует данные между связью и стандартным вводом
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
		 * @brief Функция ведения связи со стороны клиента
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int sClient(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция ведения связи со стороны сервера
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int sServer(const int argc, const char * const argv[]) noexcept;
	}
}
