/**
 * @file keys.hpp
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
 * @brief Заголовочный файл команд ключей консольной утилиты a-nts
 *
 * @details Команды повторяют устройство openssl: genpkey, genrsa, genec, pkey, rsa и ec.
 *          Ключ вырабатывается примитивами подписи, записывается и разбирается кодеком
 *          keys в обёртку PEM байт в байт с openssl
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
		 * @brief Функция универсальной выработки ключа
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int genpkey(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция выработки ключа RSA
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int genrsa(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция выработки ключа EC
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int genec(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над ключом произвольного вида
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int pkey(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над ключом RSA
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int rsa(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над ключом EC
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int ecKey(const int argc, const char * const argv[]) noexcept;
	}
}
