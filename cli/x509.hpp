/**
 * @file x509.hpp
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
 * @brief Заголовочный файл команд сертификатов консольной утилиты a-nts
 *
 * @details Команды повторяют устройство openssl: req, x509, ca, crl и pkcs12.
 *          Запрос PKCS #10, выпуск самоподписанного сертификата и подпись ЦС,
 *          просмотр сертификата и списка отзыва, разбор контейнера PKCS #12
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
		 * @brief Функция создания запроса на сертификат
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int req(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над сертификатом
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int x509(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция выпуска сертификата удостоверяющим центром
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int issueCa(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над списком отзыва
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int crl(const int argc, const char * const argv[]) noexcept;
		/**
		 * @brief Функция действий над контейнером PKCS #12
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @return     код выхода из команды
		 *
		 */
		int pkcs12(const int argc, const char * const argv[]) noexcept;
	}
}
