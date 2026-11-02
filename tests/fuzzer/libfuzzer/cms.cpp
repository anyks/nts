/**
 * @file cms.cpp
 * @date 2026-11-02
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
 * @brief Ворошитель криптографических сообщений с управлением от покрытия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cms/cms.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам CMS
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Заводим просмотр подаваемой области байтов
		const view_t input(data, size);
		// Разбираемое подписанное содержимое CMS
		cms::signed_t signedData;
		// Выполняем разбор подписанного содержимого CMS
		signedData.parse(input);
		// Разбираемое ограждённое содержимое CMS
		cms::enveloped_t envelopedData;
		// Выполняем разбор ограждённого содержимого CMS
		envelopedData.parse(input);
		// Разбираемое хешированное содержимое CMS
		cms::digested_t digestedData;
		// Выполняем разбор хешированного содержимого CMS
		digestedData.parse(input);
		// Разбираемое зашифрованное содержимое CMS
		cms::encrypted_t encryptedData;
		// Выполняем разбор зашифрованного содержимого CMS
		encryptedData.parse(input);
		// Разбираемое заверенное содержимое CMS
		cms::authenticated_t authenticatedData;
		// Выполняем разбор заверенного содержимого CMS
		authenticatedData.parse(input);
		// Выводим код продолжения ворошения
		return 0;
	}
}
