/**
 * @file lms.cpp
 * @date 2026-10-06
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
 * @brief Исходный файл проверок модуля подписей Лейтона-Микали
 *
 * @note Эталоном служит контрольный пример приложения F RFC 8554 (Test Case 1):
 *       двухуровневая подпись HSS с наборами LMS_SHA256_M32_H5 и
 *       LMOTS_SHA256_N32_W8, записанная в наборе tests/corpus/lms
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>
#include <fstream>
#include <iterator>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sign/lms.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок модуля LMS
 */
namespace {
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	static std::vector <uint8_t> slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в набор байтов
		return std::vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	}
	/**
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data набор байтов
	 *
	 * @return     просмотр набора
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) noexcept {
		// Выводим просмотр набора
		return view_t(data.data(), data.size());
	}
}

/**
 * Проверка подписи HSS контрольного примера приложения F RFC 8554
 */
TEST(LmsTest, HssVector) {
	// Открытый ключ контрольного примера
	const std::vector <uint8_t> key = slurp(std::string(CORPUS) + "/lms/pubkey.bin");
	// Сообщение контрольного примера
	const std::vector <uint8_t> message = slurp(std::string(CORPUS) + "/lms/message.bin");
	// Подпись контрольного примера
	const std::vector <uint8_t> signature = slurp(std::string(CORPUS) + "/lms/signature.bin");
	// Записи обязаны прочитаться
	ASSERT_EQ(key.size(), 60U);
	ASSERT_EQ(message.size(), 162U);
	ASSERT_EQ(signature.size(), 2644U);
	// Подпись контрольного примера обязана сойтись
	ASSERT_TRUE(sign::lms::verify(view(key), view(message), view(signature)));
}

/**
 * Проверка отказов на порченых записях
 */
TEST(LmsTest, Refusals) {
	// Открытый ключ контрольного примера
	const std::vector <uint8_t> key = slurp(std::string(CORPUS) + "/lms/pubkey.bin");
	// Сообщение контрольного примера
	const std::vector <uint8_t> message = slurp(std::string(CORPUS) + "/lms/message.bin");
	// Подпись контрольного примера
	const std::vector <uint8_t> signature = slurp(std::string(CORPUS) + "/lms/signature.bin");
	// Подделанная подпись: байт внутри звена цепочки нижнего уровня
	std::vector <uint8_t> forged(signature);
	forged[forged.size() - 200] ^= 0x01;
	// Подделка обязана отказать
	ASSERT_FALSE(sign::lms::verify(view(key), view(forged), view(signature)));
	// Подделанное сообщение обязано отказать
	std::vector <uint8_t> altered(message);
	altered[0] ^= 0x01;
	ASSERT_FALSE(sign::lms::verify(view(key), view(altered), view(signature)));
	// Усечённая подпись обязана отказать
	ASSERT_FALSE(sign::lms::verify(view(key), view(message), view_t(signature.data(), signature.size() - 1)));
	// Чужой открытый ключ обязан отказать
	std::vector <uint8_t> alien(key);
	alien[alien.size() - 1] ^= 0x01;
	ASSERT_FALSE(sign::lms::verify(view(alien), view(message), view(signature)));
	// Непереданные записи обязаны отказать
	ASSERT_FALSE(sign::lms::verify(view_t(nullptr, 0), view(message), view(signature)));
	ASSERT_FALSE(sign::lms::verify(view(key), view_t(nullptr, 0), view(signature)));
	ASSERT_FALSE(sign::lms::verify(view(key), view(message), view_t(nullptr, 0)));
}

/**
 * Проверка одноуровневой подписи LMS нижнего уровня контрольного примера
 */
TEST(LmsTest, SingleLevel) {
	// Открытый ключ контрольного примера
	const std::vector <uint8_t> key = slurp(std::string(CORPUS) + "/lms/pubkey.bin");
	// Сообщение контрольного примера
	const std::vector <uint8_t> message = slurp(std::string(CORPUS) + "/lms/message.bin");
	// Подпись контрольного примера
	const std::vector <uint8_t> signature = slurp(std::string(CORPUS) + "/lms/signature.bin");
	/**
	 * Нижний уровень контрольного примера: открытый ключ pub[1] идёт в подписи
	 * за числом уровней и первой подписью LMS (4 + 1292), подпись сообщения -
	 * за ним (ещё 56 байтов)
	 */
	const size_t lmsLength = 1292;
	// Открытый ключ нижнего уровня
	const view_t pub1(signature.data() + 4 + lmsLength, 56);
	// Подпись сообщения нижним уровнем
	const view_t sig1(signature.data() + 4 + lmsLength + 56, lmsLength);
	// Одноуровневая подпись обязана сойтись
	ASSERT_TRUE(sign::lms::verify(pub1, view(message), sig1));
	// Подделка байта пути Меркла обязана отказать
	std::vector <uint8_t> forged(sig1.data, sig1.data + sig1.size);
	forged[forged.size() - 10] ^= 0x40;
	ASSERT_FALSE(sign::lms::verify(pub1, view(message), view(forged)));
}
