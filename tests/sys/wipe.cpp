/**
 * @file wipe.cpp
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
 * @brief Проверки затирания областей памяти
 *
 * @note Затирание нужно AWH в 46 местах (хранилище тайн, шифрование, QUIC) вместо
 *       OPENSSL_cleanse; проверки закрепляют обнуление, границы и опустошение
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sys/wipe.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Признак сборки с ограждением адресов: чтение буфера контейнера за его размером
 * там считается переполнением, и сличение затёртого буфера доступно только без него
 */
#if defined(__SANITIZE_ADDRESS__)
	#define ANTS_ASAN 1
#elif defined(__has_feature)
	#if __has_feature(address_sanitizer)
		#define ANTS_ASAN 1
	#endif
#endif

/**
 * Проверка обнуления области памяти целиком и точно по границе
 */
TEST(WipeTest, Area) {
	// Область с тайной и сторожевыми байтами по краям
	uint8_t area[40];
	// Заполняем область ненулевыми байтами
	::memset(area, 0xA5, sizeof(area));
	// Затираем середину, оставляя по восемь сторожевых байтов с краёв
	sys::wipe(area + 8, 24);
	/**
	 * Выполняем перебор байтов области
	 */
	for(size_t i = 0; i < sizeof(area); i++){
		// Если байт внутри затёртой середины
		if((i >= 8) && (i < 32)){
			// Проверяем обнуление байта
			EXPECT_EQ(area[i], 0) << "смещение " << i;
		// Если байт сторожевой
		} else {
			// Проверяем нетронутость байта
			EXPECT_EQ(area[i], 0xA5) << "смещение " << i;
		}
	}
}
/**
 * Проверка терпимости к пустой области и пустому указателю
 */
TEST(WipeTest, Empty) {
	// Одиночный байт
	uint8_t byte = 0x5A;
	// Затираем нулевую длину: байт остаётся
	sys::wipe(&byte, 0);
	// Проверяем нетронутость байта
	EXPECT_EQ(byte, 0x5A);
	// Затираем пустой указатель: ничего не происходит
	sys::wipe(nullptr, 16);
	// Затираем пустой набор байтов
	std::vector <uint8_t> nothing;
	// Выполняем затирание
	sys::wipe(nothing);
	// Проверяем пустоту набора
	EXPECT_TRUE(nothing.empty());
	// Затираем пустую строку
	std::string blank;
	// Выполняем затирание
	sys::wipe(blank);
	// Проверяем пустоту строки
	EXPECT_TRUE(blank.empty());
}
/**
 * Проверка затирания набора байтов и строки с опустошением
 */
TEST(WipeTest, Containers) {
	// Набор байтов с тайной
	std::vector <uint8_t> secret(64, 0xC3);
	// Указатель на буфер набора до затирания
	const uint8_t * buffer = secret.data();
	// Ёмкость набора до затирания
	const size_t capacity = secret.capacity();
	// Выполняем затирание
	sys::wipe(secret);
	// Проверяем опустошение набора
	EXPECT_TRUE(secret.empty());
	// Проверяем сохранность буфера: опустошение ёмкость не меняет
	EXPECT_EQ(secret.capacity(), capacity);
/**
 * Если ограждения адресов нет: буфер остался у набора и обязан быть нулевым
 */
#if !defined(ANTS_ASAN)
	/**
	 * Выполняем перебор байтов прежнего буфера
	 */
	for(size_t i = 0; i < 64; i++)
		// Проверяем обнуление байта
		EXPECT_EQ(buffer[i], 0) << "смещение " << i;
#else
	// Под ограждением адресов буфер за размером не читается
	(void) buffer;
#endif
	// Строка с тайной длиннее короткого запаса
	std::string password(48, 'p');
	// Указатель на буфер строки до затирания
	const char * text = password.data();
	// Выполняем затирание
	sys::wipe(password);
	// Проверяем опустошение строки
	EXPECT_TRUE(password.empty());
/**
 * Если ограждения адресов нет
 */
#if !defined(ANTS_ASAN)
	/**
	 * Выполняем перебор байтов прежнего буфера строки
	 */
	for(size_t i = 0; i < 48; i++)
		// Проверяем обнуление байта
		EXPECT_EQ(text[i], 0) << "смещение " << i;
#else
	// Под ограждением адресов буфер за размером не читается
	(void) text;
#endif
}
