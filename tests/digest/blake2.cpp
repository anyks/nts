/**
 * @file blake2.cpp
 * @date 2026-09-07
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
 * @brief Проверки модуля хеширования BLAKE2b и BLAKE2s по RFC 7693
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <random>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/blake2.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 * @return     запись строчными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Объявляем строку итога
	std::string result;
	// Таблица шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/** Перебираем: все байты буфера по порядку */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Возвращаем запись шестнадцатеричной строкой
	return result;
}
/**
 * @brief Функция хеширования за один вызов
 *
 * @param type    разновидность
 * @param key     ключ
 * @param message сообщение
 * @param size    длина итога
 * @return        запись итога либо пустая при отказе
 *
 */
static std::string whole(const digest::blake_t type, const std::string & key, const std::string & message, const size_t size) {
	// Объявляем буфер итога
	std::vector <uint8_t> result(size, 0);
	// Выполняем хеширование за один вызов
	if(!digest::blake2(type, view_t(reinterpret_cast <const uint8_t *> (key.data()), key.size()), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result.data(), size))
		// Возвращаем пустую запись при отказе
		return std::string();
	// Возвращаем запись итога
	return text(result.data(), size);
}
/**
 * @brief Функция хеширования кусками
 *
 * @param type    разновидность
 * @param key     ключ
 * @param message сообщение
 * @param chunk   длина куска
 * @param size    длина итога
 * @return        запись итога либо пустая при отказе
 *
 */
static std::string pieces(const digest::blake_t type, const std::string & key, const std::string & message, const size_t chunk, const size_t size) {
	// Объявляем объект хеширования
	digest::blake2_t hasher;
	// Заводим хеширование с заданным ключом
	if(!hasher.start(type, size, view_t(reinterpret_cast <const uint8_t *> (key.data()), key.size())))
		// Возвращаем пустую запись при отказе
		return std::string();
	/** Перебираем: сообщение кусками заданной длины */
	for(size_t offset = 0; offset < message.size(); offset += chunk){
		// Вычисляем длину очередного куска
		const size_t length = (((message.size() - offset) < chunk) ? (message.size() - offset) : chunk);
		// Передаём кусок в хеширование
		if(!hasher.update(view_t(reinterpret_cast <const uint8_t *> (message.data()) + offset, length)))
			// Возвращаем пустую запись при отказе
			return std::string();
	}
	// Объявляем буфер итога
	std::vector <uint8_t> result(size, 0);
	// Завершаем хеширование
	if(!hasher.finish(result.data(), size))
		// Возвращаем пустую запись при отказе
		return std::string();
	// Возвращаем запись итога
	return text(result.data(), size);
}
/**
 * @brief Функция разбора шестнадцатеричной строки
 *
 * @param hex строка
 * @return    байты строкой
 *
 */
static std::string bytes(const char * hex) {
	// Объявляем строку байтов
	std::string result;
	/** Перебираем: пары знаков строки с шагом два */
	for(size_t i = 0; hex[i] && hex[i + 1]; i += 2){
		// Разбираем шестнадцатеричный знак в полубайт
		auto nib = [](char c) -> int { return ((c >= '0' && c <= '9') ? (c - '0') : ((c >= 'a' && c <= 'f') ? (c - 'a' + 10) : (c - 'A' + 10))); };
		// Складываем байт из двух полубайтов
		result.push_back(static_cast <char> ((nib(hex[i]) << 4) | nib(hex[i + 1])));
	}
	// Возвращаем строку байтов
	return result;
}

/**
 * Векторы RFC 7693 и openssl: «abc» и пустое сообщение
 */
TEST(Blake2Test, Vectors){
	// BLAKE2b-512("abc") - приложение A RFC 7693
	ASSERT_EQ(whole(digest::blake_t::BLAKE2B, "", "abc", 64), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
	// BLAKE2s-256("abc") - приложение B RFC 7693
	ASSERT_EQ(whole(digest::blake_t::BLAKE2S, "", "abc", 32), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
	// Пустое сообщение, сверено с openssl
	ASSERT_EQ(whole(digest::blake_t::BLAKE2B, "", "", 64), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
	ASSERT_EQ(whole(digest::blake_t::BLAKE2S, "", "", 32), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
}

/**
 * Ключевой режим: сверено с openssl mac BLAKE2BMAC/BLAKE2SMAC
 */
TEST(Blake2Test, Keyed){
	// Проверяем ключевой BLAKE2b, сверенный с openssl
	ASSERT_EQ(whole(digest::blake_t::BLAKE2B, bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "abc", 32), "d63a32d3e44738d7907f964316c241adaba0abfeabc32349677578a15a203f7f");
	ASSERT_EQ(whole(digest::blake_t::BLAKE2S, bytes("000102030405060708090a0b0c0d0e0f"), "abc", 16), "75296c2d2c0f51210b383f386bc8b1ff");
}

/**
 * Самопроверка приложения E RFC 7693: ключевые и бесключевые хеши разных длин над
 * порождённой последовательностью, свёрнутые в BLAKE2s-256
 */
TEST(Blake2Test, Selftest){
	// Порождение последовательности из приложения E
	auto selftestSeq = [](std::vector <uint8_t> & out, const size_t len, const uint32_t seed) {
		// Инициализируем регистры последовательности
		uint32_t a = 0xDEAD4BAD * seed, b = 1;
		// Выделяем буфер заданной длины
		out.assign(len, 0);
		/** Перебираем: байты последовательности по порядку */
		for(size_t i = 0; i < len; i++){
			// Вычисляем следующее значение суммы
			const uint32_t t = a + b;
			// Сдвигаем первый регистр
			a = b;
			// Записываем сумму во второй регистр
			b = t;
			// Записываем старший байт значения
			out[i] = static_cast <uint8_t> (t >> 24);
		}
	};
	// Таблицы длин итога и сообщения самопроверки BLAKE2b
	const size_t b2bMdLen[4] = {20, 32, 48, 64}, b2b_in_len[6] = {0, 3, 128, 129, 255, 1024};
	// Таблицы длин итога и сообщения самопроверки BLAKE2s
	const size_t b2sMdLen[4] = {16, 20, 28, 32}, b2s_in_len[6] = {0, 3, 64, 65, 255, 1024};
	// Свёртка самопроверки BLAKE2b ведётся самим BLAKE2b на 32 байта (E.2), BLAKE2s - BLAKE2s (E.3)
	digest::blake2_t checksum;
	// Заводим свёртку BLAKE2b на 32 байта
	ASSERT_TRUE(checksum.start(digest::blake_t::BLAKE2B, 32, view_t()));
	// Объявляем буферы сообщения, ключа и итога
	std::vector <uint8_t> in, key, md;
	// Объявляем буфер свёртки
	uint8_t result[32];
	/** Перебираем: четыре длины итога BLAKE2b */
	for(size_t i = 0; i < 4; i++){
		// Берём длину итога
		const size_t outlen = b2bMdLen[i];
		/** Перебираем: шесть длин сообщения */
		for(size_t j = 0; j < 6; j++){
			// Берём длину сообщения
			const size_t inlen = b2b_in_len[j];
			// Порождаем последовательность сообщения
			selftestSeq(in, inlen, static_cast <uint32_t> (inlen));
			// Выделяем буфер итога
			md.assign(outlen, 0);
			// Проверяем бесключевой хеш
			ASSERT_TRUE(digest::blake2(digest::blake_t::BLAKE2B, view_t(), view_t(in.data(), in.size()), md.data(), outlen));
			ASSERT_TRUE(checksum.update(view_t(md.data(), md.size())));
			// Порождаем последовательность ключа
			selftestSeq(key, outlen, static_cast <uint32_t> (outlen));
			// Проверяем ключевой хеш
			ASSERT_TRUE(digest::blake2(digest::blake_t::BLAKE2B, view_t(key.data(), key.size()), view_t(in.data(), in.size()), md.data(), outlen));
			ASSERT_TRUE(checksum.update(view_t(md.data(), md.size())));
		}
	}
	// Свёртка самопроверки BLAKE2b: константа приложения E.2 RFC 7693, сошлась и с hashlib.blake2b
	ASSERT_TRUE(checksum.finish(result, sizeof(result)));
	// Сверяем константу приложения E.2
	EXPECT_EQ(text(result, 32), "c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475");
	// Заводим свёртку BLAKE2s на 32 байта
	ASSERT_TRUE(checksum.start(digest::blake_t::BLAKE2S, 32, view_t()));
	/** Перебираем: четыре длины итога BLAKE2s */
	for(size_t i = 0; i < 4; i++){
		// Берём длину итога
		const size_t outlen = b2sMdLen[i];
		/** Перебираем: шесть длин сообщения */
		for(size_t j = 0; j < 6; j++){
			// Берём длину сообщения
			const size_t inlen = b2s_in_len[j];
			// Порождаем последовательность сообщения
			selftestSeq(in, inlen, static_cast <uint32_t> (inlen));
			// Выделяем буфер итога
			md.assign(outlen, 0);
			// Проверяем бесключевой хеш
			ASSERT_TRUE(digest::blake2(digest::blake_t::BLAKE2S, view_t(), view_t(in.data(), in.size()), md.data(), outlen));
			ASSERT_TRUE(checksum.update(view_t(md.data(), md.size())));
			// Порождаем последовательность ключа
			selftestSeq(key, outlen, static_cast <uint32_t> (outlen));
			// Проверяем ключевой хеш
			ASSERT_TRUE(digest::blake2(digest::blake_t::BLAKE2S, view_t(key.data(), key.size()), view_t(in.data(), in.size()), md.data(), outlen));
			ASSERT_TRUE(checksum.update(view_t(md.data(), md.size())));
		}
	}
	// Свёртка самопроверки BLAKE2s: константа приложения E.3 RFC 7693, сошлась и с hashlib.blake2s
	ASSERT_TRUE(checksum.finish(result, sizeof(result)));
	// Сверяем константу приложения E.3
	EXPECT_EQ(text(result, 32), "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe");
}

/**
 * Независимость от нарезки, включая длины вокруг блоков 64 и 128
 */
TEST(Blake2Test, Chunks){
	// Заводим генератор на фиксированном семени
	std::mt19937 generator(20260907);
	// Таблица длин кусков вокруг блоков
	const size_t chunks[] = {1, 5, 63, 64, 65, 127, 128, 129, 300};
	// Таблица проверяемых разновидностей
	const digest::blake_t kinds[] = {digest::blake_t::BLAKE2B, digest::blake_t::BLAKE2S};
	/** Перебираем: длины сообщения от нуля до 700 с шагом 41 */
	for(size_t length = 0; length <= 700; length += 41){
		// Создаём сообщение заданной длины
		std::string message(length, 'x');
		/** Перебираем: байты сообщения из генератора */
		for(size_t i = 0; i < message.size(); i++)
			// Заполняем сообщение случайными байтами
			message[i] = static_cast <char> (generator() & 0xFF);
		/** Перебираем: обе разновидности BLAKE2 */
		for(size_t k = 0; k < 2; k++){
			// Берём длину блока разновидности
			const size_t size = ((kinds[k] == digest::blake_t::BLAKE2B) ? 64 : 32);
			/** Перебираем: бесключевой и ключевой режимы */
			for(size_t keyed = 0; keyed < 2; keyed++){
				// Формируем ключ заданной длины либо пустой
				const std::string key = (keyed ? std::string(size, 'k') : std::string());
				// Вычисляем эталон хеширования за один вызов
				const std::string reference = whole(kinds[k], key, message, size);
				// Проверяем непустоту эталона
				ASSERT_FALSE(reference.empty());
				/** Перебираем: все длины кусков таблицы */
				for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++)
					// Сверяем нарезку кусками с эталоном
					ASSERT_EQ(pieces(kinds[k], key, message, chunks[c], size), reference) << "длина " << length << " кусок " << chunks[c];
			}
		}
	}
}

/**
 * Отказы
 */
TEST(Blake2Test, Refusals){
	// Объявляем буфер итога
	uint8_t result[64];
	// Объявляем объект хеширования
	digest::blake2_t hasher;
	// Не заведён
	ASSERT_FALSE(hasher.update(view_t(result, 1)));
	ASSERT_FALSE(hasher.finish(result, 32));
	// Негодные заведения
	ASSERT_FALSE(hasher.start(digest::blake_t::NONE, 32, view_t()));
	ASSERT_FALSE(hasher.start(digest::blake_t::BLAKE2B, 0, view_t()));
	ASSERT_FALSE(hasher.start(digest::blake_t::BLAKE2B, 65, view_t()));
	ASSERT_FALSE(hasher.start(digest::blake_t::BLAKE2S, 33, view_t()));
	ASSERT_FALSE(hasher.start(digest::blake_t::BLAKE2S, 32, view_t(result, 33)));
	ASSERT_FALSE(hasher.start(digest::blake_t::BLAKE2B, 32, view_t(nullptr, 5)));
	// Годное заведение
	ASSERT_TRUE(hasher.start(digest::blake_t::BLAKE2S, 20, view_t()));
	// Проверяем разновидность после заведения
	ASSERT_EQ(hasher.type(), digest::blake_t::BLAKE2S);
	ASSERT_EQ(hasher.length(), 20u);
	ASSERT_EQ(hasher.block(), 64u);
	// Проверяем обновление пустым куском
	ASSERT_TRUE(hasher.update(view_t()));
	// Проверяем отказ на нулевом буфере
	ASSERT_FALSE(hasher.update(view_t(nullptr, 3)));
	ASSERT_FALSE(hasher.finish(result, 19));
	ASSERT_FALSE(hasher.finish(nullptr, 20));
	// Проверяем завершение с годной длиной
	ASSERT_TRUE(hasher.finish(result, 20));
	// Проверяем отказ на повторном завершении
	ASSERT_FALSE(hasher.finish(result, 20));
	ASSERT_FALSE(hasher.update(view_t(result, 1)));
	// Один вызов с негодной длиной
	ASSERT_FALSE(digest::blake2(digest::blake_t::BLAKE2B, view_t(), view_t(), result, 0));
}
