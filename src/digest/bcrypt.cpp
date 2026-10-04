/**
 * @file bcrypt.cpp
 * @date 2026-10-04
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
 * @brief Модуль выработки ключа bcrypt_pbkdf
 *
 * @details PBKDF2 с хешем bcrypt по OpenBSD bcrypt_pbkdf.c (Ted Unangst, ISC).
 *          Пароль и соль предварительно хешируются SHA-512, выход расширен до 256 бит,
 *          магическая строка «OxychromaticBlowfishSwatDynamite», 64 круга начального
 *          расширения состояния. Выходные байты перемешиваются для предотвращения
 *          атаки на подключи
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/bcrypt.hpp>
#include <digest/sha2.hpp>
#include <cipher/blowfish.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён проекта
	 */
	using namespace nts;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Параметры bcrypt
	 *
	 */
	// Число слов хеша
	constexpr size_t BCRYPT_WORDS = 8;
	// Размер хеша в байтах
	constexpr size_t BCRYPT_HASHSIZE = BCRYPT_WORDS * 4;
	// Размер хеша SHA-512
	constexpr size_t SHA512_SIZE = 64;

	/**
	 * @brief Метод хеширования bcrypt
	 *
	 * @param sha2pass хеш пароля SHA-512
	 * @param sha2salt хеш соли SHA-512
	 * @param out      выходной буфер (32 байта)
	 *
	 */
	void bcrypt_hash(const uint8_t * sha2pass, const uint8_t * sha2salt, uint8_t * out) noexcept {
		cipher::blowfish_t state;
		uint8_t ciphertext[BCRYPT_HASHSIZE];
		::memcpy(ciphertext, "OxychromaticBlowfishSwatDynamite", BCRYPT_HASHSIZE);
		uint32_t cdata[BCRYPT_WORDS];
		// Расширение ключа
		cipher::init(&state);
		cipher::expand(&state, sha2salt, SHA512_SIZE, sha2pass, SHA512_SIZE);
		for(size_t i = 0; i < 64; ++i){
			cipher::expand0(&state, sha2salt, SHA512_SIZE);
			cipher::expand0(&state, sha2pass, SHA512_SIZE);
		}
		// Шифрование
		size_t j = 0;
		for(size_t i = 0; i < BCRYPT_WORDS; ++i)
			cdata[i] = cipher::stream2word(ciphertext, sizeof(ciphertext), &j);
		for(size_t i = 0; i < 64; ++i)
			cipher::encrypt(&state, cdata, BCRYPT_WORDS / 2);
		// Вывод
		for(size_t i = 0; i < BCRYPT_WORDS; ++i){
			out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
			out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
			out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
			out[4 * i + 0] = cdata[i] & 0xff;
		}
		// Затирание
		wipe(ciphertext, sizeof(ciphertext));
		wipe(cdata, sizeof(cdata));
		wipe(&state, sizeof(state));
	}
};

/**
 * \~russian
 * @brief Метод выработки ключа bcrypt_pbkdf
 *
 * \~english
 * @brief Method of the key derivation bcrypt_pbkdf
 *
 * \~
 */
bool nts::digest::bcrypt(const view_t & pass, const view_t & salt, uint8_t * key, const size_t keylen, const size_t rounds) noexcept {
	// Проверяем параметры
	if(pass.data == nullptr || pass.size == 0 ||
	   salt.data == nullptr || salt.size == 0 ||
	   key == nullptr || keylen == 0 || rounds < 1)
		return false;
	// Число блоков выхода
	const size_t stride = (keylen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE;
	size_t amt = (keylen + stride - 1) / stride;
	const size_t origkeylen = keylen;
	size_t remaining = keylen;
	// Хеш пароля
	uint8_t sha2pass[SHA512_SIZE];
	{
		digest::Sha2 sha(digest::sha_t::SHA512);
		sha.update(pass);
		sha.finish(sha2pass, sizeof(sha2pass));
	}
	// Вырабатываем ключ блоками
	uint8_t out[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t sha2salt[SHA512_SIZE];
	uint8_t countsalt[4];
	for(uint32_t count = 1; remaining > 0; ++count){
		countsalt[0] = (count >> 24) & 0xff;
		countsalt[1] = (count >> 16) & 0xff;
		countsalt[2] = (count >> 8) & 0xff;
		countsalt[3] = count & 0xff;
		// Первый круг: соль + счётчик
		{
			digest::Sha2 sha(digest::sha_t::SHA512);
			sha.update(salt);
			sha.update(view_t(countsalt, sizeof(countsalt)));
			sha.finish(sha2salt, sizeof(sha2salt));
		}
		bcrypt_hash(sha2pass, sha2salt, tmpout);
		::memcpy(out, tmpout, sizeof(out));
		// Последующие круги: соль = предыдущий выход
		for(size_t i = 1; i < rounds; ++i){
			{
				digest::Sha2 sha(digest::sha_t::SHA512);
				sha.update(view_t(tmpout, sizeof(tmpout)));
				sha.finish(sha2salt, sizeof(sha2salt));
			}
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			for(size_t j = 0; j < sizeof(out); ++j)
				out[j] ^= tmpout[j];
		}
		// Перемешивание выходных байтов
		const size_t current_amt = (amt < remaining) ? amt : remaining;
		size_t i;
		for(i = 0; i < current_amt; ++i){
			const size_t dest = i * stride + (count - 1);
			if(dest >= origkeylen)
				break;
			key[dest] = out[i];
		}
		remaining -= i;
	}
	// Затирание
	wipe(sha2pass, sizeof(sha2pass));
	wipe(sha2salt, sizeof(sha2salt));
	wipe(out, sizeof(out));
	wipe(tmpout, sizeof(tmpout));
	return true;
}
