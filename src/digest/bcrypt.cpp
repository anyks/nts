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
	 * @brief Функция хеширования bcrypt
	 *
	 * @param sha2pass хеш пароля SHA-512
	 * @param sha2salt хеш соли SHA-512
	 * @param out      выходной буфер (32 байта)
	 *
	 */
	void __ants_bcrypt_hash__(const uint8_t * sha2pass, const uint8_t * sha2salt, uint8_t * out) noexcept {
		// Состояние шифра Blowfish
		cipher::blowfish_t state;
		// Накопитель шифртекста магической строки
		uint8_t ciphertext[BCRYPT_HASHSIZE];
		// Переносим магическую строку в накопитель
		::memcpy(ciphertext, "OxychromaticBlowfishSwatDynamite", BCRYPT_HASHSIZE);
		// Слова шифртекста для вывода хеша
		uint32_t cdata[BCRYPT_WORDS];
		// Расширение ключа
		cipher::init(&state);
		// Расширяем ключ солью и паролем
		cipher::expand(&state, sha2salt, SHA512_SIZE, sha2pass, SHA512_SIZE);
		/**
		 * Выполняем 64 круга начального расширения состояния
		 */
		for(size_t i = 0; i < 64; ++i){
			// Расширяем состояние солью
			cipher::expand0(&state, sha2salt, SHA512_SIZE);
			cipher::expand0(&state, sha2pass, SHA512_SIZE);
		}
		// Шифрование
		size_t j = 0;
		/**
		 * Выполняем перебор слов накопителя шифртекста
		 */
		for(size_t i = 0; i < BCRYPT_WORDS; ++i)
			// Переносим слово шифртекста в накопитель слов
			cdata[i] = cipher::stream2word(ciphertext, sizeof(ciphertext), &j);
		/**
		 * Выполняем 64 круга шифрования слов
		 */
		for(size_t i = 0; i < 64; ++i)
			// Шифруем слова накопителя
			cipher::encrypt(&state, cdata, BCRYPT_WORDS / 2);
		/**
		 * Вывод
		 */
		for(size_t i = 0; i < BCRYPT_WORDS; ++i){
			// Старший байт слова
			out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
			// Следующий байт слова
			out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
			// Следующий байт слова
			out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
			// Младший байт слова
			out[4 * i + 0] = cdata[i] & 0xff;
		}
		// Затирание
		wipe(ciphertext, sizeof(ciphertext));
		wipe(cdata, sizeof(cdata));
		wipe(&state, sizeof(state));
	}
};

/**
 * @brief Функция выработки ключа bcrypt_pbkdf
 *
 * @param pass   пароль
 * @param salt   соль
 * @param key    место, в которое помещается выработанный ключ
 * @param keylen длина вырабатываемого ключа в байтах
 * @param rounds число кругов
 * @return       признак успешности выработки ключа
 *
 */
bool nts::digest::bcrypt(const view_t & pass, const view_t & salt, uint8_t * key, const size_t keylen, const size_t rounds) noexcept {
	// Проверяем параметры
	if(pass.data == nullptr || pass.size == 0 ||
	   salt.data == nullptr || salt.size == 0 ||
	   key == nullptr || keylen == 0 || rounds < 1)
		// Выводим отказ негодных параметров
		return false;
	// Число блоков выхода
	const size_t stride = (keylen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE;
	// Длина блока выхода в байтах
	size_t amt = (keylen + stride - 1) / stride;
	// Первоначальная длина ключа для проверки места назначения
	const size_t origkeylen = keylen;
	// Число байтов ключа, ещё не выработанных
	size_t remaining = keylen;
	// Хеш пароля
	uint8_t sha2pass[SHA512_SIZE];
	{
		// Хешируем пароль SHA-512
		digest::Sha2 sha(digest::sha_t::SHA512);
		// Передаём пароль объекту хеша
		sha.update(pass);
		// Завершаем хеш пароля
		sha.finish(sha2pass, sizeof(sha2pass));
	}
	// Вырабатываем ключ блоками
	uint8_t out[BCRYPT_HASHSIZE];
	// Накопитель выхода очередного круга
	uint8_t tmpout[BCRYPT_HASHSIZE];
	// Хеш соли SHA-512
	uint8_t sha2salt[SHA512_SIZE];
	// Соль со счётчиком блока
	uint8_t countsalt[4];
	/**
	 * Выполняем перебор блоков выхода, пока ключ не выработан
	 */
	for(uint32_t count = 1; remaining > 0; ++count){
		// Старший байт счётчика блока
		countsalt[0] = (count >> 24) & 0xff;
		// Следующий байт счётчика блока
		countsalt[1] = (count >> 16) & 0xff;
		// Следующий байт счётчика блока
		countsalt[2] = (count >> 8) & 0xff;
		// Младший байт счётчика блока
		countsalt[3] = count & 0xff;
		// Первый круг: соль + счётчик
		{
			// Хешируем соль со счётчиком SHA-512
			digest::Sha2 sha(digest::sha_t::SHA512);
			// Передаём соль объекту хеша
			sha.update(salt);
			sha.update(view_t(countsalt, sizeof(countsalt)));
			// Завершаем хеш соли
			sha.finish(sha2salt, sizeof(sha2salt));
		}
		// Вырабатываем хеш bcrypt блока
		__ants_bcrypt_hash__(sha2pass, sha2salt, tmpout);
		// Запоминаем выход первого круга
		::memcpy(out, tmpout, sizeof(out));
		/**
		 * Последующие круги: соль = предыдущий выход
		 */
		for(size_t i = 1; i < rounds; ++i){
			{
				// Хешируем выход предыдущего круга SHA-512
				digest::Sha2 sha(digest::sha_t::SHA512);
				// Передаём выход предыдущего круга объекту хеша
				sha.update(view_t(tmpout, sizeof(tmpout)));
				// Завершаем хеш соли
				sha.finish(sha2salt, sizeof(sha2salt));
			}
			// Вырабатываем хеш bcrypt очередного круга
			__ants_bcrypt_hash__(sha2pass, sha2salt, tmpout);
			/**
			 * Выполняем перебор байтов выхода блока
			 */
			for(size_t j = 0; j < sizeof(out); ++j)
				// Накапливаем выход круга по XOR
				out[j] ^= tmpout[j];
		}
		// Перемешивание выходных байтов
		const size_t currentAmt = (amt < remaining) ? amt : remaining;
		// Число байтов блока, перенесённых в ключ
		size_t i;
		/**
		 * Выполняем перебор байтов блока в пределах длины
		 */
		for(i = 0; i < currentAmt; ++i){
			// Место байта ключа в перемешанном выводе
			const size_t dest = i * stride + (count - 1);
			// Если место вышло за пределы ключа
			if(dest >= origkeylen)
				break;
			// Переносим байт выхода в ключ
			key[dest] = out[i];
		}
		// Вычитаем перенесённые байты из остатка ключа
		remaining -= i;
	}
	// Затирание
	wipe(sha2pass, sizeof(sha2pass));
	wipe(sha2salt, sizeof(sha2salt));
	wipe(out, sizeof(out));
	wipe(tmpout, sizeof(tmpout));
	// Выводим успешность выработки ключа
	return true;
}
