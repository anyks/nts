/**
 * @file kem.cpp
 * @date 2026-09-08
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
 * @brief Отвлечение KEM для PQNoise: чистый ML-KEM-768 и составной X25519MLKEM768
 *
 * @details Составной KEM по draft-ietf-tls-ecdhe-mlkem, как в гибридной группе TLS: открытый
 *          ключ ek ‖ pk, закрытый dk ‖ sk, шифртекст ct ‖ pk_e, общий секрет ss_mlkem ‖
 *          ss_x25519. Точка малого порядка у X25519 - отказ. Неявное отклонение ML-KEM остаётся
 *          его собственным: подделанный шифртекст даёт J(z ‖ c), а не отказ
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <noise/noise.hpp>
#include <agreement/mlkem.hpp>
#include <agreement/x25519.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;
	/**
	 * Длины частей ML-KEM-768 и X25519
	 */
	static constexpr size_t EK = 1184, DK = 2400, CT = 1088, SS = 32, SEED = 64, M = 32, X = 32;
	/**
	 * @brief Признак составного механизма
	 *
	 * @param kem механизм
	 *
	 * @return    признак
	 *
	 */
	static bool composite(const nts::noise::kem_t kem) noexcept {
		// Выводим признак
		return (kem == nts::noise::kem_t::X25519MLKEM768);
	}
	/**
	 * @brief Признак поддержанного механизма
	 *
	 * @param kem механизм
	 *
	 * @return    признак
	 *
	 */
	static bool known(const nts::noise::kem_t kem) noexcept {
		// Выводим признак
		return ((kem == nts::noise::kem_t::X25519MLKEM768) || (kem == nts::noise::kem_t::MLKEM768));
	}
};

/**
 * \~russian
 * @brief Метод получения длины части KEM
 *
 * @param kem  механизм упаковки ключа
 * @param part часть
 *
 * @return     длина в байтах либо нуль
 *
 * \~english
 * @brief Method of getting the length of a KEM part
 *
 * @param kem  key encapsulation mechanism
 * @param part part
 *
 * @return     length in bytes or zero
 *
 * \~
 */
size_t nts::noise::kemlength(const kem_t kem, const part_t part) noexcept {
	// Если механизм не поддержан
	if(!known(kem))
		// Выводим нуль
		return 0;
	// Добавка составного механизма
	const size_t extra = (composite(kem) ? X : 0);
	/**
	 * Определяем часть
	 */
	switch(part){
		// Открытый ключ
		case part_t::PUBLIC: return (EK + extra);
		// Закрытый ключ
		case part_t::SECRET: return (DK + extra);
		// Шифртекст
		case part_t::CIPHERTEXT: return (CT + extra);
		// Общий секрет
		case part_t::SHARED: return (SS + extra);
		// Зерно
		case part_t::SEED: return (SEED + extra);
		// Случайность упаковки
		case part_t::COINS: return (M + extra);
		// Прочее
		default: return 0;
	}
}
/**
 * \~russian
 * @brief Метод порождения пары ключей KEM из зерна
 *
 * @param kem    механизм упаковки ключа
 * @param seed   зерно
 * @param key    место открытого ключа
 * @param secret место закрытого ключа
 *
 * @return       признак того, что пара порождена
 *
 * \~english
 * @brief Method of KEM key pair generation from a seed
 *
 * @param kem    key encapsulation mechanism
 * @param seed   seed
 * @param key    place of the public key
 * @param secret place of the secret key
 *
 * \~
 */
bool nts::noise::kemgenerateDeterministic(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Если механизм, зерно либо места негодны
	if(!known(kem) || (seed.data == nullptr) || (seed.size != kemlength(kem, part_t::SEED)) || (key == nullptr) || (secret == nullptr))
		// Выводим отказ
		return false;
	// Порождаем пару ML-KEM-768 из d ‖ z
	if(!agreement::generate(agreement::kem_t::MLKEM768, view_t(seed.data, SEED), key, secret))
		// Выводим отказ
		return false;
	// Если механизм составной, за ML-KEM идёт X25519
	if(composite(kem)){
		// Закрытый ключ X25519 - хвост зерна, открытый выводится
		::memcpy(secret + DK, seed.data + SEED, X);
		// Если открытый ключ не выведен
		if(!agreement::x25519(view_t(secret + DK, X), key + EK)){
			// Затираем закрытый ключ
			wipe(secret, DK + X);
			// Выводим отказ
			return false;
		}
	}
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод порождения пары ключей KEM из энтропии
 *
 * @param kem    механизм упаковки ключа
 * @param key    место открытого ключа
 * @param secret место закрытого ключа
 *
 * @return       признак того, что пара порождена
 *
 * \~english
 * @brief Method of KEM key pair generation from entropy
 *
 * @param kem    key encapsulation mechanism
 * @param key    place of the public key
 * @param secret place of the secret key
 *
 * \~
 */
bool nts::noise::kemgenerate(const kem_t kem, uint8_t * key, uint8_t * secret) noexcept {
	// Если механизм негоден
	if(!known(kem))
		// Выводим отказ
		return false;
	// Зерно
	uint8_t seed[KEM_SEED_MAX];
	// Берём зерно из энтропии
	if(!entropy::bytes(seed, kemlength(kem, part_t::SEED)))
		// Выводим отказ
		return false;
	// Порождаем пару из зерна
	const bool status = kemgenerateDeterministic(kem, view_t(seed, kemlength(kem, part_t::SEED)), key, secret);
	// Затираем зерно
	wipe(seed, sizeof(seed));
	// Выводим успешность
	return status;
}
/**
 * \~russian
 * @brief Метод упаковки общего секрета на заданной случайности
 *
 * @param kem        механизм упаковки ключа
 * @param key        открытый ключ получателя
 * @param coins      случайность
 * @param ciphertext место шифртекста
 * @param shared     место общего секрета
 *
 * @return           признак того, что секрет упакован
 *
 * \~english
 * @brief Method of shared secret encapsulation on given randomness
 *
 * @param kem        key encapsulation mechanism
 * @param key        receiver public key
 * @param coins      randomness
 * @param ciphertext place of the ciphertext
 * @param shared     place of the shared secret
 *
 * \~
 */
bool nts::noise::encapsulateDeterministic(const kem_t kem, const view_t & key, const view_t & coins, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// Если механизм, ключ, случайность либо места негодны
	if(!known(kem) || (key.data == nullptr) || (key.size != kemlength(kem, part_t::PUBLIC)) || (coins.data == nullptr) || (coins.size != kemlength(kem, part_t::COINS)) || (ciphertext == nullptr) || (shared == nullptr))
		// Выводим отказ
		return false;
	// Упаковываем ML-KEM-768 на m
	if(!agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(key.data, EK), view_t(coins.data, M), ciphertext, shared))
		// Выводим отказ
		return false;
	// Если механизм составной, за ML-KEM идёт X25519: временный открытый ключ в шифртекст, общий секрет следом
	if(composite(kem)){
		// Если открытый ключ не выведен либо DH дал точку малого порядка
		if(!agreement::x25519(view_t(coins.data + M, X), ciphertext + CT) || !agreement::x25519(view_t(coins.data + M, X), view_t(key.data + EK, X), shared + SS)){
			// Затираем секрет и шифртекст
			wipe(shared, SS + X);
			wipe(ciphertext, CT + X);
			// Выводим отказ
			return false;
		}
	}
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод упаковки общего секрета на энтропии
 *
 * @param kem        механизм упаковки ключа
 * @param key        открытый ключ получателя
 * @param ciphertext место шифртекста
 * @param shared     место общего секрета
 *
 * @return           признак того, что секрет упакован
 *
 * \~english
 * @brief Method of shared secret encapsulation on entropy
 *
 * @param kem        key encapsulation mechanism
 * @param key        receiver public key
 * @param ciphertext place of the ciphertext
 * @param shared     place of the shared secret
 *
 * \~
 */
bool nts::noise::encapsulate(const kem_t kem, const view_t & key, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// Если механизм негоден
	if(!known(kem))
		// Выводим отказ
		return false;
	// Случайность
	uint8_t coins[KEM_SHARED_MAX];
	// Берём случайность из энтропии
	if(!entropy::bytes(coins, kemlength(kem, part_t::COINS)))
		// Выводим отказ
		return false;
	// Упаковываем на случайности
	const bool status = encapsulateDeterministic(kem, key, view_t(coins, kemlength(kem, part_t::COINS)), ciphertext, shared);
	// Затираем случайность
	wipe(coins, sizeof(coins));
	// Выводим успешность
	return status;
}
/**
 * \~russian
 * @brief Метод распаковки общего секрета
 *
 * @param kem        механизм упаковки ключа
 * @param secret     свой закрытый ключ
 * @param ciphertext шифртекст
 * @param shared     место общего секрета
 *
 * @return           признак того, что секрет распакован
 *
 * \~english
 * @brief Method of shared secret decapsulation
 *
 * @param kem        key encapsulation mechanism
 * @param secret     own secret key
 * @param ciphertext ciphertext
 * @param shared     place of the shared secret
 *
 * \~
 */
bool nts::noise::decapsulate(const kem_t kem, const view_t & secret, const view_t & ciphertext, uint8_t * shared) noexcept {
	// Если механизм, ключ, шифртекст либо место негодны
	if(!known(kem) || (secret.data == nullptr) || (secret.size != kemlength(kem, part_t::SECRET)) || (ciphertext.data == nullptr) || (ciphertext.size != kemlength(kem, part_t::CIPHERTEXT)) || (shared == nullptr))
		// Выводим отказ
		return false;
	// Распаковываем ML-KEM-768
	if(!agreement::decapsulate(agreement::kem_t::MLKEM768, view_t(secret.data, DK), view_t(ciphertext.data, CT), shared))
		// Выводим отказ
		return false;
	// Если механизм составной, DH X25519 своего закрытого с временным открытым из шифртекста
	if(composite(kem) && !agreement::x25519(view_t(secret.data + DK, X), view_t(ciphertext.data + CT, X), shared + SS)){
		// Затираем секрет
		wipe(shared, SS + X);
		// Выводим отказ
		return false;
	}
	// Выводим успешность
	return true;
}
