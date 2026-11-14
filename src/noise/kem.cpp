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
 * @details Составной KEM по RFC 10024, как в гибридной группе TLS: открытый
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
	 * @brief Функция Признак составного механизма
	 *
	 * @param kem механизм
	 * @return    признак
	 *
	 */
	static bool composite(const nts::noise::kem_t kem) noexcept {
		// Выводим признак
		return (kem == nts::noise::kem_t::X25519MLKEM768);
	}
	/**
	 * @brief Функция Признак поддержанного механизма
	 *
	 * @param kem механизм
	 * @return    признак
	 *
	 */
	static bool known(const nts::noise::kem_t kem) noexcept {
		// Выводим признак
		return ((kem == nts::noise::kem_t::X25519MLKEM768) || (kem == nts::noise::kem_t::MLKEM768));
	}
};

/**
 * @brief Функция получения длины части KEM
 *
 * @param kem  механизм упаковки ключа
 * @param part часть
 * @return     длина в байтах либо нуль у незнакомого механизма
 *
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
		// Часть шифртекста
		case part_t::CIPHERTEXT: return (CT + extra);
		// Общий секрет
		case part_t::SHARED: return (SS + extra);
		// Часть зерна
		case part_t::SEED: return (SEED + extra);
		// Случайность упаковки
		case part_t::COINS: return (M + extra);
		// Прочие части набора
		default: return 0;
	}
}
/**
 * @brief Функция порождения пары ключей KEM из зерна - детерминированный, для корпусов и потребителя, хранящего зерно
 *
 * @param kem    механизм упаковки ключа
 * @param seed   зерно длиной SEED: у ML-KEM-768 d ‖ z (64), у составного ещё закрытый X25519 (96)
 * @param key    место открытого ключа длиной PUBLIC
 * @param secret место закрытого ключа длиной SECRET
 * @return       признак того, что пара порождена
 *
 */
bool nts::noise::kemgenerateDeterministic(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Если механизм, зерно либо места негодны
	if(!known(kem) || (seed.data == nullptr) || (seed.size != kemlength(kem, part_t::SEED)) || (key == nullptr) || (secret == nullptr))
		// Выводим отрицательный результат - пара не порождена
		return false;
	// Порождаем пару ML-KEM-768 из d ‖ z
	if(!agreement::generate(agreement::kem_t::MLKEM768, view_t(seed.data, SEED), key, secret))
		// Выводим отрицательный результат - упаковка пары не удалась
		return false;
	// Если механизм составной, за ML-KEM идёт X25519
	if(composite(kem)){
		// Закрытый ключ X25519 - хвост зерна, открытый выводится
		::memcpy(secret + DK, seed.data + SEED, X);
		// Если открытый ключ не выведен
		if(!agreement::x25519(view_t(secret + DK, X), key + EK)){
			// Затираем закрытый ключ
			wipe(secret, DK + X);
			// Выводим отрицательный результат - закрытый ключ не выведен
			return false;
		}
	}
	// Закрытый ключ выведен
	return true;
}
/**
 * @brief Функция порождения пары ключей KEM из энтропии
 *
 * @param kem    механизм упаковки ключа
 * @param key    место открытого ключа длиной PUBLIC
 * @param secret место закрытого ключа длиной SECRET
 * @return       признак того, что пара порождена
 *
 */
bool nts::noise::kemgenerate(const kem_t kem, uint8_t * key, uint8_t * secret) noexcept {
	// Если механизм негоден
	if(!known(kem))
		// Выводим отрицательный результат - механизм негоден
		return false;
	// Зерно набора
	uint8_t seed[KEM_SEED_MAX];
	// Берём зерно из энтропии
	if(!entropy::bytes(seed, kemlength(kem, part_t::SEED)))
		// Выводим отрицательный результат - зерно не получено
		return false;
	// Порождаем пару из зерна
	const bool status = kemgenerateDeterministic(kem, view_t(seed, kemlength(kem, part_t::SEED)), key, secret);
	// Затираем зерно
	wipe(seed, sizeof(seed));
	// Возвращаем итог порождения с энтропией
	return status;
}
/**
 * @brief Функция упаковки общего секрета на заданной случайности - детерминированный, для корпусов
 *
 * @param kem        механизм упаковки ключа
 * @param key        открытый ключ получателя длиной PUBLIC
 * @param coins      случайность длиной COINS: у ML-KEM-768 m (32), у составного ещё закрытый временный X25519 (64)
 * @param ciphertext место шифртекста длиной CIPHERTEXT
 * @param shared     место общего секрета длиной SHARED
 * @return           признак того, что секрет упакован
 *
 */
bool nts::noise::encapsulateDeterministic(const kem_t kem, const view_t & key, const view_t & coins, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// Если механизм, ключ, случайность либо места негодны
	if(!known(kem) || (key.data == nullptr) || (key.size != kemlength(kem, part_t::PUBLIC)) || (coins.data == nullptr) || (coins.size != kemlength(kem, part_t::COINS)) || (ciphertext == nullptr) || (shared == nullptr))
		// Выводим отрицательный результат - капсула не выработана
		return false;
	// Упаковываем ML-KEM-768 на m
	if(!agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(key.data, EK), view_t(coins.data, M), ciphertext, shared))
		// Выводим отрицательный результат - упаковка не удалась
		return false;
	// Если механизм составной, за ML-KEM идёт X25519: временный открытый ключ в шифртекст, общий секрет следом
	if(composite(kem)){
		// Если открытый ключ не выведен либо DH дал точку малого порядка
		if(!agreement::x25519(view_t(coins.data + M, X), ciphertext + CT) || !agreement::x25519(view_t(coins.data + M, X), view_t(key.data + EK, X), shared + SS)){
			// Затираем секрет и шифртекст
			wipe(shared, SS + X);
			wipe(ciphertext, CT + X);
			// Выводим отрицательный результат - секрет не выделен
			return false;
		}
	}
	// Капсула и секрет выработаны
	return true;
}
/**
 * @brief Функция упаковки общего секрета к открытому ключу на энтропии
 *
 * @param kem        механизм упаковки ключа
 * @param key        открытый ключ получателя длиной PUBLIC
 * @param ciphertext место шифртекста длиной CIPHERTEXT
 * @param shared     место общего секрета длиной SHARED
 * @return           признак того, что секрет упакован
 *
 */
bool nts::noise::encapsulate(const kem_t kem, const view_t & key, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// Если механизм негоден
	if(!known(kem))
		// Выводим отрицательный результат - механизм негоден
		return false;
	// Случайность упаковки
	uint8_t coins[KEM_SHARED_MAX];
	// Берём случайность из энтропии
	if(!entropy::bytes(coins, kemlength(kem, part_t::COINS)))
		// Выводим отрицательный результат - случайность не получена
		return false;
	// Упаковываем на случайности
	const bool status = encapsulateDeterministic(kem, key, view_t(coins, kemlength(kem, part_t::COINS)), ciphertext, shared);
	// Затираем случайность
	wipe(coins, sizeof(coins));
	// Возвращаем итог упаковки с энтропией
	return status;
}
/**
 * @brief Функция распаковки общего секрета
 *
 * @param kem        механизм упаковки ключа
 * @param secret     свой закрытый ключ длиной SECRET
 * @param ciphertext шифртекст длиной CIPHERTEXT
 * @param shared     место общего секрета длиной SHARED
 * @return           признак того, что секрет распакован (у ML-KEM подделка даёт неявное отклонение, а не отказ)
 *
 */
bool nts::noise::decapsulate(const kem_t kem, const view_t & secret, const view_t & ciphertext, uint8_t * shared) noexcept {
	// Если механизм, ключ, шифртекст либо место негодны
	if(!known(kem) || (secret.data == nullptr) || (secret.size != kemlength(kem, part_t::SECRET)) || (ciphertext.data == nullptr) || (ciphertext.size != kemlength(kem, part_t::CIPHERTEXT)) || (shared == nullptr))
		// Выводим отрицательный результат - секрет не извлечён
		return false;
	// Распаковываем ML-KEM-768
	if(!agreement::decapsulate(agreement::kem_t::MLKEM768, view_t(secret.data, DK), view_t(ciphertext.data, CT), shared))
		// Выводим отрицательный результат - распаковка не удалась
		return false;
	// Если механизм составной, DH X25519 своего закрытого с временным открытым из шифртекста
	if(composite(kem) && !agreement::x25519(view_t(secret.data + DK, X), view_t(ciphertext.data + CT, X), shared + SS)){
		// Затираем секрет
		wipe(shared, SS + X);
		// Выводим отрицательный результат - секрет не выделен
		return false;
	}
	// Секрет извлечён
	return true;
}
