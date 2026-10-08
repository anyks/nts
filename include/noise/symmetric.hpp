/**
 * @file symmetric.hpp
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
 * @brief Модуль симметричного состояния Noise (SymmetricState, §5.2)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <noise/noise.hpp>
#include <noise/cipher.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён каркаса Noise
	 *
	 * \~english
	 * @brief Namespace of the Noise framework
	 *
	 * \~
	 */
	namespace noise {
		/**
		 * \~russian
		 * @brief Класс симметричного состояния: цепной ключ, хеш рукопожатия и состояние шифра
		 *
		 * @details Намеренные решения:
		 *          1. HKDF Noise это extract с солью ck и expand с пустой привязкой; при длине
		 *             хеша 64 ключ шифра усекается до KEY байтов, а ck остаётся полным.
		 *          2. При несошедшейся метке хеш рукопожатия не меняется.
		 *          3. Раскол отдаёт два состояния со счётчиками в нуле; второе у односторонних
		 *             узоров остаётся без ключа - решает вызывающий.
		 *
		 * \~english
		 * @brief Class of the symmetric state: the chaining key, the handshake hash and the cipher state
		 *
		 * @details Deliberate decisions:
		 *          1. Noise HKDF is extract with ck as the salt and expand with an empty info;
		 *             at a hash length of 64 the cipher key is truncated to KEY bytes while ck
		 *             stays whole.
		 *          2. On a mismatched tag the handshake hash does not change.
		 *          3. Split gives two states with zero counters; for one-way patterns the second
		 *             is left without a key - the caller decides.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Symmetric {
			private:
				// Функция хеширования
				digest::hash_t _hash;
				// Функция шифрования набора
				aead_t _aead;
				// Длина хеша
				size_t _length;
				// Состояние шифра
				cipher_t _cipher;
				// Цепной ключ
				uint8_t _chain[HASH_MAX];
				// Хеш рукопожатия
				uint8_t _digest[HASH_MAX];
			private:
				/**
				 * @brief Метод вывода ключевого материала (HKDF Noise)
				 *
				 * @param material входной ключевой материал
				 * @param result   место материала в count длин хеша
				 * @param count    число выходов: 2 либо 3
				 *
				 * @return         признак того, что материал выведен
				 *
				 */
				bool kdf(const view_t & material, uint8_t * result, const size_t count) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения состояния (InitializeSymmetric)
				 *
				 * @param name  имя протокола
				 * @param suite набор примитивов
				 *
				 * @return      признак того, что состояние заведено
				 *
				 * \~english
				 * @brief Method of the state initialization (InitializeSymmetric)
				 *
				 * @param name  protocol name
				 * @param suite suite of primitives
				 *
				 * @return      sign that the state is initialized
				 *
				 * \~
				 */
				bool start(const view_t & name, const suite_t & suite) noexcept;
				/**
				 * \~russian
				 * @brief Метод примешивания ключевого материала (MixKey)
				 *
				 * @param material входной ключевой материал
				 *
				 * @return         признак того, что материал примешан
				 *
				 * \~english
				 * @brief Method of mixing the key material (MixKey)
				 *
				 * @param material input key material
				 *
				 * @return         sign that the material is mixed
				 *
				 * \~
				 */
				bool key(const view_t & material) noexcept;
				/**
				 * \~russian
				 * @brief Метод примешивания данных в хеш (MixHash)
				 *
				 * @param data данные
				 *
				 * @return     признак того, что данные примешаны
				 *
				 * \~english
				 * @brief Method of mixing data into the hash (MixHash)
				 *
				 * @param data data
				 *
				 * @return     sign that the data is mixed
				 *
				 * \~
				 */
				bool hash(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод примешивания заранее разделённого ключа (MixKeyAndHash)
				 *
				 * @param material входной ключевой материал
				 *
				 * @return         признак того, что материал примешан
				 *
				 * \~english
				 * @brief Method of mixing a pre-shared key (MixKeyAndHash)
				 *
				 * @param material input key material
				 *
				 * @return         sign that the material is mixed
				 *
				 * \~
				 */
				bool blend(const view_t & material) noexcept;
				/**
				 * \~russian
				 * @brief Метод шифрования с примешиванием (EncryptAndHash)
				 *
				 * @param source открытые данные
				 * @param result место выхода: при отсутствии ключа - те же данные, иначе шифротекст с меткой
				 * @param size   на входе вместимость места, на выходе длина выхода
				 *
				 * @return       признак того, что выход получен
				 *
				 * \~english
				 * @brief Method of encryption with mixing (EncryptAndHash)
				 *
				 * @param source plaintext
				 * @param result place of the output: the same data without a key, else the ciphertext with the tag
				 * @param size   the capacity of the place on input, the output length on output
				 *
				 * @return       sign that the output is produced
				 *
				 * \~
				 */
				bool seal(const view_t & source, uint8_t * result, size_t & size) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования с примешиванием (DecryptAndHash)
				 *
				 * @param source вход: при отсутствии ключа - открытые данные, иначе шифротекст с меткой
				 * @param result место открытых данных
				 * @param size   на входе вместимость места, на выходе длина открытых данных
				 *
				 * @return       признак того, что данные подлинны и получены
				 *
				 * \~english
				 * @brief Method of decryption with mixing (DecryptAndHash)
				 *
				 * @param source input: the plaintext without a key, else the ciphertext with the tag
				 * @param result place of the plaintext
				 * @param size   the capacity of the place on input, the plaintext length on output
				 *
				 * @return       sign that the data is authentic and produced
				 *
				 * \~
				 */
				bool open(const view_t & source, uint8_t * result, size_t & size) noexcept;
				/**
				 * \~russian
				 * @brief Метод раскола на два состояния шифра (Split)
				 *
				 * @param one состояние от инициатора к отвечающему
				 * @param two состояние от отвечающего к инициатору
				 *
				 * @return    признак того, что раскол выполнен
				 *
				 * \~english
				 * @brief Method of splitting into two cipher states (Split)
				 *
				 * @param one state from the initiator to the responder
				 * @param two state from the responder to the initiator
				 *
				 * @return    sign that the split is done
				 *
				 * \~
				 */
				bool split(cipher_t & one, cipher_t & two) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения хеша рукопожатия (GetHandshakeHash)
				 *
				 * @param result место хеша в длину хеша набора
				 *
				 * @return       признак того, что хеш выдан
				 *
				 * \~english
				 * @brief Method of getting the handshake hash (GetHandshakeHash)
				 *
				 * @param result place of the hash of the suite hash length
				 *
				 * @return       sign that the hash is given
				 *
				 * \~
				 */
				bool digest(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины хеша набора
				 *
				 * @return длина хеша либо нуль до заведения
				 *
				 * \~english
				 * @brief Method of getting the suite hash length
				 *
				 * @return hash length or zero before initialization
				 *
				 * \~
				 */
				size_t length() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки наличия ключа шифра
				 *
				 * @return признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of the cipher key presence check
				 *
				 * @return sign that the key is set
				 *
				 * \~
				 */
				bool has() const noexcept;
				/**
				 * \~russian
				 * @brief Метод затирания состояния
				 *
				 * \~english
				 * @brief Method of wiping the state
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Symmetric() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Symmetric() noexcept;
		} symmetric_t;
	};
};

