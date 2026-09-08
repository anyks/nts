/**
 * @file noise.hpp
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
 * @brief Модуль описания каркаса Noise (ревизия 34): постоянные, наборы примитивов, узоры рукопожатия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_NOISE__
#define __ANTS_NOISE__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <digest/hash.hpp>

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
	 * @details Намеренные решения:
	 *          1. Узоры рукопожатия заданы данными - таблицей знаков, а не ветвями кода;
	 *             добавление узора это строка таблицы. Отложенные узоры (§7.3) - те же строки.
	 *          2. Точка малого порядка у DH (итог из одних нулей) - отказ, а не продолжение с
	 *             нулями: описание допускает оба поведения, выбран отказ, как у WireGuard и
	 *             golang.org/x/crypto.
	 *          3. Кривая 448 не поддерживается: наборы с ней разбираются именем, но dh остаётся
	 *             NONE, и рукопожатие с ними не заводится.
	 *          4. У односторонних узоров второе состояние раскола остаётся без ключа. Следствие:
	 *             собеседник, который всё же пустит обратный ход у одностороннего узора, у нас не
	 *             заработает никогда; по описанию такого быть не должно, но порождающий векторы
	 *             flynn/noise такие сообщения издаёт - это расхождение договора, не дефект flynn.
	 *          5. Корпуса векторов расходятся в направлении переноса после раскола: flynn чередует
	 *             заново с инициатора, Cacophony продолжает по номеру сообщения, а у односторонних
	 *             шлёт всё от инициатора. Наблюдение о чужих наборах, третий корпус начинать с него.
	 *          6. PQNoise по статье Angel и др. (CCS 2022): гибрид внутри KEM, а не в узоре; чистый
	 *             ML-KEM-768 - строка перечня, не умолчание; psk у PQNoise не заведён; имя протокола
	 *             с префиксом PQNoise - наше, реестра нет, собеседника, с которым оно сойдётся, не
	 *             существует. Детерминированные вызовы KEM (…Deterministic) выведены наружу ради
	 *             корпусов и потребителей, хранящих зерно; повтор зерна либо случайности - полная
	 *             потеря без отказа, потому имена длинные и отличные от обычных.
	 *
	 * \~english
	 * @brief Namespace of the Noise framework
	 *
	 * @details Deliberate decisions:
	 *          1. Handshake patterns are data - a table of tokens, not branches of code;
	 *             adding a pattern is a row of the table. Deferred patterns (§7.3) are such rows.
	 *          2. A low-order point in DH (an all-zero result) is a refusal, not a continuation
	 *             with zeros: the specification permits both, the refusal is chosen as in
	 *             WireGuard and golang.org/x/crypto.
	 *          3. Curve 448 is not supported: suites with it are parsed by name but dh stays
	 *             NONE, and no handshake starts with them.
	 *          4. For one-way patterns the second split state is left without a key. Consequence:
	 *             a peer that nevertheless sends the reverse direction of a one-way pattern will
	 *             never work with us; the specification says there should be none, yet the
	 *             flynn/noise vector generator emits such messages - a contract divergence, not
	 *             a flynn defect.
	 *          5. Vector corpora diverge in the transport direction after split: flynn alternates
	 *             anew from the initiator, Cacophony continues by message number and for one-way
	 *             patterns sends all from the initiator. An observation about foreign corpora, a
	 *             third corpus should start from it.
	 *          6. PQNoise per Angel et al. (CCS 2022): the hybrid lives inside the KEM, not in the
	 *             pattern; pure ML-KEM-768 is a row of the list, not the default; psk is not defined
	 *             for PQNoise; the protocol name with the PQNoise prefix is ours, there is no
	 *             registry and no peer it would match. Deterministic KEM calls (…Deterministic) are
	 *             exposed for corpora and consumers keeping the seed; a repeated seed or randomness
	 *             is a total loss without a refusal, hence the long names distinct from the usual.
	 *
	 * \~
	 */
	namespace noise {
		/**
		 * \~russian
		 * @brief Длина ключа шифра и ключа DH в байтах
		 *
		 * \~english
		 * @brief Length of the cipher key and of the DH key in bytes
		 *
		 * \~
		 */
		static constexpr size_t KEY = 32;
		/**
		 * \~russian
		 * @brief Длина метки подлинности в байтах
		 *
		 * \~english
		 * @brief Length of the authentication tag in bytes
		 *
		 * \~
		 */
		static constexpr size_t TAG = 16;
		/**
		 * \~russian
		 * @brief Длина заранее разделённого ключа в байтах
		 *
		 * \~english
		 * @brief Length of a pre-shared key in bytes
		 *
		 * \~
		 */
		static constexpr size_t PSK = 32;
		/**
		 * \~russian
		 * @brief Предел длины сообщения Noise целиком, вместе с меткой
		 *
		 * \~english
		 * @brief Limit of the whole Noise message length, including the tag
		 *
		 * \~
		 */
		static constexpr size_t MESSAGE = 65535;
		/**
		 * \~russian
		 * @brief Наибольшая длина хеша среди наборов
		 *
		 * \~english
		 * @brief Largest hash length among the suites
		 *
		 * \~
		 */
		static constexpr size_t HASH_MAX = 64;
		/**
		 * \~russian
		 * @brief Наибольшее число заранее разделённых ключей у одного узора
		 *
		 * \~english
		 * @brief Largest number of pre-shared keys of one pattern
		 *
		 * \~
		 */
		static constexpr size_t PSKS_MAX = 4;
		/**
		 * \~russian
		 * @brief Наибольшее число сообщений у одного узора
		 *
		 * \~english
		 * @brief Largest number of messages of one pattern
		 *
		 * \~
		 */
		static constexpr size_t MESSAGES_MAX = 4;
		/**
		 * \~russian
		 * @brief Наибольшее число знаков в одном сообщении узора
		 *
		 * \~english
		 * @brief Largest number of tokens in one message of a pattern
		 *
		 * \~
		 */
		static constexpr size_t TOKENS_MAX = 8;
		/**
		 * \~russian
		 * @brief Наибольшая длина имени протокола
		 *
		 * \~english
		 * @brief Largest length of a protocol name
		 *
		 * \~
		 */
		static constexpr size_t NAME_LIMIT = 64;
		/**
		 * \~russian
		 * @brief Предельные длины частей KEM среди поддержанных: открытый ключ, закрытый ключ, шифртекст, общий секрет, зерно
		 *
		 * \~english
		 * @brief Maximal lengths of KEM parts among the supported ones: public key, secret key, ciphertext, shared secret, seed
		 *
		 * \~
		 */
		static constexpr size_t KEM_PUBLIC_MAX = 1216, KEM_SECRET_MAX = 2432, KEM_CIPHERTEXT_MAX = 1120, KEM_SHARED_MAX = 64, KEM_SEED_MAX = 96;
		/**
		 * \~russian
		 * @brief Механизмы упаковки ключа (KEM) для PQNoise
		 *
		 * @details Гибрид живёт внутри KEM, а не в узоре: X25519MLKEM768 - составной KEM по
		 *          draft-ietf-tls-ecdhe-mlkem (ek ‖ pk, ct ‖ pk_e, ss_mlkem ‖ ss_x25519). Чистый
		 *          ML-KEM-768 - строка перечня, не умолчание
		 *
		 * \~english
		 * @brief Key encapsulation mechanisms (KEM) for PQNoise
		 *
		 * @details The hybrid lives inside the KEM, not in the pattern: X25519MLKEM768 is a
		 *          composite KEM per draft-ietf-tls-ecdhe-mlkem (ek ‖ pk, ct ‖ pk_e, ss_mlkem ‖
		 *          ss_x25519). Pure ML-KEM-768 is a row of the list, not the default
		 *
		 * \~
		 */
		enum class kem_t : uint8_t {
			NONE           = 0x00, /*!< \~russian Не установлен \~english Not set \~ */
			X25519MLKEM768 = 0x01, /*!< \~russian Составной X25519 + ML-KEM-768 \~english Composite X25519 + ML-KEM-768 \~ */
			MLKEM768       = 0x02  /*!< \~russian Чистый ML-KEM-768 по FIPS 203 \~english Pure ML-KEM-768 per FIPS 203 \~ */
		};
		/**
		 * \~russian
		 * @brief Части KEM, у которых спрашивается длина
		 *
		 * \~english
		 * @brief KEM parts whose length is queried
		 *
		 * \~
		 */
		enum class part_t : uint8_t {
			PUBLIC     = 0x01, /*!< \~russian Открытый ключ \~english Public key \~ */
			SECRET     = 0x02, /*!< \~russian Закрытый ключ \~english Secret key \~ */
			CIPHERTEXT = 0x03, /*!< \~russian Шифртекст \~english Ciphertext \~ */
			SHARED     = 0x04, /*!< \~russian Общий секрет \~english Shared secret \~ */
			SEED       = 0x05, /*!< \~russian Зерно порождения пары \~english Key pair generation seed \~ */
			COINS      = 0x06  /*!< \~russian Случайность упаковки \~english Encapsulation randomness \~ */
		};
		/**
		 * \~russian
		 * @brief Функции обмена ключами
		 *
		 * \~english
		 * @brief Key exchange functions
		 *
		 * \~
		 */
		enum class dh_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Не установлена \~english Not set \~ */
			X25519 = 0x19  /*!< \~russian X25519 по RFC 7748, «25519» в имени \~english X25519 according to RFC 7748, «25519» in the name \~ */
		};
		/**
		 * \~russian
		 * @brief Функции шифрования с подлинностью
		 *
		 * \~english
		 * @brief Authenticated encryption functions
		 *
		 * \~
		 */
		enum class aead_t : uint8_t {
			NONE       = 0x00, /*!< \~russian Не установлена \~english Not set \~ */
			CHACHAPOLY = 0x01, /*!< \~russian ChaCha20-Poly1305 по RFC 8439, нонс: нули и счётчик от младшего \~english ChaCha20-Poly1305 according to RFC 8439, nonce: zeros and the counter little-endian \~ */
			AESGCM     = 0x02  /*!< \~russian AES-256-GCM, нонс: нули и счётчик от старшего \~english AES-256-GCM, nonce: zeros and the counter big-endian \~ */
		};
		/**
		 * \~russian
		 * @brief Узоры рукопожатия: односторонние, основные и отложенные (§7.2, §7.3)
		 *
		 * \~english
		 * @brief Handshake patterns: one-way, fundamental and deferred (§7.2, §7.3)
		 *
		 * \~
		 */
		enum class pattern_t : uint8_t {
			NONE = 0x00, /*!< \~russian Не установлен \~english Not set \~ */
			N    = 0x01, /*!< \~russian Односторонний, отвечающий известен \~english One-way, the responder is known \~ */
			K    = 0x02, /*!< \~russian Односторонний, обе стороны известны \~english One-way, both sides are known \~ */
			X    = 0x03, /*!< \~russian Односторонний, отправитель передаёт свой ключ \~english One-way, the sender transmits its key \~ */
			NN   = 0x04, /*!< \~russian Без подлинности \~english Without authentication \~ */
			NK   = 0x05, /*!< \~russian Отвечающий известен \~english The responder is known \~ */
			NX   = 0x06, /*!< \~russian Отвечающий передаёт свой ключ \~english The responder transmits its key \~ */
			XN   = 0x07, /*!< \~russian Инициатор передаёт свой ключ \~english The initiator transmits its key \~ */
			XK   = 0x08, /*!< \~russian Отвечающий известен, инициатор передаёт \~english The responder is known, the initiator transmits \~ */
			XX   = 0x09, /*!< \~russian Обе стороны передают свои ключи \~english Both sides transmit their keys \~ */
			KN   = 0x0A, /*!< \~russian Инициатор известен \~english The initiator is known \~ */
			KK   = 0x0B, /*!< \~russian Обе стороны известны \~english Both sides are known \~ */
			KX   = 0x0C, /*!< \~russian Инициатор известен, отвечающий передаёт \~english The initiator is known, the responder transmits \~ */
			IN   = 0x0D, /*!< \~russian Инициатор передаёт сразу \~english The initiator transmits immediately \~ */
			IK   = 0x0E, /*!< \~russian Отвечающий известен, инициатор передаёт сразу \~english The responder is known, the initiator transmits immediately \~ */
			IX   = 0x0F, /*!< \~russian Инициатор передаёт сразу, отвечающий передаёт \~english The initiator transmits immediately, the responder transmits \~ */
			NK1  = 0x10, /*!< \~russian Отложенный \~english Deferred \~ */
			NX1  = 0x11, /*!< \~russian Отложенный \~english Deferred \~ */
			X1N  = 0x12, /*!< \~russian Отложенный \~english Deferred \~ */
			X1K  = 0x13, /*!< \~russian Отложенный \~english Deferred \~ */
			XK1  = 0x14, /*!< \~russian Отложенный \~english Deferred \~ */
			X1K1 = 0x15, /*!< \~russian Отложенный \~english Deferred \~ */
			X1X  = 0x16, /*!< \~russian Отложенный \~english Deferred \~ */
			XX1  = 0x17, /*!< \~russian Отложенный \~english Deferred \~ */
			X1X1 = 0x18, /*!< \~russian Отложенный \~english Deferred \~ */
			K1N  = 0x19, /*!< \~russian Отложенный \~english Deferred \~ */
			K1K  = 0x1A, /*!< \~russian Отложенный \~english Deferred \~ */
			KK1  = 0x1B, /*!< \~russian Отложенный \~english Deferred \~ */
			K1K1 = 0x1C, /*!< \~russian Отложенный \~english Deferred \~ */
			K1X  = 0x1D, /*!< \~russian Отложенный \~english Deferred \~ */
			KX1  = 0x1E, /*!< \~russian Отложенный \~english Deferred \~ */
			K1X1 = 0x1F, /*!< \~russian Отложенный \~english Deferred \~ */
			I1N  = 0x20, /*!< \~russian Отложенный \~english Deferred \~ */
			I1K  = 0x21, /*!< \~russian Отложенный \~english Deferred \~ */
			IK1  = 0x22, /*!< \~russian Отложенный \~english Deferred \~ */
			I1K1 = 0x23, /*!< \~russian Отложенный \~english Deferred \~ */
			I1X  = 0x24, /*!< \~russian Отложенный \~english Deferred \~ */
			IX1  = 0x25, /*!< \~russian Отложенный \~english Deferred \~ */
			I1X1 = 0x26, /*!< \~russian Отложенный \~english Deferred \~ */
			PQN  = 0x40, /*!< \~russian PQNoise односторонний \~english PQNoise one-way \~ */
			PQNN = 0x41, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQNK = 0x42, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQNX = 0x43, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQKN = 0x44, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQKK = 0x45, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQKX = 0x46, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQXN = 0x47, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQXK = 0x48, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQXX = 0x49, /*!< \~russian PQNoise, оба знака KEM в обоих направлениях \~english PQNoise, both KEM tokens in both directions \~ */
			PQIN = 0x4A, /*!< \~russian PQNoise \~english PQNoise \~ */
			PQIK = 0x4B, /*!< \~russian PQNoise, отвечающий известен \~english PQNoise, the responder is known \~ */
			PQIX = 0x4C  /*!< \~russian PQNoise \~english PQNoise \~ */
		};
		/**
		 * \~russian
		 * @brief Знаки узора рукопожатия
		 *
		 * \~english
		 * @brief Tokens of a handshake pattern
		 *
		 * \~
		 */
		enum class token_t : uint8_t {
			NONE = 0x00, /*!< \~russian Пусто \~english Empty \~ */
			E    = 0x01, /*!< \~russian Временный открытый ключ \~english Ephemeral public key \~ */
			S    = 0x02, /*!< \~russian Постоянный открытый ключ \~english Static public key \~ */
			EE   = 0x03, /*!< \~russian DH временных ключей \~english DH of the ephemeral keys \~ */
			ES   = 0x04, /*!< \~russian DH временного ключа инициатора и постоянного отвечающего \~english DH of the initiator ephemeral and the responder static \~ */
			SE   = 0x05, /*!< \~russian DH постоянного ключа инициатора и временного отвечающего \~english DH of the initiator static and the responder ephemeral \~ */
			SS   = 0x06, /*!< \~russian DH постоянных ключей \~english DH of the static keys \~ */
			PSK  = 0x07, /*!< \~russian Заранее разделённый ключ \~english Pre-shared key \~ */
			EKEM = 0x08, /*!< \~russian Шифртекст к временному ключу получателя: в открытом виде, MixHash, MixKey \~english Ciphertext to the receiver ephemeral key: in clear, MixHash, MixKey \~ */
			SKEM = 0x09  /*!< \~russian Шифртекст к постоянному ключу получателя: EncryptAndHash, MixKey \~english Ciphertext to the receiver static key: EncryptAndHash, MixKey \~ */
		};
		/**
		 * \~russian
		 * @brief Положения заранее разделённых ключей: разряд i отвечает видоизменению pski
		 *
		 * \~english
		 * @brief Positions of pre-shared keys: bit i corresponds to the pski modifier
		 *
		 * \~
		 */
		typedef uint8_t psk_t;
		/**
		 * \~russian
		 * @brief Набор примитивов протокола
		 *
		 * \~english
		 * @brief Suite of the protocol primitives
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Suite {
			// Функция обмена ключами
			dh_t dh;
			// Функция шифрования с подлинностью
			aead_t aead;
			// Функция хеширования
			digest::hash_t hash;
			// Механизм упаковки ключа (PQNoise); у классики NONE
			kem_t kem;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Suite() noexcept : dh(dh_t::NONE), aead(aead_t::NONE), hash(digest::hash_t::NONE), kem(kem_t::NONE) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param dh   функция обмена ключами
			 * @param aead функция шифрования с подлинностью
			 * @param hash функция хеширования
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * @param dh   key exchange function
			 * @param aead authenticated encryption function
			 * @param hash hash function
			 *
			 * \~
			 */
			Suite(const dh_t dh, const aead_t aead, const digest::hash_t hash) noexcept : dh(dh), aead(aead), hash(hash), kem(kem_t::NONE) {}
			/**
			 * \~russian
			 * @brief Конструктор набора PQNoise
			 *
			 * @param kem  механизм упаковки ключа
			 * @param aead функция шифрования с подлинностью
			 * @param hash функция хеширования
			 *
			 * \~english
			 * @brief Constructor of a PQNoise suite
			 *
			 * @param kem  key encapsulation mechanism
			 * @param aead authenticated encryption function
			 * @param hash hash function
			 *
			 * \~
			 */
			Suite(const kem_t kem, const aead_t aead, const digest::hash_t hash) noexcept : dh(dh_t::NONE), aead(aead), hash(hash), kem(kem) {}
		} suite_t;
		/**
		 * \~russian
		 * @brief Метод проверки годности набора: X25519 и один из хешей SHA256, SHA512, BLAKE2s, BLAKE2b
		 *
		 * @param suite набор примитивов
		 *
		 * @return      признак годности
		 *
		 * \~english
		 * @brief Method of the suite validity check: X25519 and one of SHA256, SHA512, BLAKE2s, BLAKE2b
		 *
		 * @param suite suite of primitives
		 *
		 * @return      sign of validity
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool valid(const suite_t & suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления имени протокола вида «Noise_XXpsk3_25519_ChaChaPoly_SHA256»
		 *
		 * @param pattern узор рукопожатия
		 * @param psks    положения заранее разделённых ключей
		 * @param suite   набор примитивов
		 * @param result  место имени, не короче NAME_LIMIT
		 * @param size    на входе вместимость места, на выходе длина имени без завершающего нуля
		 *
		 * @return        признак того, что имя составлено
		 *
		 * \~english
		 * @brief Method of the protocol name composition like «Noise_XXpsk3_25519_ChaChaPoly_SHA256»
		 *
		 * @param pattern handshake pattern
		 * @param psks    positions of pre-shared keys
		 * @param suite   suite of primitives
		 * @param result  place of the name, not shorter than NAME_LIMIT
		 * @param size    the capacity of the place on input, the name length without the trailing zero on output
		 *
		 * @return        sign that the name is composed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool name(const pattern_t pattern, const psk_t psks, const suite_t & suite, char * result, size_t & size) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора имени протокола
		 *
		 * @details При отказе заполнено то, что разобрано: у наборов с кривой 448 узор и хеш
		 *          распознаны, а dh остаётся NONE
		 *
		 * @param text    имя протокола
		 * @param pattern узор рукопожатия
		 * @param psks    положения заранее разделённых ключей
		 * @param suite   набор примитивов
		 *
		 * @return        признак того, что имя разобрано целиком и набор поддержан
		 *
		 * \~english
		 * @brief Method of the protocol name parsing
		 *
		 * @details On refusal what has been parsed is filled: for suites with curve 448 the
		 *          pattern and the hash are recognized while dh stays NONE
		 *
		 * @param text    protocol name
		 * @param pattern handshake pattern
		 * @param psks    positions of pre-shared keys
		 * @param suite   suite of primitives
		 *
		 * @return        sign that the name is parsed wholly and the suite is supported
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool parse(const view_t & text, pattern_t & pattern, psk_t & psks, suite_t & suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения числа сообщений узора
		 *
		 * @param pattern узор рукопожатия
		 *
		 * @return        число сообщений либо нуль у незнакомого узора
		 *
		 * \~english
		 * @brief Method of getting the number of messages of a pattern
		 *
		 * @param pattern handshake pattern
		 *
		 * @return        number of messages or zero for an unknown pattern
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t messages(const pattern_t pattern) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения знаков сообщения узора
		 *
		 * @param pattern узор рукопожатия
		 * @param index   номер сообщения от нуля
		 * @param result  указатель на знаки
		 * @param count   число знаков
		 *
		 * @return        признак того, что сообщение есть
		 *
		 * \~english
		 * @brief Method of getting the tokens of a pattern message
		 *
		 * @param pattern handshake pattern
		 * @param index   message number from zero
		 * @param result  pointer to the tokens
		 * @param count   number of tokens
		 *
		 * @return        sign that the message exists
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool tokens(const pattern_t pattern, const size_t index, const token_t *& result, size_t & count) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения знаков предсообщения узора
		 *
		 * @param pattern   узор рукопожатия
		 * @param initiator признак предсообщения инициатора (иначе - отвечающего)
		 * @param result    указатель на знаки
		 * @param count     число знаков
		 *
		 * @return          признак того, что узор знаком
		 *
		 * \~english
		 * @brief Method of getting the tokens of a pattern pre-message
		 *
		 * @param pattern   handshake pattern
		 * @param initiator sign of the initiator pre-message (otherwise of the responder)
		 * @param result    pointer to the tokens
		 * @param count     number of tokens
		 *
		 * @return          sign that the pattern is known
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool premessage(const pattern_t pattern, const bool initiator, const token_t *& result, size_t & count) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения имени узора
		 *
		 * @param pattern узор рукопожатия
		 *
		 * @return        имя узора либо пустая строка
		 *
		 * \~english
		 * @brief Method of getting the pattern name
		 *
		 * @param pattern handshake pattern
		 *
		 * @return        pattern name or an empty string
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * title(const pattern_t pattern) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления DH
		 *
		 * @param dh     функция обмена ключами
		 * @param secret свой закрытый ключ в KEY байтов
		 * @param point  чужой открытый ключ в KEY байтов
		 * @param result место общего секрета в KEY байтов
		 *
		 * @return       признак того, что секрет вычислен и не состоит из нулей
		 *
		 * \~english
		 * @brief Method of the DH computation
		 *
		 * @param dh     key exchange function
		 * @param secret own private key of KEY bytes
		 * @param point  peer public key of KEY bytes
		 * @param result place of the shared secret of KEY bytes
		 *
		 * @return       sign that the secret is computed and is not all zeros
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool agree(const dh_t dh, const view_t & secret, const view_t & point, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод вывода открытого ключа из закрытого
		 *
		 * @param dh     функция обмена ключами
		 * @param secret закрытый ключ в KEY байтов
		 * @param result место открытого ключа в KEY байтов
		 *
		 * @return       признак того, что ключ выведен
		 *
		 * \~english
		 * @brief Method of the public key derivation from the private one
		 *
		 * @param dh     key exchange function
		 * @param secret private key of KEY bytes
		 * @param result place of the public key of KEY bytes
		 *
		 * @return       sign that the key is derived
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool derive(const dh_t dh, const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки пары ключей из энтропии
		 *
		 * @param dh     функция обмена ключами
		 * @param secret место закрытого ключа в KEY байтов
		 * @param result место открытого ключа в KEY байтов
		 *
		 * @return       признак того, что пара выработана
		 *
		 * \~english
		 * @brief Method of the key pair generation from entropy
		 *
		 * @param dh     key exchange function
		 * @param secret place of the private key of KEY bytes
		 * @param result place of the public key of KEY bytes
		 *
		 * @return       sign that the pair is generated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool generate(const dh_t dh, uint8_t * secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки, что узор относится к PQNoise
		 *
		 * @param pattern узор рукопожатия
		 *
		 * @return        признак PQNoise
		 *
		 * \~english
		 * @brief Method of checking that a pattern belongs to PQNoise
		 *
		 * @param pattern handshake pattern
		 *
		 * @return        sign of PQNoise
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool postquantum(const pattern_t pattern) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины части KEM
		 *
		 * @param kem  механизм упаковки ключа
		 * @param part часть
		 *
		 * @return     длина в байтах либо нуль у незнакомого механизма
		 *
		 * \~english
		 * @brief Method of getting the length of a KEM part
		 *
		 * @param kem  key encapsulation mechanism
		 * @param part part
		 *
		 * @return     length in bytes or zero for an unknown mechanism
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t kemlength(const kem_t kem, const part_t part) noexcept;
		/**
		 * \~russian
		 * @brief Метод порождения пары ключей KEM из зерна - детерминированный, для корпусов и потребителя, хранящего зерно
		 *
		 * @warning Повтор зерна даёт ту же пару; обычный путь - kemgenerate из энтропии
		 *
		 * @param kem    механизм упаковки ключа
		 * @param seed   зерно длиной SEED: у ML-KEM-768 d ‖ z (64), у составного ещё закрытый X25519 (96)
		 * @param key    место открытого ключа длиной PUBLIC
		 * @param secret место закрытого ключа длиной SECRET
		 *
		 * @return       признак того, что пара порождена
		 *
		 * \~english
		 * @brief Method of KEM key pair generation from a seed
		 *
		 * @param kem    key encapsulation mechanism
		 * @param seed   seed of SEED length: d ‖ z (64) for ML-KEM-768, plus the X25519 secret (96) for the composite
		 * @param key    place of the public key of PUBLIC length
		 * @param secret place of the secret key of SECRET length
		 *
		 * @return       sign that the pair is generated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool kemgenerateDeterministic(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept;
		/**
		 * \~russian
		 * @brief Метод порождения пары ключей KEM из энтропии
		 *
		 * @param kem    механизм упаковки ключа
		 * @param key    место открытого ключа длиной PUBLIC
		 * @param secret место закрытого ключа длиной SECRET
		 *
		 * @return       признак того, что пара порождена
		 *
		 * \~english
		 * @brief Method of KEM key pair generation from entropy
		 *
		 * @param kem    key encapsulation mechanism
		 * @param key    place of the public key of PUBLIC length
		 * @param secret place of the secret key of SECRET length
		 *
		 * @return       sign that the pair is generated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool kemgenerate(const kem_t kem, uint8_t * key, uint8_t * secret) noexcept;
		/**
		 * \~russian
		 * @brief Метод упаковки общего секрета на заданной случайности - детерминированный, для корпусов
		 *
		 * @warning Повтор случайности на тот же открытый ключ даёт тот же шифртекст и тот же секрет - полная потеря,
		 *          которая ничем не отказывает; обычный путь - encapsulate из энтропии
		 *
		 * @param kem        механизм упаковки ключа
		 * @param key        открытый ключ получателя длиной PUBLIC
		 * @param coins      случайность длиной COINS: у ML-KEM-768 m (32), у составного ещё закрытый временный X25519 (64)
		 * @param ciphertext место шифртекста длиной CIPHERTEXT
		 * @param shared     место общего секрета длиной SHARED
		 *
		 * @return           признак того, что секрет упакован
		 *
		 * \~english
		 * @brief Method of shared secret encapsulation to a public key on given randomness
		 *
		 * @param kem        key encapsulation mechanism
		 * @param key        receiver public key of PUBLIC length
		 * @param coins      randomness of COINS length: m (32) for ML-KEM-768, plus the ephemeral X25519 secret (64) for the composite
		 * @param ciphertext place of the ciphertext of CIPHERTEXT length
		 * @param shared     place of the shared secret of SHARED length
		 *
		 * @return           sign that the secret is encapsulated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encapsulateDeterministic(const kem_t kem, const view_t & key, const view_t & coins, uint8_t * ciphertext, uint8_t * shared) noexcept;
		/**
		 * \~russian
		 * @brief Метод упаковки общего секрета к открытому ключу на энтропии
		 *
		 * @param kem        механизм упаковки ключа
		 * @param key        открытый ключ получателя длиной PUBLIC
		 * @param ciphertext место шифртекста длиной CIPHERTEXT
		 * @param shared     место общего секрета длиной SHARED
		 *
		 * @return           признак того, что секрет упакован
		 *
		 * \~english
		 * @brief Method of shared secret encapsulation to a public key on entropy
		 *
		 * @param kem        key encapsulation mechanism
		 * @param key        receiver public key of PUBLIC length
		 * @param ciphertext place of the ciphertext of CIPHERTEXT length
		 * @param shared     place of the shared secret of SHARED length
		 *
		 * @return           sign that the secret is encapsulated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encapsulate(const kem_t kem, const view_t & key, uint8_t * ciphertext, uint8_t * shared) noexcept;
		/**
		 * \~russian
		 * @brief Метод распаковки общего секрета
		 *
		 * @param kem        механизм упаковки ключа
		 * @param secret     свой закрытый ключ длиной SECRET
		 * @param ciphertext шифртекст длиной CIPHERTEXT
		 * @param shared     место общего секрета длиной SHARED
		 *
		 * @return           признак того, что секрет распакован (у ML-KEM подделка даёт неявное отклонение, а не отказ)
		 *
		 * \~english
		 * @brief Method of shared secret decapsulation
		 *
		 * @param kem        key encapsulation mechanism
		 * @param secret     own secret key of SECRET length
		 * @param ciphertext ciphertext of CIPHERTEXT length
		 * @param shared     place of the shared secret of SHARED length
		 *
		 * @return           sign that the secret is decapsulated (for ML-KEM a forgery yields implicit rejection, not a refusal)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decapsulate(const kem_t kem, const view_t & secret, const view_t & ciphertext, uint8_t * shared) noexcept;
	};
};

#endif // __ANTS_NOISE__
