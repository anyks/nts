/**
 * @file handshake.hpp
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
 * @brief Модуль состояния рукопожатия Noise (HandshakeState, §5.3)
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
#include <noise/symmetric.hpp>

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
		 * @brief Роли сторон рукопожатия
		 *
		 * \~english
		 * @brief Roles of the handshake sides
		 *
		 * \~
		 */
		enum class role_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Не установлена \~english Not set \~ */
			INITIATOR = 0x01, /*!< \~russian Инициатор \~english Initiator \~ */
			RESPONDER = 0x02  /*!< \~russian Отвечающий \~english Responder \~ */
		};
		/**
		 * \~russian
		 * @brief Ход рукопожатия
		 *
		 * \~english
		 * @brief Turn of the handshake
		 *
		 * \~
		 */
		enum class step_t : uint8_t {
			NONE  = 0x00, /*!< \~russian Не заведено либо неисправно \~english Not started or broken \~ */
			WRITE = 0x01, /*!< \~russian Наш ход: писать сообщение \~english Our turn: write a message \~ */
			READ  = 0x02, /*!< \~russian Чужой ход: читать сообщение \~english Peer turn: read a message \~ */
			DONE  = 0x03  /*!< \~russian Рукопожатие завершено, дальше раскол \~english The handshake is complete, split follows \~ */
		};
		/**
		 * \~russian
		 * @brief Класс состояния рукопожатия
		 *
		 * @details Намеренные решения:
		 *          1. Все ключи и заранее разделённые ключи задаются строго до первого сообщения;
		 *             после него любая установка - отказ. Полнота ключей по узору проверяется
		 *             при первом сообщении, а не посреди рукопожатия.
		 *          2. Принятый постоянный ключ собеседника сличается с заданным заранее; при
		 *             расхождении - отказ, не подмена.
		 *          3. После любого отказа чтения состояние неисправно: ход NONE, дальше только
		 *             clear и новое start.
		 *          4. Временный ключ вырабатывается из энтропии при первом знаке «e», если не
		 *             задан явно; явное задание нужно векторам и только им.
		 *          5. Сообщения ходят по буферам вызывающего, выделений памяти на пути нет.
		 *
		 * \~english
		 * @brief Class of the handshake state
		 *
		 * @details Deliberate decisions:
		 *          1. All keys and pre-shared keys are set strictly before the first message;
		 *             afterwards any setting is a refusal. Completeness of keys per pattern is
		 *             checked at the first message, not in the middle of the handshake.
		 *          2. The received static key of the peer is compared with the preset one; on
		 *             a mismatch - a refusal, not a substitution.
		 *          3. After any read refusal the state is broken: the turn is NONE, then only
		 *             clear and a new start.
		 *          4. The ephemeral key is generated from entropy at the first «e» token unless
		 *             set explicitly; explicit setting is needed by vectors and by them only.
		 *          5. Messages go through the caller buffers, there is no allocation on the path.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Handshake {
			private:
				// Узор рукопожатия
				pattern_t _pattern;
				// Положения заранее разделённых ключей
				psk_t _psks;
				// Роль стороны
				role_t _role;
				// Набор примитивов
				suite_t _suite;
				// Номер очередного сообщения
				size_t _index;
				// Число сообщений узора
				size_t _count;
				// Признак поглощённых предсообщений
				bool _started;
				// Признак того, что раскол выполнен: повтор дал бы вторую пару шифров с теми же ключами и нулевыми счётчиками
				bool _split;
				// Признак неисправности
				bool _broken;
				// Признаки наличия ключей: свой постоянный, свой временный, чужой постоянный, чужой временный
				bool _hasS, _hasE, _hasRS, _hasRE;
				// Число заданных заранее разделённых ключей и число уже употреблённых
				size_t _pskCount, _pskUsed;
				// Число заданных случайностей упаковки и число уже употреблённых (PQNoise, только для корпусов)
				size_t _coinCount, _coinUsed;
				// Длины открытого и закрытого ключа и зерна по набору
				size_t _public, _secret, _seed;
				// Свой постоянный ключ: закрытый и открытый (классика заполняет первые KEY байтов)
				uint8_t _s[KEM_SECRET_MAX], _sPublic[KEM_PUBLIC_MAX];
				// Свой временный ключ: закрытый и открытый
				uint8_t _e[KEM_SECRET_MAX], _ePublic[KEM_PUBLIC_MAX];
				// Чужой постоянный и временный открытые ключи
				uint8_t _rs[KEM_PUBLIC_MAX], _re[KEM_PUBLIC_MAX];
				// Заранее разделённые ключи
				uint8_t _psk[PSKS_MAX][PSK];
				// Случайности упаковки по порядку своих знаков ekem/skem
				uint8_t _coin[PSKS_MAX][KEM_SHARED_MAX];
				// Симметричное состояние
				symmetric_t _symmetric;
			private:
				/**
				 * @brief Метод поглощения предсообщений и проверки полноты ключей
				 *
				 * @return признак готовности к первому сообщению
				 *
				 */
				bool ready() noexcept;
				/**
				 * @brief Метод примешивания DH по знаку с учётом роли
				 *
				 * @param token знак: EE, ES, SE либо SS
				 *
				 * @return      признак того, что секрет примешан
				 *
				 */
				bool mix(const token_t token) noexcept;
				/**
				 * @brief Метод упаковки по знаку KEM у отправителя
				 *
				 * @param token      знак: EKEM либо SKEM
				 * @param ciphertext место шифртекста
				 * @param shared     место общего секрета
				 *
				 * @return           признак того, что секрет упакован
				 *
				 */
				bool wrap(const token_t token, uint8_t * ciphertext, uint8_t * shared) noexcept;
				/**
				 * @brief Метод распаковки по знаку KEM у получателя
				 *
				 * @param token      знак: EKEM либо SKEM
				 * @param ciphertext шифртекст
				 * @param shared     место общего секрета
				 *
				 * @return           признак того, что секрет распакован
				 *
				 */
				bool unwrap(const token_t token, const uint8_t * ciphertext, uint8_t * shared) noexcept;
				/**
				 * @brief Метод проверки, что в узоре есть заранее разделённые ключи
				 *
				 * @return признак наличия
				 *
				 */
				bool preshared() const noexcept;
				/**
				 * @brief Метод примешивания очередного заранее разделённого ключа
				 *
				 * @return признак того, что ключ примешан
				 *
				 */
				bool psk() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения рукопожатия перечислениями
				 *
				 * @param pattern  узор рукопожатия
				 * @param psks     положения заранее разделённых ключей
				 * @param suite    набор примитивов
				 * @param role     роль стороны
				 * @param prologue пролог, вправе быть пустым
				 *
				 * @return         признак того, что рукопожатие заведено
				 *
				 * \~english
				 * @brief Method of starting a handshake by enumerations
				 *
				 * @param pattern  handshake pattern
				 * @param psks     positions of pre-shared keys
				 * @param suite    suite of primitives
				 * @param role     side role
				 * @param prologue prologue, may be empty
				 *
				 * @return         sign that the handshake is started
				 *
				 * \~
				 */
				bool start(const pattern_t pattern, const psk_t psks, const suite_t & suite, const role_t role, const view_t & prologue) noexcept;
				/**
				 * \~russian
				 * @brief Метод заведения рукопожатия именем протокола
				 *
				 * @param name     имя протокола вида «Noise_XX_25519_ChaChaPoly_SHA256»
				 * @param role     роль стороны
				 * @param prologue пролог, вправе быть пустым
				 *
				 * @return         признак того, что рукопожатие заведено
				 *
				 * \~english
				 * @brief Method of starting a handshake by the protocol name
				 *
				 * @param name     protocol name like «Noise_XX_25519_ChaChaPoly_SHA256»
				 * @param role     side role
				 * @param prologue prologue, may be empty
				 *
				 * @return         sign that the handshake is started
				 *
				 * \~
				 */
				bool start(const view_t & name, const role_t role, const view_t & prologue) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки своего постоянного ключа
				 *
				 * @param secret закрытый ключ в KEY байтов у классики либо зерно KEM у PQNoise (детерминированно), открытый выводится
				 *
				 * @return       признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of setting the own static key
				 *
				 * @param secret private key of KEY bytes for classic or the KEM seed for PQNoise (deterministic), the public one is derived
				 *
				 * @return       sign that the key is set
				 *
				 * \~
				 */
				bool statics(const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод явной установки своего временного ключа
				 *
				 * @param secret закрытый ключ в KEY байтов у классики либо зерно KEM у PQNoise, открытый выводится
				 *
				 * @return       признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of setting the own ephemeral key explicitly
				 *
				 * @param secret private key of KEY bytes for classic or the KEM seed for PQNoise, the public one is derived
				 *
				 * @return       sign that the key is set
				 *
				 * \~
				 */
				bool ephemeral(const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки постоянного открытого ключа собеседника
				 *
				 * @param key открытый ключ в KEY байтов у классики либо длиной открытого ключа KEM у PQNoise
				 *
				 * @return    признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of setting the peer static public key
				 *
				 * @param key public key of KEY bytes for classic or of the KEM public key length for PQNoise
				 *
				 * @return    sign that the key is set
				 *
				 * \~
				 */
				bool remote(const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки заранее разделённых ключей в порядке появления в узоре
				 *
				 * @param keys  ключи, каждый ровно PSK байтов
				 * @param count число ключей, не больше PSKS_MAX
				 *
				 * @return      признак того, что ключи установлены
				 *
				 * \~english
				 * @brief Method of setting pre-shared keys in the order of appearance in the pattern
				 *
				 * @param keys  keys, each exactly PSK bytes
				 * @param count number of keys, not more than PSKS_MAX
				 *
				 * @return      sign that the keys are set
				 *
				 * \~
				 */
				bool psks(const view_t * keys, const size_t count) noexcept;
				/**
				 * \~russian
				 * @brief Метод явной установки случайностей упаковки KEM по порядку своих знаков ekem/skem (PQNoise; только корпусам)
				 *
				 * @warning Повтор случайности на тот же открытый ключ - полная потеря без отказа; в работе упаковка идёт из энтропии
				 *
				 * @param coins случайности, каждая длиной COINS набора
				 * @param count число случайностей, не больше PSKS_MAX
				 *
				 * @return      признак того, что случайности установлены
				 *
				 * \~english
				 * @brief Method of setting KEM encapsulation randomness explicitly in the order of own ekem/skem tokens (PQNoise; corpora only)
				 *
				 * @warning Repeated randomness to the same public key is a total loss without a refusal; in operation encapsulation uses entropy
				 *
				 * @param coins randomness values, each of the suite COINS length
				 * @param count number of values, not more than PSKS_MAX
				 *
				 * @return      sign that the values are set
				 *
				 * \~
				 */
				bool coinsDeterministic(const view_t * coins, const size_t count) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины открытого ключа набора: KEY у классики, длина открытого ключа KEM у PQNoise
				 *
				 * @return длина либо нуль до заведения
				 *
				 * \~english
				 * @brief Method of getting the suite public key length: KEY for classic, the KEM public key length for PQNoise
				 *
				 * @return length or zero before start
				 *
				 * \~
				 */
				size_t keylength() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения хода
				 *
				 * @return ход рукопожатия
				 *
				 * \~english
				 * @brief Method of getting the turn
				 *
				 * @return handshake turn
				 *
				 * \~
				 */
				step_t step() const noexcept;
				/**
				 * \~russian
				 * @brief Метод записи сообщения (WriteMessage)
				 *
				 * @param payload полезная часть, вправе быть пустой
				 * @param result  место сообщения
				 * @param size    на входе вместимость места, на выходе длина сообщения
				 *
				 * @return        признак того, что сообщение записано
				 *
				 * \~english
				 * @brief Method of writing a message (WriteMessage)
				 *
				 * @param payload payload, may be empty
				 * @param result  place of the message
				 * @param size    the capacity of the place on input, the message length on output
				 *
				 * @return        sign that the message is written
				 *
				 * \~
				 */
				bool write(const view_t & payload, uint8_t * result, size_t & size) noexcept;
				/**
				 * \~russian
				 * @brief Метод чтения сообщения (ReadMessage)
				 *
				 * @param message сообщение
				 * @param result  место полезной части
				 * @param size    на входе вместимость места, на выходе длина полезной части
				 *
				 * @return        признак того, что сообщение подлинно и прочитано
				 *
				 * \~english
				 * @brief Method of reading a message (ReadMessage)
				 *
				 * @param message message
				 * @param result  place of the payload
				 * @param size    the capacity of the place on input, the payload length on output
				 *
				 * @return        sign that the message is authentic and read
				 *
				 * \~
				 */
				bool read(const view_t & message, uint8_t * result, size_t & size) noexcept;
				/**
				 * \~russian
				 * @brief Метод раскола на транспортные состояния (Split), после завершения рукопожатия
				 *
				 * @param one состояние от инициатора к отвечающему
				 * @param two состояние от отвечающего к инициатору; у односторонних узоров остаётся без ключа
				 *
				 * @return    признак того, что раскол выполнен
				 *
				 * \~english
				 * @brief Method of splitting into transport states (Split), after the handshake completion
				 *
				 * @param one state from the initiator to the responder
				 * @param two state from the responder to the initiator; for one-way patterns it stays without a key
				 *
				 * @return    sign that the split is done
				 *
				 * \~
				 */
				bool split(cipher_t & one, cipher_t & two) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения хеша рукопожатия для привязки канала
				 *
				 * @param result место хеша в длину хеша набора
				 *
				 * @return       признак того, что хеш выдан
				 *
				 * \~english
				 * @brief Method of getting the handshake hash for channel binding
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
				 * @brief Метод получения постоянного открытого ключа собеседника, заданного либо принятого
				 *
				 * @param result место ключа длиной keylength()
				 *
				 * @return       признак того, что ключ известен и выдан
				 *
				 * \~english
				 * @brief Method of getting the peer static public key, preset or received
				 *
				 * @param result place of the key of KEY bytes
				 *
				 * @return       sign that the key is known and given
				 *
				 * \~
				 */
				bool peer(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения своего постоянного открытого ключа
				 *
				 * @param result место ключа длиной keylength()
				 *
				 * @return       признак того, что ключ задан и выдан
				 *
				 * \~english
				 * @brief Method of getting the own static public key
				 *
				 * @param result place of the key of KEY bytes
				 *
				 * @return       sign that the key is set and given
				 *
				 * \~
				 */
				bool self(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины хеша набора
				 *
				 * @return длина хеша либо нуль до заведения
				 *
				 * \~english
				 * @brief Method of getting the suite hash length
				 *
				 * @return hash length or zero before start
				 *
				 * \~
				 */
				size_t length() const noexcept;
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
				Handshake() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Handshake() noexcept;
		} handshake_t;
	};
};

