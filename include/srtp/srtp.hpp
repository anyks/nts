/**
 * @file srtp.hpp
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
 * \~russian
 * @brief Заголовочный файл модуля защиты транспорта реального времени —
 *        защищённые пакеты RTP и RTCP по RFC 3711,
 *        режим AES-GCM по RFC 7714
 *
 * \~english
 * @brief Header file of the secure real-time transport module —
 *        the protected RTP and RTCP packets according to RFC 3711,
 *        the AES-GCM mode according to RFC 7714
 *
 * \~
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
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 *
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модуля защиты транспорта реального времени
	 *
	 * @details Модуль защищает пакеты RTP и RTCP по RFC 3711: шифрование
	 *          AES в режиме счётчика (AES-CM), имитовставка HMAC-SHA1 с
	 *          усечением до 80 либо 32 разрядов, вывод сессионных ключей из
	 *          мастер-ключа и мастер-соли по разделу 4.3, защита от повторов
	 *          скользящим окном. По RFC 7714 поддерживаются профили AES-GCM
	 *          (AEAD_AES_128_GCM и AEAD_AES_256_GCM). Транспортом (UDP, DTLS)
	 *          модуль не занимается: пакет приходит просмотром и уходит
	 *          набором байтов. Раскладка ключевого материала экспорта связи
	 *          DTLS (метка EXTRACTOR-dtls_srtp) выполняется вызовом pair по
	 *          разделу 4.2 RFC 5764.
	 *
	 * \~english
	 * @brief Namespace of the secure real-time transport module
	 * @details The module protects RTP and RTCP packets according to RFC 3711:
	 *          the AES cipher in counter mode (AES-CM), the HMAC-SHA1 message
	 *          authentication truncated to 80 or 32 bits, the session key
	 *          derivation from the master key and the master salt according to
	 *          the section 4.3, the replay protection by a sliding window. The
	 *          AES-GCM profiles (AEAD_AES_128_GCM and AEAD_AES_256_GCM) are
	 *          supported according to RFC 7714. The module does not deal with
	 *          the transport (UDP, DTLS): the packet comes as a view and leaves
	 *          as a byte array. The layout of the DTLS connection export key
	 *          material (the EXTRACTOR-dtls_srtp label) is performed by the
	 *          pair call according to the section 4.2 of RFC 5764.
	 *
	 * \~
	 *
	 */
	namespace srtp {
		/**
		 * \~russian
		 * @brief Причина отказа работы модуля
		 *
		 * \~english
		 * @brief Reason of a failure of the module work
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY     = 0x01, /*!< \~russian Пакет либо ключ не установлены \~english The packet or the key is not set \~ */
			STRUCTURE = 0x02, /*!< \~russian Пакет не отвечает устройству своего вида \~english The packet does not meet the structure of its kind \~ */
			ALGORITHM = 0x03, /*!< \~russian Профиль защиты неизвестен \~english The protection profile is unknown \~ */
			SIGNATURE = 0x04, /*!< \~russian Имитовставка не сошлась \~english The authentication tag has not converged \~ */
			KEY       = 0x05, /*!< \~russian Ключ либо соль неверной длины \~english The key or the salt is of a wrong length \~ */
			REPLAY    = 0x06, /*!< \~russian Пакет повторён либо старше окна приёма \~english The packet is replayed or older than the receive window \~ */
			MEMORY    = 0x07  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Профиль защиты по разделу 4.1.2 RFC 5764
		 *
		 * \~english
		 * @brief Protection profile according to the section 4.1.2 of RFC 5764
		 *
		 * \~
		 *
		 */
		enum class profile_t : uint16_t {
			AES128_CM_SHA1_80 = 0x0001, /*!< \~russian AES-CM со имитовставкой HMAC-SHA1-80 по RFC 3711 \~english AES-CM with the HMAC-SHA1-80 authentication tag according to RFC 3711 \~ */
			AES128_CM_SHA1_32 = 0x0002, /*!< \~russian AES-CM со имитовставкой HMAC-SHA1-32 по RFC 3711 \~english AES-CM with the HMAC-SHA1-32 authentication tag according to RFC 3711 \~ */
			AEAD_AES_128_GCM  = 0x0007, /*!< \~russian AES-128-GCM по RFC 7714 \~english AES-128-GCM according to RFC 7714 \~ */
			AEAD_AES_256_GCM  = 0x0008  /*!< \~russian AES-256-GCM по RFC 7714 \~english AES-256-GCM according to RFC 7714 \~ */
		};

		/**
		 * \~russian
		 * @brief Сессионные ключи одного направления
		 *
		 * @details Ключи выводятся вызовом keys из мастер-ключа и мастер-соли
		 *          по разделу 4.3 RFC 3711 (частота вывода нулевая: вывод
		 *          начальный, один раз на мастер-ключ). Длины полей зависят
		 *          от профиля: у профилей AES-CM ключ 16 байтов, соль 14,
		 *          ключ имитовставки 20; у профилей AES-GCM ключ 16 либо 32
		 *          байта, соль 12, ключ имитовставки пуст.
		 *
		 * \~english
		 * @brief Session keys of one direction
		 * @details The keys are derived by the keys call from the master key
		 *          and the master salt according to the section 4.3 of
		 *          RFC 3711 (the derivation rate is zero: the derivation is
		 *          initial, once per master key). The field lengths depend on
		 *          the profile: the AES-CM profiles take a 16-byte key, a
		 *          14-byte salt and a 20-byte authentication key; the AES-GCM
		 *          profiles take a 16- or 32-byte key and a 12-byte salt, the
		 *          authentication key is empty.
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Keys {
			// Сессионный ключ шифрования
			vector <uint8_t> cipher;
			// Сессионный ключ имитовставки (пуст у профилей AES-GCM)
			vector <uint8_t> auth;
			// Сессионная соль
			vector <uint8_t> salt;
		} keys_t;

		/**
		 * \~russian
		 * @brief Метод получения длин ключевого материала профиля
		 *
		 * @param profile профиль защиты
		 * @param key     место, в которое записывается длина ключа шифрования в байтах
		 * @param salt    место, в которое записывается длина соли в байтах
		 *
		 * @return        отказ неизвестного профиля
		 *
		 * \~english
		 * @brief Method of getting the key material lengths of the profile
		 * @param profile the protection profile
		 * @param key     the place the encryption key length in bytes is written into
		 * @param salt    the place the salt length in bytes is written into
		 * @return        the failure of an unknown profile
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t lengths(const profile_t profile, size_t & key, size_t & salt) noexcept;

		/**
		 * \~russian
		 * @brief Метод вывода сессионных ключей из мастер-ключа и мастер-соли
		 *
		 * @param profile профиль защиты
		 * @param key     мастер-ключ (16 байтов у AES-CM и AES-128-GCM, 32 у AES-256-GCM)
		 * @param salt    мастер-соль (14 байтов у AES-CM, 12 у AES-GCM)
		 * @param result  место, в которое помещаются сессионные ключи
		 *
		 * @return        отказ вывода
		 *
		 * @details Вывод по разделу 4.3 RFC 3711: PRF на AES-CM с мастер-ключом,
		 *          вход x = (метка ‖ index DIV kdr) XOR мастер-соль, дополненный
		 *          двумя нулевыми байтами; частота вывода нулевая. Метки 0x00,
		 *          0x01 и 0x02 дают ключ шифрования, ключ имитовставки и соль
		 *          RTP; у профилей AES-GCM ключ имитовставки не выводится.
		 *
		 * \~english
		 * @brief Method of deriving the session keys from the master key and the master salt
		 * @param profile the protection profile
		 * @param key     the master key (16 bytes at AES-CM and AES-128-GCM, 32 at AES-256-GCM)
		 * @param salt    the master salt (14 bytes at AES-CM, 12 at AES-GCM)
		 * @param result  the place the session keys are put into
		 * @return        the derivation failure
		 * @details The derivation according to the section 4.3 of RFC 3711: the
		 *          PRF on AES-CM with the master key, the input x = (label ‖
		 *          index DIV kdr) XOR master salt, padded with two zero bytes;
		 *          the derivation rate is zero. The labels 0x00, 0x01 and 0x02
		 *          give the encryption key, the authentication key and the RTP
		 *          salt; the AES-GCM profiles derive no authentication key.
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t keys(const profile_t profile, const view_t & key, const view_t & salt, keys_t & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод раскладки ключевого материала экспорта связи DTLS
		 *
		 * @param profile  профиль защиты
		 * @param material ключевой материал экспорта (метка EXTRACTOR-dtls_srtp, 2 × (ключ + соль) байтов)
		 * @param client   место, в которое помещаются мастер-ключ и мастер-соль клиента
		 * @param server   место, в которое помещаются мастер-ключ и мастер-соль сервера
		 *
		 * @return         отказ раскладки
		 *
		 * @details Раскладка по разделу 4.2 RFC 5764: ключ клиента ‖ ключ
		 *          сервера ‖ соль клиента ‖ соль сервера. Поля cipher и salt
		 *          структур несут мастер-ключ и мастер-соль; поле auth пусто.
		 *
		 * \~english
		 * @brief Method of laying out the DTLS connection export key material
		 * @param profile  the protection profile
		 * @param material the export key material (the EXTRACTOR-dtls_srtp label, 2 × (key + salt) bytes)
		 * @param client   the place the client master key and master salt are put into
		 * @param server   the place the server master key and master salt are put into
		 * @return         the layout failure
		 * @details The layout according to the section 4.2 of RFC 5764: the
		 *          client key ‖ the server key ‖ the client salt ‖ the server
		 *          salt. The cipher and salt fields of the structures carry
		 *          the master key and the master salt; the auth field is empty.
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t pair(const profile_t profile, const view_t & material, keys_t & client, keys_t & server) noexcept;

		/**
		 * \~russian
		 * @brief Полусессия защиты одного направления потока
		 *
		 * @details Объект защищает пакеты RTP одного источника (SSRC) в одну
		 *          сторону: у отправителя protect ставит шифр и имитовставку,
		 *          у получателя unprotect проверяет имитовставку постоянной
		 *          сверкой, отсекает повторы окном в 64 индекса и снимает шифр.
		 *          Пакеты RTCP того же направления защищаются вызовами
		 *          protectControl и unprotectControl с отдельным счётчиком
		 *          SRTCP. Объект не потокобезопасен: направление ведётся
		 *          одним исполнением.
		 *
		 * \~english
		 * @brief Half-session of one stream direction protection
		 * @details The object protects the RTP packets of one source (SSRC) in
		 *          one direction: at the sender protect applies the cipher and
		 *          the authentication tag, at the receiver unprotect checks
		 *          the tag by a constant-time comparison, drops the replays
		 *          by a 64-index window and removes the cipher. The RTCP
		 *          packets of the same direction are protected by the
		 *          protectControl and unprotectControl calls with a separate
		 *          SRTCP counter. The object is not thread-safe: the direction
		 *          is driven by a single execution.
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Session {
			private:
				// Признак установки ключей
				bool _ready;
			private:
				// Профиль защиты
				profile_t _profile;
			private:
				// Сессионный ключ шифрования
				vector <uint8_t> _cipher;
				// Сессионный ключ имитовставки
				vector <uint8_t> _auth;
				// Сессионная соль
				vector <uint8_t> _salt;
			private:
				// Старший порядковый номер принятого пакета
				uint16_t _sl;
				// Счётчик переполнений порядкового номера (ROC)
				uint32_t _roc;
				// Признак принятого первого пакета
				bool _started;
				// Битовая карта окна приёма против повторов
				uint64_t _window;
				// Старший индекс окна приёма
				uint64_t _top;
			private:
				// Счётчик отправленных пакетов SRTCP
				uint32_t _srtcp;
				// Старший принятый индекс SRTCP
				uint32_t _srtcpTop;
				// Битовая карта окна приёма SRTCP
				uint64_t _srtcpWindow;
				// Признак принятого первого пакета SRTCP
				bool _srtcpStarted;
			public:
				/**
				 * \~russian
				 * @brief Метод установки сессионных ключей направления
				 *
				 * @param profile профиль защиты
				 * @param keys    сессионные ключи вызова keys
				 *
				 * @return        отказ установки
				 *
				 * \~english
				 * @brief Method of setting the session keys of the direction
				 * @param profile the protection profile
				 * @param keys    the session keys of the keys call
				 * @return        the setting failure
				 *
				 * \~
				 *
				 */
				bool start(const profile_t profile, const keys_t & keys) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния направления
				 *
				 *
				 * \~english
				 * @brief Method of resetting the direction state
				 *
				 * \~
				 *
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод защиты пакета RTP отправителем
				 *
				 * @param packet пакет RTP целиком (заголовок и полезная нагрузка)
				 * @param result место, в которое помещается защищённый пакет
				 *
				 * @return       отказ защиты
				 *
				 * @details Порядковый номер и SSRC берутся из заголовка пакета;
				 *          счётчик ROC наращивается при переполнении номера.
				 *          Полезная нагрузка шифруется, имитовставка ставится над
				 *          пакетом и счётчиком ROC (у профилей AES-GCM — метка
				 *          AEAD над заголовком).
				 *
				 * \~english
				 * @brief Method of protecting an RTP packet at the sender
				 * @param packet the whole RTP packet (the header and the payload)
				 * @param result the place the protected packet is put into
				 * @return       the protection failure
				 * @details The sequence number and the SSRC are taken from the
				 *          packet header; the ROC counter is incremented at the
				 *          number wrap. The payload is encrypted, the
				 *          authentication tag is applied over the packet and
				 *          the ROC counter (at the AES-GCM profiles — the AEAD
				 *          tag over the header).
				 *
				 * \~
				 *
				 */
				error_t protect(const view_t & packet, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты пакета RTP получателем
				 *
				 * @param packet защищённый пакет RTP целиком
				 * @param result место, в которое помещается открытый пакет
				 *
				 * @return       отказ снятия защиты
				 *
				 * @details Имитовставка проверяется постоянной сверкой до
				 *          расшифрования; повтор пакета отсекается окном приёма;
				 *          счётчик ROC оценивается по разделу 3.3.1 RFC 3711.
				 *
				 * \~english
				 * @brief Method of unprotecting an RTP packet at the receiver
				 * @param packet the whole protected RTP packet
				 * @param result the place the plain packet is put into
				 * @return       the unprotection failure
				 * @details The authentication tag is checked by a constant-time
				 *          comparison before the decryption; a replayed packet
				 *          is dropped by the receive window; the ROC counter is
				 *          estimated according to the section 3.3.1 of RFC 3711.
				 *
				 * \~
				 *
				 */
				error_t unprotect(const view_t & packet, vector <uint8_t> & result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод защиты пакета RTCP отправителем
				 *
				 * @param packet пакет RTCP целиком
				 * @param result место, в которое помещается защищённый пакет SRTCP
				 *
				 * @return       отказ защиты
				 *
				 * @details Полезная нагрузка с девятого байта шифруется, за
				 *          пакетом ставятся слово ESRTCP (флаг шифрования и
				 *          индекс SRTCP) и имитовставка над пакетом со словом
				 *          (у профилей AES-GCM слово входит в AAD, метка AEAD
				 *          ставится перед словом).
				 *
				 * \~english
				 * @brief Method of protecting an RTCP packet at the sender
				 * @param packet the whole RTCP packet
				 * @param result the place the protected SRTCP packet is put into
				 * @return       the protection failure
				 * @details The payload from the ninth byte is encrypted, the
				 *          ESRTCP word (the encryption flag and the SRTCP index)
				 *          and the authentication tag over the packet with the
				 *          word are appended (at the AES-GCM profiles the word
				 *          enters the AAD, the AEAD tag is placed before the
				 *          word).
				 *
				 * \~
				 *
				 */
				error_t protectControl(const view_t & packet, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты пакета SRTCP получателем
				 *
				 * @param packet защищённый пакет SRTCP целиком
				 * @param result место, в которое помещается открытый пакет RTCP
				 *
				 * @return       отказ снятия защиты
				 *
				 * \~english
				 * @brief Method of unprotecting an SRTCP packet at the receiver
				 * @param packet the whole protected SRTCP packet
				 * @param result the place the plain RTCP packet is put into
				 * @return       the unprotection failure
				 *
				 * \~
				 *
				 */
				error_t unprotectControl(const view_t & packet, vector <uint8_t> & result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 *
				 */
				Session() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 *
				 */
				~Session() noexcept;
		} session_t;
	} // namespace srtp
} // namespace nts

