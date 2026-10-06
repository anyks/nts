/**
 * @file jws.cpp
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
 * @brief Модуль подписей JWS — компактная запись подписи по RFC 7515,
 *        ключи JWK по RFC 7517 и отпечатки ключей по RFC 7638
 *
 * \~english
 * @brief The JWS signature module — the compact serialization of a signature
 *        according to RFC 7515, the JWK keys according to RFC 7517 and the key
 *        thumbprints according to RFC 7638
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочный файл модуля
 */
#include <jws/jws.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/hash.hpp>
#include <curve/parameters.hpp>
#include <sign/rsa.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <sys/wipe.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

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
	 * @brief Внутренние сущности модуля подписей JWS
	 *
	 * \~english
	 * @brief Internal entities of the JWS signature module
	 *
	 * \~
	 *
	 */
	namespace {
		/**
		 * \~russian
		 * @brief Опознаватель кривой P-256
		 *
		 * \~english
		 * @brief The identifier of the P-256 curve
		 *
		 * \~
		 */
		static const char * OID_P256 = "1.2.840.10045.3.1.7";
		/**
		 * \~russian
		 * @brief Опознаватель кривой P-384
		 *
		 * \~english
		 * @brief The identifier of the P-384 curve
		 *
		 * \~
		 */
		static const char * OID_P384 = "1.3.132.0.34";
		/**
		 * \~russian
		 * @brief Опознаватель кривой P-521
		 *
		 * \~english
		 * @brief The identifier of the P-521 curve
		 *
		 * \~
		 */
		static const char * OID_P521 = "1.3.132.0.35";

		/**
		 * \~russian
		 * @brief Метод получения размера числа кривой по её опознавателю
		 *
		 * @param oid опознаватель кривой
		 * @return    размер числа кривой в байтах, ноль у чужой кривой
		 *
		 * \~english
		 * @brief Method of getting the size of the number of a curve by its identifier
		 * @param oid the identifier of the curve
		 * @return    the size of the number of the curve in bytes, zero at a foreign curve
		 *
		 * \~
		 */
		static size_t curveSize(const string & oid) noexcept {
			// Кривая P-256
			if(oid.compare(OID_P256) == 0)
				// Выводим размер числа кривой
				return 32;
			// Кривая P-384
			if(oid.compare(OID_P384) == 0)
				// Выводим размер числа кривой
				return 48;
			// Кривая P-521
			if(oid.compare(OID_P521) == 0)
				// Выводим размер числа кривой
				return 66;
			// Кривая чужая
			return 0;
		}
		/**
		 * \~russian
		 * @brief Метод получения имени кривой JWK по её опознавателю
		 *
		 * @param oid опознаватель кривой
		 * @return    имя кривой («P-256» и прочие), пустое у чужой кривой
		 *
		 * \~english
		 * @brief Method of getting the JWK name of a curve by its identifier
		 * @param oid the identifier of the curve
		 * @return    the name of the curve («P-256» and the others), empty at a foreign curve
		 *
		 * \~
		 */
		static const char * curveName(const string & oid) noexcept {
			// Кривая P-256
			if(oid.compare(OID_P256) == 0)
				// Выводим имя кривой
				return "P-256";
			// Кривая P-384
			if(oid.compare(OID_P384) == 0)
				// Выводим имя кривой
				return "P-384";
			// Кривая P-521
			if(oid.compare(OID_P521) == 0)
				// Выводим имя кривой
				return "P-521";
			// Кривая чужая
			return "";
		}
		/**
		 * \~russian
		 * @brief Метод получения опознавателя кривой по её имени JWK
		 *
		 * @param name имя кривой
		 * @return     опознаватель кривой, пустой у чужого имени
		 *
		 * \~english
		 * @brief Method of getting the identifier of a curve by its JWK name
		 * @param name the name of the curve
		 * @return     the identifier of the curve, empty at a foreign name
		 *
		 * \~
		 */
		static const char * curveOid(const view_t & name) noexcept {
			// Кривая P-256
			if((name.size == 5) && (::memcmp(name.data, "P-256", 5) == 0))
				// Выводим опознаватель кривой
				return OID_P256;
			// Кривая P-384
			if((name.size == 5) && (::memcmp(name.data, "P-384", 5) == 0))
				// Выводим опознаватель кривой
				return OID_P384;
			// Кривая P-521
			if((name.size == 5) && (::memcmp(name.data, "P-521", 5) == 0))
				// Выводим опознаватель кривой
				return OID_P521;
			// Имя чужое
			return "";
		}

		/**
		 * \~russian
		 * @brief Метод извлечения значения строкового члена текста JSON
		 *
		 * @param text просмотр текста JSON
		 * @param name имя искомого члена
		 * @param result просмотр значения члена внутри текста
		 * @return признак того, что член найден
		 *
		 * @details Разбирается лишь плоская запись объекта без вложенных объектов:
		 *          заголовки JWS и ключи JWK вложенности не несут. Записи с экранировками
		 *          в строках отвергаются — имена и значения членов JWS и JWK их не несут
		 *
		 * \~english
		 * @brief Method of extracting the value of a string member of a JSON text
		 * @param text the view of the JSON text
		 * @param name the name of the member being looked for
		 * @param result the view of the value of the member inside the text
		 * @return the flag of the member being found
		 * @details Only a flat record of an object without nested objects is parsed: the
		 *          JWS headers and the JWK keys carry no nesting. Records with escapes in
		 *          the strings are rejected — the names and the values of the JWS and JWK
		 *          members carry none
		 *
		 * \~
		 */
		static bool member(const view_t & text, const char * name, view_t & result) noexcept {
			// Длина имени члена
			const size_t length = ::strlen(name);
			// Позиция разбора записи
			size_t position = 0;
			/**
			 * Выполняем обход записи в поисках имени члена
			 */
			while(position + length + 3 < text.size){
				// Ищем открывающую кавычку имени
				const uint8_t * quote = static_cast <const uint8_t *> (::memchr(text.data + position, '"', text.size - position));
				// Если кавычки больше нет
				if(quote == nullptr)
					// Выводим отсутствие члена
					return false;
				// Переносим позицию за кавычку
				position = static_cast <size_t> (quote - text.data) + 1;
				// Если имя члена совпало
				if((position + length < text.size) && (::memcmp(text.data + position, name, length) == 0) && (text.data[position + length] == '"')){
					// Переносим позицию за имя члена
					position += length + 1;
					// Пропускаем промежуток до двоеточия
					while((position < text.size) && (text.data[position] != ':'))
						// Переносим позицию
						position++;
					// Если двоеточия нет
					if(position >= text.size)
						// Выводим отсутствие члена
						return false;
					// Переносим позицию за двоеточие
					position++;
					// Пропускаем промежуток до значения
					while((position < text.size) && ((text.data[position] == ' ') || (text.data[position] == '\t')))
						// Переносим позицию
						position++;
					// Если значение не строковое
					if((position >= text.size) || (text.data[position] != '"'))
						// Выводим отсутствие члена
						return false;
					// Переносим позицию за кавычку
					position++;
					// Ищем закрывающую кавычку значения
					const uint8_t * end = static_cast <const uint8_t *> (::memchr(text.data + position, '"', text.size - position));
					// Если кавычки нет
					if(end == nullptr)
						// Выводим отсутствие члена
						return false;
					// Если в значении есть экранировка
					if(::memchr(text.data + position, '\\', static_cast <size_t> (end - text.data) - position) != nullptr)
						// Выводим отсутствие члена
						return false;
					// Запоминаем просмотр значения
					result = view_t(text.data + position, static_cast <size_t> (end - text.data) - position);
					// Выводим найденность члена
					return true;
				}
			}
			// Член не найден
			return false;
		}

		/**
		 * \~russian
		 * @brief Метод получения алгоритма хеша подписи JWS
		 *
		 * @param algorithm алгоритм подписи JWS
		 * @return          алгоритм хеша, hash_t::NONE у подписи без хеша
		 *
		 * \~english
		 * @brief Method of getting the hash algorithm of a JWS signature
		 * @param algorithm the JWS signature algorithm
		 * @return          the hash algorithm, hash_t::NONE at a signature without a hash
		 *
		 * \~
		 */
		static digest::hash_t hashOf(const jws::algorithm_t algorithm) noexcept {
			/**
			 * Выполняем определение алгоритма подписи
			 */
			switch(algorithm){
				// RS256 и ES256 идут с SHA-256
				case jws::algorithm_t::RS256:
				case jws::algorithm_t::ES256:
					// Выводим алгоритм хеша
					return digest::hash_t::SHA256;
				// RS384 и ES384 идут с SHA-384
				case jws::algorithm_t::RS384:
				case jws::algorithm_t::ES384:
					// Выводим алгоритм хеша
					return digest::hash_t::SHA384;
				// RS512 и ES512 идут с SHA-512
				case jws::algorithm_t::RS512:
				case jws::algorithm_t::ES512:
					// Выводим алгоритм хеша
					return digest::hash_t::SHA512;
				// Прочие алгоритмы хеша не несут
				default:
					// Выводим отсутствие алгоритма
					return digest::hash_t::NONE;
			}
		}
		/**
		 * \~russian
		 * @brief Метод проверки ответа алгоритма подписи виду ключа
		 *
		 * @param algorithm алгоритм подписи JWS
		 * @param kind      вид ключа
		 * @param oid       опознаватель кривой ключа EC
		 * @return          признак согласованности алгоритма и ключа
		 *
		 * \~english
		 * @brief Method of the check of the answer of the signature algorithm to the kind of the key
		 * @param algorithm the JWS signature algorithm
		 * @param kind      the kind of the key
		 * @param oid       the identifier of the curve of the EC key
		 * @return          the flag of the consistency of the algorithm and the key
		 *
		 * \~
		 */
		static bool suitable(const jws::algorithm_t algorithm, const keys::kind_t kind, const string & oid) noexcept {
			/**
			 * Выполняем определение алгоритма подписи
			 */
			switch(algorithm){
				// Подписи RSA идут ключом RSA
				case jws::algorithm_t::RS256:
				case jws::algorithm_t::RS384:
				case jws::algorithm_t::RS512:
					// Выводим согласованность с ключом RSA
					return (kind == keys::kind_t::RSA);
				// Подпись ES256 идёт ключом на кривой P-256
				case jws::algorithm_t::ES256:
					// Выводим согласованность с кривой P-256
					return ((kind == keys::kind_t::EC) && (oid.compare(OID_P256) == 0));
				// Подпись ES384 идёт ключом на кривой P-384
				case jws::algorithm_t::ES384:
					// Выводим согласованность с кривой P-384
					return ((kind == keys::kind_t::EC) && (oid.compare(OID_P384) == 0));
				// Подпись ES512 идёт ключом на кривой P-521
				case jws::algorithm_t::ES512:
					// Выводим согласованность с кривой P-521
					return ((kind == keys::kind_t::EC) && (oid.compare(OID_P521) == 0));
				// Подпись EdDSA идёт ключом Ed25519
				case jws::algorithm_t::EDDSA:
					// Выводим согласованность с ключом Ed25519
					return (kind == keys::kind_t::ED25519);
				// Прочие алгоритмы не согласованы ни с каким ключом
				default:
					// Выводим несогласованность
					return false;
			}
		}

		/**
		 * \~russian
		 * @brief Метод выработки подписи JWS
		 *
		 * @param algorithm алгоритм подписи JWS
		 * @param signer    подготовленный секретный ключ подписи
		 * @param content   подписываемое содержимое
		 * @param signature место, в которое помещается подпись
		 * @return          отказ выработки подписи
		 *
		 * \~english
		 * @brief Method of the production of a JWS signature
		 * @param algorithm the JWS signature algorithm
		 * @param signer    the prepared secret signature key
		 * @param content   the content being signed
		 * @param signature the place the signature is put into
		 * @return          the failure of the production of the signature
		 *
		 * \~
		 */
		static jws::error_t makeSignature(const jws::algorithm_t algorithm, const keys::signer_t & signer, const view_t & content, vector <uint8_t> & signature) noexcept {
			/**
			 * Выполняем определение алгоритма подписи
			 */
			switch(algorithm){
				// Подпись RSA
				case jws::algorithm_t::RS256:
				case jws::algorithm_t::RS384:
				case jws::algorithm_t::RS512: {
					// Модуль подписи RSA
					const sign::rsa_t & rsa = signer.rsa();
					// Алгоритм хеша подписи
					const digest::hash_t hash = hashOf(algorithm);
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
					// Занимаем место под подпись длиною в модуль ключа
					signature.assign(rsa.size(), 0);
					// Если подпись выработать не удалось
					if(!rsa.make(sign::scheme_t::PKCS1, hash, view_t(digest, digest::length(hash)), signature.data(), SIZE_MAX))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Подпись ECDSA
				case jws::algorithm_t::ES256:
				case jws::algorithm_t::ES384:
				case jws::algorithm_t::ES512: {
					// Модуль подписи ECDSA
					const sign::ecdsa_t & ecdsa = signer.ecdsa();
					// Алгоритм хеша подписи
					const digest::hash_t hash = hashOf(algorithm);
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
					// Занимаем место под подпись в сыром виде: пара r ‖ s размером в удвоенное число кривой
					signature.assign(ecdsa.size(), 0);
					// Если подпись выработать не удалось
					if(!ecdsa.make(hash, view_t(digest, digest::length(hash)), signature.data()))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Подпись Ed25519
				case jws::algorithm_t::EDDSA: {
					// Модуль подписи Ed25519
					const sign::ed25519_t & ed25519 = signer.ed25519();
					// Занимаем место под подпись Ed25519
					signature.assign(sign::ed25519_t::SIGNATURE_SIZE, 0);
					// Если подпись выработать не удалось
					if(!ed25519.make(content, signature.data()))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Прочие алгоритмы не подписывают
				default:
					// Выводим отказ алгоритма
					return jws::error_t::ALGORITHM;
			}
			// Выводим успешность выработки
			return jws::error_t::NONE;
		}
		/**
		 * \~russian
		 * @brief Метод проверки подписи JWS
		 *
		 * @param algorithm алгоритм подписи JWS
		 * @param key       сведения об открытом ключе подписавшей стороны
		 * @param content   подписанное содержимое
		 * @param signature проверяемая подпись
		 * @return          отказ проверки подписи
		 *
		 * \~english
		 * @brief Method of the check of a JWS signature
		 * @param algorithm the JWS signature algorithm
		 * @param key       the info of the public key of the side that signed
		 * @param content   the signed content
		 * @param signature the signature being checked
		 * @return          the failure of the check of the signature
		 *
		 * \~
		 */
		static jws::error_t checkSignature(const jws::algorithm_t algorithm, const keys::key_t & key, const view_t & content, const view_t & signature) noexcept {
			/**
			 * Выполняем определение алгоритма подписи
			 */
			switch(algorithm){
				// Подпись RSA
				case jws::algorithm_t::RS256:
				case jws::algorithm_t::RS384:
				case jws::algorithm_t::RS512: {
					// Модуль подписи RSA
					sign::rsa_t rsa;
					// Если открытый ключ установить не удалось
					if(!rsa.key(view_t(key.n.data(), key.n.size()), view_t(key.e.data(), key.e.size())))
						// Выводим отказ ключа
						return jws::error_t::ALGORITHM;
					// Алгоритм хеша подписи
					const digest::hash_t hash = hashOf(algorithm);
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
					// Если подпись не сошлась
					if(!rsa.check(sign::scheme_t::PKCS1, hash, view_t(digest, digest::length(hash)), signature, SIZE_MAX))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Подпись ECDSA
				case jws::algorithm_t::ES256:
				case jws::algorithm_t::ES384:
				case jws::algorithm_t::ES512: {
					// Размер числа кривой ключа
					const size_t size = curveSize(key.oid);
					// Если кривая ключа чужая либо подпись не отвечает её размеру
					if((size == 0) || (signature.size != size * 2))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
					// Кривая ключа
					curve::curve_t curve;
					// Если кривую по опознавателю завести не удалось
					if(!curve::parameters(key.oid, curve))
						// Выводим отказ ключа
						return jws::error_t::ALGORITHM;
					// Модуль подписи ECDSA
					sign::ecdsa_t ecdsa;
					// Если кривую модулю передать не удалось
					if(!ecdsa.start(curve))
						// Выводим отказ ключа
						return jws::error_t::ALGORITHM;
					// Если открытую точку установить не удалось
					if(!ecdsa.key(view_t(key.x.data(), key.x.size()), view_t(key.y.data(), key.y.size())))
						// Выводим отказ ключа
						return jws::error_t::ALGORITHM;
					// Алгоритм хеша подписи
					const digest::hash_t hash = hashOf(algorithm);
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
					// Если подпись не сошлась
					if(!ecdsa.check(view_t(digest, digest::length(hash)), signature))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Подпись Ed25519
				case jws::algorithm_t::EDDSA: {
					// Модуль подписи Ed25519
					sign::ed25519_t ed25519;
					// Если открытый ключ установить не удалось
					if(!ed25519.key(view_t(key.key.data(), key.key.size())))
						// Выводим отказ ключа
						return jws::error_t::ALGORITHM;
					// Если подпись не сошлась
					if(!ed25519.check(content, signature))
						// Выводим отказ подписи
						return jws::error_t::SIGNATURE;
				} break;
				// Прочие алгоритмы не проверяют
				default:
					// Выводим отказ алгоритма
					return jws::error_t::ALGORITHM;
			}
			// Выводим успешность проверки
			return jws::error_t::NONE;
		}
	}

	/**
	 * \~russian
	 * @brief Метод кодирования base64url
	 *
	 * @param data   просмотр кодируемых данных
	 * @param result строка, в которую помещается итог
	 *
	 * \~english
	 * @brief Method of the base64url encoding
	 * @param data   the view of the data being encoded
	 * @param result the string the result is put into
	 *
	 * \~
	 */
	void jws::base64url(const view_t & data, string & result) noexcept {
		// Алфавит кодировки base64url по разделу 5 RFC 4648
		static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		// Очищаем итог
		result.clear();
		// Занимаем место под итог
		result.reserve((data.size + 2) / 3 * 4);
		// Позиция разбора данных
		size_t position = 0;
		/**
		 * Выполняем кодирование полных троек байтов
		 */
		for(; position + 3 <= data.size; position += 3){
			// Тройка байтов
			const uint32_t triple = (static_cast <uint32_t> (data.data[position]) << 16) | (static_cast <uint32_t> (data.data[position + 1]) << 8) | data.data[position + 2];
			// Выводим четыре символа тройки
			result += alphabet[(triple >> 18) & 0x3F];
			result += alphabet[(triple >> 12) & 0x3F];
			result += alphabet[(triple >> 6) & 0x3F];
			result += alphabet[triple & 0x3F];
		}
		// Если остались два байта
		if(position + 2 == data.size){
			// Пара байтов
			const uint32_t couple = (static_cast <uint32_t> (data.data[position]) << 16) | (static_cast <uint32_t> (data.data[position + 1]) << 8);
			// Выводим три символа пары
			result += alphabet[(couple >> 18) & 0x3F];
			result += alphabet[(couple >> 12) & 0x3F];
			result += alphabet[(couple >> 6) & 0x3F];
		// Если остался один байт
		} else if(position + 1 == data.size){
			// Байт
			const uint32_t single = static_cast <uint32_t> (data.data[position]) << 16;
			// Выводим два символа байта
			result += alphabet[(single >> 18) & 0x3F];
			result += alphabet[(single >> 12) & 0x3F];
		}
	}
	/**
	 * \~russian
	 * @brief Метод декодирования base64url
	 *
	 * @param text   просмотр кодируемой строки
	 * @param result место, в которое помещается итог
	 * @return       признак успешности разбора
	 *
	 * \~english
	 * @brief Method of the base64url decoding
	 * @param text   the view of the string being decoded
	 * @param result the place the result is put into
	 * @return       the flag of the success of the parsing
	 *
	 * \~
	 */
	bool jws::unbase64url(const view_t & text, vector <uint8_t> & result) noexcept {
		// Очищаем итог
		result.clear();
		// Если запись пуста
		if((text.size == 0))
			// Выводим успешность разбора
			return true;
		// Если длина записи не отвечает кодировке без заполнителей
		if((text.size % 4) == 1)
			// Выводим отказ разбора
			return false;
		// Занимаем место под итог
		result.reserve(text.size / 4 * 3 + 3);
		// Накопитель разрядов
		uint32_t accumulator = 0;
		// Число разрядов в накопителе
		uint8_t bits = 0;
		/**
		 * Выполняем обход символов записи
		 */
		for(size_t position = 0; position < text.size; position++){
			// Символ записи
			const uint8_t symbol = text.data[position];
			// Значение символа в алфавите
			uint8_t value = 0;
			// Символ заглавной буквы
			if((symbol >= 'A') && (symbol <= 'Z'))
				// Вычисляем значение символа
				value = symbol - 'A';
			// Символ строчной буквы
			else if((symbol >= 'a') && (symbol <= 'z'))
				// Вычисляем значение символа
				value = symbol - 'a' + 26;
			// Символ цифры
			else if((symbol >= '0') && (symbol <= '9'))
				// Вычисляем значение символа
				value = symbol - '0' + 52;
			// Символ '-'
			else if(symbol == '-')
				// Вычисляем значение символа
				value = 62;
			// Символ '_'
			else if(symbol == '_')
				// Вычисляем значение символа
				value = 63;
			// Символ чужой: заполнители и прочие отвергаются
			else
				// Выводим отказ разбора
				return false;
			// Накапливаем разряды символа
			accumulator = (accumulator << 6) | value;
			// Считаем разряды в накопителе
			bits += 6;
			// Если в накопителе набрался байт
			if(bits >= 8){
				// Сбрасываем считанные разряды
				bits -= 8;
				// Выводим байт
				result.push_back(static_cast <uint8_t> (accumulator >> bits));
			}
		}
		// Если в накопителе остались ненулевые разряды: запись порчена
		if((bits != 0) && ((accumulator & ((1u << bits) - 1u)) != 0))
			// Выводим отказ разбора
			return false;
		// Выводим успешность разбора
		return true;
	}

	/**
	 * \~russian
	 * @brief Метод получения имени алгоритма подписи
	 *
	 * @param algorithm алгоритм подписи
	 * @return          имя алгоритма, пустое у неустановленного
	 *
	 * \~english
	 * @brief Method of getting the name of a signature algorithm
	 * @param algorithm the signature algorithm
	 * @return          the name of the algorithm, empty at an unset one
	 *
	 * \~
	 */
	const char * jws::name(const algorithm_t algorithm) noexcept {
		/**
		 * Выполняем определение алгоритма подписи
		 */
		switch(algorithm){
			// Подпись RS256
			case algorithm_t::RS256: return "RS256";
			// Подпись RS384
			case algorithm_t::RS384: return "RS384";
			// Подпись RS512
			case algorithm_t::RS512: return "RS512";
			// Подпись ES256
			case algorithm_t::ES256: return "ES256";
			// Подпись ES384
			case algorithm_t::ES384: return "ES384";
			// Подпись ES512
			case algorithm_t::ES512: return "ES512";
			// Подпись EdDSA
			case algorithm_t::EDDSA: return "EdDSA";
			// Алгоритм не установлен
			default: return "";
		}
	}
	/**
	 * \~russian
	 * @brief Метод получения алгоритма подписи по его имени
	 *
	 * @param name имя алгоритма
	 * @return     алгоритм подписи, algorithm_t::NONE у неизвестного имени
	 *
	 * \~english
	 * @brief Method of getting a signature algorithm by its name
	 * @param name the name of the algorithm
	 * @return     the signature algorithm, algorithm_t::NONE at an unknown name
	 *
	 * \~
	 */
	jws::algorithm_t jws::algorithm(const view_t & name) noexcept {
		// Подпись RS256
		if((name.size == 5) && (::memcmp(name.data, "RS256", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::RS256;
		// Подпись RS384
		if((name.size == 5) && (::memcmp(name.data, "RS384", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::RS384;
		// Подпись RS512
		if((name.size == 5) && (::memcmp(name.data, "RS512", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::RS512;
		// Подпись ES256
		if((name.size == 5) && (::memcmp(name.data, "ES256", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::ES256;
		// Подпись ES384
		if((name.size == 5) && (::memcmp(name.data, "ES384", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::ES384;
		// Подпись ES512
		if((name.size == 5) && (::memcmp(name.data, "ES512", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::ES512;
		// Подпись EdDSA
		if((name.size == 5) && (::memcmp(name.data, "EdDSA", 5) == 0))
			// Выводим алгоритм подписи
			return algorithm_t::EDDSA;
		// Имя неизвестно
		return algorithm_t::NONE;
	}
	/**
	 * \~russian
	 * @brief Метод определения алгоритма подписи по ключу
	 *
	 * @param key сведения о ключе
	 * @return    алгоритм подписи, algorithm_t::NONE у ключа неподходящего вида
	 *
	 * \~english
	 * @brief Method of the determination of the signature algorithm by the key
	 * @param key the info of the key
	 * @return    the signature algorithm, algorithm_t::NONE at a key of an unfit kind
	 *
	 * \~
	 */
	jws::algorithm_t jws::algorithm(const keys::key_t & key) noexcept {
		/**
		 * Выполняем определение вида ключа
		 */
		switch(key.kind){
			// Ключ RSA идёт подписью RS256
			case keys::kind_t::RSA:
				// Выводим алгоритм подписи
				return algorithm_t::RS256;
			// Ключ EC идёт подписью по своей кривой
			case keys::kind_t::EC: {
				// Кривая P-256
				if(key.oid.compare(OID_P256) == 0)
					// Выводим алгоритм подписи
					return algorithm_t::ES256;
				// Кривая P-384
				if(key.oid.compare(OID_P384) == 0)
					// Выводим алгоритм подписи
					return algorithm_t::ES384;
				// Кривая P-521
				if(key.oid.compare(OID_P521) == 0)
					// Выводим алгоритм подписи
					return algorithm_t::ES512;
				// Кривая чужая
				return algorithm_t::NONE;
			}
			// Ключ Ed25519 идёт подписью EdDSA
			case keys::kind_t::ED25519:
				// Выводим алгоритм подписи
				return algorithm_t::EDDSA;
			// Прочие виды ключей не подписывают JWS
			default:
				// Выводим отсутствие алгоритма
				return algorithm_t::NONE;
		}
	}
	/**
	 * \~russian
	 * @brief Метод определения алгоритма подписи по подготовленному ключу
	 *
	 * @param signer подготовленный секретный ключ подписи
	 * @return       алгоритм подписи, algorithm_t::NONE у ключа неподходящего вида
	 *
	 * \~english
	 * @brief Method of the determination of the signature algorithm by the prepared key
	 * @param signer the prepared secret signature key
	 * @return       the signature algorithm, algorithm_t::NONE at a key of an unfit kind
	 *
	 * \~
	 */
	jws::algorithm_t jws::algorithm(const keys::signer_t & signer) noexcept {
		/**
		 * Выполняем определение вида ключа
		 */
		switch(signer.kind()){
			// Ключ RSA идёт подписью RS256
			case keys::kind_t::RSA:
				// Выводим алгоритм подписи
				return algorithm_t::RS256;
			// Ключ EC идёт подписью по размеру своей кривой
			case keys::kind_t::EC: {
				// Размер числа кривой ключа
				switch(signer.curve().size()){
					// Кривая P-256
					case 32:
						// Выводим алгоритм подписи
						return algorithm_t::ES256;
					// Кривая P-384
					case 48:
						// Выводим алгоритм подписи
						return algorithm_t::ES384;
					// Кривая P-521
					case 66:
						// Выводим алгоритм подписи
						return algorithm_t::ES512;
					// Кривая чужая
					default:
						// Выводим отсутствие алгоритма
						return algorithm_t::NONE;
				}
			}
			// Ключ Ed25519 идёт подписью EdDSA
			case keys::kind_t::ED25519:
				// Выводим алгоритм подписи
				return algorithm_t::EDDSA;
			// Прочие виды ключей не подписывают JWS
			default:
				// Выводим отсутствие алгоритма
				return algorithm_t::NONE;
		}
	}

	/**
	 * \~russian
	 * @brief Метод сборки компактной записи JWS
	 *
	 * @param algorithm алгоритм подписи
	 * @param header    текст заголовка JSON целиком
	 * @param payload   полезная нагрузка
	 * @param signer    подготовленный секретный ключ подписи
	 * @param result    строка, в которую помещается запись
	 * @return          причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of assembling a JWS compact record
	 * @param algorithm the signature algorithm
	 * @param header    the text of the JSON header as a whole
	 * @param payload   the payload
	 * @param signer    the prepared secret signature key
	 * @param result    the string the record is put into
	 * @return          the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::encode(const algorithm_t algorithm, const string & header, const view_t & payload, const keys::signer_t & signer, string & result) noexcept {
		// Очищаем итог
		result.clear();
		// Если алгоритм не установлен
		if(algorithm == algorithm_t::NONE)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Если ключ не подготовлен
		if(!signer.ready())
			// Выводим отказ ключа
			return error_t::EMPTY;
		// Если алгоритм виду ключа не отвечает
		if(jws::algorithm(signer) != algorithm)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Собираем заголовок с членом alg
		string whole;
		// Занимаем место под заголовок
		whole.reserve(header.size() + 16);
		// Если заголовок задан: дописываем член alg к нему
		if(!header.empty()){
			// Переносим заголовок без закрывающей скобки
			whole.assign(header);
			// Если последний символ - закрывающая скобка объекта
			if(whole.back() == '}')
				// Убираем её
				whole.pop_back();
			// Если в заголовке уже есть члены
			if(whole.size() > 1)
				// Дописываем разделитель членов
				whole += ',';
			// Дописываем член alg
			whole += "\"alg\":\"";
			whole += name(algorithm);
			whole += "\"}";
		// Иначе заголовок из одного члена alg
		} else {
			// Собираем заголовок
			whole.assign("{\"alg\":\"");
			whole += name(algorithm);
			whole += "\"}";
		}
		// Кодируем заголовок в base64url
		base64url(view_t(reinterpret_cast <const uint8_t *> (whole.data()), whole.size()), result);
		// Дописываем разделитель
		result += '.';
		// Кодируем полезную нагрузку в base64url
		string body;
		base64url(payload, body);
		// Дописываем полезную нагрузку
		result += body;
		// Подписываем запись ASCII(protected '.' payload)
		vector <uint8_t> signature;
		// Если подпись выработать не удалось
		const error_t outcome = makeSignature(algorithm, signer, view_t(reinterpret_cast <const uint8_t *> (result.data()), result.size()), signature);
		// Если выработка отказала
		if(outcome != error_t::NONE)
			// Выводим причину отказа
			return outcome;
		// Дописываем разделитель
		result += '.';
		// Кодируем подпись в base64url
		string tail;
		base64url(view_t(signature.data(), signature.size()), tail);
		// Дописываем подпись
		result += tail;
		// Затираем подпись
		sys::wipe(signature.data(), signature.size());
		// Выводим успешность сборки
		return error_t::NONE;
	}

	/**
	 * \~russian
	 * @brief Метод сборки записи открытого ключа JWK
	 *
	 * @param key    сведения об открытом ключе
	 * @param result строка, в которую помещается текст JSON
	 * @return       причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of assembling a JWK public key record
	 * @param key    the info of the public key
	 * @param result the string the JSON text is put into
	 * @return       the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::jwk(const keys::key_t & key, string & result) noexcept {
		// Очищаем итог
		result.clear();
		/**
		 * Выполняем определение вида ключа
		 */
		switch(key.kind){
			// Ключ RSA
			case keys::kind_t::RSA: {
				// Если составляющие ключа пусты
				if(key.n.empty() || key.e.empty())
					// Выводим отказ ключа
					return error_t::EMPTY;
				// Кодируем модуль
				string n;
				base64url(view_t(key.n.data(), key.n.size()), n);
				// Кодируем показатель
				string e;
				base64url(view_t(key.e.data(), key.e.size()), e);
				// Собираем запись: члены в порядке словаря, как у канонической записи отпечатка
				result.assign("{\"e\":\"");
				result += e;
				result += "\",\"kty\":\"RSA\",\"n\":\"";
				result += n;
				result += "\"}";
			} break;
			// Ключ EC
			case keys::kind_t::EC: {
				// Имя кривой ключа
				const char * curve = curveName(key.oid);
				// Размер числа кривой
				const size_t size = curveSize(key.oid);
				// Если кривая чужая либо координаты ей не отвечают
				if((size == 0) || (key.x.size() != size) || (key.y.size() != size))
					// Выводим отказ ключа
					return error_t::EMPTY;
				// Кодируем первую координату
				string x;
				base64url(view_t(key.x.data(), key.x.size()), x);
				// Кодируем вторую координату
				string y;
				base64url(view_t(key.y.data(), key.y.size()), y);
				// Собираем запись: члены в порядке словаря
				result.assign("{\"crv\":\"");
				result += curve;
				result += "\",\"kty\":\"EC\",\"x\":\"";
				result += x;
				result += "\",\"y\":\"";
				result += y;
				result += "\"}";
			} break;
			// Ключ Ed25519
			case keys::kind_t::ED25519: {
				// Если ключ пуст
				if(key.key.size() != sign::ed25519_t::KEY_SIZE)
					// Выводим отказ ключа
					return error_t::EMPTY;
				// Кодируем ключ
				string x;
				base64url(view_t(key.key.data(), key.key.size()), x);
				// Собираем запись: члены в порядке словаря
				result.assign("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
				result += x;
				result += "\"}";
			} break;
			// Прочие виды ключей записи JWK не имеют
			default:
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
		}
		// Выводим успешность сборки
		return error_t::NONE;
	}
	/**
	 * \~russian
	 * @brief Метод разбора записи открытого ключа JWK
	 *
	 * @param text   просмотр текста JSON
	 * @param result ключ, в который помещается итог разбора
	 * @return       причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of parsing a JWK public key record
	 * @param text   the view of the JSON text
	 * @param result the key the result of the parsing is put into
	 * @return       the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::unjwk(const view_t & text, keys::key_t & result) noexcept {
		// Сбрасываем итог
		result.clear();
		// Если запись пуста
		if((text.size == 0))
			// Выводим отказ записи
			return error_t::EMPTY;
		// Просмотр значения члена kty
		view_t kty;
		// Если член kty не найден
		if(!member(text, "kty", kty))
			// Выводим отказ записи
			return error_t::STRUCTURE;
		// Ключ RSA
		if((kty.size == 3) && (::memcmp(kty.data, "RSA", 3) == 0)){
			// Просмотры значений членов
			view_t n, e;
			// Если члены ключа не найдены
			if(!member(text, "n", n) || !member(text, "e", e))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Декодируем модуль
			if(!unbase64url(n, result.n) || result.n.empty())
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Декодируем показатель
			if(!unbase64url(e, result.e) || result.e.empty())
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Запоминаем вид ключа
			result.kind = keys::kind_t::RSA;
		// Ключ EC
		} else if((kty.size == 2) && (::memcmp(kty.data, "EC", 2) == 0)){
			// Просмотры значений членов
			view_t crv, x, y;
			// Если члены ключа не найдены
			if(!member(text, "crv", crv) || !member(text, "x", x) || !member(text, "y", y))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Опознаватель кривой по её имени
			const char * oid = curveOid(crv);
			// Если кривая чужая
			if(oid[0] == '\0')
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
			// Запоминаем опознаватель кривой
			result.oid.assign(oid);
			// Декодируем первую координату
			if(!unbase64url(x, result.x))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Декодируем вторую координату
			if(!unbase64url(y, result.y))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Если координаты кривой не отвечают
			if((result.x.size() != curveSize(result.oid)) || (result.y.size() != curveSize(result.oid)))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Запоминаем вид ключа
			result.kind = keys::kind_t::EC;
		// Ключ Ed25519
		} else if((kty.size == 3) && (::memcmp(kty.data, "OKP", 3) == 0)){
			// Просмотры значений членов
			view_t crv, x;
			// Если члены ключа не найдены
			if(!member(text, "crv", crv) || !member(text, "x", x))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Если кривая не Ed25519
			if((crv.size != 7) || (::memcmp(crv.data, "Ed25519", 7) != 0))
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
			// Декодируем ключ
			if(!unbase64url(x, result.key) || (result.key.size() != sign::ed25519_t::KEY_SIZE))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Запоминаем вид ключа
			result.kind = keys::kind_t::ED25519;
		// Вид ключа чужой
		} else
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Выводим успешность разбора
		return error_t::NONE;
	}
	/**
	 * \~russian
	 * @brief Метод выработки отпечатка открытого ключа JWK
	 *
	 * @param key    сведения об открытом ключе
	 * @param result строка, в которую помещается отпечаток в base64url
	 * @return       причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of the production of the JWK public key thumbprint
	 * @param key    the info of the public key
	 * @param result the string the thumbprint in base64url is put into
	 * @return       the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::thumbprint(const keys::key_t & key, string & result) noexcept {
		// Очищаем итог
		result.clear();
		// Собираем каноническую запись ключа: наша сборка jwk уже пишет члены в порядке словаря
		string canonical;
		// Если запись собрать не удалось
		const error_t outcome = jwk(key, canonical);
		// Если сборка отказала
		if(outcome != error_t::NONE)
			// Выводим причину отказа
			return outcome;
		// Место, в которое помещается хеш записи
		uint8_t digest[32];
		// Если хеш записи выработать не удалось
		if(!digest::hash(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (canonical.data()), canonical.size()), digest, sizeof(digest)))
			// Выводим отказ памяти
			return error_t::MEMORY;
		// Кодируем отпечаток в base64url
		base64url(view_t(digest, sizeof(digest)), result);
		// Выводим успешность выработки
		return error_t::NONE;
	}

	/**
	 * \~russian
	 * @brief Метод разбора компактной записи JWS
	 *
	 * @param data просмотр разбираемой записи
	 * @return     причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of parsing a JWS compact record
	 * @param data the view of the record being parsed
	 * @return     the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::Signature::parse(const view_t & data) noexcept {
		// Сбрасываем разобранные сведения
		this->clear();
		// Если запись пуста
		if((data.size == 0))
			// Запоминаем причину отказа
			return (this->_error = error_t::EMPTY);
		// Ищем первый разделитель записи
		const uint8_t * first = static_cast <const uint8_t *> (::memchr(data.data, '.', data.size));
		// Если разделителя нет
		if(first == nullptr)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Позиция первого разделителя
		const size_t head = static_cast <size_t> (first - data.data);
		// Ищем второй разделитель записи
		const uint8_t * second = static_cast <const uint8_t *> (::memchr(first + 1, '.', data.size - head - 1));
		// Если разделителя нет
		if(second == nullptr)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Позиция второго разделителя
		const size_t middle = static_cast <size_t> (second - data.data);
		// Если после второго разделителя есть третий
		if(::memchr(second + 1, '.', data.size - middle - 1) != nullptr)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем просмотр записи заголовка
		this->_protected = view_t(data.data, head);
		// Запоминаем просмотр записи полезной нагрузки
		this->_payload = view_t(data.data + head + 1, middle - head - 1);
		// Если заголовок пуст
		if(this->_protected.size == 0)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Декодируем заголовок
		vector <uint8_t> header;
		if(!unbase64url(this->_protected, header) || header.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем текст заголовка
		this->_header.assign(reinterpret_cast <const char *> (header.data()), header.size());
		// Декодируем подпись
		if(!unbase64url(view_t(data.data + middle + 1, data.size - middle - 1), this->_signature) || this->_signature.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Извлекаем член alg заголовка
		view_t alg;
		if(!member(view_t(reinterpret_cast <const uint8_t *> (this->_header.data()), this->_header.size()), "alg", alg))
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Определяем алгоритм подписи по имени
		this->_algorithm = jws::algorithm(alg);
		// Если алгоритм неизвестен
		if(this->_algorithm == algorithm_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::ALGORITHM);
		// Выводим успешность разбора
		return (this->_error = error_t::NONE);
	}
	/**
	 * \~russian
	 * @brief Метод очистки разобранных сведений
	 *
	 * \~english
	 * @brief Method of clearing the parsed info
	 *
	 * \~
	 */
	void jws::Signature::clear() noexcept {
		// Сбрасываем причину отказа
		this->_error = error_t::NONE;
		// Сбрасываем алгоритм подписи
		this->_algorithm = algorithm_t::NONE;
		// Сбрасываем просмотры записи
		this->_protected = view_t();
		this->_payload = view_t();
		// Сбрасываем текст заголовка
		this->_header.clear();
		// Затираем подпись
		if(!this->_signature.empty()){
			// Затираем подпись
			sys::wipe(this->_signature.data(), this->_signature.size());
			// Сбрасываем подпись
			this->_signature.clear();
		}
	}
	/**
	 * \~russian
	 * @brief Метод извлечения причины последнего отказа
	 *
	 * @return причина последнего отказа
	 *
	 * \~english
	 * @brief Method of getting the reason of the last failure
	 * @return the reason of the last failure
	 *
	 * \~
	 */
	jws::error_t jws::Signature::err() const noexcept {
		// Выводим причину последнего отказа
		return this->_error;
	}
	/**
	 * \~russian
	 * @brief Метод извлечения алгоритма подписи
	 *
	 * @return алгоритм подписи из заголовка записи
	 *
	 * \~english
	 * @brief Method of getting the signature algorithm
	 * @return the signature algorithm from the header of the record
	 *
	 * \~
	 */
	jws::algorithm_t jws::Signature::algorithm() const noexcept {
		// Выводим алгоритм подписи
		return this->_algorithm;
	}
	/**
	 * \~russian
	 * @brief Метод извлечения текста заголовка
	 *
	 * @return разобранный текст заголовка JSON
	 *
	 * \~english
	 * @brief Method of getting the text of the header
	 * @return the parsed JSON text of the header
	 *
	 * \~
	 */
	const string & jws::Signature::header() const noexcept {
		// Выводим текст заголовка
		return this->_header;
	}
	/**
	 * \~russian
	 * @brief Метод извлечения полезной нагрузки
	 *
	 * @param result место, в которое помещается декодированная полезная нагрузка
	 * @return       причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of getting the payload
	 * @param result the place the decoded payload is put into
	 * @return       the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::Signature::payload(vector <uint8_t> & result) const noexcept {
		// Очищаем итог
		result.clear();
		// Если запись не разобрана
		if(this->_algorithm == algorithm_t::NONE)
			// Выводим отказ записи
			return error_t::EMPTY;
		// Если полезную нагрузку декодировать не удалось
		if(!unbase64url(this->_payload, result))
			// Выводим отказ записи
			return error_t::STRUCTURE;
		// Выводим успешность извлечения
		return error_t::NONE;
	}
	/**
	 * \~russian
	 * @brief Метод извлечения подписи
	 *
	 * @return подпись в разобранном виде
	 *
	 * \~english
	 * @brief Method of getting the signature
	 * @return the signature in the parsed form
	 *
	 * \~
	 */
	const vector <uint8_t> & jws::Signature::sign() const noexcept {
		// Выводим подпись
		return this->_signature;
	}
	/**
	 * \~russian
	 * @brief Метод проверки подписи записи
	 *
	 * @param key сведения об открытом ключе подписавшей стороны
	 * @return    причина отказа либо error_t::NONE
	 *
	 * \~english
	 * @brief Method of the check of the signature of the record
	 * @param key the info of the public key of the side that signed
	 * @return    the reason of the failure or error_t::NONE
	 *
	 * \~
	 */
	jws::error_t jws::Signature::verify(const keys::key_t & key) const noexcept {
		// Если запись не разобрана
		if(this->_algorithm == algorithm_t::NONE)
			// Выводим отказ записи
			return error_t::EMPTY;
		// Если ключ алгоритму не отвечает
		if(!suitable(this->_algorithm, key.kind, key.oid))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Собираем подписываемую запись ASCII(protected '.' payload)
		string content;
		// Занимаем место под запись
		content.reserve(this->_protected.size + this->_payload.size + 1);
		// Переносим заголовок
		content.assign(reinterpret_cast <const char *> (this->_protected.data), this->_protected.size);
		// Дописываем разделитель
		content += '.';
		// Дописываем полезную нагрузку
		content.append(reinterpret_cast <const char *> (this->_payload.data), this->_payload.size);
		// Проверяем подпись
		return checkSignature(this->_algorithm, key, view_t(reinterpret_cast <const uint8_t *> (content.data()), content.size()), view_t(this->_signature.data(), this->_signature.size()));
	}
	/**
	 * \~russian
	 * @brief Конструктор
	 *
	 * \~english
	 * @brief Constructor
	 *
	 * \~
	 */
	jws::Signature::Signature() noexcept :
		_error(error_t::NONE), _algorithm(algorithm_t::NONE) {}
}
