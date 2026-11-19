/**
 * @file enc.cpp
 * @date 2026-11-19
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
 * @brief Команда enc консольной утилиты a-nts — зашифрование и расшифрование данных
 *
 * @details Команда повторяет устройство openssl enc: первым параметром идёт имя шифра
 *          вида aes-256-cbc, дальше флаги. Ключ и синхропосылка задаются шестнадцатерично
 *          флагами -K и -iv либо выводятся из пароля флагами -k/-pass через EVP_BytesToKey
 *          с солью и заголовком Salted__. Вывод ключа из пароля повторяет openssl байт в
 *          байт: он живёт здесь, в утилите, а не в библиотеке, чей договор остаётся PBES2
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstdlib>
#include <cstring>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "common.hpp"
#include "enc.hpp"
#include "sys/wipe.hpp"
#include "digest/hash.hpp"
#include "digest/pbkdf2.hpp"
#include "entropy/entropy.hpp"
#include "codec/base64.hpp"
#include "cipher/mode.hpp"

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * @brief Вид блочного шифра
	 *
	 */
	enum class cipher_kind_t : uint8_t {
		// Шифр не установлен
		NONE      = 0x00,
		// Шифр AES по FIPS 197
		AES       = 0x01,
		// Шифр SM4 по GB/T 32907-2016
		SM4       = 0x02,
		// Шифр DES и 3DES
		DES       = 0x03
	};
	/**
	 * @brief Режим работы блочного шифра
	 *
	 */
	enum class cipher_mode_t : uint8_t {
		// Режим не установлен
		NONE = 0x00,
		// Режим простой замены (ECB)
		ECB  = 0x01,
		// Режим сцепления блоков (CBC)
		CBC  = 0x02,
		// Режим счётчика (CTR)
		CTR  = 0x03,
		// Режим обратной связи по шифртексту (CFB)
		CFB  = 0x04,
		// Режим обратной связи по выходу (OFB)
		OFB  = 0x05
	};
	/**
	 * @brief Описание выбранного шифра
	 *
	 */
	struct spec_t {
		// Вид блочного шифра
		cipher_kind_t kind;
		// Режим работы блочного шифра
		cipher_mode_t mode;
		// Длина ключа шифрования в байтах
		size_t keySize;
		// Длина блока шифра в байтах
		size_t blockSize;
		/**
		 * @brief Конструктор
		 *
		 */
		spec_t() noexcept : kind(cipher_kind_t::NONE), mode(cipher_mode_t::NONE), keySize(0), blockSize(0) {}
	};

	/**
	 * @brief Функция разбора имени шифра командной строки
	 *
	 * @param name   разбираемое имя шифра
	 * @param result место, в которое помещается описание шифра
	 * @return       признак успешности разбора
	 *
	 */
	bool __nts_cipher_spec__(const char * name, spec_t & result) noexcept {
		// Если имя шифра не передано
		if(name == nullptr)
			// Сообщаем об отказе разбора
			return false;
		// Имя шифра без ведущего дефиса
		const char * label = ((name[0] == '-') ? (name + 1) : name);
		// Длина имени шифра
		const size_t length = ::strlen(label);
		// Если имя шифра пустое
		if(length == 0)
			// Сообщаем об отказе разбора
			return false;
		// Разбираем шифры AES по имени
		if(::strncmp(label, "aes", 3) == 0){
			// Шифр AES выбран
			result.kind = cipher_kind_t::AES;
			// Размер блока AES
			result.blockSize = cipher::AES_BLOCK;
			// Если задан ключ в 128 разрядов
			if(::strstr(label, "128") != nullptr)
				// Длина ключа AES-128
				result.keySize = 16;
			// Иначе если задан ключ в 192 разряда
			else if(::strstr(label, "192") != nullptr)
				// Длина ключа AES-192
				result.keySize = 24;
			// Иначе задан ключ в 256 разрядов
			else result.keySize = 32;
		// Иначе разбираем шифр SM4 по имени
		} else if(::strncmp(label, "sm4", 3) == 0){
			// Шифр SM4 выбран
			result.kind = cipher_kind_t::SM4;
			// Размер блока SM4
			result.blockSize = cipher::SM4_BLOCK;
			// Длина ключа SM4
			result.keySize = cipher::SM4_KEY;
		// Иначе разбираем шифр DES по имени
		} else if(::strncmp(label, "des", 3) == 0){
			// Шифр DES выбран
			result.kind = cipher_kind_t::DES;
			// Размер блока DES
			result.blockSize = cipher::DES_BLOCK;
			// Если задан тройной DES
			if((::strstr(label, "ede3") != nullptr) || (::strstr(label, "3des") != nullptr) || (::strstr(label, "des3") != nullptr))
				// Длина ключа тройного DES
				result.keySize = cipher::DES3_KEY;
			// Иначе задан одиночный DES
			else result.keySize = cipher::DES_KEY;
		// Иначе имя шифра не распознано
		} else return false;
		// Если задан режим простой замены
		if(::strstr(label, "ecb") != nullptr)
			// Режим простой замены выбран
			result.mode = cipher_mode_t::ECB;
		// Иначе если задан режим сцепления блоков
		else if(::strstr(label, "cbc") != nullptr)
			// Режим сцепления блоков выбран
			result.mode = cipher_mode_t::CBC;
		// Иначе если задан режим счётчика
		else if(::strstr(label, "ctr") != nullptr)
			// Режим счётчика выбран
			result.mode = cipher_mode_t::CTR;
		// Иначе если задан режим обратной связи по шифртексту
		else if(::strstr(label, "cfb") != nullptr)
			// Режим обратной связи по шифртексту выбран
			result.mode = cipher_mode_t::CFB;
		// Иначе если задан режим обратной связи по выходу
		else if(::strstr(label, "ofb") != nullptr)
			// Режим обратной связи по выходу выбран
			result.mode = cipher_mode_t::OFB;
		// Иначе режим не распознан
		else return false;
		// Сообщаем об успешности разбора
		return true;
	}

	/**
	 * @brief Функция подбора алгоритма хеширования по имени
	 *
	 * @param name имя алгоритма хеширования, пустое означает MD5
	 * @return     алгоритм хеширования
	 *
	 */
	digest::hash_t __nts_md_kind__(const char * name) noexcept {
		// Если имя алгоритма не задано
		if((name == nullptr) || (name[0] == '\0'))
			// Выводим алгоритм по умолчанию SHA-256
			return digest::hash_t::SHA256;
		// Если задан SHA-1
		if(::strcmp(name, "sha1") == 0)
			// Выводим алгоритм SHA-1
			return digest::hash_t::SHA1;
		// Если задан SHA-224
		if(::strcmp(name, "sha224") == 0)
			// Выводим алгоритм SHA-224
			return digest::hash_t::SHA224;
		// Если задан SHA-256
		if(::strcmp(name, "sha256") == 0)
			// Выводим алгоритм SHA-256
			return digest::hash_t::SHA256;
		// Если задан SHA-384
		if(::strcmp(name, "sha384") == 0)
			// Выводим алгоритм SHA-384
			return digest::hash_t::SHA384;
		// Если задан SHA-512
		if(::strcmp(name, "sha512") == 0)
			// Выводим алгоритм SHA-512
			return digest::hash_t::SHA512;
		// Если задан SM3
		if(::strcmp(name, "sm3") == 0)
			// Выводим алгоритм SM3
			return digest::hash_t::SM3;
		// Если задан MD5
		if(::strcmp(name, "md5") == 0)
			// Выводим алгоритм MD5
			return digest::hash_t::MD5;
		// Выводим алгоритм по умолчанию SHA-256
		return digest::hash_t::SHA256;
	}

	/**
	 * @brief Функция вывода ключа и синхропосылки из пароля по EVP_BytesToKey
	 *
	 * @param algorithm алгоритм хеширования
	 * @param password  пароль вывода ключа
	 * @param salt      соль вывода ключа, пустая без соли
	 * @param keySize   требуемая длина ключа в байтах
	 * @param ivSize    требуемая длина синхропосылки в байтах
	 * @param key       место, в которое помещается ключ
	 * @param iv        место, в которое помещается синхропосылка
	 * @return          признак успешности вывода
	 *
	 */
	bool __nts_bytes_to_key__(const digest::hash_t algorithm, const string & password, const vector <uint8_t> & salt, const size_t keySize, const size_t ivSize, uint8_t * key, uint8_t * iv) noexcept {
		// Длина хеша алгоритма
		const size_t hashSize = digest::length(algorithm);
		// Если длина хеша не задана
		if(hashSize == 0)
			// Сообщаем об отказе вывода
			return false;
		// Выводимые байты ключа и синхропосылки
		vector <uint8_t> derived;
		// Предыдущий хеш цепочки
		vector <uint8_t> previous;
		/**
		 * Накопляем хеши, пока не наберём ключ с синхропосылкой
		 */
		while(derived.size() < (keySize + ivSize)){
			// Область хеширования текущего звена
			vector <uint8_t> item;
			// Приписываем предыдущий хеш цепочки
			item.insert(item.end(), previous.begin(), previous.end());
			// Приписываем пароль
			item.insert(item.end(), password.begin(), password.end());
			// Приписываем соль
			item.insert(item.end(), salt.begin(), salt.end());
			// Область выработанного хеша
			vector <uint8_t> digestBuf(hashSize);
			// Если хеш выработать не удалось
			if(!digest::hash(algorithm, view_t(item.data(), item.size()), digestBuf.data(), digestBuf.size()))
				// Сообщаем об отказе вывода
				return false;
			// Приписываем хеш к выводимым байтам
			derived.insert(derived.end(), digestBuf.begin(), digestBuf.end());
			// Запоминаем хеш предыдущим звеном
			previous = digestBuf;
		}
		// Копируем ключ из выведенных байтов
		::memcpy(key, derived.data(), keySize);
		// Если синхропосылка требуется
		if(ivSize > 0)
			// Копируем синхропосылку из выведенных байтов
			::memcpy(iv, derived.data() + keySize, ivSize);
		// Сообщаем об успешности вывода
		return true;
	}

	/**
	 * @brief Функция дополнения сообщения по PKCS#7
	 *
	 * @param data  дополняемое сообщение
	 * @param block длина блока шифра в байтах
	 * @return      признак успешности дополнения
	 *
	 */
	bool __nts_pad__(vector <uint8_t> & data, const size_t block) noexcept {
		// Длина дополнения до целого блока
		const size_t padSize = (block - (data.size() % block));
		// Если блок нулевой
		if(block == 0)
			// Сообщаем об отказе дополнения
			return false;
		/**
		 * Дописываем байты дополнения
		 */
		for(size_t i = 0; i < padSize; i++)
			// Дописываем очередной байт дополнения
			data.push_back(static_cast <uint8_t> (padSize));
		// Сообщаем об успешности дополнения
		return true;
	}

	/**
	 * @brief Функция снятия дополнения PKCS#7
	 *
	 * @param data  сообщение с дополнением
	 * @param block длина блока шифра в байтах
	 * @return      признак успешности снятия дополнения
	 *
	 */
	bool __nts_unpad__(vector <uint8_t> & data, const size_t block) noexcept {
		// Если сообщение пусто либо не кратно блоку
		if(data.empty() || (block == 0) || ((data.size() % block) != 0))
			// Сообщаем об отказе снятия дополнения
			return false;
		// Длина дополнения из последнего байта
		const size_t padSize = data.back();
		// Если дополнение нулевое либо больше блока либо больше сообщения
		if((padSize == 0) || (padSize > block) || (padSize > data.size()))
			// Сообщаем об отказе снятия дополнения
			return false;
		/**
		 * Сверяем байты дополнения
		 */
		for(size_t i = 0; i < padSize; i++){
			// Если байт дополнения не совпадает
			if(data[data.size() - 1 - i] != static_cast <uint8_t> (padSize))
				// Сообщаем об отказе снятия дополнения
				return false;
		}
		// Убираем дополнение из сообщения
		data.resize(data.size() - padSize);
		// Сообщаем об успешности снятия дополнения
		return true;
	}

	/**
	 * @brief Функция приращения счётчика CTR от старшего байта
	 *
	 * @param counter приращиваемый счётчик
	 * @param size    длина счётчика в байтах
	 *
	 */
	void __nts_counter_inc__(uint8_t * counter, const size_t size) noexcept {
		/**
		 * Приращиваем счётчик от младшего байта к старшему
		 */
		for(size_t i = size; i > 0; i--){
			// Приращиваем очередной байт счётчика
			counter[i - 1]++;
			// Если перенос не возник
			if(counter[i - 1] != 0)
				// Прерываем приращение
				break;
		}
	}

	/**
	 * @brief Функция выполнения шифрования либо расшифрования выбранным режимом
	 *
	 * @param block   базовый алгоритм блочного шифрования
	 * @param mode    режим работы блочного шифра
	 * @param iv      синхропосылка режима, пустая у простой замены
	 * @param decrypt признак расшифрования
	 * @param source  преобразуемое сообщение
	 * @param result  место, в которое помещается итог
	 * @return        признак успешности преобразования
	 *
	 */
	bool __nts_run_mode__(const cipher::block_t & block, const cipher_mode_t mode, const vector <uint8_t> & iv, const bool decrypt, const vector <uint8_t> & source, vector <uint8_t> & result) noexcept {
		// Если сообщение пустое
		if(source.empty()){
			// Очищаем место итога
			result.clear();
			// Сообщаем об успешности пустого преобразования
			return true;
		}
		/**
		 * Выбираем режим работы
		 */
		switch(static_cast <uint8_t> (mode)){
			// Режим простой замены
			case static_cast <uint8_t> (cipher_mode_t::ECB): {
				// Режим простой замены
				cipher::codebook_t codebook;
				// Если режим запустить не удалось
				if(!codebook.start(block)){
					// Сообщаем об отказе запуска режима
					return false;
				}
				// Область итога преобразования
				result.resize(source.size());
				// Если запрошено расшифрование
				if(decrypt)
					// Расшифровываем сообщение
					return codebook.decrypt(view_t(source.data(), source.size()), result.data());
				// Зашифровываем сообщение
				return codebook.encrypt(view_t(source.data(), source.size()), result.data());
			}
			// Режим сцепления блоков
			case static_cast <uint8_t> (cipher_mode_t::CBC): {
				// Режим сцепления блоков
				cipher::chaining_t chaining;
				// Если режим запустить не удалось
				if(!chaining.start(block, view_t(iv.data(), iv.size()))){
					// Сообщаем об отказе запуска режима
					return false;
				}
				// Область итога преобразования
				result.resize(source.size());
				// Если запрошено расшифрование
				if(decrypt)
					// Расшифровываем сообщение
					return chaining.decrypt(view_t(source.data(), source.size()), result.data());
				// Зашифровываем сообщение
				return chaining.encrypt(view_t(source.data(), source.size()), result.data());
			}
			// Режим обратной связи по выходу
			case static_cast <uint8_t> (cipher_mode_t::OFB): {
				// Режим обратной связи по выходу
				cipher::output_t output;
				// Если режим запустить не удалось
				if(!output.start(block, view_t(iv.data(), iv.size()))){
					// Сообщаем об отказе запуска режима
					return false;
				}
				// Область итога преобразования
				result.resize(source.size());
				// Преобразуем сообщение гаммой
				return output.encrypt(view_t(source.data(), source.size()), result.data());
			}
			// Режим обратной связи по шифртексту
			case static_cast <uint8_t> (cipher_mode_t::CFB): {
				// Режим обратной связи по шифртексту
				cipher::feedback_t feedback;
				// Если режим запустить не удалось
				if(!feedback.start(block, view_t(iv.data(), iv.size()))){
					// Сообщаем об отказе запуска режима
					return false;
				}
				// Область итога преобразования
				result.resize(source.size());
				// Если запрошено расшифрование
				if(decrypt)
					// Расшифровываем сообщение
					return feedback.decrypt(view_t(source.data(), source.size()), result.data());
				// Зашифровываем сообщение
				return feedback.encrypt(view_t(source.data(), source.size()), result.data());
			}
			// Режим счётчика
			case static_cast <uint8_t> (cipher_mode_t::CTR): {
				// Счётчик режима CTR
				vector <uint8_t> counter(iv);
				// Область итога преобразования
				result.resize(source.size());
				/**
				 * Перебираем блоки сообщения
				 */
				for(size_t offset = 0; offset < source.size(); offset += block.size){
					// Блок гаммы счётчика
					uint8_t gamma[cipher::MODE_BLOCK];
					// Если блок гаммы выработать не удалось
					if(!block.encrypt(block.cipher, counter.data(), gamma))
						// Сообщаем об отказе выработки гаммы
						return false;
					// Приращиваем счётчик
					__nts_counter_inc__(counter.data(), counter.size());
					// Длина текущего куска сообщения
					const size_t piece = ((source.size() - offset) < block.size ? (source.size() - offset) : block.size);
					/**
					 * Накладываем гамму на кусок сообщения
					 */
					for(size_t i = 0; i < piece; i++)
						// Накладываем очередной байт гаммы
						result[offset + i] = (source[offset + i] ^ gamma[i]);
				}
				// Сообщаем об успешности преобразования
				return true;
			}
			// Прочие режимы
			default:
				// Сообщаем об отказе преобразования
				return false;
		}
	}

	/**
	 * @brief Функция построения базового алгоритма AES и запуска режима
	 *
	 * @param spec    описание выбранного шифра
	 * @param key     ключ шифрования
	 * @param iv      синхропосылка режима
	 * @param decrypt признак расшифрования
	 * @param source  преобразуемое сообщение
	 * @param result  место, в которое помещается итог
	 * @return        признак успешности преобразования
	 *
	 */
	bool __nts_run_aes__(const spec_t & spec, const vector <uint8_t> & key, const vector <uint8_t> & iv, const bool decrypt, const vector <uint8_t> & source, vector <uint8_t> & result) noexcept {
		// Объект блочного шифра AES
		cipher::aes_t aes;
		// Если ключ шифрования установить не удалось
		if(!aes.key(view_t(key.data(), key.size())))
			// Сообщаем об отказе установки ключа
			return false;
		// Описатель базового алгоритма блочного шифрования
		const cipher::block_t block(aes);
		// Преобразуем сообщение выбранным режимом
		return __nts_run_mode__(block, spec.mode, iv, decrypt, source, result);
	}

	/**
	 * @brief Функция построения базового алгоритма SM4 и запуска режима
	 *
	 * @param spec    описание выбранного шифра
	 * @param key     ключ шифрования
	 * @param iv      синхропосылка режима
	 * @param decrypt признак расшифрования
	 * @param source  преобразуемое сообщение
	 * @param result  место, в которое помещается итог
	 * @return        признак успешности преобразования
	 *
	 */
	bool __nts_run_sm4__(const spec_t & spec, const vector <uint8_t> & key, const vector <uint8_t> & iv, const bool decrypt, const vector <uint8_t> & source, vector <uint8_t> & result) noexcept {
		// Объект блочного шифра SM4
		cipher::sm4_t base;
		// Если ключ шифрования установить не удалось
		if(!base.key(view_t(key.data(), key.size())))
			// Сообщаем об отказе установки ключа
			return false;
		// Описатель базового алгоритма блочного шифрования
		const cipher::block_t block(base);
		// Преобразуем сообщение выбранным режимом
		return __nts_run_mode__(block, spec.mode, iv, decrypt, source, result);
	}

	/**
	 * @brief Функция построения базового алгоритма DES и запуска режима
	 *
	 * @param spec    описание выбранного шифра
	 * @param key     ключ шифрования
	 * @param iv      синхропосылка режима
	 * @param decrypt признак расшифрования
	 * @param source  преобразуемое сообщение
	 * @param result  место, в которое помещается итог
	 * @return        признак успешности преобразования
	 *
	 */
	bool __nts_run_des__(const spec_t & spec, const vector <uint8_t> & key, const vector <uint8_t> & iv, const bool decrypt, const vector <uint8_t> & source, vector <uint8_t> & result) noexcept {
		// Объект блочного шифра DES
		cipher::des_t base;
		// Если ключ шифрования установить не удалось
		if(!base.key(view_t(key.data(), key.size())))
			// Сообщаем об отказе установки ключа
			return false;
		// Описатель базового алгоритма блочного шифрования
		const cipher::block_t block(base);
		// Преобразуем сообщение выбранным режимом
		return __nts_run_mode__(block, spec.mode, iv, decrypt, source, result);
	}

	/**
	 * @brief Функция вывода ключа и синхропосылки из пароля с солью
	 *
	 * @param spec     описание выбранного шифра
	 * @param password пароль вывода ключа
	 * @param pbkdf2   признак вывода через PBKDF2
	 * @param md       алгоритм хеширования вывода
	 * @param salt     соль вывода ключа, пустая без соли
	 * @param key      место, в которое помещается ключ
	 * @param iv       место, в которое помещается синхропосылка
	 * @return         признак успешности вывода
	 *
	 */
	bool __nts_derive__(const spec_t & spec, const string & password, const bool pbkdf2, const digest::hash_t md, const vector <uint8_t> & salt, vector <uint8_t> & key, vector <uint8_t> & iv) noexcept {
		// Длина синхропосылки режима
		const size_t ivSize = (spec.mode == cipher_mode_t::ECB ? 0 : spec.blockSize);
		// Отводим место под ключ
		key.resize(spec.keySize);
		// Отводим место под синхропосылку
		iv.resize(ivSize);
		// Если запрошен вывод через PBKDF2
		if(pbkdf2){
			// Область выведенных байтов ключа и синхропосылки
			vector <uint8_t> derived(spec.keySize + ivSize);
			// Если вывод через PBKDF2 не удался
			if(!digest::pbkdf2(md, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(salt.data(), salt.size()), 10000, derived.data(), derived.size()))
				// Сообщаем об отказе вывода
				return false;
			// Копируем ключ из выведенных байтов
			::memcpy(key.data(), derived.data(), key.size());
			// Копируем синхропосылку из выведенных байтов
			::memcpy(iv.data(), derived.data() + key.size(), iv.size());
		// Иначе выводим через EVP_BytesToKey
		} else if(!__nts_bytes_to_key__(md, password, salt, key.size(), iv.size(), key.data(), iv.data()))
			// Сообщаем об отказе вывода
			return false;
		// Сообщаем об успешности вывода
		return true;
	}

	/**
	 * @brief Функция запуска преобразования выбранным шифром
	 *
	 * @param spec    описание выбранного шифра
	 * @param key     ключ шифрования
	 * @param iv      синхропосылка режима
	 * @param decrypt признак расшифрования
	 * @param source  преобразуемое сообщение
	 * @param result  место, в которое помещается итог
	 * @return        признак успешности преобразования
	 *
	 */
	bool __nts_run__(const spec_t & spec, const vector <uint8_t> & key, const vector <uint8_t> & iv, const bool decrypt, const vector <uint8_t> & source, vector <uint8_t> & result) noexcept {
		/**
		 * Выбираем вид шифра
		 */
		switch(static_cast <uint8_t> (spec.kind)){
			// Шифр AES
			case static_cast <uint8_t> (cipher_kind_t::AES):
				// Преобразуем сообщение шифром AES
				return __nts_run_aes__(spec, key, iv, decrypt, source, result);
			// Шифр SM4
			case static_cast <uint8_t> (cipher_kind_t::SM4):
				// Преобразуем сообщение шифром SM4
				return __nts_run_sm4__(spec, key, iv, decrypt, source, result);
			// Шифр DES
			case static_cast <uint8_t> (cipher_kind_t::DES):
				// Преобразуем сообщение шифром DES
				return __nts_run_des__(spec, key, iv, decrypt, source, result);
			// Прочие шифры
			default:
				// Сообщаем об отказе преобразования
				return false;
		}
	}
};

/**
 * @brief Функция зашифрования и расшифрования данных блочным шифром
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::enc(const int argc, const char * const argv[]) noexcept {
	// Описание выбранного шифра
	spec_t spec;
	// Имя выбранного шифра
	const char * cipherName = nullptr;
	/**
	 * Перебираем параметры команды в поисках имени шифра
	 */
	for(int i = 2; i < argc; i++){
		// Пробуем разобрать очередной параметр как имя шифра
		if(__nts_cipher_spec__(argv[i], spec)){
			// Запоминаем имя шифра
			cipherName = argv[i];
			// Прерываем перебор
			break;
		}
	}
	// Если имя шифра разобрать не удалось
	if(!__nts_cipher_spec__(cipherName, spec)){
		// Печатаем подсказку команды
		cout << "применение: a-nts enc -aes-256-cbc [-d] [-K ключ] [-iv синхропосылка] [-k пароль] [-salt|-nosalt] [-pbkdf2] [-a] [-p] [-in файл] [-out файл]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Признак расшифрования
	const bool decrypt = cli::flag(argc, argv, "-d");
	// Признак вывода через PBKDF2
	const bool pbkdf2 = cli::flag(argc, argv, "-pbkdf2");
	// Признак отказа от соли
	const bool noSalt = cli::flag(argc, argv, "-nosalt");
	// Признак кодирования base64
	const bool base64 = cli::flag(argc, argv, "-a");
	// Признак печати ключа и синхропосылки
	const bool printKey = cli::flag(argc, argv, "-p");
	// Признак вывода base64 одной строкой
	const bool single = cli::flag(argc, argv, "-A");
	// Признак отказа от дополнения
	const bool noPad = cli::flag(argc, argv, "-nopad");
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Ключ шифрования
	vector <uint8_t> key;
	// Синхропосылка режима
	vector <uint8_t> iv;
	// Соль вывода ключа
	vector <uint8_t> salt;
	// Шестнадцатеричный ключ командной строки
	const char * keyHex = cli::value(argc, argv, "-K");
	// Шестнадцатеричная синхропосылка командной строки
	const char * ivHex = cli::value(argc, argv, "-iv");
	// Пароль вывода ключа
	const char * password = cli::value(argc, argv, "-k");
	// Шестнадцатеричная соль командной строки
	const char * saltHex = cli::value(argc, argv, "-S");
	// Алгоритм хеширования вывода ключа
	const digest::hash_t digestKind = __nts_md_kind__(cli::value(argc, argv, "-md"));
	// Признак вывода ключа из пароля
	const bool byPassword = ((keyHex == nullptr) || (keyHex[0] == '\0'));
	// Признак явно заданной соли
	const bool explicitSalt = ((saltHex != nullptr) && (saltHex[0] != '\0'));
	// Если задан шестнадцатеричный ключ
	if(!byPassword){
		// Если ключ перевести не удалось
		if(!cli::unhex(keyHex, key)){
			// Печатаем сообщение об отказе перевода ключа
			cout << "Перевести ключ из шестнадцатеричной записи не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если длина ключа не совпадает с требуемой шифром
		if(key.size() != spec.keySize){
			// Печатаем сообщение о неверной длине ключа
			cout << "Длина ключа не совпадает с требуемой шифром" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если задана шестнадцатеричная синхропосылка
		if((ivHex != nullptr) && (ivHex[0] != '\0')){
			// Если синхропосылку перевести не удалось
			if(!cli::unhex(ivHex, iv)){
				// Печатаем сообщение об отказе перевода синхропосылки
				cout << "Перевести синхропосылку из шестнадцатеричной записи не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		// Иначе заполняем синхропосылку нулями
		} else iv.assign(spec.mode == cipher_mode_t::ECB ? 0 : spec.blockSize, 0);
	// Иначе выводим ключ из пароля
	} else {
		// Если пароль не задан
		if((password == nullptr) || (password[0] == '\0')){
			// Печатаем сообщение об отсутствии ключа
			cout << "Задайте ключ флагом -K либо пароль флагом -k" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если задана явная соль
		if(explicitSalt){
			// Если соль перевести из шестнадцатеричной записи не удалось
			if(!cli::unhex(saltHex, salt)){
				// Печатаем сообщение об отказе перевода соли
				cout << "Перевести соль из шестнадцатеричной записи не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
	}
	// Если вывод ключа запрошен сразу: соль либо явная, либо придёт из заголовка не позже
	if(byPassword && !(decrypt && !noSalt && !explicitSalt)){
		// Если соль не запрещена, не задана явно и пустая, вырабатываем её
		if(!noSalt && !explicitSalt && salt.empty()){
			// Отводим место под соль
			salt.resize(8);
			// Если случайные байты выработать не удалось
			if(!entropy::bytes(salt.data(), salt.size())){
				// Печатаем сообщение об отказе выработки соли
				cout << "Выработать соль не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
		// Если вывод ключа не удался
		if(!__nts_derive__(spec, string(password), pbkdf2, digestKind, noSalt ? vector <uint8_t> () : salt, key, iv)){
			// Печатаем сообщение об отказе вывода ключа
			cout << "Вывести ключ из пароля не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Если печать ключа запрошена
	if(printKey){
		// Печатаем ключ
		cout << "key=" << cli::hex(key.data(), key.size()) << endl;
		// Печатаем синхропосылку
		cout << "iv=" << cli::hex(iv.data(), iv.size()) << endl;
	}
	// Область прочитанного сообщения
	vector <uint8_t> message;
	// Если ввод прочитать не удалось
	if(!cli::readBytes(in, message)){
		// Печатаем сообщение об отказе чтения
		cout << "Прочитать ввод не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошено кодирование base64 и расшифрование
	if(base64 && decrypt){
		// Область раскодированного сообщения
		vector <uint8_t> plain;
		// Если сообщение раскодировать не удалось
		if(!codec::decode(view_t(message.data(), message.size()), plain, codec::alphabet_t::STANDARD, true)){
			// Печатаем сообщение об отказе раскодирования
			cout << "Раскодировать base64 не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Заменяем сообщение раскодированным
		message = plain;
	}
	// Если соль не запрещена, не задана явно и расшифрование с паролем
	if(!noSalt && !explicitSalt && decrypt && byPassword){
		// Если сообщение короче заголовка с солью
		if(message.size() < 16){
			// Печатаем сообщение об отказе разбора заголовка
			cout << "Разобрать заголовок соли не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если заголовок не совпадает
		if(::memcmp(message.data(), "Salted__", 8) != 0){
			// Печатаем сообщение об отказе разбора заголовка
			cout << "Разобрать заголовок соли не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Копируем соль из сообщения
		salt.assign(message.begin() + 8, message.begin() + 16);
		// Убираем заголовок с солью из сообщения
		message.erase(message.begin(), message.begin() + 16);
		// Если вывод ключа из соли не удался
		if(!__nts_derive__(spec, string(password), pbkdf2, digestKind, salt, key, iv)){
			// Печатаем сообщение об отказе вывода ключа
			cout << "Вывести ключ из пароля не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Признак потокового режима без дополнения
	const bool streaming = ((spec.mode == cipher_mode_t::CTR) || (spec.mode == cipher_mode_t::CFB) || (spec.mode == cipher_mode_t::OFB));
	// Если запрошено зашифрование, режим не потоковый и дополнение не запрещено
	if(!decrypt && !streaming && !noPad){
		// Если дополнить сообщение не удалось
		if(!__nts_pad__(message, spec.blockSize)){
			// Печатаем сообщение об отказе дополнения
			cout << "Дополнить сообщение не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Область преобразованного сообщения
	vector <uint8_t> ciphertext;
	// Если преобразование не удалось
	if(!__nts_run__(spec, key, iv, decrypt, message, ciphertext)){
		// Печатаем сообщение об отказе преобразования
		cout << "Преобразовать сообщение не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошено расшифрование, режим не потоковый и дополнение не запрещено
	if(decrypt && !streaming && !noPad){
		// Если снять дополнение не удалось
		if(!__nts_unpad__(ciphertext, spec.blockSize)){
			// Печатаем сообщение об отказе снятия дополнения
			cout << "Снять дополнение сообщения не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Если соль не запрещена, не задана явно и зашифрование с паролем
	if(!noSalt && !explicitSalt && !decrypt && byPassword){
		// Заголовок вывода ключа openssl
		const uint8_t header[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
		// Сообщение с заголовком и солью
		vector <uint8_t> framed;
		// Приписываем заголовок
		framed.insert(framed.end(), header, header + 8);
		// Приписываем соль
		framed.insert(framed.end(), salt.begin(), salt.end());
		// Приписываем шифртекст
		framed.insert(framed.end(), ciphertext.begin(), ciphertext.end());
		// Заменяем шифртекст обрамлённым
		ciphertext = framed;
	}
	// Если запрошено кодирование base64 и зашифрование
	if(base64 && !decrypt){
		// Строка кодирования
		string text;
		// Если сообщение закодировать не удалось
		if(!codec::encode(view_t(ciphertext.data(), ciphertext.size()), text)){
			// Печатаем сообщение об отказе кодирования
			cout << "Закодировать в base64 не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если вывод одной строкой не требуется
		if(!single){
			// Строка с разбиением на строки
			string wrapped;
			/**
			 * Разбиваем кодированный текст на строки
			 */
			for(size_t i = 0; i < text.size(); i += 64){
				// Приписываем очередную строку
				wrapped.append(text, i, 64);
				// Дописываем перевод строки
				wrapped.push_back('\n');
			}
			// Заменяем текст разбитым
			text = wrapped;
		}
		// Если итог записать не удалось
		if(!cli::writeBytes(out, reinterpret_cast <const uint8_t *> (text.data()), text.size())){
			// Печатаем сообщение об отказе записи
			cout << "Записать итог не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	// Иначе выводим сообщение как есть
	} else if(!cli::writeBytes(out, ciphertext.data(), ciphertext.size())){
		// Печатаем сообщение об отказе записи
		cout << "Записать итог не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}
