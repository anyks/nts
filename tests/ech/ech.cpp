/**
 * @file ech.cpp
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
 * @brief Проверки модуля зашифрованного приветствия клиента ECH: конфигурации BoringSSL байт в
 *        байт, расширение, кодирование внутреннего приветствия, восстановление, заполнение,
 *        добавочные данные, подтверждение принятия и нехватка памяти
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <ech/ech.hpp>
#include <hpke/hpke.hpp>
#include <hello/hello.hpp>
#include <alert/alert.hpp>
#include <digest/hash.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>
#include <trust/trust.hpp>

/**
 * Подключаем заголовочные файлы проверок
 */
#include <starve.hpp>
#include <openssl.hpp>
#include <gtest/gtest.h>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Путь к набору образцов
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла
	 *
	 */
	static vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл на чтение
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое
		return result;
	}
	/**
	 * @brief Метод составления внутреннего приветствия проверок
	 *
	 * @param bodies накопители тел расширений: живут у зовущего
	 * @param result приветствие с расширениями: имя, группы, схемы, издания, доля, ECH внутреннего вида, протоколы
	 * @return       результат составления
	 *
	 */
	static bool innerhello(vector <vector <uint8_t>> & bodies, hello::client_t & result) noexcept {
		// Сбрасываем приветствие
		result = hello::client_t();
		// Издание приветствия
		result.version = 0x0303;
		// Случайное значение
		::memset(result.random, 0x5A, sizeof(result.random));
		// Опознаватель связи внутреннего приветствия: копируется из внешнего
		result.session.assign(32, 0x33);
		// Наборы
		result.suites = {0x1301, 0x1303};
		// Способ сжатия
		result.methods.push_back(0);
		// Занимаем место под тела
		bodies.assign(7, vector <uint8_t> ());
		// Имя узла
		static const char HOST[] = "secret.example";
		// Ключ доли
		static const uint8_t KEY[32] = {0x11};
		// Составляем тела
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> (HOST), sizeof(HOST) - 1), bodies[0]) != extension::error_t::NONE) return false;
		if(extension::groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1}, bodies[1]) != extension::error_t::NONE) return false;
		if(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, bodies[2]) != extension::error_t::NONE) return false;
		if(extension::versions(vector <uint16_t> {0x0304}, bodies[3]) != extension::error_t::NONE) return false;
		if(extension::shares(vector <extension::share_t> {extension::share_t(extension::group_t::X25519, view_t(KEY, 32))}, bodies[4]) != extension::error_t::NONE) return false;
		// Расширение ECH внутреннего вида
		ech::hello_t inner;
		// Внутренний вид
		inner.inner = true;
		// Составляем расширение
		if(ech::build(inner, bodies[5]) != ech::error_t::NONE) return false;
		if(extension::protocols(vector <string> {"h2"}, bodies[6]) != extension::error_t::NONE) return false;
		// Расширения в порядке: имя, группы, схемы, издания, доля, ECH, протоколы
		result.extensions.push_back(hello::extension_t(0x0000, view_t(bodies[0].data(), bodies[0].size())));
		result.extensions.push_back(hello::extension_t(0x000A, view_t(bodies[1].data(), bodies[1].size())));
		result.extensions.push_back(hello::extension_t(0x000D, view_t(bodies[2].data(), bodies[2].size())));
		result.extensions.push_back(hello::extension_t(0x002B, view_t(bodies[3].data(), bodies[3].size())));
		result.extensions.push_back(hello::extension_t(0x0033, view_t(bodies[4].data(), bodies[4].size())));
		result.extensions.push_back(hello::extension_t(ech::ECH_EXTENSION, view_t(bodies[5].data(), bodies[5].size())));
		result.extensions.push_back(hello::extension_t(0x0010, view_t(bodies[6].data(), bodies[6].size())));
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод составления внешнего приветствия проверок из внутреннего
	 *
	 * @param inner   внутреннее приветствие
	 * @param bodies  накопители тел расширений внешнего: живут у зовущего
	 * @param payload шифротекст расширения ECH
	 * @param result  внешнее приветствие
	 * @return        результат составления
	 *
	 */
	static bool outerhello(const hello::client_t & inner, vector <vector <uint8_t>> & bodies, const vector <uint8_t> & payload, hello::client_t & result) noexcept {
		// Сбрасываем приветствие
		result = hello::client_t();
		// Издание
		result.version = inner.version;
		// Случайное значение внешнего приветствия своё
		::memset(result.random, 0xA5, sizeof(result.random));
		// Опознаватель связи тот же
		result.session = inner.session;
		// Наборы те же
		result.suites = inner.suites;
		// Способ сжатия
		result.methods = inner.methods;
		// Занимаем место под тела
		bodies.assign(2, vector <uint8_t> ());
		// Публичное имя
		static const char PUBLIC[] = "public.example";
		// Составляем имя
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> (PUBLIC), sizeof(PUBLIC) - 1), bodies[0]) != extension::error_t::NONE) return false;
		// Расширение ECH внешнего вида
		ech::hello_t outer;
		// Набор
		outer.suite = ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM);
		// Опознаватель
		outer.id = 7;
		// Инкапсулированный ключ
		outer.enc.assign(32, 0x77);
		// Шифротекст
		outer.payload = payload;
		// Составляем расширение
		if(ech::build(outer, bodies[1]) != ech::error_t::NONE) return false;
		// Расширения внешнего: публичное имя, группы, схемы, издания, доля (те же тела), ECH, протоколы
		result.extensions.push_back(hello::extension_t(0x0000, view_t(bodies[0].data(), bodies[0].size())));
		result.extensions.push_back(inner.extensions[1]);
		result.extensions.push_back(inner.extensions[2]);
		result.extensions.push_back(inner.extensions[3]);
		result.extensions.push_back(inner.extensions[4]);
		result.extensions.push_back(hello::extension_t(ech::ECH_EXTENSION, view_t(bodies[1].data(), bodies[1].size())));
		result.extensions.push_back(inner.extensions[6]);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность
	 * @return       результат составления
	 *
	 */
	static bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ
			return false;
		// Сбрасываем цепочку
		result.chain.clear();
		// Выводим итог разбора цепочки
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак передачи
		bool moved = false;
		/**
		 * Выполняем перехват нехватки памяти
		 */
		try {
			// Байты клиента
			view_t data = client.output();
			// Если клиенту есть что отправить
			if(data.size > 0){
				// Переносим байты
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем байты с накопителя
				client.consume(buffer.size());
				// Подаём байты серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем передачу
				moved = true;
			}
			// Байты сервера
			data = server.output();
			// Если серверу есть что отправить
			if(data.size > 0){
				// Переносим байты
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем байты с накопителя
				server.consume(buffer.size());
				// Подаём байты клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем передачу
				moved = true;
			}
		/**
		 * Если памяти не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отсутствие передачи
			return false;
		}
		// Выводим признак передачи
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	static void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов, пока сторонам есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу
			continue;
	}
	/**
	 * @brief Метод снятия профиля приветствия с отправляемых байтов клиента
	 *
	 * @param client связь стороны клиента
	 * @param result профиль
	 * @return       результат снятия
	 *
	 */
	static bool captured(client::context_t & client, fingerprint::profile_t & result) noexcept {
		// Выводим итог разбора отправляемых байтов
		return (fingerprint::parse(client.output(), result) == fingerprint::error_t::NONE);
	}
	/**
	 * @brief Метод поиска инструмента bssl BoringSSL
	 *
	 * @return путь к инструменту либо пусто
	 *
	 */
	static std::string bssltool() noexcept {
		// Путь из окружения
		const char * given = ::getenv("ANTS_BSSL");
		// Если путь задан окружением
		if((given != nullptr) && (::access(given, X_OK) == 0))
			// Выводим путь
			return std::string(given);
		// Если инструмент в пути поиска
		if(shell("command -v bssl >/dev/null 2>&1") == 0)
			// Выводим имя
			return std::string("bssl");
		// Выводим отсутствие
		return std::string();
	}
	/**
	 * @brief Метод настройки сторон под ECH: сервер с ключом BoringSSL, клиент с перечнем BoringSSL
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param foreign признак того, что сервер ведёт свой ключ, а не ключ перечня клиента
	 * @return       результат настройки
	 *
	 */
	static bool arranged(client::context_t & client, server::context_t & server, const bool foreign) noexcept {
		// Подлинность сервера
		context::credential_t credential;
		// Составляем подлинность
		if(!identity("ec256", credential)){
			// Сообщаем о шаге
			ADD_FAILURE() << "подлинность не составлена";
			// Выводим отказ
			return false;
		}
		// Ключ и перечень BoringSSL
		const vector <uint8_t> key = corpus("ech/bssl.key"), list = corpus("ech/bssl.list");
		// Если образцы не прочитаны
		if(key.empty() || list.empty()){
			// Сообщаем о шаге
			ADD_FAILURE() << "образцы не прочитаны";
			// Выводим отказ
			return false;
		}
		// Подлинность сервера
		server.credential(credential);
		// Прикладные протоколы сервера
		server.protocols(vector <string> {"h2"});
		// Отказ установки ключа сервера: из перечня либо свой порождённый
		const context::error_t keyed = server.ech((foreign ? vector <uint8_t> () : key), "public.example", 7, 64);
		// Если ключ не поставлен
		if(keyed != context::error_t::NONE){
			// Сообщаем о шаге
			ADD_FAILURE() << "ключ сервера не поставлен: " << static_cast <int> (keyed);
			// Выводим отказ
			return false;
		}
		// Имя узла у клиента: скрываемое
		client.name("secret.example");
		// Прикладные протоколы клиента
		client.protocols(vector <string> {"h2"});
		// Отказ установки конфигураций клиента
		const context::error_t configured = client.ech(list);
		// Если конфигурации не поставлены
		if(configured != context::error_t::NONE)
			// Сообщаем о шаге
			ADD_FAILURE() << "конфигурации клиента не поставлены: " << static_cast <int> (configured);
		// Выводим итог
		return (configured == context::error_t::NONE);
	}
}

/**
 * Проверка разбора конфигураций BoringSSL байт в байт и ключа против открытой части
 */
TEST(EchTest, Boringssl){
	// Образцы BoringSSL
	const vector <uint8_t> list = corpus("ech/bssl.list"), single = corpus("ech/bssl.config"), key = corpus("ech/bssl.key");
	// Проверяем чтение образцов
	ASSERT_FALSE(list.empty() || single.empty() || key.empty());
	// Перечень конфигураций
	vector <ech::config_t> configs;
	// Разбираем перечень
	ASSERT_EQ(ech::parse(view_t(list.data(), list.size()), configs), ech::error_t::NONE);
	// Одна конфигурация
	ASSERT_EQ(configs.size(), static_cast <size_t> (1));
	// Конфигурация
	const ech::config_t & config = configs[0];
	// Проверяем поля: bssl generate-ech -config-id 7 -max-name-length 64 -public-name public.example
	EXPECT_EQ(config.id, 7);
	EXPECT_EQ(config.kem, hpke::kem_t::X25519_HKDF_SHA256);
	EXPECT_EQ(config.key.size(), static_cast <size_t> (32));
	EXPECT_EQ(config.length, 64);
	EXPECT_EQ(config.name, "public.example");
	EXPECT_TRUE(config.extensions.empty());
	// Наборы BoringSSL: AES-128-GCM и ChaCha20-Poly1305 на HKDF-SHA256
	ASSERT_EQ(config.suites.size(), static_cast <size_t> (2));
	EXPECT_EQ(config.suites[0].kdf, hpke::kdf_t::HKDF_SHA256);
	EXPECT_EQ(config.suites[0].aead, hpke::aead_t::AES_128_GCM);
	EXPECT_EQ(config.suites[1].aead, hpke::aead_t::CHACHA20_POLY1305);
	// Конфигурация как записана совпадает с одиночным образцом
	EXPECT_EQ(config.raw, single);
	// Одиночная конфигурация разбирается сама по себе
	ech::config_t alone;
	// Разбираем
	ASSERT_EQ(ech::parse(view_t(single.data(), single.size()), alone), ech::error_t::NONE);
	// Проверяем совпадение
	EXPECT_EQ(alone.raw, config.raw);
	EXPECT_EQ(alone.name, config.name);
	// Составление перечня даёт те же байты
	vector <uint8_t> rebuilt;
	// Составляем перечень
	ASSERT_EQ(ech::build(configs, rebuilt), ech::error_t::NONE);
	// Проверяем байт в байт
	EXPECT_EQ(rebuilt, list);
	// Составление конфигурации даёт те же байты
	rebuilt.clear();
	// Составляем конфигурацию
	ASSERT_EQ(ech::build(config, rebuilt), ech::error_t::NONE);
	// Проверяем байт в байт
	EXPECT_EQ(rebuilt, single);
	// Секретный ключ BoringSSL даёт ту же открытую часть
	hpke::key_t secret;
	// Устанавливаем секрет
	ASSERT_EQ(secret.set(hpke::kem_t::X25519_HKDF_SHA256, view_t(key.data(), key.size())), hpke::error_t::NONE);
	// Открытая часть
	const view_t point = secret.point();
	// Проверяем совпадение
	ASSERT_EQ(point.size, config.key.size());
	EXPECT_EQ(::memcmp(point.data, config.key.data(), point.size), 0);
	// Привязка HPKE
	vector <uint8_t> binding;
	// Составляем привязку
	ASSERT_EQ(ech::binding(view_t(config.raw.data(), config.raw.size()), binding), ech::error_t::NONE);
	// Проверяем привязку: «tls ech», ноль, конфигурация
	ASSERT_EQ(binding.size(), config.raw.size() + 8);
	EXPECT_EQ(::memcmp(binding.data(), "tls ech\0", 8), 0);
	EXPECT_EQ(::memcmp(binding.data() + 8, config.raw.data(), config.raw.size()), 0);
	// Наборы конфигурации признаются
	EXPECT_TRUE(ech::supported(config.kem, config.suites[0]));
	EXPECT_TRUE(ech::supported(config.kem, config.suites[1]));
	EXPECT_FALSE(ech::supported(config.kem, ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::EXPORT_ONLY)));
	EXPECT_FALSE(ech::supported(static_cast <hpke::kem_t> (0x0010), config.suites[0]));
}

/**
 * Проверка отказов разбора конфигураций
 */
TEST(EchTest, Configs){
	// Образец перечня
	const vector <uint8_t> list = corpus("ech/bssl.list");
	// Проверяем чтение
	ASSERT_FALSE(list.empty());
	// Перечень конфигураций
	vector <ech::config_t> configs;
	/**
	 * Выполняем перебор длин усечения
	 */
	for(size_t size = 0; size < list.size(); size++)
		// Усечённый перечень не разбирается
		EXPECT_NE(ech::parse(view_t(list.data(), size), configs), ech::error_t::NONE) << size;
	// Перечень с хвостом отвергается
	vector <uint8_t> longer = list;
	// Дописываем байт
	longer.push_back(0);
	// Проверяем отказ
	EXPECT_EQ(ech::parse(view_t(longer.data(), longer.size()), configs), ech::error_t::FORMAT);
	// Перечень чужого издания: конфигурация пропускается, перечень пуст
	vector <uint8_t> alien = list;
	// Портим издание
	alien[2] = 0xFE; alien[3] = 0x0C;
	// Проверяем отказ издания
	EXPECT_EQ(ech::parse(view_t(alien.data(), alien.size()), configs), ech::error_t::VERSION);
	EXPECT_TRUE(configs.empty());
	// Перечень из чужой и своей конфигураций: своя берётся
	vector <uint8_t> mixed;
	// Длина перечня из двух конфигураций
	const size_t length = ((list.size() - 2) * 2);
	// Дописываем длину
	mixed.push_back(static_cast <uint8_t> (length >> 8)); mixed.push_back(static_cast <uint8_t> (length));
	// Дописываем чужую конфигурацию
	mixed.insert(mixed.end(), alien.begin() + 2, alien.end());
	// Дописываем свою конфигурацию
	mixed.insert(mixed.end(), list.begin() + 2, list.end());
	// Разбираем перечень
	ASSERT_EQ(ech::parse(view_t(mixed.data(), mixed.size()), configs), ech::error_t::NONE);
	// Одна своя конфигурация
	EXPECT_EQ(configs.size(), static_cast <size_t> (1));
	EXPECT_EQ(configs[0].id, 7);
	// Конфигурация без признаваемых наборов пропускается
	ech::config_t config = configs[0];
	// Наборы чужие
	config.suites = vector <ech::suite_t> {ech::suite_t(static_cast <hpke::kdf_t> (0x0010), hpke::aead_t::AES_128_GCM)};
	// Перечень из такой конфигурации
	vector <uint8_t> unusable;
	// Составляем перечень
	ASSERT_EQ(ech::build(vector <ech::config_t> {config}, unusable), ech::error_t::NONE);
	// Проверяем отказ издания
	EXPECT_EQ(ech::parse(view_t(unusable.data(), unusable.size()), configs), ech::error_t::VERSION);
	// Пустые поля не составляются
	config = configs.empty() ? ech::config_t() : configs[0];
	// Разбираем годный перечень заново
	ASSERT_EQ(ech::parse(view_t(list.data(), list.size()), configs), ech::error_t::NONE);
	config = configs[0];
	// Пустое имя
	config.name.clear();
	EXPECT_EQ(ech::build(config, unusable), ech::error_t::EMPTY);
	// Слишком длинное имя
	config.name.assign(256, 'a');
	EXPECT_EQ(ech::build(config, unusable), ech::error_t::LENGTH);
	// Пустой ключ
	config = configs[0]; config.key.clear();
	EXPECT_EQ(ech::build(config, unusable), ech::error_t::EMPTY);
	// Пустой перечень наборов
	config = configs[0]; config.suites.clear();
	EXPECT_EQ(ech::build(config, unusable), ech::error_t::EMPTY);
	// Пустой перечень конфигураций
	EXPECT_EQ(ech::build(vector <ech::config_t> (), unusable), ech::error_t::EMPTY);
	// Одиночная конфигурация с хвостом отвергается
	ech::config_t alone;
	EXPECT_EQ(ech::parse(view_t(longer.data() + 2, longer.size() - 2), alone), ech::error_t::FORMAT);
	// Одиночная конфигурация чужого издания отвергается
	EXPECT_EQ(ech::parse(view_t(alien.data() + 2, alien.size() - 2), alone), ech::error_t::VERSION);
}

/**
 * Проверка расширения encrypted_client_hello
 */
TEST(EchTest, Extension){
	// Расширение внешнего вида
	ech::hello_t outer;
	// Набор
	outer.suite = ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::CHACHA20_POLY1305);
	// Опознаватель
	outer.id = 0xAB;
	// Инкапсулированный ключ
	outer.enc.assign(32, 0x12);
	// Шифротекст
	outer.payload.assign(100, 0x34);
	// Тело расширения
	vector <uint8_t> body;
	// Составляем тело
	ASSERT_EQ(ech::build(outer, body), ech::error_t::NONE);
	// Проверяем длину: вид, набор, опознаватель, длины и поля
	EXPECT_EQ(body.size(), static_cast <size_t> (1 + 4 + 1 + 2 + 32 + 2 + 100));
	EXPECT_EQ(body[0], 0x00);
	// Разобранное расширение
	ech::hello_t parsed;
	// Разбираем тело
	ASSERT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::NONE);
	// Проверяем поля
	EXPECT_FALSE(parsed.inner);
	EXPECT_EQ(parsed.id, 0xAB);
	EXPECT_EQ(parsed.suite.kdf, hpke::kdf_t::HKDF_SHA256);
	EXPECT_EQ(parsed.suite.aead, hpke::aead_t::CHACHA20_POLY1305);
	EXPECT_EQ(parsed.enc, outer.enc);
	EXPECT_EQ(parsed.payload, outer.payload);
	/**
	 * Выполняем перебор длин усечения
	 */
	for(size_t size = 0; size < body.size(); size++)
		// Усечённое тело не разбирается
		EXPECT_NE(ech::parse(view_t(body.data(), size), parsed), ech::error_t::NONE) << size;
	// Тело с хвостом отвергается
	body.push_back(0);
	EXPECT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::FORMAT);
	// Повторное приветствие: инкапсулированный ключ пуст
	outer.enc.clear();
	body.clear();
	ASSERT_EQ(ech::build(outer, body), ech::error_t::NONE);
	ASSERT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::NONE);
	EXPECT_TRUE(parsed.enc.empty());
	// Пустой шифротекст не составляется
	outer.payload.clear();
	EXPECT_EQ(ech::build(outer, body), ech::error_t::EMPTY);
	// Внутренний вид: один байт
	ech::hello_t inner;
	inner.inner = true;
	body.clear();
	ASSERT_EQ(ech::build(inner, body), ech::error_t::NONE);
	EXPECT_EQ(body, vector <uint8_t> {0x01});
	ASSERT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::NONE);
	EXPECT_TRUE(parsed.inner);
	// Внутренний вид с хвостом отвергается
	body.push_back(0);
	EXPECT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::FORMAT);
	// Неведомый вид отвергается
	body = {0x02};
	EXPECT_EQ(ech::parse(view_t(body.data(), body.size()), parsed), ech::error_t::FORMAT);
	// Пустое тело
	EXPECT_EQ(ech::parse(view_t(nullptr, 0), parsed), ech::error_t::HUNGRY);
}

/**
 * Проверка кодирования и восстановления внутреннего приветствия со сжатием
 */
TEST(EchTest, Encoding){
	// Тела расширений
	vector <vector <uint8_t>> bodies, outers;
	// Внутреннее приветствие
	hello::client_t inner;
	// Составляем внутреннее приветствие
	ASSERT_TRUE(innerhello(bodies, inner));
	// Закодированное приветствие без сжатия и заполнения
	vector <uint8_t> plain;
	// Кодируем
	ASSERT_EQ(ech::encode(inner, vector <uint16_t> (), 0, plain), ech::error_t::NONE);
	// Закодированное приветствие разбирается как приветствие без опознавателя
	hello::client_t parsed;
	ASSERT_EQ(hello::parse(view_t(plain.data(), plain.size()), parsed), hello::error_t::NONE);
	EXPECT_TRUE(parsed.session.empty());
	EXPECT_EQ(parsed.extensions.size(), inner.extensions.size());
	// Кодирование со сжатием групп, схем, изданий и доли и заполнением
	vector <uint8_t> compact;
	// Вынесенные расширения подряд
	const vector <uint16_t> outsourced = {0x000A, 0x000D, 0x002B, 0x0033};
	// Кодируем
	ASSERT_EQ(ech::encode(inner, outsourced, 17, compact), ech::error_t::NONE);
	// Сжатое короче и кончается нулями заполнения
	EXPECT_LT(compact.size(), plain.size());
	/**
	 * Выполняем перебор байтов заполнения
	 */
	for(size_t i = compact.size() - 17; i < compact.size(); i++)
		// Проверяем нуль
		EXPECT_EQ(compact[i], 0);
	// Сжатое разбирается с ech_outer_extensions на месте групп
	ASSERT_EQ(hello::parse(view_t(compact.data(), compact.size() - 17), parsed), hello::error_t::NONE);
	ASSERT_EQ(parsed.extensions.size(), static_cast <size_t> (4));
	EXPECT_EQ(parsed.extensions[0].type, 0x0000);
	EXPECT_EQ(parsed.extensions[1].type, ech::ECH_OUTER);
	EXPECT_EQ(parsed.extensions[2].type, ech::ECH_EXTENSION);
	EXPECT_EQ(parsed.extensions[3].type, 0x0010);
	// Тело ссылок: длина 8 и четыре вида
	EXPECT_EQ(parsed.extensions[1].data.size, static_cast <size_t> (9));
	EXPECT_EQ(parsed.extensions[1].data.data[0], 8);
	// Внешнее приветствие
	hello::client_t outer;
	// Составляем внешнее приветствие
	ASSERT_TRUE(outerhello(inner, outers, compact, outer));
	// Восстановленное тело
	vector <uint8_t> restored;
	// Восстанавливаем
	ASSERT_EQ(ech::decode(view_t(compact.data(), compact.size()), outer, restored), ech::error_t::NONE);
	// Ожидаемое тело: внутреннее приветствие как есть
	vector <uint8_t> expected;
	// Составляем
	ASSERT_EQ(hello::build(inner, expected), hello::error_t::NONE);
	// Проверяем байт в байт
	EXPECT_EQ(restored, expected);
	// Без сжатия восстанавливается то же
	ASSERT_EQ(ech::decode(view_t(plain.data(), plain.size()), outer, restored), ech::error_t::NONE);
	EXPECT_EQ(restored, expected);
	// Вынесенные не подряд: имя и издания
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0x0000, 0x002B}, 0, compact), ech::error_t::OUTER);
	// Вынесенные не в порядке перечня
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0x000D, 0x000A}, 0, compact), ech::error_t::OUTER);
	// Вынести само ECH нельзя
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {ech::ECH_EXTENSION}, 0, compact), ech::error_t::OUTER);
	// Отсутствующее во внутреннем
	EXPECT_EQ(ech::encode(inner, vector <uint16_t> {0x0015}, 0, compact), ech::error_t::OUTER);
}

/**
 * Проверка отказов восстановления по разделу 7.1 RFC 9849
 */
TEST(EchTest, Restoring){
	// Тела расширений
	vector <vector <uint8_t>> bodies, outers;
	// Приветствия
	hello::client_t inner, outer;
	// Составляем внутреннее приветствие
	ASSERT_TRUE(innerhello(bodies, inner));
	// Закодированное со сжатием
	vector <uint8_t> compact;
	// Кодируем
	ASSERT_EQ(ech::encode(inner, vector <uint16_t> {0x000A, 0x000D}, 5, compact), ech::error_t::NONE);
	// Внешнее приветствие
	ASSERT_TRUE(outerhello(inner, outers, compact, outer));
	// Восстановленное тело
	vector <uint8_t> restored;
	// Годное восстанавливается
	ASSERT_EQ(ech::decode(view_t(compact.data(), compact.size()), outer, restored), ech::error_t::NONE);
	// Ненулевое заполнение отвергается
	vector <uint8_t> spoiled = compact;
	spoiled.back() = 0x01;
	EXPECT_EQ(ech::decode(view_t(spoiled.data(), spoiled.size()), outer, restored), ech::error_t::FORMAT);
	/**
	 * Выполняем перебор длин усечения
	 */
	for(size_t size = 0; size < (compact.size() - 5); size++)
		// Усечённое не восстанавливается
		EXPECT_NE(ech::decode(view_t(compact.data(), size), outer, restored), ech::error_t::NONE) << size;
	// Внешнее без групп: ссылка на отсутствующее
	hello::client_t lacking = outer;
	lacking.extensions.erase(lacking.extensions.begin() + 1);
	EXPECT_EQ(ech::decode(view_t(compact.data(), compact.size()), lacking, restored), ech::error_t::OUTER);
	// Внешнее с группами и схемами в обратном порядке
	hello::client_t reversed = outer;
	std::swap(reversed.extensions[1], reversed.extensions[2]);
	EXPECT_EQ(ech::decode(view_t(compact.data(), compact.size()), reversed, restored), ech::error_t::OUTER);
	// Закодированное с повторной ссылкой: тело ссылок подделано
	hello::client_t parsed;
	ASSERT_EQ(hello::parse(view_t(compact.data(), compact.size() - 5), parsed), hello::error_t::NONE);
	// Ссылки: группы дважды
	static const uint8_t TWICE[] = {0x04, 0x00, 0x0A, 0x00, 0x0A};
	parsed.extensions[1].data = view_t(TWICE, sizeof(TWICE));
	vector <uint8_t> forged;
	ASSERT_EQ(hello::build(parsed, forged), hello::error_t::NONE);
	EXPECT_EQ(ech::decode(view_t(forged.data(), forged.size()), outer, restored), ech::error_t::OUTER);
	// Ссылка на само ECH
	static const uint8_t SELF[] = {0x02, 0xFE, 0x0D};
	parsed.extensions[1].data = view_t(SELF, sizeof(SELF));
	forged.clear();
	ASSERT_EQ(hello::build(parsed, forged), hello::error_t::NONE);
	EXPECT_EQ(ech::decode(view_t(forged.data(), forged.size()), outer, restored), ech::error_t::OUTER);
	// Ссылки нечётной длины
	static const uint8_t ODD[] = {0x03, 0x00, 0x0A, 0x00};
	parsed.extensions[1].data = view_t(ODD, sizeof(ODD));
	forged.clear();
	ASSERT_EQ(hello::build(parsed, forged), hello::error_t::NONE);
	EXPECT_EQ(ech::decode(view_t(forged.data(), forged.size()), outer, restored), ech::error_t::OUTER);
	// Закодированное с опознавателем связи отвергается
	hello::client_t sessioned = inner;
	vector <uint8_t> withsession;
	ASSERT_EQ(hello::build(sessioned, withsession), hello::error_t::NONE);
	EXPECT_EQ(ech::decode(view_t(withsession.data(), withsession.size()), outer, restored), ech::error_t::FORMAT);
}

/**
 * Проверка заполнения по разделу 6.1.3 RFC 9849
 */
TEST(EchTest, Padding){
	// С именем длины 14 при наибольшей 64: добавка 50, затем до кратной 32
	const size_t named = ech::padding(14, 64, 100);
	EXPECT_GE(named, static_cast <size_t> (50));
	EXPECT_EQ((100 + named) % 32, static_cast <size_t> (0));
	// Без имени: добавка 64 + 9 = 73
	const size_t nameless = ech::padding(0, 64, 100);
	EXPECT_GE(nameless, static_cast <size_t> (73));
	EXPECT_EQ((100 + nameless) % 32, static_cast <size_t> (0));
	// Имя длиннее наибольшей: добавки по имени нет
	const size_t longer = ech::padding(100, 64, 100);
	EXPECT_LT(longer, static_cast <size_t> (32));
	EXPECT_EQ((100 + longer) % 32, static_cast <size_t> (0));
	// Длина уже кратная 32 без добавки: заполнение нулевое
	EXPECT_EQ(ech::padding(64, 64, 96), static_cast <size_t> (0));
	// Длина 97: заполнение 31
	EXPECT_EQ(ech::padding(64, 64, 97), static_cast <size_t> (31));
}

/**
 * Проверка добавочных данных внешнего приветствия
 */
TEST(EchTest, Redacting){
	// Тела расширений
	vector <vector <uint8_t>> bodies, outers;
	// Приветствия
	hello::client_t inner, outer;
	// Составляем внутреннее
	ASSERT_TRUE(innerhello(bodies, inner));
	// Шифротекст
	vector <uint8_t> payload(64, 0xEE);
	// Составляем внешнее
	ASSERT_TRUE(outerhello(inner, outers, payload, outer));
	// Тело внешнего
	vector <uint8_t> body;
	ASSERT_EQ(hello::build(outer, body), hello::error_t::NONE);
	// Добавочные данные
	vector <uint8_t> aad;
	// Составляем
	ASSERT_EQ(ech::redact(view_t(body.data(), body.size()), aad), ech::error_t::NONE);
	// Длина та же
	ASSERT_EQ(aad.size(), body.size());
	// Ровно 64 байта обнулены, остальное совпадает
	size_t zeroed = 0, differing = 0;
	/**
	 * Выполняем перебор байтов
	 */
	for(size_t i = 0; i < body.size(); i++){
		// Если байты разошлись
		if(aad[i] != body[i]){
			// Считаем расхождение
			differing++;
			// Расхождение лишь на обнулённом шифротексте
			EXPECT_EQ(aad[i], 0);
			EXPECT_EQ(body[i], 0xEE);
		}
		// Считаем нули среди байтов шифротекста
		zeroed += ((body[i] == 0xEE) ? 1 : 0);
	}
	EXPECT_EQ(differing, static_cast <size_t> (64));
	EXPECT_EQ(zeroed, static_cast <size_t> (64));
	// Приветствие без ECH не редактируется
	vector <uint8_t> plain;
	ASSERT_EQ(hello::build(inner, plain), hello::error_t::NONE);
	// Внутреннее несёт ECH внутреннего вида: отказ записи
	EXPECT_EQ(ech::redact(view_t(plain.data(), plain.size()), aad), ech::error_t::FORMAT);
	// Порченое приветствие
	EXPECT_EQ(ech::redact(view_t(body.data(), body.size() - 1), aad), ech::error_t::FORMAT);
}

/**
 * Проверка подтверждения принятия ECH
 */
TEST(EchTest, Confirmation){
	// Случайное значение и хеш переписки
	uint8_t random[32], transcript[32], first[8], second[8], retried[8];
	::memset(random, 0x42, sizeof(random));
	::memset(transcript, 0x24, sizeof(transcript));
	// Вычисляем подтверждение
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), false, first));
	// Повторное вычисление совпадает
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), false, second));
	EXPECT_EQ(::memcmp(first, second, 8), 0);
	// Метка просьбы о повторе даёт иное
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), true, retried));
	EXPECT_NE(::memcmp(first, retried, 8), 0);
	// Иное случайное значение даёт иное
	random[0] ^= 1;
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), false, second));
	EXPECT_NE(::memcmp(first, second, 8), 0);
	// Иная переписка даёт иное
	random[0] ^= 1; transcript[31] ^= 1;
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), false, second));
	EXPECT_NE(::memcmp(first, second, 8), 0);
	// Хеш SHA-384: переписка длины 48
	uint8_t wider[48];
	::memset(wider, 0x24, sizeof(wider));
	ASSERT_TRUE(ech::confirmation(digest::hash_t::SHA384, view_t(random, 32), view_t(wider, 48), false, second));
	// Негодные доводы
	EXPECT_FALSE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 31), view_t(transcript, 32), false, second));
	EXPECT_FALSE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 31), false, second));
	EXPECT_FALSE(ech::confirmation(digest::hash_t::NONE, view_t(random, 32), view_t(transcript, 32), false, second));
	EXPECT_FALSE(ech::confirmation(digest::hash_t::SHA256, view_t(random, 32), view_t(transcript, 32), false, nullptr));
}

/**
 * Проверка поведения при нехватке памяти
 */
TEST(EchTest, Starved){
	// Образец перечня
	const vector <uint8_t> list = corpus("ech/bssl.list");
	// Проверяем чтение
	ASSERT_FALSE(list.empty());
	// Тела расширений
	vector <vector <uint8_t>> bodies, outers;
	// Приветствия
	hello::client_t inner, outer;
	// Составляем внутреннее
	ASSERT_TRUE(innerhello(bodies, inner));
	// Закодированное до ограничения
	vector <uint8_t> compact;
	ASSERT_EQ(ech::encode(inner, vector <uint16_t> {0x000A, 0x000D}, 5, compact), ech::error_t::NONE);
	// Внешнее приветствие
	ASSERT_TRUE(outerhello(inner, outers, compact, outer));
	// Тело внешнего
	vector <uint8_t> body;
	ASSERT_EQ(hello::build(outer, body), hello::error_t::NONE);
	// Вынесенные расширения
	const vector <uint16_t> outsourced = {0x000A, 0x000D};
	// Признаки
	bool starved = false, complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 3000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Отказы шагов
		ech::error_t outcomes[6] = {ech::error_t::NONE, ech::error_t::NONE, ech::error_t::NONE, ech::error_t::NONE, ech::error_t::NONE, ech::error_t::NONE};
		{
			// Ограничиваем запас
			starve::ration_t ration(budget);
			// Перечень конфигураций
			vector <ech::config_t> configs;
			// Накопители
			vector <uint8_t> rebuilt, encoded, restored, aad, binding;
			// Разбираем перечень
			outcomes[0] = ech::parse(view_t(list.data(), list.size()), configs);
			// Если перечень разобран
			if(outcomes[0] == ech::error_t::NONE){
				// Составляем перечень
				outcomes[1] = ech::build(configs, rebuilt);
				// Составляем привязку
				outcomes[2] = ech::binding(view_t(configs[0].raw.data(), configs[0].raw.size()), binding);
			}
			// Кодируем
			outcomes[3] = ech::encode(inner, outsourced, 5, encoded);
			// Восстанавливаем
			outcomes[4] = ech::decode(view_t(compact.data(), compact.size()), outer, restored);
			// Редактируем
			outcomes[5] = ech::redact(view_t(body.data(), body.size()), aad);
		}
		// Полный успех
		complete = true;
		/**
		 * Выполняем перебор отказов
		 */
		for(size_t i = 0; i < 6; i++){
			// Всякий отказ либо NONE, либо MEMORY
			ASSERT_TRUE((outcomes[i] == ech::error_t::NONE) || (outcomes[i] == ech::error_t::MEMORY)) << "запас " << budget << " шаг " << i << " отказ " << static_cast <int> (outcomes[i]);
			// Считаем встречу нехватки и полноту успеха
			starved = (starved || (outcomes[i] == ech::error_t::MEMORY));
			complete = (complete && (outcomes[i] == ech::error_t::NONE));
		}
	}
	// Нехватка встречена и полный успех достигнут
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}


/**
 * Проверка принятия ECH: рукопожатие идёт по внутреннему приветствию, на проводе - публичное имя
 */
TEST(EchTest, Loopback){
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Настраиваем стороны: ключ сервера тот же, что в перечне клиента
	ASSERT_TRUE(arranged(client, server, false));
	// Перечень сервера для DNS совпадает с перечнем BoringSSL байт в байт
	EXPECT_EQ(server.ech(), corpus("ech/bssl.list"));
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Профиль внешнего приветствия
	fingerprint::profile_t outer;
	// Снимаем внешнее приветствие
	ASSERT_TRUE(captured(client, outer));
	// Имя на проводе - публичное
	bool named = false, shrouded = false;
	/**
	 * Выполняем перебор расширений внешнего приветствия
	 */
	for(size_t i = 0; i < outer.extensions.size(); i++){
		// Если расширение есть имя узла
		if(outer.extensions[i].type == 0x0000){
			// Проверяем публичное имя
			EXPECT_EQ(outer.extensions[i].names[0], "public.example");
			// Отмечаем имя
			named = true;
		}
		// Если расширение есть ECH
		if(outer.extensions[i].type == ech::ECH_EXTENSION){
			// Разобранное расширение
			ech::hello_t hello;
			// Разбираем
			ASSERT_EQ(ech::parse(view_t(outer.extensions[i].data.data(), outer.extensions[i].data.size()), hello), ech::error_t::NONE);
			// Внешний вид с опознавателем перечня
			EXPECT_FALSE(hello.inner);
			EXPECT_EQ(hello.id, 7);
			EXPECT_EQ(hello.enc.size(), static_cast <size_t> (32));
			// Шифротекст кратен 32 с меткой шифра
			EXPECT_EQ((hello.payload.size() - 16) % 32, static_cast <size_t> (0));
			// Отмечаем ECH
			shrouded = true;
		}
	}
	// Публичное имя и ECH на проводе, тайное имя на проводе не встречается
	EXPECT_TRUE(named);
	EXPECT_TRUE(shrouded);
	// Байты внешнего приветствия
	const view_t wire = client.output();
	// Тайное имя на проводе не встречается
	EXPECT_EQ(string(reinterpret_cast <const char *> (wire.data), wire.size).find("secret.example"), string::npos);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Обе стороны считают ECH принятым
	EXPECT_TRUE(client.shrouded());
	EXPECT_TRUE(server.shrouded());
	// Запасных конфигураций нет
	EXPECT_TRUE(client.retry().empty());
	// Сервер видел тайное имя из внутреннего приветствия
	EXPECT_EQ(server.name(), "secret.example");
	// Прикладной протокол согласован
	EXPECT_EQ(client.protocol(), "h2");
	// Профиль сервера снят с внешнего приветствия: публичное имя
	fingerprint::profile_t seen;
	// Снимаем профиль
	ASSERT_EQ(server.profile(seen), context::error_t::NONE);
	/**
	 * Выполняем перебор расширений
	 */
	for(size_t i = 0; i < seen.extensions.size(); i++){
		// Если расширение есть имя узла
		if(seen.extensions[i].type == 0x0000)
			// Проверяем публичное имя
			EXPECT_EQ(seen.extensions[i].names[0], "public.example");
	}
	// Обмен прикладными данными
	const string request = "Запрос под ECH";
	// Отправляем
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Передаём
	converse(client, server);
	// Принятое
	vector <uint8_t> received;
	// Читаем
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), request);
	// Конфигурации после заведения не ставятся
	EXPECT_EQ(client.ech(corpus("ech/bssl.list")), context::error_t::STATE);
	EXPECT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::STATE);
}

/**
 * Проверка принятия ECH через просьбу о повторе
 */
TEST(EchTest, Retry){
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Настраиваем стороны
	ASSERT_TRUE(arranged(client, server, false));
	// Сервер ведёт лишь P-256: доли по ней клиент не шлёт
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первое приветствие серверу, просьба о повторе клиенту
	ASSERT_TRUE(pump(client, server));
	// Профиль второго внешнего приветствия
	fingerprint::profile_t second;
	// Снимаем второе приветствие
	ASSERT_TRUE(captured(client, second));
	/**
	 * Выполняем перебор расширений второго приветствия
	 */
	for(size_t i = 0; i < second.extensions.size(); i++){
		// Если расширение есть ECH
		if(second.extensions[i].type == ech::ECH_EXTENSION){
			// Разобранное расширение
			ech::hello_t hello;
			// Разбираем
			ASSERT_EQ(ech::parse(view_t(second.extensions[i].data.data(), second.extensions[i].data.size()), hello), ech::error_t::NONE);
			// Раздел 6.1.5 RFC 9849: повторное приветствие идёт с пустым enc
			EXPECT_TRUE(hello.enc.empty());
		}
	}
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Обе стороны считают ECH принятым
	EXPECT_TRUE(client.shrouded());
	EXPECT_TRUE(server.shrouded());
	// Тайное имя дошло
	EXPECT_EQ(server.name(), "secret.example");
}

/**
 * Проверка отказа ECH сервером с чужим ключом: рукопожатие по публичному имени, retry_configs, ech_required
 */
TEST(EchTest, Rejected){
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Настраиваем стороны: сервер ведёт свой ключ, перечень клиента ему чужой
	ASSERT_TRUE(arranged(client, server, true));
	// Перечень сервера отличается от перечня клиента
	EXPECT_NE(server.ech(), corpus("ech/bssl.list"));
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Сервер сложил рукопожатие по внешнему приветствию и получил извещение ech_required клиента
	EXPECT_EQ(server.error(), context::error_t::ALERT) << "сервер " << static_cast <int> (server.error()) << " клиент " << static_cast <int> (client.error());
	EXPECT_EQ(server.alert().description, alert::description_t::ECH_REQUIRED);
	EXPECT_FALSE(server.shrouded());
	// Сервер видел публичное имя
	EXPECT_EQ(server.name(), "public.example");
	// Клиент сложил рукопожатие и оборвал связь извещением ech_required
	EXPECT_EQ(client.state(), context::state_t::FAILED);
	EXPECT_EQ(client.error(), context::error_t::ECH);
	EXPECT_EQ(client.alert().description, alert::description_t::ECH_REQUIRED);
	EXPECT_FALSE(client.shrouded());
	// Запасные конфигурации сервера получены и равны его перечню
	EXPECT_EQ(client.retry(), server.ech());
	// Запасные конфигурации признаются
	vector <ech::config_t> configs;
	EXPECT_EQ(ech::parse(view_t(client.retry().data(), client.retry().size()), configs), ech::error_t::NONE);
	// Повтор связи с запасными конфигурациями сходится
	client::context_t again;
	server::context_t anew;
	// Настраиваем стороны заново
	ASSERT_TRUE(arranged(again, anew, true));
	// Ключ сервера прежний: перечень равен присланному
	ASSERT_EQ(anew.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	// Клиент берёт присланные сервером конфигурации
	ASSERT_EQ(again.ech(anew.ech()), context::error_t::NONE);
	// Заводим стороны
	ASSERT_EQ(anew.start(), context::error_t::NONE);
	ASSERT_EQ(again.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(again, anew);
	// Связь установлена с принятым ECH
	ASSERT_TRUE(again.established() && anew.established()) << static_cast <int> (again.error());
	EXPECT_TRUE(again.shrouded());
	EXPECT_EQ(anew.name(), "secret.example");
}

/**
 * Проверка сервера без ECH: расширение пропускается, клиент считает ECH отвергнутым без запасных конфигураций
 */
TEST(EchTest, Unsupported){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связи сторон
	client::context_t client;
	server::context_t server;
	// Подлинность сервера без ключа ECH
	server.credential(credential);
	// Имя и конфигурации клиента
	client.name("secret.example");
	ASSERT_EQ(client.ech(corpus("ech/bssl.list")), context::error_t::NONE);
	// Заводим стороны
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Сервер сложил рукопожатие по публичному имени и получил извещение ech_required
	EXPECT_EQ(server.error(), context::error_t::ALERT) << "сервер " << static_cast <int> (server.error()) << " клиент " << static_cast <int> (client.error());
	EXPECT_EQ(server.alert().description, alert::description_t::ECH_REQUIRED);
	EXPECT_EQ(server.name(), "public.example");
	// Клиент оборвал связь: ECH отвергнут, запасных конфигураций нет
	EXPECT_EQ(client.state(), context::state_t::FAILED);
	EXPECT_EQ(client.error(), context::error_t::ECH);
	EXPECT_TRUE(client.retry().empty());
	// С конфигурациями предел изданий ниже 1.3 не ставится, а 1.3 - ставится (находка щупа Григория)
	client::context_t bounded;
	ASSERT_EQ(bounded.ech(corpus("ech/bssl.list")), context::error_t::NONE);
	EXPECT_EQ(bounded.versions(0x0303, 0x0304), context::error_t::SETTINGS);
	EXPECT_EQ(bounded.versions(0x0304, 0x0304), context::error_t::NONE);
	EXPECT_EQ(bounded.lowest(), 0x0304);
	// Публичное имя известно сразу после установки конфигураций
	EXPECT_EQ(bounded.visible(), "public.example");
	// Негодные конфигурации не ставятся
	client::context_t other;
	EXPECT_EQ(other.ech(vector <uint8_t> {0x00, 0x02, 0xFE, 0x0C}), context::error_t::ECH);
	EXPECT_EQ(other.ech(vector <uint8_t> ()), context::error_t::ECH);
	// Фасады сторон различны по устройству: серверу перечень, клиенту ключ не подать вовсе
	server::context_t another;
	// Пустое и слишком длинное имя серверу не годны
	EXPECT_EQ(another.ech(vector <uint8_t> (), "", 7, 64), context::error_t::SETTINGS);
	EXPECT_EQ(another.ech(vector <uint8_t> (), string(256, 'a'), 7, 64), context::error_t::SETTINGS);
	// Ключ негодной длины не годен
	EXPECT_EQ(another.ech(vector <uint8_t> (31, 0x01), "public.example", 7, 64), context::error_t::SETTINGS);
}

/**
 * Проверка GREASE ECH: клиент без конфигураций с включённым GREASE против сервера с ключом и без
 */
TEST(EchTest, Grease){
	/**
	 * Выполняем перебор случаев: сервер с ключом и без
	 */
	for(size_t keyed = 0; keyed < 2; keyed++){
		// Подлинность сервера
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ec256", credential));
		// Связи сторон
		client::context_t client;
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Если сервер с ключом
		if(keyed == 1)
			// Ставим ключ
			ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
		// Имя клиента
		client.name("plain.example");
		// GREASE у клиента
		client.grease(true);
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Профиль приветствия
		fingerprint::profile_t outer;
		// Снимаем приветствие
		ASSERT_TRUE(captured(client, outer));
		// Признак GREASE ECH
		bool greased = false;
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < outer.extensions.size(); i++){
			// Если расширение есть ECH
			if(outer.extensions[i].type == ech::ECH_EXTENSION){
				// Разобранное расширение
				ech::hello_t hello;
				// Разбираем
				ASSERT_EQ(ech::parse(view_t(outer.extensions[i].data.data(), outer.extensions[i].data.size()), hello), ech::error_t::NONE);
				// Внешний вид, обязательный набор, годный ключ, шифротекст кратен 32 с меткой
				EXPECT_FALSE(hello.inner);
				EXPECT_EQ(hello.suite.aead, hpke::aead_t::AES_128_GCM);
				EXPECT_EQ(hello.enc.size(), static_cast <size_t> (32));
				EXPECT_EQ((hello.payload.size() - 16) % 32, static_cast <size_t> (0));
				// Отмечаем GREASE
				greased = true;
			}
		}
		// GREASE ECH на месте
		EXPECT_TRUE(greased) << "ключ " << keyed;
		// Проводим рукопожатие
		converse(client, server);
		// Связь установлена: значение GREASE ни к чему не обязывает
		ASSERT_TRUE(client.established() && server.established()) << "ключ " << keyed << " отказ " << static_cast <int> (client.error());
		EXPECT_FALSE(client.shrouded());
		EXPECT_FALSE(server.shrouded());
		// Сервер с ключом прислал запасные конфигурации, без ключа - нет
		EXPECT_EQ(client.retry().empty(), (keyed == 0)) << "ключ " << keyed;
		// Имя дошло как есть
		EXPECT_EQ(server.name(), "plain.example");
	}
}

/**
 * Проверка сверки с BoringSSL: наш клиент против bssl server, наш сервер против bssl client
 */
TEST(EchTest, Boringssl2){
	// Инструмент bssl
	const std::string tool = bssltool();
	// Если инструмента нет
	if(tool.empty()){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "bssl (BoringSSL) недоступен: задайте ANTS_BSSL";
	}
	// Пути к образцам
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	const std::string echkey = std::string(CORPUS) + "/ech/bssl.key", echconfig = std::string(CORPUS) + "/ech/bssl.config", echlist = std::string(CORPUS) + "/ech/bssl.list";
	{
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем порт
		ASSERT_NE(number, 0);
		// Журнал сервера bssl
		const std::string log = "/tmp/ants-ech-bssl-server-" + std::to_string(number) + ".log";
		// Запускаем сервер bssl с ключом ECH и ответом HTTP
		ASSERT_TRUE(launch(tool + " server -accept " + std::to_string(number) + " -cert " + crt + " -key " + key + " -ech-key " + echkey + " -ech-config " + echconfig + " -www </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера
		sentinel_t sentinel(log + ".pid");
		// Подключаемся
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0) << "порт " << number;
		// Связь стороны клиента
		client::context_t client;
		// Имя и конфигурации
		client.name("secret.example");
		ASSERT_EQ(client.ech(corpus("ech/bssl.list")), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до установления связи
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём
			relay(client, fd);
		// Связь установлена с принятым ECH
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		EXPECT_TRUE(client.shrouded());
		// Запрос HTTP
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Ответ
		vector <uint8_t> answer;
		/**
		 * Выполняем передачу до ответа
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём
			relay(client, fd);
			// Читаем
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Текст ответа
		const string text(answer.begin(), answer.end());
		// Сервер BoringSSL подтверждает принятие ECH и тайное имя
		EXPECT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
		EXPECT_NE(text.find("Encrypted ClientHello: yes"), string::npos) << text;
		EXPECT_NE(text.find("Client sent SNI: secret.example"), string::npos) << text;
		// Закрываем сокет
		closing(fd);
		// Снимаем сервер
		sentinel.halt();
		// Журнал
		std::string journal;
		// Дожидаемся завершения
		(void) settle(log, journal);
		// Удаляем журнал
		::remove(log.c_str());
	}
	{
		// Порт своего сервера
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента bssl
		const std::string log = "/tmp/ants-ech-bssl-client-" + std::to_string(number) + ".log";
		// Запускаем клиента bssl с перечнем конфигураций и тайным именем
		ASSERT_TRUE(launch("printf 'GET / HTTP/1.0\\r\\n\\r\\n' | " + tool + " client -connect 127.0.0.1:" + std::to_string(number) + " -ech-config-list " + echlist + " -server-name secret.example >" + log + " 2>&1", log, log + ".pid"));
		// Сторож клиента
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ec256", credential));
		// Настраиваем сервер: ключ BoringSSL, та же конфигурация
		server.credential(credential);
		ASSERT_EQ(server.ech(corpus("ech/bssl.key"), "public.example", 7, 64), context::error_t::NONE);
		// Перечень сервера равен перечню BoringSSL байт в байт
		EXPECT_EQ(server.ech(), corpus("ech/bssl.list"));
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём связь до конца рукопожатия
		const bool complete = serve(server, fd);
		// Рукопожатие сошлось с принятым ECH
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
		EXPECT_TRUE(server.shrouded());
		EXPECT_EQ(server.name(), "secret.example");
		// Закрываем связь
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем сокеты
		closing(fd);
		closing(listener);
		// Текст журнала клиента
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(settle(log, text)) << text;
		// Клиент BoringSSL подтверждает принятие ECH
		EXPECT_NE(text.find("Encrypted ClientHello: yes"), std::string::npos) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка поведения рукопожатия под ECH при нехватке памяти
 */
TEST(EchTest, Hungry){
	// Перечень и ключ
	const vector <uint8_t> list = corpus("ech/bssl.list"), key = corpus("ech/bssl.key");
	// Проверяем чтение
	ASSERT_FALSE(list.empty() || key.empty());
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Имена складываются до ограничения запаса
	const string secret = "secret.example", visible = "public.example";
	// Признаки
	bool starved = false, complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 8000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Отказы шагов
		context::error_t configured = context::error_t::NONE, keyed = context::error_t::NONE, started = context::error_t::NONE;
		// Установленность
		bool established = false;
		// Отказы сторон
		context::error_t sideclient = context::error_t::NONE, sideserver = context::error_t::NONE;
		{
			// Связи сторон
			client::context_t client;
			server::context_t server;
			/**
			 * Имя клиента ставится до ограничения запаса: у libc++ короткая строка
			 * лежит без выделения, у MSVC требует его, и при запасе в одно выделение
			 * имя не ставилось вовсе - ech() тогда честно отвечал STATE, а не MEMORY
			 */
			client.name(secret);
			// Ограничиваем запас
			starve::ration_t ration(budget);
			// Конфигурации клиента
			configured = client.ech(list);
			// Подлинность сервера
			server.credential(credential);
			// Ключ сервера
			keyed = server.ech(key, visible, 7, 64);
			// Если стороны настроены
			if((configured == context::error_t::NONE) && (keyed == context::error_t::NONE)){
				// Заводим сервер
				started = server.start();
				// Если сервер заведён
				if(started == context::error_t::NONE)
					// Заводим клиента
					started = client.start();
				// Если стороны заведены
				if(started == context::error_t::NONE){
					// Проводим рукопожатие
					converse(client, server);
					// Установленность с принятым ECH
					established = (client.established() && server.established() && client.shrouded() && server.shrouded());
					// Запоминаем отказы сторон: судятся за пределами ограничения
					sideclient = client.error();
					sideserver = server.error();
				}
			}
		}
		// Если связь не установилась: отказы сторон лишь NONE, MEMORY либо обрыв извещением собеседника
		if((started == context::error_t::NONE) && !established){
			ASSERT_TRUE((sideclient == context::error_t::NONE) || (sideclient == context::error_t::MEMORY) || (sideclient == context::error_t::ALERT)) << "запас " << budget << " клиент " << static_cast <int> (sideclient);
			ASSERT_TRUE((sideserver == context::error_t::NONE) || (sideserver == context::error_t::MEMORY) || (sideserver == context::error_t::ALERT)) << "запас " << budget << " сервер " << static_cast <int> (sideserver);
		}
		// Всякий отказ либо NONE, либо MEMORY
		ASSERT_TRUE((configured == context::error_t::NONE) || (configured == context::error_t::MEMORY)) << "запас " << budget << " конфигурации " << static_cast <int> (configured);
		ASSERT_TRUE((keyed == context::error_t::NONE) || (keyed == context::error_t::MEMORY)) << "запас " << budget << " ключ " << static_cast <int> (keyed);
		ASSERT_TRUE((started == context::error_t::NONE) || (started == context::error_t::MEMORY)) << "запас " << budget << " заведение " << static_cast <int> (started);
		// Считаем встречу нехватки
		starved = (starved || !established);
		// Полный успех
		complete = established;
	}
	// Нехватка встречена и полный успех достигнут
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}


/**
 * Проверка имени удостоверения: потребитель судит сертификат по name() при принятии и по visible() при отказе
 */
TEST(EchTest, Visible){
	/**
	 * Выполняем перебор случаев: сервер с ключом клиента (принятие) и с чужим ключом (отказ)
	 */
	for(size_t accepted = 0; accepted < 2; accepted++){
		// Связи сторон
		client::context_t client;
		server::context_t server;
		// Без ECH публичного имени нет
		EXPECT_TRUE(client.visible().empty());
		// Настраиваем стороны
		ASSERT_TRUE(arranged(client, server, (accepted == 0)));
		// Заводим стороны
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Публичное имя конфигурации известно потребителю
		EXPECT_EQ(client.visible(), "public.example");
		// Если ECH принят: сертификат судится по тайному имени
		if(accepted == 1){
			EXPECT_TRUE(client.established() && client.shrouded());
		// Если ECH отвергнут: сертификат судится по публичному имени, связь оборвана ech_required
		} else {
			EXPECT_FALSE(client.shrouded());
			EXPECT_EQ(client.error(), context::error_t::ECH);
			EXPECT_FALSE(client.retry().empty());
		}
	}
}

/**
 * Возобновление под ECH: билет и привязка идут во внутреннем приветствии, внешнее без
 * pre_shared_key и early_data с публичным именем; связь остаётся скрытой и возобновлённой
 */
TEST(EchTest, Resumed){
	// Первая связь: выдача билета
	client::context_t client;
	server::context_t server;
	ASSERT_TRUE(arranged(client, server, false));
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	ASSERT_TRUE(client.shrouded() && server.shrouded());
	// Выдаём билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	converse(client, server);
	ASSERT_FALSE(client.tickets().empty());
	ASSERT_FALSE(server.tickets().empty());
	// Вторая связь: билет предъявляется под ECH
	client::context_t resuming;
	server::context_t resumed;
	ASSERT_TRUE(arranged(resuming, resumed, false));
	resuming.resume(client.tickets()[0]);
	resumed.resume(server.tickets());
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Внешнее приветствие
	fingerprint::profile_t outer;
	ASSERT_TRUE(captured(resuming, outer));
	bool named = false, secret = false, early = false, shrouded = false;
	for(size_t i = 0; i < outer.extensions.size(); i++){
		if(outer.extensions[i].type == 0x0000){
			EXPECT_EQ(outer.extensions[i].names[0], "public.example");
			named = true;
		}
		secret = (secret || (outer.extensions[i].type == 0x0029));
		early = (early || (outer.extensions[i].type == 0x002A));
		shrouded = (shrouded || (outer.extensions[i].type == ech::ECH_EXTENSION));
	}
	EXPECT_TRUE(named);
	EXPECT_TRUE(shrouded);
	// Внешнее приветствие не несёт ни билета, ни упреждения
	EXPECT_FALSE(secret);
	EXPECT_FALSE(early);
	const view_t wire = resuming.output();
	EXPECT_EQ(string(reinterpret_cast <const char *> (wire.data), wire.size).find("secret.example"), string::npos);
	converse(resuming, resumed);
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error()) << " извещения " << static_cast <int> (resuming.alert().description) << " " << static_cast <int> (resumed.alert().description);
	// Связь скрыта и возобновлена
	EXPECT_TRUE(resuming.shrouded());
	EXPECT_TRUE(resumed.shrouded());
	EXPECT_TRUE(resuming.shared());
	EXPECT_TRUE(resumed.shared());
	EXPECT_EQ(resumed.name(), "secret.example");
	// Прикладные данные
	const string request = "Запрос под ECH с билетом";
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	converse(resuming, resumed);
	vector <uint8_t> received;
	ASSERT_EQ(resumed.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), request);
}

/**
 * Возобновление под ECH против bssl client -test-resumption: обе связи скрыты, вторая
 * возобновлена по билету нашего сервера
 */
/**
 * Проверка упреждающих данных под ECH (раздел 6.1 RFC 9849): билет со связи под ECH, второе
 * приветствие несёт early_data лишь во внутреннем, ключи упреждения с внутреннего приветствия,
 * сервер принимает ECH и данные
 */
TEST(EchTest, Early){
	client::context_t client;
	server::context_t server;
	ASSERT_TRUE(arranged(client, server, false));
	server.advance(true, 16384);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	converse(client, server);
	ASSERT_FALSE(client.tickets().empty());
	client::context_t resuming;
	server::context_t resumed;
	ASSERT_TRUE(arranged(resuming, resumed, false));
	resumed.advance(true, 16384);
	resuming.advance(true, 16384);
	resuming.resume(client.tickets()[0]);
	resumed.resume(server.tickets());
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Внешнее приветствие без early_data, внутреннее его несёт (в ECH, скрыто)
	fingerprint::profile_t outer;
	ASSERT_TRUE(captured(resuming, outer));
	bool early = false, shrouded = false;
	for(size_t i = 0; i < outer.extensions.size(); i++){
		early = (early || (outer.extensions[i].type == 0x002A));
		shrouded = (shrouded || (outer.extensions[i].type == ech::ECH_EXTENSION));
	}
	EXPECT_TRUE(shrouded);
	EXPECT_TRUE(early);
	// Упреждающие данные уходят до ответа сервера
	const string request = "Упреждающий запрос под ECH";
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	converse(resuming, resumed);
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error()) << " извещение " << static_cast <int> (resumed.alert().description);
	EXPECT_TRUE(resuming.shrouded() && resumed.shrouded());
	EXPECT_TRUE(resuming.accepted());
	EXPECT_TRUE(resumed.accepted());
	vector <uint8_t> received;
	ASSERT_EQ(resumed.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), request);
}

/**
 * Проверка упреждающих данных при отклонённом ECH: сервер с иными ключами ECH читает внешнее
 * приветствие, записи упреждения пропускает (раздел 4.2.10 RFC 8446), связь рвётся по
 * ech_required клиента, а не по bad_record_mac сервера
 */
TEST(EchTest, EarlyRejected){
	client::context_t client;
	server::context_t server;
	ASSERT_TRUE(arranged(client, server, false));
	server.advance(true, 16384);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	converse(client, server);
	ASSERT_FALSE(client.tickets().empty());
	client::context_t resuming;
	server::context_t stranger;
	// Чужой сервер: тот же опознаватель 7, но свой ключ - раскрыть приветствие ему нечем
	ASSERT_TRUE(arranged(resuming, stranger, true));
	stranger.advance(true, 16384);
	resuming.advance(true, 16384);
	resuming.resume(client.tickets()[0]);
	stranger.resume(server.tickets());
	ASSERT_EQ(stranger.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	const string request = "Упреждающий запрос под отклонённый ECH";
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	converse(resuming, stranger);
	// Клиент отверг связь по ech_required, сервер получил именно его, не упал на снятии защиты
	EXPECT_EQ(resuming.error(), context::error_t::ECH);
	EXPECT_EQ(resuming.alert().description, alert::description_t::ECH_REQUIRED);
	EXPECT_EQ(stranger.error(), context::error_t::ALERT) << static_cast <int> (stranger.error()) << " " << static_cast <int> (stranger.alert().description);
	EXPECT_EQ(stranger.alert().description, alert::description_t::ECH_REQUIRED);
	EXPECT_FALSE(resuming.accepted());
}

TEST(EchTest, Boringssl3){
	const std::string tool = bssltool();
	if(tool.empty()){
		GTEST_SKIP() << "bssl (BoringSSL) недоступен: задайте ANTS_BSSL";
	}
	const std::string echlist = std::string(CORPUS) + "/ech/bssl.list";
	uint16_t number = 0;
	const int listener = harbour(number);
	ASSERT_GE(listener, 0);
	const std::string log = "/tmp/ants-ech-bssl-resume-" + std::to_string(number) + ".log";
	ASSERT_TRUE(launch(tool + " client -connect 127.0.0.1:" + std::to_string(number) + " -ech-config-list " + echlist + " -server-name secret.example -test-resumption </dev/null >" + log + " 2>&1", log, log + ".pid"));
	sentinel_t sentinel(log + ".pid");
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	// Билеты первой связи
	vector <context::ticket_t> tickets;
	for(size_t round = 0; round < 2; round++){
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0) << "связь " << round;
		server::context_t server;
		server.credential(credential);
		ASSERT_EQ(server.ech(corpus("ech/bssl.key"), "public.example", 7, 64), context::error_t::NONE);
		if(round == 1)
			server.resume(tickets);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_TRUE(serve(server, fd)) << "связь " << round << " отказ " << static_cast <int> (server.error());
		EXPECT_TRUE(server.shrouded()) << "связь " << round;
		EXPECT_EQ(server.name(), "secret.example") << "связь " << round;
		if(round == 0){
			// Выдаём билет
			ASSERT_EQ(server.issue(), context::error_t::NONE);
			const view_t granting = server.output();
			ASSERT_EQ(sending(fd, granting.data, granting.size), static_cast <ssize_t> (granting.size));
			server.consume(granting.size);
			tickets = server.tickets();
			ASSERT_FALSE(tickets.empty());
			// Первое подключение закрывает сам bssl, получив билет: ждём его закрытия
			uint8_t buffer[4096];
			for(size_t i = 0; (i < 8) && (receiving(fd, buffer, sizeof(buffer)) > 0); i++)
				continue;
		} else {
			EXPECT_TRUE(server.shared());
			ASSERT_TRUE(farewell(server, fd));
		}
		closing(fd);
	}
	closing(listener);
	std::string text;
	ASSERT_TRUE(settle(log, text)) << text;
	EXPECT_NE(text.find("Encrypted ClientHello: yes"), std::string::npos) << text;
	EXPECT_NE(text.find("Resumed session: yes"), std::string::npos) << text;
	::remove(log.c_str());
	// bssl server в режиме -www билетов не выдаёт (проверено отладчиком без ECH и с ECH): ступень «наш клиент возобновляется у bssl server» невозможна

}

/**
 * ECH поверх дейтаграмм DTLS 1.3: внешнее приветствие с публичным именем и шифротекстом,
 * просьба о повторе с меткой несёт подтверждение, связь скрыта и установлена
 */
TEST(EchTest, Datagram){
	// Насос дейтаграмм: все дейтаграммы стороны переносятся за раз
	auto shuttle = [](client::context_t & client, server::context_t & server) -> bool {
		bool moved = false;
		for(size_t pass = 0; pass < 2; pass++){
			vector <vector <uint8_t>> datagrams;
			if(pass == 0){
				while(client.output().size > 0){
					const view_t data = client.output();
					datagrams.push_back(vector <uint8_t> (data.data, data.data + data.size));
					client.consume(data.size);
				}
				for(size_t i = 0; i < datagrams.size(); i++)
					server.push(view_t(datagrams[i].data(), datagrams[i].size()));
			} else {
				while(server.output().size > 0){
					const view_t data = server.output();
					datagrams.push_back(vector <uint8_t> (data.data, data.data + data.size));
					server.consume(data.size);
				}
				for(size_t i = 0; i < datagrams.size(); i++)
					client.push(view_t(datagrams[i].data(), datagrams[i].size()));
			}
			moved = (moved || !datagrams.empty());
		}
		return moved;
	};
	client::context_t client;
	server::context_t server;
	client.transport(context::transport_t::DATAGRAMS);
	server.transport(context::transport_t::DATAGRAMS);
	ASSERT_TRUE(arranged(client, server, false));
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	client.groups(vector <extension::group_t> {extension::group_t::X25519});
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Адрес собеседника: им сервер помечает метку возврата состояния
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
	ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
	ASSERT_EQ(server.start(), context::error_t::NONE) << static_cast <int> (server.error());
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первая дейтаграмма: внешнее приветствие
	fingerprint::profile_t outer;
	ASSERT_TRUE(captured(client, outer));
	EXPECT_TRUE(outer.datagram);
	bool named = false, shrouded = false;
	for(size_t i = 0; i < outer.extensions.size(); i++){
		if(outer.extensions[i].type == 0x0000){
			EXPECT_EQ(outer.extensions[i].names[0], "public.example");
			named = true;
		}
		shrouded = (shrouded || (outer.extensions[i].type == ech::ECH_EXTENSION));
	}
	EXPECT_TRUE(named);
	EXPECT_TRUE(shrouded);
	for(size_t i = 0; (i < 24) && shuttle(client, server); i++)
		continue;
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description);
	EXPECT_TRUE(client.shrouded());
	EXPECT_TRUE(server.shrouded());
	EXPECT_EQ(server.name(), "secret.example");
	EXPECT_EQ(client.protocol(), "h2");
	const string request = "Запрос под ECH поверх дейтаграмм";
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	for(size_t i = 0; (i < 8) && shuttle(client, server); i++)
		continue;
	vector <uint8_t> received;
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), request);
}

/**
 * Несколько служимых конфигураций: клиент с перечнем из двух берёт первую, сервер подбирает ключ по
 * опознавателю; клиент лишь со второй конфигурацией тоже раскрывается; занятый опознаватель отвергается
 */
TEST(EchTest, Several){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	server::context_t server;
	server.credential(credential);
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
	ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 9, 64), context::error_t::NONE);
	// Перечень несёт обе конфигурации
	vector <ech::config_t> configs;
	ASSERT_EQ(ech::parse(view_t(server.ech().data(), server.ech().size()), configs), ech::error_t::NONE);
	ASSERT_EQ(configs.size(), static_cast <size_t> (2));
	EXPECT_EQ(configs[0].id, 7);
	EXPECT_EQ(configs[1].id, 9);
	// Занятый опознаватель заменяет конфигурацию: перечень по-прежнему из двух, ключ второй сменился
	EXPECT_EQ(server.ech(vector <uint8_t> (), "public.example", 9, 64), context::error_t::NONE);
	{
		vector <ech::config_t> renewed;
		ASSERT_EQ(ech::parse(view_t(server.ech().data(), server.ech().size()), renewed), ech::error_t::NONE);
		ASSERT_EQ(renewed.size(), static_cast <size_t> (2));
		EXPECT_EQ(renewed[0].key, configs[0].key);
		EXPECT_NE(renewed[1].key, configs[1].key);
		configs = renewed;
	}
	// Клиент с полным перечнем
	{
		client::context_t client;
		client.name("secret.example");
		ASSERT_EQ(client.ech(server.ech()), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(client.shrouded());
		EXPECT_TRUE(server.shrouded());
	}
	// Клиент лишь со второй конфигурацией
	{
		server::context_t anew;
		anew.credential(credential);
		ASSERT_EQ(anew.ech(vector <uint8_t> (), "public.example", 7, 64), context::error_t::NONE);
		ASSERT_EQ(anew.ech(vector <uint8_t> (), "public.example", 9, 64), context::error_t::NONE);
		// Ключи anew порождены заново: перечень берётся у него, вторая конфигурация - записью как есть
		ASSERT_EQ(ech::parse(view_t(anew.ech().data(), anew.ech().size()), configs), ech::error_t::NONE);
		ASSERT_EQ(configs.size(), static_cast <size_t> (2));
		vector <uint8_t> second;
		second.push_back(static_cast <uint8_t> (configs[1].raw.size() >> 8));
		second.push_back(static_cast <uint8_t> (configs[1].raw.size() & 0xFF));
		second.insert(second.end(), configs[1].raw.begin(), configs[1].raw.end());
		client::context_t client;
		client.name("secret.example");
		ASSERT_EQ(client.ech(second), context::error_t::NONE);
		ASSERT_EQ(anew.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, anew);
		ASSERT_TRUE(client.established() && anew.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (anew.error());
		EXPECT_TRUE(client.shrouded());
		EXPECT_TRUE(anew.shrouded());
	}
}

/**
 * Ротация ключей: прежняя конфигурация удержана - клиент с прежней записью раскрывается, но retry_configs
 * и перечень DNS несут лишь новую; без удержания прежний ключ отвергается и клиент получает новую
 */
TEST(EchTest, Rotation){
	context::credential_t credential;
	ASSERT_TRUE(identity("ec256", credential));
	const vector <uint8_t> older = corpus("ech/bssl.key"), stale = corpus("ech/bssl.list");
	ASSERT_FALSE(older.empty());
	ASSERT_FALSE(stale.empty());
	// Сервер после ротации: новая объявлена, прежняя удержана
	{
		server::context_t server;
		server.credential(credential);
		ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 11, 64), context::error_t::NONE);
		ASSERT_EQ(server.retain(older, "public.example", 7, 64), context::error_t::NONE);
		vector <ech::config_t> configs;
		ASSERT_EQ(ech::parse(view_t(server.ech().data(), server.ech().size()), configs), ech::error_t::NONE);
		ASSERT_EQ(configs.size(), static_cast <size_t> (1));
		EXPECT_EQ(configs[0].id, 11);
		client::context_t client;
		client.name("secret.example");
		ASSERT_EQ(client.ech(stale), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(client.shrouded());
		EXPECT_TRUE(server.shrouded());
		EXPECT_TRUE(client.retry().empty());
	}
	// Сервер без удержания: прежний ключ отвергнут, клиент получает новую конфигурацию
	{
		server::context_t server;
		server.credential(credential);
		ASSERT_EQ(server.ech(vector <uint8_t> (), "public.example", 11, 64), context::error_t::NONE);
		client::context_t client;
		client.name("secret.example");
		ASSERT_EQ(client.ech(stale), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		EXPECT_FALSE(server.shrouded());
		EXPECT_EQ(client.retry(), server.ech());
		vector <ech::config_t> configs;
		ASSERT_EQ(ech::parse(view_t(client.retry().data(), client.retry().size()), configs), ech::error_t::NONE);
		ASSERT_EQ(configs.size(), static_cast <size_t> (1));
		EXPECT_EQ(configs[0].id, 11);
	}
	// Только удержанная конфигурация: перечень пуст, а раскрытие идёт
	{
		server::context_t server;
		server.credential(credential);
		ASSERT_EQ(server.retain(older, "public.example", 7, 64), context::error_t::NONE);
		EXPECT_TRUE(server.ech().empty());
		client::context_t client;
		client.name("secret.example");
		ASSERT_EQ(client.ech(stale), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_TRUE(server.shrouded());
	}
}
