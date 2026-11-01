/**
 * @file ffdhe.cpp
 * @date 2026-09-09
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
 * @brief Проверки модуля выработки общего ключа в конечном поле по RFC 7919: модули против
 *        системного openssl, обмен, отказы на ключах вне подгруппы, сличение с openssl
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <main.hpp>
#include <asn1/asn1.hpp>
#include <agreement/ffdhe.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Служебные помощники проверок
 *
 */
namespace {
	/**
	 * @brief Функция разбора шестнадцатеричной записи
	 *
	 * @param text запись
	 * @param data место байтов
	 * @return     число байтов
	 *
	 */
	static size_t bytes(const char * text, uint8_t * data) {
		// Число собранных байтов
		size_t result = 0;
		/**
		 * Перебираем: знаки шестнадцатеричной записи, пока не конец строки
		 */
		for(size_t i = 0; text[i * 2] != '\0'; i++){
			// Значение собираемого байта
			uint8_t value = 0;
			/**
			 * Перебираем: два знака очередного байта
			 */
			for(size_t j = 0; j < 2; j++){
				// Очередной знак записи
				const char letter = text[(i * 2) + j];
				// Сдвигаем значение и добавляем полубайт знака
				value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
			}
			// Сохраняем собранный байт
			data[result++] = value;
		}
		// Возвращаем число байтов
		return result;
	}
	/**
	 * @brief Функция шестнадцатеричной записи байтов
	 *
	 * @param data байты
	 * @param size длина
	 * @return     запись
	 *
	 */
	static std::string text(const uint8_t * data, const size_t size) {
		// Собираемая запись
		std::string result;
		// Набор шестнадцатеричных знаков
		static const char * letters = "0123456789abcdef";
		/**
		 * Перебираем: байты записи
		 */
		for(size_t i = 0; i < size; i++){
			// Дописываем старший полубайт байта
			result.append(1, letters[(data[i] >> 4) & 0x0F]);
			result.append(1, letters[data[i] & 0x0F]);
		}
		// Выводим запись в шестнадцатеричном виде
		return result;
	}
	/**
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь
	 * @return     содержимое
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Содержимое файла
		std::string result;
		// Открываем файл на чтение
		FILE * file = ::fopen(path.c_str(), "rb");
		// Проверяем успех открытия
		if(file == nullptr)
			// Возвращаем пустое содержимое
			return result;
		// Буфер чтения
		char buffer[256];
		// Число прочитанных байтов
		size_t count = 0;
		/**
		 * Читаем файл блоками, пока есть данные
		 */
		while((count = ::fread(buffer, 1, sizeof(buffer), file)) > 0)
			// Дописываем прочитанный блок
			result.append(buffer, count);
		// Закрываем файл
		::fclose(file);
		// Возвращаем содержимое файла
		return result;
	}
	/**
	 * @brief Функция записи файла
	 *
	 * @param path путь
	 * @param data байты
	 * @param size длина
	 * @return     признак успешности
	 *
	 */
	static bool spill(const std::string & path, const uint8_t * data, const size_t size) {
		// Открываем файл на запись
		FILE * file = ::fopen(path.c_str(), "wb");
		// Проверяем успех открытия
		if(file == nullptr)
			// Возвращаем признак неудачи
			return false;
		// Признак полной записи
		const bool ok = (::fwrite(data, 1, size, file) == size);
		// Закрываем файл
		::fclose(file);
		// Возвращаем признак успешной записи
		return ok;
	}
	/**
	 * @brief Функция запуска команды оболочки
	 *
	 * @param command команда
	 * @return        признак нулевого кода завершения
	 *
	 */
	static bool run(const std::string & command) {
		// Выполняем команду с отключённым вводом и возвращаем признак нулевого кода завершения
		return (::system((command + " </dev/null").c_str()) == 0);
	}
};

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Длины модулей пяти групп в байтах
	 */
	static const size_t SIZES[5] = {256, 384, 512, 768, 1024};
	/**
	 * Имена групп у openssl
	 */
	static const char * NAMES[5] = {"ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"};
	/**
	 * @brief Функция извлечения шестнадцатеричной записи поля из вывода openssl pkey -text
	 *
	 * @param text  вывод
	 * @param label подпись поля
	 * @param result байты
	 * @return      признак успешности
	 *
	 */
	static bool field(const std::string & text, const std::string & label, std::vector <uint8_t> & result) noexcept {
		// Очищаем приёмник
		result.clear();
		// Ищем подпись поля в выводе
		size_t at = text.find(label);
		// Проверяем нахождение подписи
		if(at == std::string::npos)
			// Возвращаем признак неудачи
			return false;
		// Переносим позицию за подпись
		at += label.size();
		// Собираемая шестнадцатеричная запись
		std::string hex;
		/**
		 * Перебираем: знаки поля до конца вывода
		 */
		for(; at < text.size(); at++){
			// Очередной знак вывода
			const char letter = text[at];
			// Пропускаем разделители поля
			if((letter == ':') || (letter == ' ') || (letter == '\n') || (letter == '\r'))
				continue;
			// Проверяем знак на шестнадцатеричность
			if(::isxdigit(static_cast <unsigned char> (letter))){
				// Дописываем шестнадцатеричный знак
				hex.push_back(letter);
				continue;
			}
			break;
		}
		// Проверяем непустоту и чётность записи
		if(hex.empty() || ((hex.size() % 2) != 0))
			// Возвращаем признак неудачи
			return false;
		// Выделяем место под байты записи
		result.assign(hex.size() / 2, 0);
		// Разбираем запись и сверяем число байтов
		return (bytes(hex.c_str(), result.data()) == result.size());
	}
	/**
	 * @brief Функция записи целого DER без знака
	 *
	 * @param writer записывающий
	 * @param value  байты старшим вперёд
	 * @return       признак успешности
	 *
	 */
	static bool unsignedInteger(asn1::writer_t & writer, const view_t & value) noexcept {
		// Содержимое целого
		std::vector <uint8_t> content;
		// Число отсекаемых ведущих нулей
		size_t skip = 0;
		/**
		 * Отсекаем ведущие нулевые байты, пока не останется один
		 */
		while((skip + 1 < value.size) && (value.data[skip] == 0))
			// Отсекаем очередной ведущий ноль
			skip++;
		// Проверяем установленный старший бит
		if(value.data[skip] & 0x80)
			// Дописываем нулевой старший байт
			content.push_back(0);
		// Дописываем значение без ведущих нулей
		content.insert(content.end(), value.data + skip, value.data + value.size);
		// Записываем целое и возвращаем признак успеха
		return writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(content.data(), content.size()));
	}
	/**
	 * @brief Функция записи открытого ключа DH записью SubjectPublicKeyInfo (PKCS #3) в PEM
	 *
	 * @param path путь файла
	 * @param size длина модуля
	 * @param key  открытый ключ длиной в модуль
	 * @return     признак успешности
	 *
	 */
	static bool publish(const std::string & path, const size_t size, const uint8_t * key) noexcept {
		// Модуль группы
		const view_t prime = agreement::prime(size);
		// Записывающий открытого ключа
		asn1::writer_t inner;
		// Записываем открытый ключ целым
		if(!unsignedInteger(inner, view_t(key, size)))
			// Возвращаем признак неудачи
			return false;
		// Записывающий итоговой записи
		asn1::writer_t writer;
		// Открываем цепочку последовательностей и записываем идентификатор алгоритма
		if(!writer.open(asn1::tag_t::SEQUENCE) || !writer.open(asn1::tag_t::SEQUENCE) || !writer.oid("1.2.840.113549.1.3.1") || !writer.open(asn1::tag_t::SEQUENCE))
			// Возвращаем признак неудачи
			return false;
		// Записываем параметры и закрываем последовательности
		if(!unsignedInteger(writer, prime) || !writer.integer(2) || !writer.close() || !writer.close())
			// Возвращаем признак неудачи
			return false;
		// Записываем биты открытого ключа и закрываем запись
		if(!writer.bits(inner.data()) || !writer.close())
			// Возвращаем признак неудачи
			return false;
		// Готовая DER-запись
		const view_t der = writer.data();
		// Сохраняем запись в файл и возвращаем признак успеха
		return spill(path, der.data, der.size);
	}
	/**
	 * @brief Функция снятия ведущих нулей
	 *
	 * @param data байты
	 * @return     запись без ведущих нулей
	 *
	 */
	static std::string trimmed(const std::vector <uint8_t> & data) noexcept {
		// Число отсекаемых ведущих нулей
		size_t skip = 0;
		/**
		 * Отсекаем ведущие нулевые байты, пока не останется один
		 */
		while((skip + 1 < data.size()) && (data[skip] == 0))
			// Отсекаем очередной ведущий ноль
			skip++;
		// Возвращаем запись без ведущих нулей
		return text(data.data() + skip, data.size() - skip);
	}
	/**
	 * @brief Функция записи параметров DH (p, g) в DER для openssl
	 *
	 * @param path      путь файла
	 * @param prime     модуль от старшего байта к младшему
	 * @param generator образующая от старшего байта к младшему
	 * @return          признак успешности
	 *
	 */
	static bool params(const std::string & path, const view_t & prime, const view_t & generator) noexcept {
		// Записывающий параметров
		asn1::writer_t writer;
		// Открываем последовательность
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Возвращаем признак неудачи
			return false;
		// Записываем модуль и образующую
		if(!unsignedInteger(writer, prime) || !unsignedInteger(writer, generator))
			// Возвращаем признак неудачи
			return false;
		// Закрываем последовательность
		if(!writer.close())
			// Возвращаем признак неудачи
			return false;
		// Готовая DER-запись
		const view_t der = writer.data();
		// Сохраняем запись в файл и возвращаем признак успеха
		return spill(path, der.data, der.size);
	}
	/**
	 * @brief Функция записи открытого ключа DH записью SubjectPublicKeyInfo в DER
	 *
	 * @param path      путь файла
	 * @param prime     модуль от старшего байта к младшему
	 * @param key       открытый ключ длиной в модуль
	 * @return          признак успешности
	 *
	 */
	static bool publish(const std::string & path, const view_t & prime, const uint8_t * key) noexcept {
		// Записывающий открытого ключа
		asn1::writer_t inner;
		// Записываем открытый ключ целым
		if(!unsignedInteger(inner, view_t(key, prime.size)))
			// Возвращаем признак неудачи
			return false;
		// Записывающий итоговой записи
		asn1::writer_t writer;
		// Открываем цепочку последовательностей и записываем идентификатор алгоритма
		if(!writer.open(asn1::tag_t::SEQUENCE) || !writer.open(asn1::tag_t::SEQUENCE) || !writer.oid("1.2.840.113549.1.3.1") || !writer.open(asn1::tag_t::SEQUENCE))
			// Возвращаем признак неудачи
			return false;
		// Записываем модуль, образующую и закрываем последовательности
		if(!unsignedInteger(writer, prime) || !writer.integer(2) || !writer.close() || !writer.close())
			// Возвращаем признак неудачи
			return false;
		// Записываем биты открытого ключа и закрываем запись
		if(!writer.bits(inner.data()) || !writer.close())
			// Возвращаем признак неудачи
			return false;
		// Готовая DER-запись
		const view_t der = writer.data();
		// Сохраняем запись в файл и возвращаем признак успеха
		return spill(path, der.data, der.size);
	}
};

/**
 * @brief Проверка модулей пяти групп против системного openssl
 *
 */
TEST(FfdheTest, Primes) {
	/**
	 * Перебираем: пять групп RFC 7919
	 */
	for(size_t i = 0; i < 5; i++){
		// Модуль очередной группы
		const view_t prime = agreement::prime(SIZES[i]);
		// Проверяем длину модуля
		ASSERT_EQ(prime.size, SIZES[i]) << NAMES[i];
		// Старший и младший байты модуля RFC 7919 равны 0xFF, образующая два
		EXPECT_EQ(prime.data[0], 0xFF) << NAMES[i];
		EXPECT_EQ(prime.data[SIZES[i] - 1], 0xFF) << NAMES[i];
		// Проверяем длину показателя
		EXPECT_GT(agreement::exponent(SIZES[i]), static_cast <size_t> (31)) << NAMES[i];
	}
	// Проверяем пустоту модуля негодной длины
	EXPECT_EQ(agreement::prime(128).size, static_cast <size_t> (0));
	EXPECT_EQ(agreement::exponent(128), static_cast <size_t> (0));
	// Проверяем наличие групп RFC 7919 у системного openssl
	if(!run("openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out /dev/null >/dev/null 2>&1"))
		// Пропускаем проверку без групп RFC 7919
		GTEST_SKIP() << "Системный openssl без групп RFC 7919";
	// Шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	/**
	 * Перебираем: пять групп против системного openssl
	 */
	for(size_t i = 0; i < 5; i++){
		// Порождаем параметры группы у openssl
		ASSERT_TRUE(run("openssl genpkey -genparam -algorithm DH -pkeyopt group:" + std::string(NAMES[i]) + " -out " + dir + "/p.pem 2>/dev/null"));
		// Конвейер в подоболочке: перенаправление ввода помощника run() относится к последнему звену
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p.pem | grep INTEGER | head -1 | sed 's/.*://' > " + dir + "/p.hex)"));
		// Считываем шестнадцатеричную запись модуля
		std::string hex = slurp(dir + "/p.hex");
		/**
		 * Отсекаем переводы строк с конца записи
		 */
		while(!hex.empty() && ((hex.back() == '\n') || (hex.back() == '\r')))
			// Отсекаем перевод строки
			hex.pop_back();
		/**
		 * Перебираем: знаки шестнадцатеричной записи
		 */
		for(size_t k = 0; k < hex.size(); k++)
			// Приводим знак к нижнему регистру
			hex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (hex[k])));
		// Модуль нашей реализации
		const view_t prime = agreement::prime(SIZES[i]);
		// Сверяем запись модуля с openssl
		EXPECT_EQ(text(prime.data, prime.size), hex) << NAMES[i];
	}
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * @brief Проверка порождения пар и обмена на всех пяти группах
 *
 */
TEST(FfdheTest, Exchange) {
	/**
	 * Перебираем: пять групп обмена
	 */
	for(size_t i = 0; i < 5; i++){
		// Длина модуля и показателя очередной группы
		const size_t size = SIZES[i], length = agreement::exponent(size);
		// Места секретов, ключей и общих значений сторон
		std::vector <uint8_t> secretA(length), keyA(size), secretB(length), keyB(size), sharedA(size), sharedB(size), derived(size);
		// Порождаем пару первой стороны
		ASSERT_TRUE(agreement::pairffdhe(size, secretA.data(), keyA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::pairffdhe(size, secretB.data(), keyB.data())) << NAMES[i];
		// Проверяем различие открытых ключей
		EXPECT_NE(text(keyA.data(), size), text(keyB.data(), size)) << NAMES[i];
		// Выводим открытый ключ из секрета первой стороны
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretA.data(), length), derived.data())) << NAMES[i];
		// Сверяем выведенный ключ с открытым
		EXPECT_EQ(text(derived.data(), size), text(keyA.data(), size)) << NAMES[i];
		// Вычисляем общее значение первой стороной
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretA.data(), length), view_t(keyB.data(), size), sharedA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretB.data(), length), view_t(keyA.data(), size), sharedB.data())) << NAMES[i];
		// Сверяем общие значения сторон
		EXPECT_EQ(text(sharedA.data(), size), text(sharedB.data(), size)) << NAMES[i];
	}
}

/**
 * @brief Проверка отказов: ключи 0, 1, p - 1, p, ключ вне подгруппы (p - 2), негодные длины
 *
 */
TEST(FfdheTest, Reject) {
	// Длина модуля и показателя группы
	const size_t size = 256, length = agreement::exponent(size);
	// Места секрета, ключа, чужого ключа и общего значения
	std::vector <uint8_t> secret(length), key(size), peer(size), shared(size);
	// Порождаем свою пару
	ASSERT_TRUE(agreement::pairffdhe(size, secret.data(), key.data()));
	// Модуль группы
	const view_t prime = agreement::prime(size);
	// Ноль
	std::fill(peer.begin(), peer.end(), 0);
	// Проверяем отказ для нуля
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Единица
	peer[size - 1] = 1;
	// Проверяем отказ для единицы
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p
	::memcpy(peer.data(), prime.data, size);
	// Проверяем отказ для модуля
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p - 1
	peer[size - 1] = 0xFE;
	// Проверяем отказ для модуля минус один
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p - 2: невычет вне подгруппы порядка q, но в границах - принимается намеренно (проверки Y^q нет)
	peer[size - 1] = 0xFD;
	// Проверяем приём ключа вне подгруппы
	EXPECT_TRUE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Два: вычет, лежит в подгруппе - принимается
	std::fill(peer.begin(), peer.end(), 0);
	// Задаём чужой ключ равным двум
	peer[size - 1] = 2;
	// Проверяем приём вычета из подгруппы
	EXPECT_TRUE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Негодные длины и места
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(key.data(), size - 1), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), 0), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(key.data(), size), nullptr));
	EXPECT_FALSE(agreement::ffdhe(200, view_t(secret.data(), length), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), nullptr));
	EXPECT_FALSE(agreement::pairffdhe(100, secret.data(), key.data()));
	// Нулевой показатель
	std::fill(secret.begin(), secret.end(), 0);
	// Проверяем отказ для нулевого показателя
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), key.data()));
}

/**
 * @brief Сличение с системным openssl: открытый ключ из чужого показателя и общее значение
 *
 */
TEST(FfdheTest, Foreign) {
	// Проверяем наличие групп RFC 7919 у системного openssl
	if(!run("openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out /dev/null >/dev/null 2>&1"))
		// Пропускаем проверку без групп RFC 7919
		GTEST_SKIP() << "Системный openssl без групп RFC 7919";
	// Шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	/**
	 * Перебираем: три группы против системного openssl
	 */
	for(size_t i = 0; i < 3; i++){
		// Длина модуля очередной группы
		const size_t size = SIZES[i];
		// Порождаем параметры группы у openssl
		ASSERT_TRUE(run("openssl genpkey -genparam -algorithm DH -pkeyopt group:" + std::string(NAMES[i]) + " -out " + dir + "/p.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl genpkey -paramfile " + dir + "/p.pem -out " + dir + "/a.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl pkey -in " + dir + "/a.pem -text -noout > " + dir + "/a.txt 2>/dev/null")) << NAMES[i];
		// Считываем вывод openssl с ключами
		const std::string dump = slurp(dir + "/a.txt");
		// Секрет и открытый ключ чужой пары
		std::vector <uint8_t> secret, pub;
		// Извлекаем секрет чужой пары
		ASSERT_TRUE(field(dump, "private-key:", secret)) << dump;
		ASSERT_TRUE(field(dump, "public-key:", pub)) << dump;
		// Открытый ключ из чужого показателя
		std::vector <uint8_t> derived(size);
		// Выводим открытый ключ из чужого секрета
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secret.data(), secret.size()), derived.data())) << NAMES[i];
		// Сверяем выведенный ключ с чужим
		EXPECT_EQ(trimmed(derived), trimmed(pub)) << NAMES[i];
		// Своя пара и общее значение с чужим открытым ключом
		std::vector <uint8_t> mine(agreement::exponent(size)), key(size), shared(size), peer(size, 0);
		// Порождаем свою пару
		ASSERT_TRUE(agreement::pairffdhe(size, mine.data(), key.data())) << NAMES[i];
		// Запись openssl вправе нести ведущий ноль
		size_t skip = 0;
		/**
		 * Отсекаем ведущие нулевые байты чужого ключа
		 */
		while((skip + 1 < pub.size()) && (pub[skip] == 0))
			// Отсекаем очередной ведущий ноль
			skip++;
		// Проверяем укладку чужого ключа в модуль
		ASSERT_LE(pub.size() - skip, size);
		// Копируем чужой ключ по правому краю модуля
		::memcpy(peer.data() + (size - (pub.size() - skip)), pub.data() + skip, pub.size() - skip);
		// Вычисляем общее значение с чужим ключом
		ASSERT_TRUE(agreement::ffdhe(size, view_t(mine.data(), mine.size()), view_t(peer.data(), size), shared.data())) << NAMES[i];
		// Своё открытое - в PEM для openssl
		ASSERT_TRUE(publish(dir + "/b.der", size, key.data())) << NAMES[i];
		ASSERT_TRUE(run("openssl pkey -pubin -inform DER -in " + dir + "/b.der -out " + dir + "/b.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/a.pem -peerkey " + dir + "/b.pem -out " + dir + "/shared.bin 2>/dev/null")) << NAMES[i];
		// Считываем чужое общее значение
		const std::string foreign = slurp(dir + "/shared.bin");
		// Проверяем непустоту чужого значения
		ASSERT_FALSE(foreign.empty()) << NAMES[i];
		// Сверяем своё общее значение с чужим
		EXPECT_EQ(trimmed(shared), trimmed(std::vector <uint8_t> (foreign.begin(), foreign.end()))) << NAMES[i];
	}
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * Проверка модулей, длин показателя и параметров групп RFC 3526
 */
TEST(FfdheTest, Rfc3526Primes) {
	// Проверяем пустоту модуля негодного идентификатора
	EXPECT_EQ(agreement::prime3526(13).size, static_cast <size_t> (0));
	EXPECT_EQ(agreement::exponent3526(13), static_cast <size_t> (0));
	// Идентификаторы трёх групп
	static const uint8_t IDS[3] = {14, 15, 16};
	// Длины модулей трёх групп
	static const size_t SIZES[3] = {256, 384, 512};
	// Имена групп у openssl
	static const char * NAMES[3] = {"modp2048", "modp3072", "modp4096"};
	/**
	 * Перебираем: три группы RFC 3526
	 */
	for(size_t i = 0; i < 3; i++){
		// Модуль очередной группы
		const view_t prime = agreement::prime3526(IDS[i]);
		// Проверяем длину модуля
		ASSERT_EQ(prime.size, SIZES[i]) << NAMES[i];
		// Проверяем старший байт модуля
		EXPECT_EQ(prime.data[0], 0xFF) << NAMES[i];
		EXPECT_EQ(prime.data[SIZES[i] - 1], 0xFF) << NAMES[i];
		// Обратная совместимость с RFC 7919 по длине модуля и показателя
		EXPECT_EQ(agreement::exponent(SIZES[i]), agreement::exponent3526(IDS[i])) << NAMES[i];
	}
	// Проверяем наличие dhparam у системного openssl
	if(!run("openssl dhparam -help >/dev/null 2>&1"))
		// Пропускаем проверку без dhparam
		GTEST_SKIP() << "Системный openssl без dhparam";
	// Шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	/**
	 * Перебираем: три группы против системного openssl
	 */
	for(size_t i = 0; i < 3; i++){
		// Модуль очередной группы
		const view_t prime = agreement::prime3526(IDS[i]);
		// Образующая равная двум
		const uint8_t gen[1] = {2};
		// Записываем параметры группы для openssl
		ASSERT_TRUE(params(dir + "/p" + std::to_string(IDS[i]) + ".der", prime, view_t(gen, 1))) << NAMES[i];
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p" + std::to_string(IDS[i]) + ".der -inform DER | grep INTEGER | head -1 | sed 's/.*://' > " + dir + "/p" + std::to_string(IDS[i]) + ".hex)")) << NAMES[i];
		// Считываем запись модуля
		std::string hex = slurp(dir + "/p" + std::to_string(IDS[i]) + ".hex");
		/**
		 * Отсекаем переводы строк с конца записи модуля
		 */
		while(!hex.empty() && ((hex.back() == '\n') || (hex.back() == '\r')))
			// Отсекаем перевод строки
			hex.pop_back();
		/**
		 * Перебираем: знаки записи модуля
		 */
		for(size_t k = 0; k < hex.size(); k++)
			// Приводим знак к нижнему регистру
			hex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (hex[k])));
		// Сверяем запись модуля с openssl
		EXPECT_EQ(text(prime.data, prime.size), hex) << NAMES[i];
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p" + std::to_string(IDS[i]) + ".der -inform DER | grep INTEGER | sed -n '2p' | sed 's/.*://' > " + dir + "/g" + std::to_string(IDS[i]) + ".hex)")) << NAMES[i];
		// Считываем запись образующей
		std::string ghex = slurp(dir + "/g" + std::to_string(IDS[i]) + ".hex");
		/**
		 * Отсекаем переводы строк с конца записи образующей
		 */
		while(!ghex.empty() && ((ghex.back() == '\n') || (ghex.back() == '\r')))
			// Отсекаем перевод строки
			ghex.pop_back();
		/**
		 * Перебираем: знаки записи образующей
		 */
		for(size_t k = 0; k < ghex.size(); k++)
			// Приводим знак к нижнему регистру
			ghex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (ghex[k])));
		// Сверяем запись образующей с двум
		EXPECT_EQ(std::string("02"), ghex) << NAMES[i];
	}
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * Проверка порождения пар и обмена на группах RFC 3526
 */
TEST(FfdheTest, Rfc3526Exchange) {
	// Идентификаторы трёх групп
	static const uint8_t IDS[3] = {14, 15, 16};
	// Имена групп у openssl
	static const char * NAMES[3] = {"modp2048", "modp3072", "modp4096"};
	// Образующая равная двум
	const uint8_t gen[1] = {2};
	// Просмотр образующей
	const view_t generator(gen, 1);
	/**
	 * Перебираем: три группы обмена
	 */
	for(size_t i = 0; i < 3; i++){
		// Модуль очередной группы
		const view_t prime = agreement::prime3526(IDS[i]);
		// Длина модуля
		const size_t size = prime.size;
		// Длина показателя
		const size_t length = agreement::exponent3526(IDS[i]);
		// Места секретов, ключей и общих значений сторон
		std::vector <uint8_t> secretA(length), keyA(size), secretB(length), keyB(size), sharedA(size), sharedB(size), derived(size);
		// Порождаем пару первой стороны
		ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretA.data(), keyA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretB.data(), keyB.data())) << NAMES[i];
		// Проверяем различие открытых ключей
		EXPECT_NE(text(keyA.data(), size), text(keyB.data(), size)) << NAMES[i];
		// Выводим открытый ключ из секрета первой стороны
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretA.data(), length), derived.data())) << NAMES[i];
		// Сверяем выведенный ключ с открытым
		EXPECT_EQ(text(derived.data(), size), text(keyA.data(), size)) << NAMES[i];
		// Вычисляем общее значение первой стороной
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretA.data(), length), view_t(keyB.data(), size), sharedA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretB.data(), length), view_t(keyA.data(), size), sharedB.data())) << NAMES[i];
		// Сверяем общие значения сторон
		EXPECT_EQ(text(sharedA.data(), size), text(sharedB.data(), size)) << NAMES[i];
	}
}

/**
 * Отказы границ для произвольного модуля: ключи 0, 1, p − 1, p, негодные длины и генератор
 */
TEST(FfdheTest, Rfc3526Reject) {
	// Модуль группы modp14
	const view_t prime = agreement::prime3526(14);
	// Длина модуля
	const size_t size = prime.size;
	// Длина показателя
	const size_t length = agreement::exponent3526(14);
	// Образующая равная двум
	const uint8_t gen[1] = {2};
	// Просмотр образующей
	const view_t generator(gen, 1);
	// Места секрета, ключа, чужого ключа и общего значения
	std::vector <uint8_t> secret(length), key(size), peer(size), shared(size);
	// Порождаем свою пару
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secret.data(), key.data()));
	// Ноль
	std::fill(peer.begin(), peer.end(), 0);
	// Проверяем отказ для нуля
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Единица
	std::fill(peer.begin(), peer.end(), 0);
	// Задаём чужой ключ равным единице
	peer[size - 1] = 1;
	// Проверяем отказ для единицы
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p
	::memcpy(peer.data(), prime.data, size);
	// Проверяем отказ для модуля
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p − 1
	peer[size - 1] = 0xFE;
	// Проверяем отказ для модуля минус один
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p − 2: в границах, принимается
	peer[size - 1] = 0xFD;
	// Проверяем приём ключа в границах
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Два: в границах, принимается
	std::fill(peer.begin(), peer.end(), 0);
	// Задаём чужой ключ равным двум
	peer[size - 1] = 2;
	// Проверяем приём вычета в границах
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Негодные длины и места
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(key.data(), size - 1), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), 0), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(key.data(), size), nullptr));
	// Проверяем вывод открытого ключа из секрета
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), key.data()));
	// Проверяем отказ для нулевой длины показателя
	EXPECT_FALSE(agreement::pairffdhe(prime, generator, 0, secret.data(), key.data()));
	// Негодная образующая
	uint8_t bad = 1;
	// Проверяем отказ для негодной образующей
	EXPECT_FALSE(agreement::ffdhe(prime, view_t(&bad, 1), view_t(secret.data(), length), key.data()));
	// Нулевой показатель
	std::fill(secret.begin(), secret.end(), 0);
	// Проверяем отказ для нулевого показателя
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), key.data()));
}

/**
 * Сличение modp14 с системным openssl: открытый ключ из чужого показателя и общее значение
 */
TEST(FfdheTest, Rfc3526Foreign) {
	// Проверяем наличие dhparam у системного openssl
	if(!run("openssl dhparam -help >/dev/null 2>&1"))
		// Пропускаем проверку без dhparam
		GTEST_SKIP() << "Системный openssl без dhparam";
	// Модуль группы modp14
	const view_t prime = agreement::prime3526(14);
	// Образующая равная двум
	const uint8_t gen[1] = {2};
	// Просмотр образующей
	const view_t generator(gen, 1);
	// Шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	// Записываем параметры группы для openssl
	ASSERT_TRUE(params(dir + "/p.der", prime, generator));
	ASSERT_TRUE(run("openssl dhparam -in " + dir + "/p.der -inform DER -out " + dir + "/p.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl genpkey -paramfile " + dir + "/p.pem -out " + dir + "/a.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/a.pem -text -noout > " + dir + "/a.txt 2>/dev/null"));
	// Считываем вывод openssl с ключами
	const std::string dump = slurp(dir + "/a.txt");
	// Секрет и открытый ключ чужой пары
	std::vector <uint8_t> secret, pub;
	// Извлекаем секрет чужой пары
	ASSERT_TRUE(field(dump, "private-key:", secret)) << dump;
	ASSERT_TRUE(field(dump, "public-key:", pub)) << dump;
	// Открытый ключ из чужого показателя
	std::vector <uint8_t> derived(256);
	// Выводим открытый ключ из чужого секрета
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), secret.size()), derived.data()));
	// Сверяем выведенный ключ с чужим
	EXPECT_EQ(trimmed(derived), trimmed(pub));
	// Своя пара и общее значение с чужим открытым ключом
	std::vector <uint8_t> mine(agreement::exponent3526(14)), key(256), shared(256), peer(256, 0);
	// Порождаем свою пару
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, mine.size(), mine.data(), key.data()));
	// Запись openssl вправе нести ведущий ноль
	size_t skip = 0;
	/**
	 * Отсекаем ведущие нулевые байты чужого ключа
	 */
	while((skip + 1 < pub.size()) && (pub[skip] == 0))
		// Отсекаем очередной ведущий ноль
		skip++;
	// Проверяем укладку чужого ключа в модуль
	ASSERT_LE(pub.size() - skip, static_cast <size_t> (256));
	// Копируем чужой ключ по правому краю модуля
	::memcpy(peer.data() + (256 - (pub.size() - skip)), pub.data() + skip, pub.size() - skip);
	// Вычисляем общее значение с чужим ключом
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(mine.data(), mine.size()), view_t(peer.data(), 256), shared.data()));
	// Своё открытое - в PEM для openssl
	ASSERT_TRUE(publish(dir + "/b.der", prime, key.data()));
	ASSERT_TRUE(run("openssl pkey -pubin -inform DER -in " + dir + "/b.der -out " + dir + "/b.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/a.pem -peerkey " + dir + "/b.pem -out " + dir + "/shared.bin 2>/dev/null"));
	// Считываем чужое общее значение
	const std::string foreign = slurp(dir + "/shared.bin");
	// Проверяем непустоту чужого значения
	ASSERT_FALSE(foreign.empty());
	// Сверяем своё общее значение с чужим
	EXPECT_EQ(trimmed(shared), trimmed(std::vector <uint8_t> (foreign.begin(), foreign.end())));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * Проверка группы modp18 на 8192 разряда: модуль, обмен и интероп с openssl
 */
TEST(FfdheTest, Rfc3526Modp18) {
	// Модуль и показатель modp18
	const view_t prime = agreement::prime3526(18);
	// Образующая равная двум
	const uint8_t gen[1] = {2};
	// Просмотр образующей
	const view_t generator(gen, 1);
	// Длины обязаны отвечать 8192 разрядам модуля и показателю ffdhe8192
	ASSERT_EQ(prime.size, static_cast <size_t> (1024));
	// Проверяем старший байт модуля
	EXPECT_EQ(prime.data[0], 0xFF);
	EXPECT_EQ(prime.data[1023], 0xFF);
	EXPECT_EQ(agreement::exponent3526(18), agreement::exponent(1024));
	// Круговой обмен своими парами
	const size_t length = agreement::exponent3526(18);
	// Места секретов, ключей и общих значений сторон
	std::vector <uint8_t> secretA(length), keyA(1024), secretB(length), keyB(1024), sharedA(1024), sharedB(1024);
	// Порождаем пару первой стороны
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretA.data(), keyA.data()));
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretB.data(), keyB.data()));
	// Проверяем различие открытых ключей
	EXPECT_NE(text(keyA.data(), 1024), text(keyB.data(), 1024));
	// Вычисляем общее значение первой стороной
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretA.data(), length), view_t(keyB.data(), 1024), sharedA.data()));
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretB.data(), length), view_t(keyA.data(), 1024), sharedB.data()));
	// Сверяем общие значения сторон
	EXPECT_EQ(text(sharedA.data(), 1024), text(sharedB.data(), 1024));
	// Интероп с openssl по параметрам PKCS#3
	if(!run("openssl dhparam -help >/dev/null 2>&1"))
		// Пропускаем проверку без dhparam
		GTEST_SKIP() << "Системный openssl без dhparam";
	// Шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	// Записываем параметры группы для openssl
	ASSERT_TRUE(params(dir + "/p.der", prime, generator));
	ASSERT_TRUE(run("openssl dhparam -in " + dir + "/p.der -inform DER -out " + dir + "/p.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl genpkey -paramfile " + dir + "/p.pem -out " + dir + "/a.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/a.pem -text -noout > " + dir + "/a.txt 2>/dev/null"));
	// Считываем вывод openssl с ключами
	const std::string dump = slurp(dir + "/a.txt");
	// Секрет и открытый ключ чужой пары
	std::vector <uint8_t> secret, pub;
	// Извлекаем секрет чужой пары
	ASSERT_TRUE(field(dump, "private-key:", secret)) << dump;
	ASSERT_TRUE(field(dump, "public-key:", pub)) << dump;
	// Открытый ключ из чужого показателя
	std::vector <uint8_t> derived(1024);
	// Выводим открытый ключ из чужого секрета
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), secret.size()), derived.data()));
	// Сверяем выведенный ключ с чужим
	EXPECT_EQ(trimmed(derived), trimmed(pub));
	// Своя пара и общее значение с чужим открытым ключом
	std::vector <uint8_t> mine(length), key(1024), shared(1024), peer(1024, 0);
	// Порождаем свою пару
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, mine.size(), mine.data(), key.data()));
	// Запись openssl вправе нести ведущий ноль
	size_t skip = 0;
	/**
	 * Отсекаем ведущие нулевые байты чужого ключа
	 */
	while((skip + 1 < pub.size()) && (pub[skip] == 0))
		// Отсекаем очередной ведущий ноль
		skip++;
	// Проверяем укладку чужого ключа в модуль
	ASSERT_LE(pub.size() - skip, static_cast <size_t> (1024));
	// Копируем чужой ключ по правому краю модуля
	::memcpy(peer.data() + (1024 - (pub.size() - skip)), pub.data() + skip, pub.size() - skip);
	// Вычисляем общее значение с чужим ключом
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(mine.data(), mine.size()), view_t(peer.data(), 1024), shared.data()));
	// Своё открытое - в PEM для openssl
	ASSERT_TRUE(publish(dir + "/b.der", prime, key.data()));
	ASSERT_TRUE(run("openssl pkey -pubin -inform DER -in " + dir + "/b.der -out " + dir + "/b.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/a.pem -peerkey " + dir + "/b.pem -out " + dir + "/shared.bin 2>/dev/null"));
	// Считываем чужое общее значение
	const std::string foreign = slurp(dir + "/shared.bin");
	// Проверяем непустоту чужого значения
	ASSERT_FALSE(foreign.empty());
	// Сверяем своё общее значение с чужим
	EXPECT_EQ(trimmed(shared), trimmed(std::vector <uint8_t> (foreign.begin(), foreign.end())));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}
