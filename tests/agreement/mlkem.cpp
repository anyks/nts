/**
 * @file mlkem.cpp
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
 * @brief Проверки модуля инкапсуляции ключа ML-KEM по FIPS 203
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <agreement/mlkem.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * Путь к набору векторов
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Метод разбора шестнадцатеричной строки
 *
 * @param text строка
 *
 * @return     байты
 *
 */
static std::vector <uint8_t> bytes(const std::string & text) {
	// Разобранные байты
	std::vector <uint8_t> result;
	// Значение полубайта
	auto nibble = [](const char c) -> int {
		// Цифры
		if((c >= '0') && (c <= '9')) return (c - '0');
		// Строчные буквы
		if((c >= 'a') && (c <= 'f')) return (c - 'a' + 10);
		// Прописные буквы
		if((c >= 'A') && (c <= 'F')) return (c - 'A' + 10);
		// Не шестнадцатеричный знак
		return -1;
	};
	for(size_t i = 0; (i + 1) < text.size(); i += 2){
		// Полубайты
		const int high = nibble(text[i]), low = nibble(text[i + 1]);
		// Если знаки негодны
		if((high < 0) || (low < 0))
			// Прерываем разбор
			break;
		// Записываем байт
		result.push_back(static_cast <uint8_t> ((high << 4) | low));
	}
	// Выводим байты
	return result;
}
/**
 * @brief Метод чтения блоков «имя: значение» из файла векторов
 *
 * @param name имя файла в наборе
 *
 * @return     перечень блоков, каждый есть отображение имени на значение
 *
 */
static std::vector <std::map <std::string, std::string>> blocks(const std::string & name) {
	// Перечень блоков
	std::vector <std::map <std::string, std::string>> result;
	// Файл векторов
	std::ifstream file(std::string(CORPUS) + "/mlkem/" + name);
	// Текущий блок
	std::map <std::string, std::string> block;
	// Строка файла
	std::string line;
	while(std::getline(file, line)){
		// Если строка пуста: конец блока
		if(line.empty()){
			// Если блок не пуст
			if(!block.empty())
				// Добавляем блок
				result.push_back(block);
			// Сбрасываем блок
			block.clear();
			// Переходим к следующей строке
			continue;
		}
		// Если строка есть замечание
		if(line[0] == '#')
			// Переходим к следующей строке
			continue;
		// Снимаем скобки заголовка NIST
		if((line[0] == '[') && (line.back() == ']'))
			// Оставляем содержимое скобок
			line = line.substr(1, line.size() - 2);
		// Место разделителя
		const size_t at = line.find_first_of(":=");
		// Если разделителя нет
		if(at == std::string::npos)
			// Переходим к следующей строке
			continue;
		// Имя
		std::string key = line.substr(0, at);
		// Значение
		std::string value = line.substr(at + 1);
		// Снимаем пробелы
		while(!key.empty() && (key.back() == ' ')) key.pop_back();
		while(!value.empty() && (value.front() == ' ')) value.erase(0, 1);
		while(!value.empty() && ((value.back() == ' ') || (value.back() == '\r'))) value.pop_back();
		// Записываем пару
		block[key] = value;
	}
	// Если последний блок не пуст
	if(!block.empty())
		// Добавляем блок
		result.push_back(block);
	// Выводим перечень блоков
	return result;
}
/**
 * @brief Метод прогона векторов выработки, инкапсуляции и декапсуляции набора
 *
 * @param kem    набор параметров
 * @param prefix приставка имён файлов
 *
 */
static void vectors(const agreement::kem_t kem, const std::string & prefix) {
	// Длины
	const size_t ek = agreement::encapsulation(kem), dk = agreement::decapsulation(kem), ct = agreement::ciphertext(kem);
	// Векторы выработки
	const auto keygen = blocks(prefix + "_keygen.txt");
	// Проверяем, что векторы прочитаны
	ASSERT_GE(keygen.size(), 4u);
	for(size_t i = 0; i < keygen.size(); i++){
		// Зерно
		const std::vector <uint8_t> seed = bytes(keygen[i].at("seed"));
		// Ключи
		std::vector <uint8_t> key(ek, 0), secret(dk, 0);
		// Вырабатываем пару
		ASSERT_TRUE(agreement::generate(kem, view_t(seed.data(), seed.size()), key.data(), secret.data())) << "вектор " << i;
		// Сличаем ключ инкапсуляции
		ASSERT_EQ(key, bytes(keygen[i].at("public_key"))) << "вектор " << i;
		// Сличаем ключ декапсуляции
		ASSERT_EQ(secret, bytes(keygen[i].at("private_key"))) << "вектор " << i;
	}
	// Векторы инкапсуляции
	const auto encap = blocks(prefix + "_encap.txt");
	// Проверяем, что векторы прочитаны, включая отказные
	ASSERT_GE(encap.size(), 7u);
	// Число отказных векторов
	size_t refused = 0;
	for(size_t i = 0; i < encap.size(); i++){
		// Ключ и сообщение
		const std::vector <uint8_t> key = bytes(encap[i].at("public_key")), message = bytes(encap[i].at("entropy"));
		// Шифртекст и секрет
		std::vector <uint8_t> cipher(ct, 0), shared(agreement::MLKEM_SHARED, 0);
		// Итог инкапсуляции
		const bool ok = agreement::encapsulate(kem, view_t(key.data(), key.size()), view_t(message.data(), message.size()), cipher.data(), shared.data());
		// Ожидаемый итог
		const bool pass = (encap[i].at("result") == "pass");
		// Сличаем итог
		ASSERT_EQ(ok, pass) << "вектор " << i;
		// Если инкапсуляция ожидалась
		if(pass){
			// Сличаем шифртекст
			ASSERT_EQ(cipher, bytes(encap[i].at("ciphertext"))) << "вектор " << i;
			// Сличаем секрет
			ASSERT_EQ(shared, bytes(encap[i].at("shared_secret"))) << "вектор " << i;
		// Иначе считаем отказ
		} else refused++;
	}
	// Проверяем, что отказные векторы были
	ASSERT_EQ(refused, 3u);
	// Векторы декапсуляции
	const auto decap = blocks(prefix + "_decap.txt");
	// Проверяем, что векторы прочитаны, включая отказные
	ASSERT_GE(decap.size(), 7u);
	// Сбрасываем счётчик отказов
	refused = 0;
	for(size_t i = 0; i < decap.size(); i++){
		// Ключ и шифртекст
		const std::vector <uint8_t> secret = bytes(decap[i].at("private_key")), cipher = bytes(decap[i].at("ciphertext"));
		// Секрет
		std::vector <uint8_t> shared(agreement::MLKEM_SHARED, 0);
		// Итог декапсуляции
		const bool ok = agreement::decapsulate(kem, view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), shared.data());
		// Ожидаемый итог
		const bool pass = (decap[i].at("result") == "pass");
		// Сличаем итог
		ASSERT_EQ(ok, pass) << "вектор " << i;
		// Если декапсуляция ожидалась
		if(pass)
			// Сличаем секрет
			ASSERT_EQ(shared, bytes(decap[i].at("shared_secret"))) << "вектор " << i;
		// Иначе считаем отказ
		else refused++;
	}
	// Проверяем, что отказные векторы были
	ASSERT_EQ(refused, 3u);
	// Векторы NIST выработки: d и z порознь
	const auto nist = blocks(prefix + "_nist_keygen.txt");
	// Проверяем, что векторы прочитаны
	ASSERT_GE(nist.size(), 3u);
	for(size_t i = 0; i < nist.size(); i++){
		// Зерно d || z
		std::vector <uint8_t> seed = bytes(nist[i].at("d"));
		// Часть z
		const std::vector <uint8_t> z = bytes(nist[i].at("z"));
		// Дописываем z
		seed.insert(seed.end(), z.begin(), z.end());
		// Ключи
		std::vector <uint8_t> key(ek, 0), secret(dk, 0);
		// Вырабатываем пару
		ASSERT_TRUE(agreement::generate(kem, view_t(seed.data(), seed.size()), key.data(), secret.data())) << "вектор NIST " << i;
		// Сличаем ключи
		ASSERT_EQ(key, bytes(nist[i].at("ek"))) << "вектор NIST " << i;
		ASSERT_EQ(secret, bytes(nist[i].at("dk"))) << "вектор NIST " << i;
	}
	// Векторы NIST декапсуляции: один ключ, несколько шифртекстов, включая неявно отвергаемые
	const auto rejection = blocks(prefix + "_nist_decap.txt");
	// Проверяем, что векторы прочитаны: заголовок с ключом и три пары
	ASSERT_GE(rejection.size(), 4u);
	// Ключ декапсуляции
	const std::vector <uint8_t> secret = bytes(rejection[0].at("dk"));
	// Проверяем длину ключа
	ASSERT_EQ(secret.size(), dk);
	for(size_t i = 1; i < rejection.size(); i++){
		// Шифртекст
		const std::vector <uint8_t> cipher = bytes(rejection[i].at("c"));
		// Секрет
		std::vector <uint8_t> shared(agreement::MLKEM_SHARED, 0);
		// Выполняем декапсуляцию
		ASSERT_TRUE(agreement::decapsulate(kem, view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), shared.data())) << "вектор NIST " << i;
		// Сличаем секрет: у негодных шифртекстов это J(z || c)
		ASSERT_EQ(shared, bytes(rejection[i].at("k"))) << "вектор NIST " << i;
	}
}

/**
 * Векторы ML-KEM-768
 */
TEST(MlkemTest, Vectors768){
	// Прогоняем векторы
	vectors(agreement::kem_t::MLKEM768, "768");
}

/**
 * Векторы ML-KEM-1024
 */
TEST(MlkemTest, Vectors1024){
	// Прогоняем векторы
	vectors(agreement::kem_t::MLKEM1024, "1024");
}

/**
 * Длины наборов по таблице 3 FIPS 203
 */
TEST(MlkemTest, Lengths){
	ASSERT_EQ(agreement::encapsulation(agreement::kem_t::MLKEM512), 800u);
	ASSERT_EQ(agreement::decapsulation(agreement::kem_t::MLKEM512), 1632u);
	ASSERT_EQ(agreement::ciphertext(agreement::kem_t::MLKEM512), 768u);
	ASSERT_EQ(agreement::encapsulation(agreement::kem_t::MLKEM768), 1184u);
	ASSERT_EQ(agreement::decapsulation(agreement::kem_t::MLKEM768), 2400u);
	ASSERT_EQ(agreement::ciphertext(agreement::kem_t::MLKEM768), 1088u);
	ASSERT_EQ(agreement::encapsulation(agreement::kem_t::MLKEM1024), 1568u);
	ASSERT_EQ(agreement::decapsulation(agreement::kem_t::MLKEM1024), 3168u);
	ASSERT_EQ(agreement::ciphertext(agreement::kem_t::MLKEM1024), 1568u);
	ASSERT_EQ(agreement::encapsulation(agreement::kem_t::NONE), 0u);
	ASSERT_EQ(agreement::decapsulation(agreement::kem_t::NONE), 0u);
	ASSERT_EQ(agreement::ciphertext(agreement::kem_t::NONE), 0u);
}

/**
 * Круг на случайных ключах у всех трёх наборов и неявный отказ на порченом шифртексте
 */
TEST(MlkemTest, Roundtrip){
	// Наборы
	const agreement::kem_t kinds[] = {agreement::kem_t::MLKEM512, agreement::kem_t::MLKEM768, agreement::kem_t::MLKEM1024};
	for(size_t k = 0; k < (sizeof(kinds) / sizeof(kinds[0])); k++){
		// Ключи
		std::vector <uint8_t> key(agreement::encapsulation(kinds[k]), 0), secret(agreement::decapsulation(kinds[k]), 0);
		// Вырабатываем пару
		ASSERT_TRUE(agreement::generate(kinds[k], key.data(), secret.data()));
		// Проверяем ключ
		ASSERT_TRUE(agreement::validate(kinds[k], view_t(key.data(), key.size())));
		// Шифртекст и секреты
		std::vector <uint8_t> cipher(agreement::ciphertext(kinds[k]), 0), first(32, 0), second(32, 0);
		// Инкапсулируем
		ASSERT_TRUE(agreement::encapsulate(kinds[k], view_t(key.data(), key.size()), cipher.data(), first.data()));
		// Декапсулируем
		ASSERT_TRUE(agreement::decapsulate(kinds[k], view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), second.data()));
		// Сличаем секреты
		ASSERT_EQ(first, second) << "набор " << static_cast <int> (kinds[k]);
		// Портим шифртекст
		cipher[cipher.size() / 2] ^= 0x01;
		// Декапсуляция не отказывает
		ASSERT_TRUE(agreement::decapsulate(kinds[k], view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), second.data()));
		// Секрет иной: неявный отказ
		ASSERT_NE(first, second) << "набор " << static_cast <int> (kinds[k]);
		// Повторная инкапсуляция даёт иной шифртекст: сообщение случайно
		std::vector <uint8_t> again(cipher.size(), 0);
		ASSERT_TRUE(agreement::encapsulate(kinds[k], view_t(key.data(), key.size()), again.data(), second.data()));
		ASSERT_NE(again, cipher);
	}
}

/**
 * Отказы на негодных входах
 */
TEST(MlkemTest, Refusals){
	// Набор
	const agreement::kem_t kem = agreement::kem_t::MLKEM768;
	// Ключи
	std::vector <uint8_t> key(agreement::encapsulation(kem), 0), secret(agreement::decapsulation(kem), 0);
	// Зерно
	const std::vector <uint8_t> seed(agreement::MLKEM_SEED, 0x42);
	// Отказ набора NONE
	ASSERT_FALSE(agreement::generate(agreement::kem_t::NONE, view_t(seed.data(), seed.size()), key.data(), secret.data()));
	// Отказ зерна не той длины
	ASSERT_FALSE(agreement::generate(kem, view_t(seed.data(), 63), key.data(), secret.data()));
	// Отказ пустых мест
	ASSERT_FALSE(agreement::generate(kem, view_t(seed.data(), seed.size()), nullptr, secret.data()));
	ASSERT_FALSE(agreement::generate(kem, view_t(seed.data(), seed.size()), key.data(), nullptr));
	// Выработка на зерне
	ASSERT_TRUE(agreement::generate(kem, view_t(seed.data(), seed.size()), key.data(), secret.data()));
	// Повторная выработка на том же зерне даёт те же ключи
	std::vector <uint8_t> key2(key.size(), 0), secret2(secret.size(), 0);
	ASSERT_TRUE(agreement::generate(kem, view_t(seed.data(), seed.size()), key2.data(), secret2.data()));
	ASSERT_EQ(key, key2);
	ASSERT_EQ(secret, secret2);
	// Шифртекст и секрет
	std::vector <uint8_t> cipher(agreement::ciphertext(kem), 0), shared(32, 0);
	// Сообщение
	const std::vector <uint8_t> message(32, 0x11);
	// Отказ ключа не той длины
	ASSERT_FALSE(agreement::encapsulate(kem, view_t(key.data(), key.size() - 1), view_t(message.data(), 32), cipher.data(), shared.data()));
	// Отказ ключа иного набора
	ASSERT_FALSE(agreement::encapsulate(agreement::kem_t::MLKEM1024, view_t(key.data(), key.size()), view_t(message.data(), 32), cipher.data(), shared.data()));
	// Отказ сообщения не той длины
	ASSERT_FALSE(agreement::encapsulate(kem, view_t(key.data(), key.size()), view_t(message.data(), 31), cipher.data(), shared.data()));
	// Отказ ключа с коэффициентом вне модуля: старший полубайт первого коэффициента
	key2[1] |= 0x0F;
	key2[0] = 0xFF;
	ASSERT_FALSE(agreement::validate(kem, view_t(key2.data(), key2.size())));
	ASSERT_FALSE(agreement::encapsulate(kem, view_t(key2.data(), key2.size()), view_t(message.data(), 32), cipher.data(), shared.data()));
	// Инкапсуляция на годном ключе
	ASSERT_TRUE(agreement::encapsulate(kem, view_t(key.data(), key.size()), view_t(message.data(), 32), cipher.data(), shared.data()));
	// Отказ шифртекста не той длины
	ASSERT_FALSE(agreement::decapsulate(kem, view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size() - 1), shared.data()));
	// Отказ ключа декапсуляции не той длины
	ASSERT_FALSE(agreement::decapsulate(kem, view_t(secret.data(), secret.size() - 1), view_t(cipher.data(), cipher.size()), shared.data()));
	// Отказ ключа декапсуляции с порченым хешем
	secret2[secret2.size() - 33] ^= 0x01;
	ASSERT_FALSE(agreement::decapsulate(kem, view_t(secret2.data(), secret2.size()), view_t(cipher.data(), cipher.size()), shared.data()));
	// Отказ пустого места
	ASSERT_FALSE(agreement::decapsulate(kem, view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), nullptr));
	// Декапсуляция на годном ключе
	ASSERT_TRUE(agreement::decapsulate(kem, view_t(secret.data(), secret.size()), view_t(cipher.data(), cipher.size()), shared.data()));
}

/**
 * Сличение с openssl 3.5+: наша инкапсуляция на ключ openssl раскрывается pkeyutl -decap,
 * инкапсуляция pkeyutl -encap на наш ключ раскрывается нашей декапсуляцией
 */
TEST(MlkemTest, Openssl){
	// Если openssl без ML-KEM-768
	if(std::system("(openssl list -kem-algorithms 2>/dev/null | grep -q ML-KEM-768) >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "openssl без ML-KEM-768 (нужен openssl 3.5+)";
	}
	// Набор
	const agreement::kem_t kem = agreement::kem_t::MLKEM768;
	// Заголовок SubjectPublicKeyInfo ML-KEM-768: SEQUENCE, AlgorithmIdentifier 2.16.840.1.101.3.4.4.2, BIT STRING в 1184 байта
	static const uint8_t HEADER[] = {0x30, 0x82, 0x04, 0xB2, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, 0x82, 0x04, 0xA1, 0x00};
	// Пути файлов
	const std::string stem = "/tmp/ants-mlkem-" + std::to_string(static_cast <long> (::getpid()));
	const std::string priv = stem + ".pem", pub = stem + ".pub", cipher = stem + ".ct", secret = stem + ".ss", ours = stem + ".der";
	// Читаем файл целиком
	auto slurp = [](const std::string & path) -> std::vector <uint8_t> {
		std::ifstream file(path, std::ios::binary);
		return std::vector <uint8_t> ((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	};
	{
		// Ключ openssl
		ASSERT_EQ(std::system(("openssl genpkey -algorithm ML-KEM-768 -out " + priv + " >/dev/null 2>&1 && openssl pkey -in " + priv + " -pubout -outform DER -out " + pub + " >/dev/null 2>&1").c_str()), 0);
		// Открытый ключ openssl в DER
		const std::vector <uint8_t> spki = slurp(pub);
		ASSERT_EQ(spki.size(), sizeof(HEADER) + agreement::encapsulation(kem));
		ASSERT_EQ(::memcmp(spki.data(), HEADER, sizeof(HEADER)), 0);
		// Наша инкапсуляция
		std::vector <uint8_t> ct(agreement::ciphertext(kem), 0), ss(32, 0);
		ASSERT_TRUE(agreement::encapsulate(kem, view_t(spki.data() + sizeof(HEADER), agreement::encapsulation(kem)), ct.data(), ss.data()));
		// Записываем шифртекст
		std::ofstream(cipher, std::ios::binary).write(reinterpret_cast <const char *> (ct.data()), static_cast <std::streamsize> (ct.size()));
		// Декапсуляция openssl
		ASSERT_EQ(std::system(("openssl pkeyutl -decap -inkey " + priv + " -in " + cipher + " -secret " + secret + " >/dev/null 2>&1").c_str()), 0);
		// Сличаем секреты
		ASSERT_EQ(slurp(secret), ss);
	}
	{
		// Наш ключ
		std::vector <uint8_t> key(agreement::encapsulation(kem), 0), dk(agreement::decapsulation(kem), 0);
		ASSERT_TRUE(agreement::generate(kem, key.data(), dk.data()));
		// Записываем SubjectPublicKeyInfo
		std::vector <uint8_t> spki(HEADER, HEADER + sizeof(HEADER));
		spki.insert(spki.end(), key.begin(), key.end());
		std::ofstream(ours, std::ios::binary).write(reinterpret_cast <const char *> (spki.data()), static_cast <std::streamsize> (spki.size()));
		// Инкапсуляция openssl
		ASSERT_EQ(std::system(("openssl pkeyutl -encap -inkey " + ours + " -keyform DER -pubin -secret " + secret + " -out " + cipher + " >/dev/null 2>&1").c_str()), 0);
		// Шифртекст и секрет openssl
		const std::vector <uint8_t> ct = slurp(cipher), expected = slurp(secret);
		ASSERT_EQ(ct.size(), agreement::ciphertext(kem));
		ASSERT_EQ(expected.size(), static_cast <size_t> (32));
		// Наша декапсуляция
		std::vector <uint8_t> ss(32, 0);
		ASSERT_TRUE(agreement::decapsulate(kem, view_t(dk.data(), dk.size()), view_t(ct.data(), ct.size()), ss.data()));
		ASSERT_EQ(ss, expected);
	}
	::remove(priv.c_str()); ::remove(pub.c_str()); ::remove(cipher.c_str()); ::remove(secret.c_str()); ::remove(ours.c_str());
}
