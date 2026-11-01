/**
 * @file ssh.cpp
 * @date 2026-10-04
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
 * @brief Проверки модуля формата ключей openssh-key-v1
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <keys/ssh.hpp>
#include <sign/ed25519.hpp>
#include <entropy/entropy.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция выполнения команды
 *
 * @param cmd команда
 * @return    признак успешности
 *
 */
static bool run(const std::string & cmd) {
	// Выполняем команду и проверяем код её завершения
	return ::system(cmd.c_str()) == 0;
}

/**
 * @brief Функция чтения файла
 *
 * @param path путь к файлу
 * @return     содержимое файла
 *
 */
static std::vector <uint8_t> slurp(const std::string & path) {
	// Объявляем буфер результата
	std::vector <uint8_t> result;
	// Открываем файл на чтение
	FILE * f = ::fopen(path.c_str(), "rb");
	// Проверяем успех открытия файла
	if(f == nullptr)
		// Возвращаем пустой буфер при ошибке открытия
		return result;
	::fseek(f, 0, SEEK_END);
	// Определяем размер файла
	const long size = ::ftell(f);
	::fseek(f, 0, SEEK_SET);
	// Проверяем непустоту файла
	if(size > 0){
		// Выделяем буфер под размер файла
		result.resize(static_cast <size_t> (size));
		::fread(result.data(), 1, result.size(), f);
	}
	::fclose(f);
	// Возвращаем содержимое файла
	return result;
}

/**
 * @brief Функция извлечения base64-тела из PEM
 *
 * @param pem  PEM-текст
 * @param der  место для DER
 * @return     признак успешности
 *
 */
static bool pem2der(const std::vector <uint8_t> & pem, std::vector <uint8_t> & der) {
	// Ищем начало base64
	const char * text = reinterpret_cast <const char *> (pem.data());
	// Ищем начало блока ключа
	const char * begin = ::strstr(text, "-----BEGIN OPENSSH PRIVATE KEY-----");
	// Проверяем нахождение начала блока
	if(begin == nullptr)
		// Возвращаем отказ при отсутствии начала блока
		return false;
	// Переходим к телу base64
	begin = ::strchr(begin, '\n');
	// Проверяем наличие переноса строки после заголовка
	if(begin == nullptr)
		// Возвращаем отказ при отсутствии тела
		return false;
	++begin;
	// Ищем конец блока ключа
	const char * end = ::strstr(begin, "-----END OPENSSH PRIVATE KEY-----");
	// Проверяем нахождение конца блока
	if(end == nullptr)
		// Возвращаем отказ при отсутствии конца блока
		return false;
	// Собираем base64 без переносов строк
	std::string b64;
	/** Перебираем: символы base64-тела, отбрасывая символы переноса строк */
	for(const char * p = begin; p < end; ++p){
		// Пропускаем символы переноса строк
		if(*p != '\n' && *p != '\r')
			// Добавляем очередной символ в буфер
			b64.push_back(*p);
	}
	// Декодируем
	static const int8_t TABLE[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	};
	// Очищаем буфер результата
	der.clear();
	// Резервируем место под декодированные данные
	der.reserve(b64.size() * 3 / 4);
	// Объявляем накопитель бит
	uint32_t v = 0;
	// Объявляем счётчик накопленных бит
	int bits = 0;
	/** Перебираем: символы base64, накапливая биты в байты результата */
	for(const char c : b64){
		// Получаем значение символа из таблицы
		const int8_t d = TABLE[static_cast <uint8_t> (c)];
		// Проверяем маркер конца данных
		if(d == -2)
			break;
		// Проверяем недопустимый символ
		if(d < 0)
			// Возвращаем отказ при недопустимом символе
			return false;
		// Добавляем шесть бит в накопитель
		v = (v << 6) | static_cast <uint32_t> (d);
		// Увеличиваем счётчик накопленных бит
		bits += 6;
		// Проверяем накопление полного байта
		if(bits >= 8){
			// Уменьшаем счётчик на размер байта
			bits -= 8;
			// Записываем готовый байт в результат
			der.push_back(static_cast <uint8_t> (v >> bits));
		}
	}
	// Возвращаем признак успеха
	return true;
}

/**
 * Проверка разбора незашифрованного ключа ssh-keygen
 */
TEST(SshTest, DecodePlain) {
	// Проверяем доступность ssh-keygen
	if(!run("command -v ssh-keygen >/dev/null 2>&1"))
		// Пропускаем тест без ssh-keygen
		GTEST_SKIP() << "ssh-keygen недоступен";
	// Формируем шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ssh-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Запоминаем путь к временному каталогу
	const std::string dir(pattern);
	// Формируем путь к файлу ключа
	const std::string keyfile = dir + "/key";
	// Генерируем ключ без пароля
	ASSERT_TRUE(run("ssh-keygen -t ed25519 -f " + keyfile + " -N '' -C 'test@ants' >/dev/null 2>&1"));
	// Читаем ключ
	const std::vector <uint8_t> pem = slurp(keyfile);
	// Проверяем непустоту прочитанного ключа
	ASSERT_FALSE(pem.empty());
	// Извлекаем DER
	std::vector <uint8_t> der;
	// Проверяем извлечение DER из PEM
	ASSERT_TRUE(pem2der(pem, der));
	// Разбираем
	keys::key_t key;
	// Объявляем буфер комментария ключа
	std::string comment;
	// Проверяем разбор ключа без пароля
	ASSERT_TRUE(keys::ssh::decode(view_t(der.data(), der.size()), view_t(), key, comment));
	// Проверяем тип разобранного ключа
	EXPECT_EQ(key.kind, keys::kind_t::ED25519);
	EXPECT_EQ(key.d.size(), 32u);
	EXPECT_EQ(key.key.size(), 32u);
	EXPECT_EQ(comment, "test@ants");
	// Проверяем подпись разобранным ключом
	sign::ed25519_t ed;
	// Загружаем секретный ключ подписи
	ASSERT_TRUE(ed.secret(view_t(key.d.data(), key.d.size())));
	// Задаём проверяемое сообщение
	const char * message = "test message";
	// Объявляем буфер подписи
	uint8_t signature[64];
	// Формируем подпись сообщения
	ASSERT_TRUE(ed.make(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), signature));
	// Объявляем проверяющий объект подписи
	sign::ed25519_t edpub;
	// Загружаем открытый ключ проверки
	ASSERT_TRUE(edpub.key(view_t(key.key.data(), key.key.size())));
	// Проверяем подпись открытым ключом
	EXPECT_TRUE(edpub.check(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), view_t(signature, sizeof(signature))));
	// Убираем
	run("rm -rf " + dir);
}

/**
 * Проверка разбора зашифрованного ключа ssh-keygen
 */
TEST(SshTest, DecodeEncrypted) {
	// Проверяем доступность ssh-keygen
	if(!run("command -v ssh-keygen >/dev/null 2>&1"))
		// Пропускаем тест без ssh-keygen
		GTEST_SKIP() << "ssh-keygen недоступен";
	// Формируем шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ssh-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Запоминаем путь к временному каталогу
	const std::string dir(pattern);
	// Формируем путь к файлу ключа
	const std::string keyfile = dir + "/key";
	// Задаём пароль шифрования ключа
	const std::string password = "testpass123";
	// Генерируем ключ с паролем
	ASSERT_TRUE(run("ssh-keygen -t ed25519 -f " + keyfile + " -N '" + password + "' -a 16 -C 'enc@ants' >/dev/null 2>&1"));
	// Читаем ключ
	const std::vector <uint8_t> pem = slurp(keyfile);
	// Проверяем непустоту прочитанного ключа
	ASSERT_FALSE(pem.empty());
	// Извлекаем DER
	std::vector <uint8_t> der;
	// Проверяем извлечение DER из PEM
	ASSERT_TRUE(pem2der(pem, der));
	// Разбираем с паролем
	keys::key_t key;
	// Объявляем буфер комментария ключа
	std::string comment;
	// Проверяем разбор ключа с паролем
	ASSERT_TRUE(keys::ssh::decode(view_t(der.data(), der.size()), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), key, comment));
	// Проверяем тип разобранного ключа
	EXPECT_EQ(key.kind, keys::kind_t::ED25519);
	EXPECT_EQ(key.d.size(), 32u);
	EXPECT_EQ(key.key.size(), 32u);
	EXPECT_EQ(comment, "enc@ants");
	// Проверяем подпись
	sign::ed25519_t ed;
	// Загружаем секретный ключ подписи
	ASSERT_TRUE(ed.secret(view_t(key.d.data(), key.d.size())));
	// Задаём проверяемое сообщение
	const char * message = "encrypted test";
	// Объявляем буфер подписи
	uint8_t signature[64];
	// Формируем подпись сообщения
	ASSERT_TRUE(ed.make(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), signature));
	// Объявляем проверяющий объект подписи
	sign::ed25519_t edpub;
	// Загружаем открытый ключ проверки
	ASSERT_TRUE(edpub.key(view_t(key.key.data(), key.key.size())));
	// Проверяем подпись открытым ключом
	EXPECT_TRUE(edpub.check(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), view_t(signature, sizeof(signature))));
	// Убираем
	run("rm -rf " + dir);
}

/**
 * Проверка записи и разбора своего ключа
 */
TEST(SshTest, Roundtrip) {
	// Вырабатываем ключ
	keys::key_t key;
	// Задаём тип вырабатываемого ключа
	key.kind = keys::kind_t::ED25519;
	// Выделяем буфер секретного ключа
	key.d.assign(32, 0);
	// Объявляем объект подписи
	sign::ed25519_t ed;
	// Вырабатываем секретный ключ
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	// Выделяем буфер открытого ключа
	key.key.assign(32, 0);
	// Получаем открытый ключ
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Записываем без пароля
	std::vector <uint8_t> der;
	// Проверяем запись ключа без пароля
	ASSERT_TRUE(keys::ssh::encode(key, "roundtrip@test", view_t(), der));
	// Разбираем
	keys::key_t parsed;
	// Объявляем буфер разобранного ключа
	std::string comment;
	// Объявляем буфер комментария ключа
	ASSERT_TRUE(keys::ssh::decode(view_t(der.data(), der.size()), view_t(), parsed, comment));
	// Проверяем разбор записанного ключа
	EXPECT_EQ(parsed.kind, keys::kind_t::ED25519);
	EXPECT_EQ(parsed.d, key.d);
	EXPECT_EQ(parsed.key, key.key);
	EXPECT_EQ(comment, "roundtrip@test");
	// Записываем с паролем
	const std::string password = "secret";
	// Задаём пароль шифрования
	std::vector <uint8_t> encder;
	// Объявляем буфер шифрованной записи
	ASSERT_TRUE(keys::ssh::encode(key, "enc@test", view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), encder));
	// Разбираем с паролем
	keys::key_t encparsed;
	// Объявляем буфер разобранного ключа
	std::string enccomment;
	// Объявляем буфер комментария ключа
	ASSERT_TRUE(keys::ssh::decode(view_t(encder.data(), encder.size()), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), encparsed, enccomment));
	// Проверяем разбор записи с паролем
	EXPECT_EQ(encparsed.d, key.d);
	EXPECT_EQ(encparsed.key, key.key);
	EXPECT_EQ(enccomment, "enc@test");
	// Неверный пароль отвергается
	keys::key_t bad;
	// Объявляем буфер ключа для проверки отказа
	std::string badcomment;
	// Объявляем буфер комментария отказа
	const std::string badpass = "wrong";
	// Проверяем отказ разбора с неверным паролем
	EXPECT_FALSE(keys::ssh::decode(view_t(encder.data(), encder.size()), view_t(reinterpret_cast <const uint8_t *> (badpass.data()), badpass.size()), bad, badcomment));
}

/**
 * Проверка строки authorized_keys и отпечатка
 */
TEST(SshTest, Publish) {
	// Вырабатываем ключ
	keys::key_t key;
	// Задаём тип вырабатываемого ключа
	key.kind = keys::kind_t::ED25519;
	// Выделяем буфер секретного ключа
	key.d.assign(32, 0);
	// Объявляем объект подписи
	sign::ed25519_t ed;
	// Вырабатываем секретный ключ
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	// Выделяем буфер открытого ключа
	key.key.assign(32, 0);
	// Получаем открытый ключ
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Строка authorized_keys
	const std::string line = keys::ssh::publish(key, "pub@test");
	// Проверяем тип ключа в начале строки
	EXPECT_TRUE(line.find("ssh-ed25519 ") == 0);
	EXPECT_TRUE(line.find(" pub@test") != std::string::npos);
	// Отпечаток
	const std::string fp = keys::ssh::fingerprint(key);
	// Проверяем алгоритм отпечатка
	EXPECT_TRUE(fp.find("SHA256:") == 0);
	EXPECT_EQ(fp.size(), 7 + 43); // "SHA256:" + 43 символа base64 без padding
}

/**
 * Проверка интероп записи с ssh-keygen
 */
TEST(SshTest, InteropWrite) {
	// Проверяем доступность ssh-keygen
	if(!run("command -v ssh-keygen >/dev/null 2>&1"))
		// Пропускаем тест без ssh-keygen
		GTEST_SKIP() << "ssh-keygen недоступен";
	// Формируем шаблон имени временного каталога
	char pattern[] = "/tmp/ants-ssh-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Запоминаем путь к временному каталогу
	const std::string dir(pattern);
	// Вырабатываем ключ
	keys::key_t key;
	// Задаём тип вырабатываемого ключа
	key.kind = keys::kind_t::ED25519;
	// Выделяем буфер секретного ключа
	key.d.assign(32, 0);
	// Объявляем объект подписи
	sign::ed25519_t ed;
	// Вырабатываем секретный ключ
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	// Выделяем буфер открытого ключа
	key.key.assign(32, 0);
	// Получаем открытый ключ
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Записываем
	std::vector <uint8_t> der;
	// Проверяем запись ключа без пароля
	ASSERT_TRUE(keys::ssh::encode(key, "interop@test", view_t(), der));
	// Формируем PEM
	std::string pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
	// Объявляем алфавит base64
	static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	/** Перебираем: байты DER, кодируя их в base64 */
	for(size_t i = 0; i < der.size(); i += 3){
		// Загружаем первый байт триады
		uint32_t v = static_cast <uint32_t> (der[i]) << 16;
		// Проверяем наличие второго байта
		if(i + 1 < der.size())
			// Добавляем второй байт триады
			v |= static_cast <uint32_t> (der[i + 1]) << 8;
		// Проверяем наличие третьего байта
		if(i + 2 < der.size())
			// Добавляем третий байт триады
			v |= static_cast <uint32_t> (der[i + 2]);
		// Записываем первый символ четвёрки
		pem.push_back(ALPHABET[(v >> 18) & 63]);
		pem.push_back(ALPHABET[(v >> 12) & 63]);
		pem.push_back((i + 1 < der.size()) ? ALPHABET[(v >> 6) & 63] : '=');
		pem.push_back((i + 2 < der.size()) ? ALPHABET[v & 63] : '=');
		// Проверяем конец очередной строки PEM
		if((i / 3 + 1) % 18 == 0)
			// Добавляем перенос строки
			pem.push_back('\n');
	}
	// Проверяем завершающий перенос строки
	if(pem.back() != '\n')
		// Добавляем завершающий перенос строки
		pem.push_back('\n');
	// Дописываем конец блока PEM
	pem += "-----END OPENSSH PRIVATE KEY-----\n";
	// Записываем файл
	const std::string keyfile = dir + "/key";
	// Создаём файл ключа
	FILE * f = ::fopen(keyfile.c_str(), "w");
	// Проверяем успех создания файла
	ASSERT_NE(f, nullptr);
	::fwrite(pem.data(), 1, pem.size(), f);
	::fclose(f);
	::chmod(keyfile.c_str(), 0600);
	// Проверяем ssh-keygen
	ASSERT_TRUE(run("ssh-keygen -y -f " + keyfile + " > " + dir + "/pub.txt 2>/dev/null"));
	// Читаем открытый ключ ssh-keygen
	const std::vector <uint8_t> pubtxt = slurp(dir + "/pub.txt");
	// Проверяем непустоту открытого ключа
	ASSERT_FALSE(pubtxt.empty());
	// Сравниваем с нашей строкой с тем же комментарием
	const std::string ourline = keys::ssh::publish(key, "interop@test");
	// Формируем строку ключа ssh-keygen
	std::string theirline(reinterpret_cast <const char *> (pubtxt.data()), pubtxt.size());
	/**
	 * Убираем перевод строки в конце
	 */
	while(!theirline.empty() && (theirline.back() == '\n' || theirline.back() == '\r'))
		// Убираем очередной символ переноса строки
		theirline.pop_back();
	// Сравниваем строки ключей
	EXPECT_EQ(ourline, theirline);
	// Убираем
	run("rm -rf " + dir);
}

/**
 * Проверка записей known_hosts: открытой и хешированной HMAC-SHA1
 */
TEST(SshTest, KnownHosts) {
	// Вырабатываем ключ
	keys::key_t key;
	// Задаём тип вырабатываемого ключа
	key.kind = keys::kind_t::ED25519;
	// Выделяем буфер секретного ключа
	key.d.assign(32, 0);
	// Объявляем объект подписи
	sign::ed25519_t ed;
	// Вырабатываем секретный ключ
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	// Выделяем буфер открытого ключа
	key.key.assign(32, 0);
	// Получаем открытый ключ
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Открытая запись: сборка
	std::string plain;
	// Объявляем буфер открытой записи
	ASSERT_TRUE(keys::ssh::knownHosts("example.com", key, "тестовый узел", false, plain));
	// Открытая запись обязана начинаться с хозяина
	EXPECT_EQ(plain.compare(0, 11, "example.com"), 0);
	// Открытая запись: разбор
	keys::ssh::known_host_t record;
	// Объявляем буфер разобранной записи
	ASSERT_TRUE(keys::ssh::knownHosts(plain, record));
	// Проверяем разбор открытой записи
	EXPECT_FALSE(record.hashed);
	// Проверяем открытый вид записи
	EXPECT_EQ(record.host, "example.com");
	EXPECT_EQ(record.type, "ssh-ed25519");
	EXPECT_EQ(record.comment, "тестовый узел");
	// Проверяем комментарий записи
	EXPECT_FALSE(record.key.empty());
	// Сверка хозяина: свой сходится, чужой отвергается
	EXPECT_TRUE(keys::ssh::knownHostsMatch(record, "example.com"));
	// Проверяем отказ сверки чужого хозяина
	EXPECT_FALSE(keys::ssh::knownHostsMatch(record, "other.com"));
	// Хешированная запись: сборка
	std::string hashed;
	// Проверяем сборку хешированной записи
	ASSERT_TRUE(keys::ssh::knownHosts("example.com", key, "", true, hashed));
	// Хешированная запись обязана начинаться с маркера
	EXPECT_EQ(hashed.compare(0, 3, "|1|"), 0);
	// Хешированная запись не обязана нести хозяина открытым текстом
	EXPECT_EQ(hashed.find("example.com"), std::string::npos);
	// Хешированная запись: разбор
	keys::ssh::known_host_t hrecord;
	// Проверяем разбор хешированной записи
	ASSERT_TRUE(keys::ssh::knownHosts(hashed, hrecord));
	// Проверяем хешированный вид записи
	EXPECT_TRUE(hrecord.hashed);
	// Проверяем размер соли записи
	EXPECT_EQ(hrecord.salt.size(), 20U);
	EXPECT_EQ(hrecord.hash.size(), 20U);
	EXPECT_EQ(hrecord.type, "ssh-ed25519");
	// Сверка хозяина: свой сходится, чужой отвергается
	EXPECT_TRUE(keys::ssh::knownHostsMatch(hrecord, "example.com"));
	// Проверяем отказ сверки чужого хозяина
	EXPECT_FALSE(keys::ssh::knownHostsMatch(hrecord, "other.com"));
	// Две хешированные записи одного хозяина различаются (случайная соль)
	std::string another;
	// Собираем вторую хешированную запись
	ASSERT_TRUE(keys::ssh::knownHosts("example.com", key, "", true, another));
	// Проверяем различие записей из-за случайной соли
	EXPECT_NE(hashed, another);
	// Обе сверяются с хозяином
	keys::ssh::known_host_t arecord;
	// Объявляем буфер разобранной записи
	ASSERT_TRUE(keys::ssh::knownHosts(another, arecord));
	// Проверяем разбор второй записи
	EXPECT_TRUE(keys::ssh::knownHostsMatch(arecord, "example.com"));
}

/**
 * Проверка отказов разбора known_hosts
 */
TEST(SshTest, KnownHostsRefusals) {
	// Вырабатываем ключ
	keys::key_t key;
	// Задаём тип вырабатываемого ключа
	key.kind = keys::kind_t::ED25519;
	// Выделяем буфер секретного ключа
	key.d.assign(32, 0);
	// Объявляем объект подписи
	sign::ed25519_t ed;
	// Вырабатываем секретный ключ
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	// Выделяем буфер открытого ключа
	key.key.assign(32, 0);
	// Получаем открытый ключ
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Пустая строка отвергается
	keys::ssh::known_host_t record;
	// Проверяем отказ разбора пустой строки
	EXPECT_FALSE(keys::ssh::knownHosts("", record));
	// Строка без типа и ключа отвергается
	EXPECT_FALSE(keys::ssh::knownHosts("example.com", record));
	// Строка с негодным base64 отвергается
	EXPECT_FALSE(keys::ssh::knownHosts("example.com ssh-ed25519 !!!", record));
	// Хешированная запись без второго разделителя отвергается
	EXPECT_FALSE(keys::ssh::knownHosts("|1|AAAA ssh-ed25519 AAAA", record));
	// Сборка с пустым хозяином отвергается
	std::string line;
	// Объявляем буфер записи
	EXPECT_FALSE(keys::ssh::knownHosts("", key, "", false, line));
	// Сборка с негодным ключом отвергается
	keys::key_t bad;
	// Объявляем негодный ключ
	bad.kind = keys::kind_t::ED25519;
	// Задаём тип негодного ключа
	EXPECT_FALSE(keys::ssh::knownHosts("example.com", bad, "", false, line));
	// Сверка с записью без соли и хеша отвергается
	keys::ssh::known_host_t empty;
	// Объявляем запись без соли и хеша
	empty.hashed = true;
	// Помечаем запись хешированной
	EXPECT_FALSE(keys::ssh::knownHostsMatch(empty, "example.com"));
}
