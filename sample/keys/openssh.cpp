/**
 * @file openssh.cpp
 * @date 2026-10-10
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
 * @brief Пример работы с форматом ключей openssh-key-v1 — запись и разбор ключа
 *        Ed25519, строка authorized_keys, отпечаток и записи known_hosts
 *
 * @details Формат openssh-key-v1 хранит ключ с магией «openssh-key-v1\0»: при пустом
 *          пароле блок секретных ключей открыт, при пароле - зашифрован aes256-ctr
 *          с выработкой ключа bcrypt_pbkdf. Записи known_hosts держат хозяина открытым
 *          текстом либо хешем HMAC-SHA1 со случайной солью
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <keys/openssh.hpp>
#include <sign/ed25519.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Метод вывода области байтов шестнадцатеричной записью
	 *
	 * @param title заголовок выводимой области байтов
	 * @param data  выводимая область байтов
	 * @param size  размер выводимой области байтов
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Выводим заголовок области байтов
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов выводимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Выводим очередной байт шестнадцатеричной записью
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Выполняем перевод строки за областью байтов
		cout << dec << endl;
	}
};

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина массива параметров
 * @param argv массив параметров
 *
 * @return     код выхода из приложения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Не используем параметры приложения
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Ключ подписи Ed25519 образца
	keys::key_t key;
	key.kind = keys::kind_t::ED25519;
	key.d.assign(32, 0);
	// Объект электронной подписи Ed25519 для порождения пары
	sign::ed25519_t sign;
	/**
	 * Выполняем порождение пары ключей Ed25519
	 *
	 * @details Зерно ключа подписи берётся из источника случайности, открытый ключ
	 *          проверки вырабатывается из него сразу же
	 */
	if(!sign.generate(key.d.data(), key.d.size())){
		// Выводим сообщение об отказе порождения ключа
		cout << "Породить ключ подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем получение открытого ключа проверки подписи
	key.key.assign(32, 0);
	if(!sign.key(key.key.data(), key.key.size())){
		// Выводим сообщение об отказе получения ключа
		cout << "Получить ключ проверки не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим открытый ключ проверки подписи
	::print("Открытый ключ      ", key.key.data(), key.key.size());
	// Место, в которое помещается запись ключа openssh-key-v1
	vector <uint8_t> record;
	/**
	 * Выполняем запись ключа в формате openssh-key-v1 без пароля
	 *
	 * @details При пустом пароле ciphername и kdfname равны «none», и блок секретных
	 *          ключей идёт открытым текстом
	 */
	if(!keys::openssh::encode(key, "образец@ants", view_t(), record)){
		// Выводим сообщение об отказе записи ключа
		cout << "Записать ключ openssh-key-v1 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало записи ключа openssh-key-v1
	::print("Запись ключа       ", record.data(), 16);
	// Разобранный ключ и его комментарий
	keys::key_t parsed;
	string comment;
	// Выполняем разбор записи ключа openssh-key-v1
	if(!keys::openssh::decode(view_t(record.data(), record.size()), view_t(), parsed, comment)){
		// Выводим сообщение об отказе разбора ключа
		cout << "Разобрать ключ openssh-key-v1 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим комментарий разобранного ключа
	cout << "Комментарий ключа  : " << comment << endl;
	// Если разобранный ключ разошёлся с записанным
	if((parsed.kind != key.kind) || (parsed.d != key.d) || (parsed.key != key.key)){
		// Выводим сообщение о расхождении ключа
		cout << "Разобранный ключ разошёлся с записанным" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим строку authorized_keys открытого ключа
	cout << "authorized_keys    : " << keys::openssh::publish(key, "образец@ants") << endl;
	// Выводим отпечаток ключа SHA256
	cout << "Отпечаток ключа    : " << keys::openssh::fingerprint(key) << endl;
	// Место, в которое помещается строка known_hosts
	string line;
	/**
	 * Выполняем сборку открытой записи known_hosts
	 *
	 * @details Открытая запись есть «хозяин тип ключ комментарий»: хозяин идёт
	 *          открытым текстом, как у всякой записи до OpenSSH 4.0
	 */
	if(!keys::openssh::knownHosts("example.com", key, "узел образца", false, line)){
		// Выводим сообщение об отказе сборки записи
		cout << "Собрать запись known_hosts не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим открытую запись known_hosts
	cout << "known_hosts открытая  : " << line << endl;
	// Сведения о разобранной записи known_hosts
	keys::openssh::known_host_t host;
	// Выполняем разбор открытой записи known_hosts
	if(!keys::openssh::knownHosts(line, host)){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запись known_hosts не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если хозяин записи не свёлся с собою
	if(!keys::openssh::knownHostsMatch(host, "example.com")){
		// Выводим сообщение о расхождении хозяина
		cout << "Хозяин открытой записи не свёлся" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	/**
	 * Выполняем сборку хешированной записи known_hosts
	 *
	 * @details Хешированная запись есть «|1|base64(соль)|base64(HMAC-SHA1(соль, хозяин))
	 *          тип ключ»: хозяин открытым текстом в ней не идёт, и перечень узлов
	 *          по такому файлу не собрать
	 */
	if(!keys::openssh::knownHosts("example.com", key, "", true, line)){
		// Выводим сообщение об отказе сборки записи
		cout << "Собрать хешированную запись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим хешированную запись known_hosts
	cout << "known_hosts хешем     : " << line << endl;
	// Сведения о разобранной хешированной записи
	keys::openssh::known_host_t hashed;
	// Выполняем разбор хешированной записи known_hosts
	if(!keys::openssh::knownHosts(line, hashed)){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать хешированную запись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если хозяин хешированной записи не свёлся с собою
	if(!keys::openssh::knownHostsMatch(hashed, "example.com")){
		// Выводим сообщение о расхождении хозяина
		cout << "Хозяин хешированной записи не свёлся" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о сверке хозяина хешированной записи
	cout << "Сверка хозяина     : хозяин свёлся под хешем HMAC-SHA1" << endl;
	// Если чужой хозяин не отвергнут
	if(keys::openssh::knownHostsMatch(hashed, "other.com")){
		// Выводим сообщение о неотвержении чужого хозяина
		cout << "Чужой хозяин не отвергнут" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об отвержении чужого хозяина
	cout << "Сверка подмены     : чужой хозяин отвергнут" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
