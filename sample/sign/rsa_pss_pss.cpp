/**
 * @file rsa_pss_pss.cpp
 * @date 2026-10-07
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
 * @brief Пример работы с ключом id-RSASSA-PSS и подписью RSASSA-PSS — разбор
 *        ключа из записи PEM, подписание хеша сообщения и проверка подписи
 *
 * @details Ключ id-RSASSA-PSS (опознаватель 1.2.840.113549.1.1.10) отличается от
 *          ключа rsaEncryption (1.2.840.113549.1.1.1) тем, что назначен лишь подписи
 *          RSASSA-PSS, а не шифрованию. Схемы подписи rsa_pss_pss_sha256/384/512
 *          (0x0809/0x080A/0x080B) в TLS 1.3 требуют именно такого ключа
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
#include <fstream>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <keys/keys.hpp>
#include <sign/rsa.hpp>
#include <digest/sha2.hpp>

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
	 * @brief Функция чтения файла набора данных целиком
	 *
	 * @param name имя файла набора данных
	 * @return     содержимое файла набора данных
	 *
	 */
	string slurp(const char * name) noexcept {
		// Содержимое файла набора данных
		string result;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
			// Если файл открыт
			if(file.is_open())
				// Читаем файл целиком
				result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Файл не прочитан
			result.clear();
		}
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Функция вывода области байтов шестнадцатеричной записью
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
 * @return     код выхода из приложения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Не используем параметры приложения
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Читаем ключ id-RSASSA-PSS из набора данных в записи PEM
	const string pem = ::slurp("rsapss.key");
	// Если файл ключа не прочитан
	if(pem.empty()){
		// Выводим сообщение об отказе чтения файла ключа
		cout << "Файл rsapss.key не прочитан" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Объект ключа подписи
	keys::key_t key;
	// Если ключ из записи PEM не разобран
	if(keys::decode(pem, view_t(), key) != keys::error_t::NONE){
		// Выводим сообщение об отказе разбора ключа
		cout << "Разобрать ключ id-RSASSA-PSS не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим вид разобранного ключа
	cout << "Вид ключа          : ";
	// Если ключ RSA
	if(key.kind == keys::kind_t::RSA)
		// Выводим признак ключа RSA
		cout << "RSA" << endl;
	// Если ключ не RSA
	else {
		// Выводим сообщение о неожиданном виде ключа
		cout << "неожиданный (" << static_cast <uint32_t> (key.kind) << ")" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим размер модуля ключа
	cout << "Размер модуля      : " << key.n.size() << " байтов" << endl;
	// Объект подписи RSA
	sign::rsa_t sign;
	// Если ключ подписи установить не удалось
	if(!sign.key(view_t(key.n.data(), key.n.size()), view_t(key.e.data(), key.e.size()), view_t(key.d.data(), key.d.size()), view_t(key.p.data(), key.p.size()), view_t(key.q.data(), key.q.size()), view_t(key.dP.data(), key.dP.size()), view_t(key.dQ.data(), key.dQ.size()), view_t(key.qInv.data(), key.qInv.size()))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подписываемое сообщение образца
	const char * message = "Сообщение, которое требуется подписать";
	// Место, в которое помещается хеш подписываемого сообщения
	uint8_t digest[32];
	// Выполняем хеширование подписываемого сообщения SHA-256
	if(!digest::sha2(digest::sha_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), digest, sizeof(digest))){
		// Выводим сообщение об отказе хеширования сообщения
		cout << "Захешировать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим хеш подписываемого сообщения
	::print("Хеш сообщения      ", digest, sizeof(digest));
	// Место, в которое помещается подпись сообщения
	uint8_t signature[256];
	/**
	 * Выполняем подписание хеша сообщения
	 *
	 * @details Схема PSS с хешем SHA-256 и длиной соли 32 байта — та же, что у
	 *          схемы rsa_pss_pss_sha256 (0x0809) в TLS 1.3. Соль вырабатывается
	 *          случайно внутри вызова
	 *
	 */
	if(!sign.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), signature, 32)){
		// Выводим сообщение об отказе подписания сообщения
		cout << "Подписать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим подпись сообщения
	::print("Подпись            ", signature, sign.size());
	// Если подпись сообщения не сошлась
	if(!sign.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), view_t(signature, sign.size()), 32)){
		// Выводим сообщение об отказе проверки подписи
		cout << "Подпись сообщения не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись сошлась" << endl;
	// Портим один байт хеша подписанного сообщения
	digest[0] = static_cast <uint8_t> (digest[0] ^ 0x01);
	// Если подпись испорченного сообщения отвергнута
	if(!sign.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), view_t(signature, sign.size()), 32))
		// Выводим сообщение об отвержении подписи испорченного сообщения
		cout << "Проверка подмены   : подпись подменённого сообщения отвергнута" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
