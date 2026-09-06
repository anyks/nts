/**
 * @file keys.cpp
 * @date 2026-09-06
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
 * @brief Пример кодеков ключей - выработка ключей ECDSA на кривой P-256 и Ed25519,
 *        запись их в PrivateKeyInfo (PKCS #8) и SubjectPublicKeyInfo, в обёртку PEM
 *        открытой и зашифрованной паролем, разбор обратно и подпись разобранным ключом
 *
 * @details Разобранный ключ - набор составляющих числами от старшего байта к младшему,
 *          и модуль лишь переводит его между записями: DER по RFC 5958, RFC 5480 и
 *          RFC 8410, PEM по RFC 7468, зашифрованная запись по схеме PBES2 из RFC 8018.
 *          Открытая часть ключа при разборе выводится из секретной и сличается с
 *          записанной, а ключу Ed25519 при записи довольно одного зерна
 *
 * @note Ввода и вывода модуль не делает: записи здесь остаются в памяти, а сверка с
 *       openssl лежит в проверках tests/keys - записи выходят теми же, что даёт он
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
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <keys/keys.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <digest/hash.hpp>
#include <curve/parameters.hpp>

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
	 * Опознаватель кривой P-256 (secp256r1) по RFC 5480
	 */
	static const char * P256 = "1.2.840.10045.3.1.7";
	/**
	 * @brief Метод выработки ключа ECDSA на кривой P-256
	 *
	 * @param result ключ, в который помещается итог выработки
	 *
	 * @return       признак успешности выработки ключа
	 *
	 * @note Скаляр вырабатывает примитив подписи, он же отдаёт открытую точку: запись
	 *       ключа EC несёт её обязательно (RFC 5915), и кодеку её нужно подать
	 *
	 */
	bool produce(keys::key_t & result) noexcept {
		// Кривая ключа
		curve::curve_t curve;
		// Если кривую по опознавателю завести не удалось
		if(!curve::parameters(P256, curve))
			// Выводим отказ выработки
			return false;
		// Примитив подписи, вырабатывающий ключевую пару
		sign::ecdsa_t signer;
		// Если кривую примитиву установить не удалось
		if(!signer.start(curve))
			// Выводим отказ выработки
			return false;
		// Занимаем место под секретный скаляр
		result.d.assign(curve.size(), 0);
		// Если ключевую пару выработать не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отказ выработки
			return false;
		// Занимаем место под координаты открытой точки
		result.x.assign(curve.size(), 0);
		// Вторая координата
		result.y.assign(curve.size(), 0);
		// Если открытую точку получить не удалось
		if(!signer.key(result.x.data(), result.y.data(), curve.size()))
			// Выводим отказ выработки
			return false;
		// Вид ключа
		result.kind = keys::kind_t::EC;
		// Опознаватель кривой
		result.oid = P256;
		// Выводим успешность выработки
		return true;
	}
	/**
	 * @brief Метод вывода первой и последней строк записи PEM
	 *
	 * @param title название записи
	 * @param text  текст записи PEM
	 *
	 */
	void glance(const char * title, const string & text) noexcept {
		// Конец первой строки
		const size_t first = text.find('\n');
		// Начало последней непустой строки
		const size_t last = text.rfind('\n', text.size() - 2);
		// Если строки записи не найдены
		if((first == string::npos) || (last == string::npos)){
			// Выводим запись целиком
			cout << title << text << endl;
			// Выходим
			return;
		}
		// Число строк записи
		size_t lines = 0;
		/**
		 * Выполняем подсчёт строк записи
		 */
		for(size_t i = 0; i < text.size(); i++)
			// Если знак завершает строку
			lines += ((text[i] == '\n') ? 1 : 0);
		// Выводим первую строку, число строк тела и последнюю строку
		cout << title << text.substr(0, first) << " … " << (lines - 2) << " строк … " << text.substr(last + 1, text.size() - last - 2) << " (" << text.size() << " байт)" << endl;
	}
	/**
	 * @brief Метод подписи сообщения ключом ECDSA и проверки её открытым ключом
	 *
	 * @param secret разобранный секретный ключ
	 * @param opened разобранный открытый ключ
	 *
	 * @return       признак того, что подпись выработана и сошлась
	 *
	 */
	bool ecdsa(const keys::key_t & secret, const keys::key_t & opened) noexcept {
		// Подписываемое сообщение
		const string message = "Сообщение, подписываемое разобранным ключом ECDSA";
		// Хеш сообщения
		uint8_t digest[32];
		// Если хеш сообщения выработать не удалось
		if(!digest::hash(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), digest, sizeof(digest)))
			// Выводим отказ
			return false;
		// Кривая секретного ключа: обязана жить не меньше примитива
		curve::curve_t curve;
		// Примитив подписи
		sign::ecdsa_t signer;
		// Если секретный ключ в примитив установить не удалось
		if(!secret.load(signer, curve))
			// Выводим отказ
			return false;
		// Подпись парой чисел
		vector <uint8_t> raw(curve.size() * 2, 0);
		// Если подпись выработать не удалось
		if(!signer.make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), raw.data()))
			// Выводим отказ
			return false;
		// Подпись в кодировке DER, как её понимает openssl
		vector <uint8_t> der;
		// Если подпись в кодировку DER записать не удалось
		if(!sign::encode(view_t(raw.data(), raw.size()), der))
			// Выводим отказ
			return false;
		// Кривая открытого ключа
		curve::curve_t other;
		// Примитив проверки
		sign::ecdsa_t verifier;
		// Если открытый ключ в примитив установить не удалось
		if(!opened.load(verifier, other))
			// Выводим отказ
			return false;
		// Выводим подпись
		cout << "Подпись ECDSA       : " << raw.size() << " байт парой чисел, " << der.size() << " байт в кодировке DER, проверка открытым ключом " << (verifier.check(view_t(digest, sizeof(digest)), view_t(raw.data(), raw.size())) ? "сошлась" : "не сошлась") << endl;
		// Портим хеш
		digest[0] ^= 0x01;
		// Выводим итог проверки порченого хеша
		return !verifier.check(view_t(digest, sizeof(digest)), view_t(raw.data(), raw.size()));
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
	// Выводим заголовок первого прогона
	cout << "== Ключ ECDSA на кривой P-256 ==" << endl;
	// Выработанный ключ
	keys::key_t made;
	// Если ключ выработать не удалось
	if(!produce(made)){
		// Выводим сообщение об отказе выработки
		cout << "Выработать ключ ECDSA не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим выработанный ключ
	cout << "Выработан           : секретный скаляр " << made.d.size() << " байт, открытая точка x " << made.x.size() << " и y " << made.y.size() << " байт" << endl;
	// Запись PrivateKeyInfo
	vector <uint8_t> pkcs8;
	// Если запись PrivateKeyInfo составить не удалось: точка ложится в запись по RFC 5915
	if(keys::encodePrivateKeyInfo(made, pkcs8) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать PrivateKeyInfo не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разобранный секретный ключ
	keys::key_t secret;
	// Если запись PrivateKeyInfo разобрать не удалось
	if(keys::decodePrivateKeyInfo(view_t(pkcs8.data(), pkcs8.size()), secret) != keys::error_t::NONE){
		// Выводим сообщение об отказе разбора
		cout << "Разобрать PrivateKeyInfo не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если разобранный ключ разошёлся с выработанным
	if((secret.kind != keys::kind_t::EC) || (secret.oid != made.oid) || (secret.d != made.d) || (secret.x.size() != 32) || (secret.y.size() != 32)){
		// Выводим сообщение о расхождении
		cout << "Разобранный ключ разошёлся с выработанным" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог записи и разбора
	cout << "PrivateKeyInfo      : " << pkcs8.size() << " байт DER, разобран обратно: кривая " << secret.oid << ", скаляр сошёлся, точка выведена (x " << secret.x.size() << ", y " << secret.y.size() << " байт)" << endl;
	// Запись SubjectPublicKeyInfo
	vector <uint8_t> spki;
	// Если запись SubjectPublicKeyInfo составить не удалось
	if(keys::encodeSubjectPublicKeyInfo(secret, spki) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать SubjectPublicKeyInfo не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разобранный открытый ключ
	keys::key_t opened;
	// Если запись SubjectPublicKeyInfo разобрать не удалось
	if((keys::decodeSubjectPublicKeyInfo(view_t(spki.data(), spki.size()), opened) != keys::error_t::NONE) || opened.secret() || (opened.x != secret.x) || (opened.y != secret.y)){
		// Выводим сообщение об отказе разбора
		cout << "Разобрать SubjectPublicKeyInfo не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог записи открытого ключа
	cout << "SubjectPublicKeyInfo: " << spki.size() << " байт DER, секретной части нет, точка сошлась" << endl;
	// Запись PrivateKeyInfo из открытого ключа: секретной части нет
	vector <uint8_t> refused;
	// Выводим итог: запись секретного ключа из открытого отвергается
	cout << "PKCS #8 из открытого: отказ " << keys::name(keys::encodePrivateKeyInfo(opened, refused)) << endl;
	// Если подпись разобранным ключом не сошлась
	if(!ecdsa(secret, opened)){
		// Выводим сообщение об отказе подписи
		cout << "Подпись разобранным ключом не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим заголовок прогона с обёрткой PEM
	cout << endl << "== Обёртка PEM: открытая и зашифрованная паролем ==" << endl;
	// Текст записи PEM
	string text;
	// Если запись PEM секретного ключа составить не удалось
	if(keys::encode(secret, keys::container_t::PRIVATE, text) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать ключ в PEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим запись PEM секретного ключа
	glance("PRIVATE KEY         : ", text);
	// Ключ, разобранный из PEM
	keys::key_t again;
	// Если запись PEM разобрать не удалось
	if((keys::decode(text, view_t(), again) != keys::error_t::NONE) || (again.d != secret.d)){
		// Выводим сообщение об отказе разбора
		cout << "Разобрать ключ из PEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если запись PEM открытого ключа составить не удалось
	if(keys::encode(opened, keys::container_t::PUBLIC, text) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать открытый ключ в PEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим запись PEM открытого ключа
	glance("PUBLIC KEY          : ", text);
	// Пароль зашифрованной записи: последовательность октетов без преобразования
	string password = "Пароль-123";
	// Если зашифрованную запись PEM составить не удалось: AES-256-CBC, PBKDF2 на 2048 оборотов
	if(keys::encode(secret, keys::container_t::ENCRYPTED, text, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size())) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать зашифрованный ключ в PEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим зашифрованную запись PEM
	glance("ENCRYPTED PRIVATE KEY: ", text);
	// Ключ, разобранный из зашифрованной записи
	keys::key_t unsealed;
	// Если зашифрованную запись паролем разобрать не удалось
	if((keys::decode(text, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), unsealed) != keys::error_t::NONE) || (unsealed.d != secret.d)){
		// Выводим сообщение об отказе разбора
		cout << "Разобрать зашифрованный ключ паролем не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог разбора паролем
	cout << "Паролем             : разобран, скаляр сошёлся" << endl;
	// Неверный пароль
	const string wrong = "Пароль-124";
	// Разбор неверным паролем
	const keys::error_t outcome = keys::decode(text, view_t(reinterpret_cast <const uint8_t *> (wrong.data()), wrong.size()), unsealed);
	// Если неверный пароль подошёл
	if(outcome != keys::error_t::PASSWORD){
		// Выводим сообщение о расхождении
		cout << "Неверный пароль не отвергнут: " << keys::name(outcome) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог разбора неверным паролем
	cout << "Неверным паролем    : отказ " << keys::name(outcome) << " - опознан по дополнению и устройству записи" << endl;
	// Затираем пароль: он больше не нужен
	sys::wipe(password);
	// Выводим заголовок прогона Ed25519
	cout << endl << "== Ключ Ed25519 (RFC 8410) ==" << endl;
	// Примитив подписи Ed25519
	sign::ed25519_t signer;
	// Выработанный ключ Ed25519
	keys::key_t edwards;
	// Зерно ключа
	edwards.d.assign(sign::ed25519_t::KEY_SIZE, 0);
	// Если зерно выработать не удалось
	if(!signer.generate(edwards.d.data(), edwards.d.size())){
		// Выводим сообщение об отказе выработки
		cout << "Выработать ключ Ed25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Вид ключа
	edwards.kind = keys::kind_t::ED25519;
	// Запись PrivateKeyInfo ключа Ed25519
	vector <uint8_t> seed;
	// Разобранный ключ Ed25519
	keys::key_t parsed;
	// Если запись составить либо разобрать не удалось
	if((keys::encodePrivateKeyInfo(edwards, seed) != keys::error_t::NONE) || (keys::decodePrivateKeyInfo(view_t(seed.data(), seed.size()), parsed) != keys::error_t::NONE) || (parsed.d != edwards.d) || (parsed.key.size() != sign::ed25519_t::KEY_SIZE)){
		// Выводим сообщение об отказе
		cout << "Записать и разобрать ключ Ed25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог записи: зерно в 32 байта внутри обёртки
	cout << "PrivateKeyInfo      : " << seed.size() << " байт DER, зерно " << parsed.d.size() << " байт, открытый ключ выведен (" << parsed.key.size() << " байт)" << endl;
	// Примитив проверки, заряженный разобранным ключом
	sign::ed25519_t verifier;
	// Если разобранный ключ в примитив установить не удалось
	if(!parsed.load(verifier)){
		// Выводим сообщение об отказе установки
		cout << "Установить разобранный ключ Ed25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подписываемое сообщение
	const string message = "Сообщение, подписываемое ключом Ed25519";
	// Подпись сообщения
	uint8_t signature[sign::ed25519_t::SIGNATURE_SIZE];
	// Если подпись выработать не удалось
	if(!verifier.make(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), signature)){
		// Выводим сообщение об отказе подписи
		cout << "Выработать подпись Ed25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог подписи: проверяется тем же примитивом, ибо открытый ключ в нём есть
	cout << "Подпись Ed25519     : " << sizeof(signature) << " байт, проверка " << (verifier.check(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), view_t(signature, sizeof(signature))) ? "сошлась" : "не сошлась") << endl;
	// Если запись PEM ключа Ed25519 составить не удалось
	if(keys::encode(parsed, keys::container_t::PRIVATE, text) != keys::error_t::NONE){
		// Выводим сообщение об отказе записи
		cout << "Записать ключ Ed25519 в PEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим запись PEM ключа Ed25519
	glance("PRIVATE KEY         : ", text);
	// Сбрасываем ключи с затиранием секретных составляющих
	secret.clear();
	// Сброс выработанного ключа
	made.clear();
	// Сброс ключа Ed25519
	edwards.clear();
	// Выводим итог сброса
	cout << "Сброс ключей        : секретные составляющие затёрты, скаляр " << secret.d.size() << " байт" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
