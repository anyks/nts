/**
 * @file crl.cpp
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
 * @brief Исходный файл проверок модуля списков отзыва сертификатов
 *
 * @note Эталоном служат списки набора tests/corpus, выработанные openssl ca:
 *       ca-rsa.crl и ca-ec.crl несут по одному отозванному сертификату
 *       (серийник 03, leaf-rsa и leaf-ec) и расширение CRL Number
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <posix.hpp>
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>
#include <x509/x509.hpp>
#include <x509/crl.hpp>
#include <x509/signature.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок списков отзыва
 */
namespace {
	/**
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 * @return     содержимое файла
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в поток
		std::stringstream stream;
		// Переливаем содержимое файла
		stream << file.rdbuf();
		// Выводим содержимое файла
		return stream.str();
	}
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое файла
	 *
	 */
	static std::string corpus(const std::string & name) {
		// Выводим содержимое файла набора
		return slurp(std::string(CORPUS) + "/" + name);
	}
	/**
	 * @brief Функция получения просмотра набора байтов
	 *
	 * @param data просматриваемый набор байтов
	 * @return     просмотр набора байтов
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) {
		// Выводим просмотр набора байтов
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Функция извлечения тела первой записи PEM
	 *
	 * @param text разбираемый текст
	 * @return     тело первой записи в кодировке DER
	 *
	 */
	static std::vector <uint8_t> body(const std::string & text) {
		// Разобранные записи текста
		std::vector <pem::block_t> blocks;
		// Если записи разобрать не удалось либо их нет
		if((pem::decode(text, blocks) != pem::error_t::NONE) || blocks.empty())
			// Выводим пустое тело
			return std::vector <uint8_t> ();
		// Выводим тело первой записи
		return blocks.front().data;
	}
	/**
	 * @brief Функция извлечения значения признака CN из имени
	 *
	 * @param name разбираемое имя
	 * @return     значение признака CN либо пустая строка
	 *
	 */
	static std::string common(const x509::name_t & name) {
		// Признак CN имени
		const x509::attribute_t * attribute = x509::attribute(name, "2.5.4.3");
		// Выводим значение признака либо пустую строку
		return ((attribute != nullptr) ? attribute->value : std::string());
	}
	/**
	 * @brief Функция разбора сертификата набора
	 *
	 * @param name        имя файла сертификата в наборе
	 * @param der         место, в которое помещается тело записи сертификата
	 * @param certificate объект разбираемого сертификата
	 * @return            признак успешности разбора
	 *
	 */
	static bool certificate(const std::string & name, std::vector <uint8_t> & der, x509::certificate_t & certificate) {
		// Тело записи сертификата в кодировке DER
		der = body(corpus(name));
		// Если записи нет
		if(der.empty())
			// Выводим отрицательный результат - записи нет
			return false;
		// Выводим итог разбора сертификата
		return (certificate.parse(view(der)) == x509::error_t::NONE);
	}
};

/**
 * Проверка разбора списков набора, выработанных openssl: имя издателя, даты,
 * алгоритм подписи, запись отозванного сертификата и расширения сходятся с записью
 */
TEST(CrlTest, Corpus){
	// Записи списков набора и их издатели
	const char * names[] = {"ca-rsa", "ca-ec"};
	// Имена издателей списков набора
	const char * issuers[] = {"ANYKS Root rsa", "ANYKS Root ec"};
	// Опознаватели алгоритмов подписи списков набора
	const char * signatures[] = {"1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2"};
	// Номера списков набора: у RSA-издателя список второй, у EC-издателя первый
	const uint8_t numbers[] = {0x02, 0x01};
	// Причины отзыва записей наборов: keyCompromise (1) у RSA, cessationOfOperation (5) у EC
	const uint8_t reasons[] = {0x01, 0x05};
	/**
	 * Выполняем перебор списков набора
	 */
	for(size_t i = 0; i < 2; i++){
		// Тело записи списка в кодировке DER
		const std::vector <uint8_t> der = body(corpus(std::string(names[i]) + ".crl"));
		// Проверяем наличие записи
		ASSERT_FALSE(der.empty()) << "Список: " << names[i];
		// Разбираемый список
		x509::crl_t crl;
		// Проверяем разбор записи списка
		ASSERT_EQ(crl.parse(view(der)), x509::error_t::NONE) << "Список: " << names[i];
		// Проверяем имя издателя списка
		ASSERT_EQ(common(crl.issuers()), issuers[i]) << "Список: " << names[i];
		// Проверяем опознаватель алгоритма подписи списка
		ASSERT_EQ(crl.algorithms(), signatures[i]) << "Список: " << names[i];
		// Даты списка
		int64_t thisUpdate = 0, nextUpdate = 0;
		// Извлекаем даты списка
		crl.updates(thisUpdate, nextUpdate);
		// Проверяем наличие обеих дат и их порядок
		ASSERT_NE(thisUpdate, 0) << "Список: " << names[i];
		// Дата следующего обновления позже даты выпуска: список действует до истечения
		ASSERT_GT(nextUpdate, thisUpdate) << "Список: " << names[i];
		// Проверяем число записей отозванных сертификатов
		ASSERT_EQ(crl.revoked().size(), static_cast <size_t> (1)) << "Список: " << names[i];
		// Проверяем порядковый номер отозванного сертификата: 03
		ASSERT_EQ(crl.revoked().front().serial.size, static_cast <size_t> (1)) << "Список: " << names[i];
		ASSERT_EQ(crl.revoked().front().serial.data[0], 0x03) << "Список: " << names[i];
		// Проверяем дату отзыва: совпадает с датой выдачи списка
		ASSERT_EQ(crl.revoked().front().date, thisUpdate) << "Список: " << names[i];
		// Проверяем число расширений записи отзыва: reasonCode
		ASSERT_EQ(crl.revoked().front().extensions.size(), static_cast <size_t> (1)) << "Список: " << names[i];
		// Проверяем опознаватель расширения записи отзыва: reasonCode 2.5.29.21
		ASSERT_EQ(crl.revoked().front().extensions.front().oid, "2.5.29.21") << "Список: " << names[i];
		// Проверяем содержимое reasonCode: ENUMERATED с причиной отзыва
		ASSERT_EQ(crl.revoked().front().extensions.front().value.size, static_cast <size_t> (3)) << "Список: " << names[i];
		ASSERT_EQ(crl.revoked().front().extensions.front().value.data[0], 0x0A) << "Список: " << names[i];
		ASSERT_EQ(crl.revoked().front().extensions.front().value.data[2], reasons[i]) << "Список: " << names[i];
		// Расширение CRL Number списка
		const x509::extension_t * number = crl.extension("2.5.29.20");
		// Проверяем наличие расширения CRL Number
		ASSERT_TRUE(number != nullptr) << "Список: " << names[i];
		// Проверяем содержимое CRL Number: INTEGER с номером списка
		ASSERT_EQ(number->value.size, static_cast <size_t> (3)) << "Список: " << names[i];
		ASSERT_EQ(number->value.data[0], 0x02) << "Список: " << names[i];
		ASSERT_EQ(number->value.data[2], numbers[i]) << "Список: " << names[i];
		// Тело записи сертификата издателя
		std::vector <uint8_t> caDer;
		// Сертификат издателя
		x509::certificate_t ca;
		// Проверяем разбор сертификата издателя
		ASSERT_TRUE(certificate(std::string(names[i]) + ".crt", caDer, ca)) << "Список: " << names[i];
		// Проверяем подпись списка сведениями об открытом ключе издателя
		ASSERT_EQ(x509::verify(crl, ca.key()), x509::error_t::NONE) << "Список: " << names[i];
	}
}

/**
 * Проверка отказов разбора и проверки: порченая подпись, обрезанная запись,
 * чужая запись, чужой ключ проверки
 */
TEST(CrlTest, Refusal){
	// Тело записи списка в кодировке DER
	const std::vector <uint8_t> der = body(corpus("ca-rsa.crl"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Разбираемый список
	x509::crl_t crl;
	// Проверяем разбор записи списка
	ASSERT_EQ(crl.parse(view(der)), x509::error_t::NONE);
	// Тело записи сертификата издателя
	std::vector <uint8_t> caDer;
	// Сертификат издателя
	x509::certificate_t ca;
	// Проверяем разбор сертификата издателя
	ASSERT_TRUE(certificate("ca-rsa.crt", caDer, ca));
	// Порченая запись: последний байт подписи перевёрнут
	std::vector <uint8_t> damaged(der);
	// Переворачиваем все разряды последнего байта подписи
	damaged[damaged.size() - 1] = static_cast <uint8_t> (damaged[damaged.size() - 1] ^ 0xFF);
	// Разбор порченой записи проходит: подпись не проверяется разбором
	ASSERT_EQ(crl.parse(view(damaged)), x509::error_t::NONE);
	// Проверяем отказ проверки порченой подписи
	ASSERT_EQ(x509::verify(crl, ca.key()), x509::error_t::SIGNATURE);
	// Обрезанная запись: без последних восьми байтов подписи
	const std::vector <uint8_t> cut(der.begin(), der.end() - 8);
	// Проверяем отказ разбора обрезанной записи
	ASSERT_NE(crl.parse(view(cut)), x509::error_t::NONE);
	// Проверяем отказ разбора пустой записи
	ASSERT_NE(crl.parse(view_t()), x509::error_t::NONE);
	// Проверяем отказ разбора чужой записи: сертификат не список
	ASSERT_NE(crl.parse(view(body(corpus("ca-rsa.crt")))), x509::error_t::NONE);
	// Тело записи чужого сертификата
	std::vector <uint8_t> foreignDer;
	// Чужой сертификат: издатель EC, не RSA
	x509::certificate_t foreign;
	// Проверяем разбор чужого сертификата
	ASSERT_TRUE(certificate("ca-ec.crt", foreignDer, foreign));
	// Проверяем разбор записи списка заново
	ASSERT_EQ(crl.parse(view(der)), x509::error_t::NONE);
	// Проверяем отказ проверки подписи чужим ключом
	ASSERT_NE(x509::verify(crl, foreign.key()), x509::error_t::NONE);
}

/**
 * Проверка розыска отозванного сертификата по порядковому номеру:
 * серийник leaf-rsa (03) в списке есть, серийник 04 отсутствует
 */
TEST(CrlTest, Lookup){
	// Тело записи списка в кодировке DER
	const std::vector <uint8_t> der = body(corpus("ca-ec.crl"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Разбираемый список
	x509::crl_t crl;
	// Проверяем разбор записи списка
	ASSERT_EQ(crl.parse(view(der)), x509::error_t::NONE);
	// Порядковый номер отозванного сертификата набора
	const uint8_t present[] = {0x03};
	// Порядковый номер сертификата вне списка
	const uint8_t absent[] = {0x04};
	// Признак нахождения отозванного серийника
	bool found = false;
	/**
	 * Выполняем обход записей отозванных сертификатов
	 */
	for(size_t i = 0; i < crl.revoked().size(); i++){
		// Если серийник записи совпал с отозванным
		if((crl.revoked()[i].serial.size == sizeof(present)) && (::memcmp(crl.revoked()[i].serial.data, present, sizeof(present)) == 0))
			// Запоминаем нахождение
			found = true;
		// Проверяем, что серийника вне списка в записи нет
		ASSERT_FALSE((crl.revoked()[i].serial.size == sizeof(absent)) && (::memcmp(crl.revoked()[i].serial.data, absent, sizeof(absent)) == 0));
	}
	// Проверяем, что отозванный серийник найден
	ASSERT_TRUE(found);
	// Проверяем розыск отсутствующего расширения
	ASSERT_TRUE(crl.extension("2.5.29.27") == nullptr);
}
