/**
 * @file trust.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл модуля доверия цепочке сертификатов
 *
 * @section Намеренные решения
 *
 * 1. Модуль не читает часов, а миг проверки принимает доводом. Проверка, глядящая на часы
 *    сама, ни повторению, ни проверке не подлежит: один и тот же сертификат отвечал бы то
 *    доверием, то отказом, и разобрать который из ответов верен, стало бы нечем.
 *
 * 2. Модуль не связан с ведением связи. Связь цепочку лишь принимает, а доверие к издателю
 *    решается запасом доверенных сертификатов, принадлежащим потребителю: сложи их вместе -
 *    и запас пришлось бы держать внутри всякой связи, а решение о доверии перестало бы
 *    быть его собственным.
 *
 * 3. Списки отзыва здесь не проверяются. Добываются они по сети, а ввода и вывода в
 *    библиотеке нет вовсе: проверка отзыва принадлежит тому же, кому принадлежит и сеть.
 *
 * 4. Право издавать сертификаты требуется от всякого издателя цепочки. Раздел 4.2.1.9
 *    RFC 5280 велит объявлять его расширением, и отсутствие расширения у издателя - не
 *    умолчание в его пользу: без него сертификат владельца выдаёт себя за издателя.
 *
 * 5. Имена сличаются записью, а не разбором. Раздел 7.1 RFC 5280 велит сличать имена по
 *    правилам вида всякого их свойства, и подмена этого сличения разбором в строку годится
 *    лишь для имён, записанных теми же видами строк: расхождение видов даёт отказ, а не
 *    ложное совпадение.
 *
 * 6. Имя со звёздочкой «*.X» при сличении с запрещённым поддеревом dNSName лежит в нём и
 *    тогда, когда основание поддерева само лежит под X одной либо несколькими метками
 *    («*.example.com» против excluded «secure.example.com»). RFC 5280 звёздочек не знает,
 *    и OpenSSL сличает буквально; но belongs() трактует «*.X» как всякий узел под X, и
 *    буквальное сличение с ограничением давало бы обход: издатель, которому запрещено
 *    secure.example.com, выпускал бы «*.example.com» и обслуживал им запрещённое имя.
 *    Для дозволенных поддеревьев сличение остаётся буквальным: хвост имени обязан лежать
 *    в поддереве. Закреплено проверкой AuditTest.WildcardExcluded. К основанию с ведущей
 *    точкой («.secure.example.com», лишь строго подчинённые имена) правило не применяется:
 *    звёздочка кроет ровно одну метку и ни одного имени под таким основанием обслужить не
 *    может, а применение давало ложный отказ годной цепочке. Закреплено проверкой
 *    TrustTest.WildcardExcludedLeadingDot.
 *
 * 7. Хвостовая точка доменного имени снимается перед всяким сличением: у имени владельца,
 *    у запрошенного имени узла и у основания поддерева. Запись «secure.example.com.» -
 *    законная форма FQDN, её принимают и IA5String, и резолверы, и издатели; сличаясь же
 *    буквально, она обходила запрещённое поддерево secure.example.com и при этом отвечала
 *    имени узла, поданному с той же точкой. Имя из одной точки либо с двумя точками на
 *    конце негодно. Закреплено проверкой TrustTest.TrailingDotExcluded.
 *
 * 8. Пустое поле subject именем вида directoryName не считается. Раздел 4.2.1.10 RFC 5280
 *    применяет ограничение лишь к именам того вида, что в сертификате есть, а раздел
 *    4.1.2.6 дозволяет пустой subject при критичном subjectAltName: такой лист под
 *    дозволенным поддеревом directoryName годен (так судит и openssl). Закреплено проверкой
 *    TrustTest.EmptySubjectDirName.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <trust/trust.hpp>
#include <x509/signature.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::trust;

	/**
	 * @brief Отказы работы модуля
	 *
	 * @note Имя заведено своё намеренно: у glibc есть собственный error_t в глобальном
	 *       пространстве имён (расширение GNU в <errno.h>), а помощники лежат в
	 *       безымянном пространстве, откуда поиск имени уходит сразу в глобальное - и
	 *       всякое обращение к error_t выходит там двусмысленным. Своё имя поиск
	 *       находит прежде глобального, и двусмысленности не возникает
	 *
	 */
	typedef trust::error_t error_t;

	/**
	 * Опознаватели заведены строками, а не указателями на знаки: вызовы, берущие
	 * `const string &`, иначе строили бы временную строку на каждый вызов, и у
	 * старых изданий libstdc++ такая строка выделяет память вне перехвата
	 */
	/**
	 * Опознаватель расширения основных ограничений сертификата
	 */
	static const string CONSTRAINTS = "2.5.29.19";

	/**
	 * Опознаватель расширения назначения открытого ключа
	 */
	static const string USAGE = "2.5.29.15";

	/**
	 * Опознаватель расширения дополнительных имён владельца
	 */
	static const string ALTERNATIVES = "2.5.29.17";
	/**
	 * Опознаватель расширения ограничений имён nameConstraints
	 */
	static const string BOUNDS = "2.5.29.30";

	/**
	 * Опознаватель свойства общего имени владельца
	 */
	static const string COMMON = "2.5.4.3";
	/**
	 * Опознаватель признака emailAddress владельца
	 */
	static const string MAILBOX = "1.2.840.113549.1.9.1";
	/**
	 * Опознаватель расширения расширенного назначения ключа
	 */
	static const string EXTENDED = "2.5.29.37";
	/**
	 * @brief Метод разбора адреса сети из записи имени узла
	 *
	 * @param name   имя узла, записанное адресом сети
	 * @param result место, в которое помещаются байты адреса
	 *
	 * @return       признак того, что имя узла есть адрес сети
	 *
	 */
	static bool address(const string & name, uint8_t * result) noexcept {
		// Если имя узла содержит точки и не содержит двоеточий: адрес IPv4
		if((name.find(':') == string::npos) && (name.find('.') != string::npos)){
			// Число разобранных частей адреса
			size_t count = 0;
			// Значение разбираемой части адреса
			uint32_t value = 0;
			// Число знаков разбираемой части адреса
			size_t digits = 0;
			/**
			 * Выполняем перебор знаков адреса
			 */
			for(size_t i = 0; i <= name.size(); i++){
				// Если знак кончает часть адреса
				if((i == name.size()) || (name[i] == '.')){
					// Если часть пуста, длиннее трёх знаков, больше 255 либо частей уже четыре
					if((digits == 0) || (digits > 3) || (value > 255) || (count == 4))
						// Выводим отказ разбора
						return false;
					// Записываем часть адреса
					result[count++] = static_cast <uint8_t> (value);
					// Сбрасываем значение части адреса
					value = 0;
					// Сбрасываем число знаков части адреса
					digits = 0;
				// Если знак - десятичная цифра
				} else if((name[i] >= '0') && (name[i] <= '9')) {
					// Накапливаем значение части адреса
					value = ((value * 10) + static_cast <uint32_t> (name[i] - '0'));
					// Считаем знак части адреса
					digits++;
				// Если знак чужой: не адрес
				} else return false;
			}
			// Выводим признак четырёх частей адреса
			return (count == 4);
		}
		// Если имя узла содержит двоеточия: адрес IPv6
		if(name.find(':') != string::npos){
			// Половины адреса до и после сжатия нулей
			uint16_t head[8] = {0}, tail[8] = {0};
			// Число частей в половинах адреса
			size_t heads = 0, tails = 0;
			// Признак пройденного сжатия нулей
			bool compressed = false;
			// Значение разбираемой части адреса
			uint32_t value = 0;
			// Число знаков разбираемой части адреса
			size_t digits = 0;
			/**
			 * Выполняем перебор знаков адреса
			 */
			for(size_t i = 0; i <= name.size(); i++){
				// Если знак кончает часть адреса
				if((i == name.size()) || (name[i] == ':')){
					// Если часть заполнена
					if(digits > 0){
						// Если частей больше восьми: не адрес
						if((heads + tails) == 8)
							// Выводим отказ разбора
							return false;
						// Если сжатие пройдено, часть ложится во вторую половину
						if(compressed)
							// Записываем часть адреса во вторую половину
							tail[tails++] = static_cast <uint16_t> (value);
						// Иначе часть ложится в первую половину
						else head[heads++] = static_cast <uint16_t> (value);
					// Если часть пуста посреди адреса: сжатие нулей
					} else if((i > 0) && (name[i - 1] == ':')) {
						// Если пустая часть на конце адреса: годен лишь хвост сжатия «::», одиночное двоеточие в конце («1:») не адрес
						if(i == name.size()){
							// Если перед двоеточием нет второго либо сжатия не было
							if((i < 2) || (name[i - 2] != ':') || !compressed)
								// Выводим отказ разбора
								return false;
						// Если сжатие уже встречалось посреди адреса: не адрес
						} else if(compressed)
							// Выводим отказ разбора
							return false;
						// Иначе запоминаем пройденное сжатие
						else compressed = true;
					// Если часть пуста на краю адреса не при сжатии: не адрес
					} else if((i == name.size()) || (i == 0)) {
						// Если следом не идёт двоеточие сжатия
						if((i == name.size()) || (name.size() < 2) || (name[1] != ':'))
							// Выводим отказ разбора
							return false;
					}
					// Сбрасываем значение части адреса
					value = 0;
					// Сбрасываем число знаков части адреса
					digits = 0;
				// Если знак - шестнадцатеричная цифра
				} else if(((name[i] >= '0') && (name[i] <= '9')) || ((name[i] >= 'a') && (name[i] <= 'f')) || ((name[i] >= 'A') && (name[i] <= 'F'))) {
					// Если знаков больше четырёх: не адрес
					if(digits == 4)
						// Выводим отказ разбора
						return false;
					// Накапливаем значение части адреса
					value = ((value << 4) | static_cast <uint32_t> ((name[i] <= '9') ? (name[i] - '0') : (((name[i] | 0x20) - 'a') + 10)));
					// Считаем знак части адреса
					digits++;
				// Если знак чужой: не адрес
				} else return false;
			}
			// Если сжатия не было, частей обязано быть ровно восемь
			if(!compressed && ((heads + tails) != 8))
				// Выводим отказ разбора
				return false;
			// Если сжатие было, а частей и без него восемь: не адрес
			if(compressed && ((heads + tails) == 8))
				// Выводим отказ разбора
				return false;
			/**
			 * Выполняем запись половин адреса с нулями сжатия между ними
			 */
			for(size_t i = 0; i < 8; i++){
				// Значение очередной части адреса
				const uint16_t item = ((i < heads) ? head[i] : ((i >= (8 - tails)) ? tail[i - (8 - tails)] : 0));
				// Записываем старший байт части
				result[i * 2] = static_cast <uint8_t> (item >> 8);
				// Записываем младший байт части
				result[(i * 2) + 1] = static_cast <uint8_t> (item & 0xFF);
			}
			// Выводим успешность разбора
			return true;
		}
		// Выводим отказ разбора: имя узла адресом не является
		return false;
	}
	/**
	 * @brief Метод проверки, что общее имя по виду есть имя узла
	 *
	 * @param name общее имя владельца
	 *
	 * @return     признак имени узла: лишь буквы, цифры, точки и дефисы, не адрес сети
	 *
	 * @note Ограничения dNSName судят общее имя лишь такого вида: имя человека либо
	 *       адрес сети под них не подпадают (так же поступает OpenSSL)
	 *
	 */
	static bool hostlike(const string & name) noexcept {
		// Пустое имя узлом не является
		if(name.empty())
			return false;
		/**
		 * Выполняем перебор знаков имени
		 */
		for(size_t i = 0; i < name.size(); i++){
			// Знак имени
			const char sign = name[i];
			// Если знак вне набора имени узла
			if(!(((sign >= 'a') && (sign <= 'z')) || ((sign >= 'A') && (sign <= 'Z')) || ((sign >= '0') && (sign <= '9')) || (sign == '.') || (sign == '-') || (sign == '*')))
				return false;
		}
		// Байты адреса сети
		uint8_t bytes[16];
		// Адрес сети именем узла не является
		return !address(name, bytes);
	}
	/**
	 * Опознаватели расширений, которые проверка доверия понимает: раздел 4.2 RFC 5280
	 * велит отвергать сертификат с неизвестным расширением, объявленным критичным
	 */
	// Приведение имени к нижнему регистру определено ниже
	static error_t lower(const string & name, string & result) noexcept;
	/**
	 * @brief Метод снятия хвостовой точки доменного имени (решение 7)
	 *
	 * @param name доменное имя, у которого снимается одна хвостовая точка
	 *
	 * @return     признак годности имени: имя из одной точки либо с двумя точками на конце негодно
	 *
	 */
	static bool rooted(string & name) noexcept;
	/**
	 * @brief Метод проверки назначения ключа сертификата по роли собеседника
	 *
	 * @param certificate проверяемый сертификат: лист либо издатель
	 * @param role        роль собеседника
	 *
	 * @return            отказ назначения либо нехватки памяти
	 *
	 * @details Раздел 4.2.1.12 RFC 5280: сертификат применяется лишь по объявленному
	 *          назначению; у издателей это судится так же, как у листа - openssl, NSS и
	 *          Windows применяют extendedKeyUsage ко всей цепочке
	 *
	 */
	static error_t intended(const x509::certificate_t & certificate, const role_t role) noexcept {
		// Расширение назначения
		const x509::extension_t * extension = certificate.extension(EXTENDED);
		// Если назначения нет - годится любое
		if(extension == nullptr)
			return error_t::NONE;
		// Перечень назначений
		vector <string> purposes;
		// Отказ разбора
		const x509::error_t outcome = x509::purpose(*extension, purposes);
		// Если памяти не хватило
		if(outcome == x509::error_t::MEMORY)
			return error_t::MEMORY;
		// Если назначения не разобрались
		if(outcome != x509::error_t::NONE)
			return error_t::PURPOSE;
		// Признак пригодности
		bool suitable = false;
		/**
		 * Выполняем перебор назначений: serverAuth годен серверу, clientAuth клиенту, anyExtendedKeyUsage обоим; без роли - любое из трёх
		 */
		for(size_t i = 0; !suitable && (i < purposes.size()); i++)
			suitable = ((purposes[i].compare("2.5.29.37.0") == 0) || ((role != role_t::CLIENT) && (purposes[i].compare("1.3.6.1.5.5.7.3.1") == 0)) || ((role != role_t::SERVER) && (purposes[i].compare("1.3.6.1.5.5.7.3.2") == 0)));
		// Выводим итог
		return (suitable ? error_t::NONE : error_t::PURPOSE);
	}
	/**
	 * @brief Метод извлечения содержимого записи ASN.1
	 *
	 * @param element запись целиком
	 *
	 * @return        содержимое записи либо пустой просмотр без данных
	 *
	 */
	static view_t contents(const view_t & element) noexcept {
		// Разборщик записи
		asn1::reader_t reader(element);
		// Элемент
		asn1::element_t item;
		// Если запись не прочиталась
		if(!reader.next(item))
			return view_t(nullptr, 0);
		// Выводим содержимое
		return item.content;
	}
	/**
	 * @brief Метод приведения отличительного имени к сличимому виду
	 *
	 * @param rdns   содержимое последовательности RDN имени
	 * @param result место, в которое помещаются RDN по порядку: признаки внутри RDN отсортированы, значения строк приведены
	 *
	 * @return       признак успешности разбора
	 *
	 * @note Раздел 7.1 RFC 5280: строки сличаются без учёта вида записи и регистра, с
	 *       ослаблением пробелов; побайтное сличение DER давало бы обход исключённого
	 *       поддерева подменой UTF8String на PrintableString. Может бросить bad_alloc.
	 *       Негодная запись даёт отказ, а не конец перебора: частично разобранное имя
	 *       не лежало бы ни в одном поддереве, и ограничение обходилось бы порчей записи
	 *
	 */
	static bool folded(const view_t & rdns, vector <string> & result) {
		// Разборщик последовательности RDN
		asn1::reader_t reader(rdns);
		// Очередной RDN
		asn1::element_t rdn;
		/**
		 * Выполняем перебор RDN
		 */
		while(!reader.empty()){
			// Если очередной RDN не прочитался - запись негодна
			if(!reader.next(rdn))
				return false;
			// Признаки RDN
			vector <string> attributes;
			// Разборщик набора признаков
			asn1::reader_t inner(rdn.content);
			// Очередной признак
			asn1::element_t attribute;
			/**
			 * Выполняем перебор признаков RDN
			 */
			while(!inner.empty()){
				// Если очередной признак не прочитался - запись негодна
				if(!inner.next(attribute))
					return false;
				// Разборщик признака: опознаватель и значение
				asn1::reader_t pair(attribute.content);
				// Опознаватель и значение
				asn1::element_t object, value;
				// Если признак не разобрался
				if(!pair.next(object) || !pair.next(value))
					return false;
				// Опознаватель признака
				string oid;
				// Если опознаватель не разобрался
				if(asn1::oid(object, oid) != asn1::error_t::NONE)
					return false;
				// Значение признака строкой
				string text;
				// Если значение не строка известного вида: берётся запись целиком
				if((value.cls != asn1::cls_t::UNIVERSAL) || (asn1::text(value, static_cast <asn1::tag_t> (value.tag), text) != asn1::error_t::NONE))
					text.assign(reinterpret_cast <const char *> (value.element.data), value.element.size);
				// Приведённое значение: регистр ASCII вниз, пробелы ослаблены
				string canon;
				// Признак пробела перед знаком
				bool space = true;
				/**
				 * Выполняем перебор знаков значения
				 */
				for(size_t i = 0; i < text.size(); i++){
					// Знак значения
					char sign = text[i];
					// Если знак пробельный
					if((sign == ' ') || (sign == '\t') || (sign == '\n') || (sign == '\r')){
						// Один пробел между словами
						if(!space)
							canon.push_back(' ');
						// Отмечаем пробел
						space = true;
						continue;
					}
					// Регистр ASCII вниз
					if((sign >= 'A') && (sign <= 'Z'))
						sign = static_cast <char> (sign + ('a' - 'A'));
					// Добавляем знак
					canon.push_back(sign);
					// Пробела не было
					space = false;
				}
				// Срезаем хвостовой пробел
				if(!canon.empty() && (canon.back() == ' '))
					canon.pop_back();
				// Разделители экранируются: значение с «;» либо «=» не должно читаться как два признака
				string guarded;
				for(size_t i = 0; i < canon.size(); i++){
					if((canon[i] == ';') || (canon[i] == '=') || (canon[i] == '\\'))
						guarded.push_back('\\');
					guarded.push_back(canon[i]);
				}
				// Признак записью «опознаватель=значение»
				attributes.push_back(oid + "=" + guarded);
			}
			// Порядок признаков внутри RDN не значим
			std::sort(attributes.begin(), attributes.end());
			// Собираем RDN в одну строку
			string joined;
			for(size_t i = 0; i < attributes.size(); i++)
				joined += (attributes[i] + ";");
			// Добавляем RDN
			result.push_back(joined);
		}
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод сличения имени с поддеревом ограничений
	 *
	 * @param name     имя сертификата
	 * @param tree     поддерево ограничений того же вида
	 * @param excluded признак того, что поддерево запрещённое: имя со звёздочкой судится шире (решение 6)
	 *
	 * @return         признак того, что имя лежит в поддереве, минус один при нехватке памяти
	 *
	 */
	static int within(const x509::alternative_t & name, const x509::alternative_t & tree, const bool excluded) noexcept {
		/**
		 * Выполняем определение вида имени
		 */
		switch(name.kind){
			// Доменное имя: раздел 4.2.1.10 RFC 5280 - «example.com» кроет себя и подчинённые, «.example.com» лишь подчинённые
			case x509::kind_t::DNS: {
				// Имя и поддерево без учёта регистра
				string host, base;
				// Приводим к нижнему регистру
				if((lower(name.value, host) != error_t::NONE) || (lower(tree.value, base) != error_t::NONE))
					// Нехватка памяти не обращается в «вне поддерева»
					return -1;
				// Если поддерево пусто - кроет всё
				if(base.empty())
					return 1;
				// Если имя с хвостовой точкой негодно (решение 7) - ни в одном поддереве не лежит
				if(!rooted(host))
					return 0;
				// Если основание с хвостовой точкой негодно (решение 7) - ничего не кроет
				if(!rooted(base))
					return 0;
				/**
				 * Решение 6: имя «*.X» против запрещённого поддерева лежит в нём и тогда,
				 * когда основание поддерева само лежит под X - звёздочка кроет всякий
				 * узел под X, в том числе и запрещённый. Основание с ведущей точкой кроет
				 * лишь строго подчинённые имена, а до них звёздочка одной меткой не достаёт
				 */
				if(excluded && (base[0] != '.') && (host.size() > 2) && (host[0] == '*') && (host[1] == '.')){
					// Хвост имени за звёздочкой
					const size_t tail = (host.size() - 2);
					// Если основание лежит под хвостом имени: кончается на «.» и хвост
					if((base.size() > tail) && (base[base.size() - tail - 1] == '.') && (base.compare(base.size() - tail, tail, host, 2, tail) == 0))
						return 1;
				}
				// Если поддерево начинается с точки - лишь подчинённые
				if(base[0] == '.')
					return ((host.size() > base.size()) && (host.compare(host.size() - base.size(), base.size(), base) == 0));
				// Само имя
				if(host.compare(base) == 0)
					return 1;
				// Подчинённое имя
				return ((host.size() > base.size()) && (host[host.size() - base.size() - 1] == '.') && (host.compare(host.size() - base.size(), base.size(), base) == 0));
			}
			// Адрес почты: поддерево с «@» - сам адрес, «example.com» - узел, «.example.com» - подчинённые узлы
			case x509::kind_t::EMAIL: {
				// Имя и поддерево без учёта регистра
				string mail, base;
				// Приводим к нижнему регистру
				if((lower(name.value, mail) != error_t::NONE) || (lower(tree.value, base) != error_t::NONE))
					// Нехватка памяти не обращается в «вне поддерева»
					return -1;
				// Если поддерево - сам адрес
				if(base.find('@') != string::npos)
					return ((mail.compare(base) == 0) ? 1 : 0);
				// Место разделителя адреса
				const size_t at = mail.find('@');
				// Если разделителя нет - не адрес
				if(at == string::npos)
					return 0;
				// Длина узла адреса: сличение по месту, без копии - выделений в noexcept не заводим
				const size_t host = (mail.size() - at - 1);
				// Если поддерево - подчинённые узлы
				if(!base.empty() && (base[0] == '.'))
					return (((host > base.size()) && (mail.compare(mail.size() - base.size(), base.size(), base) == 0)) ? 1 : 0);
				// Сам узел
				return (((host == base.size()) && (mail.compare(at + 1, host, base) == 0)) ? 1 : 0);
			}
			// Адрес сети: поддерево несёт адрес и маску той же длины
			case x509::kind_t::ADDRESS: {
				// Если длины не сходятся
				if(tree.value.size() != (name.value.size() * 2))
					return 0;
				/**
				 * Выполняем перебор байтов адреса под маской
				 */
				for(size_t i = 0; i < name.value.size(); i++){
					// Байт маски
					const uint8_t mask = static_cast <uint8_t> (tree.value[name.value.size() + i]);
					// Если под маской байты разошлись
					if((static_cast <uint8_t> (name.value[i]) & mask) != (static_cast <uint8_t> (tree.value[i]) & mask))
						return 0;
				}
				// Адрес в поддереве
				return 1;
			}
			// Отличительное имя: раздел 7.1 RFC 5280 - последовательность RDN имени начинается с последовательности основания
			case x509::kind_t::DIRECTORY: {
				/**
				 * Имя из subjectAltName записано меткой [4] поверх последовательности имени, а
				 * поле subject - самой последовательностью: у первого содержимое снимается дважды
				 */
				const bool tagged = ((name.element.size > 0) && (name.element.data[0] == 0xA4));
				// Содержимое имени и основания
				const view_t subject = (tagged ? contents(contents(name.element)) : contents(name.element)), base = contents(contents(tree.element));
				// Если содержимое не разобралось
				if((subject.data == nullptr) || (base.data == nullptr))
					return 0;
				// Пустое основание кроет всё
				if(base.size == 0)
					return 1;
				/**
				 * Выполняем перехват ошибок работы с памятью
				 */
				try {
					// Приведённые RDN имени и основания
					vector <string> first, second;
					// Если имя либо основание не разобрались
					if(!folded(subject, first) || !folded(base, second))
						return 0;
					// Если основание длиннее имени
					if(second.size() > first.size())
						return 0;
					/**
					 * Выполняем сличение RDN основания с началом имени (раздел 7.1 RFC 5280)
					 */
					for(size_t i = 0; i < second.size(); i++){
						// Если RDN разошлись
						if(first[i].compare(second[i]) != 0)
							return 0;
					}
					// Имя начинается с основания
					return 1;
				/**
				 * Если памяти не хватило
				 */
				} catch(const bad_alloc &) {
					return -1;
				}
			}
			// Прочие виды сличаются записью
			default: return (((name.element.size == tree.element.size) && (::memcmp(name.element.data, tree.element.data, name.element.size) == 0)) ? 1 : 0);
		}
	}
	/**
	 * @brief Метод проверки имён сертификата по ограничениям издателя
	 *
	 * @param certificate проверяемый подчинённый сертификат
	 * @param issuer      издатель с расширением nameConstraints
	 *
	 * @return            отказ ограничений либо нехватки памяти
	 *
	 * @details Раздел 6.1.4 RFC 5280: ограничения применяются ко всем подчинённым
	 *          сертификатам независимо от критичности расширения. Имена берутся из
	 *          subjectAltName; поддеревья видов, которые не сличить (отличительные имена,
	 *          указатели ресурса, иные), при наличии у подчинённого имени того же вида
	 *          отвергают цепочку - терпимость здесь была бы обходом ограничения
	 *
	 */
	static error_t constrained(const x509::certificate_t & certificate, const x509::certificate_t & issuer) noexcept {
		// Расширение ограничений
		const x509::extension_t * extension = issuer.extension(BOUNDS);
		// Если ограничений нет
		if(extension == nullptr)
			return error_t::NONE;
		// Дозволенные и запрещённые поддеревья
		vector <x509::alternative_t> permitted, excluded;
		// Отказ разбора ограничений
		const x509::error_t parsed = x509::constraints(*extension, permitted, excluded);
		// Если памяти не хватило
		if(parsed == x509::error_t::MEMORY)
			return error_t::MEMORY;
		// Если ограничения не разобрались - цепочка негодна
		if(parsed != x509::error_t::NONE)
			return error_t::CONSTRAINED;
		// Имена подчинённого сертификата
		vector <x509::alternative_t> names;
		// Расширение имён
		const x509::extension_t * listed = certificate.extension(ALTERNATIVES);
		// Если имена объявлены
		if(listed != nullptr){
			// Отказ разбора имён
			const x509::error_t named = x509::alternatives(*listed, names);
			// Если памяти не хватило
			if(named == x509::error_t::MEMORY)
				return error_t::MEMORY;
			// Если имена не разобрались
			if(named != x509::error_t::NONE)
				return error_t::PARSE;
		}
		// Признаки наличия имён вида DNS и почты в subjectAltName
		bool hosted = false, mailed = false;
		/**
		 * Выполняем перебор имён на виды
		 */
		for(size_t i = 0; i < names.size(); i++){
			hosted = (hosted || (names[i].kind == x509::kind_t::DNS));
			mailed = (mailed || (names[i].kind == x509::kind_t::EMAIL));
		}
		/**
		 * Выполняем перехват ошибок памяти
		 */
		try {
			/**
			 * Раздел 4.2.1.10 RFC 5280: без имени узла в subjectAltName ограничение dNSName
			 * судит общее имя владельца (им же belongs() сличает узел), ограничение
			 * rfc822Name - признак emailAddress владельца; ограничение directoryName
			 * судит само поле subject
			 */
			if(!hosted){
				// Общее имя владельца
				const x509::attribute_t * common = x509::attribute(certificate.subjects(), COMMON);
				// Если общее имя есть и по виду есть имя узла, а не адрес сети и не имя человека
				if((common != nullptr) && hostlike(common->value)){
					// Имя вида DNS
					x509::alternative_t name;
					name.kind = x509::kind_t::DNS;
					name.value = common->value;
					names.push_back(name);
				}
			}
			if(!mailed){
				// Признак emailAddress владельца
				const x509::attribute_t * mail = x509::attribute(certificate.subjects(), MAILBOX);
				// Если признак есть
				if(mail != nullptr){
					// Имя вида почты
					x509::alternative_t name;
					name.kind = x509::kind_t::EMAIL;
					name.value = mail->value;
					names.push_back(name);
				}
			}
			/**
			 * Само поле subject именем вида отличительного имени; пустое поле (SEQUENCE без
			 * RDN, дозволено разделом 4.1.2.6 RFC 5280 при критичном subjectAltName) имени
			 * этого вида не несёт и ограничением directoryName не судится (решение 8)
			 */
			if(!certificate.subjects().parts.empty() && (certificate.subjects().element.size > 0)){
				x509::alternative_t name;
				name.kind = x509::kind_t::DIRECTORY;
				name.element = certificate.subjects().element;
				names.push_back(name);
			}
		} catch(const bad_alloc &) {
			return error_t::MEMORY;
		}
		/**
		 * Выполняем перебор имён подчинённого
		 */
		for(size_t i = 0; i < names.size(); i++){
			// Признак того, что вид имени сличается
			const bool comparable = ((names[i].kind == x509::kind_t::DNS) || (names[i].kind == x509::kind_t::EMAIL) || (names[i].kind == x509::kind_t::ADDRESS) || (names[i].kind == x509::kind_t::DIRECTORY));
			/**
			 * Выполняем перебор запрещённых поддеревьев
			 */
			for(size_t j = 0; j < excluded.size(); j++){
				// Если вид не тот
				if(excluded[j].kind != names[i].kind)
					continue;
				// Итог сличения с запрещённым поддеревом
				const int inside = (comparable ? within(names[i], excluded[j], true) : 0);
				// Если памяти на сличение не хватило
				if(inside < 0)
					return error_t::MEMORY;
				// Если вид не сличить либо имя в запрещённом поддереве
				if(!comparable || (inside == 1))
					return error_t::CONSTRAINED;
			}
			// Признак наличия дозволенных поддеревьев этого вида и вхождения в одно из них
			bool ruled = false, allowed = false;
			/**
			 * Выполняем перебор дозволенных поддеревьев
			 */
			for(size_t j = 0; j < permitted.size(); j++){
				// Если вид не тот
				if(permitted[j].kind != names[i].kind)
					continue;
				// Дозволенные этого вида есть
				ruled = true;
				// Итог сличения с дозволенным поддеревом
				const int inside = (comparable ? within(names[i], permitted[j], false) : 0);
				// Если памяти на сличение не хватило
				if(inside < 0)
					return error_t::MEMORY;
				// Если имя в поддереве
				if(inside == 1)
					allowed = true;
			}
			// Если дозволенные есть, а имя вне их
			if(ruled && !allowed)
				return error_t::CONSTRAINED;
		}
		// Выводим успешность
		return error_t::NONE;
	}
	/**
	 * @brief Метод проверки назначения ключа листа цепочки
	 *
	 * @param certificate сертификат листа цепочки
	 *
	 * @return            отказ назначения ключа листа либо нехватки памяти под разбор
	 *
	 */
	static error_t signer(const x509::certificate_t & certificate, const role_t role) noexcept {
		// Получаем расширение назначения ключа
		const x509::extension_t * extension = certificate.extension(USAGE);
		// Если назначение ключа объявлено
		if(extension != nullptr){
			// Назначение открытого ключа
			uint16_t usage = 0;
			// Итог разбора, о нехватке памяти под который отвечает свой отказ
			const x509::error_t outcome = x509::usage(*extension, usage);
			// Если памяти под разбор не хватило
			if(outcome == x509::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Если назначение ключа разобрать не удалось
			if(outcome != x509::error_t::NONE)
				// Выводим отказ назначения ключа
				return error_t::PURPOSE;
			/**
			 * Раздел 4.4.2.2 RFC 8446 и раздел 4.2.1.3 RFC 5280: подпись владения ключом
			 * ставится ключом, назначенным проверке подписи
			 */
			if((usage & static_cast <uint16_t> (x509::usage_t::SIGNATURE)) == 0)
				// Выводим отказ
				return error_t::PURPOSE;
		}
		// Получаем расширение расширенного назначения ключа
		// Назначение ключа по роли
		return intended(certificate, role);
	}

	/**
	 * @brief Метод приведения имени узла к нижнему регистру
	 *
	 * @details Раздел 6.4 RFC 6125: доменные имена сличаются без учёта регистра, и
	 *          приведение это ведётся по таблице ASCII, а не по местным правилам языка
	 *
	 * @param name   приводимое имя узла
	 * @param result место, в которое помещается приведённое имя узла
	 *
	 * @return       отказ приведения имени узла
	 *
	 */
	static error_t lower(const string & name, string & result) noexcept {
		/**
		 * Приведение выделяет память под копию имени, и нехватка её обязана дойти
		 * до вызывающего причиной отказа, а не завершить процесс. Запись знаков тоже
		 * под перехватом: строка, разделяющая буфер с образцом (копирование при
		 * записи у старых изданий libstdc++), выделяет память первой же записью
		 */
		try {
			// Выполняем копирование имени
			result = name;
			/**
			 * Выполняем перебор символов приводимого имени узла
			 */
			for(size_t i = 0; i < result.size(); i++){
				// Если символ записан в верхнем регистре
				if((result[i] >= 'A') && (result[i] <= 'Z'))
					// Приводим символ к нижнему регистру
					result[i] = static_cast <char> (result[i] - 'A' + 'a');
			}
		/**
		 * Если памяти под копию имени не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выводим успешность приведения имени
		return error_t::NONE;
	}
	/**
	 * @brief Метод снятия хвостовой точки доменного имени
	 *
	 * @details Решение 7: «example.com.» - та же запись имени, что и «example.com», и
	 *          сличается она лишь после снятия точки; имя из одной точки либо с двумя
	 *          точками на конце - не имя вовсе
	 *
	 * @param name доменное имя, у которого снимается одна хвостовая точка
	 *
	 * @return     признак годности имени
	 *
	 */
	static bool rooted(string & name) noexcept {
		// Если имя пусто - снимать нечего, а пустое имя судится вызывающим
		if(name.empty())
			// Выводим признак годности имени
			return true;
		// Если имя кончается точкой
		if(name.back() == '.')
			// Снимаем хвостовую точку
			name.pop_back();
		// Выводим признак того, что за снятой точкой стоит имя, а не пустота и не вторая точка
		return (!name.empty() && (name.back() != '.'));
	}
	/**
	 * @brief Метод сличения имени узла с именем сертификата
	 *
	 * @param pattern имя сертификата, вправе нести звёздочку самой левой частью
	 * @param name    имя узла, за которым пришли
	 *
	 * @return        признак того, что имя узла имени сертификата отвечает
	 *
	 */
	static bool matches(const string & pattern, const string & name) noexcept {
		/**
		 * Слагаемое name.empty() ложно всегда: пустое имя узла отвергается сличением
		 * сертификата ещё до перебора имён владельца. Слагаемое оставлено ради
		 * самостоятельности сличения: сличаются имена, а не место их получения, и
		 * пустое имя узла отвечать имени сертификата не вправе ни при каком вызове
		 */
		// Если имя сертификата либо имя узла пусто
		if(pattern.empty() || name.empty())
			// Выводим признак несовпадения имён
			return false;
		// Если имя сертификата звёздочки не несёт
		if(pattern.compare(0, 2, "*.") != 0)
			// Выводим признак совпадения имён
			return (pattern.compare(name) == 0);
		// Получаем место разделителя самой левой части имени узла
		const size_t offset = name.find('.');
		// Если имя узла из одной части и состоит
		if(offset == string::npos)
			// Выводим признак несовпадения имён
			return false;
		/**
		 * Звёздочка отвечает лишь одной части имени: без этого правила имя вида
		 * «*.com» отвечало бы всякому узлу верхней области имён
		 */
		if(name.find('.', offset + 1) == string::npos)
			// Выводим признак несовпадения имён
			return false;
		// Выводим итог сличения оставшихся частей имён
		return (pattern.compare(2, string::npos, name, offset + 1, string::npos) == 0);
	}
	/**
	 * @brief Метод проверки права сертификата издавать другие сертификаты
	 *
	 * @param certificate проверяемый сертификат издателя
	 * @param depth       число звеньев цепочки, лежащих ниже проверяемого сертификата
	 *
	 * @return            отказ проверки права издавать сертификаты
	 *
	 */
	static error_t authority(const x509::certificate_t & certificate, const size_t depth) noexcept {
		// Разыскиваем расширение основных ограничений сертификата
		const x509::extension_t * extension = certificate.extension(CONSTRAINTS);
		/**
		 * Отсутствие расширения умолчанием в пользу издателя не считается: раздел
		 * 4.2.1.9 RFC 5280 велит объявлять право издавать сертификаты явно
		 */
		if(extension == nullptr)
			// Выводим отказ отсутствия права издавать сертификаты
			return error_t::CONSTRAINT;
		// Признак права издавать другие сертификаты
		bool allowed = false;
		// Предел числа звеньев цепочки под сертификатом
		int64_t limit = -1;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t limits = x509::constraints(*extension, allowed, limit);
		// Если памяти под разбор не хватило
		if(limits == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если основные ограничения сертификата разобрать не удалось
		if(limits != x509::error_t::NONE)
			// Выводим отказ разбора основных ограничений
			return error_t::CONSTRAINT;
		// Если сертификат издавать другие сертификаты не вправе
		if(!allowed)
			// Выводим отказ отсутствия права издавать сертификаты
			return error_t::CONSTRAINT;
		// Если предел числа звеньев цепочки объявлен и превышен
		if((limit >= 0) && (static_cast <int64_t> (depth) > limit))
			// Выводим отказ превышения предела длины цепочки
			return error_t::CONSTRAINT;
		// Разыскиваем расширение назначения открытого ключа
		extension = certificate.extension(USAGE);
		// Если назначение открытого ключа сертификатом не объявлено
		if(extension == nullptr)
			// Выводим успешность проверки права издавать сертификаты
			return error_t::NONE;
		// Набор разрядов назначения открытого ключа
		uint16_t usage = 0;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t usages = x509::usage(*extension, usage);
		// Если памяти под разбор не хватило
		if(usages == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если назначение открытого ключа разобрать не удалось
		if(usages != x509::error_t::NONE)
			// Выводим отказ разбора назначения открытого ключа
			return error_t::CONSTRAINT;
		/**
		 * Объявленное назначение ключа соблюдается: сертификат, ключ которого назначен
		 * не подписыванию сертификатов, подписью издателя быть не вправе
		 */
		if((usage & static_cast <uint16_t> (x509::usage_t::CERTIFICATE)) == 0)
			// Выводим отказ несовпадения назначения открытого ключа
			return error_t::CONSTRAINT;
		// Выводим успешность проверки права издавать сертификаты
		return error_t::NONE;
	}
	/**
	 * @brief Метод проверки срока действия сертификата
	 *
	 * @param certificate проверяемый сертификат
	 * @param moment      миг проверки в секундах от начала эпохи
	 *
	 * @return            отказ проверки срока действия сертификата
	 *
	 */
	static error_t validity(const x509::certificate_t & certificate, const int64_t moment) noexcept {
		// Начало срока действия сертификата
		int64_t before = 0;
		// Окончание срока действия сертификата
		int64_t after = 0;
		// Выполняем получение срока действия сертификата
		certificate.validity(before, after);
		// Если срок действия сертификата на этот миг не идёт
		if((moment < before) || (moment > after))
			// Выводим отказ истечения срока действия сертификата
			return error_t::EXPIRED;
		// Выводим успешность проверки срока действия сертификата
		return error_t::NONE;
	}
};

/**
 * @brief Метод получения числа доверенных сертификатов запаса
 *
 * @return число доверенных сертификатов запаса
 *
 */
size_t nts::trust::Store::size() const noexcept {
	// Выводим число доверенных сертификатов запаса
	return this->_chain.size();
}
/**
 * @brief Метод получения доверенного сертификата запаса
 *
 * @param index место запрашиваемого сертификата в запасе
 *
 * @return      запись запрашиваемого сертификата
 *
 */
view_t nts::trust::Store::get(const size_t index) const noexcept {
	// Если запрашиваемого сертификата в запасе нет
	if(index >= this->_chain.size())
		// Выводим пустую запись сертификата
		return view_t();
	// Выводим запись запрашиваемого сертификата запаса
	return view_t(this->_chain[index].data(), this->_chain[index].size());
}
/**
 * @brief Метод добавления доверенного сертификата в запас
 *
 * @param certificate запись добавляемого сертификата
 *
 * @return            признак успешности добавления сертификата
 *
 */
bool nts::trust::Store::add(const view_t & certificate) noexcept {
	// Если запись добавляемого сертификата не передана
	if((certificate.data == nullptr) || (certificate.size == 0))
		// Выводим отказ добавления сертификата в запас
		return false;
	// Объект разбора добавляемого сертификата
	x509::certificate_t item;
	/**
	 * Сертификат разбирается при добавлении: непригодной записью запас доверия
	 * пополнять нечего, а узнать о её непригодности посреди проверки цепочки поздно
	 */
	if(item.parse(certificate) != x509::error_t::NONE)
		// Выводим отказ добавления сертификата в запас
		return false;
	/**
	 * Выполняем добавление сертификата в запас доверенных
	 */
	try {
		// Добавляем запись сертификата в запас доверенных
		this->_chain.push_back(vector <uint8_t> (certificate.data, certificate.data + certificate.size));
	/**
	 * Если памяти под запас доверенных не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ добавления сертификата в запас
		return false;
	}
	// Выводим успешность добавления сертификата в запас
	return true;
}
/**
 * @brief Метод сброса запаса доверенных сертификатов
 *
 */
void nts::trust::Store::clear() noexcept {
	// Выполняем сброс запаса доверенных сертификатов
	this->_chain.clear();
}
/**
 * @brief Метод проверки цепочки сертификатов запасом доверенных
 *
 * @param chain  проверяемая цепочка сертификатов от своего к издателю
 * @param store  запас доверенных сертификатов
 * @param moment миг проверки в секундах от начала эпохи
 *
 * @return       отказ доверия цепочке сертификатов
 *
 */
nts::trust::error_t nts::trust::verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment) noexcept {
	// Без роли годится любое назначение листа
	return verify(chain, store, moment, role_t::ANY);
}
/**
 * @brief Метод проверки цепочки сертификатов с учётом роли собеседника
 *
 * @param chain  проверяемая цепочка
 * @param store  запас доверенных
 * @param moment миг проверки
 * @param role   роль собеседника
 *
 * @return       отказ доверия
 *
 */
nts::trust::error_t nts::trust::verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment, const role_t role) noexcept {
	// Если проверяемая цепочка сертификатов пуста
	if(chain.empty())
		// Выводим отказ пустой цепочки сертификатов
		return error_t::EMPTY;
	// Если длина цепочки сертификатов превышает дозволенную
	if(chain.size() > TRUST_DEPTH)
		// Выводим отказ превышения предела длины цепочки
		return error_t::DEPTH;
	// Разобранные сертификаты проверяемой цепочки
	vector <x509::certificate_t> items;
	/**
	 * Выполняем разбор сертификатов проверяемой цепочки
	 */
	try {
		// Занимаем место под разобранные сертификаты цепочки
		items.resize(chain.size());
	/**
	 * Если памяти под разбор цепочки не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Место звена, замкнувшего цепочку из запаса: за пределами цепочки, пока такого нет
	size_t closing = chain.size();
	/**
	 * Выполняем перебор сертификатов проверяемой цепочки
	 */
	for(size_t i = 0; i < chain.size(); i++){
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t parsed = items[i].parse(view_t(chain[i].data(), chain[i].size()));
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если сертификат цепочки разобрать не удалось
		if(parsed != x509::error_t::NONE)
			// Выводим отказ разбора сертификата цепочки
			return error_t::PARSE;
		// Если сертификат звена несёт неизвестное критичное расширение
		if(!x509::recognized(items[i]))
			// Выводим отказ неизвестного критичного расширения
			return error_t::CRITICAL;
		// Выполняем проверку срока действия сертификата цепочки
		const error_t error = validity(items[i], moment);
		// Если срок действия сертификата на этот миг не идёт
		if(error != error_t::NONE)
			// Выводим отказ истечения срока действия сертификата
			return error;
		/**
		 * Звено, лежащее в запасе доверенных, замыкает цепочку: звенья выше него (истёкший
		 * прежний корень над доверенным промежуточным, как DST Root CA X3 над ISRG Root X1)
		 * не судятся - так поступают OpenSSL с -partial_chain и браузеры
		 */
		if((i + 1) < chain.size()){
			// Признак того, что звено доверено
			bool trusted = false;
			/**
			 * Выполняем перебор запаса
			 */
			for(size_t j = 0; !trusted && (j < store.size()); j++){
				// Доверенный сертификат
				const view_t anchor = store.get(j);
				// Если записи совпали
				trusted = ((anchor.size == chain[i].size()) && (::memcmp(anchor.data, chain[i].data(), anchor.size) == 0));
			}
			// Если звено доверено: цепочка кончается на нём, и оно судится якорем
			if(trusted){
				// Запоминаем место замыкающего звена
				closing = i;
				// Укорачиваем разобранную цепочку
				items.resize(i + 1);
				// Прерываем разбор
				break;
			}
		}
	}
	// Итог проверки назначения ключа листа цепочки
	const error_t purposed = signer(items[0], role);
	// Если ключ листа цепочки подпись владения ставить не вправе либо памяти не хватило
	if(purposed != error_t::NONE)
		// Выводим отказ назначения ключа листа либо нехватки памяти
		return purposed;
	/**
	 * Выполняем перебор звеньев проверяемой цепочки сертификатов
	 */
	for(size_t i = 0; (i + 1) < items.size(); i++){
		// Имя издателя сертификата звена цепочки
		string issuer;
		/**
		 * Заслоны записи имён недостижимы данными: сборка записи имени отказывает
		 * одною лишь нехваткой памяти, а само имя разобрано ещё разбором сертификата.
		 * Стоят они ради связности сверки: сличение имён по пустой записи, молча
		 * полученной вместо настоящей, было бы хуже отказа
		 */
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t issued = x509::text(items[i].issuers(), issuer);
		// Если памяти под разбор не хватило
		if(issued == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если имя издателя сертификата получить не удалось
		if(issued != x509::error_t::NONE)
			// Выводим отказ разбора имени издателя сертификата
			return error_t::PARSE;
		// Имя владельца следующего сертификата цепочки
		string subject;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t owned = x509::text(items[i + 1].subjects(), subject);
		// Если памяти под разбор не хватило
		if(owned == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если имя владельца сертификата получить не удалось
		if(owned != x509::error_t::NONE)
			// Выводим отказ разбора имени владельца сертификата
			return error_t::PARSE;
		// Если издатель сертификата с владельцем следующего разошёлся
		if(issuer.compare(subject) != 0)
			// Выводим отказ несовпадения издателя с владельцем
			return error_t::ISSUER;
		// Выполняем проверку права издавать другие сертификаты
		const error_t error = authority(items[i + 1], i);
		// Если сертификат издавать другие сертификаты не вправе
		if(error != error_t::NONE)
			// Выводим отказ отсутствия права издавать сертификаты
			return error;
		// Назначение ключа издателя по роли (раздел 4.2.1.12 RFC 5280)
		const error_t intent = intended(items[i + 1], role);
		if(intent != error_t::NONE)
			return intent;
		/**
		 * Раздел 6.1.4 RFC 5280: ограничения имён издателя кроют все подчинённые сертификаты
		 */
		for(size_t j = 0; j <= i; j++){
			const error_t bounded = constrained(items[j], items[i + 1]);
			if(bounded != error_t::NONE)
				return bounded;
		}
		// Если звено либо его издатель слабы: подпись SHA-1/MD5 либо ключ RSA короче 2048 (RFC 9155, SP 800-131A)
		if(x509::weak(items[i], false) || x509::weak(items[i + 1], ((i + 1) == closing)))
			// Выводим отказ стойкости
			return error_t::WEAK;
		// Итог проверки подписи сертификата издателем
		const x509::error_t attested = x509::verify(items[i], items[i + 1].key());
		// Если памяти под проверку подписи не хватило
		if(attested == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если подпись сертификата издателем не сошлась
		if(attested != x509::error_t::NONE)
			// Выводим отказ схождения подписи сертификата
			return error_t::SIGNATURE;
	}
	// Получаем последний сертификат проверяемой цепочки
	const x509::certificate_t & last = items[items.size() - 1];
	// Получаем запись последнего сертификата проверяемой (быть может, укороченной) цепочки
	const vector <uint8_t> & record = chain[items.size() - 1];
	// Имя издателя последнего сертификата цепочки
	string issuer;
	// Итог разбора, о нехватке памяти под который отвечает свой отказ
	const x509::error_t issued = x509::text(last.issuers(), issuer);
	// Если памяти под разбор не хватило
	if(issued == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если имя издателя сертификата получить не удалось
	if(issued != x509::error_t::NONE)
		// Выводим отказ разбора имени издателя сертификата
		return error_t::PARSE;
	/**
	 * Выполняем перебор доверенных сертификатов запаса
	 */
	for(size_t i = 0; i < store.size(); i++){
		// Получаем запись очередного доверенного сертификата запаса
		const view_t item = store.get(i);
		/**
		 * Сертификат, лежащий в запасе сам, доверен без проверки подписи: подписал
		 * его тот же, кому он и принадлежит, а доверие ему объявлено запасом
		 */
		if((item.size == record.size()) && (::memcmp(item.data, record.data(), item.size) == 0))
			// Выводим успешность проверки цепочки сертификатов
			return error_t::NONE;
		// Объект разбора доверенного сертификата запаса
		x509::certificate_t anchor;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t parsed = anchor.parse(item);
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если доверенный сертификат запаса разобрать не удалось
		if(parsed != x509::error_t::NONE)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Если якорь несёт неизвестное критичное расширение, якорем он служить не может
		if(!x509::recognized(anchor))
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Имя владельца доверенного сертификата запаса
		string subject;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t owned = x509::text(anchor.subjects(), subject);
		// Если памяти под разбор не хватило
		if(owned == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если имя владельца сертификата получить не удалось
		if(owned != x509::error_t::NONE)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Если владелец доверенного сертификата с издателем цепочки разошёлся
		if(subject.compare(issuer) != 0)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Если срок действия доверенного сертификата на этот миг не идёт
		if(validity(anchor, moment) != error_t::NONE)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Если доверенный сертификат издавать другие сертификаты не вправе
		if(authority(anchor, items.size() - 1) != error_t::NONE)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Назначение ключа якоря по роли и его ограничения имён кроют всю цепочку (разделы 4.2.1.10, 4.2.1.12 RFC 5280 - как у openssl и NSS)
		if(intended(anchor, role) != error_t::NONE)
			continue;
		// Признак нарушения ограничений якоря
		bool bounded = false;
		/**
		 * Выполняем перебор звеньев цепочки под ограничениями якоря
		 */
		for(size_t j = 0; (j < items.size()) && !bounded; j++){
			// Отказ ограничений
			const error_t limit = constrained(items[j], anchor);
			// Если памяти не хватило
			if(limit == error_t::MEMORY)
				return error_t::MEMORY;
			// Запоминаем нарушение
			bounded = (limit != error_t::NONE);
		}
		// Если ограничения нарушены
		if(bounded)
			continue;
		// Если последнее звено слабо: подпись SHA-1/MD5 либо ключ RSA короче 2048
		if(x509::weak(last, false))
			// Выводим отказ стойкости
			return error_t::WEAK;
		// Если слаб якорь: он негоден, ищется иной
		if(x509::weak(anchor, true))
			// Переходим к следующему якорю
			continue;
		// Итог проверки подписи последнего сертификата цепочки якорем
		const x509::error_t anchored = x509::verify(last, anchor.key());
		// Если памяти под проверку подписи не хватило
		if(anchored == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если подпись последнего сертификата цепочки не сошлась
		if(anchored != x509::error_t::NONE)
			// Переходим к следующему доверенному сертификату запаса
			continue;
		// Выводим успешность проверки цепочки сертификатов
		return error_t::NONE;
	}
	// Выводим отказ отсутствия издателя цепочки в запасе доверенных
	return error_t::AUTHORITY;
}
/**
 * @brief Метод сличения имени узла с именами сертификата
 *
 * @param certificate запись сличаемого сертификата
 * @param name        имя узла, за которым пришли
 *
 * @return            отказ сличения имени узла
 *
 */
nts::trust::error_t nts::trust::belongs(const view_t & certificate, const string & name) noexcept {
	// Если имя узла не передано
	if(name.empty())
		// Выводим отказ несовпадения имени узла
		return error_t::NAME;
	// Объект разбора сличаемого сертификата
	x509::certificate_t item;
	// Итог разбора, о нехватке памяти под который отвечает свой отказ
	const x509::error_t parsed = item.parse(certificate);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если сличаемый сертификат разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::PARSE;
	// Приведённое к нижнему регистру имя узла
	string requested;
	// Если привести имя узла к нижнему регистру не удалось
	if(lower(name, requested) != error_t::NONE)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если имя узла с хвостовой точкой негодно (решение 7)
	if(!rooted(requested))
		// Выводим отказ несовпадения имени узла
		return error_t::NAME;
	// Байты адреса сети, если имя узла им записано
	uint8_t bytes[16] = {0};
	// Признак имени узла, записанного адресом сети
	const bool numeric = address(name, bytes);
	// Длина адреса сети: четыре байта у IPv4 и шестнадцать у IPv6
	const size_t width = ((name.find(':') != string::npos) ? 16 : 4);
	// Разыскиваем расширение дополнительных имён владельца
	const x509::extension_t * extension = item.extension(ALTERNATIVES);
	// Если дополнительные имена владельца сертификатом объявлены
	if(extension != nullptr){
		// Перечень дополнительных имён владельца сертификата
		vector <x509::alternative_t> alternatives;
		// Итог разбора, о нехватке памяти под который отвечает свой отказ
		const x509::error_t listed = x509::alternatives(*extension, alternatives);
		// Если памяти под разбор не хватило
		if(listed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если дополнительные имена владельца разобрать не удалось
		if(listed != x509::error_t::NONE)
			// Выводим отказ разбора дополнительных имён владельца
			return error_t::PARSE;
		/**
		 * Выполняем перебор дополнительных имён владельца сертификата
		 */
		for(size_t i = 0; i < alternatives.size(); i++){
			/**
			 * Раздел 6.4 RFC 6125 и раздел 4.2.1.6 RFC 5280: имя узла, записанное
			 * адресом сети, сличается лишь с адресами сети в двоичном виде, а доменное
			 * имя - лишь с доменными
			 */
			if(numeric){
				// Если очередное имя владельца адресом сети не является
				if(alternatives[i].kind != x509::kind_t::ADDRESS)
					// Переходим к следующему имени владельца сертификата
					continue;
				// Если байты адреса сошлись с адресом узла
				if((alternatives[i].value.size() == width) && (::memcmp(alternatives[i].value.data(), bytes, width) == 0))
					// Выводим успешность сличения
					return error_t::NONE;
				// Переходим к следующему имени владельца сертификата
				continue;
			}
			// Если очередное имя владельца доменным не является
			if(alternatives[i].kind != x509::kind_t::DNS)
				// Переходим к следующему имени владельца сертификата
				continue;
			// Приведённое к нижнему регистру имя владельца сертификата
			string pattern;
			// Если привести имя владельца сертификата к нижнему регистру не удалось
			if(lower(alternatives[i].value, pattern) != error_t::NONE)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Если имя владельца с хвостовой точкой негодно (решение 7)
			if(!rooted(pattern))
				// Переходим к следующему имени владельца сертификата
				continue;
			// Если имя узла имени сертификата отвечает
			if(matches(pattern, requested))
				// Выводим успешность сличения имени узла
				return error_t::NONE;
		}
		/**
		 * Общее имя владельца при объявленных дополнительных именах не берётся:
		 * раздел 6.4.4 RFC 6125 велит поступать так и только так
		 */
		return error_t::NAME;
	}
	// Разыскиваем общее имя владельца сертификата
	// Если имя узла записано адресом сети, общее имя владельца ему не отвечает
	if(numeric)
		// Выводим отказ сличения имени
		return error_t::NAME;
	const x509::attribute_t * attribute = x509::attribute(item.subjects(), COMMON);
	// Если общего имени владельца у сертификата нет
	if(attribute == nullptr)
		// Выводим отказ несовпадения имени узла
		return error_t::NAME;
	// Приведённое к нижнему регистру общее имя владельца сертификата
	string pattern;
	// Если привести общее имя владельца к нижнему регистру не удалось
	if(lower(attribute->value, pattern) != error_t::NONE)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если общее имя владельца с хвостовой точкой негодно (решение 7)
	if(!rooted(pattern))
		// Выводим отказ несовпадения имени узла
		return error_t::NAME;
	// Если имя узла общему имени владельца отвечает
	if(matches(pattern, requested))
		// Выводим успешность сличения имени узла
		return error_t::NONE;
	// Выводим отказ несовпадения имени узла
	return error_t::NAME;
}
