/**
 * @file extension.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля расширений приветствий протокола TLS
 *
 * @note Расширения берутся из тех же пяти настоящих приветствий приложения А, на которых
 *       проверялся разбор самих приветствий: всякое известное расширение разбирается,
 *       составляется заново и сличается со своим телом байт в байт
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstring>
#include <main.hpp>
#include <hello/hello.hpp>
#include <curve/curve.hpp>
#include <curve/parameters.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Приветствия рукопожатия контрольного примера
 */
static const struct Sample {
	// Вид сообщения рукопожатия приветствия
	uint8_t type;
	// Сообщение приветствия вместе с обвязкой
	const char * message;
} SAMPLES[] = {
	{1, "010000DE03030303030303030303030303030303030303030303030303030303030303030303000002C105010000B3000A000400020028000D0010000E0709070A070B070C070D070E070F002B0003020304002D000201000033008600840028008005EEBDF3DDC1D2F5F3822433241284E77641487938EA88721F26203E9792B5CB97EB70EF02E8F72B7491D4F2CFDC332ADF7F1778E854A88DDC2113FEC527A15171A04CB0C573793A7AEF9BBCA486B6B046B2149B46F4332903E5B7C438ADD05E185EFBF45557475A8CCBF6ACED1A2EB416F916729D7CEF9CBD8334989304AFAE"},
	{2, "020000B60303838383838383838383838383838383838383838383838383838383838383838300C10500008E002B0002030400330084002800802F3C663FE74735A1C421160DF0F43266185FD30B6E5D6E88FC4061FAEACAB338B10A1BD20CB0B4EE757E74A0027D409FE937F01633A1E3F9A5518DEFD0F89F9D3D9F6CC651413DEC2C74366D83C47EE1DE4E421F65CD1163E94EA0C2E19ED45D35558B937D9BFDC5ECC2B2A21B4EC3D53B29579A8FD5E074811028FBCF17994F"},
	{2, "020000340303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C00C10400000C002B00020304003300020023"},
	{1, "010000BF03030101010101010101010101010101010101010101010101010101010101010101000002C10401000094000A0006000400230028002B0003020304002D0002010100330046004400230040D35AA795C452450949591D60E7D5C076056D6646F3B80708CDC2E7034DE85F68D1122DC32A3B986D40FF910622A06C1226D9EC3A7D3A52E0A37C282C47602A430029002F000A00046550534B000000000021200BF74AA3933B7D1A66961B6E2CFB6A2804D696BB607710E3F56DDA91F56B57CB"},
	{2, "0200007C0303828282828282828282828282828282828282828282828282828282828282828200C104000054002B0002030400330044002300403D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC002900020000"}
};

/**
 * @brief Метод разбора строки шестнадцатеричной записи в область байтов
 *
 * @param text разбираемая строка шестнадцатеричной записи
 *
 * @return     разобранная область байтов
 *
 */
static vector <uint8_t> decode(const char * text) noexcept {
	// Разобранная область байтов
	vector <uint8_t> result;
	// Получаем длину разбираемой строки
	const size_t length = ::strlen(text);
	/**
	 * Выполняем перебор пар знаков шестнадцатеричной записи
	 */
	for(size_t i = 0; (i + 1) < length; i += 2)
		// Добавляем очередной разобранный байт
		result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
	// Выводим разобранную область байтов
	return result;
}

/**
 * Проверка соответствия групп обмена и схем подписи кривым
 */
TEST(ExtensionTest, Curve){
	// Перечень всех групп обмена ключами протокола
	const extension::group_t groups[] = {
		extension::group_t::GC256A, extension::group_t::GC256B,
		extension::group_t::GC256C, extension::group_t::GC256D,
		extension::group_t::GC512A, extension::group_t::GC512B,
		extension::group_t::GC512C
	};
	// Перечень всех схем подписи протокола
	const extension::scheme_t schemes[] = {
		extension::scheme_t::S256A, extension::scheme_t::S256B,
		extension::scheme_t::S256C, extension::scheme_t::S256D,
		extension::scheme_t::S512A, extension::scheme_t::S512B,
		extension::scheme_t::S512C
	};
	/**
	 * Выполняем перебор групп обмена ключами протокола
	 */
	for(size_t i = 0; i < (sizeof(groups) / sizeof(groups[0])); i++){
		// Получаем опознаватель кривой группы обмена ключами
		const char * oid = extension::curve(groups[i]);
		// Проверяем, что опознаватель кривой группы найден
		ASSERT_NE(oid, nullptr) << "группа " << i;
		// Объект кривой группы обмена ключами
		curve::curve_t sample;
		// Проверяем, что кривая набора параметров модулю известна
		ASSERT_TRUE(curve::parameters(oid, sample)) << "группа " << i;
		// Проверяем схождение опознавателя кривой со схемой подписи той же кривой
		ASSERT_STREQ(oid, extension::curve(schemes[i])) << "группа " << i;
		// Проверяем схождение длины ключа схемы подписи с длиной координаты кривой
		ASSERT_EQ(extension::length(schemes[i]), sample.size()) << "группа " << i;
	}
	// Проверяем, что неизвестная группа обмена опознавателя не имеет
	ASSERT_EQ(extension::curve(extension::group_t::NONE), nullptr);
	// Проверяем, что неизвестная схема подписи длины ключа не имеет
	ASSERT_EQ(extension::length(extension::scheme_t::NONE), static_cast <size_t> (0));
}

/**
 * Проверка разбора и составления тел расширений приветствий
 */
TEST(ExtensionTest, Bodies){
	// Число разобранных тел расширений приветствий
	size_t count = 0;
	/**
	 * Выполняем перебор приветствий контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Получаем сообщение приветствия вместе с обвязкой
		const vector <uint8_t> message = decode(SAMPLES[i].message);
		// Получаем тело сообщения приветствия
		const view_t body(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER);
		// Признак того, что разбирается приветствие клиента
		const bool client = (SAMPLES[i].type == 0x01);
		// Перечень расширений разобранного приветствия
		vector <hello::extension_t> extensions;
		// Признак того, что приветствие есть просьба о повторе
		bool retry = false;
		// Если разбирается приветствие клиента
		if(client){
			// Разобранное приветствие клиента
			hello::client_t hello;
			// Выполняем разбор тела приветствия клиента
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Запоминаем перечень расширений приветствия клиента
			extensions = hello.extensions;
		// Если разбирается приветствие сервера
		} else {
			// Разобранное приветствие сервера
			hello::server_t hello;
			// Выполняем разбор тела приветствия сервера
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Запоминаем перечень расширений приветствия сервера
			extensions = hello.extensions;
			// Запоминаем, есть ли приветствие просьба о повторе
			retry = hello::retry(hello);
		}
		/**
		 * Выполняем перебор расширений разобранного приветствия
		 */
		for(auto & item : extensions){
			// Накопитель, в который складывается составленное тело расширения
			vector <uint8_t> composed;
			/**
			 * Выполняем определение вида расширения приветствия
			 */
			switch(item.type){
				// Если это расширение поддерживаемых изданий протокола
				case static_cast <uint16_t> (extension::type_t::VERSIONS): {
					// Если это расширение приветствия клиента
					if(client){
						// Разобранный перечень поддерживаемых изданий протокола
						vector <uint16_t> versions;
						// Выполняем разбор перечня поддерживаемых изданий
						ASSERT_EQ(extension::versions(item.data, versions), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что клиент предлагает издание TLS 1.3
						ASSERT_EQ(versions[0], static_cast <uint16_t> (0x0304)) << "приветствие " << i;
						// Выполняем составление перечня поддерживаемых изданий заново
						ASSERT_EQ(extension::versions(versions, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия сервера
					} else {
						// Разобранное выбранное издание протокола
						uint16_t version = 0;
						// Выполняем разбор выбранного издания протокола
						ASSERT_EQ(extension::version(item.data, version), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что сервер выбрал издание TLS 1.3
						ASSERT_EQ(version, static_cast <uint16_t> (0x0304)) << "приветствие " << i;
						// Выполняем составление выбранного издания протокола заново
						ASSERT_EQ(extension::version(version, composed), extension::error_t::NONE) << "приветствие " << i;
					}
				} break;
				// Если это расширение поддерживаемых групп обмена ключами
				case static_cast <uint16_t> (extension::type_t::GROUPS): {
					// Разобранный перечень поддерживаемых групп обмена
					vector <extension::group_t> groups;
					// Выполняем разбор перечня поддерживаемых групп обмена
					ASSERT_EQ(extension::groups(item.data, groups), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень поддерживаемых групп не пуст
					ASSERT_FALSE(groups.empty()) << "приветствие " << i;
					// Проверяем, что первая предлагаемая группа обмена известна
					ASSERT_NE(extension::curve(groups[0]), nullptr) << "приветствие " << i;
					// Выполняем составление перечня поддерживаемых групп заново
					ASSERT_EQ(extension::groups(groups, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение поддерживаемых схем подписи
				case static_cast <uint16_t> (extension::type_t::SCHEMES): {
					// Разобранный перечень поддерживаемых схем подписи
					vector <extension::scheme_t> schemes;
					// Выполняем разбор перечня поддерживаемых схем подписи
					ASSERT_EQ(extension::schemes(item.data, schemes), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень поддерживаемых схем не пуст
					ASSERT_FALSE(schemes.empty()) << "приветствие " << i;
					// Проверяем, что первая предлагаемая схема подписи известна
					ASSERT_NE(extension::length(schemes[0]), static_cast <size_t> (0)) << "приветствие " << i;
					// Выполняем составление перечня поддерживаемых схем заново
					ASSERT_EQ(extension::schemes(schemes, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение открытой части ключа обмена
				case static_cast <uint16_t> (extension::type_t::SHARE): {
					// Если это расширение просьбы о повторе приветствия
					if(retry){
						// Разобранная выбранная сервером группа обмена ключами
						extension::group_t group = extension::group_t::NONE;
						// Выполняем разбор выбранной сервером группы обмена
						ASSERT_EQ(extension::selected(item.data, group), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что выбранная сервером группа обмена известна
						ASSERT_NE(extension::curve(group), nullptr) << "приветствие " << i;
						// Выполняем составление выбранной группы обмена заново
						ASSERT_EQ(extension::selected(group, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия клиента
					} else if(client){
						// Разобранный перечень открытых частей ключей обмена
						vector <extension::share_t> shares;
						// Выполняем разбор перечня открытых частей ключей обмена
						ASSERT_EQ(extension::shares(item.data, shares), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что перечень открытых частей ключей не пуст
						ASSERT_FALSE(shares.empty()) << "приветствие " << i;
						// Проверяем, что открытая часть ключа занимает две координаты кривой
						ASSERT_EQ(shares[0].key.size, (extension::length(static_cast <extension::scheme_t> (0x0709 + (static_cast <uint16_t> (shares[0].group) - 0x22))) * 2)) << "приветствие " << i;
						// Выполняем составление перечня открытых частей ключей заново
						ASSERT_EQ(extension::shares(shares, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия сервера
					} else {
						// Разобранная открытая часть ключа обмена сервера
						extension::share_t share;
						// Выполняем разбор открытой части ключа обмена сервера
						ASSERT_EQ(extension::share(item.data, share), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что группа обмена открытой части ключа известна
						ASSERT_NE(extension::curve(share.group), nullptr) << "приветствие " << i;
						// Выполняем составление открытой части ключа обмена заново
						ASSERT_EQ(extension::share(share, composed), extension::error_t::NONE) << "приветствие " << i;
					}
				} break;
				// Если это расширение способов обмена с заранее разделённым ключом
				case static_cast <uint16_t> (extension::type_t::MODES): {
					// Разобранный перечень способов обмена
					vector <extension::mode_t> modes;
					// Выполняем разбор перечня способов обмена
					ASSERT_EQ(extension::modes(item.data, modes), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень способов обмена не пуст
					ASSERT_FALSE(modes.empty()) << "приветствие " << i;
					// Выполняем составление перечня способов обмена заново
					ASSERT_EQ(extension::modes(modes, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение имени запрашиваемого узла
				case static_cast <uint16_t> (extension::type_t::NAME): {
					// Разобранное имя запрашиваемого узла
					view_t name;
					// Выполняем разбор имени запрашиваемого узла
					ASSERT_EQ(extension::name(item.data, name), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что имя запрашиваемого узла не пусто
					ASSERT_GT(name.size, static_cast <size_t> (0)) << "приветствие " << i;
					// Выполняем составление имени запрашиваемого узла заново
					ASSERT_EQ(extension::name(name, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если вид расширения этому набору проверок неизвестен
				default: continue;
			}
			// Проверяем схождение длины составленного тела расширения с исходным
			ASSERT_EQ(composed.size(), item.data.size) << "приветствие " << i << " расширение " << item.type;
			// Проверяем схождение составленного тела расширения с исходным
			ASSERT_EQ(::memcmp(composed.data(), item.data.data, composed.size()), 0) << "приветствие " << i << " расширение " << item.type;
			// Увеличиваем число разобранных тел расширений
			count++;
		}
	}
	// Проверяем, что разобранных тел расширений набралось достаточно
	ASSERT_GE(count, static_cast <size_t> (10));
}

/**
 * Проверка отказов разбора тел расширений
 */
TEST(ExtensionTest, Reject){
	// Разобранный перечень поддерживаемых групп обмена
	vector <extension::group_t> groups;
	// Тело расширения с перечнем, оборванным посреди группы
	const uint8_t broken[] = {0x00, 0x03, 0x00, 0x28, 0x00};
	// Проверяем отказ разбора перечня, оборванного посреди значения
	ASSERT_EQ(extension::groups(view_t(broken, sizeof(broken)), groups), extension::error_t::HUNGRY);
	// Тело расширения с пустым перечнем групп обмена
	const uint8_t empty[] = {0x00, 0x00};
	// Проверяем отказ разбора пустого перечня групп обмена
	ASSERT_EQ(extension::groups(view_t(empty, sizeof(empty)), groups), extension::error_t::EMPTY);
	// Тело расширения с лишними байтами за перечнем
	const uint8_t trailing[] = {0x00, 0x02, 0x00, 0x28, 0xFF};
	// Проверяем отказ разбора перечня с лишними байтами за ним
	ASSERT_EQ(extension::groups(view_t(trailing, sizeof(trailing)), groups), extension::error_t::TRAILING);
	// Тело расширения, объявившее длину перечня сверх своей области
	const uint8_t hungry[] = {0x00, 0x10, 0x00, 0x28};
	// Проверяем отказ разбора перечня, объявившего длину сверх области
	ASSERT_EQ(extension::groups(view_t(hungry, sizeof(hungry)), groups), extension::error_t::HUNGRY);
	// Накопитель, в который складывается составленное тело расширения
	vector <uint8_t> composed;
	// Проверяем отказ составления пустого перечня групп обмена
	ASSERT_EQ(extension::groups(groups, composed), extension::error_t::EMPTY);
	// Разобранное имя запрашиваемого узла
	view_t name;
	// Тело расширения с именем узла неизвестного вида
	const uint8_t foreign[] = {0x00, 0x06, 0x0A, 0x00, 0x03, 0x61, 0x62, 0x63};
	// Проверяем отказ разбора перечня без имени вида «host_name»
	ASSERT_EQ(extension::name(view_t(foreign, sizeof(foreign)), name), extension::error_t::EMPTY);
	// Проверяем отказ составления пустого имени запрашиваемого узла
	ASSERT_EQ(extension::name(view_t(nullptr, 0), composed), extension::error_t::EMPTY);
	// Разобранная метка возврата состояния сервера
	view_t cookie;
	// Проверяем отказ разбора пустой метки возврата состояния
	ASSERT_EQ(extension::cookie(view_t(empty, sizeof(empty)), cookie), extension::error_t::EMPTY);
	// Составляемая метка возврата состояния сервера
	const uint8_t sample[] = {0xDE, 0xAD, 0xBE, 0xEF};
	// Выполняем сброс накопителя составленного тела расширения
	composed.clear();
	// Выполняем составление метки возврата состояния сервера
	ASSERT_EQ(extension::cookie(view_t(sample, sizeof(sample)), composed), extension::error_t::NONE);
	// Выполняем разбор составленной метки возврата состояния
	ASSERT_EQ(extension::cookie(view_t(composed.data(), composed.size()), cookie), extension::error_t::NONE);
	// Проверяем схождение разобранной метки с составленной
	ASSERT_EQ(cookie.size, sizeof(sample));
	// Проверяем схождение содержимого разобранной метки с составленной
	ASSERT_EQ(::memcmp(cookie.data, sample, cookie.size), 0);
}

/**
 * Проверка разбора и составления предложения заранее разделённых ключей
 */
TEST(ExtensionTest, Identities){
	// Опознаватели предлагаемых заранее разделённых ключей
	const uint8_t first[4] = {0x01, 0x02, 0x03, 0x04}, second[3] = {0x0A, 0x0B, 0x0C};
	// Привязки предлагаемых заранее разделённых ключей
	uint8_t binder[32], element[32];
	// Выполняем заполнение привязки первого ключа
	::memset(binder, 0x11, sizeof(binder));
	// Выполняем заполнение привязки второго ключа
	::memset(element, 0x22, sizeof(element));
	// Составляемый перечень опознавателей ключей
	const vector <extension::identity_t> identities = {
		extension::identity_t(view_t(first, sizeof(first)), 0x01020304),
		extension::identity_t(view_t(second, sizeof(second)), 0x05060708)
	};
	// Составляемый перечень привязок ключей
	const vector <view_t> binders = {view_t(binder, sizeof(binder)), view_t(element, sizeof(element))};
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление предложения заранее разделённых ключей
	ASSERT_EQ(extension::identities(identities, binders, body), extension::error_t::NONE);
	// Разбираемый перечень опознавателей ключей
	vector <extension::identity_t> parsed;
	// Разбираемый перечень привязок ключей
	vector <view_t> items;
	// Длина усечения приветствия от начала тела расширения
	size_t truncation = 0;
	// Выполняем разбор составленного предложения ключей
	ASSERT_EQ(extension::identities(view_t(body.data(), body.size()), parsed, items, truncation), extension::error_t::NONE);
	// Проверяем число разобранных опознавателей ключей
	ASSERT_EQ(parsed.size(), static_cast <size_t> (2));
	// Проверяем число разобранных привязок ключей
	ASSERT_EQ(items.size(), static_cast <size_t> (2));
	/**
	 * Длина усечения отсчитывается до перечня привязок: за нею идут два байта длины
	 * перечня и сами привязки, длиною в байт и тридцать два байта всякая
	 */
	ASSERT_EQ(truncation, body.size() - (2 + (2 * (1 + 32))));
	// Проверяем длину первого разобранного опознавателя ключа
	ASSERT_EQ(parsed[0].identity.size, sizeof(first));
	// Проверяем схождение первого разобранного опознавателя с составленным
	ASSERT_EQ(::memcmp(parsed[0].identity.data, first, sizeof(first)), 0);
	// Проверяем скрытый возраст первого разобранного билета
	ASSERT_EQ(parsed[0].age, static_cast <uint32_t> (0x01020304));
	// Проверяем схождение второго разобранного опознавателя с составленным
	ASSERT_EQ(::memcmp(parsed[1].identity.data, second, sizeof(second)), 0);
	// Проверяем скрытый возраст второго разобранного билета
	ASSERT_EQ(parsed[1].age, static_cast <uint32_t> (0x05060708));
	// Проверяем схождение первой разобранной привязки с составленной
	ASSERT_EQ(::memcmp(items[0].data, binder, sizeof(binder)), 0);
	// Проверяем схождение второй разобранной привязки с составленной
	ASSERT_EQ(::memcmp(items[1].data, element, sizeof(element)), 0);
	// Проверяем отказ составления предложения с пустым перечнем ключей
	ASSERT_EQ(extension::identities(vector <extension::identity_t> (), binders, body), extension::error_t::EMPTY);
	// Проверяем отказ составления предложения без привязок ключей
	ASSERT_EQ(extension::identities(identities, vector <view_t> (), body), extension::error_t::EMPTY);
}

/**
 * Проверка разбора и составления выбранного сервером ключа
 */
TEST(ExtensionTest, Chosen){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление выбранного сервером ключа
	ASSERT_EQ(extension::chosen(static_cast <uint16_t> (1), body), extension::error_t::NONE);
	// Проверяем длину составленного тела расширения
	ASSERT_EQ(body.size(), static_cast <size_t> (2));
	// Место выбранного ключа в предложении клиента
	uint16_t chosen = 0;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::chosen(view_t(body.data(), body.size()), chosen), extension::error_t::NONE);
	// Проверяем разобранное место выбранного ключа
	ASSERT_EQ(chosen, static_cast <uint16_t> (1));
}

/**
 * Проверка разбора и составления перечня прикладных протоколов
 */
TEST(ExtensionTest, Protocols){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Перечень составляемых прикладных протоколов
	const vector <string> offer = {"h2", "http/1.1"};
	// Выполняем составление перечня прикладных протоколов
	ASSERT_EQ(extension::protocols(offer, body), extension::error_t::NONE);
	// Проверяем длину составленного тела расширения
	ASSERT_EQ(body.size(), static_cast <size_t> (2 + 1 + 2 + 1 + 8));
	// Проверяем длину перечня прикладных протоколов
	ASSERT_EQ(static_cast <size_t> ((body[0] << 8) | body[1]), body.size() - 2);
	// Перечень разобранных прикладных протоколов
	vector <string> protocols;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::protocols(view_t(body.data(), body.size()), protocols), extension::error_t::NONE);
	// Проверяем схождение разобранного перечня с составленным
	ASSERT_EQ(protocols, offer);
	// Проверяем отказ составления перечня из пустого набора протоколов
	ASSERT_EQ(extension::protocols(vector <string> (), body), extension::error_t::EMPTY);
	// Проверяем отказ составления перечня с пустым названием протокола
	ASSERT_EQ(extension::protocols(vector <string> (1, string()), body), extension::error_t::EMPTY);
	// Тело расширения с пустым названием прикладного протокола
	const uint8_t empty[3] = {0x00, 0x01, 0x00};
	// Выполняем сброс перечня разобранных прикладных протоколов
	protocols.clear();
	// Проверяем отказ разбора пустого названия прикладного протокола
	ASSERT_EQ(extension::protocols(view_t(empty, sizeof(empty)), protocols), extension::error_t::EMPTY);
	// Тело расширения, оборванное посреди названия протокола
	const uint8_t torn[4] = {0x00, 0x03, 0x04, 0x68};
	// Проверяем отказ разбора оборванного тела расширения
	ASSERT_EQ(extension::protocols(view_t(torn, sizeof(torn)), protocols), extension::error_t::HUNGRY);
}

/**
 * Проверка разбора и составления выбранного прикладного протокола
 */
TEST(ExtensionTest, Protocol){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление выбранного прикладного протокола
	ASSERT_EQ(extension::protocol(string("h2"), body), extension::error_t::NONE);
	// Название разобранного прикладного протокола
	string protocol;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::protocol(view_t(body.data(), body.size()), protocol), extension::error_t::NONE);
	// Проверяем схождение разобранного протокола с составленным
	ASSERT_EQ(protocol, "h2");
	// Проверяем отказ составления пустого названия протокола
	ASSERT_EQ(extension::protocol(string(), body), extension::error_t::EMPTY);
	// Выполняем сброс накопителя тела расширения
	body.clear();
	// Выполняем составление перечня из двух прикладных протоколов
	ASSERT_EQ(extension::protocols(vector <string> {"h2", "http/1.1"}, body), extension::error_t::NONE);
	/**
	 * Раздел 3.1 RFC 7301: ответом сервера идёт ровно один протокол, и перечень из
	 * двух в ответе - это уже не выбор
	 */
	ASSERT_EQ(extension::protocol(view_t(body.data(), body.size()), protocol), extension::error_t::LENGTH);
}
