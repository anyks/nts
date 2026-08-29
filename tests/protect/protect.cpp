/**
 * @file protect.cpp
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
 * @brief Исходный файл проверок модуля защиты записей протокола TLS 1.3
 *
 * @note Контрольные примеры взяты из приложения А описания наборов шифрования TLS 1.3
 *       на алгоритмах ГОСТ: пример первый ведёт связь набором на «Кузнечике» с частой
 *       сменой ключа записи, пример второй - набором на «Магме» с редкой сменой
 *
 * @note Порядковые номера записей в примерах выбраны так, чтобы застать смену ключа
 *       записи: у набора на «Кузнечике» она приходится на номер восемь, у набора на
 *       «Магме» - на номер сто двадцать восемь
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
#include <protect/protect.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Описание контрольного примера защиты записи
 */
static const struct Sample {
	// Набор шифрования контрольного примера
	protect::suite_t suite;
	// Корневой ключ направления связи
	const char * key;
	// Вектор замены направления связи
	const char * vector;
	// Порядковый номер защищаемой записи
	uint64_t sequence;
	// Ключ записи, выработанный построением TLSTREE
	const char * derived;
	// Истинный вид содержимого защищаемой записи
	uint8_t type;
	// Открытое содержимое защищаемой записи
	const char * content;
	// Защищённая запись целиком
	const char * record;
} SAMPLES[] = {
	{protect::suite_t::KUZNYECHIK_MGM_S, "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01", "6969FFAAA4525281EEBBEB4CBD0B640E", 0ULL, "56EE1813727249C9DCDF3513787EDB93DF62C61EE7B126C50F26C0AAAFAE00E1", 0x16, "080000020000", "1703030017940E5D2C753AE5FEBD20012CC9E3EB24A379841E02ABBE"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01", "6969FFAAA4525281EEBBEB4CBD0B640E", 1ULL, "56EE1813727249C9DCDF3513787EDB93DF62C61EE7B126C50F26C0AAAFAE00E1", 0x16, "0B0001510000014D000148308201443081F2A00302010202023039300A06082A85030701010302301B3119301706035504031310676F73742E6578616D706C652E636F6D301E170D3230303232383131303833375A170D3330303232353131303833375A301B3119301706035504031310676F73742E6578616D706C652E636F6D305E301706082A85030701010101300B06092A85030701020101020343000440F383CEE83048B4EB14C71A7F6DE44A37CE11A6AC1750F1CFB8DAD8A38CCDD8FD06656F7CFC075F4083C3716221478F1EE24C6B1B70CCE3C72AFD2ACE65C775BCA321301F301D0603551D0E04160414F330FA7166DF095AF3A073BC3B8EA356D7DFAC71300A06082A85030701010302034100AB2EDA23F49B48623B0CFF5906B7DD3C23B473570B296A0871DD15EF9A33201B97904A5CFA6C931C5473DC0C5A5F2FBB2E50CF587AE27C4D8E52EB80189DD08B0000", "1703030166F57944FE9A599A76E7FE9C26E3FCE5BBAC4DDCF68EF2E77624E33E80B6743E3910502EE419A219B3BB6A1712D15458BB897D3DAC7A48769945C89237DFB86620CC31C456B4374B075905E42AB53337423463819982DC6D76A067C4FD83BD3E479CD9B7FD2926A5A63B1E88B1525DB976C7F409190F955AE9F0AC5F976A471F23675DEB9B24E162D24F494ECDC483A0707129F3BD17D0FAC4944F2B3BF140D616D654709297495B23898893B211505856EEC1A96BC4DCF78A016798E5500D662C54A74BDF6A7F300AC9B72299B4F15F6F449F396CE1D0C9243CBC1C86BECD5CABBFDF50197B7AFF4BE903D7E3311B729BC32D09D2D0DCE06622985AE037DC2F87CB0C492F2D5106B259CC86E227CC8338C1DF6C63576B17DB9655FD255F156E1F4F767FAFB74471731E4225256818DE9464218263D7CF7B87EB5222E76DE6C951E462CCCCC53E06387BB4FEDEFD34B9C13AB4EE3D49057CD2672F852A5F69240829B92341CDC9"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01", "6969FFAAA4525281EEBBEB4CBD0B640E", 2ULL, "56EE1813727249C9DCDF3513787EDB93DF62C61EE7B126C50F26C0AAAFAE00E1", 0x16, "0F000044070A0040A0AA13915C5B80C602E2FD85804F992C771597AD37857AD6BC2A9D7BC5FEBEC37C7294BAA23CF69D03E4710BD70813FDAC596BC158E756BD371C442E9522DE87", "170303005952631D5BFDF48254BDFB5F9E02A6A5270163BCE1E0D818E8D74176535C6CDD252DE065AE77984A65ADBA036D59CF45B9A0047BABCCD0B28044D34BCFD09E6E4627044B26FE5CA734FCB08607146F41A871C3F95384B48ADABC"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01", "6969FFAAA4525281EEBBEB4CBD0B640E", 3ULL, "56EE1813727249C9DCDF3513787EDB93DF62C61EE7B126C50F26C0AAAFAE00E1", 0x16, "14000020E0BAA33614E069697E4DFAB071B9725773F8FE1A326A662D0F52309B45B6E031", "170303003557B1706C4918F67EACCA457F7D5B537CCE5036B4004C778022B97EE802320398119404506680ADD7D6A6CD7C8153B7553C6E646AD6"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C", "AFE91F7118354026317E1AB4D82217B8", 0ULL, "C8FC93D7C586F2B0A3101BAA6A979E4E3886706551E81187E97880409C7E8EE9", 0x17, "48454C4F20676F73742E6578616D706C652E636F6D0D0A", "1703030028ABB8C372C79681DCE5C3C909DD039D598161FD3E6CE5D6F9CA5715BD6B5C18247FB26AC1AB396A4E"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "581688D76EFE122BB55F62B38EF01BCC8C88DB83E9EA4D55D3898C53721FC384", "439A07453D0BEA0C1D1BEB738EB5B8DD", 0ULL, "E1C59B4169D896107F78456893A3751E1573543DAD8CB74069E6814A513BBB1C", 0x16, "14000020085FC7FD79B6D111CD8D3FF6B23A065A7AF7A6387342A5F3576814CD004719D2", "1703030035C9C65EAAB4A80E04849A122EB0CC26A9CA6B5DD4DB7AD6813949F629FC09E0522FF7ACDBBA93926C20008B8CCE8654227B31D439F8"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C", "AFE91F7118354026317E1AB4D82217B8", 1ULL, "C8FC93D7C586F2B0A3101BAA6A979E4E3886706551E81187E97880409C7E8EE9", 0x16, "0400003500093A8086868686080000000000000000002088888888888888888888888888888888888888888888888888888888888888880000", "170303004ACA6688A5DC22208DC8A8DE7E597292E3CB5D454945B8F06C7C50F1823D7B6BB0021178AE3ADB2DE3994539FD696945CFAA6919F3F1294CD41ED2A8EA75302869ACB994F3920B09D67186"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C", "AFE91F7118354026317E1AB4D82217B8", 10ULL, "D3CD87D5687407823978344C06B928A85898B739A31D3DE5FF2B788EF39196ED", 0x15, "0100", "17030300137CBC00AD5D29E301739394D31942C6A16658E9"},
	{protect::suite_t::KUZNYECHIK_MGM_S, "7BE64E2C12787B5B8C8756C43D92FAEF64F15A3A3C1081AD34BCA506F0322415", "310957EF71314433F576CC9B00AD9354", 10ULL, "B82D7825D15FAE18A7013228B31CB0C59752C6409C5F7899ECC6950F7463C090", 0x15, "0100", "1703030013CB19F306C3641754BE4FC95390DF06F9CD44AA"},
	{protect::suite_t::MAGMA_MGM_L, "DB619B58F4411E334F07EAC77CEFEFCA7841F54088B8D0D5CE6A62C98285C681", "FC9E2AC66304C25B", 0ULL, "3C7DF35EACF4FE71EA6ADCE0DC445DD3A929EFCD083F182FBD5142BA686D3884", 0x16, "080000020000", "170303000F4967A7E1AE7BFB375A0F4B25459117"},
	{protect::suite_t::MAGMA_MGM_L, "DB619B58F4411E334F07EAC77CEFEFCA7841F54088B8D0D5CE6A62C98285C681", "FC9E2AC66304C25B", 1ULL, "3C7DF35EACF4FE71EA6ADCE0DC445DD3A929EFCD083F182FBD5142BA686D3884", 0x16, "1400002096145B6168E01C4CF2995096EE12C86B1F531F960A489DE9C3442A2433E9AEEE", "170303002D3BFB2AEADBC349FD89AFB8E481F8426BCC6B7F5D975FE05E5B28755C00BF353FCA6A48E9F0145993C40CE06F37"},
	{protect::suite_t::MAGMA_MGM_L, "DF66601EDDD64E961DFC7DD0212EF225C00533E6DAA4AD24185EBEB224B546B8", "E8943C9FA28856A1", 0ULL, "BD009FFC04A0529E6078EBA5A07ADE74937FF3A1AB75F7AE05190478519B6DF3", 0x16, "14000020BB830994BE38A98FFCA3BFD235CD807E81821E6737AB983143DCA97B9EE02325", "170303002D14254CA6B9EBCC4A951A3D1F1040B0B145446DF131946CEECBDB6A8EC534F194223281B56532A703C492160E2C"},
	{protect::suite_t::MAGMA_MGM_L, "15D92C5147B21310EDEDF55B3D7AB776817D6FE2FCF230D7E3F29275F6E241EC", "712E2F11CD506EB9", 130ULL, "93D5D6E1036FDFB3EFBF31E6DA5EECE685171C977FF9CD6C3A3F67C0224AB6EB", 0x15, "0100", "170303000B447A3FAE8F86C135189B10"},
	{protect::suite_t::MAGMA_MGM_L, "EBD271DE19FEE18BB1998F69AF5B6AE18958E8D3702F12FBB5B03F6FD691FEFA", "18FB038DBF7241E6", 0ULL, "862A74180B4AE4C2D15F4A62ED8A4A75B08D72B046AFDECB3A8EF0C267F456BD", 0x15, "0100", "170303000B464AEEAD391D97987169F3"}
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
 * Проверка выработки ключа записи построением TLSTREE
 */
TEST(ProtectTest, Tree){
	/**
	 * Выполняем перебор контрольных примеров защиты записи
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Получаем корневой ключ направления связи
		const vector <uint8_t> key = decode(SAMPLES[i].key);
		// Получаем ожидаемый ключ записи контрольного примера
		const vector <uint8_t> sample = decode(SAMPLES[i].derived);
		// Место, в которое помещается выработанный ключ записи
		uint8_t result[protect::PROTECT_KEY];
		// Выполняем выработку ключа записи построением TLSTREE
		ASSERT_TRUE(protect::tree(SAMPLES[i].suite, view_t(key.data(), key.size()), SAMPLES[i].sequence, result)) << "пример " << i;
		// Проверяем схождение выработанного ключа записи с контрольным примером
		ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0) << "пример " << i;
	}
}

/**
 * Проверка наложения защиты на запись
 */
TEST(ProtectTest, Seal){
	/**
	 * Выполняем перебор контрольных примеров защиты записи
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Объект защиты записей одного направления связи
		protect::protection_t protection;
		// Получаем корневой ключ направления связи
		const vector <uint8_t> key = decode(SAMPLES[i].key);
		// Получаем вектор замены направления связи
		const vector <uint8_t> vector = decode(SAMPLES[i].vector);
		// Выполняем установку ключевого материала направления связи
		ASSERT_TRUE(protection.start(SAMPLES[i].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size()))) << "пример " << i;
		// Открытое содержимое защищаемой записи
		const std::vector <uint8_t> content = decode(SAMPLES[i].content);
		// Накопитель, в который складываются защищённые записи
		std::vector <uint8_t> result;
		/**
		 * Выполняем защиту записей до порядкового номера контрольного примера
		 */
		while(protection.sequence() < SAMPLES[i].sequence){
			// Выполняем сброс накопителя защищённых записей
			result.clear();
			// Выполняем наложение защиты на пропускаемую запись
			ASSERT_EQ(protection.seal(record::type_t::APPLICATION, view_t(content.data(), content.size()), result), protect::error_t::NONE) << "пример " << i;
		}
		// Выполняем сброс накопителя защищённых записей
		result.clear();
		// Выполняем наложение защиты на запись контрольного примера
		ASSERT_EQ(protection.seal(static_cast <record::type_t> (SAMPLES[i].type), view_t(content.data(), content.size()), result), protect::error_t::NONE) << "пример " << i;
		// Получаем защищённую запись контрольного примера
		const std::vector <uint8_t> sample = decode(SAMPLES[i].record);
		// Проверяем схождение длины защищённой записи с контрольным примером
		ASSERT_EQ(result.size(), sample.size()) << "пример " << i;
		// Проверяем схождение защищённой записи с контрольным примером
		ASSERT_EQ(result, sample) << "пример " << i;
		// Проверяем рост порядкового номера записи
		ASSERT_EQ(protection.sequence(), (SAMPLES[i].sequence + 1)) << "пример " << i;
	}
}

/**
 * Проверка снятия защиты с записи
 */
TEST(ProtectTest, Open){
	/**
	 * Выполняем перебор контрольных примеров защиты записи
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Объект защиты записей одного направления связи
		protect::protection_t protection;
		// Получаем корневой ключ направления связи
		const std::vector <uint8_t> key = decode(SAMPLES[i].key);
		// Получаем вектор замены направления связи
		const std::vector <uint8_t> vector = decode(SAMPLES[i].vector);
		// Выполняем установку ключевого материала направления связи
		ASSERT_TRUE(protection.start(SAMPLES[i].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size()))) << "пример " << i;
		// Открытое содержимое защищаемой записи
		const std::vector <uint8_t> content = decode(SAMPLES[i].content);
		// Накопитель, в который складываются записи
		std::vector <uint8_t> result;
		/**
		 * Выполняем пропуск записей до порядкового номера контрольного примера
		 */
		while(protection.sequence() < SAMPLES[i].sequence){
			// Выполняем сброс накопителя записей
			result.clear();
			// Выполняем наложение защиты на пропускаемую запись
			ASSERT_EQ(protection.seal(record::type_t::APPLICATION, view_t(content.data(), content.size()), result), protect::error_t::NONE) << "пример " << i;
		}
		// Получаем защищённую запись контрольного примера
		const std::vector <uint8_t> sample = decode(SAMPLES[i].record);
		// Объект сборщика входящих записей
		record::reader_t reader;
		// Выполняем подачу защищённой записи сборщику
		ASSERT_EQ(reader.push(view_t(sample.data(), sample.size())), record::error_t::NONE) << "пример " << i;
		// Заголовок принятой защищённой записи
		record::header_t header;
		// Содержимое принятой защищённой записи
		view_t payload;
		// Выполняем сборку принятой защищённой записи
		ASSERT_EQ(reader.next(header, payload), record::error_t::NONE) << "пример " << i;
		// Истинный вид содержимого принятой записи
		record::type_t type = record::type_t::NONE;
		// Выполняем сброс накопителя записей
		result.clear();
		// Выполняем снятие защиты с принятой записи
		ASSERT_EQ(protection.open(header, payload, type, result), protect::error_t::NONE) << "пример " << i;
		// Проверяем схождение истинного вида содержимого с контрольным примером
		ASSERT_EQ(static_cast <uint8_t> (type), SAMPLES[i].type) << "пример " << i;
		// Проверяем схождение открытого содержимого с контрольным примером
		ASSERT_EQ(result, content) << "пример " << i;
	}
}

/**
 * Проверка дополнения, скрывающего истинную длину содержимого
 */
TEST(ProtectTest, Padding){
	// Объект защиты записей отправляющей стороны
	protect::protection_t sender;
	// Объект защиты записей принимающей стороны
	protect::protection_t receiver;
	// Получаем корневой ключ направления связи
	const std::vector <uint8_t> key = decode(SAMPLES[0].key);
	// Получаем вектор замены направления связи
	const std::vector <uint8_t> vector = decode(SAMPLES[0].vector);
	// Выполняем установку ключевого материала отправляющей стороны
	ASSERT_TRUE(sender.start(SAMPLES[0].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size())));
	// Выполняем установку ключевого материала принимающей стороны
	ASSERT_TRUE(receiver.start(SAMPLES[0].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size())));
	// Защищаемое содержимое записи, оканчивающееся нулями
	const std::vector <uint8_t> content = {0x01, 0x02, 0x00, 0x00};
	// Накопитель, в который складывается защищённая запись
	std::vector <uint8_t> sealed;
	// Выполняем наложение защиты на запись с дополнением
	ASSERT_EQ(sender.seal(record::type_t::HANDSHAKE, view_t(content.data(), content.size()), sealed, 7), protect::error_t::NONE);
	// Проверяем, что дополнение вошло в длину защищённой записи
	ASSERT_EQ(sealed.size(), (record::RECORD_HEADER + content.size() + 1 + 7 + protect::block(SAMPLES[0].suite)));
	// Объект сборщика входящих записей
	record::reader_t reader;
	// Выполняем подачу защищённой записи сборщику
	ASSERT_EQ(reader.push(view_t(sealed.data(), sealed.size())), record::error_t::NONE);
	// Заголовок принятой защищённой записи
	record::header_t header;
	// Содержимое принятой защищённой записи
	view_t payload;
	// Выполняем сборку принятой защищённой записи
	ASSERT_EQ(reader.next(header, payload), record::error_t::NONE);
	// Истинный вид содержимого принятой записи
	record::type_t type = record::type_t::NONE;
	// Накопитель, в который складывается открытое содержимое записи
	std::vector <uint8_t> opened;
	// Выполняем снятие защиты с принятой записи
	ASSERT_EQ(receiver.open(header, payload, type, opened), protect::error_t::NONE);
	// Проверяем схождение истинного вида содержимого с наложенным
	ASSERT_EQ(type, record::type_t::HANDSHAKE);
	// Проверяем схождение открытого содержимого с защищённым вместе с его нулями
	ASSERT_EQ(opened, content);
}

/**
 * Проверка отказов защиты записей
 */
TEST(ProtectTest, Reject){
	// Объект защиты записей одного направления связи
	protect::protection_t protection;
	// Защищаемое содержимое записи
	const std::vector <uint8_t> content = {0x01, 0x02, 0x03};
	// Накопитель, в который складывается защищённая запись
	std::vector <uint8_t> sealed;
	// Проверяем отказ наложения защиты без ключевого материала
	ASSERT_EQ(protection.seal(record::type_t::HANDSHAKE, view_t(content.data(), content.size()), sealed), protect::error_t::STATE);
	// Получаем корневой ключ направления связи
	const std::vector <uint8_t> key = decode(SAMPLES[0].key);
	// Получаем вектор замены направления связи
	const std::vector <uint8_t> vector = decode(SAMPLES[0].vector);
	// Проверяем отказ установки ключевого материала неизвестного набора шифрования
	ASSERT_FALSE(protection.start(protect::suite_t::NONE, view_t(key.data(), key.size()), view_t(vector.data(), vector.size())));
	// Проверяем отказ установки ключевого материала с укороченным вектором замены
	ASSERT_FALSE(protection.start(SAMPLES[0].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size() - 1)));
	// Выполняем установку ключевого материала направления связи
	ASSERT_TRUE(protection.start(SAMPLES[0].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size())));
	// Проверяем отказ наложения защиты с неизвестным видом содержимого
	ASSERT_EQ(protection.seal(record::type_t::NONE, view_t(content.data(), content.size()), sealed), protect::error_t::TYPE);
	// Выполняем наложение защиты на запись
	ASSERT_EQ(protection.seal(record::type_t::HANDSHAKE, view_t(content.data(), content.size()), sealed), protect::error_t::NONE);
	// Объект защиты записей принимающей стороны
	protect::protection_t receiver;
	// Выполняем установку ключевого материала принимающей стороны
	ASSERT_TRUE(receiver.start(SAMPLES[0].suite, view_t(key.data(), key.size()), view_t(vector.data(), vector.size())));
	// Заголовок принятой защищённой записи
	record::header_t header;
	// Устанавливаем вид содержимого принятой защищённой записи
	header.type = record::type_t::APPLICATION;
	// Устанавливаем версию протокола принятой защищённой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого принятой защищённой записи
	header.size = (sealed.size() - record::RECORD_HEADER);
	// Истинный вид содержимого принятой записи
	record::type_t type = record::type_t::NONE;
	// Накопитель, в который складывается открытое содержимое записи
	std::vector <uint8_t> opened;
	// Портим последний байт метки целостности принятой записи
	sealed[sealed.size() - 1] = static_cast <uint8_t> (sealed[sealed.size() - 1] ^ 0x01);
	// Проверяем отказ снятия защиты с испорченной меткой целостности
	ASSERT_EQ(receiver.open(header, view_t(sealed.data() + record::RECORD_HEADER, header.size), type, opened), protect::error_t::TAG);
	// Проверяем, что отказ снятия защиты порядкового номера записи не сдвинул
	ASSERT_EQ(receiver.sequence(), static_cast <uint64_t> (0));
	// Проверяем, что открытое содержимое в накопитель не попало
	ASSERT_TRUE(opened.empty());
	// Возвращаем испорченный байт метки целостности на место
	sealed[sealed.size() - 1] = static_cast <uint8_t> (sealed[sealed.size() - 1] ^ 0x01);
	// Портим последний байт связанных данных принятой записи
	header.size++;
	// Проверяем отказ снятия защиты с расходящейся длиной содержимого
	ASSERT_EQ(receiver.open(header, view_t(sealed.data() + record::RECORD_HEADER, header.size - 1), type, opened), protect::error_t::LENGTH);
	// Возвращаем длину содержимого принятой записи на место
	header.size--;
	// Выдаём защищённую запись за запись рукопожатия
	header.type = record::type_t::HANDSHAKE;
	// Проверяем отказ снятия защиты с записи неположенного вида содержимого
	ASSERT_EQ(receiver.open(header, view_t(sealed.data() + record::RECORD_HEADER, header.size), type, opened), protect::error_t::TYPE);
}
