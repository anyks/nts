/**
 * @file integer.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля многоразрядных целых чисел
 *
 * @note Ожидаемые значения вычислены в python3 на числах, выведенных из хешей
 *       SHA-512 строк «a0», «b0» и так далее; простые числа выработаны командой
 *       openssl prime -generate, а их простота и составность соседей подтверждена
 *       командой openssl prime -hex. Все числа закреплены строками
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstring>
#include <main.hpp>
#include <math/integer.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
 *
 * @return     число разобранных байтов
 *
 */
static size_t bytes(const char * text, uint8_t * data) {
	// Число разобранных байтов
	size_t result = 0;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		data[result++] = value;
	}
	// Выводим число разобранных байтов
	return result;
}
/**
 * @brief Метод разбора числа из записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 *
 * @return     разобранное число
 *
 */
static math::integer_t number(const char * text) {
	// Место, в которое помещаются разобранные байты
	uint8_t buffer[math::INTEGER_SIZE];
	// Разобранное число
	math::integer_t result;
	// Выполняем разбор числа
	EXPECT_TRUE(result.load(view_t(buffer, bytes(text, buffer))));
	// Выводим разобранное число
	return result;
}
/**
 * @brief Метод сборки записи числа шестнадцатеричными знаками
 *
 * @param value собираемое число
 *
 * @return      собранная запись без ведущих нулей, «00» у нуля
 *
 */
static std::string text(const math::integer_t & value) {
	// Байты числа
	uint8_t buffer[math::INTEGER_SIZE];
	// Размер числа: у нуля один байт
	const size_t size = ((value.size() > 0) ? value.size() : 1);
	// Выполняем запись числа
	EXPECT_TRUE(value.store(buffer, size));
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов числа
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(buffer[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[buffer[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}

/**
 * Первое число проверки длиной 2000 разрядов
 */
static const char * FIRST =
	"560d7e456bf26693ff108e431c11bae29f8a6a65116ff22d5c9d9223d0a7fb4a4b6fe7ab027627b064db56c7107fef6c"
	"2085a271a1d9cde33cc131437f49da374f2430a7ae267fd4f37ed3f20b8c677c59dee284d45d1b062751c421c9d5e41e"
	"3e666848d2781a594a38caa60ea6323dc9f723ed49906f8dc57ebe9c9d66339c8f147362a08f8946902188aa7e24ddd2"
	"839c3d85e2c4956ac13f1cf9842cdb924ae07fb7b40bd291c46125f7199acf0ce8b2c3065ec85a70e2cdc8b340997bc5"
	"493090c578a275fbcca622915f9c4ed820da1de0f03cacab6329ced71b069287777046856ae09141595a3c9406ff5dc6"
	"90f77acf5e3194d30cdc";

/**
 * Второе число проверки длиной 1500 разрядов
 */
static const char * SECOND =
	"011e1319d50ce81f3fcdd5b98aca530de93a163d17fa863a0c8dcde71bc7b86b6d0c01e2f8b9a6c0a3bab516ebdcc15d"
	"ab46dfea502443cc0263938eb778e2cca3d7e851b031e23173b21f97b5d149d46b293d6d90182ed5eb615472c0310339"
	"8cc40e1ae5f07f623e0c61fd0fa591178cff1c90579587a9de7c7876fccabee66ea2622898bce0c10b8f21de6fa00d09"
	"6627d67ca298c649bd41f7e168a9a3dc82af330afbfea68bd8ff96e16875282990cc630004bff1e7afa29913";

/**
 * Третье число проверки длиной 4000 разрядов
 */
static const char * THIRD =
	"9ac34e85c12862e1fb7995667adca8593549c502e54be9c6b5a42f0e80f6a2aa3e95ecc82aea8d356bb787e2ff7e302a"
	"e0adb40c80e18dda9acedd64282b1d6ebcfe21e6280bf11b8fdbd045c8b3e527748d1ecf18d1c44a9be6cd054107c447"
	"988d086514f6d59be950c5fc729e88f66d58c0e57440493b08b09b32f21f073ba3bd3516b9cfa9a9a081db2d6a9aca82"
	"ff3bef0e8e10b104c13c7acf1ff1d39e8d09b63b6804adf09a7dd42efcb924b09e88a3a2d1c7c2bf6954bddbe251f0a9"
	"97bebef2596741207d7018bc1a71b161b13e75799b9a9ea70273e6e1a70172a9417114c972c129c3825223bf05639deb"
	"40faec322a21acfd5ab625136a76007ade59625cb0c748fa16ca4984a6ece929fc3b8d5cec4b449e75d1539344b6d746"
	"f8ec01c02b54af49de503b903879bcf831c8834955e84e0be20417cfeaf43766266d55af28c2cb6e858a9c2ef275731b"
	"438136f33cf72edc731c454df16d05c7cc0139475fa48608b1796a8214c2cc3cf7141dc71a0680f7a3f85168e9cdd890"
	"7cf07de175e7846ae9d2f4affcf12eff8ef653dc66ce2c1b05b92f71190cb01593ac6d578e25c0df792d31e270dbe2df"
	"36ea3754e306ad63e7fa8125a5aa2ed01350b84e31671503b8dfd7159bc2f56554867a806aaf377ba693ad99990e7708"
	"9bda6b3fda0b6025339d55c31ce4150162ba4347";

/**
 * Четвёртое число проверки длиной 3000 разрядов
 */
static const char * FOURTH =
	"8a535d5f2f052d68e8fbd166dda20555835fd7e39bd03f2d65ba657c7f9c61e76042a4038b8a6afaf91aaaf801d71d11"
	"8176cd710e1694e37de7142afc7ed3027ae67b25bc5d93c6de53216001b0426b7c8f37a10170201b694ca511279f9b0b"
	"c6b4c72a070de1440757e380ac7a54af7a62d66f01937431177773e72a5e967dcf3a25726887ffddb20a544c64c5bc48"
	"07a03a47ef79c03c195a9f46c036263a91f15193934371372f08f8f0cda83b5a7f5ab7666fd93ec1d81d2a40c5ebf837"
	"eaddf5edcc5994d3b3e9d790d2061619c31a80471a38b1632da328cd6e74a42ea68b18755cab97b36ca3fa117bb5fb19"
	"9dff93764ea4f5e771bd3617030a31ca315457d5e4a0b5dc2e185520757dfb4643e7fae450d0e99b922535b4e9bd8e68"
	"af40ca76e1de661363545cd54140ed0cd0fcaf04715a59b24412c0b5bba003c2a7fae1c57c697fbc247faa1a83807fc0"
	"bc2889fdcb9af77ce9d9abb385e2911f544a998b23cb57550e552c5c4ce7fa1ddeabcb2a9bc100";

/**
 * Сумма первого и второго чисел
 */
static const char * SUM =
	"560d7e456bf26693ff108e431c11bae29f8a6a65116ff22d5c9d9223d0a7fb4a4b6fe7ab027627b064db56c7107fef6c"
	"2085a271a1d9cde33cc131437f49db55623e05b49645bfa2c9385ebc5e9a50b6701bfa7f5a972793f538dfe98241512a"
	"404961027938be13ff4fb682d003dd84a9e174118d5c71f1590d76158032d7747766239482c0fcf8afb93e7bc7f948fb"
	"c109cd9e119a80cc15b1dd2a8766685658fb65a8336e109e265e359caab25c0c05431a9be67238ed5b44c57dff7fea67"
	"ab5929825963818aee8492316ca5b4fff756c079b68669ed5b0b3780bee31536aa7b4284116c6a40f03ba5092f28ee92"
	"f3f77f8f50194475a5ef";

/**
 * Разность первого и второго чисел
 */
static const char * DIFFERENCE =
	"560d7e456bf26693ff108e431c11bae29f8a6a65116ff22d5c9d9223d0a7fb4a4b6fe7ab027627b064db56c7107fef6c"
	"2085a271a1d9cde33cc131437f49d9193c0a5b9ac60740071dc54927b87e7e4243a1ca8a4e230e78596aa85a116a7712"
	"3c836f8f2bb7769e9521dec94d4886f6ea0cd3c905c46d2a31f00723ba998fc4a6c2c330be5e15947089d2d9345072a9"
	"462ead6db3eeaa096ccc5cc880f34ece3cc599c734a99485626416518883420dcc226b70d71e7bf46a56cbe881b30d22"
	"e707f80897e16a6caac7b2f15292e8b04a5d7b4829f2ef696b48662d772a0fd844654a86c454b841c278d41eded5ccfa"
	"2df7760f6c49e53073c9";

/**
 * Произведение первого и второго чисел
 */
static const char * PRODUCT =
	"60297ec0dca5518b356a8b8f3ee5a19b01957c512072033c39800d9b743a5af5e7c4481fa490fa5b1aaf443ce0f9cd73"
	"e5255cc39fd2428200a08e7a96ace5b0f18f2cbdc4d29f38dc4346e4adcff55e79dd713a1e233717bc023a6755ca7646"
	"9e7922624f3343ce7ee27725638126dec4b4c0b991053174d55347ceb896a129925f104ef8c7803b29b000f9fd36ee96"
	"a7a37c382dcfe5273a5a86bbc16320f1df6325ed08cc86dfb9d2a1616f93cd54af3d331254df98cb5043dd37d11c7ae9"
	"00c93c9321c1672ac6631c55b83d0f437ab857cde8e91983d939d95ef395a379e5b3f26377efd05d86d2323024d243c5"
	"252d113868bee436384b56ed885b94a8a30474f41bfc736092add149c9eec9a18cc12abc378ca8d0a452a03afccca6bf"
	"5c11efde20c8631eaf6515d2a5ad4183533ffb337293d9793849d07bebc1264a0183c01edff485a0fd460993aab3f0dd"
	"e92eeca9c86c3ea4f50fbcaa98b4fc12d0d1266d5d02dfe821dc30dc8bb6f8b389edbd69e31c9351588f9501f55e8c7f"
	"96ba9d86451eeb18a1eaf09ae54dfadf813bef286f8edab353393cf48d4f8f0d21f87ce270be16cc113f5538e38e7bc9"
	"7cb5917054";

/**
 * Частное от деления третьего числа на четвёртое
 */
static const char * QUOTIENT =
	"011e6ba916de28568ee1286c4ae3e385de46ebcfe8e81567567f5aaaa1815169d37d3437cd1326904100a03241ed5a5b"
	"478cc11bad62aa796698f4528619bb6dd5e5b0c038f44907252d4ec3d937da279dbb93283f7cd982aac919fad7b7bccf"
	"32f2e281d9c071c34e3c3499a98d0755111334993727775433ba402299ab";

/**
 * Остаток от деления третьего числа на четвёртое
 */
static const char * REMAINDER =
	"22636e73555b34a68b938ea30787d3cb457ca39d58ac3e0407210d0ea0bdcf87bda16e1ef8b2a4e233264921241c1a9f"
	"8b6894701061f6d55b27278e2080ba221cc8f8e5b5305a462d49642863304aecba10ad735bdd430586bdb44171a8e50c"
	"5f53b710fee564182c7790498469c26ad644907668aab57f3d76d9a23baa55468902955829b0a937ef4d05f20f4a95f0"
	"82d192cfc996e0ad50aaa72f4dfa0d643f93675056834887cdbf7eaa883a492da181562697d4002b7a679b85cd1e0722"
	"b6226bd4489ccfd388272371a894790ddc4191b990f93009413c1e58658aad3717adf82468a0f15cc51eb5dc15f90e25"
	"44a7ae89884e3fd9a9f98fa88ff0bb86ae2597e139b97ae082cb992f3ac4fc7a9b8f6dc84b8a6c83f75eee6d3316d4d2"
	"16c6fb040ed5fdbea332f4caf09b344e3891d12bb7ab839af67becee456be4c8f7adcf0a5eb1f84072d3744432d043fc"
	"efc1f9328c6b65fb6383e25a52b1ead71e86dcf1d9a7cc62448e26123e2f65283b14e534575847";

/**
 * Частное от деления третьего числа на второе
 */
static const char * WIDE_QUOTIENT =
	"8a7e2f9a881d9f9e430a4c2882dfe4612da7bad29773d83244fa3903c8f818a1c95ac5ef618f18fd1726d11271a26dfa"
	"20b932a11feba6249bf70308782ac88f79c65cc229344e0aacb01d277aa138778976c88e7bfdc11857a28ea324401cd9"
	"b638e642fdf872c094ce29319ea086231af44b213ef7b8cf63f5ecbf404c201985f08d51ead4bc8f460f2e3f72bc94bd"
	"2ce0c478f2806f0013b1b5b9f9011e334258df8782db4265960a1ffddd54faa0119028a0ac2aa894bd35dc51933b2b21"
	"8a1e84f801d03be97b3d7547c072ca87f6bb1fa9feaa16b23647c10224b1d0e56bdb8c09a6c0b75c61b24c5750f77654"
	"b57abe80d185e1277521d92ec7034d2899500a65b3e967ee4e9281cf610778d304c2e8ea2c8443bd61b699e32990800e"
	"5623bea826b11588dc360cbb8b8e34d973cddab8f6ca0d4f0e";

/**
 * Остаток от деления третьего числа на второе
 */
static const char * WIDE_REMAINDER =
	"d85e0002fbec96271c2f355d6ba88718c948314b88712e2984089d65bd3b4a211152869b805b96742e8bb42778dab872"
	"eacd9b984d686e7e4220c9fcb09a1f0f38858204ffe07965f40b6df591a2e9d496ad3ed20bb25d2f921487b43e88ad20"
	"2fe04934afba8dcddd08489db3edf0d51bab734f388cbf697a350597d667428ef6088399f4e381ea9b67530143df6dec"
	"07a848acb2b297531b4bcfd869a39b46797134226f3606d9d5bc2af9bee8e2c23999384ff162d5d6a2073d";

/**
 * Простое число длиной 1024 разряда, выработанное openssl prime -generate
 */
static const char * PRIME1024 =
	"cb76c2948bec0ea2536046ed685862a52ac3a01d6a14784162a631bf78fe2aa08a5d0d8990caee2e8d441abc2d851cba"
	"b31998845467b590610fb17a5368746ec591dc8e1e5e8ec4c610d815c5e6077fb9e827fe2eda115ec7ed59d7a72d60e2"
	"b2d3f839ffee5a2928a584afbbbc4b2a28d38b3dfac0e6b7f36609fb2aec9c35";

/**
 * Простое число длиной 512 разрядов, выработанное openssl prime -generate
 */
static const char * PRIME512 =
	"e702b8fe29f8525f71ee0f8761333f0ba068be6fe5951b119b72f63b7f996aed822af2d0f6f14d50fcc0cc01813292c5"
	"2061682d1f4d6cb6a9bf08e832386ff7";

/**
 * Произведение двух простых чисел: составной нечётный модуль
 */
static const char * COMPOSITE =
	"b79a5388ec764eaf457e7d586f8d84c5c4c3ff78b5ee50d05abad02d6b705e7bbf96e80f7832cff92a58106d0169910f"
	"e4ba2379df9a937d17b1f0160672b09e4db27348cb89636ab9b15a38308633628676d6d023a75d7b4fa876f0bd19e309"
	"eb3216629e557930b12fd4f9c746c7eef1c59d66481818fb0956d076e63517f9750adfc97a1f6eff6b7a1ddd9c2de829"
	"2cf41ba34d70310710bfd291ed67bc74f62962c09763875ed5b22de4cb9fde00839927e3bd82129626f55b3f879db223";

/**
 * Произведение третьего и четвёртого чисел по составному модулю
 */
static const char * MULMOD =
	"5521c0405310ebea6025fba4c60b92cd783c83f9dc444970cf79cddc1c1d89ff39fcba109e374b1d9cee50725e2846f6"
	"f6336bad7249858143f936647f3c77cf435dc071c2d9900a26540c5e9df2db44b32b6880f89a974957331fc3814992b1"
	"bd66b48fd6f05386013dcf9515043fc6b7005a1f9379d1b912990b93e7f22163ea647785888017d868153f16f75c88ed"
	"d7e54b50ac7754ac548a36338232b898b0103e10c70e42f330e755501c8a3012c73130accd54526356af88b4c30e5851";

/**
 * Первое число, приведённое по простому модулю: основание степени
 */
static const char * BASE =
	"8b7c6b370642a0da3eb4b7fcf4e5c08421166b4d8e7a90029ef1200fcced6fd2e3a1e28b456514b9c3f35cdfdb505076"
	"1447166ac3642fd4c2408bcf93ffd5696ffc2ca95c82cda041799bf62197299b5c02a9727d92a8b570294ed7e947e219"
	"31de8a7708341fa673ee56d5e7c8d8c9303573544885ddcf69ea073a464fafae";

/**
 * Второе число, усечённое до 1024 разрядов: показатель, умещающийся в слова простого модуля
 */
static const char * SHORT =
	"11e1319d50ce81f3fcdd5b98aca530de93a163d17fa863a0c8dcde71bc7b86b6d0c01e2f8b9a6c0a3bab516ebdcc15da"
	"b46dfea502443cc0263938eb778e2cca3d7e851b031e23173b21f97b5d149d46b293d6d90182ed5eb615472c03103398"
	"cc40e1ae5f07f623e0c61fd0fa591178cff1c90579587a9de7c7876fccabee66";

/**
 * Основание в степени усечённого второго числа по простому модулю
 */
static const char * POWER_SHORT =
	"9463e9498f0631426c9d72d01f40cbf0d1f624c0c83aaabe49738a136a7554a8d32db8fb76a0e40c7ad1d68a0df2304c"
	"167881592f8a7b0ae810c20ad58417fcaad8df728538e76aeb59e41af663fe8ced2dd5b54da8ac1145923341d65691bc"
	"e22ee35d93baa26f4940ee5f63df3040cefcff5ad51cf37d985bdea4680de2bb";

/**
 * Основание в степени второго числа по простому модулю
 */
static const char * POWER =
	"898d3e1156e300dc46250e3ffeb95253846e27c649cc9b2538b62024e1dec6aaebfcce277be0f308784dd4c9a28dbda3"
	"a2f4f9eb3c3dc53ecbdc90e48cfd77641b19f562b74f9a22b575b5d7b0273344d10d0b83a34b7ea7f442ffafd52ef5d1"
	"1e260917f6da90ef0d4f366a86c0b8b99537078fb630ad3e8e3dd5bd61a98e19";

/**
 * Третье число по составному модулю в степени четвёртого по нему же
 */
static const char * POWER_COMPOSITE =
	"679321abed25d7519b394a3e8595225977fc52521e24b1418b7da0c86a268f688452b2d1ff8fa3bf9ee24ff2b2895388"
	"ac6a1aeee52302c7e9e7d404ec87246a18217cd175b44d04f5839541c68c6482c4d46afa49860d2e1fdd761c943f70ae"
	"2c2b5484c3afd97839509c957a70af8c9b4f49e8983499626ad30c4c76d69c24bc7694a615259a129664d9e970613a83"
	"9f907d19218010ff5dc6d441a508fe4809f37e4a9c9cc34ba4e05d3b4090d81d27d0ea5e16076db496c5893eea29937d";

/**
 * Обратное ко второму числу по простому модулю
 */
static const char * INVERSE =
	"682e50993a4745d4b18661063046c21dd33e53f20e805d577152facd2111ba7d3972d7c704404af3163329610b538562"
	"0b27b601cf9cd930f6ab76f353b1551133e5f67f5692c0297cddcc8f8e6b5e31665a277277b971124d05ace329be02c2"
	"59780fa2e1f93b392341ca3300d9ca852ef556f21509ced795403b0316fb8695";

/**
 * Первое число проверки общего делителя
 */
static const char * GCD_FIRST =
	"065904eff6297874ef5eb88269343f3bdea50dcb661433779326eaf2225f3d9f09427029cc398c69d50e826d6fac9152"
	"684ef1ec6918b5caa1523c4bff7255e645bb15a8b22a7bd24a5b402ac8c1debbd7023034f7df60604fb0743b91ca40bf"
	"24c8647c17af4510763bf2ee520ee1e7991ab9b4b2735a492268a3407fbd104384339fce48d7a808264e2032988d5d5b"
	"b77ad04a7fbb9aeeccf910f7aa0afa4df999c536cf0fed77804b95cc974bec0346a741226a599ecba89ebfcc4a9c9af5"
	"3806019386ff8d15";

/**
 * Второе число проверки общего делителя
 */
static const char * GCD_SECOND =
	"06ccac7f00d31e9d439210886b72f1629dc8a0cafb51eb550020093cad6caee734829a2285c6425e16711a72ea632d7e"
	"0a65daf97762a30bdc0f772f13f8266f243209df95880bdda47795a9358af575019bc96c7e639427e64d044925686c55"
	"d26921106d5564aa24dd4f7f263879c529bfc97d4db000fb0f063ff60e51ccc29cbdc0f60fab7edcb4924443758af2d3"
	"90c0fdc1d52bdade94db558975a38786bc0c026527722318917f0f4b986638676033d840339b4e66e06a5c169f5eb87a"
	"87e10459a55305794a1434cea5b1d77ee953ef662b1201948088df882a68b4dd07";

/**
 * Наибольший общий делитель чисел проверки
 */
static const char * GCD =
	"82d7912d6d798834c450abe0b15dd06322c3b36242b3c15223e9f71252416a9561be83508f09878419e2d239b475e3db"
	"dba54bef3c2b23e335e4d90ff6b7670b4b26682121d6b55fdd8ca269102d1cc4d7c8900aae87f7";

/**
 * Чётный модуль: произведение простых чисел без единицы
 */
static const char * EVEN_MODULUS =
	"b79a5388ec764eaf457e7d586f8d84c5c4c3ff78b5ee50d05abad02d6b705e7bbf96e80f7832cff92a58106d0169910f"
	"e4ba2379df9a937d17b1f0160672b09d823bb0b43f9d54c86651134ac82dd0bd5bb336b2b992e539ed024531441bb869"
	"60d508d90d8a8b0223ebba3d99c1ab343eac04e1f3b0636aa8471efc92cca389c8764a3d31c88ddb337b36407514a19d"
	"d2a3353539010496ad5f827ec6a0f0a4c12a77b5a083dfe4b04bdd338eb100113a643478a373bf2789d0485c2a78a5f8";

/**
 * Обратное к 65537 по чётному модулю
 */
static const char * EVEN_INVERSE =
	"643b8a131c14524c7941dea822ee3d67c24dc5f05e51e62878ffb79ab426ba4e10800fdc32207b4d69827e25243a3f89"
	"4fb3169ef825691347964a9d9b938d3bcfd74a567ccc2576e9f4a4f59466fea801a1cae0b352b07579205e29d126d8fc"
	"1e72eecba00adc6ca4b3920f031ba99d72017300ef8a821bbe1665a2397a22659bdc8816f450aab0da600f740cf6e06c"
	"4a8bf30645427b00cf516eea4b019d9e341e3d1018bb25c5b14119578634b6f6b0cbf7a14c8a69f6e9d39d4d439a6df1";

/**
 * @brief Проверка сложения, вычитания и умножения
 *
 */
TEST(IntegerTest, Arithmetic) {
	// Слагаемые
	const math::integer_t first = number(FIRST), second = number(SECOND);
	// Итог действия
	math::integer_t result;
	// Выполняем сложение
	ASSERT_TRUE(result.add(first, second));
	// Сличаем сумму с ожидаемой
	ASSERT_EQ(text(result), std::string(SUM));
	// Выполняем вычитание
	ASSERT_TRUE(result.subtract(first, second));
	// Сличаем разность с ожидаемой
	ASSERT_EQ(text(result), std::string(DIFFERENCE));
	// Выполняем вычитание большего из меньшего
	ASSERT_FALSE(result.subtract(second, first));
	// Выполняем умножение
	ASSERT_TRUE(result.multiply(first, second));
	// Сличаем произведение с ожидаемым
	ASSERT_EQ(text(result), std::string(PRODUCT));
	// Проверяем сравнение чисел
	ASSERT_GT(first.compare(second), 0);
	// Проверяем сравнение чисел в обратном порядке
	ASSERT_LT(second.compare(first), 0);
	// Проверяем сравнение числа с собой
	ASSERT_EQ(first.compare(first), 0);
	// Проверяем равенство числа с собой
	ASSERT_TRUE(first.equal(first));
	// Проверяем неравенство различных чисел
	ASSERT_FALSE(first.equal(second));
	// Проверяем число разрядов: старший из двух тысяч разрядов вывода хеша нулевой
	ASSERT_EQ(first.bits(), static_cast <size_t> (1999));
	// Проверяем размер в байтах
	ASSERT_EQ(first.size(), static_cast <size_t> (250));
	// Сумма после вычитания обязана вернуть исходное
	ASSERT_TRUE(result.subtract(first, second));
	// Прибавляем вычтенное
	ASSERT_TRUE(result.add(result, second));
	// Проверяем восстановление исходного
	ASSERT_TRUE(result.equal(first));
}
/**
 * @brief Проверка деления с остатком
 *
 */
TEST(IntegerTest, Division) {
	// Делимое и делители
	const math::integer_t third = number(THIRD), fourth = number(FOURTH), second = number(SECOND);
	// Частное и остаток
	math::integer_t quotient, remainder;
	// Выполняем деление
	ASSERT_TRUE(quotient.divide(third, fourth, &remainder));
	// Сличаем частное с ожидаемым
	ASSERT_EQ(text(quotient), std::string(QUOTIENT));
	// Сличаем остаток с ожидаемым
	ASSERT_EQ(text(remainder), std::string(REMAINDER));
	// Выполняем деление на короткий делитель
	ASSERT_TRUE(quotient.divide(third, second, &remainder));
	// Сличаем частное с ожидаемым
	ASSERT_EQ(text(quotient), std::string(WIDE_QUOTIENT));
	// Сличаем остаток с ожидаемым
	ASSERT_EQ(text(remainder), std::string(WIDE_REMAINDER));
	// Выполняем приведение по модулю
	ASSERT_TRUE(remainder.reduce(third, second));
	// Сличаем остаток с ожидаемым
	ASSERT_EQ(text(remainder), std::string(WIDE_REMAINDER));
	// Восстанавливаем делимое из частного и остатка
	math::integer_t product, restored;
	// Умножаем частное на делитель
	ASSERT_TRUE(product.multiply(quotient, second));
	// Прибавляем остаток
	ASSERT_TRUE(restored.add(product, remainder));
	// Проверяем восстановление делимого
	ASSERT_TRUE(restored.equal(third));
	// Ноль
	math::integer_t zero;
	// Деление на ноль отвергается
	ASSERT_FALSE(quotient.divide(third, zero, &remainder));
	// Приведение по нулевому модулю отвергается
	ASSERT_FALSE(remainder.reduce(third, zero));
	// Деление меньшего на большее даёт нулевое частное
	ASSERT_TRUE(quotient.divide(second, third, &remainder));
	// Проверяем нулевое частное
	ASSERT_TRUE(quotient.zero());
	// Проверяем остаток, равный делимому
	ASSERT_TRUE(remainder.equal(second));
}
/**
 * @brief Проверка действий по модулю
 *
 */
TEST(IntegerTest, Modular) {
	// Числа проверки
	const math::integer_t third = number(THIRD), fourth = number(FOURTH), second = number(SECOND);
	// Модули проверки
	const math::integer_t prime = number(PRIME1024), composite = number(COMPOSITE), base = number(BASE);
	// Итог действия
	math::integer_t result;
	// Выполняем умножение по модулю открытых сомножителей
	ASSERT_TRUE(result.mulmod(third, fourth, composite, false));
	// Сличаем произведение с ожидаемым
	ASSERT_EQ(text(result), std::string(MULMOD));
	// Приведённые сомножители
	math::integer_t first, item;
	// Приводим первый сомножитель по модулю
	ASSERT_TRUE(first.reduce(third, composite));
	// Приводим второй сомножитель по модулю
	ASSERT_TRUE(item.reduce(fourth, composite));
	// Выполняем умножение по Монтгомери
	ASSERT_TRUE(result.mulmod(first, item, composite, true));
	// Сличаем произведение с ожидаемым
	ASSERT_EQ(text(result), std::string(MULMOD));
	// Умножение по Монтгомери сомножителей, не умещающихся в модуль, отвергается
	ASSERT_FALSE(result.mulmod(third, fourth, composite, true));
	// Усечённый показатель
	const math::integer_t shortened = number(SHORT);
	// Выполняем возведение в степень с секретным показателем
	ASSERT_TRUE(result.power(base, shortened, prime, true));
	// Сличаем степень с ожидаемой
	ASSERT_EQ(text(result), std::string(POWER_SHORT));
	// Выполняем возведение в степень с открытым показателем
	ASSERT_TRUE(result.power(base, shortened, prime, false));
	// Сличаем степень с ожидаемой
	ASSERT_EQ(text(result), std::string(POWER_SHORT));
	// Секретный показатель длиннее слов модуля отвергается
	ASSERT_FALSE(result.power(base, second, prime, true));
	// Открытый показатель длиннее слов модуля допустим
	ASSERT_TRUE(result.power(base, second, prime, false));
	// Сличаем степень с ожидаемой
	ASSERT_EQ(text(result), std::string(POWER));
	// Выполняем возведение в степень по составному модулю: показатель длиннее модуля, оттого открыт
	ASSERT_TRUE(result.power(first, fourth, composite, false));
	// Сличаем степень с ожидаемой
	ASSERT_EQ(text(result), std::string(POWER_COMPOSITE));
	// Возведение основания, не меньшего модуля, отвергается
	ASSERT_FALSE(result.power(third, second, prime, true));
	// Чётный модуль
	math::integer_t even;
	// Записываем чётный модуль
	even.word(1000);
	// Возведение по чётному модулю отвергается
	ASSERT_FALSE(result.power(base, second, even, true));
	// Единица
	math::integer_t one;
	// Записываем единицу
	one.word(1);
	// Выполняем обращение по простому модулю
	ASSERT_TRUE(result.invert(second, prime));
	// Сличаем обратное с ожидаемым
	ASSERT_EQ(text(result), std::string(INVERSE));
	// Умножаем обратное на исходное
	ASSERT_TRUE(item.mulmod(result, second, prime, false));
	// Проверяем единицу
	ASSERT_TRUE(item.equal(one));
	// Показатель и чётный модуль
	const math::integer_t exponent = number("010001"), carmichael = number(EVEN_MODULUS);
	// Выполняем обращение по чётному модулю
	ASSERT_TRUE(result.invert(exponent, carmichael));
	// Сличаем обратное с ожидаемым
	ASSERT_EQ(text(result), std::string(EVEN_INVERSE));
	// Записываем простой сомножитель составного модуля
	item = number(PRIME512);
	// Обращение сомножителя по составному модулю отвергается
	ASSERT_FALSE(result.invert(item, composite));
	// Обращение нуля отвергается
	ASSERT_FALSE(result.invert(math::integer_t(), prime));
	// Наибольший общий делитель
	ASSERT_TRUE(result.gcd(number(GCD_FIRST), number(GCD_SECOND)));
	// Сличаем делитель с ожидаемым
	ASSERT_EQ(text(result), std::string(GCD));
	// Делитель числа и нуля - само число
	ASSERT_TRUE(result.gcd(second, math::integer_t()));
	// Проверяем делитель
	ASSERT_TRUE(result.equal(second));
	// Делитель двух нулей отвергается
	ASSERT_FALSE(result.gcd(math::integer_t(), math::integer_t()));
	// Сложение по модулю
	ASSERT_TRUE(result.addmod(base, base, prime));
	// Ожидаемая сумма
	math::integer_t expected;
	// Вычисляем сумму без приведения
	ASSERT_TRUE(expected.add(base, base));
	// Приводим сумму по модулю
	ASSERT_TRUE(expected.reduce(expected, prime));
	// Сличаем суммы
	ASSERT_TRUE(result.equal(expected));
	// Вычитание по модулю нуля из основания
	ASSERT_TRUE(result.submod(math::integer_t(), base, prime));
	// Прибавляем основание обратно
	ASSERT_TRUE(result.addmod(result, base, prime));
	// Проверяем ноль
	ASSERT_TRUE(result.zero());
	// Сложение по модулю слагаемых, не меньших модуля, отвергается
	ASSERT_FALSE(result.addmod(third, base, prime));
	// Вычитание по модулю значений, не меньших модуля, отвергается
	ASSERT_FALSE(result.submod(third, base, prime));
}
/**
 * @brief Проверка теста простоты
 *
 */
TEST(IntegerTest, Prime) {
	// Простое число длиной 1024 разряда: openssl prime -hex подтверждает простоту
	const math::integer_t prime = number(PRIME1024);
	// Проверяем простоту
	ASSERT_TRUE(prime.prime());
	// Простое число длиной 512 разрядов
	ASSERT_TRUE(number(PRIME512).prime());
	// Двойка
	math::integer_t two;
	// Записываем двойку
	two.word(2);
	// Число, большее простого на два: openssl prime -hex подтверждает составность
	math::integer_t next;
	// Вычисляем соседнее число
	ASSERT_TRUE(next.add(prime, two));
	// Проверяем составность
	ASSERT_FALSE(next.prime());
	// Произведение двух простых составное
	ASSERT_FALSE(number(COMPOSITE).prime());
	// Малые числа
	math::integer_t small;
	// Ноль не простое
	ASSERT_FALSE(small.prime());
	// Единица не простое
	small.word(1);
	// Проверяем единицу
	ASSERT_FALSE(small.prime());
	// Двойка простое
	ASSERT_TRUE(two.prime());
	// Тройка простое
	small.word(3);
	// Проверяем тройку
	ASSERT_TRUE(small.prime());
	// Четвёрка составное
	small.word(4);
	// Проверяем четвёрку
	ASSERT_FALSE(small.prime());
	// Число Ферма 65537 простое
	small.word(65537);
	// Проверяем число Ферма
	ASSERT_TRUE(small.prime());
	// Число Мерсенна 8191 простое: последнее в решете
	small.word(8191);
	// Проверяем число Мерсенна
	ASSERT_TRUE(small.prime());
	// Число 8193 составное: первое за решетом, делится на три
	small.word(8193);
	// Проверяем число за решетом
	ASSERT_FALSE(small.prime());
	// Число 65539 простое: за решетом, проверяется тестом Миллера-Рабина
	small.word(65539);
	// Проверяем простое за решетом
	ASSERT_TRUE(small.prime());
	// Число Кармайкла 561 составное: обманывает тест Ферма, но не Миллера-Рабина
	small.word(561);
	// Проверяем число Кармайкла
	ASSERT_FALSE(small.prime());
	// Число Кармайкла 3215031751 составное: обманывает основания 2, 3, 5 и 7
	small.word(3215031751ULL);
	// Проверяем большое число Кармайкла
	ASSERT_FALSE(small.prime());
}
/**
 * @brief Проверка границ разбора, записи и сдвигов
 *
 */
/**
 * @brief Метод возведения в степень по модулю эталонным двоичным методом через деление
 *
 * @param base     основание
 * @param exponent показатель
 * @param modulus  модуль
 * @return         степень по модулю
 *
 */
static math::integer_t reference(const math::integer_t & base, const math::integer_t & exponent, const math::integer_t & modulus) {
	// Накопитель степени
	math::integer_t result;
	// Накопитель начинается с единицы
	result.word(1);
	/**
	 * Выполняем перебор разрядов показателя от старшего к младшему
	 */
	for(size_t i = exponent.bits(); i > 0; i--){
		// Возводим накопитель в квадрат делением
		result.mulmod(result, result, modulus, false);
		// Если разряд единичный, умножаем на основание
		if(exponent.bit(i - 1))
			result.mulmod(result, base, modulus, false);
	}
	// Выводим степень
	return result;
}
/**
 * @brief Метод сверки арифметики Монтгомери с арифметикой через деление по одному модулю
 *
 * @param modulus нечётный модуль
 * @param rounds  число случайных проверок
 *
 */
static void montgomery(const math::integer_t & modulus, const size_t rounds) {
	// Арифметика Монтгомери
	math::montgomery_t field;
	// Заводим арифметику по модулю
	ASSERT_TRUE(field.start(modulus));
	// Арифметика заведена, число слов совпадает с модулем
	ASSERT_TRUE(field.ready());
	ASSERT_EQ(field.words(), (modulus.bits() + 63) / 64);
	// Единица и число на единицу меньше модуля
	math::integer_t one, last;
	one.word(1);
	ASSERT_TRUE(last.subtract(modulus, one));
	// Итоги действий
	math::integer_t entered, left, product, expected, power, remainder, inverse, check;
	/**
	 * Выполняем случайные проверки
	 */
	for(size_t i = 0; i < rounds; i++){
		// Случайные числа, приведённые по модулю делением
		math::integer_t first, second, wide, exponent;
		ASSERT_TRUE(first.random(modulus.bits()));
		ASSERT_TRUE(second.random(modulus.bits()));
		ASSERT_TRUE(first.reduce(first, modulus));
		ASSERT_TRUE(second.reduce(second, modulus));
		// Перевод в область и обратно возвращает число
		ASSERT_TRUE(field.enter(first, entered));
		ASSERT_TRUE(field.leave(entered, left));
		ASSERT_TRUE(left.equal(first));
		// Умножение вне области сходится с умножением через деление
		ASSERT_TRUE(expected.mulmod(first, second, modulus, false));
		ASSERT_TRUE(field.mulmod(first, second, product));
		ASSERT_TRUE(product.equal(expected));
		// Умножение в области: произведение чисел в области выводится в то же произведение
		math::integer_t other;
		ASSERT_TRUE(field.enter(second, other));
		ASSERT_TRUE(field.multiply(entered, other, product));
		ASSERT_TRUE(field.leave(product, left));
		ASSERT_TRUE(left.equal(expected));
		// Приёмник вправе совпадать с сомножителем
		ASSERT_TRUE(field.mulmod(first, second, first));
		ASSERT_TRUE(first.equal(expected));
		ASSERT_TRUE(first.reduce(first, modulus));
		// Возведение в степень с секретным показателем во всю ширину модуля сходится с открытым и с прежним перебором
		ASSERT_TRUE(exponent.random(modulus.bits()));
		ASSERT_TRUE(expected.power(first, exponent, modulus, true));
		ASSERT_TRUE(field.power(first, exponent, true, power));
		ASSERT_TRUE(power.equal(expected));
		ASSERT_TRUE(field.power(first, exponent, false, power));
		ASSERT_TRUE(power.equal(expected));
		// Короткий показатель сходится с эталоном через деление: не шире слов модуля
		ASSERT_TRUE(exponent.random((modulus.bits() < 96) ? modulus.bits() : 96));
		expected = reference(first, exponent, modulus);
		ASSERT_TRUE(field.power(first, exponent, true, power));
		ASSERT_TRUE(power.equal(expected));
		ASSERT_TRUE(field.power(first, exponent, false, power));
		ASSERT_TRUE(power.equal(expected));
		// Приведение числа двойной и тройной ширины сходится с делением
		ASSERT_TRUE(wide.random(2 * modulus.bits()));
		ASSERT_TRUE(expected.reduce(wide, modulus));
		ASSERT_TRUE(field.reduce(wide, remainder));
		ASSERT_TRUE(remainder.equal(expected));
		if((3 * modulus.bits()) <= math::INTEGER_BITS){
			ASSERT_TRUE(wide.random(3 * modulus.bits()));
			ASSERT_TRUE(expected.reduce(wide, modulus));
			ASSERT_TRUE(field.reduce(wide, remainder));
			ASSERT_TRUE(remainder.equal(expected));
		}
		// Обращение: произведение числа на обратное даёт единицу, а само обратное сходится с Евклидом
		if(!second.zero()){
			// Наибольший общий делитель
			math::integer_t divisor;
			ASSERT_TRUE(divisor.gcd(second, modulus));
			// Если число взаимно просто с модулем
			if(divisor.equal(one)){
				ASSERT_TRUE(field.invert(second, inverse));
				ASSERT_TRUE(check.mulmod(second, inverse, modulus, false));
				ASSERT_TRUE(check.equal(one));
				ASSERT_TRUE(expected.invert(second, modulus));
				ASSERT_TRUE(inverse.equal(expected));
			// Если число с модулем не взаимно просто
			} else ASSERT_FALSE(field.invert(second, inverse));
		}
	}
	// Края: ноль, единица и число на единицу меньше модуля
	math::integer_t zero, two;
	two.word(2);
	ASSERT_TRUE(field.power(zero, two, true, power));
	ASSERT_TRUE(power.zero());
	ASSERT_TRUE(field.power(last, two, true, power));
	ASSERT_TRUE(power.equal(one));
	ASSERT_TRUE(field.power(last, two, false, power));
	ASSERT_TRUE(power.equal(one));
	ASSERT_TRUE(field.power(last, zero, false, power));
	ASSERT_TRUE(power.equal(one));
	ASSERT_TRUE(field.power(last, one, true, power));
	ASSERT_TRUE(power.equal(last));
	ASSERT_TRUE(field.invert(one, inverse));
	ASSERT_TRUE(inverse.equal(one));
	ASSERT_TRUE(field.invert(last, inverse));
	ASSERT_TRUE(inverse.equal(last));
	ASSERT_FALSE(field.invert(zero, inverse));
	// Числа не меньше модуля отвергаются
	ASSERT_FALSE(field.enter(modulus, entered));
	ASSERT_FALSE(field.mulmod(modulus, one, product));
	ASSERT_FALSE(field.power(modulus, one, false, power));
	ASSERT_FALSE(field.invert(modulus, inverse));
	// Секретный показатель шире слов модуля отвергается
	math::integer_t huge;
	huge.word(1);
	huge.left(huge, field.words() * 64);
	ASSERT_FALSE(field.power(one, huge, true, power));
	ASSERT_TRUE(field.power(one, huge, false, power));
	ASSERT_TRUE(power.equal(one));
}
/**
 * Арифметика Монтгомери с предвычислениями: перевод в область, умножение, степень,
 * приведение и обращение за постоянное время сверяются с арифметикой через деление
 * на модулях разной ширины, простых и составных
 */
TEST(IntegerTest, Montgomery) {
	// Незаведённая арифметика отвергает всё
	math::montgomery_t empty;
	math::integer_t one, result;
	one.word(1);
	ASSERT_FALSE(empty.ready());
	ASSERT_FALSE(empty.enter(one, result));
	ASSERT_FALSE(empty.power(one, one, true, result));
	// Чётный и нулевой модули отвергаются
	math::integer_t even, zero;
	even.word(10);
	ASSERT_FALSE(empty.start(even));
	ASSERT_FALSE(empty.start(zero));
	// Простой модуль в шестнадцать слов
	montgomery(number(PRIME1024), 4);
	// Простой модуль в восемь слов
	montgomery(number(PRIME512), 4);
	// Составной модуль
	montgomery(number(COMPOSITE), 4);
	// Модуль в одно слово: простое 2^64 - 59
	math::integer_t small;
	small.word(0xFFFFFFFFFFFFFFC5ULL);
	montgomery(small, 8);
	// Нечётный модуль в семнадцать слов: 2^1024 + 1
	math::integer_t odd;
	odd.word(1);
	odd.left(odd, 1024);
	ASSERT_TRUE(odd.add(odd, one));
	montgomery(odd, 2);
	// Составной модуль в двадцать четыре слова: произведение простых
	math::integer_t product;
	ASSERT_TRUE(product.multiply(number(PRIME1024), number(PRIME512)));
	montgomery(product, 2);
	// Случайный нечётный модуль в шестьдесят четыре слова
	math::integer_t large;
	ASSERT_TRUE(large.random(4096));
	ASSERT_TRUE(large.add(large, one));
	if(!large.odd())
		ASSERT_TRUE(large.add(large, one));
	montgomery(large, 1);
}
TEST(IntegerTest, Edges) {
	// Байты числа с запасом
	uint8_t buffer[math::INTEGER_SIZE + 2] = {};
	// Число проверки
	math::integer_t value;
	// Записываем старший байт за пределами ёмкости
	buffer[0] = 0x01;
	// Число, не умещающееся в ёмкость, отвергается
	ASSERT_FALSE(value.load(view_t(buffer, math::INTEGER_SIZE + 1)));
	// Обнуляем старший байт
	buffer[0] = 0x00;
	// Записываем младший байт
	buffer[math::INTEGER_SIZE] = 0x7F;
	// Число с ведущим нулём сверх ёмкости разбирается
	ASSERT_TRUE(value.load(view_t(buffer, math::INTEGER_SIZE + 1)));
	// Проверяем значение
	ASSERT_EQ(text(value), std::string("7f"));
	// Пустое число равно нулю
	ASSERT_TRUE(value.load(view_t()));
	// Проверяем ноль
	ASSERT_TRUE(value.zero());
	// Наибольшее число ёмкости
	memset(buffer, 0xFF, math::INTEGER_SIZE);
	// Разбираем наибольшее число
	ASSERT_TRUE(value.load(view_t(buffer, math::INTEGER_SIZE)));
	// Проверяем число разрядов
	ASSERT_EQ(value.bits(), math::INTEGER_BITS);
	// Единица
	math::integer_t one, result;
	// Записываем единицу
	one.word(1);
	// Переполнение сложения объявляется отказом
	ASSERT_FALSE(result.add(value, one));
	// Младшая часть суммы равна нулю
	ASSERT_TRUE(result.zero());
	// Переполнение умножения объявляется отказом
	ASSERT_FALSE(result.multiply(value, value));
	// Запись в меньший размер отвергается
	ASSERT_FALSE(value.store(buffer, math::INTEGER_SIZE - 1));
	// Запись в больший размер дополняется ведущими нулями
	ASSERT_TRUE(value.store(buffer, math::INTEGER_SIZE + 2));
	// Проверяем ведущий ноль
	ASSERT_EQ(buffer[0], 0x00);
	// Проверяем второй ведущий ноль
	ASSERT_EQ(buffer[1], 0x00);
	// Проверяем первый байт числа
	ASSERT_EQ(buffer[2], 0xFF);
	// Сдвиг единицы влево на 4095 разрядов
	result.left(one, math::INTEGER_BITS - 1);
	// Проверяем старший разряд
	ASSERT_TRUE(result.bit(math::INTEGER_BITS - 1));
	// Проверяем число разрядов
	ASSERT_EQ(result.bits(), math::INTEGER_BITS);
	// Сдвиг обратно вправо
	result.right(result, math::INTEGER_BITS - 1);
	// Проверяем восстановление единицы
	ASSERT_TRUE(result.equal(one));
	// Сдвиг за пределы ёмкости обнуляет число
	result.left(one, math::INTEGER_BITS);
	// Проверяем ноль
	ASSERT_TRUE(result.zero());
	// Разряд за пределами ёмкости нулевой
	ASSERT_FALSE(value.bit(math::INTEGER_BITS));
	// Сдвиг на 100 разрядов влево и вправо на числе проверки
	const math::integer_t first = number(FIRST);
	// Сдвигаем влево
	result.left(first, 100);
	// Сдвигаем вправо
	result.right(result, 100);
	// Проверяем восстановление
	ASSERT_TRUE(result.equal(first));
	// Нечётность
	ASSERT_TRUE(one.odd());
	// Чётность нуля
	ASSERT_FALSE(math::integer_t().odd());
	// Случайное число заказанной длины
	ASSERT_TRUE(result.random(100));
	// Проверяем, что число не длиннее заказанного
	ASSERT_LE(result.bits(), static_cast <size_t> (100));
	// Случайное число сверх ёмкости отвергается
	ASSERT_FALSE(result.random(math::INTEGER_BITS + 1));
	// Случайное число нулевой длины отвергается
	ASSERT_FALSE(result.random(0));
	// Обнуление числа
	value.clear();
	// Проверяем ноль
	ASSERT_TRUE(value.zero());
}
/**
 * Проверка ядер Монтгомери по всем ширинам модуля с краевыми входами: умножение рядами
 * со сдвигом против умножения через деление, ядро квадрата (сомножители по одному
 * указателю) против умножения того же числа по разным указателям, возведение в степень
 * против эталона (решение 6 шапки integer.cpp)
 */
TEST(IntegerTest, Kernels) {
	// Единица
	math::integer_t one;
	// Записываем единицу
	one.word(1);
	/**
	 * Выполняем перебор ширин модуля в словах
	 */
	for(size_t words = 1; words <= 64; words++){
		/**
		 * Выполняем перебор видов модуля
		 */
		for(int kind = 0; kind < 4; kind++){
			// Модуль
			math::integer_t modulus;
			/**
			 * Определяем вид модуля
			 */
			switch(kind){
				// Случайный нечётный со старшим разрядом
				case 0: {
					// Вырабатываем случайное число
					ASSERT_TRUE(modulus.random(words * 64));
					// Старший разряд
					math::integer_t bit;
					bit.word(1);
					bit.left(bit, (words * 64) - 1);
					// Ставим старший разряд: сложение с числом без него
					if(!modulus.bit((words * 64) - 1))
						ASSERT_TRUE(modulus.add(modulus, bit));
				} break;
				// Все разряды единицы: 2^(64 · words) - 1
				case 1: {
					math::integer_t power;
					power.word(1);
					power.left(power, words * 64);
					ASSERT_TRUE(modulus.subtract(power, one));
				} break;
				// Короткое старшее слово: 2^(64 · (words - 1)) + 1, у одного слова - три
				case 2: {
					if(words == 1) modulus.word(3);
					else {
						modulus.word(1);
						modulus.left(modulus, (words - 1) * 64);
						ASSERT_TRUE(modulus.add(modulus, one));
					}
				} break;
				// Случайный нечётный без старшего разряда
				default: {
					ASSERT_TRUE(modulus.random((words * 64) - 1));
					if(modulus.zero()) modulus.word(1);
				} break;
			}
			// Делаем модуль нечётным
			if(!modulus.odd())
				ASSERT_TRUE(modulus.add(modulus, one));
			// Арифметика Монтгомери
			math::montgomery_t field;
			// Заводим арифметику
			ASSERT_TRUE(field.start(modulus)) << "слов " << words << ", вид " << kind;
			// Число на единицу меньше модуля
			math::integer_t last;
			ASSERT_TRUE(last.subtract(modulus, one));
			/**
			 * Выполняем перебор входов: случайные, оба меньше модуля на единицу, ноль, единица
			 */
			for(int input = 0; input < 4; input++){
				// Сомножители
				math::integer_t first, second;
				/**
				 * Определяем вход
				 */
				switch(input){
					// Случайные, приведённые по модулю
					case 0: {
						ASSERT_TRUE(first.random(words * 64));
						ASSERT_TRUE(second.random(words * 64));
						ASSERT_TRUE(first.reduce(first, modulus));
						ASSERT_TRUE(second.reduce(second, modulus));
					} break;
					// Оба на единицу меньше модуля
					case 1: { first = last; second = last; } break;
					// Ноль и число меньше модуля
					case 2: { second = last; } break;
					// Единица и случайное
					default: {
						first.word(1);
						ASSERT_TRUE(second.random(words * 64));
						ASSERT_TRUE(second.reduce(second, modulus));
					} break;
				}
				// Ожидаемые и полученные итоги
				math::integer_t expected, product, square, twin;
				// Умножение через деление
				ASSERT_TRUE(expected.mulmod(first, second, modulus, false));
				// Умножение Монтгомери рядами
				ASSERT_TRUE(field.mulmod(first, second, product));
				// Проверяем сходимость
				ASSERT_TRUE(product.equal(expected)) << "умножение: слов " << words << ", вид " << kind << ", вход " << input;
				// Квадрат через деление
				ASSERT_TRUE(expected.mulmod(second, second, modulus, false));
				// Квадрат ядром квадрата: сомножители по одному указателю
				ASSERT_TRUE(field.mulmod(second, second, square));
				// Проверяем сходимость квадрата
				ASSERT_TRUE(square.equal(expected)) << "квадрат: слов " << words << ", вид " << kind << ", вход " << input;
				// Копия второго сомножителя: тот же квадрат общим ядром по разным указателям
				math::integer_t copy = second;
				ASSERT_TRUE(field.mulmod(second, copy, twin));
				// Проверяем сходимость ядер
				ASSERT_TRUE(twin.equal(square)) << "квадрат против умножения: слов " << words << ", вид " << kind << ", вход " << input;
			}
			// Возведение в степень у нескольких ширин: секретный и открытый пути
			if((words == 1) || (words == 3) || (words == 4) || (words == 8) || (words == 16) || (words == 17) || (words == 32)){
				// Основание и показатель
				math::integer_t base, exponent, power, expected;
				ASSERT_TRUE(base.random(words * 64));
				ASSERT_TRUE(base.reduce(base, modulus));
				ASSERT_TRUE(exponent.random(64));
				// Эталон
				expected = reference(base, exponent, modulus);
				// Секретный путь: окна по всей ширине слов
				ASSERT_TRUE(field.power(base, exponent, true, power));
				ASSERT_TRUE(power.equal(expected)) << "степень секретная: слов " << words << ", вид " << kind;
				// Открытый путь: двоичный метод по значимым разрядам
				ASSERT_TRUE(field.power(base, exponent, false, power));
				ASSERT_TRUE(power.equal(expected)) << "степень открытая: слов " << words << ", вид " << kind;
			}
		}
	}
}
