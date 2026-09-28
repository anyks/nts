#!/usr/bin/env python3
#
# Порождатель сшитых ядер AES-CTR + GHASH на встроенном ассемблере x86-64 и AArch64 для
# src/internal/cipher/gcm.hpp: python3 tools/cipher/gcm.py > src/internal/cipher/gcm.hpp
#
# Устройство ядер. Восьмёрка блоков счётчика идёт кругами AES разом, а между кругами с первого по
# восьмой хешируется по блоку прежней восьмёрки (при зашифровании - итог прошлой, при расшифровании -
# исходные данные текущей): произведения блоков на степени ключа хеша копятся на восьмёрку и приводятся
# один раз. Счётчики восьмёрки собираются сложениями в векторе от основания, пока младший байт не
# переполняется; на переносе через младший байт - не чаще раза на тридцать две восьмёрки - счётчики
# собираются по одному через скалярный регистр, оттого ход любой длины идёт одним вызовом.
#
# x86-64 (кодировка VEX, образец - разбор портов Broadwell круга 38): перестановки байтов делят порт с
# aesenc, потому половины хешируемого блока переставляются загрузкой movbe в регистры общего
# назначения, пишутся в ячейки кадра и грузятся порознь двумя vmovq; четыре умножения без переносов
# берут по половине, средняя часть суммы полная, поправки Карацубы нет; блок с накопителем идёт
# первым, приведение - сдвигами после записи итога. Пробы круга 43 (блок с накопителем последним,
# перестановка за круг до умножений, приведение прошлой восьмёрки вперемешку с произведениями,
# блок одним регистром через vpshufb) на Broadwell оказались не лучше либо хуже.
#
# AArch64 (образец - замер устройств Apple M4 круга 43: пары aese+aesmc и pmull идут на одних
# устройствах, ход упирается в число команд и в цепочку приведения): блоки отражаются rbit,
# произведение Карацубы тремя pmull с суммой половин степени из таблицы, произведения пары блоков
# складываются в суммы разом (eor3 при расширении SHA-3, иначе парой eor), суммы прошлой восьмёрки
# приводятся вперемешку с произведениями текущей, а блок с накопителем множится последним; счётчики
# растут цепочкой сложений с единицей - шаг один на регистр.
#
# Правки ядер вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый список команд
# на случайных ключах, счётчиках, накопителях и данных и сличает с переносимыми AES и GHASH -
# порождение отказывает, если сходимости нет.
#
import random, sys

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
M128 = (1 << 128) - 1

# ---------- AES ----------
def _sbox():
	box = [0] * 256
	p = q = 1
	while True:
		# p * 3 в поле
		p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
		# q / 3
		q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
		if q & 0x80: q ^= 0x09
		x = q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4)
		box[p] = ((x ^ (x >> 8)) & 0xFF) ^ 0x63
		if p == 1: break
	box[0] = 0x63
	return box
SBOX = _sbox()

def xtime(v):
	return ((v << 1) ^ 0x1B) & 0xFF if v & 0x80 else (v << 1)

def sub_bytes(s):
	return bytes(SBOX[b] for b in s)

def shift_rows(s):
	# Состояние по столбцам: байт r + 4c
	return bytes(s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4))

def mix_columns(s):
	out = bytearray(16)
	for c in range(4):
		a = s[4 * c:4 * c + 4]
		for r in range(4):
			out[4 * c + r] = (xtime(a[r]) ^ xtime(a[(r + 1) % 4]) ^ a[(r + 1) % 4] ^ a[(r + 2) % 4] ^ a[(r + 3) % 4])
	return bytes(out)

def xor(a, b):
	return bytes(x ^ y for x, y in zip(a, b))

def aesenc(s, k):
	return xor(mix_columns(shift_rows(sub_bytes(s))), k)

def aesenclast(s, k):
	return xor(shift_rows(sub_bytes(s)), k)

def aese(s, k):
	return shift_rows(sub_bytes(xor(s, k)))

def aesmc(s):
	return mix_columns(s)

def expand(key):
	nk = len(key) // 4
	rounds = nk + 6
	w = [key[4 * i:4 * i + 4] for i in range(nk)]
	rcon = 1
	for i in range(nk, 4 * (rounds + 1)):
		t = w[i - 1]
		if i % nk == 0:
			t = bytes([SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]])
			rcon = xtime(rcon)
		elif nk > 6 and i % nk == 4:
			t = bytes(SBOX[b] for b in t)
		w.append(xor(w[i - nk], t))
	return [b''.join(w[4 * r:4 * r + 4]) for r in range(rounds + 1)]

def encrypt(schedule, block):
	s = xor(block, schedule[0])
	for k in schedule[1:-1]: s = aesenc(s, k)
	return aesenclast(s, schedule[-1])

def encrypt_arm(schedule, block):
	s = block
	for k in schedule[:-2]: s = aesmc(aese(s, k))
	return xor(aese(s, schedule[-2]), schedule[-1])

def fips_check():
	pt = bytes(range(0x00, 0x100, 0x11))
	for key, want in ((bytes(range(16)), '69c4e0d86a7b0430d8cdb78070b4c55a'), (bytes(range(24)), 'dda97ca4864cdfe06eaf70a0ec0d7191'), (bytes(range(32)), '8ea2b7ca516745bfeafc49904b496089')):
		sch = expand(key)
		assert encrypt(sch, pt).hex() == want, 'AES x86'
		assert encrypt_arm(sch, pt).hex() == want, 'AES ARM'
fips_check()

# ---------- GHASH ----------
def clmul(a, b):
	r = 0
	for i in range(64):
		if (b >> i) & 1: r ^= a << i
	return r

def gf_mult(x, y):
	# Порядок разрядов GCM: нулевой разряд - старший
	R = 0xE1 << 120
	z = 0; v = y
	for i in range(128):
		if (x >> (127 - i)) & 1: z ^= v
		v = ((v >> 1) ^ R) if (v & 1) else (v >> 1)
	return z

def rbit(b):
	return int('{:08b}'.format(b)[::-1], 2)

def twist(h):
	# Ключ с переставленными байтами, сдвинутый на разряд влево с приведением (twistX86)
	v = int.from_bytes(h, 'big')
	r = (v << 1) & M128
	if v >> 127: r ^= ((0xC200000000000000 << 64) | 1)
	lo, hi = r & M64, r >> 64
	return lo, hi, lo ^ hi

def mirror(h):
	# Ключ с отражёнными разрядами байтов (mirrorArm), третьим словом - сумма половин
	rb = bytes(rbit(b) for b in h)
	lo, hi = int.from_bytes(rb[:8], 'little'), int.from_bytes(rb[8:], 'little')
	return lo, hi, lo ^ hi

def powers(H, arch):
	# Степени ключа хеша от восьмой к первой по 24 байта
	p = [H]
	for _ in range(7): p.append(gf_mult(p[-1], H))
	out = bytearray()
	for k in range(7, -1, -1):
		words = (twist if arch == 'x86' else mirror)(p[k].to_bytes(16, 'big'))
		for w in words: out += w.to_bytes(8, 'little')
	return bytes(out)

# ---------- ядро x86-64 ----------
# Кадр [tab]: 0 основание счётчика, 16 число средних кругов, 32 накопитель, 48 ячейки половин (8 × 16)
# Постоянные [cst]: 0…127 шаги счётчика 1…8 в старшем байте, 128 маска перестановки байтов
X86_CONSTANTS = sum(([0] * 15 + [i] for i in range(1, 9)), []) + list(range(15, -1, -1))
assert len(X86_CONSTANTS) == 144
X86_FRAME = 176

class X86:
	def __init__(self, prefetch=()):
		# Предвыборка: пары (область, смещение) в начале восьмёрки
		self.prefetch = prefetch
		self.ins = []
	def e(self, *op):
		self.ins.append(op)
	def m(self, base, off):
		return ('m', base, off)
	def round(self, keyoff):
		self.e('vmovdqu', 'x14', self.m('keys', keyoff))
		for i in range(8): self.e('vaesenc', 'x%d' % i, 'x%d' % i, 'x14')
	def hash(self, i):
		# Половины блока i переставляются movbe в ячейки, грузятся порознь и множатся по половинам на степень i
		cell = 48 + 16 * i
		self.e('movbe', 't0', self.m('hash', 16 * i))
		self.e('movbe', 't1', self.m('hash', 16 * i + 8))
		self.e('movq_s', self.m('tab', cell), 't1')
		self.e('movq_s', self.m('tab', cell + 8), 't0')
		self.e('vmovq', 'x11', self.m('tab', cell))
		self.e('vmovq', 'x12', self.m('tab', cell + 8))
		if i == 0:
			# Нулевой блок складывается с накопителем: младшая половина в 15, старшая в 13
			self.e('vpxor', 'x11', 'x11', 'x15')
			self.e('vpxor', 'x12', 'x12', 'x13')
		p = self.m('pow', 24 * i)
		self.e('vpclmulqdq', 0x00, 'x13', 'x11', p); self.e('vpxor', 'x8', 'x8', 'x13')
		self.e('vpclmulqdq', 0x10, 'x13', 'x11', p); self.e('vpxor', 'x10', 'x10', 'x13')
		self.e('vpclmulqdq', 0x00, 'x13', 'x12', p); self.e('vpxor', 'x10', 'x10', 'x13')
		self.e('vpclmulqdq', 0x10, 'x13', 'x12', p); self.e('vpxor', 'x9', 'x9', 'x13')
	def counters(self):
		# Счётчики восьмёрки от основания: сложениями, пока младший байт не переполняется, иначе по одному через скаляр
		self.e('vmovdqu', 'x11', self.m('tab', 0))
		self.e('cmpb_ja', 'tail', 0xF7, '4f')
		for i in range(8): self.e('vpaddd', 'x%d' % i, 'x11', self.m('cst', 16 * i))
		self.e('jmp', '5f')
		self.e('label', '4')
		for i in range(8):
			self.e('leal', 't1', 'tail', i + 1)
			self.e('bswapl', 't1')
			self.e('vpinsrd', 'x%d' % i, 'x11', 't1')
		self.e('label', '5')
		# Основание следующей восьмёрки - счётчик седьмого блока
		self.e('vmovdqu_s', self.m('tab', 0), 'x7')
		self.e('addl', 'tail', 8)
		for i in range(8): self.e('vpxor', 'x%d' % i, 'x%d' % i, self.m('keys', 0))
	def build(self):
		# Пролог: маска, накопитель переставленный и его старшая половина, младшее слово счётчика числом
		self.e('vmovdqu', 'x11', self.m('cst', 128))
		self.e('vmovdqu', 'x15', self.m('tab', 32))
		self.e('vpshufb', 'x15', 'x15', 'x11')
		self.e('vpsrldq', 'x13', 'x15', 8)
		self.e('movbe32', 'tail', self.m('tab', 12))
		self.e('label', '1')
		for region, off in self.prefetch: self.e('prefetch', self.m(region, off))
		self.counters()
		for r in (8, 9, 10): self.e('vpxor', 'x%d' % r, 'x%d' % r, 'x%d' % r)
		for r in range(1, 9):
			self.round(16 * r)
			self.hash(r - 1)
		# Круги с девятого до предпоследнего
		self.e('leaq', 'kp', 'keys', 144)
		self.e('movq', 'n', self.m('tab', 16))
		self.e('label', '3')
		self.e('vmovdqu', 'x14', self.m('kp', 0))
		for i in range(8): self.e('vaesenc', 'x%d' % i, 'x%d' % i, 'x14')
		self.e('addq', 'kp', 16)
		self.e('decq_jnz', 'n', '3b')
		# Последний круг, наложение гаммы и запись итога
		self.e('vmovdqu', 'x14', self.m('kp', 0))
		for i in range(8): self.e('vaesenclast', 'x%d' % i, 'x%d' % i, 'x14')
		for i in range(8):
			self.e('vpxor', 'x%d' % i, 'x%d' % i, self.m('src', 16 * i))
			self.e('vmovdqu_s', self.m('dst', 16 * i), 'x%d' % i)
		# Приведение суммы произведений в накопитель: средняя часть полная, без поправки Карацубы
		self.e('vpslldq', 'x11', 'x10', 8); self.e('vpxor', 'x8', 'x8', 'x11')
		self.e('vpsrldq', 'x11', 'x10', 8); self.e('vpxor', 'x9', 'x9', 'x11')
		self.e('vpsllq', 'x11', 'x8', 5); self.e('vpxor', 'x12', 'x11', 'x8')
		self.e('vpsllq', 'x11', 'x11', 1); self.e('vpxor', 'x11', 'x11', 'x12')
		self.e('vpsllq', 'x11', 'x11', 57)
		self.e('vpslldq', 'x12', 'x11', 8); self.e('vpxor', 'x8', 'x8', 'x12')
		self.e('vpsrldq', 'x12', 'x11', 8); self.e('vpxor', 'x9', 'x9', 'x12')
		self.e('vpxor', 'x9', 'x9', 'x8')
		self.e('vpsrlq', 'x11', 'x8', 1); self.e('vpxor', 'x12', 'x11', 'x8')
		self.e('vpsrlq', 'x11', 'x11', 5); self.e('vpxor', 'x11', 'x11', 'x12')
		self.e('vpsrlq', 'x11', 'x11', 1)
		self.e('vpxor', 'x15', 'x9', 'x11')
		self.e('vpsrldq', 'x13', 'x15', 8)
		# Следующая восьмёрка
		for p in ('hash', 'src', 'dst'): self.e('addq', p, 128)
		self.e('decq_jnz', 'cnt', '1b')
		# Накопитель обратно в порядок байтов GCM
		self.e('vmovdqu', 'x11', self.m('cst', 128))
		self.e('vpshufb', 'x15', 'x15', 'x11')
		self.e('vmovdqu_s', self.m('tab', 32), 'x15')
		self.e('vzeroupper')

def x86_operand(o):
	if isinstance(o, tuple):
		return '%d(%%[%s])' % (o[2], o[1])
	if o[0] == 'x': return '%%xmm' + o[1:]
	return '%[' + o + ']'

def render_x86(op):
	n = op[0]
	if n == 'label': return op[1] + ':'
	if n == 'jmp': return 'jmp ' + op[1]
	if n == 'cmpb_ja': return 'cmpb $%d, %%b[%s]\\n\\t" "ja %s' % (op[2], op[1], op[3])
	if n == 'decq_jnz': return 'decq %%[%s]\\n\\t" "jnz %s' % (op[1], op[2])
	if n == 'vzeroupper': return 'vzeroupper'
	if n == 'prefetch': return ('prefetchw %s' if op[1][1] == 'dst' else 'prefetcht0 %s') % x86_operand(op[1])
	if n == 'vmovdqu': return 'vmovdqu %s, %s' % (x86_operand(op[2]), x86_operand(op[1]))
	if n == 'vmovdqu_s': return 'vmovdqu %s, %s' % (x86_operand(op[2]), x86_operand(op[1]))
	if n == 'vmovq': return 'vmovq %s, %s' % (x86_operand(op[2]), x86_operand(op[1]))
	if n == 'movbe': return 'movbe %s, %%[%s]' % (x86_operand(op[2]), op[1])
	if n == 'movbe32': return 'movbe %s, %%k[%s]' % (x86_operand(op[2]), op[1])
	if n == 'movq_s': return 'movq %%[%s], %s' % (op[2], x86_operand(op[1]))
	if n == 'movq': return 'movq %s, %%[%s]' % (x86_operand(op[2]), op[1])
	if n == 'leaq': return 'leaq %d(%%[%s]), %%[%s]' % (op[3], op[2], op[1])
	if n == 'leal': return 'leal %d(%%k[%s]), %%k[%s]' % (op[3], op[2], op[1])
	if n == 'bswapl': return 'bswapl %%k[%s]' % op[1]
	if n == 'addl': return 'addl $%d, %%k[%s]' % (op[2], op[1])
	if n == 'addq': return 'addq $%d, %%[%s]' % (op[2], op[1])
	if n == 'vpinsrd': return 'vpinsrd $3, %%k[%s], %s, %s' % (op[3], x86_operand(op[2]), x86_operand(op[1]))
	if n == 'vpclmulqdq': return 'vpclmulqdq $0x%02x, %s, %s, %s' % (op[1], x86_operand(op[4]), x86_operand(op[3]), x86_operand(op[2]))
	if n in ('vpslldq', 'vpsrldq', 'vpsllq', 'vpsrlq'): return '%s $%d, %s, %s' % (n, op[3], x86_operand(op[2]), x86_operand(op[1]))
	if n in ('vpxor', 'vpaddd', 'vpshufb', 'vaesenc', 'vaesenclast'): return '%s %s, %s, %s' % (n, x86_operand(op[3]), x86_operand(op[2]), x86_operand(op[1]))
	raise Exception('x86: неизвестная команда ' + n)

# ---------- ядро AArch64 ----------
# Кадр [tab]: 0 основание счётчика, 16 число средних кругов, 32 накопитель
# Постоянные [cst]: 0 шаг счётчика в старшем байте четвёртого слова, 16 многочлен x^7 + x^2 + x + 1 в обоих словах
ARM_CONSTANTS = ([0] * 15 + [1]) + ([0x87] + [0] * 7) * 2
assert len(ARM_CONSTANTS) == 32
ARM_FRAME = 48

class Arm:
	def __init__(self, sha3=False):
		self.sha3 = sha3
		self.ins = []
	def e(self, *op):
		self.ins.append(op)
	def m(self, base, off):
		return ('m', base, off)
	def round(self, keyoff, base='keys'):
		self.e('ldr', 'v8', self.m(base, keyoff))
		for i in range(8):
			self.e('aese', 'v%d' % i, 'v8')
			self.e('aesmc', 'v%d' % i, 'v%d' % i)
	def hash(self, i, slot):
		# Блок i отражается, сумма половин под Карацубу, произведения на степень i: младшие, старшие, средние -
		# в регистры пары (13…15 у первого блока пары, 25, 26, 29 у второго), суммы копятся парами
		self.e('ldr', 'v9', self.m('hash', 16 * i))
		self.e('rbit', 'v9', 'v9')
		if i == 0: self.e('eor', 'v9', 'v9', 'v28')
		self.e('ext', 'v10', 'v9', 'v9', 8)
		self.e('eor', 'v10', 'v10', 'v9')
		self.e('ldr', 'v11', self.m('pow', 24 * i))
		self.e('ldr', 'v12', self.m('pow', 24 * i + 8))
		if slot == 'first':
			self.e('pmull', 'v16', 'v9', 'v11'); self.e('pmull2', 'v17', 'v9', 'v11'); self.e('pmull2', 'v18', 'v10', 'v12')
			return
		a = ('v13', 'v14', 'v15') if slot == 'a' else ('v25', 'v26', 'v29')
		self.e('pmull', a[0], 'v9', 'v11'); self.e('pmull2', a[1], 'v9', 'v11'); self.e('pmull2', a[2], 'v10', 'v12')
		if slot == 'b':
			for k, s_ in enumerate(('v16', 'v17', 'v18')):
				if self.sha3: self.e('eor3', s_, s_, ('v13', 'v14', 'v15')[k], a[k])
				else: self.e('eor', s_, s_, ('v13', 'v14', 'v15')[k]); self.e('eor', s_, s_, a[k])
	def reduce(self, step):
		# Приведение сумм прошлой восьмёрки (19 младшие, 20 старшие, 21 средние) в накопитель 28 пятью шагами
		if step == 1:
			# Поправка Карацубы
			if self.sha3: self.e('eor3', 'v21', 'v21', 'v19', 'v20')
			else: self.e('eor', 'v21', 'v21', 'v19'); self.e('eor', 'v21', 'v21', 'v20')
		elif step == 2:
			# Раздача средних по половинам
			self.e('ext', 'v30', 'v27', 'v21', 8); self.e('eor', 'v19', 'v19', 'v30')
			self.e('ext', 'v31', 'v21', 'v27', 8); self.e('eor', 'v20', 'v20', 'v31')
		elif step == 3:
			# Старшая половина на многочлен по словам
			self.e('pmull', 'v30', 'v20', 'v22'); self.e('pmull2', 'v31', 'v20', 'v22')
		elif step == 4:
			self.e('ext', 'v20', 'v27', 'v31', 8)
			if self.sha3: self.e('eor3', 'v19', 'v19', 'v30', 'v20')
			else: self.e('eor', 'v19', 'v19', 'v30'); self.e('eor', 'v19', 'v19', 'v20')
			# Остаток приведения старшего слова, ушедший за поле, приводится ещё раз
			self.e('pmull2', 'v31', 'v31', 'v22')
		else:
			self.e('eor', 'v28', 'v19', 'v31')
	def counters(self):
		# Счётчики восьмёрки от основания цепочкой сложений с единицей, пока младший байт не переполняется, иначе по одному через скаляр
		self.e('and', 't0', 'tail', 0xFF)
		self.e('cmp_bhi', 't0', 0xF7, '4f')
		self.e('add4s', 'v0', 'v23', 'v24')
		for i in range(1, 8): self.e('add4s', 'v%d' % i, 'v%d' % (i - 1), 'v24')
		self.e('b', '5f')
		self.e('label', '4')
		for i in range(8):
			self.e('addw', 't1', 'tail', i + 1)
			self.e('rev', 't1', 't1')
			self.e('mov', 'v%d' % i, 'v23')
			self.e('ins', 'v%d' % i, 't1')
		self.e('label', '5')
		self.e('mov', 'v23', 'v7')
		self.e('addw', 'tail', 'tail', 8)
	def build(self):
		# Пролог: многочлен, шаг, ноль, основание и его младшее слово числом, накопитель отражённый как прошлые суммы
		self.e('ldr', 'v22', self.m('cst', 16))
		self.e('ldr', 'v24', self.m('cst', 0))
		self.e('movi', 'v27', 0)
		self.e('ldr', 'v23', self.m('tab', 0))
		self.e('ldrw', 'tail', self.m('tab', 12))
		self.e('rev', 'tail', 'tail')
		self.e('ldr', 'v28', self.m('tab', 32))
		self.e('rbit', 'v28', 'v28')
		self.e('mov', 'v19', 'v28'); self.e('movi', 'v20', 0); self.e('mov', 'v21', 'v28')
		self.e('label', '1')
		self.counters()
		# Круги с нулевого по седьмой: хеш блоков с седьмого по первый парами с приведением прошлой восьмёрки, нулевой блок с накопителем последним
		plan = [(7, 'first', None), (6, 'a', 1), (5, 'b', 2), (4, 'a', 3), (3, 'b', 4), (2, 'a', 5), (1, 'b', None), (0, 'a', None)]
		for r, (blk, slot, red) in enumerate(plan):
			self.round(16 * r)
			self.hash(blk, slot)
			if red is not None: self.reduce(red)
		# Нулевой блок без пары: его произведения складываются порознь
		for k, s_ in enumerate(('v16', 'v17', 'v18')): self.e('eor', s_, s_, ('v13', 'v14', 'v15')[k])
		# Круги с восьмого до предпоследнего
		self.e('addx', 'kp', 'keys', 128)
		self.e('ldrx', 'n', self.m('tab', 16))
		self.e('label', '3')
		self.round(0, 'kp')
		self.e('addx', 'kp', 'kp', 16)
		self.e('subs_bne', 'n', '3b')
		# Последний круг, ключ итога, наложение гаммы и запись
		self.e('ldr', 'v8', self.m('kp', 0))
		for i in range(8): self.e('aese', 'v%d' % i, 'v8')
		self.e('ldr', 'v8', self.m('kp', 16))
		for i in range(8):
			t = 'v%d' % (9 + i % 7)
			self.e('ldr', t, self.m('src', 16 * i))
			if self.sha3: self.e('eor3', 'v%d' % i, 'v%d' % i, 'v8', t)
			else: self.e('eor', 'v%d' % i, 'v%d' % i, 'v8'); self.e('eor', 'v%d' % i, 'v%d' % i, t)
			self.e('str', self.m('dst', 16 * i), 'v%d' % i)
		# Суммы восьмёрки становятся прошлыми
		self.e('mov', 'v19', 'v16'); self.e('mov', 'v20', 'v17'); self.e('mov', 'v21', 'v18')
		for p in ('hash', 'src', 'dst'): self.e('addx', p, p, 128)
		self.e('subs_bne', 'cnt', '1b')
		# Приведение последней восьмёрки, накопитель обратно в порядок GCM, основание счётчика
		for step in range(1, 6): self.reduce(step)
		self.e('rbit', 'v28', 'v28')
		self.e('str', self.m('tab', 32), 'v28')
		self.e('str', self.m('tab', 0), 'v23')

def arm_mem(o, kind='q'):
	base, off = o[1], o[2]
	if kind == 'q' and (off % 16) != 0:
		return 'ldur', '[%%[%s], #%d]' % (base, off)
	return ('ldr' if kind else 'str'), ('[%%[%s], #%d]' % (base, off) if off else '[%%[%s]]' % base)

def render_arm(op):
	n = op[0]
	if n == 'label': return op[1] + ':'
	if n == 'b': return 'b ' + op[1]
	if n == 'cmp_bhi': return 'cmp %%w[%s], #%d\\n\\t" "b.hi %s' % (op[1], op[2], op[3])
	if n == 'subs_bne': return 'subs %%[%s], %%[%s], #1\\n\\t" "b.ne %s' % (op[1], op[1], op[2])
	if n == 'ldr':
		ins, mem = arm_mem(op[2]); return '%s q%s, %s' % (ins, op[1][1:], mem)
	if n == 'str':
		_, mem = arm_mem(op[1], None); return 'str q%s, %s' % (op[2][1:], mem)
	if n == 'ldrw': return 'ldr %%w[%s], [%%[%s], #%d]' % (op[1], op[2][1], op[2][2])
	if n == 'ldrx': return 'ldr %%[%s], [%%[%s], #%d]' % (op[1], op[2][1], op[2][2])
	if n == 'rev': return 'rev %%w[%s], %%w[%s]' % (op[1], op[2])
	if n == 'and': return 'and %%w[%s], %%w[%s], #%d' % (op[1], op[2], op[3])
	if n == 'addw': return 'add %%w[%s], %%w[%s], #%d' % (op[1], op[2], op[3])
	if n == 'addx': return 'add %%[%s], %%[%s], #%d' % (op[1], op[2], op[3])
	if n == 'movi': return 'movi %s.16b, #%d' % (op[1], op[2])
	if n == 'mov': return 'mov %s.16b, %s.16b' % (op[1], op[2])
	if n == 'ins': return 'mov %s.s[3], %%w[%s]' % (op[1], op[2])
	if n == 'add4s': return 'add %s.4s, %s.4s, %s.4s' % (op[1], op[2], op[3])
	if n == 'eor': return 'eor %s.16b, %s.16b, %s.16b' % (op[1], op[2], op[3])
	if n == 'eor3': return 'eor3 %s.16b, %s.16b, %s.16b, %s.16b' % (op[1], op[2], op[3], op[4])
	if n == 'ext': return 'ext %s.16b, %s.16b, %s.16b, #%d' % (op[1], op[2], op[3], op[4])
	if n == 'rbit': return 'rbit %s.16b, %s.16b' % (op[1], op[2])
	if n == 'aese': return 'aese %s.16b, %s.16b' % (op[1], op[2])
	if n == 'aesmc': return 'aesmc %s.16b, %s.16b' % (op[1], op[2])
	if n == 'pmull': return 'pmull %s.1q, %s.1d, %s.1d' % (op[1], op[2], op[3])
	if n == 'pmull2': return 'pmull2 %s.1q, %s.2d, %s.2d' % (op[1], op[2], op[3])
	raise Exception('arm: неизвестная команда ' + n)

# ---------- интерпретатор ----------
class VM:
	def __init__(self, ins, render, exec_op):
		self.ins = ins
		self.labels = {}
		for i, op in enumerate(ins):
			if op[0] == 'label': self.labels.setdefault(op[1], []).append(i)
		self.exec_op = exec_op
		self.v = {}
		self.g = {}
		self.mem = {}
	def target(self, pc, ref):
		name, way = ref[:-1], ref[-1]
		cands = self.labels[name]
		if way == 'b': return max(i for i in cands if i < pc)
		return min(i for i in cands if i > pc)
	def load(self, o, size):
		region, off = self.g[o[1]]
		return bytes(self.mem[region][off + o[2]:off + o[2] + size])
	def store(self, o, data):
		region, off = self.g[o[1]]
		self.mem[region][off + o[2]:off + o[2] + len(data)] = data
	def run(self):
		pc = 0
		steps = 0
		while pc < len(self.ins):
			op = self.ins[pc]
			jump = self.exec_op(self, op)
			if jump is not None: pc = self.target(pc, jump)
			else: pc += 1
			steps += 1
			assert steps < 10000000

def vec(v): return int.from_bytes(v, 'little')
def bvec(x): return (x & M128).to_bytes(16, 'little')

def exec_x86(vm, op):
	n = op[0]
	V, G = vm.v, vm.g
	def src(o):
		return vm.load(o, 16) if isinstance(o, tuple) else V[o]
	if n in ('label', 'vzeroupper', 'prefetch'): return None
	if n == 'jmp': return op[1]
	if n == 'cmpb_ja': return op[3] if (G[op[1]] & 0xFF) > op[2] else None
	if n == 'decq_jnz':
		G[op[1]] = (G[op[1]] - 1) & M64
		return op[2] if G[op[1]] != 0 else None
	if n == 'vmovdqu': V[op[1]] = src(op[2]); return
	if n == 'vmovdqu_s': vm.store(op[1], V[op[2]]); return
	if n == 'vmovq': V[op[1]] = vm.load(op[2], 8) + bytes(8); return
	if n == 'movbe': G[op[1]] = int.from_bytes(vm.load(op[2], 8), 'big'); return
	if n == 'movbe32': G[op[1]] = int.from_bytes(vm.load(op[2], 4), 'big'); return
	if n == 'movq_s': vm.store(op[1], G[op[2]].to_bytes(8, 'little')); return
	if n == 'movq': G[op[1]] = int.from_bytes(vm.load(op[2], 8), 'little'); return
	if n == 'leaq': G[op[1]] = (G[op[2]][0], G[op[2]][1] + op[3]); return
	if n == 'leal': G[op[1]] = (G[op[2]] + op[3]) & M32; return
	if n == 'bswapl': G[op[1]] = int.from_bytes(G[op[1]].to_bytes(4, 'little'), 'big'); return
	if n == 'addl': G[op[1]] = (G[op[1]] + op[2]) & M32; return
	if n == 'addq':
		g = G[op[1]]
		G[op[1]] = (g[0], g[1] + op[2]) if isinstance(g, tuple) else (g + op[2]) & M64
		return
	if n == 'vpinsrd': V[op[1]] = V[op[2]][:12] + (G[op[3]] & M32).to_bytes(4, 'little'); return
	if n == 'vpclmulqdq':
		a = int.from_bytes(V[op[3]][8 * (op[1] & 1):8 * (op[1] & 1) + 8], 'little')
		b = src(op[4]); b = int.from_bytes(b[8 * ((op[1] >> 4) & 1):8 * ((op[1] >> 4) & 1) + 8], 'little')
		V[op[2]] = bvec(clmul(a, b)); return
	if n == 'vpslldq': V[op[1]] = (bytes(op[3]) + V[op[2]])[:16]; return
	if n == 'vpsrldq': V[op[1]] = (V[op[2]] + bytes(16))[op[3]:op[3] + 16]; return
	if n == 'vpsllq': V[op[1]] = b''.join(((int.from_bytes(V[op[2]][8 * l:8 * l + 8], 'little') << op[3]) & M64).to_bytes(8, 'little') for l in range(2)); return
	if n == 'vpsrlq': V[op[1]] = b''.join((int.from_bytes(V[op[2]][8 * l:8 * l + 8], 'little') >> op[3]).to_bytes(8, 'little') for l in range(2)); return
	if n == 'vpxor': V[op[1]] = xor(V[op[2]], src(op[3])); return
	if n == 'vpaddd':
		a, b = V[op[2]], src(op[3])
		V[op[1]] = b''.join(((int.from_bytes(a[4 * l:4 * l + 4], 'little') + int.from_bytes(b[4 * l:4 * l + 4], 'little')) & M32).to_bytes(4, 'little') for l in range(4)); return
	if n == 'vpshufb':
		a, mask = V[op[2]], src(op[3])
		V[op[1]] = bytes(0 if (mask[i] & 0x80) else a[mask[i] & 15] for i in range(16)); return
	if n == 'vaesenc': V[op[1]] = aesenc(V[op[2]], src(op[3])); return
	if n == 'vaesenclast': V[op[1]] = aesenclast(V[op[2]], src(op[3])); return
	raise Exception('x86: не исполняется ' + n)

def exec_arm(vm, op):
	n = op[0]
	V, G = vm.v, vm.g
	if n == 'label': return None
	if n == 'b': return op[1]
	if n == 'cmp_bhi': return op[3] if G[op[1]] > op[2] else None
	if n == 'subs_bne':
		G[op[1]] = (G[op[1]] - 1) & M64
		return op[2] if G[op[1]] != 0 else None
	if n == 'ldr': V[op[1]] = vm.load(op[2], 16); return
	if n == 'str': vm.store(op[1], V[op[2]]); return
	if n == 'ldrw': G[op[1]] = int.from_bytes(vm.load(op[2], 4), 'little'); return
	if n == 'ldrx': G[op[1]] = int.from_bytes(vm.load(op[2], 8), 'little'); return
	if n == 'rev': G[op[1]] = int.from_bytes(G[op[2]].to_bytes(4, 'little'), 'big'); return
	if n == 'and': G[op[1]] = G[op[2]] & op[3]; return
	if n == 'addw': G[op[1]] = (G[op[2]] + op[3]) & M32; return
	if n == 'addx':
		g = G[op[2]]
		G[op[1]] = (g[0], g[1] + op[3]) if isinstance(g, tuple) else (g + op[3]) & M64
		return
	if n == 'movi': V[op[1]] = bytes([op[2]] * 16); return
	if n == 'mov': V[op[1]] = V[op[2]]; return
	if n == 'ins': V[op[1]] = V[op[1]][:12] + (G[op[2]] & M32).to_bytes(4, 'little'); return
	if n == 'add4s':
		a, b = V[op[2]], V[op[3]]
		V[op[1]] = b''.join(((int.from_bytes(a[4 * l:4 * l + 4], 'little') + int.from_bytes(b[4 * l:4 * l + 4], 'little')) & M32).to_bytes(4, 'little') for l in range(4)); return
	if n == 'eor': V[op[1]] = xor(V[op[2]], V[op[3]]); return
	if n == 'eor3': V[op[1]] = xor(xor(V[op[2]], V[op[3]]), V[op[4]]); return
	if n == 'ext': V[op[1]] = (V[op[2]] + V[op[3]])[op[4]:op[4] + 16]; return
	if n == 'rbit': V[op[1]] = bytes(rbit(b) for b in V[op[2]]); return
	if n == 'aese': V[op[1]] = aese(V[op[1]], V[op[2]]); return
	if n == 'aesmc': V[op[1]] = aesmc(V[op[2]]); return
	if n == 'pmull':
		V[op[1]] = bvec(clmul(int.from_bytes(V[op[2]][:8], 'little'), int.from_bytes(V[op[3]][:8], 'little'))); return
	if n == 'pmull2':
		V[op[1]] = bvec(clmul(int.from_bytes(V[op[2]][8:], 'little'), int.from_bytes(V[op[3]][8:], 'little'))); return
	raise Exception('arm: не исполняется ' + n)

def run(arch, ins, schedule, counter, pow_table, acc, hash_data, source, chunks):
	vm = VM(ins, None, exec_x86 if arch == 'x86' else exec_arm)
	rounds = len(schedule) - 1
	frame = bytearray(X86_FRAME if arch == 'x86' else ARM_FRAME)
	frame[0:16] = counter
	frame[16:24] = (rounds - 9).to_bytes(8, 'little')
	frame[32:48] = acc
	vm.mem = {'keys': bytearray(b''.join(schedule)), 'pow': bytearray(pow_table), 'tab': frame,
		'cst': bytearray(X86_CONSTANTS if arch == 'x86' else ARM_CONSTANTS), 'hash': bytearray(hash_data), 'src': bytearray(source), 'dst': bytearray(len(source))}
	for name in ('keys', 'pow', 'tab', 'cst', 'hash', 'src', 'dst'): vm.g[name] = (name, 0)
	vm.g['cnt'] = chunks
	for name in ('kp', 'n', 't0', 't1', 'tail'): vm.g[name] = 0
	regs = ['x%d' % i for i in range(16)] if arch == 'x86' else ['v%d' % i for i in range(32)]
	for r in regs: vm.v[r] = bytes(16)
	vm.run()
	return bytes(vm.mem['dst']), bytes(frame[32:48]), bytes(frame[0:16])

def reference(schedule, counter, H, acc, hash_data, source, chunks):
	word = int.from_bytes(counter[12:16], 'big')
	out = bytearray()
	for j in range(8 * chunks):
		ctr = counter[:12] + ((word + j + 1) & M32).to_bytes(4, 'big')
		out += xor(encrypt(schedule, ctr), source[16 * j:16 * j + 16])
	y = int.from_bytes(acc, 'big')
	for j in range(8 * chunks):
		y = gf_mult(y ^ int.from_bytes(hash_data[16 * j:16 * j + 16], 'big'), H)
	final = counter[:12] + ((word + 8 * chunks) & M32).to_bytes(4, 'big')
	return bytes(out), y.to_bytes(16, 'big'), final

def selfcheck(arch, ins):
	rng = random.Random(43 if arch == 'x86' else 44)
	for trial in range(36):
		key = bytes(rng.getrandbits(8) for _ in range((16, 24, 32)[trial % 3]))
		schedule = expand(key)
		H = int.from_bytes(encrypt(schedule, bytes(16)), 'big')
		counter = bytearray(rng.getrandbits(8) for _ in range(16))
		chunks = 1 + (trial % 3)
		# Каждая четвёртая проба - перенос через младший байт, каждая двенадцатая - через все четыре
		if trial % 4 == 3: counter[15] = 0xF8 + rng.randrange(8)
		if trial % 12 == 11: counter[12:16] = b'\xFF\xFF\xFF\xF9'
		acc = bytes(rng.getrandbits(8) for _ in range(16))
		hash_data = bytes(rng.getrandbits(8) for _ in range(128 * chunks))
		source = bytes(rng.getrandbits(8) for _ in range(128 * chunks))
		got = run(arch, ins, schedule, bytes(counter), powers(H, arch), acc, hash_data, source, chunks)
		want = reference(schedule, bytes(counter), H, acc, hash_data, source, chunks)
		if got[0] != want[0]: raise Exception('%s: расходится итог (проба %d, кругов %d, восьмёрок %d)' % (arch, trial, len(schedule) - 1, chunks))
		if got[1] != want[1]: raise Exception('%s: расходится накопитель (проба %d, кругов %d, восьмёрок %d)' % (arch, trial, len(schedule) - 1, chunks))
		if got[2] != want[2]: raise Exception('%s: расходится счётчик (проба %d): %s при %s' % (arch, trial, got[2].hex(), want[2].hex()))

# ---------- текст заголовка ----------
def asmtext(lines, indent):
	return '\n'.join('%s"%s\\n\\t"' % (indent, line) for line in lines)

HEADER = """/**
 * @file gcm.hpp
 * @date 2026-09-28
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
 * @brief Сшитые ядра AES-CTR + GHASH на встроенном ассемблере x86-64 и AArch64
 *
 * @details Файл порождён сценарием tools/cipher/gcm.py и руками не правится: правки вносятся в
 *          сценарий, который исполняет порождённый список команд на случайных ключах, счётчиках,
 *          накопителях и данных и сличает с переносимыми AES и GHASH до выдачи текста. Восьмёрка
 *          блоков счётчика идёт кругами AES разом, между кругами с первого по восьмой хешируется по
 *          блоку прежней восьмёрки, произведения копятся на восьмёрку и приводятся один раз; счётчики
 *          собираются сложениями в векторе, а на переносе через младший байт - по одному через
 *          скалярный регистр, оттого ход любой длины идёт одним вызовом. У x86-64 половины блока
 *          переставляются movbe через ячейки кадра (перестановки байтов делят порт с aesenc на
 *          Broadwell), четыре умножения по половинам, приведение сдвигами после записи итога; у
 *          AArch64 блоки отражаются rbit, произведение Карацубы тремя pmull, произведения пары
 *          блоков складываются в суммы разом (eor3 при расширении SHA-3), суммы прошлой восьмёрки
 *          приводятся вперемешку с произведениями текущей, блок с накопителем множится последним.
 *          Кадр даёт вызывающая сторона и затирает его после
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_CIPHER_GCM__
#define __ANTS_INTERNAL_CIPHER_GCM__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * Ядра берутся у gcc и clang на x86-64 и на AArch64 с командами AES и PMULL, разрешёнными ключами
 * сборки (признак __ARM_FEATURE_AES: у clang на процессорах Apple задан сам, у gcc и clang под Linux
 * появляется от -march=armv8-a+crypto); у прочих собирателей и архитектур остаются ветви на
 * интринсиках либо переносимый путь. Под ASan без оптимизации ядро x86-64 не берётся (признак
 * __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp: тринадцать регистров общего назначения во вставке,
 * а ASan держит адреса своего стека в регистрах); ядру AArch64 регистров хватает, и оно
 * проверяется отладочной сборкой
 */
#if ((defined(__x86_64__) && !defined(__ANTS_ASAN_UNOPTIMIZED__)) || (defined(__aarch64__) && defined(__ARM_FEATURE_AES))) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия сшитого ядра на ассемблере
	 */
	#define __ANTS_GCM_STITCH__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён модулей шифрования
		 *
		 */
		namespace cipher {
			/**
			 * @brief Пространство имён ядер на ассемблере
			 *
			 */
			namespace kernel {
				/**
				 * @brief Размер кадра сшитого ядра в байтах
				 */
				static constexpr size_t FRAME = %d;
"""

FOOTER = """			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_CIPHER_GCM__
"""

DOC = """				/**
				 * @brief Метод сшитого хода восьмёрок блоков: гамма счётчика AES и хеш прежних восьмёрок %s
				 *
				 * @param keys        расписание ключа шифрования
				 * @param rounds      число кругов: 10, 12 либо 14
				 * @param counter     блок счётчика: младшие четыре байта растут от старшего байта, первый блок - плюс один; продвигается на пройденные блоки
				 * @param powers      степени ключа хеша от восьмой к первой по 24 байта: %s
				 * @param accumulator накопитель хеша в порядке байтов GCM, заменяемый итогом
				 * @param frame       кадр ядра в FRAME байтов, выровненный на 16
				 * @param hash        хешируемые блоки: прежняя восьмёрка итога при зашифровании, исходные данные при расшифровании
				 * @param source      исходные данные
				 * @param result      место под итог
				 * @param count       число восьмёрок: не меньше одной
				 *
				 */
"""

def kernel_cpp(arch, ins, rename=None):
	if arch == 'x86':
		consts = X86_CONSTANTS; name = 'stitchX86'; brief = 'ядром x86-64 с кодировкой VEX (AVX, PCLMULQDQ, AES-NI, MOVBE)'
		note = 'сдвинутые на разряд с переставленными байтами'
		regs = ', '.join('"xmm%d"' % i for i in range(16))
		lines = [render_x86(op) for op in ins]
	else:
		consts = ARM_CONSTANTS; name = 'stitchArm'; brief = 'ядром AArch64 (AES и PMULL расширения crypto%s)' % (', eor3 расширения SHA-3' if any(op[0] == 'eor3' for op in ins) else '')
		note = 'с отражёнными разрядами байтов и суммой половин третьим словом'
		regs = ', '.join('"v%d"' % i for i in range(32))
		lines = [render_arm(op) for op in ins]
	rows = []
	for i in range(0, len(consts), 16):
		rows.append('\t\t\t\t\t\t' + ', '.join(str(v) for v in consts[i:i + 16]) + (',' if i + 16 < len(consts) else ''))
	if rename is not None: name = rename
	head = DOC % (brief, note)
	head += '\t\t\t\tstatic void %s(const uint8_t * keys, const size_t rounds, uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, uint8_t * frame, const uint8_t * hash, const uint8_t * source, uint8_t * result, size_t count) noexcept {\n' % name
	head += '\t\t\t\t\t// Шаги счётчика в старшем байте четвёртого слова%s\n' % (', маска перестановки байтов' if arch == 'x86' else ', многочлен приведения')
	head += '\t\t\t\t\talignas(16) static const uint8_t CONSTANTS[%d] = {\n%s\n\t\t\t\t\t};\n' % (len(consts), '\n'.join(rows))
	head += '\t\t\t\t\t// Число кругов с девятого до предпоследнего\n\t\t\t\t\tconst uint64_t middle = static_cast <uint64_t> (rounds - 9);\n'
	head += '\t\t\t\t\t// Записываем в кадр основание счётчика, число средних кругов и накопитель\n'
	head += '\t\t\t\t\t::memcpy(frame, counter, 16);\n\t\t\t\t\t::memcpy(frame + 16, &middle, sizeof(middle));\n\t\t\t\t\t::memcpy(frame + 32, accumulator, 16);\n'
	head += '\t\t\t\t\t// Позиция ключа круга, число средних кругов, половины блока и младшее слово счётчика\n'
	head += '\t\t\t\t\tconst uint8_t * kp = nullptr;\n\t\t\t\t\tsize_t n = 0;\n\t\t\t\t\tuint64_t t0 = 0, t1 = 0, tail = 0;\n'
	head += '\t\t\t\t\t__asm__ __volatile__(\n'
	tail = ('\n\t\t\t\t\t\t: [src] "+r" (source), [dst] "+r" (result), [hash] "+r" (hash), [cnt] "+r" (count), [kp] "=&r" (kp), [n] "=&r" (n), [t0] "=&r" (t0), [t1] "=&r" (t1), [tail] "=&r" (tail)\n'
		'\t\t\t\t\t\t: [keys] "r" (keys), [pow] "r" (powers), [tab] "r" (frame), [cst] "r" (CONSTANTS)\n'
		'\t\t\t\t\t\t: %s, "cc", "memory");\n' % regs)
	tail += '\t\t\t\t\t// Забираем продвинутый счётчик и накопитель\n\t\t\t\t\t::memcpy(counter, frame, 16);\n\t\t\t\t\t::memcpy(accumulator, frame + 32, 16);\n\t\t\t\t}\n'
	return head + asmtext(lines, '\t\t\t\t\t\t') + tail

def header():
	parts = [HEADER % max(X86_FRAME, ARM_FRAME)]
	k = X86(); k.build(); selfcheck('x86', k.ins)
	print('сходимость сшитого ядра x86-64: команд %d' % len(k.ins), file=sys.stderr)
	parts.append('\t\t\t\t#if defined(__x86_64__)\n')
	parts.append(kernel_cpp('x86', k.ins))
	parts.append('\t\t\t\t#elif defined(__ARM_FEATURE_SHA3)\n')
	k = Arm(sha3=True); k.build(); selfcheck('arm', k.ins)
	print('сходимость сшитого ядра AArch64 с eor3: команд %d' % len(k.ins), file=sys.stderr)
	parts.append(kernel_cpp('arm', k.ins))
	parts.append('\t\t\t\t#else\n')
	k = Arm(); k.build(); selfcheck('arm', k.ins)
	print('сходимость сшитого ядра AArch64: команд %d' % len(k.ins), file=sys.stderr)
	parts.append(kernel_cpp('arm', k.ins))
	parts.append('\t\t\t\t#endif\n')
	parts.append(FOOTER)
	return ''.join(parts)

if __name__ == '__main__':
	sys.stdout.write(header())
