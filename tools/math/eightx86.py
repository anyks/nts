#!/usr/bin/env python3
#
# Порождатель ядер на восемь слов для x86-64 без расширений (mulq) для src/internal/math/kernels.hpp:
# полное произведение 8×8 и полный квадрат столбцами (comba) в шестнадцать слов памяти и свёртка
# произведения по модулю вида 2^512 - c с условным вычитанием модуля.
#
# Устройство. Произведение и квадрат: три накопителя столбца (c0, c1, c2) - произведение слова столбца
# прибавляется тремя флаговыми командами (add, adc, adc $0), готовое младшее слово столбца уходит в
# память, роли накопителей сдвигаются переименованием у порождателя (без команд пересылки), новый
# старший обнуляется xor вне цепочки переносов. У квадрата произведение разных слов удваивается до
# накопления (add rax, rax; adc rdx, rdx) с переносом удвоения в третий накопитель, квадраты слов
# диагонали прибавляются как есть: удвоение в цепочке накопителей (прибавление дважды) стоило на
# Xeon E5-2630 v4 54 нс против 44 у удвоения произведения, треугольник с проходами удвоения и
# диагонали - 50. Регистров у произведения и квадрата восемь: rax, rdx, три накопителя и три
# указателя; слова сомножителей - операнды mulq в памяти. Свёртка: младшая половина в восьми
# регистрах, старшая умножается на хвост по слову с переносом в регистре (сперва накопленное, потом
# перенос), выход за сетку (не больше c при c < 2^32) сворачивается вторым произведением в слово;
# значение меньше 2^512 + c² и не меньше модуля ровно тогда, когда прибавление хвоста выходит за
# 2^512 либо разряд 2^512 уже стоит - выбор cmovnc из сохранённой в памяти копии; итог - операнды
# в памяти (при встраивании в формулы точки лежит в кадре). Свёртка по модулю 2^511 + c остаётся
# на C++ (foldplus).
#
# Правки вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый список команд на
# случайных числах и сличает с точной арифметикой Python - порождение отказывает без сходимости.
#
# Запуск: python3 tools/math/eightx86.py > eight.inc, затем текст переносится в
# src/internal/math/kernels.hpp на место ядер product8, square8 и foldminus8 ветви x86-64
import random, sys

M64 = 0xFFFFFFFFFFFFFFFF
W = 8

class Kernel:
	def __init__(self):
		self.ins = []
	def e(self, *op):
		self.ins.append(op)

def product(k):
	c = ['r8', 'r9', 'r10']
	k.e('xor', c[1]); k.e('xor', c[2])
	first = True
	for col in range(2 * W - 1):
		items = [(i, col - i) for i in range(W) if 0 <= col - i < W]
		for (i, j) in items:
			k.e('mov', 'rax', ('m', 'a', 8 * i))
			k.e('mulq', ('m', 'b', 8 * j))
			if first:
				k.e('mov', c[0], 'rax'); k.e('mov', c[1], 'rdx'); first = False
			else:
				k.e('add', c[0], 'rax'); k.e('adc', c[1], 'rdx'); k.e('adc', c[2], 0)
		k.e('store', ('m', 'r', 8 * col), c[0])
		if col < 2 * W - 2:
			k.e('xor', c[0])
			c = [c[1], c[2], c[0]]
	k.e('store', ('m', 'r', 8 * (2 * W - 1)), c[1])

def square(k):
	c = ['r8', 'r9', 'r10']
	k.e('xor', c[1]); k.e('xor', c[2])
	first = True
	for col in range(2 * W - 1):
		pairs = [(i, col - i) for i in range(W) if 0 <= col - i < W and i < col - i]
		diag = (col // 2) if (col % 2 == 0) else None
		for (i, j) in pairs:
			k.e('mov', 'rax', ('m', 'a', 8 * i))
			k.e('mulq', ('m', 'a', 8 * j))
			k.e('add', 'rax', 'rax'); k.e('adc', 'rdx', 'rdx')
			if first:
				k.e('mov', c[0], 'rax'); k.e('mov', c[1], 'rdx'); k.e('adc', c[2], 0); first = False
			else:
				k.e('adc', c[2], 0); k.e('add', c[0], 'rax'); k.e('adc', c[1], 'rdx'); k.e('adc', c[2], 0)
		if diag is not None:
			k.e('mov', 'rax', ('m', 'a', 8 * diag))
			k.e('mulq', 'rax')
			if first:
				k.e('mov', c[0], 'rax'); k.e('mov', c[1], 'rdx'); first = False
			else:
				k.e('add', c[0], 'rax'); k.e('adc', c[1], 'rdx'); k.e('adc', c[2], 0)
		k.e('store', ('m', 'r', 8 * col), c[0])
		if col < 2 * W - 2:
			k.e('xor', c[0])
			c = [c[1], c[2], c[0]]
	k.e('store', ('m', 'r', 8 * (2 * W - 1)), c[1])

def fold(k):
	R = ['r%d' % i for i in range(8, 16)]
	for i in range(W): k.e('mov', R[i], ('m', 'r', 8 * i))
	k.e('xor', 'rcx')
	for i in range(W):
		k.e('mov', 'rax', ('m', 'r', 8 * (W + i)))
		k.e('mulq', 'rbx')
		k.e('add', R[i], 'rax'); k.e('adc', 'rdx', 0)
		k.e('add', R[i], 'rcx'); k.e('adc', 'rdx', 0)
		k.e('mov', 'rcx', 'rdx')
	k.e('mov', 'rax', 'rcx'); k.e('mulq', 'rbx')
	k.e('add', R[0], 'rax')
	for i in range(1, W): k.e('adc', R[i], 0)
	k.e('adc', 'rdx', 0)
	for i in range(W): k.e('store', ('m', 'r', 8 * i), R[i])
	k.e('add', R[0], 'rbx')
	for i in range(1, W): k.e('adc', R[i], 0)
	k.e('adc', 'rdx', 0)
	k.e('neg', 'rdx')
	for i in range(W): k.e('cmovnc', R[i], ('m', 'r', 8 * i))
	for i in range(W): k.e('out', i, R[i])

# ---------- отрисовка ----------
def reg32(r):
	return r + 'd' if r[0] == 'r' and r[1:].isdigit() else 'e' + r[1:]

def operand(o):
	if isinstance(o, tuple):
		return '%d(%%[%s])' % (o[2], o[1]) if o[2] else '(%%[%s])' % o[1]
	if isinstance(o, int):
		return '$%d' % o
	return '%%' + o

def render(op):
	name = op[0]
	if name == 'xor': return 'xorl  %%%%%s, %%%%%s' % (reg32(op[1]), reg32(op[1]))
	if name == 'mov': return 'movq  %s, %s' % (operand(op[2]), operand(op[1]))
	if name == 'mulq': return 'mulq  %s' % operand(op[1])
	if name == 'add': return 'addq  %s, %s' % (operand(op[2]), operand(op[1]))
	if name == 'adc': return 'adcq  %s, %s' % (operand(op[2]), operand(op[1]))
	if name == 'store': return 'movq  %s, %s' % (operand(op[2]), operand(op[1]))
	if name == 'neg': return 'negq  %s' % operand(op[1])
	if name == 'cmovnc': return 'cmovncq %s, %s' % (operand(op[2]), operand(op[1]))
	if name == 'out': return 'movq  %s, %%[h%d]' % (operand(op[2]), op[1])
	raise Exception(name)

def render_all(ins, indent):
	out = []
	line = []
	for op in ins:
		line.append('"' + render(op) + '\\n\\t"')
		if op[0] in ('store', 'out') or len(line) >= 5:
			out.append(indent + ' '.join(line)); line = []
	if line: out.append(indent + ' '.join(line))
	return '\n'.join(out)

# ---------- интерпретатор ----------
class VM:
	def __init__(self, a, b, r, tail):
		self.r = {'rbx': tail}
		self.mem = {'a': list(a), 'b': list(b), 'r': list(r)}
		self.out = [0] * W
		self.cf = 0
	def val(self, o):
		if isinstance(o, tuple): return self.mem[o[1]][o[2] // 8]
		if isinstance(o, int): return o
		return self.r.get(o, 0)
	def run(self, ins):
		for op in ins:
			n = op[0]
			if n == 'xor': self.r[op[1]] = 0; self.cf = 0
			elif n == 'mov': self.r[op[1]] = self.val(op[2])
			elif n == 'mulq':
				p = self.r['rax'] * self.val(op[1]); self.r['rax'] = p & M64; self.r['rdx'] = p >> 64; self.cf = 1 if self.r['rdx'] else 0
			elif n == 'add':
				s = self.r[op[1]] + self.val(op[2]); self.r[op[1]] = s & M64; self.cf = s >> 64
			elif n == 'adc':
				s = self.r[op[1]] + self.val(op[2]) + self.cf; self.r[op[1]] = s & M64; self.cf = s >> 64
			elif n == 'store': self.mem[op[1][1]][op[1][2] // 8] = self.r[op[2]]
			elif n == 'neg': v = self.r[op[1]]; self.cf = 1 if v else 0; self.r[op[1]] = (0 - v) & M64
			elif n == 'cmovnc':
				if not self.cf: self.r[op[1]] = self.val(op[2])
			elif n == 'out': self.out[op[1]] = self.r[op[2]]
			else: raise Exception(n)

def words(x, n = W): return [(x >> (64 * i)) & M64 for i in range(n)]
def number(ws): return sum(w << (64 * i) for i, w in enumerate(ws))

def selfcheck(ins, kind):
	rng = random.Random(61)
	for t in range(3000):
		a = rng.getrandbits(512); b = rng.getrandbits(512)
		if t % 5 == 0: a = (1 << 512) - 1 - rng.getrandbits(3)
		if t % 7 == 0: b = (1 << 512) - 1
		if t % 11 == 0: a = rng.getrandbits(64)
		if kind == 'fold':
			tail = [569, 1, 3, 0xFFFFFFFF, 0x80000001, 0x12345][t % 6]
			p = (1 << 512) - tail
			if t % 13 == 0: a = p - 1; b = p - 1
			if t % 17 == 0: a = p - 1; b = 1
			wide = words(a * b, 2 * W)
			vm = VM([0] * W, [0] * W, wide, tail); vm.run(ins)
			got = number(vm.out); want = (a * b) % p
		else:
			vm = VM(words(a), words(b), [0] * (2 * W), 0); vm.run(ins)
			got = number(vm.mem['r']); want = a * a if kind == 'square' else a * b
		if got != want:
			sys.stderr.write('расхождение (%s) на пробе %d\n' % (kind, t)); sys.exit(1)

kp = Kernel(); product(kp); selfcheck(kp.ins, 'product')
ks = Kernel(); square(ks); selfcheck(ks.ins, 'square')
kf = Kernel(); fold(kf); selfcheck(kf.ins, 'fold')
sys.stderr.write('сходимость: произведение %d команд, квадрат %d, свёртка %d\n' % (len(kp.ins), len(ks.ins), len(kf.ins)))
ind = '\t\t\t\t\t'
print('''				/**
				 * Ядра на восемь слов для x86-64 без расширений (mulq): полное произведение 8×8 и полный
				 * квадрат столбцами (comba) в шестнадцать слов памяти и свёртка по модулю 2^512 - c;
				 * порождены сценарием tools/math/eightx86.py и сличены его интерпретатором с точной
				 * арифметикой на 3 000 пробах с краями (круг 61, 01.10.2026). Три накопителя столбца:
				 * произведение прибавляется тремя флаговыми командами, готовое младшее слово столбца
				 * уходит в память, роли накопителей сдвигаются переименованием у порождателя, старший
				 * обнуляется вне цепочки; у квадрата произведение разных слов удваивается до накопления
				 * с переносом удвоения в третий накопитель, квадраты диагонали прибавляются как есть.
				 * Регистров у произведения и квадрата восемь - rax, rdx, три накопителя и три указателя;
				 * слова сомножителей - операнды mulq в памяти. Свёртка: младшая половина в восьми
				 * регистрах, старшая умножается на хвост по слову с переносом в регистре, выход за сетку
				 * (не больше c при c < 2^32) сворачивается вторым произведением в слово, условное
				 * вычитание модуля - прибавлением хвоста с выбором cmovnc из копии в памяти; итог -
				 * операнды в памяти. Свёртка по модулю 2^511 + c остаётся на C++ (foldplus)
				 */
				/**
				 * Признак наличия ядер на восемь слов x86-64
				 */
				#define __ANTS_X86_64_KERNELS8__
				/**
				 * @brief Метод полного произведения восьми слов на восемь на ассемблере x86-64
				 *
				 * @param first  слова первого сомножителя
				 * @param second слова второго сомножителя
				 * @param result место, в которое помещаются шестнадцать слов произведения
				 *
				 */
				static __ANTS_INLINE__ void product8(const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
					__asm__ __volatile__(''')
print(render_all(kp.ins, ind))
print('''						:
						: [a] "r" (first), [b] "r" (second), [r] "r" (result)
						: "rax", "rdx", "r8", "r9", "r10", "cc", "memory"
					);
				}
				/**
				 * @brief Метод полного квадрата восьми слов на ассемблере x86-64
				 *
				 * @param value  слова числа
				 * @param result место, в которое помещаются шестнадцать слов квадрата
				 *
				 */
				static __ANTS_INLINE__ void square8(const uint64_t * value, uint64_t * result) noexcept {
					__asm__ __volatile__(''')
print(render_all(ks.ins, ind))
print('''						:
						: [a] "r" (value), [r] "r" (result)
						: "rax", "rdx", "r8", "r9", "r10", "cc", "memory"
					);
				}
				/**
				 * @brief Метод свёртки произведения шестнадцати слов по модулю вида 2^512 - c на ассемблере x86-64
				 *
				 * @param wide   шестнадцать слов произведения: младшая половина затирается копией под выбор
				 * @param tail   хвост c модуля, меньший 2^32
				 * @param result место, в которое помещаются восемь слов итога, меньшего модуля
				 *
				 */
				static __ANTS_INLINE__ void foldminus8(uint64_t * wide, const uint64_t tail, uint64_t * result) noexcept {
					__asm__ __volatile__(''')
print(render_all(kf.ins, ind))
print('''						: [h0] "=m" (result[0]), [h1] "=m" (result[1]), [h2] "=m" (result[2]), [h3] "=m" (result[3]), [h4] "=m" (result[4]), [h5] "=m" (result[5]), [h6] "=m" (result[6]), [h7] "=m" (result[7])
						: [r] "r" (wide), "b" (tail)
						: "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory"
					);
				}''')
