#!/usr/bin/env python3
#
# Порождатель квадрата Монтгомери блоками по восемь слов на встроенном ассемблере x86-64 без
# расширений BMI2 и ADX (mulq и одна цепочка переносов) для src/internal/math/mont.hpp:
# python3 tools/math/mont.py > src/internal/math/mont.hpp
#
# Устройство - решение 8 шапки integer.cpp (образец bn_sqr8x_mont OpenSSL, код свой), три прохода:
# 1 - произведения слов ниже диагонали окном накопителя из восьми регистров: треугольник блока и по
# восемь произведений на слово блока со сдвигом окна; 2 - удвоение сдвигом слов с квадратами
# диагонали; 3 - приведение по восемь рядов на блок с отложенными множителями в освободившихся словах
# накопителя и окнами остальных слов модуля на них. У mulq перенос живёт в регистре: каждое
# произведение складывается с накопленным четырьмя флаговыми командами (add, adc, add, adc), и
# ряды перекрываются переупорядочением машины; регистров четырнадцать - окно, rax, rdx, перенос
# и три указателя, счётчиков нет: шаги окна развёрнуты, а концы циклов сравниваются с памятью.
#
# Правки ядра вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый список
# команд на случайных числах и модулях и сличает с точной арифметикой Python - порождение
# отказывает, если сходимости нет.
#
import random, sys

M64 = 0xFFFFFFFFFFFFFFFF

# ---------- ядро ----------
class Kernel:
	def __init__(self):
		self.ins = []
		self.labels = 0
	def e(self, *op):
		self.ins.append(op)
	def label(self):
		self.labels += 1
		return str(self.labels)
	def m(self, base, off):
		return ('m', base, off)
	# Произведение rax = [src] на множитель mult (в памяти) с прибавлением к слову окна acc через перенос rbx
	def product(self, src, mult, acc, first):
		self.e('mov', 'rax', src)
		self.e('mulq', mult)
		if not first:
			self.e('add', 'rax', 'rbx'); self.e('adc', 'rdx', 0)
		self.e('add', acc, 'rax'); self.e('adc', 'rdx', 0)
		self.e('mov', 'rbx', 'rdx')
	# Прибавление накопленного к окну с отложенным переносом прошлого прибавления: перенос вносится в начало цепочки, новый откладывается
	def accumulate(self, w):
		self.e('mov', 'rax', self.m('args', 80)); self.e('neg', 'rax')
		for k in range(8): self.e('adc', w[k], self.m('rcx', 8 * k))
		self.e('sbb', 'rax', 'rax'); self.e('neg', 'rax'); self.e('store', self.m('args', 80), 'rax')
	# Внесение отложенного переноса в окно рипплем: сумма окна и переноса умещается
	def pending(self, w):
		self.e('mov', 'rax', self.m('args', 80)); self.e('neg', 'rax')
		for k in range(8): self.e('adc', w[k], 0)
	def build(self):
		w = ['r%d' % i for i in range(8, 16)]
		# Пролог: обнуление удвоенной ширины накопителя
		self.e('mov', 'rcx', self.m('args', 0)); self.e('mov', 'rsi', self.m('args', 24))
		self.e('xor', 'rax')
		L = self.label()
		self.e('label', L)
		self.e('store', self.m('rcx', 0), 'rax'); self.e('store', self.m('rcx', 8), 'rax')
		self.e('lea', 'rcx', 16); self.e('sub', 'rsi', 1); self.e('jnz', L)
		# Проход 1, блок I: rcx - окно накопителя (слова 16I …), rdi - конец блока слов числа, rsi - окно слов числа
		self.e('mov', 'rcx', self.m('args', 0)); self.e('mov', 'rdi', self.m('args', 8)); self.e('lea', 'rdi', 64)
		B = self.label()
		self.e('label', B)
		for k in range(8): self.e('mov', w[k], self.m('rcx', 8 * k))
		# Отложенный перенос окна блока - ноль
		self.e('xor', 'rax'); self.e('store', self.m('args', 80), 'rax')
		# Треугольник блока: ряд i - произведения a[j] · a[i], j > i, в слова i + j окна; после рядов 0…3 два младших слова итоговые
		base = 0
		for i in range(7):
			for j in range(i + 1, 8):
				self.product(self.m('rdi', -64 + 8 * j), self.m('rdi', -64 + 8 * i), w[i + j - base], (j == i + 1))
			if i <= 3:
				self.e('store', self.m('rcx', 8 * base), w[0]); self.e('store', self.m('rcx', 8 * base + 8), w[1])
				# Два освободившихся регистра становятся словами base + 8 и base + 9: они нулевые
				self.e('xor', w[0]); self.e('xor', w[1])
				w = w[2:] + w[:2]
				base += 2
			# Перенос ряда - в слово i + 8
			self.e('add', w[i + 8 - base], 'rbx')
		# Окно после треугольника: слова 8 … 15, слово 15 нулевое; rcx - на слово 8
		assert base == 8
		self.e('lea', 'rcx', 64)
		# Если блок последний
		self.e('cmp', 'rdi', self.m('args', 32)); E = self.label(); self.e('je', E)
		self.e('mov', 'rsi', 'rdi')
		# Окно следующих восьми слов числа: ранее накопленное прибавляется к окну
		W = self.label()
		self.e('label', W)
		self.accumulate(w)
		# Восемь произведений на слово блока, окно сдвигается на слово: младшее слово пишется, освобождённый регистр берёт перенос
		for i in range(8):
			for k in range(8):
				self.product(self.m('rsi', 8 * k), self.m('rdi', -64 + 8 * i), w[k], (k == 0))
			self.e('store', self.m('rcx', 8 * i), w[0])
			self.e('mov', w[0], 'rbx')
			w = w[1:] + w[:1]
		self.e('lea', 'rcx', 64); self.e('lea', 'rsi', 64)
		self.e('cmp', 'rsi', self.m('args', 32)); self.e('jne', W)
		# Окно блока с отложенным переносом целиком в слова 8I + count … 8I + count + 7; следующий блок: rcx = buffer + 2 · (rdi - value)
		self.pending(w)
		for k in range(8): self.e('store', self.m('rcx', 8 * k), w[k])
		self.e('mov', 'rcx', 'rdi'); self.e('sub', 'rcx', self.m('args', 8)); self.e('add', 'rcx', 'rcx'); self.e('add', 'rcx', self.m('args', 0))
		self.e('lea', 'rdi', 64)
		self.e('jmp', B)
		# Последний блок: слова 8 … 14 окна, старшее слово квадрата без удвоения - ноль
		self.e('label', E)
		for k in range(7): self.e('store', self.m('rcx', 8 * k), w[k])
		# Проход 2: удвоение сдвигом с квадратами диагонали; перенос между шагами в rcx через neg
		self.e('mov', 'rsi', self.m('args', 0)); self.e('mov', 'rdi', self.m('args', 8)); self.e('xor', 'rbx'); self.e('xor', 'rcx')
		D = self.label()
		self.e('label', D)
		self.e('mov', 'rax', self.m('rdi', 0)); self.e('mulq', 'rax'); self.e('mov', 'r12', 'rax'); self.e('mov', 'r13', 'rdx')
		self.e('mov', 'rax', self.m('rdi', 8)); self.e('mulq', 'rax'); self.e('mov', 'r14', 'rax'); self.e('mov', 'r15', 'rdx')
		for k in range(4): self.e('mov', 'r%d' % (8 + k), self.m('rsi', 8 * k))
		self.e('mov', 'rax', 'r11')
		self.e('shld', 'r11', 'r10'); self.e('shld', 'r10', 'r9'); self.e('shld', 'r9', 'r8'); self.e('shld', 'r8', 'rbx')
		self.e('mov', 'rbx', 'rax')
		self.e('neg', 'rcx')
		self.e('adc', 'r8', 'r12'); self.e('adc', 'r9', 'r13'); self.e('adc', 'r10', 'r14'); self.e('adc', 'r11', 'r15')
		self.e('sbb', 'rcx', 'rcx')
		for k in range(4): self.e('store', self.m('rsi', 8 * k), 'r%d' % (8 + k))
		self.e('lea', 'rsi', 32); self.e('lea', 'rdi', 16)
		self.e('cmp', 'rdi', self.m('args', 32)); self.e('jne', D)
		# Проход 3, блок I: rcx - окно накопителя (слова 8I …), rsi - окно слов модуля, rdi - конец отложенных множителей
		self.e('mov', 'rcx', self.m('args', 0))
		# Перенос между блоками - ноль
		self.e('xor', 'rax'); self.e('store', self.m('args', 48), 'rax')
		R = self.label()
		self.e('label', R)
		w = ['r%d' % i for i in range(8, 16)]
		for k in range(8): self.e('mov', w[k], self.m('rcx', 8 * k))
		self.e('mov', 'rsi', self.m('args', 16))
		# Отложенный перенос окна блока - ноль
		self.e('xor', 'rax'); self.e('store', self.m('args', 80), 'rax')
		# Восемь рядов: множитель ряда rax = слово 0 · inverse откладывается в слово накопителя; младшее слово окна обнуляется по построению, перенос - признак его ненулевости
		for i in range(8):
			self.e('mov', 'rax', w[0]); self.e('imul', 'rax', self.m('args', 40))
			self.e('store', self.m('rcx', 8 * i), 'rax')
			self.e('mulq', self.m('rsi', 0))
			self.e('neg', w[0]); self.e('adc', 'rdx', 0); self.e('mov', 'rbx', 'rdx')
			for k in range(1, 8):
				self.e('mov', 'rax', self.m('rcx', 8 * i)); self.e('mulq', self.m('rsi', 8 * k))
				self.e('add', 'rax', 'rbx'); self.e('adc', 'rdx', 0)
				self.e('add', w[k], 'rax'); self.e('adc', 'rdx', 0)
				self.e('mov', 'rbx', 'rdx')
			self.e('mov', w[0], 'rbx')
			w = w[1:] + w[:1]
		self.e('lea', 'rdi', 64, 'rcx'); self.e('lea', 'rcx', 64); self.e('lea', 'rsi', 64)
		# Окна остальных слов модуля на восемь отложенных множителей
		self.e('cmp', 'rsi', self.m('args', 56)); F = self.label(); self.e('je', F)
		V = self.label()
		self.e('label', V)
		self.accumulate(w)
		for i in range(8):
			for k in range(8):
				self.product(self.m('rsi', 8 * k), self.m('rdi', -64 + 8 * i), w[k], (k == 0))
			self.e('store', self.m('rcx', 8 * i), w[0])
			self.e('mov', w[0], 'rbx')
			w = w[1:] + w[:1]
		self.e('lea', 'rcx', 64); self.e('lea', 'rsi', 64)
		self.e('cmp', 'rsi', self.m('args', 56)); self.e('jne', V)
		# Окно блока с накопленным и переносом прошлого блока; перенос - в следующий блок
		self.e('label', F)
		# Отложенный перенос окна - рипплем, затем накопленное с переносом прошлого блока
		self.pending(w)
		self.e('mov', 'rax', self.m('args', 48)); self.e('neg', 'rax')
		for k in range(8): self.e('adc', w[k], self.m('rcx', 8 * k))
		self.e('sbb', 'rax', 'rax'); self.e('neg', 'rax'); self.e('store', self.m('args', 48), 'rax')
		for k in range(8): self.e('store', self.m('rcx', 8 * k), w[k])
		self.e('mov', 'rcx', 'rdi')
		self.e('cmp', 'rcx', self.m('args', 64)); self.e('jne', R)
		# Перенос последнего блока - старшее слово итога
		self.e('mov', 'rax', self.m('args', 48)); self.e('mov', 'rcx', self.m('args', 72)); self.e('store', self.m('rcx', 0), 'rax')

# ---------- отрисовка ----------
def reg32(r):
	# 32-разрядное имя регистра: eax … edi, r8d … r15d
	return ('%%e' + r[1:]) if r[1:].isalpha() else ('%%' + r + 'd')

# Доводы ядра - операнды в памяти по смещениям ячеек: регистров на указатель доводов не остаётся
ARGS = {0: 'buffer', 8: 'value', 16: 'modulus', 24: 'pairs', 32: 'end', 40: 'inverse', 48: 'carry', 56: 'last', 64: 'blocks', 72: 'top', 80: 'window'}

def operand(o):
	if isinstance(o, tuple):
		return ('%d(%%%%%s)' % (o[2], o[1])) if o[1] != 'args' else ('%[' + ARGS[o[2]] + ']')
	if isinstance(o, int): return '$%d' % o
	return '%%' + o

def render(op):
	n = op[0]
	if n == 'label': return op[1] + ':'
	if n in ('jmp', 'je', 'jne', 'jnz'): return '%s %s%s' % (n, op[1], 'b' if False else 'f')
	if n == 'mov': return 'movq %s, %s' % (operand(op[2]), operand(op[1]))
	if n == 'store': return 'movq %s, %s' % (operand(op[2]), operand(op[1]))
	if n == 'mulq': return 'mulq %s' % operand(op[1])
	if n == 'imul': return 'imulq %s, %s' % (operand(op[2]), operand(op[1]))
	if n in ('add', 'adc', 'sub', 'sbb', 'cmp'): return '%sq %s, %s' % (n, operand(op[2]), operand(op[1]))
	if n == 'xor': return 'xorl %s, %s' % (reg32(op[1]), reg32(op[1]))
	if n == 'neg': return 'negq %s' % operand(op[1])
	if n == 'shld': return 'shldq $1, %s, %s' % (operand(op[2]), operand(op[1]))
	if n == 'lea':
		if len(op) == 4: return 'leaq %d(%%%%%s), %%%%%s' % (op[2], op[3], op[1])
		return 'leaq %d(%%%%%s), %%%%%s' % (op[2], op[1], op[1])
	raise Exception('неизвестная команда ' + n)

def render_all(ins):
	# Переходы: направление по положению метки
	pos = {}
	for i, op in enumerate(ins):
		if op[0] == 'label': pos[op[1]] = i
	out = []
	for i, op in enumerate(ins):
		if op[0] in ('jmp', 'je', 'jne', 'jnz'):
			out.append('%s %s%s' % (op[0], op[1], 'b' if pos[op[1]] < i else 'f'))
		else:
			out.append(render(op))
	return out

# ---------- интерпретатор ----------
class VM:
	def __init__(self, ins, mem, args):
		self.ins = ins; self.mem = mem; self.args = args
		self.r = {n: 0 for n in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')}
		self.cf = 0; self.zf = 0
		self.labels = {op[1]: i for i, op in enumerate(ins) if op[0] == 'label'}
	def addr(self, o):
		if o[1] == 'args': return ('args', o[2])
		base = self.r[o[1]]
		return (base[0], base[1] + o[2])
	def load(self, o):
		region, off = self.addr(o)
		if region == 'args': return self.args[off // 8]
		return int.from_bytes(self.mem[region][off:off + 8], 'little')
	def store(self, o, v):
		region, off = self.addr(o)
		if region == 'args': self.args[off // 8] = v; return
		self.mem[region][off:off + 8] = v.to_bytes(8, 'little')
	def val(self, o):
		if isinstance(o, tuple): return self.load(o)
		if isinstance(o, int): return o & M64
		return self.r[o]
	def run(self):
		pc = 0; steps = 0
		while pc < len(self.ins):
			op = self.ins[pc]; n = op[0]; pc += 1; steps += 1
			assert steps < 5000000
			if n == 'label': continue
			if n == 'jmp': pc = self.labels[op[1]]; continue
			if n in ('jne', 'jnz'):
				if not self.zf: pc = self.labels[op[1]]
				continue
			if n == 'je':
				if self.zf: pc = self.labels[op[1]]
				continue
			if n == 'mov':
				v = self.val(op[2])
				self.r[op[1]] = v; continue
			if n == 'store': self.store(op[1], self.val(op[2])); continue
			if n == 'mulq':
				a = self.r['rax']; b = self.val(op[1]); p = a * b
				self.r['rax'] = p & M64; self.r['rdx'] = p >> 64; self.cf = int(p >> 64 != 0); continue
			if n == 'imul': self.r[op[1]] = (self.r[op[1]] * self.val(op[2])) & M64; continue
			if n in ('add', 'adc'):
				a = self.val(op[1]); b = self.val(op[2]); c = (self.cf if n == 'adc' else 0)
				if isinstance(a, tuple) or isinstance(b, tuple):
					# Указатели: смещение растёт, регион сохраняется
					if isinstance(a, tuple) and isinstance(b, tuple): s = (a[0], a[1] + b[1] + c)
					elif isinstance(a, tuple): s = (a[0], a[1] + b + c)
					else: s = (b[0], b[1] + a + c)
					self.cf = 0; self.zf = 0; self.assign(op[1], s); continue
				s = a + b + c
				self.cf = int(s >> 64); s &= M64; self.zf = int(s == 0)
				self.assign(op[1], s); continue
			if n in ('sub', 'sbb', 'cmp'):
				a = self.val(op[1]); b = self.val(op[2]); c = (self.cf if n == 'sbb' else 0)
				if isinstance(a, tuple) and isinstance(b, tuple):
					assert a[0] == b[0], 'вычитание указателей разных областей'
					s = a[1] - b[1] - c
					self.cf = int(s < 0); self.zf = int(s == 0)
					if n != 'cmp': self.assign(op[1], s)
					continue
				if isinstance(a, tuple):
					s = (a[0], a[1] - b - c); self.cf = 0; self.zf = 0
					if n != 'cmp': self.assign(op[1], s)
					continue
				s = a - b - c
				self.cf = int(s < 0); s &= M64; self.zf = int(s == 0)
				if n != 'cmp': self.assign(op[1], s)
				continue
			if n == 'xor': self.r[op[1]] = 0; self.cf = 0; self.zf = 1; continue
			if n == 'neg':
				a = self.val(op[1]); self.cf = int(a != 0); self.assign(op[1], (-a) & M64); self.zf = int(a == 0); continue
			if n == 'shld':
				d = self.r[op[1]]; s = self.r[op[2]]
				self.cf = d >> 63; self.r[op[1]] = ((d << 1) | (s >> 63)) & M64; continue
			if n == 'lea':
				if len(op) == 4: self.r[op[1]] = self.ptr_add(self.r[op[3]], op[2])
				else: self.r[op[1]] = self.ptr_add(self.r[op[1]], op[2])
				continue
			raise Exception('не исполняется ' + n)
	def ptr_add(self, p, off):
		if isinstance(p, tuple): return (p[0], p[1] + off)
		return (p + off) & M64
	def assign(self, o, v):
		if isinstance(o, tuple): self.store(o, v)
		else: self.r[o] = v

def run(ins, value, modulus, count, inverse):
	mem = {'buf': bytearray(8 * (2 * count + 2)) , 'val': bytearray(b''.join(v.to_bytes(8, 'little') for v in value)), 'mod': bytearray(b''.join(v.to_bytes(8, 'little') for v in modulus))}
	# Доводы: 0 buffer, 8 value, 16 modulus, 24 count (пар слов для обнуления), 32 конец числа, 40 inverse, 48 перенос, 56 конец модуля, 64 конец накопителя блоков, 72 старшее слово
	args = [('buf', 0), ('val', 0), ('mod', 0), count, ('val', 8 * count), inverse, 0, ('mod', 8 * count), ('buf', 8 * count), ('buf', 16 * count), 0]
	vm = VM(ins, mem, args)
	vm.run()
	return [int.from_bytes(mem['buf'][8 * i:8 * i + 8], 'little') for i in range(2 * count + 2)]

def selfcheck(ins):
	rng = random.Random(45)
	for trial in range(120):
		count = 8 * (1 + (trial % 4)) if trial < 96 else 8 * (5 + trial % 4)
		if trial % 9 == 0:
			m = (1 << (64 * count)) - 1; a = m - 1
		else:
			m = rng.getrandbits(64 * count) | 1 | (1 << (64 * count - 1)); a = rng.getrandbits(64 * count) % m
			if trial % 5 == 1: a = m - 1
		inverse = (-pow(m, -1, 1 << 64)) & M64
		value = [(a >> (64 * i)) & M64 for i in range(count)]
		modulus = [(m >> (64 * i)) & M64 for i in range(count)]
		out = run(ins, value, modulus, count, inverse)
		# Отложенные множители в младших словах, итог в старших: (a² + q·m) / R, где q составлено из множителей
		q = sum(out[i] << (64 * i) for i in range(count))
		high = sum(out[count + i] << (64 * i) for i in range(count + 1))
		total = a * a + q * m
		assert total % (1 << (64 * count)) == 0, 'проба %d: приведение не делится на R' % trial
		assert high == total >> (64 * count), 'проба %d (слов %d): расходится итог' % (trial, count)
		assert high < 2 * m, 'проба %d: итог не меньше удвоенного модуля' % trial

# ---------- заголовок ----------
HEADER = """/**
 * @file mont.hpp
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
 * @brief Квадрат Монтгомери блоками по восемь слов на встроенном ассемблере x86-64 без BMI2 и ADX
 *
 * @details Файл порождён сценарием tools/math/mont.py и руками не правится: правки вносятся в
 *          сценарий, который исполняет порождённый список команд на случайных числах и модулях и
 *          сличает с точной арифметикой до выдачи текста. Устройство - решение 8 шапки
 *          integer.cpp на mulq с переносом в регистре: три прохода (произведения ниже диагонали
 *          окном накопителя из восьми регистров, удвоение с квадратами диагонали, приведение по
 *          восемь рядов на блок с отложенными множителями), четыре флаговые команды на
 *          произведение, ряды перекрываются переупорядочением машины; доводы одним указателем
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_MATH_MONT__
#define __ANTS_INTERNAL_MATH_MONT__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * Ядро берётся у gcc и clang на x86-64; под ASan без оптимизации не берётся (все регистры
 * общего назначения заняты, признак __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядра квадрата на mulq
	 */
	#define __ANTS_MONT_SQUARE8X_MULQ__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён математики
		 *
		 */
		namespace math {
			/**
			 * @brief Пространство имён ядер на ассемблере
			 *
			 */
			namespace kernel {
				/**
				 * @brief Метод квадрата Монтгомери блоками по восемь слов на ассемблере x86-64 без BMI2 и ADX
				 *
				 * @param buffer  накопитель в 2 · count + 2 слов: на выходе слова count … 2 · count - значение, меньшее удвоенного модуля, младшие count слов - отложенные множители приведения
				 * @param value   слова числа, меньшего модуля
				 * @param modulus слова нечётного модуля
				 * @param count   число слов модуля, кратное восьми и не меньшее восьми
				 * @param inverse множитель приведения по модулю
				 *
				 */
				static void square8xMulq(uint64_t * buffer, const uint64_t * value, const uint64_t * modulus, const size_t count, const uint64_t inverse) noexcept {
					// Доводы ядра операндами в памяти: число пар слов накопителя, конец числа, конец модуля, конец накопителя блоков, старшее слово
					const uint64_t pairs = count;
					const uint64_t * end = (value + count);
					const uint64_t * last = (modulus + count);
					uint64_t * blocks = (buffer + count);
					uint64_t * top = (buffer + (2 * count));
					// Перенос между блоками и отложенный перенос окна
					uint64_t carry = 0, window = 0;
					__asm__ __volatile__(
"""
FOOTER = """						: [carry] "+m" (carry), [window] "+m" (window)
						: [buffer] "m" (buffer), [value] "m" (value), [modulus] "m" (modulus), [pairs] "m" (pairs), [end] "m" (end), [inverse] "m" (inverse), [last] "m" (last), [blocks] "m" (blocks), [top] "m" (top)
						: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory");
				}
			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_MATH_MONT__
"""

def header():
	k = Kernel(); k.build(); selfcheck(k.ins)
	print('сходимость квадрата блоками на mulq: команд %d' % len(k.ins), file=sys.stderr)
	lines = render_all(k.ins)
	body = '\n'.join('\t\t\t\t\t\t"%s\\n\\t"' % line for line in lines)
	return HEADER + body + '\n' + FOOTER

if __name__ == '__main__':
	sys.stdout.write(header())
