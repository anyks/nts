#!/usr/bin/env python3
#
# Порождатель ядер SHA-256 и SHA-512 на встроенном ассемблере x86-64 для
# src/internal/digest/sha2.hpp: python3 tools/digest/sha2.py > src/internal/digest/sha2.hpp
#
# Устройство ядра (образец - sha512-x86_64.pl OpenSSL, текст свой): круги идут с
# переименованием регистров a…h, оттого рабочие переменные не переносятся; слова расписания,
# сложенные с постоянными, считаются векторно по четыре (SHA-256) либо по два (SHA-512) слова
# и кладутся в кольцо из шестнадцати слов в кадре на стеке, круг берёт их операндом в памяти.
# Круги идут циклом по шестнадцать, а не развёрнуты целиком (круг 55): расписание группы
# считается во время кругов группы и кладётся в слот кольца после того, как круги слот прочли,
# постоянные берутся от бегущего указателя; через шестнадцать кругов кольца регистров a…h (8),
# временных a^b и b^c (2) и векторов сообщения (16 / G) возвращаются к исходным именам, потому
# тело цикла одно, а хвост из шестнадцати кругов идёт без расписания. Развёрнутое целиком ядро
# (2 214 команд у SSSE3 SHA-256, около 10 КБ) не помещалось в кэш декодированных микроопераций
# и шло с обычных декодеров: 592 такта на блок против 526 у OpenSSL при равном числе команд,
# с циклом - 1 067 команд и паритет. Сигмы круга - rorx (BMI2)
# либо последовательные повороты одной копии, выбор Ch - and и andn (BMI1) либо четырьмя командами; большинство -
# ((a^b)&(b^c))^b с переносом a^b в следующий круг. Ветвь AVX2 ведёт два блока разом:
# расписание обоих в двух полосах ymm (команды перестановки и сдвига действуют в полосах),
# круги первого блока перемежаются с расписанием, круги второго идут без векторной работы;
# постоянные у пар берутся из удвоенной таблицы (группа из 16 / G слов лежит дважды подряд, под обе
# полосы ymm) одним операндом в памяти, как из таблицы sha512-x86_64.pl OpenSSL: рассылка
# vbroadcasti128 на группу стоила на Xeon E5-2630 v4 около 1 % (круг 59);
# кадр у пар адресуется бегущим rsi (rsp стоит), а указатель постоянных лежит в кадре и
# перечитывается в rax перед чтением - rax мёртв между кругами, и перечитывание не отрывается
# от чтения при раздаче векторных команд по кругам.
# Кадр строится сдвигом rsp внутри вставки (красная зона учтена), потому доводы приходят
# регистрами и операндами в памяти, читаемыми до сдвига; указатель на постоянные лежит в
# кадре и на время кругов занимает rsi: регистров четырнадцать, rbp не берётся.
# Порча векторных регистров объявляется именами xmmN и у ядер на ymm: clang без ключа -mavx2
# молча не считает «ymmN» порчей (значение, оставленное им в xmm0, переживало вставку и
# портило вход соседнего вызова), gcc считает оба имени одним регистром; имя xmmN у обоих
# собирателей охватывает и старшую половину ymm.
#
# Правки ядра вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый
# список команд на случайных сообщениях и сличает с hashlib - порождение отказывает, если
# сходимости нет.
#
import random, sys, hashlib, struct

K256 = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
K512 = [0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817]

class Kernel:
	def __init__(self, bits, vex, bmi, pairs=False, loop=True):
		self.bits = bits; self.vex = vex; self.bmi = bmi; self.pairs = pairs; self.loop = loop
		self.W = 4 if bits == 256 else 8        # байт в слове
		self.R = 64 if bits == 256 else 80      # кругов
		self.G = 4 if bits == 256 else 2        # слов в векторной группе расписания
		self.sig1 = (6, 11, 25) if bits == 256 else (14, 18, 41)
		self.sig0 = (2, 13, 22) if bits == 256 else (28, 34, 39)
		self.s0 = (7, 18, 3) if bits == 256 else (1, 8, 7)
		self.s1 = (17, 19, 10) if bits == 256 else (19, 61, 6)
		self.K = K256 if bits == 256 else K512
		self.ins = []
		self.FRAME = 64                         # смещение слов расписания в кадре (кратно 32: хранение ymm)
		self.reg = (lambda r: r) if bits == 512 else (lambda r: r + 'd' if r.startswith('r1') or r.startswith('r8') or r.startswith('r9') else 'e' + r[1:])
		# имена регистров a…h (кольцо), временные
		self.ring = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
		self.t = ['rax', 'rbx', 'rcx', 'rdx', 'rdi']   # t0…t4; t2/t3 - пара a^b / b^c
	def e(self, *ins): self.ins.append(tuple(ins))
	# ---- скалярные ----
	def sigma(self, dst, src, tmp, rots):
		r = self.reg
		if self.bmi:
			self.e('rorx', r(dst), r(src), rots[2]); self.e('rorx', r(tmp), r(src), rots[1]); self.e('xor', r(dst), r(tmp))
			self.e('rorx', r(tmp), r(src), rots[0]); self.e('xor', r(dst), r(tmp))
		else:
			# последовательные повороты одной копии: ((x >>> (r2 - r1)) ^ x) >>> (r1 - r0) ^ x) >>> r0
			self.e('mov', r(dst), r(src)); self.e('ror', r(dst), rots[2] - rots[1]); self.e('xor', r(dst), r(src))
			self.e('ror', r(dst), rots[1] - rots[0]); self.e('xor', r(dst), r(src)); self.e('ror', r(dst), rots[0])
	def round(self, i, regs, ab, bc, offset=None):
		# regs: a,b,c,d,e,f,g,h; ab/bc - имена временных: bc держит b^c, ab получит a^b
		r = self.reg; a, b, c, d, e, f, g, h = regs
		t0, t1, t4 = 'rax', 'rbx', 'rdi'
		if offset is None: offset = i * self.W
		self.e('add', r(h), offset if isinstance(offset, tuple) else ('frame', self.FRAME + offset))              # h += W + K
		# Ch(e, f, g)
		if self.bmi:
			self.e('mov', r(t4), r(f)); self.e('and', r(t4), r(e)); self.e('andn', r(t1), r(e), r(g))
		else:
			self.e('mov', r(t4), r(f)); self.e('xor', r(t4), r(g)); self.e('and', r(t4), r(e)); self.e('xor', r(t4), r(g))
		self.sigma(t0, e, ab, self.sig1)                                   # ab свободен как временный до a^b
		self.e('add', r(h), r(t4))
		if self.bmi: self.e('add', r(h), r(t1))
		self.e('add', r(h), r(t0))                                         # T1
		self.e('add', r(d), r(h))                                          # e' = d + T1
		self.sigma(t0, a, t1, self.sig0)
		self.e('mov', r(ab), r(a)); self.e('xor', r(ab), r(b))             # a^b
		self.e('and', r(bc), r(ab)); self.e('xor', r(bc), r(b))            # Maj = ((a^b)&(b^c))^b
		self.e('add', r(h), r(bc)); self.e('add', r(h), r(t0))             # a' = T1 + Sigma0 + Maj
	# ---- векторные ----
	def vop(self, op, dst, s1, s2=None, imm=None):
		# у сдвигов и pshufd третий довод - непосредственное значение
		if op in ('psrld', 'pslld', 'psrlq', 'psllq', 'pshufd'): imm, s2 = s2, None
		self.e('v', op, dst, s1, s2, imm)
	def schedule256(self, j, X, T, stride=16, wide=False, koff=None, dest=None, kreg=None):
		if koff is None: koff = 4 * j
		# X[0..3] - четвёрки слов; вычисляет X[0] += ... (слова 16+4j… ) ; T[0..3] временные; маски: xmm8 swap, xmm9 t4, xmm10 t5
		X0, X1, X2, X3 = X; t0, t1, t2, t3 = T
		s0 = self.s0; s1 = self.s1
		self.vop('palignr', t0, X1, X0, 4)              # X[1..4]
		self.vop('palignr', t3, X3, X2, 4)              # X[9..12]
		self.vop('psrld', t2, t0, s0[0])
		self.vop('paddd', X0, X0, t3)
		self.vop('psrld', t3, t0, s0[2])
		self.vop('pslld', t1, t0, 32 - s0[1])
		self.vop('pxor', t0, t3, t2)
		self.vop('pshufd', t3, X3, 0b11111010)          # [w14, w14, w15, w15]
		self.vop('psrld', t2, t2, s0[1] - s0[0])
		self.vop('pxor', t0, t0, t1)
		self.vop('pslld', t1, t1, s0[1] - s0[0])
		self.vop('pxor', t0, t0, t2)
		self.vop('psrld', t2, t3, s1[2])
		self.vop('pxor', t0, t0, t1)                    # sigma0(X[1..4])
		self.vop('psrlq', t3, t3, s1[0])
		self.vop('paddd', X0, X0, t0)
		self.vop('pxor', t2, t2, t3)
		self.vop('psrlq', t3, t3, s1[1] - s1[0])
		self.vop('pxor', t2, t2, t3)
		self.vop('pshufb', t2, t2, self.masks[0])       # sigma1(X[14..15]) в слова 0, 1
		self.vop('paddd', X0, X0, t2)
		self.vop('pshufd', t3, X0, 0b01010000)          # [x0, x0, x1, x1]
		self.vop('psrld', t2, t3, s1[2])
		self.vop('psrlq', t3, t3, s1[0])
		self.vop('pxor', t2, t2, t3)
		self.vop('psrlq', t3, t3, s1[1] - s1[0])
		self.vop('pxor', t2, t2, t3)
		self.vop('pshufb', t2, t2, self.masks[1])       # sigma1(X[16..17]) в слова 2, 3
		self.vop('paddd', X0, X0, t2)
		if wide:
			# постоянные группы у пар лежат дважды подряд: обе полосы читаются одним операндом в памяти
			if kreg: self.e('movq', kreg, ('frame', 40)); self.vop('paddd', t2, X0, ('mem', kreg, koff * 8))
			else: self.vop('paddd', t2, X0, ('K', 2 * koff))
		else: self.vop('paddd', t2, X0, ('K', koff))
		self.vop('store', dest if dest else ('frame', self.FRAME + stride * j), t2)
	def rotr64(self, dst, src, n, tmp):
		self.vop('psrlq', dst, src, n); self.vop('psllq', tmp, src, 64 - n); self.vop('pxor', dst, dst, tmp)
	def schedule512(self, j, X, T, stride=16, wide=False, koff=None, dest=None, kreg=None):
		if koff is None: koff = 2 * j
		# X[0..7] - пары слов; X[0] += sigma0(X[1..2]) + X[9..10] + sigma1(X[14..15])
		t0, t1, t2, t3 = T
		self.vop('palignr', t0, X[1], X[0], 8)          # X[1..2]
		self.vop('palignr', t3, X[5], X[4], 8)          # X[9..10]
		self.rotr64(t1, t0, self.s0[0], t2)
		self.vop('paddq', X[0], X[0], t3)
		self.rotr64(t3, t0, self.s0[1], t2)
		self.vop('pxor', t1, t1, t3)
		self.vop('psrlq', t2, t0, self.s0[2])
		self.vop('pxor', t1, t1, t2)                    # sigma0
		self.vop('paddq', X[0], X[0], t1)
		self.rotr64(t1, X[7], self.s1[0], t2)
		self.rotr64(t3, X[7], self.s1[1], t2)
		self.vop('pxor', t1, t1, t3)
		self.vop('psrlq', t2, X[7], self.s1[2])
		self.vop('pxor', t1, t1, t2)                    # sigma1
		self.vop('paddq', X[0], X[0], t1)
		if wide:
			# постоянные группы у пар лежат дважды подряд: обе полосы читаются одним операндом в памяти
			if kreg: self.e('movq', kreg, ('frame', 40)); self.vop('paddq', t2, X[0], ('mem', kreg, koff * 16))
			else: self.vop('paddq', t2, X[0], ('K', 2 * koff))
		else: self.vop('paddq', t2, X[0], ('K', koff))
		self.vop('store', dest if dest else ('frame', self.FRAME + stride * j), t2)
	def build(self):
		if self.pairs: return self.buildpairs()
		return self.buildsingle()
	def buildpairs(self):
		# Два блока разом: расписание обоих блоков в двух полосах ymm, круги блока A перемежаются
		# с расписанием, круги блока B идут без векторной работы; count - число пар блоков.
		# Круги идут циклом по шестнадцать: кадр адресуется бегущим rsi (rsp стоит, слоты служебных
		# слов остаются на месте), указатель постоянных лежит в слоте 40 кадра, уходит на шестнадцать
		# слов за проход и перечитывается в rax перед чтением постоянных (rax мёртв между кругами)
		r = self.reg; W = self.W; R = self.R; G = self.G
		nx = 16 // G
		P = 16 // G                                     # групп расписания за проход
		X = ['ymm%d' % k for k in range(nx)]
		T = ['ymm%d' % k for k in range(nx, nx + 4)]
		swap = 'ymm%d' % (nx + 4)
		self.swap = swap; self.masks = ('ymm9', 'ymm10') if self.bits == 256 else ()
		self.e('movq', 'rax', ('in', 'kp'))
		self.e('movq', 'rbx', ('in', 'mp'))
		self.e('mov', 'rcx', 'rsp')
		self.e('sub', 'rsp', 128 + self.FRAME + 2 * R * W)
		self.e('and', 'rsp', -32)
		self.e('movq', ('frame', 16), 'rcx')
		self.e('movq', ('frame', 32), 'rax')
		self.e('movq', ('frame', 0), 'rdi')
		self.e('shl', 'rdx', 7 if self.bits == 256 else 8)
		self.e('add', 'rdx', 'rsi')
		self.e('movq', ('frame', 8), 'rdx')
		self.e('movq', ('frame', 24), 'rsi')
		self.vop('bcast', swap, ('mem', 'rbx', 0))
		for k, m in enumerate(self.masks): self.vop('bcast', m, ('mem', 'rbx', 16 + 16 * k))
		for k in range(8): self.e('load', r(self.ring[k]), ('mem', 'rdi', k * W))
		self.e('label', 'loop')
		self.e('movq', 'rsi', ('frame', 24))
		half = 16 * nx
		for k in range(nx):
			self.vop('loadu', 'xmm%d' % k, ('mem', 'rsi', 16 * k))
			self.vop('insert', X[k], X[k], ('mem', 'rsi', half + 16 * k))
			self.vop('pshufb', X[k], X[k], swap)
		self.e('lea', 'rsi', 'rsi', 2 * half)
		self.e('movq', ('frame', 24), 'rsi')
		self.e('movq', 'rsi', ('frame', 32))
		for k in range(nx):
			self.vop('paddx', T[0], X[k], ('K', 2 * G * k))
			self.vop('store', ('frame', self.FRAME + 32 * k), T[0])
		# бегущий указатель постоянных: за первые шестнадцать слов удвоенной таблицы; бегущий указатель кадра
		self.e('lea', 'rax', 'rsi', 32 * W)
		self.e('movq', ('frame', 40), 'rax')
		self.e('lea', 'rsi', 'rsp', self.FRAME)
		bc, ab = 'rdx', 'rcx'
		ring = list(self.ring)
		for blk in range(2):
			self.e('mov', r(bc), r(ring[1])); self.e('xor', r(bc), r(ring[2]))
			self.e('label', 'inner' if blk == 0 else 'innerb')
			for i in range(R):
				if i == 16:
					# конец прохода: кадр на P групп вперёд; у блока A ещё постоянные на шестнадцать слов
					self.e('lea', 'rsi', 'rsi', 32 * P)
					if blk == 0: self.e('addm', ('frame', 40), 32 * W)
					self.e('lea', 'rax', 'rsp', self.FRAME + 32 * P * ((R - 16) // 16 if blk == 0 else R // 16))
					self.e('cmp', 'rsi', 'rax')
					self.e('jb', 'inner' if blk == 0 else 'innerb')
				if blk == 0 and i < 16 and i % G == 0:
					j = i // G
					mark = len(self.ins)
					if self.bits == 256: self.schedule256(j, X, T, 32, True, G * j, ('mem', 'rsi', 32 * (P + j)), 'rax')
					else: self.schedule512(j, X, T, 32, True, G * j, ('mem', 'rsi', 32 * (P + j)), 'rax')
					self.pending = self.ins[mark:]; del self.ins[mark:]
					X = X[1:] + X[:1]
				elif 16 <= i < (R - 16 if blk == 0 else R): continue
				self.round(i, ring, ab, bc, ('mem', 'rsi', 32 * ((i // G) % P) + 16 * blk + W * (i % G)))
				ab, bc = bc, ab
				ring = ring[-1:] + ring[:-1]
				if blk == 0 and getattr(self, 'pending', None):
					share = (len(self.pending) + (G - 1 - (i % G))) // (G - (i % G))
					# перечитывание указателя постоянных не отрывать от чтения: rax жив лишь внутри доли
					if share < len(self.pending) and self.pending[share - 1][0] == 'movq' and self.pending[share - 1][1] == 'rax': share += 1
					chunk, self.pending = self.pending[:share], self.pending[share:]
					self.ins.extend(chunk)
			self.e('movq', 'rdi', ('frame', 0))
			for k in range(8):
				self.e('add', r(self.ring[k]), ('mem', 'rdi', k * W))
				self.e('store', ('mem', 'rdi', k * W), r(self.ring[k]))
			if blk == 0: self.e('lea', 'rsi', 'rsp', self.FRAME)
		self.e('movq', 'rsi', ('frame', 24))
		self.e('cmp', 'rsi', ('frame', 8))
		self.e('jb', 'loop')
		self.e('vzeroupper')
		self.e('movq', 'rsp', ('frame', 16))
		# перечитанный указатель постоянных читается следующей же командой: между ними нет круга, портящего rax
		for n, ins in enumerate(self.ins):
			if ins == ('movq', 'rax', ('frame', 40)):
				assert self.ins[n + 1][0] == 'v' and self.ins[n + 1][1] in ('paddd', 'paddq') and self.ins[n + 1][4][:2] == ('mem', 'rax'), ('перечитывание указателя постоянных оторвано от чтения', n)
		return self.ins
	def buildsingle(self):
		r = self.reg; W = self.W; R = self.R; G = self.G
		nx = 16 // G                                    # векторов слов сообщения
		X = ['xmm%d' % k for k in range(nx)]
		T = ['xmm%d' % k for k in range(nx, nx + 4)]
		swap = 'xmm%d' % (nx + 4)
		self.swap = swap; self.masks = ('xmm9', 'xmm10') if self.bits == 256 else ()
		# пролог: указатели постоянных и масок до сдвига rsp (операнды в памяти относительны rsp), затем кадр
		self.e('movq', 'rax', ('in', 'kp'))
		self.e('movq', 'rbx', ('in', 'mp'))
		self.e('mov', 'rcx', 'rsp')
		self.e('sub', 'rsp', 128 + self.FRAME + (16 * W if self.loop else R * W))
		self.e('and', 'rsp', -32)
		self.e('movq', ('frame', 16), 'rcx')            # прежний rsp
		if self.loop:
			# конец постоянных расписания: цикл идёт, пока указатель постоянных ниже
			self.e('lea', 'rcx', 'rax', (R - 16) * W)
			self.e('movq', ('frame', 40), 'rcx')
		self.e('movq', ('frame', 32), 'rax')            # постоянные
		self.e('movq', ('frame', 0), 'rdi')             # состояние
		self.e('shl', 'rdx', 6 if self.bits == 256 else 7)
		self.e('add', 'rdx', 'rsi')
		self.e('movq', ('frame', 8), 'rdx')             # конец данных
		self.e('movq', ('frame', 24), 'rsi')            # данные
		self.vop('load', swap, ('mem', 'rbx', 0))
		for k, m in enumerate(self.masks): self.vop('load', m, ('mem', 'rbx', 16 + 16 * k))
		for k in range(8): self.e('load', r(self.ring[k]), ('mem', 'rdi', k * W))
		self.e('label', 'loop')
		# слова блока: разворот байтов, затем rsi - указатель постоянных; сложение с K, в кадр
		self.e('movq', 'rsi', ('frame', 24))
		for k in range(nx):
			self.vop('loadu', X[k], ('mem', 'rsi', 16 * k))
			self.vop('pshufb', X[k], X[k], swap)
		self.e('lea', 'rsi', 'rsi', 16 * nx)
		self.e('movq', ('frame', 24), 'rsi')
		self.e('movq', 'rsi', ('frame', 32))
		for k in range(nx):
			self.vop('paddx', T[0], X[k], ('K', G * k))
			self.vop('store', ('frame', self.FRAME + 16 * k), T[0])
		# b^c
		bc, ab = 'rdx', 'rcx'
		self.e('mov', r(bc), r(self.ring[1])); self.e('xor', r(bc), r(self.ring[2]))
		ring = list(self.ring)
		groups = (R - 16) // G                          # групп расписания
		if self.loop:
			# Цикл по шестнадцать кругов: группа j расписания считает слова 16…, кладёт их в слот j кадра
			# (те же шестнадцать слов по кольцу) после того, как круги группы прочли слот, и берёт
			# постоянные от бегущего указателя rsi: за проход он уходит на шестнадцать слов вперёд.
			# Через шестнадцать кругов кольца регистров (8), временных (2) и векторов (16 / G) возвращаются
			# к исходным именам, потому тело цикла одно; хвост из шестнадцати кругов идёт без расписания
			self.e('label', 'inner')
		for i in range(R):
			regs = ring[:]
			if self.loop and i == 16:
				self.e('lea', 'rsi', 'rsi', 16 * W)
				self.e('cmp', 'rsi', ('frame', 40))
				self.e('jb', 'inner')
			# начало группы расписания: запоминаем позицию вставки векторных команд
			if self.loop:
				if i < 16 and i % G == 0:
					j = i // G
					mark = len(self.ins)
					if self.bits == 256: self.schedule256(j, X, T, 16, False, 16 + G * j)
					else: self.schedule512(j, X, T, 16, False, 16 + G * j)
					vec = self.ins[mark:]; del self.ins[mark:]
					X = X[1:] + X[:1]                   # кольцо векторов
					self.pending = vec
				elif 16 <= i < R - 16: continue
			elif i < groups * G and i % G == 0:
				j = i // G
				mark = len(self.ins)
				if self.bits == 256: self.schedule256(4 + j, X, T)
				else: self.schedule512(8 + j, X, T)
				vec = self.ins[mark:]; del self.ins[mark:]
				X = X[1:] + X[:1]                       # кольцо векторов
				self.pending = vec
			self.round(i, regs, ab, bc, W * (i & 15) if self.loop else None)
			ab, bc = bc, ab
			ring = ring[-1:] + ring[:-1]
			# перемежаем: после каждого круга группы вставляем долю векторных команд
			if hasattr(self, 'pending') and self.pending:
				share = (len(self.pending) + (G - 1 - (i % G))) // (G - (i % G))
				chunk, self.pending = self.pending[:share], self.pending[share:]
				# вставляем перед последними скалярными командами круга: кладём просто в конец круга
				self.ins.extend(chunk)
		# итог блока
		self.e('movq', 'rdi', ('frame', 0))
		for k in range(8):
			self.e('add', r(self.ring[k]), ('mem', 'rdi', k * W))
			self.e('store', ('mem', 'rdi', k * W), r(self.ring[k]))
		self.e('movq', 'rsi', ('frame', 24))
		self.e('cmp', 'rsi', ('frame', 8))
		self.e('jb', 'loop')
		self.e('movq', 'rsp', ('frame', 16))
		return self.ins

# ---------- вывод текста ----------
def operand(o):
	if isinstance(o, tuple):
		if o[0] == 'frame': return '%d(%%%%rsp)' % o[1]
		if o[0] == 'mem': return '%d(%%%%%s)' % (o[2], o[1])
		if o[0] == 'K': return '%d(%%%%rsi)' % (o[1] * o[2])
		if o[0] == 'in': return '%[' + o[1] + ']'
	if isinstance(o, int): return '$%d' % o
	return '%%' + o
def width(reg):
	return 'l' if (reg.startswith('e') or reg.endswith('d')) else 'q'
def render(kern, legacy):
	out = []
	W = kern.W
	vsfx = 'd' if W == 4 else 'q'
	for ins in kern.ins:
		op = ins[0]
		if op == 'label': out.append({'loop': '1', 'inner': '2', 'innerb': '3'}[ins[1]] + ':'); continue
		if op == 'v':
			_, vo, d, s1, s2, imm = ins
			if isinstance(s1, tuple) and s1[0] == 'K': s1 = ('K', s1[1], W)
			if isinstance(s2, tuple) and s2[0] == 'K': s2 = ('K', s2[1], W)
			if vo in ('load', 'loadu', 'store'):
				name = {'load': 'movdqa', 'loadu': 'movdqu', 'store': 'movdqa'}[vo]
				if isinstance(d, tuple) and d[0] == 'mem': out.append(('v' if not legacy else '') + '%s %s, %s' % (name, operand(s1), operand(d))); continue
				out.append(('v' if not legacy else '') + '%s %s, %s' % (name, operand(s1), operand(d))); continue
			if vo == 'bcast': out.append('vbroadcasti128 %s, %s' % (operand(s1), operand(d))); continue
			if vo == 'insert': out.append('vinserti128 $1, %s, %s, %s' % (operand(s2), operand(s1), operand(d))); continue
			name = {'paddd': 'paddd', 'paddq': 'paddq', 'paddx': 'padd' + vsfx, 'pxor': 'pxor', 'psrld': 'psrld', 'pslld': 'pslld', 'psrlq': 'psrlq', 'psllq': 'psllq', 'pshufb': 'pshufb', 'palignr': 'palignr', 'pshufd': 'pshufd'}[vo]
			if not legacy:
				if vo in ('psrld', 'pslld', 'psrlq', 'psllq', 'pshufd'): out.append('v%s $%d, %s, %s' % (name, imm, operand(s1), operand(d)))
				elif vo == 'palignr': out.append('vpalignr $%d, %s, %s, %s' % (imm, operand(s2), operand(s1), operand(d)))
				else: out.append('v%s %s, %s, %s' % (name, operand(s2), operand(s1), operand(d)))
				continue
			if vo == 'pshufd': out.append('pshufd $%d, %s, %s' % (imm, operand(s1), operand(d))); continue
			if vo in ('psrld', 'pslld', 'psrlq', 'psllq'):
				if d != s1: out.append('movdqa %s, %s' % (operand(s1), operand(d)))
				out.append('%s $%d, %s' % (name, imm, operand(d))); continue
			if vo in ('palignr', 'pshufb'):
				assert d != s2, ins
				if d != s1: out.append('movdqa %s, %s' % (operand(s1), operand(d)))
				out.append(('palignr $%d, %s, %s' % (imm, operand(s2), operand(d))) if vo == 'palignr' else ('pshufb %s, %s' % (operand(s2), operand(d)))); continue
			if d == s1: out.append('%s %s, %s' % (name, operand(s2), operand(d)))
			elif d == s2: out.append('%s %s, %s' % (name, operand(s1), operand(d)))
			else: out.append('movdqa %s, %s' % (operand(s1), operand(d))); out.append('%s %s, %s' % (name, operand(s2), operand(d)))
			continue
		if op in ('mov', 'add', 'xor', 'and', 'sub', 'cmp'):
			out.append('%s%s %s, %s' % (op, width(ins[1]), operand(ins[2]), operand(ins[1]))); continue
		if op == 'movq': out.append('movq %s, %s' % (operand(ins[2]), operand(ins[1]))); continue
		if op == 'load': out.append('mov%s %s, %s' % (width(ins[1]), operand(ins[2]), operand(ins[1]))); continue
		if op == 'store': out.append('mov%s %s, %s' % (width(ins[2]), operand(ins[2]), operand(ins[1]))); continue
		if op == 'rorx': out.append('rorx%s $%d, %s, %s' % (width(ins[1]), ins[3], operand(ins[2]), operand(ins[1]))); continue
		if op == 'ror': out.append('ror%s $%d, %s' % (width(ins[1]), ins[2], operand(ins[1]))); continue
		if op == 'andn': out.append('andn%s %s, %s, %s' % (width(ins[1]), operand(ins[3]), operand(ins[2]), operand(ins[1]))); continue
		if op == 'shl': out.append('shlq $%d, %s' % (ins[2], operand(ins[1]))); continue
		if op == 'lea': out.append('leaq %d(%s), %s' % (ins[3], operand(ins[2]), operand(ins[1]))); continue
		if op == 'jb': out.append('jb %sb' % {'loop': '1', 'inner': '2', 'innerb': '3'}[ins[1]]); continue
		if op == 'addm': out.append('addq $%d, %s' % (ins[2], operand(ins[1]))); continue
		if op == 'vzeroupper': out.append('vzeroupper'); continue
		raise Exception(ins)
	return out
def asmtext(lines, indent='\t\t\t'):
	return '\n'.join(indent + '"' + l + '\\n\\t"' for l in lines)
def kernel_cpp(kern, name, legacy, brief):
	nx = 16 // kern.G
	# порча только именами xmmN: «ymmN» clang без -mavx2 молча пропускает, а xmmN охватывает весь регистр
	regs = ', '.join('"xmm%d"' % i for i in range(nx + 5 + (2 if kern.bits == 256 else 0)))
	word = 'uint32_t' if kern.bits == 256 else 'uint64_t'
	mtab = 'MASK256' if kern.bits == 256 else 'MASK512'
	countdoc = 'число пар блоков' if kern.pairs else 'число блоков'
	kdoc = 'круговые постоянные, удвоенные по группам: каждая группа из %d слов лежит дважды подряд' % kern.G if kern.pairs else 'круговые постоянные'
	head = ('\t\t\t\t/**\n\t\t\t\t * @brief %s\n\t\t\t\t *\n\t\t\t\t * @param state     состояние: восемь слов\n\t\t\t\t * @param data      блоки сообщения\n\t\t\t\t * @param count     %s, не меньше одного\n\t\t\t\t * @param constants %s\n\t\t\t\t *\n\t\t\t\t */\n' % (brief, countdoc, kdoc)
		+ '\t\t\t\tstatic void %s(%s * state, const uint8_t * data, size_t count, const %s * constants) noexcept {\n\t\t\t\t\t// Указатели на постоянные и маски перестановки байтов: читаются вставкой до сдвига стека\n\t\t\t\t\tconst void * kp = constants;\n\t\t\t\t\tconst void * mp = %s;\n\t\t\t\t\t__asm__ __volatile__(\n' % (name, word, word, mtab))
	tail = ('\n\t\t\t\t\t\t: [data] "+S" (data), [state] "+D" (state), [count] "+d" (count)\n\t\t\t\t\t\t: [kp] "m" (kp), [mp] "m" (mp)\n\t\t\t\t\t\t: "rax", "rbx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", %s, "cc", "memory");\n\t\t\t\t}\n' % regs)
	return head + asmtext(render(kern, legacy), '\t\t\t\t\t\t') + tail

HEADER = """/**
 * @file sha2.hpp
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
 * @brief Ядра SHA-256 и SHA-512 на встроенном ассемблере x86-64
 *
 * @details Файл порождён сценарием tools/digest/sha2.py и руками не правится: правки
 *          вносятся в сценарий, который исполняет порождённый список команд на случайных
 *          сообщениях и сличает с эталоном до выдачи текста. Устройство: круги идут циклом
 *          по шестнадцать с переименованием регистров a…h (кольца регистров, временных и
 *          векторов сообщения замыкаются за шестнадцать кругов), хвост из шестнадцати кругов
 *          идёт без расписания; слова расписания с постоянными считаются векторно и лежат в
 *          кольце из шестнадцати слов в кадре на стеке, круг берёт их операндом в памяти;
 *          сигмы - rorx (BMI2) либо ror, выбор - andn (BMI1) либо четыре команды. Три ветви
 *          на преобразование: AVX2 с BMI2 - два блока разом (расписание обоих в двух полосах
 *          ymm, круги первого перемежаются с расписанием, круги второго идут без векторной
 *          работы, кадр адресуется бегущим rsi), AVX с BMI2 - по одному блоку, SSSE3 - по
 *          одному блоку без VEX и rorx. Кадр строится сдвигом rsp внутри вставки, доводы
 *          приходят регистрами; порча регистров объявлена именами xmmN и у ядер на ymm
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_DIGEST_SHA2__
#define __ANTS_INTERNAL_DIGEST_SHA2__

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
 * Ядра берутся у gcc и clang на x86-64; у прочих собирателей и архитектур остаётся переносимый
 * путь. Под ASan без оптимизации ядра не берутся: вставка занимает все четырнадцать регистров
 * общего назначения (признак __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp, круг 38)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядер на ассемблере
	 */
	#define __ANTS_SHA2_X86_64__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён модулей хеширования
		 *
		 */
		namespace digest {
			/**
			 * @brief Пространство имён ядер на ассемблере
			 *
			 */
			namespace kernel {
				/**
				 * @brief Маски перестановки байтов SHA-256: разворот слов от старшего байта и две укладки младших половин четвёрок в слова 0…1 и 2…3
				 */
				alignas(16) static const uint8_t MASK256[48] = {
					3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
					0, 1, 2, 3, 8, 9, 10, 11, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
					0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 8, 9, 10, 11
				};
				/**
				 * @brief Маска перестановки байтов SHA-512: разворот слов от старшего байта
				 */
				alignas(16) static const uint8_t MASK512[16] = {7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8};
"""
FOOTER = """			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_DIGEST_SHA2__
"""
def header():
	parts = [HEADER]
	names = {(256, 'avx2'): 'Метод разбора пар блоков SHA-256 ядром AVX2 с BMI2', (256, 'avx'): 'Метод разбора блоков SHA-256 ядром AVX с BMI2', (256, 'ssse3'): 'Метод разбора блоков SHA-256 ядром SSSE3',
		(512, 'avx2'): 'Метод разбора пар блоков SHA-512 ядром AVX2 с BMI2', (512, 'avx'): 'Метод разбора блоков SHA-512 ядром AVX с BMI2', (512, 'ssse3'): 'Метод разбора блоков SHA-512 ядром SSSE3'}
	for bits in (256, 512):
		for tag, vex, bmi, pairs in (('avx2', True, True, True), ('avx', True, True, False), ('ssse3', False, False, False)):
			k = Kernel(bits, vex, bmi, pairs); k.build(); selfcheck(k)
			print('сходимость SHA-%d %s: команд %d' % (bits, tag, len(k.ins)), file=sys.stderr)
			parts.append(kernel_cpp(k, 'sha%d%s' % (bits, tag), not vex, names[(bits, tag)]))
	parts.append(FOOTER)
	return ''.join(parts)

# ---------- интерпретатор ----------
def run(kern, message):
	W = kern.W; M = (1 << (8 * W)) - 1
	R = kern.R
	# набивка
	blocks = bytearray(message); ml = len(message) * 8
	blocks.append(0x80)
	lenbytes = 8 if W == 4 else 16
	while (len(blocks) % (16 * W)) != (16 * W - lenbytes): blocks.append(0)
	blocks += ml.to_bytes(lenbytes, 'big')
	nblocks = len(blocks) // (16 * W)
	H = ([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19] if W == 4 else
		[0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179])
	state = bytearray(b''.join(h.to_bytes(W, 'little') for h in H))
	DATA, KB, MB, ST = 0x10000000, 0x20000000, 0x30000000, 0x40000000
	regs = {'rsi': DATA, 'rdi': ST, 'rdx': (nblocks // 2) if kern.pairs else nblocks, 'rsp': 1 << 20}
	if kern.pairs and (nblocks % 2): return None
	frame = bytearray(4096)
	xmm = {}
	masktab = (bytes([3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]) if W == 4 else bytes([7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8])) + bytes([0,1,2,3,8,9,10,11] + [0x80] * 8) + bytes([0x80] * 8 + [0,1,2,3,8,9,10,11])
	# у пар таблица постоянных удвоена по группам: каждая группа из 16 / G слов лежит дважды подряд
	Ktab = ([k for j in range(kern.R // kern.G) for _ in (0, 1) for k in kern.K[kern.G * j:kern.G * j + kern.G]] if kern.pairs else kern.K)
	Kbytes = b''.join(k.to_bytes(W, 'little') for k in Ktab)
	def memread(addr, width):
		if regs['rsp'] <= addr < regs['rsp'] + 4096: return bytes(frame[addr - regs['rsp']:addr - regs['rsp'] + width])
		if DATA <= addr < KB: return bytes(blocks[addr - DATA:addr - DATA + width])
		if KB <= addr < MB: return Kbytes[addr - KB:addr - KB + width]
		if MB <= addr < ST: return masktab[addr - MB:addr - MB + width]
		if addr >= ST: return bytes(state[addr - ST:addr - ST + width])
		raise Exception(hex(addr))
	def rd(o, width):
		if isinstance(o, int): return o & ((1 << (8 * width)) - 1)
		if isinstance(o, tuple):
			if o[0] == 'frame': return int.from_bytes(frame[o[1]:o[1] + width], 'little')
			if o[0] == 'mem': return int.from_bytes(memread(regs[o[1]] + o[2], width), 'little')
			if o[0] == 'in': return {'kp': KB, 'mp': MB}[o[1]]
			raise Exception(o)
		return regs.get(o, 0) & ((1 << (8 * width)) - 1)
	def wr(o, v, width):
		v &= (1 << (8 * width)) - 1
		if isinstance(o, tuple):
			if o[0] == 'frame': frame[o[1]:o[1] + width] = v.to_bytes(width, 'little'); return
			if o[0] == 'mem':
				addr = regs[o[1]] + o[2]; assert addr >= ST; state[addr - ST:addr - ST + width] = v.to_bytes(width, 'little'); return
			raise Exception(o)
		regs[o] = v
	def vrd(o):
		if isinstance(o, tuple):
			if o[0] == 'K': base = regs['rsi'] - KB + o[1] * W; return Kbytes[base:base + 16]
			if o[0] == 'frame': return bytes(frame[o[1]:o[1] + 16])
			if o[0] == 'mem': return memread(regs[o[1]] + o[2], 16)
		return xmm[o]
	lanes = lambda b, w: [int.from_bytes(b[i:i + w], 'little') for i in range(0, len(b), w)]
	def perlane(b, fn): return b''.join(fn(b[i:i + 16]) for i in range(0, len(b), 16))
	def vname(o): return o
	def xget(o):
		# xmmN и ymmN - один регистр: xmm - младшая полоса
		if isinstance(o, str) and o.startswith('xmm'): return xmm.get('ymm' + o[3:], bytes(32))[:16]
		return vrd(o)
	def xset(o, v):
		if o.startswith('xmm'): xmm['ymm' + o[3:]] = v[:16] + bytes(16)
		else: xmm[o] = v
	pack = lambda l, w: b''.join(x.to_bytes(w, 'little') for x in l)
	labels = {ins[1]: n for n, ins in enumerate(kern.ins) if ins[0] == 'label'}
	pc = 0; steps = 0
	while pc < len(kern.ins):
		ins = kern.ins[pc]; pc += 1; steps += 1
		op = ins[0]
		if op == 'label': continue
		if op == 'v':
			_, vo, d, s1, s2, imm = ins
			width16 = isinstance(d, str) and d.startswith('xmm')
			def get(o):
				v = xget(o)
				return v[:16] if width16 else (v if len(v) == 32 else v + bytes(16))
			if vo in ('load', 'loadu'): xset(d, vrd(s1) if not d.startswith('ymm') else memread(regs[s1[1]] + s1[2], 32) if s1[0] == 'mem' else vrd(s1)); continue
			if vo == 'store':
				v = xget(s1)
				if d[0] == 'mem': off = regs[d[1]] + d[2] - regs['rsp']; assert 0 <= off < 4096, ins; frame[off:off + len(v)] = v; continue
				frame[d[1]:d[1] + len(v)] = v; continue
			if vo == 'bcast': v = vrd(s1) if s1[0] != 'mem' else memread(regs[s1[1]] + s1[2], 16); xset(d, v + v); continue
			if vo == 'insert': base = xget(s1); v = memread(regs[s2[1]] + s2[2], 16); xset(d, base[:16] + v); continue
			a = get(s1)
			if vo in ('paddd', 'paddq', 'paddx'):
				w = 4 if vo == 'paddd' or (vo == 'paddx' and W == 4) else 8
				b = get(s2) if isinstance(s2, str) else (vrd(s2) if not width16 or True else vrd(s2))
				if len(b) < len(a): b = b + b
				xset(d, pack([(x + y) & ((1 << (8 * w)) - 1) for x, y in zip(lanes(a, w), lanes(b, w))], w)); continue
			if vo == 'pxor': b = get(s2); xset(d, bytes(x ^ y for x, y in zip(a, b))); continue
			if vo in ('psrld', 'pslld', 'psrlq', 'psllq'):
				w = 4 if vo.endswith('d') else 8; m = (1 << (8 * w)) - 1
				xset(d, pack([((x >> imm) if vo[2] == 'r' else ((x << imm) & m)) for x in lanes(a, w)], w)); continue
			if vo == 'pshufb':
				m = get(s2)
				xset(d, b''.join(bytes(0 if (mb & 0x80) else a[i + (mb & 15)] for mb in m[i:i + 16]) for i in range(0, len(a), 16))); continue
			if vo == 'palignr':
				b = get(s2)
				xset(d, b''.join((b[i:i + 16] + a[i:i + 16])[imm:imm + 16] for i in range(0, len(a), 16))); continue
			if vo == 'pshufd':
				xset(d, perlane(a, lambda blk: pack([lanes(blk, 4)[(imm >> (2 * k)) & 3] for k in range(4)], 4))); continue
			raise Exception(ins)
		if op == 'vzeroupper': continue
		if op in ('mov', 'load'):
			wide = 8 if (ins[1] in ('rsp', 'rcx') and ins[2] == 'rsp') or ins[1] == 'rsp' or (isinstance(ins[2], tuple) and ins[2][0] == 'in') else W
			wr(ins[1], rd(ins[2], wide), wide); continue
		if op == 'store': wr(ins[1], rd(ins[2], W), W); continue
		if op == 'movq': wr(ins[1], rd(ins[2], 8), 8); continue
		if op == 'add':
			width = 8 if ins[1] in ('rdx', 'rsi') and ins[2] in ('rsi', 'rdx') else W
			wr(ins[1], rd(ins[1], width) + rd(ins[2], width), width); continue
		if op == 'sub': wr(ins[1], rd(ins[1], 8) - rd(ins[2], 8), 8); continue
		if op == 'addm': wr(ins[1], rd(ins[1], 8) + ins[2], 8); continue
		if op == 'and':
			if ins[1] == 'rsp': wr('rsp', rd('rsp', 8) & (ins[2] & ((1 << 64) - 1)), 8); continue
			wr(ins[1], rd(ins[1], W) & rd(ins[2], W), W); continue
		if op == 'xor': wr(ins[1], rd(ins[1], W) ^ rd(ins[2], W), W); continue
		if op == 'andn': wr(ins[1], (~rd(ins[2], W)) & rd(ins[3], W), W); continue
		if op == 'rorx':
			x = rd(ins[2], W); n = ins[3]; wr(ins[1], ((x >> n) | (x << (8 * W - n))) & M, W); continue
		if op == 'ror':
			x = rd(ins[1], W); n = ins[2]; wr(ins[1], ((x >> n) | (x << (8 * W - n))) & M, W); continue
		if op == 'shl': wr(ins[1], rd(ins[1], 8) << ins[2], 8); continue
		if op == 'lea': wr(ins[1], rd(ins[2], 8) + ins[3], 8); continue
		if op == 'cmp': flag = rd(ins[1], 8) < rd(ins[2], 8); continue
		if op == 'jb':
			if flag: pc = labels[ins[1]]
			continue
		raise Exception(ins)
	digest = b''.join(int.from_bytes(state[k * W:(k + 1) * W], 'little').to_bytes(W, 'big') for k in range(8))
	return digest

def selfcheck(kern):
	rnd = random.Random(41)
	for n in range(200):
		length = rnd.choice([0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 1000, rnd.randrange(0, 3000)])
		msg = bytes(rnd.getrandbits(8) for _ in range(length))
		ours = run(kern, msg)
		if ours is None: continue
		ref = (hashlib.sha256 if kern.bits == 256 else hashlib.sha512)(msg).digest()
		if ours != ref: raise SystemExit('РАСХОЖДЕНИЕ %d/%s/%s длина %d' % (kern.bits, kern.vex, kern.bmi, length))
	return True

if __name__ == '__main__':
	sys.stdout.write(header())
