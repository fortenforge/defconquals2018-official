
# This file was *autogenerated* from the file end_to_end.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419 = Integer(145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419); _sage_const_128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073 = Integer(128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073); _sage_const_256 = Integer(256); _sage_const_8 = Integer(8); _sage_const_739904609682520586736011252451716180456601329519 = Integer(739904609682520586736011252451716180456601329519); _sage_const_1234567 = Integer(1234567); _sage_const_16 = Integer(16); _sage_const_52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443 = Integer(52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443); _sage_const_70 = Integer(70)
import hashlib

p = _sage_const_145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419 
q = _sage_const_739904609682520586736011252451716180456601329519 

Rq = Integers(q)
Rp = Integers(p)

y = Rp(_sage_const_128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073 )
g = Rp(_sage_const_52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443 )

rs_pairs = []
with open('rs_pairs_new.txt', 'r') as f:
  for line in f:
     r, s = line.strip().split(', ')
     r, s = Rq(int(r)), Rq(int(s))
     rs_pairs.append((r,s))

def get_hash(cmd):
  return int(hashlib.sha1(cmd).hexdigest(), _sage_const_16 )

# Verify
r, s = rs_pairs[_sage_const_0 ]
h = Rq(get_hash('ls' + 'A' * (_sage_const_256  - _sage_const_2 )))
w = _sage_const_1 /s
u1 = w * h
u2 = w * r
v = Rq(pow(g, u1) * pow(y, u2))
assert v == r

# Construct lattice
n = _sage_const_70 
rs_pairs = rs_pairs[:n]
l = _sage_const_8 
L = pow(_sage_const_2 , l)

T = vector([int(r  / (L * s)) for (r, s) in rs_pairs])
U = vector([int(-h / (L * s)) for (r, s) in rs_pairs])
Q = q * matrix.identity(n)

sT = _sage_const_1 
sU = _sage_const_1 
vT = vector([_sage_const_0  for _ in range(n + _sage_const_2 )])
vU = vector([_sage_const_0  for _ in range(n + _sage_const_2 )])
vT[-_sage_const_2 ] = sT
vU[-_sage_const_1 ] = sU

'''
        [           | |   | ]
        [    q*I    | 0   0 ]
        [           | |   | ]
    M = [-----------+-------]
        [ --- T --- | sT  0 ]
        [ --- U --- | 0  sU ]
'''

M = Q.stack(T).stack(U).augment(vT).augment(vU)
B = M.LLL()

x = _sage_const_1 
for i, v in enumerate(B):
  if v[-_sage_const_1 ] == sU:
    x = Rq(-v[-_sage_const_2 ] / sT)
    break

# Check correctness
assert pow(g, x) == y

# Sign message 'cat'
h = get_hash('cat')
k = Rq(_sage_const_1234567 )
r = Rq(pow(g, k))
s = (h + x * r) / k
print('r: {}'.format(r))
print('s: {}'.format(s))
