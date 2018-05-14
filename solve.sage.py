
# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419 = Integer(145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419); _sage_const_128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073 = Integer(128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073); _sage_const_256 = Integer(256); _sage_const_8 = Integer(8); _sage_const_739904609682520586736011252451716180456601329519 = Integer(739904609682520586736011252451716180456601329519); _sage_const_16 = Integer(16); _sage_const_52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443 = Integer(52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443)
import hashlib

'''
DEFCON Quals 2018 Official: Crypto part
Partial random-value Exposure Attack for DSA (<=> biased-k DSA)
References: https://crypto.stackexchange.com/questions/44644/how-does-the-biased-k-attack-on-ecdsa-work
Thanks: @Bono_iPad and binja members
'''

y=_sage_const_128135682856750887590860168748824430714190353609169438003724812869569788088376999153566856518649548751808974042861313871720093923966663967385639616771013994922707548355367088446112595542221209828926608117506259743026809879227606814076195362151108590706375917914576011875357384956337974597411261584032533163073 
p=_sage_const_145774370140705743619288815016506936272601276321515267981294709325646228235350799641396853482542510455702593145365689674776551326526283561120782331775753481248764911686023024656237178221049671999816376444280423000085773391715885524862881877222848088840644737895543531766907185051846802894682811137086905085419 
q=_sage_const_739904609682520586736011252451716180456601329519 
g=_sage_const_52865703933600072480340150084328845769706702669400766904467248075164948743170867377627486621900744105555465052783047541675343643777082719270261354312243195450389581166294097053506337884439282134405767273312076933070573084676163659758350542617531330447790290695414443063102502247168199735083467132847036144443 


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-_sage_const_1  if aa < _sage_const_0  else _sage_const_1 ), lasty * (-_sage_const_1  if bb < _sage_const_0  else _sage_const_1 )

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != _sage_const_1 :
        raise ValueError
    return x % m

# collected data like `r,s`
# we collect 1500~ signatures but used only 100 signatures
# rs_data = map(lambda z: map(int, z), filter(lambda y: y[0] != '', map(lambda x: x.split(','), open('rs_collect.txt').read().split('\n'))))

rs_data = [(593275456000063119675354884190770498777114839100L, 578587951046676036097422817589879430723059292439L), (440498180407414431882152231382392814915743290071L, 448863286011376865902903234114301694175563137451L), (424970119165911629153386671601742366711674921803L, 294949796428458024013399070676607026409383104264L), (221462250746426469394374785274996933194118953954L, 76667894940176231711042150435082943822134146929L), (211478506600410543007676752415469405732458825091L, 334617345949068421751239236009220161381716532177L), (119752803537552207888585401849161201498005807549L, 116739605394265911309094944769682577263122066970L), (645714283196274937592522052900223154798601608556L, 693127331862177062176184216484136210183821031882L), (727423007379660260976607141795066725778132458207L, 486764248826660114540416184739795627605523188115L), (276842525527668096678304634451315541849291055189L, 621605545844981263021136377090626315975265536764L), (402100471161282942837778474938781267856119229581L, 69445373565438089730924829359174491978315358704L), (572276042111324924806861488348714640667200041266L, 153495767207739609095395548895230089477644232204L), (373637734563755618674904227811874863647368874607L, 216496833801507264197437233926846028046383430559L), (559763822648916691868398780652427549285867011135L, 600303229645590363484047527392056327737130317404L), (700780686608095242884747558718724431935103398976L, 481823318036878265067468240033047211216648347531L), (682189307302393722439091737131273946187382305553L, 228160006463572695649597469830482268819590061893L), (39010123101336655373013911258812794959035486012L, 687457183801045527022454646814088884967168801336L), (170736983535582774205679966848281091579898517329L, 251449694705315835906854246952605488549666731759L), (477648240911483346272901402654688223401824045344L, 643401786977072320050750627401009777349792001070L), (285611846254205707082602375712261236622590247000L, 403304614620349689911272923978725354504556549117L), (189701585521994400361843777407447745975000420469L, 403268298466908191359503457889783034741100833969L), (709298765710893797328789118450800547017770533939L, 511039803199596433900960245224752786802478054122L), (722293475131507342151195798888450133460136070069L, 614753842750193744954859349138268447024063201409L), (665021454225162151805946459582648869302704205691L, 8220723540269144511167991493075356225673645715L), (399286554951711316940738281416963588324115305048L, 356059648557384608584075711112666670062717812075L), (593167894225008835215146726336200973815622673173L, 651475240466110100242114407704484991433405532587L), (448923102303600103133995942877856829532211572593L, 584585389599088809525643191261059998443421594939L), (724669682788131948674620507486533439538128394444L, 73594499387215140011425139932879988838492777792L), (373163318288288953665612680704788043342015729270L, 362426695945895106911812789005879060432916986142L), (20015096749204866573738900312219141487669363581L, 120054762547266248970016383030086993395803601137L), (398445955536319491442553909561204428117800545974L, 243011206375898652446753351702807780022829915871L), (397448455762064828509581732011805419364035557813L, 361427940281547952422294852380507752976925962987L), (536812016849110094246941056119920925647304272175L, 545035993372742733381421382340167049152210701973L), (696378684328671171080868349323124255762720814297L, 64316788933251377774268160968984210460242850932L), (218793392008266705587522498712268923455383441989L, 737890665311029437909082450215900283396943983604L), (70959389246799399693325398844770434227436721275L, 165575900385289066026332622328970949550938199149L), (111688673150204982354018681898423957901200203286L, 618489674960797509056644688987895477281571330107L), (74027620115549690197371233393143626526531813286L, 430175376287341936910299677886048299125580045661L), (567041766455677317961641563015163596791728200121L, 542903798317548157402271405047777467005547055240L), (30281981914424235337655902406754870161602331235L, 433966754707314507000247640236180882575314980191L), (516457612835991659902325193088172729915176389028L, 504750856546771382735810797061409550806669270167L), (576106892092520403744956801270962219684655350700L, 20692142378769443059083820662982305232805004618L), (350700042641651192472768989204877742327557012346L, 726772610618816827000036997609888495950613173379L), (72561181472294872199903417127804031969703127583L, 526278180558813303506905674809983916843797071687L), (163537870236549529919053511306069415313016253183L, 731680831709227810465787602499113713223105964002L), (626485740109513349917624638381431652050194273482L, 121173405830126318431215404668025335249832339529L), (91502294912630688549048131890812521932547180298L, 219609531259751514669459898533153809928166076075L), (208437205431326266585532450459237409433785835599L, 478966857619603488942399349781880036737716298579L), (435146014067900154898930543659815824095037166346L, 430220797449471888749258962820269639605835113303L), (73757137788077061756916977410459895044355494051L, 170389823720846534769583098177678955792964475791L), (333456801076359271315045837603585799844639313992L, 701031979172161933412986522460970317030053005762L), (614267721935438348748883500587888489231836114119L, 370115471273741294049862983745496266904495732532L), (207594689550764923511329695388022835048086596851L, 557863084754367383987677135509345180129502486896L), (180581943199535350609054278510981997141064312775L, 554624647101003333076488482055000718679135416329L), (521938139340800248006692955375443229977743493967L, 10276541758936713688991022181494870549164768660L), (230120313948187910887809655884133753382596227605L, 336808042385009780577748194455874907496672606168L), (300721714081914016217261421085570871747961373140L, 528273564717455421205621995987445400443535196075L), (79410675175545121063655695440018431851601359235L, 542072197961159267036090709712498857415569641826L), (219146957703097298856728583009770700904342174033L, 627422924624974151118368997426591022256072889161L), (601908118321314004432505451249735672787003008115L, 166807077961312139347005053102579765447125770821L), (169337549681118076522113552244766940985032355247L, 461412738566357808720937575031742746317296445778L), (200297426020405802745392752462835277649858122127L, 462836393673145527170363362846934300382482877301L), (554906424572944097670701037509587062731930617340L, 678235143605605401735685521749931544763499016027L), (486373100214007056593584122246155008438698927274L, 12224840336893820915013303714644485822751914066L), (440350027084223394596154639681718542988826605386L, 424681803932992624106710058539667874732507592422L), (165941917406432640381855105259907840627013615208L, 465232859733406398557196972978053088256437415842L), (551149752242231696579657364481965906012231805154L, 224051413814448584062094867684041999384425004949L), (50004667112489296232853453968049742412382992946L, 363663781282961585025289221307856387737076597489L), (670366293609435519950587169517809731083986419024L, 430394657079494304727543934567369067128962154704L), (183174090464074934928042733716049157508812584427L, 481085191392638020003642013423479552201421535520L), (562100133022490465566890977055578498290000168482L, 627301490880821553661548269387520505622102459265L), (627977776424205629912357332332220197507795839326L, 720694854614039920805170588368024471064098124769L), (142069537987904690730663133904580985917124091519L, 435570652484412144790916647349086650112551200415L), (133078955011325203805950491320978318973762640492L, 224563021727706602364972352066142912330160048086L), (523033226496608086445385432448638051402858023223L, 400716609482475657009355088304149473260718424282L), (55190591691509497979220950574207057564968797562L, 627334654958083989200658447149884308093551802847L), (441438905269291793194662262916321630605743956426L, 629853714068030957842850642369274278127079959022L), (271383434069452289051594828055572259715641424340L, 500356998225870376680496722775135810499375208695L), (85449645546245618126193595755752702928646319132L, 59404328839732412079357771982212847907269496234L), (544838186677297080742400924168078163923000767153L, 343938428968261794671887574926884578873705862779L), (5298561971379201641435962951113450925191040170L, 100174159495414973022232601526174602332218085023L), (486862280580107993790698245915508974961325155263L, 499155405726070450968575227225369634370204412474L), (493800727818979143263957321195822660701789974618L, 458334318457063062496798273842412946741506891108L), (159884123962323943153460505500846950544006017487L, 162808758856264297690852118207175498574919674033L), (415610691154099413575426912576346621636072749503L, 522114239376333663747760139098914392463505814509L), (178899565187148652934392215884837950723188178352L, 485839760071749565304369349542175550689079605338L), (294256125310284814113222640372333242457518783934L, 668424852502814260271479746038008132587098168582L), (64251422743152566571726214446457834216308880925L, 638514698701385671652485018030356137225272210191L), (717385030634910386623244862382966639553859418571L, 210282556956489039844036242798183360373499737360L), (491988842576887678439909322843885543755351583377L, 126768148179010965225364462943665391643594475974L), (338438903582018560120448668173727938413250768442L, 119970086863196388532491200499481743429612322646L), (379848558832646432258408973012920980150467729345L, 149560740088282167096895404601704866001447416682L), (188383768309810557404131133062868837239533032884L, 624864316789203241855857000428954611223928936307L), (518440303069132371838586723992836081898152075010L, 213557018682598612593808680759773665217498614666L), (108067077551598119837123812559585383154154039143L, 624637294612376521273434328323167453043473621238L), (733557443035782447800862633427625566287040737963L, 106792797848232069668073628052550667745500316032L), (177474186960240667325040392806580675491673372589L, 130782850058891548557887962902548290320087244485L), (463014591493974578783659999681318347474299279864L, 309950276337453803380969391811544680317657606533L), (580674375011117543465804740482517421940816173655L, 251138476986986097986387750752413270911759177119L), (250191710398450331646269344634245590775672530713L, 182325067803192638795384519263715441227446265993L), (563259403243753802021213610152586530503103117673L, 716553125405724238490755322494878280786997052165L)]

H = int(hashlib.sha1('ls' + 'A' * (_sage_const_256  - _sage_const_2 )).hexdigest(), _sage_const_16 )

# verify
r, s = rs_data[_sage_const_0 ]
w = modinv(s, q)
u1 = (H * w) % q
u2 = (r * w) % q
v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
assert v == r

# we know the k's lowest byte is zero-filled <=> k = 2**8 * b
ell = _sage_const_8 

n = len(rs_data)

# Matrix construction & Solve HNP using LLL
M = []
for i in xrange(n):
  M += [[_sage_const_0 ] * i + [q] + [_sage_const_0 ] * (n - i + _sage_const_1 )]
t_vec = []
u_vec = []
for i in xrange(n):
  r, s = rs_data[i]
  T = modinv(_sage_const_2 **ell * s, q)
  t = (r * T) % q
  u = (-H * T) % q
  t_vec += [t]
  u_vec += [u]

# sentinel value
sT = _sage_const_1 
sU = _sage_const_1 

M += [t_vec + [sT, _sage_const_0 ]]
M += [u_vec + [_sage_const_0 , sU]]

print(M)
# print "[+] LLL"
# B = LLL(M)

# Search Shortest & Useful Vector
# for i, v in enumerate(B):
#   if v[-1] == sT:
#     x = -v[-2] / sU
#     print x
#     print x % q
#     print (x % q).bit_length()
#     break
