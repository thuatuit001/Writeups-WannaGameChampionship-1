#/usr/bin/python2
from Crypto.Util.number import getPrime
import gmpy2

p = getPrime(1024)
q = getPrime(1024)
n = p*q
print n
# 19046128460580268124792418904439923628038380443228614265420753892208104167384699017880677209377989395759591201697416049286383805170787541508371508515718955340575523473825891740622486639297040981969651065677948514952134974296831008272261057223021343503211206743996697527180249217592723774774930021834627406433820336641830463392360823794688570988028821653274089530814733340477181869238461145402905191920439212888877192355189110608852253758670096831911199834500447101981710674975983733271018776412384571799375887748182868741531950257181923159967822037157631376933663317909176616732352195034753153046658158087075518071743

flag1 = open("flag1.txt", "r").read()
m1 = int(flag1.encode("hex"), 16)
e1 = 1572840401382569468846775838644864959820115464786082316205435501177464948896069977695576806151197942229295150118114329746275714634820239013512151181115838659843753236933751862822424246721512061620016115677332253038805317760297772593740667594440874673286411343455273269682959068299741244773950134363299303660437085638394927153304076489961105440193163696356770760898601459132669139268972614341313240819408991186498196955179787046690090111362440331326174662388864160477869133489143888243688568445847955557539131936453113752964986841705559145850625843267633705056895653900187431664871087050122151130232099694959966146559
c1 = pow(m1, e1, n)
print c1
# 15117416048092133274557453853729887542200128328930534843021285730677276284270477622962058237808271356979450355418169232998967691981790282765192908642906639324432221017652654762693485091329051679364260361174886319562081628266590632455952772363206926190304116699657083860035021588113707382388882159043027411833624002939539168362346246453538337138614831397000142189340100059828194454794077279541548254328526191696750603083765773127528621356185183354118653213851144253203085401947486214639332849181929418583213278367646150546527984088057117740497924375431316139015999312203952904522317319776590085425670641209493844015554