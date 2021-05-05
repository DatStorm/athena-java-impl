package cs.au.athena.elgamal;


import cs.au.athena.CONSTANTS;
import cs.au.athena.UTIL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

public class ElGamal {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ElGamal: ");

    private Group group;
    private Random random;

    private int messageSpaceLength;
    private Map<BigInteger, Integer> lookupTable;

    public ElGamal(Group group, int messageSpaceLength, Random random) {
        if (messageSpaceLength < 0) {
            System.err.println("ERROR messageSpaceLength < 0");
        }

        this.random = random;
        this.group = group;
        this.messageSpaceLength = messageSpaceLength;

        // Generate lookup table for decryption
        BigInteger g = group.g;
        BigInteger p = group.p;

        lookupTable = new HashMap<>();
        for(int i = 0; i < messageSpaceLength; i++) {
            lookupTable.put(g.pow(i).mod(p), i);
        }
    }

    public ElGamal(Group group, Random random) {
        this.group = group;
        this.random = random;
    }

//    public ElGamal(int bitLength) {
//        this(bitLength, new SecureRandom());
//    }

    public static Map<BigInteger, Integer> generateLookupTable(Group group, int length) {
        Map<BigInteger, Integer> lookupTable = new HashMap<>();
        for(int i = 0; i < length; i++) {
            BigInteger element = group.g.pow(i).mod(group.p);
            lookupTable.put(element, i);
        }

        return lookupTable;
    }

    public Map<BigInteger, Integer> getLookupTable() {
        return this.lookupTable;
    }

    @Deprecated // Use generateGroup instead, and pass group to constructor.
    public ElGamal(int bitLength, int messageSpaceLength, Random random) {
        this(generateGroup(bitLength, random), messageSpaceLength, random);

    }

    public static Group generateGroup(int bitLength, Random random) {
        // SECURE == 2048
        BigInteger p, q, g;
        do {
            p = BigInteger.probablePrime(bitLength + 1, random); // p=2q+1
            q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = (p-1)/2

        } while (!q.isProbablePrime(bitLength)); // call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^{certainty})

        g = UTIL.getRandomElement(BigInteger.TWO, p, random).modPow(BigInteger.TWO, p);
        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }
        assert g.modPow(q, p).equals(BigInteger.ONE) : "ElGamal group defined wrong, i.e. q definition is no good";

        return new Group(p, q, g);
}

    public static Group generateEfficientGroup(int bitLength, Random random) {
        // SECURE == 2048
        BigInteger p, q, g, h;
        BigInteger r = BigInteger.valueOf(8);

        long i = 0;
        do {
            p = BigInteger.probablePrime(bitLength + 1, random); // p=Xq+1
            q = p.subtract(BigInteger.ONE).divide(r); // q = (p-1)/X


            if (i % 100000L == 0) {
                logger.info(MARKER, String.format("Iteration %d and still sampling p, q!", i));
            }

            i++;

        } while (!q.isProbablePrime(bitLength)); // call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^{certainty})

        logger.info(MARKER, "primes found");
        logger.info(MARKER, String.format("p:%d",p));
        logger.info(MARKER, String.format("q:%d", q));
        i = 0;
        do {
            h = UTIL.getRandomElement(BigInteger.TWO, p, random);
            // h^r != 1 (mod p)
            g = h.modPow(r, p);
//            g = h.modPow(q, p); // g = h^r mod p

            if (i % 100000L == 0) {
                logger.info(MARKER, String.format("Iteration %d and still sampling g, h!", i));
            }
            i++;

        } while(g.equals(BigInteger.ONE));

        logger.info(MARKER, String.format("g:%d", g));

        assert g.modPow(q, p).equals(BigInteger.ONE) : "ElGamal group defined wrong, i.e. q definition is no good";

        return new Group(p, q, g);
    }

    /* RUN 8
     * p:
     * q:
     * g:
     */

    /* RUN 6
     * p: 54963179570402518988601912914693605470531953298775708530081688635158076889906453281081733427750155235711360555890456652798286152143660930804286520139992868419742911884675719105799808870289260752565671720175521929825865906150730075748052045481009559458339335907020105306602045089287037450138539903091869733398739054473549376202984369196060577762412614500888139434201054566087633781400063754833062699191362006178540775701727106259159912809043644712083701202770429667492619665879674196413431707433772633280775726659155128493186140975671674691727285766422367419056104944149582689211276556683188082751512288218096336243467
     * q: 9160529928400419831433652152448934245088658883129284755013614772526346148317742213513622237958359205951893425981742775466381025357276821800714420023332144736623818647445953184299968145048210125427611953362586988304310984358455012624675340913501593243056555984503350884433674181547839575023089983848644955566456509078924896033830728199343429627068769083481356572366842427681272296900010625805510449865227001029756795950287851043193318801507274118680616867128404944582103277646612366068905284572295438880129287776525854748864356829278612448621214294403727903176017490691597114868546092780531347125252048036349389373911
     * g: 20595159751250889635950034581309397431972150980180179361873850963119486245002205668493852362955741673470987210100334284832110923699605282477443679390753017795316125299212604620592282347795725963460379599875688816699378516650519266699055245439857508637565491196682467376496334367730254976787414362075012808549164201358147322315029824058495789009921319838807652380246246154219410868915417488424648671811266507844568074407918689859403238467745062653357581879311867376226887276754750460627148950615425870693919070958013433991921554940552140054502525822087652828890217833137041011667630837748536305005308413713578959094914
     */

    /* RUN 4
     * p: 35186612523268353110024774944405818290491921368182496041276046088547181562326508682111553006085789187878337609487559164482916705392916429922330444984030513638747565745035516899622031081427512968286808265324842933855759717051510566345745574893747815792365119390863606587409727535956385399641900505947359016517788571265009250901008011599183550986324084252206074586264314360105033700680883308220588878194611488201729782391727507602889014852589233885391989182551041057426846432506371979808860637671248794800931027002867651011074848352969431909546428756546981980905508051924861186960197486485098070946605804207211293882317
     * q: 8796653130817088277506193736101454572622980342045624010319011522136795390581627170527888251521447296969584402371889791120729176348229107480582611246007628409686891436258879224905507770356878242071702066331210733463939929262877641586436393723436953948091279847715901646852431883989096349910475126486839754129447142816252312725252002899795887746581021063051518646566078590026258425170220827055147219548652872050432445597931876900722253713147308471347997295637760264356711608126592994952215159417812198700232756750716912752768712088242357977386607189136745495226377012981215296740049371621274517736651451051802823470579
     * g: 19872245896634532359432175739763000555859452416230183422586862808221102682321219524349763494515471059276546660957847021945548439605288847647740860214217188487348458467830896875655584053509364323447611329384962509645426607999317944842222245011915467053671907165097481137526930473485731877457876620207555220473936452060710149606496062514392424326048006645885547332529115110555386880686413652377419733504176998687000151027834764536255796389729168947564090647025833627087310228671009961151380007587557246048535278364308242222488345900733215223861666750814314335785724324071282160124818423607826341524730382443870833832227
     */

    /* RUN 2
     * p: 22738587019229374483357020027558654791203886567107685040559222322321716345302078237685371286206045002740135661182140055040683205371452622142475268817211096102060317787679078469670525666996305989751364195084493285999102114984105472940170355892545360936832150885981804484706336521294943939063615931695732357274467720681742726310749639752735737824190554016698142102253216469906831444950183819873017201059721460325469534267817619394341555756712002230610846168609771357978095733979459871735300404804928345139023743643500521112149053947750591677676770987431977155577047230145623510513338128970369400666671076669931477173503
     * q: 2842323377403671810419627503444831848900485820888460630069902790290214543162759779710671410775755625342516957647767506880085400671431577767809408602151387012757539723459884808708815708374538248718920524385561660749887764373013184117521294486568170117104018860747725560588292065161867992382951991461966544659308465085217840788843704969091967228023819252087267762781652058738353930618772977484127150132465182540683691783477202424292694469589000278826355771076221419747261966747432483966912550600616043142377967955437565139018631743468823959709596373428997144447130903768202938814167266121296175083333884583741434646687
     * g: 12286334319373217938546665142470628148388705702188568497752845048628702483730498447521759279947672506663223397790752231756068156643176949642487709042105009523002101403177849858825805955703481983883795736802707297791591965915682090851431651020978979881957169381518005918950415927699943636154731216067249298400249531097545980593850554695435974980867436814322189991194192021957328751095007404874372060900788986187695999951313631587285400143526422608893588902292826815143272581794941017035785217148016527162859590614068042302468674973524673444925838098858050900320763326988733620642089651441027670807810264603513077528269
     */

    /* RUN 1
     * p: 31189695126940392256895216267495486375714740284715475389059648915635619458140839136352959437420871931393532676676149544197677631584838954448198882386008852735546370065152719994384602036956578597488733616378399450822088810749943095529041798167121456986570849153162958168179679494264001914977035450089112293829760401140837720285287506963278899039674021330543518986579784689913942272455856095803278713632522932667698535935593287037476059448747583923437332811300564817161728594515234461584828960743033728962149002202370764604958494515616769409466507932849328104873413764730844992021997597139610988312500818333737787650171
     * q: 3898711890867549032111902033436935796964342535589434423632456114454452432267604892044119929677608991424191584584518693024709703948104869306024860298251106591943296258144089999298075254619572324686091702047299931352761101343742886941130224770890182123321356144145369771022459936783000239372129431261139036728720050142604715035660938370409862379959252666317939873322473086239242784056982011975409839204065366583462316991949160879684507431093447990429666601412570602145216074314404307698103620092879216120268625275296345575619811814452096176183313491606166013109176720591355624002749699642451373539062602291717223456271
     * g: 10647913823944883719724649650159427871445753721334881643025195148927373822131958145202195554276380300207287107636316504406719687860910499666399536171863910434446574985098515605239363025353652766392161435280980526511320019089718222039189412224103067051020195441156048680807000933107647807683122736233196061115382669059334037224165189924930076023996697259354380967644800350243135835431410334980619910459906373252843569885006731120312163095284796598125772710436520186093473278848247100319422146505128931604977317459314189768796835360426163346807621302815970201571052100716187321871618486706344421867126048785606418769868
     */

    public Group getDescription() {
        return group;
    }

    /**
     * Precondition: messageElement should be in the group
     * @param messageElement A group element in group G
     * @param pk
     * @return
     */
    public Ciphertext encrypt(BigInteger messageElement, ElGamalPK pk) {
        return encrypt(messageElement, pk, this.random);
    }

    public static Ciphertext encrypt(BigInteger messageElement, ElGamalPK pk, Random random){
        BigInteger r = UTIL.getRandomElement(BigInteger.ZERO, pk.group.q, random);
        return encrypt(messageElement, pk, r);
    }

    public static Ciphertext encrypt(BigInteger messageElement, ElGamalPK pk, BigInteger r){
        BigInteger p = pk.group.p;
        BigInteger q = pk.group.q;
        r = r.mod(q).add(q).mod(q);

        // We dont know how to check group membership, but lets just check group order for safety.
        assert messageElement.modPow(q, p).equals(BigInteger.ONE) : "This Group order fucks up!!!";

        // Extract public key
        BigInteger g = pk.group.g;
        BigInteger h = pk.h;

        // C = (g^r, m·h^r)
        return new Ciphertext(g.modPow(r, p), messageElement.multiply(h.modPow(r, p)).mod(p));
    }

    public Ciphertext exponentialEncrypt(BigInteger msg, ElGamalPK pk) {
        BigInteger r = UTIL.getRandomElement(BigInteger.ZERO, group.q, this.random);
        return exponentialEncrypt(msg, pk, r);
    }

    // Exponential ElGamal
    public Ciphertext exponentialEncrypt(BigInteger msg, ElGamalPK pk, BigInteger r) {
        BigInteger p = pk.group.p;
        BigInteger q = pk.group.q;
        r = r.mod(q).add(q).mod(q);

        msg = msg.mod(q).add(q).mod(q);
        if (msg.compareTo(q) >= 0) {
            System.err.println("Message was not be in Z_q. ElGamal encrypted msg.mod(q)");
        }

        if (msg.signum() == -1) {
            throw new IllegalArgumentException("BigInteger must be positive. Was " + msg);
        }
        // Extract public key
        BigInteger g = pk.group.g;

        // C = (g^r, g^m·h^r)
        BigInteger messageElement = g.modPow(msg, p);
        return encrypt(messageElement, pk, r);
    }

    public static BigInteger getNeutralElement() {
        return BigInteger.ONE;
    }

    public Integer exponentialDecrypt(Ciphertext cipherText, ElGamalSK sk) {
        return lookup(decrypt(cipherText, sk));
    }

    public static Integer exponentialDecrypt(Ciphertext cipherText, Map<BigInteger, Integer> lookupTable, ElGamalSK sk) {
        return lookup(lookupTable, decrypt(cipherText, sk));
    }


    // Decrypting El Gamal encryption using secret key
    public static BigInteger decrypt(Ciphertext cipherText, ElGamalSK sk) {
        BigInteger c1 = cipherText.c1;
        BigInteger c2 = cipherText.c2;
        BigInteger p = sk.getPK().getGroup().getP();
        BigInteger c1Alpha = c1.modPow(sk.toBigInteger(), p);      // c1^\alpha
        BigInteger c1NegAlpha = c1Alpha.modInverse(p); // c1^-\alpha

        // plain = g^m  (look up table to find it needed)
        return c2.multiply(c1NegAlpha).mod(p);
    }

    public Integer lookup(BigInteger element) {
        return lookup(this.lookupTable,element);
    }

    public static Integer lookup(Map<BigInteger, Integer> lookupTable, BigInteger element) {
        if(!lookupTable.containsKey(element)){
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt Dec_sk(c) = g^m = " + element + CONSTANTS.ANSI_RESET);
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt           table = " + UTIL.lookupTableToString(lookupTable) + CONSTANTS.ANSI_RESET);
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt: Possible votes = " + lookupTable.values() + CONSTANTS.ANSI_RESET);
            throw new IllegalArgumentException("Ciphertext is not contained in the decryption lookup table. The value must be smaller than: " + Collections.max(lookupTable.values()));
        } else {
            return lookupTable.get(element);
        }
    }

    // Generate random sk
    public ElGamalSK generateSK() {
        return generateSK(this.group, this.random);
    }

    // Generate random sk
    public static ElGamalSK generateSK(Group group, Random random) {
        if (group == null) {
            System.out.println("group = null");
            throw new NullPointerException("Group was null");
        }

        BigInteger q = group.q;
        BigInteger sk = UTIL.getRandomElement(q, random);

        return new ElGamalSK(group, sk);
    }



    // Generating El Gamal public key from a specified secret key
    public ElGamalPK generatePk(ElGamalSK sk) {
        BigInteger g = this.group.getG();
        BigInteger p = this.group.getP();
        BigInteger h = g.modPow(sk.toBigInteger(), p);
        return new ElGamalPK(h, this.group); // return pk=(g,h)
    }

    public BigInteger getP() {
        return this.group.getP();
    }

}
