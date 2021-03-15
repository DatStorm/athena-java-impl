package sigmas;

import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.sigma.Sigma3;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma3")
@DisplayName("Test Sigma3")
public class TestSigma3 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma3 sigma3;
    private Sigma3Statement statement;
    private ElGamalSK sk;
    private Ciphertext cipher;
    private BigInteger plain_msg_m;



    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        ElGamal elGamal = factory.getElgamal();
        ElGamalPK pk = factory.getPK();
        sk = factory.getSK();
        sigma3 = new Sigma3(factory.getHash());

        plain_msg_m = new BigInteger("491");

        cipher = elGamal.encrypt(plain_msg_m, pk);
        statement = sigma3.createStatement(pk, cipher, plain_msg_m);
    }


    @Test
    void TestSigma3_checkPart1() {
        // ProveDec s1 = ProveDec(...)'
        Sigma3Proof proof = sigma3.proveDecryption(cipher, plain_msg_m, sk, kappa);
        BigInteger c = sigma3.hash(proof.a, proof.b, statement.alpha, statement.beta, statement.alpha_base, statement.beta_base);
        boolean check1 = sigma3.checkPart1(statement.alpha_base, proof.r, proof.a, statement.alpha, c, statement.group.p);
        assertTrue("Verify check1", check1);

    }

    @Test
    void TestSigma3_checkPart2() {
        Sigma3Proof proof = sigma3.proveDecryption(cipher, plain_msg_m,sk, kappa);
        BigInteger c = sigma3.hash(proof.a, proof.b, statement.alpha, statement.beta, statement.alpha_base, statement.beta_base);
        boolean check2 = sigma3.checkPart2(statement.beta_base, proof.r, proof.b, statement.beta,  c, statement.group.p);
        assertTrue("Verify check2", check2);
    }


    @Test
    void TestSigma3() {
        Sigma3Proof sigma3Proof = sigma3.proveDecryption(cipher, plain_msg_m,sk, kappa);
        boolean verification = sigma3.verifyDecryption(cipher, plain_msg_m, sk.getPK(), sigma3Proof, kappa);
        assertTrue("VerDec(...)=1", verification);
    }


    @Test
    void TestSigma3ValuesFromAthena() {

//        Sigma3Proof sigma3Proof = sigma3.proveDecryption(cipher, plain_msg_m,sk, kappa);

        BigInteger c1 = new BigInteger("198996949930957919312247894293679105084250587335413311701311079882556290162755681710764409819419930597860422954590339050224310352931560900893659535434516913729576734002784456527294230657361157748194378413122306741303349662221707983314503554859111166131319540908048201946513636511225323887970385623808186897877");
        BigInteger c2 = new BigInteger("173661766409191321718696305134792978006740201463289185588703423263265705515050988003079713777346829406348716755991977109227263983087161663814884393240304657104275917581007580569247135174824604543918449693655048289158420857530965456487271606922017146354260551241074918671886817726887868234208025248457142155081");
        Ciphertext ci_prime = new Ciphertext(c1,c2);
        BigInteger Ni = new BigInteger("122481878830081892567663719282227468232817072462902826318011956526331656047716568235454829046433188881463427976530663582897721314105182421866162365116147976649929397328215273107478951880192347815089878709299747297583275755745623688191347256145335647408820359538488634538127406436220386260048473163335336375702");

        Sigma3Statement fixedstmnt3 = Sigma3.createStatement(sk.getPK(), ci_prime, Ni);


        BigInteger a = new BigInteger("116719213787343078469281108636526543548639009080874159278876150321227499967206383577049974121950651363054663189635757921187903724022199496892383776487291601362446933148682407903791780932539641610908633703272285351201940229096612679233542720511658837551181401340139496073074657438367850233276860781334774490488");
        BigInteger b = new BigInteger("70926059554549386054085059012641405320227489070725097156871225448968214513706488025050392313726160627107950341084013603469164709691523507989071008065330219149231801124242848018952167433554802369486882749172721980283851232510709535021725885223592281669006743932328013972027626941481967395049271380513158144995");
        BigInteger r = new BigInteger("56993834869462959468377903886910997295572530489113334845843522462194433419572634914299250082794079198172482928060883047305448881846435456436469326870903656428971930716499004204430051940959871738521709501483714406105439727733563607169492335450824704670749292017633573120769269757394720284521966654359791869986");
        Sigma3Proof sigma3Proof = new Sigma3Proof(a,b,r);
        boolean verification = sigma3.verifyDecryption(fixedstmnt3, sigma3Proof, kappa);
        assertTrue("VerDec(...)=1", verification);
    }




}
