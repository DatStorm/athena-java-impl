package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Gen;
import project.athena.Sigma1;
import project.dao.*;
import project.dao.sigma1.ProofKeyInfo;
import project.elgamal.ElGamal;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
//import java.util.SecureRandom;

@Tag("TestsSigma1")
@DisplayName("Test Sigma1")
public class TestSigma1 {

    private Random random;
    private final int kappa = CONSTANTS.KAPPA;
    private SK_R sk_r;
    private PK_SK_FRAKM pk_sk_m;
    private Sigma1 sigma1;



    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        sigma1 = new Sigma1();
        this.random = new Random(0);
        Randomness r = new Randomness(random.nextLong());
        Gen gen = new Gen(r, kappa);

        this.pk_sk_m = gen.generate();

        MessageDigest sha3_256 = MessageDigest.getInstance("SHA3-256");

        this.sk_r = new SK_R(this.pk_sk_m.getSK(), r);

    }

    @Test
    void TestFRAKM() {

        ElGamal elGamal = new ElGamal(CONSTANTS.ELGAMAL_BIT_LENGTH);
        BigInteger start = BigInteger.ONE;
        BigInteger end = elGamal.getP().subtract(BigInteger.ONE);
        FRAKM frakm = new FRAKM(start, end);
        assertEquals(frakm,true);
    }
    @Test
    void TestValues() {

        KAPPA_PK_M kappa_pk_m = new KAPPA_PK_M(this.kappa, this.pk_sk_m.getPK(), this.pk_sk_m.getFRAKM());


        ProofKeyInfo rho = sigma1.ProveKey(kappa_pk_m, this.sk_r, this.kappa);
        boolean verification = sigma1.VerKey(kappa_pk_m, rho, this.kappa);


        assertTrue("Should return 1", verification);
    }




}
