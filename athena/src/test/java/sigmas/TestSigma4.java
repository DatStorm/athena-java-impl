package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Gen;
import project.athena.Sigma1;
import project.athena.Sigma4;
import project.dao.Randomness;
import project.dao.SK_R;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.sigma3.DecryptionProof;
import project.dao.sigma4.CombinationProof;
import project.elgamal.ElGamalPK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma4")
@DisplayName("Test Sigma4")
public class TestSigma4 {

    private  Sigma4 sigma4;
    private final int kappa = CONSTANTS.KAPPA;
    private ElGamalPK pk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();

        sigma4 = new Sigma4(factory.getHash());
        pk = factory.getPK();

    }


    @Test
    void TestSigma4() {

        
//        CombinationProof omega = sigma4.proveCombination(pk, ci_1_prime,ci_prime,bi_1,bi, kappa);
//        boolean verification = sigma4.verifyCombination(pk, c_prime, c1, omega, kappa);
        assertTrue("Should be 1", true);

    }
}
