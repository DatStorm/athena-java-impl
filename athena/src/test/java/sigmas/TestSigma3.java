package sigmas;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Gen;
import project.athena.Sigma3;
import project.dao.PK_SK_FRAKM;
import project.dao.Randomness;
import project.dao.sigma3.ProveDecryptionInfo;
import project.elgamal.ElGamal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class TestSigma3 {
    private Sigma3 sigma3;
    private ElGamal elGamal;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        MessageDigest sha3_256 = MessageDigest.getInstance("SHA3-256");
        sigma3 = new Sigma3(sha3_256);

        Gen gen = new Gen(new Randomness(new Random(0).nextLong()),CONSTANTS.KAPPA);
        PK_SK_FRAKM pk_sk_frakm = gen.generate();



    }


    @Test
    void TestSigma3() {
        ProveDecryptionInfo info = new ProveDecryptionInfo();

        sigma3.proveDecryption(info,sk, CONSTANTS.KAPPA);
    }

}
