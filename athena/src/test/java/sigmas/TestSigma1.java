package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.UTIL;
import project.athena.Gen;
import project.athena.Sigma1;
import project.dao.*;
import project.dao.sigma1.CoinFlipInfo;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;


import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.Assert.*;
//import java.util.SecureRandom;

@Tag("TestsSigma1")
@DisplayName("Test Sigma1")
public class TestSigma1 {

    private final int kappa = CONSTANTS.KAPPA;
    private SK_R sk_r;
    private PK_SK_FRAKM pk_sk_m;
    private Sigma1 sigma1;
    private ElGamal elGamal;


    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        MessageDigest sha3_256 = MessageDigest.getInstance("SHA3-256");
        Random random = new Random(0);
        Randomness r = new Randomness(random.nextLong());

        Gen gen = new Gen(r, kappa);

        sigma1 = new Sigma1(sha3_256);
        elGamal = gen.getElGamal();

        this.pk_sk_m = gen.generate();
        this.sk_r = new SK_R(this.pk_sk_m.getSK(), r);

    }

    @Test
    void TestFRAKM() {

        BigInteger start = BigInteger.ONE;
        BigInteger end = BigInteger.valueOf(100);
        FRAKM frakm = new FRAKM(start, end);
        assertTrue("2 should be in range [1, 100]", frakm.isInRange(BigInteger.TWO));
        assertTrue("1 should be in range [1, 100]", frakm.isInRange(BigInteger.ONE));
        assertTrue("100 should be in range [1, 100]", frakm.isInRange(BigInteger.valueOf(100)));
        assertFalse("101 should be in range [1, 100]", frakm.isInRange(BigInteger.valueOf(101)));
        assertFalse("0 should be in range [1, 100]", frakm.isInRange(BigInteger.ZERO));
    }

    @Test
    void TestBigIntegerMod2_IntValueExact() {

        BigInteger one = BigInteger.ONE;
        boolean modedBit = one.mod(BigInteger.TWO).intValueExact() == 1;
        assertTrue("should be 1 % 2 = 1", modedBit);

        BigInteger zero = BigInteger.ZERO;
        boolean zero_modedBit = zero.mod(BigInteger.TWO).intValueExact() == 1;
        assertFalse("should be 0 % 2 = 0", zero_modedBit);


        BigInteger ten = BigInteger.valueOf(10);
        boolean ten_modedBit = ten.mod(BigInteger.TWO).intValueExact() == 1;
        assertFalse("should be 10 % 2 = 0", ten_modedBit);

        BigInteger twentyOne = BigInteger.valueOf(21);
        boolean twentyOne_modedBit = twentyOne.mod(BigInteger.TWO).intValueExact() == 1;
        assertTrue("should be 21 % 2 = 1", twentyOne_modedBit);
    }

    /**
     * Verifying the coinflip protocol.
     * f ?=? F(r,b_A)
     * @throws IOException
     */
    @Test
    void TestProveKey_Verify_step2() throws IOException {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk_sk_m.getPK(), this.pk_sk_m.getFRAKM());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk_r, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        boolean verify = sigma1.checkStep2(coinFlipInfo_pairs);
        assertTrue("fi ?=? F_i(ri,b_A_i)", verify);
    }

    @Test
    void TestProveKey_Verify_step3() throws IOException {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk_sk_m.getPK(), this.pk_sk_m.getFRAKM());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk_r, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,yj
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger yj = y1_yk.get(j);

        boolean verify = sigma1.checkStep3(coinFlipInfo_pairs, s1_sk, y1_yk, g, p, yj);
        assertTrue("bi=0 g^si = yi :: bi=1 g^si = yiyj^-1", verify);
    }

    @Test
    void TestProveKey_Verify_step4() throws IOException {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk_sk_m.getPK(), this.pk_sk_m.getFRAKM());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk_r, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,h,yj,zeta
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger h = publicInfoSigma1.getPK().getH();
        BigInteger yj = y1_yk.get(j);
        BigInteger zeta = rho.getZeta();

        boolean verify = sigma1.checkStep4(g, h, p, yj, zeta);
        assertTrue("g^zeta ?=? hy_j^-1", verify);
    }






    @Test
    void TestProveKey_Verify() throws IOException {

        ElGamalPK pk = this.pk_sk_m.getPK();
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, pk, this.pk_sk_m.getFRAKM());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk_r, this.kappa);
        boolean verification = sigma1.VerifyKey(publicInfoSigma1, rho, this.kappa);

        assertTrue("Should return 1", verification);
    }




    @Test
    void TestValues() throws IOException {

        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk_sk_m.getPK(), this.pk_sk_m.getFRAKM());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk_r, this.kappa);
        boolean verification = sigma1.VerifyKey(publicInfoSigma1, rho, this.kappa);

        assertTrue("Should return 1", verification);
    }


}
