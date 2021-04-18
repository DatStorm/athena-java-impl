package cs.au.athena.sigmas;


import cs.au.athena.CONSTANTS;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.UTIL;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.dao.sigma1.CoinFlipInfo;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
//import java.cs.au.athena.util.SecureRandom;

@Tag("TestsSigma1")
@DisplayName("Test Sigma1")
public class TestSigma1 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma1 sigma1;
    private ElGamalSK sk;
    private ElGamalPK pk;
    private Random random;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        this.sk = factory.getSK();
        this.pk = factory.getPK();
        this.sigma1 = new Sigma1();
        this.random = new Random(123);
    }


    @Test
    void TestBigIntegerMod2_IntValueExact() {

        BigInteger one = BigInteger.ONE;
        boolean modedBit = one.mod(BigInteger.TWO).intValueExact() == 1;
        MatcherAssert.assertThat("should be 1 % 2 = 1", modedBit,  is(true));

        BigInteger zero = BigInteger.ZERO;
        boolean zero_modedBit = zero.mod(BigInteger.TWO).intValueExact() == 1;
        MatcherAssert.assertThat("should be 0 % 2 = 0", zero_modedBit, is(false));


        BigInteger ten = BigInteger.valueOf(10);
        boolean ten_modedBit = ten.mod(BigInteger.TWO).intValueExact() == 1;
        MatcherAssert.assertThat("should be 10 % 2 = 0", ten_modedBit,is(false));

        BigInteger twentyOne = BigInteger.valueOf(21);
        boolean twentyOne_modedBit = twentyOne.mod(BigInteger.TWO).intValueExact() == 1;
        MatcherAssert.assertThat("should be 21 % 2 = 1", twentyOne_modedBit,  is(true));
    }

    /**
     * Verifying the coinflip protocol.
     * f ?=? F(r,b_A)
     */
    @Test
    void TestProveKey_Verify_step2() {
        Sigma1Proof rho = sigma1.ProveKey(this.pk, this.sk, random, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        boolean verify = sigma1.checkStep2(coinFlipInfo_pairs);
         MatcherAssert.assertThat("fi ?=? F_i(ri,b_A_i)", verify,  is(true));
    }

    @Test
    void TestProveKey_Verify_step3() {
        Sigma1Proof rho = sigma1.ProveKey(this.pk, this.sk, random, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,yj
        BigInteger g = this.pk.getGroup().getG();
        BigInteger p = this.pk.getGroup().getP();
        BigInteger yj = y1_yk.get(j);

        boolean verify = sigma1.checkStep3(coinFlipInfo_pairs, s1_sk, y1_yk, g, p, yj);
         MatcherAssert.assertThat("bi=0 g^si = yi :: bi=1 g^si = yiyj^-1", verify,  is(true));
    }

    @Test
    void TestProveKey_Verify_step4() {
        Sigma1Proof rho = sigma1.ProveKey(this.pk, this.sk, random, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,h,yj,zeta
        BigInteger g = this.pk.getGroup().getG();
        BigInteger p = this.pk.getGroup().getP();
        BigInteger h = this.pk.getH();
        BigInteger yj = y1_yk.get(j);
        BigInteger zeta = rho.getZeta();

        boolean verify = sigma1.checkStep4(g, h, p, yj, zeta);
         MatcherAssert.assertThat("g^zeta ?=? hy_j^-1", verify,  is(true));
    }


    @Test
    void TestProveKey_Verify() {
        Sigma1Proof rho = sigma1.ProveKey(pk, this.sk, random, this.kappa);
        boolean verification = sigma1.VerifyKey(pk, rho, this.kappa);
         MatcherAssert.assertThat("Should return 1", verification,  is(true));
    }


    @Test
    void TestSigma1() {
        Sigma1Proof rho = sigma1.ProveKey(this.pk, this.sk, random, this.kappa);
        boolean verification = sigma1.VerifyKey(this.pk, rho, this.kappa);
         MatcherAssert.assertThat("Should return 1", verification, is(true));
    }


}
