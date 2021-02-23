package project.sigma;


import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import project.UTIL;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.Randomness;
import project.dao.sigma1.CoinFlipInfo;
import project.dao.sigma1.ProveKeyInfo;
import project.elgamal.ElGamalSK;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class Sigma1 {
    private MessageDigest hashFunctionH;

    public Sigma1(MessageDigest hashFunctionH) {
        this.hashFunctionH = hashFunctionH;
    }

    //input pk, sk,
    public ProveKeyInfo ProveKey(PublicInfoSigma1 publicInfoSigma1, ElGamalSK sk, Randomness r, int kappa) throws IOException {
        Random random = new SecureRandom();

        // lists
        ArrayList<BigInteger> e1_ek = new ArrayList<>();
        ArrayList<BigInteger> y1_yk = new ArrayList<>();
        ArrayList<BigInteger> s1_sk = new ArrayList<>();

        // secret keys
        BigInteger alpha = sk.toBigInteger();

        // public keys
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger h = publicInfoSigma1.getPK().getH();


        BigInteger p_minus_1 = p.subtract(BigInteger.ONE);
        for (int i = 0; i < kappa; i++) {
            BigInteger ei = UTIL.getRandomElement(p_minus_1, random); //int ei = new rand ei in Z_p-1;

            e1_ek.add(ei);
            y1_yk.add(g.modPow(ei, p));
        }
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = coinFlippingProtocol(r, g, h, kappa, y1_yk);


        // j <- min(i: b_i = 1)
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1);
//        System.out.println("--> index j: " + j);
        BigInteger ej = e1_ek.get(j);

        int index = 0;
        for (CoinFlipInfo coinFlipInfo_pair : coinFlipInfo_pairs) {
            boolean bi = coinFlipInfo_pair.getBi();
            BigInteger ei = e1_ek.get(index);

            BigInteger si;
            if (bi) {
                // b_i = 1
                // s_i = e_i - e_j mod p-1
                si = ei.subtract(ej).mod(p_minus_1);
            } else {
                // b_i = 0
                si = ei;
            }
            s1_sk.add(si);

            index++;
        }

        // zeta = \alpha(sk) - e[j] mod (p-1)
        BigInteger zeta = alpha.subtract(ej).mod(p_minus_1);

        return new ProveKeyInfo(y1_yk, coinFlipInfo_pairs, s1_sk, zeta);
    }




    private ArrayList<CoinFlipInfo> coinFlippingProtocol(Randomness r, BigInteger g, BigInteger h, int kappa, ArrayList<BigInteger> y1_yk) throws IOException {
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = new ArrayList<>();
        Random coinRandom = new SecureRandom();
        Random hashRandom = new Random(r.getValue());

        for (int i = 1; i <= kappa; i++) {
            boolean bA = coinRandom.nextBoolean();
            // f -> F(r,b_A)
            Randomness ri = new Randomness(hashRandom.nextLong());
            byte[] fi = hashF(ri, bA); // H(...) mod 2 = {0,1} => See test that it works.
            boolean bB = hashH(fi, g, h, y1_yk).mod(BigInteger.TWO).intValueExact() == 1;
            boolean bi = bA ^ bB; // b_i = b_A \oplus b_B
            coinFlipInfo_pairs.add(new CoinFlipInfo(bA, ri, bi, fi));
        }
        return coinFlipInfo_pairs;
    }


    public BigInteger hashH(byte[] fi, BigInteger g, BigInteger h, ArrayList<BigInteger> y1_yk) throws IOException {

//        long long_r = r.getValue();
//        byte[] rand_bytes = Longs.toByteArray(long_r);
//        byte [] bA_bytes = new byte[]{(byte) (bA? 1:0)};

        // f -> F(r,b_A)
        byte[] hashbytes = this.hashFunctionH.digest(Bytes.concat(fi, UTIL.ARRAYLIST_TO_BYTE_ARRAY(y1_yk)));

        // BigInteger class, which have a constructor that takes a signum and a magnitude expressed as a byte[]
        return new BigInteger(1, hashbytes);
    }


    /**
     * Computes f -> F(r,b_A)
     *
     * @param r  randomness
     * @param bA bit
     * @return f
     */
    public byte[] hashF(Randomness r, boolean bA) {

        long long_r = r.getValue();
        byte[] rand_bytes = Longs.toByteArray(long_r);
        byte[] bA_bytes = new byte[]{(byte) (bA ? 1 : 0)};

        // f -> F(r,b_A)
        byte[] hashbytes = this.hashFunctionH.digest(Bytes.concat(rand_bytes, bA_bytes));

        return hashbytes;
    }


    public boolean VerifyKey(PublicInfoSigma1 publicInfoSigma1, ProveKeyInfo rho, int kappa) {
        // lists
        ArrayList<CoinFlipInfo> coinFlipInfoPairs = rho.getCoinFlipInfoPairs();
        BigInteger zeta = rho.getZeta();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfoPairs, 1); // find index j

        // bigints g,p,yj
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger h = publicInfoSigma1.getPK().getH();
        BigInteger yj = y1_yk.get(j);

        // Step 2 verify
        boolean checkStep2 = checkStep2(coinFlipInfoPairs);

        // Step 3 verify
        boolean checkStep3 = checkStep3(coinFlipInfoPairs, s1_sk, y1_yk, g, p, yj);

        // step 4 check
        boolean checkStep4 = checkStep4(g, h, p, yj, zeta);


        return checkStep2 && checkStep3 && checkStep4;
    }

    public boolean checkStep4(BigInteger g, BigInteger h, BigInteger p, BigInteger yj, BigInteger zeta) {
        BigInteger hyi = h.multiply(yj.modInverse(p)).mod(p);
        return (g.modPow(zeta, p).compareTo(hyi)) == 0;
    }

    public boolean checkStep3(ArrayList<CoinFlipInfo> coinFlipInfoPairs, ArrayList<BigInteger> s1_sk, ArrayList<BigInteger> y1_yk, BigInteger g, BigInteger p, BigInteger yj) {
        int index = 0;
        for (CoinFlipInfo coinFlipInfo : coinFlipInfoPairs) {
            boolean bi = coinFlipInfo.getBi();
            boolean equality = false;
            BigInteger si = s1_sk.get(index);
            BigInteger yi = y1_yk.get(index);

            // Step 3 verify
            BigInteger g_pow_si = g.modPow(si, p);
            if (bi) {
                // b_i = 1 => g^s_i ?=? y_iy_j^-1
                BigInteger yiyj_inverse = yi.multiply(yj.modInverse(p)).mod(p);
                equality = g_pow_si.compareTo(yiyj_inverse) == 0;
            } else {
                // b_i = 0 => g^s_i ?=? y_i
                equality = g_pow_si.compareTo(yi.mod(p)) == 0;
            }

            if (!equality){
                return false;
            }
            index++;
        }

        return true;
    }

    public boolean checkStep2(ArrayList<CoinFlipInfo> coinFlipInfoPairs) {
        for (CoinFlipInfo coinFlipInfo : coinFlipInfoPairs) {
            byte[] prover_fi = coinFlipInfo.getFi();
            Randomness prover_ri = coinFlipInfo.getRi();
            boolean prover_bA = coinFlipInfo.getBA();
            byte[] verifier_fi = this.hashF(prover_ri, prover_bA);

            if (!Arrays.equals(prover_fi, verifier_fi)){
                return false;
            }
        }
        return true;
    }
}