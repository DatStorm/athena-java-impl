package project.sigma.sigma2;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.sigma2.ELProof;
import project.dao.sigma2.ELStatement;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class Sigma2EL {
    private MessageDigest hashH;

    private static final int t = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_T;
    private static final int l = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_L;
    private static final int b = 2; //FIXME: WTF er b

    public Sigma2EL(MessageDigest hash) {
        this.hashH = hash;
    }



    public ELProof prove(ELStatement statement){
        BigInteger q = null;
        BigInteger x = null;
        BigInteger r1 = null;
        BigInteger r2 = null;
        //---------------
        BigInteger p = null;
        BigInteger g1 = null;
        BigInteger g2 = null;
        BigInteger h1 = null;
        BigInteger h2 = null;

        BigInteger w = pickRand_w(new Random(CONSTANTS.RANDOM_SEED));
        BigInteger n1 = pickRand_n1();
        BigInteger n2 = pickRand_n2();


        /* *******************
         * Create W1
         *********************/
        BigInteger h1_n1 = h1.modPow(n1, p); // h1^n1
        BigInteger W1 = g1.modPow(w,p).multiply(h1_n1).mod(p); // W_1 = g1^w * h1^n1 mod p


        /* *******************
         * Create W2
         *********************/
        BigInteger h2_n2 = h2.modPow(n2, p);
        BigInteger W2 = g2.modPow(w,p).multiply(h2_n2).mod(p);

        /* *******************
         * Create c = H(W1 || W2)
         *********************/
        BigInteger c = hash(W1,W2);


        /* *******************
         * Create D,D1,D2
         *********************/
        BigInteger D  = w.add(c.multiply(x).mod(q)); // FIXME: Should be in Z.
        BigInteger D1 = n1.add(c.multiply(r1).mod(q)); // FIXME: Should be in Z.
        BigInteger D2 = n2.add(c.multiply(r2).mod(q)); // FIXME: Should be in Z.



        return new ELProof(c,D,D1,D2);
    }


    public boolean verify(ELProof proof){

        BigInteger X1 = BigInteger.ONE;
        BigInteger X2 = BigInteger.ONE;

        BigInteger c = proof.getC();

        BigInteger c_hashed = hash(X1,X2);

        return c.compareTo(c_hashed) == 0;
    }


    public static BigInteger pickRand_w(Random random){
        // w \in [1; 2^{l+t} * b-1]
        BigInteger to = BigInteger.TWO.pow(l+t).multiply(BigInteger.valueOf(b-1));
        BigInteger w = UTIL.getRandomElement(to, random);
        return w;
    }

    public static BigInteger pickRand_n1(){
        // n1 \in [1; 2^{l+t+s1} * p-1]
        BigInteger n1 = BigInteger.valueOf(10);
        return n1;
    }

    public static BigInteger pickRand_n2(){
        // n2 \in [1; 2^{l+t+s2} * p-1]
        BigInteger n2 = BigInteger.valueOf(10);
        return n2;
    }

    public BigInteger hash(BigInteger a, BigInteger b) {
        byte[] bytes_a = a.toByteArray();
        byte[] bytes_b = b.toByteArray();
        byte[] concatenated = Bytes.concat(bytes_a, bytes_b);
        byte[] hashed = this.hashH.digest(concatenated);

        assert  hashed.length == 2*t : "Hash output should be 2t";
        return new BigInteger(1,hashed);
    }

}
