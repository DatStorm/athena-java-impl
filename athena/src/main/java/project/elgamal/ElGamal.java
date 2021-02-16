package project.elgamal;

//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import project.CONSTANTS;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {
//    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private int bitLength;
    private BigInteger q;
    private BigInteger p;
    private BigInteger g;

    private Random random;

    public ElGamal(int bitLength) {
        this(bitLength, new SecureRandom());
    }

    public ElGamal(int bitLength, Random random) {
        this.random = random;
        
        ElGamalDescription description = gen(bitlength);
        this(description);
    }

    public ElGamalDescription gen(int bitLength) {
        BigInteger p = BigInteger.probablePrime(bitLength + 1, random);
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        BigInteger g = getRandomGroupElement(this.random);

        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }

        return new ElGamalDescription(bitLength, p, q, g);
    }

    public ElGamal(ElGamalDescription description) {
        this.random = new SecureRandom();

        this.bitLength = description.bitLength;
        this.p = description.p;
        this.q = description.q;
        this.g = description.g;
    }

    public ElGamalDescription getDescription() {
        return new ElGamalDescription(bitLength, p, q, g);
    }

    /**
     * Generating El Gamal encryption on a message msg using public key pk
     * @param msg bigint in range [0; 2^bitlength -1]
     */
//    public Tuple encrypt(BigInteger msg, Tuple pk) {
//        if (msg.bitLength() > bitLength) {
//            throw new IllegalArgumentException("BigInteger, of length " + msg.bitLength() +", too long for " + bitLength + " bit ElGamal");
//        }
//
//        if (msg.signum() == -1) {
//                throw new IllegalArgumentException("BigInteger must be positive. Was " + msg);
//        }
//
//        msg = msg.add(BigInteger.ONE); // Cannot encrypt 0
//
//        // Extract public key
//        BigInteger g = (BigInteger) pk.getElement0();
//        BigInteger h = (BigInteger) pk.getElement1();
//
//        // sample random r
//        BigInteger r = new BigInteger(this.p.bitCount() - 1, this.random);
//
//        // C = (g^r, m·h^r)
//        return new Tuple(g.modPow(r, p), msg.multiply(h.modPow(r, p)).mod(p).add(p).mod(p));
//    }
//
//
//    // Decrypting El Gamal encryption using secret key
//    public BigInteger decrypt(Tuple cipherTextTuple, BigInteger sk) {
//        BigInteger c1 = (BigInteger) cipherTextTuple.getElement0();
//        BigInteger c2 = (BigInteger) cipherTextTuple.getElement1();
//        BigInteger c1Alpha = c1.modPow(sk, p);      // c1^\alpha
//        BigInteger c1NegAlpha = c1Alpha.modInverse(p); // c1^-\alpha
//        BigInteger plain = c2.multiply(c1NegAlpha).mod(this.p).add(this.p).mod(this.p); // m=c2 * c1^-alpha mod p
//
//        plain = plain.subtract(BigInteger.ONE); // To counter the +1 in encrypt()
//        return plain;
//    }


    // Generate random sk
    public ElGamalSK generateSk() {
        BigInteger sk;
        boolean skIsInRange;
        do {
            // Sample random number between 0 and q. The group Z_q.
            sk = new BigInteger(this.q.bitLength(), this.random);

            boolean skIsPositive = sk.compareTo(BigInteger.ONE) >= 0;
            boolean skIsLessThanQ = sk.compareTo(this.q) == -1;
            skIsInRange = skIsPositive && skIsLessThanQ;
        } while (!skIsInRange);

        return new ElGamalSK(sk);
    }

    // Generate random element g
    private BigInteger getRandomGroupElement(Random rand) {
        boolean gIsInAllowedRange;
        BigInteger g_ = null;
        do {
            // Sample random number g between 1 and p
            g_ = new BigInteger(this.bitLength, rand);
            boolean gIsGreaterThatZero = g_.compareTo(BigInteger.ZERO) == 1;
            boolean gIsLesserThanP = g_.compareTo(this.p) == -1;

            gIsInAllowedRange = gIsGreaterThatZero && gIsLesserThanP;
        } while (!gIsInAllowedRange);

        return g_.modPow(BigInteger.TWO, this.p);
    }

    // Generating El Gamal public key from a specified secret key
    public ElGamalPK generatePk(ElGamalSK sk) {
        return new ElGamalPK(g, g.modPow(sk.getSK(), p)); // return pk=(g,h)
    }


    public BigInteger getP(){
        return this.p;
    }

}
