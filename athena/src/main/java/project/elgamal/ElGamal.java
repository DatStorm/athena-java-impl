package project.elgamal;

//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import project.CONSTANTS;
import project.UTIL;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {
    //    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private GroupDescription groupDescription;
    private Random random;

    public ElGamal(int bitLength) {
        this(bitLength, new SecureRandom());
    }

    public ElGamal(int bitLength, Random random) {
        this(generateGroup(bitLength, random), random);
    }

    private static GroupDescription generateGroup(int bitLength, Random random) {
        BigInteger p = BigInteger.probablePrime(bitLength + 1, random);
        BigInteger g = UTIL.getRandomElement(p, random).modPow(BigInteger.TWO, p);;
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);

        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }

        return new GroupDescription(g, p, q);
    }

    public ElGamal(GroupDescription group, Random random) {
        this.random = random;
        this.groupDescription = group;
    }

    public GroupDescription getDescription() {
        return groupDescription;
    }

    /**
     * Generating El Gamal encryption on a message msg using public key pk
     * @param msg bigint in range [0; 2^bitlength -1]
     */
    public CipherText encrypt(BigInteger msg, ElGamalPK pk) {
        return encrypt(msg, pk, this.random.nextLong());
    }
    public CipherText encrypt(BigInteger msg, ElGamalPK pk, long randomSeed) {
        BigInteger p = pk.getGroup().getP();
        int bitLength = p.bitLength();
        
        if (msg.bitLength() > bitLength) {
            throw new IllegalArgumentException("BigInteger, of length " + msg.bitLength() +", too long for " + bitLength + " bit ElGamal");
        }

        if (msg.signum() == -1) {
                throw new IllegalArgumentException("BigInteger must be positive. Was " + msg);
        }
        // Check for 0 invalid

        // Extract public key
        BigInteger g = pk.getGroup().getG();
        BigInteger h = pk.getH();

        // sample random r
        BigInteger r = new BigInteger(p.bitCount() - 1, new Random(randomSeed));
//        BigInteger r = CONSTANTS.ELGAMAL_RAND_R;

        // C = (g^r, m·h^r)
        return new CipherText(g.modPow(r, p), msg.multiply(h.modPow(r, p)).mod(p).add(p).mod(p));
    }


    // Decrypting El Gamal encryption using secret key
    public BigInteger decrypt(CipherText cipherText, ElGamalSK sk) {
        BigInteger c1 = cipherText.c1;
        BigInteger c2 = cipherText.c2;
        BigInteger p = sk.getPK().getGroup().getP();
        BigInteger c1Alpha = c1.modPow(sk.toBigInteger(), p);      // c1^\alpha
        BigInteger c1NegAlpha = c1Alpha.modInverse(p); // c1^-\alpha

        // FIXME: OLD used this.p
//        BigInteger plain = c2.multiply(c1NegAlpha).mod(this.p).add(this.p).mod(this.p); // m=c2 * c1^-alpha mod p
        BigInteger plain = c2.multiply(c1NegAlpha).mod(p).add(p).mod(p); // m=c2 * c1^-alpha mod p

        return plain;
    }


    // Generate random sk
    public ElGamalSK generateSK() {
        if (this.groupDescription == null){
            System.out.println("MARKKKKKKKK");
        }
        BigInteger q = this.groupDescription.getQ();
        BigInteger sk = UTIL.getRandomElement(q, random);

        return new ElGamalSK(this.groupDescription, sk);
    }


    // Generating El Gamal public key from a specified secret key
    public ElGamalPK generatePk(ElGamalSK sk) {
        BigInteger g = this.groupDescription.getG();
        BigInteger p = this.groupDescription.getP();
        BigInteger h = g.modPow(sk.toBigInteger(), p);
        return new ElGamalPK(this.groupDescription, h); // return pk=(g,h)
    }


    public BigInteger getP(){
        return this.groupDescription.getP();
    }

}
