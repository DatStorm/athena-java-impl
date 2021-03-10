package project.elgamal;


import project.UTIL;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;
import java.util.Map;

public class ElGamal {
    //    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private Group group;
    private Random random;

    private int messageSpaceLength;
    private Map<BigInteger, Integer> lookupTable;

    public ElGamal(Group group, int messageSpaceLength, Random random) {
        this.random = random;
        this.group = group;
        this.messageSpaceLength = messageSpaceLength;

        // Generate lookup
        BigInteger g = group.g;
        BigInteger p = group.p;
        BigInteger q = group.q;

        /*
        lookupTable = new HashMap<>();
        for(int i = 0; i < messageSpaceLength; i++) {
            lookupTable.put(g.pow(i).mod(p), i);
        }
        */
    }

    public ElGamal(Group group, Random random) {
        this(group, 5, random);
    }

    public ElGamal(int bitLength) {
        this(bitLength, new SecureRandom());
    }

    public ElGamal(int bitLength, Random random) {
        this(generateGroup(bitLength, random), random);

    }

    private static Group generateGroup(int bitLength, Random random) {
        // SECURE == 2048
//        BigInteger p, q, g;
//        do {
//            p = BigInteger.probablePrime(bitLength + 1, random); // p=2q+1
//            q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = (p-1)/2
//
//            // TODO: FIXME: this might lead to long execution time HOW CAN WE ADDRESS THIS
//        } while (!q.isProbablePrime(bitLength)); // call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^{certainty})

        BigInteger p = new BigInteger("203563861925565177933951527681865992552429014002237425191410266898486184182026619996987894353762119957056230747716582757205994486135986076638697536841048852140992609316787978027688024528962704074922913310302293967528294897853920568227642592344438342607588008139227413464161980201861673136375912646999611663087");
        BigInteger q = new BigInteger("101781930962782588966975763840932996276214507001118712595705133449243092091013309998493947176881059978528115373858291378602997243067993038319348768420524426070496304658393989013844012264481352037461456655151146983764147448926960284113821296172219171303794004069613706732080990100930836568187956323499805831543");
        BigInteger g;

        g = UTIL.getRandomElement(BigInteger.TWO, p, random).modPow(BigInteger.TWO, p);

        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }

        assert g.modPow(q, p).equals(BigInteger.ONE) : "Inshallah";

        return new Group(g, p, q);
    }

    public Group getDescription() {
        return group;
    }

    /**
     * Generating El Gamal encryption on a message msg using public key pk
     *
     * @param msg bigint in range [0; 2^bitlength -1]
     */
    public CipherText encrypt(BigInteger msg, ElGamalPK pk) {
        BigInteger r = UTIL.getRandomElement(BigInteger.ZERO, group.q, this.random);
        return encrypt(msg, pk, r);
    }

    // Exponential ElGamal
    public CipherText encrypt(BigInteger msg, ElGamalPK pk, BigInteger r) {
        BigInteger p = pk.getGroup().getP();
        BigInteger q = pk.getGroup().getQ();
        r = r.mod(q).add(q).mod(q);

        msg = msg.mod(q).add(q).mod(q);
        if (msg.compareTo(q) >= 0) {
            System.err.println("Message was not be in Z_q. ElGamal encrypted msg.mod(q)");
        }

        if (msg.signum() == -1) {
            throw new IllegalArgumentException("BigInteger must be positive. Was " + msg);
        }
        // Check for 0 invalid

        // Extract public key
        BigInteger g = pk.getGroup().getG();
        BigInteger h = pk.getH();

        // C = (g^r, g^m·h^r)
        BigInteger expMsg = g.modPow(msg, p);
        return new CipherText(g.modPow(r, p), expMsg.multiply(h.modPow(r, p)).mod(p));
    }


    // Decrypting El Gamal encryption using secret key
    public BigInteger decrypt(CipherText cipherText, ElGamalSK sk) {
        BigInteger c1 = cipherText.c1;
        BigInteger c2 = cipherText.c2;
        BigInteger p = sk.getPK().getGroup().getP();
        BigInteger c1Alpha = c1.modPow(sk.toBigInteger(), p);      // c1^\alpha
        BigInteger c1NegAlpha = c1Alpha.modInverse(p); // c1^-\alpha

        // plain = g^m  (look up table to find it needed)
        BigInteger plain = c2.multiply(c1NegAlpha).mod(p); // m=c2 * c1^-alpha mod p

        return plain;
    }


    // Generate random sk
    public ElGamalSK generateSK() {
        if (this.group == null) {
            System.out.println("MARKKKKKKKK");
        }
        BigInteger q = this.group.getQ();
        BigInteger sk = UTIL.getRandomElement(q, random);

        return new ElGamalSK(this.group, sk);
    }


    // Generating El Gamal public key from a specified secret key
    public ElGamalPK generatePk(ElGamalSK sk) {
        BigInteger g = this.group.getG();
        BigInteger p = this.group.getP();
        BigInteger h = g.modPow(sk.toBigInteger(), p);
        return new ElGamalPK(this.group, h); // return pk=(g,h)
    }


    public BigInteger getP() {
        return this.group.getP();
    }

}
