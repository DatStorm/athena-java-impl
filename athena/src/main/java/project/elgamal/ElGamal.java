package project.elgamal;


import project.CONSTANTS;
import project.UTIL;

import java.math.BigInteger;
import java.util.*;

public class ElGamal {
    private Group group;
    private Random random;

    private int messageSpaceLength;
    private Map<BigInteger, Integer> lookupTable;

    public ElGamal(Group group, int messageSpaceLength, Random random) {

        if (messageSpaceLength < 0) {
            System.err.println("ERROR messageSpaceLength < 0");
        }

        this.random = random;
        this.group = group;
        this.messageSpaceLength = messageSpaceLength;

        // Generate lookup table for decryption
        BigInteger g = group.g;
        BigInteger p = group.p;

        lookupTable = new HashMap<>();
        for(int i = 0; i < messageSpaceLength; i++) {
            lookupTable.put(g.pow(i).mod(p), i);
        }
    }

//    public ElGamal(int bitLength) {
//        this(bitLength, new SecureRandom());
//    }

    public ElGamal(int bitLength, int messageSpaceLength, Random random) {
        this(generateGroup(bitLength, random), messageSpaceLength, random);

    }

    private static Group generateGroup(int bitLength, Random random) {
        // SECURE == 2048
        BigInteger p, q, g;
        do {
            p = BigInteger.probablePrime(bitLength + 1, random); // p=2q+1
            q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = (p-1)/2
            

            // TODO: FIXME: this might lead to long execution time HOW CAN WE ADDRESS THIS
        } while (!q.isProbablePrime(bitLength)); // call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^{certainty})

        g = UTIL.getRandomElement(BigInteger.TWO, p, random).modPow(BigInteger.TWO, p);


        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }

        assert g.modPow(q, p).equals(BigInteger.ONE) : "ElGamal group defined wrong, i.e. q definition is no good";
        

        return new Group(p, q, g);
    }
    
    public Group getDescription() {
        return group;
    }



    /**
     * Precondition: messageElement should be in the group
     * @param messageElement A group element in group G
     * @param pk
     * @return
     */
    public Ciphertext encrypt(BigInteger messageElement, ElGamalPK pk){
        BigInteger r = UTIL.getRandomElement(BigInteger.ZERO, group.q, this.random);
        return encrypt(messageElement, pk, r);
    }

    public Ciphertext encrypt(BigInteger messageElement, ElGamalPK pk, BigInteger r){
        BigInteger p = pk.group.p;
        BigInteger q = pk.group.q;
        r = r.mod(q).add(q).mod(q);

        // We dont know how to check group membership, but lets just check group order for safety.
        assert messageElement.modPow(q, p).equals(BigInteger.ONE);

        // Extract public key
        BigInteger g = pk.group.g;
        BigInteger h = pk.h;

        // C = (g^r, m·h^r)
        return new Ciphertext(g.modPow(r, p), h.modPow(r, p).multiply(messageElement).mod(p));
    }

    public Ciphertext exponentialEncrypt(BigInteger msg, ElGamalPK pk) {
        BigInteger r = UTIL.getRandomElement(BigInteger.ZERO, group.q, this.random);
        return exponentialEncrypt(msg, pk, r);
    }

    // Exponential ElGamal
    public Ciphertext exponentialEncrypt(BigInteger msg, ElGamalPK pk, BigInteger r) {
        BigInteger p = pk.group.p;
        BigInteger q = pk.group.q;
        r = r.mod(q).add(q).mod(q);

        msg = msg.mod(q).add(q).mod(q);
        if (msg.compareTo(q) >= 0) {
            System.err.println("Message was not be in Z_q. ElGamal encrypted msg.mod(q)");
        }

        if (msg.signum() == -1) {
            throw new IllegalArgumentException("BigInteger must be positive. Was " + msg);
        }
        // Extract public key
        BigInteger g = pk.group.g;

        // C = (g^r, g^m·h^r)
        BigInteger messageElement = g.modPow(msg, p);
        return encrypt(messageElement, pk, r);
    }

    public static BigInteger getNeutralElement() {
        return BigInteger.ONE;
    }


    public Integer exponentialDecrypt(Ciphertext cipherText, ElGamalSK sk) {
        return lookup(decrypt(cipherText, sk));
    }



    // Decrypting El Gamal encryption using secret key
    public BigInteger decrypt(Ciphertext cipherText, ElGamalSK sk) {
        BigInteger c1 = cipherText.c1;
        BigInteger c2 = cipherText.c2;
        BigInteger p = sk.getPK().getGroup().getP();
        BigInteger c1Alpha = c1.modPow(sk.toBigInteger(), p);      // c1^\alpha
        BigInteger c1NegAlpha = c1Alpha.modInverse(p); // c1^-\alpha

        // plain = g^m  (look up table to find it needed)
        return c2.multiply(c1NegAlpha).mod(p);
    }


    public Integer lookup(BigInteger big) {
        if(!lookupTable.containsKey(big)){
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt Dec_sk(c) = g^m = " + big + CONSTANTS.ANSI_RESET);
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt           table = " + lookupTable + CONSTANTS.ANSI_RESET);
            System.out.println(CONSTANTS.ANSI_GREEN + "ElGamal.decrypt: Possible votes = " + lookupTable.values() + CONSTANTS.ANSI_RESET);
            throw new IllegalArgumentException("Ciphertext is not contained in the decryption lookup table. The value must be smaller than: " + messageSpaceLength);
        } else {
            return lookupTable.get(big);
        }
    }

    // Generate random sk
    public ElGamalSK generateSK() {
        if (this.group == null) {
            System.out.println("group = null");
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
