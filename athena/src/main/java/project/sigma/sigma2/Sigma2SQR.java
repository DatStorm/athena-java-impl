package project.sigma.sigma2;

import project.CONSTANTS;
import project.UTIL;
import project.dao.sigma2.*;
import project.elgamal.Group;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class Sigma2SQR {
    private final MessageDigest hashH;
    private final Sigma2EL sigma2EL;
    private final Random random;

    private static final int t = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_T;
    private static final int l = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_L;
    private static final int s = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_S1;
    private static final BigInteger b = BigInteger.valueOf(110); //FIXME: |b|=512 bits

    public Sigma2SQR(MessageDigest hashH, Sigma2EL sigma2EL, Random random) {
        this.hashH = hashH;
        this.sigma2EL = sigma2EL;
        this.random = random;
    }


   public SQRProof prove(SQRStatement statementSQR, SQRSecret secretSQR){
       // Get the secret parts of the relation
       BigInteger x = secretSQR.x;
       BigInteger r = secretSQR.r;

       // Get the publicly known parts
       BigInteger y1 = statementSQR.y1;
       BigInteger g = statementSQR.g;
       BigInteger h = statementSQR.h;
       BigInteger p = statementSQR.group.p;
       BigInteger q = statementSQR.group.q;

       // step 1
       BigInteger startInclusive = (BigInteger.valueOf(2).pow(s).negate()).multiply(p.add(BigInteger.valueOf(1)));
       BigInteger endExclusive = (BigInteger.valueOf(2).pow(s)).multiply(p); // +1 cancels out the -1 due to exclusivity
       BigInteger r_2 = UTIL.getRandomElement(startInclusive, endExclusive, random); // Within [-2^s p +1, 2^s p-1]

       // y_2 = E(x; r2).
       BigInteger gx = g.modPow(x,p);
       BigInteger hr_2 = h.modPow(r_2,p);
       BigInteger y_2 = gx.multiply(hr_2).mod(p);

       // step 2
       BigInteger r_3 = r.subtract(r_2.multiply(x)).mod(q).mod(q);

       //Then, y_1 = y_2^x h^{r_3} mod p.
       BigInteger y_2x = y1.modPow(x,p);
       BigInteger hr_3 = h.modPow(r_3,p);
       BigInteger y_1 = y_2x.multiply(hr_3).mod(p);


       // step 3
       //TODO: call to EL
       ElSecret secretEL = new ElSecret(x,r_2,r_3);
       ELStatement statementEL = new ELStatement(y_2,y_1,g,h,y1,h, statementSQR.group);
       ELProof proofEL = sigma2EL.prove(statementEL, secretEL);

       // step 4
       return new SQRProof(y_2, proofEL.c, proofEL.D, proofEL.D1, proofEL.D2);
   }


    public boolean verify(SQRStatement statementSQR, SQRProof proofSQR){
        // Get from SQR proof
        BigInteger y_2 = proofSQR.y2;
        BigInteger c = proofSQR.c;
        BigInteger D = proofSQR.D;
        BigInteger D1 = proofSQR.D1;
        BigInteger D2 = proofSQR.D2;

        // Get from SQR statement
        BigInteger y_1 = statementSQR.y1;
        BigInteger g = statementSQR.g;
        BigInteger h = statementSQR.h;
        Group group = statementSQR.group;
        BigInteger p = group.p;


        ELStatement statementEL = new ELStatement(y_2, y_1, g, h, y_1, h, group);
        ELProof proofEL = new ELProof(c,D,D1,D2);

        return sigma2EL.verify(statementEL, proofEL);
    }
}
