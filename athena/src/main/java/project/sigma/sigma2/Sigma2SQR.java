package project.sigma.sigma2;

import java.math.BigInteger;
import java.security.MessageDigest;

public class Sigma2SQR {
    private final MessageDigest hashH;
    private final Sigma2EL el;

    public Sigma2SQR(MessageDigest hashH, Sigma2EL el) {

        this.hashH = hashH;
        this.el = el;
    }


//    public SQRProof prove(){
//        BigInteger x = info.x;
//        BigInteger r = info.r;
//        BigInteger p = info.p;
//        BigInteger g = info.g;
//        BigInteger h = info.h;
//
//        // step 1
//        BigInteger r_2 = randInterval; // Within a certain group
//
//        BigInteger gx = g.modPow(x,p);
//        BigInteger hr_2 = h.modPow(r_2,p);
//        BigInteger y_1 = gx.multiply(hr_2).mod(p);
//
//
//        // step 2
//        BigInteger r_3 = r.subtract(r_2.multiply(x).mod(p).mod(p);
//
//        BigInteger y_1x = y_1.modPow(x,p);
//        BigInteger hr_3 = h.modPow(r_3,p);
//        BigInteger y_2 = y_1x.multiply(hr_3).mod(p);
//
//
//        // step 3
//        //TODO: call to EL
//
//        // step 4
//        return new SQRProof(y_1,y_2,c,D,D_1,D_2);
//        return null;
//    }


    public boolean verify(){
        return true;
    }

}
