package project.sigma.sigma2;

import project.factory.Factory;

import java.security.MessageDigest;
import java.util.Random;

public class Sigma2 {
    private final Sigma2EL sigma2EL;
    private final Sigma2SQR sigma2SQR;
    private MessageDigest hashH;

    public Sigma2(Factory factory) {
        this.hashH = factory.getHash();
        Random random = factory.getRandom();
        this.sigma2EL = new Sigma2EL(this.hashH, random);
        this.sigma2SQR = new Sigma2SQR(this.hashH, this.sigma2EL, random);
    }


//    public void el(){
//        this.sigma2EL.EL();
//    }




}
