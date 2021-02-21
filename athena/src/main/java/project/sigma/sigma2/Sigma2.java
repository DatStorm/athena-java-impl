package project.sigma.sigma2;

import java.security.MessageDigest;

public class Sigma2 {
    private final Sigma2EL sigma2EL;
    private final Sigma2SQR sigma2SQR;
    private MessageDigest hashH;

    public Sigma2(MessageDigest hash) {
        this.hashH = hash;
        this.sigma2EL = new Sigma2EL(this.hashH);
        this.sigma2SQR = new Sigma2SQR(this.hashH, this.sigma2EL);
    }


//    public void el(){
//        this.sigma2EL.EL();
//    }




}
