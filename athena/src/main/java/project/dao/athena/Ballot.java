package project.dao.athena;

import project.dao.sigma2.Sigma2Proof;
import project.elgamal.CipherText;

public class Ballot {
    public final CipherText pd;
    public final CipherText c1;
    public final CipherText c2;
    public final Sigma2Proof sigma_1;
    public final Sigma2Proof sigma_2;
    public final int cnt;

    public Ballot(CipherText pd, CipherText c1, CipherText c2, Sigma2Proof sigma_1, Sigma2Proof sigma_2, int cnt) {
        this.pd = pd;
        this.c1 = c1;
        this.c2 = c2;
        this.sigma_1 = sigma_1;
        this.sigma_2 = sigma_2;
        this.cnt = cnt;
    }
}
