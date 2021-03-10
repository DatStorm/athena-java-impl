package project.dao.athena;

import project.dao.bulletproof.BulletproofProof;
import project.dao.sigma2.Sigma2Proof;
import project.elgamal.CipherText;

public class Ballot {
    public final CipherText pd;
    public final CipherText c1;
    public final CipherText c2;
    public final BulletproofProof sigma_1;
    public final BulletproofProof sigma_2;
    public final int cnt;

    public Ballot(CipherText pd, CipherText c1, CipherText c2, BulletproofProof sigma_1, BulletproofProof sigma_2, int cnt) {
        this.pd = pd;
        this.c1 = c1;
        this.c2 = c2;
        this.sigma_1 = sigma_1;
        this.sigma_2 = sigma_2;
        this.cnt = cnt;
    }

    public CipherText get1() {
        return pd;
    }

    public CipherText get2() {
        return c1;
    }

    public CipherText get3() {
        return c2;
    }

    public int get6() {
        return cnt;
    }
}
