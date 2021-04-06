package cs.au.athena.dao.sigma1;

import cs.au.athena.dao.Randomness;

public class CoinFlipInfo {
    private final boolean bA;
    private final Randomness r_i;
    private boolean bi;
    private byte[] fi;

    public CoinFlipInfo(boolean bA, Randomness r_i, boolean bi, byte[] fi) {
        this.bA = bA;
        this.r_i = r_i;
        this.bi = bi;
        this.fi = fi;
    }

    public boolean getBi() {
        return this.bi;
    }
    public boolean getBA() {
        return this.bA;
    }

    public byte[] getFi() {
        return this.fi;
    }

    public Randomness getRi() {
        return r_i;
    }
}
