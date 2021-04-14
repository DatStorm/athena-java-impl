package cs.au.athena.dao;

public class Randomness {
    private long rand_r;

    public Randomness(long rand_r) {
        this.rand_r = rand_r;
    }

    public long getValue() {
        return this.rand_r;
    }

}
