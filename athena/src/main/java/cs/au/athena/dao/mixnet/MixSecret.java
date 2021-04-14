package cs.au.athena.dao.mixnet;

import java.math.BigInteger;
import java.util.List;

public class MixSecret {
    public final List<Integer> permutation;
    public final List<BigInteger> randomnessR;
    public final List<BigInteger> randomnessS;

    public MixSecret(List<Integer> permutation, List<BigInteger> randomnessR, List<BigInteger> randomnessS) {
        this.permutation = permutation;
        this.randomnessR = randomnessR;
        this.randomnessS = randomnessS;
    }
}
