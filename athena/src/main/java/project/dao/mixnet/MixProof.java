package project.dao.mixnet;

import java.math.BigInteger;
import java.util.List;

public class MixProof {
    public final List<List<MixBallot>> shadowMixes;
    public final List<MixSecret> shadowSecrets;

    public MixProof(List<List<MixBallot>> shadowMixes,
                    List<MixSecret> shadowSecrets) {
        this.shadowMixes = shadowMixes;
        this.shadowSecrets = shadowSecrets;
    }


    @Override
    public String toString() {
        return "MixProof{" + "..." + "}";

//        return "MixProof{" +
//                "shadowMixes=" + shadowMixes +
//                ", shadowSecrets=" + shadowSecrets +
//                '}';
    }
}
