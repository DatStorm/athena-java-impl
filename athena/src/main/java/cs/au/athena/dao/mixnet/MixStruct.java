package cs.au.athena.dao.mixnet;

import java.util.List;

public class MixStruct {
    public final List<MixBallot> mixedBallots;
    public final MixSecret mixSecret;

    public MixStruct(List<MixBallot> mixedBallots, MixSecret mixSecret) {
        this.mixedBallots = mixedBallots;
        this.mixSecret = mixSecret;
    }
}
