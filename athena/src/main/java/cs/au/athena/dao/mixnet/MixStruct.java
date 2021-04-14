package cs.au.athena.dao.mixnet;

import java.util.List;

public class MixStruct {
    public final List<MixBallot> mixedBallots;
    public final MixSecret secret;

    public MixStruct(List<MixBallot> mixedBallots, MixSecret secret) {
        this.mixedBallots = mixedBallots;
        this.secret = secret;
    }
}
