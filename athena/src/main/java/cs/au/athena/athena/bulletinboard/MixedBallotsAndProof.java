package cs.au.athena.athena.bulletinboard;

import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;

import java.util.List;

public class MixedBallotsAndProof {
    // Mixnet & proof
    public final List<MixBallot> mixedBallots;
    public final MixProof mixProof;

    public MixedBallotsAndProof(List<MixBallot> mixedBallots, MixProof mixProof) {
        this.mixedBallots = mixedBallots;
        this.mixProof = mixProof;
    }
}
