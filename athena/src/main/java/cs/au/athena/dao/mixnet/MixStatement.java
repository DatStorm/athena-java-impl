package cs.au.athena.dao.mixnet;

import java.util.List;

public class MixStatement {
    public final List<MixBallot> ballots;
    public final List<MixBallot> mixedBallots;

    public MixStatement(List<MixBallot> ballots, List<MixBallot> mixedBallots) {

        this.ballots = ballots;
        this.mixedBallots = mixedBallots;
    }
}
