package project.athena;

import project.dao.athena.Ballot;

import java.util.List;

public class BullitinBoard {
    private List<Ballot> ballots;

    public BullitinBoard(List<Ballot> ballots) {
        this.ballots = ballots;
    }



    public List<Ballot> getBallots() {
        return ballots;
    }
}
