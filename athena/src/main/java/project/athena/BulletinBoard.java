package project.athena;

import project.dao.athena.Ballot;

import java.util.List;

public class BulletinBoard {
    private List<Ballot> ballots;

    public BulletinBoard(List<Ballot> ballots) {
        this.ballots = ballots;
    }



    public List<Ballot> getBallots() {
        return ballots;
    }
}
