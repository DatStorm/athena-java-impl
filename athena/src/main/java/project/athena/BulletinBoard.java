package project.athena;

import project.dao.athena.Ballot;
import project.dao.athena.ElectoralRoll;
import project.dao.athena.PFDStruct;
import project.dao.athena.PFRStruct;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;

import java.util.ArrayList;
import java.util.List;

public class BulletinBoard {
    // static variable single_instance of type Singleton
    private static BulletinBoard single_instance = null;


    private List<Ballot> ballots;
    private List<PFRStruct> PfrList;
    private List<PFDStruct> PfdList;
    private MixProof mixProof;
    private ElectoralRoll electoralRoll;
    private List<MixBallot> mixBallots;


    // static method to create instance of Singleton class
    public static BulletinBoard getInstance() {
        if (single_instance == null) {
            single_instance = new BulletinBoard();
        }
        return single_instance;
    }


    // private constructor restricted to this class itself
    private BulletinBoard() {
        this.ballots = new ArrayList<>();
        this.PfrList = new ArrayList<>();
        this.PfdList = new ArrayList<>();
        this.mixBallots = new ArrayList<>();
    }


    /*
     * Public methods.
     */
    public void addAllBallots(List<Ballot> toAddBallots) {
        printUpdate();
        this.ballots.addAll(toAddBallots);
    }
    


    /*
     * Publish values
     */
    public void publishPfr(List<PFRStruct> pfr) { this.setPfrList(pfr); }
    public void publishPfd(List<PFDStruct> pfd) { this.setPfdList(pfd); }
    public void publishBallot(Ballot ballot) { this.addBallot(ballot); }
    public void publishMixBallots(List<MixBallot> mixBallots) { this.setMixBallots(mixBallots); }
    public List<Ballot> retrievePublicBallots() { return this.getBallots(); }

    

    /*
     * Private add methods
     */
    private void addBallot(Ballot toAddBallot) {
        printUpdate();
        this.ballots.add(toAddBallot);
    }
    private void addMixBallot(MixBallot toAddMixBallot) {
        printUpdate();
        this.mixBallots.add(toAddMixBallot);
    }

    private void setPfrList(List<PFRStruct> pfrList) {
        printUpdate();
        PfrList = pfrList;
    }

    private void setPfdList(List<PFDStruct> pfdList) {
        printUpdate();
        PfdList = pfdList;
    }

    private void setMixProof(MixProof mixProof) {
        printUpdate();
        this.mixProof = mixProof;
    }

    private void setElectoralRoll(ElectoralRoll electoralRoll) {
        printUpdate();
        this.electoralRoll = electoralRoll;
    }

    private void setMixBallots(List<MixBallot> mixBallots) {
        printUpdate();
        this.mixBallots = mixBallots;
    }

    /*
     * Private Getters....
     */
    private List<PFDStruct> getPfdList() { return PfdList; }
    private MixProof getMixProof() { return mixProof; }
    private List<MixBallot> getMixBallots() { return mixBallots; }
    private ElectoralRoll getElectoralRoll() { return electoralRoll; }
    private List<Ballot> getBallots() { return ballots; }
    private List<PFRStruct> getPfrList() { return PfrList; }


    private void printUpdate() {
        System.out.println("-----------------------------");
        System.out.println("BulletinBoard  -- UPDATE --  ");
        System.out.println("ballots=                     " + ballots);
        System.out.println("PfrList=                     " + PfrList);
        System.out.println("PfdList=                     " + PfdList);
        System.out.println("mixProof=                    " + mixProof);
        System.out.println("electoralRoll=               " + electoralRoll);
        System.out.println("mixBallots=                  " + mixBallots);
        System.out.println("-----------------------------");
    }


}
