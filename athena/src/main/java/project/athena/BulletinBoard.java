package project.athena;

import project.dao.athena.*;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;
import project.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BulletinBoard {
    // static variable single_instance of type Singleton
    private static BulletinBoard single_instance = null;


    private List<Ballot> ballots;
    private List<PFRStruct> PfrList;
    private List<PFDStruct> PfdList;
    private MixProof mixProof;
    private ElectoralRoll electoralRoll;
    private List<MixBallot> mixBallots;
    private int numberOfVotes;
    private int n_negatedPrivateCredential;
    private List<BigInteger> g_vector_vote;
    private List<BigInteger> h_vector_vote;
    private List<BigInteger>  g_vector_negatedPrivateCredential;
    private List<BigInteger>  h_vector_negatedPrivateCredential;


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
        this.electoralRoll = new ElectoralRoll();
    }


    /*
     * Public methods.
     */
    public List<BigInteger> retrieve_G_VectorNegPrivCred() { return this.getG_vector_negatedPrivateCredential(); }
    public List<BigInteger> retrieve_H_VectorNegPrivCred() { return this.getH_vector_negatedPrivateCredential(); }
    public List<BigInteger> retrieve_G_VectorVote() { return this.getG_vector_vote(); }
    public List<BigInteger> retrieve_H_VectorVote() { return this.getH_vector_vote(); }
    public int retrieveNumberOfVotes() { return this.getN_negatedPrivateCredential(); }
    public int retrieveNumberfNegatedPrivCred() { return this.getNumberOfVotes(); }
    public MixProof retrieveMixProof() { return this.getMixProof(); }
    public List<Ballot> retrievePublicBallots() { return this.getBallots(); }
    public boolean electoralRollContains(Ciphertext publicCredential) { return this.electoralRoll.contains(publicCredential); }
//    public void addAllBallots(List<Ballot> toAddBallots) {
//        printUpdate();
//        this.ballots.addAll(toAddBallots);
//    }
    public void addPublicCredentitalToL(Ciphertext publicCredential_pd) {
        d();
        this.electoralRoll.add(publicCredential_pd);
    }
    public void publishTallyOfVotes(Map<BigInteger, Integer> tallyOfVotes) {
        d();
        // TODO: does nothing....
        throw new UnsupportedOperationException("GET TO WORK :P :>) :::::::::");
    }


    /*
     * Publish values
     */
    public void publish_G_VectorVote(List<BigInteger> g_vector_vote) { this.setG_vector_vote(g_vector_vote); }
    public void publishPfr(List<PFRStruct> pfr) { this.setPfrList(pfr); }
    public void publishPfd(List<PFDStruct> pfd) { this.setPfdList(pfd); }
    public void publishBallot(Ballot ballot) { this.addBallot(ballot); }
    public void publishMixBallots(List<MixBallot> mixBallots) { this.setMixBallots(mixBallots); }
    public void publishMixProof(MixProof mixProof) { this.setMixProof(mixProof); }
    public void publishNumberOfVotes(int n_vote) { this.setNumberOfVotes(n_vote); }
    public void publishNumberfNegatedPrivCred(int n_negatedPrivateCredential) { this.setN_negatedPrivateCredential(n_negatedPrivateCredential); }
    public void publish_H_VectorVote(List<BigInteger> h_vector_vote) { this.setH_vector_vote(h_vector_vote); }
    public void publish_G_VectorNegPrivCred(List<BigInteger> g_vector_negatedPrivateCredential) { this.setG_vector_negatedPrivateCredential(g_vector_negatedPrivateCredential); }
    public void publish_H_VectorNegPrivCred(List<BigInteger> h_vector_negatedPrivateCredential) { this.setH_vector_negatedPrivateCredential(h_vector_negatedPrivateCredential); }






    private void d() {
        StringBuilder b_res = new StringBuilder();
        b_res.append("[");
        boolean first = true;
        for (Ballot ballot : ballots) {
            if (first) {
                b_res.append(ballot.toString()).append(", ").append("\n");
                first = false;
            }else{

                b_res.append("                             ").append(ballot.toString()).append(", ").append("\n");
            }

        }
        b_res.append("                             ").append("]");

        StringBuilder mb_res = new StringBuilder();
        mb_res.append("[");
        boolean first_mb = true;
        for (MixBallot mb : mixBallots) {
            if (first_mb) {
                mb_res.append(mb.toShortString()).append(", ").append("\n");
                first_mb = false;
            }else{

                mb_res.append("                             ").append(mb.toShortString()).append(", ").append("\n");
            }

        }
        mb_res.append("                             ").append("]");


        System.out.println("-----------------------------");
        System.out.println("BulletinBoard  -- UPDATE --  ");
        System.out.println("ballots=                     " + b_res.toString());
        System.out.println("PfrList=                     " + PfrList);
        System.out.println("PfdList=                     " + PfdList);
        System.out.println("mixProof=                    " + mixProof);
        System.out.println("electoralRoll=              L" + electoralRoll);
        System.out.println("mixBallots=                  " + mb_res.toString());
        System.out.println("-----------------------------");
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
    private int getNumberOfVotes() { return numberOfVotes; }
    private int getN_negatedPrivateCredential() { return n_negatedPrivateCredential; }
    private List<BigInteger> getG_vector_negatedPrivateCredential() { return g_vector_negatedPrivateCredential; }
    private List<BigInteger> getG_vector_vote() { return g_vector_vote; }
    private List<BigInteger> getH_vector_vote() { return h_vector_vote; }
    private List<BigInteger> getH_vector_negatedPrivateCredential() { return h_vector_negatedPrivateCredential; }



    /*
     * Private set methods
     */
    private void addBallot(Ballot toAddBallot) { d();this.ballots.add(toAddBallot); }
    private void addMixBallot(MixBallot toAddMixBallot) { d();this.mixBallots.add(toAddMixBallot); }
    private void setPfrList(List<PFRStruct> pfrList) { d();PfrList = pfrList; }
    private void setPfdList(List<PFDStruct> pfdList) { d();PfdList = pfdList; }
    private void setMixProof(MixProof mixProof) { d();this.mixProof = mixProof; }
    private void setMixBallots(List<MixBallot> mixBallots) { d();this.mixBallots = mixBallots; }
    private void setNumberOfVotes(int numberOfVotes) { this.numberOfVotes = numberOfVotes; }
    private void setN_negatedPrivateCredential(int n_negatedPrivateCredential) { this.n_negatedPrivateCredential = n_negatedPrivateCredential; }
    private void setH_vector_vote(List<BigInteger> h_vector_vote) { this.h_vector_vote = h_vector_vote; }
    private void setG_vector_vote(List<BigInteger> g_vector_vote) { this.g_vector_vote = g_vector_vote; }
    private void setG_vector_negatedPrivateCredential(List<BigInteger> g_vector_negatedPrivateCredential) { this.g_vector_negatedPrivateCredential = g_vector_negatedPrivateCredential; }
    private void setH_vector_negatedPrivateCredential(List<BigInteger> h_vector_negatedPrivateCredential) { this.h_vector_negatedPrivateCredential = h_vector_negatedPrivateCredential; }


    public PK_Vector retrievePK_vector() {
        throw new UnsupportedOperationException("aefaefeaf");
//        return null;
    }
}
