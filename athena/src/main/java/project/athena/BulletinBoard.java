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
    private Map<BigInteger, Integer> tallyOfVotes;
    private PFStruct pf;
    private List<Ballot> ballots;
    private ElectoralRoll electoralRoll;
    private int nc;
    private int numberOfVotes;
    private int n_negatedPrivateCredential;
    private List<BigInteger> g_vector_vote;
    private List<BigInteger> h_vector_vote;
    private List<BigInteger>  g_vector_negatedPrivateCredential;
    private List<BigInteger>  h_vector_negatedPrivateCredential;
    private PK_Vector pkv;


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
        this.electoralRoll = new ElectoralRoll();
    }




    /*
     * Public retrieve methods.
     */
    public PK_Vector retrievePK_vector() { return this.getPkv(); }
    public PFStruct retrievePF() { return this.getPF(); }
    public int retrieveNumberOfCandidates() { return this.getNc(); }
    public List<BigInteger> retrieve_G_VectorNegPrivCred() { return this.getG_vector_negatedPrivateCredential(); }
    public List<BigInteger> retrieve_H_VectorNegPrivCred() { return this.getH_vector_negatedPrivateCredential(); }
    public List<BigInteger> retrieve_G_VectorVote() { return this.getG_vector_vote(); }
    public List<BigInteger> retrieve_H_VectorVote() { return this.getH_vector_vote(); }
    public int retrieveRangeBitLengthOfVote() { return this.getRangeNumberVote(); }
    public int retrieveRangeBitLengthOfNegatedPrivateCredential() { return this.getRangeNumberNegatedPrivCred(); }
    public List<Ballot> retrievePublicBallots() { return this.getBallots(); }
    public boolean electoralRollContains(Ciphertext publicCredential) { return this.electoralRoll.contains(publicCredential); }
    public void addPublicCredentitalToL(Ciphertext publicCredential_pd) { d();this.electoralRoll.add(publicCredential_pd); }
    public Map<BigInteger, Integer> retrieveTallyOfVotes() { return this.getTallyOfVotes(); }


    /*
     * Public Publish values
     */
    public void publishPKV(PK_Vector pkv) { this.setPkv(pkv); }
    public void publishPF(PFStruct pf) {  this.setPf(pf); } //d();
    public void publishNumberOfCandidates(int nc) { this.setNc(nc); }
    public void publish_G_VectorVote(List<BigInteger> g_vector_vote) { this.setG_vector_vote(g_vector_vote); }
    public void publishBallot(Ballot ballot) {
//        System.out.println("BulletinBoard.publishBallot received ballot = " + ballot.toString());
        this.addBallot(ballot);
    }
    public void publishRangeNumberVote(int n_vote) { this.setRangeNumberVote(n_vote); }
    public void publishRangeNumberNegatedPrivCred(int n_negatedPrivateCredential) { this.setRangeNumberNegatedPrivCred(n_negatedPrivateCredential); }
    public void publish_H_VectorVote(List<BigInteger> h_vector_vote) { this.setH_vector_vote(h_vector_vote); }
    public void publish_G_VectorNegPrivCred(List<BigInteger> g_vector_negatedPrivateCredential) { this.setG_vector_negatedPrivateCredential(g_vector_negatedPrivateCredential); }
    public void publish_H_VectorNegPrivCred(List<BigInteger> h_vector_negatedPrivateCredential) { this.setH_vector_negatedPrivateCredential(h_vector_negatedPrivateCredential); }
    public void publishTallyOfVotes(Map<BigInteger, Integer> tallyOfVotes) { this.setTallyOfVotes(tallyOfVotes); d(); }






    private void d() {
        StringBuilder b_res = new StringBuilder();
        b_res.append("[");
        boolean first = true;
        String space = "                             ";
        for (Ballot ballot : ballots) {
            if (first) {
                b_res.append(ballot.toString()).append(", ").append("\n");
                first = false;
            }else{

                b_res.append(space).append(ballot.toString()).append(", ").append("\n");
            }

        }
        b_res.append(space).append("]");

        StringBuilder mb_res = new StringBuilder();
        mb_res.append("[");
        if (pf != null) {
            boolean first_mb = true;
            for (MixBallot mb : pf.mixBallotList) {
                if (first_mb) {
                    mb_res.append(mb.toShortString()).append(", ").append("\n");
                    first_mb = false;
                }else{

                    mb_res.append(space).append(mb.toShortString()).append(", ").append("\n");
                }

            }
        }
        mb_res.append(space).append("]");


        p("-----------------------------");
        p("BulletinBoard  -- UPDATE --  ");
        p("ballots=                     " + b_res.toString());

        if (pf != null) {
            p("PfrList=                     " + pf.pfr);
            p("PfdList=                     " + pf.pfd);
            p("mixProof=                    " + pf.mixProof);
        }

        p("electoralRoll=              L" + electoralRoll);
        p("mixBallots=                  " + mb_res.toString());
        p("-----------------------------");
    }

    private void p(String s) {
//        System.out.println(s);
    }


    /*
     * Private Getters....
     */
    private ElectoralRoll getElectoralRoll() { return electoralRoll; }
    private List<Ballot> getBallots() { return ballots; }
    private int getRangeNumberVote() { return numberOfVotes; }
    private int getRangeNumberNegatedPrivCred() { return n_negatedPrivateCredential; }
    private List<BigInteger> getG_vector_negatedPrivateCredential() { return g_vector_negatedPrivateCredential; }
    private List<BigInteger> getG_vector_vote() { return g_vector_vote; }
    private List<BigInteger> getH_vector_vote() { return h_vector_vote; }
    private List<BigInteger> getH_vector_negatedPrivateCredential() { return h_vector_negatedPrivateCredential; }
    private int getNc() { return nc; }
    private PFStruct getPF() { return this.pf; }
    private Map<BigInteger, Integer> getTallyOfVotes() { return tallyOfVotes; }
    private PK_Vector getPkv() { return pkv; }



    /*
     * Private set methods
     */
    private void addBallot(Ballot toAddBallot) { d();this.ballots.add(toAddBallot); }
    private void setRangeNumberVote(int numberOfVotes) { this.numberOfVotes = numberOfVotes; }
    private void setRangeNumberNegatedPrivCred(int n_negatedPrivateCredential) { this.n_negatedPrivateCredential = n_negatedPrivateCredential; }
    private void setH_vector_vote(List<BigInteger> h_vector_vote) { this.h_vector_vote = h_vector_vote; }
    private void setG_vector_vote(List<BigInteger> g_vector_vote) { this.g_vector_vote = g_vector_vote; }
    private void setG_vector_negatedPrivateCredential(List<BigInteger> g_vector_negatedPrivateCredential) { this.g_vector_negatedPrivateCredential = g_vector_negatedPrivateCredential; }
    private void setH_vector_negatedPrivateCredential(List<BigInteger> h_vector_negatedPrivateCredential) { this.h_vector_negatedPrivateCredential = h_vector_negatedPrivateCredential; }
    private void setNc(int nc) { this.nc = nc; }
    private void setPf(PFStruct pf) { this.pf = pf; }
    private void setTallyOfVotes(Map<BigInteger, Integer> tallyOfVotes) { this.tallyOfVotes = tallyOfVotes; }
    private void setPkv(PK_Vector pkv) { this.pkv = pkv; }



}
