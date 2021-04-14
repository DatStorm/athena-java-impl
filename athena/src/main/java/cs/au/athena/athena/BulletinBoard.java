package cs.au.athena.athena;

import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BulletinBoard {
    // static variable single_instance of type Singleton
    private static BulletinBoard single_instance = null;
    private Map<Integer, Integer> tallyOfVotes;
    private PFStruct pf;
    private List<Ballot> ballots;
    private ElectoralRoll electoralRoll;
    private int nc;
    private List<BigInteger> g_vector_vote;
    private List<BigInteger> h_vector_vote;
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
    public List<BigInteger> retrieve_G_VectorVote() { return this.getG_vector_vote(); }
    public List<BigInteger> retrieve_H_VectorVote() { return this.getH_vector_vote(); }
    public List<Ballot> retrievePublicBallots() { return this.getBallots(); }
    public boolean electoralRollContains(Ciphertext publicCredential) { return this.electoralRoll.contains(publicCredential); }
    public void addPublicCredentialToL(Ciphertext publicCredential_pd) { d();this.electoralRoll.add(publicCredential_pd); }
    public Map<Integer, Integer> retrieveTallyOfVotes() { return this.getTallyOfVotes(); }


    /*
     * Public Publish values
     */
    public void publishPKV(PK_Vector pkv) { this.setPkv(pkv); }
    public void publishPF(PFStruct pf) {  this.setPf(pf); } //d();

    public void publishPFCiphertextCombination(int ballotIndex, int tallierIndex, Ciphertext c) {  this.pf.pfr.get(ballotIndex).ciphertextCombination.add(c);}
    public void publishPFDecryptionShare(int ballotIndex, int tallierIndex, BigInteger d) {  this.pf.pfr.get(ballotIndex).plaintext_N.add(d);}
    public void publishPFDecryptionProof(int ballotIndex, int tallierIndex, Sigma3Proof proof) {  this.pf.pfr.get(ballotIndex).proofDecryption.add(proof);}
    public void publishPFCombinationProof(int ballotIndex, int tallierIndex, Sigma4Proof proof) {  this.pf.pfr.get(ballotIndex).proofCombination.add(proof);}



    public void publishNumberOfCandidates(int nc) { this.setNc(nc); }
    public void publish_G_VectorVote(List<BigInteger> g_vector_vote) { this.setG_vector_vote(g_vector_vote); }
    public void publishBallot(Ballot ballot) { this.addBallot(ballot); }
    public void publish_H_VectorVote(List<BigInteger> h_vector_vote) { this.setH_vector_vote(h_vector_vote); }
    public void publishTallyOfVotes(Map<Integer, Integer> tallyOfVotes) { this.setTallyOfVotes(tallyOfVotes); d(); }






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
    private List<BigInteger> getG_vector_vote() { return g_vector_vote; }
    private List<BigInteger> getH_vector_vote() { return h_vector_vote; }
    private int getNc() { return nc; }
    private PFStruct getPF() { return this.pf; }
    private Map<Integer, Integer> getTallyOfVotes() { return tallyOfVotes; }
    private PK_Vector getPkv() { return pkv; }



    /*
     * Private set methods
     */
    private void addBallot(Ballot toAddBallot) { d();this.ballots.add(toAddBallot); }
    private void setH_vector_vote(List<BigInteger> h_vector_vote) { this.h_vector_vote = h_vector_vote; }
    private void setG_vector_vote(List<BigInteger> g_vector_vote) { this.g_vector_vote = g_vector_vote; }
    private void setNc(int nc) { this.nc = nc; }
    private void setPf(PFStruct pf) { this.pf = pf; }
    private void setTallyOfVotes(Map<Integer, Integer> tallyOfVotes) { this.tallyOfVotes = tallyOfVotes; }
    private void setPkv(PK_Vector pkv) { this.pkv = pkv; }



}
