package cs.au.athena.athena.bulletinboard;

import com.google.common.cache.AbstractCache;
import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.ElectoralRoll;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

// Responsible for the posting of votes with a registered credential, and other positings. Is async.
public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;
    private final int tallierCount;
    private final int k;
    private final Group group;
    private final ElectoralRoll electoralRoll;
    private final int mb;
    private final int mc;

    private final List<Ballot> ballots;

    private final Map<Integer, CompletableFuture<List<CommitmentAndProof>>> tallierCommitmentsAndProofs;
    private final Map<Pair<Integer, Integer>, CompletableFuture<Ciphertext>> encryptedSubShares;
    private final Map<Integer, CompletableFuture<PK_Vector>> mapOfIndividualPK_vector;

    // Completed when a tallier posts homocomb or decryption shares
    private final PfPhase<CombinedCiphertextAndProof> pfrPhasePhaseOne;
    private final PfPhase<DecryptionShareAndProof> pfrPhasePhaseTwo;
    private final PfPhase<CombinedCiphertextAndProof> pfdPhasePhaseOne;
    private final PfPhase<DecryptionShareAndProof> pfdPhasePhaseTwo;
    private final PfPhase<DecryptionShareAndProof> pfdPhasePhaseThree;
    private final Map<Integer, CompletableFuture<MixedBallotsAndProof>> mixedBallotAndProofs;

    //    private final Map<Pair<Ciphertext, Integer>, CompletableFuture<DecryptionShareAndProof>> decryptionShareMap;
    private final int kappa;
    private Map<Integer, CompletableFuture<Map<Integer, Integer>>> officialTallyMap;
    private int nc;

    // static method to create instance of Singleton class
    public static BulletinBoardV2_0 getInstance(int tallierCount, int kappa) {
        if (single_instance == null) {
            single_instance = new BulletinBoardV2_0(tallierCount, kappa);
        }

        return single_instance;
    }

    private BulletinBoardV2_0(int tallierCount, int kappa) {
        this.group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        this.kappa = kappa;
        this.tallierCount = tallierCount;
        this.k = (tallierCount - 1) / 2; // It must satisfy k < n/2, e.g. 0 < 2/2, 1 < 3/2,  1 < 4/2,  2 < 5/2,  2 < 6/2
        this.electoralRoll = new ElectoralRoll();
        this.ballots = new ArrayList<>();

        /**
         * Preset important values
         */
        this.nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
        this.mc = CONSTANTS.MC;
        this.mb = CONSTANTS.MB;

        this.tallierCommitmentsAndProofs = new HashMap<>();
        this.mapOfIndividualPK_vector = new HashMap<>();
        this.encryptedSubShares = new HashMap<>();
        this.pfrPhasePhaseOne = new PfPhase<>(tallierCount);
        this.pfrPhasePhaseTwo = new PfPhase<>(tallierCount);
        this.pfdPhasePhaseOne = new PfPhase<>(tallierCount);
        this.pfdPhasePhaseTwo = new PfPhase<>(tallierCount);
        this.pfdPhasePhaseThree = new PfPhase<>(tallierCount);
        this.mixedBallotAndProofs = new HashMap<>(tallierCount);
        this.officialTallyMap = new HashMap<>(tallierCount);

        /*********** FAKE FIXME; ***************/
        this.fakeSKMAP = new HashMap<>();
        /**************************/

        this.init(tallierCount);
    }

    // Set preexisting values, and populate maps with Futures
    private void init(int tallierCount) {


        // Fill with CompletableFutures
        for(int i = 1; i <= tallierCount; i++) {
            tallierCommitmentsAndProofs.put(i, new CompletableFuture<>());
            mapOfIndividualPK_vector.put(i, new CompletableFuture<>());
            mixedBallotAndProofs.put(i, new CompletableFuture<>());
            officialTallyMap.put(i, new CompletableFuture<>());

            for(int j = 1; j <= tallierCount; j++) {
                if(i == j) continue;

                Pair<Integer, Integer> key = Pair.of(i, j);
                encryptedSubShares.put(key, new CompletableFuture<>());
            }
        }
    }


    public Group retrieveGroup() {
        return group;
    }

    public int retrieveTallierCount() {
        return tallierCount;
    }

    public int retrieveK() {
        return k;
    }
    public int retrieveKappa() {
        return kappa;
    }

    public void addPublicCredentialToL(Ciphertext publicCredential_pd) {this.electoralRoll.add(publicCredential_pd); }
    public int retrieveNumberOfCandidates() { return this.nc; }
    public int retrieveMaxCandidates() {
        return this.mc;
    }
    public List<Ballot> retrievePublicBallots() { return this.ballots; }
    public boolean electoralRollContains(Ciphertext publicCredential) { return this.electoralRoll.contains(publicCredential); }

    public Map<Integer, CompletableFuture<Map<Integer, Integer>>> retrieveOfficialTally() { return this.officialTallyMap; }



    // Post commitment to P(X)
    public void publishPolynomialCommitmentsAndProofs(int tallierIndex, List<CommitmentAndProof> commitmentAndProof) {
        assert tallierIndex <= tallierCount;

        assert tallierCommitmentsAndProofs.containsKey(tallierIndex): String.format("%d not contained in tallierCommitmentsAndProofs", tallierIndex);

        assert SigmaCommonDistributed.verifyPK(commitmentAndProof, group, kappa): "verifyPK() ==> FALSE";

        tallierCommitmentsAndProofs.get(tallierIndex).complete(commitmentAndProof);
    }

    public Map<Integer, CompletableFuture<List<CommitmentAndProof>>> retrievePolynomialCommitmentsAndProofs() {
        return tallierCommitmentsAndProofs;
    }

    public void publishIndividualPKvector(int tallierIndex, PK_Vector pkv) {
        mapOfIndividualPK_vector.get(tallierIndex).complete(pkv);
    }

    public CompletableFuture<PK_Vector> retrieveIndividualPKvector(int tallierIndex) {
        return mapOfIndividualPK_vector.get(tallierIndex);
    }

    public void publishBallot(Ballot ballot) { this.ballots.add(ballot); }

    public List<Ballot> retrieveBallots() { return this.ballots; }

    public void publishEncSubShare(int i, int j, Ciphertext subShareToTallier_j) {
        Pair<Integer, Integer> key = Pair.of(i, j);
        encryptedSubShares.get(key).complete(subShareToTallier_j);
    }

    public CompletableFuture<Ciphertext> retrieveEncSubShare(int i, int j) {
        Pair<Integer, Integer> key = Pair.of(i, j);
        return encryptedSubShares.get(key);
    }

    public CompletableFuture<List<CommitmentAndProof>> retrievePolynomialCommitmentsAndProofs(int j) {
        return tallierCommitmentsAndProofs.get(j);
    }


    // each tallier update their respective tally
    public void publishTallyOfVotes(int tallierIndex, Map<Integer, Integer> tallyMap) {
        this.officialTallyMap.get(tallierIndex).complete(tallyMap);
    }


    // Returns the index in the pfrPhaseOne
    public synchronized void publishPfrPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> values) {
        if(values.size() != ballots.size()) {
            throw new IllegalArgumentException(String.format("T%d: list must be the same length as ballots", tallierIndex));
        }

        pfrPhasePhaseOne.add(new Entry<>(tallierIndex, values));
    }




    public synchronized void publishPfrPhaseTwoEntry(int tallierIndex, List<DecryptionShareAndProof> values) {
        if(values.size() != ballots.size()) {
            throw new IllegalArgumentException(String.format("T%d: list must be the same length as ballots", tallierIndex));
        }

        // Set values in pfr
        pfrPhasePhaseTwo.add(new Entry<>(tallierIndex, values));
    }


    /**
     * TODO: SHOULD THIS BE synchronized
     */
    public synchronized void publishPfdPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> values) {
        if(values.size() != ballots.size()) {
            throw new IllegalArgumentException(String.format("T%d: list must be the same length as ballots", tallierIndex));
        }

        pfdPhasePhaseOne.add(new Entry<>(tallierIndex, values));
    }

    public synchronized void publishPfdPhaseTwoEntry(int tallierIndex, List<DecryptionShareAndProof> values) {
        if(values.size() != ballots.size()) {
            throw new IllegalArgumentException("list must be the same length as ballots");
        }

        pfdPhasePhaseTwo.add(new Entry<>(tallierIndex, values));
    }

    public synchronized void publishPfdPhaseThreeEntry(int tallierIndex, List<DecryptionShareAndProof> values) {
        if(values.size() != ballots.size()) {
            throw new IllegalArgumentException("list must be the same length as ballots");
        }

        pfdPhasePhaseThree.add(new Entry<>(tallierIndex, values));
    }

    public void publishMixedBallotsAndProof(int tallierIndex, MixedBallotsAndProof mixedBallotsAndProof) {
        this.mixedBallotAndProofs.get(tallierIndex).complete(mixedBallotsAndProof);
    }



    public PfPhase<CombinedCiphertextAndProof> retrievePfrPhaseOne() {
        return this.pfrPhasePhaseOne;
    }


    public PfPhase<DecryptionShareAndProof> retrievePfrPhaseTwo() {
        return this.pfrPhasePhaseTwo;
    }


    public PfPhase<CombinedCiphertextAndProof> retrievePfdPhaseOne() {
        System.out.println("BulletinBoard retrievePfdPhaseOne of size" + this.pfdPhasePhaseOne.size());
        return this.pfdPhasePhaseOne;
    }

    public PfPhase<DecryptionShareAndProof> retrievePfdPhaseTwo() {
        return this.pfdPhasePhaseTwo;

    }

    public PfPhase<DecryptionShareAndProof> retrievePfdPhaseThree() {
        return this.pfdPhasePhaseThree;
    }


    public Map<Integer, CompletableFuture<MixedBallotsAndProof>> retrieveMixedBallotAndProofs() {
        return this.mixedBallotAndProofs;
    }

    // Returns the result of the final mix
    public List<MixBallot> retrieveMixedBallots() {
        int finalTallierIndex = this.retrieveTallierCount();
        return this.mixedBallotAndProofs.get(finalTallierIndex).join().mixedBallots;
    }

    /*********************************************
     * FAKE
     ********************************************/
    private Map<Integer, BigInteger> fakeSKMAP;
    public void postSK_i(Integer tallierIndex, BigInteger p_j_0) { //P(j)
        this.fakeSKMAP.put(tallierIndex,p_j_0);
    }

    public BigInteger getFakeSK_i(Integer tallierIndex) {
        return fakeSKMAP.get(tallierIndex);
    }

    public ElGamalSK getFakeSK() { //SK_i = P_j(0)
        BigInteger sk = BigInteger.ZERO;
        for (int i = 1; i <= tallierCount; i++) {
            sk = sk.add(this.getFakeSK_i(i)).mod(group.q); // sk = Sum( P_j(0) ) for all talliers j
        }
        return new ElGamalSK(group, sk);
    }
}
