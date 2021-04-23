package cs.au.athena.athena.bulletinboard;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.sigma.Sigma3;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

// Responsible for the posting of votes with a registered credential, and other positings. Is async.
public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;
    private final Sigma3 sigma3;
    private final int tallierCount;
    private final int k;
    private final Group group;

    List<Ballot> ballots;

    private final Map<Integer, CompletableFuture<List<CommitmentAndProof>>> tallierCommitmentsAndProofs;
    private final Map<Pair<Integer, Integer>, CompletableFuture<Ciphertext>> encryptedSubShares;
    private final Map<Integer, CompletableFuture<PK_Vector>> mapOfIndividualPK_vector;



    // Activated when a tallier posts homocomb or decryption shares
    protected PfrPhaseOne pfrPhaseOne;
    protected PfrPhaseTwo pfrPhaseTwo;

//    private final Map<Pair<Ciphertext, Integer>, CompletableFuture<DecryptionShareAndProof>> decryptionShareMap;
    private final int kappa;

    // static method to create instance of Singleton class
    public static BulletinBoardV2_0 getInstance(int tallierCount, int kappa) {
        if (single_instance == null) {
            single_instance = new BulletinBoardV2_0(tallierCount, kappa);
        }

        return single_instance;
    }

    private BulletinBoardV2_0(int tallierCount, int kappa) {
        this.group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        this.tallierCommitmentsAndProofs = new HashMap<>();
        this.mapOfIndividualPK_vector = new HashMap<>();

        this.encryptedSubShares = new HashMap<>();
//        this.decryptionShareMap = new HashMap<>();

        this.sigma3 = new Sigma3();

        this.kappa = kappa;
        this.tallierCount = tallierCount;
        this.k = (tallierCount-1)/2; // It must satisfy k < n/2, e.g. 0 < 2/2, 1 < 3/2,  1 < 4/2,  2 < 5/2,  2 < 6/2

        this.init(tallierCount);
    }

    // Set preexisting values, and populate maps with Futures
    private void init(int tallierCount) {

        this.pfrPhaseOne = new PfrPhaseOne(tallierCount);
        this.pfrPhaseTwo = new PfrPhaseTwo(tallierCount);
        //this.pfrPhaseOne = null;


        // Fill with CompletableFutures
        for(int i = 1; i <= tallierCount; i++) {
            tallierCommitmentsAndProofs.put(i, new CompletableFuture<>());
            mapOfIndividualPK_vector.put(i, new CompletableFuture<>());

            for(int j = 1; j <= tallierCount; j++) {
                if(i == j) continue;

                Pair<Integer, Integer> key = Pair.of(i, j);
                encryptedSubShares.put(key, new CompletableFuture<>());
            }
        }
    }


    public Group getGroup() {
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



    // Compute and return the entire public key from the committed polynomials
    public ElGamalPK retrievePK() {
        // Have all commitments been published?
        if (tallierCommitmentsAndProofs.keySet().size() != tallierCount) {
            // Not ready
        }

        BigInteger publicKey = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitmentsAndProofs.keySet().size(); i++) {
            List<CommitmentAndProof> commitmentAndProofs = tallierCommitmentsAndProofs.get(i).join();
            CommitmentAndProof commitmentAndProof = commitmentAndProofs.get(0);

            publicKey = publicKey.multiply(commitmentAndProof.commitment).mod(group.p);
        }

        // group, h
        return new ElGamalPK(group, publicKey);
    }

    // Compute and return the public key share h_j=g^P(j) from the committed polynomials
    public ElGamalPK retrievePKShare(int j) {
        BigInteger publicKeyShare = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitmentsAndProofs.keySet().size(); i++) {
            List<CommitmentAndProof> commitmentAndProofs = tallierCommitmentsAndProofs.get(i).join();

            for (int ell = 0; ell < this.k; ell++) {
                BigInteger j_pow_ell = BigInteger.valueOf(j).pow(ell);
                BigInteger commitment = commitmentAndProofs.get(ell).commitment;

                publicKeyShare = publicKeyShare.multiply(commitment.modPow(j_pow_ell, group.p)).mod(group.p);
            }
        }

        // group, h_j
        return new ElGamalPK(group, publicKeyShare);
    }

    // Post commitment to P(X)
    public void publishPolynomialCommitmentsAndProofs(int tallierIndex, List<CommitmentAndProof> commitmentAndProof) {
        assert tallierIndex <= tallierCount;

        if (tallierCommitmentsAndProofs.containsKey(tallierIndex)) {
            tallierCommitmentsAndProofs.get(tallierIndex).complete(commitmentAndProof);
        } else {
            throw new IllegalStateException("TallierIndex does not exists...    tallierIndex: " + tallierIndex + tallierCommitmentsAndProofs.size());
        }
    }

    public void publishIndividualPKvector(int tallierIndex, PK_Vector pkv) {
        mapOfIndividualPK_vector.get(tallierIndex).complete(pkv);
    }

    public CompletableFuture<PK_Vector> retrieveIndividualPKvector(int tallierIndex) {
        return mapOfIndividualPK_vector.get(tallierIndex);
    }

    public void publishEncSubShare(int i, int j, Ciphertext subShareToTallier_j) {
        Pair<Integer, Integer> key = Pair.of(i, j);
        encryptedSubShares.get(key).complete(subShareToTallier_j);
    }

    public CompletableFuture<Ciphertext> retrieveEncSubShare(int i, int j) {
        Pair<Integer, Integer> key = Pair.of(i, j);
        return encryptedSubShares.get(key);
    }

    public CompletableFuture<List<CommitmentAndProof>> retrieveCommitmentsAndProofs(int j) {
        return tallierCommitmentsAndProofs.get(j);
    }


    // Returns the index in the pfrPhaseOne
    public synchronized int publishPfrPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) {
        int ell = ballots.size();

        if(listOfCombinedCiphertextAndProof.size() == ell) {
            throw new IllegalArgumentException("list must be the same length as ballots");
        }

        // Set values in pfr
        int index = pfrPhaseOne.size();
        pfrPhaseOne.add(index, Pair.of(tallierIndex, listOfCombinedCiphertextAndProof));

        return index;
    }

    public PfrPhaseOne retrievePfrPhaseOne() {
        if (pfrPhaseOne == null) {
            throw new RuntimeException("publishCombinedCiphertextAndProof must be called first");
        }

        return this.pfrPhaseOne;
    }




    public synchronized void publishPfrPhaseTwoEntry(int tallierIndex, List<DecryptionShareAndProof> decryptionShareAndProof) {
        throw new UnsupportedOperationException();
    }



    public CompletableFuture<PfrPhaseTwo> retrievePfrPhaseTwo(Ciphertext ciphertext, int k) {
        throw new UnsupportedOperationException();
    }


    /***************************************************
     *             Distributed stuff below             *
     **************************************************/
//
//    // Ballots
//
//    // For each ballot (generation pfr)
//    private List<PFR> pfr = new ArrayList<>();
//    private List<PFD> pfd = new ArrayList<>();
//
//


    public void addPfrPhaseOneListener(Consumer<Integer> callback) {

        // TODO: Listen for updates to pfrPhaseOne
        // add callback to list
        // notify should call all callbacks

    }
//
//    // Returns the PFD index, and grows PFR list if needed
//    public PFD getPfd(int index) {
//        // Check
//        boolean indexIsOnePastTheEnd = index == pfd.size();
//        if (indexIsOnePastTheEnd) {
//            // Object does not already exist
//            // Add a new object to the end
//            PFD obj = new PFD();
//            pfd.add(obj);
//
//            //Return the new object
//            return obj;
//
//        } else if (index < pfd.size()) {
//            // Object already exists
//            return pfd.get(index);
//
//        } else {
//            throw new IllegalArgumentException("getPfd() !!");
//        }
//    }
//
//
//    // Construct pfr elements
//    class PFR {
//        // list of HomoAndProof
//        List<HomoCombinationAndProof> homoCombAndProofs;
//
//        // List of DecryptionAndProof{
//        List<DecryptionAndProof> decryptionAndProofs;
//
//        public PFR() {
//            homoCombAndProofs = new ArrayList<>();
//            decryptionAndProofs = new ArrayList<>();
//        }
//
//        // Add a homoComb pair
//        void addHomoCombinationAndProof(HomoCombinationAndProof obj) {
//            homoCombAndProofs.add(obj);
//        }
//
//        // Add a Decryption pair
//        void addHomoCombinationAndProof(DecryptionAndProof obj) {
//            decryptionAndProofs.add(obj);
//        }
//
//        List<HomoCombinationAndProof> blockingGetHomoCombinationAndProofs(int threshold) {
//            return null;
//        }
//
//        List<DecryptionAndProof> blockingGetDecryptionAndProofs(int threshold) {
//            return null;
//        }
//
//    }
//
//
//    // For each tallier
//    List<MixedBallotsAndProof> mixAndProofs;
//
//    // For each ballot (generation pfd)
//    class PFD {
//        // list of Pair
//        private List<HomoCombinationAndProof> homoCombAndProofs;
//        // homo combination c'
//        // homo proof
//
//        // list of Pair
//        private List<DecryptionAndProof> decryptionAndProofs_m;
//        // Decryption m
//        // Decryption proof 1 m
//
//        // list of Pair
//        private List<DecryptionAndProof> decryptionAndProofs_v;
//        // Decryption v          (optional)
//        // Decryption proof 2 v' (optional, i.e. only done if m=1)
//
//        public PFD() {
//            this.homoCombAndProofs = new ArrayList<>();
//            this.decryptionAndProofs_m = new ArrayList<>();
//            this.decryptionAndProofs_v = new ArrayList<>();
//        }
//
//        // Add a homoComb pair
//        void addHomoCombinationAndProof(HomoCombinationAndProof obj) {
//            homoCombAndProofs.add(obj);
//        }
//
//        // Add a homoComb pair
//        void addDecryptionAndProof_m(DecryptionAndProof obj) {
//            decryptionAndProofs_m.add(obj);
//        }
//
//        // Add a homoComb pair
//        void addDecryptionAndProof_v(DecryptionAndProof obj) {
//            decryptionAndProofs_v.add(obj);
//        }
//
//        List<DecryptionAndProof> blockingGetHomoCombAndProofs(int threshold) {
//            return null;
//        }
//
//        List<DecryptionAndProof> blockingGetDecryptionAndProofs_m(int threshold) {
//            return null;
//        }
//
//        List<DecryptionAndProof> blockingGetDecryptionAndProofs_v(int threshold) {
//            return null;
//        }
//    }

}
