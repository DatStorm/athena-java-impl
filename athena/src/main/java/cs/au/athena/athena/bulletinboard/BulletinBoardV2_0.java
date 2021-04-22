package cs.au.athena.athena.bulletinboard;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;

// Responsible for the posting of votes with a registered credential, and other positings. Is async.
public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;
    private final Sigma3 sigma3;
    private int tallierCount;
    private int threshold_k;
    private final Group group;

    List<Ballot> ballots;

    private final Map<Integer, CompletableFuture<List<CommitmentAndProof>>> tallierCommitmentsAndProofs;
    private final Map<Pair<Integer, Integer>, CompletableFuture<Ciphertext>> encryptedSubShares;
    private final Map<Integer, CompletableFuture<PK_Vector>> mapOfIndividualPK_vector;



    // Activated when a tallier posts homocomb or decryption shares
    public PfrPhaseOne pfrPhaseOne;
    private PfrPhaseTwo pfrPhaseTwo;

    private List<PFR> synchronizedPFR;
    private List<PFD> synchronizedPFD;

//    private final Map<Pair<Ciphertext, Integer>, CompletableFuture<DecryptionShareAndProof>> decryptionShareMap;
    private int kappa;

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

        this.synchronizedPFR = null; // Set on call to publishCombinedCiphertext
        this.synchronizedPFD = null;


        this.sigma3 = new Sigma3();
        this.kappa = kappa;

        this.init(tallierCount);
    }

    // Set preexisting values, and populate maps with Futures
    private void init(int tallierCount) {
        this.tallierCount = tallierCount;
        this.threshold_k = tallierCount / 2; //TODO: is this correct? It must satisfy k < n/2

        this.pfrPhaseOne = new PfrPhaseOne(tallierCount);
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
        return threshold_k;
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

            for (int ell = 0; ell < this.threshold_k; ell++) {
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

    private synchronized void initPFR() {
        int ell = ballots.size();

        // Create list
        if(synchronizedPFR == null) {
            synchronizedPFR = Collections.synchronizedList(new ArrayList<>(ell));
        }

        // Init all elements
        for (int i = 0; i < ell; i++) {
            synchronizedPFR.add(new PFR(tallierCount));
        }
    }

    public synchronized void publishCombinedCiphertextAndProofToPFR_PFD(int tallierIndex, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) {
        int ell = ballots.size();

        if(listOfCombinedCiphertextAndProof.size() == ell) {
            throw new IllegalArgumentException("list must be the same length as ballots");
        }

        // Set values in pfr
        for (int i = 0; i < ell; i++) {
            pfrPhaseOne.add(Pair.of(tallierIndex, listOfCombinedCiphertextAndProof));
        }

        //notifyPfrPhaseOne(listOfCombinedCiphertextAndProof); // TODO: How to eventlistener
        // onPublish will finish before continuing?
    }

    public CompletableFuture<PfrPhaseOne> retrieveThresholdCombinedCiphertextAndProofFromPFR_PFR(int threshold) {
        int ell = ballots.size();
        ElGamalPK pk = this.retrievePK();

        if (pfrPhaseOne == null) {
            throw new RuntimeException("publishCombinedCiphertextAndProof must be called first");
        }

        // A list(for each ballot) containing a list of valid CombinedCiphertextAndProof(one from each honest tallier)
        PfrPhaseOne result = new PfrPhaseOne(threshold+1);
        CompletableFuture<PfrPhaseOne> f = CompletableFuture.completedFuture(new PfrPhaseOne(tallierCount));


        List<CompletableFuture<Pair<Integer, List<CombinedCiphertextAndProof>>>> publications = new ArrayList<>(tallierCount);




        // publish1: f1.complete(val1). return
        // publish2: f2.complete(val2)
        // Publications : [f1Completed, f2Completed, f3, f4, f5, ...]
        // resultFuture: f1Completed -> [val1] -> f2Completed -> [val1, val2] -> ... -> [].size = k+1


        // OnPublish


        // When a taller posts, check if honest. Observer.
        // When T1 publishes -> call onPublish(...)

        // MISSION: make a list of valid homoComb's.

        Consumer<List<CombinedCiphertextAndProof>> onPublish = (List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) -> {
            // Check proof of each
            Sigma4 sigma4 = new Sigma4();

            // First iteration
            CombinedCiphertextAndProof previousObj = listOfCombinedCiphertextAndProof.get(0);
            Ballot previousBallot = ballots.get(0);

            for (int i = 1; i < ell; i++) {
                CombinedCiphertextAndProof currentObj = listOfCombinedCiphertextAndProof.get(i);
                Ballot currentBallot = ballots.get(i);

                // Make proof statement
                List<Ciphertext> listCombinedCiphertext = Arrays.asList(previousObj.combinedCiphertext, currentObj.combinedCiphertext);
                List<Ciphertext> listCiphertexts = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

                // Verify proof
                boolean isValid = sigma4.verifyCombination(pk, listCombinedCiphertext, listCiphertexts, currentObj.proof, kappa);

                // If a proof fails, STOP
                if (!isValid) return;
            }

            // If we made it to here, all proofs are valid

            // if all honest, add to result list
            return result;
        };








        // T1 not done publishing. Then he is skipped
        // If T1 is done later, the he is kept

        // publishCombinedCiphertextAndProofToPFR_PFD(int tallierIndex, int ballotIndex);



        return f;
    }



    public void publishDecryptionShareAndProofToPFR_PFD(int tallierIndex, int ballotIndex, Ciphertext c, DecryptionShareAndProof decryptionShareAndProof) {
        Pair<Ciphertext, Integer> key = Pair.of(c, tallierIndex);
        //this.decryptionShareMap.put(key, new CompletableFuture<>()); // TODO: THIS IS REALLY BAD I THINK
        //this.pfr.
        //decryptionShareMap.get(key).complete(decryptionShareAndProof); // TODO: post to pfr/pfd instead

        // Verify proofs. If one fail, the tallier is malicious and it's entire input is ignored
        synchronizedPFR.get(ballotIndex).set bla bla;


        // Signal to other talliers, that values are available
        phaseDecryption.get(tallierIndex).complete(null);
    }



    public CompletableFuture<List<DecryptionShareAndProof>> retrieveValidDecryptionSharesAndProofWithThreshold(Ciphertext ciphertext, int k) {
        ElGamalPK publicKey = this.retrievePK(); //FIXME: a little slow

        // Stores shares as they become available
        List<DecryptionShareAndProof> synchronizedResultList = Collections.synchronizedList(new ArrayList<>());

        // Adds shares to synchronizedResultList, as they become available
        List<CompletableFuture<DecryptionShareAndProof>> futures = new ArrayList<>();

        // Is completed when k+1 shares are available, so we can return them
        CompletableFuture<Void> enoughSharesAreAvailable = new CompletableFuture<>();


        // For each tallier, wait for the decryption share to be set
        for (int i = 1; i < tallierCount; i++) {
            Pair<Ciphertext, Integer> key = Pair.of(ciphertext, i);
            CompletableFuture<DecryptionShareAndProof> future = this.decryptionShareMap.get(key); // TODO: retrieve from pfr/pfd instead

            // When the future completes, add decryption share to list
            future.thenAccept(decryptionShare -> {
                // if is valid then add, else not
                boolean isDecValid = this.sigma3.verifyDecryption(ciphertext, decryptionShare.share, publicKey, decryptionShare.proof, this.kappa);

                if (isDecValid) {
                    synchronizedResultList.add(decryptionShare);
                }

                if (synchronizedResultList.size() >= k+1) {
                    enoughSharesAreAvailable.complete(null);
                }
            });

            futures.add(future);
        }



        CompletableFuture<List<DecryptionShareAndProof>> resultFuture = new CompletableFuture<>();
        List<DecryptionShareAndProof> resultList = new ArrayList<>();

        // We are done when isDone is completed above.
        // Copy elements into non synchronized list
        // Finally complete result future
        enoughSharesAreAvailable.thenRun(() -> {
            synchronized (synchronizedResultList) {
                // Copy first k+1 elements
                for (int i = 0; i <= k; i++) {
                    resultList.add(synchronizedResultList.get(i));
                }

                // Cancel other futures
                for (int i = 0; i < tallierCount; i++) {
                    futures.get(i).cancel(false);
                }

                // Complete result future
                resultFuture.complete(resultList);
            }
        });

       return resultFuture;
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
    // Returns the PFR index, and grows PFR list if needed
    public PFR getPfr(int index) {
        // Check
        boolean indexIsOnePastTheEnd = index == pfr.size();
        if (indexIsOnePastTheEnd) {
            // Object does not already exist
            // Add a new object to the end
            PFR obj = new PFR();
            pfr.add(obj);

            //Return the new object
            return obj;

        } else if (index < pfr.size()) {
            // Object already exists
            return pfr.get(index);

        } else {
            throw new IllegalArgumentException("getPfr() !!");
        }
    }

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
