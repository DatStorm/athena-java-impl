package cs.au.athena.athena.bulletinboard;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;
    private int tallierCount;
    private int threshold_k;
    private final Group group;
    private final Map<Integer, CompletableFuture<Pair<List<BigInteger>, List<Sigma1Proof>> >> tallierCommitmentsAndProofs;
    private final Map<Pair<Integer, Integer>, CompletableFuture<Ciphertext>> encryptedSubShares;
    private final Map<Integer, CompletableFuture<PK_Vector>> mapOfIndividualPK_vector;

    // static method to create instance of Singleton class
    public static BulletinBoardV2_0 getInstance(int tallierCount) {
        if (single_instance == null) {
            single_instance = new BulletinBoardV2_0(tallierCount);
        }

        return single_instance;
    }


    private BulletinBoardV2_0(int tallierCount) {
        this.group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        this.tallierCommitmentsAndProofs = new HashMap<>();
        this.mapOfIndividualPK_vector = new HashMap<>();
        this.encryptedSubShares = new HashMap<>();

        this.init(tallierCount);
    }

    // Set preexisting values, and populate maps with Futures
    private void init(int tallierCount) {
        this.tallierCount = tallierCount;
        this.threshold_k = tallierCount / 2; //TODO: is this correct? It must satisfy k < n/2

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







    public int retrieveTallierCount() {
        return tallierCount;
    }

    public int retrieveK() {
        return threshold_k;
    }

    // Compute and return the entire public key from the committed polynomials
    public ElGamalPK retrievePK() {
        BigInteger publicKey = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitmentsAndProofs.keySet().size(); i++) {
            List<BigInteger> commitmentCoefficients = tallierCommitmentsAndProofs.get(i).join().getLeft();
            publicKey = publicKey.multiply(commitmentCoefficients.get(0)).mod(group.p);
        }

        // group, h
        return new ElGamalPK(group, publicKey);
    }

    // Compute and return the public key share h_j=g^P(j) from the committed polynomials
    public ElGamalPK retrievePKShare(int j) {
        BigInteger publicKeyShare = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitmentsAndProofs.keySet().size(); i++) {
            List<BigInteger> commitmentCoefficients = tallierCommitmentsAndProofs.get(i).join().getLeft();

            for (int ell = 0; ell < this.threshold_k; ell++) {
                BigInteger j_pow_ell = BigInteger.valueOf(j).pow(ell);
                publicKeyShare = publicKeyShare.multiply(commitmentCoefficients.get(ell).modPow(j_pow_ell, group.p)).mod(group.p);
            }
        }

        // group, h_j
        return new ElGamalPK(group, publicKeyShare);
    }


    // Post commitment to P(X)
    public void publishPolynomialCommitmentsAndProofs(int tallierIndex, List<BigInteger> commitments, List<Sigma1Proof> commitmentProofs) {
        assert tallierIndex <= tallierCount;

        if (tallierCommitmentsAndProofs.containsKey(tallierIndex)) {
            tallierCommitmentsAndProofs.get(tallierIndex).complete(Pair.of(commitments, commitmentProofs));
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

    public CompletableFuture<Pair< List<BigInteger>, List<Sigma1Proof> >> retrieveCommitmentsAndProofs(int j) {
        return tallierCommitmentsAndProofs.get(j);
    }

    public void publishDecryptionShare(int tallierIndex, Ciphertext c, BigInteger decryptionShare) {
        throw new UnsupportedOperationException("TODO! ".repeat(30));
    }


    public Group getGroup() {
        return group;
    }

    public CompletableFuture<List<DecryptionShareAndProof>> retrieveValidDecryptionSharesAndProofWithThreshold(Ciphertext c, int k) {
        throw new UnsupportedOperationException("TODO! ".repeat(5));
//        return null;
    }


    /***************************************************
     *             Distributed stuff below             *
     **************************************************/
//
//    // Ballots
//    List<Ballot> ballots;
//
//    // For each ballot (generation pfr)
//    private List<PFR> pfr = new ArrayList<>();
//    private List<PFD> pfd = new ArrayList<>();
//
//
//    // Returns the PFR index, and grows PFR list if needed
//    public PFR getPfr(int index) {
//        // Check
//        boolean indexIsOnePastTheEnd = index == pfr.size();
//        if (indexIsOnePastTheEnd) {
//            // Object does not already exist
//            // Add a new object to the end
//            PFR obj = new PFR();
//            pfr.add(obj);
//
//            //Return the new object
//            return obj;
//
//        } else if (index < pfr.size()) {
//            // Object already exists
//            return pfr.get(index);
//
//        } else {
//            throw new IllegalArgumentException("getPfr() !!");
//        }
//    }
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
