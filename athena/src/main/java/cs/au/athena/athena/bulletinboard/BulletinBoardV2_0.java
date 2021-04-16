package cs.au.athena.athena.bulletinboard;

import com.google.common.cache.AbstractCache;
import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;

public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;
    private final int tallierCount;
    private int k;
    private Group group;
    private Map<Integer, List<BigInteger>> tallierCommitments;
    private Map<Integer, Ciphertext> encryptedSubShares;

    // static method to create instance of Singleton class
    public static BulletinBoardV2_0 getInstance() {
        if (single_instance == null) {
            single_instance = new BulletinBoardV2_0();
        }
        return single_instance;
    }


    private BulletinBoardV2_0() {
        this.group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        this.tallierCount = CONSTANTS.TALLIER_CURRENT.TALLIER_COUNT;
        this.k = CONSTANTS.TALLIER_CURRENT.K;
        tallierCommitments = new HashMap<>(this.tallierCount);
        encryptedSubShares = new HashMap<>(this.tallierCount);
    }


    // Ballots
    List<Ballot> ballots;

    // For each ballot (generation pfr)
    private List<PFR> pfr = new ArrayList<>();
    private List<PFD> pfd = new ArrayList<>();


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

    // Returns the PFD index, and grows PFR list if needed
    public PFD getPfd(int index) {
        // Check
        boolean indexIsOnePastTheEnd = index == pfd.size();
        if (indexIsOnePastTheEnd) {
            // Object does not already exist
            // Add a new object to the end
            PFD obj = new PFD();
            pfd.add(obj);

            //Return the new object
            return obj;

        } else if (index < pfd.size()) {
            // Object already exists
            return pfd.get(index);

        } else {
            throw new IllegalArgumentException("getPfd() !!");
        }
    }

    public int retrieveTallierCount() {
        return tallierCount;
    }

    public int retrieveK() {
        return k;
    }

    // Compute and return the entire public key from the committed polynomials
    public ElGamalPK retrievePK() {
        BigInteger publicKey = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitments.keySet().size(); i++) {
            List<BigInteger> commitmentCoefficients = tallierCommitments.get(i);
            publicKey = publicKey.multiply(commitmentCoefficients.get(0)).mod(group.p);
        }

        // group, h
        return new ElGamalPK(group, publicKey);
    }

    public ElGamalPK retrievePK(int j) {
        BigInteger publicKeyShare = BigInteger.ONE;

        // Iterate all commitments
        for (int i = 0; i < tallierCommitments.keySet().size(); i++) {
            List<BigInteger> commitmentCoefficients = tallierCommitments.get(i);

            for (int ell = 0; ell < this.k; ell++) {
                BigInteger j_pow_ell = BigInteger.valueOf(j).pow(ell);
                publicKeyShare = publicKeyShare.multiply(commitmentCoefficients.get(ell).modPow(j_pow_ell, group.p)).mod(group.p);
            }

        }

        // group, h_j
        return new ElGamalPK(group, publicKeyShare);
    }


    // Post commitment to P(X)
    public void publishPolynomialCommitment(int tallierIndex, List<BigInteger> commitments) {
        tallierCommitments.put(tallierIndex, commitments);
    }

    // TODO: Skipper thinks this is redundant, as it can be computed from the committed polynomials
    public void publishTallierPublicKey(int tallierIndex, ElGamalPK pk) {
        throw new UnsupportedOperationException("FIXME");
    }

    public void publishEncSubShare(int j, Ciphertext subShareToTallier_j) {
        encryptedSubShares.put(j, subShareToTallier_j);
    }

    public Ciphertext retrieveEncSubShare(int j) {
        return encryptedSubShares.get(j);
    }

    public List<BigInteger> retrievePolynomialCommitment(int j) {
        return tallierCommitments.get(j);
    }


    // Construct pfr elements
    class PFR {
        // list of HomoAndProof
        List<HomoCombinationAndProof> homoCombAndProofs;

        // List of DecryptionAndProof{
        List<DecryptionAndProof> decryptionAndProofs;

        public PFR() {
            homoCombAndProofs = new ArrayList<>();
            decryptionAndProofs = new ArrayList<>();
        }

        // Add a homoComb pair
        void addHomoCombinationAndProof(HomoCombinationAndProof obj) {
            homoCombAndProofs.add(obj);
        }

        // Add a Decryption pair
        void addHomoCombinationAndProof(DecryptionAndProof obj) {
            decryptionAndProofs.add(obj);
        }

        List<HomoCombinationAndProof> blockingGetHomoCombinationAndProofs(int threshold) {
            return null;
        }

        List<DecryptionAndProof> blockingGetDecryptionAndProofs(int threshold) {
            return null;
        }

    }


    // For each tallier
    List<MixedBallotsAndProof> mixAndProofs;

    // For each ballot (generation pfd)
    class PFD {
        // list of Pair
        private List<HomoCombinationAndProof> homoCombAndProofs;
        // homo combination c'
        // homo proof

        // list of Pair
        private List<DecryptionAndProof> decryptionAndProofs_m;
        // Decryption m
        // Decryption proof 1 m

        // list of Pair
        private List<DecryptionAndProof> decryptionAndProofs_v;
        // Decryption v          (optional)
        // Decryption proof 2 v' (optional, i.e. only done if m=1)

        public PFD() {
            this.homoCombAndProofs = new ArrayList<>();
            this.decryptionAndProofs_m = new ArrayList<>();
            this.decryptionAndProofs_v = new ArrayList<>();
        }

        // Add a homoComb pair
        void addHomoCombinationAndProof(HomoCombinationAndProof obj) {
            homoCombAndProofs.add(obj);
        }

        // Add a homoComb pair
        void addDecryptionAndProof_m(DecryptionAndProof obj) {
            decryptionAndProofs_m.add(obj);
        }

        // Add a homoComb pair
        void addDecryptionAndProof_v(DecryptionAndProof obj) {
            decryptionAndProofs_v.add(obj);
        }

        List<DecryptionAndProof> blockingGetHomoCombAndProofs(int threshold) {
            return null;
        }

        List<DecryptionAndProof> blockingGetDecryptionAndProofs_m(int threshold) {
            return null;
        }

        List<DecryptionAndProof> blockingGetDecryptionAndProofs_v(int threshold) {
            return null;
        }
    }

    class HomoCombinationAndProof {
        // ciphertext homo
        Ciphertext homoComb;

        // Proof of homo
        Sigma4Proof homoProof;

    }

    class DecryptionAndProof {
        // Decryption shares
        BigInteger d;

        // Proof of decryption share
        Sigma3Proof decryptionProof;
    }

    /***************************************************
     *             Distributed stuff below             *
     **************************************************/
    public Group getGroup() {
        return group;
    }


}
