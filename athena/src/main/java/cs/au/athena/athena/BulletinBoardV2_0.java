package cs.au.athena.athena;

import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.List;
import java.util.ArrayList;

public class BulletinBoardV2_0 {

    private static BulletinBoardV2_0 single_instance = null;

    // static method to create instance of Singleton class
    public static BulletinBoardV2_0 getInstance() {
        if (single_instance == null) {
            single_instance = new BulletinBoardV2_0();
        }
        return single_instance;
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

        List<HomoCombinationAndProof> blockingGetHomoCombinationAndProofs(int threshold){return null;}
        List<DecryptionAndProof> blockingGetDecryptionAndProofs(int threshold){return null;}

    }




    // For each tallier
    List<MixedBallotsAndProof> mixAndProofs;
    class MixedBallotsAndProof {
        // Mixnet & proof
        List<MixBallot> mixedBallots;
        MixProof mixProof;
    }

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

        List<DecryptionAndProof> blockingGetHomoCombAndProofs(int threshold){return null;}
        List<DecryptionAndProof> blockingGetDecryptionAndProofs_m(int threshold){return null;}
        List<DecryptionAndProof> blockingGetDecryptionAndProofs_v(int threshold){return null;}
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




}
