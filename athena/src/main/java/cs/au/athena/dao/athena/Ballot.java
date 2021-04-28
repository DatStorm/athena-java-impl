package cs.au.athena.dao.athena;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenProof;
import org.apache.commons.lang3.tuple.Pair;
import cs.au.athena.dao.bulletproof.BulletproofProof;
import cs.au.athena.elgamal.Ciphertext;

public class Ballot {
    public Ciphertext publicCredential;
    public Ciphertext encryptedNegatedPrivateCredential;
    public Ciphertext encryptedVote;
    public Pair<BulletproofProof, BulletproofProof> proofVotePair;
    public Sigma2PedersenProof proofNegatedPrivateCredential;
    public int counter;

    private Ballot() {
    }

    // b[1] = pd
    public Ciphertext getPublicCredential() {
        return publicCredential;
    }

    // b[2] = c1
    public Ciphertext getEncryptedNegatedPrivateCredential() {
        return encryptedNegatedPrivateCredential;
    }

    // b[3] = c2
    public Ciphertext getEncryptedVote() {
        return encryptedVote;
    }

    // b[4] = sigma_1
    public Sigma2PedersenProof getProofNegatedPrivateCredential() {
        return proofNegatedPrivateCredential;
    }

    // b[5] = sigma_2
    public Pair<BulletproofProof, BulletproofProof> getProofVotePair() {
        return proofVotePair;
    }

    // b[6] = counter
    public int getCounter() {
        return counter;
    }

    @Override
    public String toString() {
        return "Ballot{" +
                "pd=" + publicCredential.toShortString() +
                ", c1=" + CONSTANTS.ANSI_YELLOW + encryptedNegatedPrivateCredential.toShortString() + CONSTANTS.ANSI_RESET +
        ", enc_VOTE:=" +  CONSTANTS.ANSI_RED + encryptedVote.toOneLineShortString() + CONSTANTS.ANSI_RESET +
//                ", sigma1=" + proofVote.toNameString() +
//                ", sigma2=" + proofNegatedPrivateCredential.toNameString() +
                ", cnt=" + counter +
                '}';
    }


    public static class Builder {
        private Ciphertext publicCredential;
        private Ciphertext encryptedNegatedPrivateCredential;
        private Ciphertext encryptedVote;
        private Pair<BulletproofProof, BulletproofProof> proofVotePair;
        private Sigma2PedersenProof proofNegatedPrivateCredential;
        private int counter;

        public Builder setPublicCredential(Ciphertext publicCredential) {
            this.publicCredential = publicCredential;
            return this;
        }

        public Builder setEncryptedNegatedPrivateCredential(Ciphertext encryptedNegatedPrivateCredential) {
            this.encryptedNegatedPrivateCredential = encryptedNegatedPrivateCredential;
            return this;
        }

        public Builder setEncryptedVote(Ciphertext encryptedVote) {
            this.encryptedVote = encryptedVote;
            return this;
        }


        public Builder setProofVotePair(Pair<BulletproofProof, BulletproofProof> proofVotePair) {
            this.proofVotePair = proofVotePair;
            return this;
        }

        public Builder setProofNegatedPrivateCredential(Sigma2PedersenProof proofNegatedPrivateCredential) {
            this.proofNegatedPrivateCredential = proofNegatedPrivateCredential;
            return this;
        }

        public Builder setCounter(int counter) {
            this.counter = counter;
            return this;
        }


        public Ballot build() {
            //Check that all fields are set
            if (publicCredential == null ||
                    encryptedNegatedPrivateCredential == null ||
                    encryptedVote == null ||
                    proofVotePair == null ||
                    proofNegatedPrivateCredential == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            Ballot ballot = new Ballot();
            ballot.publicCredential = publicCredential;
            ballot.encryptedNegatedPrivateCredential = encryptedNegatedPrivateCredential;
            ballot.encryptedVote = encryptedVote;
            ballot.proofVotePair = proofVotePair;
            ballot.proofNegatedPrivateCredential = proofNegatedPrivateCredential;
            ballot.counter = counter;
            return ballot;
        }
    }
}
