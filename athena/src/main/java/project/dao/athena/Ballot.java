package project.dao.athena;

import project.CONSTANTS;
import project.athena.AthenaVerify;
import project.athena.BulletinBoard;
import project.dao.bulletproof.BulletproofProof;
import project.elgamal.Ciphertext;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;

public class Ballot {
    public Ciphertext publicCredential;
    public Ciphertext encryptedNegatedPrivateCredential;
    public Ciphertext encryptedVote;
    public BulletproofProof proofVote;
    public BulletproofProof proofNegatedPrivateCredential;
    public int counter;

    private Ballot() {}

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
    public BulletproofProof getProofNegatedPrivateCredential() {
        return proofNegatedPrivateCredential;
    }

    // b[5] = sigma_2
    public BulletproofProof getProofVote() {
        return proofVote;
    }

    // b[6] = counter
    public int getCounter() {
        return counter;
    }

    @Override
    public String toString() {
        return "Ballot{" +
                "pd=" + publicCredential.toShortString() +
                ", c1=" + encryptedNegatedPrivateCredential.toShortString() +
                CONSTANTS.ANSI_RED +
                ", enc_VOTE:=" + encryptedVote.toFormattedString() +
                CONSTANTS.ANSI_RESET +
//                ", sigma1=" + proofVote.toNameString() +
//                ", sigma2=" + proofNegatedPrivateCredential.toNameString() +
                ", cnt=" + counter +
                '}';
    }


    public static class Builder {
        private Ciphertext publicCredential;
        private Ciphertext encryptedNegatedPrivateCredential;
        private Ciphertext encryptedVote;
        private BulletproofProof proofVote;
        private BulletproofProof proofNegatedPrivateCredential;
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


        public Builder setProofVote(BulletproofProof proofVote) {
            this.proofVote = proofVote;
            return this;
        }

        public Builder setProofNegatedPrivateCredential(BulletproofProof proofNegatedPrivateCredential) {
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
                proofVote == null ||
                proofNegatedPrivateCredential == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            Ballot ballot = new Ballot();
            ballot.publicCredential = publicCredential;
            ballot.encryptedNegatedPrivateCredential = encryptedNegatedPrivateCredential;
            ballot.encryptedVote = encryptedVote;
            ballot.proofVote = proofVote;
            ballot.proofNegatedPrivateCredential = proofNegatedPrivateCredential;
            return ballot;
        }
    }
}
