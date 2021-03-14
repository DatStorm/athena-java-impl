package project.dao.athena;

import project.dao.bulletproof.BulletproofProof;
import project.elgamal.Ciphertext;

public class Ballot {
    public final Ciphertext publicCredential;
    public final Ciphertext encryptedNegatedPrivateCredential;
    public final Ciphertext encryptedVote;
    public final BulletproofProof proofVote;
    public final BulletproofProof proofNegatedPrivateCredential;
    public final int counter;

    public Ballot(Ciphertext publicCredential, Ciphertext encryptedVote, Ciphertext encryptedNegatedPrivateCredential, BulletproofProof proofVote, BulletproofProof proofNegatedPrivateCredential, int counter) {
        this.publicCredential = publicCredential;
        this.encryptedNegatedPrivateCredential = encryptedNegatedPrivateCredential;
        this.encryptedVote = encryptedVote;
        this.proofNegatedPrivateCredential = proofNegatedPrivateCredential;
        this.proofVote = proofVote;
        this.counter = counter;
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

    // b[4] = simga_1
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
                ", c2=" + encryptedVote.toShortString() +
//                ", sigma1=" + proofVote.toNameString() +
//                ", sigma2=" + proofNegatedPrivateCredential.toNameString() +
                ", cnt=" + counter +
                '}';
    }
}
