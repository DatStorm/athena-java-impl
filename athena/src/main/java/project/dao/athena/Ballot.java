package project.dao.athena;

import project.dao.bulletproof.BulletproofProof;
import project.dao.sigma2.Sigma2Proof;
import project.elgamal.CipherText;

public class Ballot {
    public final CipherText publicCredential;
    public final CipherText encryptedNegatedPrivateCredential;
    public final CipherText encryptedVote;
    public final BulletproofProof proofVote;
    public final BulletproofProof proofNegatedPrivateCredential;
    public final int counter;

    public Ballot(CipherText publicCredential, CipherText encryptedVote, CipherText encryptedNegatedPrivateCredential, BulletproofProof proofVote, BulletproofProof proofNegatedPrivateCredential, int counter) {
        this.publicCredential = publicCredential;
        this.encryptedNegatedPrivateCredential = encryptedNegatedPrivateCredential;
        this.encryptedVote = encryptedVote;
        this.proofNegatedPrivateCredential = proofNegatedPrivateCredential;
        this.proofVote = proofVote;
        this.counter = counter;
    }
    
    // b[1] = pd
    public CipherText getPublicCredential() {
        return publicCredential;
    }

    // b[2] = c1
    public CipherText getEncryptedNegatedPrivateCredential() {
        return encryptedNegatedPrivateCredential;
    }

    // b[3] = c2
    public CipherText getEncryptedVote() {
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
                "publicCredential=" + publicCredential +
                ", encryptedNegatedPrivateCredential=" + encryptedNegatedPrivateCredential +
                ", encryptedVote=" + encryptedVote +
                ", proofVote=" + proofVote +
                ", proofNegatedPrivateCredential=" + proofNegatedPrivateCredential +
                ", counter=" + counter +
                '}';
    }
}
