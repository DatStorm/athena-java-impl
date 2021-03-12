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
    
    // b[1]

    public CipherText getPublicCredential() {
        return publicCredential;
    }

    // b[2]
    public CipherText getEncryptedNegatedPrivateCredential() {
        return encryptedNegatedPrivateCredential;
    }

    // b[3]
    public CipherText getEncryptedVote() {
        return encryptedVote;
    }

    // b[4]
    public BulletproofProof getProofNegatedPrivateCredential() {
        return proofNegatedPrivateCredential;
    }

    // b[5]
    public BulletproofProof getProofVote() {
        return proofVote;
    }

    // b[6]
    public int getCounter() {
        return counter;
    }
}
