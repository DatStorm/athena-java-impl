package cs.au.athena.dao.athena;

import com.google.common.primitives.Bytes;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;

public class UVector {
    private final BigInteger pudCred_c1;
    private final BigInteger pudCred_c2;
    private final BigInteger encNegPrivCred_c1;
    private final BigInteger encNegPrivCred_c2;
    private final BigInteger encVote_c1;
    private final BigInteger encVote_c2;
    private final BigInteger cnt;


    public UVector(Ciphertext publicCredential, Ciphertext encryptedNegatedPrivateCredential, Ciphertext encryptedVote, BigInteger cnt) {
        this.pudCred_c1 = publicCredential.c1;
        this.pudCred_c2 = publicCredential.c2;
        this.encNegPrivCred_c1 = encryptedNegatedPrivateCredential.c1;
        this.encNegPrivCred_c2 = encryptedNegatedPrivateCredential.c2;
        this.encVote_c1 = encryptedVote.c1;
        this.encVote_c2 = encryptedVote.c2;
        this.cnt = cnt;
    }




    public byte[] toByteArray() {
        byte[] res = new byte[]{};

        res = Bytes.concat(res, this.pudCred_c1.toByteArray());
        res = Bytes.concat(res, this.pudCred_c2.toByteArray());
        res = Bytes.concat(res, this.encNegPrivCred_c1.toByteArray());
        res = Bytes.concat(res, this.encNegPrivCred_c2.toByteArray());
        res = Bytes.concat(res, this.encVote_c1.toByteArray());
        res = Bytes.concat(res, this.encVote_c2.toByteArray());
        res = Bytes.concat(res, this.cnt.toByteArray());

        return res;
    }

    public BigInteger[] toBigInteger() {

        return new BigInteger[]{this.pudCred_c1, this.pudCred_c2,
                this.encNegPrivCred_c1,
                this.encNegPrivCred_c2,
                this.encVote_c1,
                this.encVote_c2,
                this.cnt};
    }


    @Override
    public String toString() {
        return "UVector{" +
                "pudCred_c1=" + pudCred_c1 +
                ", pudCred_c2=" + pudCred_c2 +
                ", encNegPrivCred_c1=" + encNegPrivCred_c1 +
                ", encNegPrivCred_c2=" + encNegPrivCred_c2 +
                ", encVote_c1=" + encVote_c1 +
                ", encVote_c2=" + encVote_c2 +
                ", cnt=" + cnt +
                '}';
    }
}
