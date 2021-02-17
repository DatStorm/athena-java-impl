package project.dao.sigma3;

import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.List;

public class PublicInfoSigma3 {
    public ElGamalPK pk;
    public CipherText cipherText;
    public BigInteger plainText;

    public PublicInfoSigma3(ElGamalPK pk, CipherText c1_c2, BigInteger plainText) {
        this.pk = pk;
        this.cipherText = c1_c2;
        this.plainText = plainText;
    }
}