package project.dao.sigma3;

import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.List;

public class ProveDecryptionInfo {
    public ElGamalPK pk;
    public List<CipherText> cipherTextList;
    public List<BigInteger> plainTextList;
}