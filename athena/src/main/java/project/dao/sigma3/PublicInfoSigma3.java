package project.dao.sigma3;

import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.GroupDescription;

import java.math.BigInteger;
import java.util.List;



// alpha = c1 = g^r
// beta = c2 = m*h^r
public class PublicInfoSigma3 {
    public GroupDescription group;
    public BigInteger h;    // h = g^sk
    public BigInteger z;    // z = m^sk
    public BigInteger m;

    // prove log_{alpha'}alpha = log_{beta'}beta
    // alpha = alpha'^ x
    // beta  = beta' ^ x
    // in the case of
    // prove log_{g}h = log_{m}z
    public BigInteger alpha;
    public BigInteger alpha_base;
    public BigInteger beta;
    public BigInteger beta_base;

    public ElGamalPK pk;
    public CipherText cipherText;
    public BigInteger plainText;


    /**
     * TODO: !!!!!!!!!! KOD OM !!!!!!!!!!!!!!!!!!
     * @param pk
     * @param c1_c2
     * @param plainText
     */
    public PublicInfoSigma3(ElGamalPK pk, CipherText c1_c2, BigInteger plainText) {
        this.pk = pk;
        this.group = pk.getGroup();
        this.h = pk.getH();
        this.m = plainText;
        BigInteger p = pk.getGroup().getP();
        this.z = c1_c2.c2.multiply(this.m.modInverse(p)).mod(p);

        this.cipherText = c1_c2;
        this.plainText = plainText;
    }

     // prove log_{alpha_base}alpha = log_{beta_base}beta
    public PublicInfoSigma3(GroupDescription group, BigInteger alpha, BigInteger beta, BigInteger alpha_base, BigInteger beta_base) {
        this.group = group;
        this.alpha = alpha;
        this.beta = beta;
        this.alpha_base = alpha_base;
        this.beta_base = beta_base;
    }
}