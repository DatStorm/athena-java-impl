package project.dao.sigma3;

import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.GroupDescription;

import java.math.BigInteger;
import java.util.List;



// alpha = c1 = g^r
// beta = c2 = m*h^r
public class Sigma3Statement {
    public GroupDescription group;
    public BigInteger alpha;
    public BigInteger alpha_base;
    public BigInteger beta;
    public BigInteger beta_base;

     // prove log_{alpha_base}alpha = log_{beta_base}beta
    public Sigma3Statement(GroupDescription group, BigInteger alpha, BigInteger beta, BigInteger alpha_base, BigInteger beta_base) {
        this.group = group;
        this.alpha = alpha;
        this.beta = beta;
        this.alpha_base = alpha_base;
        this.beta_base = beta_base;
    }
}