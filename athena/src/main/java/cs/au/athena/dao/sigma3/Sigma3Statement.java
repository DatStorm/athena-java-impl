package cs.au.athena.dao.sigma3;

import cs.au.athena.elgamal.Group;

import java.math.BigInteger;


// alpha = c1 = g^r
// beta = c2 = m*h^r
public class Sigma3Statement {
    public Group group;
    public BigInteger alpha;
    public BigInteger alpha_base;
    public BigInteger beta;
    public BigInteger beta_base;

     // prove log_{alpha_base}alpha = log_{beta_base}beta
    public Sigma3Statement(Group group, BigInteger alpha, BigInteger beta, BigInteger alpha_base, BigInteger beta_base) {
        this.group = group;
        this.alpha = alpha;
        this.beta = beta;
        this.alpha_base = alpha_base;
        this.beta_base = beta_base;
    }

    public Group getGroup() {
        return this.group;
    }

    @Override
    public String toString() {
        return "\nSigma3Statement{" +
                "\n" + group.toString() +
                ", alpha=" + alpha +
                ", alpha_base=" + alpha_base +
                ", beta=" + beta +
                ", beta_base=" + beta_base +
                "}\n";
    }
}