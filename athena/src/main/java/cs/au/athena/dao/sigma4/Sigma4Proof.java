package cs.au.athena.dao.sigma4;

import cs.au.athena.dao.sigma3.Sigma3Proof;

import java.util.ArrayList;
import java.util.Arrays;

public class Sigma4Proof {
    private final ArrayList<Sigma3Proof> alpha_beta_omegaProofs;
    private final ArrayList<Sigma3Proof> alpha_alpha_omegaProofs;

    public Sigma4Proof(ArrayList<Sigma3Proof> alpha_beta_omegaProofs, ArrayList<Sigma3Proof> alpha_alpha_omegaProofs) {

        this.alpha_beta_omegaProofs = alpha_beta_omegaProofs;
        this.alpha_alpha_omegaProofs = alpha_alpha_omegaProofs;
    }

    public ArrayList<Sigma3Proof> getAlphaBetaProof() {
        return this.alpha_beta_omegaProofs;
    }

    public ArrayList<Sigma3Proof> getAlphaAlphaProof() {
        return this.alpha_alpha_omegaProofs;
    }

    @Override
    public String toString() {
        return "Sigma4Proof{" +
                "alphaBeta_omegaProofs=" + Arrays.toString(alpha_beta_omegaProofs.toArray()) +
                ", alpha_alpha_omegaProofs=" + Arrays.toString(alpha_alpha_omegaProofs.toArray()) +
                '}';
    }
}
