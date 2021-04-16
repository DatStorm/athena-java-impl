package cs.au.athena.athena.strategy;

import cs.au.athena.Polynomial;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class DistributedStrategy implements Strategy {

    AthenaFactory athenaFactory;
    BulletinBoardV2_0 bb;
    public DistributedStrategy(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
//        BulletinBoard bb = this.athenaFactory.getBulletinBoard();
        this.bb = BulletinBoardV2_0.getInstance();
    }


    @Override
    public Group getGroup(int bitlength, Random random) {
        return bb.getGroup();
    }

    @Override
    public ElGamalSK getElGamalSK(int tallierIndex, Group group, Random random) {
        int tallierCount = bb.retrieveTallierCount();
        int k = bb.retrieveK();

        // Generate random polynomial P_i(X)
        Polynomial p = Polynomial.newRandom(k, group, random);

        // Post commitment to P(X)
        bb.publishPolynomialCommitment(tallierIndex, p.getCommitmentOfPolynomialCoefficients());

        // Generate private (sk, pk)
        ElGamalSK sk = Elgamal.generateSK(group, random);
        ElGamalPK pk = sk.pk;

        // Send P_i(j) to T_j
        for (int j = 0; j < tallierCount; j++) {
            BigInteger subShare = p.get(j);

            // Get pk_j
            ElGamalPK pk_j = bb.retrievePK(j);

            // FIXME: Use encryption. Reversable mapping
            // Encrypt subShare using pk_j
            BigInteger subshareElement = GroupTheory.fromZqToG(subShare, group);
            Ciphertext encSubShare = Elgamal.encrypt(subshareElement, pk_j, random);

            // Publish encryption
//            bb.publishTallierPublicKey(tallierIndex, pk); // TODO: VI FATTER DEN IKKE!!!
            bb.publishEncSubShare(j, encSubShare);
        }


        // Decrypt shares and compute polynomial P(i)
        BigInteger share_i = BigInteger.ZERO;
        for (int j = 0; j < tallierCount; j++) {
            Ciphertext encSubShare = bb.retrieveEncSubShare(j);
            List<BigInteger> polynomialCommitment = bb.retrievePolynomialCommitment(j);

            // FIXME: Use encryption. Reversable mapping
            // Get P_j(i)
            BigInteger subShareFromTallier_j = Elgamal.decrypt(encSubShare, sk);
            BigInteger bigK = GroupTheory.fromGToZq(subShareFromTallier_j, group); // TODO: review this
            for(int ell = 0; ell < k; ell++) {
                // TODO: continue here
            }

            // Compute my share, as the sum of subshares
            share_i = share_i.add(subShareFromTallier_j).mod(group.p);
        }


        // Verify share


        return new ElGamalSK(group, share_i);
    }

    // Probably redundant. -Mark
    @Override
    public ElGamalPK getElGamalPK(ElGamalSK sk) {
        // return g^P(i)
        return sk.pk;
    }

    @Override
    public ProveKeyInfo proveKey(ElGamalPK pk, ElGamalSK sk, Randomness r, int kappa) {



        return null;
    }

    @Override
    public boolean verifyKey(ElGamalPK pk, ProveKeyInfo rho, int kappa) {
        return false;
    }

    @Override
    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        return null;
    }

    @Override
    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        return false;
    }

    @Override
    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        return null;
    }

    @Override
    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        return false;
    }

    @Override
    public MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        // TODO: Wait for turn

        return null;
    }

    @Override
    public boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        // TODO: For each proof
        return false;
    }

    @Override
    public Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group) {
        return null;
    }

    @Override
    public BigInteger decrypt(Ciphertext c, ElGamalSK sk) {
        return null;
    }
}
