package cs.au.athena.athena.strategy;

import cs.au.athena.Polynomial;
import cs.au.athena.athena.AthenaCommon;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.sigma.Sigma1;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class DistributedStrategy implements Strategy {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("STRATEGY-DISTRIBUTED: ");


    AthenaFactory athenaFactory;
    BulletinBoardV2_0 bb;
    public DistributedStrategy(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.bb = this.athenaFactory.getBulletinBoard();
    }


    @Override
    public Group getGroup() {
        return bb.getGroup();
    }

    @Override
    public ElGamalSK setup(int tallierIndex, int nc, int kappa) {
        logger.info(MARKER, "getElGamalSK(...) => start");
        assert tallierIndex != 0 : "DistributedStrategy.Setup(...).tallierIndex can not be 0 and was " + tallierIndex;
        assert tallierIndex <= bb.retrieveTallierCount();

        Random random = athenaFactory.getRandom();
        Group group = this.getGroup();

        int tallierCount = bb.retrieveTallierCount();
        int k = bb.retrieveK();

        // Generate random polynomial P_i(X)
        logger.info(MARKER, "computing polynomial");
        Polynomial polynomial = Polynomial.newRandom(k, group, random);

        // Post commitment to P_i(X)
        logger.info(MARKER, "publishing polynomial commitment");

        // For each commitment, coefficient pair, do proof
        List<BigInteger> coefficients = polynomial.getCoefficients();
        List<BigInteger> commitments = polynomial.getCommitments();

        // Generate proofs for the commitments
        List<Sigma1Proof> commitmentProofs = new ArrayList<>();
        for(int ell = 0; ell <= k; ell++) {
            Sigma1Proof proof = this.proveKey(commitments.get(ell), coefficients.get(ell), kappa);
            commitmentProofs.add(proof);
        }

        // Publish commitments and proofs
        logger.info(MARKER, "publishing polynomial commitment and proofs");
        bb.publishPolynomialCommitmentsAndProofs(tallierIndex, commitments, commitmentProofs);

        // Generate talliers own private (sk, pk)
        ElGamalSK sk_i = Elgamal.generateSK(group, random);
        ElGamalPK pk_i = sk_i.pk;
        Sigma1Proof rho_i = this.proveKey(pk_i, sk_i, kappa);

        // Publish my individual public key, so others can send me a subShare
        logger.info(MARKER, "publish pk_i to bb.");
        bb.publishIndividualPKvector(tallierIndex, new PK_Vector(pk_i, rho_i));

        // Send subshares P_i(j) to T_j
        logger.info(MARKER, "publishSubShares start");
        this.publishSubShares(tallierIndex, group, random, tallierCount, polynomial, kappa);

        // Receive subshares, add our own, and compute our final share
        List<BigInteger> listOfSubShares = this.receiveSubShares(tallierIndex, group, tallierCount, k, sk_i, kappa);
        listOfSubShares.add(polynomial.eval(tallierIndex));
        BigInteger share_i = listOfSubShares.stream().reduce(BigInteger.ZERO, (a,b) -> a.add(b).mod(group.q));

        return new ElGamalSK(group, share_i);
    }


    // Compute and publish the subshares P_i(j) to all talliers j
    private void publishSubShares(int tallierIndex, Group group, Random random, int tallierCount, Polynomial polynomial, int kappa) {
        // For each other tallier
        for (int j = 1; j <= tallierCount; j++) {
            if (j == tallierIndex) {
                continue;
            }

            // Tallier T_i retrieves pk_j so he can send T_j their subshare
            PK_Vector pk_j_vector = bb.retrieveIndividualPKvector(j).join();
            ElGamalPK pk_j = pk_j_vector.pk;
            boolean isPK_jValid = this.verifyKey(pk_j, pk_j_vector.rho, kappa);

            if (!isPK_jValid) {
                throw new RuntimeException("Tallier T_i retrieved an invalid public key pk_j from tallier T_j.");
            }

            BigInteger subShare = polynomial.eval(j);
//            logger.info(MARKER, String.format("tallier computed subshare P_%d(%d): %d", tallierIndex, j, subShare));

            // Encrypt subShare using pk_j
            Ciphertext encSubShare = Elgamal.encrypt(GroupTheory.fromZqToG(subShare, group), pk_j, random);
//            logger.info(MARKER, String.format("tallier encrypted subshare P_%d(%d): enc(%d) -> %d , pk=%d", tallierIndex, j, subShare, encSubShare.c1, pk_j.h));

            // Send subshare, by encrypting and positing
            logger.info(MARKER, String.format("tallier %d publishing P_%d(%d)", tallierIndex, tallierIndex ,j));
            bb.publishEncSubShare(tallierIndex, j, encSubShare); // key = (i,j)
        }
    }

    // Receive, decrypt and verify the encrypted subshares
    private List<BigInteger> receiveSubShares(int tallierIndex, Group group, int tallierCount, int k, ElGamalSK sk_i, int kappa) {
        List<BigInteger> subShares = new ArrayList<>(tallierCount);

        // For each other tallier
        for (int j = 1; j <= tallierCount; j++) {
            if (j == tallierIndex) {
                continue;
            }

            // Receive subshare

            // Retrieve commitments and proofs from BB
            Ciphertext encSubShare = bb.retrieveEncSubShare(j, tallierIndex).join();
            Pair<List<BigInteger>, List<Sigma1Proof>> commitmentProofPairs = bb.retrieveCommitmentsAndProofs(j).join();
            List<BigInteger> commitments_j = commitmentProofPairs.getLeft();
            List<Sigma1Proof> commitmentProofs_j = commitmentProofPairs.getRight();

            logger.info(MARKER, String.format("tallier %d received P_%d(%d)", tallierIndex, j, tallierIndex));

            // Check length of polynomial commitment
            if (commitments_j.size() != k +1 || commitmentProofs_j.size() != k+1) {
                // FUTUREWORK: If the commitment is invalid or incorrect length, T_j is malicious and should be removed.
                throw new RuntimeException(String.format("Tallier %d published commitments of %d degree polynomial. Should be k=%d ", j, commitments_j.size(), k));
            }

            // VerifyKey on polynomial commitments
            for(int i = 0; i <= k; i++) {
                BigInteger commitment = commitments_j.get(i);
                Sigma1Proof proof = commitmentProofs_j.get(i);
                boolean isValid = this.verifyKey(commitment, proof, kappa);

                if (!isValid) {
                    // FUTUREWORK: If the proofs are invalid, T_j is malicious and should be removed.
                    throw new RuntimeException(String.format("Tallier %d published commitments with invalid proofs", j));
                }
            }

            // Decrypt encrypted subshare
            BigInteger subShareFromTallier_j = GroupTheory.fromGToZq(Elgamal.decrypt(encSubShare, sk_i), group);

            // Verify subshare
            // - First calculate the subshare commitment from the commitments on BB
            BigInteger commitmentToSubShare_a = Polynomial.getPointCommitment(tallierIndex, commitments_j, group); // P_j(i)

            // - Next calculate the subshare commitment as g^subshare.
            BigInteger commitmentToSubShare_b = group.g.modPow(subShareFromTallier_j, group.p);

            // - Verify the received subshare
            if (!commitmentToSubShare_a.equals(commitmentToSubShare_b)) {
                //TODO: Post (subShareFromTallier_j_GroupElement, ProveDec(subShareFromTallier_j_GroupElement, sk_i), to convince others that T_j is corrupt
                throw new RuntimeException("A subshare was inconsistent with the commitments");
            }

            // Compute my final share P(i) of secret key sk, as the sum of subshares P_j(i)
            subShares.add(subShareFromTallier_j);
        }

        return subShares;
    }


    @Override
    public Sigma1Proof proveKey(ElGamalPK pk, ElGamalSK sk, int kappa) {
        return this.proveKey(pk.h, sk.sk, kappa);
    }

    public Sigma1Proof proveKey(BigInteger pk, BigInteger sk, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        Random random = athenaFactory.getRandom();
        Group group = this.getGroup();

        assert group.g.modPow(sk, group.p).equals(pk) : "ProveKey: pk and sk does not match";

//        System.out.println("PK: " + pk);
//        System.out.println("SK: " + sk);

        return sigma1.ProveKey(pk, sk, group, random, kappa);
    }

    @Override
    public boolean verifyKey(ElGamalPK pk, Sigma1Proof rho, int kappa) {
        return verifyKey(pk.h, rho, kappa);
    }

    public boolean verifyKey(BigInteger h, Sigma1Proof rho, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        Group group = this.getGroup();
        return sigma1.VerifyKey(h, rho, group, kappa);
    }

    @Override
    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        // TODO: For each proof
        throw new UnsupportedOperationException();
    }

    @Override
    public Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group) {
        return AthenaCommon.homoCombination(c, nonce, group.p);
    }

    /**
     * @param skShare is the shamir secret sharing share: P(i)
     * @param kappa
     * @return decrypted message
     */
    @Override
    public BigInteger decrypt(int tallierIndex, Ciphertext c, ElGamalSK skShare, int kappa) {
        Group group = this.getGroup();
        int k = bb.retrieveK();

        // Publish decryption share
        BigInteger decryptionShare = c.c1.modPow(skShare.toBigInteger().negate(),group.p);
        bb.publishDecryptionShare(tallierIndex, c, decryptionShare);

        // Retrieve decryption shares for ciphertext c when there is k+1 shares on the bulletin board.
        // get k+1 shares from BB.
        List<DecryptionShareAndProof> shares = bb.retrieveValidDecryptionSharesAndProofWithThreshold(c, k).join();
        assert shares.size() == k+1;

        // Verify that the decryption shares are valid, and
        BigInteger prodSumOfDecryptionShares = BigInteger.ONE;
        for (int j = 1; j <= k; j++) {
            DecryptionShareAndProof share = shares.get(j);
            ElGamalPK h_j = bb.retrievePKShare(j);
            this.verifyDecryption(c, share.share, h_j, share.proof, kappa);

            prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(share.share).mod(group.p);
        }


        // Decrypt the ciphertext with the new sk.
        return c.c2.multiply(prodSumOfDecryptionShares).mod(group.p);
    }
}
