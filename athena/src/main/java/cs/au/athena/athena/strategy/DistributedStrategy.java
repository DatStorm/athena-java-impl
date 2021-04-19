package cs.au.athena.athena.strategy;

import cs.au.athena.Polynomial;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.sigma.Sigma1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

public class DistributedStrategy implements Strategy {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("STRATEGY-DISTRIBUTED: ");


    AthenaFactory athenaFactory;
    BulletinBoardV2_0 bb;
    public DistributedStrategy(AthenaFactory athenaFactory, int tallierCount) {
        this.athenaFactory = athenaFactory;
        this.bb = this.athenaFactory.getBulletinBoard(tallierCount);
    }


    @Override
    public Group getGroup() {
        return bb.getGroup();
    }

    @Override
    public ElGamalSK setup(int tallierIndex, int nc, int kappa) {
        logger.info(MARKER, "getElGamalSK(...) => start");
        assert tallierIndex != 0 : "DistributedStrategy.Setup(...).tallierIndex can not be 0 and was " + tallierIndex;

        Random random = athenaFactory.getRandom();

        Group group = this.getGroup();

        logger.info(MARKER, "retrieving Tallier count");
        int tallierCount = bb.retrieveTallierCount();

        logger.info(MARKER, "retrieving secret share threshold k");
        int k = bb.retrieveK();

        // Generate random polynomial P_i(X)
        logger.info(MARKER, "computing polynomial");
        Polynomial polynomial = Polynomial.newRandom(k, group, random);

        // Post commitment to P_i(X)
        logger.info(MARKER, "publishing polynomial commitment");
        List<BigInteger> commitments = polynomial.getCommitmentOfPolynomialCoefficients();

        // For each commitment, coefficient pair, do proof
        List<Sigma1Proof> commitmentProofs = new ArrayList<>();
        for(int ell = 0; ell <= k; ell++) {
            BigInteger coefficient = polynomial.getCoefficients().get(ell);
            BigInteger commitment = commitments.get(ell);
            logger.info(MARKER, "commitment is " + commitment);
            logger.info(MARKER, "coefficient is " + coefficient);
            Sigma1Proof proof = this.proveKey(commitment, coefficient, kappa);
            commitmentProofs.add(proof);
        }

        logger.info(MARKER, "publishing polynomial commitment and proofs");
        bb.publishPolynomialCommitmentsAndProofs(tallierIndex, commitments, commitmentProofs);

        // Calculate proofs, and publish together
        logger.info(MARKER, "generate sk's");

        // Generate talliers own private (sk, pk)
        ElGamalSK sk_i = Elgamal.generateSK(group, random);
        ElGamalPK pk_i = sk_i.pk;
        Sigma1Proof rho_i = this.proveKey(pk_i, sk_i, kappa);

        bb.publishIndividualPKvector(tallierIndex, new PK_Vector(pk_i, rho_i));
        logger.info(MARKER, "publish pk_i to bb.");


        // Send subshares P_i(j) to T_j
        logger.info(MARKER, "publishSubShares start");
        this.publishSubShares(tallierIndex, group, random, tallierCount, polynomial, kappa);
        logger.info(MARKER, "publishSubShares end");

        // Receive subshare, and compute our share
        List<BigInteger> listOfSubShares = this.receiveSubShare(tallierIndex, group, tallierCount, k, sk_i, kappa);
        BigInteger share_i = listOfSubShares.stream().reduce(BigInteger.ZERO, (a,b) -> a.add(b).mod(group.q));

        logger.info(MARKER, "returning sk.");
        return new ElGamalSK(group, share_i);
    }


    // Compute and publish the subshares P_i(j) for 1 \leq j \leq n
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
                throw new RuntimeException("Tallier T_i retrieved an invalid public pk_j from tallier T_j.");
            }

            BigInteger subShare = polynomial.eval(j);
//            logger.info(MARKER, String.format("tallier computed subshare P_%d(%d): %d", tallierIndex, j, subShare));

            // Encrypt subShare using pk_j
            Ciphertext encSubShare = Elgamal.encrypt(GroupTheory.fromZqToG(subShare, group), pk_j, random);
//            logger.info(MARKER, String.format("tallier encrypted subshare P_%d(%d): enc(%d) -> %d , pk=%d", tallierIndex, j, subShare, encSubShare.c1, pk_j.h));

            // Send subshare, by encrypting and positing
            logger.info(MARKER, String.format("tallier %d publishing P_%d(%d) = encSubshare=%s", tallierIndex, tallierIndex ,j, encSubShare.toOneLineString()));
            bb.publishEncSubShare(tallierIndex, j, encSubShare); // key = (i,j)
        }
    }

    // Receive, decrypt and verify the encrypted subshares
    private List<BigInteger> receiveSubShare(int tallierIndex, Group group, int tallierCount, int k, ElGamalSK sk_i, int kappa) {
        List<BigInteger> subShares = new ArrayList<>(tallierCount);

        // For each other tallier
        for (int j = 1; j <= tallierCount; j++) {
            if (j == tallierIndex) {
                continue;
            }

            // Receive subshare
            Ciphertext encSubShare = bb.retrieveEncSubShare(j, tallierIndex).join();
            logger.info(MARKER, String.format("tallier %d received P_%d(%d) encSubshare=%s", tallierIndex, j, tallierIndex, encSubShare.toOneLineString()));

            // C_{j,0..k} = g^{a_(j0)}, ... g^{a_(jk)}

            // TODO: Check the Commitment proofs. left, right
            List<BigInteger> commitments_j = bb.retrieveCommitmentsAndProofs(j).join().getLeft();
            List<Sigma1Proof> commitmentProofs_j = bb.retrieveCommitmentsAndProofs(j).join().getRight();

            // VerifyKey on polynomial commitments
            for(int i = 0; i < k+1; i++) {
                BigInteger commitment = commitments_j.get(i);
                Sigma1Proof proof = commitmentProofs_j.get(i);
                boolean isValid = this.verifyKey(commitment, proof, kappa);
                if (!isValid) {
                    System.out.println("DistributedStrategy.receiveSubShare: Coefficients commitment is not valid for P_"+ i);
                }
            }

            // Check length of polynomial commitment
            if (commitments_j.size() != k +1) {
                throw new RuntimeException("Tallier " + j + " did not publish polynomialCommitment of length k: "+ k);
            }

            // Decrypt encrypted subshare
            BigInteger subShareFromTallier_j = GroupTheory.fromGToZq(Elgamal.decrypt(encSubShare, sk_i), group);
//            logger.info(MARKER, String.format("tallier decrypted subshare P_%d(%d): dec(%d) -> %d, pk=%d", j, tallierIndex, encSubShare.c1, subShareFromTallier_j, sk_i.pk.h));

            // Verify subshare
            // - First calculate the subshare commitment from the commitments on BB
            BigInteger commitmentToSubShare_a = Polynomial.getPointCommitment(tallierIndex, commitments_j, group); // P_j(i)

            // - Next calculate the subshare commitment as g^subshare.
            BigInteger commitmentToSubShare_b = group.g.modPow(subShareFromTallier_j, group.p);

            // - Verify the received subshare
            if (!commitmentToSubShare_a.equals(commitmentToSubShare_b)) {
//                logger.info(MARKER, "commitmentToSubShare_a: " + commitmentToSubShare_a);
//                logger.info(MARKER, "commitmentToSubShare_b: " + commitmentToSubShare_b);
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
        throw new UnsupportedOperationException();
    }

    @Override
    public BigInteger decrypt(Ciphertext c, ElGamalSK sk) {
        throw new UnsupportedOperationException();
    }
}
