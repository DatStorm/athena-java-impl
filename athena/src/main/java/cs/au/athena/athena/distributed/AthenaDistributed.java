package cs.au.athena.athena.distributed;

import cs.au.athena.Polynomial;
import cs.au.athena.athena.AthenaCommon;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.CommitmentAndProof;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma3.Sigma3Statement;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class AthenaDistributed {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("STRATEGY-DISTRIBUTED: ");


    AthenaFactory athenaFactory;
    BulletinBoardV2_0 bb;
    public AthenaDistributed(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.bb = this.athenaFactory.getBulletinBoard();
    }


    public Group getGroup() {
        return bb.getGroup();
    }

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
        List<CommitmentAndProof> commitmentAndProofs = new ArrayList<>();
        for(int ell = 0; ell <= k; ell++) {
            BigInteger commitment = commitments.get(ell);

            Sigma1Proof proof = this.proveKey(commitment, coefficients.get(ell), kappa);

            commitmentAndProofs.add(new CommitmentAndProof(commitment, proof));
        }

        // Publish commitments and proofs
        logger.info(MARKER, "publishing polynomial commitment and proofs");
        bb.publishPolynomialCommitmentsAndProofs(tallierIndex, commitmentAndProofs);

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
            List<CommitmentAndProof> commitmentAndProofs = bb.retrieveCommitmentsAndProofs(j).join();

            logger.info(MARKER, String.format("tallier %d received P_%d(%d)", tallierIndex, j, tallierIndex));

            // Check length of polynomial commitment
            if (commitmentAndProofs.size() != k +1) {
                // FUTUREWORK: If the commitment is invalid or incorrect length, T_j is malicious and should be removed.
                throw new RuntimeException(String.format("Tallier %d published commitments of %d degree polynomial. Should be k=%d ", j, commitmentAndProofs.size(), k));
            }

            // VerifyKey on polynomial commitments
            for(int i = 0; i <= k; i++) {
                CommitmentAndProof commitmentAndProof = commitmentAndProofs.get(i);

                BigInteger commitment = commitmentAndProof.commitment;
                Sigma1Proof proof = commitmentAndProof.proof;
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
            List<BigInteger> commitments_j = commitmentAndProofs.stream().map(o -> o.commitment).collect(Collectors.toList());
            BigInteger commitmentToSubShare_a = Polynomial.getPointCommitment(tallierIndex, commitments_j, group); // P_j(i)

            // - Next calculate the subshare commitment as g^subshare.
            BigInteger commitmentToSubShare_b = group.g.modPow(subShareFromTallier_j, group.p);

            // - Verify the received subshare
            if (!commitmentToSubShare_a.equals(commitmentToSubShare_b)) {
                //FUTUREWORK
                // : Post (subShareFromTallier_j_GroupElement, ProveDec(subShareFromTallier_j_GroupElement, sk_i), to convince others that T_j is corrupt
                throw new RuntimeException("A subshare was inconsistent with the commitments");
            }

            // Compute my final share P(i) of secret key sk, as the sum of subshares P_j(i)
            subShares.add(subShareFromTallier_j);
        }

        return subShares;
    }


    public Sigma1Proof proveKey(ElGamalPK pk, ElGamalSK sk, int kappa) {
        return this.proveKey(pk.h, sk.sk, kappa);
    }

    public Sigma1Proof proveKey(BigInteger pk, BigInteger sk, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        Random random = athenaFactory.getRandom();
        Group group = this.getGroup();
        assert group.g.modPow(sk, group.p).equals(pk) : "ProveKey: pk and sk does not match";
        return sigma1.ProveKey(pk, sk, group, random, kappa);
    }

    public boolean verifyKey(ElGamalPK pk, Sigma1Proof rho, int kappa) {
        return verifyKey(pk.h, rho, kappa);
    }

    public boolean verifyKey(BigInteger h, Sigma1Proof rho, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        Group group = this.getGroup();
        return sigma1.VerifyKey(h, rho, group, kappa);
    }


    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        throw new UnsupportedOperationException();
    }

    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException();
    }

    public MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException();
    }

    public boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        // TODO: For each proof
        throw new UnsupportedOperationException();
    }

    public Ciphertext homoCombination(List<Ciphertext> listOfCiphers, BigInteger nonce_j, Group group) {

        for (int i = 0; i < listOfCiphers.size(); i++) {
            Ciphertext c = listOfCiphers.get(i);
            Ciphertext combinedCiphertextShare = AthenaCommon.homoCombination(c, nonce_j, group.p);


        }

        // ProveComb
//        HomoCombinationAndProof combinedCiphertextShare and sigma4Proof;

        // Publish

        // Retrieve k+1 shares

        // Compute combinedCiphertext

        Sigma4Proof omega = this.distributed.proveCombination(listCombined, listCiphertexts, nonce_n, sk, kappa);

        return combinedCiphertextShare;
    }

    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        Sigma3 sigma3 = athenaFactory.getSigma3();

        /**
         * TODO: STOR OG FED !!!! AKA FIX IT
         * Needs to handle all cases of all proofs.
         */

        boolean isAllValid = true;

        isAllValid = sigma3.verifyDecryption(c,M,pk,phi,kappa);

       return isAllValid;
    }

    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        Group group = this.getGroup();
        BigInteger alpha = M;
        BigInteger alpha_base = group.g;
        BigInteger beta = c.c1.modPow(sk.toBigInteger().negate(),group.p).modInverse(group.p);
        BigInteger beta_base = c.c1;
        Sigma3Statement stmnt = new Sigma3Statement(group,alpha,beta,alpha_base,beta_base);

        return athenaFactory.getSigma3().proveDecryption(stmnt, sk.sk,kappa);
    }

    /**
     * @param skShare is the shamir secret sharing share: P(i)
     * @param kappa
     * @return decrypted message
     */
    public BigInteger decrypt(int tallierIndex, int ballotIndex,  Ciphertext ciphertext, ElGamalSK skShare, int kappa) {
        Group group = this.getGroup();
        int k = bb.retrieveK();

        // Compute decryption share and proof
        BigInteger decryptionShare = ciphertext.c1.modPow(skShare.toBigInteger().negate(),group.p);
        ElGamalPK pk_j = bb.retrievePKShare(tallierIndex);

        // log_g h_j = log_c1 d_j^-1
        Sigma3Proof decryptionShareProof = this.proveDecryption(ciphertext, pk_j.getH(), skShare, kappa);

        // Publish decryption share and proof
        bb.publishDecryptionShareAndProofToPFR_PFD(tallierIndex, ballotIndex, ciphertext, new DecryptionShareAndProof(tallierIndex, decryptionShare, decryptionShareProof)); // pushes to pfr on BB


/*
        pfd list:
        {
            CombinedCiphertextAndProof[],
            DecryptionShareAndProof[]
            DecryptionShareAndProof[]
        }
         */

        // Retrieve k+1 valid decryption shares for ciphertext c
        List<DecryptionShareAndProof> shares = bb.retrieveValidDecryptionSharesAndProofWithThreshold(ciphertext, k).join();
        assert shares.size() == k+1 : String.format("Shares does not have length k+1 it had %d", shares.size());

        // Verify that the decryption shares are valid, and decrypt
        List<Integer> S = shares.stream().map(DecryptionShareAndProof::getIndex).collect(Collectors.toList());
        BigInteger prodSumOfDecryptionShares = BigInteger.ONE;
        for (DecryptionShareAndProof share : shares) {
            ElGamalPK pkShare = bb.retrievePKShare(share.getIndex());

            // Also verified of BB
            boolean isValidDec = this.verifyDecryption(ciphertext, share.share, pkShare, share.proof, kappa);
            if (!isValidDec) {
                logger.info(MARKER, String.format("tallier %d dec not valid!", tallierIndex));

            }
            BigInteger lambda = Polynomial.getLambda(0, share.getIndex(), S);
            prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(share.share.modPow(lambda, group.p)).mod(group.p);
        }


        // Decrypt the ciphertext with the new sk.
        return ciphertext.c2.multiply(prodSumOfDecryptionShares).mod(group.p);
    }
}
