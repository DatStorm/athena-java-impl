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
//        BulletinBoard bb = this.athenaFactory.getBulletinBoard();
        this.bb = BulletinBoardV2_0.getInstance();
    }


    @Override
    public Group getGroup(int bitlength, Random random) {
        return bb.getGroup();
    }

    @Override
    public ElGamalSK getElGamalSK(int tallierIndex, Group group, Random random) {
        logger.info(MARKER, "getElGamalSK(...) => start");
        assert tallierIndex != 0;

        logger.info(MARKER, "retrieving Tallier count");
        int tallierCount = bb.retrieveTallierCount();

        logger.info(MARKER, "retrieving secret share threshold k");
        int k = bb.retrieveK();

        BigInteger p = group.p;

        // Generate random polynomial P_i(X)
        logger.info(MARKER, "computing polinomial");
        Polynomial polynomial = Polynomial.newRandom(k, group, random);

        // Post commitment to P(X)
        logger.info(MARKER, "publishing polinomial commitment");
        bb.publishPolynomialCommitment(tallierIndex, polynomial.getCommitmentOfPolynomialCoefficients());

        // Generate talliers own private (sk, pk)
        ElGamalSK sk_i = Elgamal.generateSK(group, random);
        ElGamalPK pk_i = sk_i.pk;
        bb.publishIndividualPK(tallierIndex, pk_i);


        // Send P_i(j) to T_j

        // publish subshares P_i(j) to T_j
        this.publishSubShares(tallierIndex, group, random, tallierCount, p, polynomial);


        // Receive subshare, by decrypting published shares. Then compute share P(i) of secret key sk
        List<BigInteger> listOfSubShares = this.receiveSubShare(tallierIndex, group, tallierCount, k, p, sk_i);
        BigInteger share_i = listOfSubShares.stream().reduce(0, (a,b) ?>);;

        return new ElGamalSK(group, share_i);
    }

    private void publishSubShares(int tallierIndex, Group group, Random random, int tallierCount, BigInteger p, Polynomial polynomial) {
        for (int j = 1; j <= tallierCount; j++) {
            if (j == tallierIndex) {
                continue;
            }

            // Tallier T_i retrieves pk_j so he can send T_j their subshare
            ElGamalPK pk_j = bb.retrieveIndividualPK(j);

            BigInteger subShare = polynomial.eval(j);
//            logger.info(MARKER, String.format("tallier computed subshare P_%d(%d): %d", tallierIndex, j, subShare));

            assert group.g.modPow(subShare, p).equals(polynomial.getPointCommitment(j)) : "MARKS FAILES";


            // Encrypt subShare using pk_j
            BigInteger subshareElement = GroupTheory.fromZqToG(subShare, group);
            Ciphertext encSubShare = Elgamal.encrypt(subshareElement, pk_j, random);
//            logger.info(MARKER, String.format("tallier encrypted subshare P_%d(%d): enc(%d) -> %d , pk=%d", tallierIndex, j, subShare, encSubShare.c1, pk_j.h));

            // Send subshare, by encrypting and positing
            logger.info(MARKER, String.format("tallier %d publishing %d'th encSubshare=%s", tallierIndex, j, encSubShare.toOneLineString()));
            bb.publishEncSubShare(j, encSubShare);
        }
    }

    private List<BigInteger> receiveSubShare(int tallierIndex, Group group, int tallierCount, int k, BigInteger p, ElGamalSK sk_i) {
        List<BigInteger> subShares = new ArrayList<>();
        for (int j = 1; j <= tallierCount; j++) {
            if (j == tallierIndex) {
                continue;
            }

            Ciphertext encSubShare = bb.retrieveEncSubShare(j);
            logger.info(MARKER, String.format("tallier %d published his %d'th encSubshare=%s", j, tallierIndex, encSubShare.toOneLineString()));


            // C_{j,0..k} = g^{a_(j0)}, ... g^{a_(jk)}
            List<BigInteger> polynomialCommitments_j = bb.retrievePolynomialCommitment(j);

            // Check length of polinomial commitment
            if (polynomialCommitments_j.size() != k +1) {
                throw new RuntimeException("Tallier " + j + " did not publish polynomialCommitment of length k: "+ k);
            }

            // Decrypt encrypted subshare
            BigInteger subShareFromTallier_j_GroupElement = Elgamal.decrypt(encSubShare, sk_i);
            BigInteger subShareFromTallier_j = GroupTheory.fromGToZq(subShareFromTallier_j_GroupElement, group);
//            logger.info(MARKER, String.format("tallier decrypted subshare P_%d(%d): dec(%d) -> %d, pk=%d", j, tallierIndex, encSubShare.c1, subShareFromTallier_j, sk_i.pk.h));



            // Verify subshare,
            // First calculate the subshare commitment from the commitments on BB
            BigInteger commitmentToSubShare_a = Polynomial.getPointCommitment(tallierIndex, polynomialCommitments_j, group); // P_j(i)

            // Next calculate the subshare commitment as g^subshare.
            BigInteger commitmentToSubShare_b = group.g.modPow(subShareFromTallier_j, group.p);

            // Verify the received subshare
            if (!commitmentToSubShare_a.equals(commitmentToSubShare_b)) {
//                logger.info(MARKER, "commitmentToSubShare_a: " + commitmentToSubShare_a);
//                logger.info(MARKER, "commitmentToSubShare_b: " + commitmentToSubShare_b);
                //TODO: Post (subShareFromTallier_j_GroupElement, ProveDec(subShareFromTallier_j_GroupElement, sk_i), to convince others that T_j is corrupt
                throw new RuntimeException("The received subshare from tallier " + j + " is not consistent with the published polynomial commitments");
            }

            // Compute my final share P(i) of secret key sk, as the sum of subshares P_j(i)
            subShares.add(subShareFromTallier_j);
        }

        return subShares;
    }

    // Probably redundant. -Mark
    @Override
    public ElGamalPK getElGamalPK(ElGamalSK sk) {
        // return g^P(i) // TODO: we need to be able to retrieve the "regular" pk else we cannot vote!
        return sk.pk; // TODO: retrieve pk from the bulletin board instead?
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
