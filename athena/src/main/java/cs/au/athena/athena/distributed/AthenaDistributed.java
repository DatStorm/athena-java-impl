package cs.au.athena.athena.distributed;

import cs.au.athena.GENERATOR;
import cs.au.athena.Polynomial;
import cs.au.athena.athena.AthenaCommon;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma3.Sigma3Statement;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma4;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AthenaDistributed {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-DISTRIBUTED: ");

    AthenaFactory athenaFactory;
    BulletinBoardV2_0 bb;
    VerifyingBulletinBoardV2_0 vbb;

    public AthenaDistributed(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.bb = this.athenaFactory.getBulletinBoard();
        this.vbb = this.athenaFactory.getVerifyingBulletinBoard();
    }

    public ElGamalSK setup(int tallierIndex, int nc, int kappa) {
        logger.info(MARKER, "getElGamalSK(...) => start");
        assert tallierIndex != 0 : "DistributedStrategy.Setup(...).tallierIndex can not be 0 and was " + tallierIndex;
        assert tallierIndex <= bb.retrieveTallierCount();

        Random random = athenaFactory.getRandom();
        Group group = bb.retrieveGroup();

        int tallierCount = bb.retrieveTallierCount();
        int k = bb.retrieveK();

        // Generate random polynomial P_i(X)
        logger.info(MARKER, "computing polynomial");
        Polynomial polynomial = Polynomial.newRandom(k, group, random);

        // For each commitment, coefficient pair, do proof
        List<BigInteger> coefficients = polynomial.getCoefficients();
        List<BigInteger> commitments = polynomial.getCommitments();

        // Generate proofs for the commitments
        logger.info(MARKER, "proving polynomial");
        List<CommitmentAndProof> commitmentAndProofs = new ArrayList<>();
        for(int ell = 0; ell <= k; ell++) {
            BigInteger commitment = commitments.get(ell);
            Sigma1Proof proof = this.proveKey(commitment, coefficients.get(ell), kappa);
            assert group.g.modPow(coefficients.get(ell), group.p).equals(commitment) : "Input to ProveKey in setup is incorrect";

            commitmentAndProofs.add(new CommitmentAndProof(commitment, proof));
//            assert g^v = 0;
        }

        // Publish polynomial commitments and proofs
        logger.info(MARKER, String.format("T%d publishing polynomial commitment and proofs", tallierIndex));
        bb.publishPolynomialCommitmentsAndProofs(tallierIndex, commitmentAndProofs);



        // Generate talliers own private (sk, pk)
        ElGamalSK sk_i = Elgamal.generateSK(group, random);
        ElGamalPK pk_i = sk_i.pk;
        Sigma1Proof rho_i = this.proveKey(pk_i, sk_i, kappa);

        // Publish my individual public key, so others can send me a subShare
        logger.info(MARKER, "publishing individual pk.");
        bb.publishIndividualPKvector(tallierIndex, new PK_Vector(pk_i, rho_i));

        // Send subshares P_i(j) to T_j
        logger.info(MARKER, "publishing subshares");
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
            boolean isPK_jValid = this.verifyKey(pk_j.h, pk_j_vector.rho, kappa);

            if (!isPK_jValid) {
                throw new RuntimeException("Tallier T_i retrieved an invalid public key pk_j from tallier T_j.");
            }

            BigInteger subShare = polynomial.eval(j);

            // Encrypt subShare using pk_j
            Ciphertext encSubShare = Elgamal.encrypt(GroupTheory.fromZqToG(subShare, group), pk_j, random);

            // Send subshare, by encrypting and positing
            //logger.info(MARKER, String.format("tallier %d publishing P_%d(%d)", tallierIndex, tallierIndex ,j));
            bb.publishEncSubShare(tallierIndex, j, encSubShare); // key = (i,j)
        }
    }

    public boolean verifyKey(BigInteger h, Sigma1Proof rho, int kappa) {
        Sigma1 sigma1 = new Sigma1();
        Group group = bb.retrieveGroup();

        return sigma1.VerifyKey(h, rho, group, kappa);
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
            List<CommitmentAndProof> commitmentAndProofs = bb.retrievePolynomialCommitmentsAndProofs(j).join();

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
        Group group = bb.retrieveGroup();

        assert group.g.modPow(sk, group.p).equals(pk) : "ProveKey: pk and sk does not match";


        Sigma1Proof proof = sigma1.ProveKey(pk, sk, group, random, kappa);

        return proof;
    }

    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        Sigma4 sigma4 = athenaFactory.getSigma4();
        return sigma4.proveCombination(sk,listOfCombinedCiphertexts, listCiphertexts, nonce_n, kappa);
    }

    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException();
    }


    /*
     * B0 = ballots
     * T1: mix(B0, ...) => B1, verify(B0, B1)  <---
     * T2: mix(B1, ...) => B2, verify(B1, B2)
     * T3: mix(B2, ...) => B3, verify(B2, B1)
     * return B3
     */
    public List<MixBallot> performMixnet(int tallierIndex, List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        Mixnet mixnet = this.athenaFactory.getMixnet();

        // For each tallier
        List<MixBallot> previousMixedBallots = ballots;
        for (int nextTallierToMix = 1; nextTallierToMix <= bb.retrieveTallierCount(); nextTallierToMix++) {

            // Is it our turn to mix. If so, mix and publish
            if(nextTallierToMix == tallierIndex) {
                MixedBallotsAndProof mixedBallotsAndProof = mixnet.mixAndProveMix(previousMixedBallots, pk, kappa);
                bb.publishMixedBallotsAndProof(tallierIndex, mixedBallotsAndProof);
            }

            // Retrieve mixed ballots from bb
            MixedBallotsAndProof mixedBallotsAndProof = bb.retrieveMixedBallotAndProofs().get(nextTallierToMix).join();

            // If not our turn, verify
            if(nextTallierToMix != tallierIndex) {
                // Verify
                MixStatement statement = new MixStatement(previousMixedBallots, mixedBallotsAndProof.mixedBallots);
                boolean isValidMix = mixnet.verify(statement, mixedBallotsAndProof.mixProof, pk, kappa);

                if(!isValidMix){
                    throw new RuntimeException(String.format("Malicious tallier T%d detected during mixing of the ballots", nextTallierToMix));
                }
            }

            // Remember result for next round
            previousMixedBallots = mixedBallotsAndProof.mixedBallots;
        }

        return previousMixedBallots;
    }

    public boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        throw new UnsupportedOperationException("TODO! ".repeat(30));
    }


    // Returns a list of nonced ciphertexts
    public List<Ciphertext> performPfrPhaseOneHomoComb(int tallierIndex, List<Ballot> ballots, BigInteger nonce, ElGamalSK sk, int kappa) {
        int ell = ballots.size();
        logger.info(MARKER,String.format("T%d: AthenaDistributed.performPfrPhaseOneHomoComb[started]", tallierIndex));

        List<Ciphertext> encryptedNegatedPrivateCredentials = ballots
                .stream()
                .map(Ballot::getEncryptedNegatedPrivateCredential)
                .collect(Collectors.toList());

        List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof = SigmaCommonDistributed.proveHomoCombPfrPhaseOne(encryptedNegatedPrivateCredentials, nonce, sk, kappa);

        // Publish
        logger.info(MARKER, "publishing entry and awaiting threshold entries");
        bb.publishPfrPhaseOneEntry(tallierIndex, listOfCombinedCiphertextAndProof);

        // Retrieve threshold shares
        PfPhase<CombinedCiphertextAndProof> completedPfrPhaseOne = vbb.retrieveValidThresholdPfrPhaseOne();
        logger.info(MARKER, "Retrieved threshold entries");

        // Combine shares

        // We want to create a list of cipertexts, where element i is the product of the k+1 ciphertexts
        // This is done by making a list of ciphertexts, and multiplying a talliers ciphertexts onto the corresponding entry

        // Make and initial list of neutral ciphertexts
        List<Ciphertext> result = Stream.generate(Ciphertext::ONE)
                .limit(ell)
                .collect(Collectors.toList());

        logger.info(MARKER, String.format("T%d: Calculating: RES: %s", tallierIndex, result.stream().map(Ciphertext::toOneLineString)));
        logger.info(MARKER, String.format("T%d: completedPfrPhaseOne.size() =%d", tallierIndex,completedPfrPhaseOne.size()));

        // For each tallier in the set
        for (int i = 0; i < completedPfrPhaseOne.size(); i++) {
            List<CombinedCiphertextAndProof> ciphertextAndProofs = completedPfrPhaseOne.get(i).getValues();
            logger.info(MARKER, String.format("T%d: CAlC_%d ", tallierIndex, i));

            // For each ciphertext
            for (int j = 0; j < ell; j++) {
                CombinedCiphertextAndProof combinedCiphertextAndProof = ciphertextAndProofs.get(i);
                logger.info(MARKER, String.format("T%d: CAlC_%d-Proof_%d", tallierIndex, i, j));

                // Multiply onto the result list
                Ciphertext oldValue = result.get(j);
                Ciphertext newValue = oldValue.multiply(combinedCiphertextAndProof.combinedCiphertext, sk.pk.group.p);
                result.set(j, newValue);
            }
        }

        logger.info(MARKER,String.format("T%d: AthenaDistributed.performPfrPhaseOneHomoComb[ended]", tallierIndex));

        return result;
    }


    // TODO: This might need revision before letting the "Verifiers" use it!
    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        throw new UnsupportedOperationException("FIX IT--".repeat(30));
        //Sigma3 sigma3 = athenaFactory.getSigma3();
        //return sigma3.verifyDecryption(c,M,pk,phi,kappa);
    }

    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        Group group = bb.retrieveGroup();
        BigInteger alpha = M;
        BigInteger alpha_base = group.g;
        BigInteger beta = c.c1.modPow(sk.toBigInteger().negate(),group.p).modInverse(group.p); // TODO: double check this please!
        BigInteger beta_base = c.c1;
        Sigma3Statement stmnt = new Sigma3Statement(group,alpha,beta,alpha_base,beta_base);

        return athenaFactory.getSigma3().proveDecryption(stmnt, sk.sk,kappa);
    }

    /**
     * @param skShare is the shamir secret sharing share: P(i)
     * @param kappa
     * @return decrypted message
     */
    public List<BigInteger> performPfrPhaseTwoDecryption(int tallierIndex, List<Ciphertext> ciphertexts, ElGamalSK skShare, int kappa) {
        int k = bb.retrieveK();

        List<DecryptionShareAndProof> decryptionSharesAndProofs = generateDecryptionShareAndProofs(tallierIndex, ciphertexts, skShare, kappa);

        // Publish
        bb.publishPfrPhaseTwoEntry(tallierIndex, decryptionSharesAndProofs);

        // Retrieve list of talliers with decryption shares and proofs for all ballots.
        PfPhase<DecryptionShareAndProof> completedPfrPhaseTwo = vbb.retrieveValidThresholdPfrPhaseTwo(ciphertexts);
        assert completedPfrPhaseTwo.size() == k + 1 : String.format("Shares does not have length k+1 it had %d", completedPfrPhaseTwo.size());

        // All are authorized for decryption
        List<Boolean> authorizedToDecrypt = Collections.nCopies(ciphertexts.size(), true);

        // Decrypt
        List<BigInteger> noncedNegatedPrivateCredentials = combineDecryptionSharesAndDecrypt(ciphertexts, completedPfrPhaseTwo, authorizedToDecrypt);
        return noncedNegatedPrivateCredentials;
    }



    public List<Ciphertext> performPfdPhaseOneHomoComb(int tallierIndex, List<Ciphertext> combinedCredentials, Random random, ElGamalSK sk, int kappa) {
        int ell = combinedCredentials.size();
        List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof = new ArrayList<>(ell);

        // TODO: move to SigmaCommomDistributed?
        // Nonce each ciphertext, and compute proof
        for (Ciphertext combinedCredential : combinedCredentials) {
            BigInteger nonce = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, random);

            // Homomorpically re-encrypt(by raising to power n) ballot and decrypt
            Ciphertext noncedCredential = AthenaCommon.homoCombination(combinedCredential, nonce, sk.pk.group);

            //Prove the combination of a valid combination nonce n
            Sigma4Proof omega = this.proveCombination(Collections.singletonList(noncedCredential), Collections.singletonList(combinedCredential), nonce, sk, kappa);
            listOfCombinedCiphertextAndProof.add(new CombinedCiphertextAndProof(noncedCredential, omega));
        }

        // Publish
        bb.publishPfdPhaseOneEntry(tallierIndex, listOfCombinedCiphertextAndProof);

        // Retrieve threshold shares
        PfPhase<CombinedCiphertextAndProof> completedPfdPhaseOne = vbb.retrieveValidThresholdPfdPhaseOne();

        // We want to create a list of ciphertexts, where element i is the product of the k+1 ciphertexts
        // This is done by making a list of ciphertexts, and multiplying a talliers ciphertexts onto the corresponding entry
        // Make and initial list of neutral ciphertexts
        List<Ciphertext> result = Stream.generate(Ciphertext::ONE)
                .limit(ell)
                .collect(Collectors.toList());

        // For each tallier in the set
        for (int i = 0; i < completedPfdPhaseOne.size(); i++) {
            List<CombinedCiphertextAndProof> ciphertextAndProofs = completedPfdPhaseOne.get(i).getValues();

            // For each ciphertext
            for (int j = 0; j < ell; j++) {
                CombinedCiphertextAndProof combinedCiphertextAndProof = ciphertextAndProofs.get(i);

                // Multiply onto the result list
                Ciphertext oldValue = result.get(j);
                Ciphertext newValue = oldValue.multiply(combinedCiphertextAndProof.combinedCiphertext, sk.pk.group.p);
                result.set(j, newValue);
            }
        }

        return result;
    }

    public List<BigInteger> performPfdPhaseTwoDecryption(int tallierIndex, List<Ciphertext> combinedCredentialCiphertexts, ElGamalSK skShare, int kappa) {
        int k = bb.retrieveK();
        List<DecryptionShareAndProof> decryptionSharesAndProofs = generateDecryptionShareAndProofs(tallierIndex, combinedCredentialCiphertexts, skShare, kappa);

        // Publish
        bb.publishPfdPhaseTwoEntry(tallierIndex, decryptionSharesAndProofs);

        // Retrieve list of talliers with decryption shares and proofs for all ballots.
        PfPhase<DecryptionShareAndProof> completedPfdPhaseTwo = vbb.retrieveValidThresholdPfdPhaseTwo(combinedCredentialCiphertexts);
        assert completedPfdPhaseTwo.size() == k + 1 : String.format("Shares does not have length k+1 it had %d", completedPfdPhaseTwo.size());

        // All are authorized for decryption
        List<Boolean> authorizedToDecrypt = Collections.nCopies(combinedCredentialCiphertexts.size(), true);

        // Decrypt
        List<BigInteger> noncedCombinedCredentials = combineDecryptionSharesAndDecrypt(combinedCredentialCiphertexts, completedPfdPhaseTwo, authorizedToDecrypt);
        return noncedCombinedCredentials;
    }

    public List<BigInteger> performPfdPhaseThreeDecryption(int tallierIndex, List<BigInteger> m_list, List<Ciphertext> encryptedVotes, ElGamalSK skShare, int kappa) {
        int k = bb.retrieveK();
        List<DecryptionShareAndProof> decryptionSharesAndProofs = generateDecryptionShareAndProofs(tallierIndex, encryptedVotes, skShare, kappa);

        // Publish
        bb.publishPfdPhaseThreeEntry(tallierIndex, decryptionSharesAndProofs);

        // Retrieve list of talliers with decryption shares and proofs for all ballots.
        PfPhase<DecryptionShareAndProof> completedPfdPhaseThree = vbb.retrieveValidThresholdPfdPhaseThree(encryptedVotes);
        assert completedPfdPhaseThree.size() == k + 1 : String.format("Shares does not have length k+1 it had %d", completedPfdPhaseThree.size());

        // A ballot is authorized if m == 1.
        List<Boolean> authorizedToDecrypt = m_list.stream().map(m -> m.equals(BigInteger.ONE)).collect(Collectors.toList());

        // Decrypt
        List<BigInteger> noncedCombinedCredentials = combineDecryptionSharesAndDecrypt(encryptedVotes, completedPfdPhaseThree, authorizedToDecrypt);
        return noncedCombinedCredentials;
    }

    private List<DecryptionShareAndProof> generateDecryptionShareAndProofs(int tallierIndex, List<Ciphertext> combinedCredentialCiphertexts, ElGamalSK skShare, int kappa) {
        Group group = bb.retrieveGroup();

        List<DecryptionShareAndProof> decryptionSharesAndProofs = new ArrayList<>(combinedCredentialCiphertexts.size());

        // generate decryption shares and proofs for all ballots
        for (Ciphertext ciphertext : combinedCredentialCiphertexts) {

            // Compute decryption share and proof
            BigInteger decryptionShare = ciphertext.c1.modPow(skShare.toBigInteger().negate(), group.p);
            ElGamalPK pk_j = vbb.retrievePKShare(tallierIndex);

            // Prove decryption share
            Sigma3Proof proof = this.proveDecryption(ciphertext, pk_j.getH(), skShare, kappa);

            // Add to list
            decryptionSharesAndProofs.add(new DecryptionShareAndProof(decryptionShare, proof));
        }
        return decryptionSharesAndProofs;
    }

    private List<BigInteger> combineDecryptionSharesAndDecrypt(List<Ciphertext> ciphertexts, PfPhase<DecryptionShareAndProof> completedPfdPhaseTwo, List<Boolean> authorizedToDecrypt) {
        Group group = bb.retrieveGroup();

        // Find the set of talliers in the pfr
        List<Integer> S = completedPfdPhaseTwo.getAll().stream()
                .map(Entry::getIndex)
                .collect(Collectors.toList());

        // Decrypt by combining decryption shares
        List<BigInteger> decryptedCiphertexts = new ArrayList<>(ciphertexts.size());

        // We need to get k+1 decryption shares for each ballot.
        // Therefore we need to traverse the k+1 lists in pfr simultaneously
        // This is done by making an iterator for each tallier, and using calling each one time per ballot
        List<Pair<Integer, Iterator<DecryptionShareAndProof>>> iteratorPairs = new ArrayList<>();
        for (Entry<DecryptionShareAndProof> entry : completedPfdPhaseTwo.getAll()) {
            Integer s = entry.getIndex();
            List<DecryptionShareAndProof> listOfDecryptionSharesAndProof = entry.getValues();
            iteratorPairs.add(Pair.of(s, listOfDecryptionSharesAndProof.iterator()));
        }

        // Decrypt each ciphertext
        for (int i = 0; i < ciphertexts.size(); i++) {
            Ciphertext ciphertext = ciphertexts.get(i);
            boolean isAuthorized = authorizedToDecrypt.get(i);

            // Only decrypt if authorized, skip unauthorized ballots.
            if(!isAuthorized) {
                continue;
            }

            // Decrypt by combining the shares
            BigInteger prodSumOfDecryptionShares = BigInteger.ONE;

            // For each share
            for (Pair<Integer, Iterator<DecryptionShareAndProof>> pair : iteratorPairs) {
                int s = pair.getLeft();
                Iterator<DecryptionShareAndProof> iter = pair.getRight();

                // combine the k+1 shares
                DecryptionShareAndProof decryptionShareAndProof = iter.next();

                // Make lambda
                BigInteger lambda = Polynomial.getLambda(0, s, S);

                // Perform lagrange interpolation
                BigInteger decShare = decryptionShareAndProof.share;
                prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(decShare.modPow(lambda, group.p)).mod(group.p);
            }

            // Decrypt the ciphertext
            BigInteger plaintext = ciphertext.c2.multiply(prodSumOfDecryptionShares).mod(group.p);
            decryptedCiphertexts.add(plaintext);
        }

        return decryptedCiphertexts;
    }

}
