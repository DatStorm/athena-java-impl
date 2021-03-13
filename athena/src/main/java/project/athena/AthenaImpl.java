package project.athena;

import org.apache.commons.lang3.stream.Streams;
import project.UTIL;
import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.bulletproof.BulletproofProof;
import project.dao.bulletproof.BulletproofSecret;
import project.dao.bulletproof.BulletproofStatement;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;
import project.dao.mixnet.MixStatement;
import project.dao.mixnet.MixStruct;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.*;
import project.factory.AthenaFactory;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AthenaImpl implements Athena {
    private final ElectoralRoll L;

    private final Sigma1 sigma1;
    private final Random random;
    //    private final Sigma2 sigma2;
    private final Bulletproof bulletProof;

    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private final Mixnet mixnet;
    private final BulletinBoard bb;
    private boolean initialised;
    private ElGamal elgamal;
    private int mc;
    private List<BigInteger> g_vector_vote;
    private List<BigInteger> h_vector_vote;
    private List<BigInteger> g_vector_negatedPrivateCredential;
    private List<BigInteger> h_vector_negatedPrivateCredential;
    private int n_vote;
    private int n_negatedPrivateCredential;

    private AthenaFactory athenaFacotry;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFacotry = athenaFactory;
        this.sigma1 = athenaFactory.getSigma1();
        this.bulletProof = athenaFactory.getBulletProof();
        this.sigma3 = athenaFactory.getSigma3();
        this.sigma4 = athenaFactory.getSigma4();
        this.mixnet = athenaFactory.getMixnet();
        this.random = athenaFactory.getRandom();
        this.bb = athenaFactory.getBulletinBoard();

        this.L = new ElectoralRoll();
        this.initialised = false;
    }

    @Override
    public SetupStruct Setup(int kappa) throws IOException {

        Gen gen = new Gen(random, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.getPK();
        Group group = pk.getGroup();
        this.elgamal = gen.getElGamal(); // TODO: HER!!!!

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfo, sk, randR, kappa);

        this.n_vote = group.q.bitLength();                          // TODO: FIX THESE VALUES
        this.n_negatedPrivateCredential = group.q.bitLength();      // TODO: FIX THESE VALUES
        int mb = 100;   // TODO: FIX THESE VALUES
        this.mc = 100;  // TODO: FIX THESE VALUES

        this.g_vector_vote = group.newGenerators(n_vote, random);
        this.h_vector_vote = group.newGenerators(n_vote, random);
        this.g_vector_negatedPrivateCredential = group.newGenerators(n_negatedPrivateCredential, random);
        this.h_vector_negatedPrivateCredential = group.newGenerators(n_negatedPrivateCredential, random);

        this.initialised = true;
        return new SetupStruct(new PK_Vector(pk, rho), sk, mb, mc);
    }

    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Register => ERROR: pkv null");
            return null;
        }

        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Register => ERROR: VerifyKey(...) => false");
            return null;
        }


        BigInteger p = pkv.pk.group.p;
        BigInteger q = pkv.pk.group.q;
        BigInteger g = pkv.pk.group.g;

        //Generate nonce. aka private credential
        BigInteger privateCredential = UTIL.getRandomElement(BigInteger.ONE, q, random);
        CipherText publicCredential = elgamal.encrypt(privateCredential, pkv.pk);

        // bold{d} = (pd, d) = (Enc_pk(g^d), d)
        CredentialTuple credentialTuple = new CredentialTuple(publicCredential, privateCredential);


        bb.addPublicCredentitalToL(publicCredential);
        return new RegisterStruct(publicCredential, credentialTuple);
    }


    @Override
    public Ballot Vote(CredentialTuple credentialTuple, PK_Vector pkv, int vote, int cnt, int nc, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Vote => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Vote => ERROR: pkv null");
            return null;
        }

        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Vote => ERROR: VerifyKey(...) => false");
            return null;
        }


        boolean vote_in_range = vote >= 0 && vote < nc;
        boolean not_in_message_space = BigInteger.valueOf(nc).compareTo(pkv.pk.group.q) >= 0; // Should be in Z_q
        if (!vote_in_range || not_in_message_space) {
            System.err.println("AthenaImpl.Vote => ERROR: v not in {1...nc}");
            return null;
        }

        CipherText publicCredential = credentialTuple.publicCredential;
        ElGamalPK pk = pkv.pk;
        BigInteger p = pk.group.p;
        BigInteger q = pk.group.q;
        BigInteger g = pk.group.g;

        // Make negated private credential
        BigInteger negatedPrivateCredential = credentialTuple.privateCredential.negate();
        negatedPrivateCredential = negatedPrivateCredential.mod(q).add(q).mod(q);

        // Create encryption of negated private credential, i.e. g^{-d}
        BigInteger randomness_s = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins s
        CipherText encryptedNegatedPrivateCredential = elgamal.encrypt(negatedPrivateCredential, pk, randomness_s);

        // Create encryption of vote, i.e. g^{v}
        BigInteger voteAsBigInteger = BigInteger.valueOf(vote);
        BigInteger randomness_t = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins t
        CipherText encryptedVote = elgamal.encrypt(voteAsBigInteger, pk, randomness_t);

        // Prove that negated private credential -d resides in Z_q (this is defined using n)
        BulletproofStatement stmnt_1 = new BulletproofStatement(
                this.n_negatedPrivateCredential,
                encryptedNegatedPrivateCredential.c2,
                pk,
                g_vector_negatedPrivateCredential,
                h_vector_negatedPrivateCredential);
        BulletproofSecret secret_1 = new BulletproofSecret(negatedPrivateCredential, randomness_s);
        BulletproofProof proofRangeOfNegatedPrivateCredential = bulletProof.proveStatement(stmnt_1, secret_1);

        // Prove that vote v resides in [0,nc-1] (this is defined using n)
        BulletproofStatement stmnt_2 = new BulletproofStatement(
                this.n_vote,
                encryptedVote.c2,
                pk,
                g_vector_vote,
                h_vector_vote);
        BulletproofSecret secret_2 = new BulletproofSecret(voteAsBigInteger, randomness_t);
        BulletproofProof proofRangeOfVote = bulletProof.proveStatement(stmnt_2, secret_2);

        Ballot ballot = new Ballot(publicCredential, encryptedNegatedPrivateCredential, encryptedVote, proofRangeOfNegatedPrivateCredential, proofRangeOfVote, cnt);
        bb.publishBallot(ballot);
        return ballot;
    }


    @Override
    public TallyStruct Tally(SK_Vector skv, BulletinBoard bulletinBoard, int nc, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        ElGamalSK sk = skv.sk;
        ElGamalPK pk = sk.pk;
        BigInteger p = pk.getGroup().p;

        /* ********
         * Step 1: Remove invalid ballots
         *********/
        List<Ballot> finalBallots = removeInvalidBallots(bulletinBoard, pk);
        if (finalBallots.isEmpty()){
            System.err.println("AthenaImpl.Tally =>  Step 1 yielded no valid ballots on bulletinboard.");
            return null;
        }


        /* ********
         * Step 2: Mix final votes
         *********/
        // TODO: Code a pretty version of this.....
        Object[] objects = tallyStepTwo(finalBallots, sk, kappa);
        List<PFRStruct> pfr = (List<PFRStruct>) objects[0];
        Map<MapAKey, MapAValue> A = (Map<MapAKey, MapAValue>) objects[1];
        List<MixBallot> B = pairwiseMixnet(A, bulletinBoard);

        // Post pfr and B to the bulletin board
        bb.publishPfr(pfr);
        bb.publishMixBallots(B);




        /* ********
         * Step 3: Reveal eligible votes
         *********/
        // initialise b as a zero filled vector of length nc
        Map<BigInteger, Integer> tallyOfVotes = new HashMap<>(nc);

        List<PFDStruct> pfd = new ArrayList<>();
        List<BigInteger> nonces_n1_nB = generateNonces(B.size()); // n_1, ... , n_{|B|}

        for (MixBallot mixedBallot : B) {
            CipherText homoCombPublicCredentialNegatedPrivatedCredential = mixedBallot.getC1();
            CipherText encryptedVote = mixedBallot.getC2();

            // n[ |pdf| + 1 ] => n_1, ... , n_{|B|}
            BigInteger noncePfd = nonces_n1_nB.get(pfd.size());
            CipherText c_prime = homoCombination(noncePfd, homoCombPublicCredentialNegatedPrivatedCredential, p);
            BigInteger m = elgamal.decrypt(c_prime, sk);

            // Prove that c' is a homomorphic combination of homoCombPublicCredentialNegatedPrivatedCredential
            Sigma4Proof proofCombinationCprime = sigma4.proveCombination(
                    sk,
                    Collections.singletonList(c_prime),
                    Collections.singletonList(homoCombPublicCredentialNegatedPrivatedCredential),
                    noncePfd,
                    kappa);

            // Prove that msg m is the correct decryption of c'
            Sigma3Proof proofDecryptionCprime = sigma3.proveDecryption(c_prime, m, sk, kappa);


            if (m.equals(BigInteger.ONE)) { // Dec(c_prime) == g^0
                BigInteger vote = elgamal.decrypt(encryptedVote, sk);

                // Tally the vote
                if (tallyOfVotes.containsKey(vote)) { // Check that map already has some votes for that candidate.
                    Integer totalVotes = tallyOfVotes.get(vote);
                    tallyOfVotes.put(vote, totalVotes + 1);
                } else { // First vote for the given candidate
                    tallyOfVotes.put(vote, 1);
                }

                // Prove correct decryption of vote
                Sigma3Proof proofDecryptionVote = sigma3.proveDecryption(encryptedVote, vote, sk, kappa);
                PFDStruct value = new PFDStruct(c_prime, vote, proofCombinationCprime, proofDecryptionCprime, proofDecryptionVote);

                // pfd <- pfd || (c', vote, proofCombinationCprime, proofDecryptionCprime, proofDecryptionVote);
                if (!pfd.contains(value)) {
                    pfd.add(value);
                }

            } else { // m != 1
                PFDStruct value = new PFDStruct(c_prime, m, proofCombinationCprime, proofDecryptionCprime); // FIXME: proofDecryptionVote sat to null in Object....
                if (!pfd.contains(value)) {
                    pfd.add(value);
                }
            }
        }

        // post pfd to bulletin board
        bb.publishPfd(pfd);
        bb.publishTallyOfVotes(tallyOfVotes);
         return new TallyStruct(tallyOfVotes, new PFStruct(pfr, B, pfd));
    }



    //FIXME: Working title
    private Object[] tallyStepTwo(List<Ballot> finalBallots, ElGamalSK sk, int kappa) {
        List<PFRStruct> pfr = new ArrayList<>();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        BigInteger nonce_n = UTIL.getRandomElement(sk.pk.group.q, random);


        // RUN loop for each ballot on the bulletinboard and
        // check if we should count it as a final valid ballot.
        int ell = finalBallots.size();
        CipherText ci_prime_previous = null;
        for (int i = 0; i < ell; i++) {
            Ballot ballot = finalBallots.get(i);

            // Homomorpically reencrypt(by raising to power n) ballot and decrypt
            CipherText ci_prime = homoCombination(nonce_n, ballot.getEncryptedNegatedPrivateCredential(), sk.pk.group.p);
            BigInteger noncedNegatedPrivateCredential = elgamal.decrypt(ci_prime, sk);

            // For each key. Only keep the ballots with the highest counter.
            MapAKey key = new MapAKey(ballot.getPublicCredential(), noncedNegatedPrivateCredential);

            // Update the map entry if the old counter is less. Nullify if equal
            A = updateMap(ballot, A, key);

            // Prove decryption
            Sigma3Proof decryptionProof = sigma3.proveDecryption(ci_prime, noncedNegatedPrivateCredential, sk, kappa);

            // in the first round this is not bigger then zero so we go to the else case
            if (pfr.size() > 0) {
                // Prove c0 i−1 and c0 i are derived by iterative homomorphic combination wrt nonce n
                List<CipherText> listCombined = Arrays.asList(ci_prime_previous, ci_prime);
                List<CipherText> listCipherTexts = Arrays.asList(finalBallots.get(i - 1).getEncryptedNegatedPrivateCredential(), ballot.getEncryptedNegatedPrivateCredential());
                Sigma4Proof omega = sigma4.proveCombination(sk, listCombined, listCipherTexts, nonce_n, kappa);
                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredential, decryptionProof, omega));
            } else {
                // The else case does not create the ProveComb since this else case is only used in the first iteration
                // of the loop true case is used the remaining time.
                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredential, decryptionProof, null)); // FIXME: Omega set to null.... <- in method....
            }
            ci_prime_previous = ci_prime;
        }

        return new Object[]{pfr, A};
    }

    // This method pupdates the map A according to step 2 of Tally
    private Map<MapAKey, MapAValue> updateMap(Ballot ballot, Map<MapAKey, MapAValue> A, MapAKey key) {
        // Update the map entry if the old counter is less. Nullify if equal
        MapAValue existingValue = A.get(key);
        int counter = ballot.getCounter();
        if (existingValue == null || existingValue.getCounter() < counter) { // Update the map if A[(bi[1]; N)] is empty or contains a lower counter
            CipherText combinedCredential = ballot.getPublicCredential().combine(ballot.getEncryptedNegatedPrivateCredential());
            CipherText encryptedVote = ballot.getEncryptedVote();
            MapAValue updatedValue = new MapAValue(counter, combinedCredential, encryptedVote);

            // A[publicCredential, N] <- (counter, publicCredential * encryptedNegatedPrivateCredential, encyptedVote)
            A.replace(key, updatedValue);

        } else if (existingValue.getCounter() == counter) { // Disregard duplicate counters
            MapAValue nullEntry = new MapAValue(counter, null, null);

            // A[publicCredential, N] <- (counter, null, null)
            A.replace(key, nullEntry);
        }
        return A;
    }


    @Override
    public boolean Verify(PK_Vector pkv, BulletinBoard bulletinBoard, int nc, Map<BigInteger, Integer> tallyOfVotes, PFStruct pf, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }

        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Verify => ERROR: pkv null");
            return false;
        }
        ElGamalPK pk = pkv.pk;

        // tallyVotes length should contain at most nc elements
        if (tallyOfVotes.keySet().size() != nc) {
            System.err.println("AthenaImpl.Verify => ERROR: tallyOfVotes.keySet().size() != nc");
            return false;
        }

        // Verify that the ElGamal keys are constructed correctly
        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Verify => ERROR: VerifyKey(...) => false");
            return false;
        }

        // Check that the number of candidates nc in the given election does not exceed the maximum number mc.
        if (nc > this.mc) {
            System.err.println("AthenaImpl.Verify => ERROR: nc > mc");
            return false;
        }


        /* ********
         * Check 1: Check ballot removal
         *********/
        // check {b_1,...,b_\ell} = Ø implies b is a zero-filled vector.
        List<Ballot> finalBallots = removeInvalidBallots(bulletinBoard, pk);
        if (finalBallots.isEmpty() && !valuesAreAllX(tallyOfVotes, 0)){
            System.err.println("AthenaImpl.Verify => Check 1 failed.");
            return false;
        }


        /* ********
         * Check 2: Check mix
         *********/
        int ell = finalBallots.size();
        if (!parsePF(pf)) {
            System.err.println("AthenaImpl.Verify => ERROR: pf parsed as null");
            return false;
        }

        List<PFRStruct> pfr = pf.pfr;

        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1<= i <= \ell} VerDec(pk, c'[i],N[i] , proveDecryptionOfCombination, \kappa);
        //////////////////////////////////////////////////////////////////////////////////
        for (int i = 0; i < ell; i++) {
            PFRStruct pfr_data = pfr.get(i);
            CipherText ci_prime = pfr_data.ciphertextCombination;
            BigInteger Ni = pfr_data.plaintext_N;
            Sigma3Proof sigma_i = pfr_data.proofDecryption;

            boolean veri_dec = sigma3.verifyDecryption(ci_prime, Ni, pk, sigma_i, kappa);
            if (!veri_dec) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption");
                return false;
            }
        }


        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1< i <= \ell} VerComb(pk, c'[i-1],c'[i] , b_{i-1}[2], b_{i}[2], omega[i], \kappa);
        //////////////////////////////////////////////////////////////////////////////////
       for (int i = 1; i < ell; i++) { // index starts from 1.
            CipherText ci_1_prime = pfr.get(i - 1).ciphertextCombination; // the previous combined ballot!
            CipherText ci_prime = pfr.get(i).ciphertextCombination;
            Sigma4Proof proofCombination = pfr.get(i).proofCombination;
            Ballot currentBallot = finalBallots.get(i);
            Ballot previousBallot = finalBallots.get(i - 1); // the previous ballot!
            List<CipherText> combinedList = Arrays.asList(ci_1_prime, ci_prime);
            List<CipherText> listOfEncryptedNegatedPrivateCredential = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());
            
            boolean veri_comb = sigma4.verifyCombination(pk, combinedList, listOfEncryptedNegatedPrivateCredential, proofCombination, kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination([c'_i-1, c'_i], [b_i-1, b_i])");
                return false;
            }
        }

        // initialise A as an empty map from pairs to triples
        Map<MapAKey, MapAValue> A = new HashMap<>();
        for (int i = 0; i < ell; i++) {
            Ballot ballot = finalBallots.get(i);

            BigInteger N = pfr.get(i).plaintext_N;
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);
            // Update the map with pallots. ballots t <- A.get(key_i)
            // Update the map entry if the old counter is less. Nullify if equal
            A = updateMap(ballot, A, key);
        }


        // check B was output by the mix applied in Step 2 of algorithm
        // Tally on input of the pairs of ciphertexts in A
        List<MixBallot> B = pairwiseMixnet(A, bulletinBoard);
        if (!Arrays.deepEquals(B.toArray(), pf.mixBallotList.toArray())) { // TODO: change this to use the mixBallots posted on bulletin board
            System.err.println("AthenaImpl.Verify => ERROR: Mixnet(A) => B not mixed in valid format");
            return false;
        }

        // Check our proof of mix. FIXME: are we not doing the same thing twice?
        MixProof mixProof = bulletinBoard.retrieveMixProof();



        /* ********
         * Check 3: Check revelation
         *********/
        List<PFDStruct> pfd = pf.pfd;
        if (pfd.size() != B.size()) {
            System.err.println("AthenaImpl.Verify => ERROR: pfd.size() != |B|");
            return false;
        }


        // [0,1,..., |B|-1]
        List<Integer> uncountedBallotIndices = IntStream.rangeClosed(0, B.size() - 1).boxed().collect(Collectors.toList());

        // Find which ballots vote for each candidate
        // [0, .... |B| -1]  = [0, 100]
        Map<BigInteger, Integer> tally = new HashMap<>();
        List<Integer> countedBallotIndices = new ArrayList<>();


        // Find and count valid ballots
        for (Integer i : uncountedBallotIndices) {
            // Get relevant data
            MixBallot mixBallot = B.get(i);
            CipherText homoCombPublicCredentialNegatedPrivatedCredential = mixBallot.getC1();
            CipherText encryptedVote = mixBallot.getC2();

            PFDStruct verificationInfo = pfd.get(i);
            CipherText c_prime = verificationInfo.ciphertextCombination;
            Sigma4Proof proofCombination = verificationInfo.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(pk, Collections.singletonList(c_prime), Collections.singletonList(homoCombPublicCredentialNegatedPrivatedCredential), proofCombination, kappa);
            if (!veri_comb) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                continue;
            }

            // Verify decryption of homo combitation into plaintext "1"
            Sigma3Proof proofDecryptionOfCombination = verificationInfo.proofDecryptionOfCombination;
            boolean veri_dec_1 = sigma3.verifyDecryption(c_prime, BigInteger.ONE, pk, proofDecryptionOfCombination, kappa);
            if (!veri_dec_1) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', 1)");
                continue;
            }

            // Verify decryption of vote
            BigInteger vote = verificationInfo.plaintext;
            Sigma3Proof proofDecryptionVote = verificationInfo.proofDecryptionVote;
            boolean veri_dec_v = sigma3.verifyDecryption(encryptedVote, vote, pk, proofDecryptionVote, kappa);
            if (!veri_dec_v) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(encryptedVote, vote)");
                continue;
            }

            // All checks succeeded. Increment tally and remember "good candidates"
            // https://stackoverflow.com/a/42648785
            tally.merge(vote, 1, Integer::sum);
            countedBallotIndices.add(i);

            // Ensure that the tallier counted ALL valid ballots.
            if (tally.get(vote) > countedBallotIndices.get(vote.intValueExact())) {
                System.out.println("AthenaImpl.Verify. Tallier did not count all valid votes");
                return false;
            }
        }

        // Remove the indices from 'countedBallotIndices' from 'uncountedBallotIndices'
        uncountedBallotIndices.removeAll(countedBallotIndices);

        // and for each remaining integer i \in {1,..., |B|}
        for (int j : uncountedBallotIndices) {
            // "else case" in the verification step 3
            MixBallot mixBallot = B.get(j);
            CipherText homomorphicCombinationPublicCredentialNegatedPrivateCredential = mixBallot.getC1();

            PFDStruct pfd_data = pfd.get(j);
            CipherText c_prime = pfd_data.ciphertextCombination;
            Sigma4Proof proofCombination = pfd_data.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(
                    pk,
                    Collections.singletonList(c_prime),
                    Collections.singletonList(homomorphicCombinationPublicCredentialNegatedPrivateCredential),
                    proofCombination,
                    kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                return false;
            }

            // Verify decryption of homo combination into m != 1
            BigInteger m = pfd_data.plaintext;
            Sigma3Proof proofDecryptionOfCombination = pfd_data.proofDecryptionOfCombination;
            boolean veri_dec_m = sigma3.verifyDecryption(c_prime, m, pk, proofDecryptionOfCombination, kappa);
            if (!veri_dec_m) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', m)");
                return false;
            }

            if (!m.equals(BigInteger.ONE)) {
                System.err.println("AthenaImpl.Verify => ERROR: m == 1");
                return false;
            }
        }
        return true;
    }

    // Check all values if hashmap is equal to x.
    private boolean valuesAreAllX(Map<BigInteger,Integer> map, Integer x){
        for (Integer i : map.values()) {
            if (!x.equals(i)) {
                System.out.println("found a deviating value");
                return false;
            }
        }
        return true;
    }

    // Step 1 of Tally
    private List<Ballot> removeInvalidBallots(BulletinBoard bulletinBoard,  ElGamalPK pk) {
        List<Ballot> finalBallots = new ArrayList<>(bulletinBoard.retrievePublicBallots());
        for (Ballot ballot : bulletinBoard.retrievePublicBallots()) {
            CipherText publicCredential = ballot.getPublicCredential();

            boolean isPublicCredentialInL = bulletinBoard.electoralRollContains(publicCredential);
            if (!isPublicCredentialInL) {
                System.err.println("AthenaImpl.removeInvalidBallot => ballot posted with invalid public credential");
                finalBallots.remove(ballot);
            }

            // Verify that the negated private credential is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(-d) h^s as Pedersens' commitment of (-d) using randomness s
            CipherText encryptedNegatedPrivateCredential = ballot.getEncryptedNegatedPrivateCredential();
            BulletproofStatement stmnt_1 = new BulletproofStatement(n_vote, encryptedNegatedPrivateCredential.c2, pk, g_vector_negatedPrivateCredential, h_vector_negatedPrivateCredential);
            boolean verify_encryptedNegatedPrivateCredential = bulletProof.verifyStatement(stmnt_1, ballot.getProofNegatedPrivateCredential());

            // remove invalid ballots.
            if (!verify_encryptedNegatedPrivateCredential) {
                finalBallots.remove(ballot);
            }

            // Verify that the vote is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(v) h^t as Pedersens' commitment of vote v using randomness t
            CipherText encryptedVote = ballot.getEncryptedVote();
            BulletproofStatement stmnt_2 = new BulletproofStatement(n_negatedPrivateCredential, encryptedVote.c2, pk, g_vector_vote, h_vector_vote);
            boolean verify_encryptedVote = bulletProof.verifyStatement(stmnt_2, ballot.getProofVote());

            // remove invalid ballots.
            if (!verify_encryptedVote) {
                finalBallots.remove(ballot);
            }
        }
        return finalBallots;
    }


    private boolean verifyKey(PK_Vector pkv, int kappa) {
        return sigma1.VerifyKey(new PublicInfoSigma1(kappa, pkv.pk), pkv.rho, kappa);
    }

    private boolean parsePKV(PK_Vector pkv) {
        return pkv != null && pkv.rho != null && pkv.pk != null;
    }

    private boolean parsePF(PFStruct pf) {
        return pf != null && pf.pfd != null && pf.mixBallotList != null && pf.pfr != null;
    }


    private List<BigInteger> generateNonces(int size_B) {
        List<BigInteger> nonces_n1_nB = new ArrayList<>();
        for (int i = 0; i < size_B; i++) {
            nonces_n1_nB.add(BigInteger.valueOf(i));
        }
        Collections.shuffle(nonces_n1_nB);
        return nonces_n1_nB;
    }

    private List<MixBallot> pairwiseMixnet(Map<MapAKey, MapAValue> A, BulletinBoard bulletinBoard) {
        List<MixBallot> ballots = new ArrayList<>();
        for (MapAValue val : A.values()) {
            ballots.add(val.toMixBallot());
        }

        MixStruct mixStruct = this.mixnet.mix(ballots);
        List<MixBallot> mixedBallots = mixStruct.mixedBallots;

        // TODO: WHAT ABOUT PROOF AND STATEMENT
        MixStatement statement = new MixStatement(ballots, mixedBallots);
        MixProof proofMix = mixnet.proveMix(statement, mixStruct.secret);
        boolean verification = mixnet.verify(statement, proofMix);

        // Post the mix proof
        bulletinBoard.publishMixProof(proofMix);


        if (verification) {
            System.err.println("----------------- WHAT DO WE DO HERE------------------------");
        } else {
            System.err.println("----------------- WHAT DO WE DO HERE------------------------");
        }

        return mixedBallots;
    }

    private CipherText homoCombination(BigInteger n, CipherText cipherText, BigInteger p) {
        return cipherText.modPow(n, p);
    }
}

