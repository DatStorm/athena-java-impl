package project.athena;

import org.apache.commons.lang3.tuple.Pair;
import project.UTIL;
import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.bulletproof.BulletproofProof;
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
    private final Bulletproof bulletProof;

    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private Mixnet mixnet;
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

    private AthenaFactory athenaFactory;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;

        this.sigma1 = athenaFactory.getSigma1();
        this.bulletProof = athenaFactory.getBulletProof();
        this.sigma3 = athenaFactory.getSigma3();
        this.sigma4 = athenaFactory.getSigma4();
        this.random = athenaFactory.getRandom();
        this.bb = athenaFactory.getBulletinBoard();

        this.L = new ElectoralRoll();
        this.initialised = false;
    }

    @Override
    public SetupStruct Setup(int kappa) throws IOException {

        Gen gen = new Gen(random, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.pk;
        Group group = pk.group;
        this.elgamal = gen.getElGamal(); // TODO: HER!!!!

        this.mixnet = athenaFactory.getMixnet(elgamal, pk);

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfo, sk, randR, kappa);

        this.n_vote = 3;                          // TODO: FIX THESE VALUES
        this.n_negatedPrivateCredential = 3;      // TODO: FIX THESE VALUES
        int mb = 100;                             // TODO: FIX THESE VALUES
        this.mc = 100;                            // TODO: FIX THESE VALUES

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


        BigInteger q = pkv.pk.group.q;

        //Generate nonce. aka private credential
        BigInteger privateCredential = UTIL.getRandomElement(BigInteger.ONE, q, random);
        Ciphertext publicCredential = elgamal.encrypt(privateCredential, pkv.pk);

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

        Ciphertext publicCredential = credentialTuple.publicCredential;
        ElGamalPK pk = pkv.pk;
        BigInteger q = pk.group.q;

        // Make negated private credential
        BigInteger negatedPrivateCredential = credentialTuple.privateCredential.negate();
        negatedPrivateCredential = negatedPrivateCredential.mod(q).add(q).mod(q);

        // Create encryption of negated private credential, i.e. g^{-d}
        BigInteger randomness_s = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins s
        Ciphertext encryptedNegatedPrivateCredential = elgamal.encrypt(negatedPrivateCredential, pk, randomness_s);

        // Create encryption of vote, i.e. g^{v}
        BigInteger voteAsBigInteger = BigInteger.valueOf(vote);
        BigInteger randomness_t = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins t
        Ciphertext encryptedVote = elgamal.encrypt(voteAsBigInteger, pk, randomness_t);

        // Prove that negated private credential -d resides in Z_q (this is defined using n)
//        BulletproofStatement stmnt_1 = new BulletproofStatement(
//                this.n_negatedPrivateCredential,
//                encryptedNegatedPrivateCredential.c2,
//                pk,
//                g_vector_negatedPrivateCredential,
//                h_vector_negatedPrivateCredential);
//        BulletproofSecret secret_1 = new BulletproofSecret(negatedPrivateCredential, randomness_s);
//        BulletproofProof proofRangeOfNegatedPrivateCredential = bulletProof.proveStatement(stmnt_1, secret_1);
        BulletproofProof proofRangeOfNegatedPrivateCredential = null;

//        // Prove that vote v resides in [0,nc-1] (this is defined using n)
//        BulletproofStatement stmnt_2 = new BulletproofStatement(
//                this.n_vote,
//                encryptedVote.c2,
//                pk,
//                g_vector_vote,
//                h_vector_vote);
//        BulletproofSecret secret_2 = new BulletproofSecret(voteAsBigInteger, randomness_t);
//        BulletproofProof proofRangeOfVote = bulletProof.proveStatement(stmnt_2, secret_2);
        BulletproofProof proofRangeOfVote = null;

        Ballot ballot = new Ballot(publicCredential, encryptedNegatedPrivateCredential, encryptedVote, proofRangeOfNegatedPrivateCredential, proofRangeOfVote, cnt);
        bb.publishBallot(ballot);
        return ballot;
    }


    @Override
    public TallyStruct Tally(SK_Vector skv, int nc, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        ElGamalSK sk = skv.sk;
        ElGamalPK pk = sk.pk;
        BigInteger p = pk.getGroup().p;
        BigInteger q = pk.getGroup().q;

        /* ********
         * Step 1: Remove invalid ballots
         *********/
        List<Ballot> validBallots = removeInvalidBallots( pk);
        if (validBallots.isEmpty()){
            System.err.println("AthenaImpl.Tally =>  Step 1 yielded no valid ballots on bulletinboard.");
            return null;
        }


        /* ********
         * Step 2: Mix final votes
         *********/
        //Filter ReVotes and pfr proof of same nonce
        Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterResult = filterReVotesAndProoveSameNonce(validBallots, sk, kappa);
        Map<MapAKey, MapAValue> A = filterResult.getLeft();
        List<PFRStruct> pfr = filterResult.getRight();

        // Perform random mix
        Pair<List<MixBallot>, MixProof> mixnetResult = mixnet(A);
        List<MixBallot> mixedBallots = mixnetResult.getLeft();
        MixProof mixProof = mixnetResult.getRight();

        // Publish proof
        bb.publishMixProof(mixProof);

        System.out.println("---> " + mixedBallots.size());

        // Post pfr and mixedBallots to the bulletin board
        bb.publishPfr(pfr);
        bb.publishMixBallots(mixedBallots);


        /* ********
         * Step 3: Reveal eligible votes
         *********/
        // Tally eligible votes and prove computations
        Pair<Map<BigInteger, Integer>, List<PFDStruct>> rr = revealEligibleVotes(sk, mixedBallots, kappa);
        Map<BigInteger, Integer> tallyOfVotes = rr.getLeft();
        List<PFDStruct> pfd = rr.getRight();

        // post pfd to bulletin board
        bb.publishPfd(pfd);
        bb.publishTallyOfVotes(tallyOfVotes);
        return new TallyStruct(tallyOfVotes, new PFStruct(pfr, mixedBallots, pfd, mixProof));
    }

    // Step 1 of Tally
    private List<Ballot> removeInvalidBallots(ElGamalPK pk) {
        List<Ballot> finalBallots = new ArrayList<>(bb.retrievePublicBallots());


        for (Ballot ballot : bb.retrievePublicBallots()) {
            Ciphertext publicCredential = ballot.getPublicCredential();

            // Is the public credential
            boolean isPublicCredentialInL = bb.electoralRollContains(publicCredential);
            if (!isPublicCredentialInL) {
                System.err.println("AthenaImpl.removeInvalidBallot => ballot posted with invalid public credential");
                finalBallots.remove(ballot);
            }

//            // Verify that the negated private credential is in the valid range
//            // ElGamal ciphertext (c1,c2) => use c2=g^(-d) h^s as Pedersens' commitment of (-d) using randomness s
//            CipherText encryptedNegatedPrivateCredential = ballot.getEncryptedNegatedPrivateCredential();
//            BulletproofStatement stmnt_1 = new BulletproofStatement(n_vote, encryptedNegatedPrivateCredential.c2, pk, g_vector_negatedPrivateCredential, h_vector_negatedPrivateCredential);
//            boolean verify_encryptedNegatedPrivateCredential = bulletProof.verifyStatement(stmnt_1, ballot.getProofNegatedPrivateCredential());
//
//
//            // remove invalid ballots.
//            if (!verify_encryptedNegatedPrivateCredential) {
//                finalBallots.remove(ballot);
//            }
//
//            // Verify that the vote is in the valid range
//            // ElGamal ciphertext (c1,c2) => use c2=g^(v) h^t as Pedersens' commitment of vote v using randomness t
//            CipherText encryptedVote = ballot.getEncryptedVote();
//            BulletproofStatement stmnt_2 = new BulletproofStatement(n_negatedPrivateCredential, encryptedVote.c2, pk, g_vector_vote, h_vector_vote);
//            boolean verify_encryptedVote = bulletProof.verifyStatement(stmnt_2, ballot.getProofVote());
//
//            // remove invalid ballots.
//            if (!verify_encryptedVote) {
//                finalBallots.remove(ballot);
//            }
        }
        return finalBallots;
    }

    // Step 2 of Tally. Returns map of the highest counter ballot, for each credential pair, and a proof having used the same nonce for all ballots.
    private Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterReVotesAndProoveSameNonce(List<Ballot> ballots, ElGamalSK sk, int kappa) {
        int ell = ballots.size();

        List<PFRStruct> pfr = new ArrayList<>();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        // Pick a nonce to mask public credentials.
        BigInteger nonce_n = UTIL.getRandomElement(sk.pk.group.q, random);

        // For each ballot.
        Ciphertext ci_prime_previous = null;
        for (int i = 0; i < ell; i++) {
            Ballot ballot = ballots.get(i);

            // Homomorpically reencrypt(by raising to power n) ballot and decrypt
            Ciphertext ci_prime = homoCombination(ballot.getEncryptedNegatedPrivateCredential(), nonce_n, sk.pk.group.p);
            BigInteger noncedNegatedPrivateCredential = elgamal.decrypt(ci_prime, sk);

            // Update map with highest counter entry.
            MapAKey key = new MapAKey(ballot.getPublicCredential(), noncedNegatedPrivateCredential);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, sk.pk.group.p);
            A.put(key, updatedValue);

            // Prove decryption
            Sigma3Proof decryptionProof = sigma3.proveDecryption(ci_prime, noncedNegatedPrivateCredential, sk, kappa);

            // Proove that the same nonce was used for all ballots.
            if (pfr.size() > 0) {
                // Prove c0 i−1 and c0 i are derived by iterative homomorphic combination wrt nonce n
                List<Ciphertext> listCombined = Arrays.asList(ci_prime_previous, ci_prime);
                List<Ciphertext> listCiphertexts = Arrays.asList(ballots.get(i - 1).getEncryptedNegatedPrivateCredential(), ballot.getEncryptedNegatedPrivateCredential());
                Sigma4Proof omega = sigma4.proveCombination(sk, listCombined, listCiphertexts, nonce_n, kappa);

                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredential, decryptionProof, omega));
            } else {
                // The else case does not create the ProveComb since this else case is only used in the first iteration
                // of the loop true case is used the remaining time.
                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredential, decryptionProof, null));
            }

            ci_prime_previous = ci_prime;
        }

        return Pair.of(A, pfr);
    }

    // Step 2 of Tally. Returns a MapAValue, representing the ballot with the highest counter.
    private MapAValue getHighestCounterEntry(MapAValue existingValue, Ballot ballot, BigInteger p) {
        // Update the map entry if the old counter is less. Nullify if equal
        int counter = ballot.getCounter();
        if (existingValue == null || existingValue.getCounter() < counter) {
            // Update the map if A[(bi[1]; N)] is empty, or contains a lower counter

            Ciphertext combinedCredential = ballot.getPublicCredential().multiply(ballot.getEncryptedNegatedPrivateCredential(), p);
            MapAValue updatedValue = new MapAValue(counter, combinedCredential, ballot.getEncryptedVote());

            return updatedValue;

        } else if (existingValue.getCounter() == counter) {
            // Duplicate counters are illegal. Set null entry.
            MapAValue nullValue = new MapAValue(counter, null, null);
            return nullValue;

        } else {

            return existingValue;
        }
    }

    // Step 2 of Tally. Mix ballots
    private Pair<List<MixBallot>, MixProof> mixnet(Map<MapAKey, MapAValue> A) {
        // Cast to mix ballot list
        List<MixBallot> ballots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Mix ballots
        MixStruct mixStruct = this.mixnet.mix(ballots);
        List<MixBallot> mixedBallots = mixStruct.mixedBallots;

        // Prove mix
        MixStatement statement = new MixStatement(ballots, mixedBallots);
        MixProof mixProof = mixnet.proveMix(statement, mixStruct.secret);
        assert mixnet.verify(statement, mixProof);

        return Pair.of(mixedBallots, mixProof);
    }

    // Step 3 of tally. Nonce and decrypt ballots, and keep a tally of the eligible votes.
    private Pair<Map<BigInteger, Integer>, List<PFDStruct>> revealEligibleVotes(ElGamalSK sk, List<MixBallot> mixedBallots, int kappa) {
        Map<BigInteger, Integer> tallyOfVotes = new HashMap<>();
        List<PFDStruct> pfd = new ArrayList<>(mixedBallots.size());

        BigInteger p = sk.pk.group.p;
        BigInteger q = sk.pk.group.q;

        for (MixBallot mixBallot : mixedBallots) {
            Ciphertext combinedCredential = mixBallot.getC1();
            Ciphertext encryptedVote = mixBallot.getC2();

            // Apply a nonce to the combinedCredential
            BigInteger nonce = UTIL.getRandomElement(q, random);
            Ciphertext c_prime = homoCombination(combinedCredential, nonce, p);

            // Decrypt nonced combinedCredential
            BigInteger m = elgamal.decrypt(c_prime, sk);

            // Prove that c' is a homomorphic combination of combinedCredential
            Sigma4Proof combinationProof = sigma4.proveCombination(
                    sk,
                    c_prime,
                    combinedCredential,
                    nonce,
                    kappa);

            // Prove that msg m is the correct decryption of c'
            Sigma3Proof combinationDecryptionProof = sigma3.proveDecryption(c_prime, m, sk, kappa);

            // Check validity of private credential. (decrypted combinedCredential = 1)
            if (m.equals(BigInteger.ONE)) {
                System.out.println("--> M=1");

                // Decrypt vote
                BigInteger vote = elgamal.decrypt(encryptedVote, sk);

                // Tally the vote
                if (tallyOfVotes.containsKey(vote)) { // Check that map already has some votes for that candidate.
                    Integer totalVotes = tallyOfVotes.get(vote);
                    tallyOfVotes.put(vote, totalVotes + 1);
                } else { // First vote for the given candidate
                    tallyOfVotes.put(vote, 1);
                }

                // Prove correct decryption of vote
                Sigma3Proof voteDecryptionProof = sigma3.proveDecryption(encryptedVote, vote, sk, kappa);

                // Store proofs
                PFDStruct value = new PFDStruct(c_prime, vote, combinationProof, combinationDecryptionProof, voteDecryptionProof);
                pfd.add(value);

            } else { // m != 1
                System.out.println("--> M!=1");

                PFDStruct value = new PFDStruct(c_prime, m, combinationProof, combinationDecryptionProof); // FIXME: proofDecryptionVote sat to null in Object....
                pfd.add(value);
            }
        }

        return Pair.of(tallyOfVotes, pfd);
    }




    @Override
    public boolean Verify(PK_Vector pkv, int nc, Map<BigInteger, Integer> tallyOfVotes, PFStruct pf, int kappa) {
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
            System.err.println("AthenaImpl.Verify => ERROR: tallyOfVotes.keySet().size()=" + tallyOfVotes.keySet().size()+ " != nc=" + nc);
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
        List<Ballot> validBallots = removeInvalidBallots(pk);
        if (validBallots.isEmpty() && !valuesAreAllX(tallyOfVotes, 0)){
            System.err.println("AthenaImpl.Verify => Check 1 failed.");
            return false;
        }

        /* ********
         * Check 2: Check mix
         *********/
        if (!parsePF(pf)) {
            System.err.println("AthenaImpl.Verify => ERROR: pf parsed as null");
            return false;
        }

        // Verify that homomorphic combinatins use the same nonce for all negated credentials
        boolean homoCombinationsAreValid = checkHomoCombinations(validBallots, pf.pfr, pk, kappa);
        if(!homoCombinationsAreValid) {
            return false;
        }

        // Verify decryption of homomorphic combination
        boolean decryptionsAreValid = checkDecryptions(validBallots, pf.pfr, pk, kappa);
        if (!decryptionsAreValid) {
            return false;
        }

        // Verify that filtering of ballots(only keeping highest counter) and mixnet is valid
        boolean mixIsValid = checkMix(validBallots, pf, pk);
        if(!mixIsValid) {
            return false;
        }

        /* ********
         * Check 3: Check revelation
         *********/
        // Verify that
        return checkRevalation(pf.mixBallotList, pf.pfd, pk, kappa);
    }

    private boolean checkHomoCombinations(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk, int kappa) {
        int ell = validBallots.size();
        // Verify decryption of nonced private credential
        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1<= i <= \ell} VerDec(pk, c'[i],N[i] , proveDecryptionOfCombination, \kappa);
        //////////////////////////////////////////////////////////////////////////////////
        for (int i = 0; i < ell; i++) {
            PFRStruct pfr_data = pfr.get(i);
            Ciphertext ci_prime = pfr_data.ciphertextCombination;
            BigInteger Ni = pfr_data.plaintext_N;
            Sigma3Proof sigma_i = pfr_data.proofDecryption;

            boolean veri_dec = sigma3.verifyDecryption(ci_prime, Ni, pk, sigma_i, kappa);
            if (!veri_dec) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption");
                return false;
            }
        }

        return true;
    }

    private boolean checkDecryptions(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk, int kappa) {
        int ell = validBallots.size();
        // Verify that the same nonce was used on all nonced private credentials
        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1< i <= \ell} VerComb(pk, c'[i-1],c'[i] , b_{i-1}[2], b_{i}[2], omega[i], \kappa);
        //////////////////////////////////////////////////////////////////////////////////
        for (int i = 1; i < ell; i++) { // index starts from 1.
             Ciphertext ci_1_prime = pfr.get(i - 1).ciphertextCombination; // the previous combined ballot!
             Ciphertext ci_prime = pfr.get(i).ciphertextCombination;
             Sigma4Proof proofCombination = pfr.get(i).proofCombination;
             Ballot previousBallot = validBallots.get(i - 1); // the previous ballot!
             Ballot currentBallot = validBallots.get(i);

             List<Ciphertext> combinedList = Arrays.asList(ci_1_prime, ci_prime);
             List<Ciphertext> listOfEncryptedNegatedPrivateCredential = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

             boolean veri_comb = sigma4.verifyCombination(pk, combinedList, listOfEncryptedNegatedPrivateCredential, proofCombination, kappa);
             if (!veri_comb) {
                 System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination([c'_i-1, c'_i], [b_i-1, b_i])");
                 return false;
             }
         }
        return true;
    }

    private boolean checkMix(List<Ballot> validBallots, PFStruct pf, ElGamalPK pk) {
        int ell = validBallots.size();

        List<PFRStruct> pfr = pf.pfr;
        List<MixBallot> B = pf.mixBallotList;
        MixProof mixProof = pf.mixProof;

        // initialise A as an empty map from pairs to triples, then filter
        Map<MapAKey, MapAValue> A = new HashMap<>();
        for (int i = 0; i < ell; i++) {
            Ballot ballot = validBallots.get(i);
            BigInteger N = pfr.get(i).plaintext_N;

            // Update the map with pallots. ballots t <- A.get(key_i)
            // Update the map entry if the old counter is less. Nullify if equal
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, pk.group.p);
            A.put(key, updatedValue);
        }

        // Cast A map values to list
        List<MixBallot> filteredBallots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Verify mixnet
        MixStatement statement = new MixStatement(filteredBallots, B);
        boolean veri_mix =  mixnet.verify(statement, mixProof);
        if (!veri_mix) {
            System.err.println("AthenaImpl.Verify => ERROR: mixProof was invalid");
            return false;
        }

        return true;
    }

    private boolean checkRevalation(List<MixBallot> B, List<PFDStruct> pfd, ElGamalPK pk, int kappa) {
        if (pfd.size() != B.size()) {
            System.err.println("AthenaImpl.Verify => ERROR: pfd.size() != |B|");
            return false;
        }

        // Verify that all valid ballots were counted, and that the rest are invalid.
        // [0,1,..., |B|-1]
        List<Integer> uncountedBallotIndices = IntStream
                .rangeClosed(0, B.size() - 1).boxed()
                .collect(Collectors.toList());

        // Find which ballots vote for each candidate
        // [0, .... |B| -1]  = [0, 100]
        Map<BigInteger, Integer> tally = new HashMap<>();
        List<Integer> countedBallotIndices = new ArrayList<>();


        // Find and count valid ballots
        for (Integer i : uncountedBallotIndices) {
            // Get relevant data
            MixBallot mixBallot = B.get(i);
            Ciphertext combinedCredential = mixBallot.getC1();
            Ciphertext encryptedVote = mixBallot.getC2();

            PFDStruct verificationInfo = pfd.get(i);
            Ciphertext c_prime = verificationInfo.ciphertextCombination;
            Sigma4Proof proofCombination = verificationInfo.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(pk, c_prime, combinedCredential, proofCombination, kappa);
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
            Ciphertext combinedCredential = mixBallot.getC1();

            PFDStruct pfd_data = pfd.get(j);
            Ciphertext c_prime = pfd_data.ciphertextCombination;
            Sigma4Proof proofCombination = pfd_data.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(
                    pk,
                    Collections.singletonList(c_prime),
                    Collections.singletonList(combinedCredential),
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
    private boolean valuesAreAllX(Map<BigInteger, Integer> map, Integer x){
        for (Integer i : map.values()) {
            if (!x.equals(i)) {
                System.out.println("found a deviating value");
                return false;
            }
        }
        return true;
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



    private Ciphertext homoCombination(Ciphertext cipherText, BigInteger n, BigInteger p) {
        return cipherText.modPow(n, p);
    }
}

