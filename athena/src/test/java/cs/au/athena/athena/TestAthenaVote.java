package cs.au.athena.athena;


import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.factory.AthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.MainAthenaFactory;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

@Tag("TestsAthenaVote")
@DisplayName("Test Athena Vote")
public class TestAthenaVote {

    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    private final int kappa = CONSTANTS.KAPPA;

    MainAthenaFactory msFactory;
    private CredentialTuple dv;
    private PK_Vector pkv;
    private ElGamalSK sk;

    private AthenaImpl athena;
    private Elgamal elgamal;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory(AthenaFactory.STRATEGY.SINGLE, CONSTANTS.SINGLE_TALLIER.TALLIER_COUNT);


        athena = new AthenaImpl(msFactory);
        sk = athena.Setup(CONSTANTS.SINGLE_TALLIER.TALLIER_INDEX,nc, this.kappa);
//        PK_Vector pk_vector = msFactory.getBulletinBoard().retrievePK_vector();
        PK_Vector pk_vector = BulletinBoard.getInstance().retrievePK_vector(); // TODO: RePLACE WITH ABOVE WHEN BB IS DONE!
        Group group = pk_vector.pk.group;

        this.elgamal = new Elgamal(group, nc, msFactory.getRandom());

        pkv = pk_vector;

        RegisterStruct register = athena.Register(pkv, this.kappa);
        dv = register.d;

    }

    @Test
    void TestAthenaVote() {
        int vote = 4;
        int cnt = 0;
        Ballot ballot = athena.Vote(dv, pkv, vote, cnt, nc, this.kappa);
        MatcherAssert.assertThat("Should not be null", ballot.getPublicCredential(), notNullValue());
        MatcherAssert.assertThat("Should not be null", ballot.getEncryptedNegatedPrivateCredential(), notNullValue());
        MatcherAssert.assertThat("Should not be null", ballot.getEncryptedVote(), notNullValue());
        MatcherAssert.assertThat("Should not be null", ballot.getProofNegatedPrivateCredential(), notNullValue());
        MatcherAssert.assertThat("Should not be null", ballot.getProofVotePair(), notNullValue());
        MatcherAssert.assertThat("Should be 0", ballot.getCounter(),is(0));
    }

    @Test
    void TestBallotConstruction() {
        int vote = 7;
        int cnt = 0;
        Ballot ballot = athena.Vote(this.dv, this.pkv, vote, cnt, this.nc, this.kappa);

        // Enc_pk(d) * Enc_pk(-d) = g^0
        Ciphertext combinedCredential = ballot.publicCredential.multiply(ballot.encryptedNegatedPrivateCredential, sk.pk.group.p);
        BigInteger m = Elgamal.decrypt(combinedCredential, sk);
        assertEquals("m is equal to 1 ", BigInteger.ONE, m);


        // ballot.encryptedVote = (g^t, g^v * h^t)
        Integer decryptedVote = elgamal.exponentialDecrypt(ballot.encryptedVote, sk);
        assertEquals(vote, decryptedVote.intValue());
    }


}
