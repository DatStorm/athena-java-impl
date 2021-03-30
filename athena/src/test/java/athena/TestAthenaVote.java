package athena;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.dao.athena.*;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalSK;
import project.elgamal.Group;
import project.factory.MainAthenaFactory;

import java.io.IOException;
import java.math.BigInteger;

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
    private ElGamal elgamal;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory();


        athena = new AthenaImpl(msFactory);
        ElectionSetup setup = athena.Setup(nc, this.kappa);
        Group group = setup.pkv.pk.group;

        this.elgamal = new ElGamal(group, nc, msFactory.getRandom());

        pkv = setup.pkv;
        sk = setup.sk;

        RegisterStruct register = athena.Register(pkv, this.kappa);
        dv = register.d;

    }

    @Test
    void TestAthenaVote() {
        int vote = 4;
        int cnt = 0;
        Ballot ballot = athena.Vote(dv, pkv, vote, cnt, nc, this.kappa);
        assertNotNull("Should not be null", ballot.getPublicCredential());
        assertNotNull("Should not be null", ballot.getEncryptedNegatedPrivateCredential());
        assertNotNull("Should not be null", ballot.getEncryptedVote());
        assertNotNull("Should not be null", ballot.getProofNegatedPrivateCredential());
        assertNotNull("Should not be null", ballot.getProofVotePair());
        assertEquals("Should be 0",0, ballot.getCounter());
    }

    @Test
    void TestBallotConstruction() {
        int vote = 7;
        int cnt = 0;
        Ballot ballot = athena.Vote(this.dv, this.pkv, vote, cnt, this.nc, this.kappa);

        // Enc_pk(d) * Enc_pk(-d) = g^0
        Ciphertext combinedCredential = ballot.publicCredential.multiply(ballot.encryptedNegatedPrivateCredential, sk.pk.group.p);
        BigInteger m = elgamal.decrypt(combinedCredential, sk);
        assertEquals("m is equal to 1 ", BigInteger.ONE, m);


        // ballot.encryptedVote = (g^t, g^v * h^t)
        Integer decryptedVote = elgamal.exponentialDecrypt(ballot.encryptedVote, sk);
        assertEquals(vote, decryptedVote.intValue());
    }


}
