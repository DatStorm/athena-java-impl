package project.athena;

import project.dao.Randomness;
import project.dao.athena.D_Vector;
import project.dao.athena.PK_Vector;
import project.dao.athena.RegisterStruct;
import project.dao.athena.SetupStruct;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.AthenaFactory;
import project.sigma.Sigma1;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class AthenaImpl implements Athena {
    private final Sigma1 simga1;
    private final Random random;
    private boolean initialised;
    private ElGamal elgamal;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.simga1 = athenaFactory.getSigma1();
        this.random = athenaFactory.getRandom();

        this.initialised = false;
    }

    @Override
    public SetupStruct Setup(int kappa) throws IOException {

        Gen gen = new Gen(random, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.getPK();
        this.elgamal = gen.getElGamal();

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = simga1.ProveKey(publicInfo, sk, randR, kappa);


        int mb = 100;
        int mc = 100;


        this.initialised = true;
        return new SetupStruct(new PK_Vector(pk, rho), sk, mb, mc);
    }

    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        if (pkv == null || pkv.rho == null || pkv.pk == null) {
            System.err.println("AthenaImpl.Register => ERROR: pkv null");
            return null;
        }

        boolean ver = simga1.VerifyKey(new PublicInfoSigma1(kappa, pkv.pk), pkv.rho, kappa);
        if (!ver) {
            System.err.println("AthenaImpl.Register => ERROR: VerifyKey(...) => false");
            return null;
        }


        int d = 100; // TODO: Generate nonce d.
        BigInteger g = elgamal.getDescription().getG(); // TODO: Correct g ?????
        BigInteger g_d = g.pow(d);
        CipherText pd = elgamal.encrypt(g_d, pkv.pk);

        D_Vector d_vector = new D_Vector(pd, d);
        return new RegisterStruct(pd, d_vector);
    }

    @Override
    public void Vote(D_Vector dv,  PK_Vector pkv, int vote, int cnt, int nc, int kappa) {

    }

    @Override
    public void Tally() {

    }

    @Override
    public void Verify() {

    }
}
