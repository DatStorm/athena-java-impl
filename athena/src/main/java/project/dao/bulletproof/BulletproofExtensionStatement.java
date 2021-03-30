package project.dao.bulletproof;

import project.elgamal.ElGamalPK;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.List;

public class BulletproofExtensionStatement {
    public final BigInteger H;
    public final BulletproofStatement bulletproofStatement;


    public BulletproofExtensionStatement(BigInteger H, BulletproofStatement bulletproofStatement) {
        this.H = H;
        this.bulletproofStatement = bulletproofStatement;
    }


}
