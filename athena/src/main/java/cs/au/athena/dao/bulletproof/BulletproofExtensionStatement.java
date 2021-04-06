package cs.au.athena.dao.bulletproof;

import java.math.BigInteger;

public class BulletproofExtensionStatement {
    public final BigInteger H;
    public final BulletproofStatement bulletproofStatement;


    public BulletproofExtensionStatement(BigInteger H, BulletproofStatement bulletproofStatement) {
        this.H = H;
        this.bulletproofStatement = bulletproofStatement;
    }


}
