package util;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.UTIL;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

@Tag("TestsUTIL")
@DisplayName("Test UTIL")
public class TestUTIL {


    @Test
    void TestUTIL_log() {

        BigInteger _256 = BigInteger.valueOf(256);
        BigInteger _2 = BigInteger.valueOf(2);

        double res = UTIL.BigLog(_2, _256);
        assertEquals("value res= " + res, 8.0,res, 0.00001);
    }
}
