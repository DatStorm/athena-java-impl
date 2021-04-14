package cs.au.athena.util;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class TestJUnit4 {
    
    

    @Before
    public void before() {
        System.out.println("before");
    }

    @After
    public void after() {
        System.out.println("after");
    }



    @Test
    public void test1() {
        System.out.println("test1");
    }

    @Test
    public void test2() {
        System.out.println("test2");
    }


}
