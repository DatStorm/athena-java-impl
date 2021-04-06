package entities;


import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@Tag("TestEntities")
@SelectClasses( {TestAthenaMaliciousTallier.class, TestAthenaTallierEvilVoter.class} )
public class TestEntities {
}
