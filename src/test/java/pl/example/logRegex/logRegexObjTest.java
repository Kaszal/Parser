package pl.example.logRegex;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class logRegexObjTest {

	private String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
	private String expectedValue = "May 18 09:31:44";
	
	@Test
	public void testSysLogTimeStamp1() {
	String loadedLog = sysLog;
	String toCheck = "May 18 09:31:44";
	boolean result = false;
	
	
	Pattern sysLogPattern = Pattern.compile("^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)");
    
    Matcher matcher = sysLogPattern.matcher(loadedLog);
    
    assertThat(loadedLog, equalTo(toCheck));
	
	}

	@Test
	public void testProxyIP() {
		fail("Not yet implemented");
	}

	@Test
	public void testProduct() {
		fail("Not yet implemented");
	}

	@Test
	public void testEventTimeStamp() {
		fail("Not yet implemented");
	}

	@Test
	public void testUser() {
		fail("Not yet implemented");
	}

	@Test
	public void testSourceIP() {
		fail("Not yet implemented");
	}

	@Test
	public void testStatus() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpMethod() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpProtocol() {
		fail("Not yet implemented");
	}

	@Test
	public void testUrl() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpVersion() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpCategory() {
		fail("Not yet implemented");
	}

	@Test
	public void testRisk() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpContentType() {
		fail("Not yet implemented");
	}

	@Test
	public void testBytesIN() {
		fail("Not yet implemented");
	}

	@Test
	public void testBytesOUT() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpUserAgent() {
		fail("Not yet implemented");
	}

	@Test
	public void testSignature() {
		fail("Not yet implemented");
	}

	@Test
	public void testAction() {
		fail("Not yet implemented");
	}

	@Test
	public void testBlockResult() {
		fail("Not yet implemented");
	}

	@Test
	public void testCustomRuleName() {
		fail("Not yet implemented");
	}

	@Test
	public void testDestIP() {
		fail("Not yet implemented");
	}

	@Test
	public void testHttpReferrer() {
		fail("Not yet implemented");
	}

}
