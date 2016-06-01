package pl.example.logRegex;

import java.util.Random;
import java.util.regex.Pattern;

import com.sun.org.apache.xerces.internal.impl.xs.identity.Selector.Matcher;

public class Main {

	public static void main(String[] args) {
		logRegex l1 = new logRegex();
		logRegexObj l2 = new logRegexObj();
		
		String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
		
		
		
		Random random = new Random();
		
		random.nextInt();
		
		
		//l2.customRuleName(log);
		
		//l1.sysLogTimeStamp1(log);
		
		
		
		/*l1.sysLogTimeStamp1(log);
		System.out.println();
		l1.proxyIP(log);
		System.out.println();
		l1.product(log);		// zle, mgw
		System.out.println();
		l1.eventTimeStamp(log);  // zle
		System.out.println();
		l1.user(log);
		System.out.println();
		l1.sourceIP(log);
		System.out.println();
		l1.status(log);
		System.out.println();
		l1.httpMethod(log);
		System.out.println();
		l1.httpMethod(log);
		System.out.println();
		l1.httpProtocol(log);
		System.out.println();
		l1.url(log);
		System.out.println();
		l1.httpVersion(log);
		System.out.println();
		//l1.httpCategory(log);
		System.out.println();
		l1.risk(log);
		System.out.println();
		l1.httpContentType(log);		// zle, unrevified
		System.out.println();
		l1.bytesIN(log);			// zle
		System.out.println();
		l1.bytesOUT(log);			// zle
		System.out.println();
		//l1.httpUserAgent(log);
		System.out.println();
		l1.signature(log);
		System.out.println();
		l1.action(log);
		System.out.println();
		l1.blockResult(log);		//
		System.out.println();
		//l1.customRuleName(log);		// nie dziala w ogole
		System.out.println();
		l1.destIP(log);				// ZLE
		System.out.println();
		l1.httpReferrer(log);
		System.out.println();
		
		*/
	}
}

