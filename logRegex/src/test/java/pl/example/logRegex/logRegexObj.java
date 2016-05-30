package pl.example.logRegex;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class logRegexObj {
	private String log;
	//String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\""; 
			
	
	private void findAllText(Matcher matcher) {
		int count = 0;
		while(matcher.find()) {
			count++;
			System.out.print("Found: "+count+" : "+matcher.start()+" - "+matcher.end()+" -> ");
			
			for(int i = matcher.start(); i < matcher.end(); i++ ) {
				System.out.print(log.charAt(i));
			}
			System.out.println("");
		}
	}
	
	private void findFirstText(Matcher matcher) {
			
     	matcher.find();
		//System.out.println(matcher.find());
		
		for(int i = matcher.start(); i < matcher.end(); i++ ) {
			System.out.print(log.charAt(i));
		}
		
		
	}
	
	 public void sysLogTimeStamp1(String log) {
	      this.log = log;
	       
	      Pattern sysLogPattern = Pattern.compile("^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)");
	       
	      Matcher matcher = sysLogPattern.matcher(log);
			
			//findAllText(matcher);
	      
	      findFirstText(matcher);
	    }
	
	//-----------------------------------------------
	
	public void proxyIP(String log) {
		this.log = log;
		
		Pattern proxyIPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
			
	      findAllText(matcher);
		
	}
	
	//-----------------------------------------------
	
	public void product(String log) {
		this.log = log;
		
		Pattern productPattern = Pattern.compile("\\s\\w+:\\s\\[{1}");
		
		Matcher matcher = productPattern.matcher(log);
		
	      findAllText(matcher);
	}
	
	//-----------------------------------------------
	
	public void eventTimeStamp(String log) {
		this.log = log;
		
		Pattern productPattern = Pattern.compile("\\s\\[([^\\]]+)\\]");
		
	      Matcher matcher = productPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void user(String log) {
		this.log = log;
								// LUB \x22[A-Z;a-z]+\x22 ale wtedy findFirstText()
		Pattern userPattern = Pattern.compile("\\]\\s\\x22([^\\x22]*)\\x22\\s");
		
	      Matcher matcher = userPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void sourceIP(String log) {
		this.log = log;
		
		Pattern IPPattern = Pattern.compile("\\x22\\s\\d+\\.\\d+\\.\\d+\\.\\d+\\s");
		
	      Matcher matcher = IPPattern.matcher(log);
			
	      findAllText(matcher);
	}

	public void status(String log) {
		this.log = log;
		
		Pattern IPPattern = Pattern.compile("\\s\\d{3}\\s");
		
	      Matcher matcher = IPPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void httpMethod(String log) {
		this.log = log;
		
		Pattern methodPattern = Pattern.compile("[A-Z]{3,7}\\s");
		
	      Matcher matcher = methodPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void httpProtocol(String log) {
		this.log = log;
		
		Pattern protocolPattern = Pattern.compile("(http://|https://)?");
		
	      Matcher matcher = protocolPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void url(String log) {						// BRAK REGEXA!!!!!!!!!!!!!!!!!!
		this.log = log;
		
		Pattern urlPattern = Pattern.compile("\\S+:");
		
	      Matcher matcher = urlPattern.matcher(log);
			
	      findAllText(matcher);
	}
	
	public void httpVersion(String log) {
		this.log = log;
		
		Pattern versionPattern = Pattern.compile("HTTP/[0-9]*\\.[0-9]*");
		
	      Matcher matcher = versionPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	
	public void httpCategory(String log) {					//ZADZIALA TYLKO Z findFirstText
		this.log = log;
																		//log.replaceAll("/", "znak");
		Pattern versionPattern = Pattern.compile("\\x22[A-Z;a-z]+\\S+\\s+\\S*\\x22");
		
	      Matcher matcher = versionPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void risk(String log) {
		this.log = log;
												
		Pattern riskPattern = Pattern.compile("\\x22[A-Z]\\S\\w*\\x22");
		
	      Matcher matcher = riskPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void httpContentType(String log) {									// "" ?????????????
		this.log = log;
		 
		Pattern contentTypePattern = Pattern.compile("\\x22\\x22\\s");
		
	      Matcher matcher = contentTypePattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void bytesIN(String log) {											// wyswietla z "
		this.log = log;
		
		Pattern bytesINPattern = Pattern.compile("\\x22\\s\\d+\\s");
		
	      Matcher matcher = bytesINPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void bytesOUT(String log) {											// BRAK REGEXA
		this.log = log;
		 
		Pattern bytesOUTPattern = Pattern.compile("\\s\\d+\\s\\x22");
		
	      Matcher matcher = bytesOUTPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void httpUserAgent(String log) {
		this.log = log;
		
		Pattern userAgentPattern = Pattern.compile("(^\\x22)\\w");
		
	      Matcher matcher = userAgentPattern.matcher(log);
			
	      findFirstText(matcher);
		}
	
	public void signature(String log) {
		this.log = log;
		
		Pattern signaturePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
	      Matcher matcher = signaturePattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void action(String log) {
		this.log = log;
		
		Pattern actionPattern = Pattern.compile("\\s\\x22\\d+\\x22\\s");
		
	      Matcher matcher = actionPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void blockResult(String log) {
		this.log = log;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
	      Matcher matcher = ruleNamePattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void customRuleName(String log) {										//BRAK REGEX
		this.log = log;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22[\\w\\s]*\\x22\\s");
		
	      Matcher matcher = ruleNamePattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void destIP(String log) {
		this.log = log;
		
		Pattern destIPPattern = Pattern.compile("\\x22\\d+\\.\\d+\\.\\d+\\.\\d+\\x22");
		
	      Matcher matcher = destIPPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	public void httpReferrer(String log) {
		this.log = log;
		
		Pattern referrerPattern = Pattern.compile("\\s\\x22(\\x22)$");
		
	      Matcher matcher = referrerPattern.matcher(log);
			
	      findAllText(matcher);
		}
	
	
	}
