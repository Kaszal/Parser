package pl.example.logRegex;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class logRegex {
	private String log;
	//String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\""; 
			
	
	private void findAllText(Matcher matcher) {
		int count = 0;
		while(matcher.find()) {
			count++;
			System.out.print("Found: "+count+" : "+matcher.start()+" - "+matcher.end()+" -> ");
			
			for(int i = matcher.start(); i <= matcher.end(); i++ ) {
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
	
	 public String sysLogTimeStamp1(String log) {
	        //this.log = log;
	        
	       String result = "";
	       Pattern sysLogPattern = Pattern.compile("^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)");
	       
		      Matcher matcher = sysLogPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;         
	          
	    }
	
	//-----------------------------------------------
	
	public String proxyIP(String log) {
		//this.log = log;
		String result = "";
		Pattern proxyIPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		 Matcher matcher = proxyIPPattern.matcher(log);
        if(matcher.find())
            result = matcher.group(1);
        else
        	result = "NOT FOUND";
      
        return result; 
	}
	
	//-----------------------------------------------
	
	public boolean product(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern productPattern = Pattern.compile("\\w+");
		
		if(productPattern.matcher(log).matches())
			result = true;
			
			return result;
	}
	
	//-----------------------------------------------
	
	public boolean eventTimeStamp(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern productPattern = Pattern.compile("\\s\\[([^\\]]+)\\]");
		
		if(productPattern.matcher(log).matches())
			result = true;
			
			return result;
	}
	
	public boolean user(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern userPattern = Pattern.compile("\\s\\x22([^\\x22]*)\\x22\\s");
		
		if(userPattern.matcher(log).matches())
			result = true;
		
		return result;
	}
	
	public boolean sourceIP(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern IPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		
		if(IPPattern.matcher(log).matches())
			result = true;
		
		return result;
	}

	public boolean status(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern IPPattern = Pattern.compile("\\d{1,3}");
		
		if(IPPattern.matcher(log).matches())
			result = true;
		
		return result;
	}
	
	public boolean httpMethod(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern methodPattern = Pattern.compile("\\s\\x22(\\w+)\\s");
		
		if(methodPattern.matcher(log).matches())
			result = true;
		
		return result;
	}
	
	public boolean httpProtocol(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern protocolPattern = Pattern.compile("(http://|https://)?");
		
		if(protocolPattern.matcher(log).matches())
			result = true;
		
		return result;
	}
	
	public boolean url(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern urlPattern = Pattern.compile("\\S+:");
		
		if(urlPattern.matcher(log).matches())
			result = true;
		
		return result;
	}
	
	public boolean httpVersion(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern versionPattern = Pattern.compile("\\w+/\\d+\\.\\d+");
		
		if(versionPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	
	public boolean httpCategory(String log) {
		this.log = log;
		
		boolean result = false;
		
																		//log.replaceAll("/", "znak");
		
		Pattern versionPattern = Pattern.compile("\\w*\\w*");
		
		if(versionPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean risk(String log) {
		this.log = log;
		
		boolean result = false;
												//\\s\\x22([^\\x22]*)\\x22\\s
		Pattern riskPattern = Pattern.compile("\\s\\x22\\w*\\x22\\s");
		
		if(riskPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean httpContentType(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern contentTypePattern = Pattern.compile("\\x22\\x22\\s");
		
		if(contentTypePattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean bytesIN(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern bytesINPattern = Pattern.compile("\\s\\d+");
		
		if(bytesINPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean bytesOUT(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern bytesOUTPattern = Pattern.compile("\\s\\d+");
		
		if(bytesOUTPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean httpUserAgent(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern userAgentPattern = Pattern.compile("(^\\x22)\\w");
		
		if(userAgentPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean signature(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern signaturePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
		if(signaturePattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean action(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern actionPattern = Pattern.compile("\\s\\x22\\d+\\x22\\s");
		
		if(actionPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean blockResult(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
		if(ruleNamePattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean customRuleName(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22[\\w\\s]*\\x22\\s");
		
		if(ruleNamePattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean destIP(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern destIPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		
		if(destIPPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	public boolean httpReferrer(String log) {
		this.log = log;
		
		boolean result = false;
		
		Pattern referrerPattern = Pattern.compile("\\s\\x22(\\x22)$");
		
		if(referrerPattern.matcher(log).matches())
			result = true;
			
			return result;
		}
	
	
	}
