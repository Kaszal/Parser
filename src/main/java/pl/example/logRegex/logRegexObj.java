package pl.example.logRegex;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class logRegexObj implements LogInterface {
	
	private static final String HTTP_REFERRER_REGEX = "\\s\\x22(\\x22)$";
	private static final String DEST_IP_REGEX = "(\\x22\\d+\\.\\d+\\.\\d+\\.\\d+\\x22)";
	private static final String CUSTOM_RULE_NAME_REGEX = "(\\s\\x22[\\w\\s]*\\x22\\s)";
	private static final String ACTION_REGEX = "(\\s\\x22\\d+\\x22\\s)";
	private static final String SIGNATURE_REGEX = "(\\s\\x22\\x22\\s)";
	private static final String BYTES_IN_REGEX = "(\\x22\\s\\d+\\s)";
	private static final String HTTP_CONTENT_TYPE_REGEX = "(\\x22\\x22\\s)";
	private static final String RISK_REGEX = "(\\x22[A-Z]\\S\\w*\\x22)";
	private static final String HTTP_CATEGORY_REGEX = "(\\x22[A-Z;a-z]+\\S+\\s+\\S*\\x22)";
	private static final String HTTP_VERSION_REGEX = "(HTTP/[0-9]*\\.[0-9]*)";
	private static final String HTTP_PROTOCOL_REGEX = "(http://|https://)?";
	private static final String HTTP_METHOD_REGEX = "([A-Z]{3,7}\\s)";
	private static final String SOURCE_IP_REGEX = "(\\x22\\s\\d+\\.\\d+\\.\\d+\\.\\d+\\s)";
	private static final String USER_REGEX = "(\\]\\s\\x22([^\\x22]*)\\x22\\s)";
	private static final String PRODUCT_REGEX = "(\\s\\w+:\\s\\[{1})";
	private static final String PROXY_IP_REGEX = "(\\d+\\.\\d+\\.\\d+\\.\\d+)";
	private static final String SYS_LOG_REGEX = "^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)";
	
	private static String log; 
//	private static String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\""; 
	
	public static LogGettersSetters l1 = new LogGettersSetters();
	
	//		KONSTRUKTOR--------S
	logRegexObj(String log) {
		this.log = log;
	}
	
	
	//-----------USEFUL METHODS---------
	private String FindAndClean(Matcher matcher, String result) {
		try {
		        if(matcher.find())
		            result = matcher.group(1);
		        if(!result.equals("\"\""))					// remove unnecessary tags ""
					result = result.replaceAll("\"", "");      
		  }catch(IllegalStateException isEx) {
			  System.out.println("NOT FOUND MATCH! "+isEx);  
		  }
		return result;
	}
	
	//-----------MAIN METHODS---------
	
	public void setValues() {
		l1.setSysLogTimeStamp1(sysLogTimeStamp1(log));
		l1.setProxyIP(proxyIP(log));
		l1.setProduct(product(log));
		//
		l1.setUser(user(log));
		l1.setSourceIP(sourceIP(log));
		//
		l1.setHttpMethod(httpMethod(log));
		l1.setHttpProtocol(httpMethod(log));
		//
		l1.setHttpVersion(httpVersion(log));
		l1.setHttpCategory(httpCategory(log));
		l1.setRisk(risk(log));
		l1.setHttpContentType(httpContentType(log));
		l1.setBytesIN(bytesIN(log));
		//
		//
		l1.setSignature(signature(log));
		l1.setAction(action(log));
		l1.setBlockResult(blockResult(log));
		l1.setCustomRuleName(customRuleName(log));
		l1.setDestIP(destIP(log));
		l1.setHttpReferrer(httpReferrer(log));
	}
	
	public void getValues() {
		System.out.println(l1.getSysLogTimeStamp1());
		System.out.println(l1.getProxyIP());
		System.out.println(l1.getProduct());
		
		System.out.println(l1.getUser());
		System.out.println(l1.getSourceIP());
		
		System.out.println(l1.getHttpVersion());
		System.out.println(l1.getHttpCategory());
		System.out.println(l1.getRisk());
		System.out.println(l1.getHttpContentType());
		System.out.println(l1.getBytesIN());
		
		
		System.out.println(l1.getSignature());
		System.out.println(l1.getAction());
		System.out.println(l1.getBlockResult());
		System.out.println(l1.getCustomRuleName());
		System.out.println(l1.getDestIP());
		System.out.println(l1.getHttpReferrer());
		
	}
	
	 public String sysLogTimeStamp1(String log) {
		 
	       Pattern sysLogPattern = Pattern.compile(SYS_LOG_REGEX);
	       Matcher matcher = sysLogPattern.matcher(log);
	       String result = null;
	       
		      result = FindAndClean(matcher, result);
	      
	       return result;   
	    }
	
	//-----------------------------------------------
	
	public String proxyIP(String log) {
		
		Pattern proxyIPPattern = Pattern.compile(PROXY_IP_REGEX);
	    Matcher matcher = proxyIPPattern.matcher(log);
	    String result = null;
	       
		      result = FindAndClean(matcher, result);
	      
	    return result; 
		
	}
	
	//-----------------------------------------------
	
	public String product(String log) {
		 
		Pattern productPattern = Pattern.compile(PRODUCT_REGEX);
		
		Matcher matcher = productPattern.matcher(log);
		
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
    
	    return result; 
	}
	
	//-----------------------------------------------
	
/*	public String eventTimeStamp(String log) {
		 
		Pattern eventTimeStampPattern = Pattern.compile("(\\s\\[([^\\]]+)\\])");
	    Matcher matcher = eventTimeStampPattern.matcher(log);   
	    String result = null;
		       
		result = FindAndClean(matcher, result);
	    
		return result;  
	}*/
	
	public String user(String log) {
		
		Pattern userPattern = Pattern.compile(USER_REGEX);
	    Matcher matcher = userPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result;  
	}
	
	public String sourceIP(String log) {
		 
		Pattern IPPattern = Pattern.compile(SOURCE_IP_REGEX);
		Matcher matcher = IPPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
	}

/*	public String status(String log) {
		 
		String result;
		Pattern IPPattern = Pattern.compile("(\\s\\d{3}\\s)");
		
	      Matcher matcher = IPPattern.matcher(log);
			
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}*/
	
	public String httpMethod(String log) {
		 
		Pattern methodPattern = Pattern.compile(HTTP_METHOD_REGEX);
		Matcher matcher = methodPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
	}
	
	public String httpProtocol(String log) {
		 
		Pattern protocolPattern = Pattern.compile(HTTP_PROTOCOL_REGEX);
		Matcher matcher = protocolPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
	}
	
	/*public String url(String log) {						// BRAK REGEXA!!!!!!!!!!!!!!!!!!
		 
		String result;
		Pattern urlPattern = Pattern.compile("(\\S+:)");
		
	      Matcher matcher = urlPattern.matcher(log);
			
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}*/
	
	public String httpVersion(String log) {
		 
		Pattern versionPattern = Pattern.compile(HTTP_VERSION_REGEX);
		Matcher matcher = versionPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
		}
	
	
	public String httpCategory(String log) {					//ZADZIALA TYLKO Z findFirstText
		 															//log.replaceAll("/", "znak");
		Pattern versionPattern = Pattern.compile(HTTP_CATEGORY_REGEX);
		Matcher matcher = versionPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
		}
	
	public String risk(String log) {
		 									
		Pattern riskPattern = Pattern.compile(RISK_REGEX);
		Matcher matcher = riskPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result; 
		}
	
	public String httpContentType(String log) {								
		 
		Pattern contentTypePattern = Pattern.compile(HTTP_CONTENT_TYPE_REGEX);
		Matcher matcher = contentTypePattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result);
  
	    return result;  
		}
	
	public String bytesIN(String log) {											
		 
		Pattern bytesINPattern = Pattern.compile(BYTES_IN_REGEX);
		Matcher matcher = bytesINPattern.matcher(log);
			
		String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		return result;  
		}
	
	/*public String bytesOUT(String log) {											// BRAK REGEXA
		 
		String result;
		Pattern bytesOUTPattern = Pattern.compile("(\\s\\d+\\s\\x22)");
		
	      Matcher matcher = bytesOUTPattern.matcher(log);
			
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}*/
	
/*	public String httpUserAgent(String log) {
		 
		String result;
		Pattern userAgentPattern = Pattern.compile("(^\\x22)\\w");
		
	      Matcher matcher = userAgentPattern.matcher(log);
			
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}*/
	
	public String signature(String log) {
		 
		Pattern signaturePattern = Pattern.compile(SIGNATURE_REGEX);
		Matcher matcher = signaturePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result; 
		}
	
	public String action(String log) {
		 
		Pattern actionPattern = Pattern.compile(ACTION_REGEX);
		Matcher matcher = actionPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result; 
		}
	
	public String blockResult(String log) {
		 
		Pattern ruleNamePattern = Pattern.compile(SIGNATURE_REGEX);
		Matcher matcher = ruleNamePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result;   
		}
	
	public String customRuleName(String log) {										//BRAK REGEX
		 
		Pattern ruleNamePattern = Pattern.compile(CUSTOM_RULE_NAME_REGEX);
		Matcher matcher = ruleNamePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result; 
		}
	
	public String destIP(String log) {
		 
		Pattern destIPPattern = Pattern.compile(DEST_IP_REGEX);
		Matcher matcher = destIPPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result;  
		}
	
	public String httpReferrer(String log) {
		 
		Pattern referrerPattern = Pattern.compile(HTTP_REFERRER_REGEX);
		Matcher matcher = referrerPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result);
	    
		    return result;  
		}
	
	
	public static void main(String[] args) {
		
		String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
		logRegexObj log1 = new logRegexObj(log);
		
		log1.setValues();
		
		System.out.println(l1.getSysLogTimeStamp1());
		System.out.println(l1.getProxyIP());
		System.out.println(l1.getProduct());
		System.out.println(l1.getEventTimeStamp());
		System.out.println(l1.getUser());
		System.out.println(l1.getSourceIP());
		System.out.println(l1.getStatus());
		System.out.println(l1.getHttpMethod());			
		System.out.println(l1.getHttpProtocol());
		System.out.println(l1.getUrl());					
		System.out.println(l1.getHttpVersion());
		System.out.println(l1.getHttpCategory());
		System.out.println(l1.getRisk());
		System.out.println(l1.getHttpContentType());			
		System.out.println(l1.getBytesIN());
		System.out.println(l1.getBytesOUT());
		System.out.println(l1.getHttpUserAgent());			// DYNAMIC VALUE! (TODO)
		System.out.println(l1.getSignature());
		System.out.println(l1.getAction());
		System.out.println(l1.getBlockResult());
		System.out.println(l1.getCustomRuleName());
		System.out.println(l1.getDestIP());
		System.out.println(l1.getHttpReferrer());
		
	}

	public String eventTimeStamp(String log) {
		// TODO Auto-generated method stub
		return null;
	}

	public String status(String log) {
		// TODO Auto-generated method stub
		return null;
	}

	public String url(String log) {
		// TODO Auto-generated method stub
		return null;
	}

	public String bytesOUT(String log) {
		// TODO Auto-generated method stub
		return null;
	}

	public String httpUserAgent(String log) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
	
	
	}
