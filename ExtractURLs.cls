public class ExtractURLs {

	/* regular expression used to find URL in a body of text */
	public static List<String> ParseText(String regex) {
		// credit to Stackoverflow for the regular expression
		String regexExpression = '(?:^|[\\W])((ht|f)tp(s?):\\/\\/|www\\.)'
                				 + '(([\\w\\-]+\\.){1,}?([\\w\\-.~]+\\/?)*'
                				 + '[\\p{Alnum}.,%_=?&#\\-+()\\[\\]\\*$~@!:/{};\']*)';

		Pattern myPatter = Pattern.compile(regexExpression);
		Matcher myMatch = myPatter.matcher(regex);

		List<String> foundUrls = new List<String>();
		while (myMatch.find()) {
			//system.debug(myMatch.group());
			String matches = myMatch.group();
			foundUrls.add(matches);
			system.debug('what urls were found: ' + foundUrls);
		}
		
		return foundUrls;
	}
}