public class scanURLS {

	//set the API Key for Virus Total
	Static String VIRUS_TOTAL_API_KEY = '';
	//Virus Total endpoint for URL reports
	Static String VIRUS_TOTAL_ENDPOINT = 'http://www.virustotal.com/vtapi/v2/url/report';
	//set the minimum number of positives required for url to be considered malicious
	Static Integer VT_THRESHOLD = 10;

	public void setVTThreshold(Integer threshold) {
		VT_THRESHOLD = threshold;
	}

	/*
	future method to call URL scanners

	@param urlList
	set of URLs to be scanned from the case

	@param caseID
	each case Id related to the urlList
	*/
	@future (callout = true)
	public static void checkURLMalicious(Set<String> urlList, ID caseID) {
		if (urlList.isEmpty() || caseID == NULL) {
			return;
		}

		//each URL is passed individually to be respectful of either the public or private API
		for (String singleUrl : urlList) {
			//if any URL for a single case returns True 
			//send the case to the No Man Queue
			if (VTCallout(singleUrl)) {
				system.debug('need to blacklist case');
				//call assignment class to move case to No Man Queue
				caseReassignmentPostScan.caseMovetoNoManView(caseID);
				return;
			}

            /*
                Here's the place to add additional URL scanners
            */
		}

		//if all URLs appear to be clean, push through Case Assignment Rules
		caseReassignmentPostScan.casePassAssignmentRule(caseID);
	}

	/*
	Make a callout to the VirusToal URL report endpoint
	Get the response of the URL and parse to see the number of positive hits
	If the positives are greater than the threshold, Return True
	Otherwise Return False
	*/
	public static boolean VTCallout(String url)
	{
		//encode the url
		String urlEncoded = EncodingUtil.urlEncode(url, 'UTF-8');

		// create the get request
        Http http = new Http();
        HttpRequest request = new HttpRequest();
        request.setEndpoint(VIRUS_TOTAL_ENDPOINT + '?apikey=' + VIRUS_TOTAL_API_KEY + '&resource='  + urlEncoded);
        system.debug(request);
        request.setMethod('GET');
        HttpResponse response;
        
        try {
            response = http.send(request);
        } 
        catch (System.CalloutException e) {
            System.debug('ERROR:' + e);
            System.debug(response.getStatusCode());
            System.debug(response.getStatus());
            return False;
        }

        //check the status code of the response
        if (response.getStatusCode() != 200) {
            system.debug('VT API code != 200 ' + response.getStatusCode());
            return False;
        }

        //parse the JSON response to get the resource code and positives
        Map<String,Object> urlResult = new Map<String,Object>(); 
        try {
        	urlResult = (Map<String, Object>)JSON.deserializeUntyped(response.getBody());
        }
        catch (system.JSONException e) {
        	system.debug('ERROR:' + e);
        	return False;
        }
        
        if (!urlResult.containsKey('response_code')) {
        	system.debug('no response_code field');
        	return False;
        }

        Integer resourceCode = (Integer)urlResult.get('response_code');
        //check if resource_code is 0 which means no results were found for the URL
        if (resourceCode == 0) {
        	system.debug('No Results found in VT');
        	return False;
        }

        if (!urlResult.containsKey('positives')) {
        	system.debug('no positives field in JSON reponse');
        	return False;
        }

        //check if the number of positives is higher 
        //than the threshold to determine if malicious
        Integer countofPositive = (Integer)urlResult.get('positives');
        if (countofPositive > VT_THRESHOLD) {
        	system.debug('Count of positives exceeds threshold');
        	return True;
        }

        return False;
	}
}