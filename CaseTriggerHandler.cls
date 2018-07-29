public class CaseTriggerHandler {
	
	//store Trigger.newMap
	Map<Id, Case> newCases;
	
	/*
	Class Constructor

	@param newTriggerCase
	Map between Id and Case for new values
	*/
	public CaseTriggerHandler (Map<Id,Case> newTriggerCase) {
		newCases = newTriggerCase;
	}

	/*
	Parses the body of the case to determine if there are any URLs.
	If there is at least 1 URL, then it will proceed to scan them
	*/
	public void handleTrigger() {
        scanURLS newScan = new scanURLS();
		for (Case cse : newCases.values()) {
			Id caseID = cse.Id;
			String bodyOfCase = cse.description;
			
			//call the regular expression module to extract URLs
			//keep unique URLs only after extraction
			List<String> urls = ExtractURLs.ParseText(bodyOfCase);
			Set<String> urlsList = new Set<String>(urls);
			
			// re-do assignment rules if no urls in case
			if (urlsList.isEmpty()) {
				system.debug('No URLS were found in this case');
				caseReassignmentPostScan.casePassAssignmentRule(caseID);
				continue;
			}

			//if URLs were found, check for malicious URLs
			scanURLS.checkURLMalicious(urlsList, caseID);	
		}
	}
}