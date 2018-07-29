public class caseReassignmentPostScan {
	/*

	NOTE: The logic in this class can be modified to fit your organization.
	This class works if you have the same setup as described below.

	Required setup for this class:

	 - Create a new field on Case called Bypass Assignment Rule 1 (Boolean)
	 - Update Assignment rules as follows:
		- First rule, set Bypass Assignment Rule 1 to FALSE
		- All other rules, set Bypass Assignment Rule 1 to TRUE
	 - Create a new queue called No Man's Queue
	 	- Update the NoManQueueID based on your Queue

	Setting the above structure will allow you to have all of your cases
	first be processed by the scanURLs class before allowing users 
	access to the cases.
	*/

	// populate with the Queue Id for removing the case from view
	Static String NoManQueueID = '00G1H000003tjKj';

	// resend case through the assignment rules
	public static void casePassAssignmentRule(ID caseId) {
		if (caseId == NULL){
			return;
		}

		Case cseObj = [SELECT Id FROM Case WHERE ID =: caseId LIMIT 1];
		//set Bypass Assignment Rule field to True to bypass the holding queue
		cseObj.Bypass_Assignment_Rule_1__c = True;

		Database.DMLOptions dmo = new Database.DMLOptions();
		try {
			dmo.assignmentRuleHeader.useDefaultRule = true;
        	cseObj.setOptions(dmo);
        	update cseObj;
		}
		catch (system.DmlException e) {
			system.debug('ERROR:' + e);
			system.debug('getMessage: ' + e.getMessage());
		}        
	}
	
	// moves the case to NoManQueue
	public static void caseMovetoNoManView(ID caseId) {
		if (caseId == NULL){
			return;
		}

		Case cseObj = [SELECT Id FROM Case WHERE ID =: caseId LIMIT 1];
		try {
			cseObj.OwnerId = NoManQueueID;
			update cseObj;
		}
		catch (system.DmlException e) {
			system.debug('ERROR:' + e);
			system.debug('getMessage: ' + e.getMessage());
		}
	}
}