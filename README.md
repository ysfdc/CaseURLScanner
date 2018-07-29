## Overview and Business Case: 


## Usage and Pre-reqs
* In order for this class to run, you will need to get an API Key from VirusTotal
	* https://www.virustotal.com/en/documentation/public-api/
	* Update VIRUS_TOTAL_API_KEY to your VirusTotal API Key
* Setting the below structure will allow you to have all of your cases
	first be processed by the scanURLs class before allowing users 
	access to the cases.

	 *Create a new field on Case called Bypass Assignment Rule 1 (Boolean)
	 *Update Assignment rules as follows:
		*First rule, set Bypass Assignment Rule 1 to FALSE
		*All other rules, set Bypass Assignment Rule 1 to TRUE
	 *Create a new queue called No Man's Queue
	 	*Update the NoManQueueID based on your Queue


## caseTrigger.Trigger

A logicless trigger for Case designed to call the Case Handler Class
Only runs on After Insert

## CaseTriggerHandler.cls

The description field of the case is checked to see if there are any URLs.
If no URLs are found, the case is immediately sent back through to the Assignment Rules. 
If a URL is found, the scanURLs class is called.

## ExtractURLs.cls
This class uses a regular expression to parse through the text to see if anything matches the format of a URL. 
If a URL is found it then passes that information back to the CaseTriggerHandler.

## scanURLs.cls
This class is used to call out to VT and any additional scanner you want to add.
In this class you need to update the API Key and the Threshold value.
The Threshold value is the numeric value you determine as minimum number of positives to deem the URL malicious.

##caseReassignmentPostScan.cls
This class is used to either move the case back through the assignment rules if clean or
move the case a No Man's Queue for further evaluation.
