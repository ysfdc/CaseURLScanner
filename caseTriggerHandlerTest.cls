@isTest
private class caseTriggerHandlerTest {
	
	//tests case with number of positives greater than the threshold
	//expected result: case moves to No Man's Queue
	@isTest static void caseWithUrlMalicious() {

		//create case record with a malicious url in the body
		Case caseTest = new Case(
        Subject='Test record',
        Status='New',
        Origin='Phone',
        Priority='Medium',
        Description='This is the body with bad URL www.google.com',
        OwnerId = '00G1H000003tjKe');
        	
        insert caseTest;

        Set<String> urlSet = new Set<String>{'www.google.com', 'www.example.com'};

        Test.setMock(HttpCalloutMock.class, new VTMockClassTestPositiveResponse());	
        Test.startTest();
        scanURLS.checkURLMalicious(urlSet, caseTest.Id);
        Test.stopTest();

        Case caseOwner = [Select id, OwnerId from Case where Id=: caseTest.Id];
        system.assertEquals('00G1H000003tjKjUAI', caseOwner.OwnerId);
    }

    //tests case with number of positives less than the threshold
    //expected result: case moves to general queue
	@isTest (seeAllData=true) static void caseWithUrlGood() {

		//create case record with a malicious url in the body
		Case caseTest = new Case(
        Subject='Test record',
        Status='New',
        Origin='Phone',
        Priority='Medium',
        Description='This is the body with good URL www.test.com',
        OwnerId = '00G1H000003tjKe'
        );
        	
        insert caseTest;

        Set<String> urlSet = new Set<String>{'www.test.com', 'www.example.com'};

        Test.setMock(HttpCalloutMock.class, new VTMockClassTestNegativeResponse());
        Test.startTest();
        scanURLS.checkURLMalicious(urlSet, caseTest.Id);
        Test.stopTest();

        Case caseOwner = [Select id, OwnerId from Case where Id=: caseTest.Id];
        system.assertEquals('00G1H000003tjKy', caseOwner.OwnerId);
	}

	//tests case with url not found in the system
	//expected result: case moves to general queue
	@isTest static void CaseWithNoResponse() {

		//create case record with a malicious url in the body
		Case caseTest = new Case(
        Subject='Test record',
        Status='New',
        Origin='Phone',
        Priority='Medium',
        Description='This is the body with unknown URL www.test.com',
        OwnerId = '00G1H000003tjKe'
        );
        	
        insert caseTest;

        Set<String> urlSet = new Set<String>{'www.test.com', 'www.test.com'};

        Test.setMock(HttpCalloutMock.class, new VTMockClassTestZeroResponse());
        Test.startTest();
        scanURLS.checkURLMalicious(urlSet, caseTest.Id);
        Test.stopTest();

        Case caseOwner = [Select id, OwnerId from Case where Id=: caseTest.Id];
        system.assertEquals('00G1H000003tjKy', caseOwner.OwnerId);
	}

	//create case record with no urls in the body
	//expected result: case moves to general queue
	@isTest static void caseWithNoUrls() {
		Case caseTest = new Case(
            Subject='Test record',
            Status='New',
            Origin='Phone',
            Priority='Medium',
            Description='This is the body with no URL');
        	insert caseTest;
        	
        	Case caseOwner = [Select id, OwnerId from Case where Id=: caseTest.Id];
        	system.assertEquals('00G1H000003tjKy', caseOwner.OwnerId);
	}
	
}