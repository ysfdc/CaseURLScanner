@isTest
global class VTMockClassTestNegativeResponse implements HttpCalloutMock {

    global HTTPResponse respond(HTTPRequest req) {
         // Create a fake response
        HttpResponse res = new HttpResponse();
        res.setHeader('Content-Type', 'application/json');
        res.setBody('{"response_code": 1, "positives": 0,  "resource": "www.example.com", "verbose_msg": "Resource does not exist in the dataset"}');
        res.setStatusCode(200);
        return res;
    }
}