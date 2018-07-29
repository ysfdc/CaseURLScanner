trigger caseTrigger on case (after insert) {

	CaseTriggerHandler cth = new CaseTriggerHandler(Trigger.newMap);
	cth.handleTrigger();
}