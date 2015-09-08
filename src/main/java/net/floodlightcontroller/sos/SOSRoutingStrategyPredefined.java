package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.DatapathId;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class SOSRoutingStrategyPredefined implements ISOSRoutingStrategy {

	private DatapathId redirectionSwitch;
	private DatapathId rewriteSwitch;
	private boolean macRewriteUponRedirection;
	public SOSRoutingStrategyPredefined(DatapathId redirectionSwitch, DatapathId rewriteSwitch, boolean macRewriteUponRedirection) {
		this.redirectionSwitch = redirectionSwitch;
		this.rewriteSwitch = rewriteSwitch;
		this.macRewriteUponRedirection = macRewriteUponRedirection;
	}
	
	@Override
	public void pushRoute(SOSRoute route, SOSConnection conn) {
		throw new NotImplementedException();
	}
}
