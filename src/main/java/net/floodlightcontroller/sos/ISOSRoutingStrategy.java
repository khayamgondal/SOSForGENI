package net.floodlightcontroller.sos;

import java.util.Set;

public interface ISOSRoutingStrategy {
	/**
	 * Push a route according to the underlying strategy.
	 * @param route
	 * @param conn
	 * @return names of the flows pushed
	 */
	public Set<String> pushRoute(SOSRoute route, SOSConnection conn);
}
