package net.floodlightcontroller.sos;

public interface ISOSRoutingStrategy {
	/**
	 * Push a route according to the underlying strategy.
	 * @param route
	 * @param conn
	 */
	public void pushRoute(SOSRoute route, SOSConnection conn);
}
