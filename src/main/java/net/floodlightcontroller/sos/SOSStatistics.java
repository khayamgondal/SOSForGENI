package net.floodlightcontroller.sos;

import java.util.Date;
import java.util.Set;

public class SOSStatistics {
	private Date lastConnection;
	private int numTotalConnections;
	private int numActiveConnections;
	private Set<SOSAgent> agents;
	private Set<SOSClient> clients; /* does not include any servers */
	
}
