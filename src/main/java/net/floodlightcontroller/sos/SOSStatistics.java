package net.floodlightcontroller.sos;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Singleton. Keep track of the statistics for SOS. This class
 * maintains only references to the objects it's tracking. As
 * such, any updates to the referenced objects will be reflected
 * here. This also means this class has access to all SOS public
 * and protected methods for the object references held.
 * 
 * Thus, for the integrity of the objects being tracked, only 
 * read operations should be performed here. String representations
 * of the objects will be returned upon a stats query. So, this
 * class does not further expose any object references.
 * 
 * @author Ryan Izard, rizard@g.clemson.edu
 *
 */
public class SOSStatistics {
	private static SOSStatistics instance;
	private Date lastSession;
	private Set<SOSAgent> agents;
	private Set<SOSWhitelistEntry> registered;
	private Set<SOSConnection> active;
	
	private SOSStatistics() {
		lastSession = new Date(0);
		agents = new HashSet<SOSAgent>();
		registered = new HashSet<SOSWhitelistEntry>();
		active = new HashSet<SOSConnection>();
	}
	
	public static SOSStatistics getInstance() {
		if (instance == null) {
			instance = new SOSStatistics();
		}
		return instance;
	}
	
	private void updateLastSessionTime() {
		lastSession.setTime(System.currentTimeMillis());
	}
	
	public String getLastSessionTime() {
		return lastSession.toString();
	}
	
	public void addWhitelistEntry(SOSWhitelistEntry entry) {
		registered.add(entry);
	}
	
	public void removeWhitelistEntry(SOSWhitelistEntry entry) {
		registered.remove(entry);
	}
	
	public Set<String> getWhitelistEntries() {
		Set<String> ret = new HashSet<String>(registered);
		for (SOSWhitelistEntry e : registered) {
			ret.add("");
		}
	}
		
	public void addActiveConnection(SOSConnection conn) {
		if (!active.add(conn)) {
			updateLastSessionTime();
		}
	}
	
	public void removeActiveConnection(SOSConnection conn) {
		active.remove(conn);
	}
	
	public Set<String> getActiveConnections() {
		
	}
	
	public void addAgent(SOSAgent agent) {
		agents.add(agent);
	}
	
	public void removeAgent(SOSAgent agent) {
		agents.remove(agent);
	}
	
	public Set<String> getAgents() {
		
	}
}
