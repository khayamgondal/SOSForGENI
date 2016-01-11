package net.floodlightcontroller.sos;

import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Queue;
import java.util.Set;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.sos.web.SOSStatisticsSerializer;

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
@JsonSerialize(using=SOSStatisticsSerializer.class)
public class SOSStatistics implements ISOSStatistics {
	private static SOSStatistics instance;
	private Set<ISOSAgent> agents;
	private Set<ISOSWhitelistEntry> registered;
	private Set<ISOSConnection> active;
	private Queue<ISOSConnection> terminated;
	private int terminatedCapacity;
	
	private SOSStatistics(int oldCapacity) {
		agents = new HashSet<ISOSAgent>();
		registered = new HashSet<ISOSWhitelistEntry>();
		active = new HashSet<ISOSConnection>();
		terminatedCapacity = oldCapacity;
		terminated = new ArrayDeque<ISOSConnection>(terminatedCapacity);
	}
	
	public static SOSStatistics getInstance(int oldCapacity) {
		if (instance == null) {
			instance = new SOSStatistics(oldCapacity);
		}
		return instance;
	}
	
	public void addWhitelistEntry(ISOSWhitelistEntry entry) {
		registered.add(entry);
	}
	
	public void removeWhitelistEntry(ISOSWhitelistEntry entry) {
		registered.remove(entry);
	}
	
	@Override
	public Set<ISOSWhitelistEntry> getWhitelistEntries() {
		return Collections.unmodifiableSet(registered);
	}
		
	public void addActiveConnection(ISOSConnection conn) {
		active.add(conn);
	}
	
	public boolean removeActiveConnection(ISOSConnection conn) {
		if (terminated.size() == terminatedCapacity) {
			terminated.poll(); /* trash oldest */
		}
		terminated.add(conn);
		return active.remove(conn);
	}
	
	@Override
	public Collection<ISOSConnection> getActiveConnections() {
		return Collections.unmodifiableCollection(active);
	}
	
	public void addAgent(ISOSAgent agent) {
		agents.add(agent);
	}
	
	public void removeAgent(ISOSAgent agent) {
		agents.remove(agent);
	}
	
	public void clear() {
		active.clear();
		terminated.clear();
	}
	
	@Override
	public Collection<ISOSAgent> getAgents() {
		return Collections.unmodifiableCollection(agents);
	}

	@Override
	public Collection<ISOSConnection> getTerminatedConnections() {
		return Collections.unmodifiableCollection(terminated);
	}
}