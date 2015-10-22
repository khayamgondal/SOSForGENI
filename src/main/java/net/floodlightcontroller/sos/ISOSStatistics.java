package net.floodlightcontroller.sos;

import java.util.Collection;

import net.floodlightcontroller.sos.web.SOSStatisticsSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSStatisticsSerializer.class)
public interface ISOSStatistics {
		
	public Collection<ISOSWhitelistEntry> getWhitelistEntries();
	
	public Collection<ISOSConnection> getActiveConnections();
	
	public Collection<ISOSConnection> getTerminatedConnections();
	
	public Collection<ISOSAgent> getAgents();
}