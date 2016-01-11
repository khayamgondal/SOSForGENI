package net.floodlightcontroller.sos;

import java.util.Set;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface ISOSService extends IFloodlightService {
	
	public enum SOSReturnCode {
		WHITELIST_ENTRY_ADDED, WHITELIST_ENTRY_REMOVED,
		ERR_DUPLICATE_WHITELIST_ENTRY, ERR_UNKNOWN_WHITELIST_ENTRY,
		AGENT_ADDED, AGENT_REMOVED,
		ERR_DUPLICATE_AGENT, ERR_UNKNOWN_AGENT,
		ENABLED, DISABLED,
		CONFIG_SET,
		READY, NOT_READY,
		STATS_CLEARED
	}

	/**
	 * Add a new agent to SOS.
	 * @param json
	 * @return
	 */
	public SOSReturnCode addAgent(ISOSAgent agent);
	
	/**
	 * Remove an SOS agent from SOS. Any active SOS
	 * sessions will not be impacted. The agent will
	 * not be available to future SOS sessions.
	 * @param agent
	 * @return
	 */
	public SOSReturnCode removeAgent(ISOSAgent agent);
	
	/**
	 * Get the current agents configured for use by SOS.
	 * @return
	 */
	public Set<? extends ISOSAgent> getAgents();
	
	/**
	 * Proactively add someone to the SOS whitelist . Any future 
	 * packets matching this entry will be handled by SOS.
	 * @param entry
	 * @return
	 */
	public SOSReturnCode addWhitelistEntry(ISOSWhitelistEntry entry);
	
	/**
	 * Remove a whitelist entry from SOS. Any active SOS sessions
	 * will not be impacted.
	 * @param entry
	 * @return
	 */
	public SOSReturnCode removeWhitelistEntry(ISOSWhitelistEntry entry);
	
	/**
	 * Retrieve the currently-configured whitelist entries.
	 * @return
	 */
	public Set<? extends ISOSWhitelistEntry> getWhitelistEntries();
	
	/**
	 * Enable SOS
	 * @return
	 */
	public SOSReturnCode enable();
	
	/**
	 * Disable SOS
	 * @return
	 */
	public SOSReturnCode disable();
	
	/**
	 * Check if the SOS module is enabled.
	 * @return
	 */
	public boolean isEnabled();
	
	/**
	 * Query for SOS running statistics. This includes the running configuration
	 * @return
	 */
	public ISOSStatistics getStatistics();
	
	/**
	 * Clear SOS running statistics.
	 * @return
	 */
	public SOSReturnCode clearStatistics();
	
	/**
	 * Configure flow timeouts
	 * @param hardSeconds
	 * @param idleSeconds
	 * @return
	 */
	public SOSReturnCode setFlowTimeouts(int hardSeconds, int idleSeconds);
	
	/**
	 * Retrieve the configured flow idle timeout
	 * @return
	 */
	public int getFlowIdleTimeout();
	
	/**
	 * Retrieve the configured flow hard timeout
	 * @return
	 */
	public int getFlowHardTimeout();
	
	/**
	 * Configure number of parallel connections to use between agents
	 * for a single SOS session
	 * @param num
	 * @return
	 */
	public SOSReturnCode setNumParallelConnections(int num);
	
	/**
	 * Retrieve the number of parallel connections
	 * @return
	 */
	public int getNumParallelConnections();
	
	/**
	 * Configure the size of the agent's RX buffer to store data
	 * transmitted from the server to the server-side agent
	 * @param bytes
	 * @return
	 */
	public SOSReturnCode setBufferSize(int bytes);
	
	/**
	 * Retrieve the size of the agent's RX buffer
	 * @return
	 */
	public int getBufferSize();
	
	/**
	 * Configure the size of the queue for each parallel socket
	 * @param packets
	 * @return
	 */
	public SOSReturnCode setQueueCapacity(int packets);
	
	/**
	 * Retrieve the size of the queue for each parallel socket
	 * @return
	 */
	public int getQueueCapacity();
	
	/**
	 * Check if SOS is able to handle an additional data transfer
	 * at this moment in time. This is a poll operation and does not
	 * guarantee resource availability. A time-based whitelist entry
	 * should be used to guarantee service availability during a 
	 * particular time.
	 * @return
	 */
	public SOSReturnCode ready();
}