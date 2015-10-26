package net.floodlightcontroller.sos;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface ISOSService extends IFloodlightService {
	
	public enum SOSReturnCode {
		WHITELIST_ENTRY_ADDED, WHITELIST_ENTRY_REMOVED,
		ERR_DUPLICATE_WHITELIST_ENTRY, ERR_UNKNOWN_WHITELIST_ENTRY,
		AGENT_ADDED, AGENT_REMOVED,
		ERR_DUPLICATE_AGENT, ERR_UNKNOWN_AGENT,
		ENABLED, DISABLED,
		CONFIG_SET,
		READY, NOT_READY
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
	 * Query for SOS running statistics. This includes the running configuration
	 * @return
	 */
	public ISOSStatistics getStatistics();
	
	/**
	 * Configure flow timeouts
	 * @param hardSeconds
	 * @param idleSeconds
	 * @return
	 */
	public SOSReturnCode setFlowTimeouts(int hardSeconds, int idleSeconds);
	
	/**
	 * Configure number of parallel connections to use between agents
	 * for a single SOS session
	 * @param num
	 * @return
	 */
	public SOSReturnCode setNumParallelConnections(int num);
	
	/**
	 * Configure the size of the agent's RX buffer to store data
	 * transmitted from the server to the server-side agent
	 * @param bytes
	 * @return
	 */
	public SOSReturnCode setBufferSize(int bytes);
	
	/**
	 * Configure the size of the queue for each parallel socket
	 * @param packets
	 * @return
	 */
	public SOSReturnCode setQueueCapacity(int packets);
	
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
