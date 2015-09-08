package net.floodlightcontroller.sos;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface ISOSService extends IFloodlightService {
	
	public enum SOSReturnCode {
		CLIENT_ADDED, CLIENT_REMOVED,
		ERR_DUPLICATE_CLIENT, ERR_UNKNOWN_CLIENT,
		AGENT_ADDED, AGENT_REMOVED,
		ERR_DUPLICATE_AGENT, ERR_UNKNOWN_AGENT,
		ENABLED, DISABLED,
	}

	/**
	 * Add a new agent to SOS.
	 * @param json
	 * @return
	 */
	public SOSReturnCode addAgent(SOSAgent agent);
	
	/**
	 * Remove an SOS agent from SOS. Any active SOS
	 * sessions will not be impacted. The agent will
	 * not be available to future SOS sessions.
	 * @param agent
	 * @return
	 */
	public SOSReturnCode removeAgent(SOSAgent agent);
	
	/**
	 * Proactively add a client to SOS. Any future packets
	 * matching this client will be handled by SOS.
	 * @param client
	 * @return
	 */
	public SOSReturnCode addClient(SOSClient client);
	
	/**
	 * Remove a client from SOS. Any active SOS sessions
	 * will not be impacted. The client will not be
	 * whitelisted for any future packets not presently
	 * part of a client's active SOS session.
	 * @param client
	 * @return
	 */
	public SOSReturnCode removeClient(SOSClient client);
	
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
	public SOSStatistics getStatistics();
	
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
}
