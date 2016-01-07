package net.floodlightcontroller.sos;

import java.util.Set;
import java.util.UUID;

import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSAgentSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSAgentSerializer.class)
public interface ISOSAgent extends ISOSDevice {
	/**
	 * Retrieve the TCP port the agent listens on
	 * for client/server TCP data.
	 * @return
	 */
	public TransportPort getDataPort();
	
	/**
	 * Retrieve the UDP port the agent listens on
	 * for commands from the controller.
	 * @return
	 */
	public TransportPort getControlPort();
	
	/**
	 * Retrieve the UDP port the agent sends
	 * to for commands/information to the controller.
	 * @return
	 */
	public TransportPort getFeedbackPort();

	/**
	 * Retrieve the UDP port the agent sends
	 * to for transfer statistics to the controller.
	 * @return
	 */
	public TransportPort getStatsPort();
	
	/**
	 * Retrieve all SOS sessions that are ongoing
	 * for this particular agent.
	 * @return
	 */
	public Set<UUID> getActiveTransfers();
}