package net.floodlightcontroller.sos;

/**
 * This enum defines the types of packets the controller can receive wrt SOS.
 * Under normal circumstances, the controller should only receive packets
 * matching:
 * 		INACTIVE_REGISTERED
		INACTIVE_UNREGISTERED
		ACTIVE_DST_AGENT_TO_DST_CLIENT
 * 
 * The first two are for packets detected that can be sent to a nearby SOS agent
 * to facilitate a new SOS connection. The last is when a destination agent
 * sends its first packet to the intended destination client. There are no flows
 * present for this packet, since we need to learn the L4 port number of the
 * destination agent. Once this port number is learned, flows should be inserted,
 * and all subsequent packets in either direction should match flows.
 * 
 * Any other value within this enum should only be associated with a PACKET_IN packet
 * to the controller if an error has occurred. These values are returned from the
 * method isPacketMemberOfActiveConnection() within class SOSActiveConnections.
 * 
 * @author rizard
 *
 */

public enum SOSPacketStatus {
		INACTIVE_REGISTERED,
		INACTIVE_UNREGISTERED,
		ACTIVE_SRC_CLIENT_TO_SRC_AGENT,
		ACTIVE_SRC_AGENT_TO_SRC_CLIENT,
		ACTIVE_SRC_AGENT_TO_DST_AGENT,
		ACTIVE_DST_AGENT_TO_SRC_AGENT,
		ACTIVE_DST_CLIENT_TO_DST_AGENT,
		ACTIVE_DST_AGENT_TO_DST_CLIENT
}