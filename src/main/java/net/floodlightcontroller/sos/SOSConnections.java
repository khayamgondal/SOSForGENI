package net.floodlightcontroller.sos;

import java.util.ArrayList;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

public class SOSConnections  {

	private static ArrayList<SOSConnection> CONNECTIONS = null;
	
	public SOSConnections() {
		if (CONNECTIONS == null) {
			CONNECTIONS = new ArrayList<SOSConnection>();
		}
	}
	
	/**
	 * Add a new SOS connection. Should only be invoked when handling the
	 * initial TCP packet from the client to the server.
	 * @param clientToAgent
	 * @param interAgent
	 * @param serverToAgent
	 * @param clientPort
	 * @param serverPort
	 * @param numSockets
	 * @param queueCapacity
	 * @param bufferSize
	 * @return
	 */
	public SOSConnection addConnection(SOSRoute clientToAgent, SOSRoute interAgent,
			SOSRoute serverToAgent, int numSockets, 
			int queueCapacity, int bufferSize) {
		CONNECTIONS.add(new SOSConnection(clientToAgent, interAgent,
				serverToAgent, numSockets,
				queueCapacity, bufferSize)); 
		return getConnectionFromIP(clientToAgent.getSrcDevice().getIPAddr(), ((SOSClient) clientToAgent.getSrcDevice()).getTcpPort());
	}
	
	/**
	 * Remove a terminated connection based on the server or client
	 * IP address and TCP port
	 * @param ip
	 * @param port
	 * @return
	 */
	public boolean removeConnection(IPv4Address ip, OFPort port) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getClient().getIPAddr().equals(ip) && conn.getClient().getTcpPort().equals(port) ||
					conn.getServer().getIPAddr().equals(ip) && conn.getServer().getTcpPort().equals(port)) {
				CONNECTIONS.remove(conn);
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Lookup an ongoing connection based on the server or client
	 * IP address and TCP port
	 * @param ip
	 * @param port
	 * @return
	 */
	public SOSConnection getConnectionFromIP(IPv4Address ip, TransportPort port) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getClient().getIPAddr().equals(ip) && conn.getClient().getTcpPort().equals(port)) {
				return conn;
			} else if (conn.getServer().getIPAddr().equals(ip) && conn.getServer().getTcpPort().equals(port)) {
				return conn;
			}
		}
		return null;
	}
	
	/**
	 * Based on the src/dst IP addresses and TCP port numbers of
	 * a packet, try to find out where in an SOS connection it
	 * belongs.  
	 * @param srcIP
	 * @param dstIP
	 * @param srcPort
	 * @param dstPort
	 * @return
	 */
	public SOSPacketStatus getSOSPacketStatus(IPv4Address srcIP, IPv4Address dstIP, TransportPort srcPort, TransportPort dstPort) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getClient().getIPAddr().equals(srcIP) && conn.getServer().getTcpPort().equals(dstPort) && /* don't know the source transport port in conn */
					conn.getServer().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.INACTIVE_REGISTERED;
				
			} else if (conn.getClient().getIPAddr().equals(srcIP) && conn.getClient().getTcpPort().equals(srcPort) ) {
				
				return SOSPacketStatus.ACTIVE_CLIENT_TO_CLIENT_SIDE_AGENT;
				
			} else if (conn.getServer().getIPAddr().equals(srcIP) && conn.getServer().getTcpPort().equals(srcPort)) {
				
				return SOSPacketStatus.ACTIVE_SERVER_TO_SERVER_SIDE_AGENT;
				
			} else if (conn.getServer().getIPAddr().equals(dstIP) && conn.getServer().getTcpPort().equals(dstPort) &&
					conn.getServerSideAgent().getIPAddr().equals(srcIP)) {
				
				return SOSPacketStatus.ACTIVE_SERVER_SIDE_AGENT_TO_SERVER;
				
			} else if (conn.getClient().getIPAddr().equals(dstIP) && conn.getClient().getTcpPort().equals(dstPort) && 
					conn.getClientSideAgent().getIPAddr().equals(srcIP)) {
				
				return SOSPacketStatus.ACTIVE_CLIENT_SIDE_AGENT_TO_CLIENT;
				
			} else if (conn.getClientSideAgent().getIPAddr().equals(srcIP) && conn.getServerSideAgent().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.ACTIVE_CLIENT_SIDE_AGENT_TO_SERVER_SIDE_AGENT;
				
			} else if (conn.getServerSideAgent().getIPAddr().equals(srcIP) && conn.getClientSideAgent().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.ACTIVE_SERVER_SIDE_AGENT_TO_CLIENT_SIDE_AGENT;
			}
		}
		return SOSPacketStatus.INACTIVE_UNREGISTERED;
	}
}