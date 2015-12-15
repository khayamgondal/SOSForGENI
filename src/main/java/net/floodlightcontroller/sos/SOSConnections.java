package net.floodlightcontroller.sos;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import net.floodlightcontroller.sos.ISOSService.SOSReturnCode;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SOSConnections  {
	private static final Logger log = LoggerFactory.getLogger(SOSConnections.class);
	private static ArrayList<SOSConnection> connections = null;
	private static Set<ISOSWhitelistEntry> whitelist = null;
	
	public SOSConnections() {
		if (connections == null) {
			connections = new ArrayList<SOSConnection>();
		}
		if (whitelist == null) {
			whitelist = new HashSet<ISOSWhitelistEntry>();
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
			int queueCapacity, int bufferSize,
			int flowTimeout) {
		SOSConnection conn = new SOSConnection(clientToAgent, interAgent,
				serverToAgent, numSockets,
				queueCapacity, bufferSize,
				flowTimeout);
		connections.add(conn); 
		return conn;
	}
	
	/**
	 * Remove a terminated connection based on the transfer ID.
	 * @param uuid
	 * @return
	 */
	public boolean removeConnection(UUID uuid) {
		for (SOSConnection conn : connections) {
			if (conn.getTransferID().equals(uuid)) {
				connections.remove(conn);
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Lookup an ongoing connection based on the dst IP and dst port
	 * (assumed to be the server) and the src IP (assumed to the 
	 * server-side agent).
	 * @param srcIp
	 * @param dstIp
	 * @param dstPort
	 * @return
	 */
	public SOSConnection getConnection(IPv4Address srcIp, IPv4Address dstIp, TransportPort dstPort) {
		for (SOSConnection conn : connections) {
			if (conn.getServer().getIPAddr().equals(dstIp) && conn.getServer().getTcpPort().equals(dstPort) &&
					conn.getServerSideAgent().getIPAddr().equals(srcIp)) {
				return conn;
			}
		}
		return null;
	}
	
	/**
	 * Lookup an ongoing connection based on the transfer ID.
	 * @param uuid
	 * @return
	 */
	public SOSConnection getConnection(UUID uuid) {
		for (SOSConnection conn : connections) {
			if (conn.getTransferID().equals(uuid)) {
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
		for (SOSConnection conn : connections) {
			if (conn.getClient().getIPAddr().equals(srcIP) && conn.getClient().getTcpPort().equals(srcPort) ) {
				
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
		
		for (ISOSWhitelistEntry entry : whitelist) {
			if (entry.getClientIP().equals(srcIP) && entry.getServerPort().equals(dstPort) && /* don't know the source transport port */
					entry.getServerIP().equals(dstIP)) {
				/* We found the packet's headers in our whitelist */
				return SOSPacketStatus.INACTIVE_REGISTERED;
			}
		}
		
		/* If it's not an active connection AND it's not registered, then we'll get here */
		return SOSPacketStatus.INACTIVE_UNREGISTERED;
	}
	
	public SOSReturnCode addWhitelistEntry(ISOSWhitelistEntry entry) {
		if (whitelist.contains(entry)) {
			log.error("Found pre-existing whitelist entry during entry add. Not adding new entry {}", entry);
			return SOSReturnCode.ERR_DUPLICATE_WHITELIST_ENTRY;
		} else {
			log.warn("Whitelist entry {} added.", entry);
			whitelist.add(entry);
			return SOSReturnCode.WHITELIST_ENTRY_ADDED;
		}
	}

	public SOSReturnCode removeWhitelistEntry(ISOSWhitelistEntry entry) {
		if (whitelist.contains(entry)) { 
			whitelist.remove(entry);
			log.warn("Whitelist entry {} removed.", entry);
			return SOSReturnCode.WHITELIST_ENTRY_REMOVED;
		} else {
			log.error("Could not locate whitelist entry {} to remove. Not removing entry.", entry);
			return SOSReturnCode.ERR_UNKNOWN_WHITELIST_ENTRY;
		}
	}
	
	public Set<ISOSWhitelistEntry> getWhitelistEntries() {
		return Collections.unmodifiableSet(whitelist);
	}
}