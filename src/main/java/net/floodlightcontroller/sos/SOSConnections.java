package net.floodlightcontroller.sos;

import java.util.ArrayList;

import org.projectfloodlight.openflow.types.DatapathId;
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
	
	public SOSConnection addConnection(SOSClient srcC, SOSAgent srcA, TransportPort srcP, DatapathId srcNtwkS, DatapathId srcAgentS,
			SOSClient dstC, SOSAgent dstA, TransportPort dstP, DatapathId dstNtwkS, DatapathId dstAgentS, int numSockets, int queueCap, int bufSize) {
		CONNECTIONS.add(new SOSConnection(srcC, srcA, srcP, srcAgentS, 
				dstC, dstA, dstP, dstAgentS, srcNtwkS, dstNtwkS, numSockets, queueCap, bufSize)); 
		return getConnectionFromIP(srcC.getIPAddr(), srcP);
	}
	public boolean removeConnection(IPv4Address ip, OFPort port) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(ip) && conn.getSrcPort().equals(port)) {
				CONNECTIONS.remove(conn);
				return true;
			}
		}
		return false;
	}
	
	public SOSConnection getConnectionFromIP(IPv4Address ip, TransportPort port) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(ip) && conn.getSrcPort().equals(port)) {
				return conn;
			} else if (conn.getDstClient().getIPAddr().equals(ip) && conn.getDstPort().equals(port)) {
				return conn;
			}
		}
		return null;
	}
	
	public SOSPacketStatus getSOSPacketStatus(IPv4Address srcIP, IPv4Address dstIP, TransportPort srcPort, TransportPort dstPort) {
		for (SOSConnection conn : CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(srcIP) && conn.getDstPort().equals(dstPort) && /* don't know the source transport port in conn */
					conn.getDstClient().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.INACTIVE_REGISTERED;
				
			} else if (conn.getSrcClient().getIPAddr().equals(srcIP) && conn.getSrcPort().equals(srcPort) &&
					conn.getSrcAgent().getIPAddr().equals(dstIP) ) {
				
				return SOSPacketStatus.ACTIVE_SRC_CLIENT_TO_SRC_AGENT;
				
			} else if (conn.getDstClient().getIPAddr().equals(srcIP) && conn.getDstPort().equals(srcPort) &&
					conn.getSrcClient().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.ACTIVE_DST_CLIENT_TO_DST_AGENT;
				
			} else if (conn.getDstClient().getIPAddr().equals(dstIP) && conn.getDstPort().equals(dstPort) &&
					conn.getDstAgent().getIPAddr().equals(srcIP)) {
				
				return SOSPacketStatus.ACTIVE_DST_AGENT_TO_DST_CLIENT;
				
			} else if (conn.getSrcClient().getIPAddr().equals(dstIP) && conn.getSrcPort().equals(dstPort) && 
					conn.getSrcAgent().getIPAddr().equals(srcIP)) {
				
				return SOSPacketStatus.ACTIVE_SRC_AGENT_TO_SRC_CLIENT;
				
			} else if (conn.getSrcAgent().getIPAddr().equals(srcIP) && conn.getDstAgent().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.ACTIVE_SRC_AGENT_TO_DST_AGENT;
				
			} else if (conn.getDstAgent().getIPAddr().equals(srcIP) && conn.getSrcAgent().getIPAddr().equals(dstIP)) {
				
				return SOSPacketStatus.ACTIVE_DST_AGENT_TO_SRC_AGENT;
			}
		}
		return SOSPacketStatus.INACTIVE_UNREGISTERED;
	}
}