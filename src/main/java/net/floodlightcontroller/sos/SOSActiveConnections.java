package net.floodlightcontroller.sos;

import java.util.ArrayList;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

public class SOSActiveConnections  {

	private static ArrayList<SOSConnection> ACTIVE_CONNECTIONS = null;
	
	public SOSActiveConnections() {
		if (ACTIVE_CONNECTIONS == null) {
			ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
		}
	}
	
	public SOSConnection addConnection(SOSClient srcC, SOSAgent srcA, TransportPort srcP, SOSSwitch srcNtwkS, SOSSwitch srcAgentS,
			SOSClient dstC, SOSAgent dstA, TransportPort dstP, SOSSwitch dstNtwkS, SOSSwitch dstAgentS, int numSockets, int queueCap, int bufSize) {
		ACTIVE_CONNECTIONS.add(new SOSConnection(srcC, srcA, srcP, srcAgentS, 
				dstC, dstA, dstP, dstAgentS, srcNtwkS, dstNtwkS, numSockets, queueCap, bufSize)); 
		return getConnectionFromIP(srcC.getIPAddr(), srcP);
	}
	public boolean removeConnection(IPv4Address ip, OFPort port) {
		for (SOSConnection conn : ACTIVE_CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(ip) && conn.getSrcPort().equals(port)) {
				ACTIVE_CONNECTIONS.remove(conn);
				return true;
			}
		}
		return false;
	}
	
	public SOSConnection getConnectionFromIP(IPv4Address ip, TransportPort port) {
		for (SOSConnection conn : ACTIVE_CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(ip) && conn.getSrcPort().equals(port)) {
				return conn;
			} else if (conn.getDstClient().getIPAddr().equals(ip) && conn.getDstPort().equals(port)) {
				return conn;
			}
		}
		return null;
	}
	
	public SOSConnectionPacketMembership isPacketMemberOfActiveConnection(IPv4Address srcIP, IPv4Address dstIP, TransportPort srcPort, TransportPort dstPort) {
		for (SOSConnection conn : ACTIVE_CONNECTIONS) {
			if (conn.getSrcClient().getIPAddr().equals(srcIP) && conn.getSrcPort().equals(srcPort) &&
					conn.getDstClient().getIPAddr().equals(dstIP) ) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_SRC_CLIENT_TO_SRC_AGENT;
				
			} else if (conn.getDstClient().getIPAddr().equals(srcIP) && conn.getDstPort().equals(srcPort) &&
					conn.getSrcClient().getIPAddr().equals(dstIP)) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_DST_CLIENT_TO_DST_AGENT;
				
			} else if (conn.getDstClient().getIPAddr().equals(dstIP) && conn.getDstPort().equals(dstPort) &&
					conn.getDstAgent().getIPAddr().equals(srcIP)) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_DST_AGENT_TO_DST_CLIENT;
				
			} else if (conn.getSrcClient().getIPAddr().equals(dstIP) && conn.getSrcPort().equals(dstPort) && 
					conn.getSrcAgent().getIPAddr().equals(srcIP)) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_SRC_AGENT_TO_SRC_CLIENT;
				
			} else if (conn.getSrcAgent().getIPAddr() == srcIP && conn.getDstAgent().getIPAddr() == dstIP) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_SRC_AGENT_TO_DST_AGENT;
				
			} else if (conn.getDstAgent().getIPAddr() == srcIP && conn.getSrcAgent().getIPAddr() == dstIP) {
				
				return SOSConnectionPacketMembership.ASSOCIATED_DST_AGENT_TO_SRC_AGENT;
			}
		}
		return SOSConnectionPacketMembership.NOT_ASSOCIATED_WITH_ACTIVE_SOS_CONNECTION;
	}
}