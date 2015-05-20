package net.floodlightcontroller.sos;

import java.util.ArrayList;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

public class SOSClient {
	private IPv4Address IP_ADDR;
	private MacAddress MAC_ADDR;
	private SOSAgent MY_AGENT;
	private OFPort SWITCH_PORT;
	private ArrayList<SOSConnection> ACTIVE_CONNECTIONS;
	
	public SOSClient() {
		IP_ADDR = IPv4Address.NONE;
		MAC_ADDR = MacAddress.NONE;
		MY_AGENT = null;
		SWITCH_PORT = OFPort.ANY;
		ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
	}
	public SOSClient(IPv4Address ip, MacAddress mac) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		MY_AGENT = null;
		SWITCH_PORT = OFPort.ANY;
		ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
	}
	public SOSClient(IPv4Address ip, MacAddress mac, SOSAgent agent) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		MY_AGENT = agent;
		SWITCH_PORT = OFPort.ANY;
		ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
	}
	public SOSClient(IPv4Address ip, MacAddress mac, OFPort switchPort) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		MY_AGENT = null;
		SWITCH_PORT = switchPort;
		ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
	}
	public SOSClient(IPv4Address ip, MacAddress mac, SOSAgent agent, OFPort switchPort) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		MY_AGENT = agent;
		SWITCH_PORT = switchPort;
		ACTIVE_CONNECTIONS = new ArrayList<SOSConnection>();
	}
	
	public boolean addConnection(SOSConnection conn) {
		if (!ACTIVE_CONNECTIONS.contains(conn)) {
			return ACTIVE_CONNECTIONS.add(conn);
		} else {
			return false;
		}
	}
	public boolean removeConnection(SOSConnection conn) {
		return ACTIVE_CONNECTIONS.remove(conn);
	}
	
	public void setIPAddr(IPv4Address ip) {
		IP_ADDR = ip;
	}
	public IPv4Address getIPAddr() {
		return IP_ADDR;
	}
	
	public void setMACAddr(MacAddress mac) {
		MAC_ADDR = mac;
	}
	public MacAddress getMACAddr() {
		return MAC_ADDR;
	}
	
	public void setAgent(SOSAgent agent) {
		MY_AGENT = agent;
	}
	public SOSAgent getAgent() {
		return MY_AGENT;
	}
	
	public void setSwitchPort(OFPort port) {
		SWITCH_PORT = port;
	}
	public OFPort getSwitchPort() {
		return SWITCH_PORT;
	}
	
}