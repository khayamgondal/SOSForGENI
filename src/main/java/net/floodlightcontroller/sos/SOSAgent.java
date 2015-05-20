package net.floodlightcontroller.sos;

import java.util.ArrayList;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

public class SOSAgent {
	private IPv4Address IP_ADDR;
	private MacAddress MAC_ADDR;
	private int AGENT_ID;
	private OFPort SWITCH_PORT;
	private ArrayList<SOSClient> CLIENTS;
	
	public SOSAgent() {
		IP_ADDR = IPv4Address.NONE;
		MAC_ADDR = MacAddress.NONE;
		AGENT_ID = -1;
		SWITCH_PORT = OFPort.ANY;
		CLIENTS = new ArrayList<SOSClient>();
	}
	public SOSAgent(IPv4Address ip, MacAddress mac, int id) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		AGENT_ID = id;
		SWITCH_PORT = OFPort.ANY;
		CLIENTS = new ArrayList<SOSClient>();
	}
	public SOSAgent(IPv4Address ip, MacAddress mac, OFPort port) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		AGENT_ID = -1;
		SWITCH_PORT = port;
		CLIENTS = new ArrayList<SOSClient>();
	}
	public SOSAgent(IPv4Address ip, MacAddress mac, int id, OFPort port) {
		IP_ADDR = ip;
		MAC_ADDR = mac;
		AGENT_ID = id;
		SWITCH_PORT = port;
		CLIENTS = new ArrayList<SOSClient>();
	}
	
	public boolean addClient(SOSClient client) {
		if (!CLIENTS.contains(client)) {
			return CLIENTS.add(client);
		} else {
			return false;
		}
	}
	public boolean removeClient(SOSClient client) {
		return CLIENTS.remove(client);
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
	
	public void setID(int id) {
		AGENT_ID = id;
	}
	public int getID() {
		return AGENT_ID;
	}
	
	public void setSwitchPort(OFPort port) {
		SWITCH_PORT = port;
	}
	public OFPort getSwitchPort() {
		return SWITCH_PORT;
	}
}