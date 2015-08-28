package net.floodlightcontroller.sos;

import net.floodlightcontroller.devicemanager.SwitchPort;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public class SOSClient {
	private IPv4Address ip_addr;
	private MacAddress mac_addr;
	private SOSAgent my_agent;
	private SwitchPort[] ap;
	
	public SOSClient() {
		ip_addr = IPv4Address.NONE;
		mac_addr = MacAddress.NONE;
		my_agent = null;
		ap = null;
	}
	public SOSClient(IPv4Address ip) {
		ip_addr = ip;
		mac_addr = MacAddress.NONE;
		my_agent = null;
	}
	public SOSClient(IPv4Address ip, MacAddress mac, SwitchPort[] ap) {
		ip_addr = ip;
		mac_addr = mac;
		my_agent = null;
		this.ap = ap;
	}
	public SOSClient(IPv4Address ip, MacAddress mac, SOSAgent agent, SwitchPort[] ap) {
		ip_addr = ip;
		mac_addr = mac;
		my_agent = agent;
		this.ap = ap;
	}
	
	public void setIPAddr(IPv4Address ip) {
		ip_addr = ip;
	}
	public IPv4Address getIPAddr() {
		return ip_addr;
	}
	
	public void setMACAddr(MacAddress mac) {
		mac_addr = mac;
	}
	public MacAddress getMACAddr() {
		return mac_addr;
	}
	
	public void setAgent(SOSAgent agent) {
		my_agent = agent;
	}
	public SOSAgent getAgent() {
		return my_agent;
	}
	
	public void setAttachmentPoint(SwitchPort[] ap) {
		this.ap = ap;
	}
	public SwitchPort[] getAttachmentPoint() {
		return ap;
	}
}