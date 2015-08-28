package net.floodlightcontroller.sos;

import net.floodlightcontroller.devicemanager.SwitchPort;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;

public class SOSAgent {
	private IPv4Address ip_addr;
	private MacAddress mac_addr;
	private TransportPort data_port;
	private TransportPort control_port;
	private SwitchPort[] ap;
	
	public SOSAgent() {
		ip_addr = IPv4Address.NONE;
		mac_addr = MacAddress.NONE;
		data_port = TransportPort.NONE;
		control_port = TransportPort.NONE;
		ap = null;
	}
	public SOSAgent(IPv4Address ip, TransportPort data, TransportPort control) {
		ip_addr = ip;
		mac_addr = MacAddress.NONE; /* MAC will be learned via DeviceManager */
		data_port = data;
		control_port = control;
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
	
	public TransportPort getDataPort() {
		return data_port;
	}
	
	public TransportPort getControlPort() {
		return control_port;
	}
	
	public void setAttachmentPoint(SwitchPort[] ap) {
		this.ap = ap;
	}
	public SwitchPort[] getAttachmentPoint() {
		return ap;
	}
}