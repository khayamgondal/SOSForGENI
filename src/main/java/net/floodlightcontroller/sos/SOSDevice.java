package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public abstract class SOSDevice implements ISOSDevice {
	private IPv4Address ip_addr;
	private MacAddress mac_addr;
	private SOSDeviceType type;
	
	public SOSDevice(SOSDeviceType t) {
		ip_addr = IPv4Address.NONE;
		mac_addr = MacAddress.NONE;
		type = t;
	}
	public SOSDevice(SOSDeviceType t, IPv4Address ip) {
		ip_addr = ip;
		mac_addr = MacAddress.NONE;
		type = t;
	}
	public SOSDevice(SOSDeviceType t, IPv4Address ip, MacAddress mac) {
		ip_addr = ip;
		mac_addr = mac;
		type = t;
	}
	
	public void setIPAddr(IPv4Address ip) {
		ip_addr = ip;
	}
	
	@Override
	public IPv4Address getIPAddr() {
		return ip_addr;
	}
	
	public void setMACAddr(MacAddress mac) {
		mac_addr = mac;
	}
	
	@Override
	public MacAddress getMACAddr() {
		return mac_addr;
	}
	
	public SOSDeviceType getType() {
		return type;
	}
	
	@Override
	public String toString() {
		return "SOSDevice [ip_addr=" + ip_addr + ", mac_addr=" + mac_addr
				+ ", type=" + type + "]";
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((ip_addr == null) ? 0 : ip_addr.hashCode());
		/* Ignore MAC addresses */
		/* result = prime * result
				+ ((mac_addr == null) ? 0 : mac_addr.hashCode()); */
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SOSDevice other = (SOSDevice) obj;
		if (ip_addr == null) {
			if (other.ip_addr != null)
				return false;
		} else if (!ip_addr.equals(other.ip_addr))
			return false;
		/* Ignore MAC addresses */
		/* if (mac_addr == null) {
			if (other.mac_addr != null)
				return false; 
		} else if (!mac_addr.equals(other.mac_addr))
			return false; */
		if (type != other.type)
			return false;
		return true;
	}
}
