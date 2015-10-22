package net.floodlightcontroller.sos;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public interface ISOSDevice {
	
	public IPv4Address getIPAddr();
	
	public MacAddress getMACAddr();
}
