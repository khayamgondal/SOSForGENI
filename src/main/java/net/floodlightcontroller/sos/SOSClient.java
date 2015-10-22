package net.floodlightcontroller.sos;


import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.sos.web.SOSClientSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSClientSerializer.class)
public class SOSClient extends SOSDevice implements ISOSClient {
	private TransportPort sock;
	
	public SOSClient(IPv4Address ip, TransportPort p) {
		super(SOSDeviceType.CLIENT, ip);
		this.sock = p;
	}
	
	public SOSClient(IPv4Address ip, TransportPort p, MacAddress mac) {
		super(SOSDeviceType.CLIENT, ip, mac);
		this.sock = p;
	}
	
	@Override
	public TransportPort getTcpPort() {
		return this.sock;
	}
	
	@Override
	public String toString() {
		return "SOSClient [ " + super.toString()  + " sock=" + sock.toString() + "]";
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((sock == null) ? 0 : sock.hashCode());
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		SOSClient other = (SOSClient) obj;
		if (sock == null) {
			if (other.sock != null)
				return false;
		} else if (!sock.equals(other.sock))
			return false;
		return true;
	}
}